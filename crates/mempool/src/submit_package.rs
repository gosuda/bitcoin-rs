//! Native child-with-parents submission. RPC package wire compatibility is separate.
use crate::admission::{
    AdmissionFence, MAX_ADMISSION_RETRIES, batch_requests, resolve_mempool_inputs,
};
use crate::gateway::AdmissionMode;
use crate::standardness::AcceptanceRejectReason;
use crate::{
    AdmissionChain, AdmissionOrigin, LocalOrigin, MempoolGateway, MutationResult, SubmitError,
};
use alloc::vec::Vec;
use bitcoin_rs_primitives::{Tx, unix_time_secs};

fn ordered(mut txs: Vec<Tx>) -> Result<Vec<Tx>, SubmitError> {
    if txs.is_empty() || txs.len() > crate::standardness::MAX_PACKAGE_COUNT {
        return Err(AcceptanceRejectReason::PackageCount.into());
    }
    if txs.len() > 1 {
        let ids: hashbrown::HashSet<_> = txs.iter().map(Tx::txid).collect();
        if ids.len() != txs.len() {
            return Err(AcceptanceRejectReason::PackageDuplicates.into());
        }
        let child = txs
            .iter()
            .position(|tx| {
                let parents: hashbrown::HashSet<_> = tx
                    .inputs
                    .iter()
                    .map(|input| input.previous_output.txid)
                    .filter(|id| ids.contains(id))
                    .collect();
                parents.len() == txs.len() - 1 && !parents.contains(&tx.txid())
            })
            .ok_or(AcceptanceRejectReason::PackageTopology)?;
        let child = txs.remove(child);
        if txs.iter().any(|tx| {
            tx.inputs
                .iter()
                .any(|input| ids.contains(&input.previous_output.txid))
        }) {
            return Err(AcceptanceRejectReason::PackageTopology.into());
        }
        txs.sort_by_key(Tx::txid);
        txs.push(child);
    }
    crate::package::check_structure(&txs)?;
    Ok(txs)
}

impl MempoolGateway {
    /// Atomically submits a native child-with-independent-parents package,
    /// accepting arbitrary input order. No replacement or capacity eviction;
    /// new members pay the aggregate relay/pressure floor. Resident and
    /// positively confirmed members contribute no fees. RPC/REST is unchanged.
    #[expect(
        clippy::too_many_lines,
        reason = "keep package capture, verification, stamp revalidation and atomic commit in one auditable owner"
    )]
    pub fn submit_local_package(
        &self,
        txs: Vec<Tx>,
        origin: LocalOrigin,
        max_rate: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<MutationResult, SubmitError> {
        let txs = ordered(txs)?;
        let origin = AdmissionOrigin::from(origin);
        'attempt: for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.stable_generation() else {
                continue;
            };
            let (pending, sequence, stamp, inputs) = {
                let pool = self.read();
                let pending: Vec<_> = txs
                    .iter()
                    .filter(|tx| !pool.contains_txid(&tx.txid()))
                    .cloned()
                    .collect();
                let sequence = pool.sequence_number();
                if self
                    .check_admission_state(
                        &pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        None,
                    )
                    .is_err()
                {
                    continue;
                }
                if pending.is_empty() {
                    return Ok(MutationResult::empty());
                }
                let inputs = pending
                    .iter()
                    .map(|tx| resolve_mempool_inputs(&pool, tx))
                    .collect();
                (pending, sequence, pool.policy_stamp(), inputs)
            };
            let Some(requests) = batch_requests(
                &pending,
                inputs,
                chain,
                max_rate,
                time,
                origin,
                (generation, sequence),
                AdmissionMode::PackageSubmit,
            ) else {
                continue;
            };
            // Positive confirmed membership is a chain fact, so revalidate its
            // generation and policy stamp just like both acceptance and refusal.
            let pending: Vec<_> = requests
                .iter()
                .map(|request| (*request.tx).clone())
                .collect();
            let (mut prepared, checks, plan) = {
                let pool = self.read();
                if self
                    .check_admission_state(
                        &pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        Some(stamp),
                    )
                    .is_err()
                {
                    continue;
                }
                if pending.is_empty() {
                    return Ok(MutationResult::empty());
                }
                let prepared: Vec<_> = requests
                    .iter()
                    .map(|request| {
                        Self::prepare_admission(
                            &pool,
                            request,
                            AdmissionMode::PackageSubmit,
                            AdmissionFence::Stable,
                            self.engine(),
                        )
                    })
                    .collect();
                let entries = crate::package::package_entries(&requests, &prepared);
                let checks = crate::package::capture_package_checks(&pool, &pending, &entries);
                (
                    prepared,
                    checks,
                    pool.prepare_package(entries, unix_time_secs()),
                )
            };
            // Unlike a single preview, even one new package member must use
            // aggregate-package policy, including ephemeral-spend checks.
            let aggregate_error = plan.as_ref().err().copied();
            let facts = crate::package::finish_package(
                &pending,
                &requests,
                &mut prepared,
                Some(checks),
                aggregate_error,
                AdmissionMode::PackageSubmit,
                self.script_cache(),
            );
            let verdict = facts
                .package_error
                .map(crate::AdmitError::Policy)
                .or_else(|| {
                    facts.results.iter().zip(&prepared).find_map(|(row, job)| {
                        row.reject_reason.map(|reason| {
                            // Preview facts intentionally collapse consensus
                            // errors. Submission retains the owner's verdict
                            // for this row; package-only checks remain policy.
                            job.rejection
                                .map_or(crate::AdmitError::Policy(reason), |(error, _)| error)
                        })
                    })
                });
            // Validated keys are carried out before the writer runs; the
            // atomic commit below decides whether any of them is inserted,
            // all or nothing, outside the pool write lock.
            let cache_keys: Vec<_> = prepared
                .iter()
                .filter_map(|job| job.script_cache_key)
                .collect();
            let result = self.commit(
                origin,
                |pool| {
                    self.check_admission_state(
                        pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        Some(stamp),
                    )?;
                    if let Some(error) = verdict {
                        return Err(error);
                    }
                    let plan = plan.map_err(crate::AdmitError::Policy)?;
                    pool.commit_package(plan).map_err(|error| match error {
                        crate::MempoolError::StalePolicy => crate::AdmitError::MempoolChanged,
                        other => crate::AdmitError::Policy(other.into()),
                    })
                },
                |result| Some(result),
            );
            match result {
                Ok(result) => {
                    if let Some(cache) = self.script_cache() {
                        for (wtxid, flags) in cache_keys {
                            cache.insert(wtxid, flags);
                        }
                    }
                    let admitted: Vec<_> = txs.iter().map(Tx::txid).collect();
                    self.expire_after_admission(origin, AdmissionFence::Stable, &admitted)?;
                    return Ok(result);
                }
                Err(crate::AdmitError::GenerationChanged | crate::AdmitError::MempoolChanged) => {
                    continue 'attempt;
                }
                Err(crate::AdmitError::Policy(reason)) => return Err(reason.into()),
                Err(crate::AdmitError::Consensus) => return Err(SubmitError::Consensus),
            }
        }
        Err(SubmitError::RetryExhausted)
    }
}
