//! Package submission through the existing stamped admission and mutation owner.
use crate::admission::{
    AdmissionFence, MAX_ADMISSION_RETRIES, batch_requests, resolve_mempool_inputs,
};
use crate::gateway::AdmissionMode;
use crate::standardness::AcceptanceRejectReason;
use crate::{
    AdmissionChain, AdmissionOrigin, LocalOrigin, MempoolGateway, MutationResult, SubmitError,
};
use alloc::vec::Vec;
use bitcoin_rs_primitives::{Tx, Wtxid, unix_time_secs};

/// One submitted transaction's result. Identities follow the submitted order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageTxResult {
    /// Accepted or already resident. Resident entries have no effective rate.
    Accepted {
        /// Sigop-adjusted virtual size.
        vsize: u32,
        /// Actual transaction fee, without operator deltas.
        base_fee: u64,
        /// Modified fee rate of the newly accepted subpackage, in sat/kvB.
        effective_fee_rate: Option<u64>,
        /// Exact witnesses whose fees paid for this admission.
        effective_includes: Vec<Wtxid>,
    },
    /// The resident transaction has the same txid and another witness.
    DifferentWitness(Wtxid),
    /// No membership was committed for this transaction by this attempt.
    Rejected(SubmitError),
    /// Package-wide validation stopped before this transaction was evaluated.
    Unvalidated,
}

/// Scoped submitpackage results, including independently accepted members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSubmission {
    /// A structural or combined-policy failure, if any.
    pub package_error: Option<AcceptanceRejectReason>,
    /// One result per submitted transaction, in input order.
    pub tx_results: Vec<PackageTxResult>,
}

struct PackageAttempt {
    mutation: MutationResult,
    results: Vec<PackageTxResult>,
    error: Option<SubmitError>,
    package_error: Option<AcceptanceRejectReason>,
}

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
    Ok(txs)
}

impl MempoolGateway {
    /// Core's individual-then-aggregate submission for a singleton or 1p1c.
    /// Wider packages and replacement are explicitly unsupported. The atomic
    /// native operation remains the sole owner of preparation and commit.
    #[expect(
        clippy::too_many_lines,
        reason = "keep Core's individual pass, atomic reconsideration and final membership results in one auditable sequence"
    )]
    pub fn submit_rpc_package(
        &self,
        txs: &[Tx],
        max_rate: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<PackageSubmission, SubmitError> {
        if txs.len() > 2 {
            return Err(AcceptanceRejectReason::PackageUnsupported.into());
        }
        let structure_error = crate::package::check_structure(txs).err();
        if structure_error == Some(AcceptanceRejectReason::PackageDuplicates) {
            return Ok(PackageSubmission {
                package_error: structure_error,
                tx_results: vec![PackageTxResult::Unvalidated; txs.len()],
            });
        }
        if txs.len() == 2
            && (!txs[1]
                .inputs
                .iter()
                .any(|input| input.previous_output.txid == txs[0].txid())
                || txs[0]
                    .inputs
                    .iter()
                    .any(|input| input.previous_output.txid == txs[1].txid()))
        {
            return Err(AcceptanceRejectReason::PackageTopology.into());
        }
        if let Some(reason) = structure_error {
            return Ok(PackageSubmission {
                package_error: Some(reason),
                tx_results: vec![PackageTxResult::Unvalidated; txs.len()],
            });
        }
        let mode = AdmissionMode::PackageRpcSubmit(max_rate.filter(|rate| *rate != 0));
        let mut result = PackageSubmission {
            package_error: None,
            tx_results: Vec::with_capacity(txs.len()),
        };
        let mut reconsider = Vec::new();
        let mut quit_early = false;
        // Pinned Core AcceptPackage first commits individually admissible
        // members. A valid parent survives a child's rejection; a low-fee
        // parent remains absent until its paying child passes the atomic plan.
        for (index, tx) in txs.iter().enumerate() {
            let row = match self.submit_package_attempt(
                core::slice::from_ref(tx),
                LocalOrigin::Rpc,
                None,
                |_| time,
                chain,
                mode,
            ) {
                Ok(attempt) => attempt
                    .results
                    .into_iter()
                    .next()
                    .unwrap_or(PackageTxResult::Unvalidated),
                Err(error) => PackageTxResult::Rejected(error),
            };
            if let PackageTxResult::Rejected(error) = row {
                if matches!(
                    error,
                    SubmitError::Policy(
                        AcceptanceRejectReason::MinRelayFeeNotMet
                            | AcceptanceRejectReason::MissingInputs
                    )
                ) {
                    reconsider.push(index);
                } else {
                    quit_early = true;
                }
            }
            result.tx_results.push(row);
        }
        if !quit_early && reconsider.len() > 1 {
            let pending: Vec<_> = reconsider.iter().map(|&index| txs[index].clone()).collect();
            match self.submit_package_attempt(
                &pending,
                LocalOrigin::Rpc,
                None,
                |_| time,
                chain,
                mode,
            ) {
                Ok(attempt) => {
                    result.package_error = attempt.package_error;
                    if attempt.results.iter().any(|row| {
                        matches!(
                            row,
                            PackageTxResult::Rejected(SubmitError::Policy(
                                AcceptanceRejectReason::MissingEphemeralSpends
                            ))
                        )
                    }) {
                        result.package_error = Some(AcceptanceRejectReason::MissingEphemeralSpends);
                    }
                    for (index, row) in reconsider.into_iter().zip(attempt.results) {
                        // Core retains the individual error for unfinished rows.
                        if row != PackageTxResult::Unvalidated {
                            result.tx_results[index] = row;
                        }
                    }
                }
                Err(error) => {
                    for index in reconsider {
                        result.tx_results[index] = PackageTxResult::Rejected(error);
                    }
                }
            }
        }
        // Concurrent admissions may have evicted an earlier independent
        // success. Never report it as currently resident after it disappeared.
        let pool = self.read();
        for (tx, row) in txs.iter().zip(&mut result.tx_results) {
            if !matches!(
                row,
                PackageTxResult::Accepted { .. } | PackageTxResult::DifferentWitness(_)
            ) {
                continue;
            }
            match pool.entry_by_txid(&tx.txid()) {
                Some(entry) if entry.wtxid == tx.wtxid() => {}
                Some(entry) => *row = PackageTxResult::DifferentWitness(entry.wtxid),
                None => {
                    *row = PackageTxResult::Rejected(AcceptanceRejectReason::MissingInputs.into());
                }
            }
        }
        Ok(result)
    }

    /// Atomically submits a native child-with-independent-parents package,
    /// accepting arbitrary input order. No replacement or capacity eviction;
    /// new members pay the aggregate relay/pressure floor. Resident and
    /// positively confirmed members contribute no fees. The RPC instead uses
    /// `submit_rpc_package`'s individual-first result contract.
    pub fn submit_local_package(
        &self,
        txs: Vec<Tx>,
        origin: LocalOrigin,
        max_rate: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<MutationResult, SubmitError> {
        let txs = ordered(txs)?;
        self.submit_package_with_times(&txs, origin, max_rate, |_| time, chain)
    }

    pub(crate) fn submit_package_with_times(
        &self,
        txs: &[Tx],
        origin: LocalOrigin,
        max_rate: Option<u64>,
        time: impl Fn(&Tx) -> u64,
        chain: &dyn AdmissionChain,
    ) -> Result<MutationResult, SubmitError> {
        let attempt = self.submit_package_attempt(
            txs,
            origin,
            max_rate,
            time,
            chain,
            AdmissionMode::PackageSubmit,
        )?;
        if let Some(error) = attempt.error {
            return Err(error);
        }
        Ok(attempt.mutation)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one stamped package preparation/commit owner serves native and RPC submission"
    )]
    fn submit_package_attempt(
        &self,
        txs: &[Tx],
        origin: LocalOrigin,
        max_rate: Option<u64>,
        time: impl Fn(&Tx) -> u64,
        chain: &dyn AdmissionChain,
        mode: AdmissionMode,
    ) -> Result<PackageAttempt, SubmitError> {
        crate::package::check_structure(txs)?;
        let origin = AdmissionOrigin::from(origin);
        'attempt: for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.stable_generation() else {
                continue;
            };
            let (pending, sequence, stamp, inputs, mut results) = {
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
                let results = txs
                    .iter()
                    .map(|tx| {
                        pool.entry_by_txid(&tx.txid()).map_or(
                            PackageTxResult::Unvalidated,
                            |entry| {
                                if entry.wtxid == tx.wtxid() {
                                    PackageTxResult::Accepted {
                                        vsize: entry.vsize,
                                        base_fee: entry.fee,
                                        effective_fee_rate: None,
                                        effective_includes: Vec::new(),
                                    }
                                } else {
                                    PackageTxResult::DifferentWitness(entry.wtxid)
                                }
                            },
                        )
                    })
                    .collect::<Vec<_>>();
                if pending.is_empty() {
                    return Ok(PackageAttempt {
                        mutation: MutationResult::empty(),
                        results,
                        error: None,
                        package_error: None,
                    });
                }
                let inputs = pending
                    .iter()
                    .map(|tx| resolve_mempool_inputs(&pool, tx))
                    .collect();
                (pending, sequence, pool.policy_stamp(), inputs, results)
            };
            let Some(mut requests) = batch_requests(
                &pending,
                inputs,
                chain,
                max_rate,
                0,
                origin,
                (generation, sequence),
                mode,
            ) else {
                continue;
            };
            for request in &mut requests {
                request.time = time(&request.tx);
            }
            // Positive confirmed membership is a chain fact, so revalidate its
            // generation and policy stamp just like both acceptance and refusal.
            let pending: Vec<_> = requests
                .iter()
                .map(|request| (*request.tx).clone())
                .collect();
            let (mut prepared, checks, plan, entry_fees) = {
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
                    return Ok(PackageAttempt {
                        mutation: MutationResult::empty(),
                        results,
                        error: None,
                        package_error: None,
                    });
                }
                let prepared: Vec<_> = requests
                    .iter()
                    .map(|request| {
                        Self::prepare_admission(
                            &pool,
                            request,
                            mode,
                            AdmissionFence::Stable,
                            self.engine(),
                        )
                    })
                    .collect();
                let entries = crate::package::package_entries(&requests, &prepared);
                // Modified fees decide effective rates; base fees miss the
                // deltas the pool applies (standardness.rs). A failed lookup
                // nulls the rates rather than reporting a base-fee quote.
                let entry_fees: Option<Vec<_>> = entries
                    .iter()
                    .map(|entry| {
                        pool.modified_fee_for(entry.txid, entry.fee)
                            .ok()
                            .map(|fee| (entry.txid, fee, entry.vsize))
                    })
                    .collect();
                let checks = crate::package::capture_package_checks(&pool, &pending, &entries);
                (
                    prepared,
                    checks,
                    pool.prepare_package(entries, unix_time_secs()),
                    entry_fees,
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
                mode,
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
            // A member's effective set is itself plus every member whose
            // fees flow to it through the package spend graph (its
            // descendants): Core reports the bumped parent's package rate
            // and the paying child's own rate.
            let subpackages: Vec<hashbrown::HashSet<_>> = pending
                .iter()
                .map(|tx| {
                    let mut descendants = hashbrown::HashSet::new();
                    descendants.insert(tx.txid());
                    let mut changed = true;
                    while changed {
                        changed = false;
                        for candidate in &pending {
                            if candidate
                                .inputs
                                .iter()
                                .any(|input| descendants.contains(&input.previous_output.txid))
                                && descendants.insert(candidate.txid())
                            {
                                changed = true;
                            }
                        }
                    }
                    descendants
                })
                .collect();
            let includes: Vec<Vec<_>> = subpackages
                .iter()
                .map(|descendants| {
                    pending
                        .iter()
                        .filter(|candidate| descendants.contains(&candidate.txid()))
                        .map(Tx::wtxid)
                        .collect()
                })
                .collect();
            let effective_rates: Vec<_> = match &entry_fees {
                Some(entry_fees) => subpackages
                    .iter()
                    .map(|descendants| {
                        let (fee, size): (i128, u64) = entry_fees
                            .iter()
                            .filter(|(txid, _, _)| descendants.contains(txid))
                            .map(|(_, fee, vsize)| (*fee, u64::from(*vsize)))
                            .fold((0, 0), |(fee, size), (f, s)| (fee + f, size + s));
                        fee.checked_mul(1_000)
                            .and_then(|total| (size != 0).then(|| total / i128::from(size)))
                            .and_then(|rate| u64::try_from(rate).ok())
                    })
                    .collect(),
                None => vec![None; subpackages.len()],
            };
            for (pending_index, ((tx, row), job)) in pending
                .iter()
                .zip(&facts.results)
                .zip(&prepared)
                .enumerate()
            {
                if let Some(index) = txs.iter().position(|original| original.txid() == tx.txid()) {
                    results[index] = if let Some(reason) = row.reject_reason {
                        PackageTxResult::Rejected(match job.rejection {
                            Some((crate::AdmitError::Consensus, _)) => SubmitError::Consensus,
                            _ => SubmitError::Policy(reason),
                        })
                    } else if verdict.is_none() {
                        PackageTxResult::Accepted {
                            vsize: row.vsize,
                            base_fee: row.base_fee.unwrap_or(0),
                            effective_fee_rate: effective_rates[pending_index],
                            effective_includes: includes[pending_index].clone(),
                        }
                    } else {
                        PackageTxResult::Unvalidated
                    };
                }
            }
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
                    // Only the newly submitted members: residents filtered out
                    // of `pending` above were never admitted here, and expiry
                    // must not fail the package over them.
                    let admitted: Vec<_> = pending.iter().map(Tx::txid).collect();
                    self.check_admitted_residency(origin, AdmissionFence::Stable, &admitted)?;
                    return Ok(PackageAttempt {
                        mutation: result,
                        results,
                        error: None,
                        package_error: None,
                    });
                }
                Err(crate::AdmitError::GenerationChanged | crate::AdmitError::MempoolChanged) => {
                    continue 'attempt;
                }
                Err(error) => {
                    let error = match error {
                        crate::AdmitError::Policy(reason) => SubmitError::Policy(reason),
                        _ => SubmitError::Consensus,
                    };
                    // A package floor failure is attributed to the paying child.
                    if facts.package_error == Some(AcceptanceRejectReason::MinRelayFeeNotMet) {
                        if let Some(index) = txs.iter().position(|tx| {
                            pending.last().is_some_and(|last| last.txid() == tx.txid())
                        }) {
                            results[index] = PackageTxResult::Rejected(error);
                        }
                    }
                    // A singleton always has an individual refusal, even when
                    // the atomic package planner supplies the reason.
                    if txs.len() == 1 {
                        results[0] = PackageTxResult::Rejected(error);
                    }
                    return Ok(PackageAttempt {
                        mutation: MutationResult::empty(),
                        results,
                        error: Some(error),
                        package_error: facts.package_error,
                    });
                }
            }
        }
        Err(SubmitError::RetryExhausted)
    }
}
