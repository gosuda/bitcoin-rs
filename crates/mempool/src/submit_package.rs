//! Package submission through the existing stamped admission and mutation owner.
use crate::admission::{
    AdmissionFence, MAX_ADMISSION_RETRIES, batch_requests, resolve_mempool_inputs,
};
use crate::gateway::AdmissionMode;
use crate::standardness::AcceptanceRejectReason;
use crate::{
    AdmissionChain, AdmissionOrigin, LocalOrigin, MempoolGateway, MutationResult, PeerToken,
    SubmitError,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitcoin_rs_primitives::{Tx, Txid, Wtxid, unix_time_secs};

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
        /// Witnesses of the subpackage this admission committed with.
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

/// Orders an arbitrary-order child-with-parents package for submission.
///
/// The returned vec is topologically ordered (independent parents sorted by
/// txid, child last) but deliberately NOT fully structure-checked: package
/// weight, intra-package conflicts, and package order are validated by
/// [`crate::package::check_structure`], which
/// [`MempoolGateway::submit_package_with_times`] runs as the single
/// authoritative structural gate (snapshot restore enters there directly, so
/// the check cannot live here without charging local submission a duplicate
/// pass). This function stays private with [`MempoolGateway::submit_local_package`]
/// as its only caller, so its output always flows through that gate and can
/// never reach admission unchecked.
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

/// The ancestors before the last member (the subject) in topological order,
/// stable over the sender's order, and the subject last.
///
/// BIP331 lets an `ancpkginfo` list ancestors in any order. A package that
/// cannot be ordered this way (too many members, or an ancestor that spends
/// the subject) is returned unchanged so [`crate::package::check_structure`]
/// reports it as before.
fn ancestors_in_topological_order(txs: &[Tx]) -> alloc::borrow::Cow<'_, [Tx]> {
    use alloc::borrow::Cow;
    let Some((_, ancestors)) = txs.split_last() else {
        return Cow::Borrowed(txs);
    };
    if txs.len() > crate::standardness::MAX_PACKAGE_COUNT {
        return Cow::Borrowed(txs);
    }
    let ids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
    let mut placed = alloc::vec![false; txs.len()];
    let mut order = Vec::with_capacity(txs.len());
    while order.len() < ancestors.len() {
        let next = ancestors.iter().enumerate().position(|(index, tx)| {
            !placed[index]
                && tx.inputs.iter().all(|input| {
                    ids.iter()
                        .enumerate()
                        .filter(|(other, id)| *other != index && **id == input.previous_output.txid)
                        .all(|(other, _)| placed[other])
                })
        });
        let Some(next) = next else {
            return Cow::Borrowed(txs);
        };
        placed[next] = true;
        order.push(next);
    }
    if order.iter().enumerate().all(|(at, index)| at == *index) {
        return Cow::Borrowed(txs);
    }
    order.push(ancestors.len());
    Cow::Owned(order.into_iter().map(|index| txs[index].clone()).collect())
}

/// BIP331 ancestor shape over a package that already passed
/// [`crate::package::check_structure`]: the last transaction is the subject
/// and every other member is a transitive ancestor of it. Walking from the
/// subject backwards, a member is admissible only when something later spends
/// it, directly or through another member.
fn check_ancestor_shape(txs: &[Tx]) -> Result<(), AcceptanceRejectReason> {
    let Some(subject) = txs.last() else {
        return Err(AcceptanceRejectReason::PackageCount);
    };
    let mut needed: hashbrown::HashSet<Txid> = hashbrown::HashSet::new();
    needed.insert(subject.txid());
    for tx in txs.iter().rev() {
        if !needed.contains(&tx.txid()) {
            return Err(AcceptanceRejectReason::PackageTopology);
        }
        needed.extend(tx.inputs.iter().map(|input| input.previous_output.txid));
    }
    Ok(())
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
        // Core classifies every unordered pair — duplicates included — as a
        // topology violation; run this check before the structural verdicts.
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
                AdmissionOrigin::from(LocalOrigin::Rpc),
                max_rate,
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
                AdmissionOrigin::from(LocalOrigin::Rpc),
                max_rate,
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
        crate::package::check_structure(txs)?;
        self.submit_package_atomic(txs, AdmissionOrigin::from(origin), max_rate, time, chain)
    }

    /// Atomically submits a BIP331 ancestor package relayed by `source`: the
    /// subject last, preceded by its unconfirmed ancestors. BIP331 does not
    /// require the sender to sort the ancestors, so they are put in
    /// topological order first, keeping the sender's order between
    /// independent members; the subject stays last. Members are never
    /// submitted individually, and nothing is replaced or evicted for
    /// capacity. Structure and shape failures leave the pool, observers and
    /// the orphan and reject caches untouched. An admission refusal commits
    /// nothing and hands only the individually refused members, in dependency
    /// order, to the existing bounded orphan hold or reject cache.
    pub fn submit_peer_package(
        &self,
        txs: &[Tx],
        source: PeerToken,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<MutationResult, SubmitError> {
        let txs = ancestors_in_topological_order(txs);
        crate::package::check_structure(&txs)?;
        check_ancestor_shape(&txs)?;
        self.submit_package_atomic(&txs, AdmissionOrigin::Peer(source), None, |_| time, chain)
    }

    /// The resident BIP331 ancestor package of `tip`: its unconfirmed
    /// ancestors in topological order, then `tip`. `None` when `tip` is not
    /// resident or the package would exceed
    /// [`MAX_PACKAGE_COUNT`](crate::standardness::MAX_PACKAGE_COUNT)
    /// transactions. Orphans and recent rejects are never served.
    #[must_use]
    pub fn ancestor_package_wtxids(&self, tip: Wtxid) -> Option<Vec<Wtxid>> {
        self.read().ancestor_package_wtxids(&tip)
    }

    /// The resident bodies of `wtxids`, in the requested order and from one
    /// pool read view, all or none: `None` when any wtxid is not resident.
    /// Orphans, recent rejects and the reconstruction ring are never served.
    /// The bodies are the pool's own `Arc<Tx>`, so no transaction is cloned.
    /// The caller bounds `wtxids.len()`; duplicates yield duplicate handles.
    #[must_use]
    pub fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        let pool = self.read();
        let mut bodies = Vec::with_capacity(wtxids.len());
        for wtxid in wtxids {
            bodies.push(Arc::clone(&pool.entry_by_wtxid(wtxid)?.tx));
        }
        Some(bodies)
    }

    /// The one atomic owner behind local and peer package submission. The
    /// caller has already verified the package's structure and shape.
    fn submit_package_atomic(
        &self,
        txs: &[Tx],
        origin: AdmissionOrigin,
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
        origin: AdmissionOrigin,
        max_rate: Option<u64>,
        time: impl Fn(&Tx) -> u64,
        chain: &dyn AdmissionChain,
        mode: AdmissionMode,
    ) -> Result<PackageAttempt, SubmitError> {
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
            // One atomic commit enters the pool as a single subpackage: Core
            // reports every committed member at the package's aggregate rate
            // and lists the whole package in `effective-includes`.
            let effective_rate = entry_fees.as_ref().and_then(|fees| {
                let (fee, size): (i128, u64) =
                    fees.iter()
                        .fold((0, 0), |(fee, size), (_, member_fee, vsize)| {
                            (fee + member_fee, size + u64::from(*vsize))
                        });
                fee.max(0)
                    .checked_mul(1_000)
                    .and_then(|total| (size != 0).then(|| total / i128::from(size)))
                    .and_then(|rate| u64::try_from(rate).ok())
            });
            let includes: Vec<_> = pending.iter().map(Tx::wtxid).collect();
            for ((tx, row), job) in pending.iter().zip(&facts.results).zip(&prepared) {
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
                            effective_fee_rate: effective_rate,
                            effective_includes: includes.clone(),
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
                        // A peer refusal reaches the bounded lifecycle in this
                        // same revalidated interval; other origins record nothing.
                        self.record_peer_package_refusal(pool, &requests, &prepared);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ChainAdmissionSnapshot, Mempool, MempoolLimits, MempoolObserver, MutationEnvelope,
    };
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, PeerEndpoint, Script, Sequence, TxIn, TxOut, Witness,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Records every published envelope in order.
    #[derive(Default)]
    struct Seen(parking_lot::Mutex<Vec<MutationEnvelope>>);

    impl MempoolObserver for Seen {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            self.0.lock().push(envelope.clone());
        }
    }

    struct Coins(Vec<(OutPoint, TxOut)>);

    impl AdmissionChain for Coins {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: self.0.clone(),
                height: 200,
                csv_active: true,
                ..ChainAdmissionSnapshot::default()
            })
        }
    }

    fn source() -> PeerToken {
        let endpoint = PeerEndpoint::Ip(core::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        PeerToken {
            endpoint: Some(endpoint),
            addr: Some(endpoint),
            connection_id: 7,
        }
    }

    fn coin(tag: u32) -> OutPoint {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&tag.to_le_bytes());
        OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
    }

    /// A chain that confirms each tagged coin at 100,000 sat behind an anyone-can-spend script.
    fn funded(tags: &[u32]) -> Coins {
        Coins(
            tags.iter()
                .map(|tag| {
                    (
                        coin(*tag),
                        TxOut {
                            value: Amount::from_sat(100_000),
                            script_pubkey: Script::from_bytes(vec![0x51]),
                        },
                    )
                })
                .collect(),
        )
    }

    fn output(value: u64) -> TxOut {
        let hash = sha256::Hash::hash(&[0x51]);
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(
                [vec![0, 32], hash.to_byte_array().to_vec()].concat(),
            ),
        }
    }

    /// A version-2 spend of confirmed coins behind the bare anyone-can-spend script.
    fn spend_coins(inputs: &[OutPoint], outputs: &[u64]) -> Tx {
        spend_with(inputs, outputs, &Witness::new())
    }

    /// A version-2 spend of outputs made by `output`, which need the script as witness.
    fn spend_outputs(inputs: &[OutPoint], outputs: &[u64]) -> Tx {
        spend_with(inputs, outputs, &Witness::from_stack(vec![vec![0x51]]))
    }

    fn spend_with(inputs: &[OutPoint], outputs: &[u64], witness: &Witness) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: inputs
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    sequence: Sequence::MAX,
                    script_sig: Script::new(),
                    witness: witness.clone(),
                })
                .collect(),
            outputs: outputs.iter().copied().map(output).collect(),
        }
    }

    fn gateway(min_relay: u64, observer: Option<Arc<dyn MempoolObserver>>) -> MempoolGateway {
        MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: min_relay,
                ..MempoolLimits::default()
            }))),
            observer.map(|observer| (observer, crate::BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        )
    }

    fn txids(result: &MutationResult) -> Vec<Hash256> {
        result.changes.iter().map(|change| change.txid).collect()
    }

    fn ids(txs: &[Tx]) -> Vec<Hash256> {
        txs.iter().map(|tx| Hash256::from(tx.txid())).collect()
    }

    /// A zero-conflict chain of `length` transactions, each paying 1,000 sat.
    fn chain_of(length: usize) -> Vec<Tx> {
        let mut txs: Vec<Tx> = Vec::with_capacity(length);
        let mut value = 100_000_u64;
        for index in 0..length {
            let input = txs
                .last()
                .map_or_else(|| coin(1), |previous| OutPoint::new(previous.txid(), 0));
            value -= 1_000;
            txs.push(if index > 0 {
                spend_outputs(&[input], &[value])
            } else {
                spend_coins(&[input], &[value])
            });
        }
        txs
    }

    #[test]
    fn peer_ancestor_package_commits_an_unpaid_chain_under_its_paying_subject() -> TestResult {
        let seen = Arc::new(Seen::default());
        let gateway = gateway(1_000, Some(seen.clone()));
        let chain = funded(&[1]);
        let grandparent = spend_coins(&[coin(1)], &[100_000]);
        let parent = spend_outputs(&[OutPoint::new(grandparent.txid(), 0)], &[100_000]);
        let subject = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
        let now = unix_time_secs();

        // The unpaid prefix fails the aggregate floor alone. Nothing about it is cached.
        assert_eq!(
            gateway.submit_peer_package(
                &[grandparent.clone(), parent.clone()],
                source(),
                now,
                &chain
            ),
            Err(SubmitError::Policy(
                AcceptanceRejectReason::MinRelayFeeNotMet
            ))
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert!(seen.0.lock().is_empty());

        let package = vec![grandparent.clone(), parent.clone(), subject.clone()];
        let result = gateway.submit_peer_package(&package, source(), now, &chain)?;
        assert_eq!(txids(&result), ids(&package));
        assert_eq!(gateway.read().len(), 3);
        assert_eq!(
            seen.0.lock().as_slice(),
            &[MutationEnvelope {
                origin: AdmissionOrigin::Peer(source()),
                result,
                accepted_transactions: Vec::new(),
            }]
        );
        assert_eq!(
            gateway.ancestor_package_wtxids(subject.wtxid()),
            Some(vec![grandparent.wtxid(), parent.wtxid(), subject.wtxid()])
        );
        assert_eq!(
            gateway.ancestor_package_wtxids(grandparent.wtxid()),
            Some(vec![grandparent.wtxid()])
        );
        let outsider = spend_coins(&[coin(2)], &[100_000]);
        assert_eq!(gateway.ancestor_package_wtxids(outsider.wtxid()), None);

        // Bodies come back in the requested order, repeats included, all or none.
        let requested = [subject.wtxid(), grandparent.wtxid(), subject.wtxid()];
        let bodies = gateway
            .resident_package(&requested)
            .ok_or("every member is resident")?;
        assert_eq!(
            bodies.iter().map(|tx| tx.wtxid()).collect::<Vec<_>>(),
            requested
        );
        assert!(
            gateway
                .resident_package(&[grandparent.wtxid(), outsider.wtxid()])
                .is_none()
        );
        assert!(
            gateway
                .resident_package(&[])
                .is_some_and(|bodies| bodies.is_empty())
        );

        // A replay finds every member resident: no mutation and no new envelope.
        assert!(
            gateway
                .submit_peer_package(&package, source(), now, &chain)?
                .is_empty()
        );
        assert_eq!(seen.0.lock().len(), 1);
        Ok(())
    }

    #[test]
    fn peer_package_keeps_the_senders_order_where_the_local_path_sorts() -> TestResult {
        let chain = funded(&[1, 2]);
        let mut parents = [
            spend_coins(&[coin(1)], &[100_000]),
            spend_coins(&[coin(2)], &[100_000]),
        ];
        parents.sort_by_key(Tx::txid);
        let subject = spend_outputs(
            &[
                OutPoint::new(parents[0].txid(), 0),
                OutPoint::new(parents[1].txid(), 0),
            ],
            &[196_000],
        );
        let descending = vec![parents[1].clone(), parents[0].clone(), subject.clone()];
        let ascending = vec![parents[0].clone(), parents[1].clone(), subject];
        let now = unix_time_secs();

        let peer = gateway(1_000, None);
        let result = peer.submit_peer_package(&descending, source(), now, &chain)?;
        assert_eq!(txids(&result), ids(&descending));

        let local = gateway(1_000, None);
        let result = local.submit_local_package(descending, LocalOrigin::Rpc, None, now, &chain)?;
        assert_eq!(txids(&result), ids(&ascending));
        Ok(())
    }

    #[test]
    fn peer_package_admits_ancestors_the_sender_did_not_sort() -> TestResult {
        let chain = funded(&[1]);
        let grandparent = spend_coins(&[coin(1)], &[100_000]);
        let parent = spend_outputs(&[OutPoint::new(grandparent.txid(), 0)], &[98_000]);
        let subject = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
        let unsorted = vec![parent.clone(), grandparent.clone(), subject.clone()];

        let peer = gateway(1_000, None);
        let result = peer.submit_peer_package(&unsorted, source(), unix_time_secs(), &chain)?;
        assert_eq!(txids(&result), ids(&[grandparent, parent, subject]));
        Ok(())
    }

    #[test]
    fn peer_package_structure_failures_touch_nothing() -> TestResult {
        let seen = Arc::new(Seen::default());
        let gateway = gateway(0, Some(seen.clone()));
        let chain = funded(&[1, 2]);
        let parent = spend_coins(&[coin(1)], &[100_000]);
        let child = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
        let unrelated = spend_coins(&[coin(2)], &[100_000]);
        let oversized: Vec<_> = (10..=10 + u32::try_from(crate::standardness::MAX_PACKAGE_COUNT)?)
            .map(|tag| spend_coins(&[coin(tag)], &[100_000]))
            .collect();
        assert_eq!(oversized.len(), crate::standardness::MAX_PACKAGE_COUNT + 1);
        let cases = [
            (vec![], AcceptanceRejectReason::PackageCount),
            (oversized, AcceptanceRejectReason::PackageCount),
            (
                vec![child.clone(), parent.clone()],
                AcceptanceRejectReason::PackageOrder,
            ),
            (
                vec![parent.clone(), parent.clone()],
                AcceptanceRejectReason::PackageDuplicates,
            ),
            (
                vec![parent.clone(), unrelated.clone()],
                AcceptanceRejectReason::PackageTopology,
            ),
            (
                vec![parent, child, unrelated],
                AcceptanceRejectReason::PackageTopology,
            ),
        ];
        let sequence = gateway.read().sequence_number();
        for (txs, reason) in cases {
            assert_eq!(
                gateway.submit_peer_package(&txs, source(), 1, &chain),
                Err(SubmitError::Policy(reason))
            );
        }
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert!(seen.0.lock().is_empty());
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.recent_rejects_count(), 0);
        Ok(())
    }

    #[test]
    fn refused_peer_package_rolls_back_and_caches_only_the_member_it_refused() -> TestResult {
        let seen = Arc::new(Seen::default());
        let gateway = gateway(0, Some(seen.clone()));
        let chain = funded(&[1]);
        let parent = spend_coins(&[coin(1)], &[100_000]);
        let child = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
        let mut inflating = child.clone();
        inflating.outputs[0].value = Amount::from_sat(200_000);
        let sequence = gateway.read().sequence_number();
        let now = unix_time_secs();

        assert_eq!(
            gateway.submit_peer_package(
                &[parent.clone(), inflating.clone()],
                source(),
                now,
                &chain
            ),
            Err(SubmitError::Consensus)
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert!(seen.0.lock().is_empty());
        assert!(gateway.is_rejected(Hash256::from(inflating.wtxid())));
        assert!(!gateway.is_rejected(Hash256::from(parent.wtxid())));
        assert_eq!(gateway.recent_rejects_count(), 1);
        assert_eq!(gateway.orphan_count(), 0);

        // The parent rolled back with its child, so the valid package still commits whole.
        let result = gateway.submit_peer_package(&[parent, child], source(), now, &chain)?;
        assert_eq!(result.len(), 2);
        assert_eq!(seen.0.lock().len(), 1);
        Ok(())
    }

    #[test]
    fn peer_package_with_an_unavailable_input_holds_the_orphan_and_reports_the_first_refusal() {
        let seen = Arc::new(Seen::default());
        let gateway = gateway(0, Some(seen.clone()));
        let chain = funded(&[1]);
        let parent = spend_coins(&[coin(1)], &[100_000]);
        let orphaned = spend_outputs(&[OutPoint::new(parent.txid(), 0), coin(9)], &[96_000]);
        let sequence = gateway.read().sequence_number();

        assert_eq!(
            gateway.submit_peer_package(
                &[parent, orphaned.clone()],
                source(),
                unix_time_secs(),
                &chain
            ),
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert!(seen.0.lock().is_empty());
        assert_eq!(gateway.orphan_count(), 1);
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert!(gateway.have_tx(Hash256::from(orphaned.wtxid()), true));
        // An orphan is never served as part of an ancestor package or its bodies.
        assert_eq!(gateway.ancestor_package_wtxids(orphaned.wtxid()), None);
        assert!(gateway.resident_package(&[orphaned.wtxid()]).is_none());

        // Rows are judged in dependency order: the first refusal wins, and a
        // later member that was never evaluated is not cached.
        let first = spend_outputs(&[coin(9)], &[100_000]);
        let second = spend_outputs(&[OutPoint::new(first.txid(), 0)], &[200_000]);
        let fresh = self::gateway(0, None);
        assert_eq!(
            fresh.submit_peer_package(&[first, second], source(), unix_time_secs(), &chain),
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert_eq!(fresh.orphan_count(), 1);
        assert_eq!(fresh.recent_rejects_count(), 0);
    }

    #[test]
    fn peer_package_admits_exactly_the_count_bound_atomically_and_serves_no_more() -> TestResult {
        let seen = Arc::new(Seen::default());
        let gateway = gateway(0, Some(seen.clone()));
        let chain = funded(&[1]);
        let count = crate::standardness::MAX_PACKAGE_COUNT;
        let txs = chain_of(count);
        let result = gateway.submit_peer_package(&txs, source(), unix_time_secs(), &chain)?;
        assert_eq!(txids(&result), ids(&txs));
        assert_eq!(seen.0.lock().len(), 1);
        assert_eq!(seen.0.lock()[0].result.len(), count);

        let tip = txs.last().ok_or("chain is not empty")?;
        let served = gateway
            .ancestor_package_wtxids(tip.wtxid())
            .ok_or("the 25-member package is servable")?;
        assert_eq!(
            served,
            txs.iter().map(Tx::wtxid).collect::<Vec<_>>(),
            "ancestors then the tip"
        );

        // One more descendant makes the tip's package 26 deep: nothing is served.
        let next = spend_outputs(&[OutPoint::new(tip.txid(), 0)], &[74_000]);
        let extended = gateway.submit_peer_package(
            std::slice::from_ref(&next),
            source(),
            unix_time_secs(),
            &chain,
        )?;
        assert_eq!(extended.len(), 1);
        assert_eq!(gateway.ancestor_package_wtxids(next.wtxid()), None);
        assert_eq!(
            gateway
                .ancestor_package_wtxids(tip.wtxid())
                .map(|served| served.len()),
            Some(count)
        );

        let refused = self::gateway(0, None).submit_peer_package(
            &chain_of(count + 1),
            source(),
            unix_time_secs(),
            &chain,
        );
        assert_eq!(
            refused,
            Err(SubmitError::Policy(AcceptanceRejectReason::PackageCount))
        );
        Ok(())
    }
}
