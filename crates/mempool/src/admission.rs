use alloc::{sync::Arc, vec::Vec};
#[cfg(test)]
use bitcoin_rs_primitives::unix_time_secs;
use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxOut, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

use crate::standardness::{AcceptanceRejectReason, StandardnessPolicy, is_standard_tx};
use crate::{
    AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, LocalOrigin, MempoolGateway,
    MutationResult, PeerToken,
};

pub(crate) const MAX_ADMISSION_RETRIES: usize = 4;

#[derive(Clone, Copy)]
pub(crate) enum AdmissionFence {
    Stable,
    ChainChange(u64),
}

impl AdmissionFence {
    pub(crate) fn current(self, gateway: &MempoolGateway) -> Option<u64> {
        match self {
            Self::Stable => gateway.stable_generation(),
            Self::ChainChange(odd) => (gateway.chain_generation() == odd).then_some(odd),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChainAdmissionSnapshot {
    pub prevouts: Vec<(OutPoint, TxOut)>,
    pub prevout_meta: HashMap<OutPoint, PrevoutMeta>,
    pub height: u32,
    pub locktime_cutoff: u32,
    pub csv_active: bool,
    pub next_block_script_flags: bitcoin_rs_script::VerifyFlags,
    pub confirmed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrevoutMeta {
    pub height: u32,
    pub mtp: u32,
    pub coinbase: bool,
}

pub trait AdmissionChain: Send + Sync {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmitOutcome {
    Committed(MutationResult),
    AlreadyKnown,
    AlreadyConfirmed,
    Held { missing_parents: Vec<Txid> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubmitError {
    #[error(transparent)]
    Policy(#[from] AcceptanceRejectReason),
    #[error("consensus-verification-failed")]
    Consensus,
    #[error("admission retry exhausted: chain or mempool changed during submission")]
    RetryExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanRetry {
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub source: PeerToken,
    pub result: Result<SubmitOutcome, SubmitError>,
}

pub(crate) fn can_hold_orphan(pool: &crate::Mempool, tx: &Tx, policy: &StandardnessPolicy) -> bool {
    !has_unspendable_input(pool, tx) && is_standard_tx(tx, policy).is_ok()
}

pub(crate) fn has_unspendable_input(pool: &crate::Mempool, tx: &Tx) -> bool {
    tx.inputs
        .iter()
        .any(|input| input.previous_output.is_null())
        || has_invalid_mempool_outpoint(pool, tx)
}

pub(crate) fn has_invalid_mempool_outpoint(pool: &crate::Mempool, tx: &Tx) -> bool {
    tx.inputs.iter().any(|input| {
        let outpoint = input.previous_output;
        pool.transaction_by_txid(&outpoint.txid)
            .is_some_and(|parent| {
                usize::try_from(outpoint.vout)
                    .ok()
                    .and_then(|index| parent.outputs.get(index))
                    .is_none()
            })
    })
}

pub(crate) fn resolve_mempool_inputs(
    pool: &crate::Mempool,
    tx: &Tx,
) -> Option<HashMap<OutPoint, TxOut>> {
    let mut prevouts = HashMap::new();
    for input in &tx.inputs {
        let outpoint = input.previous_output;
        if outpoint.is_null() {
            continue;
        }
        if let Some(parent) = pool.transaction_by_txid(&outpoint.txid) {
            let output = parent.outputs.get(usize::try_from(outpoint.vout).ok()?)?;
            prevouts.insert(outpoint, output.clone());
        }
    }
    Some(prevouts)
}

fn combine_input_facts(
    tx: &Tx,
    mempool_prevouts: &HashMap<OutPoint, TxOut>,
    confirmed: &HashMap<OutPoint, TxOut>,
) -> (Vec<(OutPoint, TxOut)>, Vec<Txid>) {
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    let mut missing_parents = Vec::new();
    let mut seen_missing = HashSet::new();
    for input in &tx.inputs {
        let outpoint = input.previous_output;
        if outpoint.is_null() {
            continue;
        }
        if let Some(output) = mempool_prevouts
            .get(&outpoint)
            .or_else(|| confirmed.get(&outpoint))
        {
            prevouts.push((outpoint, output.clone()));
        } else if seen_missing.insert(outpoint.txid) {
            missing_parents.push(outpoint.txid);
        }
    }
    (prevouts, missing_parents)
}

fn build_admission_request(
    tx: Arc<Tx>,
    mempool_prevouts: Option<HashMap<OutPoint, TxOut>>,
    snapshot: Option<ChainAdmissionSnapshot>,
    max_feerate_sat_per_kvb: Option<u64>,
    time: u64,
    origin: AdmissionOrigin,
    generation: u64,
    sequence: u64,
) -> (AdmissionRequest, Vec<Txid>) {
    let (confirmed, height, locktime_cutoff, prevout_meta, csv_active, next_block_script_flags) =
        snapshot.map_or_else(
            || {
                (
                    HashMap::new(),
                    0,
                    0,
                    HashMap::new(),
                    false,
                    bitcoin_rs_script::VerifyFlags::NONE,
                )
            },
            |snapshot| {
                (
                    snapshot.prevouts.into_iter().collect::<HashMap<_, _>>(),
                    snapshot.height,
                    snapshot.locktime_cutoff,
                    snapshot.prevout_meta,
                    snapshot.csv_active,
                    snapshot.next_block_script_flags,
                )
            },
        );
    let mempool_prevouts = mempool_prevouts.unwrap_or_default();
    let (prevouts, missing_parents) = combine_input_facts(&tx, &mempool_prevouts, &confirmed);
    let missing_inputs = prevouts.len() != tx.inputs.len();
    let context = crate::accounting::prepared_context(&tx, &prevouts, missing_inputs);
    let request = AdmissionRequest {
        tx,
        context,
        prevouts,
        prevout_meta,
        csv_active,
        next_block_script_flags,
        locktime_cutoff,
        max_feerate_sat_per_kvb,
        time,
        height,
        origin,
        expected_generation: generation,
        expected_sequence: sequence,
    };
    (request, missing_parents)
}

pub(crate) fn batch_requests(
    txs: &[Tx],
    mempool_inputs: Vec<Option<HashMap<OutPoint, TxOut>>>,
    chain: &dyn AdmissionChain,
    max_feerate_sat_per_kvb: Option<u64>,
    time: u64,
    origin: AdmissionOrigin,
    (generation, sequence): (u64, u64),
    mode: crate::gateway::AdmissionMode,
) -> Option<Vec<AdmissionRequest>> {
    let mut package_outputs = HashMap::new();
    let mut requests = Vec::with_capacity(txs.len());
    for (tx, mempool_inputs) in txs.iter().zip(mempool_inputs) {
        let snapshot = if mempool_inputs.is_some() {
            chain.snapshot(tx)?
        } else {
            ChainAdmissionSnapshot::default()
        };
        if mode == crate::gateway::AdmissionMode::PackageSubmit && snapshot.confirmed {
            continue;
        }
        let mut available = snapshot.prevouts.into_iter().collect::<HashMap<_, _>>();
        available.extend(mempool_inputs.unwrap_or_default());
        available.extend(
            package_outputs
                .iter()
                .map(|(outpoint, output): (&OutPoint, &TxOut)| (*outpoint, output.clone())),
        );
        let (prevouts, _) = combine_input_facts(tx, &available, &HashMap::new());
        let context =
            crate::accounting::prepared_context(tx, &prevouts, prevouts.len() != tx.inputs.len());
        requests.push(AdmissionRequest {
            tx: Arc::new(tx.clone()),
            context,
            prevouts,
            prevout_meta: snapshot.prevout_meta,
            csv_active: snapshot.csv_active,
            next_block_script_flags: snapshot.next_block_script_flags,
            locktime_cutoff: snapshot.locktime_cutoff,
            max_feerate_sat_per_kvb,
            time,
            height: snapshot.height,
            origin,
            expected_generation: generation,
            expected_sequence: sequence,
        });
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if let Ok(vout) = u32::try_from(vout) {
                package_outputs.insert(OutPoint::new(txid, vout), output.clone());
            }
        }
    }
    Some(requests)
}

impl MempoolGateway {
    #[expect(
        clippy::too_many_lines,
        reason = "keep batch capture, verification and retry fencing in one auditable owner"
    )]
    pub fn preview_transactions(
        &self,
        txs: &[Tx],
        max_feerate_sat_per_kvb: Option<u64>,
        chain: &dyn AdmissionChain,
    ) -> Result<crate::standardness::PackageAcceptanceFacts, SubmitError> {
        use crate::gateway::AdmissionMode;
        use crate::standardness::PackageAcceptanceFacts;
        if let Err(reason) = crate::package::check_structure(txs) {
            return Ok(PackageAcceptanceFacts {
                package_error: Some(reason),
                results: if reason == AcceptanceRejectReason::PackageCount {
                    Vec::new()
                } else {
                    txs.iter().map(crate::package::unfinished).collect()
                },
            });
        }
        let mode = if txs.len() == 1 {
            AdmissionMode::Single
        } else {
            AdmissionMode::PackageTest
        };
        'attempt: for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.stable_generation() else {
                continue;
            };
            let (sequence, stamp, mempool_inputs) = {
                let pool = self.pool.read();
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
                let stamp = pool.policy_stamp();
                (
                    sequence,
                    stamp,
                    txs.iter()
                        .map(|tx| resolve_mempool_inputs(&pool, tx))
                        .collect::<Vec<_>>(),
                )
            };
            let Some(requests) = batch_requests(
                txs,
                mempool_inputs,
                chain,
                max_feerate_sat_per_kvb,
                0,
                AdmissionOrigin::Rpc,
                (generation, sequence),
                mode,
            ) else {
                continue 'attempt;
            };
            let (mut prepared, package_checks) = {
                let pool = self.pool.read();
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
                let prepared = requests
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
                    .collect::<Vec<_>>();
                let checks = (mode == AdmissionMode::PackageTest
                    && prepared.iter().all(|job| job.fact.reject_reason.is_none()))
                .then(|| {
                    let entries = crate::package::package_entries(&requests, &prepared);
                    crate::package::capture_package_checks(&pool, txs, &entries)
                });
                (prepared, checks)
            };
            let facts =
                crate::package::finish_preview(txs, &requests, &mut prepared, package_checks);
            let pool = self.pool.read();
            if self
                .check_admission_state(&pool, generation, sequence, AdmissionFence::Stable, None)
                .is_err()
            {
                continue;
            }
            for row in &prepared {
                if self
                    .check_admission_state(
                        &pool,
                        generation,
                        sequence,
                        AdmissionFence::Stable,
                        Some(row.stamp),
                    )
                    .is_err()
                {
                    continue 'attempt;
                }
            }
            return Ok(facts);
        }
        Err(SubmitError::RetryExhausted)
    }

    pub fn submit_transaction(
        &self,
        tx: Arc<Tx>,
        origin: AdmissionOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<SubmitOutcome, SubmitError> {
        self.submit_transaction_claimed(
            tx,
            origin,
            max_feerate_sat_per_kvb,
            time,
            chain,
            None,
            AdmissionFence::Stable,
        )
    }

    /// # Errors
    ///
    /// Returns the gateway's refusal; nothing is inserted when this fails.
    pub fn submit_local_transaction(
        &self,
        tx: Arc<Tx>,
        origin: LocalOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<MutationResult, SubmitError> {
        match self.submit_transaction(tx, origin.into(), max_feerate_sat_per_kvb, time, chain)? {
            SubmitOutcome::Committed(result) => Ok(result),
            SubmitOutcome::AlreadyKnown => Ok(MutationResult::empty()),
            SubmitOutcome::AlreadyConfirmed | SubmitOutcome::Held { .. } => {
                Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
            }
        }
    }

    pub fn reconsider_disconnected(
        &self,
        change: &crate::gateway::ChainChangeGuard,
        chain: &dyn AdmissionChain,
        time: u64,
        txs: impl IntoIterator<Item = Arc<Tx>>,
    ) -> Vec<MutationResult> {
        if !change.owns(self) {
            return Vec::new();
        }
        let fence = AdmissionFence::ChainChange(change.odd_generation());
        let mut refused: HashSet<Txid> = HashSet::new();
        let mut committed = Vec::new();
        for tx in txs {
            let txid = tx.txid();
            let spends_refused = tx
                .inputs
                .iter()
                .any(|input| refused.contains(&input.previous_output.txid));
            if spends_refused {
                refused.insert(txid);
                continue;
            }
            match self.submit_transaction_claimed(
                tx,
                AdmissionOrigin::Reorg,
                None,
                time,
                chain,
                None,
                fence,
            ) {
                Ok(SubmitOutcome::Committed(result)) => {
                    for removed in result.removed_txids() {
                        refused.insert(removed);
                    }
                    committed.push(result);
                }
                Ok(SubmitOutcome::AlreadyKnown | SubmitOutcome::AlreadyConfirmed) => {}
                Ok(SubmitOutcome::Held { .. }) | Err(_) => {
                    refused.insert(txid);
                }
            }
        }
        committed
    }

    fn submit_transaction_claimed(
        &self,
        mut tx: Arc<Tx>,
        origin: AdmissionOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
        claim: Option<(&crate::orphan::HeldOrphan, &PeerToken)>,
        fence: AdmissionFence,
    ) -> Result<SubmitOutcome, SubmitError> {
        let txid = tx.txid();
        let peer = matches!(origin, AdmissionOrigin::Peer(_));
        for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = fence.current(self) else {
                continue;
            };
            let (sequence, mempool_prevouts, holdable) = {
                let pool = self.pool.read();
                let sequence = pool.sequence_number();
                if self
                    .check_admission_state(&pool, generation, sequence, fence, None)
                    .is_err()
                {
                    continue;
                }
                if pool.contains_txid(&txid) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                if peer && self.lifecycle.lock().rejects_transaction(txid, tx.wtxid()) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                if claim.is_some_and(|(claim, announcer)| {
                    !self.lifecycle.lock().orphans.is_current(claim, announcer)
                }) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                let prevouts = resolve_mempool_inputs(&pool, &tx);
                (
                    sequence,
                    prevouts,
                    peer && can_hold_orphan(&pool, &tx, &pool.policy_snapshot().standardness),
                )
            };
            let snapshot = if mempool_prevouts.is_some() {
                let Some(snapshot) = chain.snapshot(&tx) else {
                    continue;
                };
                Some(snapshot)
            } else {
                None
            };
            if peer && snapshot.as_ref().is_some_and(|snapshot| snapshot.confirmed) {
                let pool = self.pool.read();
                if self
                    .check_admission_state(&pool, generation, sequence, fence, None)
                    .is_err()
                {
                    continue;
                }
                let mut lifecycle = self.lifecycle.lock();
                if claim.is_some_and(|(claim, announcer)| {
                    !lifecycle.orphans.is_current(claim, announcer)
                }) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                lifecycle.orphans.remove_transaction_variants(txid);
                return Ok(SubmitOutcome::AlreadyConfirmed);
            }
            let (request, missing_parents) = build_admission_request(
                tx,
                mempool_prevouts,
                snapshot,
                max_feerate_sat_per_kvb,
                time,
                origin,
                generation,
                sequence,
            );
            match self.admit_transaction_claimed(&request, claim, fence) {
                Ok(AdmitOutcome::Committed(result)) => {
                    self.check_admitted_residency(origin, fence, &[txid])?;
                    return Ok(SubmitOutcome::Committed(result));
                }
                Ok(AdmitOutcome::AlreadyKnown) => return Ok(SubmitOutcome::AlreadyKnown),
                Err(AdmitError::GenerationChanged | AdmitError::MempoolChanged) => {
                    tx = request.tx;
                }
                Err(AdmitError::Policy(AcceptanceRejectReason::MissingInputs)) if holdable => {
                    return Ok(SubmitOutcome::Held { missing_parents });
                }
                Err(AdmitError::Policy(reason)) => return Err(SubmitError::Policy(reason)),
                Err(AdmitError::Consensus) => return Err(SubmitError::Consensus),
            }
        }
        Err(SubmitError::RetryExhausted)
    }

    pub(crate) fn check_admitted_residency(
        &self,
        origin: AdmissionOrigin,
        fence: AdmissionFence,
        admitted: &[Txid],
    ) -> Result<(), SubmitError> {
        let readmission = matches!(origin, AdmissionOrigin::Reorg)
            || matches!(fence, AdmissionFence::ChainChange(_));
        if readmission {
            return Ok(());
        }
        let pool = self.pool.read();
        if admitted.iter().any(|txid| !pool.contains_txid(txid)) {
            return Err(SubmitError::Policy(crate::MempoolError::Full.into()));
        }
        Ok(())
    }

    pub fn retry_orphans(&self, chain: &dyn AdmissionChain, time: u64) -> Vec<OrphanRetry> {
        let ready = {
            let _pool = self.pool.read();
            if self.stable_generation().is_none() {
                return Vec::new();
            }
            self.lifecycle.lock().orphans.take_ready()
        };
        let mut results = Vec::with_capacity(ready.len());
        for (held, announcer) in ready {
            let txid = held.tx.txid();
            let wtxid = held.tx.wtxid();
            if !self.lifecycle.lock().orphans.is_current(&held, &announcer) {
                let mut lifecycle = self.lifecycle.lock();
                if lifecycle.orphans.get(wtxid).is_some() {
                    lifecycle.orphans.mark_ready(wtxid, announcer);
                }
                continue;
            }
            let result = self.submit_transaction_claimed(
                Arc::clone(&held.tx),
                AdmissionOrigin::Peer(announcer),
                None,
                time,
                chain,
                Some((&held, &announcer)),
                AdmissionFence::Stable,
            );
            if matches!(result, Err(SubmitError::RetryExhausted)) {
                let mut lifecycle = self.lifecycle.lock();
                if lifecycle.orphans.is_current(&held, &announcer) {
                    lifecycle.orphans.mark_ready(wtxid, announcer);
                }
            }
            results.push(OrphanRetry {
                txid,
                wtxid,
                source: announcer,
                result,
            });
        }
        results
    }

    pub fn maintain_orphans(
        &self,
        time: u64,
        live_peers: impl IntoIterator<Item = PeerToken>,
    ) -> usize {
        let live_peers: hashbrown::HashSet<PeerToken> = live_peers.into_iter().collect();
        self.lifecycle.lock().orphans.maintain(time, &live_peers)
    }

    pub fn chain_changed(&self, available_parents: &[Txid]) {
        let _pool = self.pool.read();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.clear_rejects();
        for parent in available_parents {
            lifecycle.orphans.parent_ready(*parent);
        }
    }

    pub fn snapshot_changed(&self) {
        let _pool = self.pool.read();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.clear_rejects();
        lifecycle.orphans.mark_all_ready();
    }

    #[must_use]
    pub fn have_tx(&self, hash: Hash256, wtxid: bool) -> bool {
        let pool = self.pool.read();
        let in_pool = if wtxid {
            pool.contains_wtxid(&Wtxid::from(hash))
        } else {
            pool.contains_txid(&Txid::from(hash))
        };
        if in_pool {
            return true;
        }
        let lifecycle = self.lifecycle.lock();
        lifecycle.rejects_inventory(hash, wtxid)
            || (wtxid && lifecycle.orphans.get(Wtxid::from(hash)).is_some())
    }

    #[must_use]
    pub fn get_tx(&self, txid: Txid) -> Option<Tx> {
        let pool = self.pool.read();
        pool.transaction_by_txid(&txid).map(|tx| (*tx).clone())
    }

    #[must_use]
    pub fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(entry) = pool.entry_by_wtxid(&wtxid) {
            return Some((*entry.tx).clone());
        }
        self.lifecycle
            .lock()
            .orphans
            .get(wtxid)
            .map(|held| (*held.tx).clone())
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.lifecycle.lock().orphans.len()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn recent_rejects_count(&self) -> usize {
        self.lifecycle.lock().rejects_len()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn is_rejected(&self, hash: Hash256) -> bool {
        self.lifecycle.lock().is_rejected(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mempool, MempoolEntry};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, TxIn, Witness};
    use parking_lot::{Mutex, RwLock};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Coins(Vec<(OutPoint, TxOut)>);
    impl AdmissionChain for Coins {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: self.0.clone(),
                height: 1,
                locktime_cutoff: 0,
                prevout_meta: HashMap::new(),
                csv_active: false,
                next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
                confirmed: false,
            })
        }
    }

    struct Unavailable;
    impl AdmissionChain for Unavailable {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            None
        }
    }

    fn gateway() -> Arc<MempoolGateway> {
        Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(crate::MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ))
    }

    fn source() -> PeerToken {
        PeerToken {
            endpoint: Some(bitcoin_rs_primitives::PeerEndpoint::Ip(
                core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            )),
            addr: Some(bitcoin_rs_primitives::PeerEndpoint::from((
                [127, 0, 0, 1],
                8333,
            ))),
            connection_id: 7,
        }
    }

    fn standard_spend(outpoint: OutPoint, marker: u8) -> Tx {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[marker; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::from_bytes(script),
            }],
        }
    }

    fn parent_and_child() -> (Tx, Arc<Tx>) {
        let mut parent =
            standard_spend(OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0), 1);
        parent.outputs[0] = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        };
        let child = Arc::new(standard_spend(OutPoint::new(parent.txid(), 0), 2));
        (parent, child)
    }

    fn insert_parent(gateway: &MempoolGateway, parent: Tx, origin: AdmissionOrigin) {
        let inserted = gateway.insert_entry(
            origin,
            MempoolEntry::new(Arc::new(parent), 100, 1_000, unix_time_secs(), 1, 0),
        );
        assert!(inserted.is_ok());
    }

    #[test]
    fn parent_commit_without_observers_retries_orphan_with_original_source() {
        for origin in [
            AdmissionOrigin::Rpc,
            AdmissionOrigin::Esplora,
            AdmissionOrigin::Peer(source()),
            AdmissionOrigin::Reorg,
        ] {
            let gateway = gateway();
            let (parent, child) = parent_and_child();
            let result = gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![]),
            );
            assert_eq!(
                result,
                Ok(SubmitOutcome::Held {
                    missing_parents: vec![parent.txid()]
                })
            );
            assert!(!gateway.have_tx(Hash256::from(child.txid()), false));
            assert!(gateway.have_tx(Hash256::from(child.wtxid()), true));
            assert_eq!(gateway.get_tx(child.txid()), None);
            assert_eq!(
                gateway.get_tx_by_wtxid(child.wtxid()),
                Some((*child).clone())
            );
            insert_parent(&gateway, parent, origin);
            let retried = gateway.retry_orphans(&Coins(vec![]), unix_time_secs());
            assert_eq!(retried.len(), 1);
            assert_eq!(retried[0].source, source());
            assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
            assert_eq!(gateway.orphan_count(), 0);
            assert!(gateway.read().contains_txid(&child.txid()));
        }
    }

    #[test]
    fn rpc_missing_inputs_does_not_create_peer_lifecycle_state() {
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Esplora] {
            let gateway = gateway();
            let (_, child) = parent_and_child();
            let result = gateway.submit_transaction(child, origin, None, 1, &Coins(vec![]));
            assert_eq!(
                result,
                Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
            );
            assert_eq!(gateway.orphan_count(), 0);
            assert_eq!(gateway.recent_rejects_count(), 0);
        }
    }

    #[test]
    fn local_submission_answers_membership_as_success_without_changes() {
        for origin in [LocalOrigin::Rpc, LocalOrigin::Esplora] {
            let gateway = gateway();
            let (parent, child) = parent_and_child();
            insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
            let committed = gateway.submit_local_transaction(
                Arc::clone(&child),
                origin,
                None,
                unix_time_secs(),
                &Coins(vec![]),
            );
            assert_eq!(committed.map(|result| result.len()), Ok(1));
            let sequence = gateway.read().sequence_number();
            assert_eq!(
                gateway.submit_local_transaction(child, origin, None, 2, &Coins(vec![])),
                Ok(MutationResult::empty())
            );
            assert_eq!(gateway.read().sequence_number(), sequence);
        }
    }

    #[test]
    fn nonexistent_mempool_output_is_rejected_without_holding_or_mutating() {
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Peer(source())] {
            for vout in [1, u32::MAX] {
                let gateway = gateway();
                let (parent, child) = parent_and_child();
                let mut invalid = (*child).clone();
                invalid.inputs[0].previous_output.vout = vout;
                let invalid = Arc::new(invalid);
                insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
                let sequence = gateway.read().sequence_number();
                assert_eq!(
                    gateway.submit_transaction(Arc::clone(&invalid), origin, None, 1, &Unavailable),
                    Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
                );
                assert_eq!(gateway.orphan_count(), 0);
                assert_eq!(gateway.read().sequence_number(), sequence);
                assert_eq!(
                    gateway.is_rejected(Hash256::from(invalid.wtxid())),
                    matches!(origin, AdmissionOrigin::Peer(_))
                );
            }
        }
    }

    fn reconstruction_identities(gateway: &MempoolGateway) -> Vec<(Txid, Wtxid)> {
        let mut seen = Vec::new();
        gateway.for_each_reconstruction_identity(|txid, wtxid| seen.push((txid, wtxid)));
        seen
    }

    fn nonstandard_with_heap_usage(outpoint: OutPoint, marker: u8, heap: usize) -> Tx {
        let build = |padding: usize| {
            let mut tx = standard_spend(outpoint, marker);
            tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x6a; padding]);
            tx
        };
        let base =
            usize::try_from(crate::pool::transaction_heap_usage(&build(0))).unwrap_or(usize::MAX);
        let tx = build(heap.saturating_sub(base));
        assert_eq!(
            crate::pool::transaction_heap_usage(&tx),
            u64::try_from(heap).unwrap_or(u64::MAX),
            "the fixture must land exactly on the requested heap usage"
        );
        tx
    }

    fn funded_coin() -> (OutPoint, Coins) {
        let coin = OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0);
        let chain = Coins(vec![(
            coin,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )]);
        (coin, chain)
    }

    #[test]
    fn held_orphan_is_retained_for_reconstruction_only() {
        let gateway = gateway();
        let (_, child) = parent_and_child();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        assert_eq!(
            reconstruction_identities(&gateway),
            vec![(child.txid(), child.wtxid())]
        );

        gateway.maintain_orphans(1, []);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.get_tx_by_wtxid(child.wtxid()), None);
        assert_eq!(gateway.get_tx(child.txid()), None);
        assert!(!gateway.have_tx(Hash256::from(child.wtxid()), true));
        assert_eq!(
            gateway.reconstruction_tx_by_wtxid(child.wtxid()),
            Some((*child).clone())
        );
        assert_eq!(
            gateway.reconstruction_tx_by_txid(child.txid()),
            Some((*child).clone())
        );
    }

    #[test]
    fn promoted_orphan_is_offered_once_and_served_from_the_pool() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        let parent_wtxid = parent.wtxid();
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let retried = gateway.retry_orphans(&Coins(vec![]), unix_time_secs());
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
        assert!(gateway.read().contains_wtxid(&child.wtxid()));

        let identities = reconstruction_identities(&gateway);
        assert_eq!(identities.len(), 2, "pool entries are not repeated");
        assert!(identities.contains(&(child.txid(), child.wtxid())));
        assert!(identities.iter().any(|(_, wtxid)| *wtxid == parent_wtxid));
        assert_eq!(
            gateway.reconstruction_tx_by_wtxid(child.wtxid()),
            Some((*child).clone())
        );
    }

    #[test]
    fn witness_variants_of_one_txid_are_retained_distinctly() {
        let gateway = gateway();
        let (_, plain) = parent_and_child();
        let mut variant = (*plain).clone();
        variant.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let variant = Arc::new(variant);
        assert_eq!(plain.txid(), variant.txid());
        assert_ne!(plain.wtxid(), variant.wtxid());
        let second_source = PeerToken {
            connection_id: source().connection_id + 1,
            ..source()
        };
        for (body, announcer) in [(&plain, source()), (&variant, second_source)] {
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(body),
                    AdmissionOrigin::Peer(announcer),
                    None,
                    1,
                    &Coins(vec![])
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
        }
        assert_eq!(
            reconstruction_identities(&gateway),
            vec![
                (plain.txid(), plain.wtxid()),
                (variant.txid(), variant.wtxid())
            ]
        );
        assert_eq!(
            gateway.reconstruction_tx_by_wtxid(variant.wtxid()),
            Some((*variant).clone())
        );
        assert_eq!(
            gateway.reconstruction_tx_by_wtxid(plain.wtxid()),
            Some((*plain).clone())
        );
    }

    #[test]
    fn peer_orphans_beyond_the_ring_capacity_drop_the_oldest_first() {
        let gateway = gateway();
        let bodies: Vec<Arc<Tx>> = (1_u8..=101)
            .map(|marker| {
                Arc::new(standard_spend(
                    OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
                    marker,
                ))
            })
            .collect();
        for body in &bodies {
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(body),
                    AdmissionOrigin::Peer(source()),
                    None,
                    1,
                    &Coins(vec![])
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
        }
        assert_eq!(gateway.reconstruction_tx_by_wtxid(bodies[0].wtxid()), None);
        assert_eq!(
            reconstruction_identities(&gateway),
            bodies[1..]
                .iter()
                .map(|body| (body.txid(), body.wtxid()))
                .collect::<Vec<_>>(),
            "the newest 100 remain, oldest first"
        );
    }

    #[test]
    fn ring_body_evicted_between_walk_and_lookup_is_absent() {
        let gateway = gateway();
        let hold = |marker: u8| {
            let body = Arc::new(standard_spend(
                OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
                marker,
            ));
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(&body),
                    AdmissionOrigin::Peer(source()),
                    None,
                    1,
                    &Coins(vec![])
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
            body
        };
        let offered = hold(1);
        assert_eq!(
            reconstruction_identities(&gateway),
            vec![(offered.txid(), offered.wtxid())]
        );
        for marker in 2_u8..=101 {
            hold(marker);
        }
        assert_eq!(gateway.reconstruction_tx_by_wtxid(offered.wtxid()), None);
        assert_eq!(gateway.reconstruction_tx_by_txid(offered.txid()), None);
    }

    #[test]
    fn peer_policy_refusal_is_retained_only_below_the_memory_gate() {
        let (coin, chain) = funded_coin();
        let limit = crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES;
        for (heap, retained) in [(limit - 1, true), (limit, false)] {
            let gateway = gateway();
            let tx = Arc::new(nonstandard_with_heap_usage(coin, 3, heap));
            let result = gateway.submit_transaction(
                Arc::clone(&tx),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain,
            );
            assert!(
                matches!(result, Err(SubmitError::Policy(_))),
                "heap {heap}: {result:?}"
            );
            assert!(gateway.is_rejected(Hash256::from(tx.wtxid())));
            assert_eq!(
                gateway.reconstruction_tx_by_wtxid(tx.wtxid()).is_some(),
                retained,
                "heap {heap}"
            );
            assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), None);
        }
    }

    #[test]
    fn peer_policy_refusal_gate_follows_owned_memory_not_wire_size() {
        let (coin, chain) = funded_coin();
        let limit = u64::try_from(crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES).unwrap_or(u64::MAX);
        let packed =
            nonstandard_with_heap_usage(coin, 3, crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES - 1);
        let mut roomy =
            nonstandard_with_heap_usage(coin, 3, crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES - 1);
        let mut inputs = Vec::with_capacity(roomy.inputs.len() + 1);
        inputs.append(&mut roomy.inputs);
        roomy.inputs = inputs;
        assert_eq!(packed.total_size(), roomy.total_size(), "one wire size");
        assert_eq!(packed.wtxid(), roomy.wtxid(), "one witness identity");
        assert!(crate::pool::transaction_heap_usage(&packed) < limit);
        assert!(crate::pool::transaction_heap_usage(&roomy) >= limit);

        for (tx, retained) in [(Arc::new(packed), true), (Arc::new(roomy), false)] {
            let gateway = gateway();
            let result = gateway.submit_transaction(
                Arc::clone(&tx),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain,
            );
            assert!(matches!(result, Err(SubmitError::Policy(_))), "{result:?}");
            assert_eq!(
                gateway.reconstruction_tx_by_wtxid(tx.wtxid()).is_some(),
                retained,
                "retained {retained}"
            );
        }
    }

    #[test]
    fn peer_policy_refusal_gate_counts_script_spare_capacity() {
        let (coin, chain) = funded_coin();
        let limit = u64::try_from(crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES).unwrap_or(u64::MAX);
        let packed =
            nonstandard_with_heap_usage(coin, 3, crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES - 1);
        let mut roomy_pubkey = packed.clone();
        let mut bytes = roomy_pubkey.outputs[0].script_pubkey.as_bytes().to_vec();
        bytes.reserve(64);
        roomy_pubkey.outputs[0].script_pubkey = Script::from_bytes(bytes);
        let mut roomy_sig = packed.clone();
        roomy_sig.inputs[0].script_sig = Script::from_bytes(Vec::with_capacity(64));
        for roomy in [&roomy_pubkey, &roomy_sig] {
            assert_eq!(packed.total_size(), roomy.total_size(), "one wire size");
            assert_eq!(packed.wtxid(), roomy.wtxid(), "one witness identity");
            assert!(crate::pool::transaction_heap_usage(&packed) < limit);
            assert!(
                crate::pool::transaction_heap_usage(roomy) >= limit,
                "spare script capacity must count"
            );
        }

        for (tx, retained) in [
            (Arc::new(packed), true),
            (Arc::new(roomy_pubkey), false),
            (Arc::new(roomy_sig), false),
        ] {
            let gateway = gateway();
            let result = gateway.submit_transaction(
                Arc::clone(&tx),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain,
            );
            assert!(matches!(result, Err(SubmitError::Policy(_))), "{result:?}");
            assert_eq!(
                gateway.reconstruction_tx_by_wtxid(tx.wtxid()).is_some(),
                retained,
                "retained {retained}"
            );
        }
    }

    #[test]
    fn peer_policy_refusal_gate_counts_witness_spare_capacity() {
        let (coin, chain) = funded_coin();
        let limit = u64::try_from(crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES).unwrap_or(u64::MAX);
        let packed =
            nonstandard_with_heap_usage(coin, 3, crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES - 100);
        let mut roomy_outer = packed.clone();
        roomy_outer.inputs[0].witness = Witness::from_stack(Vec::with_capacity(8));
        let mut roomy_item = packed.clone();
        roomy_item.inputs[0].witness = Witness::from_stack(vec![Vec::with_capacity(128)]);
        for roomy in [&roomy_outer, &roomy_item] {
            assert!(crate::pool::transaction_heap_usage(&packed) < limit);
            assert!(
                crate::pool::transaction_heap_usage(roomy) >= limit,
                "spare witness capacity must count"
            );
        }

        for (tx, retained) in [
            (Arc::new(packed), true),
            (Arc::new(roomy_outer), false),
            (Arc::new(roomy_item), false),
        ] {
            let gateway = gateway();
            let result = gateway.submit_transaction(
                Arc::clone(&tx),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain,
            );
            assert!(matches!(result, Err(SubmitError::Policy(_))), "{result:?}");
            assert_eq!(
                gateway.reconstruction_tx_by_wtxid(tx.wtxid()).is_some(),
                retained,
                "retained {retained}"
            );
        }
    }

    #[test]
    fn local_origin_policy_refusal_is_not_retained() {
        let (coin, chain) = funded_coin();
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Esplora] {
            let gateway = gateway();
            let tx = Arc::new(nonstandard_with_heap_usage(
                coin,
                3,
                crate::gateway::EXTRA_TXN_MAX_MEMORY_BYTES - 1,
            ));
            let result = gateway.submit_transaction(Arc::clone(&tx), origin, None, 1, &chain);
            assert!(
                matches!(result, Err(SubmitError::Policy(_))),
                "{origin:?}: {result:?}"
            );
            assert_eq!(gateway.reconstruction_tx_by_wtxid(tx.wtxid()), None);
            assert_eq!(reconstruction_identities(&gateway), vec![]);
        }
    }

    #[test]
    fn consensus_refusal_is_not_retained_for_reconstruction() {
        let gateway = gateway();
        let (parent, valid) = parent_and_child();
        let chain = Coins(vec![(
            valid.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let invalid = Arc::new(invalid);
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain
            ),
            Err(SubmitError::Consensus)
        );
        assert!(gateway.is_rejected(Hash256::from(invalid.wtxid())));
        assert_eq!(gateway.reconstruction_tx_by_wtxid(invalid.wtxid()), None);
        assert_eq!(reconstruction_identities(&gateway), vec![]);
    }

    #[test]
    fn unspendable_pool_outpoint_refusal_is_not_retained_for_reconstruction() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut invalid = (*child).clone();
        invalid.inputs[0].previous_output.vout = 1;
        let invalid = Arc::new(invalid);
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Unavailable
            ),
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert!(gateway.is_rejected(Hash256::from(invalid.wtxid())));
        assert_eq!(gateway.reconstruction_tx_by_wtxid(invalid.wtxid()), None);
    }

    #[test]
    fn no_chain_invalid_attempt_rebuilds_after_its_parent_leaves_the_pool()
    -> Result<(), Box<dyn std::error::Error>> {
        struct ResetPark;
        impl Drop for ResetPark {
            fn drop(&mut self) {
                crate::reset_admission_park();
            }
        }
        let _reset = ResetPark;
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut invalid = (*child).clone();
        invalid.inputs[0].previous_output.vout = 1;
        let invalid = Arc::new(invalid);
        let txid = invalid.txid();
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        crate::arm_admission_park(
            std::ptr::from_ref(gateway.as_ref()).expose_provenance(),
            parked_tx,
            release_rx,
        );
        let worker_gateway = Arc::clone(&gateway);
        let worker = std::thread::spawn(move || {
            worker_gateway.submit_transaction(
                invalid,
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Unavailable,
            )
        });
        assert!(
            parked_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok()
        );
        gateway.clear(AdmissionOrigin::Rpc);
        let sequence = gateway.read().sequence_number();
        assert!(release_tx.send(()).is_ok());
        let Ok(result) = worker.join() else {
            panic!("admission worker panicked")
        };
        assert_eq!(result, Err(SubmitError::RetryExhausted));
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert!(!gateway.read().contains_txid(&txid));
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.recent_rejects_count(), 0);

        for mode in 0..3 {
            assert_verified_admission_rebuilds_after_change(mode)?;
        }
        Ok(())
    }

    fn assert_verified_admission_rebuilds_after_change(
        mode: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        struct MutableCoins(Mutex<Coins>, AtomicUsize);
        impl AdmissionChain for MutableCoins {
            fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
                self.1.fetch_add(1, Ordering::SeqCst);
                self.0.lock().snapshot(tx)
            }
        }
        let gateway = gateway();
        let (valid, coins) = witness_spend();
        let chain = Arc::new(MutableCoins(Mutex::new(coins), AtomicUsize::new(0)));
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        crate::arm_admission_park(
            std::ptr::from_ref(gateway.as_ref()).expose_provenance(),
            parked_tx,
            release_rx,
        );
        let worker_gateway = Arc::clone(&gateway);
        let worker_chain = Arc::clone(&chain);
        let worker_tx = Arc::clone(&valid);
        let worker = std::thread::spawn(move || {
            worker_gateway.submit_transaction(
                worker_tx,
                AdmissionOrigin::Rpc,
                None,
                1,
                worker_chain.as_ref(),
            )
        });
        parked_rx.recv_timeout(std::time::Duration::from_secs(5))?;
        assert!(
            gateway.pool.try_write().is_some(),
            "verification retains no pool guard"
        );
        match mode {
            0 => {
                gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 100_000;
                assert_eq!(gateway.read().sequence_number(), 0, "policy alone changed");
            }
            1 => {
                let mut conflict = (*valid).clone();
                conflict.outputs[0].value =
                    Amount::from_sat(conflict.outputs[0].value.to_sat() - 1);
                gateway.insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::new(conflict), 100, 1_000, 1, 1, 0),
                )?;
            }
            _ => {
                let transition = gateway.begin_chain_change()?;
                chain.0.lock().0.clear();
                transition.finish()?;
            }
        }
        let sequence = gateway.read().sequence_number();
        release_tx.send(())?;
        let result = worker.join().map_err(|_| "submission worker panicked")?;
        match mode {
            0 => assert_eq!(
                result,
                Err(SubmitError::Policy(
                    AcceptanceRejectReason::MinRelayFeeNotMet
                ))
            ),
            1 => assert!(matches!(
                result,
                Err(SubmitError::Policy(AcceptanceRejectReason::Replacement(_)))
            )),
            _ => assert_eq!(
                result,
                Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
            ),
        }
        assert_eq!(
            chain.1.load(Ordering::SeqCst),
            2,
            "stale approval is prepared again"
        );
        assert!(!gateway.read().contains_txid(&valid.txid()));
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.recent_rejects_count(), 0);
        Ok(())
    }

    #[test]
    fn absent_parent_is_held_but_its_nonexistent_output_is_rejected_on_retry() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut invalid = (*child).clone();
        invalid.inputs[0].previous_output.vout = 1;
        let invalid = Arc::new(invalid);
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held {
                missing_parents: vec![parent.txid()]
            })
        );
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let retries = gateway.retry_orphans(&Coins(vec![]), 2);
        assert_eq!(retries.len(), 1);
        assert_eq!(
            retries[0].result,
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.is_rejected(Hash256::from(invalid.wtxid())));
        assert_eq!(gateway.retry_orphans(&Coins(vec![]), 3), []);
    }

    #[test]
    fn stale_invalid_outpoint_claim_cannot_reject_a_refreshed_orphan() {
        let gateway = gateway();
        let (_parent, child) = parent_and_child();
        let mut invalid = (*child).clone();
        invalid.inputs[0].previous_output.vout = 1;
        let invalid = Arc::new(invalid);
        let departed = source();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(departed),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        let claim = gateway
            .lifecycle
            .lock()
            .orphans
            .get(invalid.wtxid())
            .cloned();
        let Some(claim) = claim else {
            panic!("the missing transaction must be resident")
        };
        let mut refreshed = (*invalid).clone();
        refreshed.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let refreshed = Arc::new(refreshed);
        let survivor = PeerToken {
            connection_id: departed.connection_id + 1,
            ..departed
        };
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&refreshed),
                AdmissionOrigin::Peer(survivor),
                None,
                2,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        assert_eq!(gateway.orphan_count(), 2);

        gateway.maintain_orphans(50, [survivor]);
        assert_eq!(gateway.orphan_count(), 1);

        assert_eq!(
            gateway.submit_transaction_claimed(
                Arc::clone(&refreshed),
                AdmissionOrigin::Peer(survivor),
                None,
                3,
                &Unavailable,
                Some((&claim, &departed)),
                AdmissionFence::Stable,
            ),
            Ok(SubmitOutcome::AlreadyKnown)
        );
        assert_eq!(
            gateway.get_tx_by_wtxid(refreshed.wtxid()),
            Some((*refreshed).clone())
        );
        assert_eq!(gateway.orphan_count(), 1);
        assert_eq!(gateway.recent_rejects_count(), 0);
    }

    #[test]
    fn rejected_witness_does_not_suppress_a_valid_body_with_the_same_txid() {
        let gateway = gateway();
        let (parent, valid) = parent_and_child();
        let chain = Coins(vec![(
            valid.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let invalid = Arc::new(invalid);
        assert_eq!(invalid.txid(), valid.txid());
        assert_ne!(invalid.wtxid(), valid.wtxid());
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain
            ),
            Err(SubmitError::Consensus)
        );
        assert!(gateway.have_tx(Hash256::from(invalid.wtxid()), true));
        assert!(!gateway.have_tx(Hash256::from(valid.wtxid()), true));
        assert!(!gateway.have_tx(Hash256::from(valid.txid()), false));
        let now = unix_time_secs();
        assert!(matches!(
            gateway.submit_transaction(valid, AdmissionOrigin::Peer(source()), None, now, &chain),
            Ok(SubmitOutcome::Committed(_))
        ));
    }

    #[test]
    fn rejected_stripped_body_does_not_suppress_its_valid_witness_variant() {
        use bitcoin::hashes::{Hash as _, sha256};

        let gateway = gateway();
        let (_, child) = parent_and_child();
        let witness_script = vec![0x51];
        let mut script_pubkey = vec![0x00, 0x20];
        script_pubkey.extend_from_slice(&sha256::Hash::hash(&witness_script).to_byte_array());
        let chain = Coins(vec![(
            child.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(script_pubkey),
            },
        )]);
        let mut valid = (*child).clone();
        valid.inputs[0].witness = Witness::from_stack(vec![witness_script]);
        let valid = Arc::new(valid);
        let stripped_wtxid = child.wtxid();
        assert_eq!(child.txid(), valid.txid());
        assert_ne!(stripped_wtxid, valid.wtxid());
        assert_eq!(
            gateway.submit_transaction(child, AdmissionOrigin::Peer(source()), None, 1, &chain),
            Err(SubmitError::Consensus)
        );
        assert!(gateway.is_rejected(Hash256::from(valid.txid())));
        assert!(!gateway.is_rejected(Hash256::from(valid.wtxid())));
        assert!(gateway.have_tx(Hash256::from(stripped_wtxid), true));
        assert!(!gateway.have_tx(Hash256::from(valid.txid()), false));
        assert!(!gateway.have_tx(Hash256::from(valid.wtxid()), true));
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&valid),
                AdmissionOrigin::Peer(source()),
                None,
                unix_time_secs(),
                &chain
            ),
            Ok(SubmitOutcome::Committed(_))
        ));
        assert!(gateway.have_tx(Hash256::from(valid.txid()), false));
        assert!(gateway.have_tx(Hash256::from(valid.wtxid()), true));
    }

    #[test]
    fn submission_carries_prepared_fee_size_and_weighted_sigops_into_entry() {
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Peer(source())] {
            let gateway = gateway();
            let (parent, child) = parent_and_child();
            let chain = Coins(vec![(
                child.inputs[0].previous_output,
                parent.outputs[0].clone(),
            )]);
            let now = unix_time_secs();
            assert!(matches!(
                gateway.submit_transaction(Arc::clone(&child), origin, None, now, &chain),
                Ok(SubmitOutcome::Committed(_))
            ));
            let pool = gateway.read();
            let Some(entry) = pool.entry_by_txid(&child.txid()) else {
                panic!("committed transaction must be present")
            };
            assert_eq!(entry.fee, 1_000);
            assert_eq!(u64::from(entry.bip141_vsize), child.vsize());
            assert_eq!(entry.sigop_cost, 4);
            assert_eq!(entry.time, now);
            assert_eq!(entry.height, 1);
        }
    }

    #[test]
    fn chain_change_with_no_pool_mutation_clears_rejects_and_preserves_odd_ready_work() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut rejected = (*child).clone();
        rejected.version = 4;
        let rejected = Arc::new(rejected);
        assert!(
            gateway
                .submit_transaction(
                    Arc::clone(&rejected),
                    AdmissionOrigin::Peer(source()),
                    None,
                    1,
                    &Coins(vec![])
                )
                .is_err()
        );
        assert!(gateway.is_rejected(Hash256::from(rejected.txid())));
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        let reservation = gateway.begin_chain_change();
        assert!(reservation.is_ok());
        let Ok(reservation) = reservation else { return };
        let sequence = gateway.read().sequence_number();
        gateway.chain_changed(&[parent.txid()]);
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert_eq!(gateway.read().sequence_number(), sequence);
        let chain = Coins(vec![(
            child.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        assert_eq!(gateway.retry_orphans(&chain, 2), []);
        assert_eq!(gateway.orphan_count(), 1);
        assert!(reservation.finish().is_ok());
        let retried = gateway.retry_orphans(&chain, unix_time_secs());
        assert_eq!(retried.len(), 1);
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
    }

    #[test]
    fn exhausted_ready_retry_stays_bounded_and_is_retried_on_later_poll() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        gateway.chain_changed(&[parent.txid(), parent.txid()]);
        for _ in 0..3 {
            let retried = gateway.retry_orphans(&Unavailable, 2);
            assert_eq!(retried.len(), 1);
            assert_eq!(retried[0].result, Err(SubmitError::RetryExhausted));
            assert_eq!(gateway.orphan_count(), 1);
        }
        let chain = Coins(vec![(
            child.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        let retried = gateway.retry_orphans(&chain, unix_time_secs());
        assert_eq!(retried.len(), 1);
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
        assert_eq!(gateway.retry_orphans(&chain, 4), []);
    }

    struct ParentArrivesDuringPreparation {
        gateway: Arc<MempoolGateway>,
        parent: Mutex<Option<Tx>>,
        reads: AtomicUsize,
    }
    impl AdmissionChain for ParentArrivesDuringPreparation {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let parent = self.parent.lock().take();
            if let Some(parent) = parent {
                insert_parent(&self.gateway, parent, AdmissionOrigin::Rpc);
            }
            Coins(vec![]).snapshot(&Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![],
                outputs: vec![],
            })
        }
    }

    #[test]
    fn parent_commit_between_resolution_and_hold_cannot_lose_the_only_wake() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let chain = ParentArrivesDuringPreparation {
            gateway: Arc::clone(&gateway),
            parent: Mutex::new(Some(parent)),
            reads: AtomicUsize::new(0),
        };
        let result = gateway.submit_transaction(
            Arc::clone(&child),
            AdmissionOrigin::Peer(source()),
            None,
            unix_time_secs(),
            &chain,
        );
        assert!(matches!(result, Ok(SubmitOutcome::Committed(_))));
        assert_eq!(chain.reads.load(Ordering::Relaxed), 2);
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.read().contains_txid(&child.txid()));
    }

    struct TipChangesDuringPreparation {
        gateway: Arc<MempoolGateway>,
        coin: (OutPoint, TxOut),
        reads: AtomicUsize,
    }
    impl AdmissionChain for TipChangesDuringPreparation {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            let first = self.reads.fetch_add(1, Ordering::Relaxed) == 0;
            let mut coin = self.coin.clone();
            if first {
                let reservation = self.gateway.begin_chain_change();
                assert!(reservation.is_ok());
                let Ok(reservation) = reservation else {
                    return None;
                };
                self.gateway.chain_changed(&[]);
                assert!(reservation.finish().is_ok());
                coin.1.script_pubkey = Script::from_bytes(vec![0x00]);
            }
            Some(ChainAdmissionSnapshot {
                prevouts: vec![coin],
                height: 1,
                locktime_cutoff: 0,
                prevout_meta: HashMap::new(),
                csv_active: false,
                next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
                confirmed: false,
            })
        }
    }

    #[test]
    fn changed_chain_rebuilds_invalid_facts_before_recording_peer_rejection() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let chain = TipChangesDuringPreparation {
            gateway: Arc::clone(&gateway),
            coin: (child.inputs[0].previous_output, parent.outputs[0].clone()),
            reads: AtomicUsize::new(0),
        };
        let now = unix_time_secs();
        assert!(matches!(
            gateway.submit_transaction(child, AdmissionOrigin::Peer(source()), None, now, &chain),
            Ok(SubmitOutcome::Committed(_))
        ));
        assert_eq!(chain.reads.load(Ordering::Relaxed), 2);
        assert_eq!(gateway.recent_rejects_count(), 0);
    }

    struct Confirmed(Coins);
    impl AdmissionChain for Confirmed {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            let mut snapshot = self.0.snapshot(tx)?;
            snapshot.confirmed = true;
            Some(snapshot)
        }
    }

    #[test]
    fn confirmed_lookup_suppresses_peers_but_is_not_rpc_membership() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let chain = Confirmed(Coins(vec![(
            child.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]));
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &chain
            ),
            Ok(SubmitOutcome::AlreadyConfirmed)
        );
        assert_eq!(gateway.read().sequence_number(), 0);
        let now = unix_time_secs();
        assert!(matches!(
            gateway.submit_transaction(child, AdmissionOrigin::Rpc, None, now, &chain),
            Ok(SubmitOutcome::Committed(_))
        ));
    }

    #[test]
    fn coinbase_and_nonstandard_missing_transactions_are_not_held() {
        let gateway = gateway();
        let (_, child) = parent_and_child();
        let mut nonstandard = (*child).clone();
        nonstandard.version = 4;
        let mut coinbase = (*child).clone();
        coinbase.inputs[0].previous_output = OutPoint::null();
        for tx in [nonstandard, coinbase] {
            let tx = Arc::new(tx);
            assert!(
                gateway
                    .submit_transaction(
                        Arc::clone(&tx),
                        AdmissionOrigin::Peer(source()),
                        None,
                        1,
                        &Coins(vec![])
                    )
                    .is_err()
            );
            assert!(gateway.is_rejected(Hash256::from(tx.txid())));
            assert_eq!(gateway.orphan_count(), 0);
        }
    }

    struct ReplaceOrphanDuringSnapshot {
        gateway: Arc<MempoolGateway>,
        replacement: Mutex<Option<Arc<Tx>>>,
        available: Option<(OutPoint, TxOut)>,
        unstable: bool,
    }

    impl AdmissionChain for ReplaceOrphanDuringSnapshot {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            let replacement = self.replacement.lock().take();
            if let Some(replacement) = replacement {
                let mut new_source = source();
                new_source.connection_id -= 1;
                assert!(matches!(
                    self.gateway.submit_transaction(
                        replacement,
                        AdmissionOrigin::Peer(new_source),
                        None,
                        2,
                        &Coins(vec![])
                    ),
                    Ok(SubmitOutcome::Held { .. })
                ));
            }
            if self.unstable {
                return None;
            }
            Some(ChainAdmissionSnapshot {
                prevouts: self.available.iter().cloned().collect(),
                height: 1,
                locktime_cutoff: 0,
                prevout_meta: HashMap::new(),
                csv_active: false,
                next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
                confirmed: false,
            })
        }
    }

    #[test]
    fn refreshed_or_evicted_retry_claim_cannot_commit_hold_reject_or_requeue() {
        for refresh in [true, false] {
            for mode in 0..4 {
                let gateway = gateway();
                gateway.lifecycle.lock().orphans = crate::orphan::OrphanPool::new(1);
                let (parent, base) = parent_and_child();
                let mut child = (*base).clone();
                child.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
                let child = Arc::new(child);
                assert!(matches!(
                    gateway.submit_transaction(
                        Arc::clone(&child),
                        AdmissionOrigin::Peer(source()),
                        None,
                        1,
                        &Coins(vec![])
                    ),
                    Ok(SubmitOutcome::Held { .. })
                ));
                gateway.chain_changed(&[parent.txid()]);
                let mut replacement = (*child).clone();
                if refresh {
                    replacement.inputs[0].witness = Witness::from_stack(vec![vec![2]]);
                } else {
                    replacement.outputs[0].value =
                        Amount::from_sat(replacement.outputs[0].value.to_sat() - 1);
                }
                let replacement = Arc::new(replacement);
                let available = match mode {
                    0 => Some((child.inputs[0].previous_output, parent.outputs[0].clone())),
                    2 => Some((
                        child.inputs[0].previous_output,
                        TxOut {
                            value: Amount::from_sat(10_000),
                            script_pubkey: Script::from_bytes(vec![0x00]),
                        },
                    )),
                    _ => None,
                };
                let chain = ReplaceOrphanDuringSnapshot {
                    gateway: Arc::clone(&gateway),
                    replacement: Mutex::new(Some(Arc::clone(&replacement))),
                    available,
                    unstable: mode == 3,
                };
                let sequence = gateway.read().sequence_number();
                let results = gateway.retry_orphans(&chain, 2);
                assert_eq!(results.len(), 1);
                assert_eq!(gateway.read().sequence_number(), sequence);
                assert_eq!(gateway.orphan_count(), 1);
                assert_eq!(
                    gateway.get_tx_by_wtxid(replacement.wtxid()),
                    Some((*replacement).clone())
                );
                let mut new_source = source();
                new_source.connection_id -= 1;
                assert!(
                    gateway
                        .lifecycle
                        .lock()
                        .orphans
                        .get(replacement.wtxid())
                        .is_some_and(|held| held.announcers.contains(&new_source))
                );
                assert!(!gateway.is_rejected(Hash256::from(child.txid())));
                assert!(!gateway.is_rejected(Hash256::from(replacement.txid())));
                assert_eq!(gateway.retry_orphans(&Unavailable, 3), []);
            }
        }
    }

    #[test]
    fn known_parent_invalid_output_is_rejected_without_orphan_retention() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let mut malformed = (*child).clone();
        malformed.inputs[0].previous_output.vout = 1;
        let malformed = Arc::new(malformed);
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&malformed),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.is_rejected(Hash256::from(malformed.txid())));
        assert!(!gateway.read().contains_txid(&malformed.txid()));
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&malformed),
                AdmissionOrigin::Rpc,
                None,
                2,
                &Coins(vec![])
            ),
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        let mut variant = (*malformed).clone();
        variant.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
        assert_eq!(
            gateway.submit_transaction(
                Arc::new(variant),
                AdmissionOrigin::Peer(source()),
                None,
                3,
                &Unavailable
            ),
            Ok(SubmitOutcome::AlreadyKnown)
        );
    }

    #[test]
    fn orphan_retry_removes_known_invalid_outpoint_after_parent_arrival() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut malformed = (*child).clone();
        malformed.inputs[0].previous_output.vout = 1;
        let malformed = Arc::new(malformed);
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&malformed),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held {
                missing_parents: vec![parent.txid()]
            })
        );
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let results = gateway.retry_orphans(&Coins(vec![]), 2);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].result,
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.is_rejected(Hash256::from(malformed.txid())));
    }

    fn witness_parent_and_child() -> (Tx, Arc<Tx>) {
        let (mut parent, child) = parent_and_child();
        let mut tx = (*child).clone();
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&Sha256::digest([0x51]));
        parent.outputs[0].script_pubkey = Script::from_bytes(script);
        tx.inputs[0].previous_output.txid = parent.txid();
        (parent, Arc::new(tx))
    }

    fn witness_spend() -> (Arc<Tx>, Coins) {
        let (parent, tx) = witness_parent_and_child();
        let chain = Coins(vec![(
            tx.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        (tx, chain)
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "keep the independent BIP141 oracle and offered-output boundary vectors together"
    )]
    fn package_prevouts_preserve_sigops_without_mutating_the_pool()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_primitives::consensus_bytes;
        let gateway = gateway();
        let sequence = gateway.read().sequence_number();
        let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let p2wsh = [vec![0x00, 0x20], vec![3; 32]].concat();
        let multisig = vec![0x52, 0xae];
        let cases = [
            (p2wpkh, Vec::new(), Vec::new(), 1),
            (p2sh.clone(), vec![2, 0x52, 0xae], Vec::new(), 8),
            (p2wsh.clone(), Vec::new(), vec![multisig.clone()], 2),
            (p2sh, [vec![34], p2wsh].concat(), vec![multisig], 2),
        ];
        for (script_pubkey, script_sig, witness, input_cost) in cases {
            let parent = Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat(1),
                        script_pubkey: Script::from_bytes(vec![0x51]),
                    },
                    TxOut {
                        value: Amount::from_sat(9_000),
                        script_pubkey: Script::from_bytes(script_pubkey),
                    },
                ],
            };
            let child = Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent.txid(), 1),
                    script_sig: Script::from_bytes(script_sig),
                    sequence: Sequence::MAX,
                    witness: Witness::from_stack(witness),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(8_000),
                    script_pubkey: Script::from_bytes(vec![0xac]),
                }],
            };
            let oracle: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&consensus_bytes(&child))?;
            let expected_outpoint = oracle.input[0].previous_output;
            let oracle_output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(parent.outputs[1].value.to_sat()),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(
                    parent.outputs[1].script_pubkey.as_bytes().to_vec(),
                ),
            };
            assert_eq!(
                u32::try_from(oracle.total_sigop_cost(|outpoint| {
                    (*outpoint == expected_outpoint).then(|| oracle_output.clone())
                }))?,
                4 + input_cost,
                "independent rust-bitcoin oracle",
            );
            let outpoint = child.inputs[0].previous_output;
            let context = crate::accounting::prepared_context(
                &child,
                &[(outpoint, parent.outputs[1].clone())],
                false,
            );
            assert_eq!(context.fee, 1_000);
            assert_eq!(context.sigop_cost, 4 + input_cost);
            assert_eq!(
                context.vsize,
                crate::accounting::policy_vsize(&child, 4 + input_cost)
            );
            let txs = [parent, child];
            let facts = gateway.preview_transactions(&txs, None, &Coins(vec![]))?;
            assert_eq!(
                facts.results[0].reject_reason,
                Some(AcceptanceRejectReason::MissingInputs)
            );
            assert_eq!(
                facts.results[1].allowed, None,
                "Core stops before child validation"
            );
            assert_eq!(facts.results[1].base_fee, None);
            for vout in [2, u32::MAX] {
                let mut missing = txs[1].clone();
                missing.inputs[0].previous_output.vout = vout;
                let context = crate::accounting::prepared_context(&missing, &[], true);
                assert!(context.missing_inputs);
                assert_eq!(context.fee, 0);
                assert_eq!(context.sigop_cost, 4);
                let facts = gateway.preview_transactions(
                    &[txs[0].clone(), missing],
                    None,
                    &Coins(vec![]),
                )?;
                assert_eq!(facts.results[1].allowed, None);
            }
            assert_eq!(gateway.read().sequence_number(), sequence);
            assert!(gateway.read().is_empty());
        }
        Ok(())
    }

    #[test]
    fn preview_matches_submission_and_has_no_side_effects() -> Result<(), Box<dyn std::error::Error>>
    {
        struct Observer(AtomicUsize);
        impl crate::MempoolObserver for Observer {
            fn on_mutation(&self, _: &crate::MutationEnvelope) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let observer = Arc::new(Observer(AtomicUsize::new(0)));
        let preview_gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(crate::MempoolLimits::default()))),
            Some((observer.clone(), crate::BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        let (valid, chain) = witness_spend();
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        let mut second = (*valid).clone();
        second.outputs[0].value = Amount::from_sat(second.outputs[0].value.to_sat() - 1);
        assert!(matches!(
            preview_gateway.submit_transaction(
                Arc::clone(&valid),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        for (tx, allowed, reason) in [
            ((*valid).clone(), true, None),
            (second.clone(), true, None),
            (
                invalid.clone(),
                false,
                Some(AcceptanceRejectReason::ScriptVerify),
            ),
        ] {
            let facts =
                preview_gateway.preview_transactions(core::slice::from_ref(&tx), None, &chain)?;
            assert_eq!(facts.results[0].allowed, Some(allowed));
            assert_eq!(facts.results[0].reject_reason, reason);
            let fresh = gateway();
            let now = unix_time_secs();
            let submitted =
                fresh.submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, None, now, &chain);
            if allowed {
                assert!(matches!(submitted, Ok(SubmitOutcome::Committed(_))));
            } else {
                assert_eq!(submitted, Err(SubmitError::Consensus));
            }
        }
        assert_eq!(preview_gateway.orphan_count(), 1);
        assert_eq!(preview_gateway.recent_rejects_count(), 0);
        assert!(preview_gateway.read().is_empty());
        assert_eq!(preview_gateway.read().sequence_number(), 0);
        assert_eq!(observer.0.load(Ordering::SeqCst), 0);
        assert_eq!(preview_gateway.read().estimator_last_decayed_height(), None);
        preview_gateway.remove_for_block(
            AdmissionOrigin::Block,
            &[valid.as_ref(), &second],
            &[valid.txid(), second.txid()],
            2,
            0,
        );
        assert_eq!(preview_gateway.read().estimate_fee_rate(2), None);
        assert_eq!(observer.0.load(Ordering::SeqCst), 0);
        let submitted = gateway();
        let now = unix_time_secs();
        assert!(matches!(
            submitted.submit_transaction(
                Arc::clone(&valid),
                AdmissionOrigin::Rpc,
                None,
                now,
                &chain
            ),
            Ok(SubmitOutcome::Committed(_))
        ));
        for tx in [(*valid).clone(), invalid] {
            let facts = submitted.preview_transactions(&[tx], None, &chain)?;
            assert_eq!(
                facts.results[0].reject_reason,
                Some(AcceptanceRejectReason::AlreadyInMempool)
            );
        }
        assert_eq!(submitted.read().sequence_number(), 1);
        Ok(())
    }

    #[test]
    fn preview_and_submission_check_scripts_before_maxfeerate()
    -> Result<(), Box<dyn std::error::Error>> {
        let gateway = gateway();
        let (valid, chain) = witness_spend();
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        for (tx, reason, submitted) in [
            (
                (*valid).clone(),
                AcceptanceRejectReason::MaxFeeExceeded,
                Err(SubmitError::Policy(AcceptanceRejectReason::MaxFeeExceeded)),
            ),
            (
                invalid,
                AcceptanceRejectReason::ScriptVerify,
                Err(SubmitError::Consensus),
            ),
        ] {
            let preview =
                gateway.preview_transactions(core::slice::from_ref(&tx), Some(1), &chain)?;
            assert_eq!(preview.results[0].reject_reason, Some(reason));
            assert_eq!(
                gateway.submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, Some(1), 1, &chain),
                submitted
            );
        }
        Ok(())
    }

    #[test]
    fn preview_retries_chain_pool_and_policy_changes() -> Result<(), Box<dyn std::error::Error>> {
        struct ChangingRead {
            gateway: Arc<MempoolGateway>,
            coins: Coins,
            reads: AtomicUsize,
            mode: u8,
            every_time: bool,
        }
        impl AdmissionChain for ChangingRead {
            fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
                let read = self.reads.fetch_add(1, Ordering::SeqCst);
                if read == 0 || self.every_time {
                    match self.mode {
                        0 => self.gateway.begin_chain_change().ok()?.finish().ok()?,
                        1 => {
                            let (parent, _) = parent_and_child();
                            insert_parent(&self.gateway, parent, AdmissionOrigin::Rpc);
                        }
                        _ => self.gateway.pool.write().limits.min_relay_fee_sat_per_kvb = 100_000,
                    }
                }
                self.coins.snapshot(tx)
            }
        }
        for mode in 0..3 {
            let gateway = gateway();
            let (tx, coins) = witness_spend();
            let chain = ChangingRead {
                gateway: Arc::clone(&gateway),
                coins,
                reads: AtomicUsize::new(0),
                mode,
                every_time: false,
            };
            let facts = gateway.preview_transactions(&[(*tx).clone()], None, &chain)?;
            assert_eq!(chain.reads.load(Ordering::SeqCst), 2);
            assert_eq!(facts.results[0].allowed, Some(mode != 2));
            if mode == 2 {
                assert_eq!(
                    facts.results[0].reject_reason,
                    Some(AcceptanceRejectReason::MinRelayFeeNotMet)
                );
                assert_eq!(gateway.read().sequence_number(), 0);
            }
            assert!(!gateway.read().contains_txid(&tx.txid()));
        }
        let gateway = gateway();
        let (tx, coins) = witness_spend();
        let chain = ChangingRead {
            gateway: Arc::clone(&gateway),
            coins,
            reads: AtomicUsize::new(0),
            mode: 0,
            every_time: true,
        };
        assert_eq!(
            gateway.preview_transactions(&[(*tx).clone()], None, &chain),
            Err(SubmitError::RetryExhausted)
        );
        assert_eq!(
            chain.reads.load(Ordering::SeqCst),
            4,
            "POL-03 pins four attempts independently of the loop constant"
        );
        assert!(gateway.read().is_empty());
        Ok(())
    }

    #[test]
    fn witness_rejection_preserves_valid_variant_and_legacy_inventory() {
        for stripped in [false, true] {
            let gateway = gateway();
            let (valid, chain) = witness_spend();
            let mut invalid = (*valid).clone();
            invalid.inputs[0].witness = if stripped {
                Witness::new()
            } else {
                Witness::from_stack(vec![vec![0x00]])
            };
            let invalid = Arc::new(invalid);
            assert_eq!(valid.txid(), invalid.txid());
            assert_ne!(valid.wtxid(), invalid.wtxid());
            assert_eq!(
                gateway.submit_transaction(
                    Arc::clone(&invalid),
                    AdmissionOrigin::Peer(source()),
                    None,
                    1,
                    &chain
                ),
                Err(SubmitError::Consensus)
            );
            assert!(!gateway.have_tx(Hash256::from(valid.txid()), false));
            assert!(!gateway.have_tx(Hash256::from(valid.wtxid()), true));
            assert!(gateway.have_tx(Hash256::from(invalid.wtxid()), true));
            assert_eq!(
                gateway.submit_transaction(
                    Arc::clone(&invalid),
                    AdmissionOrigin::Peer(source()),
                    None,
                    2,
                    &Unavailable
                ),
                Ok(SubmitOutcome::AlreadyKnown)
            );
            let now = unix_time_secs();
            assert!(matches!(
                gateway.submit_transaction(
                    valid,
                    AdmissionOrigin::Peer(source()),
                    None,
                    now,
                    &chain
                ),
                Ok(SubmitOutcome::Committed(_))
            ));
        }
    }

    #[test]
    fn fresh_invalid_witness_preserves_a_different_resident_orphan_variant() {
        let gateway = gateway();
        let (parent, valid) = witness_parent_and_child();
        let chain = Coins(vec![(
            valid.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&valid),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        let invalid = Arc::new(invalid);
        let mut attacker = source();
        attacker.connection_id += 1;
        assert_eq!(
            gateway.submit_transaction(invalid, AdmissionOrigin::Peer(attacker), None, 2, &chain),
            Err(SubmitError::Consensus)
        );
        assert_eq!(
            gateway.get_tx_by_wtxid(valid.wtxid()),
            Some((*valid).clone())
        );
        assert!(
            gateway
                .lifecycle
                .lock()
                .orphans
                .get(valid.wtxid())
                .is_some_and(|held| held.announcers.contains(&source()))
        );
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let results = gateway.retry_orphans(&Coins(vec![]), unix_time_secs());
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, Ok(SubmitOutcome::Committed(_))));
        assert_eq!(results[0].source, source());
        assert_eq!(results[0].wtxid, valid.wtxid());
        assert_ne!(
            Hash256::from(results[0].wtxid),
            Hash256::from(results[0].txid)
        );
    }

    fn p2wsh_parent_and_variants() -> (Tx, Arc<Tx>, Arc<Tx>) {
        use bitcoin::hashes::{Hash as _, sha256};

        let witness_script = vec![0x75, 0x51];
        let mut script_pubkey = vec![0x00, 0x20];
        script_pubkey.extend_from_slice(&sha256::Hash::hash(&witness_script).to_byte_array());
        let mut parent =
            standard_spend(OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0), 1);
        parent.outputs[0] = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(script_pubkey),
        };
        let outpoint = OutPoint::new(parent.txid(), 0);
        let mut first = standard_spend(outpoint, 2);
        first.inputs[0].witness = Witness::from_stack(vec![vec![0x11], witness_script.clone()]);
        let first = Arc::new(first);
        let mut second = (*first).clone();
        second.inputs[0].witness = Witness::from_stack(vec![vec![0x22], witness_script]);
        let second = Arc::new(second);
        (parent, first, second)
    }

    #[test]
    fn orphan_txid_does_not_suppress_txid_inventory_but_wtxid_does() {
        let gateway = gateway();
        let (_parent, held, _other) = p2wsh_parent_and_variants();
        assert_ne!(
            Hash256::from(held.txid()),
            Hash256::from(held.wtxid()),
            "a witnessed body hashes differently per identity"
        );
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&held),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        assert!(!gateway.have_tx(Hash256::from(held.txid()), false));
        assert!(gateway.have_tx(Hash256::from(held.wtxid()), true));
        assert_eq!(gateway.get_tx(held.txid()), None);
        assert_eq!(gateway.get_tx_by_wtxid(held.wtxid()), Some((*held).clone()));
    }

    #[test]
    fn same_txid_different_witnesses_both_survive_and_retry_after_parent() {
        let gateway = gateway();
        let (parent, first, second) = p2wsh_parent_and_variants();
        assert_eq!(first.txid(), second.txid());
        assert_ne!(first.wtxid(), second.wtxid());
        let second_source = PeerToken {
            connection_id: source().connection_id + 1,
            ..source()
        };
        for (body, announcer) in [(&first, source()), (&second, second_source)] {
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(body),
                    AdmissionOrigin::Peer(announcer),
                    None,
                    1,
                    &Coins(vec![])
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
        }
        assert_eq!(gateway.orphan_count(), 2);
        assert_eq!(
            gateway.get_tx_by_wtxid(first.wtxid()),
            Some((*first).clone())
        );
        assert_eq!(
            gateway.get_tx_by_wtxid(second.wtxid()),
            Some((*second).clone())
        );

        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let results = gateway.retry_orphans(&Coins(vec![]), unix_time_secs());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].txid, first.txid());
        assert!(matches!(results[0].result, Ok(SubmitOutcome::Committed(_))));
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.read().contains_txid(&first.txid()));
    }

    #[test]
    fn zero_hash_output_zero_is_requested_and_retried_as_an_ordinary_outpoint() {
        use bitcoin::hashes::Hash as _;

        let reference = bitcoin::OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        assert!(!reference.is_null());
        let outpoint = OutPoint::default();
        assert!(!outpoint.is_null());
        let gateway = gateway();
        let tx = Arc::new(standard_spend(outpoint, 3));
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&tx),
                AdmissionOrigin::Peer(source()),
                None,
                1,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held {
                missing_parents: vec![Txid::default()]
            })
        );
        gateway.chain_changed(&[Txid::default()]);
        let coins = Coins(vec![(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )]);
        let retried = gateway.retry_orphans(&coins, unix_time_secs());
        assert_eq!(retried.len(), 1);
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
        assert!(gateway.read().contains_txid(&tx.txid()));
        assert_eq!(gateway.orphan_count(), 0);
    }

    #[test]
    fn null_input_in_a_non_coinbase_transaction_is_not_held() {
        let reference = bitcoin::OutPoint::null();
        assert!(reference.is_null());
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut tx = (*child).clone();
        tx.inputs.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        let tx = Arc::new(tx);
        let coins = Coins(vec![(
            tx.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        assert!(
            gateway
                .submit_transaction(
                    Arc::clone(&tx),
                    AdmissionOrigin::Peer(source()),
                    None,
                    1,
                    &coins
                )
                .is_err()
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert!(!gateway.read().contains_txid(&tx.txid()));
        assert!(gateway.is_rejected(Hash256::from(tx.txid())));
    }

    struct InputStructureChain {
        coins: Coins,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl AdmissionChain for InputStructureChain {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.coins.snapshot(tx)
        }
    }

    fn assert_input_structure_rejection(mut tx: Tx, coins: Coins) {
        let gateway = gateway();
        let chain = InputStructureChain {
            coins,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        tx.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let tx = Arc::new(tx);
        let origin = AdmissionOrigin::Peer(source());
        assert_eq!(
            gateway.submit_transaction(Arc::clone(&tx), origin, None, 1, &chain),
            Err(SubmitError::Consensus)
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), 0);
        assert!(gateway.have_tx(Hash256::from(tx.txid()), false));
        assert!(gateway.get_tx(tx.txid()).is_none());

        let mut alternate = (*tx).clone();
        alternate.inputs[0].witness = Witness::from_stack(vec![vec![2]]);
        assert_eq!(alternate.txid(), tx.txid());
        assert_ne!(alternate.wtxid(), tx.wtxid());
        let alternate = Arc::new(alternate);
        assert_eq!(
            gateway.submit_transaction(Arc::clone(&alternate), origin, None, 2, &chain),
            Ok(SubmitOutcome::AlreadyKnown)
        );
        assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 0);

        gateway.chain_changed(&[]);
        assert_eq!(
            gateway.submit_transaction(alternate, origin, None, 3, &chain),
            Err(SubmitError::Consensus)
        );
        assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 0);
    }

    #[test]
    fn input_structure_duplicate_rejection_is_shared_across_witnesses() {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[91; 32])), 0);
        for resolved in [false, true] {
            let mut tx = standard_spend(outpoint, 3);
            tx.inputs.push(tx.inputs[0].clone());
            let coins = if resolved {
                vec![(
                    outpoint,
                    TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: Script::from_bytes(vec![0x51]),
                    },
                )]
            } else {
                vec![]
            };
            assert_input_structure_rejection(tx, Coins(coins));
        }
    }

    #[test]
    fn input_structure_null_rejection_is_shared_across_witnesses() {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[92; 32])), 0);
        let mut tx = standard_spend(outpoint, 4);
        let mut null_input = tx.inputs[0].clone();
        null_input.previous_output = OutPoint::null();
        tx.inputs.push(null_input);
        assert_input_structure_rejection(tx, Coins(vec![]));
    }

    #[test]
    fn input_structure_rpc_rejection_does_not_populate_peer_caches() {
        let gateway = gateway();
        let mut tx = standard_spend(OutPoint::default(), 5);
        tx.inputs.push(tx.inputs[0].clone());
        tx.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        assert_eq!(
            gateway.submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, None, 1, &Coins(vec![])),
            Err(SubmitError::Consensus)
        );
        assert_eq!(gateway.recent_rejects_count(), 0);
        assert_eq!(gateway.orphan_count(), 0);
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), 0);
    }

    #[derive(Default)]
    struct ReorgRecording(Mutex<Vec<(Txid, AdmissionOrigin)>>);

    impl crate::MempoolObserver for ReorgRecording {
        fn on_mutation(&self, envelope: &crate::MutationEnvelope) {
            let mut seen = self.0.lock();
            for change in &envelope.result.changes {
                seen.push((Txid::from(change.txid), envelope.origin));
            }
        }
    }

    type ReorgBatch = (AdmissionOrigin, Vec<(Txid, crate::MutationOutcome)>);

    #[derive(Default)]
    struct ReorgBatchLog(Mutex<Vec<ReorgBatch>>);

    impl crate::MempoolObserver for ReorgBatchLog {
        fn on_mutation(&self, envelope: &crate::MutationEnvelope) {
            let mut seen = self.0.lock();
            seen.push((
                envelope.origin,
                envelope
                    .result
                    .changes
                    .iter()
                    .map(|change| (Txid::from(change.txid), change.outcome))
                    .collect(),
            ));
        }
    }

    fn observed_gateway(observer: &Arc<ReorgRecording>) -> Arc<MempoolGateway> {
        let leg: Arc<dyn crate::MempoolObserver> = observer.clone();
        Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(crate::MempoolLimits::default()))),
            Some((leg, crate::BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ))
    }

    fn funded_chain(outpoint: OutPoint, value: u64) -> Coins {
        Coins(vec![(
            outpoint,
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )])
    }

    fn seed_rolling_floor_via_capacity_eviction(gateway: &Arc<MempoolGateway>, now: u64) {
        let markers = [100u8, 101, 102, 103, 104];
        let funded = Coins(
            markers
                .iter()
                .map(|&marker| {
                    (
                        OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
                        TxOut {
                            value: Amount::from_sat(50_000),
                            script_pubkey: Script::from_bytes(vec![0x51]),
                        },
                    )
                })
                .collect(),
        );
        for &marker in &markers {
            let tx = Arc::new(standard_spend(
                OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
                marker,
            ));
            let _ = gateway.submit_transaction(tx, AdmissionOrigin::Rpc, None, now, &funded);
        }
        let floor = gateway.read().min_fee_sat_per_kvb(now);
        let min_relay = gateway.read().min_relay_fee_sat_per_kvb();
        assert!(
            floor > min_relay,
            "a capacity eviction must raise the rolling floor above min relay, got floor {floor} min_relay {min_relay}"
        );
        let residents: Vec<Arc<Tx>> = gateway
            .read()
            .iter_entries()
            .map(|entry| Arc::clone(&entry.tx))
            .collect();
        if !residents.is_empty() {
            let refs: Vec<&Tx> = residents.iter().map(AsRef::as_ref).collect();
            let ids: Vec<Txid> = residents.iter().map(|tx| tx.txid()).collect();
            gateway.remove_for_block(AdmissionOrigin::Rpc, &refs, &ids, 2, now);
        }
        assert!(
            gateway.read().is_empty(),
            "block settlement must leave an empty pool for the floor probe"
        );
        let floor_after = gateway.read().min_fee_sat_per_kvb(now);
        assert!(
            floor_after > min_relay,
            "the rolling floor must survive block settlement within the decay grace, got {floor_after}"
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reconsider_disconnected_admits_parent_then_child_under_the_guard() {
        let observer = Arc::new(ReorgRecording::default());
        let gateway = observed_gateway(&observer);
        let (parent, child) = witness_parent_and_child();
        let parent_txid = parent.txid();
        let child_txid = child.txid();
        let chain = funded_chain(parent.inputs[0].previous_output, 20_000);
        let change = gateway.begin_chain_change().expect("fence");
        assert!(gateway.stable_generation().is_none());

        let committed = gateway.reconsider_disconnected(
            &change,
            &chain,
            1,
            [Arc::new(parent), Arc::clone(&child)],
        );
        change.finish().expect("finish");

        assert_eq!(committed.len(), 2, "one committed result per candidate");
        for result in &committed {
            assert_eq!(result.changes.len(), 1);
        }
        assert_eq!(gateway.read().sequence_number(), 2);
        assert_eq!(
            *observer.0.lock(),
            vec![
                (parent_txid, AdmissionOrigin::Reorg),
                (child_txid, AdmissionOrigin::Reorg)
            ],
            "commits publish Reorg in dependency order"
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reconsider_disconnected_withholds_descendants_of_a_refused_parent() {
        let observer = Arc::new(ReorgRecording::default());
        let gateway = observed_gateway(&observer);
        let (mut parent, child) = witness_parent_and_child();
        parent.lock_time = LockTime::from_consensus(5);
        parent.inputs[0].sequence = Sequence::from_consensus(0);
        let child_txid = child.txid();
        let chain = funded_chain(parent.inputs[0].previous_output, 20_000);
        let change = gateway.begin_chain_change().expect("fence");

        let committed =
            gateway.reconsider_disconnected(&change, &chain, 1, [Arc::new(parent), child]);
        change.finish().expect("finish");

        assert!(
            committed.is_empty(),
            "a refused parent must keep its descendant out"
        );
        assert!(!gateway.read().contains_txid(&child_txid));
        assert!(observer.0.lock().is_empty());
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reconsider_disconnected_refuses_a_script_failure() {
        let gateway = gateway();
        let (parent, valid) = witness_parent_and_child();
        let mut bad = (*valid).clone();
        bad.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        let chain = Coins(vec![(
            bad.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        let change = gateway.begin_chain_change().expect("fence");

        let committed = gateway.reconsider_disconnected(&change, &chain, 1, [Arc::new(bad)]);
        change.finish().expect("finish");

        assert!(committed.is_empty(), "script failure must refuse");
        assert!(gateway.read().is_empty());
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reconsider_disconnected_does_not_register_with_the_estimator() {
        let gateway = gateway();
        let (parent, child) = witness_parent_and_child();
        let chain = funded_chain(parent.inputs[0].previous_output, 20_000);
        let before = gateway.read().estimator_history();
        let now = unix_time_secs();
        let change = gateway.begin_chain_change().expect("fence");

        let committed = gateway.reconsider_disconnected(
            &change,
            &chain,
            now,
            [Arc::new(parent), Arc::clone(&child)],
        );
        change.finish().expect("finish");

        assert_eq!(committed.len(), 2);
        assert_eq!(
            gateway.read().estimator_history(),
            before,
            "reorg re-admission must not touch estimator state"
        );

        let control = standard_spend(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[60; 32])), 0),
            12,
        );
        let control_chain = funded_chain(control.inputs[0].previous_output, 20_000);
        assert!(matches!(
            gateway.submit_transaction(
                Arc::new(control),
                AdmissionOrigin::Rpc,
                None,
                now,
                &control_chain
            ),
            Ok(SubmitOutcome::Committed(_))
        ));
        assert_ne!(gateway.read().estimator_history(), before);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reconsider_disconnected_admits_below_floor_then_trims_once() {
        const CEILING: u64 = 150;
        let limits = crate::MempoolLimits {
            max_total_bytes: CEILING,
            ..crate::MempoolLimits::default()
        };
        let log = Arc::new(ReorgBatchLog::default());
        let leg: Arc<dyn crate::MempoolObserver> = log.clone();
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(limits))),
            Some((leg, crate::BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        let now = unix_time_secs();
        seed_rolling_floor_via_capacity_eviction(&gateway, now);
        log.0.lock().clear();
        let (parent, child) = witness_parent_and_child();
        let parent_txid = parent.txid();
        let child_txid = child.txid();
        let chain = funded_chain(parent.inputs[0].previous_output, 20_000);
        let floor_before = gateway.read().min_fee_sat_per_kvb(now);
        assert!(
            floor_before > gateway.read().min_relay_fee_sat_per_kvb(),
            "the walk must start above a live rolling floor, got {floor_before}"
        );
        let parent_arc = Arc::new(parent);
        let probe = gateway.submit_transaction(
            Arc::clone(&parent_arc),
            AdmissionOrigin::Rpc,
            None,
            now,
            &chain,
        );
        assert_eq!(
            probe,
            Err(SubmitError::Policy(
                AcceptanceRejectReason::MinRelayFeeNotMet
            )),
            "fresh relay below the rolling floor must be refused"
        );
        assert!(
            !gateway.read().contains_txid(&parent_txid),
            "a floor refusal must not admit"
        );

        let change = gateway.begin_chain_change().expect("fence");
        let committed = gateway.reconsider_disconnected(
            &change,
            &chain,
            now,
            [Arc::clone(&parent_arc), Arc::clone(&child)],
        );
        assert_eq!(committed.len(), 2, "the whole family must re-enter");
        assert!(gateway.read().contains_txid(&parent_txid));
        assert!(
            gateway.read().contains_txid(&child_txid),
            "a below-floor re-admission must not be refused"
        );
        assert!(
            gateway.read().total_vsize() > CEILING,
            "no size trim may run during the walk"
        );

        let swept = gateway.remove_for_reorg(&change, &chain).expect("sweep");
        assert!(swept.is_empty(), "the funded family stays supported");

        let trimmed = gateway
            .enforce_size_limit(AdmissionOrigin::Reorg, CEILING)
            .expect("settlement trim");
        change.finish().expect("finish");

        assert!(!trimmed.changes.is_empty(), "the trim must act");
        assert!(
            gateway.read().total_vsize() <= CEILING,
            "one trim over the settled pool must reach the ceiling"
        );

        assert_reorg_publication_order(&log.0.lock(), &[parent_txid, child_txid], child_txid);
    }

    #[expect(clippy::expect_used)]
    fn assert_reorg_publication_order(
        batches: &[ReorgBatch],
        admissions: &[Txid],
        trimmed_txid: Txid,
    ) {
        let is_eviction = |(_, changes): &ReorgBatch| {
            changes.iter().any(|(_, outcome)| {
                matches!(
                    outcome,
                    crate::MutationOutcome::Removed(crate::RemovalReason::PolicyEviction)
                )
            })
        };
        let trim_index = batches
            .iter()
            .position(is_eviction)
            .expect("the settlement trim publishes one policy-eviction batch");
        assert_eq!(
            batches.iter().filter(|batch| is_eviction(batch)).count(),
            1,
            "exactly one policy-eviction batch in all"
        );
        assert_eq!(
            batches[trim_index].0,
            AdmissionOrigin::Reorg,
            "the trim publishes as Reorg"
        );
        assert_eq!(
            batches[trim_index].1,
            vec![(
                trimmed_txid,
                crate::MutationOutcome::Removed(crate::RemovalReason::PolicyEviction)
            )],
            "the trim sheds the lowest fee-rate member"
        );
        assert_eq!(
            batches.len(),
            trim_index + 1,
            "nothing commits after the trim"
        );
        assert!(
            batches[..trim_index].iter().all(|(origin, changes)| {
                origin == &AdmissionOrigin::Reorg
                    && changes
                        .iter()
                        .all(|(_, outcome)| matches!(outcome, crate::MutationOutcome::Accepted))
            }),
            "only reorg admissions may precede the one trim"
        );
        assert_eq!(
            batches[..trim_index]
                .iter()
                .flat_map(|(_, changes)| changes.iter().map(|(txid, _)| *txid))
                .collect::<Vec<_>>(),
            admissions,
            "admissions publish parent before child"
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reconsider_control_refuses_fresh_relay_below_floor() {
        const CEILING: u64 = 150;
        let limits = crate::MempoolLimits {
            max_total_bytes: CEILING,
            ..crate::MempoolLimits::default()
        };
        let control = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(limits))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let now = unix_time_secs();
        seed_rolling_floor_via_capacity_eviction(&control, now);
        let floor = control.read().min_fee_sat_per_kvb(now);
        assert!(
            floor > control.read().min_relay_fee_sat_per_kvb(),
            "fresh relay must face a live rolling floor, got {floor}"
        );
        let (control_parent, control_child) = witness_parent_and_child();
        let control_parent_txid = control_parent.txid();
        let control_chain = funded_chain(control_parent.inputs[0].previous_output, 20_000);
        let change = control.begin_chain_change().expect("control fence");
        let admitted = control.reconsider_disconnected(
            &change,
            &control_chain,
            now,
            [Arc::new(control_parent)],
        );
        assert_eq!(
            admitted.len(),
            1,
            "the fenced parent must bypass the rolling floor"
        );
        assert!(
            control.read().contains_txid(&control_parent_txid),
            "bypassed parent must be resident"
        );
        change.finish().expect("control finish");
        let relay = control.submit_transaction(
            control_child,
            AdmissionOrigin::Rpc,
            None,
            now,
            &Coins(vec![]),
        );
        assert_eq!(
            relay,
            Err(SubmitError::Policy(
                AcceptanceRejectReason::MinRelayFeeNotMet
            )),
            "fresh relay must meet the rolling floor"
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn remove_for_reorg_sweeps_only_unsupported_residents() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let parent_txid = parent.txid();
        let child_txid = child.txid();
        let locktime_out = OutPoint::new(Txid(Hash256::from_le_bytes(&[41; 32])), 0);
        let mut locked = standard_spend(locktime_out, 9);
        locked.lock_time = LockTime::from_consensus(5);
        locked.inputs[0].sequence = Sequence::from_consensus(0);
        let locked_txid = locked.txid();
        let valid_out = OutPoint::new(Txid(Hash256::from_le_bytes(&[42; 32])), 0);
        let valid = standard_spend(valid_out, 10);
        let valid_txid = valid.txid();
        for tx in [parent, (*child).clone(), locked, valid] {
            gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 1, 0),
                )
                .expect("fixture entry");
        }
        let chain = Coins(vec![
            (
                valid_out,
                TxOut {
                    value: Amount::from_sat(20_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                },
            ),
            (
                locktime_out,
                TxOut {
                    value: Amount::from_sat(20_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                },
            ),
        ]);
        let change = gateway.begin_chain_change().expect("fence");

        let result = gateway
            .remove_for_reorg(&change, &chain)
            .expect("generation held");
        change.finish().expect("finish");

        let removed: HashSet<Txid> = result.removed_txids().into_iter().collect();
        assert!(removed.contains(&parent_txid), "missing-input parent");
        assert!(removed.contains(&child_txid), "its descendant");
        assert!(removed.contains(&locked_txid), "no-longer-final entry");
        assert!(!removed.contains(&valid_txid));
        assert!(
            result.changes.iter().all(|c| matches!(
                c.outcome,
                crate::MutationOutcome::Removed(crate::RemovalReason::Reorg)
            )),
            "every swept entry carries the Reorg reason"
        );
        assert!(gateway.read().contains_txid(&valid_txid));
        assert_eq!(gateway.read().len(), 1);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn remove_for_reorg_refuses_a_moved_generation() {
        let gateway = gateway();
        let (parent, _child) = parent_and_child();
        let parent_txid = parent.txid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1, 0),
            )
            .expect("fixture entry");
        let change = gateway.begin_chain_change().expect("fence");
        gateway.force_chain_generation(2);

        assert_eq!(
            gateway.remove_for_reorg(&change, &Coins(vec![])),
            Err(crate::ChainChangeError::GenerationMoved)
        );
        assert!(gateway.read().contains_txid(&parent_txid));
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn admission_state_accepts_only_the_current_generation() {
        let gateway = gateway();
        let change = gateway.begin_chain_change().expect("fence");
        let request = AdmissionRequest {
            tx: Arc::new(standard_spend(
                OutPoint::new(Txid(Hash256::from_le_bytes(&[50; 32])), 0),
                11,
            )),
            context: crate::standardness::PackageTxContext {
                fee: 1_000,
                vsize: 100,
                sigop_cost: 0,
                missing_inputs: false,
            },
            prevouts: vec![],
            prevout_meta: HashMap::new(),
            csv_active: false,
            next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
            locktime_cutoff: 0,
            max_feerate_sat_per_kvb: None,
            time: 1,
            height: 1,
            origin: AdmissionOrigin::Rpc,
            expected_generation: 0,
            expected_sequence: gateway.read().sequence_number(),
        };
        let pool = gateway.read();
        assert_eq!(
            gateway.check_admission_state(
                &pool,
                request.expected_generation,
                request.expected_sequence,
                AdmissionFence::Stable,
                None,
            ),
            Err(AdmitError::GenerationChanged),
            "an even token cannot admit while the change fence is held"
        );
        let mut odd_request = request;
        odd_request.expected_generation = change.odd_generation();
        assert_eq!(
            gateway.check_admission_state(
                &pool,
                odd_request.expected_generation,
                odd_request.expected_sequence,
                AdmissionFence::Stable,
                None,
            ),
            Err(AdmitError::GenerationChanged),
            "the odd integer without the guard's fence is refused"
        );
        assert_eq!(
            gateway.check_admission_state(
                &pool,
                odd_request.expected_generation,
                odd_request.expected_sequence,
                AdmissionFence::ChainChange(change.odd_generation()),
                None,
            ),
            Ok(()),
            "the guard's exact odd value admits under its own fence"
        );
        drop(pool);
        change.finish().expect("finish");
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reorg_methods_refuse_a_guard_from_another_gateway() {
        let gateway_a = gateway();
        let gateway_b = gateway();
        let (parent, _child) = parent_and_child();
        insert_parent(&gateway_b, parent.clone(), AdmissionOrigin::Rpc);
        let guard_b = gateway_b.begin_chain_change().expect("fence on b");

        assert_eq!(
            gateway_a.remove_for_reorg(&guard_b, &Coins(vec![])),
            Err(crate::ChainChangeError::ForeignGuard),
            "a foreign guard cannot sweep this gateway's pool"
        );
        assert!(
            gateway_a
                .reconsider_disconnected(&guard_b, &Coins(vec![]), 1, [Arc::new(parent)])
                .is_empty(),
            "a foreign guard admits nothing"
        );
        assert!(gateway_a.read().iter_entries().next().is_none());
        guard_b.finish().expect("finish b");
    }

    fn batch_logged_gateway() -> (Arc<ReorgBatchLog>, Arc<MempoolGateway>) {
        let log = Arc::new(ReorgBatchLog::default());
        let leg: Arc<dyn crate::MempoolObserver> = log.clone();
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(crate::MempoolLimits::default()))),
            Some((leg, crate::BodyInterest::Metadata)),
            ValidationEngine::Native,
            None,
        ));
        (log, gateway)
    }

    fn independent_spend(marker: u8) -> (Arc<Tx>, Coins) {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0);
        let tx = standard_spend(outpoint, marker);
        (Arc::new(tx), funded_chain(outpoint, 20_000))
    }

    #[test]
    fn expiry_capacity_ordering_under_pressure() {
        for package in [false, true] {
            for fee in [100, 11_000] {
                for expire_first in [false, true] {
                    let log = Arc::new(ReorgBatchLog::default());
                    let observer: Arc<dyn crate::MempoolObserver> = log.clone();
                    let gateway = MempoolGateway::new(
                        Arc::new(RwLock::new(Mempool::new(crate::MempoolLimits {
                            max_total_bytes: 100,
                            ..crate::MempoolLimits::default()
                        }))),
                        Some((observer, crate::BodyInterest::Metadata)),
                        ValidationEngine::Native,
                        None,
                    );
                    let (stale, _) = independent_spend(70);
                    let stale_id = stale.txid();
                    insert_stale(&gateway, stale);
                    let (fresh, _) = independent_spend(71);
                    let chain = funded_chain(fresh.inputs[0].previous_output, 9_000 + fee);
                    let fresh_id = fresh.txid();
                    let now = unix_time_secs();
                    if expire_first {
                        gateway.expire(AdmissionOrigin::Rpc, now);
                    }
                    let result = if package {
                        gateway
                            .submit_local_package(
                                vec![(*fresh).clone()],
                                LocalOrigin::Rpc,
                                None,
                                now,
                                &chain,
                            )
                            .map(|_| ())
                    } else {
                        gateway
                            .submit_transaction(fresh, AdmissionOrigin::Rpc, None, now, &chain)
                            .map(|_| ())
                    };
                    let pool = gateway.read();
                    let events = log
                        .0
                        .lock()
                        .iter()
                        .map(|(_, changes)| {
                            changes
                                .iter()
                                .map(|(_, outcome)| *outcome)
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    println!(
                        "B package={package} fee={fee} expire_first={expire_first} now={now} stale_time=0 limit=100 result={result:?} stale={} fresh={} count={} vbytes={} floor={} events={events:?}",
                        pool.contains_txid(&stale_id),
                        pool.contains_txid(&fresh_id),
                        pool.len(),
                        pool.total_vsize(),
                        pool.min_fee_sat_per_kvb(now)
                    );
                    assert!(result.is_ok());
                    assert_eq!(pool.total_vsize(), 85);
                    assert_eq!(pool.min_fee_sat_per_kvb(now), 1_000);
                }
            }
        }
    }

    fn insert_stale(gateway: &MempoolGateway, tx: Arc<Tx>) {
        let vsize = u32::try_from(tx.vsize()).unwrap_or(80);
        let inserted = gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(tx, vsize, 1_000, 0, 1, 0),
        );
        assert!(inserted.is_ok());
    }

    fn expired(txid: Txid) -> (Txid, crate::MutationOutcome) {
        (
            txid,
            crate::MutationOutcome::Removed(crate::RemovalReason::Expiry),
        )
    }

    #[test]
    fn committed_admission_publishes_acceptance_before_expiry_atomically() {
        let (log, gateway) = batch_logged_gateway();
        let (stale, _) = independent_spend(70);
        let stale_txid = stale.txid();
        insert_stale(&gateway, stale);
        let (fresh, chain) = independent_spend(71);
        let fresh_txid = fresh.txid();

        let now = unix_time_secs();

        let outcome = gateway.submit_transaction(fresh, AdmissionOrigin::Rpc, None, now, &chain);

        assert!(matches!(outcome, Ok(SubmitOutcome::Committed(_))));
        assert!(!gateway.read().contains_txid(&stale_txid));
        assert!(gateway.read().contains_txid(&fresh_txid));
        assert_eq!(
            *log.0.lock(),
            vec![
                (
                    AdmissionOrigin::Rpc,
                    vec![(stale_txid, crate::MutationOutcome::Accepted)]
                ),
                (
                    AdmissionOrigin::Rpc,
                    vec![
                        (fresh_txid, crate::MutationOutcome::Accepted),
                        expired(stale_txid)
                    ]
                ),
            ],
            "acceptance precedes expiry in the same atomic publication"
        );
    }

    #[test]
    fn child_of_a_stale_parent_expires_with_it_and_is_refused_as_full() {
        for package in [false, true] {
            let log = Arc::new(ReorgBatchLog::default());
            let observer: Arc<dyn crate::MempoolObserver> = log.clone();
            let gateway = Arc::new(MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(crate::MempoolLimits {
                    max_total_bytes: 100,
                    ..crate::MempoolLimits::default()
                }))),
                Some((observer, crate::BodyInterest::Metadata)),
                ValidationEngine::Native,
                None,
            ));
            let (parent, child) = {
                let (parent, child) = parent_and_child();
                let mut child_tx = (*child).clone();
                child_tx.outputs[0].value = Amount::from_sat(4_000);
                child_tx.outputs.push(child_tx.outputs[0].clone());
                (parent, Arc::new(child_tx))
            };
            let (parent_txid, child_txid) = (parent.txid(), child.txid());
            insert_stale(&gateway, Arc::new(parent));
            let peer = AdmissionOrigin::Peer(source());

            let now = unix_time_secs();

            let err = if package {
                gateway
                    .submit_local_package(
                        vec![(*child).clone()],
                        LocalOrigin::Rpc,
                        None,
                        now,
                        &Coins(vec![]),
                    )
                    .err()
            } else {
                gateway
                    .submit_transaction(child, peer, None, now, &Coins(vec![]))
                    .err()
            };

            assert_eq!(
                err,
                Some(SubmitError::Policy(AcceptanceRejectReason::Mempool(
                    crate::MempoolError::Full
                )))
            );
            assert!(
                gateway.read().is_empty(),
                "pool must be empty for package={package}"
            );
            assert_eq!(gateway.recent_rejects_count(), 0);
            assert_eq!(gateway.orphan_count(), 0);
            assert!(!gateway.is_rejected(Hash256::from(child_txid)));
            let batches = log.0.lock();
            assert_eq!(
                batches.len(),
                2,
                "stale insert, atomic child and expiry commit"
            );
            assert_eq!(
                batches[1].1.first(),
                Some(&(child_txid, crate::MutationOutcome::Accepted)),
                "the refused child's commit stays published"
            );
            let (origin, changes) = &batches[1];
            assert_eq!(
                *origin,
                if package { AdmissionOrigin::Rpc } else { peer },
                "the atomic commit publishes the submission's own origin"
            );
            let removed = &changes[1..];
            assert_eq!(removed.len(), 2);
            assert!(removed.contains(&expired(parent_txid)));
            assert!(removed.contains(&expired(child_txid)));
        }
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn reorg_origin_and_chain_change_fence_never_expire() {
        let (log, gateway) = batch_logged_gateway();
        let (stale, _) = independent_spend(72);
        let stale_txid = stale.txid();
        insert_stale(&gateway, stale);

        let now = unix_time_secs();
        let (origin_tx, origin_chain) = independent_spend(73);
        let outcome =
            gateway.submit_transaction(origin_tx, AdmissionOrigin::Reorg, None, now, &origin_chain);
        assert!(matches!(outcome, Ok(SubmitOutcome::Committed(_))));

        let (fenced_tx, fenced_chain) = independent_spend(74);
        let change = gateway.begin_chain_change().expect("fence");
        let committed = gateway.reconsider_disconnected(&change, &fenced_chain, now, [fenced_tx]);
        change.finish().expect("finish");

        assert_eq!(committed.len(), 1);
        assert!(gateway.read().contains_txid(&stale_txid));
        assert!(
            log.0
                .lock()
                .iter()
                .all(|(_, changes)| !changes.contains(&expired(stale_txid))),
            "no re-admission publishes an expiry"
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn chain_change_fence_skips_expiry_for_a_non_reorg_origin() {
        let gateway = gateway();
        let (stale, _) = independent_spend(75);
        let stale_txid = stale.txid();
        insert_stale(&gateway, stale);
        let (fresh, chain) = independent_spend(76);
        let fresh_txid = fresh.txid();
        let now = unix_time_secs();

        let change = gateway.begin_chain_change().expect("fence");
        let outcome = gateway.submit_transaction_claimed(
            fresh,
            AdmissionOrigin::Rpc,
            None,
            now,
            &chain,
            None,
            AdmissionFence::ChainChange(change.odd_generation()),
        );
        change.finish().expect("finish");

        assert!(matches!(outcome, Ok(SubmitOutcome::Committed(_))));
        assert!(gateway.read().contains_txid(&stale_txid));
        assert!(gateway.read().contains_txid(&fresh_txid));
    }
}
