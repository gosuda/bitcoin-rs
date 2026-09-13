//! Shared preparation and bounded admission retry for RPC and peer producers.
//!
//! Chain facts are collected without gateway locks. The existing atomic gateway
//! operation validates exact generation/sequence tokens before either a pool
//! commit or a peer orphan/reject transition.

use alloc::{sync::Arc, vec::Vec};
use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxOut, Txid, Wtxid};
use hashbrown::{HashMap, HashSet};

use crate::standardness::{AcceptanceRejectReason, StandardnessPolicy, is_standard_tx};
use crate::{
    AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, MempoolGateway, MutationResult,
    PeerToken,
};

const MAX_ADMISSION_RETRIES: usize = 4;

/// Provisional applied-chain facts collected during one submission attempt.
///
/// Height and median time past refer to one sampled applied tip. Coin reads
/// may overlap a chain transition; the gateway must validate the generation
/// captured before these reads before using any fact for admission or holding.
#[derive(Clone, Debug, Default)]
pub struct ChainAdmissionSnapshot {
    /// Confirmed input outputs; unavailable inputs are absent.
    pub prevouts: Vec<(OutPoint, TxOut)>,
    /// Per-confirmed-output chain metadata needed for BIP68 and coinbase
    /// maturity checks. Pool parents are not included here.
    pub prevout_meta: HashMap<OutPoint, PrevoutMeta>,
    /// Applied tip height; finality is checked at the next height.
    pub height: u32,
    /// Applied tip's median time past (zero before genesis).
    pub locktime_cutoff: u32,
    /// Whether CSV (BIP68/112/113) is active for the next block.
    pub csv_active: bool,
    /// Peer duplicate suppression only. RPC cache membership is not admission.
    pub confirmed: bool,
}

/// Chain-origin metadata for one confirmed input.
///
/// Used to evaluate BIP68 relative locks and coinbase maturity at admission.
/// The `MTP` value is the median-time-past of the block *before* the one that
/// created the output, matching `bip68_prevout_mtp` in the block-connect path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrevoutMeta {
    /// Height the spent output was created at.
    pub height: u32,
    /// Median-time-past of the block before the one at `height`.
    pub mtp: u32,
    /// Whether the spent output came from a coinbase transaction.
    pub coinbase: bool,
}

/// Narrow chain read capability.
///
/// Each call reads the current backing state without pool/lifecycle locks.
/// Height and median time past use one applied-tip identity; coin and confirmed
/// reads are provisional until the gateway revalidates the exact generation
/// and mempool sequence captured before the call. Implementations must not
/// reuse facts retained from an earlier attempt.
///
/// The authoritative chain owner must bracket every mutation affecting these
/// facts with this gateway's chain-change reservation and finish. The same
/// generation fence rejects mixed reads, so a snapshot need not take an
/// exclusive transition lock or maintain a second version counter. `None`
/// indicates that the capability could not provide facts for this attempt.
pub trait AdmissionChain: Send + Sync {
    /// Reads the chain inputs and applied-tip context needed by `tx`.
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot>;
}

/// Surface-independent outcome. Peer-only holding is not a mempool mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmitOutcome {
    /// Atomic admission committed these ordered changes.
    Committed(MutationResult),
    /// Current mempool membership, or a suppressed recent peer rejection.
    AlreadyKnown,
    /// A peer transaction was already confirmed.
    AlreadyConfirmed,
    /// A standard peer transaction is missing inputs. Its body is retained
    /// subject to the orphan quota; P2P owns requesting these parent txids.
    Held {
        /// Missing parent transaction identifiers, without duplicates.
        missing_parents: Vec<Txid>,
    },
}

/// Failure after the common preparation/retry operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubmitError {
    /// Policy refused the transaction.
    #[error(transparent)]
    Policy(#[from] AcceptanceRejectReason),
    /// Consensus or policy script verification refused the transaction.
    #[error("consensus-verification-failed")]
    Consensus,
    /// Every attempt observed changing or unavailable state.
    #[error("admission retry exhausted: chain or mempool changed during submission")]
    RetryExhausted,
}

/// One resident orphan's bounded retry result and its original source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanRetry {
    /// Transaction identifier for relay.
    pub txid: Txid,
    /// Witness identifier of the exact body offered for re-admission.
    pub wtxid: Wtxid,
    /// Delivering connection metadata; never a socket/connection handle.
    pub source: PeerToken,
    /// The same result a fresh submission receives.
    pub result: Result<SubmitOutcome, SubmitError>,
}

pub(crate) fn can_hold_orphan(pool: &crate::Mempool, tx: &Tx, policy: &StandardnessPolicy) -> bool {
    let null_input = tx
        .inputs
        .iter()
        .any(|input| input.previous_output.is_null());
    !(null_input || has_invalid_mempool_outpoint(pool, tx)) && is_standard_tx(tx, policy).is_ok()
}

/// A known parent cannot later acquire an output without changing its txid.
///
/// The atomic gateway rechecks this against the live pool before classifying
/// the failure; preparation uses the same rule to distinguish Held outcomes.
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

// An absent parent can arrive later; a resident parent's nonexistent output
// cannot. Keep that distinction in the resolved outpoints rather than a second
// parent-membership index.
fn resolve_mempool_inputs(pool: &crate::Mempool, tx: &Tx) -> Option<HashMap<OutPoint, TxOut>> {
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

impl MempoolGateway {
    /// Evaluates a bounded batch through the submission evaluator without
    /// changing membership, sequence, fee history, orphan state or observers.
    /// Earlier offered outputs satisfy later rows, preserving the supported
    /// independent-row preview contract. This is not atomic package admission.
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
        use crate::standardness::{MAX_PACKAGE_COUNT, PackageAcceptanceFacts};
        if txs.is_empty() || txs.len() > MAX_PACKAGE_COUNT {
            return Ok(PackageAcceptanceFacts {
                package_error: Some(AcceptanceRejectReason::PackageTooLarge),
                results: Vec::new(),
            });
        }
        'attempt: for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.stable_generation() else {
                continue;
            };
            let (sequence, limits, policy, mempool_inputs) = {
                let pool = self.pool.read();
                if self.stable_generation() != Some(generation) {
                    continue;
                }
                (
                    pool.sequence_number(),
                    pool.limits,
                    pool.policy_snapshot(),
                    txs.iter()
                        .map(|tx| resolve_mempool_inputs(&pool, tx))
                        .collect::<Vec<_>>(),
                )
            };
            let mut package_outputs = HashMap::new();
            let mut requests = Vec::with_capacity(txs.len());
            for (tx, mempool_inputs) in txs.iter().zip(mempool_inputs) {
                // Chain I/O never holds the pool read or lifecycle lock.
                let snapshot = if mempool_inputs.is_some() {
                    let Some(snapshot) = chain.snapshot(tx) else {
                        continue 'attempt;
                    };
                    snapshot
                } else {
                    ChainAdmissionSnapshot::default()
                };
                let mut available = snapshot.prevouts.into_iter().collect::<HashMap<_, _>>();
                available.extend(mempool_inputs.unwrap_or_default());
                available.extend(
                    package_outputs
                        .iter()
                        .map(|(outpoint, output): (&OutPoint, &TxOut)| (*outpoint, output.clone())),
                );
                let (prevouts, _) = combine_input_facts(tx, &available, &HashMap::new());
                let context = crate::accounting::prepared_context(
                    tx,
                    &prevouts,
                    prevouts.len() != tx.inputs.len(),
                );
                requests.push(AdmissionRequest {
                    tx: Arc::new(tx.clone()),
                    context,
                    prevouts,
                    prevout_meta: snapshot.prevout_meta,
                    csv_active: snapshot.csv_active,
                    locktime_cutoff: snapshot.locktime_cutoff,
                    max_feerate_sat_per_kvb,
                    time: 0,
                    height: snapshot.height,
                    origin: AdmissionOrigin::Rpc,
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
            let mut prepared = {
                let pool = self.pool.read();
                if self.stable_generation() != Some(generation)
                    || pool.sequence_number() != sequence
                    || pool.limits != limits
                    || pool.policy_snapshot() != policy
                {
                    continue;
                }
                requests
                    .iter()
                    .map(|request| Self::prepare_admission(&pool, request))
                    .collect::<Vec<_>>()
            };
            for (prepared, request) in prepared.iter_mut().zip(&requests) {
                prepared.verify(request);
            }
            let pool = self.pool.read();
            if self.stable_generation() != Some(generation)
                || pool.sequence_number() != sequence
                || pool.limits != limits
                || pool.policy_snapshot() != policy
            {
                continue;
            }
            return Ok(PackageAcceptanceFacts {
                package_error: None,
                results: prepared.into_iter().map(|prepared| prepared.fact).collect(),
            });
        }
        Err(SubmitError::RetryExhausted)
    }

    /// Prepares and submits one transaction, rebuilding all facts after a
    /// transient token mismatch. Only peer-origin failures affect relay caches.
    pub fn submit_transaction(
        &self,
        tx: Arc<Tx>,
        origin: AdmissionOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
    ) -> Result<SubmitOutcome, SubmitError> {
        self.submit_transaction_claimed(tx, origin, max_feerate_sat_per_kvb, time, chain, None)
    }

    fn submit_transaction_claimed(
        &self,
        mut tx: Arc<Tx>,
        origin: AdmissionOrigin,
        max_feerate_sat_per_kvb: Option<u64>,
        time: u64,
        chain: &dyn AdmissionChain,
        claim: Option<&crate::orphan::HeldOrphan>,
    ) -> Result<SubmitOutcome, SubmitError> {
        let txid = tx.txid();
        let peer = matches!(origin, AdmissionOrigin::Peer(_));
        for _ in 0..MAX_ADMISSION_RETRIES {
            let Some(generation) = self.stable_generation() else {
                continue;
            };
            let (sequence, mempool_prevouts, holdable) = {
                let pool = self.pool.read();
                if self.stable_generation() != Some(generation) {
                    continue;
                }
                if pool.contains_txid(&txid) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                if peer && self.lifecycle.lock().rejects_transaction(txid, tx.wtxid()) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                let prevouts = resolve_mempool_inputs(&pool, &tx);
                (
                    pool.sequence_number(),
                    prevouts,
                    peer && can_hold_orphan(&pool, &tx, &pool.policy_snapshot().standardness),
                )
            };
            // A nonexistent output of a known parent needs no chain data. It
            // still goes through the one atomic gate, including private-claim
            // validation; no separate lifecycle writer is introduced here.
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
                if self.stable_generation() != Some(generation)
                    || pool.sequence_number() != sequence
                {
                    continue;
                }
                let mut lifecycle = self.lifecycle.lock();
                if claim.is_some_and(|claim| !lifecycle.orphans.is_current(claim)) {
                    return Ok(SubmitOutcome::AlreadyKnown);
                }
                lifecycle.orphans.remove(txid);
                return Ok(SubmitOutcome::AlreadyConfirmed);
            }
            // Without chain facts, the empty/missing context and zero tip
            // fields cannot authorize a commit: the gate checks the same
            // generation/sequence first, then rejects the still-known invalid
            // outpoint before policy or finality. Changed tokens rebuild a
            // normal attempt, including chain lookup if the parent disappeared.
            let (confirmed, height, locktime_cutoff, prevout_meta, csv_active) = snapshot
                .map_or_else(
                    || (HashMap::new(), 0, 0, HashMap::new(), false),
                    |snapshot| {
                        (
                            snapshot.prevouts.into_iter().collect::<HashMap<_, _>>(),
                            snapshot.height,
                            snapshot.locktime_cutoff,
                            snapshot.prevout_meta,
                            snapshot.csv_active,
                        )
                    },
                );
            let mempool_prevouts = mempool_prevouts.unwrap_or_default();
            let (prevouts, missing_parents) =
                combine_input_facts(&tx, &mempool_prevouts, &confirmed);
            let missing_inputs = prevouts.len() != tx.inputs.len();
            let context = crate::accounting::prepared_context(&tx, &prevouts, missing_inputs);
            let request = AdmissionRequest {
                tx,
                context,
                prevouts,
                prevout_meta,
                csv_active,
                locktime_cutoff,
                max_feerate_sat_per_kvb,
                time,
                height,
                origin,
                expected_generation: generation,
                expected_sequence: sequence,
            };
            match self.admit_transaction_claimed(&request, claim) {
                Ok(AdmitOutcome::Committed(result)) => return Ok(SubmitOutcome::Committed(result)),
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

    /// Processes the current bounded ready set once. Work remains resident when
    /// generation changes, and no call immediately consumes its own retry again.
    pub fn retry_orphans(&self, chain: &dyn AdmissionChain, time: u64) -> Vec<OrphanRetry> {
        let ready = {
            let _pool = self.pool.read();
            if self.stable_generation().is_none() {
                return Vec::new();
            }
            self.lifecycle.lock().orphans.take_ready()
        };
        let mut results = Vec::with_capacity(ready.len());
        for held in ready {
            let txid = held.tx.txid();
            let wtxid = held.tx.wtxid();
            // An intervening eviction or witness refresh retires this claim.
            if !self.lifecycle.lock().orphans.is_current(&held) {
                continue;
            }
            let result = self.submit_transaction_claimed(
                Arc::clone(&held.tx),
                AdmissionOrigin::Peer(held.source),
                None,
                time,
                chain,
                Some(&held),
            );
            if matches!(result, Err(SubmitError::RetryExhausted)) {
                let mut lifecycle = self.lifecycle.lock();
                if lifecycle.orphans.is_current(&held) {
                    lifecycle.orphans.mark_ready(txid);
                }
            }
            results.push(OrphanRetry {
                txid,
                wtxid,
                source: held.source,
                result,
            });
        }
        results
    }

    /// Applies the orphan retention policy to one snapshot of live connections.
    ///
    /// Expiry and peer-disconnect cleanup are mempool-owned transitions. The node
    /// supplies only the current P2P connection tokens; a same-address replacement
    /// has a different token and cannot retain its predecessor's bodies.
    pub fn maintain_orphans(
        &self,
        time: u64,
        live_peers: impl IntoIterator<Item = PeerToken>,
    ) -> usize {
        let live_peers: hashbrown::HashSet<PeerToken> = live_peers.into_iter().collect();
        self.lifecycle.lock().orphans.maintain(time, &live_peers)
    }

    /// Called for every committed connect/disconnect, including ones with no
    /// pool mutation, while the caller still holds its chain transition.
    pub fn chain_changed(&self, available_parents: &[Txid]) {
        let _pool = self.pool.read();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.clear_rejects();
        for parent in available_parents {
            lifecycle.orphans.parent_ready(*parent);
        }
    }

    /// Inventory membership includes resident orphans and recent peer rejects.
    ///
    /// A txid announcement is suppressed only by a base-transaction rejection;
    /// a witness-specific rejection suppresses only the corresponding wtxid.
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
            || if wtxid {
                lifecycle.orphans.get_by_wtxid(&Wtxid::from(hash)).is_some()
            } else {
                lifecycle.orphans.contains(&Txid::from(hash))
            }
    }

    /// Returns an accepted or resident orphan transaction body by txid.
    #[must_use]
    pub fn get_tx(&self, txid: Txid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(tx) = pool.transaction_by_txid(&txid) {
            return Some((*tx).clone());
        }
        self.lifecycle
            .lock()
            .orphans
            .get(&txid)
            .map(|held| (*held.tx).clone())
    }

    /// Returns an accepted or resident orphan transaction body by witness txid.
    #[must_use]
    pub fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        let pool = self.pool.read();
        if let Some(entry) = pool.entry_by_wtxid(&wtxid) {
            return Some((*entry.tx).clone());
        }
        self.lifecycle
            .lock()
            .orphans
            .get_by_wtxid(&wtxid)
            .map(|held| (*held.tx).clone())
    }

    /// Invokes `f` for every resident pool transaction as `(txid, wtxid)`.
    ///
    /// The BIP152 compact-block reconstruction scan walks these identities
    /// to match short IDs. Orphan-pool residents are deliberately excluded:
    /// their parents are still unknown, so their bodies cannot yet complete
    /// a connected block reconstruction.
    pub fn for_each_identity(&self, mut f: impl FnMut(Txid, Wtxid)) {
        let pool = self.pool.read();
        for entry in pool.iter_entries() {
            f(entry.txid, entry.wtxid);
        }
    }

    /// Number of resident orphan transaction bodies.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.lifecycle.lock().orphans.len()
    }

    /// Number of retained rejection hashes with transaction or witness scope.
    #[must_use]
    pub fn recent_rejects_count(&self) -> usize {
        self.lifecycle.lock().rejects_len()
    }

    /// Whether a hash belongs to the bounded recent peer rejection cache.
    #[must_use]
    pub fn is_rejected(&self, hash: Hash256) -> bool {
        self.lifecycle.lock().is_rejected(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mempool, MempoolEntry};
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
        ))
    }

    fn source() -> PeerToken {
        PeerToken {
            addr: core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id: 7,
        }
    }

    fn standard_spend(outpoint: OutPoint, marker: u8) -> Tx {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[marker; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        Tx {
            version: 2,
            lock_time: LockTime::from_consensus(0),
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(u32::MAX),
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
        // Gateway raw insertion fixtures stage an anyone-can-spend output;
        // the child still traverses complete policy/script admission.
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
            MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1),
        );
        assert!(inserted.is_ok());
    }

    // MPL-04: parent readiness belongs to the commit, not observer delivery.
    #[test]
    fn parent_commit_without_observers_retries_orphan_with_original_source() {
        for origin in [
            AdmissionOrigin::Rpc,
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
            assert!(gateway.have_tx(Hash256::from(child.txid()), false));
            assert!(gateway.have_tx(Hash256::from(child.wtxid()), true));
            assert_eq!(gateway.get_tx(child.txid()), Some((*child).clone()));
            assert_eq!(
                gateway.get_tx_by_wtxid(child.wtxid()),
                Some((*child).clone())
            );
            insert_parent(&gateway, parent, origin);
            let retried = gateway.retry_orphans(&Coins(vec![]), 2);
            assert_eq!(retried.len(), 1);
            assert_eq!(retried[0].source, source());
            assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
            assert_eq!(gateway.orphan_count(), 0);
            assert!(gateway.read().contains_txid(&child.txid()));
        }
    }

    // MPL-04: RPC failures do not populate peer lifecycle state.
    #[test]
    fn rpc_missing_inputs_does_not_create_peer_lifecycle_state() {
        let gateway = gateway();
        let (_, child) = parent_and_child();
        let result =
            gateway.submit_transaction(child, AdmissionOrigin::Rpc, None, 1, &Coins(vec![]));
        assert_eq!(
            result,
            Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
        );
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.recent_rejects_count(), 0);
    }

    // MPL-04: nonexistent outputs of resident parents cannot become orphans.
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

    // MPL-04: changed pool facts must rebuild a normal chain lookup.
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
        // The previous no-chain attempt has stale pool facts. After rebuilding,
        // this absent parent requires real chain lookup, which is unavailable.
        assert_eq!(result, Err(SubmitError::RetryExhausted));
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert!(!gateway.read().contains_txid(&txid));
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.recent_rejects_count(), 0);

        // Run all cases under this existing process-global park owner.
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
                    MempoolEntry::new(Arc::new(conflict), 100, 1_000, 1, 1),
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

    // MPL-04: arrival resolves missing ancestry without retaining invalid outputs.
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
        assert!(gateway.retry_orphans(&Coins(vec![]), 3).is_empty());
    }

    // MPL-04: only the resident body's claim may mutate its lifecycle state.
    #[test]
    fn stale_invalid_outpoint_claim_cannot_reject_a_refreshed_orphan() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut invalid = (*child).clone();
        invalid.inputs[0].previous_output.vout = 1;
        let invalid = Arc::new(invalid);
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(source()),
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
            .get(&invalid.txid())
            .cloned();
        let Some(claim) = claim else {
            panic!("the missing transaction must be resident")
        };
        let mut refreshed = (*invalid).clone();
        refreshed.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
        let refreshed = Arc::new(refreshed);
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&refreshed),
                AdmissionOrigin::Peer(source()),
                None,
                2,
                &Coins(vec![])
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        assert_eq!(
            gateway.submit_transaction_claimed(
                Arc::clone(&invalid),
                AdmissionOrigin::Peer(source()),
                None,
                3,
                &Unavailable,
                Some(&claim)
            ),
            Ok(SubmitOutcome::AlreadyKnown)
        );
        assert_eq!(gateway.get_tx(invalid.txid()), Some((*refreshed).clone()));
        assert_eq!(gateway.recent_rejects_count(), 0);
    }

    // MPL-04: witness rejection does not poison another body with the same txid.
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
        assert!(matches!(
            gateway.submit_transaction(valid, AdmissionOrigin::Peer(source()), None, 2, &chain),
            Ok(SubmitOutcome::Committed(_))
        ));
    }

    // MPL-04: stripped-body rejects cannot suppress txid inventory or valid admission.
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
                2,
                &chain
            ),
            Ok(SubmitOutcome::Committed(_))
        ));
        assert!(gateway.have_tx(Hash256::from(valid.txid()), false));
        assert!(gateway.have_tx(Hash256::from(valid.wtxid()), true));
    }

    // MPL-04: shared preparation carries BIP141 accounting into committed entries.
    #[test]
    fn submission_carries_prepared_fee_size_and_weighted_sigops_into_entry() {
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Peer(source())] {
            let gateway = gateway();
            let (parent, child) = parent_and_child();
            let chain = Coins(vec![(
                child.inputs[0].previous_output,
                parent.outputs[0].clone(),
            )]);
            assert!(matches!(
                gateway.submit_transaction(Arc::clone(&child), origin, None, 7, &chain),
                Ok(SubmitOutcome::Committed(_))
            ));
            let pool = gateway.read();
            let Some(entry) = pool.entry_by_txid(&child.txid()) else {
                panic!("committed transaction must be present")
            };
            assert_eq!(entry.fee, 1_000);
            assert_eq!(u64::from(entry.bip141_vsize), child.vsize());
            // The sole legacy CHECKSIG in the output costs four BIP141 units.
            assert_eq!(entry.sigop_cost, 4);
            assert_eq!(entry.time, 7);
            assert_eq!(entry.height, 1);
        }
    }

    // MPL-04: chain notifications clear rejects but cannot consume odd-generation work.
    #[test]
    fn chain_change_with_no_pool_mutation_clears_rejects_and_preserves_odd_ready_work() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut rejected = (*child).clone();
        rejected.version = 3;
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
        assert!(gateway.retry_orphans(&chain, 2).is_empty());
        assert_eq!(gateway.orphan_count(), 1);
        assert!(reservation.finish().is_ok());
        let retried = gateway.retry_orphans(&chain, 2);
        assert_eq!(retried.len(), 1);
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
    }

    // MPL-04: exhausted retries remain resident and retry only on a later poll.
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
        let retried = gateway.retry_orphans(&chain, 3);
        assert_eq!(retried.len(), 1);
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
        assert!(gateway.retry_orphans(&chain, 4).is_empty());
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
            // The first snapshot still reports the old missing facts. The
            // gateway must reject those tokens and rebuild from the pool.
            Coins(vec![]).snapshot(&Tx {
                version: 2,
                lock_time: LockTime::from_consensus(0),
                inputs: vec![],
                outputs: vec![],
            })
        }
    }

    // MPL-04: preparation cannot lose a parent commit between resolution and holding.
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
            1,
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
                confirmed: false,
            })
        }
    }

    // MPL-04: changed generation invalidates rejection facts before publication.
    #[test]
    fn changed_chain_rebuilds_invalid_facts_before_recording_peer_rejection() {
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let chain = TipChangesDuringPreparation {
            gateway: Arc::clone(&gateway),
            coin: (child.inputs[0].previous_output, parent.outputs[0].clone()),
            reads: AtomicUsize::new(0),
        };
        assert!(matches!(
            gateway.submit_transaction(child, AdmissionOrigin::Peer(source()), None, 1, &chain),
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

    // MPL-04: confirmed-chain facts suppress peers, not RPC admission by cache lookup.
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
        assert!(matches!(
            gateway.submit_transaction(child, AdmissionOrigin::Rpc, None, 1, &chain),
            Ok(SubmitOutcome::Committed(_))
        ));
    }

    // MPL-04: only standard, non-coinbase missing-input bodies may be held.
    #[test]
    fn coinbase_and_nonstandard_missing_transactions_are_not_held() {
        let gateway = gateway();
        let (_, child) = parent_and_child();
        let mut nonstandard = (*child).clone();
        nonstandard.version = 3;
        let mut coinbase = (*child).clone();
        coinbase.inputs[0].previous_output = OutPoint::new(Txid::default(), u32::MAX);
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
                new_source.connection_id += 1;
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
                confirmed: false,
            })
        }
    }

    // MPL-04: retired retry claims cannot commit, hold, reject, or requeue work.
    #[test]
    fn refreshed_or_evicted_retry_claim_cannot_commit_hold_reject_or_requeue() {
        // Exercise final commit, missing-input hold, invalid-script rejection,
        // and retry exhaustion after lifecycle identity changed without any
        // pool sequence or chain-generation change.
        for refresh in [true, false] {
            for mode in 0..4 {
                let gateway = gateway();
                gateway.lifecycle.lock().orphans = crate::orphan::OrphanPool::new(1);
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
                gateway.chain_changed(&[parent.txid()]);
                let mut replacement = (*child).clone();
                if refresh {
                    replacement.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
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
                new_source.connection_id += 1;
                assert_eq!(
                    gateway
                        .lifecycle
                        .lock()
                        .orphans
                        .get(&replacement.txid())
                        .map(|held| held.source),
                    Some(new_source)
                );
                assert!(!gateway.is_rejected(Hash256::from(child.txid())));
                assert!(!gateway.is_rejected(Hash256::from(replacement.txid())));
                assert!(gateway.retry_orphans(&Unavailable, 3).is_empty());
            }
        }
    }

    // MPL-04: base-invalid outpoints reject without orphan retention or pool mutation.
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

    // MPL-04: parent arrival retires impossible orphan inputs through atomic rejection.
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

    /// POL-01 / BIP141: package prevouts retain the scripts used by accounting.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops>
    #[test]
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
                lock_time: LockTime::from_consensus(0),
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(u32::MAX),
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
                lock_time: LockTime::from_consensus(0),
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent.txid(), 1),
                    script_sig: Script::from_bytes(script_sig),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::from_stack(witness),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(8_000),
                    script_pubkey: Script::from_bytes(vec![0xac]),
                }],
            };
            // Preparation only: no script execution or successful package
            // acceptance is claimed. The parent's chain input is absent.
            let oracle: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&consensus_bytes(&child))?;
            let expected_outpoint = oracle.input[0].previous_output;
            let oracle_output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(parent.outputs[1].value.to_sat()),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(Vec::from(
                    parent.outputs[1].script_pubkey.clone(),
                )),
            };
            assert_eq!(
                u32::try_from(oracle.total_sigop_cost(|outpoint| {
                    (*outpoint == expected_outpoint).then(|| oracle_output.clone())
                }))?,
                4 + input_cost,
                "independent rust-bitcoin oracle",
            );
            let vsize = child.vsize();
            let txs = [parent, child];
            let contexts = gateway
                .preview_transactions(&txs, None, &Coins(vec![]))?
                .results;
            assert_eq!(contexts.len(), 2);
            assert_eq!(
                contexts[0].reject_reason,
                Some(AcceptanceRejectReason::MissingInputs)
            );
            assert_ne!(
                contexts[1].reject_reason,
                Some(AcceptanceRejectReason::MissingInputs)
            );
            assert_eq!(contexts[1].base_fee, Some(1_000));
            assert_eq!(u64::from(contexts[1].vsize), vsize);
            // BIP141: the legacy output CHECKSIG adds four to the input cost.
            assert_eq!(contexts[1].sigop_cost, 4 + input_cost);
            for vout in [2, u32::MAX] {
                let mut missing = txs[1].clone();
                missing.inputs[0].previous_output.vout = vout;
                let contexts = gateway
                    .preview_transactions(&[txs[0].clone(), missing], None, &Coins(vec![]))?
                    .results;
                assert_eq!(
                    contexts[1].reject_reason,
                    Some(AcceptanceRejectReason::MissingInputs)
                );
                assert_eq!(contexts[1].base_fee, Some(0));
                assert_eq!(contexts[1].sigop_cost, 4);
            }
            assert_eq!(gateway.read().sequence_number(), sequence);
            assert!(gateway.read().is_empty());
        }
        Ok(())
    }

    /// POL-01 / BIP141 P2WSH: the witness script must match the output's
    /// SHA256 commitment and succeed. Core v31.1 applies `PolicyScriptChecks`
    /// before test-accept success (validation.cpp `AcceptSingleTransaction`).
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
            Some(observer.clone()),
        ));
        let (valid, chain) = witness_spend();
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        let mut second = (*valid).clone();
        second.outputs[0].value = Amount::from_sat(second.outputs[0].value.to_sat() - 1);
        // A prior peer orphan must survive both successful and failed preview.
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
            let submitted =
                fresh.submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, None, 1, &chain);
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
        // Detect hidden estimator arrivals by confirming previewed txids:
        // two real arrivals would supply enough history for an estimate.
        preview_gateway.remove_for_block(
            AdmissionOrigin::Block,
            &[valid.as_ref(), &second],
            &[valid.txid(), second.txid()],
            2,
        );
        assert_eq!(preview_gateway.read().estimate_fee_rate(2), None);
        assert_eq!(observer.0.load(Ordering::SeqCst), 0);
        let submitted = gateway();
        assert!(matches!(
            submitted.submit_transaction(Arc::clone(&valid), AdmissionOrigin::Rpc, None, 1, &chain),
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

    /// Core applies maxfeerate only to an admission-valid result; both
    /// entry points must report the script failure before the RPC fee guard.
    /// <https://github.com/bitcoin/bitcoin/blob/v31.1/src/node/transaction.cpp>
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

    /// MPL-04: provisional preview facts are discarded after any relevant
    /// source changes; the same four-attempt bound applies to preview.
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
        assert_eq!(chain.reads.load(Ordering::SeqCst), MAX_ADMISSION_RETRIES);
        assert!(gateway.read().is_empty());
        Ok(())
    }

    // MPL-04: witness-scoped rejects preserve txid inventory and alternative witnesses.
    #[test]
    fn witness_rejection_preserves_valid_variant_and_legacy_inventory() {
        // BIP141 P2WSH commits to SHA256(witnessScript), excluding witness
        // data from txid. Rejection must not suppress a correct script body.
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
            assert!(matches!(
                gateway.submit_transaction(valid, AdmissionOrigin::Peer(source()), None, 2, &chain),
                Ok(SubmitOutcome::Committed(_))
            ));
        }
    }

    // MPL-04: a rejected witness cannot retire a different resident body or its retry.
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
        assert_eq!(
            gateway
                .lifecycle
                .lock()
                .orphans
                .get(&valid.txid())
                .map(|held| held.source),
            Some(source())
        );
        // A mempool parent accept wakes the retained variant without clearing
        // the rejection cache. Retry must relay the actual accepted wtxid.
        insert_parent(&gateway, parent, AdmissionOrigin::Rpc);
        let results = gateway.retry_orphans(&Coins(vec![]), 3);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, Ok(SubmitOutcome::Committed(_))));
        assert_eq!(results[0].source, source());
        assert_eq!(results[0].wtxid, valid.wtxid());
        assert_ne!(
            Hash256::from(results[0].wtxid),
            Hash256::from(results[0].txid)
        );
    }

    // MPL-04 and Core COutPoint::IsNull: zero-hash vout 0 is an ordinary
    // non-null outpoint, so missing-parent requests, indexing and coin lookup agree.
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
        let retried = gateway.retry_orphans(&coins, 2);
        assert_eq!(retried.len(), 1);
        assert!(matches!(retried[0].result, Ok(SubmitOutcome::Committed(_))));
        assert!(gateway.read().contains_txid(&tx.txid()));
        assert_eq!(gateway.orphan_count(), 0);
    }

    // MPL-04 / Core CheckTransaction: a true null prevout in any non-coinbase
    // input is invalid and must not consume orphan capacity.
    #[test]
    fn null_input_in_a_non_coinbase_transaction_is_not_held() {
        let reference = bitcoin::OutPoint::null();
        assert!(reference.is_null());
        let gateway = gateway();
        let (parent, child) = parent_and_child();
        let mut tx = (*child).clone();
        tx.inputs.push(TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(u32::MAX),
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

    // MPL-04; Core v31.1 CheckTransaction rejects duplicate/null outpoints
    // independently of witness bytes and without requiring previous outputs:
    // https://github.com/bitcoin/bitcoin/blob/v31.1/src/consensus/tx_check.cpp
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
        null_input.previous_output = OutPoint::new(Txid::default(), u32::MAX);
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
}
