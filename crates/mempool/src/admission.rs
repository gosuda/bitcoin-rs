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
#[derive(Clone, Debug)]
pub struct ChainAdmissionSnapshot {
    /// Confirmed input outputs; unavailable inputs are absent.
    pub prevouts: Vec<(OutPoint, TxOut)>,
    /// Applied tip height; finality is checked at the next height.
    pub height: u32,
    /// Applied tip's median time past (zero before genesis).
    pub locktime_cutoff: u32,
    /// Peer duplicate suppression only. RPC cache membership is not admission.
    pub confirmed: bool,
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
    /// Delivering connection metadata; never a socket/connection handle.
    pub source: PeerToken,
    /// The same result a fresh submission receives.
    pub result: Result<SubmitOutcome, SubmitError>,
}

pub(crate) fn can_hold_orphan(tx: &Tx, policy: &StandardnessPolicy) -> bool {
    !(tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null())
        && is_standard_tx(tx, policy).is_ok()
}

// An absent parent can arrive later; a resident parent's nonexistent output
// cannot. Keep that distinction in the resolved outpoints rather than a second
// parent-membership index.
fn resolve_mempool_inputs(pool: &crate::Mempool, tx: &Tx) -> Option<HashMap<OutPoint, TxOut>> {
    let mut prevouts = HashMap::new();
    for input in &tx.inputs {
        let outpoint = input.previous_output;
        if outpoint.is_null() || outpoint == OutPoint::default() {
            continue;
        }
        if let Some(parent) = pool.transaction_by_txid(&outpoint.txid) {
            let output = parent.outputs.get(usize::try_from(outpoint.vout).ok()?)?;
            prevouts.insert(outpoint, output.clone());
        }
    }
    Some(prevouts)
}

impl MempoolGateway {
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
                if peer {
                    let lifecycle = self.lifecycle.lock();
                    if lifecycle.is_rejected(Hash256::from(tx.wtxid())) {
                        return Ok(SubmitOutcome::AlreadyKnown);
                    }
                }
                let Some(prevouts) = resolve_mempool_inputs(&pool, &tx) else {
                    // These facts are wholly mempool-owned and still fenced
                    // by the stable pool guard. Do not park an impossible
                    // outpoint or let an obsolete retry reject a fresh body.
                    if peer {
                        let mut lifecycle = self.lifecycle.lock();
                        if claim.is_some_and(|claim| !lifecycle.orphans.is_current(claim)) {
                            return Ok(SubmitOutcome::AlreadyKnown);
                        }
                        lifecycle.reject(&tx);
                    }
                    return Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs));
                };
                (
                    pool.sequence_number(),
                    prevouts,
                    peer && can_hold_orphan(&tx, &pool.policy_snapshot().standardness),
                )
            };
            let Some(snapshot) = chain.snapshot(&tx) else {
                continue;
            };
            if peer && snapshot.confirmed {
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
            let confirmed = snapshot.prevouts.into_iter().collect::<HashMap<_, _>>();
            let mut prevouts = Vec::with_capacity(tx.inputs.len());
            let mut missing_inputs = false;
            let mut missing_parents = Vec::new();
            let mut seen_missing = HashSet::new();
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                if outpoint.is_null() || outpoint == OutPoint::default() {
                    missing_inputs = true;
                } else if let Some(output) = mempool_prevouts
                    .get(&outpoint)
                    .or_else(|| confirmed.get(&outpoint))
                {
                    prevouts.push((outpoint, output.clone()));
                } else {
                    missing_inputs = true;
                    if seen_missing.insert(outpoint.txid) {
                        missing_parents.push(outpoint.txid);
                    }
                }
            }
            let context = crate::accounting::prepared_context(&tx, &prevouts, missing_inputs);
            let request = AdmissionRequest {
                tx,
                context,
                prevouts,
                locktime_cutoff: snapshot.locktime_cutoff,
                max_feerate_sat_per_kvb,
                time,
                height: snapshot.height,
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
                source: held.source,
                result,
            });
        }
        results
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
        lifecycle.is_rejected(hash)
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

    /// Number of resident orphan transaction bodies.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.lifecycle.lock().orphans.len()
    }

    /// Number of retained exact-body rejection hashes (wtxids).
    #[must_use]
    pub fn recent_rejects_count(&self) -> usize {
        self.lifecycle.lock().rejects_len()
    }

    /// Whether a transaction body is parked pending missing inputs.
    #[must_use]
    pub fn is_orphan(&self, txid: &Txid) -> bool {
        self.lifecycle.lock().orphans.contains(txid)
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
    use bitcoin_rs_primitives::TxIn;
    use parking_lot::{Mutex, RwLock};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Coins(Vec<(OutPoint, TxOut)>);
    impl AdmissionChain for Coins {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: self.0.clone(),
                height: 1,
                locktime_cutoff: 0,
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
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: vec![],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 9_000,
                script_pubkey: script,
            }],
        }
    }

    fn parent_and_child() -> (Tx, Arc<Tx>) {
        let mut parent =
            standard_spend(OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0), 1);
        // Gateway raw insertion fixtures stage an anyone-can-spend output;
        // the child still traverses complete policy/script admission.
        parent.outputs[0] = TxOut {
            value: 10_000,
            script_pubkey: vec![0x51],
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
        let claim = gateway.lifecycle.lock().orphans.get(&invalid.txid()).cloned();
        let Some(claim) = claim else {
            panic!("the missing transaction must be resident")
        };
        let mut refreshed = (*invalid).clone();
        refreshed.inputs[0].witness = vec![vec![1]];
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

    #[test]
    fn rejected_witness_does_not_suppress_a_valid_body_with_the_same_txid() {
        let gateway = gateway();
        let (parent, valid) = parent_and_child();
        let chain = Coins(vec![(
            valid.inputs[0].previous_output,
            parent.outputs[0].clone(),
        )]);
        let mut invalid = (*valid).clone();
        invalid.inputs[0].witness = vec![vec![1]];
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
        assert!(matches!(
            gateway.submit_transaction(valid, AdmissionOrigin::Peer(source()), None, 2, &chain),
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
                value: 10_000,
                script_pubkey,
            },
        )]);
        let mut valid = (*child).clone();
        valid.inputs[0].witness = vec![witness_script];
        let valid = Arc::new(valid);
        assert_eq!(child.txid(), valid.txid());
        assert_ne!(child.wtxid(), valid.wtxid());
        assert_eq!(
            gateway.submit_transaction(child, AdmissionOrigin::Peer(source()), None, 1, &chain),
            Err(SubmitError::Consensus)
        );
        assert!(gateway.is_rejected(Hash256::from(valid.txid())));
        assert!(!gateway.is_rejected(Hash256::from(valid.wtxid())));
        assert!(matches!(
            gateway.submit_transaction(valid, AdmissionOrigin::Peer(source()), None, 2, &chain),
            Ok(SubmitOutcome::Committed(_))
        ));
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
                lock_time: 0,
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
                coin.1.script_pubkey = vec![0x00];
            }
            Some(ChainAdmissionSnapshot {
                prevouts: vec![coin],
                height: 1,
                locktime_cutoff: 0,
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
            assert!(!gateway.is_orphan(&tx.txid()));
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
                confirmed: false,
            })
        }
    }

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
                    replacement.inputs[0].witness = vec![vec![1]];
                } else {
                    replacement.outputs[0].value -= 1;
                }
                let replacement = Arc::new(replacement);
                let available = match mode {
                    0 => Some((child.inputs[0].previous_output, parent.outputs[0].clone())),
                    2 => Some((
                        child.inputs[0].previous_output,
                        TxOut {
                            value: 10_000,
                            script_pubkey: vec![0x00],
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
}
