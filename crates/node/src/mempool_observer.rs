//! Node-owned mempool observers for P2P admission and local relay.
//!
//! Sequence ZMQ and mining-generation wakes stay with their owner crates
//! ([`crate::zmq_publisher`] and [`crate::mining`]). This module holds only
//! the two legs this wiring adds: recent-reject invalidation on chain
//! movement, and `inv` announce for RPC/reorg accepts.

use std::sync::Arc;

use bitcoin_rs_mempool::{AdmissionOrigin, MempoolObserver, MutationEnvelope, MutationOutcome};
use bitcoin_rs_primitives::{Txid, Wtxid};

/// Clears the recent-rejects cache when the chain moves.
///
/// A transaction rejected against an old tip may become valid once its
/// inputs confirm, so stale rejections must not suppress the next `inv`.
pub(crate) struct RejectInvalidationObserver {
    admission: Arc<crate::tx_admission::TxAdmission>,
}

impl RejectInvalidationObserver {
    /// Observes chain-moving mutations on behalf of `admission`.
    #[must_use]
    pub(crate) fn new(admission: Arc<crate::tx_admission::TxAdmission>) -> Self {
        Self { admission }
    }
}

impl MempoolObserver for RejectInvalidationObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if matches!(
            envelope.origin,
            AdmissionOrigin::Block | AdmissionOrigin::Reorg
        ) {
            self.admission.invalidate_recent_rejects();
        }
    }
}

/// Announces locally-injected accepted transactions (`sendrawtransaction`,
/// reorg re-admission) to every connected peer.
///
/// Peer-origin accepts are announced by the ingress consumer, which is the
/// only place that still has the delivering connection id in scope at the
/// moment of evaluation. This observer covers the origins that have no
/// source peer to exclude.
pub(crate) struct LocalTxRelayObserver {
    relay: crate::tx_relay::TxRelayQueue,
}

impl LocalTxRelayObserver {
    /// Relays accepted local mutations through `relay`.
    #[must_use]
    pub(crate) fn new(relay: crate::tx_relay::TxRelayQueue) -> Self {
        Self { relay }
    }
}

impl MempoolObserver for LocalTxRelayObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if !matches!(
            envelope.origin,
            AdmissionOrigin::Rpc | AdmissionOrigin::Reorg
        ) {
            return;
        }
        for change in &envelope.result.changes {
            if !matches!(change.outcome, MutationOutcome::Accepted) {
                continue;
            }
            let txid = Txid(change.txid);
            // The mutation record carries txid only; the current `inv` path
            // announces by txid, so the wtxid field is unused by the sink.
            self.relay.announce(txid, Wtxid(change.txid), None);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolGateway, MempoolLimits, MempoolObserver, MutationOutcome,
    };
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use parking_lot::RwLock;
    use std::sync::Arc;

    fn tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51, label],
            }],
        }
    }

    fn envelope(
        origin: AdmissionOrigin,
        txid: Hash256,
        outcome: MutationOutcome,
    ) -> bitcoin_rs_mempool::MutationEnvelope {
        bitcoin_rs_mempool::MutationEnvelope {
            origin,
            result: bitcoin_rs_mempool::MutationResult {
                changes: vec![bitcoin_rs_mempool::MutationChange { txid, outcome }],
                sequence_base: 1,
            },
        }
    }

    #[test]
    fn reject_invalidation_clears_cache_only_on_chain_movement() {
        use bitcoin_rs_primitives::Wtxid;

        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
        );
        let admission = Arc::new(crate::tx_admission::TxAdmission::new(Arc::new(gateway)));
        let rejected = tx(8);
        admission.record_reject(rejected.txid(), rejected.wtxid());
        assert!(admission.is_rejected(Hash256::from(rejected.txid())));

        let observer = super::RejectInvalidationObserver::new(Arc::clone(&admission));
        observer.on_mutation(&envelope(
            AdmissionOrigin::Rpc,
            Hash256::from(rejected.txid()),
            MutationOutcome::Accepted,
        ));
        assert!(
            admission.is_rejected(Hash256::from(rejected.txid())),
            "RPC admission must not drop recent-rejects"
        );

        observer.on_mutation(&envelope(
            AdmissionOrigin::Block,
            Hash256::from(rejected.txid()),
            MutationOutcome::Removed(bitcoin_rs_mempool::RemovalReason::BlockInclusion),
        ));
        assert!(
            !admission.is_rejected(Hash256::from(rejected.txid())),
            "block-connect must drop recent-rejects"
        );

        admission.record_reject(rejected.txid(), Wtxid(rejected.txid().0));
        observer.on_mutation(&envelope(
            AdmissionOrigin::Reorg,
            Hash256::from(rejected.txid()),
            MutationOutcome::Accepted,
        ));
        assert!(
            !admission.is_rejected(Hash256::from(rejected.txid())),
            "reorg must drop recent-rejects"
        );
    }

    #[test]
    fn local_tx_relay_announces_rpc_and_reorg_accepts_only() {
        use bitcoin_rs_mempool::PeerToken;
        use bitcoin_rs_primitives::Wtxid;

        let (queue, rx) = crate::tx_relay::TxRelayQueue::new(8);
        let observer = super::LocalTxRelayObserver::new(queue);
        let accepted = tx(9);
        let txid_hash = Hash256::from(accepted.txid());

        observer.on_mutation(&envelope(
            AdmissionOrigin::Peer(PeerToken {
                addr: std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
                connection_id: 7,
            }),
            txid_hash,
            MutationOutcome::Accepted,
        ));
        assert!(
            rx.try_recv().is_err(),
            "peer-origin accepts are announced by the ingress consumer"
        );

        observer.on_mutation(&envelope(
            AdmissionOrigin::Rpc,
            txid_hash,
            MutationOutcome::Removed(bitcoin_rs_mempool::RemovalReason::PolicyEviction),
        ));
        assert!(rx.try_recv().is_err(), "removals must not announce");

        observer.on_mutation(&envelope(
            AdmissionOrigin::Rpc,
            txid_hash,
            MutationOutcome::Accepted,
        ));
        let announced = rx.try_recv().expect("RPC accept must announce");
        assert_eq!(announced.txid, accepted.txid());
        assert_eq!(announced.wtxid, Wtxid(txid_hash));
        assert_eq!(announced.source, None);

        observer.on_mutation(&envelope(
            AdmissionOrigin::Reorg,
            txid_hash,
            MutationOutcome::Accepted,
        ));
        let announced = rx.try_recv().expect("reorg accept must announce");
        assert_eq!(announced.source, None);
    }
}
