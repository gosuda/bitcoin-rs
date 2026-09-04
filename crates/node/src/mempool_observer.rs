//! Node-owned mempool observers for P2P admission and local relay.
//!
//! Sequence ZMQ and mining-generation wakes stay with their owner crates
//! ([`crate::zmq_publisher`] and [`crate::mining`]). This module holds only
//! the two legs this wiring adds: orphan wake on any-origin parent accept,
//! and `inv` announce for RPC/reorg accepts. Chain movement clears
//! recent-rejects in [`crate::apply`], not here.

use std::sync::Arc;

use bitcoin_rs_mempool::{AdmissionOrigin, MempoolObserver, MutationEnvelope, MutationOutcome};
use bitcoin_rs_primitives::{Txid, Wtxid};

/// Re-queues orphans whose parent was just admitted, from any origin.
///
/// Peer, RPC, and reorg accepts all publish `Accepted` here, so waiting
/// children share one wake path. Block confirmation of a parent that was
/// never in the pool is handled by the apply path, which sees every
/// connected txid.
pub(crate) struct OrphanWakeObserver {
    admission: Arc<crate::tx_admission::TxAdmission>,
}

impl OrphanWakeObserver {
    /// Wakes held children when `admission` sees a newly available parent.
    #[must_use]
    pub(crate) fn new(admission: Arc<crate::tx_admission::TxAdmission>) -> Self {
        Self { admission }
    }
}

impl MempoolObserver for OrphanWakeObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        for change in &envelope.result.changes {
            if matches!(change.outcome, MutationOutcome::Accepted) {
                self.admission.enqueue_orphans_waiting_on(Txid(change.txid));
            }
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
    use bitcoin_rs_p2p::InboundTx;
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
    fn orphan_wake_requeues_children_on_parent_accept() {
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
        );
        let admission = Arc::new(crate::tx_admission::TxAdmission::new(Arc::new(gateway)));
        let (ingress_tx, ingress_rx) = crossbeam_channel::bounded::<InboundTx>(4);
        admission.attach_ingress(ingress_tx);

        let child = Arc::new(tx(8));
        let parent = child.inputs[0].previous_output.txid;
        let (lease_tx, _lease_rx) = crossbeam_channel::unbounded();
        let source = bitcoin_rs_p2p::PeerLease::new(lease_tx)
            .source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        admission.record_orphan(&child, source);

        let observer = super::OrphanWakeObserver::new(Arc::clone(&admission));
        observer.on_mutation(&envelope(
            AdmissionOrigin::Rpc,
            Hash256::from(parent),
            MutationOutcome::Accepted,
        ));

        let inbound = ingress_rx
            .try_recv()
            .expect("accepted parent must re-queue the waiting child");
        assert_eq!(inbound.tx.txid(), child.txid());
        assert_eq!(inbound.source, source);
        assert_eq!(admission.orphan_count(), 0);
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
