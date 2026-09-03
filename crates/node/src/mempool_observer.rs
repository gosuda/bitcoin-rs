//! Node-side mempool mutation observer.
//!
//! Bridges committed [`MutationEnvelope`]s from the [`MempoolGateway`] onto
//! Core's unified `sequence` ZMQ topic: accepted changes publish `A` events,
//! removals publish `R` events — except block-inclusion removals, which Core
//! suppresses because the block's own `C` event covers the departure.

use std::sync::Arc;

use bitcoin_rs_mempool::{MempoolObserver, MutationEnvelope, MutationOutcome, RemovalReason};
use bitcoin_rs_primitives::Txid;

use crate::zmq_publisher::{SequenceEvent, ZmqPublisher};

/// Publishes every committed mempool mutation as `A`/`R` sequence events.
///
/// Install behind the [`MempoolGateway`] observer slot only when a
/// `--zmq-pub-sequence` endpoint is configured; otherwise the gateway runs
/// observer-less and publishes nothing.
pub struct MempoolSequenceObserver {
    publisher: Arc<dyn ZmqPublisher>,
}

impl core::fmt::Debug for MempoolSequenceObserver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MempoolSequenceObserver")
            .field("publisher", &self.publisher)
            .finish()
    }
}

impl MempoolSequenceObserver {
    /// Observes on behalf of `publisher`.
    #[must_use]
    pub fn new(publisher: Arc<dyn ZmqPublisher>) -> Self {
        Self { publisher }
    }
}

impl MempoolObserver for MempoolSequenceObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        for (offset, change) in result.changes.iter().enumerate() {
            let Some(sequence) = result.sequence_of(offset) else {
                continue;
            };
            let txid = Txid(change.txid);
            match change.outcome {
                MutationOutcome::Accepted => {
                    self.publisher
                        .publish_sequence(SequenceEvent::Added(txid, sequence));
                }
                // Core emits no `R` for block inclusion: the block `C` event
                // covers the departure.
                MutationOutcome::Removed(RemovalReason::BlockInclusion) => {}
                MutationOutcome::Removed(_) => {
                    self.publisher
                        .publish_sequence(SequenceEvent::Removed(txid, sequence));
                }
            }
        }
    }
}

/// The node's one mutation observer: every committed mempool mutation fans
/// out to the `sequence` wire events and the mining generation wake, in that
/// order, after the gateway has released the publish mutex.
///
/// Installed exactly once, on the node-owned [`MempoolGateway`] at
/// [`crate::state::NodeState::open`], so both fan-outs stay ordered with the
/// single commit stream. The sequence leg is present only when a
/// `--zmq-pub-sequence` endpoint is configured; the mining leg always is,
/// because a mutation that changes the generation key must reach the
/// coordinator whenever one exists.
pub(crate) struct NodeMutationObserver {
    /// Core unified-`sequence` ZMQ events; `None` without an endpoint.
    sequence: Option<Arc<dyn MempoolObserver>>,
    /// Template-coordinator wake; a no-op until the coordinator attaches.
    mining_generation: Arc<crate::mining::MiningGenerationSignal>,
}

impl NodeMutationObserver {
    /// Composes the fan-out from its two legs.
    #[must_use]
    pub(crate) fn new(
        sequence: Option<Arc<dyn MempoolObserver>>,
        mining_generation: Arc<crate::mining::MiningGenerationSignal>,
    ) -> Self {
        Self {
            sequence,
            mining_generation,
        }
    }
}

impl MempoolObserver for NodeMutationObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if let Some(sequence) = &self.sequence {
            sequence.on_mutation(envelope);
        }
        // The last change's sequence is the pool's current sequence after this
        // mutation. Thread it directly so the coordinator never takes the
        // mempool read lock from the observer path.
        let result = &envelope.result;
        let wake_sequence = result
            .sequence_of(result.changes.len().saturating_sub(1))
            .unwrap_or(result.sequence_base);
        self.mining_generation
            .publish_generation_from(wake_sequence);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::MempoolSequenceObserver;
    use crate::zmq_publisher::{SequenceEvent, ZmqNotifier, ZmqPublisher, sequence_payload};
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits, MempoolObserver,
    };
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use parking_lot::{Mutex, RwLock};
    use std::sync::Arc;

    /// Captures the body frame of every `sequence` publication.
    #[derive(Default)]
    struct RecordingPublisher {
        sequence_bodies: Mutex<Vec<Vec<u8>>>,
    }

    impl core::fmt::Debug for RecordingPublisher {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("RecordingPublisher")
        }
    }

    impl ZmqPublisher for RecordingPublisher {
        fn wants_notifications(&self) -> bool {
            true
        }
        fn wants_rawtx(&self) -> bool {
            false
        }
        fn wants_rawblock(&self) -> bool {
            false
        }
        fn active_notifiers(&self) -> Vec<ZmqNotifier> {
            Vec::new()
        }
        fn publish_hashblock(&self, _hash: Hash256) {}
        fn publish_hashtx(&self, _txid: Txid) {}
        fn publish_rawblock(&self, _bytes: &[u8]) {}
        fn publish_rawtx(&self, _bytes: &[u8]) {}
        fn publish_sequence(&self, event: SequenceEvent) {
            self.sequence_bodies.lock().push(sequence_payload(event));
        }
    }

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

    fn entry(tx: &Tx) -> MempoolEntry {
        MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7)
    }

    fn expected_body(txid: &Txid, label: u8, sequence: u64) -> Vec<u8> {
        let mut body = *txid.as_bytes();
        body.reverse();
        let mut expected = body.to_vec();
        expected.push(label);
        expected.extend_from_slice(&sequence.to_le_bytes());
        expected
    }

    fn wired_gateway() -> (MempoolGateway, Arc<RecordingPublisher>) {
        let publisher = Arc::new(RecordingPublisher::default());
        let publisher_dyn = Arc::clone(&publisher);
        let observer: Arc<dyn MempoolObserver> =
            Arc::new(MempoolSequenceObserver::new(publisher_dyn));
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some(observer),
        );
        (gateway, publisher)
    }

    #[test]
    fn admission_publishes_one_a_frame_with_core_payload_bytes() {
        let (gateway, publisher) = wired_gateway();
        let admitted = tx(1);
        let txid = admitted.txid();

        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&admitted))
            .expect("in");

        let bodies = publisher.sequence_bodies.lock();
        assert_eq!(bodies.len(), 1, "exactly one event for one change");
        // First change ever: mempool sequence 1.
        assert_eq!(*bodies[0], expected_body(&txid, b'A', 1));
    }

    #[test]
    fn explicit_removal_publishes_r_frames_in_commit_order() {
        let (gateway, publisher) = wired_gateway();
        let parent = tx(2);
        let parent_txid = parent.txid();
        let mut child = tx(3);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        let child_txid = child.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
            .expect("parent in");
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&child))
            .expect("child in");
        publisher.sequence_bodies.lock().clear();

        gateway.remove_by_txid(AdmissionOrigin::Rpc, &parent_txid);

        let bodies = publisher.sequence_bodies.lock();
        assert_eq!(
            *bodies,
            vec![
                expected_body(&parent_txid, b'R', 3),
                expected_body(&child_txid, b'R', 4),
            ],
            "parent commits before descendant, each with its own sequence"
        );
    }

    #[test]
    fn block_inclusion_suppresses_r_frames() {
        let (gateway, publisher) = wired_gateway();
        let mined = tx(4);
        let mined_txid = mined.txid();
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&mined))
            .expect("in");
        publisher.sequence_bodies.lock().clear();

        gateway.remove_for_block(AdmissionOrigin::Rpc, &[&mined], &[mined_txid], 8);

        assert!(
            publisher.sequence_bodies.lock().is_empty(),
            "Core suppresses `R` on block inclusion; the block `C` event covers it"
        );
        assert_eq!(gateway.read().len(), 0, "the pool still moved");
    }

    #[test]
    fn policy_eviction_publishes_r_frames_with_contiguous_sequences() {
        let publisher = Arc::new(RecordingPublisher::default());
        let publisher_dyn = Arc::clone(&publisher);
        let observer: Arc<dyn MempoolObserver> =
            Arc::new(MempoolSequenceObserver::new(publisher_dyn));
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: 150,
                ..MempoolLimits::default()
            }))),
            Some(observer),
        );
        let low = MempoolEntry::new(Arc::new(tx(5)), 100, 100, 1, 7);
        let high = MempoolEntry::new(Arc::new(tx(6)), 100, 900, 1, 7);
        gateway
            .insert_entry(AdmissionOrigin::Rpc, low)
            .expect("low in");
        publisher.sequence_bodies.lock().clear();

        gateway
            .insert_entry(AdmissionOrigin::Rpc, high)
            .expect("high in");

        let bodies = publisher.sequence_bodies.lock();
        assert_eq!(
            *bodies,
            vec![
                expected_body(&tx(6).txid(), b'A', 2),
                expected_body(&tx(5).txid(), b'R', 3),
            ],
            "accepted commits first, then its policy eviction"
        );
    }

    /// The node's one mutation observer must fire both legs per committed
    /// mutation, in order: the `sequence` wire event first, then the mining
    /// generation wake. This is the wiring `NodeState::open` installs — a
    /// mutation that bypassed the gateway would satisfy neither assertion.
    #[test]
    fn node_mutation_observer_fans_out_to_sequence_and_mining_wake() {
        use crate::mining::{MempoolSequenceWake, MiningGenerationSignal};
        use bitcoin_rs_primitives::Block;
        use bitcoin_rs_rpc::context::{
            BlockTemplateRequest, BlockTemplateResult, MiningControl, MiningControlError,
        };
        use compact_str::CompactString;

        struct RecordingControl {
            published: Mutex<usize>,
            published_from: Mutex<Vec<u64>>,
        }

        fn unavailable() -> MiningControlError {
            MiningControlError::Unavailable(CompactString::from("not wired in this test"))
        }

        impl MiningControl for RecordingControl {
            fn get_block_template(
                &self,
                _request: BlockTemplateRequest,
            ) -> Result<BlockTemplateResult, MiningControlError> {
                Err(unavailable())
            }

            fn mining_info(
                &self,
            ) -> Result<bitcoin_rs_rpc::context::MiningInfo, MiningControlError> {
                Err(unavailable())
            }

            fn submit_block(
                &self,
                _block: Block,
            ) -> Result<bitcoin_rs_rpc::context::BlockValidationResult, MiningControlError>
            {
                Err(unavailable())
            }

            fn publish_generation(&self) {
                *self.published.lock() += 1;
            }
        }

        impl MempoolSequenceWake for RecordingControl {
            fn publish_generation_from(&self, sequence: u64) {
                self.published_from.lock().push(sequence);
            }
        }

        let (publisher, bodies) = {
            let publisher = Arc::new(RecordingPublisher::default());
            (publisher.clone(), Arc::clone(&publisher))
        };
        let signal = Arc::new(MiningGenerationSignal::new());
        let control = Arc::new(RecordingControl {
            published: Mutex::new(0),
            published_from: Mutex::new(Vec::new()),
        });
        let control_dyn: Arc<dyn MiningControl> = control.clone();
        let wake_dyn: Arc<dyn MempoolSequenceWake> = control.clone();
        signal.attach(&control_dyn);
        signal.attach_sequence_wake(&wake_dyn);

        let sequence = MempoolSequenceObserver::new(publisher);
        let sequence: Arc<dyn MempoolObserver> = Arc::new(sequence);
        let observer = super::NodeMutationObserver::new(Some(sequence), Arc::clone(&signal));
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some(Arc::new(observer)),
        );

        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&tx(7)))
            .expect("the fixture admission must commit");

        assert_eq!(
            bodies.sequence_bodies.lock().len(),
            1,
            "the sequence leg publishes the admission's A frame"
        );
        assert_eq!(
            *control.published_from.lock(),
            vec![1],
            "the mining leg wakes the coordinator with the mutation's sequence"
        );
        assert_eq!(
            *control.published.lock(),
            0,
            "the lock-free path is used, not the publish_generation fallback"
        );
    }
}
