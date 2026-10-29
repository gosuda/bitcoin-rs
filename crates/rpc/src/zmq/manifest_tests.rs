use super::*;

#[test]
fn zmq_topic_names_match_the_compatibility_manifest() {
    let published: std::collections::BTreeSet<&str> = [
        ZmqTopic::HashBlock,
        ZmqTopic::HashTx,
        ZmqTopic::RawBlock,
        ZmqTopic::RawTx,
        ZmqTopic::Sequence,
    ]
    .iter()
    .map(|topic| topic.as_str())
    .collect();
    let declared: std::collections::BTreeSet<&str> =
        crate::manifest::entries_of_kind(crate::manifest::SurfaceKind::Zmq)
            .map(|entry| entry.name)
            .collect();
    assert_eq!(
        published, declared,
        "published ZMQ topics and the declared ZMQ rows must name the same set"
    );

    for topic in [
        ZmqTopic::HashBlock,
        ZmqTopic::HashTx,
        ZmqTopic::RawBlock,
        ZmqTopic::RawTx,
        ZmqTopic::Sequence,
    ] {
        assert_eq!(
            topic.notifier_type(),
            format!("pub{}", topic.as_str()),
            "the notifier name for `{}` no longer follows pub<topic>",
            topic.as_str()
        );
    }
}

#[derive(Default)]
struct RecordingPublisher {
    sequence_bodies: parking_lot::Mutex<Vec<Vec<u8>>>,
    capture_rawtx: bool,
    raw_bodies: parking_lot::Mutex<Vec<Vec<u8>>>,
    hashtx: parking_lot::Mutex<Vec<Txid>>,
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
        self.capture_rawtx
    }
    fn wants_rawblock(&self) -> bool {
        false
    }
    fn active_notifiers(&self) -> Vec<ZmqNotifier> {
        Vec::new()
    }
    fn publish_hashblock(&self, _hash: Hash256) {}
    fn publish_hashtx(&self, txid: Txid) {
        self.hashtx.lock().push(txid);
    }
    fn publish_rawblock(&self, _bytes: &[u8]) {}
    fn publish_rawtx(&self, bytes: &[u8]) {
        self.raw_bodies.lock().push(bytes.to_vec());
    }
    fn publish_sequence(&self, event: SequenceEvent) {
        self.sequence_bodies.lock().push(sequence_payload(event));
    }
}

fn sequence_tx(label: u8) -> bitcoin_rs_primitives::Tx {
    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51, label].into(),
        }],
    }
}

fn sequence_entry(tx: &bitcoin_rs_primitives::Tx) -> bitcoin_rs_mempool::MempoolEntry {
    bitcoin_rs_mempool::MempoolEntry::new(std::sync::Arc::new(tx.clone()), 100, 1_000, 1, 7, 0)
}

fn expected_sequence_body(txid: &Txid, label: u8, sequence: u64) -> Vec<u8> {
    let mut body = *txid.as_bytes();
    body.reverse();
    let mut expected = body.to_vec();
    expected.push(label);
    expected.extend_from_slice(&sequence.to_le_bytes());
    expected
}

fn wired_sequence_gateway() -> (
    bitcoin_rs_mempool::MempoolGateway,
    std::sync::Arc<RecordingPublisher>,
) {
    use bitcoin_rs_mempool::{
        BodyInterest, Mempool, MempoolGateway, MempoolLimits, MempoolObserver,
    };
    use parking_lot::RwLock;
    let publisher = std::sync::Arc::new(RecordingPublisher::default());
    let observer: std::sync::Arc<dyn MempoolObserver> =
        std::sync::Arc::new(MempoolSequenceObserver::new(publisher.clone()));
    let gateway = MempoolGateway::new(
        std::sync::Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((observer, BodyInterest::Bodies)),
        bitcoin_rs_consensus::ValidationEngine::Native,
        None,
    );
    (gateway, publisher)
}

#[cfg(feature = "zmq")]
#[test]
fn admitted_unconfirmed_rawtx_is_exact_and_not_repeated() -> anyhow::Result<()> {
    struct EmptyChain;
    impl bitcoin_rs_mempool::AdmissionChain for EmptyChain {
        fn snapshot(
            &self,
            _: &bitcoin_rs_primitives::Tx,
        ) -> Option<bitcoin_rs_mempool::ChainAdmissionSnapshot> {
            Some(bitcoin_rs_mempool::ChainAdmissionSnapshot::default())
        }
    }
    use bitcoin_rs_mempool::{AdmissionOrigin, Mempool, MempoolGateway, MempoolLimits};
    use bitcoin_rs_primitives::encode::consensus_bytes;
    use std::sync::Arc;
    let dir = tempfile::tempdir()?;
    let address = format!("ipc://{}", dir.path().join("admission.sock").display());
    let publisher = Arc::new(SocketZmqPublisher::bind(&[ZmqEndpointConfig {
        endpoint: address.clone(),
        topics: vec![ZmqTopic::HashTx, ZmqTopic::RawTx, ZmqTopic::Sequence],
        hwm: Some(100),
    }])?);
    let context = zmq::Context::new();
    let subscriber = context.socket(zmq::SUB)?;
    subscriber.set_subscribe(b"")?;
    subscriber.set_rcvtimeo(3_000)?;
    subscriber.connect(&address)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        publisher.publish_sequence(SequenceEvent::Connected(Hash256::from_le_bytes(&[0; 32])));
        if subscriber.poll(zmq::POLLIN, 25)? != 0 {
            subscriber.recv_multipart(0)?;
            break;
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "ZMQ subscription timed out"
        );
    }
    while subscriber.poll(zmq::POLLIN, 50)? != 0 {
        subscriber.recv_multipart(0)?;
    }
    let observer = Arc::new(MempoolSequenceObserver::new(publisher));
    let gateway = MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        Some((observer, bitcoin_rs_mempool::BodyInterest::Bodies)),
        bitcoin_rs_consensus::ValidationEngine::Native,
        None,
    );
    let tx = sequence_tx(91);
    let expected = consensus_bytes(&tx);
    gateway.insert_entry(AdmissionOrigin::Rpc, sequence_entry(&tx))?;
    let announced = subscriber.recv_multipart(0)?;
    assert_eq!(announced[0].as_slice(), b"hashtx");
    assert_eq!(
        announced[1],
        reversed_hash_body(*tx.txid().as_bytes()),
        "hashtx carries the admitted txid in wire byte order"
    );
    assert_eq!(announced[2], 0_u32.to_le_bytes());
    let raw = subscriber.recv_multipart(0)?;
    assert_eq!(raw[0].as_slice(), b"rawtx");
    assert_eq!(raw[1], expected);
    assert_eq!(raw[2], 0_u32.to_le_bytes());
    let added = subscriber.recv_multipart(0)?;
    assert_eq!(added[0].as_slice(), b"sequence");
    assert_eq!(added[1], expected_sequence_body(&tx.txid(), b'A', 1));
    assert!(matches!(
        gateway.submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, None, 2, &EmptyChain),
        Ok(bitcoin_rs_mempool::SubmitOutcome::AlreadyKnown),
    ));
    let refused = sequence_tx(93);
    assert!(matches!(
        gateway.submit_transaction(
            Arc::new(refused),
            AdmissionOrigin::Rpc,
            None,
            2,
            &EmptyChain
        ),
        Err(bitcoin_rs_mempool::SubmitError::Policy(_)),
    ));
    assert_eq!(subscriber.poll(zmq::POLLIN, 100)?, 0);
    assert_eq!(gateway.read().len(), 1);
    Ok(())
}

#[test]
fn rawtx_disabled_does_not_retain_admission_bodies() {
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolGateway, MempoolLimits, MempoolObserver,
    };
    #[derive(Default)]
    struct CaptureCheck(parking_lot::Mutex<Vec<bitcoin_rs_mempool::MutationEnvelope>>);
    impl MempoolObserver for CaptureCheck {
        fn on_mutation(&self, envelope: &bitcoin_rs_mempool::MutationEnvelope) {
            self.0.lock().push(envelope.clone());
        }
    }
    let publisher = std::sync::Arc::new(RecordingPublisher::default());
    let observer = std::sync::Arc::new(MempoolSequenceObserver::new(publisher));
    let capture = std::sync::Arc::new(CaptureCheck::default());
    let composite = bitcoin_rs_mempool::CompositeObserver::new();
    composite.add_leg("zmq", observer, bitcoin_rs_mempool::BodyInterest::Metadata);
    composite.add_leg(
        "capture",
        capture.clone(),
        bitcoin_rs_mempool::BodyInterest::Metadata,
    );
    assert!(!composite.wants_bodies(), "no leg registered body interest");
    let gateway = MempoolGateway::new(
        std::sync::Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        Some((
            std::sync::Arc::new(composite),
            bitcoin_rs_mempool::BodyInterest::Metadata,
        )),
        bitcoin_rs_consensus::ValidationEngine::Native,
        None,
    );
    gateway
        .insert_entry(AdmissionOrigin::Rpc, sequence_entry(&sequence_tx(92)))
        .expect("admitted without rawtx");
    let envelopes = capture.0.lock();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].accepted_transactions, Vec::new());
    assert_eq!(envelopes[0].result.len(), 1);
    assert_eq!(gateway.read().len(), 1);
}

#[test]
fn mixed_package_changes_publish_only_their_indexed_admitted_bodies() {
    use bitcoin_rs_mempool::{
        AdmissionOrigin, MempoolObserver, MutationChange, MutationEnvelope, MutationOutcome,
        MutationResult, RemovalReason,
    };
    use bitcoin_rs_primitives::encode::consensus_bytes;
    use std::sync::Arc;
    let first = Arc::new(sequence_tx(185));
    let second = Arc::new(sequence_tx(186));
    let removed = sequence_tx(187);
    let publisher = Arc::new(RecordingPublisher {
        capture_rawtx: true,
        ..RecordingPublisher::default()
    });
    let observer = MempoolSequenceObserver::new(publisher.clone());
    let envelope = MutationEnvelope {
        origin: AdmissionOrigin::Rpc,
        result: MutationResult {
            changes: vec![
                MutationChange {
                    txid: Hash256::from(removed.txid()),
                    outcome: MutationOutcome::Removed(RemovalReason::Replaced),
                },
                MutationChange {
                    txid: Hash256::from(first.txid()),
                    outcome: MutationOutcome::Accepted,
                },
                MutationChange {
                    txid: Hash256::from(first.txid()),
                    outcome: MutationOutcome::Removed(RemovalReason::PolicyEviction),
                },
                MutationChange {
                    txid: Hash256::from(second.txid()),
                    outcome: MutationOutcome::Accepted,
                },
            ],
            sequence_base: 41,
        },
        accepted_transactions: vec![(1, first.clone()), (3, second.clone())],
    };
    observer.on_mutation(&envelope);
    assert_eq!(
        *publisher.raw_bodies.lock(),
        vec![
            consensus_bytes(first.as_ref()),
            consensus_bytes(second.as_ref()),
        ]
    );
    assert_eq!(
        *publisher.hashtx.lock(),
        vec![first.txid(), second.txid()],
        "every admission notifies hashtx, as Core does"
    );
    assert_eq!(
        *publisher.sequence_bodies.lock(),
        vec![
            expected_sequence_body(&removed.txid(), b'R', 41),
            expected_sequence_body(&first.txid(), b'A', 42),
            expected_sequence_body(&first.txid(), b'R', 43),
            expected_sequence_body(&second.txid(), b'A', 44),
        ]
    );
}

#[test]
fn admission_publishes_one_a_frame_with_core_payload_bytes() {
    use bitcoin_rs_mempool::AdmissionOrigin;
    let (gateway, publisher) = wired_sequence_gateway();
    let admitted = sequence_tx(1);
    let txid = admitted.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, sequence_entry(&admitted))
        .expect("in");
    let bodies = publisher.sequence_bodies.lock();
    assert_eq!(bodies.len(), 1, "exactly one event for one change");
    assert_eq!(*bodies[0], expected_sequence_body(&txid, b'A', 1));
}

#[test]
fn policy_eviction_publishes_r_frames_in_commit_order() {
    use bitcoin_rs_mempool::AdmissionOrigin;
    use bitcoin_rs_primitives::OutPoint;
    let (gateway, publisher) = wired_sequence_gateway();
    let parent = sequence_tx(2);
    let parent_txid = parent.txid();
    let mut child = sequence_tx(3);
    child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
    let child_txid = child.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, sequence_entry(&parent))
        .expect("parent in");
    gateway
        .insert_entry(AdmissionOrigin::Rpc, sequence_entry(&child))
        .expect("child in");
    publisher.sequence_bodies.lock().clear();
    gateway.evict_below_fee_rate(AdmissionOrigin::Rpc, 10_001);
    let bodies = publisher.sequence_bodies.lock();
    assert_eq!(
        *bodies,
        vec![
            expected_sequence_body(&parent_txid, b'R', 3),
            expected_sequence_body(&child_txid, b'R', 4),
        ],
        "parent commits before descendant, each with its own sequence"
    );
}

#[test]
fn block_inclusion_suppresses_r_frames() {
    use bitcoin_rs_mempool::AdmissionOrigin;
    let (gateway, publisher) = wired_sequence_gateway();
    let mined = sequence_tx(4);
    let mined_txid = mined.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, sequence_entry(&mined))
        .expect("in");
    publisher.sequence_bodies.lock().clear();
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[&mined], &[mined_txid], 8, 1);
    assert!(
        publisher.sequence_bodies.lock().is_empty(),
        "Core suppresses `R` on block inclusion; the block `C` event covers it"
    );
    assert_eq!(gateway.read().len(), 0, "the pool still moved");
}

#[test]
fn policy_eviction_publishes_r_frames_with_contiguous_sequences() {
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits, MempoolObserver,
    };
    use parking_lot::RwLock;
    let publisher = std::sync::Arc::new(RecordingPublisher::default());
    let observer: std::sync::Arc<dyn MempoolObserver> =
        std::sync::Arc::new(MempoolSequenceObserver::new(publisher.clone()));
    let gateway = MempoolGateway::new(
        std::sync::Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 150,
            ..MempoolLimits::default()
        }))),
        Some((observer, bitcoin_rs_mempool::BodyInterest::Bodies)),
        bitcoin_rs_consensus::ValidationEngine::Native,
        None,
    );
    let low = MempoolEntry::new(std::sync::Arc::new(sequence_tx(5)), 100, 100, 1, 7, 0);
    let high = MempoolEntry::new(std::sync::Arc::new(sequence_tx(6)), 100, 900, 1, 7, 0);
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
            expected_sequence_body(&sequence_tx(6).txid(), b'A', 2),
            expected_sequence_body(&sequence_tx(5).txid(), b'R', 3),
        ],
        "accepted commits first, then its policy eviction"
    );
}

#[test]
fn composite_observer_fans_out_to_sequence_then_mining_wake() {
    use bitcoin_rs_mempool::{
        AdmissionOrigin, BodyInterest, CompositeObserver, Mempool, MempoolGateway, MempoolLimits,
        MempoolObserver,
    };
    use bitcoin_rs_mining::FakeMiningControl;
    use bitcoin_rs_mining::MempoolSequenceWake;
    use bitcoin_rs_mining::MiningControl;
    use bitcoin_rs_node::mining::MiningGenerationSignal;
    use parking_lot::RwLock;

    let publisher = std::sync::Arc::new(RecordingPublisher::default());
    let signal = std::sync::Arc::new(MiningGenerationSignal::new());
    let control = FakeMiningControl::unavailable("not wired in this test");
    let control_dyn: std::sync::Arc<dyn MiningControl> = control.clone();
    let wake_dyn: std::sync::Arc<dyn MempoolSequenceWake> = control.clone();
    signal.attach(&control_dyn);
    signal.attach_sequence_wake(&wake_dyn);

    let composite = CompositeObserver::new();
    composite.add_leg(
        "sequence",
        std::sync::Arc::new(MempoolSequenceObserver::new(publisher.clone())),
        BodyInterest::Bodies,
    );
    composite.add_leg("mining", signal, BodyInterest::Metadata);
    let gateway = MempoolGateway::new(
        std::sync::Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((
            std::sync::Arc::new(composite) as std::sync::Arc<dyn MempoolObserver>,
            BodyInterest::Bodies,
        )),
        bitcoin_rs_consensus::ValidationEngine::Native,
        None,
    );
    gateway
        .insert_entry(AdmissionOrigin::Rpc, sequence_entry(&sequence_tx(7)))
        .expect("the fixture admission must commit");
    assert_eq!(
        publisher.sequence_bodies.lock().len(),
        1,
        "the sequence leg publishes the admission's A frame"
    );
    assert_eq!(
        *control.published_from.lock(),
        vec![1],
        "the mining leg wakes the coordinator with the mutation's sequence"
    );
    assert_eq!(
        control.publish_count(),
        0,
        "the lock-free path is used, not the publish_generation fallback"
    );
}
