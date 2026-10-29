use super::*;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::bounded;
use parking_lot::Mutex;
use std::sync::atomic::AtomicBool;

#[derive(Clone)]
struct FakePeer {
    node_id: u64,
    capacity: usize,
}

type SinkEntry = (Txid, Option<u64>, RelayOutcome);

struct FakeSink {
    peers: Mutex<Vec<FakePeer>>,
    log: Arc<Mutex<Vec<SinkEntry>>>,
}

impl FakeSink {
    fn new(peers: Vec<FakePeer>) -> Self {
        Self {
            peers: Mutex::new(peers),
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn log(&self) -> Vec<SinkEntry> {
        self.log.lock().clone()
    }
}

impl RelaySink for FakeSink {
    fn announce_inv(
        &self,
        txid: Txid,
        _wtxid: Wtxid,
        exclude: Option<u64>,
        _sequence: u64,
    ) -> RelayOutcome {
        let mut peers = self.peers.lock();
        let mut outcome = RelayOutcome::default();
        for peer in peers.iter_mut() {
            outcome.attempted += 1;
            if let Some(id) = exclude
                && peer.node_id == id
            {
                outcome.excluded += 1;
                continue;
            }
            if peer.capacity == 0 {
                outcome.saturated += 1;
            } else {
                peer.capacity -= 1;
            }
        }
        self.log.lock().push((txid, exclude, outcome));
        outcome
    }
}

fn dummy_txid(byte: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[byte; 32]))
}

fn dummy_wtxid(byte: u8) -> Wtxid {
    Wtxid::from(Hash256::from_le_bytes(&[byte; 32]))
}

fn fresh_node_id() -> u64 {
    let (tx, _rx) = bounded::<crate::QueuedFrame>(1);
    PeerLease::new(tx).node_id()
}

fn fake_peers(count: usize) -> (Vec<FakePeer>, Vec<u64>) {
    let mut peers = Vec::with_capacity(count);
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let id = fresh_node_id();
        peers.push(FakePeer {
            node_id: id,
            capacity: 64,
        });
        ids.push(id);
    }
    (peers, ids)
}

#[test]
fn pending_local_broadcast_survives_absent_peers_and_saturation() {
    let gateway = relay_identity_gateway();
    let (local, _) = admit_live_tx(21, &gateway);
    let mut peer_tx = (*local).clone();
    peer_tx.inputs[0].previous_output.txid = dummy_txid(22);
    gateway
        .insert_entry(
            relay_identity_peer(),
            bitcoin_rs_mempool::MempoolEntry::new(Arc::new(peer_tx), 100, 10_000, 1, 0, 0),
        )
        .expect("peer member");
    let sink = FakeSink::new(Vec::new());
    let mut cursor = None;
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(sink.log()[0].2.attempted, 0);
    let (mut peers, _) = fake_peers(1);
    peers[0].capacity = 0;
    *sink.peers.lock() = peers;
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(sink.log()[1].2.saturated, 1);
    sink.peers.lock()[0].capacity = 64;
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(sink.log()[2].2.attempted, 1);
    assert_eq!(gateway.read().unbroadcast_transactions().count(), 1);
    assert!(sink.log().iter().all(|row| row.0 == local.txid()));
    gateway.mark_broadcast(local.wtxid());
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(sink.log().len(), 3);
}

#[test]
fn pending_broadcast_batches_resume_by_key_after_completion_and_removal() {
    let gateway = relay_identity_gateway();
    for marker in 0_u32..1027 {
        let mut tx = (*relay_identity_tx()).clone();
        let mut hash = [0_u8; 32];
        hash[..4].copy_from_slice(&marker.to_le_bytes());
        tx.inputs[0].previous_output.txid = Txid(Hash256::from_le_bytes(&hash));
        admit_entry(&Arc::new(tx), &gateway);
    }
    let sink = FakeSink::new(Vec::new());
    let mut cursor = None;
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(sink.log().len(), INITIAL_BROADCAST_BATCH);
    let mut first = gateway
        .read()
        .unbroadcast_transactions()
        .take(INITIAL_BROADCAST_BATCH)
        .collect::<Vec<_>>();
    assert_eq!(cursor, first.last().map(|(_, wtxid, _)| *wtxid));
    let (removed_id, _, _) = first.pop().expect("full batch");
    let removed = gateway
        .read()
        .transaction_by_txid(&removed_id)
        .expect("live cursor entry");
    gateway.remove_for_block(
        AdmissionOrigin::Block,
        &[removed.as_ref()],
        &[removed_id],
        2,
        2,
    );
    for (_, wtxid, _) in first {
        gateway.mark_broadcast(wtxid);
    }
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(
        sink.log().len(),
        1027,
        "completion must not shift an offset past pending entries"
    );
    assert!(cursor.is_none());
    let remaining = gateway
        .read()
        .unbroadcast_transactions()
        .collect::<Vec<_>>();
    for (_, wtxid, _) in remaining {
        gateway.mark_broadcast(wtxid);
    }
    gateway
        .insert_entry(
            relay_identity_peer(),
            bitcoin_rs_mempool::MempoolEntry::new(removed, 100, 10_000, 1, 0, 0),
        )
        .expect("peer readmission");
    retry_initial_broadcast(&gateway, &sink, &mut cursor);
    assert_eq!(sink.log().len(), 1027);
    assert_eq!(
        gateway.read().len(),
        1027,
        "idle retry keeps ordinary membership"
    );
    gateway.clear(AdmissionOrigin::Block);
    assert_eq!(gateway.read().unbroadcast_transactions().count(), 0);
}

#[test]
fn relay_queue_saturation_drops_overflow() {
    let gateway = relay_identity_gateway();
    let (queue, rx) = TxRelayQueue::new(2);
    let live: Vec<(Txid, u64)> = (1..=3)
        .map(|marker| {
            let (tx, sequence) = admit_live_tx(marker, &gateway);
            (tx.txid(), sequence)
        })
        .collect();

    assert!(queue.announce(live[0].0, live_wtxid(&live[0].0, &gateway), None, live[0].1));
    assert!(queue.announce(live[1].0, live_wtxid(&live[1].0, &gateway), None, live[1].1));
    assert!(!queue.announce(live[2].0, live_wtxid(&live[2].0, &gateway), None, live[2].1));

    assert_eq!(queue.enqueued(), 2);
    assert_eq!(queue.dropped(), 1);

    let (peers, _ids) = fake_peers(1);
    let sink = FakeSink::new(peers);
    let processed = drain_relay_queue(&rx, &sink, &gateway);
    assert_eq!(processed, 2);
    assert_eq!(sink.log().len(), 2);
}

#[test]
fn drain_relay_queue_excludes_source_per_request() {
    let gateway = relay_identity_gateway();
    let (peers, ids) = fake_peers(3);
    let (queue, rx) = TxRelayQueue::new(8);
    let sink = FakeSink::new(peers);
    let live: Vec<(Txid, u64)> = (1..=3)
        .map(|marker| {
            let (tx, sequence) = admit_live_tx(marker, &gateway);
            (tx.txid(), sequence)
        })
        .collect();

    queue.announce(
        live[0].0,
        live_wtxid(&live[0].0, &gateway),
        Some(ids[0]),
        live[0].1,
    );
    queue.announce(
        live[1].0,
        live_wtxid(&live[1].0, &gateway),
        Some(ids[1]),
        live[1].1,
    );
    queue.announce(live[2].0, live_wtxid(&live[2].0, &gateway), None, live[2].1);

    let processed = drain_relay_queue(&rx, &sink, &gateway);
    assert_eq!(processed, 3);

    let log = sink.log();
    assert_eq!(log[0].1, Some(ids[0]));
    assert_eq!(log[0].2.excluded, 1);
    assert_eq!(log[1].1, Some(ids[1]));
    assert_eq!(log[1].2.excluded, 1);
    assert_eq!(log[2].1, None);
    assert_eq!(log[2].2.excluded, 0);
}

#[test]
fn drain_live_announcement_excludes_its_source() {
    let gateway = relay_identity_gateway();
    let (peers, ids) = fake_peers(3);
    let (queue, rx) = TxRelayQueue::new(8);
    let sink = FakeSink::new(peers);
    let (tx, sequence) = admit_live_tx(0xA1, &gateway);

    assert!(queue.announce(
        tx.txid(),
        live_wtxid(&tx.txid(), &gateway),
        Some(ids[1]),
        sequence
    ));

    let processed = drain_relay_queue(&rx, &sink, &gateway);
    assert_eq!(processed, 1);

    let log = sink.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].1, Some(ids[1]));
    assert_eq!(log[0].2.attempted, 3);
    assert_eq!(log[0].2.excluded, 1);
    assert_eq!(log[0].2.saturated, 0);
    let locked = sink.peers.lock();
    assert_eq!(locked[0].capacity, 63);
    assert_eq!(locked[1].capacity, 64);
    assert_eq!(locked[2].capacity, 63);
}

#[test]
fn drain_announcement_with_stale_source_excludes_nothing() {
    let gateway = relay_identity_gateway();
    let stale_source = fresh_node_id();
    let (peers, _ids) = fake_peers(2);
    let (queue, rx) = TxRelayQueue::new(8);
    let sink = FakeSink::new(peers);
    let (tx, sequence) = admit_live_tx(0xC3, &gateway);

    assert!(queue.announce(
        tx.txid(),
        live_wtxid(&tx.txid(), &gateway),
        Some(stale_source),
        sequence
    ));

    let processed = drain_relay_queue(&rx, &sink, &gateway);
    assert_eq!(processed, 1);

    let log = sink.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].1, Some(stale_source));
    assert_eq!(log[0].2.attempted, 2);
    assert_eq!(log[0].2.excluded, 0);
    assert_eq!(log[0].2.saturated, 0);
    let locked = sink.peers.lock();
    assert!(locked.iter().all(|peer| peer.capacity == 63));
}

#[test]
fn a_re_admitted_request_is_not_announced() {
    let (peers, _ids) = fake_peers(1);
    let sink = FakeSink::new(peers);
    let gateway = relay_identity_gateway();
    let (queue, rx) = TxRelayQueue::new(8);

    let (tx, sequence) = admit_live_tx(20, &gateway);
    queue.announce(tx.txid(), tx.wtxid(), None, sequence);

    gateway.clear(AdmissionOrigin::Block);
    let re_admitted = admit_entry(&tx, &gateway);
    assert_ne!(re_admitted, sequence);

    let processed = drain_relay_queue(&rx, &sink, &gateway);

    assert_eq!(processed, 1);
    assert!(
        sink.log().is_empty(),
        "a request whose admission epoch no longer matches must not be announced"
    );
}

#[test]
fn stale_queued_transaction_is_not_announced() {
    let (peers, _ids) = fake_peers(1);
    let sink = FakeSink::new(peers);
    let gateway = relay_identity_gateway();
    let (queue, rx) = TxRelayQueue::new(8);

    let (tx, sequence) = admit_live_tx(10, &gateway);
    queue.announce(tx.txid(), tx.wtxid(), None, sequence);

    gateway.clear(AdmissionOrigin::Block);

    let processed = drain_relay_queue(&rx, &sink, &gateway);

    assert_eq!(processed, 1);
    assert!(
        sink.log().is_empty(),
        "a removed transaction must not be announced"
    );
}

#[test]
fn relay_worker_announces_only_live_transactions() {
    let (peers, _ids) = fake_peers(1);
    let sink = FakeSink::new(peers);
    let log = Arc::clone(&sink.log);
    let gateway = relay_identity_gateway();
    let (queue, rx) = TxRelayQueue::new(8);

    let (live, live_seq) = admit_live_tx(11, &gateway);
    let (confirmed, confirmed_seq) = admit_live_tx(12, &gateway);
    queue.announce(live.txid(), live.wtxid(), None, live_seq);
    queue.announce(confirmed.txid(), confirmed.wtxid(), None, confirmed_seq);

    gateway.remove_for_block(
        AdmissionOrigin::Block,
        &[&*confirmed],
        &[confirmed.txid()],
        1,
        1,
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker = spawn_tx_relay_worker(sink, rx, Arc::downgrade(&gateway), Arc::clone(&shutdown))
        .expect("relay worker spawns");
    drop(queue);
    worker.join().expect("relay worker exits");

    let entries = log.lock().clone();
    assert_eq!(entries.len(), 1, "only the live tx is announced");
    assert_eq!(entries[0].0, live.txid());
}

#[test]
fn relay_worker_exits_when_queue_closes_with_observer_attached() {
    let gateway = relay_identity_gateway();
    let (queue, rx) = TxRelayQueue::new(1);
    gateway
        .attach_observer_leg(
            "relay",
            Arc::new(LocalTxRelayObserver::new(
                queue.clone(),
                Arc::downgrade(&gateway),
            )),
            BodyInterest::Metadata,
        )
        .expect("observer slot");
    let sink = FakeSink::new(Vec::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker = spawn_tx_relay_worker(sink, rx, Arc::downgrade(&gateway), Arc::clone(&shutdown))
        .expect("relay worker spawns");

    drop(queue);
    drop(gateway);
    let (joined_tx, joined_rx) = bounded(1);
    let joiner = std::thread::spawn(move || {
        let _ = joined_tx.send(worker.join().is_ok());
    });
    let queue_close = joined_rx.recv_timeout(std::time::Duration::from_secs(1));
    let exited_on_queue_close = matches!(&queue_close, Ok(true));
    if !exited_on_queue_close {
        shutdown.store(true, Ordering::Relaxed);
        let stopped = joined_rx.recv_timeout(std::time::Duration::from_secs(1));
        assert!(
            matches!(&stopped, Ok(true)),
            "explicit shutdown must still stop the relay worker"
        );
    }
    assert!(
        exited_on_queue_close,
        "dropping the last queue sender must stop the worker without shutdown"
    );
    joiner.join().expect("relay worker join coordinator exits");
}

#[test]
fn per_peer_pending_capacity_reports_saturation() {
    let id_a = fresh_node_id();
    let id_b = fresh_node_id();
    let sink = FakeSink::new(vec![
        FakePeer {
            node_id: id_a,
            capacity: 0,
        },
        FakePeer {
            node_id: id_b,
            capacity: 64,
        },
    ]);
    let outcome = sink.announce_inv(dummy_txid(0xE5), dummy_wtxid(0xE5), None, 0);

    assert_eq!(outcome.attempted, 2);
    assert_eq!(outcome.saturated, 1);
    assert_eq!(outcome.excluded, 0);
    let locked = sink.peers.lock();
    assert_eq!(
        locked[0].capacity, 0,
        "full pending queue capacity unchanged"
    );
    assert_eq!(locked[1].capacity, 63);
}

#[test]
fn disconnected_relay_worker_does_not_count_queue_saturation() {
    let (queue, receiver) = TxRelayQueue::new(1);
    drop(receiver);

    assert!(!queue.announce(dummy_txid(1), dummy_wtxid(1), None, 0));
    assert_eq!(queue.enqueued(), 0);
    assert_eq!(queue.dropped(), 0);
}

fn mutation_envelope(
    origin: AdmissionOrigin,
    txid: Hash256,
    outcome: MutationOutcome,
) -> MutationEnvelope {
    MutationEnvelope {
        origin,
        accepted_transactions: Vec::new(),
        result: bitcoin_rs_mempool::MutationResult {
            changes: vec![bitcoin_rs_mempool::MutationChange { txid, outcome }],
            sequence_base: 1,
        },
    }
}

#[test]
fn local_tx_relay_uses_committed_wtxid_and_ignores_peer_and_removed_entries() {
    use bitcoin_rs_mempool::{CompositeObserver, Mempool, MempoolEntry, MempoolLimits, PeerToken};
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use parking_lot::RwLock;

    let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        Some((Arc::new(CompositeObserver::new()), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ));
    let (queue, rx) = TxRelayQueue::new(8);
    let observer = Arc::new(LocalTxRelayObserver::new(queue, Arc::downgrade(&gateway)));
    gateway
        .attach_observer_leg("relay", observer.clone(), BodyInterest::Metadata)
        .expect("observer slot");
    let mut last_txid = Txid::default();
    for (marker, origin, should_announce) in [
        (1, AdmissionOrigin::Rpc, true),
        (2, AdmissionOrigin::Reorg, true),
        (4, AdmissionOrigin::Esplora, true),
        (5, AdmissionOrigin::Block, false),
        (6, AdmissionOrigin::Snapshot, false),
        (
            3,
            AdmissionOrigin::Peer(PeerToken {
                endpoint: Some(crate::PeerEndpoint::from(([127, 0, 0, 1], 8333))),
                addr: Some(crate::PeerEndpoint::from(([127, 0, 0, 1], 8333))),
                connection_id: 7,
            }),
            false,
        ),
    ] {
        let tx = Arc::new(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(dummy_txid(marker), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]),
            }],
            lock_time: LockTime::ZERO,
        });
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        assert_ne!(txid.as_bytes(), wtxid.as_bytes());
        gateway
            .insert_entry(origin, MempoolEntry::new(tx, 100, 10_000, 1, 0, 0))
            .expect("insert fixture");
        if should_announce {
            let announced = rx.try_recv().expect("local commit announces once");
            assert_eq!(
                (announced.txid, announced.wtxid, announced.source),
                (txid, wtxid, None)
            );
        }
        assert!(
            rx.try_recv().is_err(),
            "no duplicate or peer-origin observer announcement"
        );
        last_txid = txid;
    }
    gateway.clear(AdmissionOrigin::Rpc);
    observer.on_mutation(&mutation_envelope(
        AdmissionOrigin::Rpc,
        Hash256::from(last_txid),
        MutationOutcome::Accepted,
    ));
    assert!(
        rx.try_recv().is_err(),
        "a delayed notification cannot advertise a missing body"
    );
    let weak = Arc::downgrade(&gateway);
    drop(gateway);
    assert!(
        weak.upgrade().is_none(),
        "the observer must not retain its gateway"
    );
    observer.on_mutation(&mutation_envelope(
        AdmissionOrigin::Reorg,
        Hash256::from(last_txid),
        MutationOutcome::Accepted,
    ));
    assert!(rx.try_recv().is_err());
}

fn relay_identity_tx() -> Arc<bitcoin_rs_primitives::Tx> {
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    Arc::new(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(dummy_txid(90), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_fffd),
            witness: Witness::from_stack(vec![vec![1]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]),
        }],
        lock_time: LockTime::ZERO,
    })
}

fn admit_live_tx(marker: u8, gateway: &MempoolGateway) -> (Arc<bitcoin_rs_primitives::Tx>, u64) {
    use bitcoin_rs_primitives::OutPoint;

    let mut tx = (*relay_identity_tx()).clone();
    tx.inputs[0].previous_output = OutPoint::new(dummy_txid(marker), 0);
    let tx = Arc::new(tx);
    let sequence = admit_entry(&tx, gateway);
    (tx, sequence)
}

fn admit_entry(tx: &Arc<bitcoin_rs_primitives::Tx>, gateway: &MempoolGateway) -> u64 {
    use bitcoin_rs_mempool::MempoolEntry;

    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::clone(tx), 100, 10_000, 1, 0, 0),
        )
        .expect("admit live fixture")
        .sequence_of(0)
        .expect("a single insert carries one admission sequence")
}

fn live_wtxid(txid: &Txid, gateway: &MempoolGateway) -> Wtxid {
    gateway
        .read()
        .entry_by_txid(txid)
        .expect("fixture entry present")
        .wtxid
}
fn relay_identity_peer() -> AdmissionOrigin {
    AdmissionOrigin::Peer(bitcoin_rs_mempool::PeerToken {
        endpoint: Some(crate::PeerEndpoint::from(([127, 0, 0, 1], 8333))),
        addr: Some(crate::PeerEndpoint::from(([127, 0, 0, 1], 8333))),
        connection_id: 7,
    })
}

fn relay_identity_gateway() -> Arc<MempoolGateway> {
    use bitcoin_rs_mempool::{CompositeObserver, Mempool, MempoolLimits};
    Arc::new(MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        Some((Arc::new(CompositeObserver::new()), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ))
}

struct MutateBeforeLocalRelay {
    gateway: Weak<MempoolGateway>,
    next: Mutex<Option<bitcoin_rs_mempool::MempoolEntry>>,
    clear_first: bool,
}

impl MempoolObserver for MutateBeforeLocalRelay {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let Some(entry) = self.next.lock().take() else {
            return;
        };
        let gateway = self.gateway.upgrade().expect("fixture gateway lives");
        if self.clear_first {
            gateway.clear(AdmissionOrigin::Block);
        }
        gateway
            .insert_entry(relay_identity_peer(), entry)
            .expect("nested admission");
        let original = Txid(envelope.result.changes[0].txid);
        gateway
            .prioritise(original, 1)
            .expect("fee overlay does not change admission identity");
    }
}

fn delayed_relay_fixture(
    origin: AdmissionOrigin,
    original: Arc<bitcoin_rs_primitives::Tx>,
    next: Arc<bitcoin_rs_primitives::Tx>,
    clear_first: bool,
) -> (Arc<MempoolGateway>, Receiver<RelayRequest>) {
    use bitcoin_rs_mempool::MempoolEntry;
    let gateway = relay_identity_gateway();
    let (relay, rx) = TxRelayQueue::new(8);
    gateway
        .attach_observer_leg(
            "mutate-first",
            Arc::new(MutateBeforeLocalRelay {
                gateway: Arc::downgrade(&gateway),
                next: Mutex::new(Some(MempoolEntry::new(next, 100, 10_000, 2, 0, 0))),
                clear_first,
            }),
            BodyInterest::Metadata,
        )
        .expect("fixture observer slot");
    gateway
        .attach_observer_leg(
            "relay",
            Arc::new(LocalTxRelayObserver::new(relay, Arc::downgrade(&gateway))),
            BodyInterest::Metadata,
        )
        .expect("relay observer slot");
    gateway
        .insert_entry(origin, MempoolEntry::new(original, 100, 10_000, 1, 0, 0))
        .expect("local admission");
    (gateway, rx)
}

#[test]
fn delayed_local_relay_does_not_adopt_a_reinserted_body() {
    for origin in [
        AdmissionOrigin::Rpc,
        AdmissionOrigin::Esplora,
        AdmissionOrigin::Reorg,
    ] {
        for alternate_witness in [false, true] {
            let original = relay_identity_tx();
            let next = if alternate_witness {
                let mut variant = (*original).clone();
                variant.inputs[0].witness =
                    bitcoin_rs_primitives::Witness::from_stack(vec![vec![2]]);
                Arc::new(variant)
            } else {
                Arc::clone(&original)
            };
            assert_eq!(original.txid(), next.txid());
            assert_eq!(original.wtxid() != next.wtxid(), alternate_witness);
            let txid = original.txid();
            let (gateway, rx) = delayed_relay_fixture(origin, original, Arc::clone(&next), true);
            assert_eq!(
                gateway.read().entry_by_txid(&txid).map(|entry| entry.wtxid),
                Some(next.wtxid())
            );
            assert!(
                rx.try_recv().is_err(),
                "old local event cannot advertise the peer re-admission"
            );
        }
    }
}

#[test]
fn delayed_local_relay_survives_unrelated_mutations() {
    let original = relay_identity_tx();
    let mut unrelated = (*original).clone();
    unrelated.inputs[0].previous_output = bitcoin_rs_primitives::OutPoint::new(dummy_txid(91), 0);
    let (gateway, rx) = delayed_relay_fixture(
        AdmissionOrigin::Rpc,
        Arc::clone(&original),
        Arc::new(unrelated),
        false,
    );
    assert_eq!(gateway.read().sequence_number(), 2);
    let request = rx
        .try_recv()
        .expect("unrelated mutation does not invalidate the local admission");
    assert_eq!(
        (request.txid, request.wtxid, request.source),
        (original.txid(), original.wtxid(), None)
    );
    assert!(rx.try_recv().is_err());
}

#[test]
fn local_replacement_relay_uses_the_accepted_change_sequence() {
    use bitcoin_rs_mempool::{MempoolEntry, ReplacementCandidate};
    let gateway = relay_identity_gateway();
    let (relay, rx) = TxRelayQueue::new(8);
    gateway
        .attach_observer_leg(
            "relay",
            Arc::new(LocalTxRelayObserver::new(relay, Arc::downgrade(&gateway))),
            BodyInterest::Metadata,
        )
        .expect("observer slot");
    let original = relay_identity_tx();
    gateway
        .insert_entry(
            relay_identity_peer(),
            MempoolEntry::new(Arc::clone(&original), 100, 10_000, 1, 0, 0),
        )
        .expect("original peer admission");
    assert!(rx.try_recv().is_err());
    let mut replacement = (*original).clone();
    replacement.outputs[0].value = bitcoin_rs_primitives::Amount::from_sat(900);
    let replacement = Arc::new(replacement);
    let outcome = gateway
        .replace_transaction(
            AdmissionOrigin::Rpc,
            &ReplacementCandidate::new(Arc::clone(&replacement), 100, 11_000, 1_000)
                .with_sigop_cost(4),
            2,
            0,
        )
        .expect("local replacement");
    assert_eq!(outcome.len(), 2);
    assert!(matches!(
        outcome.changes[0].outcome,
        MutationOutcome::Removed(_)
    ));
    assert_eq!(outcome.changes[1].outcome, MutationOutcome::Accepted);
    let request = rx
        .try_recv()
        .expect("accepted change after removal is announced");
    assert_eq!(
        (request.txid, request.wtxid, request.source),
        (replacement.txid(), replacement.wtxid(), None)
    );
    assert!(rx.try_recv().is_err());
}
