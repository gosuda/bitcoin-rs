//! Outbound transaction relay worker.
//!
//! Announces mempool-accepted transactions to connected peers as `inv`
//! messages, **excluding the peer that delivered the transaction** (by its
//! node id). Bitcoin Core never re-advertises a transaction to the peer it
//! just received it from; this worker encodes that policy.
//!
//! # Architecture
//!
//! [`TxRelayQueue`] is the producer side: a bounded crossbeam channel of
//! [`RelayRequest`]s plus drop accounting. The admission path calls
//! [`TxRelayQueue::announce`] without blocking — relay is best-effort and
//! must never stall mempool admission.
//!
//! [`RelaySink`] is the consumer seam: [`PeerRelaySink`] iterates the live
//! peer table from [`crate::PeerTable`] and sends one
//! `inv` per non-excluded peer. A test fake records announcements without a
//! real connection, so the exclude/saturation logic is unit-testable without
//! a running node.
//!
//! [`spawn_tx_relay_worker`] drains the queue on a dedicated thread; tests
//! call [`drain_relay_queue`] synchronously for deterministic fixtures.
//!
//! # Queue saturation
//!
//! The relay queue is bounded. When full, the newest announcement is
//! **dropped** (the producer never blocks). Later inventory exchanges may
//! advertise it again; relay stays best-effort and admission never stalls.
//! Per-peer outbound saturation follows the existing
//! p2p disconnect policy on [`crate::PeerLease::send`]: a peer whose
//! outbound queue is full is disconnected (its lease is cancelled), never
//! silently dropped while the connection remains live.
//!
//! Peer-origin accepts are announced by the ingress caller after the gateway
//! returns a committed admission. RPC and reorg accepts announce through
//! [`LocalTxRelayObserver`] on the same queue. These triggers intentionally
//! retain their separate timing. Local notifications look up the accepted
//! entry's real wtxid only while that acceptance remains resident. The
//! gateway reference is weak so its observer cannot retain the gateway.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::Message;
use bitcoin_rs_mempool::{
    AdmissionOrigin, MempoolGateway, MempoolObserver, MutationEnvelope, MutationOutcome,
};
use bitcoin_rs_primitives::{Txid, Wtxid};
use crossbeam_channel::{Receiver, Sender, TrySendError};

/// Default maximum pending transaction announcements.
pub const DEFAULT_TX_RELAY_QUEUE_CAPACITY: usize = 1024;

/// Drain poll interval when the relay queue is empty.
const RELAY_POLL: Duration = Duration::from_millis(100);

/// One accepted transaction awaiting `inv` announcement.
///
/// `source` is the delivering peer's node id to exclude from the
/// announcement, or `None` for a locally-injected transaction (RPC
/// `sendrawtransaction`), which is announced to every connected peer.
#[derive(Clone, Copy, Debug)]
pub struct RelayRequest {
    /// The transaction id to advertise in the `inv` vector.
    pub txid: Txid,
    /// The accepted transaction's actual witness identifier for BIP339 peers.
    pub wtxid: Wtxid,
    /// The delivering peer's node id to exclude, or `None` for local
    /// injection.
    pub source: Option<u64>,
}

impl RelayRequest {
    /// Builds a relay request for an accepted transaction.
    #[must_use]
    pub fn new(txid: Txid, wtxid: Wtxid, source: Option<u64>) -> Self {
        Self {
            txid,
            wtxid,
            source,
        }
    }
}

/// Bounded producer side of the relay queue.
///
/// Cloneable and cheap to share: the underlying crossbeam [`Sender`] is
/// cloneable. [`announce`](Self::announce) never blocks — on a full queue the
/// request is dropped and [`dropped`](Self::dropped) is incremented.
#[derive(Clone)]
pub struct TxRelayQueue {
    tx: Sender<RelayRequest>,
    enqueued: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl TxRelayQueue {
    /// Creates a bounded relay queue of `capacity` pending announcements and
    /// returns the queue plus the receiver the worker drains.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Receiver<RelayRequest>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        let queue = Self {
            tx,
            enqueued: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (queue, rx)
    }

    /// Enqueues one announcement without blocking.
    ///
    /// Returns `true` if the request was queued, `false` if the queue was
    /// full (the request is dropped) or the worker receiver has been dropped.
    /// Admission callers ignore the return value: relay is best-effort.
    pub fn announce(&self, txid: Txid, wtxid: Wtxid, source: Option<u64>) -> bool {
        let request = RelayRequest::new(txid, wtxid, source);
        match self.tx.try_send(request) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Total announcements successfully enqueued since construction.
    #[must_use]
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    /// Total announcements dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Announces locally-injected accepted transactions (`sendrawtransaction`,
/// reorg re-admission) to every connected peer.
///
/// Peer-origin accepts are announced by their ingress caller after admission
/// returns a committed outcome. This observer preserves the existing RPC and
/// reorg publication trigger, including their lack of a source peer to exclude.
pub struct LocalTxRelayObserver {
    relay: TxRelayQueue,
    gateway: Weak<MempoolGateway>,
}

impl LocalTxRelayObserver {
    /// Relays accepted local mutations through `relay`.
    #[must_use]
    pub fn new(relay: TxRelayQueue, gateway: Weak<MempoolGateway>) -> Self {
        Self { relay, gateway }
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
        let Some(gateway) = self.gateway.upgrade() else {
            return;
        };
        for (index, change) in envelope.result.changes.iter().enumerate() {
            if !matches!(change.outcome, MutationOutcome::Accepted) {
                continue;
            }
            let txid = Txid(change.txid);
            let Some(sequence) = envelope.result.sequence_of(index) else {
                continue;
            };
            let wtxid = gateway
                .read()
                .entry_by_txid_at_sequence(&txid, sequence)
                .map(|entry| entry.wtxid);
            if let Some(wtxid) = wtxid {
                self.relay.announce(txid, wtxid, None);
            }
        }
    }
}

/// Per-announce relay outcome reported by a [`RelaySink`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Handshake-complete peers considered for the announcement.
    pub attempted: usize,
    /// Peers skipped because they were the source of the transaction.
    pub excluded: usize,
    /// Peers whose outbound queue was saturated or already disconnected; the
    /// existing p2p policy disconnects such peers rather than dropping the
    /// message silently.
    pub saturated: usize,
}

/// Consumer seam for the relay worker.
///
/// [`PeerRelaySink`] is the production implementation; tests supply a fake
/// that records announcements without a live connection.
pub trait RelaySink: Send + Sync {
    /// Announces `txid` as a transaction `inv` to every connected peer
    /// except the one identified by `exclude` (if any). Returns the
    /// per-announce outcome.
    fn announce_inv(&self, txid: Txid, wtxid: Wtxid, exclude: Option<u64>) -> RelayOutcome;
}

/// Production [`RelaySink`] over the shared peer table.
///
/// Borrows the shared table, so the relay worker sees peer
/// connect/disconnect/reconnect and their published BIP339 preference. A
/// handshaking lease receives no inventory: choosing before negotiation could
/// queue `MSG_TX` for a connection that later requests `MSG_WTX`.
pub struct PeerRelaySink {
    peers: Arc<crate::PeerTable>,
}

impl PeerRelaySink {
    /// Wraps the shared peer table.
    #[must_use]
    pub fn new(peers: Arc<crate::PeerTable>) -> Self {
        Self { peers }
    }
}

impl RelaySink for PeerRelaySink {
    fn announce_inv(&self, txid: Txid, wtxid: Wtxid, exclude: Option<u64>) -> RelayOutcome {
        use bitcoin::p2p::message_blockdata::Inventory;

        let mut outcome = RelayOutcome::default();
        self.peers.for_each_ready_lease(|addr, lease, info| {
            outcome.attempted += 1;
            if exclude.is_some_and(|id| lease.node_id() == id) {
                outcome.excluded += 1;
                return;
            }
            let inv = if info.wtxid_relay {
                Inventory::WTx(bitcoin::hashes::Hash::from_byte_array(*wtxid.as_bytes()))
            } else {
                Inventory::Transaction(bitcoin::hashes::Hash::from_byte_array(*txid.as_bytes()))
            };
            if let Err(error) = lease.send(Message::Inv(vec![inv])) {
                // Saturation or a cancelled/disconnected lease: the existing
                // p2p policy disconnects this peer (PeerLease::send cancels
                // the lease on Full/Disconnected). Count it and continue;
                // the listener reaps the dead connection.
                tracing::debug!(
                    peer_addr = %addr,
                    %error,
                    "relay tx inv saturated/disconnected peer; p2p will disconnect"
                );
                outcome.saturated += 1;
            }
        });
        outcome
    }
}

/// Synchronously drains every currently-queued relay request into `sink`.
///
/// Returns the number of requests processed. The worker loop calls this per
/// item; tests call it to flush the queue deterministically.
pub fn drain_relay_queue(rx: &Receiver<RelayRequest>, sink: &dyn RelaySink) -> usize {
    let mut processed = 0;
    while let Ok(request) = rx.try_recv() {
        sink.announce_inv(request.txid, request.wtxid, request.source);
        processed += 1;
    }
    processed
}

/// Spawns the single tx-relay worker thread.
///
/// The thread drains [`RelayRequest`]s from `rx` and announces each through
/// `sink`, excluding the source connection. It exits when `shutdown` is set
/// or the queue sender is dropped.
pub fn spawn_tx_relay_worker<S: RelaySink + 'static>(
    sink: S,
    rx: Receiver<RelayRequest>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-relay".to_owned())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match rx.recv_timeout(RELAY_POLL) {
                    Ok(request) => {
                        sink.announce_inv(request.txid, request.wtxid, request.source);
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::PeerLease;
    use bitcoin_rs_primitives::Hash256;
    use crossbeam_channel::bounded;
    use parking_lot::Mutex;
    use std::net::SocketAddr;

    /// A peer in the fake sink: a node id and a remaining send budget.
    #[derive(Clone)]
    struct FakePeer {
        node_id: u64,
        capacity: usize,
    }

    /// Test sink that records announcements without a live connection.
    struct FakeSink {
        peers: Mutex<Vec<FakePeer>>,
        log: Mutex<Vec<(Txid, Option<u64>, RelayOutcome)>>,
    }

    impl FakeSink {
        fn new(peers: Vec<FakePeer>) -> Self {
            Self {
                peers: Mutex::new(peers),
                log: Mutex::new(Vec::new()),
            }
        }

        fn log(&self) -> Vec<(Txid, Option<u64>, RelayOutcome)> {
            self.log.lock().clone()
        }
    }

    impl RelaySink for FakeSink {
        fn announce_inv(&self, txid: Txid, _wtxid: Wtxid, exclude: Option<u64>) -> RelayOutcome {
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
                    // Simulate a saturated outbound queue: the p2p layer
                    // would disconnect this peer.
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

    fn publish_peer(
        peers: &crate::PeerTable,
        addr: SocketAddr,
        lease: &PeerLease,
        wtxid_relay: bool,
    ) {
        let mut info = crate::PeerInfo::inbound_from_version(
            addr,
            addr,
            &crate::handshake::version_message(1, 0),
            0,
            0,
            Arc::new(crate::PeerCounters::default()),
        );
        info.wtxid_relay = wtxid_relay;
        assert!(peers.publish_info(addr, lease, info));
    }

    /// Allocates a fresh process-unique node id via a throwaway lease.
    /// `ConnectionId` has no public constructor, so tests obtain real ids
    /// the same way production code does — from `PeerLease::node_id()`.
    fn fresh_node_id() -> u64 {
        let (tx, _rx) = bounded::<Message>(1);
        PeerLease::new(tx).node_id()
    }

    /// Builds `count` fake peers with generous capacity and returns the
    /// peers plus their node ids, so tests can exclude a specific peer.
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
    fn announce_excludes_source_peer() {
        let (peers, ids) = fake_peers(3);
        let sink = FakeSink::new(peers);
        let txid = dummy_txid(0xA1);

        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), Some(ids[1]));

        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.excluded, 1);
        assert_eq!(outcome.saturated, 0);
        // The remaining two peers each consumed one unit of capacity; the
        // source peer's capacity is unchanged.
        let locked = sink.peers.lock();
        assert_eq!(locked[0].capacity, 63);
        assert_eq!(
            locked[1].capacity, 64,
            "source peer must not be announced to"
        );
        assert_eq!(locked[2].capacity, 63);
    }

    #[test]
    fn announce_to_all_when_source_is_none() {
        let (peers, _ids) = fake_peers(3);
        let sink = FakeSink::new(peers);
        let txid = dummy_txid(0xB2);

        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), None);

        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.excluded, 0);
        assert_eq!(outcome.saturated, 0);
        let locked = sink.peers.lock();
        assert!(locked.iter().all(|p| p.capacity == 63));
    }

    #[test]
    fn reconnect_uses_new_node_id_and_old_source_excludes_nothing() {
        // A peer disconnects and reconnects with a fresh node id. The old
        // source id is no longer in the peer set, so an announcement
        // excluding the stale source reaches every live peer.
        let stale_source = fresh_node_id();
        let (peers, _ids) = fake_peers(2);
        let sink = FakeSink::new(peers);
        let txid = dummy_txid(0xC3);

        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), Some(stale_source));

        assert_eq!(outcome.attempted, 2);
        assert_eq!(outcome.excluded, 0, "stale source id no longer connected");
        assert_eq!(outcome.saturated, 0);
        let locked = sink.peers.lock();
        assert!(locked.iter().all(|p| p.capacity == 63));
    }

    #[test]
    fn replacement_txid_is_announced_excluding_source() {
        // A replacement transaction has a fresh txid replacing a same-input
        // mempool entry. Relay announces the new txid to every peer except
        // the one that submitted it.
        let (peers, ids) = fake_peers(3);
        let sink = FakeSink::new(peers);
        let replacement = dummy_txid(0xD4);

        let outcome = sink.announce_inv(replacement, dummy_wtxid(0xF0), Some(ids[2]));

        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.excluded, 1);
        assert_eq!(outcome.saturated, 0);
        let entry = &sink.log()[0];
        assert_eq!(entry.0, replacement);
        assert_eq!(entry.1, Some(ids[2]));
    }

    #[test]
    fn relay_queue_saturation_drops_overflow() {
        let (queue, rx) = TxRelayQueue::new(2);

        assert!(queue.announce(dummy_txid(1), dummy_wtxid(1), None));
        assert!(queue.announce(dummy_txid(2), dummy_wtxid(2), None));
        // Queue is full: the third announcement is dropped, not blocked.
        assert!(!queue.announce(dummy_txid(3), dummy_wtxid(3), None));

        assert_eq!(queue.enqueued(), 2);
        assert_eq!(queue.dropped(), 1);

        // The dropped request never reaches the sink.
        let (peers, _ids) = fake_peers(1);
        let sink = FakeSink::new(peers);
        let processed = drain_relay_queue(&rx, &sink);
        assert_eq!(processed, 2);
        assert_eq!(sink.log().len(), 2);
    }

    #[test]
    fn drain_relay_queue_excludes_source_per_request() {
        let (peers, ids) = fake_peers(3);
        let (queue, rx) = TxRelayQueue::new(8);
        let sink = FakeSink::new(peers);

        queue.announce(dummy_txid(1), dummy_wtxid(1), Some(ids[0]));
        queue.announce(dummy_txid(2), dummy_wtxid(2), Some(ids[1]));
        queue.announce(dummy_txid(3), dummy_wtxid(3), None);

        let processed = drain_relay_queue(&rx, &sink);
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
    fn per_peer_saturation_counts_saturated_not_dropped() {
        // One peer has capacity 0 (saturated outbound queue). The
        // announcement is counted as saturated for that peer; the other
        // peer still receives it. The p2p layer disconnects the saturated
        // peer rather than silently dropping the message.
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
        let outcome = sink.announce_inv(dummy_txid(0xE5), dummy_wtxid(0xE5), None);

        assert_eq!(outcome.attempted, 2);
        assert_eq!(outcome.saturated, 1);
        assert_eq!(outcome.excluded, 0);
        let locked = sink.peers.lock();
        assert_eq!(locked[0].capacity, 0, "saturated peer capacity unchanged");
        assert_eq!(locked[1].capacity, 63);
    }

    #[test]
    fn peer_relay_sink_excludes_source_by_node_id() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::p2p::message_blockdata::Inventory;

        // End-to-end with real PeerLease objects: build the production peer
        // map, announce excluding one peer's node id, and confirm only the
        // other peer's outbound channel receives the inv.
        let addr_a: SocketAddr = "127.0.0.1:1".parse().expect("valid addr");
        let addr_b: SocketAddr = "127.0.0.1:2".parse().expect("valid addr");
        let (tx_a, rx_a) = bounded::<Message>(8);
        let (tx_b, rx_b) = bounded::<Message>(8);
        let lease_a = PeerLease::new(tx_a);
        let lease_b = PeerLease::new(tx_b);
        let source_id = lease_a.node_id();

        let peers = Arc::new(crate::PeerTable::new());
        peers.register(addr_a, lease_a.clone());
        peers.register(addr_b, lease_b.clone());
        publish_peer(&peers, addr_a, &lease_a, false);
        publish_peer(&peers, addr_b, &lease_b, false);
        let sink = PeerRelaySink::new(peers);

        let txid = dummy_txid(0xF6);
        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), Some(source_id));

        assert_eq!(outcome.attempted, 2);
        assert_eq!(outcome.excluded, 1);
        assert_eq!(outcome.saturated, 0);

        // The source peer (a) must not receive the inv; the other peer (b)
        // must receive exactly one inv carrying the announced txid.
        assert!(
            rx_a.try_recv().is_err(),
            "source peer must not be announced to"
        );
        let msg_b = rx_b.try_recv().expect("non-source peer receives inv");
        match msg_b {
            Message::Inv(items) => {
                assert_eq!(items.len(), 1, "one inventory vector per announce");
                match items[0] {
                    Inventory::Transaction(hash) => {
                        assert_eq!(hash.as_byte_array(), txid.as_bytes());
                    }
                    _ => panic!("expected a Transaction inventory vector"),
                }
            }
            other => panic!("expected Inv, got {other:?}"),
        }
    }

    #[test]
    fn relay_waits_for_handshake_and_selects_the_peers_inventory_type() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::p2p::message_blockdata::Inventory;

        let peers = Arc::new(crate::PeerTable::new());
        let mut connections = Vec::new();
        for port in 1..=4 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            let (sender, receiver) = bounded(4);
            let lease = PeerLease::new(sender);
            peers.register(addr, lease.clone());
            if port != 4 {
                publish_peer(&peers, addr, &lease, port != 2);
            }
            connections.push((addr, lease, receiver));
        }
        let txid = dummy_txid(1);
        let wtxid = dummy_wtxid(2);
        let source = connections[0].1.node_id();
        let sink = PeerRelaySink::new(Arc::clone(&peers));
        let outcome = sink.announce_inv(txid, wtxid, Some(source));
        assert_eq!((outcome.attempted, outcome.excluded), (3, 1));
        assert!(connections[0].2.try_recv().is_err());
        assert_eq!(
            connections[1].2.try_recv().expect("legacy announcement"),
            Message::Inv(vec![Inventory::Transaction(
                bitcoin::Txid::from_byte_array(*txid.as_bytes())
            ),])
        );
        let witness_inv = Message::Inv(vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(
            *wtxid.as_bytes(),
        ))]);
        assert_eq!(
            connections[2].2.try_recv().expect("BIP339 announcement"),
            witness_inv
        );
        assert!(
            connections[3].2.try_recv().is_err(),
            "no legacy packet may wait through negotiation"
        );

        publish_peer(&peers, connections[3].0, &connections[3].1, true);
        sink.announce_inv(txid, wtxid, Some(source));
        assert_eq!(
            connections[3]
                .2
                .try_recv()
                .expect("newly ready BIP339 peer"),
            witness_inv
        );

        // A replacement must neither inherit the old negotiation nor be
        // excluded by its retired source identity.
        let (sender, receiver) = bounded(2);
        let replacement = PeerLease::new(sender);
        peers.register(connections[0].0, replacement.clone());
        sink.announce_inv(txid, wtxid, Some(source));
        assert!(receiver.try_recv().is_err());
        publish_peer(&peers, connections[0].0, &replacement, false);
        sink.announce_inv(txid, wtxid, Some(source));
        assert_eq!(
            receiver
                .try_recv()
                .expect("replacement legacy announcement"),
            Message::Inv(vec![Inventory::Transaction(
                bitcoin::Txid::from_byte_array(*txid.as_bytes())
            ),])
        );
    }

    #[test]
    fn peer_relay_reaches_replacement_and_cancels_only_saturated_peer() {
        let peers = Arc::new(crate::PeerTable::new());
        let source_addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let saturated_addr = SocketAddr::from(([127, 0, 0, 1], 8334));
        let (old_sender, old_receiver) = bounded(1);
        let old = PeerLease::new(old_sender);
        let stale_source_id = old.node_id();
        peers.register(source_addr, old);
        let (current_sender, current_receiver) = bounded(1);
        let current = PeerLease::new(current_sender);
        peers.register(source_addr, current.clone());
        publish_peer(&peers, source_addr, &current, false);
        let (saturated_sender, _saturated_receiver) = bounded(1);
        let saturated = PeerLease::new(saturated_sender);
        assert!(saturated.send(Message::Ping(1)).is_ok());
        peers.register(saturated_addr, saturated.clone());
        publish_peer(&peers, saturated_addr, &saturated, true);

        let outcome = PeerRelaySink::new(peers).announce_inv(
            dummy_txid(1),
            dummy_wtxid(1),
            Some(stale_source_id),
        );

        assert_eq!(outcome.attempted, 2);
        assert_eq!(outcome.excluded, 0);
        assert_eq!(outcome.saturated, 1);
        assert!(old_receiver.try_recv().is_err());
        assert!(matches!(current_receiver.try_recv(), Ok(Message::Inv(_))));
        assert!(!current.is_cancelled());
        assert!(saturated.is_cancelled());
    }

    #[test]
    fn disconnected_relay_worker_does_not_count_queue_saturation() {
        let (queue, receiver) = TxRelayQueue::new(1);
        drop(receiver);

        assert!(!queue.announce(dummy_txid(1), dummy_wtxid(1), None));
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
            result: bitcoin_rs_mempool::MutationResult {
                changes: vec![bitcoin_rs_mempool::MutationChange { txid, outcome }],
                sequence_base: 1,
            },
        }
    }

    #[test]
    fn local_tx_relay_uses_committed_wtxid_and_ignores_peer_and_removed_entries() {
        use bitcoin_rs_mempool::{
            CompositeObserver, Mempool, MempoolEntry, MempoolLimits, PeerToken,
        };
        use bitcoin_rs_primitives::{
            Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
        };
        use parking_lot::RwLock;

        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let gateway = MempoolGateway::shared_with(pool, Arc::new(CompositeObserver::new()));
        let (queue, rx) = TxRelayQueue::new(8);
        let observer = Arc::new(LocalTxRelayObserver::new(queue, Arc::downgrade(&gateway)));
        gateway
            .attach_observer_leg("relay", observer.clone())
            .expect("observer slot");
        let mut last_txid = Txid::default();
        for (marker, origin) in [
            (1, AdmissionOrigin::Rpc),
            (2, AdmissionOrigin::Reorg),
            (
                3,
                AdmissionOrigin::Peer(PeerToken {
                    addr: SocketAddr::from(([127, 0, 0, 1], 8333)),
                    connection_id: 7,
                }),
            ),
        ] {
            let tx = Arc::new(Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(dummy_txid(marker), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::from_stack(vec![vec![0x51]]),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]),
                }],
                lock_time: LockTime::from_consensus(0),
            });
            let txid = tx.txid();
            let wtxid = tx.wtxid();
            assert_ne!(txid.as_bytes(), wtxid.as_bytes());
            gateway
                .insert_entry(origin, MempoolEntry::new(tx, 100, 10_000, 1, 0))
                .expect("insert fixture");
            if matches!(origin, AdmissionOrigin::Rpc | AdmissionOrigin::Reorg) {
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
            lock_time: LockTime::from_consensus(0),
        })
    }

    fn relay_identity_peer() -> AdmissionOrigin {
        AdmissionOrigin::Peer(bitcoin_rs_mempool::PeerToken {
            addr: SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id: 7,
        })
    }

    fn relay_identity_gateway() -> Arc<MempoolGateway> {
        use bitcoin_rs_mempool::{CompositeObserver, Mempool, MempoolLimits};
        Arc::new(MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            Some(Arc::new(CompositeObserver::new())),
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
                    next: Mutex::new(Some(MempoolEntry::new(next, 100, 10_000, 2, 0))),
                    clear_first,
                }),
            )
            .expect("fixture observer slot");
        gateway
            .attach_observer_leg(
                "relay",
                Arc::new(LocalTxRelayObserver::new(relay, Arc::downgrade(&gateway))),
            )
            .expect("relay observer slot");
        gateway
            .insert_entry(origin, MempoolEntry::new(original, 100, 10_000, 1, 0))
            .expect("local admission");
        (gateway, rx)
    }

    // P2P-01 / MPL-01: callbacks may re-enter the gateway before a later leg.
    // An old local event must not borrow a new peer admission's identity.
    #[test]
    fn delayed_local_relay_does_not_adopt_a_reinserted_body() {
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Reorg] {
            for alternate_witness in [false, true] {
                let original = relay_identity_tx();
                let next = if alternate_witness {
                    let mut variant = (*original).clone();
                    variant.inputs[0].witness = bitcoin_rs_primitives::Witness::from_stack(vec![vec![2]]);
                    Arc::new(variant)
                } else {
                    // Same allocation, not merely equal bytes: Arc identity is
                    // not an admission identity either.
                    Arc::clone(&original)
                };
                assert_eq!(original.txid(), next.txid());
                assert_eq!(original.wtxid() != next.wtxid(), alternate_witness);
                let txid = original.txid();
                let (gateway, rx) =
                    delayed_relay_fixture(origin, original, Arc::clone(&next), true);
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
        unrelated.inputs[0].previous_output =
            bitcoin_rs_primitives::OutPoint::new(dummy_txid(91), 0);
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
            )
            .expect("observer slot");
        let original = relay_identity_tx();
        gateway
            .insert_entry(
                relay_identity_peer(),
                MempoolEntry::new(Arc::clone(&original), 100, 10_000, 1, 0),
            )
            .expect("original peer admission");
        assert!(rx.try_recv().is_err());
        let mut replacement = (*original).clone();
        replacement.outputs[0].value = bitcoin_rs_primitives::Amount::from_sat(900);
        let replacement = Arc::new(replacement);
        let outcome = gateway
            .replace_transaction(
                AdmissionOrigin::Rpc,
                ReplacementCandidate::new(Arc::clone(&replacement), 100, 11_000, 1_000),
                2,
                0,
                4,
            )
            .expect("local replacement");
        assert_eq!(outcome.mutation().len(), 2);
        assert!(matches!(
            outcome.mutation().changes[0].outcome,
            MutationOutcome::Removed(_)
        ));
        assert_eq!(
            outcome.mutation().changes[1].outcome,
            MutationOutcome::Accepted
        );
        let request = rx
            .try_recv()
            .expect("accepted change after removal is announced");
        assert_eq!(
            (request.txid, request.wtxid, request.source),
            (replacement.txid(), replacement.wtxid(), None)
        );
        assert!(rx.try_recv().is_err());
    }
}
