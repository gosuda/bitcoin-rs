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
//! peer table from [`bitcoin_rs_p2p::PeerTable`] and sends one
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
//! **dropped** (the producer never blocks): a dropped `inv` is recovered by
//! the next peer's `inv`/`getdata` exchange, so relay stays best-effort and
//! admission never stalls. Per-peer outbound saturation follows the existing
//! p2p disconnect policy on [`bitcoin_rs_p2p::PeerLease::send`]: a peer whose
//! outbound queue is full is disconnected (its lease is cancelled), never
//! silently dropped while the connection remains live.
//!
//! # Integration one-liner
//!
//! The source peer's node id is only in scope at the tx-ingress consumer
//! (`source.connection_id().get()`), not in [`crate::mempool_observer`]
//! (the observer sees [`bitcoin_rs_mempool::MutationResult`] which carries
//! no per-connection attribution). The relay hook therefore belongs in the
//! tx-ingress accepted-only branch, replacing the current broadcast
//! `relay_tx` with:
//!
//! ```text
//! self.relay.announce(txid, tx.wtxid(), Some(source.connection_id().get()));
//! ```
//!
//! Wiring that line is out of scope for this file (it edits `tx_ingress.rs`);
//! the worker and queue here are ready to receive it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bitcoin_rs_p2p::Message;
use bitcoin_rs_primitives::{Txid, Wtxid};
use crossbeam_channel::{Receiver, Sender, TrySendError};

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
    /// The witness transaction id (reserved for BIP339 wtxid-relay; the
    /// current announcement uses `txid` to match the existing relay path).
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

/// Per-announce relay outcome reported by a [`RelaySink`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Peers considered for the announcement (all connected peers).
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
    fn announce_inv(&self, txid: Txid, exclude: Option<u64>) -> RelayOutcome;
}

/// Production [`RelaySink`] over the shared peer table.
///
/// Borrows the shared table, so the relay worker sees peer
/// connect/disconnect/reconnect as the listener mutates sessions.
pub struct PeerRelaySink {
    peers: Arc<bitcoin_rs_p2p::PeerTable>,
}

impl PeerRelaySink {
    /// Wraps the shared peer table.
    #[must_use]
    pub fn new(peers: Arc<bitcoin_rs_p2p::PeerTable>) -> Self {
        Self { peers }
    }
}

impl RelaySink for PeerRelaySink {
    fn announce_inv(&self, txid: Txid, exclude: Option<u64>) -> RelayOutcome {
        use bitcoin::p2p::message_blockdata::Inventory;

        let inv = Inventory::Transaction(bitcoin::hashes::Hash::from_byte_array(*txid.as_bytes()));
        let message = Message::Inv(vec![inv]);

        let mut outcome = RelayOutcome::default();
        self.peers.for_each_lease(|addr, lease| {
            outcome.attempted += 1;
            if exclude.is_some_and(|id| lease.node_id() == id) {
                outcome.excluded += 1;
                return;
            }
            if let Err(error) = lease.send(message.clone()) {
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
        sink.announce_inv(request.txid, request.source);
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
                        sink.announce_inv(request.txid, request.source);
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
    use bitcoin_rs_p2p::PeerLease;
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
        fn announce_inv(&self, txid: Txid, exclude: Option<u64>) -> RelayOutcome {
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

        let outcome = sink.announce_inv(txid, Some(ids[1]));

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

        let outcome = sink.announce_inv(txid, None);

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

        let outcome = sink.announce_inv(txid, Some(stale_source));

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

        let outcome = sink.announce_inv(replacement, Some(ids[2]));

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
        let outcome = sink.announce_inv(dummy_txid(0xE5), None);

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

        let peers = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        peers.register(addr_a, lease_a);
        peers.register(addr_b, lease_b);
        let sink = PeerRelaySink::new(peers);

        let txid = dummy_txid(0xF6);
        let outcome = sink.announce_inv(txid, Some(source_id));

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
    fn relay_request_new_carries_fields() {
        let id = fresh_node_id();
        let req = RelayRequest::new(dummy_txid(1), dummy_wtxid(2), Some(id));
        assert_eq!(req.txid, dummy_txid(1));
        assert_eq!(req.wtxid, dummy_wtxid(2));
        assert_eq!(req.source, Some(id));
    }
}
