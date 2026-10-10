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
//! [`PeerRelaySink`] queues identities and admission epochs in the shared
//! transaction-policy owner. Its timer drains fee-filtered, dependency-ordered
//! batches after randomized per-connection deadlines; known inventory and
//! source exclusion prevent repeats. A delayed item is checked against the
//! gateway again before enqueueing the wire message. A later removal can
//! still race the peer's eventual `getdata`, which then answers `notfound`.
//!
//! [`spawn_tx_relay_worker`] drives both request deadlines and relay timers.
//! Admission callbacks only write the bounded producer queue and never wait
//! for a peer or a timer.
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

#[cfg(test)]
use crate::{Message, PeerLease};
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
#[derive(Clone, Copy, Debug)]
pub struct RelayRequest {
    /// The transaction id to advertise in the `inv` vector.
    pub txid: Txid,
    /// The accepted transaction's actual witness identifier for BIP339 peers.
    pub wtxid: Wtxid,
    /// The delivering peer's node id to exclude, or `None` for local
    /// injection.
    pub source: Option<u64>,
    /// The mempool admission epoch the request was queued under, from
    /// [`bitcoin_rs_mempool::mutation::MutationResult::sequence_of`]. Removal
    /// and re-admission of the same body invalidates the epoch, so the
    /// send-time check matches the exact admission that queued the request.
    pub sequence: u64,
}

impl RelayRequest {
    /// Builds a relay request for an accepted transaction.
    #[must_use]
    pub fn new(txid: Txid, wtxid: Wtxid, source: Option<u64>, sequence: u64) -> Self {
        Self {
            txid,
            wtxid,
            source,
            sequence,
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
    pub fn announce(&self, txid: Txid, wtxid: Wtxid, source: Option<u64>, sequence: u64) -> bool {
        let request = RelayRequest::new(txid, wtxid, source, sequence);
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
/// Esplora `POST /tx`, reorg re-admission) to every connected peer.
///
/// Peer-origin accepts are announced by their ingress caller after admission
/// returns a committed outcome. This observer publishes RPC, Esplora and reorg
/// acceptances, which have no source peer to exclude.
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
            AdmissionOrigin::Rpc | AdmissionOrigin::Esplora | AdmissionOrigin::Reorg
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
                self.relay.announce(txid, wtxid, None, sequence);
            }
        }
    }
}

/// Synchronous announcement admission reported by a [`RelaySink`].
///
/// Deferred inventory delivery occurs during `poll`; its send failures cannot
/// be reported in an earlier admission result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Handshake-complete peers considered for the announcement.
    pub attempted: usize,
    /// Peers skipped because they were the source of the transaction.
    pub excluded: usize,
    /// Peers whose pending announcement queue could not accept this identity
    /// because its per-peer or global budget was saturated. This counts queue
    /// admission failures; later transport failures are logged when polled.
    pub saturated: usize,
}

/// Consumer seam for the relay worker.
pub trait RelaySink: Send + Sync {
    /// Advances time-based transaction download policy.
    fn poll(&self, _gateway: &MempoolGateway) {}

    /// Queues an accepted identity and admission epoch, excluding its source.
    /// The production sink emits inventory on its next eligible timer tick.
    fn announce_inv(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        exclude: Option<u64>,
        sequence: u64,
    ) -> RelayOutcome;
}

/// Production [`RelaySink`] over the shared peer table.
///
/// Borrows the shared table, so the relay worker sees peer
/// connect/disconnect/reconnect and their published BIP339 preference. A
/// handshaking lease receives no inventory: choosing before negotiation could
/// queue `MSG_TX` for a connection that later requests `MSG_WTX`. A
/// block-relay-only lease receives none either: transaction relay is
/// prohibited on such a connection, as Core restricts `RelayTransaction` to
/// full-relay peers (`net_processing.cpp:5186-5260`).
pub struct PeerRelaySink {
    peers: Arc<crate::PeerTable>,
    ibd: Option<(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
}

impl PeerRelaySink {
    /// Wraps the shared peer table.
    #[must_use]
    pub fn new(peers: Arc<crate::PeerTable>) -> Self {
        Self { peers, ibd: None }
    }

    /// Shares the node's existing IBD decision for outgoing fee filters.
    #[must_use]
    pub fn with_ibd(
        mut self,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
        network: bitcoin_rs_primitives::Network,
    ) -> Self {
        self.ibd = Some((ibd, network));
        self
    }
}

impl RelaySink for PeerRelaySink {
    fn poll(&self, gateway: &MempoolGateway) {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        let ibd = self.ibd.as_ref().is_some_and(|(latch, network)| {
            latch.is_active(bitcoin_rs_primitives::unix_time_secs(), *network)
        });
        if !ibd {
            self.peers.poll_transaction_requests(gateway);
        }
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        self.peers
            .poll_transaction_relay(gateway, std::time::Instant::now(), ibd, &mut rng);
    }

    fn announce_inv(
        &self,
        txid: Txid,
        wtxid: Wtxid,
        exclude: Option<u64>,
        sequence: u64,
    ) -> RelayOutcome {
        use bitcoin::secp256k1::rand::SeedableRng as _;
        let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::from_entropy();
        let outcome = self.peers.queue_transaction_relay(
            RelayRequest::new(txid, wtxid, exclude, sequence),
            std::time::Instant::now(),
            &mut rng,
        );
        if outcome.saturated > 0 {
            tracing::debug!(%txid, peers = outcome.saturated, "transaction relay pending budget full");
        }
        outcome
    }
}

/// Returns whether the queued transaction is still relayable.
///
/// PRE: `gateway` is the shared gateway for the node's live mempool.
/// POST: returns true exactly when the admission that queued `request` —
/// identified by its txid at its admission epoch — is still resident in the
/// mempool read at this call. Removal and re-admission, even of byte-identical
/// bytes or a witness-mutated same-txid entry, does not satisfy the queued
/// request: `entry_by_txid_at_sequence` invalidates on the sequence, so a
/// stale request can neither announce a transaction admitted under a
/// different epoch nor advertise it back to a different source peer.
/// INVARIANT: the check does not mutate the mempool, relay queue, or
/// observer state. The read guard is released before this function
/// returns, so no caller holds it while it sends to peers.
fn transaction_is_live(gateway: &MempoolGateway, request: &RelayRequest) -> bool {
    gateway
        .read()
        .entry_by_txid_at_sequence(&request.txid, request.sequence)
        .is_some()
}

/// Synchronously drains every currently-queued relay request into `sink`,
/// announcing only transactions still resident in `gateway`.
///
/// Returns the number of requests processed. Tests call it to flush the
/// queue deterministically.
///
/// PRE: `gateway` is the shared gateway for the node's live mempool; `rx`
/// is the relay queue receiver.
/// POST: every request queued at the call is consumed and counted once. A
/// request whose transaction is resident with its queued wtxid at the send
/// is announced through `sink`, excluding its source connection. A request
/// whose transaction left the mempool — or was re-admitted under a
/// different wtxid — produces no announcement.
/// INVARIANT: no mempool guard is held while `sink` sends to peers.
#[cfg(test)]
pub(crate) fn drain_relay_queue(
    rx: &Receiver<RelayRequest>,
    sink: &dyn RelaySink,
    gateway: &MempoolGateway,
) -> usize {
    let mut processed = 0;
    while let Ok(request) = rx.try_recv() {
        if transaction_is_live(gateway, &request) {
            sink.announce_inv(
                request.txid,
                request.wtxid,
                request.source,
                request.sequence,
            );
        }
        processed += 1;
    }
    processed
}

/// Spawns the single tx-relay worker thread.
///
/// The thread drains [`RelayRequest`]s from `rx` and announces each through
/// `sink`, excluding the source connection, while its transaction is still
/// in `gateway`. It exits when `shutdown` is set or the queue sender is
/// dropped.
///
/// PRE: `gateway` is a weak handle to the shared gateway for the node's live
/// mempool; it remains upgradeable while the node is running.
/// POST: each request is announced exactly when its transaction is resident
/// with its queued wtxid at the send; a request for a removed or
/// witness-mutated transaction is consumed with no announcement. The
/// thread ends on `shutdown` or queue close.
/// INVARIANT: no mempool guard is held while `sink` sends to peers. The
/// worker applies the same send-time rule as `drain_relay_queue` and never
/// retains a strong gateway reference while it waits for queue input.
pub fn spawn_tx_relay_worker<S: RelaySink + 'static>(
    sink: S,
    rx: Receiver<RelayRequest>,
    gateway: Weak<MempoolGateway>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-tx-relay".to_owned())
        .spawn(move || {
            while !shutdown.load() {
                {
                    let Some(gateway) = gateway.upgrade() else {
                        break;
                    };
                    sink.poll(&gateway);
                }
                match rx.recv_timeout(RELAY_POLL) {
                    Ok(request) => {
                        let Some(gateway) = gateway.upgrade() else {
                            break;
                        };
                        if transaction_is_live(&gateway, &request) {
                            sink.announce_inv(
                                request.txid,
                                request.wtxid,
                                request.source,
                                request.sequence,
                            );
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_primitives::Hash256;
    use crossbeam_channel::bounded;
    use parking_lot::Mutex;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;

    /// A peer in the fake sink: a node id and a remaining send budget.
    #[derive(Clone)]
    struct FakePeer {
        node_id: u64,
        capacity: usize,
    }

    /// One recorded announcement: txid, excluded source, outcome.
    type SinkEntry = (Txid, Option<u64>, RelayOutcome);

    /// Test sink that records announcements without a live connection.
    struct FakeSink {
        peers: Mutex<Vec<FakePeer>>,
        /// Shared so a test can read it after the sink moves into the
        /// spawned relay worker.
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

    /// Allocates a fresh process-unique node id via a throwaway lease.
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

        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), Some(ids[1]), 0);

        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.excluded, 1);
        assert_eq!(outcome.saturated, 0);
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

        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), None, 0);

        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.excluded, 0);
        assert_eq!(outcome.saturated, 0);
        let locked = sink.peers.lock();
        assert!(locked.iter().all(|p| p.capacity == 63));
    }

    #[test]
    fn reconnect_uses_new_node_id_and_old_source_excludes_nothing() {
        let stale_source = fresh_node_id();
        let (peers, _ids) = fake_peers(2);
        let sink = FakeSink::new(peers);
        let txid = dummy_txid(0xC3);

        let outcome = sink.announce_inv(txid, dummy_wtxid(0xF0), Some(stale_source), 0);

        assert_eq!(outcome.attempted, 2);
        assert_eq!(outcome.excluded, 0, "stale source id no longer connected");
        assert_eq!(outcome.saturated, 0);
        let locked = sink.peers.lock();
        assert!(locked.iter().all(|p| p.capacity == 63));
    }

    #[test]
    fn replacement_txid_is_announced_excluding_source() {
        let (peers, ids) = fake_peers(3);
        let sink = FakeSink::new(peers);
        let replacement = dummy_txid(0xD4);

        let outcome = sink.announce_inv(replacement, dummy_wtxid(0xF0), Some(ids[2]), 0);

        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.excluded, 1);
        assert_eq!(outcome.saturated, 0);
        let entry = &sink.log()[0];
        assert_eq!(entry.0, replacement);
        assert_eq!(entry.1, Some(ids[2]));
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
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        let worker =
            spawn_tx_relay_worker(sink, rx, Arc::downgrade(&gateway), Arc::clone(&shutdown))
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
            )
            .expect("observer slot");
        let sink = FakeSink::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker =
            spawn_tx_relay_worker(sink, rx, Arc::downgrade(&gateway), Arc::clone(&shutdown))
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
        let gateway = Arc::new(MempoolGateway::new(
            pool,
            Some(Arc::new(CompositeObserver::new())),
            ValidationEngine::Native,
        ));
        let (queue, rx) = TxRelayQueue::new(8);
        let observer = Arc::new(LocalTxRelayObserver::new(queue, Arc::downgrade(&gateway)));
        gateway
            .attach_observer_leg("relay", observer.clone())
            .expect("observer slot");
        let mut last_txid = Txid::default();
        for (marker, origin, should_announce) in [
            (1, AdmissionOrigin::Rpc, true),
            (2, AdmissionOrigin::Reorg, true),
            (4, AdmissionOrigin::Esplora, true),
            (5, AdmissionOrigin::Block, false),
            (
                3,
                AdmissionOrigin::Peer(PeerToken {
                    addr: SocketAddr::from(([127, 0, 0, 1], 8333)),
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

    /// Admits a transaction with a distinct coinbase-style input to
    /// `gateway`, so a queued announcement for its txid is live at send
    /// time, and returns the transaction with its admission epoch.
    fn admit_live_tx(
        marker: u8,
        gateway: &MempoolGateway,
    ) -> (Arc<bitcoin_rs_primitives::Tx>, u64) {
        use bitcoin_rs_primitives::OutPoint;

        let mut tx = (*relay_identity_tx()).clone();
        tx.inputs[0].previous_output = OutPoint::new(dummy_txid(marker), 0);
        let tx = Arc::new(tx);
        let sequence = admit_entry(&tx, gateway);
        (tx, sequence)
    }

    /// Inserts `tx` and returns the admission epoch its relay request must
    /// carry for the send-time residency check to match.
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

    /// Reads the resident entry's wtxid for a fixture transaction, so a
    /// queued request carries the same identity the gateway serves.
    fn live_wtxid(txid: &Txid, gateway: &MempoolGateway) -> Wtxid {
        gateway
            .read()
            .entry_by_txid(txid)
            .expect("fixture entry present")
            .wtxid
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
            ValidationEngine::Native,
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
            )
            .expect("fixture observer slot");
        gateway
            .attach_observer_leg(
                "relay",
                Arc::new(LocalTxRelayObserver::new(relay, Arc::downgrade(&gateway))),
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
}
