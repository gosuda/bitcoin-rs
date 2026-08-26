//! Per-connection identity and cancellation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use crossbeam_channel::{SendError, Sender};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Process-unique identity for one peer connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId(u64);

impl ConnectionId {
    fn allocate() -> Self {
        match NEXT_CONNECTION_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        {
            Ok(id) => Self(id),
            Err(_) => std::process::abort(),
        }
    }

    /// Returns the process-unique numeric id backing this identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Live traffic and ping telemetry for one peer connection.
///
/// Shared between the connection's reader/writer threads and external
/// observers (network control queries), so every counter is atomic and every
/// timestamp is supplied by the caller for deterministic tests. Timestamps are
/// Unix microseconds; ping durations are microseconds.
#[derive(Debug)]
pub struct PeerStats {
    bytes_recv: AtomicU64,
    bytes_sent: AtomicU64,
    msgs_recv: AtomicU64,
    msgs_sent: AtomicU64,
    time_offset_secs: AtomicI64,
    next_ping_nonce: AtomicU64,
    ping_out_nonce: AtomicU64,
    ping_sent_us: AtomicU64,
    last_ping_us: AtomicU64,
    min_ping_us: AtomicU64,
}

impl Default for PeerStats {
    fn default() -> Self {
        Self {
            bytes_recv: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            msgs_recv: AtomicU64::new(0),
            msgs_sent: AtomicU64::new(0),
            time_offset_secs: AtomicI64::new(TIME_OFFSET_UNSET),
            next_ping_nonce: AtomicU64::new(0),
            ping_out_nonce: AtomicU64::new(0),
            ping_sent_us: AtomicU64::new(0),
            last_ping_us: AtomicU64::new(0),
            min_ping_us: AtomicU64::new(0),
        }
    }
}

/// Sentinel for "no time offset recorded yet" (`0` is a valid offset).
const TIME_OFFSET_UNSET: i64 = i64::MIN;

impl PeerStats {
    /// Accounts `bytes` of received wire traffic.
    pub fn record_recv(&self, bytes: u64) {
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Accounts `bytes` of sent wire traffic.
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Counts one received message.
    pub fn record_msg_recv(&self) {
        self.msgs_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one sent message.
    pub fn record_msg_sent(&self) {
        self.msgs_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Total wire bytes received on this connection.
    #[must_use]
    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Total wire bytes sent on this connection.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Number of messages received on this connection.
    #[must_use]
    pub fn msgs_recv(&self) -> u64 {
        self.msgs_recv.load(Ordering::Relaxed)
    }

    /// Number of messages sent on this connection.
    #[must_use]
    pub fn msgs_sent(&self) -> u64 {
        self.msgs_sent.load(Ordering::Relaxed)
    }

    /// Records the remote clock offset in seconds observed from its `version`.
    pub fn set_time_offset(&self, offset_secs: i64) {
        self.time_offset_secs.store(offset_secs, Ordering::Relaxed);
    }

    /// Remote clock offset in seconds, when a `version` message was observed.
    #[must_use]
    pub fn time_offset(&self) -> Option<i64> {
        let offset = self.time_offset_secs.load(Ordering::Relaxed);
        (offset != TIME_OFFSET_UNSET).then_some(offset)
    }

    /// Registers an outgoing ping at `now_us` and returns its nonce.
    ///
    /// Mirrors Bitcoin Core: a new ping supersedes any outstanding one, so a
    /// later pong carrying a stale nonce is discarded by [`Self::complete_ping`].
    pub fn begin_ping(&self, now_us: u64) -> u64 {
        let nonce = self.next_ping_nonce.fetch_add(1, Ordering::Relaxed) + 1;
        self.ping_out_nonce.store(nonce, Ordering::Relaxed);
        self.ping_sent_us.store(now_us, Ordering::Relaxed);
        nonce
    }

    /// Completes the outstanding ping when `nonce` matches, returning its
    /// round-trip duration; a stale or unknown nonce completes nothing.
    pub fn complete_ping(&self, nonce: u64, now_us: u64) -> Option<u64> {
        if self
            .ping_out_nonce
            .compare_exchange(nonce, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let elapsed = now_us.saturating_sub(self.ping_sent_us.load(Ordering::Relaxed));
        self.last_ping_us.store(elapsed, Ordering::Relaxed);
        let prior = self.min_ping_us.load(Ordering::Relaxed);
        if prior == 0 || elapsed < prior {
            self.min_ping_us.store(elapsed, Ordering::Relaxed);
        }
        Some(elapsed)
    }

    /// Duration of the most recently completed ping round trip.
    #[must_use]
    pub fn ping_time(&self) -> Option<Duration> {
        let micros = self.last_ping_us.load(Ordering::Relaxed);
        (micros != 0).then(|| Duration::from_micros(micros))
    }

    /// Shortest observed ping round trip on this connection.
    #[must_use]
    pub fn min_ping(&self) -> Option<Duration> {
        let micros = self.min_ping_us.load(Ordering::Relaxed);
        (micros != 0).then(|| Duration::from_micros(micros))
    }

    /// Time an outstanding ping has been unanswered at `now_us`.
    #[must_use]
    pub fn ping_wait(&self, now_us: u64) -> Option<Duration> {
        let nonce = self.ping_out_nonce.load(Ordering::Relaxed);
        (nonce != 0).then(|| {
            Duration::from_micros(now_us.saturating_sub(self.ping_sent_us.load(Ordering::Relaxed)))
        })
    }
}

/// Attribution token for an event delivered by one connection.
///
/// This value intentionally contains no outbound sender, so queued inbound
/// events cannot keep a retired connection's writer alive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSource {
    /// Remote socket address at delivery time.
    pub addr: SocketAddr,
    connection_id: ConnectionId,
}

/// Cloneable handle for one live peer connection.
#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<crate::Message>,
    cancel: Arc<AtomicBool>,
    stats: Arc<PeerStats>,
    inbound: bool,
}

impl PeerLease {
    /// Creates an outbound-direction lease with a fresh process-unique identity.
    #[must_use]
    pub fn new(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(outbound, false)
    }

    /// Creates an inbound-direction lease with a fresh process-unique identity.
    #[must_use]
    pub fn new_inbound(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(outbound, true)
    }

    fn with_direction(outbound: Sender<crate::Message>, inbound: bool) -> Self {
        Self {
            id: ConnectionId::allocate(),
            outbound,
            cancel: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(PeerStats::default()),
            inbound,
        }
    }

    /// Stable process-unique node id for this connection (Core `nodeid`).
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.id.get()
    }

    /// Whether this connection was accepted by the listener.
    #[must_use]
    pub const fn is_inbound(&self) -> bool {
        self.inbound
    }

    /// Live traffic and ping telemetry for this connection.
    #[must_use]
    pub fn stats(&self) -> &PeerStats {
        &self.stats
    }

    /// Shared handle to this connection's telemetry.
    #[must_use]
    pub fn stats_handle(&self) -> Arc<PeerStats> {
        Arc::clone(&self.stats)
    }

    /// Stamps an inbound event with this connection's identity and address.
    #[must_use]
    pub fn source(&self, addr: SocketAddr) -> PeerSource {
        PeerSource {
            addr,
            connection_id: self.id,
        }
    }

    /// Queues a message for this connection's writer.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, message: crate::Message) -> Result<(), SendError<crate::Message>> {
        self.outbound.send(message)
    }

    /// Returns whether `source` was stamped by this lease.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.id == source.connection_id
    }

    /// Returns whether both handles refer to the same connection.
    #[must_use]
    pub fn same_connection(&self, other: &Self) -> bool {
        self.id == other.id
    }

    /// Requests prompt teardown of this connection.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// Returns whether teardown has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::PeerLease;

    #[test]
    fn lease_ids_are_unique_and_clones_keep_identity() {
        let (first_tx, _first_rx) = crossbeam_channel::unbounded();
        let (second_tx, _second_rx) = crossbeam_channel::unbounded();
        let first = PeerLease::new(first_tx);
        let first_clone = first.clone();
        let second = PeerLease::new(second_tx);

        assert!(first.same_connection(&first_clone));
        assert!(!first.same_connection(&second));
    }

    #[test]
    fn cancellation_is_shared_by_clones() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        let clone = lease.clone();

        lease.cancel();

        assert!(clone.is_cancelled());
    }

    #[test]
    fn node_ids_are_stable_and_distinct() {
        let (first_tx, _first_rx) = crossbeam_channel::unbounded();
        let (second_tx, _second_rx) = crossbeam_channel::unbounded();
        let first = PeerLease::new(first_tx);
        let clone = first.clone();
        let second = PeerLease::new(second_tx);

        assert_eq!(first.node_id(), clone.node_id());
        assert_ne!(first.node_id(), second.node_id());
    }

    #[test]
    fn direction_distinguishes_inbound_from_outbound_leases() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        assert!(!PeerLease::new(tx.clone()).is_inbound());
        assert!(PeerLease::new_inbound(tx).is_inbound());
    }

    #[test]
    fn ping_round_trip_records_last_and_min_durations() {
        let stats = super::PeerStats::default();

        let first = stats.begin_ping(1_000);
        assert_eq!(stats.complete_ping(first, 3_000), Some(2_000));
        let second = stats.begin_ping(10_000);
        assert_eq!(stats.complete_ping(second, 11_000), Some(1_000));

        assert_eq!(stats.ping_time(), Some(std::time::Duration::from_millis(1)));
        assert_eq!(stats.min_ping(), Some(std::time::Duration::from_millis(1)));
        assert_eq!(stats.ping_wait(12_000), None);
    }

    #[test]
    fn stale_ping_nonce_does_not_complete_outstanding_ping() {
        let stats = super::PeerStats::default();

        let superseded = stats.begin_ping(1_000);
        let current = stats.begin_ping(2_000);

        assert_eq!(stats.complete_ping(superseded, 9_000), None);
        assert_eq!(
            stats.ping_wait(3_000),
            Some(std::time::Duration::from_millis(1))
        );
        assert_eq!(stats.complete_ping(current, 9_000), Some(7_000));
    }

    #[test]
    fn traffic_and_offset_counters_accumulate() {
        let stats = super::PeerStats::default();
        assert_eq!(stats.time_offset(), None);

        stats.record_recv(120);
        stats.record_recv(24);
        stats.record_sent(48);
        stats.record_msg_recv();
        stats.record_msg_recv();
        stats.record_msg_sent();
        stats.set_time_offset(-3);

        assert_eq!(stats.bytes_recv(), 144);
        assert_eq!(stats.bytes_sent(), 48);
        assert_eq!(stats.msgs_recv(), 2);
        assert_eq!(stats.msgs_sent(), 1);
        assert_eq!(stats.time_offset(), Some(-3));
    }
}
