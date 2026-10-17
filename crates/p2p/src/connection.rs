//! Per-connection identity and cancellation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, SendError, Sender, TrySendError};
use parking_lot::{Condvar, Mutex};
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Process-unique identity for one peer connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId(u64);

impl ConnectionId {
    fn allocate() -> Self {
        let mut id = NEXT_CONNECTION_ID.load(Ordering::Relaxed);
        loop {
            let Some(next) = id.checked_add(1) else {
                std::process::abort();
            };
            match NEXT_CONNECTION_ID.compare_exchange_weak(
                id,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Self(id),
                Err(actual) => id = actual,
            }
        }
    }

    /// Returns the process-unique numeric id backing this identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Attribution token for an event delivered by one connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSource {
    /// Remote socket address at delivery time.
    pub(crate) addr: SocketAddr,
    connection_id: ConnectionId,
}

impl PeerSource {
    /// Returns the connection id of the delivering peer.
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Mints a source with a fresh process-unique identity for tests.
    #[cfg(test)]
    pub(crate) fn for_test(addr: SocketAddr) -> Self {
        Self {
            addr,
            connection_id: ConnectionId::allocate(),
        }
    }
}

impl From<PeerSource> for bitcoin_rs_mempool::PeerToken {
    fn from(source: PeerSource) -> Self {
        Self {
            addr: source.addr,
            connection_id: source.connection_id.get(),
        }
    }
}

/// Maximum queued messages for one peer connection.
const OUTBOUND_QUEUE_MAX_MESSAGES: usize = 4096;

/// Maximum queued full wire bytes for one peer connection.
const OUTBOUND_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Consensus maximum serialized block size. `peer` owns the value
/// ([`crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE`]); `connection` references it
/// rather than carrying an independent copy.
const BLOCK_SERIALIZED_SIZE: usize = crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE;

/// Full framed-wire bytes reserved before loading a worst-case block body.
const BLOCK_PRODUCTION_RESERVE_BYTES: usize = crate::wire::HEADER_LEN + BLOCK_SERIALIZED_SIZE;

const _: () = assert!(OUTBOUND_QUEUE_MAX_BYTES > 15 * BLOCK_PRODUCTION_RESERVE_BYTES);

/// Maximum unsolicited block bodies one connection may hold in the shared
/// inbound block channel at once.
///
/// The channel itself is bounded globally, so without this per-connection
/// bound one flooding peer can occupy every slot and starve the rest of the
/// swarm of block ingress. Sixteen is the per-peer in-flight budget: a
/// connection may always keep the bodies it was asked for in play, and no
/// more unsolicited ones.
pub(crate) const MAX_UNSOLICITED_BLOCK_FORWARDS: usize = 16;

/// One admitted unsolicited block forward.
///
/// Holding it is the credit; dropping it — once the forwarded body is drained
/// by sync, discarded by the stager, or rejected — releases the connection's
/// slot. A credit for a body the download window already owns releases
/// nothing, because nothing was counted.
#[derive(Debug)]
pub(crate) struct BlockForwardCredit(Option<Arc<AtomicUsize>>);

impl Drop for BlockForwardCredit {
    fn drop(&mut self) {
        if let Some(counter) = &self.0 {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Shared item and full-framed-wire-byte accounting for one outbound queue.
///
/// A message is admitted when both counters were below their high-water marks
/// immediately before its addition. This admits one oversized message to an
/// empty queue and bounds concurrent overshoot to one item per sender. The
/// writer releases exactly the byte count returned by `write_message`, equal
/// to the `wire_len` charged here. The channel continues to carry `Message`.
///
/// # Saturation policy
///
/// Saturation disconnects only this peer. `PeerLease::send` cancels the lease
/// and returns the refused message; no message is silently dropped while the
/// connection remains live. Producer pacing may shrink the cap later, but the
/// pre-load block-production gate is what bounds materialization. A `getdata`
/// session checks [`OutboundBudget::has_block_production_headroom`] (a free
/// item slot and room for a worst-case block) before each load and pauses on
/// [`OutboundBudget::wait_for_release`] until the writer drains, so a queue
/// that fills by item count or by bytes parks it instead of reaching a
/// refusal. Only a concurrent sender can still lose the race for the last
/// slot, and that send cancels the lease.
///
/// # Waiting for the writer
///
/// A paused session sleeps on `drained`, guarded by `drained_lock`. The
/// predicate it waits for (`writer_dead` or block-production headroom) lives
/// in the atomics, and every writer of that state (`release`,
/// `mark_writer_dead`) takes `drained_lock` after the update and before it
/// notifies. A waiter therefore either sees the new state in its predicate
/// check, or is already parked in `wait_for` when the notification fires, so
/// no wake is lost.
#[derive(Debug)]
pub(crate) struct OutboundBudget {
    max_messages: usize,
    max_bytes: usize,
    block_reserve: usize,
    pending_messages: AtomicUsize,
    pending_bytes: AtomicUsize,
    /// Signalled when the writer releases a frame or exits.
    drained: Condvar,
    /// Orders state updates against a waiter's predicate check; guards no data.
    drained_lock: Mutex<()>,
    /// Set once the connection writer has returned and will release nothing more.
    writer_dead: AtomicBool,
}

impl OutboundBudget {
    /// Builds a production budget with the block-production reserve.
    #[must_use]
    pub(crate) fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self::with_reserve(max_messages, max_bytes, BLOCK_PRODUCTION_RESERVE_BYTES)
    }

    fn with_reserve(max_messages: usize, max_bytes: usize, block_reserve: usize) -> Self {
        Self {
            max_messages,
            max_bytes,
            block_reserve,
            pending_messages: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
            drained: Condvar::new(),
            drained_lock: Mutex::new(()),
            writer_dead: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    /// Builds a test budget with a reduced block-production reserve.
    #[must_use]
    pub(crate) fn with_block_reserve(
        max_messages: usize,
        max_bytes: usize,
        block_reserve: usize,
    ) -> Self {
        Self::with_reserve(max_messages, max_bytes, block_reserve)
    }

    fn admit(&self, wire_len: usize) -> bool {
        let messages = self.pending_messages.fetch_add(1, Ordering::AcqRel);
        let bytes = self.pending_bytes.fetch_add(wire_len, Ordering::AcqRel);
        if messages < self.max_messages && bytes < self.max_bytes {
            return true;
        }
        self.release(wire_len);
        false
    }

    /// Releases one successfully written message.
    ///
    /// Write errors deliberately do not release: the connection and its
    /// counters are dying, and releasing there would risk double-accounting.
    pub(crate) fn release(&self, wire_len: usize) {
        let mut messages = self.pending_messages.load(Ordering::Acquire);
        while let Err(actual) = self.pending_messages.compare_exchange_weak(
            messages,
            messages.saturating_sub(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            messages = actual;
        }
        let mut bytes = self.pending_bytes.load(Ordering::Acquire);
        while let Err(actual) = self.pending_bytes.compare_exchange_weak(
            bytes,
            bytes.saturating_sub(wire_len),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            bytes = actual;
        }
        self.wake_waiters();
    }

    /// Notifies every session paused in [`OutboundBudget::wait_for_release`].
    ///
    /// PRE: the state a waiter's predicate reads was updated before the call.
    /// POST: a waiter either observed that update or is woken by this call.
    /// INVARIANT: the empty critical section orders the update before any
    /// waiter's next predicate check; it never holds the lock across the
    /// notification's effects, so a woken waiter does not contend with it.
    fn wake_waiters(&self) {
        drop(self.drained_lock.lock());
        self.drained.notify_all();
    }

    /// Records that the connection writer has returned and releases nothing
    /// more, then wakes every waiting session.
    pub(crate) fn mark_writer_dead(&self) {
        self.writer_dead.store(true, Ordering::Release);
        self.wake_waiters();
    }

    /// Returns whether the connection writer has returned.
    #[must_use]
    pub(crate) fn writer_dead(&self) -> bool {
        self.writer_dead.load(Ordering::Acquire)
    }

    /// Blocks the calling session until the writer drains a frame, exits, or
    /// `timeout` elapses.
    ///
    /// PRE: the caller holds no lock another thread needs to release the
    /// budget (the pool, the socket).
    /// POST: returns at once when the writer is dead or the queue already has
    /// block-production headroom; otherwise returns once either holds or
    /// `timeout` has elapsed on the monotonic clock. Spurious wakeups re-enter
    /// the wait. The return promises nothing: the headroom it announced can
    /// be taken by another sender before the caller looks, so the caller
    /// rechecks [`OutboundBudget::has_block_production_headroom`],
    /// [`OutboundBudget::writer_dead`], and its own cancellation.
    pub(crate) fn wait_for_release(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut guard = self.drained_lock.lock();
        while !(self.writer_dead() || self.has_block_production_headroom()) {
            if self.drained.wait_until(&mut guard, deadline).timed_out() {
                return;
            }
        }
    }

    /// Returns the charged `(messages, full wire bytes)` awaiting release.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> (usize, usize) {
        (
            self.pending_messages.load(Ordering::Acquire),
            self.pending_bytes.load(Ordering::Acquire),
        )
    }

    /// Returns whether one more worst-case block body may be loaded and
    /// queued: the item cap has a free slot and the byte cap has room for a
    /// worst-case block behind everything pending. An empty queue always
    /// qualifies, as `admit` takes one oversized message into it.
    ///
    /// This is the load gate of every producer (`getdata`, `getblocktxn`,
    /// compact filters) and of the keepalive probe, so a queue that is full
    /// by item count stops them exactly as one that is full by bytes does.
    #[must_use]
    pub(crate) fn has_block_production_headroom(&self) -> bool {
        let messages = self.pending_messages.load(Ordering::Acquire);
        messages == 0
            || (messages < self.max_messages
                && self
                    .pending_bytes
                    .load(Ordering::Acquire)
                    .saturating_add(self.block_reserve)
                    <= self.max_bytes)
    }

    /// Returns whether `admit` would take one more small message right now:
    /// both caps are below their high-water marks, with no reserve held back.
    ///
    /// With a nonzero block reserve (always, in production) headroom implies
    /// capacity: it needs a free slot and the bytes to spare behind a
    /// worst-case block. The converse does not hold, so a queue can refuse
    /// another body load yet still take a short control message. A caller
    /// must check this predicate before it sends, not infer it from headroom:
    /// with a zero reserve (tests only) headroom stays true at the byte cap,
    /// where `admit` refuses.
    /// The answer is a snapshot: another sender can fill the queue before the
    /// caller's send, and that send then cancels the lease as every refused
    /// send does.
    #[must_use]
    pub(crate) fn has_send_capacity(&self) -> bool {
        self.pending_messages.load(Ordering::Acquire) < self.max_messages
            && self.pending_bytes.load(Ordering::Acquire) < self.max_bytes
    }
}

/// Cloneable handle for one live peer connection.
#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<crate::Message>,
    cancel: Arc<AtomicBool>,
    close_tx: Sender<()>,
    close_rx: Receiver<()>,
    budget: Arc<OutboundBudget>,
    /// Live unsolicited block forwards admitted by this connection.
    unsolicited_forwards: Arc<AtomicUsize>,
    /// Instant the writer queue last admitted a message on this connection.
    last_send: Arc<Mutex<Instant>>,
    inbound: bool,
    role: crate::peer_info::PeerRole,
    /// Whether the operator pinned this dial by hand (`--connect` or
    /// `addnode`). Core: `ConnectionType::MANUAL`.
    manual: bool,
    /// Granted only from operator configuration using the actual socket IP.
    no_ban: bool,
    /// Monotonic instant the connection was created.
    connected: Instant,
}

impl PeerLease {
    /// Creates an outbound full-relay lease with a fresh process-unique identity.
    #[must_use]
    pub fn new(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(
            outbound,
            false,
            crate::peer_info::PeerRole::FullRelay,
            false,
        )
    }

    /// Creates an outbound block-relay-only lease.
    ///
    /// PRE: none.
    /// POST: the lease is outbound and its role is
    ///   [`crate::peer_info::PeerRole::BlockRelayOnly`], so the connection
    ///   carries blocks and headers only, in either direction.
    /// INVARIANT: the role is fixed for the life of the lease.
    #[must_use]
    pub(crate) fn new_block_relay(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(
            outbound,
            false,
            crate::peer_info::PeerRole::BlockRelayOnly,
            false,
        )
    }

    /// Creates an outbound lease the operator asked for by name.
    ///
    /// PRE: none.
    /// POST: the lease is outbound, carries `role`, and is manual.
    /// INVARIANT: Core's `ConnectionType::MANUAL` is exempt from the
    ///   chain-sync timeout and the extra-peer retirement
    ///   (`net_processing.cpp:5502`, `net_processing.cpp:5558-5604`):
    ///   replacing a hand-pinned connection would undo an explicit
    ///   instruction, so the flag must outlive every policy check.
    #[must_use]
    pub(crate) fn new_manual(
        outbound: Sender<crate::Message>,
        role: crate::peer_info::PeerRole,
    ) -> Self {
        Self::with_direction(outbound, false, role, true)
    }

    /// Creates an inbound lease with a fresh process-unique identity.
    #[must_use]
    pub fn new_inbound(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(outbound, true, crate::peer_info::PeerRole::FullRelay, false)
    }

    /// Test constructor: an outbound lease already `connected_at` old, for
    /// exercising rules gated on connection age without sleeping.
    #[cfg(test)]
    pub(crate) fn new_connected_at(
        outbound: Sender<crate::Message>,
        connected_at: Instant,
    ) -> Self {
        let mut lease = Self::new(outbound);
        lease.backdate_for_test(connected_at);
        lease
    }

    fn with_direction(
        outbound: Sender<crate::Message>,
        inbound: bool,
        role: crate::peer_info::PeerRole,
        manual: bool,
    ) -> Self {
        Self::with_budget(
            outbound,
            inbound,
            role,
            manual,
            OutboundBudget::new(OUTBOUND_QUEUE_MAX_MESSAGES, OUTBOUND_QUEUE_MAX_BYTES),
        )
    }

    fn with_budget(
        outbound: Sender<crate::Message>,
        inbound: bool,
        role: crate::peer_info::PeerRole,
        manual: bool,
        budget: OutboundBudget,
    ) -> Self {
        let (close_tx, close_rx) = crossbeam_channel::bounded(1);
        Self {
            id: ConnectionId::allocate(),
            outbound,
            cancel: Arc::new(AtomicBool::new(false)),
            close_tx,
            close_rx,
            budget: Arc::new(budget),
            unsolicited_forwards: Arc::new(AtomicUsize::new(0)),
            last_send: Arc::new(Mutex::new(Instant::now())),
            inbound,
            role,
            manual,
            no_ban: false,
            connected: Instant::now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_budget(
        outbound: Sender<crate::Message>,
        inbound: bool,
        budget: OutboundBudget,
    ) -> Self {
        Self::with_budget(
            outbound,
            inbound,
            crate::peer_info::PeerRole::FullRelay,
            false,
            budget,
        )
    }

    pub(crate) fn with_no_ban(mut self, no_ban: bool) -> Self {
        self.no_ban = no_ban;
        self
    }

    /// Whether the operator exempted this connection from automatic punishment.
    #[must_use]
    pub const fn is_no_ban(&self) -> bool {
        self.no_ban
    }

    pub(crate) const fn is_protected(&self) -> bool {
        self.manual || self.no_ban
    }

    pub(crate) fn ignores_protocol_error(&self, error: &crate::PeerError) -> bool {
        self.is_protected() && error.recoverable_for_protected()
    }

    /// Stable process-unique node id for this connection (Core `nodeid`).
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.id.get()
    }

    /// Process-unique identity of this connection.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.id
    }

    /// Whether this connection was accepted by the listener.
    #[must_use]
    pub const fn is_inbound(&self) -> bool {
        self.inbound
    }

    /// What this connection relays. See [`crate::peer_info::PeerRole`].
    ///
    /// PRE: none.
    /// POST: the role assigned when the lease was created.
    /// INVARIANT: never changes; a replacement connection gets its own lease
    ///   and therefore its own role.
    #[must_use]
    pub const fn role(&self) -> crate::peer_info::PeerRole {
        self.role
    }

    /// Whether the operator pinned this connection by hand.
    ///
    /// PRE: none.
    /// POST: true exactly for a dial asked for by `--connect` or `addnode`.
    /// INVARIANT: never changes, like the role: the exemption the flag
    ///   carries is Core's `ConnectionType::MANUAL`
    ///   (`net_processing.cpp:5502`), and a connection that could lose it
    ///   mid-life could be evicted by a rule that never applied to it.
    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.manual
    }

    /// When this connection was created, on the monotonic clock.
    ///
    /// PRE: none.
    /// POST: the instant never moves, and it is never in the future
    ///   relative to a later read.
    /// INVARIANT: this holds the role Core's `nTimeConnected` holds
    ///   (`net.h`): the age a connection must reach before policy may
    ///   hold its silence against it.
    #[must_use]
    pub(crate) const fn connected_at(&self) -> Instant {
        self.connected
    }

    /// Moves this lease's connection instant into the past.
    #[cfg(test)]
    pub(crate) fn backdate_for_test(&mut self, at: Instant) {
        debug_assert!(at <= Instant::now());
        self.connected = at;
    }

    /// Receiver half of the close signal raised by [`PeerLease::cancel`].
    /// The connection writer selects on it so teardown never depends on
    /// remaining sender clones. Node code never observes this channel.
    pub(crate) fn close_signal(&self) -> Receiver<()> {
        self.close_rx.clone()
    }

    /// Shared handle to this connection's outbound admission budget.
    pub(crate) fn budget_handle(&self) -> Arc<OutboundBudget> {
        Arc::clone(&self.budget)
    }

    /// Admits one inbound block body into the shared inbound channel.
    ///
    /// PRE: `source` was stamped by this lease and `requested` reports whether
    ///   the download window already owns `hash` for this connection.
    /// POST: a requested body is always admitted; an unsolicited one is
    ///   admitted only while this connection holds fewer than
    ///   [`MAX_UNSOLICITED_BLOCK_FORWARDS`] credits, and `Some` carries the
    ///   credit that releases the slot when the forwarded body is dropped.
    /// INVARIANT: no admission here waits on the channel, disconnects the
    ///   connection, or lets one source exceed its own bound. Ownership is
    ///   the connection's, so a same-address replacement starts fresh.
    pub(crate) fn admit_block_forward(
        &self,
        source: PeerSource,
        hash: bitcoin_rs_primitives::Hash256,
        requested: bool,
    ) -> Option<BlockForwardCredit> {
        if requested {
            return Some(BlockForwardCredit(None));
        }
        let counter = Arc::clone(&self.unsolicited_forwards);
        // Increment-then-compare: a credit released on the sync thread
        // concurrently can never let two admissions cross the bound.
        if counter.fetch_add(1, Ordering::AcqRel) >= MAX_UNSOLICITED_BLOCK_FORWARDS {
            counter.fetch_sub(1, Ordering::AcqRel);
            tracing::debug!(
                peer_addr = %source.addr,
                %hash,
                limit = MAX_UNSOLICITED_BLOCK_FORWARDS,
                "p2p dropping unsolicited block: per-connection forward bound reached"
            );
            return None;
        }
        Some(BlockForwardCredit(Some(counter)))
    }

    /// Instant the writer queue last admitted a message on this connection.
    #[must_use]
    pub(crate) fn last_send(&self) -> Instant {
        *self.last_send.lock()
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
    #[expect(clippy::result_large_err)]
    pub fn send(&self, message: crate::Message) -> Result<(), SendError<crate::Message>> {
        if self.is_cancelled() {
            return Err(SendError(message));
        }
        let wire_len = if let Ok(wire_len) = crate::wire::wire_len(&message) {
            wire_len
        } else {
            self.cancel();
            return Err(SendError(message));
        };
        if !self.budget.admit(wire_len) {
            self.cancel();
            return Err(SendError(message));
        }
        match self.outbound.try_send(message) {
            Ok(()) => {
                *self.last_send.lock() = Instant::now();
                Ok(())
            }
            Err(TrySendError::Full(message) | TrySendError::Disconnected(message)) => {
                self.budget.release(wire_len);
                self.cancel();
                Err(SendError(message))
            }
        }
    }

    /// Returns whether `source` was stamped by this lease.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.id == source.connection_id
    }

    /// Returns whether both handles refer to the same connection.
    #[must_use]
    pub(crate) fn same_connection(&self, other: &Self) -> bool {
        self.id == other.id
    }

    /// Requests prompt teardown of this connection.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        let _ = self.close_tx.try_send(());
    }

    /// Returns whether teardown has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    /// The flag [`Self::cancel`] sets, for a socket wrapper to observe.
    pub(crate) fn cancellation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }
}

#[cfg(test)]
mod tests {
    use super::PeerLease;
    use crossbeam_channel::SendError;
    use std::net::SocketAddr;

    fn peer_info(addr: SocketAddr, conn_time: u64) -> crate::PeerInfo {
        crate::PeerInfo {
            addr,
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        }
    }

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
    fn stale_connection_cannot_publish_over_replacement() {
        let table = crate::PeerTable::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_450));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        assert!(!table.register(addr, old.clone()));
        assert!(table.publish_info(addr, &old, peer_info(addr, 1)));

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        assert!(table.register(addr, replacement.clone()));
        assert!(old.is_cancelled());
        assert_eq!(table.infos(), []);
        assert_eq!(table.ready_source(addr), None);
        assert!(!table.publish_info(addr, &old, peer_info(addr, 2)));
        assert_eq!(table.infos(), []);

        assert!(table.publish_info(addr, &replacement, peer_info(addr, 3)));
        assert_eq!(table.infos(), vec![peer_info(addr, 3)]);
        assert_eq!(table.ready_source(addr), Some(replacement.source(addr)));
        assert!(
            table
                .lease(addr)
                .is_some_and(|current| current.same_connection(&replacement))
        );
    }

    #[test]
    fn stale_disconnect_source_preserves_replacement() {
        let table = crate::PeerTable::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_451));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let stale_source = old.source(addr);

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());
        table.publish_info(addr, &replacement, peer_info(addr, 2));

        assert!(!table.disconnect_source(stale_source));
        assert!(!replacement.is_cancelled());
        assert!(table.is_connected(addr));
        assert_eq!(table.infos(), vec![peer_info(addr, 2)]);

        assert!(table.disconnect_source(replacement.source(addr)));
        assert!(replacement.is_cancelled());
        assert!(!table.is_connected(addr));
        assert_eq!(table.infos(), []);
    }

    #[test]
    fn ready_snapshot_keeps_identity_across_same_address_replacement() {
        let table = crate::PeerTable::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_452));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        table.register(addr, old.clone());
        assert!(table.publish_info(addr, &old, peer_info(addr, 1)));
        let snapshot = table
            .ready_peers()
            .pop()
            .unwrap_or_else(|| panic!("ready peer snapshot missing"));

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());

        assert!(table.lease_source(snapshot).is_none());
        assert!(table.lease_source(replacement.source(addr)).is_some());
    }

    #[test]
    fn block_production_reserve_admits_worst_case_block() {
        let Ok(block_size) = usize::try_from(bitcoin_rs_consensus::MAX_BLOCK_SERIALIZED_SIZE)
        else {
            panic!("MAX_BLOCK_SERIALIZED_SIZE exceeds usize on this platform")
        };
        let worst_case_wire = crate::wire::HEADER_LEN + block_size;
        assert_eq!(
            super::BLOCK_PRODUCTION_RESERVE_BYTES,
            worst_case_wire,
            "reserve must equal header + consensus max block size"
        );
        let budget = super::OutboundBudget::with_block_reserve(
            1,
            super::BLOCK_PRODUCTION_RESERVE_BYTES,
            super::BLOCK_PRODUCTION_RESERVE_BYTES,
        );
        assert!(
            budget.admit(worst_case_wire),
            "a worst-case block must be admissible when the byte cap equals the reserve"
        );

        let progress = super::OutboundBudget::with_block_reserve(4, 100, 1_000);
        assert!(progress.has_block_production_headroom());

        let reserve = 100;
        let budget = super::OutboundBudget::with_block_reserve(10, 3 * reserve, reserve);
        assert!(budget.has_block_production_headroom());
        assert!(budget.admit(reserve));
        assert!(budget.has_block_production_headroom());
        assert!(budget.admit(reserve));
        assert!(budget.has_block_production_headroom());
        assert!(budget.admit(reserve));
        assert!(!budget.has_block_production_headroom());
        budget.release(reserve);
        assert!(budget.has_block_production_headroom());
    }

    #[test]
    fn headroom_needs_a_free_item_slot_as_well_as_the_byte_reserve() {
        // Bytes are abundant: only the item cap can close the gate.
        let budget = super::OutboundBudget::with_block_reserve(2, 1_000_000, 100);
        assert!(budget.has_block_production_headroom(), "empty queue");
        assert!(budget.admit(10));
        assert!(budget.has_block_production_headroom(), "one slot is free");
        assert!(budget.admit(10));
        assert!(
            !budget.has_block_production_headroom(),
            "no item slot is free, however few bytes are queued"
        );
        budget.release(10);
        assert!(budget.has_block_production_headroom());
        budget.release(10);
        assert!(
            budget.has_block_production_headroom(),
            "an empty queue admits one oversized message"
        );
    }

    #[test]
    fn send_capacity_is_the_admit_condition_without_the_reserve() {
        let reserve = 100;
        let budget = super::OutboundBudget::with_block_reserve(3, 3 * reserve, reserve);
        assert!(budget.has_send_capacity());
        // 250 queued bytes plus the 100-byte reserve exceed the 300-byte cap.
        assert!(budget.admit(2 * reserve + 50));
        assert!(
            !budget.has_block_production_headroom(),
            "no room left for a worst-case block"
        );
        assert!(
            budget.has_send_capacity(),
            "a short control message still fits below both caps"
        );
        assert!(budget.admit(2 * reserve));
        assert!(
            !budget.has_send_capacity(),
            "the byte cap is reached: admit would refuse"
        );
        budget.release(2 * reserve);
        assert!(budget.admit(10));
        assert!(budget.admit(10));
        assert!(
            !budget.has_send_capacity(),
            "the item cap is reached: admit would refuse"
        );
    }

    #[test]
    fn outbound_budget_refuses_at_exact_item_cap_and_byte_cap() {
        let ping_len = wire_len_of(&crate::Message::Ping(1));

        let items = super::OutboundBudget::with_block_reserve(2, 100 * ping_len, 0);
        assert!(items.admit(ping_len));
        assert!(items.admit(ping_len));
        assert!(!items.admit(ping_len));
        assert_eq!(items.pending(), (2, 2 * ping_len));

        let bytes = super::OutboundBudget::with_block_reserve(100, 2 * ping_len, 0);
        assert!(bytes.admit(ping_len));
        assert!(bytes.admit(ping_len));
        assert!(!bytes.admit(ping_len));
        assert_eq!(bytes.pending(), (2, 2 * ping_len));
    }

    #[test]
    fn oversized_single_message_admits_on_empty_queue() {
        let budget = super::OutboundBudget::with_block_reserve(10, 100, 0);

        assert!(budget.admit(1_000));
        assert_eq!(budget.pending(), (1, 1_000));
        assert!(!budget.admit(1));
        budget.release(1_000);
        assert!(budget.admit(1));
    }

    #[test]
    fn saturated_send_cancels_lease_and_returns_message() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let first = crate::Message::Ping(1);
        let second = crate::Message::Ping(2);
        let lease = PeerLease::new_with_budget(
            tx,
            false,
            super::OutboundBudget::with_block_reserve(1, 1_000_000, 0),
        );

        assert!(lease.send(first).is_ok());
        assert!(lease.send(second).is_err());
        assert!(lease.is_cancelled());
    }
    #[test]
    fn full_channel_send_cancels_lease_and_returns_message() {
        let (tx, _rx) = crossbeam_channel::bounded(1);
        let lease = PeerLease::new(tx);

        assert!(lease.send(crate::Message::Ping(1)).is_ok());
        let message = crate::Message::Ping(2);
        assert_eq!(lease.send(message.clone()), Err(SendError(message)));
        assert!(lease.is_cancelled());
    }

    #[test]
    fn disconnected_channel_send_cancels_lease_and_returns_message() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        drop(rx);
        let lease = PeerLease::new(tx);

        let message = crate::Message::Ping(3);
        assert_eq!(lease.send(message.clone()), Err(SendError(message)));
        assert!(lease.is_cancelled());
    }

    #[test]
    fn cancelled_lease_refuses_send() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        lease.cancel();

        assert!(lease.send(crate::Message::Verack).is_err());
    }

    #[test]
    fn release_replenishes_budget() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let first = crate::Message::Ping(7);
        let ping_len = wire_len_of(&first);
        let lease = PeerLease::new_with_budget(
            tx,
            false,
            super::OutboundBudget::with_block_reserve(1, 10 * ping_len, 0),
        );

        assert!(lease.send(first).is_ok());
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));

        assert!(lease.send(crate::Message::Ping(8)).is_err());
        assert!(lease.is_cancelled());
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));

        lease.budget_handle().release(ping_len);
        assert_eq!(lease.budget_handle().pending(), (0, 0));

        let (fresh_tx, _fresh_rx) = crossbeam_channel::unbounded();
        let fresh = PeerLease::new_with_budget(
            fresh_tx,
            false,
            super::OutboundBudget::with_block_reserve(1, 10 * ping_len, 0),
        );

        assert!(fresh.send(crate::Message::Ping(9)).is_ok());
    }

    #[test]
    fn saturated_getdata_fourth_send_refuses_and_closes_lease() {
        let (tx, _undrained_rx) = crossbeam_channel::unbounded();
        let test_block = bitcoin_rs_primitives::Block::default();
        let block_wire_len = wire_len_of(&crate::Message::Block(test_block.clone()));
        let lease = PeerLease::new_with_budget(
            tx,
            false,
            super::OutboundBudget::with_block_reserve(100_000, 3 * block_wire_len, block_wire_len),
        );

        for _ in 0..3 {
            assert!(
                lease
                    .send(crate::Message::Block(test_block.clone()))
                    .is_ok()
            );
        }
        assert!(lease.send(crate::Message::Block(test_block)).is_err());

        assert!(lease.is_cancelled());
        assert_eq!(lease.budget_handle().pending(), (3, 3 * block_wire_len));

        let (independent_tx, _independent_rx) = crossbeam_channel::unbounded();
        let independent = PeerLease::new(independent_tx);
        assert!(independent.send(crate::Message::Ping(1)).is_ok());
    }

    /// Runs `wait_for_release` on a thread and reports when it returned.
    fn spawn_waiter(
        budget: &std::sync::Arc<super::OutboundBudget>,
        timeout: std::time::Duration,
    ) -> (
        std::thread::JoinHandle<()>,
        crossbeam_channel::Receiver<std::time::Instant>,
    ) {
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let waiter = std::sync::Arc::clone(budget);
        let handle = std::thread::spawn(move || {
            waiter.wait_for_release(timeout);
            let _ = done_tx.send(std::time::Instant::now());
        });
        (handle, done_rx)
    }

    /// A saturated budget with one worst-case message pending: no headroom
    /// until the writer releases it.
    fn saturated_budget() -> (std::sync::Arc<super::OutboundBudget>, usize) {
        let reserve = 100;
        let budget = std::sync::Arc::new(super::OutboundBudget::with_block_reserve(
            10,
            2 * reserve,
            reserve,
        ));
        assert!(budget.admit(reserve + 1));
        assert!(!budget.has_block_production_headroom());
        (budget, reserve + 1)
    }

    const WAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn release_wakes_a_waiter_long_before_its_timeout() {
        let (budget, charged) = saturated_budget();
        let (waiter, done) = spawn_waiter(&budget, std::time::Duration::from_secs(60));

        // The waiter may not have parked yet; the protocol must hold either way.
        std::thread::sleep(std::time::Duration::from_millis(50));
        budget.release(charged);

        let woke = done.recv_timeout(WAKE_DEADLINE);
        // Unblock the waiter on failure so the join below cannot hang.
        budget.mark_writer_dead();
        waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(woke.is_ok(), "a release must wake the waiter");
        assert!(budget.has_block_production_headroom());
    }

    #[test]
    fn writer_death_wakes_a_waiter_that_no_release_will_reach() {
        let (budget, _charged) = saturated_budget();
        let (waiter, done) = spawn_waiter(&budget, std::time::Duration::from_secs(60));

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!budget.writer_dead());
        budget.mark_writer_dead();

        let woke = done.recv_timeout(WAKE_DEADLINE);
        waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(woke.is_ok(), "writer death must wake the waiter");
        assert!(budget.writer_dead());
        assert!(
            !budget.has_block_production_headroom(),
            "death releases nothing; the queue stays saturated"
        );
    }

    #[test]
    fn wait_returns_at_once_when_headroom_or_death_already_holds() {
        let open = super::OutboundBudget::with_block_reserve(10, 1_000, 100);
        let started = std::time::Instant::now();
        open.wait_for_release(std::time::Duration::from_secs(60));
        assert!(started.elapsed() < WAKE_DEADLINE);

        let (dead, _charged) = saturated_budget();
        dead.mark_writer_dead();
        let started = std::time::Instant::now();
        dead.wait_for_release(std::time::Duration::from_secs(60));
        assert!(started.elapsed() < WAKE_DEADLINE);
    }

    #[test]
    fn wait_times_out_without_a_wake() {
        let (budget, _charged) = saturated_budget();
        let timeout = std::time::Duration::from_millis(100);
        let started = std::time::Instant::now();

        budget.wait_for_release(timeout);

        assert!(
            started.elapsed() >= timeout,
            "no wake, so the wait runs to its timeout"
        );
        assert!(!budget.has_block_production_headroom());
        assert!(!budget.writer_dead());
    }

    #[test]
    fn a_release_that_leaves_the_queue_saturated_does_not_end_the_wait() {
        let reserve = 100;
        let budget = std::sync::Arc::new(super::OutboundBudget::with_block_reserve(
            10,
            2 * reserve,
            reserve,
        ));
        for _ in 0..3 {
            assert!(budget.admit(90));
        }
        assert!(!budget.has_block_production_headroom());
        let (waiter, done) = spawn_waiter(&budget, std::time::Duration::from_secs(60));

        // 180 pending plus the 100 reserve still exceeds the 200 cap: the
        // wake finds no headroom and the waiter must keep waiting.
        std::thread::sleep(std::time::Duration::from_millis(50));
        budget.release(90);
        let early = done.recv_timeout(std::time::Duration::from_millis(300));
        // 90 + 100 <= 200: this release opens the gate.
        budget.release(90);
        let woke = done.recv_timeout(WAKE_DEADLINE);
        budget.mark_writer_dead();
        waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(
            early.is_err(),
            "a still-saturated queue keeps the waiter parked"
        );
        assert!(woke.is_ok(), "the release that opens the gate wakes it");
    }

    fn wire_len_of(message: &crate::Message) -> usize {
        crate::wire::wire_len(message).unwrap_or_else(|_| panic!("test message must encode"))
    }
}
