//! Per-connection identity and cancellation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TrySendError};
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

    /// Test-only identity with a chosen numeric value (eviction fixtures
    /// order candidates by it).
    #[cfg(test)]
    pub(crate) fn for_test_raw(id: u64) -> Self {
        Self(id)
    }
}

/// Attribution token for an event delivered by one connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSource {
    /// Logical peer endpoint; `None` for unidentified inbound sessions.
    pub(crate) endpoint: Option<crate::PeerEndpoint>,
    connection_id: ConnectionId,
}

impl PeerSource {
    /// Returns the connection id of the delivering peer.
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Logical endpoint of the delivering peer, if identified.
    #[must_use]
    pub fn endpoint(&self) -> Option<crate::PeerEndpoint> {
        self.endpoint
    }

    /// Mints a source with a fresh process-unique identity for tests.
    #[cfg(test)]
    pub(crate) fn for_test(addr: SocketAddr) -> Self {
        Self {
            endpoint: Some(crate::PeerEndpoint::Ip(addr)),
            connection_id: ConnectionId::allocate(),
        }
    }

    /// Mints a source for an endpoint-identified test peer.
    #[cfg(test)]
    pub(crate) fn for_test_endpoint(endpoint: crate::PeerEndpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
            connection_id: ConnectionId::allocate(),
        }
    }

    /// Mints an unidentified source for tests.
    #[cfg(test)]
    pub(crate) fn for_test_unidentified() -> Self {
        Self {
            endpoint: None,
            connection_id: ConnectionId::allocate(),
        }
    }
}

impl From<PeerSource> for bitcoin_rs_mempool::PeerToken {
    fn from(source: PeerSource) -> Self {
        Self {
            endpoint: source.endpoint,
            connection_id: source.connection_id.get(),
        }
    }
}

/// Maximum queued messages for one peer connection.
const OUTBOUND_QUEUE_MAX_MESSAGES: usize = 4096;

/// Maximum queued full wire bytes for one peer connection.
const OUTBOUND_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Aggregate queued full wire bytes shared by every connection of one node.
///
/// The per-connection [`OutboundBudget`] keeps its own message and byte
/// bounds; this budget caps the SUM of queued bytes across all of them, so
/// one stalled peer's full queue cannot multiply by the connection count
/// into gigabytes of retained memory. No tuning knob: the aggregate equals
/// one connection's maximum, the operator-visible queue bound.
///
/// The cap is strict. Every byte is charged by compare-and-swap before the
/// message that owns it exists, so the counter never exceeds the cap, not
/// even transiently, and an empty local queue gets no exemption. A refusal by
/// this budget is backpressure on the producer ([`Refusal::Shared`]); it
/// never disconnects a peer for bytes another peer queued.
pub(crate) const SHARED_OUTBOUND_QUEUE_MAX_BYTES: usize = OUTBOUND_QUEUE_MAX_BYTES;

/// Bytes of the aggregate that bulk production may never take: one maximum
/// frame, derived from the block-production reserve. Control traffic (pings,
/// replies, parked misses) keeps flowing into this margin while bulk
/// production is parked behind the lower bulk limit.
const SHARED_BULK_MARGIN_BYTES: usize = BLOCK_PRODUCTION_RESERVE_BYTES;

const _: () = assert!(
    BLOCK_PRODUCTION_RESERVE_BYTES >= crate::wire::HEADER_LEN + crate::wire::MAX_MESSAGE_PAYLOAD
);

/// Per-node shared outbound queued-byte budget, owned by the P2P service
/// (never process-global: independent services stay independent).
///
/// Byte-only: the per-connection budget keeps the message-count bound and
/// the block-production reserve, and takes this aggregate's bytes for every
/// charge it hands out. `pending_bytes` always equals the sum of the live
/// [`OutboundCredit`]s of every connection of the node.
#[derive(Debug)]
pub(crate) struct SharedOutboundBudget {
    /// Hard cap: no charge may take the counter above it.
    max_bytes: usize,
    /// Cap for bulk production reservations: `max_bytes` less the margin.
    bulk_limit: usize,
    pending_bytes: AtomicUsize,
    /// Signalled when any connection releases aggregate bytes.
    drained: Condvar,
    /// Orders aggregate updates against a waiter's predicate check; guards
    /// no data.
    drained_lock: Mutex<()>,
}

impl SharedOutboundBudget {
    /// Builds the node budget with the shared aggregate cap and the derived
    /// one-maximum-frame bulk margin.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_limits(SHARED_OUTBOUND_QUEUE_MAX_BYTES, SHARED_BULK_MARGIN_BYTES)
    }

    /// Builds a budget with an explicit cap and bulk margin (tests size both).
    #[must_use]
    pub(crate) fn with_limits(max_bytes: usize, margin: usize) -> Self {
        debug_assert!(margin <= max_bytes, "the bulk margin sits inside the cap");
        Self {
            max_bytes,
            bulk_limit: max_bytes.saturating_sub(margin),
            pending_bytes: AtomicUsize::new(0),
            drained: Condvar::new(),
            drained_lock: Mutex::new(()),
        }
    }

    /// Takes `bytes` from the aggregate when the total stays at or below
    /// `limit`; the total is never above `limit` at any instant.
    fn try_charge(&self, bytes: usize, limit: usize) -> bool {
        self.pending_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_add(bytes).filter(|total| *total <= limit)
            })
            .is_ok()
    }

    /// Returns `bytes` to the aggregate counter. The caller wakes the
    /// waiters with [`Self::wake_waiters`] once its own state is consistent:
    /// the counter moves first, then the lock is taken, then the waiters are
    /// notified, so no wake is lost.
    ///
    /// The subtraction is checked: a release larger than the charge would be
    /// a double release, which the debug assertion reports.
    fn release_counter(&self, bytes: usize) {
        let released =
            self.pending_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "released more shared bytes than charged");
    }

    /// Notifies every session parked in a shared wait.
    ///
    /// PRE: the aggregate state a waiter's predicate reads was updated
    /// before the call. POST: a waiter either observed that update or is
    /// woken by this call.
    fn wake_waiters(&self) {
        drop(self.drained_lock.lock());
        self.drained.notify_all();
    }

    /// Snapshot: whether a charge of `bytes` would fit under the hard cap
    /// right now. For wait and pacing predicates only; admission is
    /// [`Self::try_charge`].
    #[must_use]
    fn may_admit(&self, bytes: usize) -> bool {
        self.pending_bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .is_some_and(|total| total <= self.max_bytes)
    }

    /// Snapshot: whether a bulk reservation of `bytes` would fit under the
    /// bulk limit right now. For wait and pacing predicates only.
    #[must_use]
    fn may_reserve_bulk(&self, bytes: usize) -> bool {
        self.pending_bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .is_some_and(|total| total <= self.bulk_limit)
    }

    /// Charged aggregate bytes awaiting release.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> usize {
        self.pending_bytes.load(Ordering::Acquire)
    }
}

/// Why a charge was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The connection's own bounds: its item cap, its byte cap, or a writer
    /// that has already returned.
    Local,
    /// The node aggregate is full. Pure backpressure: the lease stays live
    /// and the caller keeps its intent.
    Shared,
}

/// The sole owner of one outbound charge: one local message, `bytes` local
/// bytes, and `bytes` aggregate bytes.
///
/// A charge has exactly one owner at every moment: this credit, then the
/// [`QueuedFrame`] that carries it through the channel, then the writer's
/// burst. Dropping the owner releases both halves, wherever the drop happens
/// (written, refused, drained, or discarded with the channel). There is no
/// reclaim and no conversion across threads.
#[must_use]
#[derive(Debug)]
pub(crate) struct OutboundCredit {
    budget: Arc<OutboundBudget>,
    bytes: usize,
}

impl OutboundCredit {
    /// Bytes this credit still owns.
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether this credit was charged to `budget`.
    fn belongs_to(&self, budget: &Arc<OutboundBudget>) -> bool {
        Arc::ptr_eq(&self.budget, budget)
    }
}

impl Drop for OutboundCredit {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// One channel item: a message together with the charge that pays for it.
///
/// The writer receives frames; a frame's credit drops, and its bytes return
/// to the budgets, when the writer is done with it, when the channel discards
/// it, or when a refused enqueue returns it.
#[derive(Debug)]
pub struct QueuedFrame {
    message: crate::Message,
    credit: OutboundCredit,
}

impl QueuedFrame {
    /// The queued message.
    #[must_use]
    pub fn message(&self) -> &crate::Message {
        &self.message
    }

    /// Takes the message out, releasing the frame's charge.
    #[must_use]
    pub fn into_message(self) -> crate::Message {
        let Self { message, credit } = self;
        drop(credit);
        message
    }
}

/// Why [`PeerLease::send`] did not queue a message. The refused message is
/// returned to the caller either way.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboundRefusal {
    /// The lease is cancelled, or this send cancelled it: the connection is
    /// over.
    Closed(crate::Message),
    /// The node's aggregate outbound budget is full while the lease is
    /// live. Nothing was cancelled and nothing was queued; the caller keeps
    /// its intent and retries.
    Saturated(crate::Message),
}

impl OutboundRefusal {
    /// Takes the refused message back.
    #[must_use]
    pub fn into_message(self) -> crate::Message {
        match self {
            Self::Closed(message) | Self::Saturated(message) => message,
        }
    }

    /// Whether the refusal was aggregate backpressure on a live lease.
    #[must_use]
    pub const fn is_saturated(&self) -> bool {
        matches!(self, Self::Saturated(_))
    }
}

impl std::fmt::Display for OutboundRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(_) => f.write_str("outbound queue closed"),
            Self::Saturated(_) => f.write_str("outbound queue saturated"),
        }
    }
}

impl std::error::Error for OutboundRefusal {}

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

/// Item and full-framed-wire-byte accounting for one outbound queue.
///
/// Every queued message is owned by an [`OutboundCredit`]: a charge taken
/// here, against the local bounds first and then against the node aggregate,
/// before the message is queued. A message is charged when both local
/// counters were below their high-water marks immediately before its
/// addition, which admits one oversized message to an empty local queue. The
/// credit travels with the message as a [`QueuedFrame`] and releases both
/// halves when dropped, whether the writer wrote it, the writer's error path
/// dropped it, or the channel discarded it.
///
/// # Refusal policy
///
/// A local refusal ([`Refusal::Local`]: item cap, byte cap, dead writer)
/// disconnects only this peer: [`PeerLease::send`] cancels the lease and
/// returns the refused message. An aggregate refusal ([`Refusal::Shared`])
/// never does: the lease stays live and the caller keeps its intent. Bulk
/// production reserves a worst-case frame ([`OutboundBudget::try_reserve_production`])
/// before it loads a body, so a queue that is full by item count or by bytes
/// parks the session instead of reaching a refusal.
///
/// # Waiting
///
/// A paused session sleeps on a condvar guarded by a lock that protects no
/// data. The predicate it waits for reads atomics only, and every decrease of
/// those atomics (`release`, `shrink`, `mark_writer_dead`) updates the
/// counter, then takes the lock, then notifies. A waiter therefore either
/// sees the new state in its predicate check, or is already parked when the
/// notification fires, so no wake is lost. While an aggregate is attached the
/// wait parks on the aggregate condvar, so another connection's drain wakes
/// it too.
///
/// # Lock order
///
/// Caller locks (peer table, scheduler, relay state), then this budget's
/// `drained_lock`, then the aggregate's. No path holds the two budget locks
/// at once (the aggregate is charged and released with atomics under the
/// local lock, and notified only after the local lock is dropped), and no
/// send ever blocks.
#[derive(Debug)]
pub(crate) struct OutboundBudget {
    max_messages: usize,
    max_bytes: usize,
    block_reserve: usize,
    pending_messages: AtomicUsize,
    pending_bytes: AtomicUsize,
    /// Test instrumentation: count of refused charges and reservations.
    #[cfg(test)]
    refusals: AtomicUsize,
    /// Signalled when a credit releases or the writer exits.
    drained: Condvar,
    /// Serializes this connection's admissions and releases against each
    /// other and orders updates against a waiter's predicate check; guards
    /// no data.
    drained_lock: Mutex<()>,
    /// Set once the connection writer has returned. Later charges are
    /// refused; credits still release when their owners drop.
    writer_dead: AtomicBool,
    /// Aggregate byte budget of the owning node, or `None` for standalone
    /// budgets (tests). Every charge takes the local bound first, then the
    /// aggregate; every release returns both.
    shared: Option<Arc<SharedOutboundBudget>>,
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
            #[cfg(test)]
            refusals: AtomicUsize::new(0),
            drained: Condvar::new(),
            drained_lock: Mutex::new(()),
            writer_dead: AtomicBool::new(false),
            shared: None,
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

    /// Charges `wire_len` bytes and one message.
    ///
    /// PRE: none. POST: `Ok` carries the credit that owns the charge on both
    /// halves; `Err(Local)` means the writer is gone or a local cap is at its
    /// high-water mark; `Err(Shared)` means the aggregate cap would be
    /// exceeded. A refusal charges nothing.
    pub(crate) fn try_charge(self: &Arc<Self>, wire_len: usize) -> Result<OutboundCredit, Refusal> {
        let _guard = self.drained_lock.lock();
        if self.writer_dead.load(Ordering::Acquire) {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Local);
        }
        let messages = self.pending_messages.load(Ordering::Acquire);
        let bytes = self.pending_bytes.load(Ordering::Acquire);
        if messages >= self.max_messages || bytes >= self.max_bytes {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Local);
        }
        if let Some(shared) = &self.shared
            && !shared.try_charge(wire_len, shared.max_bytes)
        {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Shared);
        }
        Ok(self.commit_locked(wire_len))
    }

    /// Reserves one worst-case frame before a body is loaded.
    ///
    /// PRE: none. POST: `Ok` carries a credit of the block-production
    /// reserve. The local rule is the production headroom (a free item slot
    /// and room for the reserve behind everything pending, or an empty
    /// queue); the aggregate rule is that the reserve fits under the bulk
    /// limit, which keeps one maximum frame of the aggregate for control
    /// traffic. A refusal charges nothing.
    pub(crate) fn try_reserve_production(self: &Arc<Self>) -> Result<OutboundCredit, Refusal> {
        let _guard = self.drained_lock.lock();
        if self.writer_dead.load(Ordering::Acquire) || !self.local_production_headroom() {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Local);
        }
        if let Some(shared) = &self.shared
            && !shared.try_charge(self.block_reserve, shared.bulk_limit)
        {
            #[cfg(test)]
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refusal::Shared);
        }
        Ok(self.commit_locked(self.block_reserve))
    }

    /// Reserves `bound` bytes for a reply that is built only afterwards.
    ///
    /// PRE: `bound` is at least the reply's wire length. POST: as
    /// [`Self::try_charge`].
    pub(crate) fn try_reserve_reply(
        self: &Arc<Self>,
        bound: usize,
    ) -> Result<OutboundCredit, Refusal> {
        self.try_charge(bound)
    }

    /// Adds the local half of a charge whose aggregate half is already taken.
    ///
    /// PRE: the caller holds `drained_lock`.
    fn commit_locked(self: &Arc<Self>, bytes: usize) -> OutboundCredit {
        self.pending_messages.fetch_add(1, Ordering::AcqRel);
        self.pending_bytes.fetch_add(bytes, Ordering::AcqRel);
        OutboundCredit {
            budget: Arc::clone(self),
            bytes,
        }
    }

    /// Gives back the part of `credit` beyond `to` bytes, on both halves.
    ///
    /// PRE: `credit` was charged to this budget and `to <= credit.bytes()`.
    /// POST: the credit owns exactly `to` bytes and still one message.
    fn shrink(&self, credit: &mut OutboundCredit, to: usize) {
        debug_assert!(to <= credit.bytes, "a credit only shrinks");
        let excess = credit.bytes.saturating_sub(to);
        if excess == 0 {
            return;
        }
        credit.bytes -= excess;
        {
            let _guard = self.drained_lock.lock();
            self.release_bytes_locked(excess);
            if let Some(shared) = &self.shared {
                shared.release_counter(excess);
            }
        }
        self.wake_after_release();
    }

    /// Returns one credit's charge. Called only by [`OutboundCredit`]'s drop.
    fn release(&self, wire_len: usize) {
        {
            let _guard = self.drained_lock.lock();
            let messages =
                self.pending_messages
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                        pending.checked_sub(1)
                    });
            debug_assert!(messages.is_ok(), "released more messages than charged");
            self.release_bytes_locked(wire_len);
            if let Some(shared) = &self.shared {
                shared.release_counter(wire_len);
            }
        }
        self.wake_after_release();
    }

    /// Subtracts local bytes. The caller holds `drained_lock`.
    fn release_bytes_locked(&self, bytes: usize) {
        let released =
            self.pending_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "released more bytes than charged");
    }

    /// Notifies local waiters, then aggregate waiters, after counters moved.
    fn wake_after_release(&self) {
        self.wake_waiters();
        if let Some(shared) = &self.shared {
            shared.wake_waiters();
        }
    }

    /// Notifies every session paused in [`OutboundBudget::wait_for`].
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

    /// Records that the connection writer has returned, then wakes every
    /// waiting session. It reclaims nothing: queued frames release their own
    /// charges when they drop.
    pub(crate) fn mark_writer_dead(&self) {
        {
            // Under the admission lock, so a charge either finished before
            // the writer died (its frame is drained or discarded, and
            // releases) or sees the flag and is refused.
            let _guard = self.drained_lock.lock();
            self.writer_dead.store(true, Ordering::Release);
        }
        self.wake_after_release();
    }

    /// Returns whether the connection writer has returned.
    #[must_use]
    pub(crate) fn writer_dead(&self) -> bool {
        self.writer_dead.load(Ordering::Acquire)
    }

    /// Blocks the calling session until `ready` holds, the writer exits, or
    /// `timeout` elapses.
    ///
    /// PRE: the caller holds no lock another thread needs to release the
    /// budget (the pool, the socket), and `ready` reads atomics only.
    /// POST: returns at once when the writer is dead or `ready` already
    /// holds; otherwise returns once either holds or `timeout` has elapsed on
    /// the monotonic clock. Spurious wakeups re-enter the wait. The return
    /// promises nothing: a snapshot that held can be taken by another sender
    /// before the caller acts, so the caller retries through the admission
    /// itself and rechecks [`OutboundBudget::writer_dead`] and its own
    /// cancellation.
    ///
    /// While an aggregate budget is attached the wait parks on the aggregate
    /// condvar instead: any connection's drain can open shared room, and
    /// every release wakes here.
    pub(crate) fn wait_for(&self, timeout: Duration, ready: impl Fn() -> bool) {
        let deadline = Instant::now() + timeout;
        if let Some(shared) = &self.shared {
            let mut guard = shared.drained_lock.lock();
            while !(self.writer_dead() || ready()) {
                if shared.drained.wait_until(&mut guard, deadline).timed_out() {
                    return;
                }
            }
            return;
        }
        let mut guard = self.drained_lock.lock();
        while !(self.writer_dead() || ready()) {
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

    /// Returns the count of charges and reservations refused on this budget.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn refusals(&self) -> usize {
        self.refusals.load(Ordering::Acquire)
    }

    /// Snapshot: whether one more worst-case frame could be reserved right
    /// now ([`Self::try_reserve_production`] would not refuse). A wait and
    /// pacing predicate only; the reservation itself is the admission.
    #[must_use]
    pub(crate) fn may_reserve_production(&self) -> bool {
        self.local_production_headroom()
            && self
                .shared
                .as_ref()
                .is_none_or(|shared| shared.may_reserve_bulk(self.block_reserve))
    }

    /// Snapshot: whether a charge of `bytes` could be taken right now
    /// ([`Self::try_charge`] would not refuse). A wait and pacing predicate
    /// only.
    #[must_use]
    pub(crate) fn may_charge(&self, bytes: usize) -> bool {
        self.local_has_room()
            && self
                .shared
                .as_ref()
                .is_none_or(|shared| shared.may_admit(bytes))
    }

    /// The per-connection half of the production gate: a free item slot and
    /// room for the reserve behind everything pending, or an empty queue
    /// (which admits one oversized message). A snapshot of this connection's
    /// own queue state only: a probe whose refusal would close the lease
    /// asks it before sending, so the connection's own saturation is never
    /// mistaken for the aggregate's.
    pub(crate) fn local_production_headroom(&self) -> bool {
        let messages = self.pending_messages.load(Ordering::Acquire);
        messages == 0
            || (messages < self.max_messages
                && self
                    .pending_bytes
                    .load(Ordering::Acquire)
                    .saturating_add(self.block_reserve)
                    <= self.max_bytes)
    }

    /// The per-connection admit condition without the reserve: both local
    /// caps are below their high-water marks and the writer is alive.
    fn local_has_room(&self) -> bool {
        !self.writer_dead()
            && self.pending_messages.load(Ordering::Acquire) < self.max_messages
            && self.pending_bytes.load(Ordering::Acquire) < self.max_bytes
    }
}

/// Cloneable handle for one live peer connection.
#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<QueuedFrame>,
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
    pub fn new(outbound: Sender<QueuedFrame>) -> Self {
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
    pub(crate) fn new_block_relay(outbound: Sender<QueuedFrame>) -> Self {
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
        outbound: Sender<QueuedFrame>,
        role: crate::peer_info::PeerRole,
    ) -> Self {
        Self::with_direction(outbound, false, role, true)
    }

    /// Creates an inbound lease with a fresh process-unique identity.
    #[must_use]
    pub fn new_inbound(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(outbound, true, crate::peer_info::PeerRole::FullRelay, false)
    }

    /// Test constructor: an outbound lease already `connected_at` old, for
    /// exercising rules gated on connection age without sleeping.
    #[cfg(test)]
    pub(crate) fn new_connected_at(outbound: Sender<QueuedFrame>, connected_at: Instant) -> Self {
        let mut lease = Self::new(outbound);
        lease.backdate_for_test(connected_at);
        lease
    }

    fn with_direction(
        outbound: Sender<QueuedFrame>,
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
        outbound: Sender<QueuedFrame>,
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
        outbound: Sender<QueuedFrame>,
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

    /// Attaches the owning node's aggregate outbound budget to this lease's
    /// fresh per-connection budget: local message and byte bounds stay
    /// per-peer, queued bytes also count against the node aggregate.
    /// Construction-time only: call before any send, while the budget `Arc`
    /// is still solely owned (no handle has escaped) and its counters are
    /// still zero.
    #[must_use]
    pub(crate) fn with_shared_budget(mut self, shared: &Arc<SharedOutboundBudget>) -> Self {
        // Sole ownership holds: the budget `Arc` was just built with this
        // lease and no handle has escaped yet.
        if let Some(budget) = Arc::get_mut(&mut self.budget) {
            debug_assert!(budget.shared.is_none());
            budget.shared = Some(Arc::clone(shared));
        } else {
            debug_assert!(false, "the aggregate attaches before the budget is shared");
        }
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
                peer_addr = ?source.endpoint,
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

    /// Stamps an inbound event with this connection's identity and endpoint.
    #[must_use]
    pub fn source(&self, endpoint: Option<crate::PeerEndpoint>) -> PeerSource {
        PeerSource {
            endpoint,
            connection_id: self.id,
        }
    }

    /// Stamps an event for a direct-IP connection at `addr`.
    #[must_use]
    pub fn source_ip(&self, addr: SocketAddr) -> PeerSource {
        self.source(Some(crate::accepted_ip_identity(addr)))
    }

    /// Queues a message for this connection's writer.
    ///
    /// PRE: none. POST: `Ok` means the message is queued with its charge.
    /// `Closed` means the lease is cancelled, or this call cancelled it for
    /// the connection's own state (an unencodable message, a local item or
    /// byte cap, a dead writer, a full or closed channel). `Saturated` means
    /// the node's aggregate budget is full: the lease is live, nothing was
    /// cancelled, and the caller keeps its intent. The refused message is
    /// returned either way.
    /// INVARIANT: never blocks.
    ///
    /// Exactness of the accounting does not depend on the channel flavor:
    /// each frame's credit drops when the frame drops, wherever that
    /// happens (after the writer wrote it, when a refused enqueue returns
    /// it, when the writer drains the channel on exit, or when the channel
    /// discards it).
    #[expect(clippy::result_large_err)]
    pub fn send(&self, message: crate::Message) -> Result<(), OutboundRefusal> {
        if self.is_cancelled() {
            return Err(OutboundRefusal::Closed(message));
        }
        let Ok(wire_len) = crate::wire::wire_len(&message) else {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        };
        match self.budget.try_charge(wire_len) {
            Ok(credit) => self.enqueue(message, credit),
            Err(Refusal::Local) => {
                self.cancel();
                Err(OutboundRefusal::Closed(message))
            }
            Err(Refusal::Shared) => Err(OutboundRefusal::Saturated(message)),
        }
    }

    /// Queues a message under a reservation taken before the message existed.
    ///
    /// PRE: `credit` was charged to this lease's budget and covers the
    /// message's wire length. POST: the credit is shrunk to the exact wire
    /// length and travels with the message. A cancelled lease, an unencodable
    /// message, or a message larger than its reservation closes the lease
    /// (fail closed) and drops the credit. This never returns `Saturated`:
    /// the bytes were already taken.
    #[expect(clippy::result_large_err)]
    pub(crate) fn send_with(
        &self,
        mut credit: OutboundCredit,
        message: crate::Message,
    ) -> Result<(), OutboundRefusal> {
        debug_assert!(
            credit.belongs_to(&self.budget),
            "a credit is spent only on the lease that charged it"
        );
        if self.is_cancelled() {
            return Err(OutboundRefusal::Closed(message));
        }
        let Ok(wire_len) = crate::wire::wire_len(&message) else {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        };
        if wire_len > credit.bytes() {
            self.cancel();
            return Err(OutboundRefusal::Closed(message));
        }
        self.budget.shrink(&mut credit, wire_len);
        self.enqueue(message, credit)
    }

    /// Hands a charged message to the writer channel.
    #[expect(clippy::result_large_err)]
    fn enqueue(
        &self,
        message: crate::Message,
        credit: OutboundCredit,
    ) -> Result<(), OutboundRefusal> {
        match self.outbound.try_send(QueuedFrame { message, credit }) {
            Ok(()) => {
                *self.last_send.lock() = Instant::now();
                Ok(())
            }
            Err(TrySendError::Full(frame) | TrySendError::Disconnected(frame)) => {
                // Taking the frame apart returns its charge.
                let message = frame.into_message();
                self.cancel();
                Err(OutboundRefusal::Closed(message))
            }
        }
    }

    /// Reserves one worst-case bulk frame before a body is loaded.
    ///
    /// PRE: none. POST: `Ok` carries the credit, spent with
    /// [`Self::send_with`] or dropped to return the bytes. Refusal charges
    /// nothing and cancels nothing; the caller decides what a local or a
    /// shared refusal means.
    pub(crate) fn try_reserve_production(&self) -> Result<OutboundCredit, Refusal> {
        self.budget.try_reserve_production()
    }

    /// Reserves `bound` bytes for a reply built only afterwards.
    ///
    /// PRE: `bound` is at least the reply's full wire length. POST: as
    /// [`Self::try_reserve_production`].
    pub(crate) fn try_reserve_reply(&self, bound: usize) -> Result<OutboundCredit, Refusal> {
        self.budget.try_reserve_reply(bound)
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
    use super::{
        OutboundBudget, OutboundCredit, OutboundRefusal, PeerLease, QueuedFrame, Refusal,
        SharedOutboundBudget,
    };
    use crossbeam_channel::Receiver;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// A standalone per-connection budget (no aggregate).
    fn standalone(max_messages: usize, max_bytes: usize, reserve: usize) -> Arc<OutboundBudget> {
        Arc::new(OutboundBudget::with_block_reserve(
            max_messages,
            max_bytes,
            reserve,
        ))
    }

    /// Charges `bytes` or fails the test with the refusal kind.
    fn charge(budget: &Arc<OutboundBudget>, bytes: usize) -> OutboundCredit {
        budget
            .try_charge(bytes)
            .unwrap_or_else(|refusal| panic!("charge of {bytes} refused: {refusal:?}"))
    }

    /// Reserves a production credit or fails the test with the refusal kind.
    fn reserve(budget: &Arc<OutboundBudget>) -> OutboundCredit {
        budget
            .try_reserve_production()
            .unwrap_or_else(|refusal| panic!("production reservation refused: {refusal:?}"))
    }

    /// A lease on `shared` with roomy local bounds and the given reserve; the
    /// receiver is returned so the channel stays connected.
    fn shared_lease_with_reserve(
        shared: &Arc<SharedOutboundBudget>,
        reserve_bytes: usize,
    ) -> (PeerLease, Receiver<QueuedFrame>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new_with_budget(
            tx,
            false,
            OutboundBudget::with_block_reserve(100, 1_000_000, reserve_bytes),
        )
        .with_shared_budget(shared);
        (lease, rx)
    }

    /// A default lease on `shared`.
    fn shared_lease(shared: &Arc<SharedOutboundBudget>) -> (PeerLease, Receiver<QueuedFrame>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        (PeerLease::new(tx).with_shared_budget(shared), rx)
    }

    fn peer_info(
        addr: crate::PeerEndpoint,
        conn_time: u64,
    ) -> Result<crate::PeerInfo, Box<dyn std::error::Error>> {
        let ip = addr
            .as_ip()
            .ok_or_else(|| std::io::Error::other("ip test peer"))?;
        Ok(crate::PeerInfo {
            endpoint: Some(addr),
            network: addr.net(),
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
            addr_bind: crate::TransportRemote::new(ip),
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        })
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
    fn stale_connection_cannot_publish_over_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let table = crate::PeerTable::new();
        let addr: crate::PeerEndpoint = SocketAddr::from(([127, 0, 0, 1], 18_450)).into();
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        assert!(!table.register(addr, old.clone()));
        assert!(table.publish_info(addr, &old, peer_info(addr, 1)?));

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        assert!(table.register(addr, replacement.clone()));
        assert!(old.is_cancelled());
        assert_eq!(table.infos(), []);
        assert_eq!(table.ready_source(addr), None);
        assert!(!table.publish_info(addr, &old, peer_info(addr, 2)?));
        assert_eq!(table.infos(), []);

        assert!(table.publish_info(addr, &replacement, peer_info(addr, 3)?));
        assert_eq!(table.infos(), vec![peer_info(addr, 3)?]);
        assert_eq!(
            table.ready_source(addr),
            Some(replacement.source(Some(addr)))
        );
        assert!(
            table
                .lease(addr)
                .is_some_and(|current| current.same_connection(&replacement))
        );
        Ok(())
    }

    #[test]
    fn stale_disconnect_source_preserves_replacement() -> Result<(), Box<dyn std::error::Error>> {
        let table = crate::PeerTable::new();
        let addr: crate::PeerEndpoint = SocketAddr::from(([127, 0, 0, 1], 18_451)).into();
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let stale_source = old.source(Some(addr));

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());
        table.publish_info(addr, &replacement, peer_info(addr, 2)?);

        assert!(!table.disconnect_source(stale_source));
        assert!(!replacement.is_cancelled());
        assert!(table.is_connected(addr));
        assert_eq!(table.infos(), vec![peer_info(addr, 2)?]);

        assert!(table.disconnect_source(replacement.source(Some(addr))));
        assert!(replacement.is_cancelled());
        assert!(!table.is_connected(addr));
        assert_eq!(table.infos(), []);
        Ok(())
    }

    #[test]
    fn ready_snapshot_keeps_identity_across_same_address_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = crate::PeerTable::new();
        let addr: crate::PeerEndpoint = SocketAddr::from(([127, 0, 0, 1], 18_452)).into();
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        table.register(addr, old.clone());
        assert!(table.publish_info(addr, &old, peer_info(addr, 1)?));
        let Some(snapshot) = table.ready_peers().pop() else {
            return Err(std::io::Error::other("ready peer snapshot missing").into());
        };

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());

        assert!(table.lease_source(snapshot).is_none());
        assert!(table.lease_source(replacement.source(Some(addr))).is_some());
        Ok(())
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
        let budget = standalone(
            1,
            super::BLOCK_PRODUCTION_RESERVE_BYTES,
            super::BLOCK_PRODUCTION_RESERVE_BYTES,
        );
        let credit = charge(&budget, worst_case_wire);
        assert_eq!(
            credit.bytes(),
            worst_case_wire,
            "a worst-case block must be admissible when the byte cap equals the reserve"
        );
        drop(credit);

        let progress = standalone(4, 100, 1_000);
        assert!(progress.may_reserve_production());

        let reserve_bytes = 100;
        let budget = standalone(10, 3 * reserve_bytes, reserve_bytes);
        assert!(budget.may_reserve_production());
        let first = charge(&budget, reserve_bytes);
        assert!(budget.may_reserve_production());
        let second = charge(&budget, reserve_bytes);
        assert!(budget.may_reserve_production());
        let third = charge(&budget, reserve_bytes);
        assert!(!budget.may_reserve_production());
        assert_eq!(budget.try_reserve_production().err(), Some(Refusal::Local));
        drop(first);
        assert!(budget.may_reserve_production());
        drop((second, third));
    }

    #[test]
    fn headroom_needs_a_free_item_slot_as_well_as_the_byte_reserve() {
        // Bytes are abundant: only the item cap can close the gate.
        let budget = standalone(2, 1_000_000, 100);
        assert!(budget.may_reserve_production(), "empty queue");
        let first = charge(&budget, 10);
        assert!(budget.may_reserve_production(), "one slot is free");
        let second = charge(&budget, 10);
        assert!(
            !budget.may_reserve_production(),
            "no item slot is free, however few bytes are queued"
        );
        drop(first);
        assert!(budget.may_reserve_production());
        drop(second);
        assert!(
            budget.may_reserve_production(),
            "an empty queue admits one oversized message"
        );
    }

    #[test]
    fn may_charge_is_the_admit_condition_without_the_reserve() {
        let reserve_bytes = 100;
        let budget = standalone(3, 3 * reserve_bytes, reserve_bytes);
        assert!(budget.may_charge(10));
        // 250 queued bytes plus the 100-byte reserve exceed the 300-byte cap.
        let first = charge(&budget, 2 * reserve_bytes + 50);
        assert!(
            !budget.may_reserve_production(),
            "no room left for a worst-case block"
        );
        assert!(
            budget.may_charge(10),
            "a short control message still fits below both caps"
        );
        let second = charge(&budget, 2 * reserve_bytes);
        assert!(
            !budget.may_charge(10),
            "the byte cap is reached: a charge would refuse"
        );
        drop(second);
        let third = charge(&budget, 10);
        let fourth = charge(&budget, 10);
        assert!(
            !budget.may_charge(10),
            "the item cap is reached: a charge would refuse"
        );
        drop((first, third, fourth));
    }

    #[test]
    fn outbound_budget_refuses_at_exact_item_cap_and_byte_cap() {
        let ping_len = wire_len_of(&crate::Message::Ping(1));

        let items = standalone(2, 100 * ping_len, 0);
        let first = charge(&items, ping_len);
        let second = charge(&items, ping_len);
        assert_eq!(items.try_charge(ping_len).err(), Some(Refusal::Local));
        assert_eq!(items.pending(), (2, 2 * ping_len));
        drop((first, second));
        assert_eq!(items.pending(), (0, 0));

        let bytes = standalone(100, 2 * ping_len, 0);
        let first = charge(&bytes, ping_len);
        let second = charge(&bytes, ping_len);
        assert_eq!(bytes.try_charge(ping_len).err(), Some(Refusal::Local));
        assert_eq!(bytes.pending(), (2, 2 * ping_len));
        drop((first, second));
        assert_eq!(bytes.pending(), (0, 0));
    }

    #[test]
    fn oversized_single_message_admits_on_empty_local_queue() {
        let budget = standalone(10, 100, 0);

        let oversized = charge(&budget, 1_000);
        assert_eq!(budget.pending(), (1, 1_000));
        assert_eq!(budget.try_charge(1).err(), Some(Refusal::Local));
        drop(oversized);
        let next = charge(&budget, 1);
        drop(next);
        assert_eq!(budget.pending(), (0, 0));
    }

    #[test]
    fn saturated_send_cancels_lease_and_returns_message() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let first = crate::Message::Ping(1);
        let second = crate::Message::Ping(2);
        let lease = PeerLease::new_with_budget(
            tx,
            false,
            OutboundBudget::with_block_reserve(1, 1_000_000, 0),
        );

        assert!(lease.send(first).is_ok());
        assert_eq!(
            lease.send(second.clone()),
            Err(OutboundRefusal::Closed(second))
        );
        assert!(lease.is_cancelled());
    }

    #[test]
    fn full_channel_send_cancels_lease_and_returns_message() {
        let (tx, _rx) = crossbeam_channel::bounded(1);
        let lease = PeerLease::new(tx);
        let ping_len = wire_len_of(&crate::Message::Ping(1));

        assert!(lease.send(crate::Message::Ping(1)).is_ok());
        let message = crate::Message::Ping(2);
        assert_eq!(
            lease.send(message.clone()),
            Err(OutboundRefusal::Closed(message))
        );
        assert!(lease.is_cancelled());
        assert_eq!(
            lease.budget_handle().pending(),
            (1, ping_len),
            "the refused frame returned its charge; the queued frame keeps its own"
        );
    }

    #[test]
    fn disconnected_channel_send_cancels_lease_and_returns_charge() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        drop(rx);
        let lease = PeerLease::new(tx);

        let message = crate::Message::Ping(3);
        assert_eq!(
            lease.send(message.clone()),
            Err(OutboundRefusal::Closed(message))
        );
        assert!(lease.is_cancelled());
        assert_eq!(lease.budget_handle().pending(), (0, 0));
    }

    #[test]
    fn cancelled_lease_refuses_send() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        lease.cancel();

        assert_eq!(
            lease.send(crate::Message::Verack),
            Err(OutboundRefusal::Closed(crate::Message::Verack))
        );
    }

    /// The aggregate is a strict cap: with it full, a peer whose own queue is
    /// empty is refused too (no empty-queue bypass), its lease stays live,
    /// nothing is charged, and a retry after the drain succeeds.
    #[test]
    fn strict_cap_no_empty_queue_bypass() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(100, 0));
        let (hog, _hog_rx) = shared_lease(&shared);
        let hog_credit = charge(&hog.budget_handle(), 100);
        let (other, _other_rx) = shared_lease(&shared);

        let message = crate::Message::Ping(1);
        assert_eq!(
            other.send(message.clone()),
            Err(OutboundRefusal::Saturated(message))
        );
        assert!(!other.is_cancelled());
        assert_eq!(other.budget_handle().pending(), (0, 0));
        assert_eq!(shared.pending(), 100, "the cap is never exceeded");

        drop(hog_credit);
        assert_eq!(shared.pending(), 0);
        assert!(other.send(crate::Message::Ping(2)).is_ok());
    }

    /// The reservation is the admission: `max = 2R - 1 + margin` admits one
    /// production credit, `max = 2R + margin` admits two, and the next is a
    /// shared refusal that charges nothing.
    #[test]
    fn reservation_is_the_admission() {
        let reserve_bytes = 100;
        let margin = 40;
        for (max, admitted) in [
            (2 * reserve_bytes - 1 + margin, 1),
            (2 * reserve_bytes + margin, 2),
        ] {
            let shared = Arc::new(SharedOutboundBudget::with_limits(max, margin));
            let (lease, _rx) = shared_lease_with_reserve(&shared, reserve_bytes);
            let budget = lease.budget_handle();
            let mut held = Vec::new();
            while let Ok(credit) = budget.try_reserve_production() {
                held.push(credit);
            }
            assert_eq!(held.len(), admitted);
            assert_eq!(budget.try_reserve_production().err(), Some(Refusal::Shared));
            assert!(!lease.is_cancelled(), "a shared refusal cancels nothing");
            assert_eq!(shared.pending(), admitted * reserve_bytes);
            assert_eq!(budget.pending(), (admitted, admitted * reserve_bytes));
        }
    }

    /// 32 threads race for production credits while a sampler watches the
    /// counter: the cap is never exceeded at any instant and exactly
    /// `floor(bulk_limit / R)` reservations win.
    #[test]
    fn concurrent_reservations_never_exceed_cap() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let reserve_bytes = 100;
        let margin = 50;
        let max = 1_000 + margin;
        let shared = Arc::new(SharedOutboundBudget::with_limits(max, margin));
        let threads = 32;
        let start = Arc::new(Barrier::new(threads + 1));
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicUsize::new(0));
        let sampler = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let peak = Arc::clone(&peak);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    peak.fetch_max(shared.pending(), Ordering::AcqRel);
                }
            })
        };
        let mut racers = Vec::with_capacity(threads);
        for _ in 0..threads {
            let start = Arc::clone(&start);
            let (lease, rx) = shared_lease_with_reserve(&shared, reserve_bytes);
            racers.push(std::thread::spawn(move || {
                start.wait();
                let credit = lease.budget_handle().try_reserve_production().ok();
                (lease, rx, credit)
            }));
        }
        start.wait();
        let results: Vec<_> = racers
            .into_iter()
            .map(|racer| {
                racer
                    .join()
                    .unwrap_or_else(|_| panic!("racing reservation thread panicked"))
            })
            .collect();
        stop.store(true, Ordering::Release);
        sampler
            .join()
            .unwrap_or_else(|_| panic!("sampler thread panicked"));

        let admitted = results
            .iter()
            .filter(|(_, _, credit)| credit.is_some())
            .count();
        assert_eq!(admitted, 1_000 / reserve_bytes);
        assert_eq!(shared.pending(), admitted * reserve_bytes);
        assert!(
            peak.load(Ordering::Acquire) <= max,
            "the counter never exceeded the cap, even transiently"
        );
        drop(results);
        assert_eq!(shared.pending(), 0);
    }

    /// Dropping a credit and shrinking a credit each wake a session parked on
    /// the aggregate.
    #[test]
    fn shrink_and_drop_wake_waiters() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(100, 0));
        let (hog, _hog_rx) = shared_lease(&shared);
        let (waiter, _waiter_rx) = shared_lease(&shared);
        let hog_budget = hog.budget_handle();
        let waiter_budget = waiter.budget_handle();
        let mut hog_credit = charge(&hog_budget, 100);
        assert!(!waiter_budget.may_charge(50));

        let ready = {
            let budget = Arc::clone(&waiter_budget);
            move || budget.may_charge(50)
        };
        let (thread, done) = spawn_waiter(&waiter_budget, Duration::from_secs(60), ready);
        // The waiter may not have parked yet; the protocol must hold either way.
        std::thread::sleep(Duration::from_millis(50));
        hog_budget.shrink(&mut hog_credit, 40);
        let woke = done.recv_timeout(WAKE_DEADLINE);
        waiter_budget.mark_writer_dead();
        thread.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(woke.is_ok(), "a shrink must wake the waiter");
        assert_eq!(shared.pending(), 40);
        assert_eq!(hog_budget.pending(), (1, 40));

        // A fresh pair for the drop half, since the first waiter's writer is
        // marked dead.
        let (second_waiter, _second_rx) = shared_lease(&shared);
        let second_budget = second_waiter.budget_handle();
        let held = charge(&second_budget, 50);
        assert!(!second_budget.may_charge(50), "40 + 50 + 50 exceeds 100");
        let ready = {
            let budget = Arc::clone(&second_budget);
            move || budget.may_charge(50)
        };
        let (thread, done) = spawn_waiter(&second_budget, Duration::from_secs(60), ready);
        std::thread::sleep(Duration::from_millis(50));
        drop(hog_credit);
        let woke = done.recv_timeout(WAKE_DEADLINE);
        second_budget.mark_writer_dead();
        thread.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(woke.is_ok(), "a credit drop must wake the waiter");
        drop(held);
        assert_eq!(shared.pending(), 0);
    }

    /// Every credit returns its charge exactly once on both halves: a drop
    /// releases it, a shrink releases only the excess, and a bystander's
    /// charge is never touched.
    #[test]
    fn credit_drop_exactly_once() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(1_000, 0));
        let (bystander, _bystander_rx) = shared_lease(&shared);
        let bystander_credit = charge(&bystander.budget_handle(), 100);
        let (lease, _rx) = shared_lease(&shared);
        let budget = lease.budget_handle();

        let credit = charge(&budget, 40);
        assert_eq!(budget.pending(), (1, 40));
        assert_eq!(shared.pending(), 140);
        drop(credit);
        assert_eq!(budget.pending(), (0, 0));
        assert_eq!(shared.pending(), 100);

        let mut credit = charge(&budget, 60);
        budget.shrink(&mut credit, 20);
        assert_eq!(credit.bytes(), 20);
        assert_eq!(budget.pending(), (1, 20));
        assert_eq!(shared.pending(), 120);
        budget.shrink(&mut credit, 20);
        assert_eq!(
            shared.pending(),
            120,
            "shrinking to the same size is a no-op"
        );
        drop(credit);
        assert_eq!(budget.pending(), (0, 0));
        assert_eq!(shared.pending(), 100);

        drop(bystander_credit);
        assert_eq!(shared.pending(), 0);
    }

    /// The bulk margin keeps one maximum frame of the aggregate for control
    /// traffic: production credits stop at the bulk limit while an ordinary
    /// charge still takes the margin, and only then does the aggregate refuse.
    #[test]
    fn bulk_margin_keeps_control_flowing() {
        let reserve_bytes = 100;
        let shared = Arc::new(SharedOutboundBudget::with_limits(1_000, reserve_bytes));
        let (lease, _rx) = shared_lease_with_reserve(&shared, reserve_bytes);
        let budget = lease.budget_handle();

        let bulk: Vec<_> = (0..9).map(|_| reserve(&budget)).collect();
        assert_eq!(shared.pending(), 900);
        assert_eq!(budget.try_reserve_production().err(), Some(Refusal::Shared));
        assert!(!budget.may_reserve_production());

        // Control traffic still flows into the margin.
        let ping = crate::Message::Ping(9);
        assert!(lease.send(ping).is_ok());
        let control = charge(
            &budget,
            reserve_bytes - wire_len_of(&crate::Message::Ping(9)),
        );
        assert_eq!(shared.pending(), 1_000);
        assert_eq!(budget.try_charge(1).err(), Some(Refusal::Shared));
        drop((bulk, control));
    }

    /// A credit reserved before the message existed shrinks to the exact wire
    /// length when spent, and its charge then rides with the queued frame.
    #[test]
    fn send_with_shrinks_the_reservation_to_the_wire_length() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 1_000));
        let (lease, rx) = shared_lease_with_reserve(&shared, 1_000);
        let credit = reserve(&lease.budget_handle());
        assert_eq!(shared.pending(), 1_000);

        let ping = crate::Message::Ping(1);
        let ping_len = wire_len_of(&ping);
        assert!(lease.send_with(credit, ping.clone()).is_ok());
        assert_eq!(shared.pending(), ping_len);
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));

        let frame = rx
            .try_recv()
            .unwrap_or_else(|_| panic!("the frame was queued"));
        assert_eq!(frame.message(), &ping);
        assert_eq!(
            shared.pending(),
            ping_len,
            "the charge rides with the frame"
        );
        assert_eq!(frame.into_message(), ping);
        assert_eq!(shared.pending(), 0);
        assert_eq!(lease.budget_handle().pending(), (0, 0));
    }

    /// `send_with` fails closed and returns the charge when the lease is
    /// cancelled or the message outgrew its reservation.
    #[test]
    fn send_with_fails_closed_and_releases_the_credit() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(10_000, 0));

        let (small, _small_rx) = shared_lease(&shared);
        let credit = charge(&small.budget_handle(), 8);
        let ping = crate::Message::Ping(1);
        assert_eq!(
            small.send_with(credit, ping.clone()),
            Err(OutboundRefusal::Closed(ping))
        );
        assert!(
            small.is_cancelled(),
            "an outgrown reservation closes the lease"
        );
        assert_eq!(shared.pending(), 0);

        let (cancelled, _cancelled_rx) = shared_lease(&shared);
        let credit = charge(&cancelled.budget_handle(), 100);
        cancelled.cancel();
        let pong = crate::Message::Pong(2);
        assert_eq!(
            cancelled.send_with(credit, pong.clone()),
            Err(OutboundRefusal::Closed(pong))
        );
        assert_eq!(shared.pending(), 0);
        assert_eq!(cancelled.budget_handle().pending(), (0, 0));
    }

    /// A dead writer reclaims nothing: charges taken before death stay with
    /// their queued frames and release when those drop; later charges are
    /// refused locally and close the lease.
    #[test]
    fn dead_writer_refuses_charges_and_reclaims_nothing() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(1_000, 0));
        let (lease, rx) = shared_lease(&shared);
        let budget = lease.budget_handle();
        let ping_len = wire_len_of(&crate::Message::Ping(1));
        assert!(lease.send(crate::Message::Ping(1)).is_ok());
        assert!(lease.send(crate::Message::Ping(2)).is_ok());

        budget.mark_writer_dead();
        assert_eq!(shared.pending(), 2 * ping_len, "death reclaims nothing");
        assert_eq!(budget.pending(), (2, 2 * ping_len));
        assert_eq!(budget.try_charge(1).err(), Some(Refusal::Local));
        assert!(matches!(
            lease.send(crate::Message::Ping(3)),
            Err(OutboundRefusal::Closed(_))
        ));
        assert!(lease.is_cancelled());

        while let Ok(frame) = rx.try_recv() {
            drop(frame);
        }
        assert_eq!(shared.pending(), 0);
        assert_eq!(budget.pending(), (0, 0));
    }

    /// Two leases sharing one aggregate: the first fills it, a peer with an
    /// empty queue is refused without being cancelled, and the first
    /// connection's own local bounds never moved. Draining the hog reopens
    /// the aggregate.
    #[test]
    fn shared_aggregate_caps_two_connections_without_touching_local_bounds() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(100, 0));
        let (hog, _hog_rx) = shared_lease(&shared);
        let (other, _other_rx) = shared_lease(&shared);

        let hog_budget = hog.budget_handle();
        let first = charge(&hog_budget, 60);
        let second = charge(&hog_budget, 39);
        assert_eq!(shared.pending(), 99);
        // Local bounds are untouched: the hog still has its whole local
        // budget, only the aggregate is nearly full.
        assert!(hog_budget.may_charge(1));
        assert_eq!(hog_budget.pending(), (2, 99));

        let ping_len = wire_len_of(&crate::Message::Ping(1));
        let refused = crate::Message::Ping(1);
        assert_eq!(
            other.send(refused.clone()),
            Err(OutboundRefusal::Saturated(refused))
        );
        assert!(!other.is_cancelled());
        assert!(!hog.is_cancelled());
        assert_eq!(shared.pending(), 99);
        assert_eq!(other.budget_handle().pending(), (0, 0));

        // Draining the hog reopens the aggregate for the same lease.
        drop(first);
        assert!(other.send(crate::Message::Ping(2)).is_ok());
        assert_eq!(shared.pending(), 39 + ping_len);

        // A further send that no longer fits is backpressure, not a close.
        let overflow = crate::Message::Ping(3);
        assert_eq!(
            other.send(overflow.clone()),
            Err(OutboundRefusal::Saturated(overflow))
        );
        assert!(!other.is_cancelled());
        drop(second);
    }

    /// A healthy peer progresses while another peer saturates only its own
    /// local budget: local bounds isolate connections, the aggregate only
    /// binds the sum.
    #[test]
    fn healthy_peer_progresses_beside_a_locally_saturated_peer() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(1_000_000, 0));
        let (saturated_tx, _saturated_rx) = crossbeam_channel::unbounded();
        let saturated = PeerLease::new_with_budget(
            saturated_tx,
            false,
            OutboundBudget::with_block_reserve(1, 1_000_000, 0),
        )
        .with_shared_budget(&shared);
        let (healthy, _healthy_rx) = shared_lease(&shared);

        assert!(saturated.send(crate::Message::Ping(1)).is_ok());
        assert!(matches!(
            saturated.send(crate::Message::Ping(2)),
            Err(OutboundRefusal::Closed(_))
        ));
        assert!(saturated.is_cancelled());
        assert!(healthy.send(crate::Message::Ping(3)).is_ok());
        assert!(!healthy.is_cancelled());
    }

    /// A waiter parked on the aggregate wakes when a DIFFERENT connection
    /// drains: cross-connection resumption, not just local release.
    #[test]
    fn aggregate_waiter_resumes_on_another_connections_drain() {
        let shared = Arc::new(SharedOutboundBudget::with_limits(200, 0));
        let (hog, _hog_rx) = shared_lease(&shared);
        let (waiter, _waiter_rx) = shared_lease_with_reserve(&shared, 100);
        let waiter_budget = waiter.budget_handle();
        let hog_credit = charge(&hog.budget_handle(), 150);
        // The hog's bytes plus the worst-case reserve exceed the aggregate.
        assert!(!waiter_budget.may_reserve_production());

        let ready = {
            let budget = Arc::clone(&waiter_budget);
            move || budget.may_reserve_production()
        };
        let (thread, done) = spawn_waiter(&waiter_budget, Duration::from_secs(60), ready);
        // The waiter may not have parked yet; the protocol must hold either way.
        std::thread::sleep(Duration::from_millis(50));
        drop(hog_credit);
        let woke = done.recv_timeout(WAKE_DEADLINE);
        waiter_budget.mark_writer_dead();
        thread.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(
            woke.is_ok(),
            "another connection's drain must resume the waiter"
        );
        assert!(waiter_budget.may_reserve_production());
        assert_eq!(shared.pending(), 0);
    }

    /// Independent aggregates stay independent: exhausting one node's budget
    /// leaves another node's connections unaffected (no global singleton).
    #[test]
    fn independent_aggregates_stay_independent() {
        let first = Arc::new(SharedOutboundBudget::with_limits(100, 0));
        let second = Arc::new(SharedOutboundBudget::with_limits(100, 0));
        let (a, _a_rx) = shared_lease(&first);
        let (b, _b_rx) = shared_lease(&second);

        let a_credit = charge(&a.budget_handle(), 100);
        assert_eq!(first.pending(), 100);
        let b_credit = charge(&b.budget_handle(), 100);
        assert_eq!(second.pending(), 100);
        drop(a_credit);
        assert_eq!(first.pending(), 0);
        assert_eq!(second.pending(), 100);
        drop(b_credit);
    }

    #[test]
    fn release_replenishes_budget() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let first = crate::Message::Ping(7);
        let ping_len = wire_len_of(&first);
        let lease = PeerLease::new_with_budget(
            tx,
            false,
            OutboundBudget::with_block_reserve(1, 10 * ping_len, 0),
        );

        assert!(lease.send(first).is_ok());
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));

        assert!(matches!(
            lease.send(crate::Message::Ping(8)),
            Err(OutboundRefusal::Closed(_))
        ));
        assert!(lease.is_cancelled());
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));

        let frame = rx
            .try_recv()
            .unwrap_or_else(|_| panic!("the first message was queued"));
        drop(frame);
        assert_eq!(lease.budget_handle().pending(), (0, 0));

        let (fresh_tx, _fresh_rx) = crossbeam_channel::unbounded();
        let fresh = PeerLease::new_with_budget(
            fresh_tx,
            false,
            OutboundBudget::with_block_reserve(1, 10 * ping_len, 0),
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
            OutboundBudget::with_block_reserve(100_000, 3 * block_wire_len, block_wire_len),
        );

        for _ in 0..3 {
            assert!(
                lease
                    .send(crate::Message::Block(test_block.clone()))
                    .is_ok()
            );
        }
        assert!(matches!(
            lease.send(crate::Message::Block(test_block)),
            Err(OutboundRefusal::Closed(_))
        ));

        assert!(lease.is_cancelled());
        assert_eq!(lease.budget_handle().pending(), (3, 3 * block_wire_len));

        let (independent_tx, _independent_rx) = crossbeam_channel::unbounded();
        let independent = PeerLease::new(independent_tx);
        assert!(independent.send(crate::Message::Ping(1)).is_ok());
    }

    /// Runs `wait_for` on a thread and reports when it returned.
    fn spawn_waiter(
        budget: &Arc<OutboundBudget>,
        timeout: Duration,
        ready: impl Fn() -> bool + Send + 'static,
    ) -> (std::thread::JoinHandle<()>, Receiver<Instant>) {
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let waiter = Arc::clone(budget);
        let handle = std::thread::spawn(move || {
            waiter.wait_for(timeout, ready);
            let _ = done_tx.send(Instant::now());
        });
        (handle, done_rx)
    }

    /// A saturated budget with one worst-case message pending: no headroom
    /// until the credit drops.
    fn saturated_budget() -> (Arc<OutboundBudget>, OutboundCredit) {
        let reserve_bytes = 100;
        let budget = standalone(10, 2 * reserve_bytes, reserve_bytes);
        let credit = charge(&budget, reserve_bytes + 1);
        assert!(!budget.may_reserve_production());
        (budget, credit)
    }

    fn production_ready(budget: &Arc<OutboundBudget>) -> impl Fn() -> bool + Send + use<> {
        let budget = Arc::clone(budget);
        move || budget.may_reserve_production()
    }

    const WAKE_DEADLINE: Duration = Duration::from_secs(10);

    #[test]
    fn release_wakes_a_waiter_long_before_its_timeout() {
        let (budget, credit) = saturated_budget();
        let (waiter, done) =
            spawn_waiter(&budget, Duration::from_secs(60), production_ready(&budget));

        // The waiter may not have parked yet; the protocol must hold either way.
        std::thread::sleep(Duration::from_millis(50));
        drop(credit);

        let woke = done.recv_timeout(WAKE_DEADLINE);
        // Unblock the waiter on failure so the join below cannot hang.
        budget.mark_writer_dead();
        waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(woke.is_ok(), "a release must wake the waiter");
        assert!(budget.may_reserve_production());
    }

    #[test]
    fn writer_death_wakes_a_waiter_that_no_release_will_reach() {
        let (budget, _credit) = saturated_budget();
        let (waiter, done) =
            spawn_waiter(&budget, Duration::from_secs(60), production_ready(&budget));

        std::thread::sleep(Duration::from_millis(50));
        assert!(!budget.writer_dead());
        budget.mark_writer_dead();

        let woke = done.recv_timeout(WAKE_DEADLINE);
        waiter.join().unwrap_or_else(|_| panic!("waiter panicked"));
        assert!(woke.is_ok(), "writer death must wake the waiter");
        assert!(budget.writer_dead());
        assert!(
            !budget.may_reserve_production(),
            "death releases nothing; the queue stays saturated"
        );
    }

    #[test]
    fn wait_returns_at_once_when_headroom_or_death_already_holds() {
        let open = standalone(10, 1_000, 100);
        let started = Instant::now();
        open.wait_for(Duration::from_secs(60), production_ready(&open));
        assert!(started.elapsed() < WAKE_DEADLINE);

        let (dead, _charged) = saturated_budget();
        dead.mark_writer_dead();
        let started = Instant::now();
        dead.wait_for(Duration::from_secs(60), production_ready(&dead));
        assert!(started.elapsed() < WAKE_DEADLINE);
    }

    #[test]
    fn wait_times_out_without_a_wake() {
        let (budget, _credit) = saturated_budget();
        let timeout = Duration::from_millis(100);
        let started = Instant::now();

        budget.wait_for(timeout, production_ready(&budget));

        assert!(
            started.elapsed() >= timeout,
            "no wake, so the wait runs to its timeout"
        );
        assert!(!budget.may_reserve_production());
        assert!(!budget.writer_dead());
    }

    #[test]
    fn a_release_that_leaves_the_queue_saturated_does_not_end_the_wait() {
        let reserve_bytes = 100;
        let budget = standalone(10, 2 * reserve_bytes, reserve_bytes);
        let mut credits: Vec<_> = (0..3).map(|_| charge(&budget, 90)).collect();
        assert!(!budget.may_reserve_production());
        let (waiter, done) =
            spawn_waiter(&budget, Duration::from_secs(60), production_ready(&budget));

        // 180 pending plus the 100 reserve still exceeds the 200 cap: the
        // wake finds no headroom and the waiter must keep waiting.
        std::thread::sleep(Duration::from_millis(50));
        drop(credits.pop());
        let early = done.recv_timeout(Duration::from_millis(300));
        // 90 + 100 <= 200: this release opens the gate.
        drop(credits.pop());
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
