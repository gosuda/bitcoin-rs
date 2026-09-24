//! Per-connection identity and cancellation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crossbeam_channel::{Receiver, SendError, Sender, TrySendError};
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
pub const OUTBOUND_QUEUE_MAX_MESSAGES: usize = 4096;

/// Maximum queued full wire bytes for one peer connection.
///
/// Admission tests usage before adding, so sixteen worst-case block messages
/// fit: after fifteen, 60,000,360 bytes remain below this 64 MiB high-water.
pub const OUTBOUND_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Consensus maximum serialized block size. `peer` owns the value
/// ([`crate::MAX_BLOCK_SERIALIZED_SIZE_USIZE`]); `connection` references it
/// rather than carrying an independent copy.
const BLOCK_SERIALIZED_SIZE: usize = crate::MAX_BLOCK_SERIALIZED_SIZE_USIZE;

/// Full framed-wire bytes reserved before loading a worst-case block body.
///
/// Equals `HEADER_LEN + MAX_BLOCK_SERIALIZED_SIZE_USIZE`: the full encoded wire
/// byte count that `wire_len` charges and `write_message` releases.
pub const BLOCK_PRODUCTION_RESERVE_BYTES: usize = crate::wire::HEADER_LEN + BLOCK_SERIALIZED_SIZE;

const _: () = assert!(OUTBOUND_QUEUE_MAX_BYTES > 15 * BLOCK_PRODUCTION_RESERVE_BYTES);

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
/// pre-load block-production gate is what bounds materialization.
#[derive(Debug)]
pub struct OutboundBudget {
    max_messages: usize,
    max_bytes: usize,
    block_reserve: usize,
    pending_messages: AtomicUsize,
    pending_bytes: AtomicUsize,
}

impl OutboundBudget {
    /// Builds a production budget with the block-production reserve.
    #[must_use]
    pub fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self::with_reserve(max_messages, max_bytes, BLOCK_PRODUCTION_RESERVE_BYTES)
    }

    fn with_reserve(max_messages: usize, max_bytes: usize, block_reserve: usize) -> Self {
        Self {
            max_messages,
            max_bytes,
            block_reserve,
            pending_messages: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    /// Builds a test budget with a reduced block-production reserve.
    #[must_use]
    pub fn with_block_reserve(max_messages: usize, max_bytes: usize, block_reserve: usize) -> Self {
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
        let _ =
            self.pending_messages
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    Some(pending.saturating_sub(1))
                });
        let _ = self
            .pending_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                Some(pending.saturating_sub(wire_len))
            });
    }

    /// Returns the charged `(messages, full wire bytes)` awaiting release.
    #[must_use]
    pub fn pending(&self) -> (usize, usize) {
        (
            self.pending_messages.load(Ordering::Acquire),
            self.pending_bytes.load(Ordering::Acquire),
        )
    }

    /// Returns whether one more worst-case block body may be loaded.
    ///
    /// This gate is evaluated immediately before each body load. The empty
    /// queue arm preserves progress for a block larger than a configured cap.
    #[must_use]
    pub fn has_block_production_headroom(&self) -> bool {
        self.pending_messages.load(Ordering::Acquire) == 0
            || self
                .pending_bytes
                .load(Ordering::Acquire)
                .saturating_add(self.block_reserve)
                <= self.max_bytes
    }
}

/// A ready peer snapshot that keeps the connection identity beside its
/// handshake metadata.
///
/// The source must be carried through selection to the eventual send or
/// disconnect; resolving its address again can target a same-address
/// replacement.
#[derive(Clone, Debug)]
pub struct ReadyPeer {
    /// Identity of the connection that supplied `info`.
    pub source: PeerSource,
    /// Handshake metadata published by that connection.
    pub info: crate::PeerInfo,
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
        Self::with_budget(
            outbound,
            inbound,
            OutboundBudget::new(OUTBOUND_QUEUE_MAX_MESSAGES, OUTBOUND_QUEUE_MAX_BYTES),
        )
    }

    fn with_budget(
        outbound: Sender<crate::Message>,
        inbound: bool,
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
            inbound,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_budget(
        outbound: Sender<crate::Message>,
        inbound: bool,
        budget: OutboundBudget,
    ) -> Self {
        Self::with_budget(outbound, inbound, budget)
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

    /// Stamps an inbound event with this connection's identity and address.
    #[must_use]
    pub fn source(&self, addr: SocketAddr) -> PeerSource {
        PeerSource {
            addr,
            connection_id: self.id,
        }
    }

    /// Queues a message for this connection's writer.
    ///
    /// Saturation applies the disconnect policy documented on
    /// [`OutboundBudget`]: the lease is cancelled and the message is returned.
    #[allow(clippy::result_large_err)]
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
            Ok(()) => Ok(()),
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
    pub fn same_connection(&self, other: &Self) -> bool {
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
            compact_block_relay: false,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            best_known_height: 0,
            conn_time,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
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
        assert!(table.infos().is_empty());
        assert_eq!(table.ready_source(addr), None);
        assert!(!table.publish_info(addr, &old, peer_info(addr, 2)));
        assert!(table.infos().is_empty());

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
        assert!(table.infos().is_empty());
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

        assert!(table.lease_source(snapshot.source).is_none());
        assert!(table.lease_source(replacement.source(addr)).is_some());
    }

    #[test]
    fn block_production_reserve_admits_worst_case_block() {
        // A worst-case block body is the consensus limit that
        // `bitcoin_rs_consensus` owns. Its full wire message (header + body)
        // must be admissible into a queue whose byte cap equals the reserve.
        // A smaller reserve would refuse a real 4 MB block; a larger one
        // would over-reserve.
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

        // Empty-queue progress arm: the first worst-case body is always
        // allowed, even when its reserve alone exceeds the byte cap.
        let progress = super::OutboundBudget::with_block_reserve(4, 100, 1_000);
        assert!(progress.has_block_production_headroom());

        // Reserve arithmetic at the boundary: three worst-case bodies fill
        // the three-reserve budget exactly; the next load would exceed it
        // and the gate halts. A released queue regains headroom.
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
    fn outbound_budget_refuses_at_exact_item_cap_and_byte_cap() {
        let ping_len = wire_len_of(&crate::Message::Ping(1));

        let items = super::OutboundBudget::with_block_reserve(2, 100 * ping_len, 0);
        assert!(items.admit(ping_len));
        assert!(items.admit(ping_len));
        // pending_messages == max refuses; a `<=` admission check would let
        // this third message through.
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
        // The queue is no longer empty, so every further message refuses.
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

        // At cap: the refused send leaves the admitted accounting in place.
        assert!(lease.send(crate::Message::Ping(8)).is_err());
        assert!(lease.is_cancelled());
        assert_eq!(lease.budget_handle().pending(), (1, ping_len));

        // Writer-side release empties the accounting...
        lease.budget_handle().release(ping_len);
        assert_eq!(lease.budget_handle().pending(), (0, 0));

        // ...and a fresh connection admits again.
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
        // Direct queue-admission proof: no dispatch, no writer, no chain
        // view, no body loads. The outbound receiver stays undrained, so
        // every admitted message remains charged to the budget.
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

        // Connection-local failure: an independent lease on its own budget
        // is unaffected by the saturated peer's closure.
        let (independent_tx, _independent_rx) = crossbeam_channel::unbounded();
        let independent = PeerLease::new(independent_tx);
        assert!(independent.send(crate::Message::Ping(1)).is_ok());
    }

    fn wire_len_of(message: &crate::Message) -> usize {
        crate::wire::wire_len(message).unwrap_or_else(|_| panic!("test message must encode"))
    }
}
