//! Per-connection identity and cancellation.

use bitcoin_rs_primitives::PeerEndpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TrySendError};
use parking_lot::{Condvar, Mutex};
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test_raw(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PeerRemote {
    Endpoint(PeerEndpoint),
    AnonymousTor(ConnectionId),
}

impl PeerRemote {
    pub const fn endpoint(self) -> Option<PeerEndpoint> {
        match self {
            Self::Endpoint(endpoint) => Some(endpoint),
            Self::AnonymousTor(_) => None,
        }
    }

    pub fn network(self) -> crate::PeerNetwork {
        match self {
            Self::Endpoint(endpoint) => endpoint.address().network(),
            Self::AnonymousTor(_) => crate::PeerNetwork::Onion,
        }
    }

    #[must_use]
    pub const fn from_endpoint(
        endpoint: Option<PeerEndpoint>,
        connection_id: ConnectionId,
    ) -> Self {
        match endpoint {
            Some(endpoint) => Self::Endpoint(endpoint),
            None => Self::AnonymousTor(connection_id),
        }
    }

    #[must_use]
    pub fn from_source(source: PeerSource) -> Self {
        Self::from_endpoint(source.endpoint(), source.connection_id())
    }
}

impl From<PeerEndpoint> for PeerRemote {
    fn from(endpoint: PeerEndpoint) -> Self {
        Self::Endpoint(endpoint)
    }
}

impl From<std::net::SocketAddr> for PeerRemote {
    fn from(socket: std::net::SocketAddr) -> Self {
        Self::Endpoint(socket.into())
    }
}

impl<T> From<(T, u16)> for PeerRemote
where
    std::net::SocketAddr: From<(T, u16)>,
{
    fn from(value: (T, u16)) -> Self {
        Self::from(std::net::SocketAddr::from(value))
    }
}

impl std::fmt::Display for PeerRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(endpoint) => endpoint.fmt(f),
            Self::AnonymousTor(id) => write!(f, "tor-inbound-{}:0", id.get()),
        }
    }
}

impl std::str::FromStr for PeerRemote {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(id) = value
            .strip_prefix("tor-inbound-")
            .and_then(|id| id.strip_suffix(":0"))
        {
            return id
                .parse()
                .map(|id| Self::AnonymousTor(ConnectionId(id)))
                .map_err(|_| "invalid anonymous Tor connection handle");
        }
        value.parse().map(Self::Endpoint)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSource {
    pub(crate) endpoint: Option<crate::PeerEndpoint>,
    connection_id: ConnectionId,
}

impl PeerSource {
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    #[must_use]
    pub fn endpoint(&self) -> Option<crate::PeerEndpoint> {
        self.endpoint
    }

    #[must_use]
    pub fn remote(&self) -> PeerRemote {
        PeerRemote::from(*self)
    }

    #[cfg(test)]
    pub(crate) fn for_test(addr: impl Into<PeerRemote>) -> Self {
        Self {
            endpoint: {
                let remote: PeerRemote = addr.into();
                remote.endpoint()
            },
            connection_id: ConnectionId::allocate(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_endpoint(endpoint: crate::PeerEndpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
            connection_id: ConnectionId::allocate(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_unidentified() -> Self {
        Self {
            endpoint: None,
            connection_id: ConnectionId::allocate(),
        }
    }
}

impl From<PeerSource> for PeerRemote {
    fn from(source: PeerSource) -> Self {
        source
            .endpoint
            .map_or(Self::AnonymousTor(source.connection_id), Self::Endpoint)
    }
}

impl From<PeerSource> for bitcoin_rs_mempool::PeerToken {
    fn from(source: PeerSource) -> Self {
        Self {
            endpoint: source.endpoint,
            addr: PeerRemote::from(source).endpoint(),
            connection_id: source.connection_id.get(),
        }
    }
}

impl From<bitcoin_rs_mempool::PeerToken> for PeerSource {
    fn from(token: bitcoin_rs_mempool::PeerToken) -> Self {
        let connection_id = ConnectionId(token.connection_id);
        Self {
            endpoint: token.endpoint,
            connection_id,
        }
    }
}

const OUTBOUND_QUEUE_MAX_MESSAGES: usize = 4096;

const OUTBOUND_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

pub(crate) const SHARED_OUTBOUND_QUEUE_MAX_BYTES: usize = OUTBOUND_QUEUE_MAX_BYTES;

const SHARED_BULK_MARGIN_BYTES: usize = BLOCK_PRODUCTION_RESERVE_BYTES;

const _: () = assert!(
    BLOCK_PRODUCTION_RESERVE_BYTES >= crate::wire::HEADER_LEN + crate::wire::MAX_MESSAGE_PAYLOAD
);

#[derive(Debug)]
pub(crate) struct SharedOutboundBudget {
    max_bytes: usize,
    bulk_limit: usize,
    pending_bytes: AtomicUsize,
    drained: Condvar,
    drained_lock: Mutex<()>,
}

impl SharedOutboundBudget {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_limits(SHARED_OUTBOUND_QUEUE_MAX_BYTES, SHARED_BULK_MARGIN_BYTES)
    }

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

    fn try_charge(&self, bytes: usize, limit: usize) -> bool {
        self.pending_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_add(bytes).filter(|total| *total <= limit)
            })
            .is_ok()
    }

    fn release_counter(&self, bytes: usize) {
        let released =
            self.pending_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "released more shared bytes than charged");
    }

    fn wake_waiters(&self) {
        drop(self.drained_lock.lock());
        self.drained.notify_all();
    }

    #[must_use]
    fn may_admit(&self, bytes: usize) -> bool {
        self.pending_bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .is_some_and(|total| total <= self.max_bytes)
    }

    #[must_use]
    fn may_reserve_bulk(&self, bytes: usize) -> bool {
        self.pending_bytes
            .load(Ordering::Acquire)
            .checked_add(bytes)
            .is_some_and(|total| total <= self.bulk_limit)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> usize {
        self.pending_bytes.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Local,
    Shared,
}

#[must_use]
#[derive(Debug)]
pub(crate) struct OutboundCredit {
    budget: Arc<OutboundBudget>,
    bytes: usize,
}

impl OutboundCredit {
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }

    fn belongs_to(&self, budget: &Arc<OutboundBudget>) -> bool {
        Arc::ptr_eq(&self.budget, budget)
    }
}

impl Drop for OutboundCredit {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

#[derive(Debug)]
pub struct QueuedFrame {
    message: crate::Message,
    credit: OutboundCredit,
}

impl QueuedFrame {
    #[must_use]
    pub fn message(&self) -> &crate::Message {
        &self.message
    }

    #[must_use]
    pub fn into_message(self) -> crate::Message {
        let Self { message, credit } = self;
        drop(credit);
        message
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OutboundRefusal {
    Closed(crate::Message),
    Saturated(crate::Message),
}

impl OutboundRefusal {
    #[must_use]
    pub fn into_message(self) -> crate::Message {
        match self {
            Self::Closed(message) | Self::Saturated(message) => message,
        }
    }

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

const BLOCK_SERIALIZED_SIZE: usize = crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE;

const BLOCK_PRODUCTION_RESERVE_BYTES: usize = crate::wire::HEADER_LEN + BLOCK_SERIALIZED_SIZE;

const _: () = assert!(OUTBOUND_QUEUE_MAX_BYTES > 15 * BLOCK_PRODUCTION_RESERVE_BYTES);

pub(crate) const MAX_UNSOLICITED_BLOCK_FORWARDS: usize = 16;

#[derive(Debug)]
pub(crate) struct BlockForwardCredit(Option<Arc<AtomicUsize>>);

impl Drop for BlockForwardCredit {
    fn drop(&mut self) {
        if let Some(counter) = &self.0 {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug)]
pub(crate) struct OutboundBudget {
    max_messages: usize,
    max_bytes: usize,
    block_reserve: usize,
    pending_messages: AtomicUsize,
    pending_bytes: AtomicUsize,
    #[cfg(test)]
    refusals: AtomicUsize,
    drained: Condvar,
    drained_lock: Mutex<()>,
    writer_dead: AtomicBool,
    shared: Option<Arc<SharedOutboundBudget>>,
}

impl OutboundBudget {
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
    #[must_use]
    pub(crate) fn with_block_reserve(
        max_messages: usize,
        max_bytes: usize,
        block_reserve: usize,
    ) -> Self {
        Self::with_reserve(max_messages, max_bytes, block_reserve)
    }

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

    pub(crate) fn try_reserve_reply(
        self: &Arc<Self>,
        bound: usize,
    ) -> Result<OutboundCredit, Refusal> {
        self.try_charge(bound)
    }

    fn commit_locked(self: &Arc<Self>, bytes: usize) -> OutboundCredit {
        self.pending_messages.fetch_add(1, Ordering::AcqRel);
        self.pending_bytes.fetch_add(bytes, Ordering::AcqRel);
        OutboundCredit {
            budget: Arc::clone(self),
            bytes,
        }
    }

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

    fn release_bytes_locked(&self, bytes: usize) {
        let released =
            self.pending_bytes
                .try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    pending.checked_sub(bytes)
                });
        debug_assert!(released.is_ok(), "released more bytes than charged");
    }

    fn wake_after_release(&self) {
        self.wake_waiters();
        if let Some(shared) = &self.shared {
            shared.wake_waiters();
        }
    }

    fn wake_waiters(&self) {
        drop(self.drained_lock.lock());
        self.drained.notify_all();
    }

    pub(crate) fn mark_writer_dead(&self) {
        {
            let _guard = self.drained_lock.lock();
            self.writer_dead.store(true, Ordering::Release);
        }
        self.wake_after_release();
    }

    #[must_use]
    pub(crate) fn writer_dead(&self) -> bool {
        self.writer_dead.load(Ordering::Acquire)
    }

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

    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> (usize, usize) {
        (
            self.pending_messages.load(Ordering::Acquire),
            self.pending_bytes.load(Ordering::Acquire),
        )
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn refusals(&self) -> usize {
        self.refusals.load(Ordering::Acquire)
    }

    #[must_use]
    pub(crate) fn may_reserve_production(&self) -> bool {
        self.local_production_headroom()
            && self
                .shared
                .as_ref()
                .is_none_or(|shared| shared.may_reserve_bulk(self.block_reserve))
    }

    #[must_use]
    pub(crate) fn may_charge(&self, bytes: usize) -> bool {
        self.local_has_room()
            && self
                .shared
                .as_ref()
                .is_none_or(|shared| shared.may_admit(bytes))
    }

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

    fn local_has_room(&self) -> bool {
        !self.writer_dead()
            && self.pending_messages.load(Ordering::Acquire) < self.max_messages
            && self.pending_bytes.load(Ordering::Acquire) < self.max_bytes
    }
}

#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<QueuedFrame>,
    cancel: Arc<AtomicBool>,
    transport_alive: Option<Arc<AtomicBool>>,
    close_tx: Sender<()>,
    close_rx: Receiver<()>,
    budget: Arc<OutboundBudget>,
    unsolicited_forwards: Arc<AtomicUsize>,
    last_send: Arc<Mutex<Instant>>,
    inbound: bool,
    role: crate::peer_info::PeerRole,
    manual: bool,
    no_ban: bool,
    connected: Instant,
}

impl PeerLease {
    #[must_use]
    pub fn new(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(
            outbound,
            false,
            crate::peer_info::PeerRole::FullRelay,
            false,
        )
    }

    #[must_use]
    pub(crate) fn new_block_relay(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(
            outbound,
            false,
            crate::peer_info::PeerRole::BlockRelayOnly,
            false,
        )
    }

    #[must_use]
    pub(crate) fn new_manual(
        outbound: Sender<QueuedFrame>,
        role: crate::peer_info::PeerRole,
    ) -> Self {
        Self::with_direction(outbound, false, role, true)
    }

    #[must_use]
    pub fn new_inbound(outbound: Sender<QueuedFrame>) -> Self {
        Self::with_direction(outbound, true, crate::peer_info::PeerRole::FullRelay, false)
    }

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
            transport_alive: None,
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

    pub(crate) fn with_transport_alive(mut self, alive: Option<Arc<AtomicBool>>) -> Self {
        self.transport_alive = alive;
        self
    }

    pub(crate) fn belongs_to_transport_epoch(&self, epoch: &Arc<AtomicBool>) -> bool {
        self.transport_alive
            .as_ref()
            .is_some_and(|alive| Arc::ptr_eq(alive, epoch))
    }

    pub(crate) fn with_no_ban(mut self, no_ban: bool) -> Self {
        self.no_ban = no_ban;
        self
    }

    #[must_use]
    pub(crate) fn with_shared_budget(mut self, shared: &Arc<SharedOutboundBudget>) -> Self {
        if let Some(budget) = Arc::get_mut(&mut self.budget) {
            debug_assert!(budget.shared.is_none());
            budget.shared = Some(Arc::clone(shared));
        } else {
            debug_assert!(false, "the aggregate attaches before the budget is shared");
        }
        self
    }

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

    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.id.get()
    }

    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.id
    }

    #[must_use]
    pub const fn is_inbound(&self) -> bool {
        self.inbound
    }

    #[must_use]
    pub const fn role(&self) -> crate::peer_info::PeerRole {
        self.role
    }

    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.manual
    }

    #[must_use]
    pub(crate) const fn connected_at(&self) -> Instant {
        self.connected
    }

    #[cfg(test)]
    pub(crate) fn backdate_for_test(&mut self, at: Instant) {
        debug_assert!(at <= Instant::now());
        self.connected = at;
    }

    pub(crate) fn close_signal(&self) -> Receiver<()> {
        self.close_rx.clone()
    }

    pub(crate) fn budget_handle(&self) -> Arc<OutboundBudget> {
        Arc::clone(&self.budget)
    }

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

    #[must_use]
    pub(crate) fn last_send(&self) -> Instant {
        *self.last_send.lock()
    }

    #[must_use]
    pub fn source(&self, endpoint: Option<crate::PeerEndpoint>) -> PeerSource {
        PeerSource {
            endpoint,
            connection_id: self.id,
        }
    }

    #[must_use]
    pub fn source_ip(&self, addr: SocketAddr) -> PeerSource {
        self.source(Some(crate::accepted_ip_identity(addr)))
    }

    #[expect(clippy::result_large_err)]
    pub fn send(&self, message: crate::Message) -> Result<(), OutboundRefusal> {
        if self.is_cancelled() {
            return Err(OutboundRefusal::Closed(message));
        }
        if matches!(message, crate::Message::Feature(_)) {
            self.cancel();
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
        if matches!(message, crate::Message::Feature(_)) {
            self.cancel();
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
                let message = frame.into_message();
                self.cancel();
                Err(OutboundRefusal::Closed(message))
            }
        }
    }

    pub(crate) fn try_reserve_production(&self) -> Result<OutboundCredit, Refusal> {
        self.budget.try_reserve_production()
    }

    pub(crate) fn try_reserve_reply(&self, bound: usize) -> Result<OutboundCredit, Refusal> {
        self.budget.try_reserve_reply(bound)
    }

    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.id == source.connection_id
    }

    #[must_use]
    pub(crate) fn same_connection(&self, other: &Self) -> bool {
        self.id == other.id
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        let _ = self.close_tx.try_send(());
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
            || self
                .transport_alive
                .as_ref()
                .is_some_and(|alive| !alive.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests;
