//! Outbound block announcement owner: headers-first, high-bandwidth compact block,
//! and `inv` fallback.
//!
//! # Architecture
//!
//! [`BlockAnnounceEvent`] carries the identity of a newly committed active tip:
//! height, block hash, and previous block hash.
//!
//! [`BlockAnnounceQueue`] is the non-blocking producer: a bounded channel that drops
//! announcements under backpressure rather than stalling chainstate commit.
//!
//! [`BlockAnnouncer`] is the P2P-owned decision engine:
//! - Tracks peer known-header/block state.
//! - Tracks peer `sendheaders` preference (BIP130).
//! - Maintains a bounded set of up to 3 peers promoted to BIP152 high-bandwidth mode.
//! - Selects the best announcement mechanism for each peer:
//!   1. BIP152 high-bandwidth compact block (`cmpctblock`) if selected, previous block is known, and not blocksonly.
//!   2. BIP130 `headers` sequence (up to 8 headers) if `sendheaders` was negotiated and anchored to active chain.
//!   3. Compatibility fallback `inv` (`MSG_BLOCK`) announcing the current active tip.
//! - Discards stale announcements across reorgs.
//! - Coalesces intermediate updates to the latest active tip under queue saturation.
//! - Disconnect cleanly removes peer announcement state.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin_rs_primitives::{BlockHash, Hash256};
use crossbeam_channel::{Receiver, Sender, TrySendError};
use hashbrown::HashMap;
use parking_lot::Mutex;

use crate::PeerTable;
use crate::connection::{PeerLease, PeerSource};
use crate::dispatch::ChainQuery;
use crate::peer_info::PeerInfo;
use crate::wire::Message;

/// Core's `MAX_BLOCKS_TO_ANNOUNCE` (`net_processing.cpp:111`).
pub const MAX_BLOCKS_TO_ANNOUNCE: usize = 8;

/// Core's `MAX_PEERS_FOR_HIGH_BANDWIDTH_CMPCT` (`net_processing.cpp:142`).
pub const MAX_HIGH_BANDWIDTH_PEERS: usize = 3;

/// Default capacity for the pending tip announcement queue.
pub const DEFAULT_BLOCK_ANNOUNCE_QUEUE_CAPACITY: usize = 128;

/// Drain poll interval when the block announce queue is empty.
const ANNOUNCE_POLL: Duration = Duration::from_millis(100);

/// Committed block identity emitted after active-tip durable commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockAnnounceEvent {
    /// Height of the committed block on the active chain.
    pub height: u32,
    /// Block hash of the newly committed tip.
    pub hash: Hash256,
    /// Hash of the previous block.
    pub prev_hash: Hash256,
}

impl BlockAnnounceEvent {
    /// Creates a new announcement event.
    #[must_use]
    pub const fn new(height: u32, hash: Hash256, prev_hash: Hash256) -> Self {
        Self {
            height,
            hash,
            prev_hash,
        }
    }
}

/// Configuration for block announcements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockAnnounceConfig {
    /// Whether the node operates in blocksonly/no-tx mode.
    /// In blocksonly mode, high-bandwidth compact block relay is disabled.
    pub blocksonly: bool,
}

/// Thread-safe non-blocking block announcement queue with pending tip preservation under saturation.
#[derive(Clone)]
pub struct BlockAnnounceQueue {
    sender: Sender<SequencedAnnounceEvent>,
    pending_tip: Arc<Mutex<Option<SequencedAnnounceEvent>>>,
    next_sequence: Arc<AtomicU64>,
    enqueued: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

/// Receiving end of the block announcement queue that coalesces and preserves pending tips.
pub struct BlockAnnounceReceiver {
    receiver: Receiver<SequencedAnnounceEvent>,
    pending_tip: Arc<Mutex<Option<SequencedAnnounceEvent>>>,
}

#[derive(Clone, Copy)]
struct SequencedAnnounceEvent {
    sequence: u64,
    event: BlockAnnounceEvent,
}

impl BlockAnnounceQueue {
    /// Creates a bounded announcement queue with `capacity`.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, BlockAnnounceReceiver) {
        let (sender, receiver) = crossbeam_channel::bounded(capacity.max(1));
        let pending_tip = Arc::new(Mutex::new(None));
        let queue = Self {
            sender,
            pending_tip: Arc::clone(&pending_tip),
            next_sequence: Arc::new(AtomicU64::new(0)),
            enqueued: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let rx = BlockAnnounceReceiver {
            receiver,
            pending_tip,
        };
        (queue, rx)
    }

    /// Announces a newly committed active block. Never blocks chainstate.
    /// Under saturation, the newest committed tip is preserved in the pending slot.
    pub fn announce(&self, event: BlockAnnounceEvent) -> bool {
        let event = SequencedAnnounceEvent {
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            event,
        };
        match self.sender.try_send(event) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                // A producer can enqueue again after the receiver frees one
                // channel slot but before it observes this overflow slot. Keep
                // an explicit publication order so the receiver can select the
                // newest event across both stores instead of blindly preferring
                // whichever store it reads last.
                let mut pending = self.pending_tip.lock();
                if pending.is_none_or(|current| current.sequence < event.sequence) {
                    *pending = Some(event);
                }
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Total announcements enqueued.
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

impl BlockAnnounceReceiver {
    /// Receives the next announcement event, or waits up to `timeout`.
    /// Coalesces intermediate queue entries and incorporates any overflow pending tip.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<BlockAnnounceEvent, crossbeam_channel::RecvTimeoutError> {
        match self.receiver.recv_timeout(timeout) {
            Ok(mut latest) => {
                while let Ok(next) = self.receiver.try_recv() {
                    if next.sequence > latest.sequence {
                        latest = next;
                    }
                }
                let pending = self.pending_tip.lock().take();
                if let Some(pending) = pending.filter(|pending| pending.sequence > latest.sequence)
                {
                    latest = pending;
                }
                Ok(latest.event)
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                let pending = self.pending_tip.lock().take();
                if let Some(pending) = pending {
                    Ok(pending.event)
                } else {
                    Err(crossbeam_channel::RecvTimeoutError::Timeout)
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                let pending = self.pending_tip.lock().take();
                if let Some(pending) = pending {
                    Ok(pending.event)
                } else {
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected)
                }
            }
        }
    }

    /// Drains all available queued events and pending overflow, returning the latest tip if any.
    pub fn try_recv_latest(&self) -> Option<BlockAnnounceEvent> {
        let mut latest: Option<SequencedAnnounceEvent> = None;
        while let Ok(event) = self.receiver.try_recv() {
            if latest.is_none_or(|current| current.sequence < event.sequence) {
                latest = Some(event);
            }
        }
        let pending = self.pending_tip.lock().take();
        if let Some(pending) = pending
            && latest.is_none_or(|current| current.sequence < pending.sequence)
        {
            latest = Some(pending);
        }
        latest.map(|sequenced| sequenced.event)
    }
}

/// Per-peer announcement tracker.
#[derive(Clone, Debug, Default)]
pub struct PeerAnnounceTracker {
    /// Highest header/block known to be held by this peer.
    pub best_known_block: Option<Hash256>,
    /// Whether the peer negotiated BIP130 `sendheaders`.
    pub send_headers: bool,
    /// Inbound compact block announcement preference: whether the peer sent
    /// `sendcmpct(high_bandwidth=true, ...)`, requesting that WE announce new blocks via `cmpctblock`.
    pub peer_wants_high_bandwidth: bool,
    /// Compact-block protocol version requested by the peer (e.g. 1 or 2).
    pub peer_compact_version: Option<u64>,
}

#[derive(Default)]
struct AnnounceState {
    peer_trackers: HashMap<PeerSource, PeerAnnounceTracker>,
    /// Up to 3 peers we have requested high-bandwidth compact blocks from via `sendcmpct(true, 2)`.
    /// BIP152: "Nodes MUST NOT send `sendcmpct(high_bandwidth=true)` to more than 3 peers."
    high_bandwidth_requested_peers: Vec<PeerSource>,
    last_announced_tip: Option<Hash256>,
}

#[derive(Clone)]
struct PlannedAnnouncement {
    source: PeerSource,
    message: Message,
    confirms_tip: bool,
}

/// Owner of block announcement selection, peer state, and high-bandwidth relay.
pub struct BlockAnnouncer {
    peers: Arc<PeerTable>,
    chain_query: Arc<dyn ChainQuery>,
    config: BlockAnnounceConfig,
    ibd: Option<(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
    state: Mutex<AnnounceState>,
}

impl BlockAnnouncer {
    /// Constructs a new block announcer over the peer table and chain query.
    #[must_use]
    pub fn new(
        peers: Arc<PeerTable>,
        chain_query: Arc<dyn ChainQuery>,
        config: BlockAnnounceConfig,
    ) -> Self {
        Self {
            peers,
            chain_query,
            config,
            ibd: None,
            state: Mutex::new(AnnounceState::default()),
        }
    }

    /// Configures the IBD gate to suppress proactive block announcements during initial block download.
    #[must_use]
    pub fn with_ibd(
        mut self,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
        network: bitcoin_rs_primitives::Network,
    ) -> Self {
        self.ibd = Some((ibd, network));
        self
    }

    /// Whether the node is currently in initial block download.
    #[must_use]
    pub fn in_ibd(&self) -> bool {
        self.ibd.as_ref().is_some_and(|(latch, network)| {
            latch.is_active(bitcoin_rs_primitives::unix_time_secs(), *network)
        })
    }

    /// Marks whether a peer negotiated BIP130 `sendheaders`.
    pub fn set_send_headers(&self, source: PeerSource, send_headers: bool) {
        let mut state = self.state.lock();
        state.peer_trackers.entry(source).or_default().send_headers = send_headers;
    }

    /// Records inbound compact-block preferences received from `source`.
    pub fn note_peer_compact_preference(
        &self,
        source: PeerSource,
        high_bandwidth: bool,
        version: u64,
    ) {
        let mut state = self.state.lock();
        let tracker = state.peer_trackers.entry(source).or_default();
        tracker.peer_wants_high_bandwidth = high_bandwidth;
        tracker.peer_compact_version = Some(version);
    }

    /// Records that `source` is known to hold `hash`.
    pub fn mark_known_block(&self, source: PeerSource, hash: Hash256) {
        let mut state = self.state.lock();
        state
            .peer_trackers
            .entry(source)
            .or_default()
            .best_known_block = Some(hash);
    }

    /// Reports whether we have requested high-bandwidth compact blocks from `addr`.
    #[must_use]
    pub fn is_high_bandwidth_requested(&self, addr: &SocketAddr) -> bool {
        let Some(source) = self.peers.lease(*addr).map(|lease| lease.source(*addr)) else {
            return false;
        };
        let state = self.state.lock();
        state.high_bandwidth_requested_peers.contains(&source)
    }

    /// Returns the current list of peers we requested high-bandwidth compact blocks from.
    #[must_use]
    pub fn high_bandwidth_requested_peers(&self) -> Vec<SocketAddr> {
        let state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .iter()
            .map(|source| source.addr)
            .collect()
    }

    /// Returns the best block known for `addr`.
    #[must_use]
    pub fn peer_known_block(&self, addr: SocketAddr) -> Option<Hash256> {
        let source = self.peers.lease(addr)?.source(addr);
        let state = self.state.lock();
        state
            .peer_trackers
            .get(&source)
            .and_then(|t| t.best_known_block)
    }

    /// Returns whether the peer requested high-bandwidth compact block announcements.
    #[must_use]
    pub fn peer_wants_high_bandwidth(&self, addr: SocketAddr) -> bool {
        let Some(source) = self.peers.lease(addr).map(|lease| lease.source(addr)) else {
            return false;
        };
        let state = self.state.lock();
        state
            .peer_trackers
            .get(&source)
            .is_some_and(|t| t.peer_wants_high_bandwidth)
    }

    /// Called when a peer handshake completes.
    pub fn on_peer_ready(&self, addr: SocketAddr, lease: &PeerLease, info: &PeerInfo) {
        let source = lease.source(addr);
        if !self.peers.is_current(source) {
            return;
        }
        if info.send_headers {
            self.set_send_headers(source, true);
        }
        if !self.in_ibd() {
            let msgs = self.maybe_promote_peer(addr, lease);
            for (target, msg) in msgs {
                let _ = self.peers.send(target, msg);
            }
        }
    }

    /// Called when a peer disconnects: cleans up its announcement state.
    pub fn on_peer_disconnected(&self, source: PeerSource) {
        let mut state = self.state.lock();
        state.peer_trackers.remove(&source);
        state
            .high_bandwidth_requested_peers
            .retain(|candidate| *candidate != source);
    }

    /// Evaluates whether to request high-bandwidth compact relay from `addr` (sending `sendcmpct(true, 2)`).
    /// If we already have 3 peers in high-bandwidth mode, demotes the oldest peer (`sendcmpct(false, 2)`).
    pub fn maybe_promote_peer(
        &self,
        addr: SocketAddr,
        lease: &PeerLease,
    ) -> Vec<(PeerSource, Message)> {
        let source = lease.source(addr);
        if self.config.blocksonly
            || self.in_ibd()
            || !lease.role().relays_transactions()
            || !self.peers.is_current(source)
        {
            return Vec::new();
        }
        let mut state = self.state.lock();
        if state.high_bandwidth_requested_peers.contains(&source) {
            return Vec::new();
        }
        let mut messages = Vec::new();
        if state.high_bandwidth_requested_peers.len() >= MAX_HIGH_BANDWIDTH_PEERS {
            let demoted_source = state.high_bandwidth_requested_peers.remove(0);
            let demote_msg = Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            });
            messages.push((demoted_source, demote_msg));
        }
        state.high_bandwidth_requested_peers.push(source);
        let promote_msg = Message::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        });
        messages.push((source, promote_msg));
        messages
    }

    fn ready_sessions(&self, state: &mut AnnounceState) -> Vec<crate::PeerSession> {
        let sessions: Vec<_> = self
            .peers
            .sessions()
            .into_iter()
            .filter(|session| session.info.is_some() && !session.lease.is_cancelled())
            .collect();
        let sources: hashbrown::HashSet<PeerSource> = sessions
            .iter()
            .map(|session| session.lease.source(session.addr))
            .collect();
        state
            .peer_trackers
            .retain(|source, _| sources.contains(source));
        state
            .high_bandwidth_requested_peers
            .retain(|source| sources.contains(source));
        sessions
    }

    fn planned_announcements(&self, event: &BlockAnnounceEvent) -> Vec<PlannedAnnouncement> {
        if self.in_ibd() {
            return Vec::new();
        }

        let mut state = self.state.lock();
        // 1. Idempotence: duplicate notifications for the same committed tip are no-op.
        if state.last_announced_tip == Some(event.hash) {
            return Vec::new();
        }

        // 2. Announce only the current active tip. An active-chain ancestor is
        // still stale for this path: under worker delay it must not become an
        // old `inv`, nor reach compact serving's full-block depth fallback.
        if self.chain_query.active_tip() != Some((event.height, BlockHash::from(event.hash))) {
            return Vec::new();
        }

        state.last_announced_tip = Some(event.hash);

        // Clean up trackers for disconnected peers.
        let live_sessions = self.ready_sessions(&mut state);

        let mut planned = Vec::new();

        for session in &live_sessions {
            let addr = session.addr;
            let source = session.lease.source(addr);

            let tracker = state.peer_trackers.entry(source).or_default();

            // 3. Do not redundantly announce if the peer is already known to have this tip.
            if tracker.best_known_block == Some(event.hash)
                || session.demonstrated_tips.contains(&event.hash)
            {
                tracker.best_known_block = Some(event.hash);
                continue;
            }

            // Option A: High-Bandwidth BIP152 Compact Block
            // Peer must have explicitly requested high-bandwidth compact blocks from us.
            if tracker.peer_wants_high_bandwidth
                && tracker.peer_compact_version == Some(2)
                && !self.config.blocksonly
                && session.lease.role().relays_transactions()
            {
                let knows_prev = tracker.best_known_block == Some(event.prev_hash)
                    || session.demonstrated_tips.contains(&event.prev_hash);
                if knows_prev {
                    if let Some(msg @ Message::CmpctBlock(_)) = self.chain_query.compact_block_for(
                        event.height,
                        BlockHash::from(event.hash),
                        Some(2),
                    ) {
                        planned.push(PlannedAnnouncement {
                            source,
                            message: msg,
                            confirms_tip: true,
                        });
                        continue;
                    }
                }
            }

            // Option B: Headers-First Announcement (BIP130)
            let send_headers = tracker.send_headers
                || self.peers.send_headers_of(addr)
                || session.info.as_ref().is_some_and(|i| i.send_headers);
            if send_headers {
                if let Some(known_hash) = tracker.best_known_block {
                    if let Some(known_height) =
                        self.chain_query.active_height(BlockHash::from(known_hash))
                    {
                        if known_height < event.height {
                            let distance = event.height - known_height;
                            let max_announce =
                                u32::try_from(MAX_BLOCKS_TO_ANNOUNCE).unwrap_or(u32::MAX);
                            if distance <= max_announce {
                                let limit = usize::try_from(distance).unwrap_or(usize::MAX);
                                let headers = self.chain_query.headers_after(
                                    &[BlockHash::from(known_hash)],
                                    BlockHash::from(event.hash),
                                    limit,
                                );
                                if !headers.is_empty()
                                    && headers.last().map(|h| h.compute_hash().into())
                                        == Some(event.hash)
                                {
                                    planned.push(PlannedAnnouncement {
                                        source,
                                        message: Message::Headers(headers),
                                        confirms_tip: true,
                                    });
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            // Option C: `inv` Compatibility Fallback
            let block_inv = Inventory::Block(bitcoin::BlockHash::from_byte_array(
                event.hash.to_le_bytes(),
            ));
            planned.push(PlannedAnnouncement {
                source,
                message: Message::Inv(vec![block_inv]),
                confirms_tip: false,
            });
        }

        planned
    }

    /// Plans announcements for `event` without sending them directly.
    pub fn plan_announcements(&self, event: &BlockAnnounceEvent) -> Vec<(SocketAddr, Message)> {
        self.planned_announcements(event)
            .into_iter()
            .map(|planned| (planned.source.addr, planned.message))
            .collect()
    }

    /// Processes one committed tip event and sends announcements to eligible peers.
    pub fn process_tip(&self, event: &BlockAnnounceEvent) -> Vec<(SocketAddr, Message)> {
        let planned = self.planned_announcements(event);
        let mut sent = Vec::with_capacity(planned.len());
        for announcement in planned {
            if self
                .peers
                .send(announcement.source, announcement.message.clone())
                .is_err()
            {
                continue;
            }
            if announcement.confirms_tip {
                let mut state = self.state.lock();
                if let Some(tracker) = state.peer_trackers.get_mut(&announcement.source) {
                    tracker.best_known_block = Some(event.hash);
                }
            }
            sent.push((announcement.source.addr, announcement.message));
        }
        sent
    }

    /// Synchronously drains the queue, coalesces to the latest tip, and processes it.
    pub fn drain_queue_and_process(&self, rx: &BlockAnnounceReceiver) -> usize {
        if let Some(event) = rx.try_recv_latest() {
            self.process_tip(&event);
            1
        } else {
            0
        }
    }
}

/// Dedicated background worker thread that drains `BlockAnnounceQueue` and announces new blocks.
pub fn spawn_block_announce_worker(
    announcer: Arc<BlockAnnouncer>,
    rx: BlockAnnounceReceiver,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> Result<std::thread::JoinHandle<()>, std::io::Error> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-block-announce".into())
        .spawn(move || {
            while !shutdown.load() {
                match rx.recv_timeout(ANNOUNCE_POLL) {
                    Ok(event) => {
                        announcer.process_tip(&event);
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
}

#[cfg(test)]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::explicit_iter_loop,
    clippy::unreadable_literal,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use crate::dispatch::InventoryServing;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin_rs_primitives::{CompactTarget, Header, Network};

    struct MockAnnounceChain {
        headers: Vec<Header>,
        active_len: usize,
        orphan_hashes: Vec<BlockHash>,
    }

    impl MockAnnounceChain {
        fn new(count: usize) -> Self {
            let mut headers = Vec::with_capacity(count);
            let mut prev = BlockHash::default();
            for i in 0..count {
                let h = Header {
                    version: 1,
                    prev_blockhash: prev,
                    merkle_root: Hash256::default(),
                    time: i as u32 * 600,
                    bits: CompactTarget::from_consensus(0x1d00_ffff),
                    nonce: i as u32,
                };
                prev = h.compute_hash();
                headers.push(h);
            }
            Self {
                headers,
                active_len: count,
                orphan_hashes: Vec::new(),
            }
        }

        fn hash_at(&self, idx: usize) -> Hash256 {
            self.headers[idx].compute_hash().into()
        }

        fn block_hash_at(&self, idx: usize) -> BlockHash {
            self.headers[idx].compute_hash()
        }
    }

    impl ChainQuery for MockAnnounceChain {
        fn serve_inventory_blocks(
            &self,
            _items: &[Inventory],
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
            _serve: &mut dyn FnMut(Message) -> Result<(), crate::wire::PeerError>,
        ) -> Result<InventoryServing, crate::wire::PeerError> {
            Ok(InventoryServing::default())
        }

        fn block_transactions(
            &self,
            _request: &bitcoin::bip152::BlockTransactionsRequest,
            _compact_version: Option<u64>,
            _headroom: &dyn Fn() -> bool,
        ) -> Result<Option<Message>, crate::wire::PeerError> {
            Ok(None)
        }

        fn active_tip(&self) -> Option<(u32, BlockHash)> {
            if self.active_len == 0 {
                return None;
            }
            let idx = self.active_len - 1;
            Some((idx as u32, self.block_hash_at(idx)))
        }

        fn active_height(&self, hash: BlockHash) -> Option<u32> {
            if self.orphan_hashes.contains(&hash) {
                return None;
            }
            for (idx, h) in self.headers[..self.active_len].iter().enumerate() {
                if h.compute_hash() == hash {
                    return Some(idx as u32);
                }
            }
            None
        }

        fn headers_after(
            &self,
            locators: &[BlockHash],
            stop: BlockHash,
            limit: usize,
        ) -> Vec<Header> {
            let mut start_idx = 0;
            for loc in locators {
                if let Some(h) = self.active_height(*loc) {
                    start_idx = (h + 1) as usize;
                    break;
                }
            }
            let mut result = Vec::new();
            for h in &self.headers[start_idx..self.active_len] {
                if result.len() >= limit {
                    break;
                }
                result.push(*h);
                if h.compute_hash() == stop {
                    break;
                }
            }
            result
        }

        fn compact_block_for(
            &self,
            _height: u32,
            hash: BlockHash,
            _compact_version: Option<u64>,
        ) -> Option<Message> {
            let h = self.headers[..self.active_len]
                .iter()
                .find(|header| header.compute_hash() == hash)?;
            let btc_header = bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(h.version),
                prev_blockhash: bitcoin::BlockHash::from_byte_array(*h.prev_blockhash.as_bytes()),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array(*h.merkle_root.as_byte_array()),
                time: h.time,
                bits: bitcoin::pow::CompactTarget::from_consensus(h.bits.to_consensus()),
                nonce: h.nonce,
            };
            Some(Message::CmpctBlock(CmpctBlock {
                compact_block: HeaderAndShortIds {
                    header: btc_header,
                    nonce: 42,
                    short_ids: Vec::new(),
                    prefilled_txs: Vec::new(),
                },
            }))
        }
    }

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn test_peer_info(addr: SocketAddr, send_headers: bool) -> PeerInfo {
        PeerInfo {
            addr,
            version: 70016,
            wtxid_relay: false,
            compact_block_relay: false,
            send_headers,
            services: 0,
            user_agent: String::new(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: Arc::new(crate::counters::PeerCounters::default()),
        }
    }

    fn setup_peer(
        table: &Arc<PeerTable>,
        announcer: &BlockAnnouncer,
        addr: SocketAddr,
        send_headers: bool,
    ) -> (PeerLease, Receiver<Message>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        table.register(addr, lease.clone());
        let info = test_peer_info(addr, send_headers);
        table.publish_info(addr, &lease, info);
        announcer.set_send_headers(lease.source(addr), send_headers);
        (lease, rx)
    }

    fn source(table: &PeerTable, addr: SocketAddr) -> PeerSource {
        table.lease(addr).expect("live test peer").source(addr)
    }

    fn mark_known(table: &PeerTable, announcer: &BlockAnnouncer, addr: SocketAddr, hash: Hash256) {
        announcer.mark_known_block(source(table, addr), hash);
    }

    fn note_compact_preference(
        table: &PeerTable,
        announcer: &BlockAnnouncer,
        addr: SocketAddr,
        high_bandwidth: bool,
        version: u64,
    ) {
        announcer.note_peer_compact_preference(source(table, addr), high_bandwidth, version);
    }

    #[test]
    fn test_headers_first_announcement_to_sendheaders_peer() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1001);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let event = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, addr);
        match &sent[0].1 {
            Message::Headers(headers) => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].compute_hash(), chain.block_hash_at(1));
            }
            other => panic!("expected Headers message, got {other:?}"),
        }

        let received = rx.try_recv().expect("peer received message");
        assert!(matches!(received, Message::Headers(_)));

        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(1)));
    }

    #[test]
    fn test_inv_fallback_without_sendheaders() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1002);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, false);

        let event = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 1);
        match &sent[0].1 {
            Message::Inv(inv) => {
                assert_eq!(inv.len(), 1);
                let expected = Inventory::Block(bitcoin::BlockHash::from_byte_array(
                    chain.hash_at(1).to_le_bytes(),
                ));
                assert_eq!(inv[0], expected);
            }
            other => panic!("expected Inv message, got {other:?}"),
        }

        let received = rx.try_recv().expect("peer received message");
        assert!(matches!(received, Message::Inv(_)));
    }

    #[test]
    fn test_no_redundant_announcement_when_peer_already_knows_tip() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1003);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(1));

        let event = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let sent = announcer.process_tip(&event);

        assert!(
            sent.is_empty(),
            "no redundant announcement should be planned"
        );
        assert!(rx.try_recv().is_err(), "peer should receive nothing");
    }

    #[test]
    fn test_disconnected_peer_cleans_up_state() {
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1004);
        let (lease, _rx) = setup_peer(&table, &announcer, addr, true);
        let _ = announcer.maybe_promote_peer(addr, &lease);
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![addr]);

        announcer.on_peer_disconnected(lease.source(addr));
        assert!(announcer.high_bandwidth_requested_peers().is_empty());
        assert_eq!(announcer.peer_known_block(addr), None);
    }

    #[test]
    fn test_reorg_before_send_discards_stale_branch() {
        let mut mock = MockAnnounceChain::new(3);
        let orphan_block_hash = BlockHash::default();
        mock.orphan_hashes.push(orphan_block_hash);

        let chain = Arc::new(mock);
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1005);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, orphan_block_hash.into());

        let event = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 1);
        match &sent[0].1 {
            Message::Inv(inv) => {
                let expected = Inventory::Block(bitcoin::BlockHash::from_byte_array(
                    chain.hash_at(2).to_le_bytes(),
                ));
                assert_eq!(inv[0], expected);
            }
            other => panic!("expected Inv fallback on unanchored reorg, got {other:?}"),
        }
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_idempotent_repeated_tip() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1006);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let event = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let sent1 = announcer.process_tip(&event);
        assert_eq!(sent1.len(), 1);
        assert!(rx.try_recv().is_ok());

        // Repeated tip event
        let sent2 = announcer.process_tip(&event);
        assert!(sent2.is_empty(), "repeated tip event must be a no-op");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_queue_capacity_and_pending_tip_preservation() {
        let chain = Arc::new(MockAnnounceChain::new(4));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let (queue, rx) = BlockAnnounceQueue::new(2);
        let e1 = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let e2 = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let e3 = BlockAnnounceEvent::new(3, chain.hash_at(3), chain.hash_at(2));

        assert!(queue.announce(e1));
        assert!(queue.announce(e2));
        assert!(
            !queue.announce(e3),
            "queue must report saturation when full"
        );
        assert_eq!(queue.enqueued(), 2);
        assert_eq!(queue.dropped(), 1);

        let addr = test_addr(1007);
        let (_lease, peer_rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        // When draining the saturated queue, e3 was preserved in the pending slot!
        let drained = announcer.drain_queue_and_process(&rx);
        assert_eq!(drained, 1);

        // Crucial invariant: latest committed tip e3 (height 3) is NOT lost!
        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(3)));
        let msg = peer_rx.try_recv().expect("peer received preserved tip");
        match msg {
            Message::Headers(h) => {
                assert_eq!(h.len(), 3);
                assert_eq!(h.last().unwrap().compute_hash(), chain.block_hash_at(3));
            }
            other => panic!("expected Headers, got {other:?}"),
        }
    }

    #[test]
    fn pending_overflow_does_not_replace_a_newer_reenqueued_tip() {
        let chain = MockAnnounceChain::new(4);
        let (queue, rx) = BlockAnnounceQueue::new(1);
        let e1 = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let e2 = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let e3 = BlockAnnounceEvent::new(3, chain.hash_at(3), chain.hash_at(2));

        assert!(queue.announce(e1));
        assert!(!queue.announce(e2));
        let _ = rx.receiver.try_recv().expect("consumer frees one slot");
        assert!(queue.announce(e3));

        assert_eq!(rx.try_recv_latest(), Some(e3));
    }

    #[test]
    fn stale_active_ancestor_is_not_announced_as_the_tip() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1009);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let stale = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        assert!(announcer.process_tip(&stale).is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn failed_send_does_not_advance_peer_known_tip() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1010);
        let (lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));
        drop(rx);

        let event = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        assert!(announcer.process_tip(&event).is_empty());
        assert_eq!(
            announcer
                .state
                .lock()
                .peer_trackers
                .get(&lease.source(addr))
                .and_then(|tracker| tracker.best_known_block),
            Some(chain.hash_at(0))
        );
    }

    #[test]
    fn test_bip152_promotion_sends_sendcmpct_true() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1008);
        let (lease, _rx) = setup_peer(&table, &announcer, addr, true);

        let msgs = announcer.maybe_promote_peer(addr, &lease);

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, lease.source(addr));
        assert_eq!(
            msgs[0].1,
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![addr]);
    }

    #[test]
    fn ready_peer_is_promoted_in_the_production_callback() {
        let chain = Arc::new(MockAnnounceChain::new(1));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1011);
        let (lease, rx) = setup_peer(&table, &announcer, addr, false);

        announcer.on_peer_ready(addr, &lease, &test_peer_info(addr, false));

        assert_eq!(
            rx.try_recv().expect("ready peer receives promotion"),
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![addr]);
    }

    #[test]
    fn stale_disconnect_keeps_replacement_announcement_state() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1012);
        let (old, _old_rx) = setup_peer(&table, &announcer, addr, true);
        let old_source = old.source(addr);

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());
        assert!(table.publish_info(addr, &replacement, test_peer_info(addr, true),));
        let replacement_source = replacement.source(addr);
        announcer.set_send_headers(replacement_source, true);
        announcer.mark_known_block(replacement_source, chain.hash_at(1));

        announcer.on_peer_disconnected(old_source);

        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(1)));
    }

    #[test]
    fn test_high_bandwidth_bounded_to_3_peers() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        for i in 1..=3 {
            let addr = test_addr(1010 + i);
            let (lease, _) = setup_peer(&table, &announcer, addr, true);
            let msgs = announcer.maybe_promote_peer(addr, &lease);
            assert_eq!(msgs.len(), 1);
        }

        assert_eq!(announcer.high_bandwidth_requested_peers().len(), 3);
    }

    #[test]
    fn test_promoting_4th_peer_demotes_1st_peer() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let a1 = test_addr(1021);
        let a2 = test_addr(1022);
        let a3 = test_addr(1023);
        let a4 = test_addr(1024);

        for a in [a1, a2, a3] {
            let (lease, _) = setup_peer(&table, &announcer, a, true);
            announcer.maybe_promote_peer(a, &lease);
        }

        let (lease4, _) = setup_peer(&table, &announcer, a4, true);
        let msgs = announcer.maybe_promote_peer(a4, &lease4);

        assert_eq!(msgs.len(), 2);
        assert_eq!(
            msgs[0],
            (
                source(&table, a1),
                Message::SendCmpct(SendCmpct {
                    send_compact: false,
                    version: 2,
                })
            )
        );
        assert_eq!(
            msgs[1],
            (
                source(&table, a4),
                Message::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: 2,
                })
            )
        );

        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![a2, a3, a4]);
    }

    #[test]
    fn test_compact_announcement_requires_peer_high_bandwidth_and_prev_hash() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        // addr1: peer wants high-bandwidth compact blocks AND knows prev_hash
        let addr1 = test_addr(1031);
        let (_lease1, _rx1) = setup_peer(&table, &announcer, addr1, true);
        note_compact_preference(&table, &announcer, addr1, true, 2);
        mark_known(&table, &announcer, addr1, chain.hash_at(1));

        // addr2: peer wants high-bandwidth compact blocks, but does NOT know prev_hash
        let addr2 = test_addr(1032);
        let (_lease2, _rx2) = setup_peer(&table, &announcer, addr2, true);
        note_compact_preference(&table, &announcer, addr2, true, 2);
        mark_known(&table, &announcer, addr2, chain.hash_at(0));

        // addr3: peer sent sendcmpct(false), knows prev_hash -> must NOT receive CmpctBlock
        let addr3 = test_addr(1033);
        let (_lease3, _rx3) = setup_peer(&table, &announcer, addr3, true);
        note_compact_preference(&table, &announcer, addr3, false, 2);
        mark_known(&table, &announcer, addr3, chain.hash_at(1));

        let event = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 3);
        let sent1 = sent.iter().find(|(a, _)| *a == addr1).unwrap();
        assert!(
            matches!(sent1.1, Message::CmpctBlock(_)),
            "peer with high-bandwidth request and prev_hash should receive CmpctBlock"
        );

        let sent2 = sent.iter().find(|(a, _)| *a == addr2).unwrap();
        assert!(
            matches!(sent2.1, Message::Headers(_)),
            "peer without prev_hash should fall back to Headers"
        );

        let sent3 = sent.iter().find(|(a, _)| *a == addr3).unwrap();
        assert!(
            matches!(sent3.1, Message::Headers(_)),
            "peer that sent sendcmpct(false) must fall back to Headers"
        );
    }

    #[test]
    fn test_blocksonly_suppresses_compact_announcement() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig { blocksonly: true },
        );

        let addr = test_addr(1041);
        let (lease, _rx) = setup_peer(&table, &announcer, addr, true);
        note_compact_preference(&table, &announcer, addr, true, 2);
        let promote_msgs = announcer.maybe_promote_peer(addr, &lease);
        assert!(
            promote_msgs.is_empty(),
            "blocksonly must suppress promotion to compact relay"
        );
        assert!(announcer.high_bandwidth_requested_peers().is_empty());

        mark_known(&table, &announcer, addr, chain.hash_at(1));
        let event = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 1);
        assert!(
            matches!(sent[0].1, Message::Headers(_)),
            "blocksonly must announce via Headers, not CmpctBlock"
        );
    }

    #[test]
    fn test_ibd_suppresses_proactive_announcements() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let ibd_latch = crate::sync::syncing_ibd_latch();
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        )
        .with_ibd(ibd_latch, Network::Regtest);

        let addr = test_addr(1042);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let event = BlockAnnounceEvent::new(1, chain.hash_at(1), chain.hash_at(0));
        let sent = announcer.process_tip(&event);

        assert!(
            sent.is_empty(),
            "announcements must be suppressed during IBD"
        );
        assert!(
            rx.try_recv().is_err(),
            "peer must receive nothing during IBD"
        );
    }

    #[test]
    fn test_core_parity_max_blocks_to_announce() {
        let chain = Arc::new(MockAnnounceChain::new(7));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        // Case A: distance = 5 <= MAX_BLOCKS_TO_ANNOUNCE (8) -> Headers
        let addr_a = test_addr(1051);
        let (_lease_a, rx_a) = setup_peer(&table, &announcer, addr_a, true);
        mark_known(&table, &announcer, addr_a, chain.hash_at(1));

        let event_a = BlockAnnounceEvent::new(6, chain.hash_at(6), chain.hash_at(5));
        let sent_a = announcer.process_tip(&event_a);
        assert_eq!(sent_a.len(), 1);
        match &sent_a[0].1 {
            Message::Headers(headers) => {
                assert_eq!(headers.len(), 5);
                assert_eq!(
                    headers.last().unwrap().compute_hash(),
                    chain.block_hash_at(6)
                );
            }
            other => panic!("expected Headers, got {other:?}"),
        }
        assert!(rx_a.try_recv().is_ok());

        // Case B: distance = 10 > MAX_BLOCKS_TO_ANNOUNCE (8) -> Inv fallback
        let chain = Arc::new(MockAnnounceChain::new(12));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr_b = test_addr(1052);
        let (_lease_b, rx_b) = setup_peer(&table, &announcer, addr_b, true);
        mark_known(&table, &announcer, addr_b, chain.hash_at(1));

        let event_b = BlockAnnounceEvent::new(11, chain.hash_at(11), chain.hash_at(10));
        let sent_b = announcer.process_tip(&event_b);
        let sent_b_item = sent_b
            .iter()
            .find(|(addr, _)| *addr == addr_b)
            .expect("announcement for peer B");
        match &sent_b_item.1 {
            Message::Inv(inv) => {
                assert_eq!(inv.len(), 1);
                let expected = Inventory::Block(bitcoin::BlockHash::from_byte_array(
                    chain.hash_at(11).to_le_bytes(),
                ));
                assert_eq!(inv[0], expected);
            }
            other => panic!("expected Inv fallback when distance > 8, got {other:?}"),
        }
        assert!(rx_b.try_recv().is_ok());
    }
}
