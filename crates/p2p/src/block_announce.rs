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
use crate::connection::PeerLease;
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

/// Bounded producer side of the block announcement queue.
#[derive(Clone)]
pub struct BlockAnnounceQueue {
    sender: Sender<BlockAnnounceEvent>,
    enqueued: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl BlockAnnounceQueue {
    /// Creates a bounded announcement queue with `capacity`.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Receiver<BlockAnnounceEvent>) {
        let (sender, receiver) = crossbeam_channel::bounded(capacity.max(1));
        let queue = Self {
            sender,
            enqueued: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (queue, receiver)
    }

    /// Announces a newly committed active block. Never blocks chainstate.
    pub fn announce(&self, event: BlockAnnounceEvent) -> bool {
        match self.sender.try_send(event) {
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

/// Per-peer announcement tracker.
#[derive(Clone, Debug, Default)]
pub struct PeerAnnounceTracker {
    /// Highest header/block known to be held by this peer.
    pub best_known_block: Option<Hash256>,
    /// Whether the peer negotiated BIP130 `sendheaders`.
    pub send_headers: bool,
    /// Whether this peer is currently in high-bandwidth compact mode.
    pub high_bandwidth: bool,
    /// Compact-block protocol version requested by the peer (e.g. 1 or 2).
    pub compact_version: Option<u64>,
}

#[derive(Default)]
struct AnnounceState {
    peer_trackers: HashMap<SocketAddr, PeerAnnounceTracker>,
    high_bandwidth_peers: Vec<SocketAddr>,
    last_announced_tip: Option<Hash256>,
}

/// Owner of block announcement selection, peer state, and high-bandwidth relay.
pub struct BlockAnnouncer {
    peers: Arc<PeerTable>,
    chain_query: Arc<dyn ChainQuery>,
    config: BlockAnnounceConfig,
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
            state: Mutex::new(AnnounceState::default()),
        }
    }

    /// Marks whether a peer negotiated BIP130 `sendheaders`.
    pub fn set_send_headers(&self, addr: SocketAddr, send_headers: bool) {
        let mut state = self.state.lock();
        state.peer_trackers.entry(addr).or_default().send_headers = send_headers;
    }

    /// Records BIP152 compact-block negotiation from a peer.
    pub fn note_compact_relay(&self, addr: SocketAddr, send_compact: bool, version: u64) {
        let mut state = self.state.lock();
        let tracker = state.peer_trackers.entry(addr).or_default();
        tracker.compact_version = Some(version);
        if !send_compact {
            tracker.high_bandwidth = false;
            state.high_bandwidth_peers.retain(|a| *a != addr);
        }
    }

    /// Records that `addr` is known to hold `hash`.
    pub fn mark_known_block(&self, addr: SocketAddr, hash: Hash256) {
        let mut state = self.state.lock();
        state
            .peer_trackers
            .entry(addr)
            .or_default()
            .best_known_block = Some(hash);
    }

    /// Reports whether `addr` is currently selected for high-bandwidth compact relay.
    #[must_use]
    pub fn is_high_bandwidth(&self, addr: &SocketAddr) -> bool {
        let state = self.state.lock();
        state.high_bandwidth_peers.contains(addr)
    }

    /// Returns the current list of peers in high-bandwidth compact mode.
    #[must_use]
    pub fn high_bandwidth_peers(&self) -> Vec<SocketAddr> {
        let state = self.state.lock();
        state.high_bandwidth_peers.clone()
    }

    /// Returns the best block known for `addr`.
    #[must_use]
    pub fn peer_known_block(&self, addr: SocketAddr) -> Option<Hash256> {
        let state = self.state.lock();
        state
            .peer_trackers
            .get(&addr)
            .and_then(|t| t.best_known_block)
    }

    /// Called when a peer handshake completes.
    pub fn on_peer_ready(&self, addr: SocketAddr, lease: &PeerLease, info: &PeerInfo) {
        if info.send_headers {
            self.set_send_headers(addr, true);
        }
        if info.compact_block_relay {
            self.note_compact_relay(addr, false, 2);
            let msgs = self.maybe_promote_peer(addr, lease);
            for (target, msg) in msgs {
                if let Some(target_lease) = self.peers.lease(target) {
                    let _ = target_lease.send(msg);
                }
            }
        }
    }

    /// Called when a peer disconnects: cleans up its announcement state.
    pub fn on_peer_disconnected(&self, addr: SocketAddr) {
        let mut state = self.state.lock();
        state.peer_trackers.remove(&addr);
        state.high_bandwidth_peers.retain(|a| *a != addr);
    }

    /// Considers promoting `addr` to high-bandwidth compact relay.
    ///
    /// Returns the messages that should be sent (demotions and promotion).
    pub fn maybe_promote_peer(
        &self,
        addr: SocketAddr,
        lease: &PeerLease,
    ) -> Vec<(SocketAddr, Message)> {
        if self.config.blocksonly || !lease.role().relays_transactions() {
            return Vec::new();
        }
        let mut state = self.state.lock();
        if let Some(tracker) = state.peer_trackers.get(&addr) {
            if tracker.high_bandwidth {
                return Vec::new();
            }
        }
        let mut messages = Vec::new();
        if state.high_bandwidth_peers.len() >= MAX_HIGH_BANDWIDTH_PEERS {
            let demoted_addr = state.high_bandwidth_peers.remove(0);
            if let Some(demoted_tracker) = state.peer_trackers.get_mut(&demoted_addr) {
                demoted_tracker.high_bandwidth = false;
            }
            let demote_msg = Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            });
            messages.push((demoted_addr, demote_msg));
        }
        let tracker = state.peer_trackers.entry(addr).or_default();
        tracker.high_bandwidth = true;
        state.high_bandwidth_peers.push(addr);
        let promote_msg = Message::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        });
        messages.push((addr, promote_msg));
        messages
    }

    /// Plans announcements for `event` without sending them directly.
    pub fn plan_announcements(&self, event: &BlockAnnounceEvent) -> Vec<(SocketAddr, Message)> {
        let mut state = self.state.lock();
        // 1. Idempotence: duplicate notifications for the same committed tip are no-op.
        if state.last_announced_tip == Some(event.hash) {
            return Vec::new();
        }

        // 2. Active-chain check: do not announce reorged-away or uncommitted blocks.
        let active_height = self.chain_query.active_height(BlockHash::from(event.hash));
        if active_height != Some(event.height) {
            return Vec::new();
        }

        state.last_announced_tip = Some(event.hash);

        // Clean up trackers for disconnected peers.
        let live_sessions = self.peers.sessions();
        let live_addrs: hashbrown::HashSet<SocketAddr> =
            live_sessions.iter().map(|s| s.addr).collect();
        state
            .peer_trackers
            .retain(|addr, _| live_addrs.contains(addr));
        state
            .high_bandwidth_peers
            .retain(|addr| live_addrs.contains(addr));

        let mut planned = Vec::new();

        for session in &live_sessions {
            let addr = session.addr;
            if session.lease.is_cancelled() {
                continue;
            }

            let tracker = state.peer_trackers.entry(addr).or_default();

            // 3. Do not redundantly announce if the peer is already known to have this tip.
            if tracker.best_known_block == Some(event.hash)
                || session.demonstrated_tips.contains(&event.hash)
            {
                tracker.best_known_block = Some(event.hash);
                continue;
            }

            // Option A: High-Bandwidth BIP152 Compact Block
            if tracker.high_bandwidth
                && !self.config.blocksonly
                && session.lease.role().relays_transactions()
            {
                let knows_prev = tracker.best_known_block == Some(event.prev_hash)
                    || session.demonstrated_tips.contains(&event.prev_hash);
                if knows_prev {
                    let version = tracker.compact_version.or(Some(2));
                    if let Some(msg) = self.chain_query.compact_block_for(
                        event.height,
                        BlockHash::from(event.hash),
                        version,
                    ) {
                        planned.push((addr, msg));
                        tracker.best_known_block = Some(event.hash);
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
                                    planned.push((addr, Message::Headers(headers)));
                                    tracker.best_known_block = Some(event.hash);
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
            planned.push((addr, Message::Inv(vec![block_inv])));
            tracker.best_known_block = Some(event.hash);
        }

        planned
    }

    /// Processes one committed tip event and sends announcements to eligible peers.
    pub fn process_tip(&self, event: &BlockAnnounceEvent) -> Vec<(SocketAddr, Message)> {
        let planned = self.plan_announcements(event);
        for (addr, msg) in &planned {
            if let Some(lease) = self.peers.lease(*addr) {
                let _ = lease.send(msg.clone());
            }
        }
        planned
    }

    /// Synchronously drains the queue, coalesces to the latest tip, and processes it.
    pub fn drain_queue_and_process(&self, rx: &Receiver<BlockAnnounceEvent>) -> usize {
        let mut count = 0;
        let mut latest = None;
        while let Ok(event) = rx.try_recv() {
            count += 1;
            latest = Some(event);
        }
        if let Some(event) = latest {
            self.process_tip(&event);
        }
        count
    }
}

/// Dedicated background worker thread that drains `BlockAnnounceQueue` and announces new blocks.
pub fn spawn_block_announce_worker(
    announcer: Arc<BlockAnnouncer>,
    rx: Receiver<BlockAnnounceEvent>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> Result<std::thread::JoinHandle<()>, std::io::Error> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-block-announce".into())
        .spawn(move || {
            while !shutdown.load() {
                match rx.recv_timeout(ANNOUNCE_POLL) {
                    Ok(event) => {
                        let mut latest = event;
                        // Coalesce: drain all currently pending events to the latest active tip.
                        while let Ok(next) = rx.try_recv() {
                            latest = next;
                        }
                        announcer.process_tip(&latest);
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
    use bitcoin_rs_primitives::{CompactTarget, Header};

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
        table.publish_info(addr, &lease, info.clone());
        announcer.on_peer_ready(addr, &lease, &info);
        (lease, rx)
    }

    #[test]
    fn test_headers_first_announcement_to_sendheaders_peer() {
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1001);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        announcer.mark_known_block(addr, chain.hash_at(0));

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
        let chain = Arc::new(MockAnnounceChain::new(5));
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
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1003);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        announcer.mark_known_block(addr, chain.hash_at(1));

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
        assert_eq!(announcer.high_bandwidth_peers(), vec![addr]);

        announcer.on_peer_disconnected(addr);
        assert!(announcer.high_bandwidth_peers().is_empty());
        assert_eq!(announcer.peer_known_block(addr), None);
    }

    #[test]
    fn test_reorg_before_send_discards_stale_branch() {
        let mut mock = MockAnnounceChain::new(5);
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
        announcer.mark_known_block(addr, orphan_block_hash.into());

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
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1006);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        announcer.mark_known_block(addr, chain.hash_at(0));

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
    fn test_queue_capacity_and_coalescing() {
        let chain = Arc::new(MockAnnounceChain::new(5));
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
        assert!(!queue.announce(e3), "queue must drop when full");
        assert_eq!(queue.enqueued(), 2);
        assert_eq!(queue.dropped(), 1);

        let addr = test_addr(1007);
        let (_lease, peer_rx) = setup_peer(&table, &announcer, addr, true);
        announcer.mark_known_block(addr, chain.hash_at(0));

        let drained = announcer.drain_queue_and_process(&rx);
        assert_eq!(drained, 2);

        // Should have coalesced to e2 (height 2)
        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(2)));
        let msg = peer_rx.try_recv().expect("peer received coalesced tip");
        match msg {
            Message::Headers(h) => {
                assert_eq!(h.len(), 2);
                assert_eq!(h.last().unwrap().compute_hash(), chain.block_hash_at(2));
            }
            other => panic!("expected Headers, got {other:?}"),
        }
    }

    #[test]
    fn test_bip152_promotion_sends_sendcmpct_true() {
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1008);
        let (lease, _rx) = setup_peer(&table, &announcer, addr, true);

        announcer.note_compact_relay(addr, true, 2);
        let msgs = announcer.maybe_promote_peer(addr, &lease);

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, addr);
        assert_eq!(
            msgs[0].1,
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(announcer.high_bandwidth_peers(), vec![addr]);
    }

    #[test]
    fn test_high_bandwidth_bounded_to_3_peers() {
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        for i in 1..=3 {
            let addr = test_addr(1010 + i);
            let (lease, _) = setup_peer(&table, &announcer, addr, true);
            announcer.note_compact_relay(addr, true, 2);
            let msgs = announcer.maybe_promote_peer(addr, &lease);
            assert_eq!(msgs.len(), 1);
        }

        assert_eq!(announcer.high_bandwidth_peers().len(), 3);
    }

    #[test]
    fn test_promoting_4th_peer_demotes_1st_peer() {
        let chain = Arc::new(MockAnnounceChain::new(5));
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
            announcer.note_compact_relay(a, true, 2);
            announcer.maybe_promote_peer(a, &lease);
        }

        let (lease4, _) = setup_peer(&table, &announcer, a4, true);
        announcer.note_compact_relay(a4, true, 2);
        let msgs = announcer.maybe_promote_peer(a4, &lease4);

        assert_eq!(msgs.len(), 2);
        assert_eq!(
            msgs[0],
            (
                a1,
                Message::SendCmpct(SendCmpct {
                    send_compact: false,
                    version: 2,
                })
            )
        );
        assert_eq!(
            msgs[1],
            (
                a4,
                Message::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: 2,
                })
            )
        );

        assert_eq!(announcer.high_bandwidth_peers(), vec![a2, a3, a4]);
    }

    #[test]
    fn test_compact_announcement_requires_prev_hash() {
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr1 = test_addr(1031);
        let (lease1, _rx1) = setup_peer(&table, &announcer, addr1, true);
        announcer.note_compact_relay(addr1, true, 2);
        announcer.maybe_promote_peer(addr1, &lease1);
        // addr1 knows block 1 (which is prev_hash for block 2)
        announcer.mark_known_block(addr1, chain.hash_at(1));

        let addr2 = test_addr(1032);
        let (lease2, _rx2) = setup_peer(&table, &announcer, addr2, true);
        announcer.note_compact_relay(addr2, true, 2);
        announcer.maybe_promote_peer(addr2, &lease2);
        // addr2 knows block 0 (NOT prev_hash for block 2)
        announcer.mark_known_block(addr2, chain.hash_at(0));

        let event = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 2);
        let sent1 = sent.iter().find(|(a, _)| *a == addr1).unwrap();
        assert!(
            matches!(sent1.1, Message::CmpctBlock(_)),
            "peer with prev_hash should receive CmpctBlock"
        );

        let sent2 = sent.iter().find(|(a, _)| *a == addr2).unwrap();
        assert!(
            matches!(sent2.1, Message::Headers(_)),
            "peer without prev_hash should fall back to Headers"
        );
    }

    #[test]
    fn test_blocksonly_suppresses_compact_announcement() {
        let chain = Arc::new(MockAnnounceChain::new(5));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig { blocksonly: true },
        );

        let addr = test_addr(1041);
        let (lease, _rx) = setup_peer(&table, &announcer, addr, true);
        announcer.note_compact_relay(addr, true, 2);
        let promote_msgs = announcer.maybe_promote_peer(addr, &lease);
        assert!(
            promote_msgs.is_empty(),
            "blocksonly must suppress promotion to compact relay"
        );
        assert!(announcer.high_bandwidth_peers().is_empty());

        announcer.mark_known_block(addr, chain.hash_at(1));
        let event = BlockAnnounceEvent::new(2, chain.hash_at(2), chain.hash_at(1));
        let sent = announcer.process_tip(&event);

        assert_eq!(sent.len(), 1);
        assert!(
            matches!(sent[0].1, Message::Headers(_)),
            "blocksonly must announce via Headers, not CmpctBlock"
        );
    }

    #[test]
    fn test_core_parity_max_blocks_to_announce() {
        let chain = Arc::new(MockAnnounceChain::new(15));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        // Case A: distance = 5 <= MAX_BLOCKS_TO_ANNOUNCE (8) -> Headers
        let addr_a = test_addr(1051);
        let (_lease_a, rx_a) = setup_peer(&table, &announcer, addr_a, true);
        announcer.mark_known_block(addr_a, chain.hash_at(1));

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
        let addr_b = test_addr(1052);
        let (_lease_b, rx_b) = setup_peer(&table, &announcer, addr_b, true);
        announcer.mark_known_block(addr_b, chain.hash_at(1));

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
