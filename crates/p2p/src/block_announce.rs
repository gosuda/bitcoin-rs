//! Outbound block announcement owner: headers-first, high-bandwidth compact block,
//! and `inv` fallback.
//!
//! # Architecture
//!
//! [`BlockAnnounceQueue`] is the non-blocking producer: a one-slot wake channel
//! that coalesces notifications under backpressure. Chainstate remains the
//! authoritative owner of the committed tip.
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
//! - Coalesces wakeups under queue saturation and rereads the committed tip from chainstate.
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
use parking_lot::Mutex;

use crate::PeerTable;
#[cfg(test)]
use crate::connection::PeerLease;
use crate::connection::PeerSource;
use crate::dispatch::{ChainQuery, CommittedTip};
#[cfg(test)]
use crate::peer_info::PeerInfo;
use crate::wire::Message;

/// Core's `MAX_BLOCKS_TO_ANNOUNCE` (`net_processing.cpp:111`).
pub const MAX_BLOCKS_TO_ANNOUNCE: usize = 8;

/// Core's `MAX_PEERS_FOR_HIGH_BANDWIDTH_CMPCT` (`net_processing.cpp:142`).
pub const MAX_HIGH_BANDWIDTH_PEERS: usize = 3;

/// Drain poll interval when the block announce queue is empty.
const ANNOUNCE_POLL: Duration = Duration::from_millis(100);

/// Configuration for block announcements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockAnnounceConfig {
    /// Whether the node operates in blocksonly/no-tx mode.
    /// In blocksonly mode, high-bandwidth compact block relay is disabled.
    pub blocksonly: bool,
}

/// Thread-safe non-blocking wake queue for committed-tip announcements.
#[derive(Clone)]
pub struct BlockAnnounceQueue {
    sender: Sender<()>,
    enqueued: Arc<AtomicU64>,
    coalesced: Arc<AtomicU64>,
}

/// Receiving end of the committed-tip wake queue.
pub struct BlockAnnounceReceiver {
    receiver: Receiver<()>,
}

impl BlockAnnounceQueue {
    /// Creates a one-slot wake queue. One pending token represents any number
    /// of committed-tip changes because the consumer rereads chainstate.
    #[must_use]
    pub fn new() -> (Self, BlockAnnounceReceiver) {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let queue = Self {
            sender,
            enqueued: Arc::new(AtomicU64::new(0)),
            coalesced: Arc::new(AtomicU64::new(0)),
        };
        let rx = BlockAnnounceReceiver { receiver };
        (queue, rx)
    }

    /// Wakes the P2P consumer after a committed chain change. Never blocks
    /// chainstate; a full slot already guarantees a future reread.
    pub fn wake(&self) -> bool {
        match self.sender.try_send(()) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(())) => {
                self.coalesced.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(())) => false,
        }
    }

    /// Total announcements enqueued.
    #[must_use]
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    /// Total wakes coalesced into an already-pending token.
    #[must_use]
    pub fn coalesced(&self) -> u64 {
        self.coalesced.load(Ordering::Relaxed)
    }
}

impl BlockAnnounceReceiver {
    /// Receives one wake, or waits up to `timeout`, then drains redundant
    /// tokens so the caller performs one chainstate reread.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(), crossbeam_channel::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)?;
        while self.receiver.try_recv().is_ok() {}
        Ok(())
    }

    /// Drains all available wake tokens.
    pub fn try_recv(&self) -> bool {
        let mut woke = false;
        while self.receiver.try_recv().is_ok() {
            woke = true;
        }
        woke
    }
}

#[derive(Default)]
struct AnnounceState {
    /// Up to 3 peers we have requested high-bandwidth compact blocks from via `sendcmpct(true, 2)`.
    /// BIP152: "Nodes MUST NOT send `sendcmpct(high_bandwidth=true)` to more than 3 peers."
    high_bandwidth_requested_peers: Vec<PeerSource>,
    /// Observation cursor only; chainstate remains the authoritative tip owner.
    last_processed_tip: Option<Hash256>,
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

    /// Records that `source` is known to hold `hash`.
    pub fn mark_known_block(&self, source: PeerSource, hash: Hash256) {
        self.peers.note_known_block(source, hash);
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
        self.peers
            .announcement_state(source)
            .and_then(|state| state.best_known_block)
    }

    /// Returns whether the peer requested high-bandwidth compact block announcements.
    #[must_use]
    pub fn peer_wants_high_bandwidth(&self, addr: SocketAddr) -> bool {
        let Some(source) = self.peers.lease(addr).map(|lease| lease.source(addr)) else {
            return false;
        };
        self.peers
            .announcement_state(source)
            .is_some_and(|state| state.compact_high_bandwidth == Some(true))
    }

    /// Called when a peer handshake completes.
    pub fn on_peer_ready(&self, source: PeerSource) {
        self.reconcile_high_bandwidth_peers_inner(Some(source));
    }

    /// Called when a peer disconnects: cleans up its announcement state.
    pub fn on_peer_disconnected(&self, source: PeerSource) {
        let mut state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .retain(|candidate| *candidate != source);
    }

    /// Reconciles the selected high-bandwidth compact-relay peers against
    /// current ready sessions and IBD state.
    pub fn reconcile_high_bandwidth_peers(&self) -> Vec<(SocketAddr, Message)> {
        self.reconcile_high_bandwidth_peers_inner(None)
    }

    fn reconcile_high_bandwidth_peers_inner(
        &self,
        preferred: Option<PeerSource>,
    ) -> Vec<(SocketAddr, Message)> {
        let eligible: Vec<_> = self
            .peers
            .sessions()
            .into_iter()
            .filter(|session| {
                session.info.is_some()
                    && !session.lease.is_cancelled()
                    && session.lease.role().relays_transactions()
            })
            .map(|session| session.lease.source(session.addr))
            .collect();
        let selection_open = !self.config.blocksonly && !self.in_ibd();
        let mut state = self.state.lock();
        let mut sent = Vec::new();

        let selected = state.high_bandwidth_requested_peers.clone();
        for source in selected {
            if selection_open && eligible.contains(&source) {
                continue;
            }
            let message = Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            });
            let send_succeeded = self.peers.send(source, message.clone()).is_ok();
            state
                .high_bandwidth_requested_peers
                .retain(|candidate| *candidate != source);
            if send_succeeded {
                sent.push((source.addr, message));
            }
        }

        if selection_open {
            if preferred.as_ref().is_some_and(|source| {
                eligible.contains(source) && !state.high_bandwidth_requested_peers.contains(source)
            }) {
                if state.high_bandwidth_requested_peers.len() >= MAX_HIGH_BANDWIDTH_PEERS {
                    let demoted = state.high_bandwidth_requested_peers.remove(0);
                    let message = Message::SendCmpct(SendCmpct {
                        send_compact: false,
                        version: 2,
                    });
                    if self.peers.send(demoted, message.clone()).is_ok() {
                        sent.push((demoted.addr, message));
                    }
                }
            }

            let candidates = preferred.into_iter().chain(eligible);
            for source in candidates {
                if state.high_bandwidth_requested_peers.len() >= MAX_HIGH_BANDWIDTH_PEERS {
                    break;
                }
                if state.high_bandwidth_requested_peers.contains(&source) {
                    continue;
                }
                let message = Message::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: 2,
                });
                if self.peers.send(source, message.clone()).is_ok() {
                    state.high_bandwidth_requested_peers.push(source);
                    sent.push((source.addr, message));
                }
            }
        }
        sent
    }

    fn ready_sessions(&self) -> Vec<crate::PeerSession> {
        self.peers
            .sessions()
            .into_iter()
            .filter(|session| session.info.is_some() && !session.lease.is_cancelled())
            .collect()
    }

    fn planned_announcements(&self, tip: CommittedTip) -> Vec<PlannedAnnouncement> {
        if self.in_ibd() {
            return Vec::new();
        }

        let mut state = self.state.lock();
        let tip_hash = Hash256::from(tip.hash);
        let prev_hash = Hash256::from(tip.prev_hash);
        // This is only an observation cursor. The authoritative current tip
        // was read from chainstate immediately before this call.
        if state.last_processed_tip == Some(tip_hash) {
            return Vec::new();
        }
        state.last_processed_tip = Some(tip_hash);
        drop(state);

        let live_sessions = self.ready_sessions();

        let mut planned = Vec::new();

        for session in &live_sessions {
            let addr = session.addr;
            let source = session.lease.source(addr);

            let peer_state = self.peers.announcement_state(source).unwrap_or_default();

            if peer_state.best_known_block == Some(tip_hash)
                || session.demonstrated_tips.contains(&tip_hash)
            {
                self.peers.note_known_block(source, tip_hash);
                continue;
            }

            // Option A: High-Bandwidth BIP152 Compact Block
            // Peer must have explicitly requested high-bandwidth compact blocks from us.
            if peer_state.compact_high_bandwidth == Some(true)
                && peer_state.compact_version == Some(2)
                && !self.config.blocksonly
                && session.lease.role().relays_transactions()
            {
                let knows_prev = peer_state.best_known_block == Some(prev_hash)
                    || session.demonstrated_tips.contains(&prev_hash);
                if knows_prev {
                    if let Some(msg @ Message::CmpctBlock(_)) =
                        self.chain_query
                            .compact_block_for(tip.height, tip.hash, Some(2))
                    {
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
            let send_headers = session.info.as_ref().is_some_and(|i| i.send_headers);
            if send_headers {
                if let Some(known_hash) = peer_state.best_known_block {
                    if let Some(known_height) =
                        self.chain_query.active_height(BlockHash::from(known_hash))
                    {
                        if known_height < tip.height {
                            let distance = tip.height - known_height;
                            let max_announce =
                                u32::try_from(MAX_BLOCKS_TO_ANNOUNCE).unwrap_or(u32::MAX);
                            if distance <= max_announce {
                                let limit = usize::try_from(distance).unwrap_or(usize::MAX);
                                let headers = self.chain_query.headers_after(
                                    &[BlockHash::from(known_hash)],
                                    tip.hash,
                                    limit,
                                );
                                if !headers.is_empty()
                                    && headers.last().map(|h| h.compute_hash().into())
                                        == Some(tip_hash)
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
            let block_inv =
                Inventory::Block(bitcoin::BlockHash::from_byte_array(tip_hash.to_le_bytes()));
            planned.push(PlannedAnnouncement {
                source,
                message: Message::Inv(vec![block_inv]),
                confirms_tip: false,
            });
        }

        planned
    }

    /// Plans announcements for the current committed tip without sending.
    pub fn plan_announcements(&self) -> Vec<(SocketAddr, Message)> {
        let Some(tip) = self.chain_query.committed_tip() else {
            return Vec::new();
        };
        self.planned_announcements(tip)
            .into_iter()
            .map(|planned| (planned.source.addr, planned.message))
            .collect()
    }

    /// Rereads and processes the current committed tip.
    pub fn process_tip(&self) -> Vec<(SocketAddr, Message)> {
        self.reconcile_high_bandwidth_peers();
        let Some(tip) = self.chain_query.committed_tip() else {
            return Vec::new();
        };
        let planned = self.planned_announcements(tip);
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
                self.peers
                    .note_known_block(announcement.source, Hash256::from(tip.hash));
            }
            sent.push((announcement.source.addr, announcement.message));
        }
        sent
    }

    /// Synchronously drains the queue, coalesces to the latest tip, and processes it.
    pub fn drain_queue_and_process(&self, rx: &BlockAnnounceReceiver) -> usize {
        if rx.try_recv() {
            self.process_tip();
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
                    Ok(()) => {
                        announcer.process_tip();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        announcer.reconcile_high_bandwidth_peers();
                    }
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
    use arc_swap::ArcSwapOption;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin_rs_chain::{
        BlockTree, BlockTreeReader, InitialBlockDownload, NodeStatus, TipReader,
    };
    use bitcoin_rs_primitives::{CompactTarget, Header, Network};
    use parking_lot::RwLock;
    use std::sync::atomic::AtomicU32;

    struct MockAnnounceChain {
        headers: Vec<Header>,
        active_len: usize,
        committed_height: AtomicU32,
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
                committed_height: AtomicU32::new(
                    u32::try_from(count.saturating_sub(1)).unwrap_or(u32::MAX),
                ),
                orphan_hashes: Vec::new(),
            }
        }

        fn hash_at(&self, idx: usize) -> Hash256 {
            self.headers[idx].compute_hash().into()
        }

        fn block_hash_at(&self, idx: usize) -> BlockHash {
            self.headers[idx].compute_hash()
        }

        fn set_committed_height(&self, height: u32) {
            self.committed_height.store(height, Ordering::Relaxed);
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

        fn committed_tip(&self) -> Option<CommittedTip> {
            if self.active_len == 0 {
                return None;
            }
            let height = self.committed_height.load(Ordering::Relaxed);
            let idx = usize::try_from(height).ok()?;
            let header = *self.headers.get(idx)?;
            Some(CommittedTip {
                height,
                hash: header.compute_hash(),
                prev_hash: header.prev_blockhash,
            })
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
        announcer.on_peer_ready(lease.source(addr));
        while rx.try_recv().is_ok() {}
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
        addr: SocketAddr,
        high_bandwidth: bool,
        version: u64,
    ) {
        table.note_compact_announcement(source(table, addr), high_bandwidth, version);
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

        let sent = announcer.process_tip();

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

        let sent = announcer.process_tip();

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

        let sent = announcer.process_tip();

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
        announcer.reconcile_high_bandwidth_peers();
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![addr]);

        announcer.on_peer_disconnected(lease.source(addr));
        assert_eq!(announcer.high_bandwidth_requested_peers(), Vec::new());
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

        let sent = announcer.process_tip();

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

        let sent1 = announcer.process_tip();
        assert_eq!(sent1.len(), 1);
        assert!(rx.try_recv().is_ok());

        // Repeated tip event
        let sent2 = announcer.process_tip();
        assert!(sent2.is_empty(), "repeated tip event must be a no-op");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn coalesced_wake_processes_the_latest_committed_tip() {
        let chain = Arc::new(MockAnnounceChain::new(4));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let (queue, rx) = BlockAnnounceQueue::new();

        assert!(queue.wake());
        assert!(!queue.wake(), "a pending wake must coalesce saturation");
        assert!(!queue.wake(), "all later commits share the pending wake");
        assert_eq!(queue.enqueued(), 1);
        assert_eq!(queue.coalesced(), 2);

        let addr = test_addr(1007);
        let (_lease, peer_rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let drained = announcer.drain_queue_and_process(&rx);
        assert_eq!(drained, 1);

        // The wake carries no stale payload: the consumer rereads height 3.
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
    fn producer_never_waits_for_a_saturated_wake_slot() {
        let (queue, rx) = BlockAnnounceQueue::new();

        assert!(queue.wake());
        assert!(!queue.wake());
        assert!(rx.try_recv());
        assert!(queue.wake());
        assert!(rx.try_recv());
    }

    #[test]
    fn committed_tip_is_announced_while_header_tip_is_ahead() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        chain.set_committed_height(1);
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1009);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let sent = announcer.process_tip();
        assert_eq!(sent.len(), 1);
        assert!(matches!(sent[0].1, Message::Headers(_)));
        assert!(rx.try_recv().is_ok());
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

        assert_eq!(announcer.process_tip(), Vec::new());
        assert_eq!(
            table
                .announcement_state(lease.source(addr))
                .and_then(|state| state.best_known_block),
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
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, test_peer_info(addr, true));

        let msgs = announcer.reconcile_high_bandwidth_peers();

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, addr);
        assert_eq!(
            msgs[0].1,
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(rx.try_recv(), Ok(msgs[0].1.clone()));
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
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        table.register(addr, lease.clone());
        let info = test_peer_info(addr, false);
        table.publish_info(addr, &lease, info);

        announcer.on_peer_ready(lease.source(addr));

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
            let _ = setup_peer(&table, &announcer, addr, true);
        }

        assert_eq!(announcer.high_bandwidth_requested_peers().len(), 3);
    }

    #[test]
    fn ready_peer_rotates_the_bounded_selection() {
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

        let (_lease1, rx1) = setup_peer(&table, &announcer, a1, true);
        let _ = setup_peer(&table, &announcer, a2, true);
        let _ = setup_peer(&table, &announcer, a3, true);

        let (tx4, rx4) = crossbeam_channel::unbounded();
        let lease4 = PeerLease::new(tx4);
        table.register(a4, lease4.clone());
        table.publish_info(a4, &lease4, test_peer_info(a4, true));
        let msgs = announcer.reconcile_high_bandwidth_peers_inner(Some(lease4.source(a4)));

        assert_eq!(msgs.len(), 2);
        assert_eq!(
            rx1.try_recv().expect("oldest peer receives demotion"),
            Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            })
        );
        assert_eq!(
            rx4.try_recv().expect("ready peer receives promotion"),
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
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
        note_compact_preference(&table, addr1, true, 2);
        mark_known(&table, &announcer, addr1, chain.hash_at(1));

        // addr2: peer wants high-bandwidth compact blocks, but does NOT know prev_hash
        let addr2 = test_addr(1032);
        let (_lease2, _rx2) = setup_peer(&table, &announcer, addr2, true);
        note_compact_preference(&table, addr2, true, 2);
        mark_known(&table, &announcer, addr2, chain.hash_at(0));

        // addr3: peer sent sendcmpct(false), knows prev_hash -> must NOT receive CmpctBlock
        let addr3 = test_addr(1033);
        let (_lease3, _rx3) = setup_peer(&table, &announcer, addr3, true);
        note_compact_preference(&table, addr3, false, 2);
        mark_known(&table, &announcer, addr3, chain.hash_at(1));

        let sent = announcer.process_tip();

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
        let (_lease, _rx) = setup_peer(&table, &announcer, addr, true);
        note_compact_preference(&table, addr, true, 2);
        let promote_msgs = announcer.reconcile_high_bandwidth_peers();
        assert!(
            promote_msgs.is_empty(),
            "blocksonly must suppress promotion to compact relay"
        );
        assert_eq!(announcer.high_bandwidth_requested_peers(), Vec::new());

        mark_known(&table, &announcer, addr, chain.hash_at(1));
        let sent = announcer.process_tip();

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

        let sent = announcer.process_tip();

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
    fn peer_connected_during_ibd_is_promoted_after_exit() {
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let ibd = Arc::new(InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        ));
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        )
        .with_ibd(Arc::clone(&ibd), Network::Regtest);
        let addr = test_addr(1043);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);

        assert!(announcer.in_ibd());
        assert_eq!(announcer.high_bandwidth_requested_peers(), Vec::new());

        let genesis = Network::Regtest.genesis_block();
        let recent = Header {
            prev_blockhash: genesis.block_hash(),
            time: u32::try_from(bitcoin_rs_primitives::unix_time_secs()).unwrap_or(u32::MAX),
            ..genesis.header
        };
        {
            let mut tree = block_tree.write();
            let genesis_id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .expect("insert genesis");
            tree.insert_node(Some(genesis_id), recent, NodeStatus::Active)
                .expect("insert recent child");
        }
        applied_tip.store(block_tree.read().tip());

        let sent = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            rx.try_recv().expect("IBD exit promotes existing peer"),
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![addr]);
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

        let sent_a = announcer.process_tip();
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

        let sent_b = announcer.process_tip();
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
