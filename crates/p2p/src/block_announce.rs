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
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256};
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use crate::PeerTable;
use crate::chain_query::{RecentBlockSlot, cmpct_message_from_native};
#[cfg(test)]
use crate::connection::PeerLease;
use crate::connection::PeerSource;
use crate::dispatch::{ChainQuery, CommittedTip};
use crate::peer::COMPACT_BLOCK_VERSION;
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
        let queue = Self { sender };
        let rx = BlockAnnounceReceiver { receiver };
        (queue, rx)
    }

    /// Wakes the P2P consumer after a committed chain change. Never blocks
    /// chainstate; a full slot already guarantees a future reread.
    pub fn wake(&self) -> bool {
        self.sender.try_send(()).is_ok()
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
    /// Greatest height announced early. Monotonic: a second block at the
    /// same height (reorg race, duplicate connect) or a stale side branch
    /// never re-announces.
    highest_fast_announce: u32,
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
    recent: RecentBlockSlot,
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
            recent: RecentBlockSlot::default(),
        }
    }

    /// Attaches the early-announce body rendezvous shared with the chain
    /// query, so compact `getdata` and `getblocktxn` for the most recently
    /// announced hash answer from the held body before the store carries it.
    #[must_use]
    pub fn with_recent_block(mut self, recent: RecentBlockSlot) -> Self {
        self.recent = recent;
        self
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

    /// Returns the current list of peers we requested high-bandwidth compact blocks from.
    #[cfg(test)]
    pub fn high_bandwidth_requested_peers(&self) -> Vec<SocketAddr> {
        let state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .iter()
            .map(|source| source.addr)
            .collect()
    }

    /// Returns the best block known for `addr`.
    #[cfg(test)]
    pub fn peer_known_block(&self, addr: SocketAddr) -> Option<Hash256> {
        let source = self.peers.lease(addr)?.source(addr);
        self.peers
            .announcement_state(source)
            .and_then(|state| state.last_announced_block)
    }

    /// Called when a peer handshake completes.
    pub fn on_peer_ready(&self) {
        self.reconcile_high_bandwidth_peers();
    }

    /// Called when a peer disconnects: cleans up its announcement state.
    pub fn on_peer_disconnected(&self, source: PeerSource) {
        let mut state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .retain(|candidate| *candidate != source);
        // Keep the table's `bip152_hb_to` snapshot consistent for the window
        // where the entry outlives the worker's set membership.
        self.peers.note_high_bandwidth_selected(source, false);
    }

    /// Initial fill: offer unused high-bandwidth slots to eligible peers,
    /// proven deliverers first. Pushes the fresh promotions into `sent`.
    fn fill_high_bandwidth_slots(
        &self,
        state: &mut AnnounceState,
        eligible: &[(PeerSource, u64)],
        sent: &mut Vec<(SocketAddr, Message)>,
    ) {
        // BIP152 asks for high-bandwidth slots to go to peers that recently
        // delivered blocks quickly. Filling strictly in session order
        // freezes the initial fill on whoever connected first — measured
        // live on testnet4, where a fresh v2/`hb=true` peer never won a
        // slot from the earliest-connected Core relayers — so prefer proven
        // deliverers here. Ties (all-zero sequences on quiet networks) keep
        // session order because the sort is stable; the rotation pass in
        // the caller still owns later upgrades.
        let mut fill_order = eligible.to_vec();
        fill_order.sort_by_key(|&(_, sequence)| std::cmp::Reverse(sequence));
        for &(source, _) in &fill_order {
            if state.high_bandwidth_requested_peers.len() >= MAX_HIGH_BANDWIDTH_PEERS {
                break;
            }
            if state.high_bandwidth_requested_peers.contains(&source) {
                continue;
            }
            let message = Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: COMPACT_BLOCK_VERSION,
            });
            if self.peers.send(source, message.clone()).is_ok() {
                state.high_bandwidth_requested_peers.push(source);
                self.peers.note_high_bandwidth_selected(source, true);
                sent.push((source.addr, message));
            }
        }
    }

    /// Reconciles the selected high-bandwidth compact-relay peers against
    /// current ready sessions and IBD state.
    pub fn reconcile_high_bandwidth_peers(&self) -> Vec<(SocketAddr, Message)> {
        let eligible: Vec<_> = self
            .peers
            .sessions()
            .into_iter()
            .filter_map(|session| {
                let source = session.lease.source(session.addr);
                let info = session.info.as_ref()?;
                let announcement = self.peers.announcement_state(source)?;
                (!session.lease.is_cancelled()
                    && session.lease.role().relays_transactions()
                    && info.compact_block_relay
                    && announcement.compact_version == Some(COMPACT_BLOCK_VERSION))
                .then_some((source, announcement.useful_block_sequence))
            })
            .collect();
        let selection_open = !self.config.blocksonly && !self.in_ibd();
        let mut state = self.state.lock();
        let mut sent = Vec::new();

        let selected = state.high_bandwidth_requested_peers.clone();
        for source in selected {
            if selection_open && eligible.iter().any(|(candidate, _)| *candidate == source) {
                continue;
            }
            let message = Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: COMPACT_BLOCK_VERSION,
            });
            let send_succeeded = self.peers.send(source, message.clone()).is_ok();
            state
                .high_bandwidth_requested_peers
                .retain(|candidate| *candidate != source);
            self.peers.note_high_bandwidth_selected(source, false);
            if send_succeeded {
                sent.push((source.addr, message));
            }
        }

        if selection_open {
            self.fill_high_bandwidth_slots(&mut state, &eligible, &mut sent);

            while let Some(&(candidate, candidate_sequence)) = eligible
                .iter()
                .filter(|(source, sequence)| {
                    *sequence > 0 && !state.high_bandwidth_requested_peers.contains(source)
                })
                .max_by_key(|(_, sequence)| *sequence)
            {
                let Some((demote_index, demoted_sequence)) = state
                    .high_bandwidth_requested_peers
                    .iter()
                    .enumerate()
                    .filter_map(|(index, source)| {
                        eligible
                            .iter()
                            .find(|(candidate, _)| candidate == source)
                            .map(|(_, sequence)| (index, *sequence))
                    })
                    .min_by_key(|(_, sequence)| *sequence)
                else {
                    break;
                };
                if candidate_sequence <= demoted_sequence {
                    break;
                }

                let demoted = state.high_bandwidth_requested_peers.remove(demote_index);
                self.peers.note_high_bandwidth_selected(demoted, false);
                let demote = Message::SendCmpct(SendCmpct {
                    send_compact: false,
                    version: COMPACT_BLOCK_VERSION,
                });
                if self.peers.send(demoted, demote.clone()).is_ok() {
                    sent.push((demoted.addr, demote));
                }

                let promote = Message::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: COMPACT_BLOCK_VERSION,
                });
                if self.peers.send(candidate, promote.clone()).is_ok() {
                    state.high_bandwidth_requested_peers.push(candidate);
                    self.peers.note_high_bandwidth_selected(candidate, true);
                    sent.push((candidate.addr, promote));
                } else {
                    break;
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

    /// Why the planner fell back to a plain `inv` for one peer. Kept out of
    /// `planned_announcements` so the decision skeleton stays readable.
    fn inv_fallback_reason(
        send_headers: bool,
        known_position: Option<(Hash256, u32)>,
        tip_height: u32,
    ) -> &'static str {
        if !send_headers {
            "sendheaders not negotiated"
        } else if known_position.is_none() {
            "no demonstrated anchor"
        } else if !known_position.is_some_and(|(_, known_height)| {
            tip_height - known_height <= u32::try_from(MAX_BLOCKS_TO_ANNOUNCE).unwrap_or(u32::MAX)
        }) {
            "anchor beyond MAX_BLOCKS_TO_ANNOUNCE"
        } else {
            "headers walk unavailable"
        }
    }

    /// One ready session's announcement anchor: its source, its recorded
    /// compact preference, and its best demonstrated-or-announced position on
    /// the active chain. Shared by post-commit planning and the pre-commit
    /// early send so both read the same eligibility.
    fn peer_anchor(
        &self,
        session: &crate::PeerSession,
    ) -> (
        PeerSource,
        crate::peer_table::PeerAnnouncementState,
        Option<(Hash256, u32)>,
    ) {
        let source = session.lease.source(session.addr);
        let peer_state = self.peers.announcement_state(source).unwrap_or_default();
        let known_position = peer_state
            .last_announced_block
            .into_iter()
            .chain(session.demonstrated_tips.iter().copied())
            .filter_map(|hash| {
                self.chain_query
                    .active_height(BlockHash::from(hash))
                    .map(|height| (hash, height))
            })
            .max_by_key(|(_, height)| *height);
        (source, peer_state, known_position)
    }

    /// High-bandwidth compact-push candidacy for one ready session: the peer
    /// asked for high-bandwidth compact blocks, is not blocksonly-gated,
    /// knows the tip's parent, and was not already sent this header. The
    /// compact body builds lazily through `build`, so ineligible peers cost
    /// no store load and the pre-commit path builds its hand-held body once
    /// for all peers. One rule, two callers.
    fn plan_compact_push(
        &self,
        session: &crate::PeerSession,
        peer_state: crate::peer_table::PeerAnnouncementState,
        known_position: Option<(Hash256, u32)>,
        tip_height: u32,
        build: impl FnOnce() -> Option<Message>,
    ) -> Option<PlannedAnnouncement> {
        if known_position.is_some_and(|(_, height)| height >= tip_height) {
            return None;
        }
        // Peer must have explicitly requested high-bandwidth compact blocks
        // from us.
        if peer_state.compact_high_bandwidth != Some(true)
            || peer_state.compact_version != Some(COMPACT_BLOCK_VERSION)
            || self.config.blocksonly
            || !session.lease.role().relays_transactions()
        {
            return None;
        }
        let knows_prev =
            known_position.is_some_and(|(_, height)| height >= tip_height.saturating_sub(1));
        if !knows_prev {
            return None;
        }
        build().map(|message| PlannedAnnouncement {
            source: session.lease.source(session.addr),
            message,
            confirms_tip: true,
        })
    }

    /// Early compact-block announce for a PoW-valid tip child: relays the
    /// block to eligible high-bandwidth peers before connect finishes, and
    /// holds the body so compact `getdata` and `getblocktxn` answer before
    /// the store carries it. Never publishes a tip and never advances the
    /// mining generation; miners switch on the post-commit path. Skipped in
    /// initial block download and for a height at or below the greatest
    /// already announced early, so reorg races and duplicate connects send
    /// nothing more. A later connect failure is not retracted — the send
    /// stands, and the failure sends nothing further.
    pub fn announce_pow_valid(
        &self,
        block: &Block,
        hash: Hash256,
        height: u32,
    ) -> Vec<(SocketAddr, Message)> {
        if self.in_ibd() {
            return Vec::new();
        }
        let Some(prebuilt) = cmpct_message_from_native(block, COMPACT_BLOCK_VERSION) else {
            return Vec::new();
        };
        {
            let mut state = self.state.lock();
            if height <= state.highest_fast_announce {
                return Vec::new();
            }
            state.highest_fast_announce = height;
            // The one held body: `block` is borrowed from the connect call,
            // so retaining it past this call needs exactly one copy.
            self.recent.store(hash, Arc::new(block.clone()));
        }
        let mut sent = Vec::new();
        for session in self.ready_sessions() {
            let (_, peer_state, known_position) = self.peer_anchor(&session);
            let Some(announcement) =
                self.plan_compact_push(&session, peer_state, known_position, height, || {
                    Some(prebuilt.clone())
                })
            else {
                continue;
            };
            if self
                .peers
                .send(announcement.source, announcement.message.clone())
                .is_err()
            {
                continue;
            }
            // Record the per-peer announcement: the post-commit `process_tip`
            // reads it as the peer's known position and sends no second
            // `cmpctblock` for this hash.
            self.peers.note_announced_block(announcement.source, hash);
            sent.push((announcement.source.addr, announcement.message));
        }
        sent
    }

    fn planned_announcements(&self, tip: CommittedTip) -> Vec<PlannedAnnouncement> {
        let tip_hash = Hash256::from(tip.hash);
        let live_sessions = self.ready_sessions();

        let mut planned = Vec::new();

        for session in &live_sessions {
            let addr = session.addr;
            let (source, peer_state, known_position) = self.peer_anchor(session);

            if known_position.is_some_and(|(_, height)| height >= tip.height) {
                continue;
            }

            // Option A: High-Bandwidth BIP152 Compact Block
            if let Some(announcement) =
                self.plan_compact_push(session, peer_state, known_position, tip.height, || {
                    self.chain_query
                        .compact_block_for(tip.height, tip.hash, Some(COMPACT_BLOCK_VERSION))
                        .filter(|msg| matches!(msg, Message::CmpctBlock(_)))
                })
            {
                tracing::debug!(
                    peer = %addr,
                    tip_height = tip.height,
                    mode = "compact",
                    "block announcement planned"
                );
                planned.push(announcement);
                continue;
            }

            // Option B: Headers-First Announcement (BIP130)
            //
            // Anchoring requires a demonstrated position: a tip this
            // connection delivered and the node accepted (`demonstrated_tips`
            // from a headers-download round, or its last announced block). A
            // sendheaders peer that only listens for announcements has no
            // anchor, so it stays on the `inv` fallback — measured live on
            // testnet4 and pinned by
            // `test_sendheaders_peer_without_demonstrated_tip_gets_inv`.
            // Core additionally anchors on the peer's own announcements;
            // closing that gap is a sync-credit change, not a planner one.
            let send_headers = session.info.as_ref().is_some_and(|i| i.send_headers);
            if send_headers {
                if let Some((known_hash, known_height)) = known_position
                    && known_height < tip.height
                {
                    let distance = tip.height - known_height;
                    let max_announce = u32::try_from(MAX_BLOCKS_TO_ANNOUNCE).unwrap_or(u32::MAX);
                    if distance <= max_announce {
                        let limit = usize::try_from(distance).unwrap_or(usize::MAX);
                        let headers = self.chain_query.headers_after(
                            &[BlockHash::from(known_hash)],
                            tip.hash,
                            limit,
                        );
                        if !headers.is_empty()
                            && headers.last().map(|h| h.compute_hash().into()) == Some(tip_hash)
                        {
                            planned.push(PlannedAnnouncement {
                                source,
                                message: Message::Headers(headers),
                                confirms_tip: true,
                            });
                            tracing::debug!(
                                peer = %addr,
                                tip_height = tip.height,
                                mode = "headers",
                                "block announcement planned"
                            );
                            continue;
                        }
                    }
                }
            }

            // Option C: `inv` Compatibility Fallback
            let reason = Self::inv_fallback_reason(send_headers, known_position, tip.height);
            let block_inv =
                Inventory::Block(bitcoin::BlockHash::from_byte_array(tip_hash.to_le_bytes()));
            planned.push(PlannedAnnouncement {
                source,
                message: Message::Inv(vec![block_inv]),
                confirms_tip: false,
            });
            tracing::debug!(
                peer = %addr,
                tip_height = tip.height,
                mode = "inv",
                reason,
                "block announcement planned"
            );
        }

        planned
    }

    /// Rereads and processes the current committed tip.
    pub fn process_tip(&self) -> Vec<(SocketAddr, Message)> {
        self.reconcile_high_bandwidth_peers();
        if self.in_ibd() {
            return Vec::new();
        }
        let Some(tip) = self.chain_query.committed_tip() else {
            return Vec::new();
        };
        let tip_hash = Hash256::from(tip.hash);
        {
            let mut state = self.state.lock();
            // Claim the observation only on the processing path. Planning is
            // side-effect free, while this claim prevents concurrent workers
            // from sending the same committed tip twice.
            if state.last_processed_tip == Some(tip_hash) {
                return Vec::new();
            }
            state.last_processed_tip = Some(tip_hash);
        }
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
                    .note_announced_block(announcement.source, tip_hash);
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
    use bitcoin_rs_primitives::{
        Amount, Block, CompactTarget, Header, LockTime, Network, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Witness,
    };
    use parking_lot::RwLock;
    use std::sync::atomic::{AtomicU32, Ordering};

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
            relay_transactions: true,
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
            transport: crate::TransportProtocol::V1,
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
        announcer.on_peer_ready();
        while rx.try_recv().is_ok() {}
        (lease, rx)
    }

    fn source(table: &PeerTable, addr: SocketAddr) -> PeerSource {
        table.lease(addr).expect("live test peer").source(addr)
    }

    fn mark_known(table: &PeerTable, _announcer: &BlockAnnouncer, addr: SocketAddr, hash: Hash256) {
        table.note_announced_block(source(table, addr), hash);
    }

    fn note_compact_preference(
        table: &PeerTable,
        addr: SocketAddr,
        high_bandwidth: bool,
        version: u64,
    ) {
        let mut negotiation = crate::CompactBlockNegotiation::default();
        negotiation.record_remote_preference(&SendCmpct {
            send_compact: high_bandwidth,
            version,
        });
        if negotiation.remote_preference().is_some() {
            table.note_compact_relay(source(table, addr));
            table.note_compact_announcement(source(table, addr), &negotiation);
        }
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
    fn test_high_bandwidth_fill_prefers_proven_deliverers() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        // Four eligible compact peers connected in order; a4 delivered three
        // blocks and a1 one, the middle two none. BIP152 wants the slots on
        // the proven deliverers, deepest sequence first. All peers are set
        // up before any compact preference is recorded so the explicit
        // reconcile below is the only one that sees eligible peers.
        let addrs = [
            test_addr(1201),
            test_addr(1202),
            test_addr(1203),
            test_addr(1204),
        ];
        let _peers: Vec<_> = addrs
            .iter()
            .map(|addr| setup_peer(&table, &announcer, *addr, false))
            .collect();
        for addr in addrs {
            note_compact_preference(&table, addr, true, 2);
        }
        table.note_useful_block(source(&table, addrs[0]));
        for _ in 0..3 {
            table.note_useful_block(source(&table, addrs[3]));
        }

        let sent = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(sent.len(), 3);
        assert_eq!(
            announcer.high_bandwidth_requested_peers(),
            vec![addrs[3], addrs[0], addrs[1]]
        );

        // The selection is written through to the snapshot rpc reads.
        for (addr, expected) in addrs.iter().zip([true, true, false, true]) {
            let state = table
                .announcement_state(source(&table, *addr))
                .expect("published peer");
            assert_eq!(
                state.selected_high_bandwidth, expected,
                "bip152_hb_to must reflect the worker's selection"
            );
        }
    }

    #[test]
    fn test_high_bandwidth_fill_keeps_session_order_without_evidence() {
        // All sequences zero (quiet network): the stable sort keeps session
        // order, so the fill behaves exactly like the old connection-order
        // rule whenever no peer has delivered blocks yet.
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addrs = [
            test_addr(1211),
            test_addr(1212),
            test_addr(1213),
            test_addr(1214),
        ];
        let _peers: Vec<_> = addrs
            .iter()
            .map(|addr| setup_peer(&table, &announcer, *addr, false))
            .collect();
        for addr in addrs {
            note_compact_preference(&table, addr, true, 2);
        }

        let sent = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(sent.len(), 3);
        assert_eq!(
            announcer.high_bandwidth_requested_peers(),
            vec![addrs[0], addrs[1], addrs[2]]
        );
    }

    #[test]
    fn test_sendheaders_peer_without_demonstrated_tip_gets_inv() {
        // Live-measured on testnet4: a sendheaders peer that never
        // participates in a headers-download round has no demonstrated
        // anchor, so the planner conservatively falls back to `inv` instead
        // of BIP130 `headers`. See the Option B comment in
        // `planned_announcements`.
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1221);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        // No mark_known: the peer demonstrated nothing.

        let sent = announcer.process_tip();
        assert_eq!(sent.len(), 1);
        assert!(matches!(sent[0].1, Message::Inv(_)));
        assert!(
            matches!(rx.try_recv(), Ok(Message::Inv(_))),
            "an unanchored sendheaders peer must get the inv fallback"
        );
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
        note_compact_preference(&table, addr, false, 2);
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
    fn planning_does_not_consume_the_committed_tip() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1007);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let tip = chain.committed_tip().expect("committed tip");
        assert_eq!(announcer.planned_announcements(tip).len(), 1);
        assert_eq!(announcer.planned_announcements(tip).len(), 1);

        let sent = announcer.process_tip();
        assert_eq!(sent.len(), 1);
        assert!(rx.try_recv().is_ok(), "planning must not suppress the send");
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

        let addr = test_addr(1008);
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
                .and_then(|state| state.last_announced_block),
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
        note_compact_preference(&table, addr, false, 2);

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
    fn high_bandwidth_selection_requires_full_relay_and_compact_v2() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let v1_addr = test_addr(1006);
        let _v1_peer = setup_peer(&table, &announcer, v1_addr, true);
        note_compact_preference(&table, v1_addr, false, 1);

        let block_only_addr = test_addr(1007);
        let (block_only_tx, _block_only_rx) = crossbeam_channel::unbounded();
        let block_only = PeerLease::new_block_relay(block_only_tx);
        table.register(block_only_addr, block_only.clone());
        table.publish_info(
            block_only_addr,
            &block_only,
            test_peer_info(block_only_addr, true),
        );
        note_compact_preference(&table, block_only_addr, false, 2);

        assert_eq!(announcer.reconcile_high_bandwidth_peers(), Vec::new());
        assert_eq!(announcer.high_bandwidth_requested_peers(), Vec::new());
    }

    #[test]
    fn ready_peer_waits_for_compact_v2_support_before_promotion() {
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

        announcer.on_peer_ready();
        assert!(rx.try_recv().is_err());
        assert_eq!(announcer.high_bandwidth_requested_peers(), Vec::new());

        note_compact_preference(&table, addr, false, 2);
        announcer.reconcile_high_bandwidth_peers();

        assert_eq!(
            rx.try_recv().expect("compact-v2 peer receives promotion"),
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
        table.note_announced_block(replacement_source, chain.hash_at(1));

        announcer.on_peer_disconnected(old_source);

        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(1)));
    }

    #[test]
    fn verified_peer_progress_does_not_retreat_on_late_older_evidence() {
        let chain = Arc::new(MockAnnounceChain::new(4));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1013);
        let (lease, rx) = setup_peer(&table, &announcer, addr, true);
        let source = lease.source(addr);
        table.note_announced_tip(source, chain.hash_at(3), Some(3));
        table.note_announced_tip(source, chain.hash_at(1), Some(1));

        assert_eq!(announcer.process_tip(), Vec::new());
        assert!(rx.try_recv().is_err());
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

        let mut peers = Vec::new();
        for i in 1..=3 {
            let addr = test_addr(1010 + i);
            peers.push(setup_peer(&table, &announcer, addr, true));
            note_compact_preference(&table, addr, false, 2);
            announcer.reconcile_high_bandwidth_peers();
        }

        assert_eq!(peers.len(), 3);
        assert_eq!(announcer.high_bandwidth_requested_peers().len(), 3);
    }

    #[test]
    fn useful_compact_v2_peer_rotates_the_bounded_selection() {
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
        note_compact_preference(&table, a1, false, 2);
        announcer.reconcile_high_bandwidth_peers();
        assert!(rx1.try_recv().is_ok());
        let _peer2 = setup_peer(&table, &announcer, a2, true);
        note_compact_preference(&table, a2, false, 2);
        announcer.reconcile_high_bandwidth_peers();
        let _peer3 = setup_peer(&table, &announcer, a3, true);
        note_compact_preference(&table, a3, false, 2);
        announcer.reconcile_high_bandwidth_peers();

        let (tx4, rx4) = crossbeam_channel::unbounded();
        let lease4 = PeerLease::new(tx4);
        table.register(a4, lease4.clone());
        table.publish_info(a4, &lease4, test_peer_info(a4, true));
        note_compact_preference(&table, a4, false, 2);

        let connected = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(connected, Vec::new());
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![a1, a2, a3]);

        table.note_useful_block(lease4.source(a4));
        let msgs = announcer.reconcile_high_bandwidth_peers();

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
        note_compact_preference(&table, addr, false, 2);

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

    /// One-coinbase native tip child for early-send tests. The encoder never
    /// validates, so the merkle root stays default; only the header linkage
    /// matters for anchor resolution.
    fn tip_child_block(prev: BlockHash, time: u32) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 0,
            },
            txs: vec![Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![0x51]),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: Script::from_bytes(vec![]),
                }],
            }],
        }
    }

    #[test]
    fn early_announce_sends_one_cmpctblock_to_parent_known_hb_peer() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        // A high-bandwidth peer that demonstrated the tip (the parent).
        let addr = test_addr(1301);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, false);
        note_compact_preference(&table, addr, true, 2);
        mark_known(&table, &announcer, addr, chain.hash_at(1));
        // A second peer without compact relay must stay silent.
        let quiet = test_addr(1302);
        let (_quiet_lease, quiet_rx) = setup_peer(&table, &announcer, quiet, false);
        // The second setup reconciles high-bandwidth slots and may promote
        // the first peer (`SendCmpct`); drain it so the assertions below see
        // only the early send.
        while rx.try_recv().is_ok() {}

        let block = tip_child_block(chain.block_hash_at(1), 1200);
        let hash = Hash256::from(block.block_hash());
        let sent = announcer.announce_pow_valid(&block, hash, 2);

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, addr);
        assert!(
            matches!(sent[0].1, Message::CmpctBlock(_)),
            "expected one cmpctblock, got {:?}",
            sent[0].1
        );
        assert!(
            quiet_rx.try_recv().is_err(),
            "a non-compact peer must receive nothing early"
        );
        let received = rx.try_recv().expect("peer received the early send");
        assert!(matches!(received, Message::CmpctBlock(_)));
        assert_eq!(announcer.peer_known_block(addr), Some(hash));
    }

    #[test]
    fn early_announce_same_height_sends_nothing() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1311);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, false);
        note_compact_preference(&table, addr, true, 2);
        mark_known(&table, &announcer, addr, chain.hash_at(1));

        let block = tip_child_block(chain.block_hash_at(1), 1200);
        let hash = Hash256::from(block.block_hash());
        assert_eq!(announcer.announce_pow_valid(&block, hash, 2).len(), 1);
        while rx.try_recv().is_ok() {}

        // Same height again — duplicate or reorg sibling — sends nothing.
        assert_eq!(announcer.announce_pow_valid(&block, hash, 2), []);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn early_announce_without_parent_knowledge_sends_nothing() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        // High-bandwidth preference recorded, but the parent never
        // demonstrated: the peer cannot anchor the tip child.
        let addr = test_addr(1321);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, false);
        note_compact_preference(&table, addr, true, 2);

        let block = tip_child_block(chain.block_hash_at(1), 1200);
        let hash = Hash256::from(block.block_hash());
        assert_eq!(announcer.announce_pow_valid(&block, hash, 2), []);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn post_commit_process_tip_sends_no_second_cmpctblock() {
        let mut chain = MockAnnounceChain::new(2);
        let mut early = tip_child_block(chain.block_hash_at(1), 1200);
        early.header.nonce = 7;
        chain.headers.push(early.header);
        chain.active_len = 3;
        chain.set_committed_height(1);
        let chain = Arc::new(chain);
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1331);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, false);
        note_compact_preference(&table, addr, true, 2);
        mark_known(&table, &announcer, addr, chain.hash_at(1));

        let hash = Hash256::from(early.block_hash());
        assert_eq!(announcer.announce_pow_valid(&early, hash, 2).len(), 1);
        while rx.try_recv().is_ok() {}
        chain.set_committed_height(2);

        let sent = announcer.process_tip();
        assert!(
            !sent
                .iter()
                .any(|(peer, message)| *peer == addr && matches!(message, Message::CmpctBlock(_))),
            "post-commit must not resend cmpctblock to the early peer: {sent:?}"
        );
        // Reconciliation inside `process_tip` may promote the peer with
        // `SendCmpct`; the wire must carry no second `cmpctblock`.
        while let Ok(message) = rx.try_recv() {
            assert!(
                !matches!(message, Message::CmpctBlock(_)),
                "post-commit must not resend cmpctblock to the early peer"
            );
        }
    }
}
