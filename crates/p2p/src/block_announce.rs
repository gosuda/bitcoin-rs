//! Outbound block announcement owner: headers-first, high-bandwidth compact block,

#[cfg(test)]
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

pub const MAX_BLOCKS_TO_ANNOUNCE: usize = 8;

pub const MAX_HIGH_BANDWIDTH_PEERS: usize = 3;

const ANNOUNCE_POLL: Duration = Duration::from_millis(100);

pub(crate) fn ibd_active(
    ibd: Option<&(
        Arc<bitcoin_rs_chain::InitialBlockDownload>,
        bitcoin_rs_primitives::Network,
    )>,
) -> bool {
    ibd.is_some_and(|(latch, network)| {
        latch.is_active(bitcoin_rs_primitives::unix_time_secs(), *network)
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockAnnounceConfig {
    pub blocksonly: bool,
}

#[derive(Clone)]
pub struct BlockAnnounceQueue {
    sender: Sender<()>,
}

pub struct BlockAnnounceReceiver {
    receiver: Receiver<()>,
}

impl BlockAnnounceQueue {
    #[must_use]
    pub fn new() -> (Self, BlockAnnounceReceiver) {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let queue = Self { sender };
        let rx = BlockAnnounceReceiver { receiver };
        (queue, rx)
    }

    pub fn wake(&self) -> bool {
        self.sender.try_send(()).is_ok()
    }
}

impl BlockAnnounceReceiver {
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(), crossbeam_channel::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)?;
        while self.receiver.try_recv().is_ok() {}
        Ok(())
    }

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
    /// BIP152: "Nodes MUST NOT send `sendcmpct(high_bandwidth=true)` to more than 3 peers."
    high_bandwidth_requested_peers: Vec<PeerSource>,
    last_processed_tip: Option<Hash256>,
    highest_fast_announce: u32,
    announcement_retry: bool,
    announcement_epoch: u64,
}

#[derive(Clone)]
struct PlannedAnnouncement {
    source: PeerSource,
    message: Message,
    confirms_tip: bool,
}

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
    stale_tips: Option<Arc<crate::sync::StaleTipRetainer>>,
    block_tree: Option<bitcoin_rs_chain::BlockTreeReader>,
}

impl BlockAnnouncer {
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
            stale_tips: None,
            block_tree: None,
        }
    }

    /// can relay recent stale tips to peers that negotiated BIP332.
    #[must_use]
    pub fn with_stale_tips(
        mut self,
        stale_tips: Arc<crate::sync::StaleTipRetainer>,
        block_tree: bitcoin_rs_chain::BlockTreeReader,
    ) -> Self {
        self.stale_tips = Some(stale_tips);
        self.block_tree = Some(block_tree);
        self
    }

    #[must_use]
    pub fn with_recent_block(mut self, recent: RecentBlockSlot) -> Self {
        self.recent = recent;
        self
    }

    #[must_use]
    pub fn with_ibd(
        mut self,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
        network: bitcoin_rs_primitives::Network,
    ) -> Self {
        self.ibd = Some((ibd, network));
        self
    }

    #[must_use]
    pub fn in_ibd(&self) -> bool {
        ibd_active(self.ibd.as_ref())
    }

    #[cfg(test)]
    pub fn high_bandwidth_requested_peers(&self) -> Vec<crate::PeerEndpoint> {
        let state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .iter()
            .filter_map(|source| source.endpoint)
            .collect()
    }

    #[cfg(test)]
    pub fn peer_known_block(&self, addr: crate::PeerEndpoint) -> Option<Hash256> {
        let source = self.peers.lease(addr)?.source(Some(addr));
        self.peers
            .announcement_state(source)
            .and_then(|state| state.last_announced_block)
    }

    pub fn on_peer_ready(&self) {
        self.reconcile_high_bandwidth_peers();
    }

    pub fn on_peer_disconnected(&self, source: PeerSource) {
        if let Some(stale_tips) = &self.stale_tips {
            stale_tips.forget_peer(source);
        }
        let mut state = self.state.lock();
        state
            .high_bandwidth_requested_peers
            .retain(|candidate| *candidate != source);
        state.announcement_retry = true;
        state.announcement_epoch += 1;
        self.peers.note_high_bandwidth_selected(source, false);
    }

    fn fill_high_bandwidth_slots(
        &self,
        state: &mut AnnounceState,
        eligible: &[(PeerSource, u64)],
        sent: &mut Vec<(Option<crate::PeerEndpoint>, Message)>,
    ) {
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
                sent.push((source.endpoint, message));
            }
        }
    }

    pub fn reconcile_high_bandwidth_peers(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        let eligible: Vec<_> = self
            .peers
            .sessions()
            .into_iter()
            .filter_map(|session| {
                let source = session.lease.source(session.endpoint);
                let info = session.info.as_ref()?;
                let announcement = self.peers.announcement_state(source)?;
                (!session.lease.is_cancelled()
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
            let send_succeeded = match self.peers.send(source, message.clone()) {
                Ok(()) => true,
                Err(refusal) if refusal.is_saturated() => continue,
                Err(_) => false,
            };
            state
                .high_bandwidth_requested_peers
                .retain(|candidate| *candidate != source);
            self.peers.note_high_bandwidth_selected(source, false);
            if send_succeeded {
                sent.push((source.endpoint, message));
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
                match self.peers.send(demoted, demote.clone()) {
                    Ok(()) => sent.push((demoted.endpoint, demote)),
                    Err(refusal) if refusal.is_saturated() => {
                        state
                            .high_bandwidth_requested_peers
                            .insert(demote_index, demoted);
                        self.peers.note_high_bandwidth_selected(demoted, true);
                        break;
                    }
                    Err(_) => {}
                }

                let promote = Message::SendCmpct(SendCmpct {
                    send_compact: true,
                    version: COMPACT_BLOCK_VERSION,
                });
                if self.peers.send(candidate, promote.clone()).is_ok() {
                    state.high_bandwidth_requested_peers.push(candidate);
                    self.peers.note_high_bandwidth_selected(candidate, true);
                    sent.push((candidate.endpoint, promote));
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

    fn peer_anchor(
        &self,
        session: &crate::PeerSession,
    ) -> (
        PeerSource,
        crate::peer_table::PeerAnnouncementState,
        Option<(Hash256, u32)>,
    ) {
        let source = session.lease.source(session.endpoint);
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

    /// knows the tip's parent, and was not already sent this header. BIP152
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
        if peer_state.compact_high_bandwidth != Some(true)
            || peer_state.compact_version != Some(COMPACT_BLOCK_VERSION)
            || self.config.blocksonly
        {
            return None;
        }
        let knows_prev =
            known_position.is_some_and(|(_, height)| height >= tip_height.saturating_sub(1));
        if !knows_prev {
            return None;
        }
        build().map(|message| PlannedAnnouncement {
            source: session.lease.source(session.endpoint),
            message,
            confirms_tip: true,
        })
    }

    pub fn announce_pow_valid(
        &self,
        block: &Block,
        hash: Hash256,
        height: u32,
    ) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
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
            self.peers.note_announced_block(announcement.source, hash);
            sent.push((announcement.source.endpoint, announcement.message));
        }
        sent
    }

    fn planned_announcements(
        &self,
        tip: CommittedTip,
        live_sessions: &[crate::PeerSession],
    ) -> Vec<PlannedAnnouncement> {
        let tip_hash = Hash256::from(tip.hash);

        let mut planned = Vec::new();

        for session in live_sessions {
            let addr = session.endpoint;
            let (source, peer_state, known_position) = self.peer_anchor(session);

            if known_position.is_some_and(|(_, height)| height >= tip.height) {
                let stale_relay = self
                    .peers
                    .announcement_state(source)
                    .and_then(|s| s.stale_tip_prefers_blocks)
                    .is_some();
                if stale_relay {
                    let block_inv = Inventory::Block(bitcoin::BlockHash::from_byte_array(
                        tip_hash.to_le_bytes(),
                    ));
                    planned.push(PlannedAnnouncement {
                        source,
                        message: Message::Inv(vec![block_inv]),
                        confirms_tip: false,
                    });
                }
                continue;
            }

            if let Some(announcement) =
                self.plan_compact_push(session, peer_state, known_position, tip.height, || {
                    self.chain_query
                        .compact_block_for(tip.height, tip.hash, Some(COMPACT_BLOCK_VERSION))
                        .filter(|msg| matches!(msg, Message::CmpctBlock(_)))
                })
            {
                tracing::debug!(
                    peer = ?addr,
                    tip_height = tip.height,
                    mode = "compact",
                    "block announcement planned"
                );
                planned.push(announcement);
                continue;
            }

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
                                peer = ?addr,
                                tip_height = tip.height,
                                mode = "headers",
                                "block announcement planned"
                            );
                            continue;
                        }
                    }
                }
            }

            let reason = Self::inv_fallback_reason(send_headers, known_position, tip.height);
            let block_inv =
                Inventory::Block(bitcoin::BlockHash::from_byte_array(tip_hash.to_le_bytes()));
            planned.push(PlannedAnnouncement {
                source,
                message: Message::Inv(vec![block_inv]),
                confirms_tip: false,
            });
            tracing::debug!(
                peer = ?addr,
                tip_height = tip.height,
                mode = "inv",
                reason,
                "block announcement planned"
            );
        }

        planned
    }

    pub fn process_tip(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        self.reconcile_high_bandwidth_peers();
        if self.in_ibd() {
            return Vec::new();
        }
        let Some(tip) = self.chain_query.committed_tip() else {
            return Vec::new();
        };
        let tip_hash = Hash256::from(tip.hash);
        let send_epoch = {
            let mut state = self.state.lock();
            if state.last_processed_tip == Some(tip_hash) {
                return Vec::new();
            }
            state.last_processed_tip = Some(tip_hash);
            state.announcement_epoch
        };
        let live_sessions = self.ready_sessions();
        let no_ready_peers = live_sessions.is_empty();
        let planned = self.planned_announcements(tip, &live_sessions);
        let attempted = !planned.is_empty();
        let planned_sources: Vec<_> = planned.iter().map(|plan| plan.source).collect();
        let mut sent = Vec::with_capacity(planned.len());
        let mut refused_by_node_budget = false;
        for announcement in planned {
            match self
                .peers
                .send(announcement.source, announcement.message.clone())
            {
                Ok(()) => {}
                Err(refusal) => {
                    refused_by_node_budget |= refusal.is_saturated();
                    continue;
                }
            }
            if announcement.confirms_tip {
                self.peers
                    .note_announced_block(announcement.source, tip_hash);
            }
            sent.push((announcement.source.endpoint, announcement.message));
        }
        let lost_delivery = planned_sources
            .iter()
            .any(|source| !self.peers.is_current(*source));
        let mut state = self.state.lock();
        let peer_lost_in_window = state.announcement_epoch != send_epoch;
        state.announcement_retry = refused_by_node_budget
            || (attempted && sent.is_empty())
            || no_ready_peers
            || lost_delivery
            || peer_lost_in_window;
        sent
    }

    pub fn process_tip_retry(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        if self.in_ibd() {
            return Vec::new();
        }
        {
            let mut state = self.state.lock();
            if !std::mem::take(&mut state.announcement_retry) {
                return Vec::new();
            }
            state.last_processed_tip = None;
        }
        self.process_tip()
    }

    /// Relays recent stale tips to ready peers that negotiated BIP332.
    pub fn process_stale_tips(&self) -> Vec<(Option<crate::PeerEndpoint>, Message)> {
        if self.in_ibd() {
            return Vec::new();
        }
        let (Some(stale_tips), Some(block_tree)) = (&self.stale_tips, &self.block_tree) else {
            return Vec::new();
        };

        {
            let tree = block_tree.read();
            stale_tips.prune(&tree);
        }

        let live_sessions = self.ready_sessions();
        let mut sent = Vec::new();

        for session in live_sessions {
            let source = session.lease.source(session.endpoint);
            let Some(announcement_state) = self.peers.announcement_state(source) else {
                continue;
            };
            let Some(prefers_blocks) = announcement_state.stale_tip_prefers_blocks else {
                continue;
            };
            if session.demonstrated_tips.is_empty() {
                continue;
            }

            let pending = stale_tips.pending_for(source, |tip_hash| {
                match self
                    .chain_query
                    .stale_tip_announcement(tip_hash, &session.demonstrated_tips)
                {
                    Some(crate::dispatch::StaleTipHeaders::Headers(a)) => {
                        !prefers_blocks || a.have_block
                    }
                    Some(crate::dispatch::StaleTipHeaders::TooMany) | None => false,
                }
            });

            for tip_hash in pending {
                if stale_tips.knows(source, tip_hash) {
                    continue;
                }
                let Some(crate::dispatch::StaleTipHeaders::Headers(announcement)) = self
                    .chain_query
                    .stale_tip_announcement(tip_hash, &session.demonstrated_tips)
                else {
                    continue;
                };

                let message = Message::StaleTip(announcement);
                match self.peers.send(source, message.clone()) {
                    Ok(()) => {
                        stale_tips.mark_known(source, tip_hash);
                        sent.push((session.endpoint, message));
                    }
                    Err(refusal) => {
                        if !refusal.is_saturated() {
                            stale_tips.forget_peer(source);
                        }
                        break;
                    }
                }
            }
        }

        sent
    }

    pub fn drain_queue_and_process(&self, rx: &BlockAnnounceReceiver) -> usize {
        if rx.try_recv() {
            self.process_tip();
            1
        } else {
            0
        }
    }
}

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
                        announcer.process_stale_tips();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        announcer.reconcile_high_bandwidth_peers();
                        announcer.process_tip_retry();
                        announcer.process_stale_tips();
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
        stale_announcement: Mutex<Option<crate::staletip::StaleTipAnnouncement>>,
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
                stale_announcement: Mutex::new(None),
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
        fn stale_tip_announcement(
            &self,
            _tip: Hash256,
            _peer_tips: &[Hash256],
        ) -> Option<crate::dispatch::StaleTipHeaders> {
            self.stale_announcement
                .lock()
                .clone()
                .map(crate::dispatch::StaleTipHeaders::Headers)
        }
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

    fn test_addr(port: u16) -> crate::PeerEndpoint {
        crate::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn test_peer_info(addr: crate::PeerEndpoint, send_headers: bool) -> PeerInfo {
        PeerInfo {
            addr: addr.into(),
            endpoint: Some(addr),
            network: addr.net(),
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
            addr_bind: crate::TransportRemote::new(addr.as_ip().expect("ip test peer")),
            time_offset: 0,
            counters: Arc::new(crate::counters::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        }
    }

    fn setup_peer(
        table: &Arc<PeerTable>,
        announcer: &BlockAnnouncer,
        addr: crate::PeerEndpoint,
        send_headers: bool,
    ) -> (PeerLease, crate::test_support::MessageReceiver) {
        let (tx, rx) = crate::test_support::message_channel();
        let lease = PeerLease::new(tx);
        table.register(addr, lease.clone());
        let info = test_peer_info(addr, send_headers);
        table.publish_info(addr, &lease, info);
        announcer.on_peer_ready();
        while rx.try_recv().is_ok() {}
        (lease, rx)
    }

    fn source(table: &PeerTable, addr: crate::PeerEndpoint) -> PeerSource {
        table
            .lease(addr)
            .expect("live test peer")
            .source(Some(addr))
    }

    fn mark_known(
        table: &PeerTable,
        _announcer: &BlockAnnouncer,
        addr: crate::PeerEndpoint,
        hash: Hash256,
    ) {
        table.note_announced_block(source(table, addr), hash);
    }

    fn note_compact_preference(
        table: &PeerTable,
        addr: crate::PeerEndpoint,
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
    fn announcement_saturated_retried() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let aggregate = Arc::new(crate::connection::SharedOutboundBudget::with_limits(512, 0));
        let addr = test_addr(1020);
        let (tx, rx) = crate::test_support::message_channel();
        let lease = PeerLease::new(tx).with_shared_budget(&aggregate);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, test_peer_info(addr, true));
        announcer.on_peer_ready();
        while rx.try_recv().is_ok() {}
        mark_known(&table, &announcer, addr, chain.hash_at(0));
        let hold = crate::test_support::hog(&aggregate, 512);

        assert!(announcer.process_tip().is_empty(), "nothing was queued");
        assert!(!lease.is_cancelled(), "a full aggregate is not a dead peer");
        assert_eq!(
            announcer.peer_known_block(addr),
            Some(chain.hash_at(0)),
            "a refused announcement is not recorded as delivered"
        );
        assert!(
            announcer.process_tip().is_empty(),
            "a repeated tip event stays a no-op"
        );
        assert!(rx.is_empty());

        drop(hold);
        let sent = announcer.process_tip_retry();
        assert_eq!(sent.len(), 1, "the retry announces the tip once");
        assert!(matches!(sent[0].1, Message::Headers(_)));
        assert!(matches!(rx.try_recv(), Ok(Message::Headers(_))));
        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(1)));
        assert!(
            announcer.process_tip_retry().is_empty(),
            "the retry is spent once it ran"
        );
    }

    #[test]
    fn demotion_saturated_keeps_the_selection_and_retries() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let aggregate = Arc::new(crate::connection::SharedOutboundBudget::with_limits(256, 0));
        let addr = test_addr(1021);
        let (tx, rx) = crate::test_support::message_channel();
        let lease = PeerLease::new(tx).with_shared_budget(&aggregate);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, test_peer_info(addr, true));
        note_compact_preference(&table, addr, false, 2);
        assert_eq!(announcer.reconcile_high_bandwidth_peers().len(), 1);
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![addr]);
        assert!(matches!(rx.try_recv(), Ok(Message::SendCmpct(_))));

        let mut info = test_peer_info(addr, true);
        info.compact_block_relay = false;
        table.publish_info(addr, &lease, info);
        let hold = crate::test_support::hog(&aggregate, 256);
        assert_eq!(announcer.reconcile_high_bandwidth_peers(), Vec::new());
        assert_eq!(
            announcer.high_bandwidth_requested_peers(),
            vec![addr],
            "the refused demotion did not happen"
        );
        assert!(!lease.is_cancelled());
        assert!(rx.is_empty());

        drop(hold);
        let sent = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(sent.len(), 1, "the next reconcile retries the demotion");
        assert!(matches!(
            &sent[0].1,
            Message::SendCmpct(SendCmpct {
                send_compact: false,
                ..
            })
        ));
        assert_eq!(announcer.high_bandwidth_requested_peers(), Vec::new());
    }

    #[test]
    fn rotation_saturated_restores_full_selection_in_place_and_retries() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let aggregate = Arc::new(crate::connection::SharedOutboundBudget::with_limits(256, 0));
        let a1 = test_addr(1061);
        let a2 = test_addr(1062);
        let a3 = test_addr(1063);
        let a4 = test_addr(1064);
        let mut leases = Vec::new();
        let mut rxs = Vec::new();
        for addr in [a1, a2, a3] {
            let (tx, rx) = crate::test_support::message_channel();
            let lease = PeerLease::new(tx).with_shared_budget(&aggregate);
            table.register(addr, lease.clone());
            table.publish_info(addr, &lease, test_peer_info(addr, true));
            note_compact_preference(&table, addr, false, 2);
            announcer.reconcile_high_bandwidth_peers();
            leases.push(lease);
            rxs.push(rx);
        }
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![a1, a2, a3]);
        for rx in &rxs {
            while rx.try_recv().is_ok() {}
        }
        let (tx4, rx4) = crate::test_support::message_channel();
        let lease4 = PeerLease::new(tx4).with_shared_budget(&aggregate);
        table.register(a4, lease4.clone());
        table.publish_info(a4, &lease4, test_peer_info(a4, true));
        note_compact_preference(&table, a4, false, 2);
        assert_eq!(announcer.reconcile_high_bandwidth_peers(), Vec::new());
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![a1, a2, a3]);
        assert!(table.note_useful_block(leases[1].source(Some(a2))));
        assert!(table.note_useful_block(leases[2].source(Some(a3))));
        assert!(table.note_useful_block(lease4.source(Some(a4))));
        let hold = crate::test_support::hog(&aggregate, 256);
        assert_eq!(announcer.reconcile_high_bandwidth_peers(), Vec::new());
        assert_eq!(
            announcer.high_bandwidth_requested_peers(),
            vec![a1, a2, a3],
            "the refused rotation restores the full prior selection in order"
        );
        assert!(
            table
                .announcement_state(source(&table, a1))
                .is_some_and(|state| state.selected_high_bandwidth),
            "the displaced entry stays selected through the refusal"
        );
        assert!(!leases[0].is_cancelled());
        assert!(rxs[0].try_recv().is_err(), "no demotion was queued");
        assert!(rx4.try_recv().is_err(), "no promotion was queued");
        drop(hold);
        let sent = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(
            sent.len(),
            2,
            "the next reconcile retries demotion plus promotion"
        );
        assert_eq!(sent[0].0, Some(a1));
        assert!(matches!(
            sent[0].1,
            Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            })
        ));
        assert_eq!(sent[1].0, Some(a4));
        assert!(matches!(
            sent[1].1,
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        ));
        assert_eq!(
            rxs[0].try_recv().expect("the retried demotion is queued"),
            Message::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            })
        );
        assert_eq!(
            rx4.try_recv().expect("the retried promotion is queued"),
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![a2, a3, a4]);
    }

    struct WorkerStop {
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        queue: Option<BlockAnnounceQueue>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for WorkerStop {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Release);
            self.queue.take();
            if let Some(handle) = self.handle.take() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !handle.is_finished() && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                if handle.is_finished() {
                    let _ = handle.join();
                }
            }
        }
    }

    #[test]
    fn worker_timeout_retries_saturated_announcement_without_new_wake() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = Arc::new(BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        ));
        let aggregate = Arc::new(crate::connection::SharedOutboundBudget::with_limits(512, 0));
        let addr = test_addr(1071);
        let (tx, rx) = crate::test_support::message_channel();
        let lease = PeerLease::new(tx).with_shared_budget(&aggregate);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, test_peer_info(addr, true));
        announcer.on_peer_ready();
        while rx.try_recv().is_ok() {}
        mark_known(&table, announcer.as_ref(), addr, chain.hash_at(0));
        let hold = crate::test_support::hog(&aggregate, 512);
        let (queue, worker_rx) = BlockAnnounceQueue::new();
        assert!(queue.wake(), "the wake enqueued the tip");
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker =
            spawn_block_announce_worker(Arc::clone(&announcer), worker_rx, Arc::clone(&shutdown))
                .expect("the announce worker spawns");
        let _stop = WorkerStop {
            shutdown: Arc::clone(&shutdown),
            queue: Some(queue),
            handle: Some(worker),
        };
        let armed_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if announcer.state.lock().announcement_retry {
                break;
            }
            assert!(
                std::time::Instant::now() < armed_deadline,
                "the worker took the saturated wake"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!lease.is_cancelled(), "a full aggregate is not a dead peer");
        assert!(rx.try_recv().is_err(), "nothing was queued while saturated");
        assert_eq!(
            announcer.peer_known_block(addr),
            Some(chain.hash_at(0)),
            "a refused announcement is not recorded as delivered"
        );
        drop(hold);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let received = loop {
            if let Ok(message) = rx.try_recv() {
                break message;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the worker timeout retried the refused tip"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(
            matches!(received, Message::Headers(_)),
            "the retried tip announces once, got {received:?}"
        );
        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(1)));
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
        assert_eq!(sent[0].0, Some(addr));
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
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1221);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);

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

        announcer.on_peer_disconnected(lease.source(Some(addr)));
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
        let sessions = announcer.ready_sessions();
        assert_eq!(announcer.planned_announcements(tip, &sessions).len(), 1);
        assert_eq!(announcer.planned_announcements(tip, &sessions).len(), 1);

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
    fn failed_sends_retry_latest_committed_tip_after_reconnect() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        chain.set_committed_height(1);
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
                .announcement_state(lease.source(Some(addr)))
                .and_then(|state| state.last_announced_block),
            Some(chain.hash_at(0))
        );

        assert!(lease.is_cancelled());
        assert_eq!(announcer.process_tip_retry(), Vec::new());
        assert_eq!(announcer.process_tip_retry(), Vec::new());
        chain.set_committed_height(2);
        let (_replacement, replacement_rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));
        let sent = announcer.process_tip_retry();
        assert_eq!(sent.len(), 1);
        let Message::Headers(headers) = replacement_rx.try_recv().unwrap() else {
            panic!("the replacement must receive the current committed headers");
        };
        assert_eq!(
            headers.last().unwrap().compute_hash(),
            chain.block_hash_at(2)
        );
        assert_eq!(announcer.peer_known_block(addr), Some(chain.hash_at(2)));
        assert_eq!(announcer.process_tip_retry(), Vec::new());
    }

    #[test]
    fn a_delivered_tip_clears_the_stale_retry_intent() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        chain.set_committed_height(1);
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1011);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));
        drop(rx);

        assert_eq!(announcer.process_tip(), Vec::new());
        assert!(
            announcer.state.lock().announcement_retry,
            "an all-failed send arms the retry"
        );

        let (_replacement, replacement_rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));
        chain.set_committed_height(2);
        let sent = announcer.process_tip();
        assert_eq!(sent.len(), 1);
        assert!(replacement_rx.try_recv().is_ok());

        assert!(
            !announcer.state.lock().announcement_retry,
            "a delivered tip discharges the retry intent"
        );
        assert_eq!(announcer.process_tip_retry(), Vec::new());
    }

    #[test]
    fn a_disconnect_inside_the_send_window_keeps_the_retry_armed() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        chain.set_committed_height(1);
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );
        let addr = test_addr(1012);
        let (old_lease, _rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        let sent = announcer.process_tip();
        assert_eq!(sent.len(), 1);
        let old_source = old_lease.source(Some(addr));
        table.remove_current(addr, &old_lease);
        announcer.on_peer_disconnected(old_source);
        let (_replacement, replacement_rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        assert!(
            announcer.state.lock().announcement_retry,
            "a disconnect after enqueue must re-arm the retry"
        );
        let resent = announcer.process_tip_retry();
        assert_eq!(resent.len(), 1);
        assert!(
            replacement_rx.try_recv().is_ok(),
            "the replacement receives the committed tip on retry"
        );
    }

    #[test]
    fn worker_retries_tip_with_no_ready_peers_until_connection_arrives() {
        let chain = Arc::new(MockAnnounceChain::new(2));
        let table = Arc::new(PeerTable::new());
        let announcer = Arc::new(BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        ));
        assert_eq!(announcer.process_tip(), Vec::new());
        assert_eq!(announcer.process_tip_retry(), Vec::new());
        let (_lease, rx) = setup_peer(&table, &announcer, test_addr(1014), false);
        let (queue, worker_rx) = BlockAnnounceQueue::new();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker =
            spawn_block_announce_worker(Arc::clone(&announcer), worker_rx, Arc::clone(&shutdown))
                .expect("the announce worker spawns");
        let _stop = WorkerStop {
            shutdown,
            queue: Some(queue),
            handle: Some(worker),
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let message = loop {
            if let Ok(message) = rx.try_recv() {
                break message;
            }
            assert!(std::time::Instant::now() < deadline, "tip was not retried");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            message,
            Message::Inv(vec![Inventory::Block(bitcoin::BlockHash::from_byte_array(
                chain.hash_at(1).to_le_bytes()
            ))])
        );
        assert_eq!(announcer.process_tip_retry(), Vec::new());
        assert!(rx.try_recv().is_err());
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
        let (tx, rx) = crate::test_support::message_channel();
        let lease = PeerLease::new(tx);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, test_peer_info(addr, true));
        note_compact_preference(&table, addr, false, 2);

        let msgs = announcer.reconcile_high_bandwidth_peers();

        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, Some(addr));
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
    fn high_bandwidth_selection_ignores_relay_role_but_requires_compact_v2() {
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
        let (block_only_tx, block_only_rx) = crate::test_support::message_channel();
        let block_only = PeerLease::new_block_relay(block_only_tx);
        table.register(block_only_addr, block_only.clone());
        table.publish_info(
            block_only_addr,
            &block_only,
            test_peer_info(block_only_addr, true),
        );
        note_compact_preference(&table, block_only_addr, false, 2);

        let msgs = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, Some(block_only_addr));
        assert_eq!(
            msgs[0].1,
            Message::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            })
        );
        assert_eq!(block_only_rx.try_recv(), Ok(msgs[0].1.clone()));
        assert_eq!(
            announcer.high_bandwidth_requested_peers(),
            vec![block_only_addr]
        );
    }

    #[test]
    fn block_relay_only_peer_with_high_bandwidth_receives_compact_push() {
        let chain = Arc::new(MockAnnounceChain::new(3));
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let addr = test_addr(1042);
        let (tx, _rx) = crate::test_support::message_channel();
        let lease = PeerLease::new_block_relay(tx);
        table.register(addr, lease.clone());
        table.publish_info(addr, &lease, test_peer_info(addr, true));
        note_compact_preference(&table, addr, true, 2);
        mark_known(&table, &announcer, addr, chain.hash_at(1));

        let sent = announcer.process_tip();
        let pushed = sent.iter().find(|(a, _)| *a == Some(addr));
        let Some((_, message)) = pushed else {
            panic!("a block-relay-only high-bandwidth peer must receive an announcement");
        };
        assert!(
            matches!(message, Message::CmpctBlock(_)),
            "expected CmpctBlock for the block-relay-only peer, got {message:?}"
        );
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
        let (tx, rx) = crate::test_support::message_channel();
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
        let old_source = old.source(Some(addr));

        let (replacement_tx, _replacement_rx) = crate::test_support::message_channel();
        let replacement = PeerLease::new(replacement_tx);
        table.register(addr, replacement.clone());
        assert!(table.publish_info(addr, &replacement, test_peer_info(addr, true),));
        let replacement_source = replacement.source(Some(addr));
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
        let source = lease.source(Some(addr));
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

        let (tx4, rx4) = crate::test_support::message_channel();
        let lease4 = PeerLease::new(tx4);
        table.register(a4, lease4.clone());
        table.publish_info(a4, &lease4, test_peer_info(a4, true));
        note_compact_preference(&table, a4, false, 2);

        let connected = announcer.reconcile_high_bandwidth_peers();
        assert_eq!(connected, Vec::new());
        assert_eq!(announcer.high_bandwidth_requested_peers(), vec![a1, a2, a3]);

        table.note_useful_block(lease4.source(Some(a4)));
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

        let addr1 = test_addr(1031);
        let (_lease1, _rx1) = setup_peer(&table, &announcer, addr1, true);
        note_compact_preference(&table, addr1, true, 2);
        mark_known(&table, &announcer, addr1, chain.hash_at(1));

        let addr2 = test_addr(1032);
        let (_lease2, _rx2) = setup_peer(&table, &announcer, addr2, true);
        note_compact_preference(&table, addr2, true, 2);
        mark_known(&table, &announcer, addr2, chain.hash_at(0));

        let addr3 = test_addr(1033);
        let (_lease3, _rx3) = setup_peer(&table, &announcer, addr3, true);
        note_compact_preference(&table, addr3, false, 2);
        mark_known(&table, &announcer, addr3, chain.hash_at(1));

        let sent = announcer.process_tip();

        assert_eq!(sent.len(), 3);
        let sent1 = sent.iter().find(|(a, _)| *a == Some(addr1)).unwrap();
        assert!(
            matches!(sent1.1, Message::CmpctBlock(_)),
            "peer with high-bandwidth request and prev_hash should receive CmpctBlock"
        );

        let sent2 = sent.iter().find(|(a, _)| *a == Some(addr2)).unwrap();
        assert!(
            matches!(sent2.1, Message::Headers(_)),
            "peer without prev_hash should fall back to Headers"
        );

        let sent3 = sent.iter().find(|(a, _)| *a == Some(addr3)).unwrap();
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
    fn a_disconnect_during_ibd_keeps_the_retry_armed_until_delivery() {
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let ibd = Arc::new(InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        ));
        let chain = Arc::new(MockAnnounceChain::new(2));
        chain.set_committed_height(1);
        let table = Arc::new(PeerTable::new());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        )
        .with_ibd(Arc::clone(&ibd), Network::Regtest);

        let addr = test_addr(1044);
        let (old_lease, _rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));
        let old_source = old_lease.source(Some(addr));
        table.remove_current(addr, &old_lease);
        announcer.on_peer_disconnected(old_source);
        let (_replacement, replacement_rx) = setup_peer(&table, &announcer, addr, true);
        mark_known(&table, &announcer, addr, chain.hash_at(0));

        assert!(announcer.in_ibd());
        assert_eq!(
            announcer.process_tip_retry(),
            Vec::new(),
            "IBD suppresses announcements"
        );
        assert!(
            announcer.state.lock().announcement_retry,
            "the IBD poll must not consume the armed retry"
        );

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
        assert!(!announcer.in_ibd());

        let sent = announcer.process_tip_retry();
        assert_eq!(sent.len(), 1);
        assert!(
            replacement_rx.try_recv().is_ok(),
            "the replacement receives the committed tip after IBD exits"
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
            .find(|(addr, _)| *addr == Some(addr_b))
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

        let addr = test_addr(1301);
        let (_lease, rx) = setup_peer(&table, &announcer, addr, false);
        note_compact_preference(&table, addr, true, 2);
        mark_known(&table, &announcer, addr, chain.hash_at(1));
        let quiet = test_addr(1302);
        let (_quiet_lease, quiet_rx) = setup_peer(&table, &announcer, quiet, false);
        while rx.try_recv().is_ok() {}

        let block = tip_child_block(chain.block_hash_at(1), 1200);
        let hash = Hash256::from(block.block_hash());
        let sent = announcer.announce_pow_valid(&block, hash, 2);

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, Some(addr));
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
                .any(|(peer, message)| *peer == Some(addr)
                    && matches!(message, Message::CmpctBlock(_))),
            "post-commit must not resend cmpctblock to the early peer: {sent:?}"
        );
        while let Ok(message) = rx.try_recv() {
            assert!(
                !matches!(message, Message::CmpctBlock(_)),
                "post-commit must not resend cmpctblock to the early peer"
            );
        }
    }

    #[test]
    fn stale_tip_relayed_to_bip332_peer_and_suppressed_on_repeat() {
        use crate::staletip::{CompressedHeader, StaleTipAnnouncement};
        use bitcoin_rs_chain::regtest_fixture::mined_regtest_header;
        let table = Arc::new(PeerTable::new());
        let chain = Arc::new(MockAnnounceChain::new(5));
        let addr = test_addr(1401);

        let mut tree = BlockTree::new();
        let genesis = Network::Regtest.genesis_block().header;
        let g_id = tree
            .insert_node(None, genesis, NodeStatus::HeaderValid)
            .unwrap();
        let h1 = mined_regtest_header(genesis.compute_hash(), 1).unwrap();
        let fork_node = tree
            .insert_node(Some(g_id), h1, NodeStatus::HeaderValid)
            .unwrap();
        let fork_hash = Hash256::from(h1.compute_hash());

        let dummy_announcement = StaleTipAnnouncement {
            fork_point: fork_hash,
            headers: vec![CompressedHeader {
                version: 1,
                merkle_root: Hash256::default(),
                time: 12345,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 42,
            }],
            have_block: true,
        };
        *chain.stale_announcement.lock() = Some(dummy_announcement);

        let h2 = mined_regtest_header(BlockHash::from(fork_hash), 2).unwrap();
        let old_active_id = tree
            .insert_node(Some(fork_node), h2, NodeStatus::HeaderValid)
            .unwrap();
        let demoted_hash = Hash256::from(h2.compute_hash());
        assert_eq!(
            tree.tip().map(|t| t.hash),
            Some(demoted_hash),
            "h2 starts as active tip"
        );

        let b1 = mined_regtest_header(BlockHash::from(fork_hash), 101).unwrap();
        let b1_id = tree
            .insert_node(Some(fork_node), b1, NodeStatus::HeaderValid)
            .unwrap();
        let b2 = mined_regtest_header(b1.compute_hash(), 102).unwrap();
        let _b2_id = tree
            .insert_node(Some(b1_id), b2, NodeStatus::HeaderValid)
            .unwrap();

        assert_eq!(
            tree.node(old_active_id).unwrap().status,
            NodeStatus::Stale,
            "h2 must be demoted to Stale"
        );
        assert_eq!(
            tree.tip().map(|t| t.hash),
            Some(Hash256::from(b2.compute_hash())),
            "heavier branch became active"
        );

        let reader = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let retainer = Arc::new(crate::sync::StaleTipRetainer::default());
        assert!(
            retainer.learn(&reader.read(), demoted_hash, None),
            "demoted tip must be learned"
        );

        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        )
        .with_stale_tips(Arc::clone(&retainer), reader);

        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        let src = source(&table, addr);
        table.note_stale_tip_relay(src, false);
        table.note_announced_tip(src, fork_hash, Some(1));

        let sent = announcer.process_stale_tips();
        assert_eq!(sent.len(), 1);
        assert!(matches!(sent[0].1, Message::StaleTip(_)));
        assert_eq!(sent[0].0, Some(addr));

        let msg = rx.try_recv().expect("message delivered");
        assert!(matches!(msg, Message::StaleTip(_)));

        let sent_again = announcer.process_stale_tips();
        assert!(sent_again.is_empty(), "repeat stale tip must be suppressed");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn prefers_blocks_peer_gets_same_retained_tip_once_body_available() {
        use crate::staletip::{CompressedHeader, StaleTipAnnouncement};
        use bitcoin_rs_chain::regtest_fixture::mined_regtest_header;
        let table = Arc::new(PeerTable::new());
        let chain = Arc::new(MockAnnounceChain::new(5));
        let addr = test_addr(1403);

        let mut tree = BlockTree::new();
        let genesis = Network::Regtest.genesis_block().header;
        let g_id = tree
            .insert_node(None, genesis, NodeStatus::HeaderValid)
            .expect("genesis");
        let h1 = mined_regtest_header(genesis.compute_hash(), 1).expect("h1");
        let fork_node = tree
            .insert_node(Some(g_id), h1, NodeStatus::HeaderValid)
            .expect("fork");
        let fork_hash = Hash256::from(h1.compute_hash());

        let h2 = mined_regtest_header(BlockHash::from(fork_hash), 2).expect("h2");
        let old_active_id = tree
            .insert_node(Some(fork_node), h2, NodeStatus::HeaderValid)
            .expect("demoted");
        let demoted_hash = Hash256::from(h2.compute_hash());

        let b1 = mined_regtest_header(BlockHash::from(fork_hash), 101).expect("b1");
        let b1_id = tree
            .insert_node(Some(fork_node), b1, NodeStatus::HeaderValid)
            .expect("b1 node");
        let b2 = mined_regtest_header(b1.compute_hash(), 102).expect("b2");
        let _b2_id = tree
            .insert_node(Some(b1_id), b2, NodeStatus::HeaderValid)
            .expect("b2 node");
        assert_eq!(
            tree.node(old_active_id).expect("demoted node").status,
            NodeStatus::Stale,
            "h2 must be demoted to Stale"
        );

        let reader = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let retainer = Arc::new(crate::sync::StaleTipRetainer::default());
        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        )
        .with_stale_tips(Arc::clone(&retainer), reader.clone());

        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        let src = source(&table, addr);
        table.note_stale_tip_relay(src, true);
        table.note_announced_tip(src, fork_hash, Some(1));

        let opened = announcer.process_stale_tips();
        assert!(opened.is_empty(), "empty retainer opens relay with no send");

        assert!(
            retainer.learn(&reader.read(), demoted_hash, None),
            "demoted tip must be learned"
        );

        *chain.stale_announcement.lock() = Some(StaleTipAnnouncement {
            fork_point: fork_hash,
            headers: vec![CompressedHeader {
                version: 1,
                merkle_root: Hash256::default(),
                time: 12345,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 42,
            }],
            have_block: false,
        });
        let absent = announcer.process_stale_tips();
        assert!(
            absent.is_empty(),
            "prefers-blocks peer must not get body-absent tip"
        );
        assert!(rx.try_recv().is_err());
        assert!(
            !retainer.knows(src, demoted_hash),
            "refused tip must stay unoffered, not marked known"
        );

        *chain.stale_announcement.lock() = Some(StaleTipAnnouncement {
            fork_point: fork_hash,
            headers: vec![CompressedHeader {
                version: 1,
                merkle_root: Hash256::default(),
                time: 12345,
                bits: CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 42,
            }],
            have_block: true,
        });
        let sent = announcer.process_stale_tips();
        assert_eq!(sent.len(), 1, "same hash must relay once body is available");
        assert!(matches!(sent[0].1, Message::StaleTip(_)));
        assert_eq!(sent[0].0, Some(addr));
        let msg = rx.try_recv().expect("staletip delivered");
        assert!(matches!(msg, Message::StaleTip(_)));

        let again = announcer.process_stale_tips();
        assert!(again.is_empty(), "repeat same-hash tip must be suppressed");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn origin_peer_receives_inv_fallback_even_when_known_position_meets_tip() {
        let table = Arc::new(PeerTable::new());
        let chain = Arc::new(MockAnnounceChain::new(5));
        let addr = test_addr(1402);
        let tip_hash = chain.hash_at(4);

        let announcer = BlockAnnouncer::new(
            Arc::clone(&table),
            Arc::clone(&chain) as Arc<dyn ChainQuery>,
            BlockAnnounceConfig::default(),
        );

        let (_lease, rx) = setup_peer(&table, &announcer, addr, true);
        let src = source(&table, addr);

        table.note_stale_tip_relay(src, false);
        table.note_announced_tip(src, tip_hash, Some(4));

        let sent = announcer.process_tip();
        assert_eq!(sent.len(), 1);
        assert!(
            matches!(sent[0].1, Message::Inv(_)),
            "origin peer must get inv fallback"
        );
        let msg = rx.try_recv().expect("inv received");
        assert!(matches!(msg, Message::Inv(_)));
    }
}
