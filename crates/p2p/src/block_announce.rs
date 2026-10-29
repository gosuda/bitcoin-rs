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
mod tests;
