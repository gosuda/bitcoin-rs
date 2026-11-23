use super::GetdataRequestOutcome;
use super::GetheadersOutcome;
use super::HEADER_REQUEST_TIMEOUT;
use super::HeaderRequest;
use super::HeaderRequestKind;
use super::HeaderRequestState;
use super::LOCATOR_MAX_ENTRIES;
use super::chain::HeaderAdmission;
use super::frontier::ChainFrontier;
use super::frontier::SyncFrontier;
use super::headers_presync::HeaderAnchor;
use super::headers_presync::HeaderSyncError;
use super::headers_presync::HeadersSyncPhase;
use super::headers_presync::HeadersSyncState;
use super::peers::is_peer_fault;
use super::peers::outranks;
use super::peers::shared_active_height;
use super::peers::sync_peer_candidate;
use super::requests::COMPACT_RELAY_NEAR_TIP_BLOCKS;
use super::{BlockSync, HeaderSyncMode, SchedulerState};
use crate::p2p::download_window::SyncPeer;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_chain::chain::{
    BlockTree, ChainError, HeaderCandidate, HeaderCandidateError, HeaderCandidatePhase,
    HeaderContextError, NodeId, NodeStatus, validate_pow,
};
use bitcoin_rs_chain::{HeaderAdmissionError, HeaderResourceError};
use bitcoin_rs_consensus::header_rules::ChainWork;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::Header;
use bitcoin_rs_p2p::peer_info::PeerInfo;
use bitcoin_rs_p2p::{InboundHeaders, Message, OutboundRefusal, PeerSource};
use std::time::Instant;
use std::vec::Vec;

const MAX_UNRESOLVED_DEMONSTRATED_TIPS: usize = 8;

const NEAR_TIP_WORK_BLOCKS: u64 = 144;

pub(super) const MAX_HEADER_BATCHES_PER_TICK: usize = 32;
/// Stop between whole batches, never in a download-twice response page.
/// A final protocol-bounded batch can exceed this by at most 1,999 headers.
pub(super) const MAX_HEADERS_PER_TICK: usize = 2 * bitcoin_rs_p2p::wire::MAX_HEADERS_MESSAGE_COUNT;

struct PresyncOutcome {
    failure: Option<HeaderSyncError>,
    request_more: bool,
    ready_headers: Vec<Header>,
    locator: Vec<Hash256>,
    height: u32,
    finished: bool,
}

impl BlockSync {
    pub(crate) fn note_header_response_received(&self, source: PeerSource) {
        let now = Instant::now();
        self.peer_table.with_current(source, || {
            let mut scheduler = self.scheduler.lock();
            if let Some(request) = scheduler
                .headers_sync
                .get_mut(&source)
                .and_then(|owned| owned.request.as_mut())
                && request.state == HeaderRequestState::AwaitingResponse
                && now >= request.requested_at
                && request.is_live(now)
            {
                request.state = HeaderRequestState::ResponseQueued;
            }
        });
    }

    pub(super) fn drain_inbound_headers(&self) {
        let mut total_headers = 0_usize;
        let mut credit_refresh_needed = false;
        let mut direct_fetch: Vec<(PeerSource, Hash256)> = Vec::new();
        let mut replay_remaining = MAX_HEADERS_PER_TICK;
        if let Err(error) = self.chain.maintain_header_retention() {
            tracing::debug!(%error, "block sync: header retention maintenance deferred");
        }
        self.drain_winning_headers(
            &mut replay_remaining,
            &mut direct_fetch,
            &mut credit_refresh_needed,
        );
        for _ in 0..MAX_HEADER_BATCHES_PER_TICK {
            if total_headers >= MAX_HEADERS_PER_TICK {
                break;
            }
            let Ok(InboundHeaders {
                headers,
                source,
                wire_response,
            }) = self.inbound_headers_rx.try_recv()
            else {
                break;
            };
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);
            if source.is_some_and(|source| !self.peer_table.is_current(source)) {
                continue;
            }

            self.consume_header_request(source, wire_response, headers.is_empty());

            let feeds_live_sync = wire_response
                && source.is_some_and(|source| {
                    self.scheduler
                        .lock()
                        .headers_sync
                        .get(&source)
                        .is_some_and(|owned| owned.mode.is_some())
                });

            if !feeds_live_sync
                && let Some((tip_hash, active_height)) = self.known_batch_outcome(&headers)
            {
                self.record_admitted_tips(None, Some(tip_hash), source);
                if let Some(source) = source {
                    self.peer_table
                        .note_announced_tip(source, tip_hash, active_height);
                    credit_refresh_needed = true;
                    if wire_response && !self.owns_body_fetch(source, tip_hash) {
                        direct_fetch.push((source, tip_hash));
                    }
                }
                continue;
            }

            let pre_tip = self.chain.chain_tip().map(|tip| tip.hash);
            let Some(admission) =
                self.route_headers_batch(&headers, source, wire_response, batch_len)
            else {
                continue;
            };
            if matches!(&admission, HeaderAdmission::Rejected(_)) {
                let demoted = bitcoin_rs_chain::chain::header_sync::demoted_tip_after_rejection(
                    &self.chain.block_tree(),
                    pre_tip,
                );
                if let Some(demoted) = demoted {
                    self.record_demoted_tip(demoted);
                }
            }
            self.handle_header_admission(
                admission,
                source,
                wire_response,
                batch_len,
                &mut direct_fetch,
                &mut credit_refresh_needed,
            );
        }
        self.drain_winning_headers(
            &mut replay_remaining,
            &mut direct_fetch,
            &mut credit_refresh_needed,
        );
        self.resume_owned_header_requests();
        self.post_headers_drain(credit_refresh_needed, direct_fetch, total_headers);
    }

    fn handle_header_admission(
        &self,
        admission: HeaderAdmission,
        source: Option<PeerSource>,
        wire_response: bool,
        batch_len: usize,
        direct_fetch: &mut Vec<(PeerSource, Hash256)>,
        credit_refresh_needed: &mut bool,
    ) {
        match admission {
            HeaderAdmission::Accepted {
                accepted,
                announced_tip,
                active_height,
                demoted_tip,
            } => {
                self.record_admitted_tips(demoted_tip, announced_tip, source);
                if let (Some(tip_hash), Some(source)) = (announced_tip, source) {
                    self.peer_table
                        .note_announced_tip(source, tip_hash, active_height);
                    if wire_response && !self.owns_body_fetch(source, tip_hash) {
                        direct_fetch.push((source, tip_hash));
                    }
                }
                *credit_refresh_needed = true;
                tracing::debug!(
                    accepted,
                    received = batch_len,
                    "block sync: accepted inbound headers batch",
                );
            }
            HeaderAdmission::Rejected(error) if is_peer_fault(&error) => {
                let mut blamed_peer = None;
                if let Some(source) = source {
                    let disconnected = self.peer_table.disconnect_source(source);
                    self.scheduler.lock().clear_headers_sync_for(source);
                    if disconnected {
                        self.scheduler
                            .lock()
                            .window
                            .mark_peer_unresponsive(source, Instant::now());
                        blamed_peer = Some(source.endpoint);
                    }
                }
                if let Some(peer_addr) = blamed_peer {
                    tracing::warn!(
                        peer_addr = ?peer_addr,
                        received = batch_len,
                        %error,
                        "block sync: peer served invalid headers; disconnecting",
                    );
                } else {
                    tracing::warn!(
                        received = batch_len,
                        %error,
                        "block sync: rejected source-less or stale headers batch",
                    );
                }
            }
            HeaderAdmission::Rejected(error) => {
                if matches!(
                    error,
                    ChainError::MissingParent { .. } | ChainError::NoCommonAncestor { .. }
                ) {
                    self.request_headers_from(source);
                }
                tracing::warn!(
                    received = batch_len,
                    %error,
                    "block sync: rejected inbound headers batch",
                );
            }
            HeaderAdmission::Refused(error) => {
                self.request_ancestry_after_refusal(source, &error);
            }
        }
    }

    fn post_headers_drain(
        &self,
        credit_refresh_needed: bool,
        direct_fetch: Vec<(PeerSource, Hash256)>,
        total_headers: usize,
    ) {
        if credit_refresh_needed {
            self.refresh_active_peer_credit();
        }
        self.resolve_owned_body_fetches();
        if !direct_fetch.is_empty() {
            let chain = self.observe_chain_frontier();
            for (source, announced_tip) in direct_fetch {
                self.direct_fetch_announced_tip(source, announced_tip, &chain);
            }
        }
        self.drain_block_announcements();
        if total_headers > 0 {
            tracing::debug!(total_headers, "block sync: drained inbound headers");
        }
    }

    fn drain_block_announcements(&self) {
        let pending = std::mem::take(&mut *self.block_announcements.lock());
        if pending.is_empty() {
            return;
        }
        let mut credit_refresh_needed = false;
        let mut deferred: Vec<(PeerSource, Hash256)> = Vec::new();
        for (source, hash) in pending {
            if !self.peer_table.is_current(source) {
                continue;
            }
            let (known, active_height) = {
                let tree = self.chain.block_tree();
                let height = tree
                    .tip()
                    .and_then(|tip| shared_active_height(&tree, tip.tip_id, hash))
                    .and_then(|height| i32::try_from(height).ok());
                (tree.lookup(hash).is_some(), height)
            };
            if !known {
                if self.scheduler.lock().header_request().is_some() {
                    deferred.push((source, hash));
                } else {
                    self.request_headers_from(Some(source));
                }
                continue;
            }
            self.peer_table
                .note_announced_tip(source, hash, active_height);
            credit_refresh_needed = true;
        }
        if !deferred.is_empty() {
            let mut announcements = self.block_announcements.lock();
            for (source, hash) in deferred {
                announcements.insert(source, hash);
            }
        }
        if credit_refresh_needed {
            self.refresh_active_peer_credit();
        }
    }

    fn direct_fetch_announced_tip(
        &self,
        source: PeerSource,
        announced_tip: Hash256,
        chain: &ChainFrontier,
    ) -> GetdataRequestOutcome {
        let (Some(chain_tip), Some(required)) = (chain.chain_tip.as_ref(), chain.next_required)
        else {
            return GetdataRequestOutcome::default();
        };
        if chain.closed_for_recovery {
            return GetdataRequestOutcome::default();
        }
        let Some(height) = self.tip_height_on_active_branch(chain_tip.tip_id, announced_tip) else {
            return GetdataRequestOutcome::default();
        };
        if chain_tip.height.saturating_sub(required.height) >= COMPACT_RELAY_NEAR_TIP_BLOCKS
            || height < required.height
        {
            return GetdataRequestOutcome::default();
        }
        self.send_getdata_for_pending_blocks(source, height, chain)
    }

    fn tip_height_on_active_branch(&self, tip: NodeId, hash: Hash256) -> Option<u32> {
        let tree = self.chain.block_tree();
        let node_id = tree.lookup(hash)?;
        let height = tree.node(node_id).ok()?.height;
        tree.node_at_height_from(tip, height)
            .is_some_and(|on_branch| on_branch == node_id)
            .then_some(height)
    }

    fn request_ancestry_after_refusal(
        &self,
        source: Option<PeerSource>,
        error: &bitcoin_rs_chain::chain::HeaderRefusal,
    ) {
        if let (Some(source), Some(anchor)) = (source, error.candidate_anchor()) {
            let already_verifying = self
                .scheduler
                .lock()
                .headers_sync
                .get(&source)
                .is_some_and(|owned| matches!(&owned.mode, Some(HeaderSyncMode::Winning(_))));
            if already_verifying {
                self.resume_owned_header_requests();
                return;
            }
            self.clear_header_request_for(source);
            self.clear_header_mode_for(source);
            match self
                .chain
                .begin_header_candidate(anchor, self.chain.minimum_chain_work())
            {
                Ok(candidate) => {
                    let locator = candidate.locator();
                    let height = candidate.height();
                    if self.peer_table.is_current(source) {
                        self.scheduler
                            .lock()
                            .headers_sync
                            .entry(source)
                            .or_default()
                            .mode = Some(HeaderSyncMode::Winning(candidate));
                        self.send_presync_getheaders(source, locator, height);
                    }
                }
                Err(error) => self.settle_winning_header_error(source, error),
            }
            return;
        }
        let now = Instant::now();
        let mut last = self.refused_rerequest_at.lock();
        if last.is_none_or(|last| now.duration_since(last) >= HEADER_REQUEST_TIMEOUT) {
            *last = Some(now);
            drop(last);
            self.request_headers_from(source);
            tracing::debug!(
                %error,
                "block sync: header admission refused; requesting ancestry",
            );
        } else {
            tracing::debug!(
                %error,
                "block sync: header admission refused; ancestry request already recent",
            );
        }
    }

    fn consume_header_request(
        &self,
        source: Option<PeerSource>,
        wire_response: bool,
        batch_empty: bool,
    ) {
        let Some(source) = source.filter(|_| wire_response) else {
            return;
        };
        if !batch_empty {
            self.clear_header_request_for(source);
            return;
        }
        let mut scheduler = self.scheduler.lock();
        if let Some(owned) = scheduler.headers_sync.get_mut(&source) {
            if let Some(request) = owned.request.as_mut() {
                request.state = HeaderRequestState::Answered;
            }
            owned.mode = None;
        }
        let prune = scheduler
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_none() && owned.mode.is_none());
        if prune {
            scheduler.headers_sync.remove(&source);
        }
        if scheduler.header_request_owner == Some(source)
            && scheduler
                .headers_sync
                .get(&source)
                .is_none_or(|owned| owned.request.is_none())
        {
            scheduler.header_request_owner = None;
        }
    }

    pub(super) fn clear_header_request_for(&self, source: PeerSource) {
        let mut scheduler = self.scheduler.lock();
        if let Some(owned) = scheduler.headers_sync.get_mut(&source) {
            owned.request = None;
        }
        if scheduler
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.mode.is_none())
        {
            scheduler.headers_sync.remove(&source);
        }
        if scheduler.header_request_owner == Some(source) {
            scheduler.header_request_owner = None;
        }
    }

    fn clear_header_mode_for(&self, source: PeerSource) -> Option<HeaderSyncMode> {
        let mut scheduler = self.scheduler.lock();
        let state = scheduler
            .headers_sync
            .get_mut(&source)
            .and_then(|owned| owned.mode.take());
        if scheduler
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_none() && owned.mode.is_none())
        {
            scheduler.headers_sync.remove(&source);
        }
        state
    }

    pub(super) fn retire_timed_out_header_syncs(&self, now: Instant) {
        for source in self.clear_timed_out_header_syncs(now) {
            self.peer_table.disconnect_source(source);
            tracing::debug!(peer_addr = ?source.endpoint, "block sync: header sync request timed out");
        }
    }

    fn clear_timed_out_header_syncs(&self, now: Instant) -> Vec<PeerSource> {
        let below_floor = self.below_header_work_floor();
        let mut scheduler = self.scheduler.lock();
        let expired: Vec<_> = scheduler
            .headers_sync
            .iter()
            .filter_map(|(source, owned)| {
                let request = owned.request?;
                (request.state == HeaderRequestState::AwaitingResponse
                    && !owned.has_local_replay()
                    && !owned.has_cancelled_candidate()
                    && (below_floor || owned.mode.is_some())
                    && now.saturating_duration_since(request.requested_at) >= request.timeout())
                .then_some(*source)
            })
            .collect();
        for source in &expired {
            scheduler.clear_headers_sync_for(*source);
        }
        expired
    }

    fn below_header_work_floor(&self) -> bool {
        let minimum_work = self.chain.minimum_chain_work();
        self.chain
            .chain_tip()
            .is_none_or(|tip| tip.chainwork < minimum_work)
    }

    pub(super) fn resolve_owned_body_fetches(&self) {
        let snapshot = {
            let scheduler = self.scheduler.lock();
            if scheduler.owned_body_fetches.is_empty() {
                return;
            }
            scheduler.owned_body_fetches.clone()
        };
        let mut dead = Vec::new();
        let mut resolved = Vec::with_capacity(snapshot.len());
        {
            let tree = self.chain.block_tree();
            for (source, hash) in snapshot {
                if !self.peer_table.is_current(source) {
                    dead.push((source, hash));
                    continue;
                }
                let height = tree
                    .lookup(hash)
                    .and_then(|id| tree.node(id).ok().map(|node| node.height));
                if let Some(height) = height {
                    resolved.push((source, hash, height));
                }
            }
        }
        self.scheduler
            .lock()
            .owned_body_fetches
            .retain(|mark| !dead.contains(mark));
        for (source, hash, height) in resolved {
            self.install_resolved_owned_body_fetch(source, hash, height);
        }
    }

    pub(super) fn install_resolved_owned_body_fetch(
        &self,
        source: PeerSource,
        hash: Hash256,
        height: u32,
    ) {
        let current = self.peer_table.with_current(source, || {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState {
                window,
                stager,
                owned_body_fetches,
                ..
            } = &mut *scheduler;
            let Some(index) = owned_body_fetches
                .iter()
                .position(|mark| *mark == (source, hash))
            else {
                return;
            };
            let installed = window.mark_owned_fetch(stager, source, hash, height, Instant::now())
                && window
                    .pending_owner(&hash)
                    .is_none_or(|owner| owner == source);
            if installed {
                owned_body_fetches.remove(index);
            }
        });
        if !current {
            self.scheduler
                .lock()
                .owned_body_fetches
                .retain(|mark| *mark != (source, hash));
        }
    }

    fn known_batch_outcome(
        &self,
        headers: &[bitcoin_rs_consensus::primitives::Header],
    ) -> Option<(Hash256, Option<i32>)> {
        let tree = self.chain.block_tree();
        let last_hash = Hash256::from(headers.last()?.compute_hash());
        headers
            .iter()
            .all(|header| {
                tree.lookup(Hash256::from(header.compute_hash()))
                    .and_then(|id| tree.node(id).ok())
                    .is_some_and(|node| !matches!(node.status, NodeStatus::Invalid))
            })
            .then(|| {
                (
                    last_hash,
                    tree.tip()
                        .and_then(|tip| shared_active_height(&tree, tip.tip_id, last_hash))
                        .and_then(|height| i32::try_from(height).ok()),
                )
            })
    }

    fn request_headers_from(&self, source: Option<PeerSource>) {
        let Some(source) = source else {
            return;
        };
        let header_height = self.chain.chain_tip().map_or(0, |tip| tip.height);
        let target_height = self
            .peer_table
            .sessions()
            .iter()
            .find(|session| session.endpoint == source.endpoint)
            .map_or(i32::MAX, |session| {
                headers_target_height(session.headers_horizon, session.info.as_ref())
            });
        self.send_getheaders(source, header_height, target_height, self.build_locator());
    }

    pub(super) fn request_headers_from_eligible(&self) {
        let required = bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
            | bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
        let source = self
            .peer_table
            .sessions()
            .into_iter()
            .filter(|session| {
                !session.lease.is_cancelled()
                    && session
                        .info
                        .as_ref()
                        .is_some_and(|info| info.services & required == required)
            })
            .min_by_key(|session| session.endpoint)
            .map(|session| session.lease.source(session.endpoint));
        self.request_headers_from(source);
    }

    pub(super) fn refresh_active_peer_credit(&self) {
        let sessions = self.peer_table.sessions();
        let updates: Vec<(PeerSource, Option<i32>, Vec<Hash256>)> = {
            let tree = self.chain.block_tree();
            let Some(active_tip) = tree.tip() else {
                return;
            };
            sessions
                .into_iter()
                .filter_map(|session| {
                    let mut argmax: Option<(u32, Hash256)> = None;
                    let mut unresolved: Vec<(NodeId, u32, Hash256)> = Vec::new();
                    for hash in &session.demonstrated_tips {
                        let Some(node_id) = tree.lookup(*hash) else {
                            continue;
                        };
                        let Ok(node) = tree.node(node_id) else {
                            continue;
                        };
                        if tree.node_at_height_from(active_tip.tip_id, node.height) == Some(node_id)
                        {
                            if argmax.is_none_or(|(max, _)| node.height > max) {
                                argmax = Some((node.height, *hash));
                            }
                        } else {
                            unresolved.push((node_id, node.height, *hash));
                        }
                    }
                    unresolved.sort_by_key(|entry| std::cmp::Reverse(entry.1));
                    let mut branch_kept: Vec<NodeId> = Vec::new();
                    let mut keep = Vec::with_capacity(unresolved.len() + 1);
                    let mut best_shared = argmax.map_or(0, |(height, _)| height);
                    for (node_id, height, hash) in unresolved {
                        if keep.len() >= MAX_UNRESOLVED_DEMONSTRATED_TIPS {
                            break;
                        }
                        if branch_kept.iter().any(|&kept_id| {
                            tree.node_at_height_from(kept_id, height) == Some(node_id)
                        }) {
                            continue;
                        }
                        branch_kept.push(node_id);
                        best_shared = best_shared
                            .max(shared_active_height(&tree, active_tip.tip_id, hash).unwrap_or(0));
                        keep.push(hash);
                    }
                    if let Some((_, hash)) = argmax {
                        keep.push(hash);
                    }
                    let needs_prune = keep.len() < session.demonstrated_tips.len();
                    let credit = i32::try_from(best_shared).ok().filter(|height| {
                        session
                            .info
                            .is_some_and(|info| *height > info.best_known_height)
                    });
                    (needs_prune || credit.is_some())
                        .then(|| (session.lease.source(session.endpoint), credit, keep))
                })
                .collect()
        };
        for (source, credit, keep) in updates {
            self.peer_table.set_demonstrated_tips(source, keep);
            if let Some(height) = credit {
                self.peer_table.note_announced_height(source, height);
            }
        }
    }

    pub(super) fn request_headers_from_best_peer(
        &self,
        frontier: &SyncFrontier,
        exclude: Option<PeerSource>,
    ) {
        let (applied_height, header_height) = frontier.heights();
        let mut header_peer: Option<(PeerSource, SyncPeer)> = None;
        for peer in &frontier.usable_peers {
            let Some(candidate) = sync_peer_candidate(
                peer.source,
                &peer.info,
                peer.headers_horizon,
                applied_height,
            ) else {
                continue;
            };
            if exclude.is_some_and(|excluded| excluded == peer.source) {
                continue;
            }
            if header_peer
                .as_ref()
                .is_none_or(|(_, current)| outranks(*current, candidate))
            {
                header_peer = Some((peer.source, candidate));
            }
        }
        if let Some((source, peer)) = header_peer {
            let peer_best_height = u32::try_from(peer.best_known_height).unwrap_or(0);
            if peer_best_height > header_height {
                self.send_getheaders(
                    source,
                    header_height,
                    peer.best_known_height,
                    self.build_locator(),
                );
            }
        }
    }

    pub(super) fn probe_frontier_peer(
        &self,
        frontier: &SyncFrontier,
        source: PeerSource,
    ) -> GetheadersOutcome {
        if frontier.chain.applied_tip.is_none() || frontier.chain.chain_tip.is_none() {
            return GetheadersOutcome::Failed;
        }
        let frontier_owned = frontier.chain.next_required.is_some_and(|required| {
            let scheduler = self.scheduler.lock();
            scheduler.window.contains_pending(&required.hash)
                || scheduler.stager.contains(&required.hash)
        });
        if frontier_owned {
            return GetheadersOutcome::FrontierOwned;
        }
        let Some((our_height, target_height, locator)) = self.applied_frontier_probe(frontier)
        else {
            return GetheadersOutcome::Failed;
        };
        let outcome = self.send_getheaders(source, our_height, target_height, locator);
        if outcome == GetheadersOutcome::Sent {
            tracing::debug!(
                peer_addr = ?source.endpoint,
                "block sync: sent idle-frontier capability probe"
            );
        }
        outcome
    }

    pub(super) fn send_chain_sync_probe(
        &self,
        frontier: &SyncFrontier,
        source: PeerSource,
    ) -> GetheadersOutcome {
        let has_presync = {
            let scheduler = self.scheduler.lock();
            scheduler
                .headers_sync
                .get(&source)
                .is_some_and(|owned| owned.mode.is_some())
        };
        if has_presync {
            return GetheadersOutcome::Suppressed;
        }
        let Some(headers) = frontier.chain.chain_tip.as_ref() else {
            return GetheadersOutcome::Failed;
        };
        let locator = {
            let tree = self.chain.block_tree();
            let anchor = tree
                .node(headers.tip_id)
                .ok()
                .and_then(|node| node.parent)
                .unwrap_or(headers.tip_id);
            tree.block_locator(anchor, LOCATOR_MAX_ENTRIES)
        };
        let our_height = headers.height.saturating_sub(1);
        let target_height = i32::try_from(headers.height).unwrap_or(i32::MAX);
        let outcome = self.send_getheaders_tracked(
            source,
            our_height,
            target_height,
            locator,
            HeaderRequestKind::ChainSyncProbe,
        );
        if outcome == GetheadersOutcome::Sent {
            tracing::debug!(
                peer_addr = ?source.endpoint,
                "block sync: sent chain-sync eviction probe"
            );
        }
        outcome
    }

    fn applied_frontier_probe(&self, frontier: &SyncFrontier) -> Option<(u32, i32, Vec<Hash256>)> {
        let (applied, headers) = (
            frontier.chain.applied_tip.as_ref()?,
            frontier.chain.chain_tip.as_ref()?,
        );
        let tree = self.chain.block_tree();
        let active_anchor = tree.node_at_height_from(headers.tip_id, applied.height)?;
        Some((
            applied.height,
            i32::try_from(headers.height).unwrap_or(i32::MAX),
            tree.block_locator(active_anchor, LOCATOR_MAX_ENTRIES),
        ))
    }

    pub(super) fn send_getheaders(
        &self,
        source: PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
    ) -> GetheadersOutcome {
        self.send_getheaders_tracked(
            source,
            our_height,
            target_height,
            locator,
            HeaderRequestKind::Frontier,
        )
    }

    fn send_getheaders_tracked(
        &self,
        source: PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
        kind: HeaderRequestKind,
    ) -> GetheadersOutcome {
        let (our_height, locator, finished_candidate) = {
            let scheduler = self.scheduler.lock();
            let owned = scheduler.headers_sync.get(&source);
            if owned.is_some_and(|owned| owned.has_local_replay()) {
                return GetheadersOutcome::Suppressed;
            }
            match owned.and_then(|owned| owned.mode.as_ref()) {
                Some(HeaderSyncMode::Winning(candidate)) if candidate.is_cancelled() => {
                    return GetheadersOutcome::Suppressed;
                }
                Some(mode) => (
                    mode.height(),
                    mode.locator(),
                    matches!(mode, HeaderSyncMode::Winning(candidate)
                        if candidate.phase() == HeaderCandidatePhase::Finished),
                ),
                None => (our_height, locator, false),
            }
        };
        let Some(locator_tip_hash) = locator.first().copied() else {
            return GetheadersOutcome::Failed;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
        let now = Instant::now();
        if self.has_pending_getheaders(source, locator_tip_hash, target_height, now) {
            tracing::trace!(
                peer_addr = ?source.endpoint,
                our_height,
                target_height,
                "block sync: getheaders already pending",
            );
            return GetheadersOutcome::Suppressed;
        }
        let locator_hashes: Vec<bitcoin::BlockHash> = locator
            .into_iter()
            .map(|hash| bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()))
            .collect();
        let getheaders = GetHeadersMessage::new(locator_hashes, bitcoin::BlockHash::all_zeros());
        let getheaders_version = getheaders.version;
        let msg = Message::GetHeaders(getheaders);
        let sent = self.peer_table.send_then(source, msg, || {
            let mut scheduler = self.scheduler.lock();
            scheduler.headers_sync.entry(source).or_default().request = Some(HeaderRequest {
                source,
                kind,
                locator_tip_hash,
                target_height,
                requested_at: now,
                state: HeaderRequestState::AwaitingResponse,
            });
            if kind == HeaderRequestKind::Frontier {
                let can_claim_owner = scheduler.header_request_owner.is_none_or(|owner| {
                    owner == source
                        || scheduler
                            .headers_sync
                            .get(&owner)
                            .and_then(|owned| owned.request)
                            .is_none_or(|request| !request.is_live(now))
                });
                if can_claim_owner {
                    scheduler.header_request_owner = Some(source);
                }
            } else if scheduler.header_request_owner == Some(source) {
                scheduler.header_request_owner = None;
            }
        });
        match sent {
            Ok(()) => {}
            Err(OutboundRefusal::Saturated(_)) => {
                tracing::debug!(
                    peer_addr = ?source.endpoint,
                    "block sync: getheaders deferred; node outbound budget is full"
                );
                return GetheadersOutcome::Failed;
            }
            Err(OutboundRefusal::Closed(_)) => {
                tracing::warn!(
                    peer_addr = ?source.endpoint,
                    "block sync: outbound channel disconnected"
                );
                self.peer_table.disconnect_source(source);
                self.scheduler.lock().clear_headers_sync_for(source);
                return GetheadersOutcome::Failed;
            }
        }
        if finished_candidate {
            self.clear_header_mode_for(source);
        }
        tracing::debug!(
            peer_addr = ?source.endpoint,
            our_height,
            target_height,
            getheaders_version,
            "block sync: sent getheaders"
        );
        GetheadersOutcome::Sent
    }

    fn has_pending_getheaders(
        &self,
        source: PeerSource,
        locator_tip_hash: Hash256,
        target_height: u32,
        now: Instant,
    ) -> bool {
        let below_floor = self.below_header_work_floor();
        let scheduler = self.scheduler.lock();
        let Some(owned) = scheduler.headers_sync.get(&source) else {
            return false;
        };
        let Some(request) = owned.request else {
            return false;
        };
        let unexpired = now.saturating_duration_since(request.requested_at) < request.timeout();
        match request.state {
            HeaderRequestState::ResponseQueued => true,
            HeaderRequestState::AwaitingResponse
                if below_floor || owned.mode.is_some() || unexpired =>
            {
                true
            }
            HeaderRequestState::Answered
                if request.locator_tip_hash == locator_tip_hash
                    && request.target_height == target_height
                    && unexpired =>
            {
                true
            }
            HeaderRequestState::AwaitingResponse | HeaderRequestState::Answered => false,
        }
    }

    pub(super) fn route_headers_batch(
        &self,
        headers: &[Header],
        source: Option<PeerSource>,
        wire_response: bool,
        batch_len: usize,
    ) -> Option<HeaderAdmission> {
        if wire_response && source.is_some_and(|source| !self.peer_table.is_current(source)) {
            return None;
        }
        if headers.is_empty() {
            if wire_response && let Some(source) = source {
                self.clear_header_mode_for(source);
            }
            return Some(self.chain.admit_headers(headers));
        }
        let Some(source) = source else {
            return Some(self.chain.admit_headers(headers));
        };
        if !wire_response {
            if self.presync_anchor(headers).is_none()
                || self.body_carried_header_needs_admission(headers)
            {
                return Some(self.chain.admit_headers(headers));
            }
            return None;
        }
        let outcome = {
            let parked = {
                let mut scheduler = self.scheduler.lock();
                scheduler
                    .headers_sync
                    .get_mut(&source)
                    .and_then(|owned| owned.mode.take())
            };
            let mut state = match parked {
                Some(HeaderSyncMode::Winning(candidate)) => {
                    self.receive_winning_headers(source, candidate, headers, batch_len);
                    return None;
                }
                Some(HeaderSyncMode::LowWork(state)) => state,
                None => {
                    let Some((anchor, minimum_work)) = self.presync_anchor(headers) else {
                        return Some(self.chain.admit_headers(headers));
                    };
                    let params = anchor.network.headers_sync_params();
                    HeadersSyncState::new(anchor, minimum_work, params, presync_salt())
                }
            };
            let outcome = Self::advance_presync_state(&mut state, headers, batch_len);
            if self.peer_table.is_current(source) {
                self.scheduler
                    .lock()
                    .headers_sync
                    .entry(source)
                    .or_default()
                    .mode = Some(HeaderSyncMode::LowWork(state));
            }
            outcome
        };
        if outcome.finished {
            self.clear_header_mode_for(source);
        }
        if let Some(error) = outcome.failure {
            self.clear_header_mode_for(source);
            self.settle_presync_fault(source, error);
            return None;
        }
        if outcome.finished && !outcome.request_more && outcome.ready_headers.is_empty() {
            self.peer_table.note_headers_horizon(source, outcome.height);
        } else {
            self.peer_table
                .note_headers_progress(source, outcome.height);
        }
        if !outcome.ready_headers.is_empty() {
            let admission = self.chain.admit_headers(&outcome.ready_headers);
            if let HeaderAdmission::Refused(error) = admission {
                let dropped = self.clear_header_mode_for(source);
                if let Some(mut state) = dropped {
                    state.finalize();
                }
                self.request_ancestry_after_refusal(Some(source), &error);
                return None;
            }
            if outcome.request_more && matches!(admission, HeaderAdmission::Accepted { .. }) {
                self.send_presync_getheaders(source, outcome.locator, outcome.height);
            }
            return Some(admission);
        }
        if outcome.request_more {
            self.send_presync_getheaders(source, outcome.locator, outcome.height);
        }
        None
    }
    fn receive_winning_headers(
        &self,
        source: PeerSource,
        mut candidate: HeaderCandidate,
        headers: &[Header],
        batch_len: usize,
    ) {
        if !candidate.has_verified_headers()
            && let Err(error) = candidate.receive(
                headers,
                batch_len >= bitcoin_rs_p2p::wire::MAX_HEADERS_MESSAGE_COUNT,
            )
        {
            self.settle_winning_header_error(source, error.into());
            return;
        }
        self.peer_table
            .note_headers_progress(source, candidate.height());
        if self.peer_table.is_current(source) {
            self.scheduler
                .lock()
                .headers_sync
                .entry(source)
                .or_default()
                .mode = Some(HeaderSyncMode::Winning(candidate));
        }
    }

    fn drain_winning_headers(
        &self,
        remaining: &mut usize,
        direct_fetch: &mut Vec<(PeerSource, Hash256)>,
        credit_refresh_needed: &mut bool,
    ) {
        let sources: Vec<_> = self
            .scheduler
            .lock()
            .headers_sync
            .iter()
            .filter_map(|(source, owned)| {
                matches!(&owned.mode, Some(HeaderSyncMode::Winning(_))).then_some(*source)
            })
            .collect();
        for source in sources {
            let Some(mode) = self.clear_header_mode_for(source) else {
                continue;
            };
            let HeaderSyncMode::Winning(mut candidate) = mode else {
                self.scheduler
                    .lock()
                    .headers_sync
                    .entry(source)
                    .or_default()
                    .mode = Some(mode);
                continue;
            };
            if !self.peer_table.is_current(source) {
                continue;
            }
            if candidate.is_cancelled() {
                self.settle_winning_header_error(source, HeaderCandidateError::Cancelled.into());
                continue;
            }
            let mut failed = None;
            while candidate.has_verified_headers() && *remaining > 0 {
                let maximum = (*remaining).min(bitcoin_rs_p2p::wire::MAX_HEADERS_MESSAGE_COUNT);
                match self.chain.admit_verified_headers(&mut candidate, maximum) {
                    Ok(outcome) => {
                        assert!(outcome.accepted > 0 && outcome.accepted <= maximum);
                        *remaining -= outcome.accepted;
                        self.handle_header_admission(
                            HeaderAdmission::Accepted {
                                accepted: outcome.accepted,
                                announced_tip: outcome.announced_tip,
                                active_height: outcome.active_height,
                                demoted_tip: outcome.demoted_tip,
                            },
                            Some(source),
                            true,
                            outcome.accepted,
                            direct_fetch,
                            credit_refresh_needed,
                        );
                    }
                    Err(
                        HeaderAdmissionError::Candidate(
                            HeaderCandidateError::Busy | HeaderCandidateError::NoVerifiedBatch,
                        )
                        | HeaderAdmissionError::Resource(HeaderResourceError::Reclaiming),
                    ) => break,
                    Err(error) => {
                        failed = Some(error);
                        break;
                    }
                }
            }
            if let Some(error) = failed {
                self.settle_winning_header_error(source, error);
            } else if self.peer_table.is_current(source) {
                self.scheduler
                    .lock()
                    .headers_sync
                    .entry(source)
                    .or_default()
                    .mode = Some(HeaderSyncMode::Winning(candidate));
            }
        }
    }

    fn resume_owned_header_requests(&self) {
        let pending: Vec<_> = self
            .scheduler
            .lock()
            .headers_sync
            .iter()
            .filter_map(|(source, owned)| {
                if owned.request.is_some() || owned.has_local_replay() {
                    return None;
                }
                let mode = owned.mode.as_ref()?;
                if matches!(mode, HeaderSyncMode::Winning(candidate) if candidate.is_cancelled()) {
                    return None;
                }
                Some((*source, mode.locator(), mode.height()))
            })
            .collect();
        for (source, locator, height) in pending {
            self.send_presync_getheaders(source, locator, height);
        }
    }

    fn settle_winning_header_error(&self, source: PeerSource, error: HeaderAdmissionError) {
        let peer_fault = match &error {
            HeaderAdmissionError::Candidate(HeaderCandidateError::Chain(
                ChainError::NonContinuousHeader { .. },
            ))
            | HeaderAdmissionError::Candidate(HeaderCandidateError::Validation(
                HeaderContextError::Chain(ChainError::NonContinuousHeader { .. }),
            )) => false,
            HeaderAdmissionError::Rejected(error)
            | HeaderAdmissionError::Candidate(HeaderCandidateError::Chain(error))
            | HeaderAdmissionError::Candidate(HeaderCandidateError::Validation(
                HeaderContextError::Chain(error),
            )) => is_peer_fault(error),
            HeaderAdmissionError::Refused(_)
            | HeaderAdmissionError::Resource(_)
            | HeaderAdmissionError::Candidate(_) => false,
        };
        self.scheduler.lock().clear_headers_sync_for(source);
        if peer_fault {
            if self.peer_table.disconnect_source(source) {
                self.scheduler
                    .lock()
                    .window
                    .mark_peer_unresponsive(source, Instant::now());
            }
            tracing::warn!(peer_addr = ?source.endpoint, %error,
                "block sync: peer served invalid winning-candidate headers");
        } else {
            self.request_ancestry_after_refusal(
                Some(source),
                &bitcoin_rs_chain::chain::HeaderRefusal::from_cause(&error),
            );
        }
    }

    fn body_carried_header_needs_admission(&self, headers: &[Header]) -> bool {
        let [header] = headers else {
            return self.stale_tip_page_needs_admission(headers);
        };
        let tree = self.chain.block_tree();
        let Some(parent_id) = tree.lookup(Hash256::from(header.prev_blockhash)) else {
            return true;
        };
        let network = self.chain.network();
        let hash = Hash256::from(header.compute_hash());
        validate_pow(header, hash, network)
            .and_then(|()| {
                bitcoin_rs_chain::chain::validate_contextual_header(
                    &tree,
                    parent_id,
                    header,
                    network,
                    bitcoin_rs_chain::chain::current_unix_seconds(),
                    bitcoin_rs_chain::chain::HeaderValidationMode::LiveAdmission,
                )
            })
            .is_err()
    }

    fn stale_tip_page_needs_admission(&self, headers: &[Header]) -> bool {
        if headers.len() <= 1 {
            return true;
        }
        let tree = self.chain.block_tree();
        let network = self.chain.network();
        let Some(first_parent) = tree.lookup(Hash256::from(headers[0].prev_blockhash)) else {
            return true;
        };
        if tree
            .node(first_parent)
            .is_ok_and(|node| node.status == NodeStatus::Invalid)
        {
            return true;
        }
        if headers.iter().any(|header| {
            let hash = Hash256::from(header.compute_hash());
            validate_pow(header, hash, network).is_err()
        }) || headers.windows(2).any(|pair| {
            Hash256::from(pair[1].prev_blockhash) != Hash256::from(pair[0].compute_hash())
        }) {
            return true;
        }
        let hash = Hash256::from(headers[0].compute_hash());
        validate_pow(&headers[0], hash, network)
            .and_then(|()| {
                bitcoin_rs_chain::chain::validate_contextual_header(
                    &tree,
                    first_parent,
                    &headers[0],
                    network,
                    bitcoin_rs_chain::chain::current_unix_seconds(),
                    bitcoin_rs_chain::chain::HeaderValidationMode::LiveAdmission,
                )
            })
            .is_err()
    }

    fn advance_presync_state(
        state: &mut HeadersSyncState,
        headers: &[Header],
        batch_len: usize,
    ) -> PresyncOutcome {
        let (failure, request_more, ready_headers, finished) = match state.process(
            headers,
            batch_len >= bitcoin_rs_p2p::wire::MAX_HEADERS_MESSAGE_COUNT,
        ) {
            Ok(result) => (
                None,
                result.request_more,
                result.ready_headers,
                result.phase == HeadersSyncPhase::Final,
            ),
            Err(error) => (Some(error), false, Vec::new(), true),
        };
        PresyncOutcome {
            failure,
            request_more,
            ready_headers,
            locator: state.next_locator(),
            height: state.sync_height(),
            finished,
        }
    }

    fn anti_dos_work_threshold(&self, tree: &BlockTree) -> ChainWork {
        let minimum_work = self.chain.minimum_chain_work();
        let Some(tip) = self.chain.applied_tip() else {
            return minimum_work;
        };
        let Ok(node) = tree.node(tip.tip_id) else {
            log::error!(
                "applied tip {:?} is missing from the block tree; fork headers need the full tip work",
                tip.tip_id,
            );
            return minimum_work.max(tip.chainwork);
        };
        let buffer = bitcoin_rs_chain::chain::block_work(&node.header)
            .saturating_mul(ChainWork::from(NEAR_TIP_WORK_BLOCKS));
        minimum_work.max(tip.chainwork.saturating_sub(buffer))
    }

    fn presync_anchor(&self, headers: &[Header]) -> Option<(HeaderAnchor, ChainWork)> {
        let first = headers.first()?;
        let network = self.chain.network();
        let tree = self.chain.block_tree();
        let fork_id = tree.lookup(Hash256::from(first.prev_blockhash))?;
        let fork = tree.node(fork_id).ok()?;
        if fork.status == NodeStatus::Invalid {
            return None;
        }
        let minimum_work = self.anti_dos_work_threshold(&tree);
        let page_self_valid = headers.iter().all(|header| {
            let hash = Hash256::from(header.compute_hash());
            validate_pow(header, hash, network).is_ok()
        }) && headers.windows(2).all(|pair| {
            Hash256::from(pair[1].prev_blockhash) == Hash256::from(pair[0].compute_hash())
        });
        if page_self_valid {
            let claimed = headers.iter().fold(fork.chainwork, |sum, header| {
                sum.saturating_add(bitcoin_rs_chain::chain::block_work(header))
            });
            if claimed >= minimum_work {
                return None;
            }
        }
        let median_time_past = tree.median_time_past_at(fork_id)?;
        let anchor = HeaderAnchor {
            network,
            height: fork.height,
            hash: fork.hash,
            header: fork.header,
            chain_work: fork.chainwork,
            median_time_past,
            locator: tree.block_locator(fork_id, LOCATOR_MAX_ENTRIES),
        };
        Some((anchor, minimum_work))
    }

    fn send_presync_getheaders(
        &self,
        source: PeerSource,
        locator: Vec<Hash256>,
        height: u32,
    ) -> GetheadersOutcome {
        let target_height = self
            .peer_table
            .sessions()
            .iter()
            .find(|session| session.endpoint == source.endpoint)
            .map_or(i32::MAX, |session| {
                headers_target_height(session.headers_horizon, session.info.as_ref())
            });
        self.send_getheaders(source, height, target_height, locator)
    }

    fn settle_presync_fault(&self, source: PeerSource, error: HeaderSyncError) {
        if !error.is_peer_fault() {
            tracing::debug!(
                peer_addr = ?source.endpoint,
                %error,
                "block sync: header presync gave up on a possibly reorged continuation",
            );
            return;
        }
        let disconnected = self.peer_table.disconnect_source(source);
        self.scheduler.lock().clear_headers_sync_for(source);
        if disconnected {
            self.scheduler
                .lock()
                .window
                .mark_peer_unresponsive(source, Instant::now());
        }
        tracing::warn!(
            peer_addr = ?source.endpoint,
            %error,
            "block sync: peer failed header presync validation; disconnecting",
        );
    }

    fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.chain.chain_tip() {
            return self
                .chain
                .block_tree()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        std::vec![self.chain.network().genesis_block_hash()]
    }
}

impl SchedulerState {
    fn clear_headers_sync_for(&mut self, source: PeerSource) {
        self.headers_sync.remove(&source);
        if self.header_request_owner == Some(source) {
            self.header_request_owner = None;
        }
    }
}

fn headers_target_height(horizon: Option<u32>, info: Option<&PeerInfo>) -> i32 {
    let claimed = info.map_or(i32::MAX, |info| info.best_known_height);
    match horizon {
        Some(cap) => claimed.min(i32::try_from(cap).unwrap_or(i32::MAX)),
        None => claimed,
    }
}

fn presync_salt() -> [u8; 16] {
    use bitcoin::secp256k1::rand::RngCore as _;
    let mut salt = [0_u8; 16];
    bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod stale_tip_routing_tests {
    use super::super::BlockSync;
    use super::super::chain::HeaderAdmission;
    use super::super::chain::SyncChain;
    use super::super::chain::SyncChainError;
    use super::super::chain::WindowCommitError;
    use bitcoin_rs_chain::chain::TipSnapshot;
    use bitcoin_rs_chain::chain::{BlockTree, NodeStatus};
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::{Hash256, Header, Network};
    use parking_lot::RwLockReadGuard;
    use std::sync::Arc;

    struct RoutingStubChain {
        tree: parking_lot::RwLock<BlockTree>,
        network: Network,
        floor: ChainWork,
        applied: parking_lot::RwLock<Option<Arc<TipSnapshot>>>,
    }

    impl RoutingStubChain {
        fn with_floor(tree: BlockTree, floor: ChainWork) -> Self {
            let applied = tree.tip();
            Self {
                tree: parking_lot::RwLock::new(tree),
                network: Network::Regtest,
                floor,
                applied: parking_lot::RwLock::new(applied),
            }
        }
    }

    impl SyncChain for RoutingStubChain {
        fn begin_header_candidate(
            &self,
            anchor: Hash256,
            _minimum_work: ChainWork,
        ) -> Result<bitcoin_rs_chain::chain::HeaderCandidate, bitcoin_rs_chain::HeaderAdmissionError>
        {
            Err(bitcoin_rs_chain::chain::HeaderCandidateError::AnchorUnavailable { anchor }.into())
        }

        fn admit_verified_headers(
            &self,
            _candidate: &mut bitcoin_rs_chain::chain::HeaderCandidate,
            _maximum: usize,
        ) -> Result<bitcoin_rs_chain::HeaderAdmissionOutcome, bitcoin_rs_chain::HeaderAdmissionError>
        {
            Err(bitcoin_rs_chain::chain::HeaderCandidateError::WrongChainstate.into())
        }

        fn maintain_header_retention(
            &self,
        ) -> Result<usize, bitcoin_rs_chain::HeaderAdmissionError> {
            Ok(0)
        }

        fn network(&self) -> Network {
            self.network
        }

        fn block_tree(&self) -> RwLockReadGuard<'_, BlockTree> {
            self.tree.read()
        }

        fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.tree.read().tip()
        }

        fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.applied.read().clone()
        }

        fn bootstrap_genesis(&self) {}

        fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
            let mut tree = self.tree.write();
            match bitcoin_rs_chain::chain::accept_headers(
                &mut tree,
                headers,
                self.network,
                bitcoin_rs_chain::chain::current_unix_seconds(),
                bitcoin_rs_chain::chain::HeaderValidationMode::LiveAdmission,
            ) {
                Ok(admitted) => {
                    let announced_tip = admitted
                        .ids
                        .last()
                        .and_then(|id| tree.node(*id).ok())
                        .map(|node| node.hash);
                    let active_height = tree.tip().zip(announced_tip).and_then(|(tip, hash)| {
                        tree.active_height_of(tip.tip_id, hash)
                            .and_then(|h| i32::try_from(h).ok())
                    });
                    HeaderAdmission::Accepted {
                        accepted: admitted.ids.len(),
                        announced_tip,
                        active_height,
                        demoted_tip: admitted.demoted_tip,
                    }
                }
                Err(error) => HeaderAdmission::Rejected(error),
            }
        }

        fn minimum_chain_work(&self) -> ChainWork {
            self.floor
        }

        fn check_body_binding(
            &self,
            _block: &bitcoin_rs_consensus::primitives::BlockImage,
        ) -> Result<(), SyncChainError> {
            Ok(())
        }

        fn window_len(&self, _serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
            0
        }

        fn commit_window(
            &self,
            _payloads: &[&bitcoin_rs_consensus::primitives::BlockImage],
        ) -> Result<usize, WindowCommitError> {
            Ok(0)
        }

        fn switch_to_branch(
            &self,
            _target: bitcoin_rs_chain::chain::NodeId,
            _staged_body: &mut dyn FnMut(
                Hash256,
            )
                -> Option<bitcoin_rs_consensus::primitives::BlockImage>,
            _connected_body: &mut dyn FnMut(Hash256),
        ) -> Result<(), bitcoin_rs_chain::reorg::ReorgError> {
            Ok(())
        }
    }

    fn routing_sync(
        tree: BlockTree,
        floor: ChainWork,
    ) -> (
        BlockSync,
        Arc<bitcoin_rs_p2p::PeerTable>,
        crossbeam_channel::Sender<bitcoin_rs_p2p::InboundHeaders>,
    ) {
        let peers = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (_blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let chain: Arc<dyn SyncChain> = Arc::new(RoutingStubChain::with_floor(tree, floor));
        let sync = BlockSync::new(
            chain,
            Arc::clone(&peers),
            headers_rx,
            blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        );
        (sync, peers, headers_tx)
    }

    fn connected_peer(
        peers: &Arc<bitcoin_rs_p2p::PeerTable>,
        port: u16,
        best_height: i32,
    ) -> (
        bitcoin_rs_p2p::PeerSource,
        bitcoin_rs_p2p::test_support::MessageReceiver,
    ) {
        let (tx, rx) = bitcoin_rs_p2p::test_support::message_channel();
        let lease = bitcoin_rs_p2p::PeerLease::new(tx);
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
        peers.register(endpoint, lease.clone());
        let info = bitcoin_rs_p2p::peer_info::PeerInfo {
            addr: endpoint.into(),
            endpoint: Some(endpoint),
            network: endpoint.net(),
            version: 70016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
                | bitcoin::p2p::ServiceFlags::WITNESS.to_u64(),
            user_agent: String::from("/test/"),
            start_height: best_height,
            best_known_height: best_height,
            conn_time: 0,
            inbound: false,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new(addr),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        };
        peers.publish_info(endpoint, &lease, info);
        (lease.source_ip(addr), rx)
    }

    fn regtest_tree_with_main() -> BlockTree {
        let mut tree = BlockTree::new();
        let genesis = Network::Regtest.genesis_block();
        tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)
            .unwrap_or_else(|error| panic!("genesis inserts: {error}"));
        let mut prev = genesis.block_hash();
        let mut tip_id = tree
            .lookup(Hash256::from(prev))
            .unwrap_or_else(|| panic!("genesis indexed"));
        for height in 1..=2_u32 {
            let header =
                bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(prev, height)
                    .unwrap_or_else(|error| panic!("fixture mines: {error}"));
            prev = header.compute_hash();
            tip_id = tree
                .insert_node(Some(tip_id), header, NodeStatus::HeaderValid)
                .unwrap_or_else(|error| panic!("main header inserts: {error}"));
        }
        tree
    }

    #[test]
    fn low_work_stale_tip_page_defers_while_broken_page_admits() {
        let tree = regtest_tree_with_main();
        let floor = ChainWork::from_be_bytes([0xFF_u8; 32]);
        let (sync, _peers, _headers_tx) = routing_sync(tree, floor);
        let genesis_prev = Network::Regtest.genesis_block().block_hash();
        let first =
            bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(genesis_prev, 101)
                .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        let second = bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(
            first.compute_hash(),
            102,
        )
        .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        let valid_page = [first, second];
        assert!(
            sync.presync_anchor(&valid_page).is_some(),
            "the fixture page must sit below the raised floor"
        );
        assert!(
            !sync.body_carried_header_needs_admission(&valid_page),
            "a valid low-work stale-tip page must defer, not admit past the hold"
        );
        let mut broken = valid_page;
        broken[1].nonce = broken[1].nonce.wrapping_add(1).wrapping_mul(7919);
        if bitcoin_rs_chain::chain::validate_pow(
            &broken[1],
            Hash256::from(broken[1].compute_hash()),
            Network::Regtest,
        )
        .is_ok()
        {
            broken[1].bits =
                bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1d00_ffff);
        }
        assert!(
            sync.body_carried_header_needs_admission(&broken),
            "a broken stale-tip page must admit so the fault is reported"
        );
    }

    #[test]
    fn partial_prefix_rejection_preserves_demoted_tip() {
        let tree = regtest_tree_with_main();
        let floor = ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work());
        let (sync, peers, headers_tx) = routing_sync(tree, floor);
        let (source, _rx) = connected_peer(&peers, 18445, 3);
        let pre_tip = sync
            .chain
            .chain_tip()
            .unwrap_or_else(|| panic!("tree has a tip"))
            .hash;
        let genesis_prev = Network::Regtest.genesis_block().block_hash();
        let mut batch = Vec::new();
        let mut prev = genesis_prev;
        for height in [101_u32, 102, 103] {
            let header =
                bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(prev, height)
                    .unwrap_or_else(|error| panic!("fixture mines: {error}"));
            prev = header.compute_hash();
            batch.push(header);
        }
        let garbage = bitcoin_rs_consensus::primitives::BlockHash::from(
            bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0xFF_u8; 32]),
        );
        batch.push(
            bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(garbage, 104)
                .unwrap_or_else(|error| panic!("fixture mines: {error}")),
        );
        headers_tx
            .send(bitcoin_rs_p2p::InboundHeaders {
                headers: batch,
                source: Some(source),
                wire_response: false,
            })
            .unwrap_or_else(|error| panic!("queue stale-tip batch: {error}"));
        sync.drain_inbound_headers();
        let moved = sync
            .chain
            .chain_tip()
            .unwrap_or_else(|| panic!("tree has a tip"))
            .hash;
        assert_ne!(
            moved, pre_tip,
            "the above-floor prefix must move the tip before the tail fails"
        );
        let fresh = bitcoin_rs_p2p::PeerSource::for_test(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            18499,
        )));
        let pending = sync.stale_tips().pending_for(fresh, |_| true);
        assert!(
            pending.contains(&pre_tip),
            "the drain must retain the displaced tip for stale relay, got {pending:?}"
        );
    }

    #[test]
    fn duplicate_fetch_skips_owned_body() {
        let tree = regtest_tree_with_main();
        let floor = ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work());
        let (sync, peers, headers_tx) = routing_sync(tree, floor);
        let (source, rx) = connected_peer(&peers, 18446, 3);
        let tip = sync
            .chain
            .chain_tip()
            .unwrap_or_else(|| panic!("tree has a tip"));
        let prev = bitcoin_rs_consensus::primitives::BlockHash::from(tip.hash);
        let header = bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(prev, 3)
            .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        let tip_hash = Hash256::from(header.compute_hash());
        assert!(
            sync.enqueue_owned_body_fetch(source, tip_hash, || true),
            "the compact follow-up publishes ownership"
        );
        headers_tx
            .send(bitcoin_rs_p2p::InboundHeaders {
                headers: vec![header],
                source: Some(source),
                wire_response: true,
            })
            .unwrap_or_else(|error| panic!("queue owned announcement: {error}"));
        sync.drain_inbound_headers();
        assert!(
            sync.owns_body_fetch(source, tip_hash),
            "the owned mark must survive the drain that admitted its header"
        );
        let mut saw_getdata = false;
        while let Ok(message) = rx.try_recv() {
            if matches!(message, crate::p2p::Message::GetData(_)) {
                saw_getdata = true;
            }
        }
        assert!(
            !saw_getdata,
            "the owned body must not be direct-fetched twice"
        );
        let (control_source, control_rx) = connected_peer(&peers, 18447, 4);
        let tip = sync
            .chain
            .chain_tip()
            .unwrap_or_else(|| panic!("tree has a tip"));
        let prev = bitcoin_rs_consensus::primitives::BlockHash::from(tip.hash);
        let control_header =
            bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_header(prev, 4)
                .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        headers_tx
            .send(bitcoin_rs_p2p::InboundHeaders {
                headers: vec![control_header],
                source: Some(control_source),
                wire_response: true,
            })
            .unwrap_or_else(|error| panic!("queue control announcement: {error}"));
        sync.drain_inbound_headers();
        let mut control_saw_getdata = false;
        while let Ok(message) = control_rx.try_recv() {
            if matches!(message, crate::p2p::Message::GetData(_)) {
                control_saw_getdata = true;
            }
        }
        assert!(
            control_saw_getdata,
            "the unowned control announcement must direct-fetch its body"
        );
    }
}

#[cfg(test)]
mod winning_header_tests {
    use super::*;
    use crate::test_support::TestError;
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_chain::chain::{NodeStatus, regtest_fixture};
    use bitcoin_rs_p2p::connection::SharedOutboundBudget;
    use bitcoin_rs_p2p::test_support::{
        MessageReceiver, hog, message_channel, synthetic_peer, test_addr,
    };
    use bitcoin_rs_p2p::{PeerLease, PeerTable};
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::time::Duration;

    struct WinningFixture {
        sync: BlockSync,
        chain: Arc<bitcoin_rs_chain::Chainstate>,
        source: PeerSource,
        outbound: MessageReceiver,
        aggregate: Arc<SharedOutboundBudget>,
        inbound_headers: crossbeam_channel::Sender<InboundHeaders>,
        fork: Vec<Header>,
    }

    fn headers(count: u32, marker: u8) -> Result<Vec<Header>, TestError> {
        let mut parent = bitcoin_rs_consensus::primitives::Network::Regtest
            .genesis_block()
            .block_hash();
        let mut headers = Vec::with_capacity(usize::try_from(count)?);
        for height in 1..=count {
            let mut header = regtest_fixture::mined_regtest_header(parent, height)?;
            header.merkle_root = Hash256::from_le_bytes(&[marker; 32]);
            header.nonce = 0;
            regtest_fixture::mine_header_to_declared_target(&mut header)?;
            parent = header.compute_hash();
            headers.push(header);
        }
        Ok(headers)
    }

    fn fixture(main_height: u32, fork_height: u32) -> Result<WinningFixture, TestError> {
        let network = bitcoin_rs_consensus::primitives::Network::Regtest;
        let mut tree = BlockTree::new();
        tree.insert_header(network.genesis_block().header, NodeStatus::HeaderValid)?;
        let applied = tree.tip();
        bitcoin_rs_chain::chain::accept_headers(
            &mut tree,
            &headers(main_height, 1)?,
            network,
            bitcoin_rs_chain::chain::current_unix_seconds(),
            bitcoin_rs_chain::chain::HeaderValidationMode::LiveAdmission,
        )?;
        let tip = tree.tip_handle();
        let stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let mut utxo = UtxoSet::new();
        utxo.track_coin_stats((*stats).clone());
        let chain = Arc::new(bitcoin_rs_chain::Chainstate::new(
            network,
            tip,
            Arc::new(ArcSwapOption::new(applied)),
            Arc::new(RwLock::new(tree)),
            Arc::new(utxo),
            stats,
            Arc::new(bitcoin_rs_chain::events::ChainEventPublisher::detached(0)),
        ));
        chain.set_header_side_cache_limit(8);
        let peers = Arc::new(PeerTable::new());
        let aggregate = Arc::new(SharedOutboundBudget::with_limits(4096, 0));
        let (sender, outbound) = message_channel();
        let lease = PeerLease::new(sender).with_shared_budget(&aggregate);
        let endpoint = test_addr(28371, 0)?;
        peers.register(endpoint, lease.clone());
        peers.publish_info(
            endpoint,
            &lease,
            synthetic_peer(endpoint, i32::try_from(fork_height)?),
        );
        let source = lease.source(endpoint.endpoint());
        let (inbound_headers, inbound_headers_rx) = crossbeam_channel::unbounded();
        let (_, inbound_blocks_rx) = crossbeam_channel::unbounded();
        let sync = crate::sync::block_sync(crate::sync::BlockSyncInputs {
            handles: Arc::clone(&chain),
            followers: crate::chain_effects::ChainFollowers::noop(),
            peer_table: peers,
            inbound_headers_rx,
            inbound_blocks_rx,
            ibd: chain.ibd_latch(),
            assumeutxo: None,
            budget: Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
                bitcoin_rs_storage::split_chainstate_cache_budget(64 << 20),
                1,
            )),
        });
        Ok(WinningFixture {
            sync,
            chain,
            source,
            outbound,
            aggregate,
            inbound_headers,
            fork: headers(fork_height, 2)?,
        })
    }

    fn candidate(fixture: &WinningFixture) -> Result<HeaderCandidate, TestError> {
        fixture
            .chain
            .begin_header_candidate(
                bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block_hash(),
                ChainWork::ZERO,
            )
            .map_err(|error| TestError::message(error.to_string()))
    }

    fn receive(
        candidate: &mut HeaderCandidate,
        headers: &[Header],
        full: bool,
    ) -> Result<(), TestError> {
        candidate
            .receive(headers, full)
            .map(|_| ())
            .map_err(|error| TestError::message(error.to_string()))
    }

    fn install(fixture: &WinningFixture, candidate: HeaderCandidate) {
        fixture
            .sync
            .scheduler
            .lock()
            .headers_sync
            .entry(fixture.source)
            .or_default()
            .mode = Some(HeaderSyncMode::Winning(candidate));
    }

    fn first_locator(outbound: &MessageReceiver) -> Option<Hash256> {
        outbound.try_iter().find_map(|message| match message {
            Message::GetHeaders(request) => request
                .locator_hashes
                .first()
                .map(|hash| Hash256::from_le_bytes(hash.as_byte_array())),
            _ => None,
        })
    }

    // P2P-10, P2P-07, SYNC-01
    #[test]
    fn winning_replay_admits_at_most_four_thousand_headers_per_tick() -> Result<(), TestError> {
        let fixture = fixture(5_000, 6_000)?;
        let mut candidate = candidate(&fixture)?;
        for page in fixture.fork.chunks(2_000) {
            receive(&mut candidate, page, true)?;
        }
        assert_eq!(candidate.phase(), HeaderCandidatePhase::Redownloading);
        for page in fixture.fork.chunks(2_000) {
            receive(&mut candidate, page, true)?;
        }
        assert!(candidate.has_verified_headers());
        install(&fixture, candidate);
        let before = fixture.chain.block_tree_reader().read().len();
        fixture.sync.drain_inbound_headers();
        assert_eq!(
            fixture.chain.block_tree_reader().read().len() - before,
            4_000
        );
        let scheduler = fixture.sync.scheduler.lock();
        let owned = scheduler
            .headers_sync
            .get(&fixture.source)
            .ok_or("missing local replay")?;
        assert!(owned.has_local_replay());
        assert!(owned.request.is_none());
        drop(scheduler);
        assert!(fixture.outbound.is_empty());
        fixture.sync.drain_inbound_headers();
        assert_eq!(
            fixture
                .chain
                .header_tip()
                .ok_or("missing winning tip")?
                .height,
            6_000
        );
        assert_eq!(
            first_locator(&fixture.outbound),
            Some(Hash256::from(fixture.fork[5_999].compute_hash()))
        );
        Ok(())
    }

    // P2P-10, SYNC-01
    #[test]
    fn authenticated_fifo_wait_does_not_expire_as_network_silence() -> Result<(), TestError> {
        let fixture = fixture(2, 3)?;
        let mut first = candidate(&fixture)?;
        receive(&mut first, &fixture.fork, false)?;
        let mut waiting = candidate(&fixture)?;
        receive(&mut waiting, &fixture.fork, false)?;
        receive(&mut waiting, &fixture.fork, false)?;
        install(&fixture, waiting);
        fixture.sync.drain_inbound_headers();
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .headers_sync
                .get(&fixture.source)
                .is_some_and(|owned| owned.has_local_replay() && owned.request.is_none())
        );
        let now = Instant::now() + Duration::from_mins(30);
        fixture.sync.retire_timed_out_header_syncs(now);
        for elapsed in [0, 21, 24] {
            let now = now + Duration::from_mins(elapsed);
            let frontier = fixture
                .sync
                .observe_frontier(fixture.sync.observe_chain_frontier(), now);
            fixture.sync.sweep_chain_sync(&frontier, now);
        }
        assert!(fixture.sync.peer_table.is_current(fixture.source));
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .chain_sync
                .get(&fixture.source)
                .is_none()
        );
        assert!(fixture.outbound.is_empty());
        drop(first);
        fixture.sync.drain_inbound_headers();
        assert_eq!(
            fixture
                .chain
                .header_tip()
                .ok_or("missing replay tip")?
                .height,
            3
        );
        Ok(())
    }

    // P2P-10
    #[test]
    fn winning_network_wait_expires_with_no_authenticated_prefix() -> Result<(), TestError> {
        for incomplete_redownload in [false, true] {
            let fixture = fixture(2_000, 4_000)?;
            let mut candidate = candidate(&fixture)?;
            if incomplete_redownload {
                for page in fixture.fork.chunks(2_000) {
                    receive(&mut candidate, page, true)?;
                }
                receive(&mut candidate, &fixture.fork[..2_000], true)?;
                assert_eq!(candidate.phase(), HeaderCandidatePhase::Redownloading);
            }
            assert!(!candidate.has_verified_headers());
            install(&fixture, candidate);
            fixture.sync.resume_owned_header_requests();
            assert!(first_locator(&fixture.outbound).is_some());
            assert!(
                fixture
                    .sync
                    .scheduler
                    .lock()
                    .headers_sync
                    .get(&fixture.source)
                    .is_some_and(|owned| !owned.has_local_replay() && owned.request.is_some())
            );
            fixture.sync.retire_timed_out_header_syncs(
                Instant::now() + HEADER_REQUEST_TIMEOUT + Duration::from_secs(1),
            );
            assert!(!fixture.sync.peer_table.is_current(fixture.source));
            assert!(
                !fixture
                    .sync
                    .scheduler
                    .lock()
                    .headers_sync
                    .contains_key(&fixture.source)
            );
        }
        Ok(())
    }

    // P2P-10, BUD-02
    #[test]
    fn saturated_winning_request_retries_its_own_locator() -> Result<(), TestError> {
        let fixture = fixture(2_000, 2_001)?;
        let mut candidate = candidate(&fixture)?;
        receive(&mut candidate, &fixture.fork[..2_000], true)?;
        assert_eq!(candidate.phase(), HeaderCandidatePhase::Verifying);
        install(&fixture, candidate);
        let hold = hog(&fixture.aggregate, 4096);
        fixture.sync.resume_owned_header_requests();
        assert!(fixture.outbound.is_empty());
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .headers_sync
                .get(&fixture.source)
                .is_some_and(|owned| owned.mode.is_some() && owned.request.is_none())
        );
        assert_eq!(
            fixture.sync.send_getheaders(
                fixture.source,
                2_000,
                2_001,
                fixture.sync.build_locator(),
            ),
            GetheadersOutcome::Failed
        );
        assert!(fixture.sync.peer_table.is_current(fixture.source));
        drop(hold);
        fixture.sync.resume_owned_header_requests();
        assert_eq!(
            first_locator(&fixture.outbound),
            Some(Hash256::from(fixture.fork[1_999].compute_hash()))
        );
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .headers_sync
                .get(&fixture.source)
                .is_some_and(|owned| owned.mode.is_some() && owned.request.is_some())
        );
        Ok(())
    }
    // P2P-06, P2P-10
    #[test]
    fn body_carried_headers_preserve_a_winning_candidate() -> Result<(), TestError> {
        let fixture = fixture(2_000, 2_001)?;
        let mut candidate = candidate(&fixture)?;
        receive(&mut candidate, &fixture.fork[..2_000], true)?;
        install(&fixture, candidate);
        fixture.sync.resume_owned_header_requests();
        let expected = Hash256::from(fixture.fork[1_999].compute_hash());
        assert_eq!(first_locator(&fixture.outbound), Some(expected));
        let genesis = bitcoin_rs_consensus::primitives::Network::Regtest
            .genesis_block()
            .header;
        for header in std::iter::once(genesis).chain(fixture.fork[..9].iter().copied()) {
            fixture
                .inbound_headers
                .send(InboundHeaders {
                    headers: vec![header],
                    source: Some(fixture.source),
                    wire_response: false,
                })
                .map_err(|_| TestError::message("body-header queue closed"))?;
        }
        fixture.sync.drain_inbound_headers();
        let scheduler = fixture.sync.scheduler.lock();
        let owned = scheduler
            .headers_sync
            .get(&fixture.source)
            .ok_or("missing winning owner")?;
        let Some(HeaderSyncMode::Winning(candidate)) = owned.mode.as_ref() else {
            return Err(TestError::message(
                "body traffic discarded the winning owner",
            ));
        };
        assert_eq!(candidate.phase(), HeaderCandidatePhase::Verifying);
        assert_eq!(candidate.height(), 2_000);
        assert_eq!(candidate.locator().first(), Some(&expected));
        assert_eq!(
            owned.request.map(|request| request.locator_tip_hash),
            Some(expected)
        );
        assert!(fixture.outbound.is_empty());
        Ok(())
    }

    // P2P-10, SYNC-01
    #[test]
    fn reorged_winning_continuations_restart_without_peer_blame() -> Result<(), TestError> {
        for redownload in [false, true] {
            let fixture = fixture(2_000, 4_000)?;
            let mut candidate = candidate(&fixture)?;
            receive(&mut candidate, &fixture.fork[..2_000], true)?;
            if redownload {
                receive(&mut candidate, &fixture.fork[2_000..], true)?;
                receive(&mut candidate, &fixture.fork[..2_000], true)?;
            }
            let expected = Hash256::from(fixture.fork[1_999].compute_hash());
            install(&fixture, candidate);
            fixture.sync.resume_owned_header_requests();
            assert_eq!(first_locator(&fixture.outbound), Some(expected));
            let (alternative, active_hash) = {
                let reader = fixture.chain.block_tree_reader();
                let tree = reader.read();
                let tip = tree.tip().ok_or("missing active branch")?;
                let first = tree
                    .node_at_height_from(tip.tip_id, 1)
                    .ok_or("missing alternate header")?;
                (tree.node(first)?.header, tip.hash)
            };
            fixture
                .inbound_headers
                .send(InboundHeaders {
                    headers: vec![alternative],
                    source: Some(fixture.source),
                    wire_response: true,
                })
                .map_err(|_| TestError::message("alternate header queue closed"))?;
            fixture.sync.drain_inbound_headers();
            assert!(
                fixture.sync.peer_table.is_current(fixture.source),
                "a valid reorged continuation must keep its source connected"
            );
            assert_eq!(first_locator(&fixture.outbound), Some(active_hash));
            assert!(
                fixture
                    .sync
                    .scheduler
                    .lock()
                    .headers_sync
                    .get(&fixture.source)
                    .is_some_and(|owned| owned.mode.is_none() && owned.request.is_some())
            );
            assert_eq!(
                fixture
                    .chain
                    .header_tip()
                    .ok_or("missing unchanged tip")?
                    .hash,
                active_hash
            );
        }
        Ok(())
    }

    // P2P-10, SYNC-01
    #[test]
    fn locally_cancelled_candidate_drops_its_old_network_deadline() -> Result<(), TestError> {
        struct NoBodyChanges;
        impl bitcoin_rs_chain::reorg::ReorgObserver for NoBodyChanges {
            fn disconnected(&mut self, _: &bitcoin_rs_chain::DisconnectOutcome) {
                panic!("header-only invalidation disconnected a body");
            }
            fn connected(
                &mut self,
                _: &bitcoin_rs_consensus::primitives::BlockImage,
                _: &bitcoin_rs_chain::ConnectOutcome,
            ) {
                panic!("header-only invalidation connected a body");
            }
            fn reconsider_disconnected(
                &mut self,
                _: &bitcoin_rs_consensus::primitives::BlockImage,
            ) {
                panic!("header-only invalidation reconsidered a body");
            }
        }
        let fixture = fixture(2, 3)?;
        install(&fixture, candidate(&fixture)?);
        fixture.sync.resume_owned_header_requests();
        assert!(first_locator(&fixture.outbound).is_some());
        let invalidated = {
            let reader = fixture.chain.block_tree_reader();
            let tree = reader.read();
            let tip = tree.tip().ok_or("missing main branch")?;
            let first = tree
                .node_at_height_from(tip.tip_id, 1)
                .ok_or("missing invalidation root")?;
            tree.node(first)?.hash
        };
        bitcoin_rs_chain::reorg::invalidate_block(
            &fixture.chain,
            &mut NoBodyChanges,
            invalidated,
            |_, outcome| outcome,
        )
        .map_err(|error| TestError::message(error.to_string()))?;
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .headers_sync
                .get(&fixture.source)
                .is_some_and(|owned| owned.has_cancelled_candidate() && owned.request.is_some())
        );
        fixture.sync.retire_timed_out_header_syncs(
            Instant::now() + HEADER_REQUEST_TIMEOUT + Duration::from_secs(1),
        );
        assert!(
            fixture.sync.peer_table.is_current(fixture.source),
            "local candidate cancellation must not blame its peer"
        );
        fixture.sync.drain_inbound_headers();
        assert_eq!(
            first_locator(&fixture.outbound),
            Some(bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block_hash())
        );
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .headers_sync
                .get(&fixture.source)
                .is_some_and(|owned| owned.mode.is_none() && owned.request.is_some())
        );
        Ok(())
    }
}
