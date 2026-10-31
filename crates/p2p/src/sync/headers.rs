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
use super::{BlockSync, SchedulerState};
use crate::InboundHeaders;
use crate::Message;
use crate::PeerSource;
use crate::download_window::SyncPeer;
use crate::peer_info::PeerInfo;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_chain::{ChainError, NodeId, NodeStatus, validate_pow};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use std::time::Instant;
use std::vec::Vec;

const MAX_UNRESOLVED_DEMONSTRATED_TIPS: usize = 8;

pub(super) const MAX_HEADER_BATCHES_PER_TICK: usize = 32;
/// Stop between whole batches, never in a download-twice response page.
/// A final protocol-bounded batch can exceed this by at most 1,999 headers.
pub(super) const MAX_HEADERS_PER_TICK: usize = 2 * crate::wire::MAX_HEADERS_MESSAGE_COUNT;

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
                        .is_some_and(|owned| owned.presync.is_some())
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
                let demoted = bitcoin_rs_chain::header_sync::demoted_tip_after_rejection(
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
                self.request_ancestry_after_refusal(source, error.as_ref());
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
        if chain.apply_halted {
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
        error: &(dyn core::error::Error + Send + Sync),
    ) {
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
            owned.presync = None;
        }
        let prune = scheduler
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_none() && owned.presync.is_none());
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
            .is_some_and(|owned| owned.presync.is_none())
        {
            scheduler.headers_sync.remove(&source);
        }
        if scheduler.header_request_owner == Some(source) {
            scheduler.header_request_owner = None;
        }
    }

    fn clear_presync_for(&self, source: PeerSource) -> Option<HeadersSyncState> {
        let mut scheduler = self.scheduler.lock();
        let state = scheduler
            .headers_sync
            .get_mut(&source)
            .and_then(|owned| owned.presync.take());
        if scheduler
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_none() && owned.presync.is_none())
        {
            scheduler.headers_sync.remove(&source);
        }
        state
    }

    pub(super) fn retire_timed_out_header_syncs(&self, now: Instant) {
        let below_floor = self.below_header_work_floor();
        let expired: Vec<_> = {
            let mut scheduler = self.scheduler.lock();
            let expired: Vec<_> = scheduler
                .headers_sync
                .iter()
                .filter_map(|(source, owned)| {
                    let request = owned.request?;
                    (request.state == HeaderRequestState::AwaitingResponse
                        && (below_floor || owned.presync.is_some())
                        && now.saturating_duration_since(request.requested_at) >= request.timeout())
                    .then_some(*source)
                })
                .collect();
            // Receipt and timeout settle under the same request-state lock.
            for source in &expired {
                scheduler.clear_headers_sync_for(*source);
            }
            expired
        };
        for source in expired {
            self.peer_table.disconnect_source(source);
            tracing::debug!(peer_addr = ?source.endpoint, "block sync: header sync request timed out");
        }
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
        headers: &[bitcoin_rs_primitives::Header],
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
                .is_some_and(|owned| owned.presync.is_some())
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
        source: crate::PeerSource,
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
        source: crate::PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
        kind: HeaderRequestKind,
    ) -> GetheadersOutcome {
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
            Err(crate::OutboundRefusal::Saturated(_)) => {
                tracing::debug!(
                    peer_addr = ?source.endpoint,
                    "block sync: getheaders deferred; node outbound budget is full"
                );
                return GetheadersOutcome::Failed;
            }
            Err(crate::OutboundRefusal::Closed(_)) => {
                tracing::warn!(
                    peer_addr = ?source.endpoint,
                    "block sync: outbound channel disconnected"
                );
                self.peer_table.disconnect_source(source);
                self.scheduler.lock().clear_headers_sync_for(source);
                return GetheadersOutcome::Failed;
            }
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
                if below_floor || owned.presync.is_some() || unexpired =>
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
                self.clear_presync_for(source);
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
                    .and_then(|owned| owned.presync.take())
            };
            let mut state = if let Some(state) = parked {
                state
            } else {
                let Some(anchor) = self.presync_anchor(headers) else {
                    return Some(self.chain.admit_headers(headers));
                };
                let minimum_work = self.chain.minimum_chain_work();
                let params = anchor.network.headers_sync_params();
                HeadersSyncState::new(anchor, minimum_work, params, presync_salt())
            };
            let outcome = Self::advance_presync_state(&mut state, headers, batch_len);
            if self.peer_table.is_current(source) {
                self.scheduler
                    .lock()
                    .headers_sync
                    .entry(source)
                    .or_default()
                    .presync = Some(state);
            }
            outcome
        };
        if outcome.finished {
            self.clear_presync_for(source);
        }
        if let Some(error) = outcome.failure {
            self.clear_presync_for(source);
            self.settle_presync_fault(source, error);
            return None;
        }
        if outcome.finished && !outcome.request_more && outcome.ready_headers.is_empty() {
            self.peer_table.note_headers_horizon(source, outcome.height);
        } else {
            self.peer_table
                .note_headers_progress(source, outcome.height);
        }
        if outcome.request_more {
            self.send_presync_getheaders(source, outcome.locator, outcome.height);
        }
        if !outcome.ready_headers.is_empty() {
            let admission = self.chain.admit_headers(&outcome.ready_headers);
            if let HeaderAdmission::Refused(error) = admission {
                let dropped = self.clear_presync_for(source);
                if let Some(mut state) = dropped {
                    state.finalize();
                }
                self.request_ancestry_after_refusal(Some(source), error.as_ref());
                return None;
            }
            return Some(admission);
        }
        None
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
                bitcoin_rs_chain::validate_contextual_header(
                    &tree,
                    parent_id,
                    header,
                    network,
                    bitcoin_rs_chain::current_unix_seconds(),
                    bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
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
                bitcoin_rs_chain::validate_contextual_header(
                    &tree,
                    first_parent,
                    &headers[0],
                    network,
                    bitcoin_rs_chain::current_unix_seconds(),
                    bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
                )
            })
            .is_err()
    }

    fn advance_presync_state(
        state: &mut HeadersSyncState,
        headers: &[Header],
        batch_len: usize,
    ) -> PresyncOutcome {
        let (failure, request_more, ready_headers, finished) =
            match state.process(headers, batch_len >= crate::wire::MAX_HEADERS_MESSAGE_COUNT) {
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

    fn presync_anchor(&self, headers: &[Header]) -> Option<HeaderAnchor> {
        let first = headers.first()?;
        let network = self.chain.network();
        let minimum_work = self.chain.minimum_chain_work();
        let tree = self.chain.block_tree();
        let fork_id = tree.lookup(Hash256::from(first.prev_blockhash))?;
        let fork = tree.node(fork_id).ok()?;
        if fork.status == NodeStatus::Invalid {
            return None;
        }
        let page_self_valid = headers.iter().all(|header| {
            let hash = Hash256::from(header.compute_hash());
            validate_pow(header, hash, network).is_ok()
        }) && headers.windows(2).all(|pair| {
            Hash256::from(pair[1].prev_blockhash) == Hash256::from(pair[0].compute_hash())
        });
        if page_self_valid {
            let claimed = headers.iter().fold(fork.chainwork, |sum, header| {
                sum.saturating_add(bitcoin_rs_chain::block_work(header))
            });
            if claimed >= minimum_work {
                return None;
            }
        }
        let median_time_past = tree.median_time_past_at(fork_id)?;
        Some(HeaderAnchor {
            network,
            height: fork.height,
            hash: fork.hash,
            header: fork.header,
            chain_work: fork.chainwork,
            median_time_past,
            locator: tree.block_locator(fork_id, LOCATOR_MAX_ENTRIES),
        })
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
mod stale_tip_routing_tests;
