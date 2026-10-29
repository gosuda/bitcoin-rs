//! Header request ownership, locator construction, and inbound header admission.

use super::GetdataRequestOutcome;
use super::GetheadersOutcome;
use super::HEADER_REQUEST_TIMEOUT;
use super::HeaderRequest;
use super::HeaderRequestKind;
use super::HeaderRequestState;
use super::LOCATOR_MAX_ENTRIES;
use super::chain::HeaderAdmission;
use super::chain::SyncChainError;
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

/// Cap on retained off-chain tips per session: honest peers announce one
/// chain, so more than this many distinct side branches is a misbehavior
/// signal rather than evidence worth keeping.
const MAX_UNRESOLVED_DEMONSTRATED_TIPS: usize = 8;

/// One batch's result from a connection's download-twice sync state.
struct PresyncOutcome {
    failure: Option<HeaderSyncError>,
    request_more: bool,
    ready_headers: Vec<Header>,
    locator: Vec<Hash256>,
    height: u32,
    finished: bool,
}

impl BlockSync {
    #[expect(clippy::too_many_lines)]
    pub(super) fn drain_inbound_headers(&self) {
        let mut total_headers = 0_usize;
        let mut credit_refresh_needed = false;
        // Near-tip batches whose body the announcing connection can serve
        // straight away; drained after the loop with one frontier read.
        let mut direct_fetch: Vec<(PeerSource, Hash256)> = Vec::new();
        while let Ok(InboundHeaders {
            headers,
            source,
            wire_response,
        }) = self.inbound_headers_rx.try_recv()
        {
            if source.is_some_and(|source| !self.peer_table.is_current(source)) {
                continue;
            }
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);

            self.consume_header_request(source, wire_response, headers.is_empty());

            // A connection with a live download-twice state must feed its
            // page to that state even when the tree already holds it:
            // bypassing the state leaves its cursor behind and the next
            // page breaks continuity against a stale position.
            let feeds_live_sync = wire_response
                && source.is_some_and(|source| {
                    self.scheduler
                        .lock()
                        .headers_sync
                        .get(&source)
                        .is_some_and(|owned| owned.presync.is_some())
                });

            // Already-known batches skip the transition lock. The listener
            // forwards every inbound body's embedded header here so
            // unannounced tips (`inv`-served, compact-reconstructed, or
            // pushed blocks) reach admission — during bulk delivery those
            // batches would otherwise pay a lock acquisition per body for
            // what is almost always a lookup hit.
            if !feeds_live_sync
                && let Some((tip_hash, active_height)) = self.known_batch_outcome(&headers)
            {
                // A known batch displaces nothing, but its newest header can
                // be a stale branch tip the retainer has not seen.
                self.record_admitted_tips(None, Some(tip_hash), source);
                if let Some(source) = source {
                    self.peer_table
                        .note_announced_tip(source, tip_hash, active_height);
                    credit_refresh_needed = true;
                    // The compact path may already own this body through
                    // `enqueue_owned_body_fetch`; a second window request
                    // would duplicate the fetch it already issued.
                    if wire_response && !self.owns_body_fetch(source, tip_hash) {
                        direct_fetch.push((source, tip_hash));
                    }
                }
                continue;
            }

            // A batch whose fork point has not yet demonstrated the
            // network's minimum chain work is retained by that connection's
            // download-twice header sync; only headers the committed phase
            // releases — and batches at or above the threshold — reach
            // admission here. Snapshot the tip so a rejection that still
            // committed a higher-work prefix can preserve the tip it
            // displaced (see `demoted_tip_after_rejection`).
            let pre_tip = self.chain.chain_tip().map(|tip| tip.hash);
            let Some(admission) =
                self.route_headers_batch(&headers, source, wire_response, batch_len)
            else {
                continue;
            };
            // A rejected batch can still have inserted a valid higher-work
            // prefix and moved the tip; the `Err` reports no displacement, so
            // infer it from the tip movement and retain the old tip for
            // stale-tip relay instead of losing it.
            if matches!(&admission, HeaderAdmission::Rejected(_)) {
                let demoted = bitcoin_rs_chain::header_sync::demoted_tip_after_rejection(
                    &self.chain.block_tree(),
                    pre_tip,
                );
                if let Some(demoted) = demoted {
                    self.record_demoted_tip(demoted);
                }
            }
            match admission {
                HeaderAdmission::Accepted {
                    accepted,
                    announced_tip,
                    active_height,
                    demoted_tip,
                } => {
                    // The tip this batch displaced and the batch's own tip
                    // are the stale-tip relay's candidates; the retainer
                    // re-reads the tree for every fact it ranks by.
                    self.record_admitted_tips(demoted_tip, announced_tip, source);
                    if let (Some(tip_hash), Some(source)) = (announced_tip, source) {
                        self.peer_table
                            .note_announced_tip(source, tip_hash, active_height);
                        // Same owned-fetch guard as the known-batch path: skip
                        // the direct fetch when the compact path already owns
                        // the body so one announcement never issues two
                        // `getdata` requests for the same hash.
                        if wire_response && !self.owns_body_fetch(source, tip_hash) {
                            direct_fetch.push((source, tip_hash));
                        }
                    }
                    credit_refresh_needed = true;
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
                        self.clear_headers_sync_for(source);
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
                    // A batch that cannot attach (`MissingParent`,
                    // `NoCommonAncestor`) proves the announcer knows a chain
                    // beyond our tip: ask it for the missing ancestry so a
                    // later batch lands instead of wedging the live tip
                    // behind one missed header. Other non-fault rejections
                    // (`TimestampTooFarAhead`, `DuplicateHeader`) get no
                    // re-request — the announcer would only replay the same
                    // batch into the same rejection, which paces no one.
                    if matches!(
                        error,
                        ChainError::MissingParent { .. } | ChainError::NoCommonAncestor { .. }
                    ) {
                        // A header carried by a delivered body is not a
                        // response to the pending request, and the delivery
                        // itself is the new evidence that this connection
                        // holds the missing ancestry. The pending gate is
                        // left alone either way: `send_getheaders` suppresses
                        // an identical ask while one is unexpired, so an
                        // unanswering peer's original deadline keeps ticking
                        // and `header_request_live` still frees the slot when
                        // it elapses. Clearing a live gate here would let
                        // every delivered body install a fresh `requested_at`
                        // and pin header sync to a peer that never answers.
                        self.request_headers_from(source);
                    }
                    tracing::warn!(
                        received = batch_len,
                        %error,
                        "block sync: rejected inbound headers batch",
                    );
                }
                HeaderAdmission::Refused(error) => {
                    // Admission is paused (checkpoint publish or shutdown).
                    // The source still has the headers; a paced re-request
                    // relearns the tip once admission reopens rather than
                    // silently losing the announcement.
                    self.request_ancestry_after_refusal(source, &error);
                }
            }
        }
        if credit_refresh_needed {
            self.refresh_active_peer_credit();
        }
        // The drain may have attached the ancestry a deferred owned fetch
        // was waiting on — resolve it against the tree now.
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

    /// Applies every queued `MSG_BLOCK` announcement to the announcing
    /// connection's header-sync state, as Core does in
    /// `net_processing.cpp:4370-4410`.
    ///
    /// PRE: entries were queued by [`BlockSync::announce_block`].
    /// POST: a hash already in the tree credits its connection with that tip
    /// and refreshes active-peer credit; a hash the tree does not know asks
    /// that connection for headers. No block body is requested here.
    /// INVARIANT: block inventory never bypasses header admission and the
    /// download-window budget.
    fn drain_block_announcements(&self) {
        let pending = std::mem::take(&mut *self.block_announcements.lock());
        if pending.is_empty() {
            return;
        }
        let mut credit_refresh_needed = false;
        // The frontier request has one pacing owner: asking a second peer
        // before the first answers would orphan that owner's request from
        // discovery, so unknown announcements queue back for a later drain.
        let mut deferred: Vec<(PeerSource, Hash256)> = Vec::new();
        for (source, hash) in pending {
            if !self.peer_table.is_current(source) {
                continue;
            }
            // The tree read is scoped so no lock is held across the peer
            // table or the outbound send the unknown case performs.
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
                // The captured announcement predates anything the listener
                // queued while this drain ran — the first unprocessed
                // announcement wins, so it must overwrite, not defer to, a
                // hash enqueued mid-drain.
                announcements.insert(source, hash);
            }
        }
        if credit_refresh_needed {
            self.refresh_active_peer_credit();
        }
    }

    /// Requests the body of a freshly announced near-tip header from the
    /// connection that proved it, without waiting for the next scheduler
    /// tick. Core direct-fetches in the same situation
    /// (`HeadersDirectFetchBlocks`, `net_processing.cpp:3098-3158`, gated by
    /// `CanDirectFetch` at `:1450-1453`).
    ///
    /// PRE: `source` is the connection that delivered `announced_tip`.
    /// POST: the eligible body is requested through
    /// `send_getdata_for_pending_blocks`, so the download window owns the
    /// pending hash before this returns; a failed guard requests nothing.
    /// INVARIANT: the request stays inside the existing window, per-peer, and
    /// byte budgets, and work too deep below the header tip — a bulk download
    /// or a large reorg — is left to the ordinary tick scheduler.
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
        // "Close to synced", in height terms: the block the apply frontier
        // needs must sit within the near-tip window of the header tip, and
        // the announced tip must reach at least that far.
        if chain_tip.height.saturating_sub(required.height) >= COMPACT_RELAY_NEAR_TIP_BLOCKS
            || height < required.height
        {
            return GetdataRequestOutcome::default();
        }
        self.send_getdata_for_pending_blocks(source, false, height, chain)
    }

    /// Height of `hash` when it lies on the branch that ends at `tip`, and
    /// `None` when the tree does not know it or it belongs to another branch.
    fn tip_height_on_active_branch(&self, tip: NodeId, hash: Hash256) -> Option<u32> {
        let tree = self.chain.block_tree();
        let node_id = tree.lookup(hash)?;
        let height = tree.node(node_id).ok()?.height;
        tree.node_at_height_from(tip, height)
            .is_some_and(|on_branch| on_branch == node_id)
            .then_some(height)
    }

    /// Re-requests header ancestry from `source` after a `Refused`
    /// admission, paced to the request timeout: while admission stays
    /// closed each response clears its pending slot and re-refuses, so an
    /// unpaced retry would replay the same batch at round-trip pace.
    fn request_ancestry_after_refusal(&self, source: Option<PeerSource>, error: &SyncChainError) {
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

    /// Updates the request lifecycle from a wire `headers` response on its
    /// exact connection. An empty response preserves the original pacing
    /// deadline but is no longer unanswered; a nonempty response removes
    /// that source's request. Headers forwarded out of a delivered body
    /// (`wire_response = false`) are not a response.
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

    /// Clears only the wire request, retaining a live presync cursor.
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

    fn clear_headers_sync_for(&self, source: PeerSource) {
        let mut scheduler = self.scheduler.lock();
        scheduler.headers_sync.remove(&source);
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

    /// A timed-out download-twice cursor cannot be retried on the same
    /// connection: the wire has no request IDs to disambiguate late pages.
    pub(super) fn retire_timed_out_header_syncs(&self, now: Instant) {
        let below_floor = self.below_header_work_floor();
        let expired: Vec<_> = {
            let scheduler = self.scheduler.lock();
            scheduler
                .headers_sync
                .iter()
                .filter_map(|(source, owned)| {
                    let request = owned.request?;
                    (request.state == HeaderRequestState::AwaitingResponse
                        && (below_floor || owned.presync.is_some())
                        && now.saturating_duration_since(request.requested_at) >= request.timeout())
                    .then_some(*source)
                })
                .collect()
        };
        for source in expired {
            self.peer_table.disconnect_source(source);
            self.clear_headers_sync_for(source);
            tracing::debug!(peer_addr = ?source.endpoint, "block sync: header sync request timed out");
        }
    }

    fn below_header_work_floor(&self) -> bool {
        let minimum_work = self.chain.minimum_chain_work();
        self.chain
            .chain_tip()
            .is_none_or(|tip| tip.chainwork < minimum_work)
    }

    /// Resolves deferred owned-fetch marks now that this drain may have
    /// admitted the ancestry their tips were waiting on.
    ///
    /// PRE: runs on the sync thread, outside every lock.
    /// POST: a mark whose header is in the tree and whose connection is
    ///   current becomes a window pending (or stays a mark when the window
    ///   refuses it, or another connection already owns the hash); a mark
    ///   whose connection left is dropped; a mark whose header is unknown
    ///   stays.
    /// INVARIANT: a mark is the proof of a matched outstanding request, so
    ///   it never leaves the scheduler while it resolves. The tree and peer
    ///   table reads run on a snapshot outside the scheduler lock. Each
    ///   install holds exact-source peer authority across the scheduler lock
    ///   and rechecks its mark under the same lock hold that installs it:
    ///   a mark released since the snapshot (the exact owner's `notfound`, a
    ///   session sweep, an eviction) installs nothing, so a stale snapshot
    ///   can never re-create a request the owner already declined. A
    ///   `notfound` that lands anywhere in the resolve therefore finds the
    ///   mark or, after the install, the window pending it became.
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
                // A stale source names a dead connection: its fetch died
                // with it, so the mark must neither settle a staged body's
                // gate nor mark it pending under the dead owner.
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

    /// Publishes a resolved snapshot only while its exact connection and its
    /// authoritative deferred mark are both still live. Lock order is peer
    /// table then scheduler, matching request publication and `notfound`.
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
            // Recheck under the lock that installs: a mark released since the
            // snapshot is gone and must not become a pending request.
            let Some(index) = owned_body_fetches
                .iter()
                .position(|mark| *mark == (source, hash))
            else {
                return;
            };
            // A refusal leaves the fetch in flight: keep the deferred mark so
            // the delivered body still classifies as requested. So does a
            // hash already pending under a different owner — `mark_owned_fetch`
            // resolves it without recording this owner, and dropping the mark
            // would disown the second connection's in-flight fetch.
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

    /// `(announced_tip, active_height)` when every header in `headers` is
    /// already in the tree — the same credit outcome `admit_headers` would
    /// produce, without taking the transition lock for a lookup hit.
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

    /// Asks `source` for the header ancestry past our tip.
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

    /// Asks any live full-witness peer for the header ancestry past our tip.
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
        // Partition each session's retained tips into unresolved (fork
        // evidence that must be kept until the branch wins or dies) and
        // resolved. Only the max-resolving tip carries the active-chain
        // evidence — resolved tips below it are dead weight the scalar
        // watermark already covers. Forwarded body headers (P2P-06) push a
        // tip per delivered body, so without pruning this record would grow
        // with every download. Unresolved tips are deduplicated per branch
        // and capped — shared-ancestor resolution (P2P-03) still lets each
        // kept fork tip attest the deepest prefix it shares with the active
        // chain.
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
                    // Keep the maximal unresolved tip per branch, deepest
                    // first — a kept descendant's evidence subsumes its
                    // ancestors, so redundant entries are skipped.
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

    /// Requests the next header batch from the highest usable peer above the
    /// applied tip, using a locator taken after `drain_inbound_headers` so it
    /// reflects headers accepted this tick.
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

    /// P2P-05: probes the capability frontier at the applied anchor through
    /// `source` — the peer `SyncFrontier::probe_pick` selected this tick.
    ///
    /// The probe fires only while the canonical next-required body is
    /// unowned (`HeaderAction::Probe`): staged successors behind an unowned
    /// or rejected frontier are stuck inventory awaiting the staged-body
    /// timeout, not progress. The locator anchors on the active chain at
    /// the applied height, not on the applied tip's branch: during a deep
    /// header-first reorg the applied tip may still sit on the losing
    /// branch, and a locator from that branch can match only at a common
    /// ancestor more than the 2,000-header wire page behind us.
    pub(super) fn probe_frontier_peer(
        &self,
        frontier: &SyncFrontier,
        source: PeerSource,
    ) -> GetheadersOutcome {
        if frontier.chain.applied_tip.is_none() || frontier.chain.chain_tip.is_none() {
            return GetheadersOutcome::Failed;
        }
        // The plan's Probe decision was taken at observation time; a body
        // request scheduled since may already own the frontier, in which
        // case capability discovery has nothing left to resolve and nothing
        // was sent to this connection.
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

    /// Sends one `getheaders` for the chain-sync eviction probe without
    /// claiming the frontier request owner. A live presync cursor defers the
    /// probe; the common request gate handles wire-request ownership.
    ///
    /// PRE: `source` names a live subject connection.
    /// POST: return the wire outcome; only an unowned connection receives
    ///   an eviction probe.
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
        // Core anchors this probe at the best header's parent
        // (`net_processing.cpp` ConsiderEviction) so the answer can carry
        // the header tip the eviction benchmark is measured against. The
        // applied anchor cannot reach it while IBD lags by more than one
        // headers page — a correct answer there would credit only the
        // applied side and retire a peer that answered honestly.
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

    /// The `getheaders` envelope both probes share: `our_height` is the
    /// applied tip's height, `target_height` the chain tip's, and the
    /// locator anchors on the active chain at the applied height.
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

    /// Sends `getheaders` to the exact connection `source` identifies and
    /// registers the request under that connection's ownership.
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

    /// Every request is registered under its exact connection. Its kind
    /// selects the response timeout and whether it claims the frontier owner.
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
        // The wire version of `getheaders` is the rust-bitcoin protocol
        // constant (70001), independent of the version this node advertises
        // in `version`; log the field that is actually sent.
        let getheaders_version = getheaders.version;
        let msg = Message::GetHeaders(getheaders);
        // `send_then` holds the connection's identity through the enqueue
        // and the pending stamp under one table authority, so a replacement
        // slipping in between cannot leave a request registered to a dead
        // connection.
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
                // A continuation from a different peer must not replace
                // the frontier request its current owner still owes.
                let can_claim_owner = scheduler.header_request_owner.is_none_or(|owner| {
                    owner == source
                        || scheduler
                            .headers_sync
                            .get(&owner)
                            .and_then(|owned| owned.request)
                            .is_none_or(|request| {
                                now.saturating_duration_since(request.requested_at)
                                    >= request.timeout()
                            })
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
                // The node's aggregate outbound budget is full while this
                // connection is healthy: nothing was queued and nothing was
                // stamped, so the next tick rebuilds the request from the
                // then-current locator. The peer stays connected and keeps
                // its sync state.
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
                // The send failure means this connection is gone: evict it so
                // the scheduler cannot re-pick a dead peer every tick. The
                // identity check inside `disconnect_source` keeps a
                // same-address replacement untouched, and the exact-source
                // lifecycle is dropped so a fast reconnect does not inherit
                // stale sync state.
                self.peer_table.disconnect_source(source);
                self.clear_headers_sync_for(source);
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

    /// An unanswered request owns its exact connection while its ordinary
    /// timeout is live, and indefinitely below the work floor or during a
    /// download-twice sync. An answered request only paces an identical
    /// locator and target until its original deadline.
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

    /// Routes one inbound batch to direct admission or to the delivering
    /// connection's download-twice header sync.
    ///
    /// PRE: `headers` is the received batch, `source` its delivering
    ///   connection when known, `wire_response` says whether the batch is
    ///   a genuine wire `headers` message, and `batch_len` is the received
    ///   size.
    /// POST: only a wire batch touches the sync state: a batch from a
    ///   connection with a live state always routes into that state — the
    ///   state, not the tree, owns the connection's chain — and a wire
    ///   batch on a below-floor fork opens one. A body-carried batch
    ///   (`wire_response = false`) never opens or feeds the state: below
    ///   the work floor, a valid one-header batch returns `None` and retries
    ///   after the wire sync commits it; invalid body-carried headers and
    ///   batches at or above the floor take direct admission. Otherwise
    ///   return `Some` with the admission outcome when the batch may be
    ///   admitted directly — an empty batch, source-less delivery, unknown
    ///   fork, or fork already at the network minimum — or when the
    ///   committed phase released headers; and `None` when the sync state
    ///   retained the batch, in which case the drain already consumed the
    ///   wire request and this call sent the state-cursor continuation or ran
    ///   the fault path.
    /// A stale wire batch also returns `None` before sync state or admission
    /// is touched.
    /// INVARIANT: a body-carried header is deferred below the work floor
    ///   only after standalone `PoW` and contextual validation pass; wire
    ///   batches reach admission below the floor only as
    ///   [`super::headers_presync::HeaderSyncResult::ready_headers`], and
    ///   only a wire `headers` message mutates the nested presync state.
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
            // An empty answer ends a live download-twice sync — the peer
            // has no more headers for this cursor — rather than leaving
            // the state to pace a stale request.
            if wire_response && let Some(source) = source {
                self.clear_presync_for(source);
            }
            return Some(self.chain.admit_headers(headers));
        }
        let Some(source) = source else {
            return Some(self.chain.admit_headers(headers));
        };
        // Only a genuine wire `headers` message opens or feeds the
        // download-twice state: Core feeds the sync state only from
        // processed `headers` messages (`net_processing.cpp:2915-2924`).
        // A header carried by a delivered body — a staged-body retry or a
        // drain-forwarded tip — arrives as a one-header page, and feeding
        // it to a live state would finalize the wire sync's progress (a
        // short page never asks for more) instead of advancing it. Below
        // the work floor it retires here and retries once the wire sync
        // commits it; at or above the floor, direct admission applies as
        // to any batch.
        if !wire_response {
            if self.presync_anchor(headers).is_none()
                || self.body_carried_header_needs_admission(headers)
            {
                return Some(self.chain.admit_headers(headers));
            }
            return None;
        }
        let outcome = {
            // Page validation runs without the scheduler lock: hashing a
            // full page under `scheduler` would stall body-fetch ownership
            // and every other scheduler read for its duration, so a live
            // state leaves the entry for the check and is committed back
            // while its connection is still live. The request remains in
            // the entry throughout this unlocked validation.
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
                // A fresh sync anchors on the tree's fork point, read
                // before any scheduler or transition lock is taken.
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
            // The sync ended below the floor without releasing headers: the
            // peer demonstrated it has nothing past the cursor, so cap its
            // advertised horizon there.
            self.peer_table.note_headers_horizon(source, outcome.height);
        } else {
            // A batch that advanced the verified cursor past a previous
            // cap disproves the terminal-page observation: lift the cap so
            // the connection can win selection again on its new evidence.
            self.peer_table
                .note_headers_progress(source, outcome.height);
        }
        // The inbound drain consumed the wire request before routing here.
        // Send the state-cursor continuation from that released request;
        // REDOWNLOAD may sit deeper than the release point, so reusing its
        // locator would fail continuity and restart the sync.
        if outcome.request_more {
            self.send_presync_getheaders(source, outcome.locator, outcome.height);
        }
        if !outcome.ready_headers.is_empty() {
            let admission = self.chain.admit_headers(&outcome.ready_headers);
            if let HeaderAdmission::Refused(error) = admission {
                // Admission is paused (checkpoint publish or shutdown):
                // retaining the released prefix in the live state grows
                // without bound — every refused page requeues the whole
                // excess and the next page adds another page's worth. Drop
                // the sync instead; the paced ancestry re-request restarts
                // it once admission reopens, the same retry the direct path
                // gets.
                let dropped = self.clear_presync_for(source);
                if let Some(mut state) = dropped {
                    state.finalize();
                }
                self.request_ancestry_after_refusal(Some(source), &error);
                return None;
            }
            return Some(admission);
        }
        None
    }
    /// Checks a body-carried header before deferring it below the work floor.
    ///
    /// PRE: `headers` is a body-carried batch whose parent was anchored by
    ///   [`Self::presync_anchor`].
    /// POST: return `true` when the batch is not one header, its parent is
    ///   no longer known, or its header fails proof-of-work or contextual
    ///   checks against that parent.
    /// INVARIANT: the block-tree read guard is released before the caller
    ///   enters ordinary admission.
    fn body_carried_header_needs_admission(&self, headers: &[Header]) -> bool {
        // A stale-tip announcement arrives as a multi-header batch on the
        // identified peer with `wire_response = false`: it must not bypass
        // the minimum-work hold the way a blanket `true` would. A fully
        // valid, well-linked page on a known parent defers below the floor
        // (the caller returns `None` and retries after the wire sync commits
        // it); any break in the page needs direct admission so the error —
        // and the peer fault it carries — is reported instead of silently
        // deferred.
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

    /// Whether a multi-header non-wire page (a stale-tip announcement)
    /// needs direct admission rather than deferring below the work floor.
    ///
    /// PRE: `headers` holds more than one header.
    /// POST: `true` when the page is broken — unknown first parent, unmet
    ///   proof of work, broken prev-to-hash linkage, or a contextually
    ///   invalid first header — so direct admission reports the error and
    ///   carries the peer fault; `false` when the page is a fully valid,
    ///   well-linked chain on a known, valid parent, in which case the
    ///   caller defers it below the floor instead of admitting past the
    ///   minimum-work hold.
    /// INVARIANT: reads only the block tree; later headers build on earlier
    ///   batch headers the tree does not yet hold, so only the first
    ///   header faces the contextual check — a later contextual break
    ///   defers safely without entering the tree, while a high-work page
    ///   (anchor `None`) admits directly through the caller either way.
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
        // Declared `bits` honesty and prev-to-hash continuity across the
        // whole page: a pasted tail of genuine headers after a break must
        // not read as valid.
        if headers.iter().any(|header| {
            let hash = Hash256::from(header.compute_hash());
            validate_pow(header, hash, network).is_err()
        }) || headers.windows(2).any(|pair| {
            Hash256::from(pair[1].prev_blockhash) != Hash256::from(pair[0].compute_hash())
        }) {
            return true;
        }
        // First-header contextual gate (the only one whose parent the tree
        // holds). A failure here needs admission to fault the peer.
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

    /// Feeds one batch to one connection's sync state.
    ///
    /// PRE: `state` belongs to the connection that delivered `headers`.
    /// POST: return the failure, the continuation request, the committed
    ///   headers, the sync cursor, and whether the state is spent.
    /// INVARIANT: a spent (finished or faulted) state is retired by the
    ///   caller, so the next batch from this connection starts a fresh
    ///   sync with a fresh salt rather than feeding a punished one.
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

    /// The fork point a batch builds from, when that fork is not yet worth
    /// admitting directly.
    ///
    /// PRE: none.
    /// POST: return the anchor for the batch's first header's parent when
    ///   this node holds that parent, it is not already `Invalid` (the
    ///   admission path owns that refusal), and its cumulative chainwork
    ///   plus the batch's claimed work stays below the network minimum;
    ///   return `None` when the parent is unknown (the admission path
    ///   reports the missing ancestry) or the floor is already met
    ///   (Core's `TryLowWorkHeadersSync` fast path,
    ///   `net_processing.cpp:3010-3018`).
    /// INVARIANT: the tree read closes before any scheduler or transition
    ///   lock is taken.
    fn presync_anchor(&self, headers: &[Header]) -> Option<HeaderAnchor> {
        let first = headers.first()?;
        let network = self.chain.network();
        let minimum_work = self.chain.minimum_chain_work();
        let tree = self.chain.block_tree();
        let fork_id = tree.lookup(Hash256::from(first.prev_blockhash))?;
        let fork = tree.node(fork_id).ok()?;
        // An anchor a subtree invalidation already marked `Invalid` can
        // never admit: decline it so the batch routes straight through the
        // admission path's `InvalidParent` refusal instead of opening a
        // presync that hashes and retains commitments for a doomed pass.
        if fork.status == NodeStatus::Invalid {
            return None;
        }
        // Core's `TryLowWorkHeadersSync` fast path counts the work the batch
        // itself claims (`chain_start->nChainWork +
        // CalculateClaimedHeadersWork`, `net_processing.cpp:3010-3018`): a
        // batch that crosses the floor on its own admits directly instead
        // of opening a presync that re-requests the same page after the
        // crossing.
        //
        // The claim counts declared `bits`, so it is honest only when every
        // header actually meets its target: a page ending in an unmet
        // tiny-target header inflates `claimed` and takes the direct path,
        // where admission inserts each valid prefix as it goes and never
        // rolls back on the failure — letting a reconnecting peer fill the
        // tree below the floor. The same splice inflates the sum through a
        // disconnected tail of genuine headers pasted after the break, so
        // the whole page must also link prev-to-hash before the sum is
        // trusted. A page failing either check falls through to the presync,
        // which faults the peer on it without mutating the tree.
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

    /// Continues one download-twice sync on the connection that owns it.
    ///
    /// PRE: `locator` came from that connection's live sync state and
    ///   `height` is the cursor the state has reached.
    /// POST: the next `getheaders` is sent to that exact connection and
    ///   registered under its ownership, or nothing is sent when an
    ///   identical request is already pending.
    /// INVARIANT: the continuation never re-elects a different connection:
    ///   commitments, salt, and cursor belong to the one sync.
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

    /// Settles a failed download-twice sync.
    ///
    /// PRE: `error` is why [`HeadersSyncState::process`] gave up.
    /// POST: a peer's fault disconnects the connection and releases its
    ///   request gate; a possibly benign break (a lost continuation) keeps
    ///   the connection and moves the request deadline to this answer, the
    ///   same treatment a rejected non-fault batch gets.
    /// INVARIANT: the sync state is already gone — `process` spends it on
    ///   every failure — so nothing is retained for a punished chain.
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
        self.clear_headers_sync_for(source);
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

/// The tallest header tip worth requesting from this session: the
/// demonstrated horizon when a spent low-work presync proved one, else the
/// published best-known height, `i32::MAX` while the handshake is still
/// unpublished.
fn headers_target_height(horizon: Option<u32>, info: Option<&PeerInfo>) -> i32 {
    let claimed = info.map_or(i32::MAX, |info| info.best_known_height);
    match horizon {
        Some(cap) => claimed.min(i32::try_from(cap).unwrap_or(i32::MAX)),
        None => claimed,
    }
}

/// Fresh unpredictable key material for one sync's commitment hash
/// (`headerssync.cpp:24` draws the same from a fast RNG).
///
/// PRE: none.
/// POST: return a salt from OS-seeded randomness; anything predictable
///   (clock, PID, peer address) would let a peer precompute which mutated
///   headers keep their one-bit commitments.
/// INVARIANT: one salt per sync state, and a spent state's salt is never
///   reused: every new state draws a fresh one.
fn presync_salt() -> [u8; 16] {
    use bitcoin::secp256k1::rand::RngCore as _;
    let mut salt = [0_u8; 16];
    bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod stale_tip_routing_tests {
    //! Low-work, partial-prefix, and duplicate-fetch regressions for
    //! stale-tip batches: identified-peer, non-wire batches take the same
    //! minimum-work/fault hold as ordinary headers, preserve a displaced
    //! tip on rejection, and never double-fetch an owned body.

    use super::super::BlockSync;
    use super::super::chain::HeaderAdmission;
    use super::super::chain::SyncChain;
    use super::super::chain::SyncChainError;
    use super::super::chain::WindowCommitError;
    use bitcoin_rs_chain::TipSnapshot;
    use bitcoin_rs_chain::{BlockTree, ChainWork, NodeStatus};
    use bitcoin_rs_primitives::{Hash256, Header, Network};
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
            match bitcoin_rs_chain::accept_headers(
                &mut tree,
                headers,
                self.network,
                bitcoin_rs_chain::current_unix_seconds(),
                bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
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
            _block: &bitcoin_rs_primitives::Block,
        ) -> Result<(), SyncChainError> {
            Ok(())
        }

        fn window_len(&self, _serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
            0
        }

        fn commit_window(
            &self,
            _payloads: &[&bitcoin_rs_primitives::BlockPayload],
        ) -> Result<usize, WindowCommitError> {
            Ok(0)
        }

        fn switch_to_branch(
            &self,
            _target: bitcoin_rs_chain::NodeId,
            _staged_body: &mut dyn FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
            _connected_body: &mut dyn FnMut(Hash256),
        ) -> Result<(), bitcoin_rs_chainstate::reorg::ReorgError> {
            Ok(())
        }
    }

    fn routing_sync(
        tree: BlockTree,
        floor: ChainWork,
    ) -> (
        BlockSync,
        Arc<crate::PeerTable>,
        crossbeam_channel::Sender<crate::InboundHeaders>,
    ) {
        let peers = Arc::new(crate::PeerTable::new());
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (_blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let chain: Arc<dyn SyncChain> = Arc::new(RoutingStubChain::with_floor(tree, floor));
        let sync = BlockSync::new(
            chain,
            Arc::clone(&peers),
            headers_rx,
            blocks_rx,
            crate::sync::syncing_ibd_latch(),
        );
        (sync, peers, headers_tx)
    }

    fn connected_peer(
        peers: &Arc<crate::PeerTable>,
        port: u16,
        best_height: i32,
    ) -> (crate::PeerSource, crate::test_support::MessageReceiver) {
        let (tx, rx) = crate::test_support::message_channel();
        let lease = crate::PeerLease::new(tx);
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        let endpoint = crate::PeerEndpoint::Ip(addr);
        peers.register(endpoint, lease.clone());
        let info = crate::peer_info::PeerInfo {
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
            addr_bind: crate::TransportRemote::new(addr),
            time_offset: 0,
            counters: Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
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
            let header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, height)
                .unwrap_or_else(|error| panic!("fixture mines: {error}"));
            prev = header.compute_hash();
            tip_id = tree
                .insert_node(Some(tip_id), header, NodeStatus::HeaderValid)
                .unwrap_or_else(|error| panic!("main header inserts: {error}"));
        }
        tree
    }

    /// A valid low-work multi-header stale-tip page defers below the floor
    /// instead of admitting past the minimum-work hold; a broken page needs
    /// direct admission so the fault is reported.
    #[test]
    fn low_work_stale_tip_page_defers_while_broken_page_admits() {
        let tree = regtest_tree_with_main();
        let floor = ChainWork::from_be_bytes([0xFF_u8; 32]);
        let (sync, _peers, _headers_tx) = routing_sync(tree, floor);
        let genesis_prev = Network::Regtest.genesis_block().block_hash();
        let first = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(genesis_prev, 101)
            .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        let second =
            bitcoin_rs_chain::regtest_fixture::mined_regtest_header(first.compute_hash(), 102)
                .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        let valid_page = [first, second];
        // Below the floor with a known parent: the valid page is complete
        // and well-linked, so it defers rather than bypassing the hold.
        assert!(
            sync.presync_anchor(&valid_page).is_some(),
            "the fixture page must sit below the raised floor"
        );
        assert!(
            !sync.body_carried_header_needs_admission(&valid_page),
            "a valid low-work stale-tip page must defer, not admit past the hold"
        );
        // A broken page (unmet proof of work) needs admission to fault.
        let mut broken = valid_page;
        broken[1].nonce = broken[1].nonce.wrapping_add(1).wrapping_mul(7919);
        // The grind above almost surely breaks the target; if it somehow
        // still meets it, flip bits to force the failure deterministically.
        if bitcoin_rs_chain::validate_pow(
            &broken[1],
            Hash256::from(broken[1].compute_hash()),
            Network::Regtest,
        )
        .is_ok()
        {
            broken[1].bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x1d00_ffff);
        }
        assert!(
            sync.body_carried_header_needs_admission(&broken),
            "a broken stale-tip page must admit so the fault is reported"
        );
    }

    /// A rejected batch whose valid prefix displaced the tip preserves the
    /// old tip through the drain's tip-movement wiring instead of losing it.
    ///
    /// Drives a stale-tip-style batch (identified peer, non-wire) through
    /// `drain_inbound_headers`: the above-floor prefix moves the tip, the
    /// garbage tail rejects, and the retainer must hold the pre-batch tip.
    /// Deleting the drain's `Rejected -> record_demoted_tip` wiring leaves
    /// the retainer empty and fails this test.
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
            let header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, height)
                .unwrap_or_else(|error| panic!("fixture mines: {error}"));
            prev = header.compute_hash();
            batch.push(header);
        }
        let garbage = bitcoin_rs_primitives::BlockHash::from(
            bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xFF_u8; 32]),
        );
        batch.push(
            bitcoin_rs_chain::regtest_fixture::mined_regtest_header(garbage, 104)
                .unwrap_or_else(|error| panic!("fixture mines: {error}")),
        );
        headers_tx
            .send(crate::InboundHeaders {
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
        let fresh =
            crate::PeerSource::for_test(std::net::SocketAddr::from(([127, 0, 0, 1], 18499)));
        let pending = sync.stale_tips().pending_for(fresh, |_| true);
        assert!(
            pending.contains(&pre_tip),
            "the drain must retain the displaced tip for stale relay, got {pending:?}"
        );
    }

    /// A body the compact path already owns is never direct-fetched twice:
    /// both drain branches gate on `owns_body_fetch`.
    ///
    /// Drives a linear-extension announcement through
    /// `drain_inbound_headers` with the tip body pre-owned by the announcer:
    /// the drain must resolve the owned mark and send no `getdata` for it.
    /// A control announcement without ownership must fetch, proving the
    /// test exercises the real direct-fetch path. Deleting either drain
    /// guard turns the owned case into a fetch and fails.
    #[test]
    fn duplicate_fetch_skips_owned_body() {
        let tree = regtest_tree_with_main();
        let floor = ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work());
        let (sync, peers, headers_tx) = routing_sync(tree, floor);
        // Owned case: linear extension at height 3, pre-owned by announcer.
        let (source, rx) = connected_peer(&peers, 18446, 3);
        let tip = sync
            .chain
            .chain_tip()
            .unwrap_or_else(|| panic!("tree has a tip"));
        let prev = bitcoin_rs_primitives::BlockHash::from(tip.hash);
        let header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, 3)
            .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        let tip_hash = Hash256::from(header.compute_hash());
        assert!(
            sync.enqueue_owned_body_fetch(source, tip_hash, || true),
            "the compact follow-up publishes ownership"
        );
        headers_tx
            .send(crate::InboundHeaders {
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
            if matches!(message, crate::Message::GetData(_)) {
                saw_getdata = true;
            }
        }
        assert!(
            !saw_getdata,
            "the owned body must not be direct-fetched twice"
        );
        // Control: a fresh announcement without ownership must fetch,
        // proving this test drives the real direct-fetch path.
        let (control_source, control_rx) = connected_peer(&peers, 18447, 4);
        let tip = sync
            .chain
            .chain_tip()
            .unwrap_or_else(|| panic!("tree has a tip"));
        let prev = bitcoin_rs_primitives::BlockHash::from(tip.hash);
        let control_header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, 4)
            .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        headers_tx
            .send(crate::InboundHeaders {
                headers: vec![control_header],
                source: Some(control_source),
                wire_response: true,
            })
            .unwrap_or_else(|error| panic!("queue control announcement: {error}"));
        sync.drain_inbound_headers();
        let mut control_saw_getdata = false;
        while let Ok(message) = control_rx.try_recv() {
            if matches!(message, crate::Message::GetData(_)) {
                control_saw_getdata = true;
            }
        }
        assert!(
            control_saw_getdata,
            "the unowned control announcement must direct-fetch its body"
        );
    }
}
