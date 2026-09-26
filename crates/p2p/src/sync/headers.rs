//! Header request ownership, locator construction, and inbound header admission.

use super::GetdataRequestOutcome;
use super::GetheadersOutcome;
use super::HEADER_REQUEST_TIMEOUT;
use super::LOCATOR_MAX_ENTRIES;
use super::MAX_DEFERRED_OWNED_FETCHES;
use super::PROTOCOL_VERSION;
use super::PendingHeaderRequest;
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
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_chain::{ChainError, NodeId, NodeStatus};
use bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
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
    #[allow(clippy::too_many_lines)]
    pub(super) fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        let mut credit_refresh_needed = false;
        // Near-tip batches whose body the announcing connection can serve
        // straight away; drained after the loop with one frontier read.
        let mut direct_fetch: Vec<(PeerSource, Hash256)> = Vec::new();
        while let Ok(InboundHeaders {
            headers,
            source,
            wire_response,
            body_fetch_owned,
        }) = receiver.try_recv()
        {
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);

            self.consume_header_request(source, wire_response, headers.is_empty());

            // A connection with a live download-twice state must feed its
            // page to that state even when the tree already holds it:
            // bypassing the state leaves its cursor behind and the next
            // page breaks continuity against a stale position.
            let feeds_live_sync = wire_response
                && source
                    .is_some_and(|source| self.scheduler.lock().headers_sync.contains_key(&source));

            // Already-known batches skip the transition lock. The listener
            // forwards every inbound body's embedded header here so
            // unannounced tips (`inv`-served, compact-reconstructed, or
            // pushed blocks) reach admission — during bulk delivery those
            // batches would otherwise pay a lock acquisition per body for
            // what is almost always a lookup hit.
            if !feeds_live_sync
                && let Some((tip_hash, active_height)) = self.known_batch_outcome(&headers)
            {
                if let Some(source) = source {
                    self.peer_table
                        .note_announced_tip(source, tip_hash, active_height);
                    credit_refresh_needed = true;
                    if wire_response && !body_fetch_owned {
                        direct_fetch.push((source, tip_hash));
                    }
                }
                if body_fetch_owned {
                    self.note_owned_body_fetch(source, headers.last());
                }
                continue;
            }

            // A batch whose fork point has not yet demonstrated the
            // network's minimum chain work is retained by that connection's
            // download-twice header sync; only headers the committed phase
            // releases — and batches at or above the threshold — reach
            // admission here.
            let Some(admission) =
                self.route_headers_batch(&headers, source, wire_response, batch_len)
            else {
                if body_fetch_owned {
                    self.note_owned_body_fetch(source, headers.last());
                }
                continue;
            };
            match admission {
                HeaderAdmission::Accepted {
                    accepted,
                    announced_tip,
                    active_height,
                } => {
                    if let (Some(tip_hash), Some(source)) = (announced_tip, source) {
                        self.peer_table
                            .note_announced_tip(source, tip_hash, active_height);
                        if wire_response && !body_fetch_owned {
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
                        if self.peer_table.disconnect_source(source) {
                            // Every removal path releases a `getheaders`
                            // gate the peer owned, or a same-address
                            // reconnect inherits a dead deadline.
                            self.clear_header_request_for(source);
                            self.scheduler
                                .lock()
                                .window
                                .mark_peer_unresponsive(source.addr, Instant::now());
                            blamed_peer = Some(source.addr);
                        }
                    }
                    if let Some(peer_addr) = blamed_peer {
                        tracing::warn!(
                            peer_addr = %peer_addr,
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
                        if !wire_response {
                            // A header carried by a delivered body is not a
                            // response to the pending request, and the
                            // delivery itself is the new evidence that this
                            // connection holds the missing ancestry: retire
                            // the stale gate so the recovery ask reaches the
                            // wire with this delivery instead of waiting for
                            // the deadline to clear first.
                            if let Some(source) = source {
                                self.clear_header_request_for(source);
                            }
                        }
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
            if body_fetch_owned {
                self.note_owned_body_fetch(source, headers.last());
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
        // `header_request` is a singleton: asking a second peer before the
        // first answers would orphan the earlier request untracked, so
        // unknown announcements queue back for a later drain instead.
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
                if self.scheduler.lock().header_request.is_some() {
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
                announcements.entry(source).or_insert(hash);
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
        let outcome = self.send_getdata_for_pending_blocks(source, false, height, chain);
        // The request path primes the expected-apply cache with exactly this
        // batch. A direct fetch runs before this round's apply pass, where
        // more bodies may already be staged, so drop the primed cache and let
        // the apply path walk the tree and repopulate it with the full run —
        // but only when a request actually went out; a refused outcome left
        // the cache untouched.
        if outcome.sent {
            *self.expected_apply_cache.lock() = None;
        }
        outcome
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

    /// Consumes the pending `getheaders` when a nonempty wire `headers`
    /// response arrives on the exact connection that owns it. An empty
    /// response supplies no new capability: retain its deadline so idle
    /// discovery is paced and rotates to another peer. The consumption is
    /// identity-exact: only the connection the request was sent to can
    /// answer it, so a same-address replacement's batch never frees the
    /// predecessor's deadline. Headers forwarded out of a delivered body
    /// (`wire_response = false`) are not a response: letting them clear the
    /// pending slot would let every delivered block reset request pacing
    /// and emit duplicate `getheaders`.
    fn consume_header_request(
        &self,
        source: Option<PeerSource>,
        wire_response: bool,
        batch_empty: bool,
    ) {
        if let Some(source) = source.filter(|_| wire_response && !batch_empty) {
            self.clear_header_request_for(source);
        }
    }

    /// Releases a `getheaders` gate owned by `source`. Every disconnect
    /// path — send failure, window or staged-header blame — clears the
    /// owner so a same-address reconnect cannot inherit a stale deadline.
    /// The match is identity-exact (P2P-02): a same-address replacement
    /// never frees its predecessor's pending request.
    pub(super) fn clear_header_request_for(&self, source: PeerSource) {
        let mut scheduler = self.scheduler.lock();
        if scheduler
            .header_request
            .is_some_and(|request| request.source == source)
        {
            scheduler.header_request = None;
        }
    }

    /// Records a body fetch the window does not own — the compact outcome
    /// that forwarded this header already issued a `getblocktxn` or a
    /// fallback `getdata` for the tip body — as pending under `source`, so
    /// `next_peer_request` does not schedule a duplicate getdata for the
    /// freshly admitted tip. A tip that has not attached yet is retained in
    /// `SchedulerState::owned_body_fetches` and resolved once ancestry
    /// admits it; without retention a gap batch would let the window
    /// schedule a second fetch in parallel with the pending compact one.
    fn note_owned_body_fetch(
        &self,
        source: Option<PeerSource>,
        header: Option<&bitcoin_rs_primitives::Header>,
    ) {
        let (Some(source), Some(header)) = (source, header) else {
            return;
        };
        // A stale source names a dead connection: its compact fetch died
        // with it, and marking the body pending under that address would
        // suppress scheduling from the live replacement until expiry.
        if !self.peer_table.is_current(source) {
            return;
        }
        let hash = Hash256::from(header.compute_hash());
        let height = {
            let tree = self.chain.block_tree();
            tree.lookup(hash)
                .and_then(|id| tree.node(id).ok().map(|node| node.height))
        };
        let mut scheduler = self.scheduler.lock();
        let Some(height) = height else {
            if !scheduler
                .owned_body_fetches
                .iter()
                .any(|(_, known)| *known == hash)
            {
                if scheduler.owned_body_fetches.len() >= MAX_DEFERRED_OWNED_FETCHES {
                    scheduler.owned_body_fetches.remove(0);
                }
                scheduler.owned_body_fetches.push((source, hash));
            }
            return;
        };
        let SchedulerState { window, stager, .. } = &mut *scheduler;
        if !window.mark_owned_fetch(stager, source, hash, height, Instant::now()) {
            scheduler.owned_body_fetches.push((source, hash));
        }
    }

    /// Resolves deferred owned-fetch marks now that this drain may have
    /// admitted the ancestry their tips were waiting on. Marks whose source
    /// went stale are dropped: the dead connection's fetch died with it and
    /// normal scheduling asks a live peer instead.
    pub(super) fn resolve_owned_body_fetches(&self) {
        let deferred = {
            let mut scheduler = self.scheduler.lock();
            if scheduler.owned_body_fetches.is_empty() {
                return;
            }
            std::mem::take(&mut scheduler.owned_body_fetches)
        };
        let mut unresolved = Vec::with_capacity(deferred.len());
        let mut resolved = Vec::with_capacity(deferred.len());
        {
            let tree = self.chain.block_tree();
            for (source, hash) in deferred {
                // A stale source names a dead connection: its fetch died
                // with it, so the mark must neither settle a staged body's
                // gate nor mark it pending under the dead owner.
                if !self.peer_table.is_current(source) {
                    continue;
                }
                let height = tree
                    .lookup(hash)
                    .and_then(|id| tree.node(id).ok().map(|node| node.height));
                match height {
                    Some(height) => resolved.push((source, hash, height)),
                    None => unresolved.push((source, hash)),
                }
            }
        }
        let mut scheduler = self.scheduler.lock();
        let now = Instant::now();
        let SchedulerState { window, stager, .. } = &mut *scheduler;
        for (source, hash, height) in resolved {
            // A refusal leaves the fetch in flight: keep the deferred mark so
            // the delivered body still classifies as requested.
            if !window.mark_owned_fetch(stager, source, hash, height, now) {
                unresolved.push((source, hash));
            }
        }
        scheduler.owned_body_fetches.extend(unresolved);
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

    /// Asks `source` for the header ancestry past our tip. The delivering
    /// peer demonstrably knows a chain beyond ours whenever its batch cannot
    /// attach (`MissingParent`) or cannot be admitted (`Refused`): the
    /// response makes the next batch attachable instead of leaving the live
    /// tip wedged on one missed header.
    fn request_headers_from(&self, source: Option<PeerSource>) {
        let Some(source) = source else {
            return;
        };
        let header_height = self.chain.chain_tip().map_or(0, |tip| tip.height);
        let target_height = self
            .peer_table
            .sessions()
            .iter()
            .find(|session| session.addr == source.addr)
            .and_then(|session| session.info.as_ref())
            .map_or(i32::MAX, |info| info.best_known_height);
        self.send_getheaders(source, header_height, target_height, self.build_locator());
    }

    /// Asks any live full-witness peer for the header ancestry past our tip.
    /// Used when a staged body's parent header is unknown and no delivering
    /// source was recorded; every fully serving peer can fill the gap.
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
            .min_by_key(|session| session.addr)
            .map(|session| session.lease.source(session.addr));
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
                        .then(|| (session.lease.source(session.addr), credit, keep))
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
    /// `exclude` carries the source whose probe send failed this tick, so the
    /// same-tick fallback cannot retry it.
    pub(super) fn request_headers_from_best_peer(
        &self,
        frontier: &SyncFrontier,
        exclude: Option<PeerSource>,
    ) {
        let applied_height = frontier
            .chain
            .applied_tip
            .as_ref()
            .map_or(0, |tip| tip.height);
        let header_height = frontier
            .chain
            .chain_tip
            .as_ref()
            .map_or(applied_height, |tip| tip.height);
        let mut header_peer: Option<(PeerSource, SyncPeer)> = None;
        for peer in &frontier.usable_peers {
            let Some(candidate) = sync_peer_candidate(peer.source, &peer.info, applied_height)
            else {
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
            metrics::counter!("node.sync.idle_frontier_probes").increment(1);
        }
        outcome
    }

    /// Sends one `getheaders` for the chain-sync eviction probe: the same
    /// applied-anchor locator the frontier probe uses, but without the
    /// frontier-ownership gate — a lagging peer owes an answer for its own
    /// silence regardless of who owns the next body, and without claiming
    /// the singleton `header_request` slot.
    ///
    /// PRE: `source` names a live subject connection.
    /// POST: return the wire outcome; `Suppressed` counts only when an
    ///   identical request is already pending for this connection, and
    ///   nothing else suppresses the send.
    pub(super) fn send_chain_sync_probe(
        &self,
        frontier: &SyncFrontier,
        source: PeerSource,
    ) -> GetheadersOutcome {
        let Some((our_height, target_height, locator)) = self.applied_frontier_probe(frontier)
        else {
            return GetheadersOutcome::Failed;
        };
        let outcome =
            self.send_getheaders_tracked(source, our_height, target_height, locator, false);
        if outcome == GetheadersOutcome::Sent {
            metrics::counter!("node.sync.chain_sync_probes").increment(1);
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
        self.send_getheaders_tracked(source, our_height, target_height, locator, true)
    }

    /// `track` registers the request in the singleton `header_request` slot;
    /// a probe that must not displace the frontier's pending request sends
    /// untracked — its answer arrives as ordinary inbound headers.
    fn send_getheaders_tracked(
        &self,
        source: crate::PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
        track: bool,
    ) -> GetheadersOutcome {
        let Some(locator_tip_hash) = locator.first().copied() else {
            return GetheadersOutcome::Failed;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
        let now = Instant::now();
        if self.has_pending_getheaders(source, locator_tip_hash, target_height, now) {
            tracing::trace!(
                peer_addr = %source.addr,
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
        let msg = Message::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            bitcoin::BlockHash::all_zeros(),
        ));
        // `send_then` holds the connection's identity through the enqueue
        // and the pending stamp under one table authority, so a replacement
        // slipping in between cannot leave a request registered to a dead
        // connection.
        if self
            .peer_table
            .send_then(source, msg, || {
                if track {
                    self.scheduler.lock().header_request = Some(PendingHeaderRequest {
                        source,
                        locator_tip_hash,
                        target_height,
                        requested_at: now,
                    });
                }
            })
            .is_err()
        {
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: outbound channel disconnected"
            );
            // The send failure means this connection is gone: evict it so the
            // scheduler cannot re-pick a dead peer every tick. The identity
            // check inside `disconnect_source` keeps a same-address
            // replacement untouched, and only then is a pending request keyed
            // to this connection dropped so a fast reconnect does not inherit
            // a stale deadline gate.
            if self.peer_table.disconnect_source(source) {
                self.clear_header_request_for(source);
            }
            return GetheadersOutcome::Failed;
        }
        tracing::debug!(
            peer_addr = %source.addr,
            our_height,
            target_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
        GetheadersOutcome::Sent
    }

    /// Whether an unexpired request with these exact parameters is already
    /// pending on this exact connection. Identity is the full `PeerSource`:
    /// a same-address replacement is a different request.
    pub(super) fn has_pending_getheaders(
        &self,
        source: PeerSource,
        locator_tip_hash: Hash256,
        target_height: u32,
        now: Instant,
    ) -> bool {
        let scheduler = self.scheduler.lock();
        let Some(pending) = scheduler.header_request else {
            return false;
        };
        pending.source == source
            && pending.locator_tip_hash == locator_tip_hash
            && pending.target_height == target_height
            && now.duration_since(pending.requested_at) < HEADER_REQUEST_TIMEOUT
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
    ///   the work floor it returns `None`, retiring to retry once the
    ///   wire sync commits it; at or above the floor it takes direct
    ///   admission. Otherwise return `Some` with the admission outcome
    ///   when the batch may be admitted directly — an empty batch, a
    ///   source-less delivery, an unknown fork, or a fork already at the
    ///   network minimum — or when the committed phase released headers;
    ///   and `None` when the sync state retained the batch, in which case
    ///   this call already retired the answered request, sent the
    ///   state-cursor continuation, or ran the fault path.
    /// INVARIANT: a batch below the work threshold reaches
    ///   [`SyncChain::admit_headers`] only as
    ///   [`super::headers_presync::HeaderSyncResult::ready_headers`], and
    ///   only a wire `headers` message mutates `headers_sync`.
    pub(super) fn route_headers_batch(
        &self,
        headers: &[Header],
        source: Option<PeerSource>,
        wire_response: bool,
        batch_len: usize,
    ) -> Option<HeaderAdmission> {
        if headers.is_empty() {
            // An empty answer ends a live download-twice sync — the peer
            // has no more headers for this cursor — rather than leaving
            // the state to pace a stale request.
            if wire_response {
                if let Some(source) = source {
                    self.scheduler.lock().headers_sync.remove(&source);
                }
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
            if self.presync_anchor(headers).is_some() {
                return None;
            }
            return Some(self.chain.admit_headers(headers));
        }
        let outcome = {
            // Page validation runs without the scheduler lock: hashing a
            // full page under `scheduler` would stall body-fetch ownership
            // and every other scheduler read for its duration, so a live
            // state leaves the map for the check and is committed back only
            // while its connection is still live — an ownership sweep that
            // raced in just drops the parked state.
            let parked = self.scheduler.lock().headers_sync.remove(&source);
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
                self.scheduler.lock().headers_sync.insert(source, state);
            }
            outcome
        };
        if outcome.finished {
            self.scheduler.lock().headers_sync.remove(&source);
        }
        if let Some(error) = outcome.failure {
            self.settle_presync_fault(source, error);
            return None;
        }
        // The batch answered the connection's outstanding request, so
        // that request retires here, before the continuation: Core
        // clears the request stamp on every processed headers message
        // and then sends the sync's own locator whenever the sync wants
        // more (`net_processing.cpp:2932-2943`). Retiring first lets a
        // phase transition reach the wire even when its locator repeats
        // the request this batch answered — the transition re-anchors at
        // the fork — and the fresh registration restarts expiry from this
        // send, so the connection that did respond is never blamed for
        // silence. The continuation also leaves on a releasing batch: the
        // REDOWNLOAD cursor sits up to `redownload_buffer_size` headers
        // deeper than the release point, and a page requested from the
        // release point would fail the state's continuity check and
        // restart the whole sync.
        self.consume_header_request(Some(source), wire_response, false);
        if outcome.request_more {
            self.send_presync_getheaders(source, outcome.locator, outcome.height);
        }
        if !outcome.ready_headers.is_empty() {
            let admission = self.chain.admit_headers(&outcome.ready_headers);
            if matches!(admission, HeaderAdmission::Refused(_)) {
                // Admission is paused: return the released prefix to the
                // live state so the next page's release re-emits it once
                // admission reopens. The sync's own continuation is already
                // in flight, so no tree-anchored re-request runs here — one
                // would restart the whole sync.
                if let Some(state) = self.scheduler.lock().headers_sync.get_mut(&source) {
                    state.requeue_released(&outcome.ready_headers);
                    return None;
                }
            }
            return Some(admission);
        }
        None
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
            match state.process(headers, batch_len >= crate::dispatch::MAX_HEADERS_RESPONSE) {
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
    ///   this node holds that parent and its cumulative chainwork is below
    ///   the network minimum; return `None` when the parent is unknown (the
    ///   admission path reports the missing ancestry) or already sufficient
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
        if fork.chainwork >= minimum_work {
            return None;
        }
        let median_time_past = tree.median_time_past_at(fork_id, MEDIAN_TIME_PAST_WINDOW)?;
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
            .find(|session| session.addr == source.addr)
            .and_then(|session| session.info.as_ref())
            .map_or(i32::MAX, |info| info.best_known_height);
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
                peer_addr = %source.addr,
                %error,
                "block sync: header presync gave up on a possibly reorged continuation",
            );
            return;
        }
        if self.peer_table.disconnect_source(source) {
            self.clear_header_request_for(source);
            self.scheduler
                .lock()
                .window
                .mark_peer_unresponsive(source.addr, Instant::now());
        }
        tracing::warn!(
            peer_addr = %source.addr,
            %error,
            "block sync: peer failed header presync validation; disconnecting",
        );
    }

    pub(super) fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.chain.chain_tip() {
            return self
                .chain
                .block_tree()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        std::vec![self.chain.network().genesis_block_hash()]
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
