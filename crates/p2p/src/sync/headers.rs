//! Header request ownership, locator construction, and inbound header admission.

use super::GetdataRequestOutcome;
use super::GetheadersOutcome;
use super::HEADER_REQUEST_TIMEOUT;
use super::LOCATOR_MAX_ENTRIES;
use super::MAX_HEADERS_RESULTS;
use super::PROTOCOL_VERSION;
use super::PendingHeaderRequest;
use super::chain::HeaderAdmission;
use super::chain::SyncChainError;
use super::frontier::ChainFrontier;
use super::frontier::SyncFrontier;
use super::frontier::UsablePeer;
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
use bitcoin_rs_chain::{ChainError, NodeId};
use bitcoin_rs_primitives::Hash256;
use std::time::Instant;
use std::vec::Vec;

/// Cap on retained off-chain tips per session: honest peers announce one
/// chain, so more than this many distinct side branches is a misbehavior
/// signal rather than evidence worth keeping.
const MAX_UNRESOLVED_DEMONSTRATED_TIPS: usize = 8;

/// Cap on deferred owned-fetch marks waiting on unattached tip headers:
/// bounded so a peer cannot grow the scheduler by announcing tips that
/// never admit. The oldest mark is evicted first.
const MAX_DEFERRED_OWNED_FETCHES: usize = 16;

impl BlockSync {
    #[allow(clippy::too_many_lines)]
    pub(super) fn drain_inbound_headers(&self, now: Instant) {
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

            // The pending request is consumed only once this batch is known to
            // be a valid answer. An unconnecting or rejected batch is not an
            // answer, so the request stays live and keeps gating the peer.
            // Already-known batches skip the transition lock. The listener
            // forwards every inbound body's embedded header here so
            // unannounced tips (`inv`-served, compact-reconstructed, or
            // pushed blocks) reach admission — during bulk delivery those
            // batches would otherwise pay a lock acquisition per body for
            // what is almost always a lookup hit.
            if let Some((tip_hash, active_height)) = self.known_batch_outcome(&headers) {
                self.consume_header_request(source, wire_response, headers.is_empty());
                if let Some(source) = source {
                    self.peer_table
                        .note_announced_tip(source, tip_hash, active_height);
                    credit_refresh_needed = true;
                    if wire_response && !body_fetch_owned {
                        direct_fetch.push((source, tip_hash));
                    }
                    self.continue_full_page(Some(source), batch_len, Some(tip_hash), now);
                }
                if body_fetch_owned {
                    self.note_owned_body_fetch(source, headers.last());
                }
                continue;
            }

            // Header admission moves the header tip, which the apply path
            // reads under the transition; the implementation holds that lock
            // inside `admit_headers` until commit.
            match self.chain.admit_headers(&headers) {
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
                    self.consume_header_request(source, wire_response, headers.is_empty());
                    self.continue_full_page(source, batch_len, announced_tip, now);
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
                                .mark_peer_unresponsive(source.addr, now);
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
                        if wire_response {
                            // The connection answered this request with a
                            // batch that will not attach. The gate stays and
                            // paces the retry; its deadline moves to this
                            // answer, so expiry cannot blame a peer that did
                            // respond.
                            self.rearm_header_request(source, now);
                        } else {
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
                        self.request_headers_from(source, now);
                    } else {
                        // The connection answered, so its deadline moves to
                        // this answer: the gate stays and paces the retry,
                        // and expiry cannot later blame a peer that did
                        // respond.
                        self.rearm_header_request(source, now);
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
                    // silently losing the announcement. Our own paused
                    // admission is not the peer's silence, so the deadline
                    // moves to this answer.
                    self.rearm_header_request(source, now);
                    self.request_ancestry_after_refusal(source, &error, now);
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
        self.drain_block_announcements(now);
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
    fn drain_block_announcements(&self, now: Instant) {
        let pending = std::mem::take(&mut *self.block_announcements.lock());
        if pending.is_empty() {
            return;
        }
        let mut credit_refresh_needed = false;
        for (source, hash) in pending {
            if !self.peer_table.is_current(source) {
                continue;
            }
            // The tree read is scoped so no lock is held across the peer
            // table or the outbound send the unknown case performs.
            let (known, active_height) = {
                let tree = self.chain.block_tree().read();
                let height = tree
                    .tip()
                    .and_then(|tip| shared_active_height(&tree, tip.tip_id, hash))
                    .and_then(|height| i32::try_from(height).ok());
                (tree.lookup(hash).is_some(), height)
            };
            if !known {
                self.request_headers_from(Some(source), now);
                continue;
            }
            self.peer_table
                .note_announced_tip(source, hash, active_height);
            credit_refresh_needed = true;
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
        // the apply path walk the tree and repopulate it with the full run.
        *self.expected_apply_cache.lock() = None;
        outcome
    }

    /// Height of `hash` when it lies on the branch that ends at `tip`, and
    /// `None` when the tree does not know it or it belongs to another branch.
    fn tip_height_on_active_branch(&self, tip: NodeId, hash: Hash256) -> Option<u32> {
        let tree = self.chain.block_tree().read();
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
    fn request_ancestry_after_refusal(
        &self,
        source: Option<PeerSource>,
        error: &SyncChainError,
        now: Instant,
    ) {
        let mut last = self.refused_rerequest_at.lock();
        if last.is_none_or(|last| now.duration_since(last) >= HEADER_REQUEST_TIMEOUT) {
            *last = Some(now);
            drop(last);
            self.request_headers_from(source, now);
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
    /// response arrives on the exact connection that owns it, and clears that
    /// connection's header-timeout penalty: an answered request is the evidence
    /// that retires the blame a previous timeout recorded. An empty
    /// response supplies no new capability: retain its deadline so idle
    /// discovery is paced and rotates to another peer. The consumption is
    /// identity-exact: only the connection the request was sent to can
    /// answer it, so a same-address replacement's batch never frees the
    /// predecessor's deadline nor redeems its penalty. Headers forwarded out
    /// of a delivered body (`wire_response = false`) are not a response:
    /// letting them clear the pending slot would let every delivered block
    /// reset request pacing and emit duplicate `getheaders`.
    fn consume_header_request(
        &self,
        source: Option<PeerSource>,
        wire_response: bool,
        batch_empty: bool,
    ) {
        let Some(source) = source.filter(|_| wire_response && !batch_empty) else {
            return;
        };
        self.clear_header_request_for(source);
        self.scheduler.lock().header_penalties.remove(&source);
    }

    /// Moves the retained request's deadline to `now` after `source` answered
    /// with a batch this node could not use.
    ///
    /// PRE: `source` is the connection that delivered the batch, if any.
    /// POST: the request stays registered, so the gate keeps pacing duplicate
    ///   `getheaders`, and its deadline no longer predates this answer.
    /// INVARIANT: only the exact owner's request is re-armed. A connection that
    ///   answered — even unusably — is never later blamed by expiry for a
    ///   silence it did not cause, so a wrong local clock or a paused admission
    ///   cannot rotate header sync away from an honest peer.
    fn rearm_header_request(&self, source: Option<PeerSource>, now: Instant) {
        let Some(source) = source else {
            return;
        };
        let mut scheduler = self.scheduler.lock();
        if let Some(request) = &mut scheduler.header_request {
            if request.source == source {
                request.requested_at = now;
            }
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
            let tree = self.chain.block_tree().read();
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
        window.mark_owned_fetch(stager, source, hash, height, Instant::now());
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
            let tree = self.chain.block_tree().read();
            for (source, hash) in deferred {
                let height = tree
                    .lookup(hash)
                    .and_then(|id| tree.node(id).ok().map(|node| node.height));
                match height {
                    Some(height) => resolved.push((source, hash, height)),
                    None if self.peer_table.is_current(source) => {
                        unresolved.push((source, hash));
                    }
                    None => {}
                }
            }
        }
        let mut scheduler = self.scheduler.lock();
        let now = Instant::now();
        let SchedulerState { window, stager, .. } = &mut *scheduler;
        for (source, hash, height) in resolved {
            window.mark_owned_fetch(stager, source, hash, height, now);
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
        let tree = self.chain.block_tree().read();
        let last_hash = Hash256::from(headers.last()?.compute_hash());
        headers
            .iter()
            .all(|header| tree.lookup(Hash256::from(header.compute_hash())).is_some())
            .then(|| {
                (
                    last_hash,
                    tree.tip()
                        .and_then(|tip| shared_active_height(&tree, tip.tip_id, last_hash))
                        .and_then(|height| i32::try_from(height).ok()),
                )
            })
    }

    /// Continues a full header page on the connection that delivered it.
    ///
    /// PRE: `source` is the connection the page arrived on, `batch_len` is the
    ///   size of that page, and `page_tip` is the deepest header of the page
    ///   that this node now holds.
    /// POST: when the page filled the wire batch and `source` is known, exactly
    ///   one `getheaders` was sent to that connection; nothing is sent for a
    ///   short page or a source-less delivery.
    /// INVARIANT: a full page is continued on the connection that proved it can
    ///   serve it, never by re-electing a peer, so header sync does not stall
    ///   waiting for a later tick to rediscover the tip; and the anchor is the
    ///   header this node actually holds, because a page may be admitted only
    ///   as far as consensus validation allows.
    fn continue_full_page(
        &self,
        source: Option<PeerSource>,
        batch_len: usize,
        page_tip: Option<Hash256>,
        now: Instant,
    ) {
        if batch_len != MAX_HEADERS_RESULTS {
            return;
        }
        let (Some(source), Some(page_tip)) = (source, page_tip) else {
            return;
        };
        let target_height = self.header_continuation_target(source);
        self.continue_headers_from(source, page_tip, target_height, now);
    }

    /// Asks `source` for the page that follows the one it just delivered.
    ///
    /// PRE: `batch_tip` is the last header of `source`'s full page and
    ///   `target_height` is the height still wanted from that connection.
    /// POST: the locator handed to `send_getheaders` has `batch_tip` as its
    ///   first entry and the request is registered under `source`; returns the
    ///   send outcome, or `Failed` when `batch_tip` is not in the tree.
    /// INVARIANT: the anchor is the delivered page's own deepest admitted
    ///   header, never a separately loaded chain tip, so the peer resumes
    ///   exactly where this page stopped.
    fn continue_headers_from(
        &self,
        source: PeerSource,
        batch_tip: Hash256,
        target_height: u32,
        now: Instant,
    ) -> GetheadersOutcome {
        let (locator, our_height) = {
            let tree = self.chain.block_tree().read();
            let Some(anchor) = tree.lookup(batch_tip) else {
                return GetheadersOutcome::Failed;
            };
            let height = tree.node(anchor).map_or(0, |node| node.height);
            (tree.block_locator(anchor, LOCATOR_MAX_ENTRIES), height)
        };
        self.send_getheaders(
            source,
            our_height,
            i32::try_from(target_height).unwrap_or(i32::MAX),
            locator,
            now,
        )
    }

    /// The height a continuation for `source` aims at: the target of the request
    /// this page answered, else that connection's advertised height.
    ///
    /// PRE: none.
    /// POST: returns the pending request's target when `source` owns it, the
    ///   connection's advertised height when it does not, and the largest
    ///   addressable height when neither is known.
    /// INVARIANT: the target is read from the exact connection, so a
    ///   same-address replacement never inherits its predecessor's target.
    fn header_continuation_target(&self, source: PeerSource) -> u32 {
        let pending = self.scheduler.lock().header_request;
        if let Some(request) = pending.filter(|request| request.source == source) {
            return request.target_height;
        }
        self.peer_table
            .sessions()
            .into_iter()
            .find(|session| session.lease.source(session.addr) == source)
            .and_then(|session| session.info)
            .and_then(|info| u32::try_from(info.best_known_height).ok())
            .unwrap_or(u32::MAX)
    }

    /// Asks `source` for the header ancestry past our tip. The delivering
    /// peer demonstrably knows a chain beyond ours whenever its batch cannot
    /// attach (`MissingParent`) or cannot be admitted (`Refused`): the
    /// response makes the next batch attachable instead of leaving the live
    /// tip wedged on one missed header.
    fn request_headers_from(&self, source: Option<PeerSource>, now: Instant) {
        let Some(source) = source else {
            return;
        };
        let header_height = self
            .chain
            .chain_tip()
            .load_full()
            .map_or(0, |tip| tip.height);
        let target_height = self
            .peer_table
            .sessions()
            .iter()
            .find(|session| session.addr == source.addr)
            .and_then(|session| session.info.as_ref())
            .map_or(i32::MAX, |info| info.best_known_height);
        self.send_getheaders(
            source,
            header_height,
            target_height,
            self.build_locator(),
            now,
        );
    }

    /// Asks any live full-witness peer for the header ancestry past our tip.
    /// Used when a staged body's parent header is unknown and no delivering
    /// source was recorded; every fully serving peer can fill the gap.
    pub(super) fn request_headers_from_eligible(&self, now: Instant) {
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
        self.request_headers_from(source, now);
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
            let tree = self.chain.block_tree().read();
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
        now: Instant,
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
        // Each connection's own header-timeout record lowers its effective
        // rank, so a peer that failed to answer is not re-picked over one that
        // has not been asked yet at the same advertised height.
        let penalties = self.header_penalties();
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
                .is_none_or(|(_, current)| outranks(current, &candidate, &penalties))
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
                    now,
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
        now: Instant,
    ) -> GetheadersOutcome {
        let (Some(applied), Some(headers)) = (
            frontier.chain.applied_tip.as_ref(),
            frontier.chain.chain_tip.as_ref(),
        ) else {
            return GetheadersOutcome::Failed;
        };
        // The plan's Probe decision was taken at observation time; a body
        // request scheduled since may already own the frontier, in which
        // case capability discovery has nothing left to resolve.
        let frontier_owned = frontier.chain.next_required.is_some_and(|required| {
            let scheduler = self.scheduler.lock();
            scheduler.window.contains_pending(&required.hash)
                || scheduler.stager.contains(&required.hash)
        });
        if frontier_owned {
            return GetheadersOutcome::Suppressed;
        }
        let locator = {
            let tree = self.chain.block_tree().read();
            let Some(active_anchor) = tree.node_at_height_from(headers.tip_id, applied.height)
            else {
                return GetheadersOutcome::Failed;
            };
            tree.block_locator(active_anchor, LOCATOR_MAX_ENTRIES)
        };
        let outcome = self.send_getheaders(
            source,
            applied.height,
            i32::try_from(headers.height).unwrap_or(i32::MAX),
            locator,
            now,
        );
        if outcome == GetheadersOutcome::Sent {
            metrics::counter!("node.sync.idle_frontier_probes").increment(1);
        }
        outcome
    }

    /// This tick's header-timeout penalties, one count per exact connection.
    ///
    /// PRE: none.
    /// POST: returns a snapshot of the penalty records, empty for connections
    ///   that have answered every request asked of them.
    /// INVARIANT: the snapshot is taken and released in one lock acquisition,
    ///   so no peer comparison ever runs while the scheduler is held.
    pub(super) fn header_penalties(&self) -> hashbrown::HashMap<PeerSource, u32> {
        self.scheduler.lock().header_penalties.clone()
    }

    /// Retires a `getheaders` that outlived its deadline and rotates away from
    /// the connection that ignored it.
    ///
    /// PRE: `now` is the instant this tick was taken at and `usable` is the
    ///   peer snapshot observed at that same instant.
    /// POST: when the pending request is older than `HEADER_REQUEST_TIMEOUT` and
    ///   its exact owner is still usable, the request is cleared, that owner is
    ///   marked unresponsive at `now`, and its penalty rises by one; the owner
    ///   is disconnected only while another usable peer remains. Returns the
    ///   retired connection, or `None` when nothing expired.
    /// INVARIANT: expiry reads only `now` and compares whole connection
    ///   identity, so a same-address replacement never inherits the blame, and
    ///   a cleared request can never gate a later selection.
    pub(super) fn expire_header_request(
        &self,
        now: Instant,
        usable: &[UsablePeer],
    ) -> Option<PeerSource> {
        let expired = {
            let mut scheduler = self.scheduler.lock();
            let request = scheduler.header_request.filter(|request| {
                now.saturating_duration_since(request.requested_at) >= HEADER_REQUEST_TIMEOUT
                    && usable.iter().any(|peer| peer.source == request.source)
            })?;
            scheduler.header_request = None;
            *scheduler
                .header_penalties
                .entry(request.source)
                .or_insert(0) += 1;
            scheduler
                .window
                .mark_peer_unresponsive(request.source.addr, now);
            request.source
        };
        let fallback_exists = usable.len() > 1;
        if !fallback_exists {
            // Nothing else to ask, so the request stays cleared rather than
            // gating the next peer that connects.
            tracing::warn!(
                peer_addr = %expired.addr,
                "block sync: peer did not answer getheaders; request cleared, no fallback peer",
            );
            return Some(expired);
        }
        if self.peer_table.disconnect_source(expired) {
            tracing::warn!(
                peer_addr = %expired.addr,
                "block sync: peer did not answer getheaders; disconnecting and rotating to a fallback",
            );
        }
        Some(expired)
    }

    /// Sends `getheaders` to the exact connection `source` identifies and
    /// registers the request under that connection's ownership.
    pub(super) fn send_getheaders(
        &self,
        source: crate::PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
        now: Instant,
    ) -> GetheadersOutcome {
        let Some(locator_tip_hash) = locator.first().copied() else {
            return GetheadersOutcome::Failed;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
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
                self.scheduler.lock().header_request = Some(PendingHeaderRequest {
                    source,
                    locator_tip_hash,
                    target_height,
                    requested_at: now,
                });
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

    pub(super) fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.chain.chain_tip().load_full() {
            return self
                .chain
                .block_tree()
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        std::vec![self.chain.network().genesis_block_hash()]
    }
}
