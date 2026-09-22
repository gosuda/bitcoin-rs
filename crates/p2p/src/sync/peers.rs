//! Session reconciliation, useful-peer selection, and stalled-peer retirement.

use super::BlockSync;
use super::frontier::SyncFrontier;
use crate::PeerInfo;
use crate::download_window::DownloadWindow;
use crate::download_window::FanoutCandidate;
use crate::download_window::SyncPeer;
use crate::download_window::SyncPeerSelection;
use crate::download_window::configure_request_mode;
use crate::download_window::statically_fanout_eligible;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use std::vec::Vec;

pub(super) fn is_peer_fault(error: &ChainError) -> bool {
    match error {
        ChainError::NbitsMismatch { .. }
        | ChainError::InvalidPow { .. }
        | ChainError::TargetExceedsLimit { .. }
        | ChainError::ZeroTarget { .. }
        | ChainError::NonContinuousHeader { .. }
        | ChainError::ChainworkOverflow { .. }
        | ChainError::HeightOverflow { .. }
        // A median-time-past violation is decided entirely by the chain the peer
        // itself sent, so it is unambiguously the peer's fault.
        | ChainError::TimestampTooEarly { .. } => true,
        // Future drift is judged against OUR clock, so a wrong local clock
        // would otherwise let us ban every honest peer and partition
        // ourselves. The header is rejected without blaming the sender.
        ChainError::TimestampTooFarAhead { .. }
        | ChainError::DuplicateHeader { .. }
        | ChainError::MissingParent { .. }
        | ChainError::NodeIdOverflow { .. }
        | ChainError::UnknownNode { .. }
        | ChainError::NoCommonAncestor { .. } => false,
    }
}

/// The one eligibility and ordering rule for demonstrated-best-known
/// height peer selection (P2P-03): a peer is request-eligible when its
/// demonstrated height exceeds `floor`, and among eligible peers the
/// greatest height wins. First-wins on equal heights.
pub(super) fn sync_peer_candidate(peer: &PeerInfo, floor: u32) -> Option<SyncPeer> {
    let height = u32::try_from(peer.best_known_height).ok()?;
    (height > floor).then_some(SyncPeer {
        addr: peer.addr,
        best_known_height: peer.best_known_height,
    })
}

/// Whether `candidate` outranks `current`: strictly greater demonstrated
/// height; first-wins on ties.
pub(super) fn outranks(current: SyncPeer, candidate: SyncPeer) -> bool {
    candidate.best_known_height > current.best_known_height
}

pub(super) fn active_demonstrated_height(
    tree: &BlockTree,
    active_tip: NodeId,
    demonstrated_tips: &[Hash256],
) -> Option<u32> {
    demonstrated_tips
        .iter()
        .filter_map(|hash| tree.active_height_of(active_tip, *hash))
        .max()
}

pub(super) fn body_capability_height(
    peer: &PeerInfo,
    tree: &BlockTree,
    active_tip: Option<NodeId>,
    demonstrated_tips: &[Hash256],
) -> Option<u32> {
    // A session has no branch evidence until its first accepted header batch;
    // keep the handshake capability during that discovery window. Once it has
    // evidence, only a tip on the current active chain is usable for bodies.
    if demonstrated_tips.is_empty() {
        return u32::try_from(peer.best_known_height).ok();
    }
    active_tip.and_then(|tip| active_demonstrated_height(tree, tip, demonstrated_tips))
}

impl BlockSync {
    /// Clears leftover address-scoped scheduler state for a newly ready
    /// connection. Stale sources are ignored per P2P-02.
    pub fn on_peer_ready(&self, source: crate::PeerSource) {
        // Table before window, as in request publication. Validating again
        // under the window can deadlock behind a queued table writer while
        // an existing table reader waits for this window.
        self.peer_table.with_current(source, || {
            let mut state = self.frontier_state.lock();
            state.window.forget_peer(source.addr);
            if state.header_request.is_some_and(|request| {
                request.source.addr == source.addr && request.source != source
            }) {
                state.header_request = None;
            }
        });
    }

    pub(super) fn reconcile_peer_sessions(&self) {
        // Backstop: a session whose connection already cancelled its lease
        // leaves the table within one tick, whatever path cancelled it, so
        // zombie entries are never candidates for fetch work.
        self.peer_table
            .disconnect_matching(|_, lease| lease.is_cancelled());
        let live = self.peer_table.live_connections();
        let mut state = self.frontier_state.lock();
        if state.header_request.is_some_and(|request| {
                !live.iter().any(|(addr, id)| {
                    *addr == request.source.addr && *id == request.source.connection_id()
                })
            }) {
            state.header_request = None;
        }
        for (addr, id) in &live {
            if state
                .known_sessions
                .insert(*addr, *id)
                .is_some_and(|prev| prev != *id)
            {
                state.window.forget_peer(*addr);
                if state
                    .header_request
                    .is_some_and(|request| request.source.addr == *addr)
                {
                    state.header_request = None;
                }
            }
        }
        state
            .known_sessions
            .retain(|addr, _| live.iter().any(|(a, _)| a == addr));
        state
            .window
            .release_disconnected_peers(|peer| live.iter().any(|(a, _)| a == peer));
    }

    pub(super) fn sync_peer_selection(
        &self,
        frontier: &SyncFrontier,
        now: Instant,
    ) -> SyncPeerSelection {
        let our_height = frontier.applied_tip.as_ref().map_or(0, |tip| tip.height);
        let mut candidates: Vec<FanoutCandidate> = Vec::new();
        let tree = self.chain.block_tree().read();
        let active_tip = tree.tip_id();
        for usable in &frontier.usable_peers {
            let peer = &usable.info;
            // Height clause of the fan-out eligibility predicate (KTD6) and
            // the pre-existing candidate filter: the peer's known chain must
            // reach past our applied tip, i.e., cover the window front being
            // requested. Like Core's `pindexBestKnownBlock`, eligibility reads
            // the demonstrated best-known height (handshake snapshot, raised
            // as the peer hands us accepted headers) rather than the
            // handshake value alone — a long-lived at-tip peer would
            // otherwise become ineligible for every newly announced block
            // (#617). Per-request truncation by `peer_best_height` still
            // bounds the damage of a stale value.
            let Some(active_height) =
                body_capability_height(peer, &tree, active_tip, &usable.demonstrated_tips)
            else {
                continue;
            };
            if active_height <= our_height {
                continue;
            }
            let body_peer = SyncPeer {
                addr: peer.addr,
                best_known_height: i32::try_from(active_height).unwrap_or(i32::MAX),
            };
            candidates.push(FanoutCandidate {
                peer: body_peer,
                fanout_eligible: statically_fanout_eligible(peer),
                soft_blocked: false,
            });
        }
        drop(tree);
        let (request_peer_limit, fanout_active, cold_preferred) = {
            let mut frontier_state = self.frontier_state.lock();
            let window = &mut frontier_state.window;
            for candidate in &mut candidates {
                candidate.soft_blocked = window.peer_has_expired_pending(candidate.peer.addr, now)
                    || window.peer_in_staller_cooldown(candidate.peer.addr, now);
                candidate.fanout_eligible = candidate.fanout_eligible && !candidate.soft_blocked;
            }
            let cold_preferred = configure_request_mode(window, &candidates, now);
            (
                window.request_peer_scan_limit(now),
                window.fanout_active(),
                cold_preferred,
            )
        };
        let probe_peers = candidates
            .iter()
            .filter(|candidate| candidate.fanout_eligible)
            .map(|candidate| candidate.peer)
            .collect();
        let mut request_peers: Vec<SyncPeer> = if let Some(preferred) = cold_preferred {
            std::vec![preferred]
        } else if fanout_active {
            candidates
                .iter()
                .filter(|candidate| candidate.fanout_eligible)
                .map(|candidate| candidate.peer)
                .collect()
        } else if request_peer_limit > 1 {
            candidates.iter().map(|candidate| candidate.peer).collect()
        } else {
            // Fallback, single deep peer: the highest peer that the window
            // does not currently soft-block (expired pendings / staller
            // cooldown) fills the window; a soft-blocked peer serves only as
            // the last resort when no alternative exists. Without the
            // preference, a disconnected staller that reconnects with an
            // inflated demonstrated best-known height would out-sort every
            // honest peer and re-acquire the window front (RE-ADV-2 /
            // first-audit ADV-2).
            let mut preferred: Option<SyncPeer> = None;
            let allow_soft = candidates.iter().all(|candidate| candidate.soft_blocked);
            for candidate in candidates
                .iter()
                .filter(|candidate| allow_soft || !candidate.soft_blocked)
            {
                // First-wins on equal heights, matching the header-peer fold.
                if preferred.is_none_or(|current| outranks(current, candidate.peer)) {
                    preferred = Some(candidate.peer);
                }
            }
            preferred.into_iter().take(request_peer_limit).collect()
        };
        if request_peers.len() > 1 {
            request_peers.sort_by_key(|peer| std::cmp::Reverse(peer.best_known_height));
        }
        request_peers.truncate(request_peer_limit);
        SyncPeerSelection {
            request_peers,
            probe_peers,
        }
    }

    /// R8: window-blocked staller detection and disconnect.
    ///
    /// Computes the sync-layer terms of the stall predicate and advances the
    /// window's stall state machine ([`DownloadWindow::observe_stall`] holds
    /// the predicate itself). While the stager holds the next expected block,
    /// the apply side owns the frontier and no peer is blamed; that
    /// suppression is time-bounded (`DownloadWindow::observe_apply_side_bound`):
    /// past the bound the stuck staged body is evicted for refetch, still
    /// without blame (issue #1091).
    ///
    /// On fire the peer's outbound entry is removed. The p2p loop observes
    /// that lease removal and exits; the next tick releases and reassigns the
    /// peer's in-flight blocks. The cooldown prevents an immediate reconnect
    /// from reacquiring the same stripe.
    pub(super) fn disconnect_window_staller(
        &self,
        applied_tip: Option<&TipSnapshot>,
        now: Instant,
    ) -> bool {
        let Some(applied_tip) = applied_tip else {
            return false;
        };
        let Some(next_apply_height) = applied_tip.height.checked_add(1) else {
            return false;
        };
        // Snapshot the apply frontier once, before the window lock: the hash
        // keys the stuck-clock episode and gates the escalation's final
        // equality check, and `apply_side_busy` derives from the same
        // snapshot so both inputs describe one observation. The snapshot
        // reads `block_tree`, so it must stay outside
        // [`Self::select_and_evict_window_peer`] — its callback runs under
        // the window lock, and tree->window is the codebase's lock order.
        let frontier_hash = self.next_expected_block_hash();
        let apply_side_busy =
            frontier_hash.is_some_and(|hash| self.frontier_state.lock().stager.contains(&hash));
        let mut cold_hedge = None;
        let mut apply_side_escalation = None;
        let mut fired = false;
        let removed_peer = self.select_and_evict_window_peer(|window| {
            apply_side_escalation = window.observe_apply_side_bound(
                next_apply_height,
                frontier_hash,
                apply_side_busy,
                now,
            );
            cold_hedge = window.observe_cold_front(next_apply_height, apply_side_busy, now);
            let selected = window.observe_stall(next_apply_height, apply_side_busy, now);
            fired = selected.is_some();
            let stall_seconds = window
                .stalling_peer()
                .map_or(0.0, |(_, since)| now.duration_since(since).as_secs_f64());
            metrics::gauge!("node.sync.stall_seconds").set(stall_seconds);
            selected
        });
        if let Some(suppressed_for) = apply_side_escalation {
            // The no-blame suppression outlived its bound (issue #1091):
            // evict the stuck staged body for refetch and stand down for
            // this tick. No peer is convicted here; while the body is
            // absent the unsuppressed stall path applies as usual.
            self.escalate_stuck_staged_body(next_apply_height, frontier_hash, suppressed_for);
            return false;
        }
        if fired {
            let Some(peer_addr) = removed_peer else {
                return false;
            };
            metrics::counter!("node.sync.staller_disconnects").increment(1);
            tracing::warn!(
                peer_addr = %peer_addr,
                next_apply_height,
                "block sync: peer is stalling the download window; disconnecting and re-queueing its blocks"
            );
            return true;
        }
        if let Some((owner, front_hash)) = cold_hedge
            && let Some(alternate) =
                self.send_cold_front_hedge(owner, front_hash, next_apply_height, now)
        {
            self.frontier_state
                .lock()
                .window
                .confirm_cold_front_hedge(owner, alternate, front_hash);
        }
        false
    }

    /// Issue #1091 escalation: evict the stuck staged next-expected body for
    /// refetch, without blaming any peer.
    ///
    /// Fired by [`DownloadWindow::observe_apply_side_bound`] after the
    /// apply-side suppression held for two full `received_timeout` windows.
    /// `frontier_hash` is the snapshot the window observation fired on; the
    /// final equality check against the live frontier ensures a same-height
    /// branch replacement between observation and eviction cannot drain a
    /// body that never stalled. The eviction reuses the staged-body prune's
    /// requeue flow — stager removal first, then the tree-height re-evaluation,
    /// then the window drop-for-retry — so the request path re-requests the
    /// body: either the fresh delivery applies, or, while the body is
    /// absent, the normal unsuppressed stall path engages. If a peer then
    /// fails to re-deliver, THAT is a peer fault and the existing conviction
    /// machinery handles it; the eviction itself carries no blame.
    fn escalate_stuck_staged_body(
        &self,
        next_apply_height: u32,
        frontier_hash: Option<Hash256>,
        suppressed_for: Duration,
    ) {
        let Some(frontier_hash) = frontier_hash else {
            return;
        };
        if self.next_expected_block_hash() != Some(frontier_hash) {
            // Raced with a frontier change (e.g. a same-height branch
            // switch): the convicted body is no longer the expected one and
            // must not be drained.
            return;
        }
        let evicted = self
            .frontier_state
            .lock()
            .stager
            .drain_expected_prefix(&[frontier_hash]);
        if evicted.is_empty() {
            // Raced: the body was applied or pruned between the window
            // observation and this eviction; nothing is stuck anymore.
            return;
        }
        let height = {
            let tree = self.chain.block_tree().read();
            tree.lookup(frontier_hash)
                .and_then(|node_id| tree.node(node_id).ok())
                .map(|node| node.height)
        };
        {
            let mut frontier_state = self.frontier_state.lock();
            if let Some(height) = height {
                frontier_state
                    .window
                    .update_received_height(&frontier_hash, height);
            }
            frontier_state.window.drop_received_for_retry(&frontier_hash);
        }
        metrics::counter!("node.sync.apply_side_stall_escalations").increment(1);
        tracing::warn!(
            next_apply_height,
            suppressed_secs = suppressed_for.as_secs(),
            "block sync: staged next-expected body stuck past the apply-side bound; \
             evicting it for refetch without blaming any peer"
        );
    }

    pub(super) fn disconnect_timed_out_peer(&self, now: Instant) -> bool {
        let apply_side_busy = self
            .next_expected_block_hash()
            .is_some_and(|hash| self.frontier_state.lock().stager.contains(&hash));
        let Some(peer_addr) = self.select_and_evict_window_peer(|window| {
            window.observe_pending_timeout(apply_side_busy, now)
        }) else {
            return false;
        };
        metrics::counter!("node.sync.pending_timeout_disconnects").increment(1);
        tracing::warn!(
            peer_addr = %peer_addr,
            "block sync: peer missed the block request timeout; disconnecting and re-queueing its blocks"
        );
        true
    }

    /// Selects and evicts a download-window owner only when its latest
    /// reconciled connection identity is still live.
    pub(super) fn select_and_evict_window_peer(
        &self,
        select: impl FnOnce(&mut DownloadWindow) -> Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let peer_addr = {
            let mut frontier_state = self.frontier_state.lock();
            select(&mut frontier_state.window)?
        };
        let connection_id = self
            .frontier_state
            .lock()
            .known_sessions
            .get(&peer_addr)
            .copied()?;
        if !self
            .peer_table
            .disconnect_connection(peer_addr, connection_id)
        {
            return None;
        }
        let mut state = self.frontier_state.lock();
        if state
            .header_request
            .is_some_and(|request| request.source.addr == peer_addr)
        {
            state.header_request = None;
        }
        Some(peer_addr)
    }
}
