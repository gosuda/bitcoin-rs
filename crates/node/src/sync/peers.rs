//! Session reconciliation, useful-peer selection, and stalled-peer retirement.

use super::BlockSync;
use alloc::vec::Vec;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_p2p::PeerInfo;
use bitcoin_rs_p2p::download_window::DownloadWindow;
use bitcoin_rs_p2p::download_window::FanoutCandidate;
use bitcoin_rs_p2p::download_window::SyncPeer;
use bitcoin_rs_p2p::download_window::SyncPeerSelection;
use bitcoin_rs_p2p::download_window::configure_request_mode;
use bitcoin_rs_p2p::download_window::statically_fanout_eligible;
use bitcoin_rs_primitives::Hash256;
use std::net::SocketAddr;
use std::time::Instant;

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
    /// connection. Stale sources are ignored; see
    /// `docs/solutions/architecture-patterns/p2p-owns-peer-lifecycle.md`.
    pub fn on_peer_ready(&self, source: bitcoin_rs_p2p::PeerSource) {
        // Window before table, matching `tick` / `send_getdata_for_pending_blocks`.
        let mut window = self.download_window.lock();
        if !self.peer_table.is_current(source) {
            return;
        }
        window.forget_peer(source.addr);
        drop(window);
        let mut pending = self.pending_getheaders.lock();
        if pending.is_some_and(|request| request.peer_addr == source.addr)
            && self.peer_table.is_current(source)
        {
            *pending = None;
        }
    }

    pub(super) fn reconcile_peer_sessions(&self) {
        let live = self.peer_table.live_connections();
        let mut window = self.download_window.lock();
        let mut known = self.known_sessions.lock();
        for (addr, id) in &live {
            if known.insert(*addr, *id).is_some_and(|prev| prev != *id) {
                window.forget_peer(*addr);
                let mut pending = self.pending_getheaders.lock();
                if pending.is_some_and(|request| request.peer_addr == *addr) {
                    *pending = None;
                }
            }
        }
        known.retain(|addr, _| live.iter().any(|(a, _)| a == addr));
        window.release_disconnected_peers(|peer| live.iter().any(|(a, _)| a == peer));
    }

    pub(super) fn sync_peer_selection(&self, our_height: u32, now: Instant) -> SyncPeerSelection {
        let mut header_peer: Option<SyncPeer> = None;
        let mut candidates: Vec<FanoutCandidate> = Vec::new();
        let sessions = self.peer_table.sessions();
        let tree = self.handles.block_tree.read();
        let active_tip = tree.tip_id();
        for session in sessions {
            let Some(peer) = session.info else {
                continue;
            };
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
            let Some(sync_peer) = sync_peer_candidate(&peer, our_height) else {
                continue;
            };
            if header_peer.is_none_or(|current| outranks(current, sync_peer)) {
                header_peer = Some(sync_peer);
            }
            let Some(active_height) =
                body_capability_height(&peer, &tree, active_tip, &session.demonstrated_tips)
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
                fanout_eligible: statically_fanout_eligible(&peer),
                soft_blocked: false,
            });
        }
        drop(tree);
        let (request_peer_limit, fanout_active, cold_preferred) = {
            let mut window = self.download_window.lock();
            for candidate in &mut candidates {
                candidate.soft_blocked = window.peer_has_expired_pending(candidate.peer.addr, now)
                    || window.peer_in_staller_cooldown(candidate.peer.addr, now);
                candidate.fanout_eligible = candidate.fanout_eligible && !candidate.soft_blocked;
            }
            let cold_preferred = configure_request_mode(&mut window, &candidates, now);
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
            alloc::vec![preferred]
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
            for candidate in candidates
                .iter()
                .filter(|candidate| !candidate.soft_blocked)
            {
                // First-wins on equal heights, matching the header-peer fold.
                if preferred.is_none_or(|current| outranks(current, candidate.peer)) {
                    preferred = Some(candidate.peer);
                }
            }
            preferred
                .or(header_peer)
                .into_iter()
                .take(request_peer_limit)
                .collect()
        };
        if request_peers.len() > 1 {
            request_peers.sort_by_key(|peer| std::cmp::Reverse(peer.best_known_height));
        }
        request_peers.truncate(request_peer_limit);
        SyncPeerSelection {
            header_peer,
            request_peers,
            probe_peers,
        }
    }

    /// R8: window-blocked staller detection and disconnect.
    ///
    /// Computes the sync-layer terms of the stall predicate and advances the
    /// window's stall state machine ([`DownloadWindow::observe_stall`] holds
    /// the predicate itself). While the stager holds the next expected block,
    /// the apply side owns the frontier and no peer is blamed.
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
        let apply_side_busy = self
            .next_expected_block_hash()
            .is_some_and(|hash| self.block_stager.lock().contains(&hash));
        let mut cold_hedge = None;
        let mut fired = false;
        let removed_peer = self.select_and_evict_window_peer(|window| {
            cold_hedge = window.observe_cold_front(next_apply_height, apply_side_busy, now);
            let selected = window.observe_stall(next_apply_height, apply_side_busy, now);
            fired = selected.is_some();
            let stall_seconds = window
                .stalling_peer()
                .map_or(0.0, |(_, since)| now.duration_since(since).as_secs_f64());
            metrics::gauge!("node.sync.stall_seconds").set(stall_seconds);
            selected
        });
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
            self.download_window
                .lock()
                .confirm_cold_front_hedge(owner, alternate, front_hash);
        }
        false
    }

    pub(super) fn disconnect_timed_out_peer(&self, now: Instant) -> bool {
        let apply_side_busy = self
            .next_expected_block_hash()
            .is_some_and(|hash| self.block_stager.lock().contains(&hash));
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
        let mut window = self.download_window.lock();
        let peer_addr = select(&mut window)?;
        let connection_id = self.known_sessions.lock().get(&peer_addr).copied()?;
        if !self
            .peer_table
            .disconnect_connection(peer_addr, connection_id)
        {
            return None;
        }
        let mut pending = self.pending_getheaders.lock();
        if pending.is_some_and(|request| request.peer_addr == peer_addr) {
            *pending = None;
        }
        Some(peer_addr)
    }
}
