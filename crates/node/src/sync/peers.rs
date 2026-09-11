//! Peer selection, request dispatch, hedging, and staller policy.

use alloc::vec::Vec;

use bitcoin::{hashes::Hash as _, p2p::message_blockdata::Inventory};

use bitcoin_rs_chain::{BlockTree, ChainError, NodeId, TipSnapshot, plan_reorg};

use bitcoin_rs_p2p::{
    Message, PeerInfo,
    download_window::{
        DownloadWindow, FanoutCandidate, SyncPeer, SyncPeerSelection, configure_request_mode,
        statically_fanout_eligible,
    },
};

use bitcoin_rs_primitives::Hash256;

use smallvec::SmallVec;

use std::{net::SocketAddr, time::Instant};

use super::{
    BlockSync,
    expected::{ExpectedApplyCache, ExpectedBlockHashes},
    observability::metric_count,
};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct GetdataRequestOutcome {
    pub(super) sent: bool,
    pub(super) has_request_capacity: bool,
}

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

    /// Sends one estimated-2MiB common-prefix probe to each idle alternate.
    ///
    /// Every alternate receives the same earliest hashes, so the probe cannot
    /// create a unique out-of-order height hole. It runs once per deep owner.
    pub(super) fn send_prefix_probes(&self, probe_peers: &[SyncPeer], now: Instant) {
        let mut window = self.download_window.lock();
        let Some((owner, hashes, required_height)) = window.prefix_probe_plan() else {
            return;
        };
        let candidates = probe_peers.iter().filter(|peer| {
            peer.addr != owner
                && u32::try_from(peer.best_known_height)
                    .is_ok_and(|height| height >= required_height)
        });
        let mut successful = SmallVec::<[SocketAddr; 8]>::new();
        for peer in candidates {
            let peer_addr = peer.addr;
            let Some(tx) = self.peer_table.lease(peer_addr) else {
                continue;
            };
            let inventory = hashes
                .iter()
                .map(|hash| {
                    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                        *hash.as_byte_array(),
                    ))
                })
                .collect();
            if tx.send(Message::GetData(inventory)).is_ok() {
                successful.push(peer_addr);
            }
        }
        if successful.is_empty() {
            return;
        }
        let block_count = hashes.len();
        window.confirm_prefix_probe(owner, hashes, &successful, now);
        metrics::counter!("node.sync.prefix_probe_peers")
            .increment(u64::try_from(successful.len()).unwrap_or(u64::MAX));
        tracing::info!(
            owner = %owner,
            alternates = successful.len(),
            blocks = block_count,
            "block sync: started common-prefix peer probe"
        );
    }

    pub(super) fn send_getdata_for_pending_blocks(
        &self,
        sync_peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
    ) -> GetdataRequestOutcome {
        let now = Instant::now();
        let tree = self.handles.block_tree.read();
        let Some(applied_id) = tree.lookup(applied_tip.hash) else {
            return GetdataRequestOutcome::default();
        };
        let Ok(plan) = plan_reorg(&tree, applied_id, chain_tip.tip_id) else {
            return GetdataRequestOutcome::default();
        };
        let Some(first_connect) = plan.connect.first() else {
            return GetdataRequestOutcome::default();
        };
        let Ok(first_connect) = tree.node(*first_connect) else {
            return GetdataRequestOutcome::default();
        };
        let request_start_height = first_connect.height;

        let mut window = self.download_window.lock();
        let request = window.next_peer_request(
            sync_peer_addr,
            allow_expired_retry_from_peer,
            chain_tip,
            request_start_height,
            peer_best_height,
            &tree,
            now,
        );
        drop(tree);
        let Some(request) = request else {
            return GetdataRequestOutcome::default();
        };

        let count = request.len();
        let mut inventory = Vec::with_capacity(count);
        let mut expected_hashes = ExpectedBlockHashes::with_capacity(count);
        let mut expected_height = applied_tip.height.saturating_add(1);
        let mut is_contiguous = true;
        for (height, hash) in request.entries() {
            inventory.push(Inventory::WitnessBlock(
                bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()),
            ));
            if is_contiguous && height == expected_height {
                expected_hashes.push(hash);
                expected_height = if let Some(next) = expected_height.checked_add(1) {
                    next
                } else {
                    is_contiguous = false;
                    expected_height
                };
            } else {
                is_contiguous = false;
            }
        }
        let msg = Message::GetData(inventory);

        let tx = self.peer_table.lease(request.peer_addr());
        let Some(tx) = tx else {
            tracing::trace!(
                peer_addr = %request.peer_addr(),
                "block sync: target peer has no outbound channel (getdata skipped)"
            );
            return GetdataRequestOutcome::default();
        };
        let source = tx.source(request.peer_addr());
        let mut send_ok = false;
        let mut has_request_capacity = false;
        let still_current = self.peer_table.with_current(source, || {
            send_ok = tx.send(msg).is_ok();
            if send_ok {
                has_request_capacity = window.mark_requested(&request, now);
            }
        });
        if !still_current {
            return GetdataRequestOutcome::default();
        }
        if !send_ok {
            tracing::warn!(
                peer_addr = %request.peer_addr(),
                "block sync: outbound channel disconnected (getdata)"
            );
            return GetdataRequestOutcome::default();
        }
        if is_contiguous {
            *self.expected_apply_cache.lock() = Some(ExpectedApplyCache {
                chain_tip_hash: chain_tip.hash,
                applied_tip_hash: applied_tip.hash,
                applied_tip_height: applied_tip.height,
                offset: 0,
                hashes: expected_hashes,
            });
        }
        metrics::histogram!("node.sync.getdata_batch_size").record(metric_count(count));
        tracing::debug!(
            peer_addr = %request.peer_addr(),
            count,
            applied_height = applied_tip.height,
            chain_height = chain_tip.height,
            "block sync: sent getdata batch"
        );
        GetdataRequestOutcome {
            sent: true,
            has_request_capacity,
        }
    }

    /// Sends one untracked duplicate request for a cold-start stalled front.
    ///
    /// The original request remains the sole pending owner. This bounded
    /// hedge therefore changes neither capacity accounting nor timeout state.
    pub(super) fn send_cold_front_hedge(
        &self,
        owner: SocketAddr,
        front_hash: Hash256,
        front_height: u32,
        now: Instant,
    ) -> Option<SocketAddr> {
        let sessions = self.peer_table.sessions();
        let tree = self.handles.block_tree.read();
        let active_tip = self.handles.chain_tip.load_full()?.tip_id;
        let active_front_height = tree.active_height_of(active_tip, front_hash)?;
        let mut candidates = SmallVec::<[SocketAddr; 8]>::new();
        for session in sessions {
            let Some(peer) = session.info else {
                continue;
            };
            if peer.addr != owner
                && statically_fanout_eligible(&peer)
                && body_capability_height(
                    &peer,
                    &tree,
                    Some(active_tip),
                    &session.demonstrated_tips,
                )
                .is_some_and(|height| height >= active_front_height)
            {
                candidates.push(peer.addr);
            }
        }
        drop(tree);
        let candidates: SmallVec<[SocketAddr; 8]> = {
            let window = self.download_window.lock();
            candidates
                .into_iter()
                .filter(|addr| {
                    !window.peer_has_expired_pending(*addr, now)
                        && !window.peer_in_staller_cooldown(*addr, now)
                })
                .collect()
        };
        let mut message = Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array(*front_hash.as_byte_array()),
        )]);
        for peer_addr in candidates {
            let tx = self.peer_table.lease(peer_addr);
            let Some(tx) = tx else {
                continue;
            };
            match tx.send(message) {
                Ok(()) => {
                    metrics::counter!("node.sync.cold_front_hedges").increment(1);
                    tracing::info!(
                        owner = %owner,
                        hedge_peer = %peer_addr,
                        %front_hash,
                        front_height,
                        "block sync: hedged cold-start stalled front"
                    );
                    return Some(peer_addr);
                }
                Err(error) => {
                    message = error.0;
                }
            }
        }
        None
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
