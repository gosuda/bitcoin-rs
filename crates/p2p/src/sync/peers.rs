//! Session reconciliation, useful-peer selection, and stalled-peer retirement.

use super::BlockSync;
use super::GetheadersOutcome;
use super::SchedulerState;
use super::frontier::{ChainFrontier, SyncFrontier, UsablePeer};
use crate::PeerInfo;
use crate::connection::PeerSource;
use crate::download_window::BlameReason;
use crate::download_window::BlockedContext;
use crate::download_window::BlockedDecision;
use crate::download_window::FanoutCandidate;
use crate::download_window::MINIMUM_CONNECT_TIME;
use crate::download_window::SyncPeer;
use crate::download_window::SyncPeerSelection;
use crate::download_window::configure_request_mode;
use crate::download_window::{
    BlockDownloadPolicy, peer_can_serve_height, serves_requested_height, statically_fanout_eligible,
};
use crate::peer_info::PeerRole;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_primitives::Hash256;
use std::sync::Arc;
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
        | ChainError::TimestampTooEarly { .. }
        | ChainError::BadVersion { .. }
        | ChainError::TimewarpAttack { .. }
        | ChainError::KnownInvalidHeader { .. } => true,
        ChainError::TimestampTooFarAhead { .. }
        | ChainError::DuplicateHeader { .. }
        | ChainError::MissingParent { .. }
        | ChainError::NodeIdOverflow { .. }
        | ChainError::UnknownNode { .. }
        | ChainError::NoCommonAncestor { .. }
        | ChainError::InvalidParent { .. } => false,
    }
}

/// The one eligibility and ordering rule for demonstrated-best-known height
/// peer selection (P2P-03): a peer is request-eligible when its demonstrated
/// height exceeds `floor`, and among eligible peers the greatest height wins.
pub(super) fn sync_peer_candidate(
    source: PeerSource,
    peer: &PeerInfo,
    headers_horizon: Option<u32>,
    floor: u32,
) -> Option<SyncPeer> {
    let claimed = u32::try_from(peer.best_known_height).ok()?;
    let height = headers_horizon.map_or(claimed, |cap| claimed.min(cap));
    (height > floor).then_some(SyncPeer {
        source,
        best_known_height: i32::try_from(height).unwrap_or(i32::MAX),
    })
}

/// Whether `candidate` outranks `current`: strictly greater demonstrated
/// height; first-wins on ties.
pub(super) fn outranks(current: SyncPeer, candidate: SyncPeer) -> bool {
    candidate.best_known_height > current.best_known_height
}
fn body_request_peers(candidates: &[FanoutCandidate]) -> Vec<SyncPeer> {
    let healthy: Vec<SyncPeer> = candidates
        .iter()
        .filter(|candidate| candidate.serves_bodies && !candidate.soft_blocked)
        .map(|candidate| candidate.peer)
        .collect();
    if healthy.is_empty() {
        candidates
            .iter()
            .filter(|candidate| candidate.serves_bodies)
            .map(|candidate| candidate.peer)
            .collect()
    } else {
        healthy
    }
}

fn fallback_request_peer(
    candidates: &[FanoutCandidate],
    request_peer_limit: usize,
) -> Vec<SyncPeer> {
    let mut preferred: Option<SyncPeer> = None;
    let servers: Vec<&FanoutCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.serves_bodies)
        .collect();
    let allow_soft = servers.iter().all(|candidate| candidate.soft_blocked);
    for candidate in servers
        .iter()
        .filter(|candidate| allow_soft || !candidate.soft_blocked)
    {
        if preferred.is_none_or(|current| outranks(current, candidate.peer)) {
            preferred = Some(candidate.peer);
        }
    }
    preferred.into_iter().take(request_peer_limit).collect()
}

pub(super) fn shared_active_height(
    tree: &BlockTree,
    active_tip: NodeId,
    hash: Hash256,
) -> Option<u32> {
    let ancestor = tree.find_common_ancestor(active_tip, tree.lookup(hash)?)?;
    let height = tree.node(ancestor).ok()?.height;
    (tree.node_at_height_from(active_tip, height) == Some(ancestor)).then_some(height)
}

pub(super) fn active_demonstrated_height(
    tree: &BlockTree,
    active_tip: NodeId,
    demonstrated_tips: &[Hash256],
) -> Option<u32> {
    demonstrated_tips
        .iter()
        .filter_map(|hash| shared_active_height(tree, active_tip, *hash))
        .max()
}

/// How long a full-relay outbound connection may sit below our tip before it
/// is probed, and then retired: `CHAIN_SYNC_TIMEOUT` is 20 * 60 seconds, as
/// Core sets it (`net_processing.cpp`).
const CHAIN_SYNC_TIMEOUT: Duration = Duration::from_mins(20);

/// How long the answer to that probe is awaited: `HEADERS_RESPONSE_TIME` is
/// 2 * 60 seconds, as Core sets it (`net_processing.cpp`).
pub(super) const HEADERS_RESPONSE_TIME: Duration = Duration::from_mins(2);

/// How many tip-reaching outbound connections are never retired. Core's
/// `MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT` (`net_processing.cpp`).
const MAX_OUTBOUND_PEERS_TO_PROTECT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChainSyncAction {
    Probe,
    Evict,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ChainSyncState {
    timeout_start: Option<Instant>,
    benchmark: Option<u32>,
    probe_sent: bool,
    protected: bool,
}

impl ChainSyncState {
    #[must_use]
    pub(super) const fn is_protected(&self) -> bool {
        self.protected
    }

    #[cfg(test)]
    #[must_use]
    pub(super) const fn probe_sent(&self) -> bool {
        self.probe_sent
    }

    fn arm(&mut self, tip_height: u32, now: Instant) {
        self.timeout_start = Some(now);
        self.benchmark = Some(tip_height);
        self.probe_sent = false;
    }
}

pub(super) fn chain_sync_subject(peer: &UsablePeer, now: Instant) -> bool {
    !peer.info.inbound
        && !peer.manual
        && peer.role == PeerRole::FullRelay
        && now.saturating_duration_since(peer.connected_at) >= MINIMUM_CONNECT_TIME
}

pub(super) fn consider_eviction(
    peer: &UsablePeer,
    state: &mut ChainSyncState,
    tip_height: u32,
    now: Instant,
    protected_count: &mut usize,
) -> Option<ChainSyncAction> {
    let demonstrated = peer.demonstrated_height();
    if demonstrated.is_some_and(|height| height >= tip_height) {
        if !state.protected && *protected_count < MAX_OUTBOUND_PEERS_TO_PROTECT {
            state.protected = true;
            *protected_count += 1;
        }
        state.timeout_start = None;
        state.benchmark = None;
        state.probe_sent = false;
        return None;
    }
    if state.protected {
        return None;
    }
    let Some(start) = state.timeout_start else {
        state.arm(tip_height, now);
        return None;
    };
    let reached_benchmark = matches!(
        (state.benchmark, demonstrated),
        (Some(benchmark), Some(height)) if height >= benchmark
    );
    if reached_benchmark {
        state.arm(tip_height, now);
        return None;
    }
    if !state.probe_sent {
        if now.saturating_duration_since(start) < CHAIN_SYNC_TIMEOUT {
            return None;
        }
        state.probe_sent = true;
        state.timeout_start = Some(now);
        return Some(ChainSyncAction::Probe);
    }
    (now.saturating_duration_since(start) >= HEADERS_RESPONSE_TIME)
        .then_some(ChainSyncAction::Evict)
}

impl BlockSync {
    pub fn on_peer_ready(&self, source: crate::PeerSource) {
        if !self.peer_table.is_current(source) {
            return;
        }
        self.release_unowned_sessions();
    }

    pub(super) fn reconcile_peer_sessions(&self) {
        self.peer_table
            .disconnect_matching(|_, lease| lease.is_cancelled());
        self.release_unowned_sessions();
    }

    fn release_unowned_sessions(&self) {
        self.peer_table
            .with_live_sessions(|live| self.scheduler.lock().release_unowned(live));
    }

    pub(super) fn reconcile_window_recovery(&self, chain: &ChainFrontier, now: Instant) {
        if chain.apply_halted {
            return;
        }
        let frontier_hash = chain.next_required.map(|body| body.hash);
        let next_apply_height = chain.next_required.map(|body| body.height).or_else(|| {
            chain
                .applied_tip
                .as_ref()
                .and_then(|tip| tip.height.checked_add(1))
        });
        let decision = {
            let tree = self.chain.block_tree();
            let mut scheduler = self.scheduler.lock();
            let SchedulerState { window, stager, .. } = &mut *scheduler;
            let ctx = BlockedContext {
                next_apply_height,
                frontier_hash,
                apply_side_busy: frontier_hash.is_some_and(|hash| stager.contains(&hash)),
            };
            let decision = window.observe_blocked(ctx, stager, &tree, now);
            let stall_seconds = window
                .stalling_peer()
                .map_or(0.0, |(_, since)| now.duration_since(since).as_secs_f64());
            metrics::gauge!("node.sync.stall_seconds").set(stall_seconds);
            decision
        };
        if let BlockedDecision::Blame { owner, reason } = decision {
            self.disconnect_convicted(owner, reason, next_apply_height);
            return;
        }
        if let BlockedDecision::EvictStaged {
            height,
            hash,
            suppressed_for,
        } = decision
        {
            self.escalate_stuck_staged_body(height, Some(hash), suppressed_for, now);
            return;
        }
        if let BlockedDecision::HedgeColdFront { owner, front_hash } = decision
            && let Some(next_apply_height) = next_apply_height
            && let Some(alternate) =
                self.send_cold_front_hedge(owner, front_hash, next_apply_height, now)
        {
            self.scheduler
                .lock()
                .window
                .confirm_cold_front_hedge(owner, alternate, front_hash);
        }
    }

    fn disconnect_convicted(
        &self,
        owner: PeerSource,
        reason: BlameReason,
        next_apply_height: Option<u32>,
    ) {
        match reason {
            BlameReason::Staller => {
                if self.peer_table.disconnect_source(owner) {
                    metrics::counter!("node.sync.staller_disconnects").increment(1);
                    tracing::warn!(
                        peer_addr = ?owner.endpoint,
                        next_apply_height,
                        "block sync: peer is stalling the download window; disconnecting and re-queueing its blocks"
                    );
                }
            }
            BlameReason::PendingTimeout => {
                if self.peer_table.disconnect_source(owner) {
                    metrics::counter!("node.sync.pending_timeout_disconnects").increment(1);
                    tracing::warn!(
                        peer_addr = ?owner.endpoint,
                        "block sync: peer missed the block request timeout; disconnecting and re-queueing its blocks"
                    );
                }
            }
        }
    }

    fn escalate_stuck_staged_body(
        &self,
        next_apply_height: u32,
        frontier_hash: Option<Hash256>,
        suppressed_for: Duration,
        now: Instant,
    ) {
        let Some(frontier_hash) = frontier_hash else {
            return;
        };
        if self.next_expected_block_hash() != Some(frontier_hash) {
            return;
        }
        let evicted = self
            .scheduler
            .lock()
            .stager
            .drain_expected_prefix(&[frontier_hash]);
        if evicted.is_empty() {
            return;
        }
        let height = {
            let tree = self.chain.block_tree();
            tree.lookup(frontier_hash)
                .and_then(|node_id| tree.node(node_id).ok())
                .map(|node| node.height)
        };
        {
            let mut scheduler = self.scheduler.lock();
            scheduler
                .window
                .requeue_for_retry(&frontier_hash, height, now);
        }
        metrics::counter!("node.sync.apply_side_stall_escalations").increment(1);
        tracing::warn!(
            next_apply_height,
            suppressed_secs = suppressed_for.as_secs(),
            "block sync: staged next-expected body stuck past the apply-side bound; \
             evicting it for refetch without blaming any peer"
        );
    }

    pub(super) fn sync_peer_selection(
        &self,
        frontier: &SyncFrontier,
        now: Instant,
    ) -> SyncPeerSelection {
        let mut candidates = self.fanout_candidates(frontier);
        let (request_peer_limit, fanout_active, cold_preferred) =
            self.window_selection_limits(frontier, &mut candidates, now);
        let probe_peers = candidates
            .iter()
            .filter(|candidate| candidate.fanout_eligible && !candidate.soft_blocked)
            .map(|candidate| candidate.peer)
            .collect();
        let mut request_peers: Vec<SyncPeer> = if let Some(preferred) = cold_preferred {
            std::vec![preferred]
        } else if fanout_active {
            candidates
                .iter()
                .filter(|candidate| candidate.fanout_eligible && !candidate.soft_blocked)
                .map(|candidate| candidate.peer)
                .collect()
        } else if request_peer_limit > 1 {
            body_request_peers(&candidates)
        } else {
            fallback_request_peer(&candidates, request_peer_limit)
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

    fn fanout_candidates(&self, frontier: &SyncFrontier) -> Vec<FanoutCandidate> {
        let required_height = frontier.chain.next_required.map_or_else(
            || {
                frontier
                    .chain
                    .applied_tip
                    .as_ref()
                    .map_or(0, |tip| tip.height)
                    .saturating_add(1)
            },
            |body| body.height,
        );
        let policy = BlockDownloadPolicy {
            ibd: Arc::clone(&self.ibd),
            network: self.chain.network(),
            requested_height: required_height,
        };
        let mut candidates: Vec<FanoutCandidate> = Vec::new();
        for peer in &frontier.usable_peers {
            let Some(active_height) = peer.capability() else {
                continue;
            };
            if !peer_can_serve_height(&peer.info, active_height, required_height) {
                continue;
            }
            candidates.push(FanoutCandidate {
                peer: SyncPeer {
                    source: peer.source,
                    best_known_height: i32::try_from(active_height).unwrap_or(i32::MAX),
                },
                serves_bodies: serves_requested_height(&peer.info, &policy),
                fanout_eligible: statically_fanout_eligible(&peer.info, &policy),
                soft_blocked: false,
            });
        }
        candidates
    }

    fn window_selection_limits(
        &self,
        frontier: &SyncFrontier,
        candidates: &mut [FanoutCandidate],
        now: Instant,
    ) -> (usize, bool, Option<SyncPeer>) {
        let tree = (!frontier.chain.apply_halted
            && frontier.chain.chain_tip.is_some()
            && frontier.chain.next_required.is_some())
        .then(|| self.chain.block_tree());
        let mut scheduler = self.scheduler.lock();
        let SchedulerState {
            window,
            stager,
            body_unavailable,
            ..
        } = &mut *scheduler;
        if !frontier.chain.apply_halted
            && let (Some(tree), Some(chain_tip), Some(required)) = (
                tree.as_deref(),
                frontier.chain.chain_tip.as_ref(),
                frontier.chain.next_required.as_ref(),
            )
        {
            window.retarget_request_branch(stager, chain_tip, required.height, tree, now);
        }
        let required_hash = frontier.chain.next_required.map(|body| body.hash);
        for candidate in &mut *candidates {
            candidate.soft_blocked = window.peer_has_expired_pending(candidate.peer.source, now)
                || window.peer_in_staller_cooldown(candidate.peer.source, now)
                || required_hash
                    .is_some_and(|hash| body_unavailable.refuses(candidate.peer.source, hash, now));
        }
        let cold_preferred = configure_request_mode(window, candidates, now);
        (
            window.request_peer_scan_limit(stager, now),
            window.fanout_active(),
            cold_preferred,
        )
    }

    pub(super) fn sweep_chain_sync(&self, frontier: &SyncFrontier, now: Instant) -> bool {
        let Some(tip_height) = frontier.chain.chain_tip.as_ref().map(|tip| tip.height) else {
            return false;
        };
        let outcomes = {
            let mut scheduler = self.scheduler.lock();
            let mut protected = scheduler
                .chain_sync
                .values()
                .filter(|state| state.is_protected())
                .count();
            let mut outcomes = Vec::new();
            for peer in &frontier.usable_peers {
                if !chain_sync_subject(peer, now) {
                    continue;
                }
                let prior = scheduler.chain_sync.get(&peer.source).copied();
                let mut next = prior.unwrap_or_default();
                let action = consider_eviction(peer, &mut next, tip_height, now, &mut protected);
                match action {
                    Some(ChainSyncAction::Evict) => {
                        scheduler.chain_sync.remove(&peer.source);
                    }
                    _ => {
                        scheduler.chain_sync.insert(peer.source, next);
                    }
                }
                outcomes.push((peer.source, prior, action));
            }
            outcomes
        };

        let mut peers_changed = false;
        for (source, prior, action) in outcomes {
            match action {
                Some(ChainSyncAction::Probe) if !self.probe_chain_sync(source, frontier) => {
                    peers_changed |= !self.peer_table.is_current(source);
                    self.scheduler.lock().restore_chain_sync(source, prior);
                }
                Some(ChainSyncAction::Evict) => {
                    self.retire_chain_sync_peer(source);
                    peers_changed = true;
                }
                Some(ChainSyncAction::Probe) | None => {}
            }
        }
        peers_changed
    }

    fn retire_chain_sync_peer(&self, source: PeerSource) {
        if self.peer_table.disconnect_source(source) {
            metrics::counter!("node.sync.chain_sync_disconnects").increment(1);
            tracing::warn!(
                peer_addr = ?source.endpoint,
                "block sync: peer brought no better chain within the sync timeout; disconnecting"
            );
        }
    }

    pub(super) fn probe_chain_sync(&self, source: PeerSource, frontier: &SyncFrontier) -> bool {
        matches!(
            self.send_chain_sync_probe(frontier, source),
            GetheadersOutcome::Sent,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::body_request_peers;
    use super::is_peer_fault;
    use crate::connection::PeerSource;
    use crate::download_window::FanoutCandidate;
    use crate::download_window::SyncPeer;
    use bitcoin_rs_chain::{
        BlockTree, ChainError, NodeId, NodeStatus, accept_headers, compact_is_met_by,
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Header, Network};
    use std::net::SocketAddr;
    fn body_candidate_impl(port: u16, height: i32, soft_blocked: bool) -> FanoutCandidate {
        FanoutCandidate {
            peer: SyncPeer {
                source: PeerSource::for_test(SocketAddr::from(([127, 0, 0, 1], port))),
                best_known_height: height,
            },
            serves_bodies: true,
            fanout_eligible: true,
            soft_blocked,
        }
    }

    fn healthy_body_candidate(port: u16, height: i32) -> FanoutCandidate {
        body_candidate_impl(port, height, false)
    }

    fn soft_body_candidate(port: u16, height: i32) -> FanoutCandidate {
        body_candidate_impl(port, height, true)
    }

    #[test]
    fn multi_peer_body_scan_skips_soft_blocked_until_all_soft() {
        let mixed = body_request_peers(&[
            healthy_body_candidate(9001, 10),
            soft_body_candidate(9002, 20),
        ]);
        assert_eq!(mixed.len(), 1);
        assert_eq!(mixed[0].best_known_height, 10);
        assert_eq!(
            mixed[0].source.endpoint,
            Some(crate::PeerEndpoint::Ip(SocketAddr::from((
                [127, 0, 0, 1],
                9001
            )))),
        );

        let all_soft =
            body_request_peers(&[soft_body_candidate(9001, 10), soft_body_candidate(9002, 20)]);
        assert_eq!(all_soft.len(), 2);
    }

    #[test]
    fn header_contextual_refusals_blame_the_sender() {
        let hash = Hash256::default();
        for error in [
            ChainError::BadVersion {
                version: 1,
                required: 2,
                height: 500,
            },
            ChainError::TimewarpAttack {
                height: 2016,
                timestamp: 1,
                minimum: 601,
            },
            ChainError::TimestampTooEarly {
                hash,
                timestamp: 1,
                median: 2,
            },
            ChainError::NbitsMismatch {
                actual: 1,
                expected: 2,
                height: 3,
            },
        ] {
            assert!(is_peer_fault(&error), "{error:?} must retire the peer");
        }
    }

    #[test]
    fn clock_and_bookkeeping_refusals_spare_the_sender() {
        let hash = Hash256::default();
        for error in [
            ChainError::TimestampTooFarAhead {
                hash,
                timestamp: 9,
                max_allowed: 1,
            },
            ChainError::InvalidParent {
                parent: NodeId::new(3),
            },
            ChainError::MissingParent { prev_hash: hash },
            ChainError::UnknownNode { id: NodeId::new(1) },
        ] {
            assert!(!is_peer_fault(&error), "{error:?} must spare the peer");
        }
    }

    fn mined_header(prev_blockhash: BlockHash, time: u32) -> Header {
        let mut header = Header {
            version: 4,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        while !compact_is_met_by(header.bits, header.compute_hash().0) {
            header.nonce = header
                .nonce
                .checked_add(1)
                .unwrap_or_else(|| panic!("test nonce exhausted"));
        }
        header
    }

    #[test]
    fn descendant_of_an_invalidated_block_spares_the_sender()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = mined_header(BlockHash::default(), 900_000);
        let genesis_id = tree.insert_header(genesis, NodeStatus::HeaderValid)?;
        let child = mined_header(BlockHash::from(tree.node(genesis_id)?.hash), 900_600);
        let child_id = tree.insert_header(child, NodeStatus::HeaderValid)?;

        tree.invalidate_subtree(child_id)?;

        let grandchild = mined_header(BlockHash::from(tree.node(child_id)?.hash), 901_200);
        let error = accept_headers(
            &mut tree,
            &[grandchild],
            Network::Regtest,
            901_800,
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        )
        .err()
        .ok_or("a descendant of an invalidated block must be refused")?;
        assert_eq!(error, ChainError::InvalidParent { parent: child_id });
        assert!(
            !is_peer_fault(&error),
            "an operator invalidation must not retire the peer relaying a descendant"
        );
        Ok(())
    }
}
