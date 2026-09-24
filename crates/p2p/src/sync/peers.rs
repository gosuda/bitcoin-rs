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
    BlockDownloadPolicy, serves_requested_height, statically_fanout_eligible,
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
        // A median-time-past violation is decided entirely by the chain the peer
        // itself sent, so it is unambiguously the peer's fault.
        | ChainError::TimestampTooEarly { .. }
        // Re-announcing a header we already know is invalid or extending a
        // known-invalid parent is unambiguously peer-invalid data.
        | ChainError::KnownInvalidHeader { .. }
        | ChainError::InvalidParent { .. } => true,
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
pub(super) fn sync_peer_candidate(
    source: PeerSource,
    peer: &PeerInfo,
    floor: u32,
) -> Option<SyncPeer> {
    let height = u32::try_from(peer.best_known_height).ok()?;
    (height > floor).then_some(SyncPeer {
        source,
        best_known_height: peer.best_known_height,
    })
}

/// Whether `candidate` outranks `current`: strictly greater demonstrated
/// height; first-wins on ties.
pub(super) fn outranks(current: SyncPeer, candidate: SyncPeer) -> bool {
    candidate.best_known_height > current.best_known_height
}

/// Height of the deepest active-chain node that is an ancestor of `hash` —
/// `hash`'s own height when it is on the active chain, `None` only when
/// `hash` is unknown to the tree. A demonstrated tip implies capability for
/// every ancestor it shares with the active chain: a fork tip whose branch
/// later wins already proved the peer can serve the shared prefix, and one
/// whose branch lost still proved the same.
pub(super) fn shared_active_height(
    tree: &BlockTree,
    active_tip: NodeId,
    hash: Hash256,
) -> Option<u32> {
    let mut node_id = tree.lookup(hash)?;
    loop {
        let node = tree.node(node_id).ok()?;
        if tree.node_at_height_from(active_tip, node.height) == Some(node_id) {
            return Some(node.height);
        }
        node_id = node.parent?;
    }
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
/// Core sets it (`net_processing.cpp:109`).
const CHAIN_SYNC_TIMEOUT: Duration = Duration::from_mins(20);

/// How long the answer to that probe is awaited: `HEADERS_RESPONSE_TIME` is
/// 2 * 60 seconds, as Core sets it (`net_processing.cpp:103`).
const HEADERS_RESPONSE_TIME: Duration = Duration::from_mins(2);

/// How many tip-reaching outbound connections are never retired. Core's
/// `MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT` (`net_processing.cpp:107`).
const MAX_OUTBOUND_PEERS_TO_PROTECT: usize = 4;

/// What the chain-sync rule owes one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChainSyncAction {
    /// Send this connection exactly one `getheaders` from our locator.
    Probe,
    /// Retire it: it had the timeout to show a better chain and the response
    /// window to answer the probe.
    Evict,
}

/// The chain-sync record of one connection.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ChainSyncState {
    /// When this connection became worth timing out, `None` while it is
    /// keeping up, protected, or never yet observed behind the tip.
    timeout_start: Option<Instant>,
    /// The tip height recorded when the running window was armed: a
    /// connection that reaches it gets a fresh window even while our tip has
    /// moved on. Core's `m_work_header` (`net_processing.cpp:5519-5527`).
    benchmark: Option<u32>,
    /// Whether a probe was sent since `timeout_start` was set.
    probe_sent: bool,
    /// Whether this connection is one of the first
    /// `MAX_OUTBOUND_PEERS_TO_PROTECT` to reach the tip.
    protected: bool,
}

impl ChainSyncState {
    /// Whether this connection holds protection from the timer.
    #[must_use]
    pub(super) const fn is_protected(&self) -> bool {
        self.protected
    }

    /// Starts a fresh window against the current tip, as Core's
    /// `m_work_header = tip` arm does
    /// (`net_processing.cpp:5519-5527`).
    fn arm(&mut self, tip_height: u32, now: Instant) {
        self.timeout_start = Some(now);
        self.benchmark = Some(tip_height);
        self.probe_sent = false;
    }
}

/// Whether the chain-sync rule applies to `peer`.
///
/// PRE: `now` is this tick's monotonic stamp.
/// POST: return true exactly for an outbound, not operator-pinned,
///   full-relay connection older than `MINIMUM_CONNECT_TIME`.
/// INVARIANT: an inbound connection is never timed out, because we did not
///   choose it; neither is a manual one, because the operator did — Core
///   gates the rule on `IsOutboundOrBlockRelayConn()`, which excludes
///   `ConnectionType::MANUAL` (`net_processing.cpp:5502`). Neither is a
///   block-relay-only one, which is never asked to bring us a chain: Core
///   times out both outbound classes
///   (`ConsiderEviction`, `net_processing.cpp:5498-5550`); keeping the
///   block-relay population out of the rule is a documented divergence, so a
///   connection we dialed for blocks alone is never replaced by this timer.
pub(super) fn chain_sync_subject(peer: &UsablePeer, now: Instant) -> bool {
    !peer.info.inbound
        && !peer.manual
        && peer.role == PeerRole::FullRelay
        && now.saturating_duration_since(peer.connected_at) >= MINIMUM_CONNECT_TIME
}

/// Advances one connection's chain-sync record and names the action owed.
///
/// PRE: `peer` is a subject connection (`chain_sync_subject`), `tip_height` is
///   our heaviest header height, and `protected_count` is how many
///   connections already hold protection.
/// POST: return `Some(Probe)` once a connection has sat below `tip_height` for
///   `CHAIN_SYNC_TIMEOUT`, `Some(Evict)` when `HEADERS_RESPONSE_TIME` passes
///   after that probe, and `None` otherwise. A connection that DEMONSTRATED a
///   tip at or above `tip_height` has its window cleared and, while fewer
///   than `MAX_OUTBOUND_PEERS_TO_PROTECT` hold it, takes protection, which it
///   keeps for the life of the connection. A connection that only CLAIMED a
///   height in its handshake is armed like any other: the claim is the
///   remote's word, not evidence. Reaching the benchmark recorded at the last
///   arm restarts the window against the current tip.
/// INVARIANT: this is Core's `ConsiderEviction`
///   (`net_processing.cpp:5498-5550`) with the chainwork comparison replaced
///   by the demonstrated height the scheduler already carries, because that
///   height is the fact this node requests bodies on. Protection and the
///   catch-up clear read `demonstrated_height`, never the handshake claim,
///   as Core reads `pindexBestKnownBlock` and not `nStartingHeight`
///   (`net_processing.cpp:3203-3210`).
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
    // Progress to the tip we held when the window started buys a fresh
    // window, even while our own tip has moved past it.
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
    /// Sweeps scheduler state owned by dead connections when `source`
    /// becomes ready. Stale sources are ignored per P2P-02.
    pub fn on_peer_ready(&self, source: crate::PeerSource) {
        // Identity gate first, outside the scheduler lock: validating under
        // the scheduler can deadlock behind a queued table writer while an
        // existing table reader waits for this scheduler.
        if !self.peer_table.is_current(source) {
            return;
        }
        self.release_unowned_sessions();
    }

    /// Reconciles the scheduler with the peer table: cancelled leases leave
    /// the table, then one sweep releases every fact owned by a connection
    /// outside the live session set.
    pub(super) fn reconcile_peer_sessions(&self) {
        // Backstop: a session whose connection already cancelled its lease
        // leaves the table within one tick, whatever path cancelled it, so
        // zombie entries are never candidates for fetch work.
        self.peer_table
            .disconnect_matching(|_, lease| lease.is_cancelled());
        self.release_unowned_sessions();
    }

    /// Releases every scheduler ownership fact whose connection left the
    /// live session set: one sweep keyed on connection identity.
    ///
    /// PRE: the caller holds no scheduler lock.
    /// POST: every scheduler ownership fact names a live connection.
    /// INVARIANT: lock order is peer table, then scheduler; the snapshot and
    ///   the release see the same live set.
    fn release_unowned_sessions(&self) {
        self.peer_table
            .with_live_sessions(|live| self.scheduler.lock().release_unowned(live));
    }

    /// Advances the window's blockage observations against the canonical
    /// frontier and performs the single action the unified decision names:
    /// convict one owner, evict one stuck staged body, or fire one bounded
    /// cold-front hedge.
    ///
    /// R8: window-blocked staller detection, the #1091 apply-side
    /// suppression bound, and the pending-timeout fallback all read the
    /// same `next_required` body the scheduler requests — the frontier
    /// cannot disagree with itself about which block is required next.
    ///
    /// Convictions are identity-exact: `disconnect_source` removes only the
    /// connection that owns the stalled work, so a same-address replacement
    /// survives and never inherits the blame.
    ///
    /// While the apply path has latched a fatal settlement no recovery fires:
    /// deliveries cannot apply, so non-delivery is not a peer fault, and a
    /// staged body stays queued for the re-created apply path rather than
    /// being evicted past the suppression bound.
    pub(super) fn reconcile_window_recovery(&self, chain: &ChainFrontier, now: Instant) {
        if chain.apply_halted {
            return;
        }
        let frontier_hash = chain.next_required.map(|body| body.hash);
        // The stall family keys on the same `next_required` body the
        // scheduler requests; at the tip the front sits one past the applied
        // height, exactly as the pre-frontier derivation computed it.
        let next_apply_height = chain.next_required.map(|body| body.height).or_else(|| {
            chain
                .applied_tip
                .as_ref()
                .and_then(|tip| tip.height.checked_add(1))
        });
        let decision = {
            // Lock order tree -> scheduler (as in request publication): the
            // stall predicate resolves staged hashes against block-tree
            // heights, so the tree guard is held across the window read.
            let tree = self.chain.block_tree();
            let mut scheduler = self.scheduler.lock();
            let SchedulerState { window, stager, .. } = &mut *scheduler;
            let ctx = BlockedContext {
                next_apply_height,
                frontier_hash,
                apply_side_busy: frontier_hash.is_some_and(|hash| stager.contains(&hash)),
                active_downloading_peers: window.active_downloading_peers(),
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
            // The no-blame suppression outlived its bound (issue #1091):
            // evict the stuck staged body for refetch. No peer is convicted
            // here; while the body is absent the unsuppressed stall path
            // applies as usual.
            self.escalate_stuck_staged_body(height, Some(hash), suppressed_for, now);
            return;
        }
        // The hedge only fires with a frontier height present, so
        // `next_apply_height` is `Some` here.
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

    /// Performs the blame action of [`BlockedDecision`]: disconnect the
    /// convicted exact owner and report the reason on the frozen operator
    /// counters.
    ///
    /// PRE: `owner` names the exact connection the window convicted.
    /// POST: at most one connection is disconnected; a dead owner makes
    ///      the disconnect a no-op.
    /// INVARIANT: the counter names (`node.sync.staller_disconnects`,
    ///      `node.sync.pending_timeout_disconnects`) are operator-visible
    ///      and frozen.
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
                        peer_addr = %owner.addr,
                        next_apply_height,
                        "block sync: peer is stalling the download window; disconnecting and re-queueing its blocks"
                    );
                }
            }
            BlameReason::PendingTimeout => {
                if self.peer_table.disconnect_source(owner) {
                    metrics::counter!("node.sync.pending_timeout_disconnects").increment(1);
                    tracing::warn!(
                        peer_addr = %owner.addr,
                        "block sync: peer missed the block request timeout; disconnecting and re-queueing its blocks"
                    );
                }
            }
        }
    }

    /// Issue #1091 escalation: evict the stuck staged body for
    /// refetch, without blaming any peer.
    ///
    /// Fired on [`BlockedDecision::EvictStaged`] after the apply-side
    /// suppression held for two full `received_timeout` windows.
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
        now: Instant,
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
            .scheduler
            .lock()
            .stager
            .drain_expected_prefix(&[frontier_hash]);
        if evicted.is_empty() {
            // Raced: the body was applied or pruned between the window
            // observation and this eviction; nothing is stuck anymore.
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
            // The tree owns the height: requeue drops the cursor to the
            // body's tree height, or leaves it alone when unresolvable.
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

    /// Picks the peers eligible for body requests and prefix probes from the
    /// frontier's usable-peer snapshot. The selection no longer re-walks the
    /// session table or the block tree: `observe_frontier` already resolved
    /// each peer's demonstrated capability once this tick.
    pub(super) fn sync_peer_selection(
        &self,
        frontier: &SyncFrontier,
        now: Instant,
    ) -> SyncPeerSelection {
        // Height clause of the fan-out eligibility predicate (KTD6) and
        // the pre-existing candidate filter: the peer's demonstrated chain
        // must cover the canonical next-required body — on a reorg whose
        // first connect node sits below the applied tip, that is lower
        // than the applied height, so gating on the applied height would
        // declare the body requestable yet never pick a peer for it.
        // Like Core's `pindexBestKnownBlock`, eligibility reads the
        // demonstrated best-known height (handshake snapshot, raised as
        // the peer hands us accepted headers) rather than the handshake
        // value alone — a long-lived at-tip peer would otherwise become
        // ineligible for every newly announced block (#617). Per-request
        // truncation by `peer_best_height` still bounds the damage of a
        // stale value. With nothing required the clause reduces to the
        // applied tip's successor, as before.
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
            requested_height: required_height,
        };
        let mut candidates: Vec<FanoutCandidate> = Vec::new();
        for peer in &frontier.usable_peers {
            let Some(active_height) = peer.capability() else {
                continue;
            };
            if active_height < required_height {
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
        let (request_peer_limit, fanout_active, cold_preferred) = {
            let mut scheduler = self.scheduler.lock();
            let SchedulerState { window, stager, .. } = &mut *scheduler;
            for candidate in &mut candidates {
                candidate.soft_blocked = window
                    .peer_has_expired_pending(candidate.peer.source, now)
                    || window.peer_in_staller_cooldown(candidate.peer.source.addr, now);
            }
            let cold_preferred = configure_request_mode(window, &candidates, now);
            (
                window.request_peer_scan_limit(stager, now),
                window.fanout_active(),
                cold_preferred,
            )
        };
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
            candidates
                .iter()
                .filter(|candidate| candidate.serves_bodies)
                .map(|candidate| candidate.peer)
                .collect()
        } else {
            // Fallback, single deep peer: the highest peer that may serve
            // block bodies and that the window does not currently soft-block
            // (expired pendings / staller cooldown) fills the window; a
            // soft-blocked peer serves only as the last resort when no
            // alternative exists. Without the preference, a disconnected
            // staller that reconnects with an inflated demonstrated
            // best-known height would out-sort every honest peer and
            // re-acquire the window front (RE-ADV-2 / first-audit ADV-2).
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

    /// Runs the chain-sync rule over this tick's connections and performs the
    /// actions it names.
    ///
    /// PRE: `frontier` is the observation made at `now`.
    /// POST: every subject connection is armed, probed, or retired, and a
    ///   retired connection keeps no record.
    /// INVARIANT: the probe send and the disconnect happen outside the
    ///   scheduler lock, and a probe that never left the node restores the
    ///   record it was about to change, so the rule retries instead of
    ///   condemning a connection it never asked.
    pub(super) fn sweep_chain_sync(&self, frontier: &SyncFrontier, now: Instant) {
        let Some(tip_height) = frontier.chain.chain_tip.as_ref().map(|tip| tip.height) else {
            return;
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

        for (source, prior, action) in outcomes {
            match action {
                Some(ChainSyncAction::Probe) => {
                    if !self.probe_chain_sync(source, frontier) {
                        self.scheduler.lock().restore_chain_sync(source, prior);
                    }
                }
                Some(ChainSyncAction::Evict) => self.retire_chain_sync_peer(source),
                None => {}
            }
        }
    }

    /// Retires a connection the chain-sync rule condemned.
    ///
    /// PRE: `source` names the connection the rule chose to retire.
    /// POST: the connection is gone, and the retirement is counted only when
    ///   it was still live.
    /// INVARIANT: `node.sync.chain_sync_disconnects` is the operator-visible
    ///   name for this reason and never changes once published.
    fn retire_chain_sync_peer(&self, source: PeerSource) {
        if self.peer_table.disconnect_source(source) {
            metrics::counter!("node.sync.chain_sync_disconnects").increment(1);
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: peer brought no better chain within the sync timeout; disconnecting"
            );
        }
    }

    /// Asks one connection for headers once and reports whether the request
    /// is now outstanding.
    ///
    /// PRE: `source` names a live subject connection.
    /// POST: return true when a `getheaders` was sent or already pending for
    ///   this locator, false when nothing could be sent.
    /// INVARIANT: a suppressed probe still counts, because the pending request
    ///   it suppressed is the very question the response window waits on.
    fn probe_chain_sync(&self, source: PeerSource, frontier: &SyncFrontier) -> bool {
        let outcome = self.probe_frontier_peer(frontier, source);
        if outcome == GetheadersOutcome::Failed {
            return false;
        }
        metrics::counter!("node.sync.chain_sync_probes").increment(1);
        true
    }
}
