//! Canonical sync-frontier reconciliation (issue #1128).
//!
//! The reconciler answers one question per tick: is the canonical
//! next-required body owned by a live connection, staged, or applying — and
//! when it is none of those, what concrete work unblocks it or what
//! explicit reason makes progress impossible. All observation funnels
//! through [`BlockSync::observe_frontier`] and every recovery decision
//! through [`SyncFrontier::plan`], so exactly one place evaluates the
//! frontier invariant; there is no second model of "is sync stuck".
//!
//! All work ownership is stamped with the requesting connection's
//! [`PeerSource`]: a cancelled or same-address-replaced connection never
//! inherits its predecessor's assignments, convictions, or deadlines.

use std::sync::Arc;
use std::time::Instant;

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;

use crate::PeerInfo;
use crate::connection::PeerSource;

use super::HEADER_REQUEST_TIMEOUT;
use super::PendingHeaderRequest;

/// The canonical next-required body: the block the apply frontier commits
/// next — the applied tip's successor on the active branch, or the first
/// connect node of the reorg plan when the applied tip is off-branch. One
/// value serves both recovery observation and request scheduling, so the
/// two can never disagree about what the frontier needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequiredBody {
    /// Height of the required block on the active branch.
    pub height: u32,
    /// Hash of the required block.
    pub hash: Hash256,
}

/// Where the canonical next-required body sits in the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyState {
    /// In flight under a specific connection's ownership.
    InFlight(PeerSource),
    /// Staged and waiting for the apply path.
    Staged,
    /// Neither pending, staged, nor applying: unowned work the reconciler
    /// must schedule this tick or account for in `no_progress`.
    Unowned,
}

/// Chain-side frontier observation: both tips plus the resolved
/// next-required body, taken from one consistent read of the tree.
#[derive(Clone, Debug)]
pub(crate) struct ChainFrontier {
    /// The applied (validated) tip.
    pub applied_tip: Option<Arc<TipSnapshot>>,
    /// The heaviest header tip.
    pub chain_tip: Option<Arc<TipSnapshot>>,
    /// The canonical next-required body on the active branch, `None` at tip
    /// or when the first connect node cannot be resolved.
    pub next_required: Option<RequiredBody>,
    /// Whether the apply path has latched a fatal settlement.
    pub apply_halted: bool,
}

/// A handshake-complete, uncancelled connection eligible for sync work.
#[derive(Clone, Debug)]
pub(crate) struct UsablePeer {
    /// Exact connection identity; every request sent to this peer is owned
    /// by this source.
    pub source: PeerSource,
    /// Published peer metadata (services, best-known height, relay prefs).
    pub info: PeerInfo,
    /// Tip hashes this connection demonstrated by serving accepted headers.
    pub demonstrated_tips: Vec<Hash256>,
    /// The peer's demonstrated height resolved on the active chain, `None`
    /// when its announced tips do not intersect it.
    pub active_height: Option<u32>,
    /// What this connection relays, fixed when it was created.
    pub role: crate::peer_info::PeerRole,
    /// Whether the operator pinned this dial by name (`--connect` or
    /// `addnode`). Core: `ConnectionType::MANUAL`.
    pub manual: bool,
    /// Monotonic instant this connection was created.
    pub connected_at: Instant,
}

/// The height a connection may be asked to serve bodies up to.
///
/// `claimed` is the best-known height the peer advertises and this node
/// raises as it accepts that peer's headers; `active_height` is what the
/// peer's demonstrated tips resolve to on the active chain.
///
/// PRE: both heights are heights this node derived from the peer itself,
///   never from a third party.
/// POST: the greater of the two, `None` only when the peer offered neither:
///   an unusable advertised height and no tip that resolves.
/// INVARIANT: branch evidence never LOWERS the height a peer is trusted at.
///   A tip that resolves off the active chain says the peer's best chain is
///   elsewhere; it does not retract the height the peer claimed, and a
///   connection that cannot serve what it claimed is judged by the request
///   that times out — `expired_release` convicts it — not by being skipped
///   without ever being asked. Without that floor, one fork answer pins a
///   connection below the frontier for its whole life: its later
///   `getheaders` replies follow the same losing branch, so the probe meant
///   to restore capability replays headers this node already holds, and the
///   frontier starves on peers it never asks (issue #1153).
#[must_use]
pub(crate) fn body_capability(claimed: i32, active_height: Option<u32>) -> Option<u32> {
    match (u32::try_from(claimed).ok(), active_height) {
        (Some(claimed), Some(resolved)) => Some(claimed.max(resolved)),
        (Some(claimed), None) => Some(claimed),
        (None, resolved) => resolved,
    }
}

impl UsablePeer {
    /// Demonstrated serving capability for this connection: the height it is
    /// trusted at, precomputed once per observation instead of per request
    /// peer. See [`body_capability`] for the rule and why branch evidence
    /// cannot lower it.
    pub(crate) fn capability(&self) -> Option<u32> {
        body_capability(self.info.best_known_height, self.active_height)
    }

    /// The height this connection PROVED it can serve by handing us headers
    /// that entered the block tree. `None` while it has announced nothing we
    /// accepted, whatever its handshake claimed: Core's eviction rule reads
    /// `pindexBestKnownBlock`, a tip the peer actually sent, and never the
    /// version height (`net_processing.cpp:3203-3210`). Where `capability`
    /// falls back to the claimed height to choose whom to ask for a body,
    /// this one has no fallback, because the rule that reads it decides
    /// whether to keep the connection.
    pub(crate) fn demonstrated_height(&self) -> Option<u32> {
        if self.demonstrated_tips.is_empty() {
            return None;
        }
        self.active_height
    }
}

/// Everything the reconciler needs for one tick, all observed consistently.
#[derive(Debug)]
pub(crate) struct SyncFrontier {
    /// The chain-side frontier.
    pub chain: ChainFrontier,
    /// State of `chain.next_required`, `None` when none is required.
    pub body_state: Option<BodyState>,
    /// The outstanding header request, if any.
    pub header_request: Option<PendingHeaderRequest>,
    /// Whether `header_request` is unexpired and owned by a usable
    /// connection — the identity-exact liveness the scheduler waits on.
    pub header_request_live: bool,
    /// Identity-bearing snapshot of the peers usable this tick. A
    /// cancelled lease is not representable here.
    pub usable_peers: Vec<UsablePeer>,
}

/// What the header side of the scheduler does this tick.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HeaderAction {
    /// No header work this tick.
    #[default]
    Idle,
    /// An unexpired header request is owned by a usable connection; await
    /// its answer.
    AwaitPending,
    /// The apply frontier is unowned: probe the capability frontier at the
    /// applied anchor with this peer (the rotation pick).
    Probe(PeerSource),
    /// Request the next header page from the best demonstrated peer.
    Extend,
}

/// Why the scheduler cannot advance the apply frontier this tick. Always
/// `Some` when a next-required body exists and no recovery work was
/// scheduled — progress is never silently impossible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoProgressReason {
    /// The applied tip already equals the header tip.
    AtTip,
    /// A fatal apply settlement latched; recreation reopens admission.
    ApplyHalted,
    /// The applied or header tip could not be read.
    ChainViewUnavailable,
    /// The tips disagree but the first connect node cannot be resolved.
    FrontierUnresolvable,
    /// Work exists but no handshake-complete uncancelled peer is usable.
    NoUsablePeers,
    /// No usable peer demonstrates a chain reaching the required body.
    NoCapablePeer,
}

/// The tick's scheduling decision.
#[derive(Clone, Debug, Default)]
pub(crate) struct FrontierPlan {
    /// Whether the body-request loop runs this tick.
    pub schedule_bodies: bool,
    /// What the header side does.
    pub header_action: HeaderAction,
    /// Why no apply-frontier progress is possible, when nothing was
    /// scheduled that can advance it.
    pub no_progress: Option<NoProgressReason>,
}

impl SyncFrontier {
    /// The canonical reconciliation: either concrete work is scheduled for
    /// this tick or `no_progress` names why progress is impossible.
    ///
    /// The invariant: when the header tip is ahead of the applied tip and
    /// the canonical next-required body is unowned, this either schedules
    /// recovery work (`schedule_bodies` and/or a header action that can
    /// discover capability) or produces an explicit reason.
    pub(crate) fn plan(&self) -> FrontierPlan {
        let peers_exist = !self.usable_peers.is_empty();
        let body_owned_or_missing =
            matches!(self.body_state, Some(BodyState::Unowned)) && !self.chain.apply_halted;
        let header_action = if self.header_request_live {
            HeaderAction::AwaitPending
        } else if !peers_exist {
            HeaderAction::Idle
        } else if body_owned_or_missing {
            self.probe_pick()
                .map_or(HeaderAction::Extend, HeaderAction::Probe)
        } else {
            HeaderAction::Extend
        };
        let mut plan = FrontierPlan {
            header_action,
            ..FrontierPlan::default()
        };

        let Some(required) = self.chain.next_required else {
            plan.no_progress = Some(if self.chain.apply_halted {
                NoProgressReason::ApplyHalted
            } else if self.chain.applied_tip.is_none() || self.chain.chain_tip.is_none() {
                NoProgressReason::ChainViewUnavailable
            } else if self.at_tip() {
                NoProgressReason::AtTip
            } else {
                NoProgressReason::FrontierUnresolvable
            });
            return plan;
        };

        if self.chain.apply_halted {
            plan.no_progress = Some(NoProgressReason::ApplyHalted);
            return plan;
        }

        if !peers_exist {
            plan.no_progress = Some(NoProgressReason::NoUsablePeers);
            return plan;
        }

        plan.schedule_bodies = true;
        let body_state = match self.body_state {
            // A pending whose owner fell out of the usable set is unowned
            // work; reconcile released it, and it must be re-requested.
            Some(BodyState::InFlight(owner))
                if !self.usable_peers.iter().any(|peer| peer.source == owner) =>
            {
                Some(BodyState::Unowned)
            }
            state => state,
        };
        match body_state {
            Some(BodyState::Unowned) => {
                if !self
                    .usable_peers
                    .iter()
                    .any(|peer| peer.capability().is_some_and(|h| h >= required.height))
                {
                    plan.no_progress = Some(NoProgressReason::NoCapablePeer);
                }
            }
            Some(BodyState::Staged | BodyState::InFlight(_)) => {}
            None => unreachable!("next_required implies a body state"),
        }
        plan
    }

    /// Whether the applied tip is the header tip's block.
    fn at_tip(&self) -> bool {
        match (&self.chain.applied_tip, &self.chain.chain_tip) {
            (Some(applied), Some(chain)) => applied.hash == chain.hash,
            _ => false,
        }
    }

    /// The P2P-05 probe pick: a witness-network peer rotated past the
    /// expired (or dead) pending request's owner so consecutive probes do
    /// not land on the same connection.
    fn probe_pick(&self) -> Option<PeerSource> {
        let required = ServiceFlags::NETWORK.to_u64() | ServiceFlags::WITNESS.to_u64();
        let eligible = |peer: &&UsablePeer| peer.info.services & required == required;
        let pending_addr = self.header_request.map(|request| request.source.addr);
        self.usable_peers
            .iter()
            .filter(|peer| {
                eligible(peer) && pending_addr.is_none_or(|addr| peer.source.addr > addr)
            })
            .min_by_key(|peer| peer.source.addr)
            .map(|peer| peer.source)
            .or_else(|| {
                self.usable_peers
                    .iter()
                    .filter(|peer| eligible(peer))
                    .min_by_key(|peer| peer.source.addr)
                    .map(|peer| peer.source)
            })
    }
}

/// Whether `header_request` is live: unexpired and owned by a peer in the
/// usable set.
pub(crate) fn header_request_live(
    header_request: Option<PendingHeaderRequest>,
    usable_peers: &[UsablePeer],
    now: Instant,
) -> bool {
    header_request.is_some_and(|request| {
        now.saturating_duration_since(request.requested_at) < HEADER_REQUEST_TIMEOUT
            && usable_peers
                .iter()
                .any(|peer| peer.source == request.source)
    })
}
