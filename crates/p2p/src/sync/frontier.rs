//! Canonical P2P sync-frontier observation and reconciliation.
//!
//! This module owns no durable chain or scheduler state. It derives one
//! read-only observation from the chain capability and P2P-owned state, then
//! decides which classes of work the current tick must attempt.

use super::{BlockSync, PendingHeaderRequest};
use crate::{BlockStager, DownloadWindow, PeerSource};
use crate::peer_table::UsablePeer;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RequiredBody {
    pub(super) height: u32,
    pub(super) hash: Hash256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BodyState {
    Missing,
    InFlight,
    Staged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HeaderAction {
    ProbeMissingFrontier,
    ExtendHeaderTip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoProgressReason {
    AtTip,
    NoUsablePeers,
    BodyInFlight,
    BodyStaged,
    ApplyHalted,
    ChainViewUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrontierPlan {
    pub(super) schedule_bodies: bool,
    pub(super) header_action: HeaderAction,
    pub(super) no_progress_reason: Option<NoProgressReason>,
}

/// One tick's canonical view of the chain frontier and P2P work ownership.
pub(super) struct SyncFrontier {
    pub(super) applied_tip: Option<Arc<TipSnapshot>>,
    pub(super) header_tip: Option<Arc<TipSnapshot>>,
    pub(super) next_required: Option<RequiredBody>,
    pub(super) body_state: Option<BodyState>,
    pub(super) header_request: Option<PendingHeaderRequest>,
    pub(super) usable_peers: Vec<UsablePeer>,
    pub(super) apply_halted: bool,
}

pub(super) struct ReconciledFrontier {
    pub(super) observation: SyncFrontier,
    pub(super) plan: FrontierPlan,
}

/// Sole owner of mutable P2P scheduler state used to reconcile the canonical
/// chain frontier. `DownloadWindow` and `BlockStager` remain policy
/// components; they are not independently published scheduler authorities.
pub(super) struct FrontierSchedulerState {
    pub(super) window: DownloadWindow,
    pub(super) stager: BlockStager,
    pub(super) header_request: Option<PendingHeaderRequest>,
    pub(super) known_sessions: HashMap<SocketAddr, crate::ConnectionId>,
}

impl SyncFrontier {
    /// Derives the work classes for this tick from one observation.
    pub(super) fn reconcile(&self) -> FrontierPlan {
        reconcile_facts(
            self.applied_tip.is_some()
                && self.header_tip.is_some()
                && (self
                    .applied_tip
                    .as_ref()
                    .zip(self.header_tip.as_ref())
                    .is_some_and(|(applied, header)| applied.hash == header.hash)
                    || self.next_required.is_some()),
            self.body_state,
            !self.usable_peers.is_empty(),
            self.apply_halted,
        )
    }
}

fn reconcile_facts(
    chain_view_available: bool,
    body_state: Option<BodyState>,
    has_usable_peers: bool,
    apply_halted: bool,
) -> FrontierPlan {
    if apply_halted {
        return FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::ApplyHalted),
        };
    }
    if !chain_view_available {
        return FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::ChainViewUnavailable),
        };
    }
    let Some(body_state) = body_state else {
        return FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::AtTip),
        };
    };
    match body_state {
        BodyState::Missing if has_usable_peers => FrontierPlan {
            schedule_bodies: true,
            header_action: HeaderAction::ProbeMissingFrontier,
            no_progress_reason: None,
        },
        BodyState::Missing => FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::NoUsablePeers),
        },
        BodyState::InFlight => FrontierPlan {
            schedule_bodies: true,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::BodyInFlight),
        },
        BodyState::Staged => FrontierPlan {
            schedule_bodies: true,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::BodyStaged),
        },
    }
}

impl BlockSync {
    pub(super) fn frontier_chain_is_current(&self, frontier: &SyncFrontier) -> bool {
        let applied = self.chain.applied_tip().load_full();
        let header = self.chain.chain_tip().load_full();
        applied.as_ref().map(|tip| tip.hash) == frontier.applied_tip.as_ref().map(|tip| tip.hash)
            && header.as_ref().map(|tip| tip.hash)
                == frontier.header_tip.as_ref().map(|tip| tip.hash)
    }

    /// Normalizes timeout and peer-lifecycle transitions, then derives the
    /// single canonical observation and decision consumed by this tick.
    pub(super) fn reconcile_frontier(&self, now: Instant) -> ReconciledFrontier {
        let applied_tip = self.chain.applied_tip().load_full();
        if !self.disconnect_window_staller(applied_tip.as_deref(), now) {
            self.disconnect_timed_out_peer(now);
        }
        self.reconcile_peer_sessions();
        let observation = self.observe_frontier();
        let plan = observation.reconcile();
        ReconciledFrontier { observation, plan }
    }

    pub(super) fn observe_frontier(&self) -> SyncFrontier {
        let applied_tip = self.chain.applied_tip().load_full();
        let header_tip = self.chain.chain_tip().load_full();
        let usable_peers = self.peer_table.usable_peers();
        let next_required = match (&applied_tip, &header_tip) {
            (Some(applied), Some(headers)) if applied.hash != headers.hash => {
                let tree = self.chain.block_tree().read();
                Self::first_connect_height(&tree, applied.hash, headers.tip_id).and_then(|height| {
                    tree.node_at_height_from(headers.tip_id, height)
                        .and_then(|id| tree.node(id).ok())
                        .map(|node| RequiredBody {
                            height,
                            hash: node.hash,
                        })
                })
            }
            _ => None,
        };
        let state = self.frontier_state.lock();
        let body_state = next_required.map(|required| {
            if state.stager.contains(&required.hash) {
                BodyState::Staged
            } else if state.window.contains_pending(&required.hash) {
                BodyState::InFlight
            } else {
                BodyState::Missing
            }
        });
        // Preserve an expired request as the peer-rotation cursor. Session
        // reconciliation already removes ownership belonging to a replaced or
        // disconnected source.
        let header_request = state.header_request;
        SyncFrontier {
            applied_tip,
            header_tip,
            next_required,
            body_state,
            header_request,
            usable_peers,
            apply_halted: self.apply_halted.load(std::sync::atomic::Ordering::Acquire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn missing_body_is_the_only_state_that_arms_frontier_probe() {
        let missing = reconcile_facts(true, Some(BodyState::Missing), true, false);
        assert_eq!(
            missing,
            FrontierPlan {
                schedule_bodies: true,
                header_action: HeaderAction::ProbeMissingFrontier,
                no_progress_reason: None,
            }
        );
        for state in [BodyState::InFlight, BodyState::Staged] {
            assert_eq!(
                reconcile_facts(true, Some(state), true, false).header_action,
                HeaderAction::ExtendHeaderTip
            );
        }
    }

    proptest! {
        /// A missing canonical body can never disappear into silent idleness:
        /// it either arms concrete recovery work or reports why no work can
        /// be owned in this observation.
        #[test]
        fn missing_frontier_always_has_action_or_reason(
            chain_view_available in any::<bool>(),
            has_usable_peers in any::<bool>(),
            apply_halted in any::<bool>(),
        ) {
            let plan = reconcile_facts(
                chain_view_available,
                Some(BodyState::Missing),
                has_usable_peers,
                apply_halted,
            );
            prop_assert!(plan.schedule_bodies || plan.no_progress_reason.is_some());
            if plan.schedule_bodies {
                prop_assert_eq!(plan.header_action, HeaderAction::ProbeMissingFrontier);
            }
        }
    }
}
