//! Canonical P2P sync-frontier observation and reconciliation.
//!
//! This module owns the mutable P2P scheduler state and the one transition
//! that normalizes peer lifecycle, settles inbound bodies and timeout
//! recovery, and derives the work the current tick must attempt. It owns no
//! durable chainstate.

use super::HEADER_REQUEST_TIMEOUT;
use super::peers::body_capability_height;
use super::{BlockSync, PendingHeaderRequest};
use crate::peer_table::UsablePeer;
use crate::{BlockStager, DownloadWindow};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
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
    ProbeMissingFrontier(crate::PeerSource),
    AwaitPending,
    ExtendHeaderTip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NoProgressReason {
    AtTip,
    NoUsablePeers,
    NoActionablePeers,
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
    /// Owner of the in-flight frontier body request, for operator telemetry.
    pub(super) body_owner: Option<SocketAddr>,
    pub(super) header_request: Option<PendingHeaderRequest>,
    pub(super) usable_peers: Vec<UsablePeer>,
    pub(super) has_body_candidate: bool,
    pub(super) apply_halted: bool,
}

pub(super) struct ReconciledFrontier {
    pub(super) observation: SyncFrontier,
    pub(super) plan: FrontierPlan,
    pub(super) cold_hedge: Option<ColdFrontHedge>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ColdFrontHedge {
    pub(super) owner: SocketAddr,
    pub(super) hash: Hash256,
    pub(super) height: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WindowRecovery {
    pub(super) disconnected_staller: bool,
    pub(super) cold_hedge: Option<ColdFrontHedge>,
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
    pub(super) fn reconcile(&self, now: Instant) -> FrontierPlan {
        let missing_header_action = self.missing_frontier_header_action(now);
        reconcile_facts(&ReconcileFacts {
            chain_view: if self.applied_tip.is_some()
                && self.header_tip.is_some()
                && (self
                    .applied_tip
                    .as_ref()
                    .zip(self.header_tip.as_ref())
                    .is_some_and(|(applied, header)| applied.hash == header.hash)
                    || self.next_required.is_some())
            {
                ChainView::Available
            } else {
                ChainView::Unavailable
            },
            body_state: self.body_state,
            peers: if self.has_body_candidate {
                PeerAvailability::BodyCandidate
            } else if self.usable_peers.is_empty() {
                PeerAvailability::None
            } else {
                PeerAvailability::UsableOnly
            },
            missing_header_action,
            apply_halted: self.apply_halted,
        })
    }

    fn missing_frontier_header_action(&self, now: Instant) -> Option<HeaderAction> {
        if self.header_request.is_some_and(|request| {
            now.saturating_duration_since(request.requested_at) < HEADER_REQUEST_TIMEOUT
                && self
                    .usable_peers
                    .iter()
                    .any(|peer| peer.source == request.source)
        }) {
            return Some(HeaderAction::AwaitPending);
        }
        let required_services = bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
            | bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
        let eligible = || {
            self.usable_peers
                .iter()
                .filter(|peer| peer.info.services & required_services == required_services)
        };
        let peer = eligible()
            .filter(|peer| {
                self.header_request
                    .is_none_or(|request| peer.source.addr > request.source.addr)
            })
            .min_by_key(|peer| peer.source.addr)
            .or_else(|| eligible().min_by_key(|peer| peer.source.addr))?;
        Some(HeaderAction::ProbeMissingFrontier(peer.source))
    }
}

#[derive(Clone, Copy, Debug)]
enum ChainView {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug)]
enum PeerAvailability {
    None,
    UsableOnly,
    BodyCandidate,
}

struct ReconcileFacts {
    chain_view: ChainView,
    body_state: Option<BodyState>,
    peers: PeerAvailability,
    missing_header_action: Option<HeaderAction>,
    apply_halted: bool,
}

fn reconcile_facts(facts: &ReconcileFacts) -> FrontierPlan {
    if facts.apply_halted {
        return FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::ApplyHalted),
        };
    }
    if matches!(facts.chain_view, ChainView::Unavailable) {
        return FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::ChainViewUnavailable),
        };
    }
    let Some(body_state) = facts.body_state else {
        return FrontierPlan {
            schedule_bodies: false,
            header_action: HeaderAction::ExtendHeaderTip,
            no_progress_reason: Some(NoProgressReason::AtTip),
        };
    };
    match body_state {
        BodyState::Missing => {
            let header_action = facts
                .missing_header_action
                .unwrap_or(HeaderAction::ExtendHeaderTip);
            let has_body_candidate = matches!(facts.peers, PeerAvailability::BodyCandidate);
            let actionable = has_body_candidate || facts.missing_header_action.is_some();
            FrontierPlan {
                schedule_bodies: has_body_candidate,
                header_action,
                no_progress_reason: (!actionable).then_some(match facts.peers {
                    PeerAvailability::None => NoProgressReason::NoUsablePeers,
                    PeerAvailability::UsableOnly | PeerAvailability::BodyCandidate => {
                        NoProgressReason::NoActionablePeers
                    }
                }),
            }
        }
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
        // Replacement/disconnect cleanup must precede both queued delivery
        // attribution and peer conviction. Otherwise an address-identical
        // successor can inherit its predecessor's request or cooldown.
        self.reconcile_peer_sessions();
        self.drain_inbound_blocks();
        let applied_tip = self.chain.applied_tip().load_full();
        let recovery = self.reconcile_window_recovery(applied_tip.as_deref(), now);
        if !recovery.disconnected_staller {
            self.disconnect_timed_out_peer(now);
        }
        // Conviction may disconnect a source and release its work. Normalize
        // again inside this same canonical transition before observing it.
        self.reconcile_peer_sessions();
        let observation = self.observe_frontier();
        let plan = observation.reconcile(now);
        ReconciledFrontier {
            observation,
            plan,
            cold_hedge: recovery.cold_hedge,
        }
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
        // Chain reads stay outside the scheduler write lock.
        let has_body_candidate = applied_tip.as_ref().is_some_and(|applied| {
            let tree = self.chain.block_tree().read();
            let active_tip = tree.tip_id();
            usable_peers.iter().any(|usable| {
                body_capability_height(&usable.info, &tree, active_tip, &usable.demonstrated_tips)
                    .is_some_and(|height| height > applied.height)
            })
        });
        let state = self.frontier_state.lock();
        let (body_state, body_owner) = next_required
            .map(|required| {
                if state.stager.contains(&required.hash) {
                    (BodyState::Staged, None)
                } else if let Some(owner) = state.window.pending_owner(&required.hash) {
                    (BodyState::InFlight, Some(owner))
                } else {
                    (BodyState::Missing, None)
                }
            })
            .unzip();
        let body_owner = body_owner.flatten();
        // Preserve an expired request as the peer-rotation cursor. Session
        // reconciliation already removes ownership belonging to a replaced or
        // disconnected source.
        let header_request = state.header_request;
        SyncFrontier {
            applied_tip,
            header_tip,
            next_required,
            body_state,
            body_owner,
            header_request,
            usable_peers,
            has_body_candidate,
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
        let missing = reconcile_facts(&ReconcileFacts {
            chain_view: ChainView::Available,
            body_state: Some(BodyState::Missing),
            peers: PeerAvailability::BodyCandidate,
            missing_header_action: Some(HeaderAction::AwaitPending),
            apply_halted: false,
        });
        assert_eq!(
            missing,
            FrontierPlan {
                schedule_bodies: true,
                header_action: HeaderAction::AwaitPending,
                no_progress_reason: None,
            }
        );
        for state in [BodyState::InFlight, BodyState::Staged] {
            assert_eq!(
                reconcile_facts(&ReconcileFacts {
                    chain_view: ChainView::Available,
                    body_state: Some(state),
                    peers: PeerAvailability::BodyCandidate,
                    missing_header_action: None,
                    apply_halted: false,
                })
                .header_action,
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
            peers in prop_oneof![
                Just(PeerAvailability::None),
                Just(PeerAvailability::UsableOnly),
                Just(PeerAvailability::BodyCandidate)
            ],
            missing_header_action in prop_oneof![
                Just(None),
                Just(Some(HeaderAction::AwaitPending))
            ],
            apply_halted in any::<bool>(),
        ) {
            let plan = reconcile_facts(&ReconcileFacts {
                chain_view: if chain_view_available {
                    ChainView::Available
                } else {
                    ChainView::Unavailable
                },
                body_state: Some(BodyState::Missing),
                peers,
                missing_header_action,
                apply_halted,
            });
            let armed = !apply_halted && chain_view_available;
            prop_assert_eq!(
                plan.schedule_bodies,
                armed && matches!(peers, PeerAvailability::BodyCandidate)
            );
            prop_assert_eq!(
                plan.no_progress_reason.is_some(),
                !(plan.schedule_bodies
                    || plan.header_action != HeaderAction::ExtendHeaderTip)
            );
        }
    }
}
