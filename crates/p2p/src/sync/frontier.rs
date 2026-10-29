//! Canonical sync-frontier reconciliation.

use std::sync::Arc;
use std::time::Instant;

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;

use crate::PeerInfo;
use crate::connection::PeerSource;

use super::HeaderRequest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequiredBody {
    pub height: u32,
    pub hash: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyState {
    InFlight(PeerSource),
    Staged,
    Unowned,
}

#[derive(Clone, Debug)]
pub(crate) struct ChainFrontier {
    pub applied_tip: Option<Arc<TipSnapshot>>,
    pub chain_tip: Option<Arc<TipSnapshot>>,
    pub next_required: Option<RequiredBody>,
    pub apply_halted: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct UsablePeer {
    pub source: PeerSource,
    pub info: PeerInfo,
    pub demonstrated_tips: Vec<Hash256>,
    pub active_height: Option<u32>,
    pub headers_horizon: Option<u32>,
    pub role: crate::peer_info::PeerRole,
    pub manual: bool,
    pub connected_at: Instant,
}

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
    /// peer.
    pub(crate) fn capability(&self) -> Option<u32> {
        body_capability(self.info.best_known_height, self.active_height)
    }

    /// The height this connection PROVED it can serve by handing us headers that
    /// entered the block tree.
    ///
    /// `None` while it has announced nothing we accepted, whatever its handshake
    /// claimed: Core's eviction rule reads `pindexBestKnownBlock`, a tip the peer
    /// actually sent, and never the version height (`net_processing.cpp`).
    /// Where `capability` falls back to the claimed height to choose whom to ask for a
    /// body, this one has no fallback, because the rule that reads it decides whether
    /// to keep the connection.
    pub(crate) fn demonstrated_height(&self) -> Option<u32> {
        if self.demonstrated_tips.is_empty() {
            return None;
        }
        self.active_height
    }
}

#[derive(Debug)]
pub(crate) struct SyncFrontier {
    pub chain: ChainFrontier,
    pub body_state: Option<BodyState>,
    pub header_request: Option<HeaderRequest>,
    pub header_request_live: bool,
    pub usable_peers: Vec<UsablePeer>,
}

impl SyncFrontier {
    pub(crate) fn heights(&self) -> (u32, u32) {
        let applied = self.chain.applied_tip.as_ref().map_or(0, |tip| tip.height);
        let header = self
            .chain
            .chain_tip
            .as_ref()
            .map_or(applied, |tip| tip.height);
        (applied, header)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HeaderAction {
    #[default]
    Idle,
    AwaitPending,
    Probe(PeerSource),
    Extend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoProgressReason {
    AtTip,
    ApplyHalted,
    ChainViewUnavailable,
    FrontierUnresolvable,
    NoUsablePeers,
    NoCapablePeer,
}

#[derive(Clone, Debug, Default)]
pub(super) struct FrontierPlan {
    pub schedule_bodies: bool,
    pub header_action: HeaderAction,
    pub no_progress: Option<NoProgressReason>,
}

impl SyncFrontier {
    /// The canonical reconciliation: either concrete work is scheduled for this tick or
    /// `no_progress` names why progress is impossible.
    ///
    /// The invariant: when the header tip is ahead of the applied tip and the canonical
    /// next-required body is unowned, this either schedules recovery work
    /// (`schedule_bodies` and/or a header action that can discover capability) or
    /// produces an explicit reason.
    pub(super) fn plan(&self) -> FrontierPlan {
        let peers_exist = !self.usable_peers.is_empty();
        let body_state = match self.body_state {
            Some(BodyState::InFlight(owner))
                if !self.usable_peers.iter().any(|peer| peer.source == owner) =>
            {
                Some(BodyState::Unowned)
            }
            state => state,
        };
        let body_unowned =
            matches!(body_state, Some(BodyState::Unowned)) && !self.chain.apply_halted;
        let header_action = if self.header_request_live {
            HeaderAction::AwaitPending
        } else if !peers_exist {
            HeaderAction::Idle
        } else if body_unowned {
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

    fn at_tip(&self) -> bool {
        match (&self.chain.applied_tip, &self.chain.chain_tip) {
            (Some(applied), Some(chain)) => applied.hash == chain.hash,
            _ => false,
        }
    }

    fn probe_pick(&self) -> Option<PeerSource> {
        let required = ServiceFlags::NETWORK.to_u64() | ServiceFlags::WITNESS.to_u64();
        let eligible = |peer: &&UsablePeer| peer.info.services & required == required;
        let pending_id = self
            .header_request
            .map(|request| request.source.connection_id().get());
        self.usable_peers
            .iter()
            .filter(|peer| {
                eligible(peer) && pending_id.is_none_or(|id| peer.source.connection_id().get() > id)
            })
            .min_by_key(|peer| peer.source.connection_id().get())
            .map(|peer| peer.source)
            .or_else(|| {
                self.usable_peers
                    .iter()
                    .filter(|peer| eligible(peer))
                    .min_by_key(|peer| peer.source.connection_id().get())
                    .map(|peer| peer.source)
            })
    }
}

pub(crate) fn header_request_live(
    header_request: Option<HeaderRequest>,
    usable_peers: &[UsablePeer],
    now: Instant,
) -> bool {
    header_request.is_some_and(|request| {
        now.saturating_duration_since(request.requested_at) < request.timeout()
            && usable_peers
                .iter()
                .any(|peer| peer.source == request.source)
    })
}
#[cfg(test)]
mod tests {
    use super::super::HeaderRequestKind;
    use super::super::HeaderRequestState;
    use super::*;
    use crate::connection::PeerSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> crate::PeerRemote {
        crate::PeerRemote::Endpoint(crate::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        ))
    }

    fn usable(source: PeerSource) -> UsablePeer {
        UsablePeer {
            source,
            info: crate::test_support::synthetic_peer(addr(9001), 100),
            demonstrated_tips: Vec::new(),
            active_height: None,
            headers_horizon: None,
            role: crate::peer_info::PeerRole::FullRelay,
            manual: false,
            connected_at: Instant::now(),
        }
    }

    fn snap(tip_id: u32, height: u32, hash_byte: u8) -> std::sync::Arc<TipSnapshot> {
        std::sync::Arc::new(TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(tip_id),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
            height,
            chainwork: bitcoin_rs_chain::ChainWork::from(u64::from(height) + 1),
            hash: Hash256::from_le_bytes(&[hash_byte; 32]),
        })
    }

    fn frontier_with_request(
        usable_peers: Vec<UsablePeer>,
        request_source: PeerSource,
    ) -> SyncFrontier {
        let frontier = SyncFrontier {
            chain: ChainFrontier {
                applied_tip: Some(snap(1, 4, 0x01)),
                chain_tip: Some(snap(2, 9, 0x02)),
                next_required: Some(RequiredBody {
                    height: 5,
                    hash: Hash256::from_le_bytes(&[0x03; 32]),
                }),
                apply_halted: false,
            },
            body_state: Some(BodyState::Unowned),
            header_request: Some(super::super::HeaderRequest {
                source: request_source,
                kind: HeaderRequestKind::Frontier,
                locator_tip_hash: Hash256::from_le_bytes(&[0x01; 32]),
                target_height: 6,
                requested_at: Instant::now(),
                state: HeaderRequestState::AwaitingResponse,
            }),
            header_request_live: false,
            usable_peers,
        };
        let live = header_request_live(
            frontier.header_request,
            &frontier.usable_peers,
            Instant::now(),
        );
        SyncFrontier {
            header_request_live: live,
            ..frontier
        }
    }

    #[test]
    fn probe_rotation_orders_by_connection_id_not_endpoint() {
        let earliest = PeerSource::for_test(addr(9007));
        let dead = PeerSource::for_test(addr(9005));
        let latest = PeerSource::for_test(addr(9001));
        let frontier = frontier_with_request(vec![usable(earliest), usable(latest)], dead);
        assert!(!frontier.header_request_live);
        match frontier.plan().header_action {
            HeaderAction::Probe(picked) => assert_eq!(picked, latest),
            action => panic!("expected Probe, got {action:?}"),
        }
    }

    #[test]
    fn probe_rotation_distinguishes_anonymous_sessions() {
        let first = PeerSource::for_test_unidentified();
        let dead = PeerSource::for_test_unidentified();
        let last = PeerSource::for_test_unidentified();
        let frontier = frontier_with_request(vec![usable(last), usable(first)], dead);
        assert!(!frontier.header_request_live);
        match frontier.plan().header_action {
            HeaderAction::Probe(picked) => assert_eq!(picked, last),
            action => panic!("expected Probe, got {action:?}"),
        }
    }
}
