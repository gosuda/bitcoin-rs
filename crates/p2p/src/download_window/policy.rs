//! Peer-eligibility and budget policy for the block download window.
use std::time::Duration;

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_primitives::Network;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_chain::InitialBlockDownload;

use super::DownloadWindow;
use crate::connection::PeerSource;

use super::SyncBudget;
use crate::PeerInfo;

pub(super) const BLOCK_DOWNLOAD_TIMEOUT_BASE: u32 = 2;
pub(super) const BLOCK_DOWNLOAD_TIMEOUT_PER_PEER: u32 = 1;
pub(super) const NODE_NETWORK_LIMITED_MIN_BLOCKS: u32 = 288;
const NODE_NETWORK_LIMITED_RACE_BUFFER: u32 = 2;
pub(super) const NETWORK_LIMITED: u64 = 1_u64 << 10;
pub(crate) const PENDING_BUDGET: usize = 256;
pub(crate) const RECEIVED_BLOCK_TIMEOUT: Duration = Duration::from_mins(1);
pub(crate) const RECEIVED_BLOCK_BUDGET: usize = 256;
/// Mainnet-oriented block-size estimate for sizing the in-flight request window.
pub(crate) const PENDING_BLOCK_BYTE_ESTIMATE: usize = 2 * 1024 * 1024;
const PENDING_BYTE_BUDGET: usize = PENDING_BUDGET * PENDING_BLOCK_BYTE_ESTIMATE;
const RECEIVED_BLOCK_BYTE_BUDGET: usize = PENDING_BYTE_BUDGET;
/// Consensus-maximum serialized block size in bytes: a witness-serialized
/// block cannot exceed its 4,000,000 weight, so no valid block is larger.
const MAX_SERIALIZED_BLOCK_SIZE: usize = crate::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE;
const _: () = assert!(
    RECEIVED_BLOCK_BYTE_BUDGET >= RECEIVED_BLOCK_BUDGET / 2 * MAX_SERIALIZED_BLOCK_SIZE,
    "staged byte budget must admit half the staged count window at max block size"
);
pub(crate) const INBOUND_BLOCK_STAGE_CHUNK: usize =
    at_least_one(RECEIVED_BLOCK_BYTE_BUDGET / PENDING_BLOCK_BYTE_ESTIMATE);
pub(crate) const PEER_INFLIGHT_BUDGET: usize = PENDING_BUDGET;
pub(crate) const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;
pub(crate) const MIN_PEERS_FOR_FANOUT: usize = 8;

pub(crate) const MINIMUM_CONNECT_TIME: Duration = Duration::from_secs(30);

pub(super) const FAST_BLOCKS_IN_TRANSIT_PER_PEER: usize = 8;
pub(super) const FAST_MIN_PEERS_FOR_FANOUT: usize = 2;
pub const FAST_OUTBOUND_PEER_TARGET: usize = PENDING_BUDGET / FAST_BLOCKS_IN_TRANSIT_PER_PEER;
pub(crate) const BLOCK_STALLING_TIMEOUT: Duration = Duration::from_secs(2);
const BLOCK_STALLING_TIMEOUT_MAX: Duration = Duration::from_secs(64);
const STALLER_COOLDOWN: Duration = BLOCK_STALLING_TIMEOUT_MAX;

const _: () = assert!(PENDING_BUDGET == RECEIVED_BLOCK_BUDGET);
const _: () = assert!(
    MIN_PEERS_FOR_FANOUT * MAX_BLOCKS_IN_TRANSIT_PER_PEER <= PENDING_BUDGET,
    "fan-out at the outbound target must not exceed the download window"
);
const _: () = assert!(
    FAST_OUTBOUND_PEER_TARGET * FAST_BLOCKS_IN_TRANSIT_PER_PEER <= PENDING_BUDGET
        && FAST_MIN_PEERS_FOR_FANOUT <= FAST_OUTBOUND_PEER_TARGET,
    "fast-sync fan-out at its outbound target must not exceed the download window"
);

pub(crate) const GETDATA_BATCH_SIZE: usize = PENDING_BUDGET;

const fn at_least_one(value: usize) -> usize {
    if value == 0 { 1 } else { value }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SyncPeer {
    pub source: PeerSource,
    pub best_known_height: i32,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SyncPeerSelection {
    pub request_peers: Vec<SyncPeer>,
    pub probe_peers: Vec<SyncPeer>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FanoutCandidate {
    pub peer: SyncPeer,
    pub serves_bodies: bool,
    pub fanout_eligible: bool,
    pub soft_blocked: bool,
}

pub(crate) struct BlockDownloadPolicy {
    pub ibd: Arc<InitialBlockDownload>,
    pub requested_height: u32,
    pub network: Network,
}

pub(crate) fn serves_requested_height(peer: &PeerInfo, policy: &BlockDownloadPolicy) -> bool {
    let network = ServiceFlags::NETWORK.to_u64();
    let witness = ServiceFlags::WITNESS.to_u64();
    if peer.services & witness == 0 {
        return false;
    }
    if peer.services & network != 0 {
        return true;
    }
    if peer.services & ServiceFlags::NETWORK_LIMITED.to_u64() == 0 {
        return false;
    }
    if policy
        .ibd
        .is_active(bitcoin_rs_primitives::unix_time_secs(), policy.network)
    {
        return false;
    }
    u32::try_from(peer.best_known_height).is_ok_and(|demonstrated| {
        demonstrated
            .checked_sub(policy.requested_height)
            .is_some_and(|left_tip| left_tip < NODE_NETWORK_LIMITED_MIN_BLOCKS)
    })
}

#[must_use]
pub(crate) fn servable_floor(peer: &PeerInfo, policy: &BlockDownloadPolicy) -> u32 {
    let network = ServiceFlags::NETWORK.to_u64();
    if peer.services & network != 0
        || policy
            .ibd
            .is_active(bitcoin_rs_primitives::unix_time_secs(), policy.network)
    {
        return 0;
    }
    if peer.services & ServiceFlags::NETWORK_LIMITED.to_u64() == 0 {
        return u32::MAX;
    }
    u32::try_from(peer.best_known_height)
        .unwrap_or(0)
        .saturating_sub(NODE_NETWORK_LIMITED_MIN_BLOCKS.saturating_sub(1))
}

pub(crate) fn statically_fanout_eligible(peer: &PeerInfo, policy: &BlockDownloadPolicy) -> bool {
    !peer.inbound && serves_requested_height(peer, policy)
}

fn peer_advertises_block_service(peer: &PeerInfo) -> bool {
    let network = ServiceFlags::NETWORK.to_u64();
    peer.services & (network | NETWORK_LIMITED) != 0
}

pub(crate) fn peer_can_serve_height(
    peer: &PeerInfo,
    peer_height: u32,
    required_height: u32,
) -> bool {
    if !peer_advertises_block_service(peer) || required_height > peer_height {
        return false;
    }
    let limited_only =
        peer.services & NETWORK_LIMITED != 0 && peer.services & ServiceFlags::NETWORK.to_u64() == 0;
    !limited_only
        || peer_height - required_height
            < NODE_NETWORK_LIMITED_MIN_BLOCKS - NODE_NETWORK_LIMITED_RACE_BUFFER
}

pub(crate) fn configure_request_mode(
    window: &mut DownloadWindow,
    candidates: &[FanoutCandidate],
    now: Instant,
) -> Option<SyncPeer> {
    let eligible = candidates
        .iter()
        .filter(|candidate| candidate.fanout_eligible && !candidate.soft_blocked)
        .count();
    let preferred_source = window.preferred_peer();
    let preferred_candidate = preferred_source.and_then(|source| {
        candidates
            .iter()
            .find(|candidate| candidate.peer.source == source)
    });
    let preferred = preferred_candidate
        .filter(|candidate| candidate.fanout_eligible && !candidate.soft_blocked)
        .map(|candidate| candidate.peer);
    if eligible < window.min_peers_for_fanout() && preferred_candidate.is_some() {
        window.set_fanout_eligible_peers(0, now);
        return preferred;
    }
    if preferred_source.is_some() {
        window.clear_preferred_peer();
    }
    window.set_fanout_eligible_peers(eligible, now);
    None
}

#[must_use]
pub fn default_sync_budget(network: Network) -> SyncBudget {
    SyncBudget {
        max_pending_blocks: PENDING_BUDGET,
        max_pending_bytes: PENDING_BYTE_BUDGET,
        max_received_blocks: RECEIVED_BLOCK_BUDGET,
        max_received_bytes: RECEIVED_BLOCK_BYTE_BUDGET,
        max_peer_inflight: PEER_INFLIGHT_BUDGET,
        fanout_peer_inflight: MAX_BLOCKS_IN_TRANSIT_PER_PEER,
        min_peers_for_fanout: MIN_PEERS_FOR_FANOUT,
        getdata_batch_limit: GETDATA_BATCH_SIZE,
        block_spacing: Duration::from_secs(u64::from(network.target_spacing_seconds())),
        #[cfg(test)]
        pending_timeout_override: None,
        received_timeout: RECEIVED_BLOCK_TIMEOUT,
        stall_timeout_initial: BLOCK_STALLING_TIMEOUT,
        stall_timeout_max: BLOCK_STALLING_TIMEOUT_MAX,
        staller_cooldown: STALLER_COOLDOWN,
    }
}

pub fn fast_sync_budget(network: Network) -> SyncBudget {
    SyncBudget {
        fanout_peer_inflight: FAST_BLOCKS_IN_TRANSIT_PER_PEER,
        min_peers_for_fanout: FAST_MIN_PEERS_FOR_FANOUT,
        ..default_sync_budget(network)
    }
}
