//! Peer-eligibility and budget policy for the block download window.
//!
//! These constants and predicates mirror Core's `net_processing` download
//! policy. [`super::DownloadWindow`] is the only caller that turns them into
//! requests.
use std::time::Duration;

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_primitives::Network;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_chain::InitialBlockDownload;

use super::DownloadWindow;
use crate::connection::PeerSource;

use super::SyncBudget;
use crate::PeerInfo;
// ---------------------------------------------------------------------------
// Download-policy constants
// ---------------------------------------------------------------------------

/// Core's `BLOCK_DOWNLOAD_TIMEOUT_BASE` in half-target-spacing units
/// (`net_processing.cpp:153-168`): an owner with no other validated-block
/// downloaders gets one full proof-of-work target spacing of queue age
/// before its oldest request is considered stuck.
pub(super) const BLOCK_DOWNLOAD_TIMEOUT_BASE: u32 = 2;
/// Core's `BLOCK_DOWNLOAD_TIMEOUT_PER_PEER` in half-target-spacing units:
/// each additional active downloader adds half a spacing to the budget.
pub(super) const BLOCK_DOWNLOAD_TIMEOUT_PER_PEER: u32 = 1;
/// How far below a pruned peer's own tip this node may still ask it for
/// blocks: Core's `NODE_NETWORK_LIMITED_MIN_BLOCKS`
/// (`net_processing.cpp:159`), the 288 blocks a `NODE_NETWORK_LIMITED` peer
/// keeps past its pruning horizon. Core holds a two-block race buffer at
/// `:1637`; the handshake clause keeps the plain 288, and the
/// demonstrated-height clause ([`peer_can_serve_height`]) applies the
/// buffer.
pub(super) const NODE_NETWORK_LIMITED_MIN_BLOCKS: u32 = 288;
/// Core's limited-service race buffer (`net_processing.cpp:1637`): a peer
/// that keeps only the retained window may have pruned two of its newest
/// blocks by the time the request lands.
pub(super) const NODE_NETWORK_LIMITED_RACE_BUFFER: u32 = 2;
/// `NODE_NETWORK_LIMITED` (bit 10) has no `ServiceFlags` variant in this
/// `rust-bitcoin` version; the bit follows the protocol assignment also
/// decoded in `PeerInfo::services_names`.
pub(super) const NETWORK_LIMITED: u64 = 1_u64 << 10;
/// Maximum number of in-flight getdata requests we'll track per `BlockSync`.
///
/// 256 is the measured single-peer IBD depth: a bounded 0–150,000 daemon
/// run at this window was 1.52× the 128-block control. Fan-out still stripes
/// at [`MAX_BLOCKS_IN_TRANSIT_PER_PEER`] once [`MIN_PEERS_FOR_FANOUT`] eligible
/// peers exist, so a full outbound set does not deepen per-peer pipelines.
pub const PENDING_BUDGET: usize = 256;
/// Time after which a received out-of-order block is discarded.
pub const RECEIVED_BLOCK_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of received blocks waiting for their predecessor.
pub const RECEIVED_BLOCK_BUDGET: usize = 256;
/// Mainnet-oriented block-size estimate for sizing the in-flight request window.
pub const PENDING_BLOCK_BYTE_ESTIMATE: usize = 2 * 1024 * 1024;
/// Maximum estimated bytes in the in-flight request window.
pub const PENDING_BYTE_BUDGET: usize = PENDING_BUDGET * PENDING_BLOCK_BYTE_ESTIMATE;
/// Maximum serialized bytes staged in memory while waiting for predecessors.
///
/// Defined as [`PENDING_BYTE_BUDGET`] so the in-flight and staged byte bounds
/// stay one consistent pair: a full download window (`PENDING_BUDGET` blocks
/// at the high-height `PENDING_BLOCK_BYTE_ESTIMATE`) always fits in staging
/// without eviction. At the 150k acceptance window this bound rarely binds —
/// blocks there are far below the per-slot estimate.
pub const RECEIVED_BLOCK_BYTE_BUDGET: usize = PENDING_BYTE_BUDGET;
/// Consensus-maximum serialized block size in bytes: a witness-serialized
/// block cannot exceed its 4,000,000 weight, so no valid block is larger.
pub const MAX_SERIALIZED_BLOCK_SIZE: usize = crate::MAX_BLOCK_SERIALIZED_SIZE_USIZE;
// Staller-arming reachability invariant (Phase 1 of the staller arming
// redesign): the stall episode arms on a staged-count fraction
// (`received >= max_received_blocks / 2`, `window_blocked_on` term 3), so the
// staged byte budget must admit at least half the staged count window even at
// consensus-maximum block size. If a depth bump (e.g. the w256 re-attempt)
// outgrows the byte budget, byte backpressure would silently hold the staged
// count below the arming fraction and byte-shaped wedges would stop arming at
// production budgets, degrading to the 60s pending-timeout fallback. Rebalance
// both constants together; this assertion turns silent drift into a build
// failure. (Margin at 256: 256 * 2 MiB >= 128 * 4_000_000, ~4.9%.)
const _: () = assert!(
    RECEIVED_BLOCK_BYTE_BUDGET >= RECEIVED_BLOCK_BUDGET / 2 * MAX_SERIALIZED_BLOCK_SIZE,
    "staged byte budget must admit half the staged count window at max block size"
);
/// Maximum decoded inbound blocks held before handing them to `BlockStager`,
/// sized from the same byte budget that bounds retained staged blocks.
pub const INBOUND_BLOCK_STAGE_CHUNK: usize =
    at_least_one(RECEIVED_BLOCK_BYTE_BUDGET / PENDING_BLOCK_BYTE_ESTIMATE);
/// Maximum block requests one peer may own at once outside fan-out.
///
/// Keep the fallback per-peer cap equal to the global cap so the bounded
/// scheduler needs only one healthy peer to fill the whole window — this IS
/// the shipped single-peer behavior and stays bit-identical when fewer than
/// [`MIN_PEERS_FOR_FANOUT`] eligible peers exist.
pub const PEER_INFLIGHT_BUDGET: usize = PENDING_BUDGET;
/// Per-peer in-flight cap while fan-out is active.
///
/// Mirrors Bitcoin Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER` (16,
/// `net_processing.cpp`). A deep per-peer pipeline under fan-out reproduces
/// the recorded head-of-line collapse; a shallow stripe without the fallback
/// reproduces the early-height under-fill regression — both were established
/// by a live-tested and reverted attempt (commit 5608279, recoverable from
/// git history).
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;
/// Minimum eligible peers before fan-out stripes.
///
/// Matches the default outbound target. Below this count, one healthy peer's
/// deep sequential pipeline fills [`PENDING_BUDGET`]. At the threshold, each
/// peer is capped at [`MAX_BLOCKS_IN_TRANSIT_PER_PEER`] so a full outbound set
/// does not reproduce the recorded head-of-line collapse. Do not scale this
/// with [`PENDING_BUDGET`]: `PENDING_BUDGET / 16` would be 16, and fan-out
/// would never engage at the 8-outbound default.
pub const MIN_PEERS_FOR_FANOUT: usize = 8;

/// How young a connection may be before policy may hold its silence against
/// it. Core's `MINIMUM_CONNECT_TIME` (`net_processing.cpp:115`).
pub const MINIMUM_CONNECT_TIME: Duration = Duration::from_secs(30);

/// Fast-sync per-peer stripe floor. Half the Core cap so the window spreads
/// across a larger outbound set; opt-in, not measured against the default.
pub const FAST_BLOCKS_IN_TRANSIT_PER_PEER: usize = 8;
/// Fast-sync fan-out threshold: stripe as soon as a second eligible peer
/// exists instead of waiting for a full outbound set.
pub const FAST_MIN_PEERS_FOR_FANOUT: usize = 2;
/// Fast-sync outbound peer target.
///
/// The peer count that fully stripes [`PENDING_BUDGET`] (and thus
/// [`PENDING_BYTE_BUDGET`], the estimated in-flight bandwidth) at
/// [`FAST_BLOCKS_IN_TRANSIT_PER_PEER`] each. More peers would sit idle behind
/// the window; fewer leave the stripe deeper.
pub const FAST_OUTBOUND_PEER_TARGET: usize = PENDING_BUDGET / FAST_BLOCKS_IN_TRANSIT_PER_PEER;
/// Initial window-blocked stalling threshold.
///
/// Mirrors Bitcoin Core's `BLOCK_STALLING_TIMEOUT_DEFAULT` (2s,
/// `net_processing.cpp`): when the window front has been in flight to one
/// peer this long with the apply frontier idle and no other download
/// progress possible, that peer is disconnected and its blocks re-queued
/// (R8).
pub const BLOCK_STALLING_TIMEOUT: Duration = Duration::from_secs(2);
/// Adaptive ceiling for the stalling threshold.
///
/// Mirrors Core's `BLOCK_STALLING_TIMEOUT_MAX` (64s): the threshold doubles
/// per staller disconnect so a sudden bandwidth drop cannot cascade into
/// disconnecting every peer at the 2s floor, and decays by x0.85 per
/// window-front arrival (never snapping back) so the elevation survives a
/// peer rotation.
pub const BLOCK_STALLING_TIMEOUT_MAX: Duration = Duration::from_secs(64);
/// How long a disconnected staller stays excluded from fan-out eligibility
/// and non-last-resort block requests.
///
/// Sized to the threshold ceiling: a staller flapping through reconnects can
/// capture the window front at most once per cooldown, and the
/// (window-global) doubled threshold bounds each capture — Core has no
/// equivalent only because its reconnecting peer cannot re-acquire in-flight
/// assignments this cheaply.
pub const STALLER_COOLDOWN: Duration = BLOCK_STALLING_TIMEOUT_MAX;

// The apply-side cache horizon (`expected_apply_horizon`) stays within the
// inline capacity below only because the staging budget equals the in-flight
// budget; a drift would silently spill every cached run to the heap. The
// byte-budget pair needs no twin assertion: `RECEIVED_BLOCK_BYTE_BUDGET` is
// `PENDING_BYTE_BUDGET` by definition.
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

/// Maximum number of block inventory entries we request per tick.
///
/// Keep the private default at the full pending window so a healthy peer can
/// fill it in one tick; [`DownloadWindow`] still caps requests by pending bytes,
/// block budget, and per-peer inflight budget.
pub const GETDATA_BATCH_SIZE: usize = PENDING_BUDGET;

/// Clamp a `usize` to at least 1, preventing zero-sized budgets.
pub const fn at_least_one(value: usize) -> usize {
    if value == 0 { 1 } else { value }
}

// ---------------------------------------------------------------------------
// Peer-assignment policy types
// ---------------------------------------------------------------------------

/// A peer selected for block-header or block-body synchronization.
#[derive(Clone, Copy, Debug)]
pub struct SyncPeer {
    /// The exact connection that may carry requests for this selection.
    pub source: PeerSource,
    /// Best known block height the peer advertises.
    pub best_known_height: i32,
}

impl SyncPeer {
    /// Peer network address.
    pub fn addr(&self) -> SocketAddr {
        self.source.addr
    }
}

/// The set of peers chosen for the current sync cycle.
#[derive(Clone, Debug, Default)]
pub struct SyncPeerSelection {
    /// Peers used for block-body requests.
    pub request_peers: Vec<SyncPeer>,
    /// Peers used for cold-front prefix probes.
    pub probe_peers: Vec<SyncPeer>,
}

/// A height-eligible sync candidate annotated with its block-service
/// eligibility, fan-out eligibility, and soft-block status.
///
/// The clauses stay separate because the selection paths combine them
/// differently: fan-out, probes, and hedges require an eligible outbound
/// peer, while the deep request set and the single-peer fallback ask any
/// peer whose advertised services can serve the range — an inbound-only
/// node must still sync. A soft-blocked peer still serves as the last
/// resort when nothing better exists.
#[derive(Clone, Copy, Debug)]
pub struct FanoutCandidate {
    /// The peer this candidate refers to.
    pub peer: SyncPeer,
    /// Whether [`serves_requested_height`] accepted this peer: the one
    /// block-body service clause every body-selection path reads.
    pub serves_bodies: bool,
    /// Whether [`statically_fanout_eligible`] accepted this peer: the body
    /// service clause plus the outbound requirement, for the paths that
    /// stripe or hedge across self-chosen connections.
    pub fanout_eligible: bool,
    /// Whether the window currently soft-blocks this peer for requests.
    pub soft_blocked: bool,
}

/// The chain facts one block-body peer choice reads.
///
/// PRE: `requested_height` is the height of the block the selection fills,
///   taken from the same frontier snapshot as the candidates; `ibd` is the
///   node's one latch.
/// POST: [`serves_requested_height`] answers for that height.
/// INVARIANT: one shared latch decides initial block download for every
///   selection path; no path caches or re-derives the answer.
pub struct BlockDownloadPolicy {
    /// The node's chain-owned initial-block-download latch.
    pub ibd: Arc<InitialBlockDownload>,
    /// The height of the block body this selection fills.
    pub requested_height: u32,
    /// The network the latch judges: the work floor is network-dependent.
    pub network: Network,
}

/// Whether a peer's advertised services can serve the policy's height.
///
/// This is the one block-body service clause: the request, fan-out, probe,
/// and hedge paths all read it, and none re-derives a witness-only rule. It
/// runs before the window's dynamic clauses (KTD6).
///
/// PRE: `policy` names the requested height and the node's sync phase.
/// POST: true only for a witness peer whose advertised services cover that
///   height. During initial block download the peer must advertise
///   `NODE_NETWORK`, so a pruned peer is never asked for old blocks (Core
///   `net_processing.cpp:6521`). Afterwards a peer without `NODE_NETWORK`
///   serves only the last [`NODE_NETWORK_LIMITED_MIN_BLOCKS`] blocks of its
///   own demonstrated chain (`net_processing.cpp:1637`); one below the
///   requested height is ineligible.
/// INVARIANT: every body-selection path applies this clause; a peer that
///   cannot serve the range is never asked for it.
pub fn serves_requested_height(peer: &PeerInfo, policy: &BlockDownloadPolicy) -> bool {
    let network = ServiceFlags::NETWORK.to_u64();
    let witness = ServiceFlags::WITNESS.to_u64();
    if peer.services & witness == 0 {
        return false;
    }
    if peer.services & network != 0 {
        return true;
    }
    // Core applies the retained window only to `NODE_NETWORK_LIMITED`
    // (`net_processing.cpp:1637`): a peer without it serves no blocks.
    if peer.services & ServiceFlags::NETWORK_LIMITED.to_u64() == 0 {
        return false;
    }
    if policy
        .ibd
        .is_active(crate::counters::now_seconds(), policy.network)
    {
        return false;
    }
    u32::try_from(peer.best_known_height).is_ok_and(|demonstrated| {
        demonstrated
            .checked_sub(policy.requested_height)
            .is_some_and(|left_tip| left_tip < NODE_NETWORK_LIMITED_MIN_BLOCKS)
    })
}

/// The lowest height a peer's advertised services may serve.
///
/// `0` for a `NODE_NETWORK` peer or while initial block download already
/// excludes limited peers outright, else the retained-window floor of the
/// peer's demonstrated chain (`NODE_NETWORK_LIMITED_MIN_BLOCKS`,
/// `net_processing.cpp:159-161`). Request schedulers clamp batches to
/// `floor..=best` so a limited peer is never sent a height outside the
/// window [`serves_requested_height`] certified at selection time.
#[must_use]
pub fn servable_floor(peer: &PeerInfo, policy: &BlockDownloadPolicy) -> u32 {
    let network = ServiceFlags::NETWORK.to_u64();
    if peer.services & network != 0
        || policy
            .ibd
            .is_active(crate::counters::now_seconds(), policy.network)
    {
        return 0;
    }
    if peer.services & ServiceFlags::NETWORK_LIMITED.to_u64() == 0 {
        // No block-serving flag at all: nothing is servable.
        return u32::MAX;
    }
    u32::try_from(peer.best_known_height)
        .unwrap_or(0)
        .saturating_sub(NODE_NETWORK_LIMITED_MIN_BLOCKS.saturating_sub(1))
}

/// Whether a connection may take part in fan-out striping, prefix probes,
/// and cold-front hedges: the [`serves_requested_height`] clause plus the
/// pre-existing outbound requirement.
///
/// PRE: `policy` names the requested height and the node's sync phase.
/// POST: true only for an outbound peer that may serve that height. Inbound
///   peers never qualify here: they are attacker-chosen, and counting them
///   toward fan-out is the recorded under-fill regression. The deep request
///   set and the single-peer fallback are not fan-out paths and read the
///   service clause alone, so an inbound-only node still syncs.
/// INVARIANT: this is the only fan-out service clause.
pub fn statically_fanout_eligible(peer: &PeerInfo, policy: &BlockDownloadPolicy) -> bool {
    !peer.inbound && serves_requested_height(peer, policy)
}

pub(super) fn peer_advertises_block_service(peer: &PeerInfo) -> bool {
    let network = ServiceFlags::NETWORK.to_u64();
    peer.services & (network | NETWORK_LIMITED) != 0
}

/// Whether a peer advertising block service can serve one required body height.
///
/// Core leaves two blocks of race buffer inside the 288-block limited-service
/// window (`net_processing.cpp:1636-1638`).
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

/// Set the fan-out/request mode on the window from the current candidate set.
///
/// PRE: each candidate carries the service clause and the window clause
///   separately.
/// POST: the counted fan-out set and the returned cold-front peer satisfy both
///   clauses.
/// INVARIANT: a candidate soft-blocked by the window never counts toward
///   fan-out.
pub fn configure_request_mode(
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

/// Returns the production [`SyncBudget`] used by the sync coordinator.
///
/// PRE: `network` is the chain the coordinator syncs.
/// POST: the per-owner block-download budget derives from that network's
///      proof-of-work target spacing; no timeout override is set.
/// INVARIANT: production never populates `pending_timeout_override`.
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

/// Returns the opt-in fast-sync [`SyncBudget`]: the default window striped
/// shallower and earlier across up to [`FAST_OUTBOUND_PEER_TARGET`] peers.
pub fn fast_sync_budget(network: Network) -> SyncBudget {
    SyncBudget {
        fanout_peer_inflight: FAST_BLOCKS_IN_TRANSIT_PER_PEER,
        min_peers_for_fanout: FAST_MIN_PEERS_FOR_FANOUT,
        ..default_sync_budget(network)
    }
}
