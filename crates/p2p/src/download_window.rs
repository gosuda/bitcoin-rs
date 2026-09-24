//! Block download window, peer-assignment, stall, and scheduling policy.
//!
//! This module owns the download-side policy that decides which blocks to
//! request from which peers, how to detect and recover from stalls, and how
//! to manage the in-flight window budget. [`crate::BlockStager`] owns the
//! matching inbound staging set. The node sync coordinator drives these
//! types; it does not own the policy.
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin::p2p::ServiceFlags;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::{Hash256, Network};
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

use crate::BlockStager;
use crate::PeerInfo;
use crate::connection::PeerSource;

// ---------------------------------------------------------------------------
// Download-policy constants
// ---------------------------------------------------------------------------

/// Core's `BLOCK_DOWNLOAD_TIMEOUT_BASE` in half-target-spacing units
/// (`net_processing.cpp:153-168`): an owner with no other validated-block
/// downloaders gets one full proof-of-work target spacing of queue age
/// before its oldest request is considered stuck.
const BLOCK_DOWNLOAD_TIMEOUT_BASE: u32 = 2;
/// Core's `BLOCK_DOWNLOAD_TIMEOUT_PER_PEER` in half-target-spacing units:
/// each additional active downloader adds half a spacing to the budget.
const BLOCK_DOWNLOAD_TIMEOUT_PER_PEER: u32 = 1;
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
pub const MAX_SERIALIZED_BLOCK_SIZE: usize = 4_000_000;
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

/// A height-eligible sync candidate annotated with its fan-out eligibility
/// and soft-block status.
///
/// The fan-out eligibility is the KTD6 predicate, finalized across
/// `statically_fanout_eligible` and the window's soft-demotion check; the
/// soft-block flag indicates whether the window currently soft-blocks the
/// candidate for block requests (expired pendings or staller cooldown).
#[derive(Clone, Copy, Debug)]
pub struct FanoutCandidate {
    /// The peer this candidate refers to.
    pub peer: SyncPeer,
    /// Whether the peer satisfies the KTD6 fan-out eligibility predicate.
    pub fanout_eligible: bool,
    /// Whether the window currently soft-blocks this peer for requests.
    pub soft_blocked: bool,
}

/// Connection-level clauses of the fan-out eligibility predicate (KTD6).
///
/// Outbound and witness-serving (`NODE_WITNESS`), per Bitcoin Core's
/// block-download peer criteria in `net_processing.cpp` (Core requests blocks
/// only from witness peers post-segwit, and inbound peers are
/// attacker-chosen — counting them toward fan-out is the recorded under-fill
/// regression). The height clause lives in the candidate filter and the
/// soft-demotion clause in [`DownloadWindow::peer_has_expired_pending`].
pub fn statically_fanout_eligible(peer: &PeerInfo) -> bool {
    let witness = ServiceFlags::WITNESS.to_u64();
    !peer.inbound && peer.services & witness != 0
}

/// Set the fan-out/request mode on the window from the current candidate set.
pub fn configure_request_mode(
    window: &mut DownloadWindow,
    candidates: &[FanoutCandidate],
    now: Instant,
) -> Option<SyncPeer> {
    let eligible = candidates
        .iter()
        .filter(|candidate| candidate.fanout_eligible)
        .count();
    let preferred_source = window.preferred_peer();
    let preferred_candidate = preferred_source.and_then(|source| {
        candidates
            .iter()
            .find(|candidate| candidate.peer.source == source)
    });
    let preferred = preferred_candidate
        .filter(|candidate| !candidate.soft_blocked)
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

// ---------------------------------------------------------------------------
// Download window (stall, peer-inflight, cold-front, prefix-probe policy)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct SyncBudget {
    pub max_pending_blocks: usize,
    pub max_pending_bytes: usize,
    pub max_received_blocks: usize,
    pub max_received_bytes: usize,
    pub max_peer_inflight: usize,
    pub fanout_peer_inflight: usize,
    pub min_peers_for_fanout: usize,
    pub getdata_batch_limit: usize,
    /// The network's proof-of-work target spacing (Core's nPowTargetSpacing):
    /// the unit of the per-owner block-download budget,
    /// `block_spacing / 2 * (BASE + PER_PEER * other)`, where `other`
    /// counts the other owners with validated in-flight blocks, with the
    /// two Core constants expressed in half-spacing units.
    pub block_spacing: Duration,
    /// When `Some`, every owner expires at this fixed age instead of the
    /// spacing-derived per-owner budget. The slot is compiled only into
    /// test builds; production budgets never carry it.
    #[cfg(test)]
    pub(crate) pending_timeout_override: Option<Duration>,
    pub received_timeout: Duration,
    pub stall_timeout_initial: Duration,
    pub stall_timeout_max: Duration,
    pub staller_cooldown: Duration,
}

impl SyncBudget {
    /// Sets the fixed per-owner pending timeout. Test-only: this
    /// constructor is compiled out of production builds.
    ///
    /// PRE: `timeout` is the fixed age every owner expires at.
    /// POST: `pending_timeout_override` is `Some(timeout)`.
    /// INVARIANT: production never populates `pending_timeout_override`.
    #[cfg(test)]
    pub(crate) fn with_pending_timeout_override(mut self, timeout: Duration) -> Self {
        self.pending_timeout_override = Some(timeout);
        self
    }
}

/// A batch of block requests prepared for a single peer.
#[derive(Clone, Debug)]
pub struct PeerRequest {
    owner: PeerSource,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
}

impl PeerRequest {
    /// Returns the exact connection this request is directed to.
    pub fn owner(&self) -> PeerSource {
        self.owner
    }

    /// Iterates over the `(height, hash)` pairs in this request.
    pub fn entries(&self) -> impl Iterator<Item = (u32, Hash256)> + '_ {
        self.entries.iter().map(|entry| (entry.height, entry.hash))
    }

    /// Returns the number of block entries in this request.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the request contains no block entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
struct PeerRequestEntry {
    hash: Hash256,
    height: u32,
}

#[derive(Clone, Copy, Debug)]
struct RequestScan {
    height: u32,
    request_tip_height: u32,
    remaining_limit: usize,
    next_request_height: u32,
}

enum SelectedHashes {
    Inline(SmallVec<[Hash256; 4]>),
    Set(HashSet<Hash256>),
}

impl SelectedHashes {
    fn from_entries(entries: &[PeerRequestEntry]) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        if entries.len() <= 4 {
            return Some(Self::Inline(
                entries.iter().map(|entry| entry.hash).collect(),
            ));
        }
        let mut selected_hashes = HashSet::with_capacity(entries.len());
        selected_hashes.extend(entries.iter().map(|entry| entry.hash));
        Some(Self::Set(selected_hashes))
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline(hashes) => hashes.len(),
            Self::Set(hashes) => hashes.len(),
        }
    }

    fn contains(&self, hash: &Hash256) -> bool {
        match self {
            Self::Inline(hashes) => hashes.contains(hash),
            Self::Set(hashes) => hashes.contains(hash),
        }
    }
}

/// Smallest inter-front-advance interval (milliseconds) accepted as a front
/// cadence sample. The sync layer timestamps a whole inbound chunk with one
/// `Instant` (`buffer_received_block_chunk`), so an in-order run of front
/// blocks processed in the same chunk yields same-instant "advances" whose
/// 0ms samples are batching artifacts, not network cadence — left unfiltered
/// they walk the EWMA toward zero (x3/4 each) and collapse the adaptive stall
/// floor back to the static minimum. Skipping genuine sub-50ms cadence loses
/// nothing: at that speed the decay floor is clamped at
/// `stall_timeout_initial` anyway.
const EWMA_MIN_SAMPLE_MS: u64 = 50;

#[derive(Clone, Copy, Debug)]
struct PendingBlock {
    /// The exact connection that owns this request. Same-address
    /// replacement must never inherit it: liveness is checked on the pair
    /// `(owner.addr, owner.connection_id())`, not the address alone.
    owner: PeerSource,
    requested_at: Instant,
    height: u32,
    estimated_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct PendingTimeoutObservation {
    owner: PeerSource,
    hash: Hash256,
    /// Set when the owner's own timeout expiry released the observed
    /// request: the blame evidence the second tick convicts on. A
    /// delivery or a requeue releases without it and pardons.
    expired_release: bool,
}

/// A running window-blocked stall observation: the window front (`front_hash`)
/// has been in flight to `peer_addr` with the apply frontier idle and no other
/// download progress possible since `since`. The analog of Bitcoin Core's
/// per-peer `m_stalling_since` (`net_processing.cpp`).
#[derive(Clone, Copy, Debug)]
struct StallEpisode {
    owner: PeerSource,
    front_hash: Hash256,
    since: Instant,
    /// Whether the one-shot episode-observability INFO line has been emitted
    /// for this episode (fires once when the episode survives
    /// [`STALL_EPISODE_LOG_AGE`]; see [`DownloadWindow::advance_stall`]).
    info_logged: bool,
}

/// One continuous apply-side stuck episode: the apply frontier pinned at
/// `(height, frontier_hash)` with a staged body held (`apply_side_busy`)
/// across [`DownloadWindow::advance_apply_side_stuck`] calls.
///
/// Keyed by height AND hash: the prune/refetch cycle briefly removes and
/// re-delivers the stuck staged body (flipping `apply_side_busy` off and
/// back on within one tick) and the conviction is about the pinned
/// frontier, so the episode survives that seam — while a same-height branch
/// replacement swaps in a different expected body and must start its own
/// clock. The episode also starts only while a body is actually staged: an
/// idle frontier (nothing staged yet) accumulates nothing, so a frontier
/// that simply took long to deliver its first body does not have that
/// delivery evicted on arrival.
#[derive(Clone, Copy, Debug)]
struct ApplySideStuck {
    height: u32,
    frontier_hash: Hash256,
    since: Instant,
}
#[derive(Clone, Copy, Debug)]
enum ColdFrontState {
    Waiting {
        owner: PeerSource,
        hash: Hash256,
        since: Instant,
    },
    Racing {
        owner: PeerSource,
        alternate: PeerSource,
        hash: Hash256,
    },
}

/// The canonical frontier facts one blockage observation needs.
///
/// PRE: `next_apply_height` and `frontier_hash` describe the same
///      `next_required` body the scheduler requested this tick;
///      `apply_side_busy` is current for that body.
/// POST: one tick advances every observation from this one snapshot.
/// INVARIANT: a frontier without a next-expected block has `None` height
///      and `None` hash; only the pending timeout still runs there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockedContext {
    /// The next height apply expects, or `None` at the chain tip.
    pub next_apply_height: Option<u32>,
    /// The hash of that next-expected body, or `None` at the chain tip.
    pub frontier_hash: Option<Hash256>,
    /// Whether the stager holds the next-expected body (apply lag).
    pub apply_side_busy: bool,
    /// Distinct exact connections owning validated in-flight blocks this
    /// tick, from [`DownloadWindow::active_downloading_peers`].
    pub active_downloading_peers: usize,
}

/// Why the unified blockage observation convicted an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlameReason {
    /// The window-blocked stall predicate fired on this owner.
    Staller,
    /// This owner's pending block passed its timeout twice.
    PendingTimeout,
}

/// The single action the sync coordinator owes this tick.
///
/// PRE: apply-side state and exact pending owners are current; `now` is
///      injected by the caller.
/// POST: at most one action returns, in precedence
///      `EvictStaged` > `Blame(Staller)` > `Blame(PendingTimeout)` >
///      `HedgeColdFront` > `None`.
/// INVARIANT: a same-address replacement never inherits blame, because
///      every observation keys on the exact [`PeerSource`]; only the
///      apply-side bound can produce [`BlockedDecision::EvictStaged`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedDecision {
    /// Disconnect `owner`: it is stalling the window or missed its
    /// request timeout.
    Blame {
        /// The exact owning connection.
        owner: PeerSource,
        /// Which rule convicted it.
        reason: BlameReason,
    },
    /// The apply-side no-blame suppression outlived its bound: evict the
    /// staged body at `height`/`hash` for refetch. No peer is blamed.
    EvictStaged {
        /// The stuck apply-frontier height.
        height: u32,
        /// The stuck staged body's hash.
        hash: Hash256,
        /// How long the suppression had held when it fired.
        suppressed_for: Duration,
    },
    /// Send a duplicate request for the cold front from another peer.
    HedgeColdFront {
        /// The current exact owner of the front block.
        owner: PeerSource,
        /// The front block's hash.
        front_hash: Hash256,
    },
    /// Nothing to do this tick.
    None,
}
#[derive(Debug)]
struct PrefixProbe {
    owner: PeerSource,
    hashes: SmallVec<[Hash256; PREFIX_PROBE_BLOCK_LIMIT]>,
    racers: HashMap<PeerSource, u8>,
    accepted: u8,
    started_at: Instant,
}

/// Episode age at which the one-shot stall-episode observability INFO line is
/// emitted. Below the 2s conviction floor by design: the line exists to make
/// episode dynamics visible in run logs *below* the WARN fire line — which
/// clearing rule zeroed the clock, and what the front-cadence EWMA (the
/// threshold's falsifier) was while the episode ran.
const STALL_EPISODE_LOG_AGE: Duration = Duration::from_secs(1);
/// Maximum distinct cold-start front blocks hedged before the cadence EWMA
/// seeds. Two advances are sufficient to produce the first cadence sample.
const MAX_COLD_FRONT_HEDGES: usize = 2;
/// One-shot duplicate prefix used to select a responsive deep-window peer.
const PREFIX_PROBE_BLOCK_LIMIT: usize = 8;
/// A peer must deliver the first four accepted prefix blocks to win.
const PREFIX_PROBE_WIN_BLOCKS: usize = 4;
const _: () = assert!(PREFIX_PROBE_WIN_BLOCKS > 0);
const _: () = assert!(PREFIX_PROBE_WIN_BLOCKS <= PREFIX_PROBE_BLOCK_LIMIT);
const _: () = assert!(PREFIX_PROBE_BLOCK_LIMIT <= 8);
const PREFIX_PROBE_WIN_MASK: u8 = (1_u8 << PREFIX_PROBE_WIN_BLOCKS) - 1;
/// Estimated duplicate bytes per alternate during the one-shot probe.
const PREFIX_PROBE_ESTIMATED_BYTES: usize = 2 * 1024 * 1024;

/// Stall-episode clearing reasons, the counter taxonomy for
/// `node.sync.stall_episodes_cleared{reason}`. Every path that zeroes the
/// episode clock tags exactly one reason:
/// - `apply_busy`: the no-blame guard held this tick ([`DownloadWindow::advance_stall`]).
/// - `predicate`: a [`DownloadWindow::window_blocked_on`] term went false
///   (front moved off the frontier, no staged successor, or capacity opened).
/// - `front_moved`: the predicate still holds but for a different
///   `(peer, front_hash)` — the episode re-keyed and a new one started.
/// - `peer_delivery`: the blamed peer delivered a requested block
///   ([`DownloadWindow::record_delivery_progress`]).
/// - `fired`: conviction — the episode reached the effective threshold.
fn count_stall_episode_cleared(reason: &'static str) {
    metrics::counter!("node.sync.stall_episodes_cleared", "reason" => reason).increment(1);
}

/// Block download window: tracks pending and in-flight block requests with
/// stall detection, cold-front hedging, and fan-out policy.
#[derive(Debug)]
pub struct DownloadWindow {
    budget: SyncBudget,
    pending: HashMap<Hash256, PendingBlock>,
    pending_bytes: usize,
    /// Highest `pending` population observed; feeds the high-water gauge.
    pending_blocks_high_water: usize,
    /// Highest `pending_bytes` observed; feeds the high-water gauge.
    pending_bytes_high_water: usize,
    /// Start of the current apply-idle interval: no staged work while the
    /// window still owes downloads. `None` while apply has work.
    apply_idle_since: Option<Instant>,
    /// Start of the current download-blocked-by-apply interval: blocks are
    /// staged (apply owns the frontier) while the window front stays in
    /// flight. `None` while apply is not the gate.
    download_blocked_by_apply_since: Option<Instant>,
    ewma_block_bytes: usize,
    next_request_height: u32,
    request_tip: Option<(Hash256, u32)>,
    /// Per-owner block-download queue start: the local equivalent of
    /// Core's per-peer `m_downloading_since` (`net_processing.cpp:1323-1332,
    /// 1363-1368`). Keyed by the exact `PeerSource`; an entry exists exactly
    /// while that owner has validated in-flight blocks.
    owner_downloading_since: HashMap<PeerSource, Instant>,
    /// Eligible outbound witness peers available for new block assignments.
    /// The count sizes each stripe; engagement keeps one-peer hysteresis so a
    /// transient demotion does not switch candidate classes mid-window.
    fanout_eligible_peers: usize,
    fanout_engaged: bool,
    /// Current window-blocked stall observation, if any (R8). Re-derived from
    /// the predicate every [`Self::advance_stall`] call; cleared whenever any
    /// predicate term stops holding, so a transient stall never accumulates
    /// blame across unrelated episodes.
    stall: Option<StallEpisode>,
    /// Current apply-side stuck observation, if any (#1091 bound). Re-keyed
    /// on the apply-front `(height, hash)` every
    /// [`Self::advance_apply_side_stuck`] call; a front advance or a
    /// same-height branch replacement resets it, brief unbusy seams do not,
    /// and an idle frontier starts no clock at all.
    apply_side_stuck: Option<ApplySideStuck>,
    /// Adaptive stalling threshold: starts at `stall_timeout_initial` (2s),
    /// doubles on every staller disconnect up to `stall_timeout_max` (64s),
    /// and decays by x0.85 per window-front arrival back toward the decay
    /// floor ([`Self::stall_decay_floor`]) — Core's `m_block_stalling_timeout`
    /// shape (PR #25880) with an adaptive floor. Decay, never reset: snapping
    /// to the floor on front progress would discard the anti-cascade doubling
    /// across a peer rotation and re-arm the 2s floor against the next
    /// honest-but-slow front owner. Window-global (not per-peer) exactly like
    /// Core's, so an immediately-reconnecting staller faces the doubled
    /// threshold instead of a fresh 2s.
    stall_timeout: Duration,
    /// EWMA (integer milliseconds, smoothing alpha = 1/4) of the interval
    /// between consecutive window-front arrivals — the network's demonstrated
    /// front cadence. `None` until the second front arrival produces the
    /// first sample; the first sample seeds the EWMA directly. Feeds
    /// [`Self::stall_decay_floor`] (the ADV-DRIP-1 fix): with a uniform
    /// honest per-peer delivery gap g > `stall_timeout_initial` (ordinary
    /// high-height IBD under peer upload caps), the static 2s floor lets the
    /// x0.85 decay re-cross g in ~4-5 front advances and fire again — a limit
    /// cycle draining one honest peer per ~5g seconds. Keying the floor to
    /// twice the demonstrated cadence kills the cycle while a true staller
    /// (silent while others stream) still convicts at ~2g. The estimate
    /// stays honest because same-chunk batch arrivals (samples under
    /// [`EWMA_MIN_SAMPLE_MS`]) are skipped so an in-order burst sharing one
    /// chunk timestamp cannot deflate the floor. A window with no sample at
    /// all (cold start) convicts at the `stall_timeout_initial` floor —
    /// [`Self::advance_stall`] never suppresses conviction for lack of a
    /// cadence estimate.
    front_interval_ewma_ms: Option<u64>,
    /// When the window front last advanced (a front block arrived); the
    /// anchor for the next `front_interval_ewma_ms` sample.
    last_front_advance: Option<Instant>,
    /// Cold-start front wait or active duplicate race. Unlike `stall`, this
    /// needs no staged successors and can never disconnect a peer.
    cold_front: Option<ColdFrontState>,
    /// Distinct cold-start front hashes whose duplicate request was sent.
    cold_hedged_fronts: SmallVec<[Hash256; MAX_COLD_FRONT_HEDGES]>,
    /// Peer that proved it could deliver a blocked cold front before its
    /// tracked owner. It receives the replacement deep window.
    preferred_peer: Option<PeerSource>,
    /// One-shot same-prefix race used to select a responsive deep owner
    /// without assigning unique height holes to alternate peers.
    prefix_probe: Option<PrefixProbe>,
    /// Deep owner already tested for the current pending assignment.
    prefix_probe_attempted_owner: Option<PeerSource>,
    /// First observation of an expired front request. Conviction needs a
    /// second tick so blocks delivered during synchronous apply can drain.
    pending_timeout_observation: Option<PendingTimeoutObservation>,
    /// Peers disconnected for stalling or an expired block request, by fire
    /// time. While inside `staller_cooldown` such a peer is not fan-out
    /// eligible and receives no block requests except as the last-resort peer.
    /// This prevents immediate re-acquisition of the same block stripe.
    recent_stallers: HashMap<SocketAddr, Instant>,
}

impl DownloadWindow {
    /// Creates a new download window with the given budget.
    pub fn new(budget: SyncBudget) -> Self {
        Self {
            budget,
            pending: HashMap::with_capacity(budget.max_pending_blocks),
            pending_bytes: 0,
            pending_blocks_high_water: 0,
            pending_bytes_high_water: 0,
            apply_idle_since: None,
            download_blocked_by_apply_since: None,
            ewma_block_bytes: 256 * 1024,
            next_request_height: 1,
            request_tip: None,
            owner_downloading_since: HashMap::with_capacity(budget.max_pending_blocks),
            fanout_eligible_peers: 0,
            fanout_engaged: false,
            stall: None,
            apply_side_stuck: None,
            stall_timeout: budget.stall_timeout_initial,
            front_interval_ewma_ms: None,
            last_front_advance: None,
            cold_front: None,
            cold_hedged_fronts: SmallVec::new(),
            preferred_peer: None,
            prefix_probe: None,
            prefix_probe_attempted_owner: None,
            pending_timeout_observation: None,
            recent_stallers: HashMap::new(),
        }
    }

    /// Records the eligible population and updates engagement with one-peer
    /// hysteresis. Dynamic stripe sizing prevents the old whole-window
    /// re-concentration when the count dips.
    ///
    /// Bounded prefix-race-before-fanout handoff: when the eligible count
    /// reaches the fanout threshold while a prefix probe is active and
    /// younger than `stall_timeout_initial`, defer only fanout engagement so
    /// the one-shot race (typically sub-second) can elect a preferred peer
    /// instead of being cancelled by the engagement. After the probe
    /// resolves/cancels or the fixed `stall_timeout_initial` interval
    /// expires, existing hysteresis and immediate prefix-probe cancellation
    /// behavior resume unchanged. `now` is injected (not read here) so the
    /// tick/selection path controls the clock; see [`Self::advance_stall`]
    /// for the same discipline.
    pub fn set_fanout_eligible_peers(&mut self, count: usize, now: Instant) {
        let was_engaged = self.fanout_engaged;
        self.fanout_eligible_peers = count;
        let would_engage = count >= self.budget.min_peers_for_fanout;
        // Bound the deferral: while a fresh prefix probe (age <
        // stall_timeout_initial) is racing, hold fanout disengaged so the
        // race is not cancelled mid-flight. The probe's elapsed time is
        // computed from the injected `now` against the probe's
        // `started_at` (itself an injected `Instant`), never
        // `Instant::now()`. The bound is a strict less-than: at an elapsed
        // time exactly equal to `stall_timeout_initial` the probe is no
        // longer fresh (the race had its full budget), so fanout engages at
        // the deadline — `<` rather than `<=`. The boundary is pinned by
        // tests that cross at exactly `stall_timeout_initial`.
        let probe_young = self.prefix_probe.as_ref().is_some_and(|probe| {
            now.duration_since(probe.started_at) < self.budget.stall_timeout_initial
        });
        let engaging = would_engage && !probe_young;
        if engaging {
            self.fanout_engaged = true;
        } else if count.saturating_add(1) < self.budget.min_peers_for_fanout {
            self.fanout_engaged = false;
        }
        if self.fanout_engaged != was_engaged {
            tracing::info!(
                eligible = count,
                fanout_active = self.fanout_active(),
                min_peers_for_fanout = self.budget.min_peers_for_fanout,
                "fanout engagement changed"
            );
        }
        if self.fanout_engaged {
            self.prefix_probe = None;
        }
    }

    /// Whether requests use a distributed cap or the one-peer deep fallback.
    pub const fn fanout_active(&self) -> bool {
        self.fanout_engaged
    }

    /// Per-peer cap for new assignments. With multiple eligible peers, divide
    /// the global window across them but never go below Core's 16-block cap.
    /// One peer retains the deep fallback. Existing over-cap assignments drain
    /// naturally after the eligible population changes.
    fn effective_peer_inflight(&self) -> usize {
        if !self.fanout_active() {
            return self.budget.max_peer_inflight;
        }
        self.budget
            .max_pending_blocks
            .div_ceil(self.fanout_eligible_peers.max(1))
            .max(self.budget.fanout_peer_inflight)
            .min(self.budget.max_peer_inflight)
    }

    /// Returns the number of blocks currently pending (requested, not yet received).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Maximum number of blocks the download window will keep pending at once.
    ///
    /// Used as the horizon cap when the apply-side cache is repopulated on a
    /// miss: at most this many blocks can be in flight (and therefore stage)
    /// before the cache's validity keys change and force a refresh.
    pub const fn max_pending_blocks(&self) -> usize {
        self.budget.max_pending_blocks
    }

    /// Returns the total estimated bytes of pending blocks.
    pub const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Returns `true` if the window can accept new block requests.
    ///
    /// PRE: `stager` is the staging set coupled to this window (the same
    ///      one the scheduler holds); expiry has run this tick.
    /// POST: `true` only while pending counts, pending bytes, and the
    ///      stager's staged byte and slot headroom can absorb one more
    ///      estimated block.
    /// INVARIANT: staged-body counts and bytes are read from `stager`,
    ///      never from a window-local copy.
    pub fn has_request_capacity(&self, stager: &BlockStager) -> bool {
        self.pending.len() < self.budget.max_pending_blocks
            && self.pending_bytes.saturating_add(self.ewma_block_bytes)
                <= self.budget.max_pending_bytes
            && self.staged_byte_headroom(stager) >= self.ewma_block_bytes
            && self.staged_count_headroom(stager, 0) > 0
    }

    /// Staged-byte backpressure: once the blocks already received and waiting
    /// to apply have consumed the staging byte budget, stop issuing new block
    /// requests — arrivals would only be refused by the stager and
    /// re-requested, churning bandwidth. Capacity returns as staged blocks are
    /// applied (or expire) and their bytes are released.
    ///
    /// PRE: `stager` is the staging set coupled to this window.
    /// POST: `true` while the stager's staged bytes have exhausted the
    ///      staging byte budget.
    /// INVARIANT: the byte total is read from `stager`.
    fn staged_bytes_exhausted(&self, stager: &BlockStager) -> bool {
        stager.received_bytes() >= self.budget.max_received_bytes
    }

    /// Staging bytes still free if every in-flight pending block arrives at
    /// the current per-block estimate. Request sizing is clamped to this so a
    /// gate-open burst cannot top a partially full stager over its budget and
    /// trigger refuse/re-download churn in the high-height regime (the
    /// staged-byte gate alone is headroom-blind: it only closes once staging
    /// is already exhausted).
    ///
    /// The clamp engages only while blocks are actually staged. With an empty
    /// stager liveness wins: the window-front request must stay issuable even
    /// when one estimated block exceeds the staging budget (the stager's
    /// expected-block exemption and drop-for-retry are the degrade path
    /// there), and the default budget pair (`max_pending_bytes ==
    /// max_received_bytes`) already bounds a from-empty burst to exactly the
    /// staging budget.
    ///
    /// PRE: `stager` is the staging set coupled to this window.
    /// POST: the free staging bytes after subtracting in-flight pending
    ///      bytes; `usize::MAX` while nothing is staged.
    /// INVARIANT: the staged byte total is read from `stager`.
    fn staged_byte_headroom(&self, stager: &BlockStager) -> usize {
        let staged_bytes = stager.received_bytes();
        if staged_bytes == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_bytes
            .saturating_sub(staged_bytes)
            .saturating_sub(self.pending_bytes)
    }

    /// Staging slots still free if every in-flight pending block arrives: the
    /// count-denominated twin of [`Self::staged_byte_headroom`]. The twin is
    /// load-bearing, not symmetry for its own sake: the stager enforces its
    /// byte budget as admission backpressure but its count budget by
    /// **evicting the oldest staged blocks** (`block_stager.rs`,
    /// `evict_over_budget`) — the blocks nearest the apply frontier. A window
    /// clamped on bytes alone keeps requesting while a stalled front-stripe
    /// peer freezes the frontier, and the healthy peers' next wave pushes the
    /// staged count over budget into evict → drop-for-retry → re-request →
    /// evict churn (the recorded live-collapse signature). Clamping requests
    /// so staged + pending never exceeds `max_received_blocks` turns count
    /// overflow into request backpressure, exactly like the byte bound.
    ///
    /// Same from-empty engagement rule as the byte twin: with nothing staged
    /// the clamp stands down for liveness, and the default budget pair
    /// (`max_pending_blocks == max_received_blocks`) bounds a from-empty
    /// burst at exactly the count budget — and the stager evicts only
    /// strictly *above* `max_received_blocks`, so even a fully delivered
    /// burst lands at the budget without eviction.
    ///
    /// `expired_pending_blocks` credits pendings past the re-request timeout
    /// back to headroom. Unlike the byte clamp (which leaves expired bytes
    /// uncredited and recovers through the staged-block prune, the tested U5
    /// chain), the count clamp must credit them in the scan limit: a stalled
    /// front whose pendings hold staged + pending at the budget would
    /// otherwise pin the scan limit at zero — and expiry runs only inside
    /// [`Self::next_peer_request`], so the wedge could not process its own
    /// deadlines until the prune discarded every staged block into
    /// re-download. With the credit, the scan limit reopens at the pending
    /// timeout and the normal request path expires and re-requests the front
    /// while the staged set survives intact. Late arrival of an expired
    /// original deduplicates against its re-request by hash, so the credit
    /// cannot double-fill staging.
    ///
    /// PRE: `stager` is the staging set coupled to this window.
    /// POST: the free staging slots after subtracting live pendings
    ///      (crediting `expired_pending_blocks`); `usize::MAX` while nothing
    ///      is staged.
    /// INVARIANT: the staged count is read from `stager`.
    fn staged_count_headroom(&self, stager: &BlockStager, expired_pending_blocks: usize) -> usize {
        if stager.received_len() == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_blocks
            .saturating_sub(stager.received_len())
            .saturating_sub(self.pending.len().saturating_sub(expired_pending_blocks))
    }

    /// Maximum number of blocks to request from one peer this tick.
    ///
    /// PRE: `stager` is the staging set coupled to this window; expiry has
    ///      run this tick.
    /// POST: the per-peer scan bound derived from the pending budgets and
    ///      the stager's staged byte and slot headroom.
    /// INVARIANT: staged totals are read from `stager`.
    pub fn request_peer_scan_limit(&self, stager: &BlockStager, now: Instant) -> usize {
        if self.staged_bytes_exhausted(stager) {
            return 0;
        }
        let per_peer = self
            .budget
            .getdata_batch_limit
            .min(self.effective_peer_inflight());
        if per_peer == 0 || self.ewma_block_bytes == 0 {
            return 0;
        }
        let (expired_blocks, expired_bytes) = self.expired_pending_capacity(now);
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len().saturating_sub(expired_blocks))
            .min(self.staged_count_headroom(stager, expired_blocks));
        // Expired bytes are credited back to pending capacity (they will be
        // re-requested) but not to staging byte headroom: a late arrival of
        // the original request still stages. The count headroom does credit
        // them — see `staged_count_headroom` for why the wedge needs it.
        let byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes.saturating_sub(expired_bytes))
            .min(self.staged_byte_headroom(stager))
            / self.ewma_block_bytes;
        let request_blocks = block_capacity.min(byte_capacity);
        if request_blocks == 0 {
            return 0;
        }
        request_blocks
            .div_ceil(per_peer)
            .saturating_add(self.owner_address_count())
    }

    /// Blocks and bytes whose owner's queue has aged past its budget: the
    /// capacity the request path credits back for re-request this tick.
    ///
    /// PRE: `now` is the caller's injected clock.
    /// POST: totals over `pending` entries whose owner satisfies
    ///      [`Self::owner_download_expired`] under this tick's owner count.
    /// INVARIANT: the same per-owner predicate every consumer uses; no
    ///      fixed-duration path remains.
    fn expired_pending_capacity(&self, now: Instant) -> (usize, usize) {
        let active = self.active_downloading_peers();
        self.pending
            .values()
            .fold((0_usize, 0_usize), |(blocks, bytes), pending| {
                if !self.owner_download_expired(pending.owner, active, now) {
                    return (blocks, bytes);
                }
                (
                    blocks.saturating_add(1),
                    bytes.saturating_add(pending.estimated_bytes),
                )
            })
    }

    /// Whether `source` owns a pending block past the re-request timeout —
    /// the soft-demotion signal: such a peer gets no new front-of-window
    /// requests unless it is the last-resort peer, and it does not count as
    /// fan-out-eligible (KTD6's "not currently soft-demoted" clause).
    pub fn peer_has_expired_pending(&self, source: PeerSource, now: Instant) -> bool {
        self.owner_download_expired(source, self.active_downloading_peers(), now)
    }

    /// Advances every blockage observation once and returns at most one
    /// action for this tick.
    ///
    /// The order is fixed: the measurement intervals; the apply-side bound;
    /// the no-blame guard; the cold-front timer and the stall predicate;
    /// staller blame; the pending timeout (also at the chain tip); pending
    /// blame; the cold-front hedge.
    ///
    /// PRE: `ctx` describes the canonical frontier after this tick's apply
    ///      drain; `stager` is the coupled staging set and `tree` resolves
    ///      staged hashes to heights; `now` is injected by the caller.
    /// POST: the no-blame guard is evaluated once; the return value is the
    ///      single action the caller owes: disconnect the blamed exact
    ///      owner, evict the stuck staged body without blame, send the
    ///      cold-front duplicate request, or nothing.
    /// INVARIANT: a same-address replacement never inherits blame, because
    ///      every observation keys on the exact [`PeerSource`].
    /// INVARIANT: while `ctx.apply_side_busy` holds, no stall, timeout, or
    ///      hedge action returns; only the apply-side bound can return
    ///      [`BlockedDecision::EvictStaged`].
    pub fn observe_blocked(
        &mut self,
        ctx: BlockedContext,
        stager: &BlockStager,
        tree: &BlockTree,
        now: Instant,
    ) -> BlockedDecision {
        let evicted = if let Some(next_apply_height) = ctx.next_apply_height {
            self.observe_intervals(ctx.apply_side_busy, now);
            self.advance_apply_side_stuck(
                next_apply_height,
                ctx.frontier_hash,
                ctx.apply_side_busy,
                now,
            )
        } else {
            None
        };
        if ctx.apply_side_busy {
            // The no-blame guard: our own slowness is never a peer's fault.
            if self.stall.take().is_some() {
                count_stall_episode_cleared("apply_busy");
            }
            self.pending_timeout_observation = None;
            if !matches!(self.cold_front, Some(ColdFrontState::Racing { .. })) {
                self.cold_front = None;
            }
            return match (ctx.next_apply_height, evicted) {
                (Some(height), Some((hash, suppressed_for))) => BlockedDecision::EvictStaged {
                    height,
                    hash,
                    suppressed_for,
                },
                _ => BlockedDecision::None,
            };
        }
        let mut hedge = None;
        if let Some(next_apply_height) = ctx.next_apply_height {
            hedge = self.advance_cold_front(next_apply_height, now);
            if let Some(owner) = self.advance_stall(next_apply_height, stager, tree, now) {
                return BlockedDecision::Blame {
                    owner,
                    reason: BlameReason::Staller,
                };
            }
        }
        if let Some(owner) = self.advance_pending_timeout(now, self.active_downloading_peers()) {
            return BlockedDecision::Blame {
                owner,
                reason: BlameReason::PendingTimeout,
            };
        }
        hedge.map_or(BlockedDecision::None, |(owner, front_hash)| {
            BlockedDecision::HedgeColdFront { owner, front_hash }
        })
    }

    /// Observes the lowest expired request and convicts only on a second
    /// idle tick.
    ///
    /// A block may arrive while synchronous apply is running and wait in the
    /// inbound channel after its request timestamp expires. The first
    /// observation records suspicion only; delivery from the observed owner
    /// clears it at once, and any path that releases the observed hash
    /// without a delivery (the retarget and purge paths) leaves a suspicion
    /// that no longer measures anything. The second tick therefore
    /// re-verifies the observation against the live window before it
    /// converts suspicion into blame.
    ///
    /// PRE: the apply side is not busy this tick.
    /// POST: `Some(owner)` exactly when the previous observation named
    ///      `owner`, that owner still owns the observed hash in `pending`,
    ///      and that owner is still expired this tick; the owner's address
    ///      then enters the staller cooldown. Every other outcome clears
    ///      the observation and blames nobody.
    /// INVARIANT: the observation names the exact owning connection, and a
    ///      conviction never outlives the queue age it measured.
    fn advance_pending_timeout(
        &mut self,
        now: Instant,
        active_downloading_peers: usize,
    ) -> Option<PeerSource> {
        if let Some(observation) = self.pending_timeout_observation {
            self.pending_timeout_observation = None;
            let still_owned = self
                .pending
                .get(&observation.hash)
                .is_some_and(|pending| pending.owner == observation.owner);
            if observation.expired_release
                || (still_owned
                    && self.owner_download_expired(
                        observation.owner,
                        active_downloading_peers,
                        now,
                    ))
            {
                self.mark_peer_unresponsive(observation.owner.addr, now);
                return Some(observation.owner);
            }
            return None;
        }
        self.pending_timeout_observation = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                self.owner_download_expired(pending.owner, active_downloading_peers, now)
            })
            .min_by_key(|(_, pending)| pending.height)
            .map(|(hash, pending)| PendingTimeoutObservation {
                owner: pending.owner,
                hash: *hash,
                expired_release: false,
            });
        None
    }

    /// Time-bounds the apply-side no-blame suppression (issue #1091).
    ///
    /// While the stager holds the next expected block, `apply_side_busy`
    /// suppresses stall conviction, pending-timeout conviction, and the
    /// cold-front hedge — our own slowness is never a peer's fault. Left
    /// unbounded, a well-formed body that is staged but never applied wedges
    /// the window in silence: the 60s staged-body prune expires it, the
    /// re-request re-delivers it, the fresh insert re-stamps its
    /// `received_at`, and the suppression re-arms — a sawtooth that never
    /// lets any recovery path mature (observed live as 13h frozen at
    /// `gap=1`).
    ///
    /// This observation advances the stuck clock: an episode keyed by the
    /// apply-front `(height, frontier_hash)`. It accumulates across the
    /// brief unbusy seams of that sawtooth, and any frontier change — the
    /// apply side actually progressing, or a same-height branch replacement
    /// swapping the expected body — resets it. An idle frontier (no body
    /// staged yet) starts no clock, so a frontier that simply took longer
    /// than the bound to deliver does not have its first normal delivery
    /// evicted on arrival. Once one continuous stuck interval reaches
    /// twice `SyncBudget::received_timeout` (one full staged-body expiry
    /// plus one full refetch window have both failed to unblock the
    /// frontier), it fires: the caller must escalate WITHOUT peer blame, by
    /// evicting the stuck staged body for refetch so either the fresh
    /// delivery applies or the normal unsuppressed stall path engages.
    /// Firing re-arms the clock, so a persistently stuck frontier escalates
    /// at most once per bound.
    ///
    /// PRE: `frontier_hash` is `None` when no next-expected block exists
    ///      (the applied tip sits at the chain tip).
    /// POST: `Some((frontier_hash, suppressed_for))` exactly on fire; a
    ///      missing frontier drops any leftover episode.
    /// INVARIANT: the clock runs only while `apply_side_busy` holds.
    fn advance_apply_side_stuck(
        &mut self,
        next_apply_height: u32,
        frontier_hash: Option<Hash256>,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<(Hash256, Duration)> {
        let Some(frontier_hash) = frontier_hash else {
            // No expected frontier: nothing can be stuck.
            self.apply_side_stuck = None;
            return None;
        };
        match self.apply_side_stuck {
            Some(stuck)
                if stuck.height == next_apply_height && stuck.frontier_hash == frontier_hash => {}
            _ if apply_side_busy => {
                // A new episode starts only while a body for this frontier
                // is actually staged; an idle frontier accumulates nothing.
                self.apply_side_stuck = Some(ApplySideStuck {
                    height: next_apply_height,
                    frontier_hash,
                    since: now,
                });
            }
            _ => {
                // The frontier changed (or its body is absent with no active
                // episode): no clock may run for a frontier with nothing
                // staged about it.
                self.apply_side_stuck = None;
            }
        }
        if !apply_side_busy {
            return None;
        }
        let suppressed_for = now.duration_since(self.apply_side_stuck.as_ref()?.since);
        let bound = self.budget.received_timeout.saturating_mul(2);
        if suppressed_for < bound {
            return None;
        }
        // Re-arm: the eviction escalation consumed this conviction.
        if let Some(stuck) = self.apply_side_stuck.as_mut() {
            stuck.since = now;
        }
        Some((frontier_hash, suppressed_for))
    }

    /// Measurement only (issue #51): interval bookkeeping that never feeds
    /// a blockage decision.
    ///
    /// - download-blocked-by-apply: apply owns the frontier while requests
    ///   are in flight — download progress gated by apply speed.
    /// - apply-idle: requests in flight, nothing staged — apply starved by
    ///   the network.
    ///
    /// PRE: called once per tick that has an apply frontier.
    /// POST: at most one of the two intervals is open.
    /// INVARIANT: a closed interval records its duration exactly once.
    fn observe_intervals(&mut self, apply_side_busy: bool, now: Instant) {
        if apply_side_busy {
            if self.pending.is_empty() {
                self.close_download_blocked_by_apply(now);
            } else if self.download_blocked_by_apply_since.is_none() {
                self.download_blocked_by_apply_since = Some(now);
            }
            self.close_apply_idle(now);
        } else {
            self.close_download_blocked_by_apply(now);
            if self.pending.is_empty() {
                self.close_apply_idle(now);
            } else if self.apply_idle_since.is_none() {
                self.apply_idle_since = Some(now);
            }
        }
    }

    /// Advances the window-blocked stall state machine one observation (R8).
    ///
    /// `next_apply_height` is `applied_tip.height + 1`, the apply frontier.
    ///
    /// Deliberately *not* an input: a chain-tail arm ("nothing above the
    /// window left to request"). At the tip, one >2s block from a caught-up
    /// peer is the normal regime, not a stall — Core's stalling logic does
    /// not engage there either, and the last <window blocks of IBD stay
    /// covered by the pending-timeout machinery.
    ///
    /// An unseeded front-cadence EWMA (cold start) does not suppress
    /// conviction: the threshold is then the stored adaptive value, whose
    /// floor is `stall_timeout_initial` — Core's `BLOCK_STALLING_TIMEOUT_DEFAULT`.
    ///
    /// PRE: the apply side is not busy this tick.
    /// POST: `Some(owner)` exactly when the stall threshold fires: the
    ///      caller must disconnect that exact owner (its pendings then
    ///      re-queue through [`Self::retain_owned_by`]). On fire the
    ///      adaptive threshold doubles (capped at `stall_timeout_max`) and
    ///      the owner's address enters the staller cooldown.
    /// INVARIANT: when any predicate term stops holding — including any
    ///      delivery from the blamed peer ([`Self::record_delivery_progress`])
    ///      — the episode is cleared, more forgiving than freezing the clock
    ///      and Core-shaped (`m_stalling_since` is likewise re-derived,
    ///      never frozen).
    fn advance_stall(
        &mut self,
        next_apply_height: u32,
        stager: &BlockStager,
        tree: &BlockTree,
        now: Instant,
    ) -> Option<PeerSource> {
        let Some((owner, front_hash)) = self.window_blocked_on(stager, tree, next_apply_height)
        else {
            if self.stall.take().is_some() {
                count_stall_episode_cleared("predicate");
            }
            return None;
        };
        let episode = match self.stall {
            Some(episode) if episode.owner == owner && episode.front_hash == front_hash => episode,
            previous => {
                if previous.is_some() {
                    // Predicate still holds but for a different
                    // (peer, front_hash): the front advanced (or rotated
                    // owner) and the episode re-keyed.
                    count_stall_episode_cleared("front_moved");
                }
                metrics::counter!("node.sync.stall_episodes_started").increment(1);
                let episode = StallEpisode {
                    owner,
                    front_hash,
                    since: now,
                    info_logged: false,
                };
                self.stall = Some(episode);
                episode
            }
        };
        // Phase 0 observability: one INFO line per episode, once it survives
        // STALL_EPISODE_LOG_AGE — visible below the WARN fire line so episode
        // dynamics (and the EWMA the threshold tracks, the design falsifier)
        // appear in run logs.
        //
        // The fire threshold is the stored adaptive value, never below the
        // ADV-DRIP-1 decay floor: on a network whose demonstrated front
        // cadence exceeds `stall_timeout_initial`, an episode younger than
        // twice that cadence is the uniform-slow steady state, not a stall.
        let effective_timeout = self.stall_timeout.max(self.stall_decay_floor());
        if !episode.info_logged && now.duration_since(episode.since) >= STALL_EPISODE_LOG_AGE {
            if let Some(stored) = self.stall.as_mut() {
                stored.info_logged = true;
            }
            tracing::info!(
                peer_addr = %episode.owner.addr,
                front_hash = %episode.front_hash,
                front_height = next_apply_height,
                episode_age_ms = u64::try_from(now.duration_since(episode.since).as_millis())
                    .unwrap_or(u64::MAX),
                effective_timeout_ms = u64::try_from(effective_timeout.as_millis())
                    .unwrap_or(u64::MAX),
                front_interval_ewma_ms = ?self.front_interval_ewma_ms,
                "block sync: stall episode running"
            );
        }
        if now.duration_since(episode.since) < effective_timeout {
            return None;
        }
        count_stall_episode_cleared("fired");
        // Fire: blame is settled. Double the threshold for the next episode
        // (sudden bandwidth drops must not cascade into disconnecting every
        // peer at 2s — Core's rationale) and start the re-acquisition
        // cooldown for this peer. Doubling starts from the effective
        // threshold the fire was judged against, so a conviction at the
        // adaptive floor elevates the next episode's bar just like one at
        // the stored value.
        self.stall = None;
        self.stall_timeout = effective_timeout
            .saturating_mul(2)
            .min(self.budget.stall_timeout_max);
        self.mark_peer_unresponsive(owner.addr, now);
        Some(owner)
    }

    /// Closes an open apply-idle interval, recording its duration.
    fn close_apply_idle(&mut self, now: Instant) {
        if let Some(since) = self.apply_idle_since.take() {
            metrics::histogram!("node.sync.apply_idle_seconds")
                .record(now.duration_since(since).as_secs_f64());
        }
    }

    /// Closes an open download-blocked-by-apply interval, recording its
    /// duration.
    fn close_download_blocked_by_apply(&mut self, now: Instant) {
        if let Some(since) = self.download_blocked_by_apply_since.take() {
            metrics::histogram!("node.sync.download_blocked_by_apply_seconds")
                .record(now.duration_since(since).as_secs_f64());
        }
    }

    /// Exposes the pending high-water marks for the metrics gauges.
    pub const fn pending_high_water(&self) -> (usize, usize) {
        (
            self.pending_blocks_high_water,
            self.pending_bytes_high_water,
        )
    }

    /// Lower bound for the adaptive threshold's x0.85 decay (and for the
    /// fire check itself): twice the network's demonstrated front cadence
    /// ([`Self::front_interval_ewma_ms`]), never below
    /// `stall_timeout_initial` and never above `stall_timeout_max`.
    ///
    /// The ADV-DRIP-1 fix. Consequences, pinned by tests:
    /// - Fast network (front cadence well under 1s): the EWMA term stays
    ///   below `stall_timeout_initial`, the floor is the static 2s, and
    ///   conviction speed matches Core.
    /// - Slow network (uniform honest gap g = 3s): the floor lands at ~6s
    ///   (> g), so the decay limit cycle that fired one honest peer per ~5g
    ///   cannot re-cross g — zero false fires — while a true staller
    ///   (silent while others stream) still convicts at ~6s, far inside the
    ///   60s pending-timeout fallback. That zero-false-fires guarantee
    ///   holds only because same-chunk batch arrivals are filtered out of
    ///   the EWMA (sub-[`EWMA_MIN_SAMPLE_MS`] samples share one chunk
    ///   timestamp and would otherwise deflate the floor back to the static
    ///   2s). A cold-start window (no sample yet) convicts at the
    ///   `stall_timeout_initial` floor: an unproven cadence is never an
    ///   exemption, matching Core's `BLOCK_STALLING_TIMEOUT_DEFAULT`
    ///   behavior for a fresh connection.
    ///
    /// The 2x multiplier is deliberately hardcoded (no `SyncBudget` knob):
    /// it is the audit finding's refuted-equilibrium margin — the floor must
    /// clear the cadence itself (1x fires on jitter) and stay well under the
    /// fallback machinery; nothing tunes it per deployment.
    fn stall_decay_floor(&self) -> Duration {
        self.front_interval_ewma_ms
            .map_or(Duration::ZERO, |ewma_ms| {
                Duration::from_millis(ewma_ms.saturating_mul(2))
            })
            .max(self.budget.stall_timeout_initial)
            .min(self.budget.stall_timeout_max)
    }

    /// The stall predicate: the window cannot progress and exactly one peer's
    /// in-flight front block is why. The terms read the pending set, the
    /// stager, and the block tree:
    ///
    /// 1. **Front in flight at the apply frontier**: the minimum-height
    ///    pending entry sits exactly at `next_apply_height`. This is also the
    ///    structural half of the no-blame rule — if anything applicable were
    ///    staged instead, the frontier would be the apply side's to drain and
    ///    the front pending could not be at `next_apply_height`. It equally
    ///    discriminates "frontier block never requested / expired" (front
    ///    above the frontier): no peer owns the gap, so no peer is blamed.
    /// 2. **Delivered successors are waiting**: at least one staged block
    ///    above the front. Without arrivals the download is generally slow or
    ///    just started — download-bound, not window-blocked, no single
    ///    blocker.
    /// 3. **Deep staged backlog**: at least half the staged count window
    ///    (`max_received_blocks / 2`, integer division) is occupied. Staged
    ///    blocks pile up only when the frontier is slow while the rest of the
    ///    window is fast (apply outruns download by orders of magnitude, so
    ///    healthy staged occupancy stays near zero between frontier waits) —
    ///    the term encodes the asymmetric-frontier-blockage signature that
    ///    defines a staller. As a fixed fraction of the window it scales with
    ///    depth by construction, and a single apply cannot drop the staged
    ///    count below half the window, so the tick-ordering flap that zeroed
    ///    episodes during partial progress under the previous term
    ///    (`!has_request_capacity()`, which one freed slot per applied block
    ///    momentarily reopened) cannot clear it. The U5 count/byte clamps are
    ///    read by the request path, not here; the recorded R+P count-wedge
    ///    shapes (staged + pending pinned at the count budget) satisfy this
    ///    term trivially, so wedge conviction is preserved. The chain tail
    ///    (nothing above the window left to request) is deliberately not an
    ///    arm of this term — see [`Self::advance_stall`].
    ///
    /// PRE: `stager` is the coupled staging set and `tree` resolves staged
    ///      hashes to heights.
    /// POST: `Some((owner, front_hash))` exactly when every predicate term
    ///      holds: the lowest pending sits at the frontier, at least one
    ///      staged body resolves above it, and the staged count covers half
    ///      the count window.
    /// INVARIANT: staged identity, count, and heights come from `stager`
    ///      and `tree`; the window holds no staged-body copy.
    fn window_blocked_on(
        &self,
        stager: &BlockStager,
        tree: &BlockTree,
        next_apply_height: u32,
    ) -> Option<(PeerSource, Hash256)> {
        let (front_hash, front) = self
            .pending
            .iter()
            .min_by_key(|(_, pending)| pending.height)?;
        if front.height != next_apply_height {
            return None;
        }
        if stager.received_len() < self.budget.max_received_blocks / 2 {
            return None;
        }
        let has_staged_successor = stager.staged_hashes().any(|hash| {
            tree.height_of_hash(hash)
                .is_some_and(|height| height > front.height)
        });
        if !has_staged_successor {
            return None;
        }
        Some((front.owner, *front_hash))
    }

    /// Current stall observation, if one is running: the blamed peer and when
    /// the episode started. The R10 slow-trickle observability surface — a
    /// peer delivering each front block just under the adaptive threshold is
    /// never disconnected (same exposure as Core) but is visible here and on
    /// the `node.sync.stall_seconds` gauge.
    pub fn stalling_peer(&self) -> Option<(SocketAddr, Instant)> {
        self.stall
            .map(|episode| (episode.owner.addr, episode.since))
    }
    /// Advances the cold-start front timer independently of the strong stall
    /// predicate. Returns a duplicate request only after the same apply-front
    /// hash remains pending to one owner for the initial stall timeout.
    ///
    /// PRE: the apply side is not busy this tick (the no-blame guard in
    ///      [`Self::observe_blocked`] owns the busy case).
    /// POST: `Some((owner, hash))` names the exact owner of the waiting
    ///      front; a seeded cadence EWMA or a spent hedge budget drops the
    ///      timer.
    /// INVARIANT: a running race is never restarted from here.
    fn advance_cold_front(
        &mut self,
        next_apply_height: u32,
        now: Instant,
    ) -> Option<(PeerSource, Hash256)> {
        if matches!(self.cold_front, Some(ColdFrontState::Racing { .. })) {
            return None;
        }
        if self.front_interval_ewma_ms.is_some()
            || self.cold_hedged_fronts.len() >= MAX_COLD_FRONT_HEDGES
        {
            self.cold_front = None;
            return None;
        }
        let Some((&hash, pending)) = self
            .pending
            .iter()
            .find(|(_, pending)| pending.height == next_apply_height)
        else {
            self.cold_front = None;
            return None;
        };
        match self.cold_front {
            Some(ColdFrontState::Waiting {
                owner,
                hash: waiting_hash,
                since,
            }) if owner == pending.owner && waiting_hash == hash => {
                if now.duration_since(since) >= self.budget.stall_timeout_initial {
                    Some((owner, hash))
                } else {
                    None
                }
            }
            _ => {
                self.cold_front = Some(ColdFrontState::Waiting {
                    owner: pending.owner,
                    hash,
                    since: now,
                });
                None
            }
        }
    }

    /// Records a successfully sent cold-front duplicate request.
    pub fn confirm_cold_front_hedge(
        &mut self,
        owner: PeerSource,
        alternate: PeerSource,
        hash: Hash256,
    ) {
        if !matches!(
            self.cold_front,
            Some(ColdFrontState::Waiting {
                owner: waiting_owner,
                hash: waiting_hash,
                ..
            }) if waiting_owner == owner && waiting_hash == hash
        ) {
            return;
        }
        if !self.cold_hedged_fronts.contains(&hash) {
            if self.cold_hedged_fronts.len() >= MAX_COLD_FRONT_HEDGES {
                return;
            }
            self.cold_hedged_fronts.push(hash);
        }
        self.cold_front = Some(ColdFrontState::Racing {
            owner,
            alternate,
            hash,
        });
    }

    /// Preferred deep-window peer after winning a cold-front race.
    pub const fn preferred_peer(&self) -> Option<PeerSource> {
        self.preferred_peer
    }

    /// Number of eligible peers that activates striped fanout.
    pub const fn min_peers_for_fanout(&self) -> usize {
        self.budget.min_peers_for_fanout
    }

    /// Clears a preferred peer that is no longer serviceable.
    pub fn clear_preferred_peer(&mut self) {
        self.preferred_peer = None;
    }
    /// Builds the one-shot common-prefix probe after a deep fallback request.
    pub fn prefix_probe_plan(
        &self,
    ) -> Option<(
        PeerSource,
        SmallVec<[Hash256; PREFIX_PROBE_BLOCK_LIMIT]>,
        u32,
    )> {
        if self.preferred_peer.is_some() || self.prefix_probe.is_some() || self.fanout_active() {
            return None;
        }
        let owner = self
            .pending
            .values()
            .min_by_key(|pending| pending.height)?
            .owner;
        if self.prefix_probe_attempted_owner == Some(owner)
            || self.pending.values().any(|pending| pending.owner != owner)
        {
            return None;
        }
        let limit =
            (PREFIX_PROBE_ESTIMATED_BYTES / self.ewma_block_bytes).min(PREFIX_PROBE_BLOCK_LIMIT);
        if limit < PREFIX_PROBE_WIN_BLOCKS {
            return None;
        }
        let mut ordered: Vec<(u32, Hash256)> = self
            .pending
            .iter()
            .map(|(hash, pending)| (pending.height, *hash))
            .collect();
        ordered.sort_unstable_by_key(|(height, _)| *height);
        let mut hashes = SmallVec::new();
        let mut expected_height = ordered.first()?.0;
        for (height, hash) in ordered {
            if hashes.len() >= limit || height != expected_height {
                break;
            }
            hashes.push(hash);
            expected_height = expected_height.saturating_add(1);
        }
        (hashes.len() >= PREFIX_PROBE_WIN_BLOCKS).then_some((
            owner,
            hashes,
            expected_height.saturating_sub(1),
        ))
    }

    /// Starts the prefix race after at least one alternate accepted the probe.
    pub fn confirm_prefix_probe(
        &mut self,
        owner: PeerSource,
        hashes: SmallVec<[Hash256; PREFIX_PROBE_BLOCK_LIMIT]>,
        alternates: &[PeerSource],
        now: Instant,
    ) {
        if alternates.is_empty() {
            return;
        }
        let valid_plan =
            self.prefix_probe_plan()
                .is_some_and(|(planned_owner, planned_hashes, _)| {
                    planned_owner == owner && planned_hashes == hashes
                });
        if !valid_plan {
            return;
        }
        self.prefix_probe_attempted_owner = Some(owner);
        let mut racers = HashMap::with_capacity(alternates.len().saturating_add(1));
        racers.insert(owner, 0);
        racers.extend(alternates.iter().copied().map(|peer| (peer, 0)));
        self.prefix_probe = Some(PrefixProbe {
            owner,
            hashes,
            racers,
            accepted: 0,
            started_at: now,
        });
    }

    /// Current adaptive stalling threshold (2s doubling to 64s).
    pub const fn stall_timeout(&self) -> Duration {
        self.stall_timeout
    }

    /// Starts the re-acquisition cooldown for an unresponsive peer.
    pub fn mark_peer_unresponsive(&mut self, peer_addr: SocketAddr, now: Instant) {
        let cooldown = self.budget.staller_cooldown;
        self.recent_stallers
            .retain(|_, fired_at| now.duration_since(*fired_at) < cooldown);
        self.recent_stallers.insert(peer_addr, now);
    }

    /// Whether `peer_addr` was disconnected for stalling within the cooldown.
    /// Such a peer is not fan-out eligible and gets no block requests unless
    /// it is the last-resort peer — without this, a staller reconnecting on
    /// the same address immediately re-acquires the window front and restarts
    /// the cycle (the RE-ADV-2 recurrence).
    pub fn peer_in_staller_cooldown(&self, peer_addr: SocketAddr, now: Instant) -> bool {
        self.recent_stallers
            .get(&peer_addr)
            .is_some_and(|fired_at| now.duration_since(*fired_at) < self.budget.staller_cooldown)
    }

    /// Returns `true` if `hash` is currently pending.
    pub fn contains_pending(&self, hash: &Hash256) -> bool {
        self.pending.contains_key(hash)
    }

    /// The exact connection owning the pending request for `hash`.
    pub fn pending_owner(&self, hash: &Hash256) -> Option<PeerSource> {
        self.pending.get(hash).map(|pending| pending.owner)
    }

    /// Returns the start time of the active prefix probe, if any. Test-only.
    pub fn active_prefix_probe_started_at(&self) -> Option<Instant> {
        self.prefix_probe.as_ref().map(|probe| probe.started_at)
    }

    /// Distinct exact connections owning validated in-flight blocks: the
    /// per-owner block-download budget's peer count (Core's
    /// `m_peers_downloading_from`, `net_processing.cpp:153-168`).
    ///
    /// POST: equals the population of `owner_downloading_since`.
    /// INVARIANT: announced or merely-assigned peers never count; only
    ///      ownership of at least one pending block does.
    pub fn active_downloading_peers(&self) -> usize {
        self.owner_downloading_since.len()
    }

    /// Whether `owner` holds one of the per-owner download slots.
    ///
    /// PRE: none.
    /// POST: true exactly while `owner` is in the population that
    ///   `active_downloading_peers` counts.
    /// INVARIANT: the answer is the same fact the fan-out budget reads, so a
    ///   peer counted as downloading is never retired as idle.
    #[must_use]
    pub fn is_downloading(&self, owner: PeerSource) -> bool {
        self.owner_downloading_since.contains_key(&owner)
    }

    /// The per-owner block-download budget for one tick.
    ///
    /// PRE: `active_downloading_peers` counts the owners with validated
    ///      in-flight blocks.
    /// POST: `SyncBudget::pending_timeout_override` when set; else
    ///      `block_spacing * (BLOCK_DOWNLOAD_TIMEOUT_BASE
    ///      + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * other) / 2` with `other`
    ///      the count minus one, saturating at `Duration::MAX`.
    /// INVARIANT: one tick applies this one budget to every owner; the
    ///      override is a test-only escape hatch, never production.
    fn effective_owner_timeout(&self, active_downloading_peers: usize) -> Duration {
        #[cfg(test)]
        if let Some(timeout) = self.budget.pending_timeout_override {
            return timeout;
        }
        let other = u32::try_from(active_downloading_peers.saturating_sub(1)).unwrap_or(u32::MAX);
        let raw_factor = BLOCK_DOWNLOAD_TIMEOUT_BASE
            .saturating_add(BLOCK_DOWNLOAD_TIMEOUT_PER_PEER.saturating_mul(other));
        self.budget.block_spacing.saturating_mul(raw_factor) / 2
    }

    /// Whether `owner`'s download queue has aged past its budget.
    ///
    /// PRE: `active_downloading_peers` is this tick's owner count.
    /// POST: `true` exactly while the owner has a queue start at least the
    ///      budget old; an owner with no entry never expired.
    /// INVARIANT: every expiry, eligibility, and blame decision shares this
    ///      one predicate.
    fn owner_download_expired(
        &self,
        owner: PeerSource,
        active_downloading_peers: usize,
        now: Instant,
    ) -> bool {
        self.owner_downloading_since
            .get(&owner)
            .is_some_and(|since| {
                now.duration_since(*since) >= self.effective_owner_timeout(active_downloading_peers)
            })
    }

    /// Re-derives one owner's queue start after a removal from `pending`.
    ///
    /// PRE: the entry is already out of `pending`; `removed_requested_at`
    ///      is its request time; `now` is the caller's injected clock.
    /// POST: the owner keeps no entry once it owns nothing; the entry moves
    ///      to `now` exactly when the removed entry was strictly older
    ///      than every survivor (the true queue head left); when a
    ///      survivor carries the removed entry's own stamp, the clock
    ///      adopts that stamp without ever regressing; otherwise the
    ///      entry is untouched.
    /// INVARIANT: the local equivalent of Core's `m_downloading_since`
    ///      start-and-oldest-removal reset (`net_processing.cpp:1323-1332,
    ///      1363-1368`); `requested_at` stays the ordering and diagnostic
    ///      record, never the sole source of the queue age. One batched
    ///      `mark_requested` stamps every entry with one `requested_at`,
    ///      so only that batch's front advances the clock: a peer cannot
    ///      postpone its timeout by dripping non-front deliveries.
    fn reset_owner_queue_start(
        &mut self,
        owner: PeerSource,
        removed_requested_at: Instant,
        now: Instant,
    ) {
        let oldest_remaining = self
            .pending
            .values()
            .filter(|pending| pending.owner == owner)
            .map(|pending| pending.requested_at)
            .min();
        match oldest_remaining {
            None => {
                self.owner_downloading_since.remove(&owner);
            }
            // Strictly older than every survivor: the true head left, and
            // the clock restarts at the removal instant.
            Some(oldest) if removed_requested_at < oldest => {
                self.owner_downloading_since.insert(owner, now);
            }
            // The removed entry shares the surviving head's stamp (entries
            // of one batched request share one `requested_at`): the head
            // keeps that stamp, so the clock stays at the batch origin
            // until the front itself is removed. The clock may already sit
            // ahead of the stamp — an earlier true-head removal moved it
            // to the removal instant — and must not regress: Core's
            // `m_downloading_since` only ever moves forward
            // (`max(since, now)`).
            Some(oldest) if removed_requested_at == oldest => {
                self.owner_downloading_since
                    .entry(owner)
                    .and_modify(|since| *since = (*since).max(oldest))
                    .or_insert(oldest);
            }
            // A strictly older survivor is still the head: untouched.
            Some(_) => {}
        }
    }

    /// Retains only ownership facts whose connection `owns` still names.
    ///
    /// PRE: `owns` is false for every connection absent from the peer
    ///   table's live set.
    /// POST: `pending` holds only entries whose owner satisfies `owns`, with
    ///   `pending_bytes`, `next_request_height`, and `owner_downloading_since`
    ///   kept in step; `cold_front` survives only while its waiting owner or
    ///   both racing participants do; `preferred_peer` and
    ///   `prefix_probe_attempted_owner` clear when their owner fails `owns`;
    ///   probe racers failing `owns` leave the race, a probe whose owner
    ///   fails `owns` is cancelled regardless of its racers, and a race left
    ///   with fewer than two racers is cancelled.
    /// INVARIANT: no fact here is compared by address alone.
    ///   `recent_stallers` is the one address-keyed fact and stays exempt;
    ///   `stall` is untouched because the conviction paths own its release.
    pub fn retain_owned_by(&mut self, owns: impl Fn(&PeerSource) -> bool) {
        let cold_front_owned = match self.cold_front {
            Some(ColdFrontState::Waiting { owner, .. }) => owns(&owner),
            Some(ColdFrontState::Racing {
                owner, alternate, ..
            }) => owns(&owner) && owns(&alternate),
            None => true,
        };
        if !cold_front_owned {
            self.cold_front = None;
        }
        if self.preferred_peer.is_some_and(|peer| !owns(&peer)) {
            self.preferred_peer = None;
        }
        if self
            .prefix_probe_attempted_owner
            .is_some_and(|owner| !owns(&owner))
        {
            self.prefix_probe_attempted_owner = None;
        }
        let cancel_probe = self.prefix_probe.as_mut().is_some_and(|probe| {
            let owner_alive = owns(&probe.owner);
            probe.racers.retain(|peer, _| owns(peer));
            !owner_alive || probe.racers.len() < 2
        });
        if cancel_probe {
            self.prefix_probe = None;
        }
        self.retain_peer_assignments(owns);
    }

    fn retain_peer_assignments(&mut self, retain_owner: impl Fn(&PeerSource) -> bool) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| !retain_owner(&observation.owner))
        {
            self.pending_timeout_observation = None;
        }
        let mut retry_height = self.next_request_height;
        self.pending.retain(|_hash, pending| {
            if retain_owner(&pending.owner) {
                return true;
            }
            retry_height = retry_height.min(pending.height);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            false
        });
        // A released owner loses every pending it had: its queue start
        // goes with them, so no phantom age survives to blame a later
        // assignment to the same connection.
        self.owner_downloading_since
            .retain(|owner, _| retain_owner(owner));
        self.next_request_height = retry_height;
    }

    /// Builds the next batch of block requests for `peer_addr`, or `None` if
    /// no blocks are available to request.
    ///
    /// PRE: `stager` is the coupled staging set; expiry has run this tick.
    /// POST: a request whose entries are unowned, on the request branch, and
    ///      inside every pending/staging budget; `next_request_height` covers
    ///      every height the scan offered.
    /// INVARIANT: staged membership, count, and bytes are read from `stager`.
    #[allow(clippy::too_many_arguments)]
    pub fn next_peer_request(
        &mut self,
        stager: &mut BlockStager,
        source: PeerSource,
        allow_expired_retry_from_peer: bool,
        chain_tip: &TipSnapshot,
        request_start_height: u32,
        peer_best_height: u32,
        tree: &BlockTree,
        now: Instant,
    ) -> Option<PeerRequest> {
        self.retarget_request_branch(stager, chain_tip, request_start_height, tree, now);
        if self.staged_bytes_exhausted(stager) {
            return None;
        }
        if !allow_expired_retry_from_peer
            && (self.peer_has_expired_pending(source, now)
                || self.peer_in_staller_cooldown(source.addr, now))
        {
            return None;
        }
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let owned = self.pending_count_for(source);
        let peer_capacity = self.effective_peer_inflight().saturating_sub(owned);
        // Expiry already ran above, so the count headroom needs no expired
        // credit here: `pending` reflects only live in-flight requests.
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len())
            .min(self.staged_count_headroom(stager, 0));
        let mut byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes)
            .min(self.staged_byte_headroom(stager));
        let batch_limit = self
            .budget
            .getdata_batch_limit
            .min(peer_capacity)
            .min(block_capacity);
        if batch_limit == 0 || byte_capacity < self.ewma_block_bytes {
            return None;
        }

        let mut entries =
            self.expired_request_entries(stager, expired, batch_limit, &mut byte_capacity);
        let selected_hashes = SelectedHashes::from_entries(&entries);

        // The current chain frontier outranks the forward-scan hint. A
        // disconnect can move it backwards without changing the header tip.
        // Rewind only an unowned frontier; retain live pending/staged work.
        if request_start_height < self.next_request_height
            && tree
                .node_at_height_from(chain_tip.tip_id, request_start_height)
                .and_then(|id| tree.node(id).ok())
                .is_some_and(|node| {
                    !self.pending.contains_key(&node.hash) && !stager.contains(&node.hash)
                })
        {
            self.next_request_height = request_start_height;
            metrics::counter!("node.sync.frontier_rewinds").increment(1);
        }
        let height = request_start_height.max(self.next_request_height);
        let mut next_request_height = self.next_request_height;
        let request_tip_height = chain_tip.height.min(peer_best_height);
        let remaining_limit = batch_limit
            .saturating_sub(entries.len())
            .min(byte_capacity / self.ewma_block_bytes);
        if height <= request_tip_height && remaining_limit > 0 {
            let scan = RequestScan {
                height,
                request_tip_height,
                remaining_limit,
                next_request_height,
            };
            if entries.is_empty()
                && let Some(request) =
                    self.clean_contiguous_peer_request(stager, source, chain_tip, tree, scan)
            {
                return Some(request);
            }

            next_request_height = self.extend_request_by_reverse_scan(
                stager,
                chain_tip,
                tree,
                scan,
                selected_hashes.as_ref(),
                &mut entries,
            );
        }
        non_empty_request(source, entries, next_request_height)
    }

    fn retarget_request_branch(
        &mut self,
        stager: &mut BlockStager,
        chain_tip: &TipSnapshot,
        request_start_height: u32,
        tree: &BlockTree,
        now: Instant,
    ) {
        let Some((previous_hash, previous_height)) =
            self.request_tip.replace((chain_tip.hash, chain_tip.height))
        else {
            return;
        };
        let extends_request_tip = previous_height <= chain_tip.height
            && tree.lookup(previous_hash)
                == tree.node_at_height_from(chain_tip.tip_id, previous_height);
        if extends_request_tip {
            return;
        }

        let is_on_request_branch = |hash: Hash256, height: u32| {
            height >= request_start_height
                && tree.lookup(hash) == tree.node_at_height_from(chain_tip.tip_id, height)
        };
        let stale_pending: Vec<Hash256> = self
            .pending
            .iter()
            .filter_map(|(hash, pending)| {
                (!is_on_request_branch(*hash, pending.height)).then_some(*hash)
            })
            .collect();
        for hash in stale_pending {
            self.remove_pending(&hash, now);
        }
        // The stager is the single staged-body store: bodies the request
        // branch left behind are released here, so freed capacity is real
        // and a late old-branch delivery cannot re-acquire purged state.
        // A hash the tree cannot resolve is off-branch by definition.
        let stale_staged: Vec<Hash256> = stager
            .staged_hashes()
            .filter(|hash| {
                let on_branch = tree
                    .lookup(*hash)
                    .and_then(|node_id| tree.node(node_id).ok())
                    .map(|node| is_on_request_branch(node.hash, node.height));
                on_branch != Some(true)
            })
            .collect();
        for hash in stale_staged {
            stager.discard(&hash);
        }
        // The stager is the single staged-body store: bodies the request
        // branch left behind are released here, so freed capacity is real
        // and a late old-branch delivery cannot re-acquire purged state.
        // A hash the tree cannot resolve is off-branch by definition.
        let stale_staged: Vec<Hash256> = stager
            .staged_hashes()
            .filter(|hash| {
                let on_branch = tree
                    .lookup(*hash)
                    .and_then(|node_id| tree.node(node_id).ok())
                    .map(|node| is_on_request_branch(node.hash, node.height));
                on_branch != Some(true)
            })
            .collect();
        for hash in stale_staged {
            stager.discard(&hash);
        }

        self.next_request_height = request_start_height;
        self.stall = None;
        self.cold_front = None;
        self.cold_hedged_fronts.clear();
        self.prefix_probe = None;
        self.prefix_probe_attempted_owner = None;
        self.pending_timeout_observation = None;
    }

    fn extend_request_by_reverse_scan(
        &self,
        stager: &BlockStager,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        scan: RequestScan,
        selected_hashes: Option<&SelectedHashes>,
        entries: &mut Vec<PeerRequestEntry>,
    ) -> u32 {
        if scan.remaining_limit == 0 {
            return scan.next_request_height;
        }
        let mut next_request_height = scan.next_request_height;
        let skipped_hashes = self
            .pending
            .len()
            .saturating_add(stager.received_len())
            .saturating_add(selected_hashes.map_or(0, SelectedHashes::len));
        // Each skipped hash can displace at most one eligible height from the prefix.
        let scan_limit = scan.remaining_limit.saturating_add(skipped_hashes);
        let scan_span = u32::try_from(scan_limit.saturating_sub(1)).unwrap_or(u32::MAX);
        let request_end_height = scan
            .height
            .saturating_add(scan_span)
            .min(scan.request_tip_height);
        let Some(mut cursor) = tree.node_at_height_from(chain_tip.tip_id, request_end_height)
        else {
            return scan.next_request_height;
        };
        let mut candidates = Vec::with_capacity(scan_limit);
        while let Ok(node) = tree.node(cursor) {
            if node.height < scan.height {
                break;
            }
            if !self.pending.contains_key(&node.hash)
                && !stager.contains(&node.hash)
                && selected_hashes.is_none_or(|hashes| !hashes.contains(&node.hash))
            {
                candidates.push(PeerRequestEntry {
                    hash: node.hash,
                    height: node.height,
                });
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        let scanned_all_eligible = candidates.len() < scan.remaining_limit;
        let first_selected = candidates.len().saturating_sub(scan.remaining_limit);
        for entry in candidates[first_selected..].iter().rev().copied() {
            next_request_height = next_request_height.max(entry.height.saturating_add(1));
            entries.push(entry);
        }
        if scanned_all_eligible {
            next_request_height =
                next_request_height.max(scan.request_tip_height.saturating_add(1));
        }
        next_request_height
    }

    fn expired_request_entries(
        &self,
        stager: &BlockStager,
        expired: Vec<PeerRequestEntry>,
        batch_limit: usize,
        byte_capacity: &mut usize,
    ) -> Vec<PeerRequestEntry> {
        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || *byte_capacity < self.ewma_block_bytes {
                break;
            }
            if stager.contains(&entry.hash) || self.pending.contains_key(&entry.hash) {
                continue;
            }
            *byte_capacity = byte_capacity.saturating_sub(self.ewma_block_bytes);
            entries.push(entry);
        }
        entries
    }

    fn clean_contiguous_peer_request(
        &self,
        stager: &BlockStager,
        source: PeerSource,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        scan: RequestScan,
    ) -> Option<PeerRequest> {
        if !self.pending.is_empty() || stager.received_len() > 0 {
            return None;
        }
        let span = u32::try_from(scan.remaining_limit.saturating_sub(1)).unwrap_or(u32::MAX);
        let request_end_height = scan
            .height
            .saturating_add(span)
            .min(scan.request_tip_height);
        let entries =
            contiguous_request_entries(tree, chain_tip.tip_id, scan.height, request_end_height)?;
        let next_request_height = scan
            .next_request_height
            .max(request_end_height.saturating_add(1));
        non_empty_request(source, entries, next_request_height)
    }

    fn record_prefix_probe_delivery(
        &mut self,
        hash: Hash256,
        delivery_peer: Option<PeerSource>,
        now: Instant,
    ) {
        let Some(mut probe) = self.prefix_probe.take() else {
            return;
        };
        let Some(index) = probe.hashes.iter().position(|candidate| *candidate == hash) else {
            self.prefix_probe = Some(probe);
            return;
        };
        let Ok(shift) = u32::try_from(index) else {
            self.prefix_probe = Some(probe);
            return;
        };
        let bit = 1_u8 << shift;
        probe.accepted |= bit;
        if let Some(progress) = delivery_peer.and_then(|peer| probe.racers.get_mut(&peer)) {
            *progress |= bit;
        }
        let win_mask = PREFIX_PROBE_WIN_MASK;
        let winner = probe
            .racers
            .iter()
            .find_map(|(peer, progress)| ((*progress & win_mask) == win_mask).then_some(*peer));
        let Some(winner) = winner else {
            if probe.accepted & win_mask != win_mask {
                self.prefix_probe = Some(probe);
            }
            return;
        };
        let owner = probe.owner;
        self.cold_front = None;
        self.pending_timeout_observation = None;
        self.retain_peer_assignments(|peer| *peer == winner || !probe.racers.contains_key(peer));
        if winner != owner {
            self.mark_peer_unresponsive(owner.addr, now);
        }
        self.preferred_peer = Some(winner);
        tracing::info!(
            owner = %owner.addr,
            winner = %winner.addr,
            winner_is_owner = winner == owner,
            blocks = probe.hashes.len(),
            elapsed_ms = u64::try_from(now.duration_since(probe.started_at).as_millis()).unwrap_or(u64::MAX),
            "block sync: prefix probe elected winner"
        );
        metrics::counter!("node.sync.prefix_probe_wins").increment(1);
    }

    fn resolve_cold_front_delivery(
        &mut self,
        hash: Hash256,
        delivery_peer: Option<PeerSource>,
        now: Instant,
    ) {
        let Some(state) = self.cold_front else {
            return;
        };
        match state {
            ColdFrontState::Waiting {
                hash: waiting_hash, ..
            } if waiting_hash == hash => {
                self.cold_front = None;
            }
            ColdFrontState::Racing {
                owner,
                alternate,
                hash: racing_hash,
            } if racing_hash == hash => {
                self.cold_front = None;
                if delivery_peer != Some(alternate) {
                    return;
                }
                self.prefix_probe = None;
                self.retain_peer_assignments(|peer| *peer != owner);
                self.mark_peer_unresponsive(owner.addr, now);
                self.preferred_peer = Some(alternate);
                metrics::counter!("node.sync.cold_front_wins").increment(1);
            }
            _ => {}
        }
    }

    /// Records that `request` has been sent to `owner`, moving entries to
    /// pending under that exact connection's ownership.
    ///
    /// PRE: `stager` is the coupled staging set; no entry of `request` is
    ///      pending or staged.
    /// POST: every entry is pending under `owner`; the return value states
    ///      whether the window still has request capacity.
    /// INVARIANT: staged membership is read from `stager`.
    pub fn mark_requested(
        &mut self,
        stager: &BlockStager,
        request: &PeerRequest,
        owner: PeerSource,
        now: Instant,
    ) -> bool {
        if self.pending.is_empty() && !request.entries.is_empty() {
            self.prefix_probe_attempted_owner = None;
        }
        let estimated_bytes = self.ewma_block_bytes;
        for entry in &request.entries {
            debug_assert!(!self.pending.contains_key(&entry.hash));
            debug_assert!(!stager.contains(&entry.hash));
            let previous = self.pending.insert(
                entry.hash,
                PendingBlock {
                    owner,
                    requested_at: now,
                    height: entry.height,
                    estimated_bytes,
                },
            );
            debug_assert!(previous.is_none());
            self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);
        }
        self.pending_blocks_high_water = self.pending_blocks_high_water.max(self.pending.len());
        self.pending_bytes_high_water = self.pending_bytes_high_water.max(self.pending_bytes);
        if !request.entries.is_empty() {
            self.owner_downloading_since.entry(owner).or_insert(now);
        }
        self.next_request_height = self.next_request_height.max(request.next_request_height);
        self.has_request_capacity(stager)
    }

    /// Records a delivery: pending release, source credit, EWMA byte
    /// estimate. Staging itself is the [`BlockStager`]'s job.
    ///
    /// PRE: `hash` was staged by the caller, or was never requested.
    /// POST: returns the height the pending carried at removal; `None` means
    ///   the delivery was not pending. No staged state is written.
    /// INVARIANT: the window holds no staged-body bytes or counts.
    ///
    /// The source-attributed credit runs through [`Self::credit_delivery_from`];
    /// callers proving the source's connection is still current may also call
    /// it directly after an unattributed `mark_received_from(hash, bytes, None, _)`.
    pub fn mark_received_from(
        &mut self,
        hash: Hash256,
        bytes: usize,
        source_peer: Option<PeerSource>,
        now: Instant,
    ) -> Option<u32> {
        let pending = self.remove_pending(&hash, now);
        let pending_height = pending.map(|pending| pending.height);
        if let Some(source) = source_peer {
            self.credit_delivery_from(hash, source, pending_height, now);
        }
        self.ewma_block_bytes = self
            .ewma_block_bytes
            .saturating_mul(7)
            .saturating_add(bytes)
            / 8;
        self.ewma_block_bytes = self.ewma_block_bytes.max(80);
        pending_height
    }

    /// Releases whatever the window holds for `hash` and makes it
    /// requestable again.
    ///
    /// PRE: `height`, when known, is the tree height of `hash`.
    /// POST: a pending for `hash` is released; the request cursor is lowered
    ///   to the lower of `height` and the released pending's height, when
    ///   either is known; the owner's queue start follows the removal rules
    ///   of [`Self::reset_owner_queue_start`].
    /// INVARIANT: every rewind target is a tree height (the caller's, or the
    ///   one the pending recorded at request time); a body of unknown height
    ///   with no pending never moves the cursor, so the height-0 rewind to
    ///   genesis is unrepresentable.
    pub fn requeue_for_retry(&mut self, hash: &Hash256, height: Option<u32>, now: Instant) {
        let pending_height = self.remove_pending(hash, now).map(|pending| pending.height);
        let target = match (height, pending_height) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (known, None) | (None, known) => known,
        };
        if let Some(target) = target {
            self.next_request_height = self.next_request_height.min(target);
        }
    }

    /// The request cursor: the lowest height not yet scanned or offered.
    #[cfg(test)]
    pub(crate) fn request_cursor(&self) -> u32 {
        self.next_request_height
    }

    /// The owner's live queue start, for in-crate tests that pin queue-age
    /// bookkeeping across sync seams.
    #[cfg(test)]
    pub(crate) fn owner_queue_start_for_test(&self, owner: PeerSource) -> Option<Instant> {
        self.owner_downloading_since.get(&owner).copied()
    }

    /// The source-attributed share of a staged delivery: pending-timeout,
    /// cold-front, and prefix-probe resolution plus stall-episode progress,
    /// all under the delivering connection's exact identity. `pending_height`
    /// is the height the pending carried at removal — `None` for an
    /// unsolicited delivery, which carries no progress credit.
    pub fn credit_delivery_from(
        &mut self,
        hash: Hash256,
        source: PeerSource,
        pending_height: Option<u32>,
        now: Instant,
    ) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| observation.hash == hash && observation.owner == source)
        {
            self.pending_timeout_observation = None;
        }
        self.resolve_cold_front_delivery(hash, Some(source), now);
        self.record_prefix_probe_delivery(hash, Some(source), now);
        if let Some(height) = pending_height {
            self.record_delivery_progress(source, hash, height, now);
        }
    }

    /// Credits a duplicate after the first copy was already staged.
    ///
    /// The first copy owns all byte, EWMA, cold-front and probe accounting.
    pub fn credit_duplicate_delivery(&mut self, hash: Hash256, source: PeerSource) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| observation.hash == hash && observation.owner == source)
        {
            self.pending_timeout_observation = None;
        }
    }

    /// Delivery progress for the stall state machine, charged per peer
    /// (Core's `RemoveBlockRequest`: "this peer delivered, so it's not
    /// stalling"). Called after `hash` was removed from `pending`.
    ///
    /// Any requested block arriving from the episode *connection* clears the
    /// running episode, so blame accumulates only against a connection that
    /// delivers *nothing* while owning the front and others stream past it.
    /// A same-address replacement's deliveries never clear its predecessor's
    /// clock. In the
    /// saturated fan-out steady state (the staged backlog sits at the count
    /// budget, so the staged-fraction arming term holds almost always),
    /// charging only front arrivals would serially false-blame
    /// every slow-but-streaming peer — the self-eclipse cascade. Deliveries
    /// from *other* peers do not clear it: they are the discriminator that
    /// convicts a true staller.
    ///
    /// A window-front arrival additionally samples the inter-front-advance
    /// interval into [`Self::front_interval_ewma_ms`] (unless the sample is
    /// a same-chunk batch artifact under [`EWMA_MIN_SAMPLE_MS`]) and decays
    /// the adaptive threshold by x0.85 toward [`Self::stall_decay_floor`]
    /// (Core's PR #25880 shape with the ADV-DRIP-1 adaptive floor) instead
    /// of snapping it to the floor: after a real fire the elevated threshold
    /// must survive the peer rotation, so the next front owner is judged
    /// against the doubled value while it gradually relaxes with front
    /// progress.
    fn record_delivery_progress(
        &mut self,
        source: PeerSource,
        hash: Hash256,
        height: u32,
        now: Instant,
    ) {
        if self
            .stall
            .is_some_and(|episode| episode.owner == source || episode.front_hash == hash)
        {
            self.stall = None;
            count_stall_episode_cleared("peer_delivery");
        }
        let was_front = self.pending.values().all(|pending| pending.height > height);
        if was_front {
            if let Some(previous) = self.last_front_advance {
                // Millisecond integer math throughout: ewma += (sample -
                // ewma) / 4 (alpha = 1/4). `Instant::duration_since`
                // saturates to zero for an earlier `now`, so out-of-order
                // timestamps fall under the batch filter below instead of
                // corrupting the EWMA.
                let sample_ms =
                    u64::try_from(now.duration_since(previous).as_millis()).unwrap_or(u64::MAX);
                // Batch artifacts are not cadence: an in-order front run
                // processed in one chunk shares the chunk's single timestamp
                // (see `EWMA_MIN_SAMPLE_MS`), so sub-threshold samples are
                // skipped entirely — never averaged in, never seeding. The
                // anchor below still moves to `now` (all batched advances
                // share it), so the next genuine sample correctly measures
                // from the batch.
                if sample_ms >= EWMA_MIN_SAMPLE_MS {
                    self.front_interval_ewma_ms = Some(match self.front_interval_ewma_ms {
                        None => sample_ms,
                        Some(ewma_ms) if sample_ms >= ewma_ms => {
                            ewma_ms.saturating_add((sample_ms - ewma_ms) / 4)
                        }
                        Some(ewma_ms) => ewma_ms - (ewma_ms - sample_ms) / 4,
                    });
                }
            }
            self.last_front_advance = Some(now);
            self.stall_timeout =
                (self.stall_timeout.saturating_mul(85) / 100).max(self.stall_decay_floor());
        }
    }

    /// Current inter-front-advance EWMA in milliseconds, if seeded.
    pub const fn front_interval_ewma_ms(&self) -> Option<u64> {
        self.front_interval_ewma_ms
    }

    /// Test-only cold-start disarm: installs a front-cadence estimate as if
    /// the network had demonstrated `ewma_ms` with its last front advance at
    /// `now`. Sync-layer tests whose fixtures never advance the window front
    /// (the recorded wedge constructions) use this instead of replaying two
    /// real front deliveries; the real sampling path is pinned by the window
    /// tests.
    pub const fn seed_front_cadence_for_test(&mut self, ewma_ms: u64, now: Instant) {
        self.front_interval_ewma_ms = Some(ewma_ms);
        self.last_front_advance = Some(now);
    }

    /// Rejects a malformed block delivery, source-aware (issue #1070).
    ///
    /// When the delivering peer owns the pending request for `hash`, the
    /// pending is released so the block becomes re-requestable from a
    /// different peer. When a different peer delivers the malformed body
    /// unsolicited, the body is discarded and any existing pending request is
    /// preserved — the original owner may still supply the correct body.
    ///
    /// The malformed body was never staged, so the stager is not touched.
    pub fn reject_delivery(
        &mut self,
        hash: Hash256,
        source_peer: Option<PeerSource>,
        now: Instant,
    ) -> RejectDelivery {
        // A malformed response is still proof that this peer answered. Do not
        // let a first-tick timeout observation disconnect it on the next tick.
        if self.pending_timeout_observation.is_some_and(|observation| {
            observation.hash == hash && Some(observation.owner) == source_peer
        }) {
            self.pending_timeout_observation = None;
        }

        // A rejected race participant cannot remain eligible to complete the
        // cold-front race. Clear the episode without electing a winner or
        // blaming either peer; a later observation may arm another hedge.
        if self.cold_front.is_some_and(|state| match state {
            ColdFrontState::Waiting {
                owner,
                hash: waiting_hash,
                ..
            } => waiting_hash == hash && Some(owner) == source_peer,
            ColdFrontState::Racing {
                owner,
                alternate,
                hash: racing_hash,
            } => {
                racing_hash == hash
                    && source_peer.is_some_and(|peer| peer == owner || peer == alternate)
            }
        }) {
            self.cold_front = None;
        }

        let is_owner = self
            .pending
            .get(&hash)
            .is_some_and(|pending| Some(pending.owner) == source_peer);
        if is_owner {
            if let Some(pending) = self.remove_pending(&hash, now) {
                self.next_request_height = self.next_request_height.min(pending.height);
            }
            RejectDelivery::ReleasedPending
        } else {
            RejectDelivery::DiscardedUnsolicited
        }
    }

    fn expire_pending(&mut self, now: Instant) -> Vec<PeerRequestEntry> {
        let timeout = self.effective_owner_timeout(self.active_downloading_peers());
        let expired_owners: HashSet<PeerSource> = self
            .owner_downloading_since
            .iter()
            .filter(|(_, since)| now.duration_since(**since) >= timeout)
            .map(|(owner, _)| *owner)
            .collect();
        if expired_owners.is_empty() {
            return Vec::new();
        }
        let mut entries = Vec::new();
        let mut removed: Vec<(PeerSource, Instant)> = Vec::new();
        let armed_observation = &mut self.pending_timeout_observation;
        {
            let pending_bytes = &mut self.pending_bytes;
            let next_request_height = &mut self.next_request_height;
            for (hash, pending) in self
                .pending
                .extract_if(|_hash, pending| expired_owners.contains(&pending.owner))
            {
                if let Some(observation) = armed_observation
                    && observation.hash == hash
                    && observation.owner == pending.owner
                {
                    observation.expired_release = true;
                }
                *pending_bytes = pending_bytes.saturating_sub(pending.estimated_bytes);
                *next_request_height = (*next_request_height).min(pending.height);
                entries.push(PeerRequestEntry {
                    hash,
                    height: pending.height,
                });
                removed.push((pending.owner, pending.requested_at));
            }
        }
        for (owner, requested_at) in removed {
            self.reset_owner_queue_start(owner, requested_at, now);
        }
        entries
    }

    /// Records a body fetch the window does not own — a compact
    /// `getblocktxn` or fallback `getdata` already issued on `owner` —
    /// as pending so `next_peer_request` does not schedule a duplicate
    /// request for a freshly admitted tip. Delivery resolves it like any
    /// window request; expiry or peer disconnect hands it back to normal
    /// scheduling, so a silently dropped compact fetch still re-requests.
    /// The window owns no frontier for the entry: `next_request_height`
    /// must not advance past heights it never scanned.
    ///
    /// The mark still consumes window budgets, so the same gates a real
    /// request would face apply: no mark when the window has no request
    /// capacity (its `pending` would overflow), when `owner` already holds
    /// its per-peer inflight share, or when `height` sits below the
    /// request frontier — a below-frontier entry could never be scheduled
    /// anyway, and its expiry would drag `next_request_height` back down
    /// into a re-request sweep of heights already applied.
    /// `false` when capacity refused the mark: the caller keeps the deferred
    /// ownership record so a fast delivery still counts as requested.
    pub fn mark_owned_fetch(
        &mut self,
        stager: &mut BlockStager,
        owner: PeerSource,
        hash: Hash256,
        height: u32,
        now: Instant,
    ) -> bool {
        if self.pending.contains_key(&hash) {
            return true;
        }
        if stager.contains(&hash) {
            // The fetch's body is already staged: the owned fetch is its
            // request evidence, so the body counts as requested and owes
            // no unrequested-admission gate.
            stager.clear_gate_pending(&hash);
            return true;
        }
        if height < self.next_request_height
            || !self.has_request_capacity(stager)
            || self.pending_count_for(owner) >= self.effective_peer_inflight()
        {
            return false;
        }
        let request = PeerRequest {
            owner,
            entries: vec![PeerRequestEntry { hash, height }],
            next_request_height: 0,
        };
        // `mark_requested` re-enables `prefix_probe_attempted_owner` when
        // pending was empty — that re-arm is for a real post-drain request.
        // An externally owned fetch is not one: keep the marker so a
        // proven-stall owner stays ineligible for the next prefix probe.
        let attempted_owner = self.prefix_probe_attempted_owner;
        self.mark_requested(stager, &request, owner, now);
        self.prefix_probe_attempted_owner = attempted_owner;
        true
    }

    /// Releases `hash`'s pending entry without rewinding the request cursor:
    /// drop-only release for hashes that must never be re-requested
    /// (invalidated subtrees).
    pub(crate) fn release_pending(&mut self, hash: &Hash256, now: Instant) {
        let _ = self.remove_pending(hash, now);
    }

    fn remove_pending(&mut self, hash: &Hash256, now: Instant) -> Option<PendingBlock> {
        let pending = self.pending.remove(hash)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
        self.reset_owner_queue_start(pending.owner, pending.requested_at, now);
        Some(pending)
    }

    /// Live requests owned by `source`. Derived from `pending`; the window
    /// keeps no shadow count.
    ///
    /// PRE: expiry has run this tick, so `pending` holds only live in-flight
    ///   requests.
    /// POST: returns the number of `pending` values with `owner == source`.
    /// INVARIANT: source-exact, so a same-address predecessor's share never
    ///   reduces a replacement's headroom.
    fn pending_count_for(&self, source: PeerSource) -> usize {
        self.pending
            .values()
            .filter(|pending| pending.owner == source)
            .count()
    }

    /// Distinct owner addresses holding live requests: how many peers the
    /// tick's request scan must reach in addition to fresh capacity.
    ///
    /// PRE: expiry has run this tick.
    /// POST: returns the number of distinct `pending.owner.addr` values.
    /// INVARIANT: each address counts once, however many requests it owns.
    fn owner_address_count(&self) -> usize {
        let mut owners: SmallVec<[SocketAddr; 16]> = SmallVec::new();
        for pending in self.pending.values() {
            if !owners.contains(&pending.owner.addr) {
                owners.push(pending.owner.addr);
            }
        }
        owners.len()
    }
}

/// Outcome of rejecting a malformed block delivery (issue #1070).
///
/// The window decides whether the delivering peer owned the pending request.
/// Only the owner's malformed delivery releases the pending slot so the block
/// becomes re-requestable; an unsolicited malformed body from a different peer
/// is discarded without disturbing the in-flight request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectDelivery {
    /// The pending owner delivered the malformed body. Its pending request was
    /// released so the block can be re-requested from a different peer. Any
    /// matching timeout observation and cold-front race participation are
    /// cleared for a peer that demonstrably responded.
    ReleasedPending,
    /// A peer other than the pending owner delivered the malformed body
    /// (or no pending existed). The body is discarded; any existing pending
    /// request is preserved.
    DiscardedUnsolicited,
}

fn non_empty_request(
    owner: PeerSource,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
) -> Option<PeerRequest> {
    (!entries.is_empty()).then_some(PeerRequest {
        owner,
        entries,
        next_request_height,
    })
}

fn contiguous_request_entries(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    start_height: u32,
    end_height: u32,
) -> Option<Vec<PeerRequestEntry>> {
    let mut cursor = tree.node_at_height_from(tip_id, end_height)?;
    let capacity =
        usize::try_from(end_height.saturating_sub(start_height).saturating_add(1)).ok()?;
    let mut entries = Vec::with_capacity(capacity);
    while let Ok(node) = tree.node(cursor) {
        if node.height < start_height {
            break;
        }
        entries.push(PeerRequestEntry {
            hash: node.hash,
            height: node.height,
        });
        if node.height == start_height {
            entries.reverse();
            return Some(entries);
        }
        cursor = node.parent?;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitcoin_rs_primitives::Hash256;

    use bitcoin_rs_chain::Network;
    use bitcoin_rs_primitives::{
        Amount, Block, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
        consensus_bytes,
    };

    use super::{
        BlameReason, BlockStager, BlockedContext, BlockedDecision, ColdFrontState, DownloadWindow,
        FAST_BLOCKS_IN_TRANSIT_PER_PEER, FAST_MIN_PEERS_FOR_FANOUT, FAST_OUTBOUND_PEER_TARGET,
        PENDING_BUDGET, SyncBudget, count_stall_episode_cleared, fast_sync_budget,
    };
    use crate::connection::PeerSource;

    /// A stager whose budget mirrors `window`'s, so window-side backpressure
    /// reads see the same bytes/counts a real sync pair would.
    fn test_stager(window: &DownloadWindow) -> BlockStager {
        BlockStager::new(window.budget)
    }

    /// A 256-header regtest chain: the height-`n` header hashes to `hash(n)`.
    static TEST_CHAIN: std::sync::LazyLock<Vec<bitcoin_rs_primitives::Header>> =
        std::sync::LazyLock::new(|| {
            let genesis = Network::Regtest.genesis_block().header;
            std::iter::successors(Some(genesis), |prev| {
                let height = prev.time.saturating_sub(genesis.time).saturating_add(1);
                let mut merkle = [0_u8; 32];
                merkle[..4].copy_from_slice(&height.to_le_bytes());
                Some(bitcoin_rs_primitives::Header {
                    prev_blockhash: prev.compute_hash(),
                    merkle_root: Hash256::from_le_bytes(&merkle),
                    time: prev.time.saturating_add(1),
                    ..*prev
                })
            })
            .take(256)
            .collect()
        });

    /// The [`TEST_CHAIN`] tree: every test hash resolves to the height its
    /// byte names.
    fn test_tree() -> bitcoin_rs_chain::BlockTree {
        let mut tree = bitcoin_rs_chain::BlockTree::new();
        let mut parent = None;
        for header in TEST_CHAIN.iter() {
            let inserted =
                tree.insert_node(parent, *header, bitcoin_rs_chain::NodeStatus::HeaderValid);
            parent = Some(inserted.unwrap_or_else(|error| panic!("test chain header: {error}")));
        }
        tree
    }

    /// The serialized size of the smallest padded test block: an empty
    /// coinbase script.
    const SMALL_BODY: usize = 141;

    /// A one-coinbase block whose serialized size is exactly `total_bytes`.
    /// The script-length prefix grows by 2 bytes at 253 and again at 65536,
    /// so sizes 253, 254, 65538, and 65539 above the empty-script size do
    /// not exist.
    fn padded_regtest_block(total_bytes: usize) -> Block {
        let wanted = total_bytes.saturating_sub(padded_regtest_block_with_script(0).total_size());
        let script_len = match wanted {
            0..=252 => wanted,
            255..=65_537 => wanted - 2,
            _ => wanted.saturating_sub(4),
        };
        let block = padded_regtest_block_with_script(script_len);
        assert_eq!(block.total_size(), total_bytes);
        block
    }

    fn padded_regtest_block_with_script(script_len: usize) -> Block {
        Block {
            header: Network::Regtest.genesis_block().header,
            txs: vec![Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: vec![0_u8; script_len].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::ZERO,
            }],
        }
    }

    /// Stages one `total_bytes`-long body into `stager`.
    fn stage_body(
        stager: &mut BlockStager,
        hash: Hash256,
        total_bytes: usize,
        source: Option<PeerSource>,
        now: Instant,
    ) {
        let block = padded_regtest_block(total_bytes);
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        match stager.insert(hash, None, block, serialized, source, now) {
            crate::StagedBlock::Memory { .. } => {}
            other => panic!("stage_body refused: {other:?}"),
        }
    }

    /// Test replacement for the deleted `mark_received` shorthand: stages the
    /// body (the wire path's only staged store) and records the delivery,
    /// attributed to the pending owner when one exists. Returns whether the
    /// hash was not pending, as the deleted shorthand did.
    fn receive_staged(
        window: &mut DownloadWindow,
        stager: &mut BlockStager,
        hash: Hash256,
        total_bytes: usize,
        now: Instant,
    ) -> bool {
        let source = window.pending_owner(&hash);
        stage_body(stager, hash, total_bytes, source, now);
        window
            .mark_received_from(hash, total_bytes, source, now)
            .is_none()
    }

    /// Retires one staged body the way an applied commit does. The window
    /// holds nothing for an applied body: its pending was released at
    /// delivery, so only the stager entry is removed.
    fn apply_staged(stager: &mut BlockStager, hash: &Hash256) {
        stager.retire_applied(hash);
    }

    fn test_source(addr: std::net::SocketAddr) -> PeerSource {
        PeerSource::for_test(addr)
    }

    // The per-rule wrappers drive the private advances directly, including
    // the no-blame guard's clears, so each test observes exactly one state
    // machine. `BlockedDecision` precedence is pinned separately through
    // the unified `observe_blocked` entry.
    fn stall_owner(
        window: &mut DownloadWindow,
        stager: &BlockStager,
        tree: &bitcoin_rs_chain::BlockTree,
        next_apply_height: u32,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<std::net::SocketAddr> {
        if apply_side_busy {
            if window.stall.take().is_some() {
                count_stall_episode_cleared("apply_busy");
            }
            return None;
        }
        window
            .advance_stall(next_apply_height, stager, tree, now)
            .map(|owner| owner.addr)
    }

    fn timeout_owner(
        window: &mut DownloadWindow,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<std::net::SocketAddr> {
        if apply_side_busy {
            window.pending_timeout_observation = None;
            return None;
        }
        let active = window.active_downloading_peers();
        window
            .advance_pending_timeout(now, active)
            .map(|owner| owner.addr)
    }

    fn cold_front_owner(
        window: &mut DownloadWindow,
        next_apply_height: u32,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<(std::net::SocketAddr, Hash256)> {
        if apply_side_busy {
            if !matches!(window.cold_front, Some(ColdFrontState::Racing { .. })) {
                window.cold_front = None;
            }
            return None;
        }
        window
            .advance_cold_front(next_apply_height, now)
            .map(|(owner, hash)| (owner.addr, hash))
    }

    fn apply_side_bound(
        window: &mut DownloadWindow,
        next_apply_height: u32,
        frontier_hash: Option<Hash256>,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<Duration> {
        window
            .advance_apply_side_stuck(next_apply_height, frontier_hash, apply_side_busy, now)
            .map(|(hash, suppressed_for)| {
                debug_assert_eq!(Some(hash), frontier_hash);
                suppressed_for
            })
    }

    #[test]
    fn request_peer_scan_limit_accounts_for_pending_bytes_and_inflight_peers() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 8,
            max_pending_bytes: 4 * 256 * 1024,
            max_peer_inflight: 2,
            getdata_batch_limit: 4,
            ..test_budget()
        });
        let stager = test_stager(&window);
        let now = Instant::now();
        let owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        insert_pending(&mut window, owner, hash(1), 1, now);
        insert_pending(&mut window, owner, hash(2), 2, now);
        window.pending_bytes = 256 * 1024;

        assert_eq!(window.request_peer_scan_limit(&stager, now), 3);
    }

    #[test]
    fn request_peer_scan_limit_counts_expired_pending_capacity() {
        let mut window = DownloadWindow::new(
            SyncBudget {
                max_pending_blocks: 2,
                max_pending_bytes: 2 * 256 * 1024,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                ..test_budget()
            }
            .with_pending_timeout_override(Duration::ZERO),
        );
        let stager = test_stager(&window);
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let owner = test_source(peer_addr);
        for (byte, height) in [(1, 1_u32), (2, 2)] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    owner,
                    requested_at: now,
                    height,
                    estimated_bytes: 256 * 1024,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(256 * 1024);
        }
        window.owner_downloading_since.insert(owner, now);

        assert_eq!(window.request_peer_scan_limit(&stager, now), 2);
    }

    #[test]
    fn pending_timeout_waits_for_second_delivery_drain() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let mut stager = test_stager(&window);
        let requested_at = Instant::now();
        let observed_at = requested_at + Duration::from_secs(10);
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let block_hash = hash(0x90);
        let owner = test_source(peer_addr);
        window.pending.insert(
            block_hash,
            super::PendingBlock {
                owner,
                requested_at,
                height: 1,
                estimated_bytes: 80,
            },
        );
        window.owner_downloading_since.insert(owner, requested_at);
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        receive_staged(
            &mut window,
            &mut stager,
            block_hash,
            SMALL_BODY,
            observed_at,
        );
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(!window.peer_in_staller_cooldown(peer_addr, observed_at));
    }

    #[test]
    fn pending_timeout_apply_busy_clears_suspicion_without_blame() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let requested_at = Instant::now();
        let observed_at = requested_at + Duration::from_secs(10);
        let peer_addr = staller_addr();
        insert_pending(
            &mut window,
            test_source(peer_addr),
            hash(0x92),
            1,
            requested_at,
        );

        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_some());
        assert_eq!(timeout_owner(&mut window, true, observed_at), None);
        assert!(window.pending_timeout_observation.is_none());
        assert!(!window.peer_in_staller_cooldown(peer_addr, observed_at));
    }

    /// A retry delivery releases the observed hash without the owner: the
    /// second tick must re-verify the suspicion against the live window
    /// and blame nobody, because a conviction here would outlive the
    /// queue age it measured.
    #[test]
    fn retry_delivery_resolves_original_peer_timeout_without_blame() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let requested_at = Instant::now();
        let observed_at = requested_at + Duration::from_secs(10);
        let original_peer = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let retry_peer = std::net::SocketAddr::from(([127, 0, 0, 2], 8333));
        let block_hash = hash(0x91);
        let original_owner = test_source(original_peer);
        window.pending.insert(
            block_hash,
            super::PendingBlock {
                owner: original_owner,
                requested_at,
                height: 1,
                estimated_bytes: 80,
            },
        );
        window
            .owner_downloading_since
            .insert(original_owner, requested_at);

        // First idle tick arms the suspicion on the original owner.
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_some());

        // A retry from another peer releases the observed hash; the second
        // tick clears the suspicion without convicting anyone.
        window.mark_received_from(block_hash, 80, Some(test_source(retry_peer)), observed_at);
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_none());
        assert!(!window.peer_in_staller_cooldown(original_peer, observed_at));
        assert!(!window.peer_in_staller_cooldown(retry_peer, observed_at));
    }

    /// One batched `mark_requested` stamps every entry with one
    /// `requested_at`: removing a non-front entry ties with the surviving
    /// front's stamp, so the queue start must stay at the batch origin.
    /// Re-stamping from the removal instant on each tie would let a peer
    /// postpone its timeout indefinitely by dripping non-front deliveries
    /// of one batch while the front stays outstanding.
    #[test]
    fn batched_non_front_deliveries_do_not_postpone_the_owner_timeout() {
        let mut window = DownloadWindow::new(test_budget());
        let stager = test_stager(&window);
        let now = Instant::now();
        let owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        let front = hash(0xe5);
        let first = super::non_empty_request(
            owner,
            vec![
                super::PeerRequestEntry {
                    hash: front,
                    height: 1,
                },
                super::PeerRequestEntry {
                    hash: hash(0xe6),
                    height: 2,
                },
                super::PeerRequestEntry {
                    hash: hash(0xe7),
                    height: 3,
                },
            ],
            4,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        assert!(window.mark_requested(&stager, &first, owner, now));

        // A later batch keeps the owner active, so front removal must move
        // the clock forward rather than drop the entry.
        let second_at = now + Duration::from_secs(9);
        let second = super::non_empty_request(
            owner,
            vec![super::PeerRequestEntry {
                hash: hash(0xe8),
                height: 4,
            }],
            5,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        assert!(window.mark_requested(&stager, &second, owner, second_at));
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&now));

        // Deliver every non-front entry one at a time: each removal ties
        // with the front's own stamp, so the clock never leaves the first
        // batch's origin.
        for byte in [0xe6, 0xe7] {
            window.mark_received_from(hash(byte), SMALL_BODY, Some(owner), second_at);
            assert_eq!(window.owner_downloading_since.get(&owner), Some(&now));
        }

        // Removing the front itself — the first batch's true oldest, with
        // only the newer batch surviving — advances the clock to the
        // removal instant.
        let front_removed_at = second_at + Duration::from_millis(1);
        window.mark_received_from(front, SMALL_BODY, Some(owner), front_removed_at);
        assert_eq!(
            window.owner_downloading_since.get(&owner),
            Some(&front_removed_at)
        );
    }

    /// A batch sibling removed after the clock already restarted must not
    /// drag the clock back to its older batch stamp — the rewind would
    /// postpone `owner_download_expired` for a queue the peer is actively
    /// draining.
    #[test]
    fn tied_removal_never_rewinds_the_owner_queue_clock() {
        let mut window = DownloadWindow::new(test_budget());
        let stager = test_stager(&window);
        let t0 = Instant::now();
        let owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        let batch_a = super::non_empty_request(
            owner,
            vec![
                super::PeerRequestEntry {
                    hash: hash(0xf1),
                    height: 1,
                },
                super::PeerRequestEntry {
                    hash: hash(0xf2),
                    height: 2,
                },
            ],
            3,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        assert!(window.mark_requested(&stager, &batch_a, owner, t0));

        let t5 = t0 + Duration::from_secs(5);
        let batch_b = super::non_empty_request(
            owner,
            vec![
                super::PeerRequestEntry {
                    hash: hash(0xf3),
                    height: 3,
                },
                super::PeerRequestEntry {
                    hash: hash(0xf4),
                    height: 4,
                },
            ],
            5,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        assert!(window.mark_requested(&stager, &batch_b, owner, t5));

        // Drain batch A: its front ties with its sibling (clock stays at
        // the batch origin), then the sibling leaves as the true head and
        // restarts the clock at the removal instant.
        window.mark_received_from(hash(0xf1), SMALL_BODY, Some(owner), t5);
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&t0));
        let t9 = t5 + Duration::from_secs(4);
        window.mark_received_from(hash(0xf2), SMALL_BODY, Some(owner), t9);
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&t9));

        // The first batch-B removal ties with its sibling's t5 stamp: the
        // clock must keep t9, not regress to t5.
        window.mark_received_from(hash(0xf3), SMALL_BODY, Some(owner), t9);
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&t9));
    }

    /// The retarget path releases a pending without a delivery; a
    /// suspicion armed on its owner must clear instead of convicting when
    /// the second tick finds the observed hash no longer pending-owned.
    #[test]
    fn requeue_of_the_observed_block_clears_the_suspicion_without_blame() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let requested_at = Instant::now();
        let observed_at = requested_at + Duration::from_secs(10);
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let block_hash = hash(0x93);
        let owner = insert_pending(
            &mut window,
            test_source(peer_addr),
            block_hash,
            1,
            requested_at,
        );

        // First idle tick arms the suspicion.
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_some());

        // The retarget path releases the observed hash before the second
        // tick, and the owner's queue age leaves with it.
        window.requeue_for_retry(&block_hash, Some(1), observed_at);
        assert_eq!(window.pending_owner(&block_hash), None);
        assert_eq!(window.owner_queue_start_for_test(owner), None);

        // The second tick clears the suspicion without blame.
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_none());
        assert!(!window.peer_in_staller_cooldown(peer_addr, observed_at));
    }

    #[test]
    fn default_budget_keeps_full_request_window_for_large_blocks() {
        let mut window = DownloadWindow::new(super::default_sync_budget(Network::Regtest));
        let stager = test_stager(&window);
        window.ewma_block_bytes = 2 * 1024 * 1024;
        window.pending_bytes = window
            .budget
            .max_pending_blocks
            .saturating_sub(1)
            .saturating_mul(window.ewma_block_bytes);

        assert!(window.has_request_capacity(&stager));
    }

    #[test]
    fn releasing_a_dead_owner_drops_its_queue_start() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let now = Instant::now();
        let stale_owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        let live_owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 2], 8333)));
        let stale_requested_at = now
            .checked_sub(Duration::from_secs(9))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let estimated_bytes = 256 * 1024;
        for (owner, requested_at, height, byte) in [
            (stale_owner, stale_requested_at, 1_u32, 0x81),
            (live_owner, now, 2_u32, 0x82),
        ] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    owner,
                    requested_at,
                    height,
                    estimated_bytes,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(estimated_bytes);
            window.owner_downloading_since.insert(owner, requested_at);
        }

        window.retain_owned_by(|p| p.addr == live_owner.addr);

        assert_eq!(window.pending_len(), 1);
        assert_eq!(window.pending_bytes(), estimated_bytes);
        assert_eq!(window.next_request_height, 1);
        // The dead owner's queue start is gone with its pendings; the live
        // owner's age bookkeeping is untouched.
        assert_eq!(window.active_downloading_peers(), 1);
        assert_eq!(window.owner_downloading_since.get(&live_owner), Some(&now));
        assert!(!window.owner_download_expired(
            live_owner,
            window.active_downloading_peers(),
            now + Duration::from_secs(9)
        ));
    }

    #[test]
    fn receiving_the_oldest_pending_resets_the_owner_queue_start() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let mut stager = test_stager(&window);
        let now = Instant::now();
        let owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        let earliest = hash(0x91);
        let later = hash(0x92);
        let earliest_requested_at = now
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let estimated_bytes = 256 * 1024;
        for (hash, requested_at, height) in [
            (earliest, earliest_requested_at, 1_u32),
            (later, now, 2_u32),
        ] {
            window.pending.insert(
                hash,
                super::PendingBlock {
                    owner,
                    requested_at,
                    height,
                    estimated_bytes,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(estimated_bytes);
        }
        window
            .owner_downloading_since
            .insert(owner, earliest_requested_at);

        let unsolicited = receive_staged(&mut window, &mut stager, earliest, SMALL_BODY, now);

        assert!(!unsolicited);
        assert_eq!(window.pending_len(), 1);
        assert!(window.contains_pending(&later));
        // The queue head left: the surviving head's clock starts at the
        // removal instant, not at its own request time.
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&now));
        assert_eq!(
            timeout_owner(&mut window, false, now + Duration::from_secs(9)),
            None
        );
        assert!(window.pending_timeout_observation.is_none());
        assert_eq!(
            timeout_owner(&mut window, false, now + Duration::from_secs(10)),
            None
        );
        assert!(window.pending_timeout_observation.is_some());
    }

    /// BLK-05: the block-download budget is Core's per-owner queue-age
    /// rule — one target spacing plus half a spacing per other active
    /// owner (`net_processing.cpp:153-168`) — not a fixed 60 seconds.
    /// One active owner expires at exactly one spacing; three active
    /// owners each get two spacings.
    #[test]
    fn slow_peer_timeout_uses_spacing_and_other_downloaders() {
        let spacing = Duration::from_secs(10);
        let requested_at = Instant::now();

        // One active owner: the budget is exactly one spacing.
        let mut window = DownloadWindow::new(SyncBudget {
            block_spacing: spacing,
            pending_timeout_override: None,
            ..test_budget()
        });
        let solo = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        insert_pending(&mut window, solo, hash(0xb1), 1, requested_at);
        assert_eq!(
            timeout_owner(
                &mut window,
                false,
                requested_at + spacing.saturating_sub(Duration::from_millis(1)),
            ),
            None
        );
        assert!(window.pending_timeout_observation.is_none());
        assert_eq!(
            timeout_owner(&mut window, false, requested_at + spacing),
            None
        );
        assert!(window.pending_timeout_observation.is_some());
        assert_eq!(
            timeout_owner(&mut window, false, requested_at + spacing),
            Some(solo.addr)
        );

        // Three active owners: every owner's `other` count is 2, so the
        // budget is exactly two spacings and one spacing convicts nobody.
        let mut window = DownloadWindow::new(SyncBudget {
            block_spacing: spacing,
            pending_timeout_override: None,
            ..test_budget()
        });
        let owners: Vec<PeerSource> = (1..=3_u8)
            .map(|byte| {
                let owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 20 + byte], 8333)));
                insert_pending(
                    &mut window,
                    owner,
                    hash(0xc0 + byte),
                    u32::from(byte),
                    requested_at,
                );
                owner
            })
            .collect();
        assert_eq!(window.active_downloading_peers(), 3);
        assert_eq!(
            timeout_owner(&mut window, false, requested_at + spacing),
            None
        );
        assert!(
            window.pending_timeout_observation.is_none(),
            "one spacing must not convict while three owners share the queue"
        );
        assert_eq!(
            timeout_owner(&mut window, false, requested_at + 2 * spacing),
            None
        );
        assert!(window.pending_timeout_observation.is_some());
        assert_eq!(
            timeout_owner(&mut window, false, requested_at + 2 * spacing),
            Some(owners[0].addr),
            "the second observation convicts the pinned owner"
        );
    }

    /// The override is a test-only escape hatch and wins over the derived
    /// budget, keeping deterministic tests independent of spacing math.
    #[test]
    fn pending_timeout_override_wins_over_spacing_policy() {
        let mut window = DownloadWindow::new(
            SyncBudget {
                block_spacing: Duration::from_mins(10),
                ..test_budget()
            }
            .with_pending_timeout_override(Duration::from_secs(5)),
        );
        let requested_at = Instant::now();
        let owner = test_source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
        insert_pending(&mut window, owner, hash(0xd1), 1, requested_at);
        assert_eq!(
            timeout_owner(&mut window, false, requested_at + Duration::from_secs(5)),
            None
        );
        assert!(window.pending_timeout_observation.is_some());
    }

    #[test]
    fn retire_applied_leaves_pending_accounting_untouched() {
        let mut window = DownloadWindow::new(test_budget());
        let mut stager = test_stager(&window);
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let applied = hash(0xa1);
        let pending = hash(0xa2);
        let pending_bytes = 256 * 1024;
        let received_bytes = SMALL_BODY;
        window.pending.insert(
            pending,
            super::PendingBlock {
                owner: test_source(peer_addr),
                requested_at: now,
                height: 2,
                estimated_bytes: pending_bytes,
            },
        );
        window.pending_bytes = pending_bytes;
        // The staged body lives only in the stager now: seed it there.
        stage_body(&mut stager, applied, received_bytes, None, now);

        apply_staged(&mut stager, &applied);

        assert_eq!(stager.received_len(), 0);
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(window.pending_len(), 1);
        assert!(window.contains_pending(&pending));
        assert_eq!(window.pending_bytes, pending_bytes);
    }

    #[test]
    fn staged_byte_exhaustion_stops_new_requests_until_applied() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_bytes: SMALL_BODY,
            ..test_budget()
        });
        let mut stager = test_stager(&window);
        let staged = hash(0xb1);
        assert!(window.has_request_capacity(&stager));
        assert_ne!(window.request_peer_scan_limit(&stager, Instant::now()), 0);

        receive_staged(&mut window, &mut stager, staged, SMALL_BODY, Instant::now());

        // Staged bytes at the budget: stop issuing new block requests instead
        // of letting arrivals bounce off the exhausted stager.
        assert!(!window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 0);

        apply_staged(&mut stager, &staged);

        // Applying the staged block releases its bytes and reopens the window.
        assert!(window.has_request_capacity(&stager));
        assert_ne!(window.request_peer_scan_limit(&stager, Instant::now()), 0);
    }

    #[test]
    fn fanout_threshold_switches_effective_peer_cap() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 128,
            max_peer_inflight: 128,
            fanout_peer_inflight: 16,
            min_peers_for_fanout: 8,
            getdata_batch_limit: 128,
            ..test_budget()
        });
        let stager = test_stager(&window);
        let now = Instant::now();

        // Below the threshold: single-peer deep window — one peer can take
        // the full 128, so only one peer needs scanning.
        window.set_fanout_eligible_peers(7, now);
        assert!(!window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(&stager, now), 1);

        // At the threshold: shallow per-peer cap engages and the scan fans
        // out to enough peers to fill the window (128 / 16 = 8).
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(&stager, now), 8);
    }

    #[test]
    fn fast_sync_budget_stripes_window_across_fast_outbound_target() {
        let mut window = DownloadWindow::new(fast_sync_budget(Network::Regtest));
        let stager = test_stager(&window);
        let now = Instant::now();

        // One peer keeps the deep fallback.
        window.set_fanout_eligible_peers(1, now);
        assert!(!window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(&stager, now), 1);

        // A second eligible peer engages fan-out immediately.
        window.set_fanout_eligible_peers(FAST_MIN_PEERS_FOR_FANOUT, now);
        assert!(window.fanout_active());
        assert_eq!(window.effective_peer_inflight(), PENDING_BUDGET / 2);

        // At the fast outbound target every peer holds the fast stripe and
        // the scan reaches all of them.
        window.set_fanout_eligible_peers(FAST_OUTBOUND_PEER_TARGET, now);
        assert_eq!(
            window.effective_peer_inflight(),
            FAST_BLOCKS_IN_TRANSIT_PER_PEER
        );
        assert_eq!(
            window.request_peer_scan_limit(&stager, now),
            FAST_OUTBOUND_PEER_TARGET
        );
    }

    #[test]
    fn request_sizing_clamped_to_staged_byte_headroom() {
        // Staging budget of four estimated blocks with three already staged:
        // the gate is still open, but only one more block fits — a gate-open
        // burst must not over-request past that headroom.
        let slot = 256 * 1024;
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_bytes: 4 * slot,
            ..test_budget()
        });
        let mut stager = test_stager(&window);
        for byte in [0xc1, 0xc2, 0xc3] {
            receive_staged(&mut window, &mut stager, hash(byte), slot, Instant::now());
        }

        assert!(window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 1);

        // The fourth staged block consumes the last slot: headroom hits zero
        // and request capacity closes before any eviction can happen.
        receive_staged(&mut window, &mut stager, hash(0xc4), slot, Instant::now());
        assert!(!window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 0);
    }

    #[test]
    fn request_sizing_clamped_to_staged_count_headroom() {
        // Count budget of four with three blocks already staged: the byte
        // budgets are unbounded, so only the count clamp can stop a burst
        // from over-requesting into the stager's eviction threshold.
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_blocks: 4,
            ..test_budget()
        });
        let mut stager = test_stager(&window);
        for byte in [0xd1, 0xd2, 0xd3] {
            receive_staged(
                &mut window,
                &mut stager,
                hash(byte),
                SMALL_BODY,
                Instant::now(),
            );
        }

        assert!(window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 1);

        // The fourth staged block consumes the last slot: count headroom hits
        // zero and requests stop — overflow becomes request backpressure
        // before the stager's count budget could ever evict.
        receive_staged(
            &mut window,
            &mut stager,
            hash(0xd4),
            SMALL_BODY,
            Instant::now(),
        );
        assert!(!window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 0);
    }

    #[test]
    fn expired_pendings_reopen_scan_limit_through_count_headroom() {
        // Count wedge: staged (2) + pending (2) at the count budget (4), with
        // the pendings held by a stalled peer. While the pendings are live
        // the scan limit must be zero; once they pass the re-request timeout
        // the credit must reopen the scan limit so the request path can
        // expire and re-request the front (otherwise the wedge can only be
        // broken by pruning every staged block into re-download).
        let mut window = DownloadWindow::new(
            SyncBudget {
                max_pending_blocks: 4,
                max_received_blocks: 4,
                max_peer_inflight: 4,
                getdata_batch_limit: 4,
                ..test_budget()
            }
            .with_pending_timeout_override(Duration::from_secs(10)),
        );
        let mut stager = test_stager(&window);
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let owner = test_source(peer_addr);
        for (byte, height) in [(0xe1, 1_u32), (0xe2, 2)] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    owner,
                    requested_at: now,
                    height,
                    estimated_bytes: 256 * 1024,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(256 * 1024);
        }
        window.owner_downloading_since.insert(owner, now);
        for byte in [0xe3, 0xe4] {
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }

        assert_eq!(window.request_peer_scan_limit(&stager, now), 0);

        let after_timeout = now + Duration::from_secs(10);
        assert_ne!(window.request_peer_scan_limit(&stager, after_timeout), 0);
    }

    #[test]
    fn fanout_engagement_has_one_peer_hysteresis() {
        let mut window = DownloadWindow::new(SyncBudget {
            min_peers_for_fanout: 8,
            ..test_budget()
        });
        let now = Instant::now();

        // Fresh window: disengaged until the threshold is reached.
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7, now);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());

        // One transient demotion at the threshold must not flap the mode.
        window.set_fanout_eligible_peers(7, now);
        assert!(window.fanout_active());
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());

        // A second peer dropping out is structural: disengage, and stay
        // disengaged at one-below until the full threshold returns.
        window.set_fanout_eligible_peers(6, now);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7, now);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());
    }

    /// Budget for the stall state-machine tests: a 4-slot window whose count
    /// clamp saturates with three staged successors plus the pending front,
    /// unbounded bytes, and short injectable stall thresholds.
    fn stall_budget() -> SyncBudget {
        SyncBudget {
            max_pending_blocks: 4,
            max_received_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            stall_timeout_initial: Duration::from_secs(2),
            stall_timeout_max: Duration::from_secs(8),
            staller_cooldown: Duration::from_secs(30),
            ..test_budget()
        }
    }

    fn insert_pending(
        window: &mut DownloadWindow,
        owner: PeerSource,
        block_hash: Hash256,
        height: u32,
        now: Instant,
    ) -> PeerSource {
        window.pending.insert(
            block_hash,
            super::PendingBlock {
                owner,
                requested_at: now,
                height,
                estimated_bytes: 80,
            },
        );
        window.pending_bytes = window.pending_bytes.saturating_add(80);
        window.owner_downloading_since.entry(owner).or_insert(now);
        owner
    }

    /// Seeds the front-cadence EWMA through the real delivery path: heights
    /// 1 and 2 arrive from `peer` `gap` apart (must be >=
    /// `EWMA_MIN_SAMPLE_MS` or the second advance is skipped as a batch
    /// artifact) and apply immediately. Lifts `advance_stall`'s decay floor
    /// to twice the demonstrated cadence and returns the instant of the
    /// second front advance — the anchor for the next interval sample.
    fn seed_front_cadence(
        window: &mut DownloadWindow,
        peer: std::net::SocketAddr,
        t0: Instant,
        gap: Duration,
    ) -> Instant {
        let mut stager = test_stager(window);
        insert_pending(window, test_source(peer), hash(0x01), 1, t0);
        receive_staged(window, &mut stager, hash(0x01), SMALL_BODY, t0);
        apply_staged(&mut stager, &hash(0x01));
        let t1 = t0 + gap;
        insert_pending(window, test_source(peer), hash(0x02), 2, t1);
        receive_staged(window, &mut stager, hash(0x02), SMALL_BODY, t1);
        apply_staged(&mut stager, &hash(0x02));
        t1
    }

    /// A fully window-blocked construction with a seeded front-cadence EWMA:
    /// heights 1-2 first seed the EWMA at a 100ms cadence (the decay floor
    /// stays clamped at the static `stall_timeout_initial`, so the fire
    /// arithmetic matches a fast network while the cold-start suppression is
    /// disarmed), then the front (height 3) is in flight to `staller` while
    /// `healthy` delivered heights 4..=6, leaving zero staged-count headroom
    /// — every stall-predicate term holds. Returns the window, the
    /// coupled stager, and the construction instant (100ms after `t0`); observe with
    /// `next_apply_height` 3.
    fn window_blocked_on_staller(
        staller: std::net::SocketAddr,
        healthy: std::net::SocketAddr,
        t0: Instant,
    ) -> (DownloadWindow, BlockStager, Instant) {
        let mut window = DownloadWindow::new(stall_budget());
        let t1 = seed_front_cadence(&mut window, healthy, t0, Duration::from_millis(100));
        assert_eq!(window.front_interval_ewma_ms(), Some(100));
        let mut stager = test_stager(&window);
        insert_pending(&mut window, test_source(staller), hash(0x03), 3, t1);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5), (0x06, 6)] {
            insert_pending(&mut window, test_source(healthy), hash(byte), height, t1);
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, t1);
        }
        (window, stager, t1)
    }

    fn staller_addr() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 8333))
    }

    fn healthy_addr() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 2], 8333))
    }

    #[test]
    fn stall_clock_idle_without_staged_successors() {
        // Download-bound, not window-blocked: the front is in flight but
        // nothing was delivered — no single peer can be blamed, regardless of
        // how much time passes.
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        let stager = test_stager(&window);
        let tree = test_tree();
        insert_pending(&mut window, test_source(staller_addr()), hash(0x01), 1, now);

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 1, false, now),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                1,
                false,
                now + Duration::from_mins(1)
            ),
            None
        );
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn stall_clock_idle_when_frontier_block_is_not_in_flight() {
        // The apply frontier (height 1) was never requested (or expired): the
        // pending front sits above it, so no peer owns the gap and no blame
        // attaches even with delivered successors and zero headroom.
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        insert_pending(&mut window, test_source(staller_addr()), hash(0x02), 2, now);
        for (byte, height) in [(0x03_u8, 3_u32), (0x04, 4), (0x05, 5)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 1, false, now),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                1,
                false,
                now + Duration::from_mins(1)
            ),
            None
        );
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn stall_clock_idle_below_staged_backlog_fraction() {
        // Phase 1 arming term: one staged successor in a 4-slot staged
        // window is below the half-window fraction (4 / 2 = 2), so the
        // backlog is too shallow to show the asymmetric-frontier-blockage
        // signature — the front owner is not yet a staller. (Pre-Phase-1
        // this test pinned the "request capacity open" term; the fraction
        // term subsumes it here, and the capacity-closed counterpart is
        // pinned by `below_fraction_staged_backlog_never_arms_even_with_
        // capacity_closed`.)
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        insert_pending(&mut window, test_source(staller_addr()), hash(0x01), 1, now);
        insert_pending(&mut window, test_source(healthy_addr()), hash(0x02), 2, now);
        receive_staged(&mut window, &mut stager, hash(0x02), SMALL_BODY, now);
        assert!(window.has_request_capacity(&stager));

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 1, false, now),
            None
        );
        assert!(window.stalling_peer().is_none());

        // Chain-tail decision (ADV-2): this same state at the header tip
        // (nothing above the window left to request) must NOT arm the clock
        // either — a caught-up peer taking >2s on one tip block is the
        // normal tip regime, owned by the 60s pending-timeout machinery.
        // Below the staged fraction the predicate stays false no matter how
        // much time passes.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                1,
                false,
                now + Duration::from_mins(1)
            ),
            None
        );
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn staged_backlog_fraction_arms_with_request_capacity_open() {
        // Phase 1 arming: staged >= max_received_blocks / 2 with the
        // frontier pending to one peer arms the episode even while request
        // capacity is OPEN — the state the old `!has_request_capacity()`
        // term could never arm (it blamed nobody until the U5 clamps
        // closed, widening the blind region with window depth). Conviction
        // semantics are unchanged: the episode still runs the same clock to
        // the same threshold.
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, test_source(staller_addr()), hash(0x03), 3, now);
        // Exactly half the 4-slot staged window (2 blocks) above the front.
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }
        assert!(
            window.has_request_capacity(&stager),
            "the construction must keep request capacity open: arming no longer reads it"
        );

        // U7 no-blame guard, under the new arming term: while the apply
        // side is busy the armed-shaped window must not start an episode.
        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
        assert!(window.stalling_peer().is_none());

        // Apply idle: the staged fraction arms, and the unchanged
        // conviction clock fires at the unchanged threshold.
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));
        assert!(window.has_request_capacity(&stager));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(2)
            ),
            Some(staller_addr())
        );
    }

    #[test]
    fn arming_threshold_is_same_fraction_of_window_at_any_depth() {
        // The w256 re-attempt condition: the arm point is a fixed FRACTION
        // of the staged window (half, integer division), so deepening the
        // window moves the arming bar proportionally instead of widening a
        // capacity-closed blind region. Request capacity stays open
        // throughout at both depths — arming is independent of it.
        for depth in [128_usize, 256] {
            let mut window = DownloadWindow::new(SyncBudget {
                max_pending_blocks: depth,
                max_received_blocks: depth,
                max_peer_inflight: depth,
                getdata_batch_limit: depth,
                ..stall_budget()
            });
            let mut stager = test_stager(&window);
            let tree = test_tree();
            let now = seed_front_cadence(
                &mut window,
                healthy_addr(),
                Instant::now(),
                Duration::from_millis(100),
            );
            insert_pending(&mut window, test_source(staller_addr()), hash(0x03), 3, now);
            let half = depth / 2;
            // One below the fraction: no episode, no matter the depth.
            for offset in 0..half - 1 {
                let byte = u8::try_from(4 + offset).unwrap_or_else(|_| panic!("height fits u8"));
                insert_pending(
                    &mut window,
                    test_source(healthy_addr()),
                    hash(byte),
                    u32::from(byte),
                    now,
                );
                receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
            }
            assert!(window.has_request_capacity(&stager));
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert!(
                window.stalling_peer().is_none(),
                "one below half the window must not arm (depth {depth})"
            );

            // At the fraction: the episode arms.
            let byte = u8::try_from(4 + half - 1).unwrap_or_else(|_| panic!("height fits u8"));
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                u32::from(byte),
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
            assert!(window.has_request_capacity(&stager));
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(
                window.stalling_peer(),
                Some((staller_addr(), now)),
                "half the window must arm (depth {depth})"
            );
        }
    }

    #[test]
    fn below_fraction_staged_backlog_never_arms_even_with_capacity_closed() {
        // The old rule's trigger, inverted: request capacity CLOSED (here by
        // the staged-byte clamp) with the staged backlog below half the
        // window (4 of 10 staged, 40%) must NOT arm — pre-Phase-1 exactly
        // this state armed the episode. A shallow backlog above a slow front
        // does not show the asymmetric-frontier-blockage signature, however
        // the byte budget happens to sit.
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 10,
            max_received_blocks: 10,
            max_peer_inflight: 10,
            getdata_batch_limit: 10,
            max_received_bytes: 4 * SMALL_BODY,
            ..stall_budget()
        });
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, test_source(staller_addr()), hash(0x03), 3, now);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5), (0x06, 6), (0x07, 7)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }
        assert!(
            !window.has_request_capacity(&stager),
            "the staged-byte clamp must close request capacity (the old arming trigger)"
        );

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert!(window.stalling_peer().is_none());
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_mins(1)
            ),
            None,
            "capacity-closed below the staged fraction must never arm"
        );
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn stall_fires_after_threshold_and_starts_cooldown() {
        let (mut window, stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();

        // Episode starts on first observation; no fire before the threshold.
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(1)
            ),
            None
        );

        let fired = stall_owner(
            &mut window,
            &stager,
            &tree,
            3,
            false,
            now + Duration::from_secs(2),
        );

        assert_eq!(fired, Some(staller_addr()));
        assert!(window.stalling_peer().is_none());
        assert!(window.peer_in_staller_cooldown(staller_addr(), now + Duration::from_secs(2)));
        assert!(!window.peer_in_staller_cooldown(healthy_addr(), now + Duration::from_secs(2)));
        // Cooldown expires after `staller_cooldown`.
        assert!(!window.peer_in_staller_cooldown(staller_addr(), now + Duration::from_secs(33)));
    }

    #[test]
    fn stall_timeout_doubles_per_fire_caps_and_decays_on_front_arrival() {
        let (mut window, mut stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));

        // Fire 1 at +2s: threshold doubles to 4s.
        stall_owner(&mut window, &stager, &tree, 3, false, now);
        let mut at = now + Duration::from_secs(2);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(4));

        // The window state still satisfies the predicate (the disconnect and
        // re-queue are the sync layer's job), so a fresh episode starts and
        // must now survive the doubled threshold: fire 2 doubles to the 8s
        // cap, fire 3 stays capped.
        stall_owner(&mut window, &stager, &tree, 3, false, at);
        at += Duration::from_secs(4);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));
        stall_owner(&mut window, &stager, &tree, 3, false, at);
        at += Duration::from_secs(8);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));

        // Progress: the front block arrives — any running episode ends, and
        // the threshold must not snap back to the 2s floor: that snap is
        // what let the anti-cascade doubling be discarded across a peer
        // rotation (the self-eclipse blocker). The 14s front gap is a real
        // (non-batch) sample, so it lifts the EWMA from the 100ms seed to
        // 100 + (14000-100)/4 = 3575ms and the adaptive floor to 7150ms —
        // above the bare x0.85 decay (8s x0.85 = 6.8s), so the floor binds.
        // (The bare decay arithmetic in isolation is pinned by
        // `stall_timeout_decays_across_rotation_and_shields_slow_honest_peer`.)
        stall_owner(&mut window, &stager, &tree, 3, false, at);
        receive_staged(&mut window, &mut stager, hash(0x03), SMALL_BODY, at);
        assert_eq!(window.front_interval_ewma_ms(), Some(3575));
        assert_eq!(window.stall_timeout(), Duration::from_millis(7150));
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn successor_arrival_does_not_reset_stall_clock() {
        // Mid-window deliveries are data progress but not front progress: the
        // episode keeps running and fires on schedule. Heights 1-2 seed the
        // cadence EWMA; the 100ms cadence keeps the decay floor at the
        // static 2s.
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, test_source(staller_addr()), hash(0x03), 3, now);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }
        insert_pending(&mut window, test_source(healthy_addr()), hash(0x06), 6, now);

        stall_owner(&mut window, &stager, &tree, 3, false, now);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));

        receive_staged(
            &mut window,
            &mut stager,
            hash(0x06),
            SMALL_BODY,
            now + Duration::from_secs(1),
        );

        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(2)
            ),
            Some(staller_addr())
        );
    }

    #[test]
    fn no_blame_guard_keeps_stall_clock_idle_while_apply_side_is_busy() {
        let (mut window, stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();

        // With the apply side busy the clock never runs, no matter how long
        // the state persists.
        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
        assert!(window.stalling_peer().is_none());
        let later = now + Duration::from_mins(1);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, true, later),
            None
        );
        assert!(window.stalling_peer().is_none());

        // Once the apply side drains, blame starts from scratch — the busy
        // interval is never retroactively charged to the peer.
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, later),
            None
        );
        assert_eq!(window.stalling_peer(), Some((staller_addr(), later)));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                later + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                later + Duration::from_secs(2)
            ),
            Some(staller_addr())
        );
    }

    /// Counter-only local metrics recorder for the stall-episode
    /// observability tests: counters keyed `name{label=value}`, gauges and
    /// histograms discarded.
    #[derive(Clone, Default)]
    struct CounterRecorder {
        counts: std::sync::Arc<parking_lot::Mutex<hashbrown::HashMap<String, u64>>>,
    }

    impl CounterRecorder {
        fn counter_key(key: &metrics::Key) -> String {
            use std::fmt::Write as _;
            let mut name = key.name().to_owned();
            for label in key.labels() {
                let _ = write!(name, "{{{}={}}}", label.key(), label.value());
            }
            name
        }

        fn count(&self, name: &str) -> u64 {
            self.counts.lock().get(name).copied().unwrap_or(0)
        }

        fn cleared(&self, reason: &str) -> u64 {
            self.count(&format!(
                "node.sync.stall_episodes_cleared{{reason={reason}}}"
            ))
        }

        fn started(&self) -> u64 {
            self.count("node.sync.stall_episodes_started")
        }
    }

    struct CounterHandle {
        key: String,
        recorder: CounterRecorder,
    }

    impl metrics::CounterFn for CounterHandle {
        fn increment(&self, value: u64) {
            let mut counts = self.recorder.counts.lock();
            let entry = counts.entry(self.key.clone()).or_insert(0);
            *entry = entry.saturating_add(value);
        }

        fn absolute(&self, value: u64) {
            self.recorder.counts.lock().insert(self.key.clone(), value);
        }
    }

    impl metrics::Recorder for CounterRecorder {
        fn describe_counter(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _key: metrics::KeyName,
            _unit: Option<metrics::Unit>,
            _description: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            metrics::Counter::from_arc(std::sync::Arc::new(CounterHandle {
                key: Self::counter_key(key),
                recorder: self.clone(),
            }))
        }

        fn register_gauge(
            &self,
            _key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _key: &metrics::Key,
            _metadata: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// Phase 0 taxonomy exhaustiveness: every path that zeroes the episode
    /// clock tags exactly one cleared reason, and every episode start
    /// increments `stall_episodes_started`. The five reasons mirror
    /// `count_stall_episode_cleared`'s doc table; a new clear path without a
    /// counter shows up here as a started/cleared imbalance.
    #[test]
    fn stall_episode_counters_cover_every_clear_path() {
        let recorder = CounterRecorder::default();
        metrics::with_local_recorder(&recorder, || {
            let (mut window, mut stager, now) =
                window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
            let tree = test_tree();

            // No running episode: the guard paths must not count a clear.
            assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 4, false, now),
                None
            );
            assert_eq!(recorder.cleared("apply_busy"), 0);
            assert_eq!(recorder.cleared("predicate"), 0);
            assert_eq!(recorder.started(), 0);

            // apply_busy: a running episode cleared by the no-blame guard.
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(recorder.started(), 1);
            assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
            assert_eq!(recorder.cleared("apply_busy"), 1);

            // predicate: re-arm, then a predicate term goes false (the
            // frontier moves past the pending front, so term 1 fails).
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(recorder.started(), 2);
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 4, false, now),
                None
            );
            assert_eq!(recorder.cleared("predicate"), 1);

            // front_moved: re-arm, then re-key the front to another peer at
            // the same frontier while every predicate term still holds — the
            // old episode clears as front_moved and a new one starts.
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(recorder.started(), 3);
            window.remove_pending(&hash(0x03), now);
            insert_pending(&mut window, test_source(healthy_addr()), hash(0x07), 3, now);
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(recorder.cleared("front_moved"), 1);
            assert_eq!(recorder.started(), 4);

            // peer_delivery: the blamed peer (now `healthy`, owning the
            // re-keyed front) delivers a requested block.
            receive_staged(
                &mut window,
                &mut stager,
                hash(0x07),
                SMALL_BODY,
                now + Duration::from_millis(100),
            );
            assert_eq!(recorder.cleared("peer_delivery"), 1);

            // fired: a fresh construction runs an episode to conviction.
            let (mut window, stager, now) =
                window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(recorder.started(), 5);
            assert_eq!(
                stall_owner(
                    &mut window,
                    &stager,
                    &tree,
                    3,
                    false,
                    now + Duration::from_secs(2)
                ),
                Some(staller_addr())
            );
            assert_eq!(recorder.cleared("fired"), 1);

            // Exhaustive: five episodes started, five cleared, one per reason.
            for reason in [
                "apply_busy",
                "predicate",
                "front_moved",
                "peer_delivery",
                "fired",
            ] {
                assert_eq!(recorder.cleared(reason), 1, "reason {reason}");
            }
            assert_eq!(recorder.started(), 5);
        });
    }

    /// The stored episode's one-shot log latch, if an episode is running.
    /// `advance_stall` emits the INFO line in exactly the branch that flips
    /// this `false -> true`, so the latch IS the emission contract — pinned
    /// here at the state level because asserting through the global tracing
    /// pipeline is racy under parallel tests (tracing-core caches per-callsite
    /// interest globally; sibling tests hitting the same callsite with no
    /// dispatcher can poison a thread-local `with_default` capture).
    fn info_logged(window: &DownloadWindow) -> Option<bool> {
        window.stall.map(|episode| episode.info_logged)
    }

    /// Phase 0 observability: an episode surviving `STALL_EPISODE_LOG_AGE`
    /// emits the INFO line exactly once — not per tick — and a subsequent
    /// episode gets its own line. Pinned via the `info_logged` latch (see
    /// [`info_logged`] for why not via log capture).
    #[test]
    fn stall_episode_logs_info_once_per_episode_after_one_second() {
        let (mut window, stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();

        // Below the 1s log age: episode running, nothing emitted.
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert_eq!(info_logged(&window), Some(false));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_millis(500)
            ),
            None
        );
        assert_eq!(info_logged(&window), Some(false));

        // Past 1s: the latch flips on the emitting tick and stays latched —
        // one line, no matter how many further ticks the episode survives.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_millis(1500)
            ),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_millis(1900)
            ),
            None
        );
        assert_eq!(info_logged(&window), Some(true));

        // Fire ends the episode; the replacement episode (judged against the
        // doubled threshold) carries a fresh latch and re-emits once at 1s.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(2)
            ),
            Some(staller_addr())
        );
        assert_eq!(info_logged(&window), None);
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(2)
            ),
            None
        );
        assert_eq!(info_logged(&window), Some(false));
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                now + Duration::from_secs(4)
            ),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
    }

    /// An unseeded front-cadence EWMA (cold start) is not a conviction
    /// exemption: the fire threshold is the stored adaptive value, whose
    /// floor is `stall_timeout_initial` — Core's
    /// `BLOCK_STALLING_TIMEOUT_DEFAULT`. The observability line still fires
    /// at 1s, one full second before the first possible conviction.
    #[test]
    fn stall_convicts_at_initial_floor_before_ewma_is_seeded() {
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        insert_pending(&mut window, test_source(staller_addr()), hash(0x01), 1, now);
        for (byte, height) in [(0x02_u8, 2_u32), (0x03, 3), (0x04, 4)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }
        assert_eq!(window.front_interval_ewma_ms(), None);

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 1, false, now),
            None
        );
        assert_eq!(info_logged(&window), Some(false));
        // The INFO latch flips at 1s; the initial floor has not elapsed.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                1,
                false,
                now + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
        // Past the 2s initial floor the exact owner convicts with no EWMA
        // sample: an unproven cadence never exempts a proven-slow front.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                1,
                false,
                now + Duration::from_millis(2100)
            ),
            Some(staller_addr())
        );
    }

    /// The unified entry returns at most one action per tick and blame
    /// outranks the hedge: a tick where the cold-front timer and the stall
    /// predicate both mature convicts the staller and sends no duplicate
    /// request.
    #[test]
    fn at_most_one_action_per_tick_blame_outranks_hedge() {
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let staller = test_source(staller_addr());
        insert_pending(&mut window, staller, hash(0x01), 1, now);
        for (byte, height) in [(0x02_u8, 2_u32), (0x03, 3), (0x04, 4)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }
        let ctx = BlockedContext {
            next_apply_height: Some(1),
            frontier_hash: None,
            apply_side_busy: false,
            active_downloading_peers: window.active_downloading_peers(),
        };
        // First tick: the episode and the cold-front timer both start.
        assert_eq!(
            window.observe_blocked(ctx, &stager, &tree, now),
            BlockedDecision::None
        );
        // Both mature past the 2s floor: the blame wins alone.
        let decision =
            window.observe_blocked(ctx, &stager, &tree, now + Duration::from_millis(2100));
        assert_eq!(
            decision,
            BlockedDecision::Blame {
                owner: staller,
                reason: BlameReason::Staller,
            }
        );
    }

    fn peer_addr(idx: u8) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([10, 0, 0, idx], 8333))
    }

    #[test]
    fn uniform_slow_streaming_saturated_fanout_never_fires() {
        // The self-eclipse blocker construction, time-injected: a uniformly
        // slow honest network in saturated fan-out (8 peers, window 24, R+P
        // pinned at the count budget, so "no request capacity" is the steady
        // state) where EVERY peer keeps streaming — one block per peer per
        // round — but each round arrives 3s apart, past the 2s threshold.
        // Each peer serves its stripe slowest-block-last, so the window
        // front is always the laggard while its owner demonstrably keeps
        // delivering. Per-peer delivery progress keeps every delivery-time
        // episode from surviving to the threshold, and the ADV-DRIP-1
        // adaptive floor keeps the MID-GAP observations (the wake path
        // observes at ~g/8 cadence, so most observations land between the
        // front owner's deliveries) from firing: zero fires, zero cooldowns.
        let t0 = Instant::now();
        let budget = SyncBudget {
            max_pending_blocks: 24,
            max_received_blocks: 24,
            max_peer_inflight: 24,
            getdata_batch_limit: 24,
            ..stall_budget()
        };
        let mut window = DownloadWindow::new(budget);
        let mut stager = test_stager(&window);
        let tree = test_tree();

        // Pre-seed: the network has already demonstrated its 3s front
        // cadence — two front advances 3s apart seed the interval EWMA at
        // 3000ms and lift the decay floor to 2x3s = 6s before the saturated
        // rounds begin. An unseeded window would fire at the static 2s
        // floor while its honest peers need 3s per round, so the adaptive
        // floor must be demonstrated before the saturated rounds start; in
        // real IBD the EWMA has tracked the cadence since the first two
        // blocks of the session anyway, long before blocks grow past one
        // threshold of transfer time.
        insert_pending(&mut window, test_source(peer_addr(0)), hash(0x01), 1, t0);
        receive_staged(&mut window, &mut stager, hash(0x01), SMALL_BODY, t0);
        apply_staged(&mut stager, &hash(0x01));
        let t1 = t0 + Duration::from_secs(3);
        insert_pending(&mut window, test_source(peer_addr(0)), hash(0x02), 2, t1);
        receive_staged(&mut window, &mut stager, hash(0x02), SMALL_BODY, t1);
        apply_staged(&mut stager, &hash(0x02));
        assert_eq!(window.front_interval_ewma_ms(), Some(3000));
        assert_eq!(
            window.stall_timeout(),
            Duration::from_secs(6),
            "the second front advance must lift the threshold to the adaptive floor"
        );

        // The saturated window: heights 3..=26 striped 3 per peer.
        for peer in 0..8u8 {
            for slot in 0..3u8 {
                let height = peer * 3 + slot + 3;
                insert_pending(
                    &mut window,
                    test_source(peer_addr(peer)),
                    hash(height),
                    u32::from(height),
                    t1,
                );
            }
        }
        // Nothing staged yet: download-bound, no episode regardless of time.
        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, false, t1), None);

        for round in 0..3u8 {
            let at = t1 + Duration::from_secs(3) * (u32::from(round) + 1);
            for peer in 0..8u8 {
                // Highest remaining block of the stripe first: the front
                // (height 3, peer 0) arrives only in the last round.
                let height = peer * 3 + 5 - round;
                receive_staged(&mut window, &mut stager, hash(height), SMALL_BODY, at);
            }
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, at),
                None,
                "a streaming peer must never fire (round {round})"
            );
            // ADV-DRIP-1 mid-gap wake, 2s into the 3s gap between the front
            // owner's deliveries: the saturated fan-out predicate holds and
            // the episode is 2s old — past the static 2s floor (the
            // pre-fix drip fired exactly here) but under the 6s adaptive
            // floor.
            assert_eq!(
                stall_owner(
                    &mut window,
                    &stager,
                    &tree,
                    3,
                    false,
                    at + Duration::from_secs(2)
                ),
                None,
                "a mid-gap observation must never fire on a streaming peer (round {round})"
            );
        }

        let end = t1 + Duration::from_secs(12);
        // The last round drains the whole window in ascending front order:
        // the deferred front (slowest-block-last) lands one real 9s interval
        // sample (3000 + (9000-3000)/4 = 4500ms), then seven same-instant
        // front advances follow — batch artifacts of the chunk-shared
        // timestamp. Pre-fix each walked the EWMA down by a quarter
        // (4500 x (3/4)^7 = 602ms), collapsing the adaptive floor back to
        // the static 2s; now they are skipped and the EWMA must hold at
        // 4500ms. The threshold tracked the moving floor throughout and was
        // never doubled by a fire (the per-round and cooldown asserts above
        // pin that directly).
        assert_eq!(window.front_interval_ewma_ms(), Some(4500));
        for peer in 0..8u8 {
            assert!(
                !window.peer_in_staller_cooldown(peer_addr(peer), end),
                "no staller cooldown may exist after uniform-slow streaming"
            );
        }

        // Consequence pin: with the burst filtered out, the floor stays at
        // min(2x4500ms, stall_timeout_max) = 8s, so a slow honest owner of
        // the next front — 7s of blame, well past the static 2s that the
        // deflated floor would have re-armed — still does not fire. The
        // staged backlog (heights 3..=26, never applied in this
        // construction) sits at the count budget, far past the half-window
        // arming fraction, so the predicate holds the moment a front
        // pending and a staged successor exist.
        insert_pending(&mut window, test_source(peer_addr(0)), hash(27), 27, end);
        insert_pending(&mut window, test_source(peer_addr(1)), hash(28), 28, end);
        receive_staged(&mut window, &mut stager, hash(28), SMALL_BODY, end);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 27, false, end),
            None
        );
        assert_eq!(
            window.stalling_peer().map(|(addr, _)| addr),
            Some(peer_addr(0))
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                27,
                false,
                end + Duration::from_secs(7)
            ),
            None,
            "a slow honest front owner must stay under the preserved adaptive floor"
        );
    }

    #[test]
    fn episode_peer_delivery_restarts_stall_clock() {
        // The per-peer progress discriminator in isolation: the front owner
        // delivers a NON-front block mid-episode — under front-only progress
        // accounting the episode would survive and fire at +2.5s; charging
        // per-peer delivery restarts the clock instead. When the same peer
        // then stops delivering entirely, it is a true staller and still
        // fires one full threshold after its last delivery. Heights 1-2 seed
        // the cadence EWMA; the 100ms cadence keeps the decay floor at the
        // static 2s.
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        // Both pendings belong to one connection: its mid-window delivery is
        // owner progress and restarts that connection's episode clock.
        let staller = test_source(staller_addr());
        insert_pending(&mut window, staller, hash(0x03), 3, now);
        insert_pending(&mut window, staller, hash(0x06), 6, now);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                now,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, now);
        }

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));

        // The episode peer delivers its mid-window block at +1.5s: progress,
        // episode cleared (and no threshold decay — not the front).
        receive_staged(
            &mut window,
            &mut stager,
            hash(0x06),
            SMALL_BODY,
            now + Duration::from_millis(1500),
        );
        assert!(window.stalling_peer().is_none());
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));

        // +2.5s (past the original episode's threshold): blame restarts from
        // the delivery, no fire.
        let restarted = now + Duration::from_millis(2500);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, restarted),
            None
        );
        assert_eq!(window.stalling_peer(), Some((staller_addr(), restarted)));

        // No deliveries for a full threshold after that: a true staller now,
        // and it fires.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                restarted + Duration::from_secs(2)
            ),
            Some(staller_addr())
        );
    }

    #[test]
    fn stall_timeout_decays_across_rotation_and_shields_slow_honest_peer() {
        // Anti-cascade across a peer rotation: after a true fire doubles the
        // threshold, front arrivals from healthy peers must DECAY it in
        // x0.85 steps — never snap it to the floor — so a subsequent
        // ~3s-honest front owner is judged against the still-elevated value
        // and does not fire.
        //
        // Every front past the rotation is delivered with the same
        // `fired_at` timestamp: those 0ms inter-front-advance samples are
        // batch artifacts (same-chunk timestamp sharing) and are SKIPPED, so
        // the interval EWMA stays at 575ms (the 100ms seed plus the one real
        // 2s rotation sample) and the adaptive decay floor sits at the
        // static 2s — this test pins the bare x0.85 decay arithmetic. The
        // adaptive-floor interaction is pinned separately in
        // `stall_decay_limit_cycle_stops_at_adaptive_floor`.
        let (mut window, mut stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        let fired_at = now + Duration::from_secs(2);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, fired_at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(4));

        // Rotation: the sync layer drops the staller and re-queues the front
        // to the healthy peer, which delivers it. The 2s wedge gap is a real
        // sample: EWMA 100 -> 100 + (2000-100)/4 = 575ms, floor still 2s.
        window.retain_owned_by(|p| p.addr != staller_addr());
        insert_pending(
            &mut window,
            test_source(healthy_addr()),
            hash(0x03),
            3,
            fired_at,
        );
        receive_staged(&mut window, &mut stager, hash(0x03), SMALL_BODY, fired_at);
        assert_eq!(window.front_interval_ewma_ms(), Some(575));
        assert_eq!(
            window.stall_timeout(),
            Duration::from_millis(3400),
            "front arrival after a fire must decay the threshold, not snap it to the floor"
        );

        // A ~3s-honest peer now owns the new front (height 7) with the
        // window again saturated: 3s of blame stays under the elevated
        // 3.4s threshold — no fire.
        let honest = peer_addr(3);
        insert_pending(&mut window, test_source(honest), hash(0x07), 7, fired_at);
        for (byte, height) in [(0x08_u8, 8_u32), (0x09, 9)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                fired_at,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, fired_at);
        }
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 7, false, fired_at),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                7,
                false,
                fired_at + Duration::from_secs(3)
            ),
            None,
            "a ~3s honest front owner must not fire while the threshold is elevated"
        );
        receive_staged(&mut window, &mut stager, hash(0x07), SMALL_BODY, fired_at);

        // Gradual 0.85 steps down to the floor, never below it. All these
        // same-instant front advances are skipped batch samples: the EWMA
        // (and so the floor) must not move.
        assert_eq!(window.stall_timeout(), Duration::from_millis(2890));
        for (byte, expected) in [
            (0x0a_u8, Duration::from_micros(2_456_500)),
            (0x0b, Duration::from_micros(2_088_025)),
            (0x0c, Duration::from_secs(2)),
            (0x0d, Duration::from_secs(2)),
        ] {
            insert_pending(
                &mut window,
                test_source(honest),
                hash(byte),
                u32::from(byte),
                fired_at,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, fired_at);
            assert_eq!(window.stall_timeout(), expected);
        }
        assert_eq!(window.front_interval_ewma_ms(), Some(575));
    }

    #[test]
    fn stall_decay_limit_cycle_stops_at_adaptive_floor() {
        // ADV-DRIP-1, the drip itself: with a uniform honest front cadence
        // g = 3s above the 2s static floor, the x0.85 decay used to re-cross
        // g within a few front advances after a fire and fire again — a
        // limit cycle draining one honest peer per ~5g seconds. The adaptive
        // floor must stop the decay at 2x the demonstrated cadence (>= 2g):
        // no re-fire ever, while a true staller still convicts at the
        // elevated ~2g threshold.
        //
        // The session's first two blocks seed the EWMA at the 3s cadence,
        // so even the FIRST conviction is judged at the 6s adaptive floor
        // (an unseeded window would convict at the static 2s floor, below
        // the honest 3s cadence).
        let (mut window, stager, front, at, _silent) = limit_cycle_window_state();
        let tree = test_tree();
        assert_eq!(window.front_interval_ewma_ms(), Some(3239));
        // No re-fire: the honest 3s owner must never cross the adaptive floor.
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, u32::from(front), false, at),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                u32::from(front),
                false,
                at + Duration::from_secs(3)
            ),
            None,
            "honest front owner must not fire after limit cycle stops"
        );
    }

    #[test]
    fn adaptive_floor_still_convicts_true_staller_after_limit_cycle() {
        // Companion to `stall_decay_limit_cycle_stops_at_adaptive_floor`:
        // once the decay floor stabilises at 2g, a genuinely silent peer that
        // holds the front must still convict at the elevated threshold.
        let (mut window, mut stager, front, at, silent) = limit_cycle_window_state();
        let tree = test_tree();

        // A true staller now owns the front: zero deliveries while the
        // healthy peer keeps streaming successors. The episode survives the
        // successor arrival (different peer, not the front hash) and convicts
        // at the adaptive ~2g threshold — 6.478s, far inside the 60s
        // pending-timeout fallback.
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, u32::from(front), false, at),
            None
        );
        insert_pending(
            &mut window,
            test_source(healthy_addr()),
            hash(front + 4),
            u32::from(front) + 4,
            at,
        );
        receive_staged(
            &mut window,
            &mut stager,
            hash(front + 4),
            SMALL_BODY,
            at + Duration::from_secs(2),
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                u32::from(front),
                false,
                at + Duration::from_secs(3)
            ),
            None,
            "a true staller is judged at the adaptive floor, not the static 2s"
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                u32::from(front),
                false,
                at + Duration::from_millis(6478)
            ),
            Some(silent),
            "a silent front owner must still convict at the adaptive threshold"
        );
        // Doubling starts from the effective (floor-bound) threshold, capped
        // at `stall_timeout_max` (8s in this budget).
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));
        let end = at + Duration::from_millis(6478);
        assert!(window.peer_in_staller_cooldown(silent, end));
        assert!(!window.peer_in_staller_cooldown(healthy_addr(), end));
    }

    /// Builds the window state reached after the first stall conviction in the
    /// ADV-DRIP-1 limit-cycle scenario: EWMA seeded at 3s cadence, one fire
    /// and release, four more 3s front advances with the decay clamped at the
    /// adaptive floor. Returns `(window, stager, front_height, now, silent_peer)`.
    #[allow(clippy::too_many_lines)]
    fn limit_cycle_window_state() -> (
        DownloadWindow,
        BlockStager,
        u8,
        Instant,
        std::net::SocketAddr,
    ) {
        let mut window = DownloadWindow::new(stall_budget());
        let healthy = test_source(healthy_addr());
        let staller = test_source(staller_addr());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let t1 = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_secs(3),
        );

        // First conviction: staller takes height 3 at the 6s adaptive floor.
        insert_pending(&mut window, staller, hash(0x03), 3, t1);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5), (0x06, 6)] {
            insert_pending(&mut window, healthy, hash(byte), height, t1);
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, t1);
        }
        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, false, t1), None);
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                3,
                false,
                t1 + Duration::from_secs(3)
            ),
            None,
            "one honest-cadence gap of blame must stay under the adaptive floor"
        );
        let fired_at = t1 + Duration::from_secs(6);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, fired_at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));
        window.retain_owned_by(|p| p.addr != staller_addr());

        // Healthy peer resumes; four 3s cycles walk the EWMA back with the
        // decay clamped at the adaptive floor — the limit cycle never re-fires.
        insert_pending(&mut window, healthy, hash(0x03), 3, fired_at);
        receive_staged(&mut window, &mut stager, hash(0x03), SMALL_BODY, fired_at);
        for offset in 0..4u8 {
            apply_staged(&mut stager, &hash(3 + offset));
        }
        let silent = peer_addr(9);
        insert_pending(&mut window, healthy, hash(0x07), 7, fired_at);
        for offset in 1..4u8 {
            insert_pending(
                &mut window,
                healthy,
                hash(7 + offset),
                u32::from(7 + offset),
                fired_at,
            );
            receive_staged(
                &mut window,
                &mut stager,
                hash(7 + offset),
                SMALL_BODY,
                fired_at,
            );
        }
        let mut front: u8 = 7;
        let mut at = fired_at;
        let expected = [
            Duration::from_millis(7126),
            Duration::from_millis(6846),
            Duration::from_millis(6636),
            Duration::from_millis(6478),
        ];
        for expected_timeout in expected {
            let arrive = at + Duration::from_secs(3);
            // No fire at wake or at honest-cadence arrival.
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, u32::from(front), false, at),
                None
            );
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, u32::from(front), false, arrive),
                None
            );
            receive_staged(&mut window, &mut stager, hash(front), SMALL_BODY, arrive);
            assert_eq!(
                window.stall_timeout(),
                expected_timeout,
                "the decay must stop at the adaptive floor, never re-crossing the 3s cadence"
            );
            for offset in 0..4u8 {
                apply_staged(&mut stager, &hash(front + offset));
            }
            let next_front = front + 4;
            let owner = if next_front == 23 {
                silent
            } else {
                healthy_addr()
            };
            insert_pending(
                &mut window,
                test_source(owner),
                hash(next_front),
                u32::from(next_front),
                arrive,
            );
            for offset in 1..4u8 {
                let height = next_front + offset;
                insert_pending(
                    &mut window,
                    healthy,
                    hash(height),
                    u32::from(height),
                    arrive,
                );
                receive_staged(&mut window, &mut stager, hash(height), SMALL_BODY, arrive);
            }
            front = next_front;
            at = arrive;
        }
        assert_eq!(window.front_interval_ewma_ms(), Some(3239));
        (window, stager, front, at, silent)
    }

    #[test]
    fn cold_start_hedges_front_without_convicting_owner() {
        // Cold recovery is independent of the strong staged-successor stall
        // predicate. It races only the unchanged apply-front hash.
        let t0 = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        insert_pending(&mut window, test_source(staller_addr()), hash(0x01), 1, t0);
        for (byte, height) in [(0x02_u8, 2_u32), (0x03, 3), (0x04, 4)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                t0,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, t0);
        }
        assert_eq!(window.front_interval_ewma_ms(), None);

        assert_eq!(cold_front_owner(&mut window, 1, false, t0), None);
        assert_eq!(
            cold_front_owner(&mut window, 1, false, t0 + Duration::from_secs(2)),
            Some((staller_addr(), hash(0x01)))
        );
        let owner = window
            .pending_owner(&hash(0x01))
            .unwrap_or_else(|| panic!("pending owner"));
        let alternate = test_source(healthy_addr());
        window.confirm_cold_front_hedge(owner, alternate, hash(0x01));
        assert_eq!(
            cold_front_owner(&mut window, 1, false, t0 + Duration::from_secs(30)),
            None
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));
        assert!(!window.peer_in_staller_cooldown(staller_addr(), t0 + Duration::from_secs(30)));

        // The alternate wins the duplicate race. Only this delivery proof
        // demotes the tracked owner and selects the replacement deep peer.
        let t1 = t0 + Duration::from_secs(30);
        window.pending_timeout_observation = Some(super::PendingTimeoutObservation {
            owner,
            hash: hash(0x01),
            expired_release: false,
        });
        window.mark_received_from(hash(0x01), 80, Some(alternate), t1);
        assert_eq!(window.preferred_peer(), Some(alternate));
        assert!(window.peer_in_staller_cooldown(staller_addr(), t1));
        assert!(window.pending_timeout_observation.is_none());
        assert_eq!(window.front_interval_ewma_ms(), None);
        for byte in [0x01_u8, 0x02, 0x03, 0x04] {
            apply_staged(&mut stager, &hash(byte));
        }
        let t2 = t1 + Duration::from_secs(3);
        insert_pending(&mut window, test_source(healthy_addr()), hash(0x05), 5, t1);
        receive_staged(&mut window, &mut stager, hash(0x05), SMALL_BODY, t2);
        apply_staged(&mut stager, &hash(0x05));
        assert_eq!(window.front_interval_ewma_ms(), Some(3000));

        // A true staller (silent on the front while the healthy peer's
        // staged successors wait) now fires at the effective threshold —
        // the 6s adaptive floor (2x the demonstrated 3s cadence).
        let silent = peer_addr(9);
        insert_pending(&mut window, test_source(silent), hash(0x06), 6, t2);
        for (byte, height) in [(0x07_u8, 7_u32), (0x08, 8), (0x09, 9)] {
            insert_pending(
                &mut window,
                test_source(healthy_addr()),
                hash(byte),
                height,
                t2,
            );
            receive_staged(&mut window, &mut stager, hash(byte), SMALL_BODY, t2);
        }
        assert_eq!(stall_owner(&mut window, &stager, &tree, 6, false, t2), None);
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                6,
                false,
                t2 + Duration::from_secs(3)
            ),
            None
        );
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                6,
                false,
                t2 + Duration::from_secs(6)
            ),
            Some(silent),
            "a seeded window must convict a true staller at the effective threshold"
        );
    }

    #[test]
    fn disconnected_alternate_rearms_same_cold_front() {
        let t0 = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        insert_pending(&mut window, test_source(staller_addr()), hash(0x01), 1, t0);
        assert_eq!(cold_front_owner(&mut window, 1, false, t0), None);
        assert_eq!(
            cold_front_owner(&mut window, 1, false, t0 + Duration::from_secs(2)),
            Some((staller_addr(), hash(0x01)))
        );
        let owner = window
            .pending_owner(&hash(0x01))
            .unwrap_or_else(|| panic!("pending owner"));
        let alternate = test_source(healthy_addr());
        window.confirm_cold_front_hedge(owner, alternate, hash(0x01));

        window.retain_owned_by(|p| p.addr != healthy_addr());
        let retry_started = t0 + Duration::from_secs(3);
        assert_eq!(cold_front_owner(&mut window, 1, false, retry_started), None);
        assert_eq!(
            cold_front_owner(
                &mut window,
                1,
                false,
                retry_started + Duration::from_secs(2)
            ),
            Some((staller_addr(), hash(0x01)))
        );
        let owner = window
            .pending_owner(&hash(0x01))
            .unwrap_or_else(|| panic!("pending owner"));
        window.confirm_cold_front_hedge(owner, test_source(peer_addr(2)), hash(0x01));
        assert!(matches!(
            window.cold_front,
            Some(super::ColdFrontState::Racing { alternate, .. }) if alternate.addr == peer_addr(2)
        ));
    }

    #[test]
    fn cold_front_distinct_hedge_cap_blocks_another_probe() {
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        window.cold_hedged_fronts.extend([hash(0x01), hash(0x02)]);
        insert_pending(&mut window, test_source(staller_addr()), hash(0x03), 3, now);

        assert_eq!(
            cold_front_owner(&mut window, 3, false, now + Duration::from_secs(2)),
            None
        );
        assert!(window.cold_front.is_none());
        assert_eq!(
            window.cold_hedged_fronts.len(),
            super::MAX_COLD_FRONT_HEDGES
        );
    }

    #[test]
    fn mixed_prefix_sources_do_not_elect_a_winner() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let first = test_source(healthy_addr());
        let second = test_source(peer_addr(2));
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[first, second], now);

        for (byte, source) in [(1_u8, first), (2, second), (3, first), (4, second)] {
            window.mark_received_from(hash(byte), 80, Some(source), now);
        }

        assert_eq!(window.preferred_peer(), None);
        assert!(
            window.prefix_probe_plan().is_none(),
            "an inconclusive race must not probe the remaining suffix"
        );
        assert!(window.prefix_probe.is_none());
        Ok(())
    }

    #[test]
    fn prefix_probe_respects_estimated_byte_cutoff() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }

        window.ewma_block_bytes = 512 * 1024 + 1;
        assert!(window.prefix_probe_plan().is_none());
        window.ewma_block_bytes = 512 * 1024;
        let (_, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("cutoff-sized probe must be planned"))?;
        assert_eq!(hashes.len(), super::PREFIX_PROBE_WIN_BLOCKS);
        Ok(())
    }

    /// Direct window-boundary test for the bounded prefix-race-before-fanout
    /// handoff: fanout cancels the probe at exactly `stall_timeout_initial`,
    /// neither before nor after. The exact cross-tick boundary is pinned in
    /// `sync::tests::tick_fanout_deferred_for_fresh_probe_engages_at_deadline`.

    #[test]
    fn fanout_cancels_prefix_probe_without_rearming_it() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let alternate = test_source(healthy_addr());
        let budget = SyncBudget {
            min_peers_for_fanout: 2,
            ..stall_budget()
        };
        // Direct window-boundary pin: the deferral must expire at exactly
        // `stall_timeout_initial`, not one tick beyond it. With the production
        // `<` operator, an elapsed time equal to the budget makes the probe
        // no longer fresh, so fanout engages at the deadline and clears the
        // probe. Flipping the operator to `<=` would keep the probe young at
        // the deadline and this assertion would fail (fanout stays deferred).
        // The exact cross-tick boundary is tested in
        // `sync::tests::tick_fanout_deferred_for_fresh_probe_engages_at_deadline`.
        let stall_timeout_initial = budget.stall_timeout_initial;
        let mut window = DownloadWindow::new(budget);
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, terminal_height) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        assert_eq!(terminal_height, 8);
        window.confirm_prefix_probe(planned_owner, hashes, &[alternate], now);
        assert!(window.prefix_probe.is_some());
        // At exactly the `stall_timeout_initial` deadline (direct
        // window-boundary): the bounded deferral expires, fanout engages, and
        // the probe is cleared exactly as before the deferral existed.
        let now = now + stall_timeout_initial;

        window.set_fanout_eligible_peers(2, now);

        assert!(window.prefix_probe.is_none());
        window.set_fanout_eligible_peers(0, now);
        assert!(window.prefix_probe_plan().is_none());
        Ok(())
    }

    /// A fanout threshold transition during a fresh prefix probe retains the
    /// probe and keeps fanout inactive: the bounded deferral holds engagement
    /// while the one-shot race (age < `stall_timeout_initial`) is still in
    /// flight, instead of cancelling it.
    #[test]
    fn fanout_threshold_during_fresh_probe_defers_engagement()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let alternate = test_source(healthy_addr());
        let mut window = DownloadWindow::new(SyncBudget {
            min_peers_for_fanout: 2,
            ..stall_budget()
        });
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[alternate], now);
        assert!(window.prefix_probe.is_some());

        // The eligible count reaches the fanout threshold while the probe is
        // still younger than stall_timeout_initial (2s): fanout engagement is
        // deferred and the probe survives.
        window.set_fanout_eligible_peers(2, now);

        assert!(
            !window.fanout_active(),
            "fanout must stay deferred for a fresh probe"
        );
        assert!(
            window.prefix_probe.is_some(),
            "a fresh prefix probe must survive the threshold transition"
        );
        Ok(())
    }

    /// A probe cancellation before the deferral deadline lets fanout engage
    /// immediately on the next evaluation, with no leftover deferral state.
    /// A healthy preferred winner remains selected only while the eligible
    /// population is below the fanout threshold. A cancellation clears the
    /// probe without setting a preferred peer, so the next threshold
    /// evaluation must not be held by a deferral for a probe that no longer
    /// exists.
    ///
    /// The test first proves the deferral itself: with a fresh live probe it
    /// crosses the fanout threshold and asserts fanout stays off and the
    /// probe survives. Only then does it cancel the probe and prove the next
    /// threshold evaluation engages immediately — so the immediate-engagement
    /// assertion is meaningful (the deferral was actually holding).
    #[test]
    fn probe_resolution_before_deadline_allows_fanout_immediately()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let alternate = test_source(healthy_addr());
        let mut window = DownloadWindow::new(SyncBudget {
            min_peers_for_fanout: 2,
            ..stall_budget()
        });
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[alternate], now);
        assert!(window.prefix_probe.is_some());

        // First prove the deferral holds: cross the fanout threshold while
        // the probe is fresh (age 0 < stall_timeout_initial). Fanout must stay
        // off and the probe must survive — this is the guarded transition.
        window.set_fanout_eligible_peers(2, now);
        assert!(
            !window.fanout_active(),
            "a fresh live probe must defer the threshold transition"
        );
        assert!(
            window.prefix_probe.is_some(),
            "a fresh live probe must survive the threshold transition"
        );

        // The alternate disconnects before the deadline, dropping racers
        // below two and cancelling the probe — without electing a winner or
        // setting a preferred peer.
        window.retain_owned_by(|p| p.addr != alternate.addr);
        assert!(window.prefix_probe.is_none(), "the probe must be cancelled");
        assert!(
            window.preferred_peer().is_none(),
            "cancellation must not elect a winner"
        );

        // With the probe gone, the next threshold evaluation engages fanout
        // immediately — the young-probe guard no longer holds and no
        // deferral state lingers.
        window.set_fanout_eligible_peers(2, now);
        assert!(
            window.fanout_active(),
            "fanout must engage once the probe is cancelled"
        );
        Ok(())
    }

    #[test]
    fn disconnected_prefix_racer_queued_deliveries_cannot_win()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let disconnected = test_source(healthy_addr());
        let live_alternate = test_source(peer_addr(2));
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[disconnected, live_alternate], now);
        window.retain_owned_by(|p| p.addr != disconnected.addr);

        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(disconnected), now);
        }

        assert_eq!(window.preferred_peer(), None);
        assert!(window.prefix_probe.is_none());
        Ok(())
    }

    #[test]
    fn dead_owner_prefix_probe_is_released_even_with_live_alternates()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let alternate_a = test_source(healthy_addr());
        let alternate_b = test_source(peer_addr(2));
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[alternate_a, alternate_b], now);

        // The owner's connection dies while both alternates stay live: the
        // probe must be released with the rest of the dead owner's work,
        // not orphaned on its racer count.
        window.retain_owned_by(|p| p.addr != owner.addr);
        assert!(window.prefix_probe.is_none());

        // The released race can never complete: a live racer's probe
        // deliveries install no confirmation, elect no winner, and never
        // enter the dead owner's address in the staller cooldown that a
        // live same-address replacement would inherit.
        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(alternate_a), now);
        }

        assert!(window.prefix_probe.is_none());
        assert_eq!(window.preferred_peer(), None);
        assert!(!window.peer_in_staller_cooldown(owner.addr, now));
        Ok(())
    }

    #[test]
    fn late_prefix_loser_cannot_replace_winner() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let winner = test_source(healthy_addr());
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        let loser = test_source(peer_addr(2));
        window.confirm_prefix_probe(planned_owner, hashes, &[winner, loser], now);
        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(winner), now);
        }
        assert_eq!(window.preferred_peer(), Some(winner));
        window.mark_received_from(hash(5), 80, Some(owner), now);
        assert_eq!(window.preferred_peer(), Some(winner));
        window.retain_owned_by(|p| p.addr != winner.addr);
        assert_eq!(window.preferred_peer(), None);
        assert!(!window.peer_in_staller_cooldown(loser.addr, now));
        Ok(())
    }

    #[test]
    fn prefix_owner_win_keeps_unrelated_peer_requests() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let loser = test_source(healthy_addr());
        let unrelated = test_source(peer_addr(2));
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[loser], now);
        insert_pending(&mut window, unrelated, hash(9), 9, now);
        insert_pending(&mut window, loser, hash(10), 10, now);

        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(owner), now);
        }

        assert_eq!(window.preferred_peer(), Some(owner));
        assert!(window.contains_pending(&hash(9)));
        assert!(window.pending_count_for(owner) > 0);
        assert!(window.pending_count_for(unrelated) > 0);
        assert!(!window.contains_pending(&hash(10)));
        assert_eq!(window.pending_count_for(loser), 0);
        assert!(!window.peer_in_staller_cooldown(owner.addr, now));
        Ok(())
    }

    #[test]
    fn prefix_alternate_win_releases_only_probe_losers() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let winner = test_source(healthy_addr());
        let loser = test_source(peer_addr(2));
        let unrelated = test_source(peer_addr(3));
        let mut window = DownloadWindow::new(stall_budget());
        for height in 1..=8_u8 {
            insert_pending(&mut window, owner, hash(height), u32::from(height), now);
        }
        let (planned_owner, hashes, _) = window
            .prefix_probe_plan()
            .ok_or_else(|| std::io::Error::other("missing probe plan"))?;
        window.confirm_prefix_probe(planned_owner, hashes, &[winner, loser], now);
        insert_pending(&mut window, unrelated, hash(9), 9, now);
        insert_pending(&mut window, loser, hash(10), 10, now);

        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(winner), now);
        }

        assert_eq!(window.preferred_peer(), Some(winner));
        for byte in 5..=8_u8 {
            assert!(!window.contains_pending(&hash(byte)));
        }
        assert!(window.contains_pending(&hash(9)));
        assert!(!window.contains_pending(&hash(10)));
        assert_eq!(window.pending_count_for(owner), 0);
        assert_eq!(window.pending_count_for(loser), 0);
        assert!(window.pending_count_for(unrelated) > 0);
        assert_eq!(window.next_request_height, 1);
        assert!(window.owner_downloading_since.contains_key(&unrelated));
        assert!(window.peer_in_staller_cooldown(owner.addr, now));
        Ok(())
    }

    #[test]
    fn stale_cold_hedge_confirmation_after_release_does_not_blame_replacement() {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let alternate = test_source(healthy_addr());
        let front = hash(0x51);
        let mut window = DownloadWindow::new(stall_budget());
        insert_pending(&mut window, owner, front, 1, now);
        assert_eq!(cold_front_owner(&mut window, 1, false, now), None);

        window.retain_owned_by(|p| *p != owner);
        window.confirm_cold_front_hedge(owner, alternate, front);
        window.mark_received_from(front, 80, Some(alternate), now);

        assert!(window.cold_front.is_none());
        assert!(window.cold_hedged_fronts.is_empty());
        assert_eq!(window.preferred_peer(), None);
        assert!(!window.peer_in_staller_cooldown(owner.addr, now));
    }

    #[test]
    fn stale_prefix_confirmation_after_release_does_not_install_probe_or_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let mut window = DownloadWindow::new(test_budget());
        let win_blocks = u8::try_from(super::PREFIX_PROBE_WIN_BLOCKS)?;
        for byte in 1..=win_blocks {
            insert_pending(&mut window, owner, hash(byte), u32::from(byte), now);
        }
        let (planned_owner, hashes, _) = window.prefix_probe_plan().ok_or_else(|| {
            std::io::Error::other("contiguous owner should produce a prefix plan")
        })?;
        window.retain_owned_by(|p| *p != owner);
        window.confirm_prefix_probe(planned_owner, hashes, &[test_source(healthy_addr())], now);

        assert!(window.prefix_probe.is_none());
        assert!(window.prefix_probe_attempted_owner.is_none());
        Ok(())
    }

    #[test]
    fn release_of_a_dead_connection_clears_state_but_preserves_cooldown() {
        let mut window = DownloadWindow::new(test_budget());
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let now = Instant::now();
        let source = test_source(peer_addr);
        insert_pending(&mut window, source, hash(1), 1, now);
        window.preferred_peer = Some(source);
        window.mark_peer_unresponsive(peer_addr, now);

        window.retain_owned_by(|p| *p != source);

        assert_eq!(window.pending_count_for(source), 0);
        assert!(window.preferred_peer.is_none());
        assert!(window.peer_in_staller_cooldown(peer_addr, now));
    }

    /// (i) When the pending owner delivers a malformed body, `reject_delivery`
    /// releases the pending request so the block becomes re-requestable from a
    /// different peer. The pending slot and peer inflight are freed.
    #[test]
    fn reject_delivery_from_pending_owner_releases_pending() {
        let now = Instant::now();
        let owner = test_source(peer_addr(1));
        let block_hash = hash(0x42);
        let mut window = DownloadWindow::new(test_budget());
        insert_pending(&mut window, owner, block_hash, 100, now);
        assert!(window.contains_pending(&block_hash));
        assert_eq!(window.pending_len(), 1);

        let outcome = window.reject_delivery(block_hash, Some(owner), now);

        assert_eq!(outcome, super::RejectDelivery::ReleasedPending);
        assert!(!window.contains_pending(&block_hash));
        assert_eq!(window.pending_len(), 0);
        // next_request_height lowered so the block is re-requestable.
        assert!(window.next_request_height <= 100);
    }

    /// Rejecting the observed owner's response proves it was responsive, so a
    /// stale first-tick timeout observation must not convict it later.
    #[test]
    fn reject_delivery_from_owner_clears_timeout_observation() {
        let now = Instant::now();
        let owner = test_source(peer_addr(1));
        let block_hash = hash(0x42);
        let mut window = DownloadWindow::new(test_budget());
        insert_pending(&mut window, owner, block_hash, 100, now);
        window.pending_timeout_observation = Some(super::PendingTimeoutObservation {
            owner,
            hash: block_hash,
            expired_release: false,
        });

        assert_eq!(
            window.reject_delivery(block_hash, Some(owner), now),
            super::RejectDelivery::ReleasedPending
        );
        assert!(window.pending_timeout_observation.is_none());
        assert_eq!(timeout_owner(&mut window, false, now), None);
        assert!(!window.peer_in_staller_cooldown(owner.addr, now));
    }

    /// Either participant's malformed response terminates a cold-front race
    /// without electing a winner. If both copies are malformed, no stale
    /// `Racing` state remains and the owner's pending request is released.
    #[test]
    fn reject_delivery_cleans_cold_front_race_participants() {
        let now = Instant::now();
        let owner = test_source(peer_addr(1));
        let alternate = test_source(peer_addr(2));
        let block_hash = hash(0x42);
        let mut window = DownloadWindow::new(test_budget());
        insert_pending(&mut window, owner, block_hash, 100, now);
        window.cold_front = Some(super::ColdFrontState::Racing {
            owner,
            alternate,
            hash: block_hash,
        });

        assert_eq!(
            window.reject_delivery(block_hash, Some(alternate), now),
            super::RejectDelivery::DiscardedUnsolicited
        );
        assert!(window.cold_front.is_none());
        assert!(window.contains_pending(&block_hash));
        let retry_started = now + Duration::from_secs(3);
        assert_eq!(
            cold_front_owner(&mut window, 100, false, retry_started),
            None
        );
        assert_eq!(
            cold_front_owner(
                &mut window,
                100,
                false,
                retry_started + Duration::from_secs(2)
            ),
            Some((owner.addr, block_hash))
        );

        assert_eq!(
            window.reject_delivery(block_hash, Some(owner), now),
            super::RejectDelivery::ReleasedPending
        );
        assert!(window.cold_front.is_none());
        assert!(!window.contains_pending(&block_hash));
    }

    /// An unrelated malformed delivery cannot cancel another peer's timeout
    /// observation or cold-front race.
    #[test]
    fn reject_delivery_from_unrelated_peer_preserves_observations() {
        let now = Instant::now();
        let owner = test_source(peer_addr(1));
        let alternate = test_source(peer_addr(2));
        let unrelated = test_source(peer_addr(3));
        let block_hash = hash(0x42);
        let mut window = DownloadWindow::new(test_budget());
        insert_pending(&mut window, owner, block_hash, 100, now);
        window.pending_timeout_observation = Some(super::PendingTimeoutObservation {
            owner,
            hash: block_hash,
            expired_release: false,
        });
        window.cold_front = Some(super::ColdFrontState::Racing {
            owner,
            alternate,
            hash: block_hash,
        });

        assert_eq!(
            window.reject_delivery(block_hash, Some(unrelated), now),
            super::RejectDelivery::DiscardedUnsolicited
        );
        assert!(window.pending_timeout_observation.is_some());
        assert!(matches!(
            window.cold_front,
            Some(super::ColdFrontState::Racing { .. })
        ));
        assert!(window.contains_pending(&block_hash));
    }

    /// (ii) When a peer other than the pending owner delivers a malformed body
    /// unsolicited, `reject_delivery` discards the body and preserves the
    /// existing pending request — the original owner may still supply the
    /// correct body.
    #[test]
    fn reject_delivery_from_different_peer_preserves_pending() {
        let now = Instant::now();
        let owner = test_source(peer_addr(1));
        let other = test_source(peer_addr(2));
        let block_hash = hash(0x42);
        let mut window = DownloadWindow::new(test_budget());
        insert_pending(&mut window, owner, block_hash, 100, now);
        assert!(window.contains_pending(&block_hash));
        assert_eq!(window.pending_len(), 1);

        let outcome = window.reject_delivery(block_hash, Some(other), now);

        assert_eq!(outcome, super::RejectDelivery::DiscardedUnsolicited);
        assert!(window.contains_pending(&block_hash));
        assert_eq!(window.pending_len(), 1);
        // next_request_height unchanged — the pending is still in flight.
        assert_eq!(window.next_request_height, 1);
    }

    /// `reject_delivery` with no source peer (local injection) preserves any
    /// existing pending — a local injection cannot prove it was the owner.
    #[test]
    fn reject_delivery_with_no_source_preserves_pending() {
        let now = Instant::now();
        let owner = test_source(peer_addr(1));
        let block_hash = hash(0x42);
        let mut window = DownloadWindow::new(test_budget());
        insert_pending(&mut window, owner, block_hash, 100, now);

        let outcome = window.reject_delivery(block_hash, None, now);

        assert_eq!(outcome, super::RejectDelivery::DiscardedUnsolicited);
        assert!(window.contains_pending(&block_hash));
    }

    /// `reject_delivery` with no pending is a no-op (`DiscardedUnsolicited`).
    #[test]
    fn reject_delivery_with_no_pending_is_noop() {
        let mut window = DownloadWindow::new(test_budget());
        let block_hash = hash(0x99);

        let outcome =
            window.reject_delivery(block_hash, Some(test_source(peer_addr(1))), Instant::now());

        assert_eq!(outcome, super::RejectDelivery::DiscardedUnsolicited);
        assert_eq!(window.pending_len(), 0);
    }

    // --- Apply-side suppression bound (#1091) -------------------------------

    /// `start + (bound - secs)`, expressed without `Instant - Duration` or
    /// `unwrap` so the pedantic lints stay clean in tests.
    fn just_below(start: Instant, bound: Duration, secs: u64) -> Instant {
        let Some(delta) = bound.checked_sub(Duration::from_secs(secs)) else {
            unreachable!("test bounds always exceed the shaved amount");
        };
        start + delta
    }

    #[test]
    fn apply_side_bound_holds_below_two_received_timeouts() {
        let mut window = DownloadWindow::new(test_budget());
        let stager = test_stager(&window);
        let tree = test_tree();
        let start = Instant::now();
        // test_budget received_timeout is 30s, so the bound is 60s.
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);

        // Stuck at the same frontier (height, hash): observations prime and
        // advance the clock, but nothing fires below the bound.
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), true, start),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                just_below(start, bound, 1)
            ),
            None
        );
        // The no-blame suppression itself is unchanged below the bound.
        assert_eq!(
            stall_owner(
                &mut window,
                &stager,
                &tree,
                7,
                true,
                just_below(start, bound, 1)
            ),
            None
        );
    }

    #[test]
    fn apply_side_bound_fires_and_rearms_at_two_received_timeouts() {
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);
        let _ = apply_side_bound(&mut window, 7, Some(frontier), true, start);

        let fired = apply_side_bound(&mut window, 7, Some(frontier), true, start + bound);
        assert_eq!(fired, Some(bound));
        // Re-armed: the next stuck observation does not immediately re-fire,
        // so a persistently stuck frontier escalates once per bound, not
        // once per tick.
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                start + bound + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                start + bound.saturating_mul(2) + Duration::from_secs(1)
            ),
            Some(bound + Duration::from_secs(1))
        );
    }

    #[test]
    fn apply_side_bound_survives_prune_refetch_seams() {
        // The #1091 sawtooth: the staged-body prune expires the stuck body,
        // the re-request re-delivers it, and the fresh insert re-stamps its
        // received_at — so per-body age never convicts and apply_side_busy
        // flickers off for a seam. The stuck clock keys on the frontier
        // (height, hash) and must accumulate across that seam.
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);
        let _ = apply_side_bound(&mut window, 7, Some(frontier), true, start);

        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                just_below(start, bound, 10)
            ),
            None
        );
        // The prune seam: the body is briefly absent (unbusy), then the
        // refetched copy is staged again.
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                false,
                just_below(start, bound, 9)
            ),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                start + bound + Duration::from_secs(1)
            ),
            Some(bound + Duration::from_secs(1))
        );
    }

    #[test]
    fn apply_side_bound_resets_on_front_advance() {
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);
        let _ = apply_side_bound(&mut window, 7, Some(frontier), true, start);
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                just_below(start, bound, 1)
            ),
            None
        );

        // The frontier applies and advances: conviction clears and the new
        // stuck height starts its own full bound.
        let moved = start + bound + Duration::from_secs(1);
        let advanced = hash(0x08);
        assert_eq!(
            apply_side_bound(&mut window, 8, Some(advanced), true, moved),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                8,
                Some(advanced),
                true,
                just_below(moved, bound, 1)
            ),
            None
        );
        assert_eq!(
            apply_side_bound(&mut window, 8, Some(advanced), true, moved + bound),
            Some(bound)
        );
    }

    #[test]
    fn apply_side_bound_never_runs_on_idle_frontier_before_first_delivery() {
        // The episode used to start before the busy check, so a frontier
        // that simply took longer than the bound to deliver its first body
        // had that delivery evicted on arrival. The stuck clock may only
        // run while a body is actually staged.
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);

        // Idle (nothing staged) far past the bound: no episode, no clock.
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), false, start),
            None
        );
        let delivered = start + bound + Duration::from_secs(10);
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), false, delivered),
            None
        );

        // The first normal delivery arrives: the clock starts here and must
        // hold a full bound before any escalation.
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), true, delivered),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(frontier),
                true,
                just_below(delivered, bound, 1)
            ),
            None
        );
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), true, delivered + bound),
            Some(bound)
        );
    }

    #[test]
    fn apply_side_bound_resets_on_same_height_frontier_replacement() {
        // A same-height branch replacement swaps the expected body: the new
        // branch's fresh delivery must not be evicted on the old branch's
        // inherited stuck time.
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let branch_a = hash(0xA1);
        let branch_b = hash(0xB2);

        // Branch A nearly exhausted its bound.
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(branch_a), true, start),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(branch_a),
                true,
                just_below(start, bound, 1)
            ),
            None
        );

        // Same height, different frontier body: a fresh episode.
        let moved = start + bound + Duration::from_secs(1);
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(branch_b), true, moved),
            None
        );
        assert_eq!(
            apply_side_bound(
                &mut window,
                7,
                Some(branch_b),
                true,
                just_below(moved, bound, 1)
            ),
            None
        );
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(branch_b), true, moved + bound),
            Some(bound)
        );
    }

    fn test_budget() -> SyncBudget {
        SyncBudget {
            max_pending_blocks: 128,
            block_spacing: Duration::from_mins(10),
            max_pending_bytes: usize::MAX,
            max_received_blocks: 128,
            max_received_bytes: usize::MAX,
            max_peer_inflight: 128,
            // Fan-out disengaged: these unit tests pin the legacy single-mode
            // mechanics where `max_peer_inflight` is always the binding cap.
            fanout_peer_inflight: 128,
            min_peers_for_fanout: usize::MAX,
            getdata_batch_limit: 16,
            received_timeout: Duration::from_secs(30),
            stall_timeout_initial: Duration::from_secs(2),
            stall_timeout_max: Duration::from_secs(64),
            staller_cooldown: Duration::from_secs(64),
            pending_timeout_override: None,
        }
        .with_pending_timeout_override(Duration::from_secs(30))
    }

    /// The hash of the height-`byte` header of [`TEST_CHAIN`].
    fn hash(byte: u8) -> Hash256 {
        Hash256::from(TEST_CHAIN[usize::from(byte)].compute_hash())
    }

    #[test]
    fn owned_fetch_preserves_prefix_probe_attempted_owner() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let stall_owner = super::PeerSource::for_test(staller_addr());
        let compact_peer = super::PeerSource::for_test(healthy_addr());
        window.prefix_probe_attempted_owner = Some(stall_owner);

        // An externally owned fetch on an empty window is not a post-drain
        // request: the marker must survive so the proven-stall owner stays
        // ineligible for the next prefix probe.
        window.mark_owned_fetch(&mut test_stager(&window), compact_peer, hash(0xf1), 7, now);
        assert_eq!(window.prefix_probe_attempted_owner, Some(stall_owner));
        assert!(window.contains_pending(&hash(0xf1)));

        // A real post-drain request still re-arms probe eligibility.
        window.remove_pending(&hash(0xf1), now);
        let request = super::non_empty_request(
            compact_peer,
            vec![super::PeerRequestEntry {
                hash: hash(0xf2),
                height: 8,
            }],
            9,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        window.mark_requested(&test_stager(&window), &request, compact_peer, now);
        assert!(window.prefix_probe_attempted_owner.is_none());
    }

    #[test]
    fn owned_fetch_respects_window_capacity_and_frontier() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 1,
            ..test_budget()
        });
        let now = Instant::now();
        let owner = super::PeerSource::for_test(healthy_addr());

        // The first mark lands; the second exceeds the pending budget a
        // real request would face, so it is not recorded — the compact
        // fetch still resolves delivery by hash either way.
        window.mark_owned_fetch(&mut test_stager(&window), owner, hash(0xa1), 9, now);
        assert!(window.contains_pending(&hash(0xa1)));
        window.mark_owned_fetch(&mut test_stager(&window), owner, hash(0xa2), 10, now);
        assert!(!window.contains_pending(&hash(0xa2)));

        // Below the request frontier a mark could never be scheduled
        // anyway — and its expiry would drag `next_request_height` back
        // down into a re-request sweep of heights already applied.
        let mut window = DownloadWindow::new(test_budget());
        let request = super::non_empty_request(
            owner,
            vec![super::PeerRequestEntry {
                hash: hash(0xb0),
                height: 10,
            }],
            11,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        window.mark_requested(&test_stager(&window), &request, owner, now);
        window.mark_owned_fetch(&mut test_stager(&window), owner, hash(0xb1), 3, now);
        assert!(!window.contains_pending(&hash(0xb1)));
        assert_eq!(window.next_request_height, 11);
    }
}
