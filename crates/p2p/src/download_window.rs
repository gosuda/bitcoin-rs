//! Block download window, peer-assignment, stall, and scheduling policy.
//!
//! This module owns the download-side policy that decides which blocks to
//! request from which peers, how to detect and recover from stalls, and how
//! to manage the in-flight window budget. [`crate::BlockStager`] owns the
//! matching inbound staging set. The node sync coordinator drives these
//! types; it does not own the policy.
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

use crate::BlockStager;
use crate::connection::PeerSource;

mod policy;

pub use policy::*;

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
        servable_floor: u32,
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

        let mut entries = self.expired_request_entries(
            stager,
            expired,
            batch_limit,
            servable_floor,
            &mut byte_capacity,
        );
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
            let previous_height = self.next_request_height;
            self.next_request_height = request_start_height;
            tracing::debug!(
                previous_height,
                request_start_height,
                "block sync: rewound unowned request frontier"
            );
        }
        // `servable_floor` keeps a limited peer's batch inside its retained
        // window: `serves_requested_height` certified only the first height
        // at selection time.
        let height = request_start_height
            .max(self.next_request_height)
            .max(servable_floor);
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

    pub(crate) fn retarget_request_branch(
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
        servable_floor: u32,
        byte_capacity: &mut usize,
    ) -> Vec<PeerRequestEntry> {
        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || *byte_capacity < self.ewma_block_bytes {
                break;
            }
            // Below the peer's retained window the entry is unservable for
            // it: leave it unowned so another peer's scan picks it up.
            if entry.height < servable_floor
                || stager.contains(&entry.hash)
                || self.pending.contains_key(&entry.hash)
            {
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
                tracing::info!(
                    owner = %owner.addr,
                    winner = %alternate.addr,
                    %hash,
                    "block sync: cold-front hedge elected alternate"
                );
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
mod tests;
