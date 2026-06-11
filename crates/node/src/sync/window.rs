use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

#[derive(Clone, Copy, Debug)]
pub(super) struct SyncBudget {
    pub(super) max_pending_blocks: usize,
    pub(super) max_pending_bytes: usize,
    pub(super) max_received_blocks: usize,
    pub(super) max_received_bytes: usize,
    pub(super) max_peer_inflight: usize,
    pub(super) fanout_peer_inflight: usize,
    pub(super) min_peers_for_fanout: usize,
    pub(super) getdata_batch_limit: usize,
    pub(super) pending_timeout: Duration,
    pub(super) received_timeout: Duration,
    pub(super) stall_timeout_initial: Duration,
    pub(super) stall_timeout_max: Duration,
    pub(super) staller_cooldown: Duration,
}

#[derive(Clone, Debug)]
pub(super) struct PeerRequest {
    peer_addr: SocketAddr,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
}

impl PeerRequest {
    pub(super) fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = (u32, Hash256)> + '_ {
        self.entries.iter().map(|entry| (entry.height, entry.hash))
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
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
    peer_addr: SocketAddr,
    requested_at: Instant,
    height: u32,
    estimated_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerInflight {
    blocks: usize,
}

/// A running window-blocked stall observation: the window front (`front_hash`)
/// has been in flight to `peer_addr` with the apply frontier idle and no other
/// download progress possible since `since`. The analog of Bitcoin Core's
/// per-peer `m_stalling_since` (`net_processing.cpp`).
#[derive(Clone, Copy, Debug)]
struct StallEpisode {
    peer_addr: SocketAddr,
    front_hash: Hash256,
    since: Instant,
    /// Whether the one-shot episode-observability INFO line has been emitted
    /// for this episode (fires once when the episode survives
    /// [`STALL_EPISODE_LOG_AGE`]; see [`DownloadWindow::observe_stall`]).
    info_logged: bool,
}

/// Episode age at which the one-shot stall-episode observability INFO line is
/// emitted. Below the 2s conviction floor by design: the line exists to make
/// episode dynamics visible in run logs *below* the WARN fire line — which
/// clearing rule zeroed the clock, and what the front-cadence EWMA (the
/// threshold's falsifier) was while the episode ran.
const STALL_EPISODE_LOG_AGE: Duration = Duration::from_secs(1);

/// Stall-episode clearing reasons, the counter taxonomy for
/// `node.sync.stall_episodes_cleared{reason}`. Every path that zeroes the
/// episode clock tags exactly one reason:
/// - `apply_busy`: the no-blame guard held this tick ([`DownloadWindow::observe_stall`]).
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

#[derive(Debug)]
pub(super) struct DownloadWindow {
    budget: SyncBudget,
    pending: HashMap<Hash256, PendingBlock>,
    received: HashMap<Hash256, ReceivedBlock>,
    peer_inflight: HashMap<SocketAddr, PeerInflight>,
    pending_bytes: usize,
    received_bytes: usize,
    ewma_block_bytes: usize,
    next_request_height: u32,
    next_pending_deadline: Option<Instant>,
    /// Whether block requests currently fan out across peers. Driven by the
    /// sync layer's per-tick count of fan-out-eligible peers (KTD6 predicate:
    /// outbound, witness-serving, header chain above ours, not soft-demoted)
    /// through [`Self::set_fanout_eligible_peers`]'s one-peer hysteresis.
    /// Starts disengaged so a fresh window always begins in single-peer
    /// fallback.
    fanout_engaged: bool,
    /// Current window-blocked stall observation, if any (R8). Re-derived from
    /// the predicate every [`Self::observe_stall`] call; cleared whenever any
    /// predicate term stops holding, so a transient stall never accumulates
    /// blame across unrelated episodes.
    stall: Option<StallEpisode>,
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
    /// (silent while others stream) still convicts at ~2g. Two guards keep
    /// the estimate honest: same-chunk batch arrivals (samples under
    /// [`EWMA_MIN_SAMPLE_MS`]) are skipped so an in-order burst sharing one
    /// chunk timestamp cannot deflate the floor, and while no sample exists
    /// at all (cold start) [`Self::observe_stall`] suppresses conviction
    /// entirely, deferring to the 60s pending-timeout fallback.
    front_interval_ewma_ms: Option<u64>,
    /// When the window front last advanced (a front block arrived); the
    /// anchor for the next `front_interval_ewma_ms` sample.
    last_front_advance: Option<Instant>,
    /// Peers disconnected for stalling, by fire time. While inside
    /// `staller_cooldown` such a peer is not fan-out eligible and receives no
    /// block requests except as the last-resort peer — the re-acquisition
    /// guard for a staller that immediately reconnects on the same address.
    recent_stallers: HashMap<SocketAddr, Instant>,
}

#[derive(Clone, Copy, Debug)]
struct ReceivedBlock {
    height: u32,
    bytes: usize,
}

impl DownloadWindow {
    pub(super) fn new(budget: SyncBudget) -> Self {
        Self {
            budget,
            pending: HashMap::with_capacity(budget.max_pending_blocks),
            received: HashMap::with_capacity(budget.max_received_blocks),
            peer_inflight: HashMap::with_capacity(
                budget.max_pending_blocks.min(budget.max_peer_inflight),
            ),
            pending_bytes: 0,
            received_bytes: 0,
            ewma_block_bytes: 256 * 1024,
            next_request_height: 1,
            next_pending_deadline: None,
            fanout_engaged: false,
            stall: None,
            stall_timeout: budget.stall_timeout_initial,
            front_interval_ewma_ms: None,
            last_front_advance: None,
            recent_stallers: HashMap::new(),
        }
    }

    /// Records how many peers currently satisfy the fan-out eligibility
    /// predicate and updates the fan-out engagement with one-peer hysteresis:
    /// engage at `min_peers_for_fanout`, hold at one below, disengage only
    /// further down.
    ///
    /// The count keeps KTD6's demotion clause (a stalled peer must not count
    /// toward fan-out), so without hysteresis a single transient soft-demotion
    /// at the threshold would flap the mode tick-to-tick and re-concentrate
    /// the whole window on one deep peer mid-stripe. Holding the mode one
    /// peer below the threshold instead costs at most one undistributed
    /// stripe (`fanout_peer_inflight` blocks) until the demotion clears or a
    /// second peer drops out — at which point the drop is structural and the
    /// single-peer fallback is the right mode.
    pub(super) fn set_fanout_eligible_peers(&mut self, count: usize) {
        if count >= self.budget.min_peers_for_fanout {
            self.fanout_engaged = true;
        } else if count.saturating_add(1) < self.budget.min_peers_for_fanout {
            self.fanout_engaged = false;
        }
    }

    /// Whether block requests fan out across peers (true) or collapse to the
    /// single-peer deep window (false). Fan-out engages only when enough
    /// eligible peers exist to fill the window at the shallow per-peer cap
    /// (with [`Self::set_fanout_eligible_peers`]'s hysteresis); below that
    /// the per-peer cap reverts to the deep fallback so one healthy peer can
    /// fill the whole window (no under-fill regression).
    pub(super) const fn fanout_active(&self) -> bool {
        self.fanout_engaged
    }

    /// Per-peer in-flight cap for the current mode: the shallow fan-out cap
    /// (Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER` shape) when fan-out is active,
    /// the deep fallback cap otherwise. The fan-out cap never exceeds the
    /// fallback cap, so injected shallow budgets stay binding in either mode.
    const fn effective_peer_inflight(&self) -> usize {
        if self.fanout_active() && self.budget.fanout_peer_inflight < self.budget.max_peer_inflight
        {
            self.budget.fanout_peer_inflight
        } else {
            self.budget.max_peer_inflight
        }
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Maximum number of blocks the download window will keep pending at once.
    ///
    /// Used as the horizon cap when the apply-side cache is repopulated on a
    /// miss: at most this many blocks can be in flight (and therefore stage)
    /// before the cache's validity keys change and force a refresh.
    pub(super) const fn max_pending_blocks(&self) -> usize {
        self.budget.max_pending_blocks
    }

    pub(super) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub(super) fn has_request_capacity(&self) -> bool {
        self.pending.len() < self.budget.max_pending_blocks
            && self.pending_bytes.saturating_add(self.ewma_block_bytes)
                <= self.budget.max_pending_bytes
            && self.staged_byte_headroom() >= self.ewma_block_bytes
            && self.staged_count_headroom(0) > 0
    }

    /// Staged-byte backpressure: once the blocks already received and waiting
    /// to apply have consumed the staging byte budget, stop issuing new block
    /// requests — arrivals would only be refused by the stager and
    /// re-requested, churning bandwidth. Capacity returns as staged blocks are
    /// applied (or expire) and their bytes are released.
    const fn staged_bytes_exhausted(&self) -> bool {
        self.received_bytes >= self.budget.max_received_bytes
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
    const fn staged_byte_headroom(&self) -> usize {
        if self.received_bytes == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_bytes
            .saturating_sub(self.received_bytes)
            .saturating_sub(self.pending_bytes)
    }

    /// Staging slots still free if every in-flight pending block arrives: the
    /// count-denominated twin of [`Self::staged_byte_headroom`]. The twin is
    /// load-bearing, not symmetry for its own sake: the stager enforces its
    /// byte budget as admission backpressure but its count budget by
    /// **evicting the oldest staged blocks** (`stage.rs`,
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
    fn staged_count_headroom(&self, expired_pending_blocks: usize) -> usize {
        if self.received.is_empty() {
            return usize::MAX;
        }
        self.budget
            .max_received_blocks
            .saturating_sub(self.received.len())
            .saturating_sub(self.pending.len().saturating_sub(expired_pending_blocks))
    }

    pub(super) fn request_peer_scan_limit(&self, now: Instant) -> usize {
        if self.staged_bytes_exhausted() {
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
            .min(self.staged_count_headroom(expired_blocks));
        // Expired bytes are credited back to pending capacity (they will be
        // re-requested) but not to staging byte headroom: a late arrival of
        // the original request still stages. The count headroom does credit
        // them — see `staged_count_headroom` for why the wedge needs it.
        let byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes.saturating_sub(expired_bytes))
            .min(self.staged_byte_headroom())
            / self.ewma_block_bytes;
        let request_blocks = block_capacity.min(byte_capacity);
        if request_blocks == 0 {
            return 0;
        }
        request_blocks
            .div_ceil(per_peer)
            .saturating_add(self.peer_inflight.len())
    }

    fn expired_pending_capacity(&self, now: Instant) -> (usize, usize) {
        if self
            .next_pending_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return (0, 0);
        }
        self.pending
            .values()
            .fold((0_usize, 0_usize), |(blocks, bytes), pending| {
                if now.duration_since(pending.requested_at) < self.budget.pending_timeout {
                    return (blocks, bytes);
                }
                (
                    blocks.saturating_add(1),
                    bytes.saturating_add(pending.estimated_bytes),
                )
            })
    }

    /// Whether `peer_addr` owns a pending block past the re-request timeout —
    /// the soft-demotion signal: such a peer gets no new front-of-window
    /// requests unless it is the last-resort peer, and it does not count as
    /// fan-out-eligible (KTD6's "not currently soft-demoted" clause).
    pub(super) fn peer_has_expired_pending(&self, peer_addr: SocketAddr, now: Instant) -> bool {
        if self
            .next_pending_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return false;
        }
        self.pending.values().any(|pending| {
            pending.peer_addr == peer_addr
                && now.duration_since(pending.requested_at) >= self.budget.pending_timeout
        })
    }

    /// Advances the window-blocked stall state machine one observation (R8).
    ///
    /// Inputs computed by the sync layer each tick, after the apply drain:
    /// - `next_apply_height`: `applied_tip.height + 1`, the apply frontier.
    /// - `apply_side_busy`: the no-blame guard — true while the stager holds
    ///   the next expected block (apply lag / failed-apply restore). Our own
    ///   slowness must never be blamed on a peer, so the stall clock does not
    ///   run at all.
    ///
    /// Deliberately *not* an input: a chain-tail arm ("nothing above the
    /// window left to request"). At the tip, one >2s block from a caught-up
    /// peer is the normal regime, not a stall — Core's stalling logic does
    /// not engage there either, and the last <window blocks of IBD stay
    /// covered by the pre-existing 60s pending-timeout machinery.
    ///
    /// Returns `Some(peer)` exactly when the stall threshold fires: the
    /// caller must disconnect that peer (its pendings then re-queue through
    /// `release_disconnected_peers`). On fire the adaptive threshold doubles
    /// (capped at `stall_timeout_max`) and the peer enters the staller
    /// cooldown. When any predicate term stops holding — including any
    /// delivery from the blamed peer ([`Self::record_delivery_progress`]) —
    /// the episode is cleared, more forgiving than freezing the clock and
    /// Core-shaped (`m_stalling_since` is likewise re-derived, never frozen).
    pub(super) fn observe_stall(
        &mut self,
        next_apply_height: u32,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<SocketAddr> {
        let staller_cooldown = self.budget.staller_cooldown;
        self.recent_stallers
            .retain(|_, fired_at| now.duration_since(*fired_at) < staller_cooldown);
        if apply_side_busy {
            if self.stall.take().is_some() {
                count_stall_episode_cleared("apply_busy");
            }
            return None;
        }
        let Some((peer_addr, front_hash)) = self.window_blocked_on(next_apply_height) else {
            if self.stall.take().is_some() {
                count_stall_episode_cleared("predicate");
            }
            return None;
        };
        let episode = match self.stall {
            Some(episode) if episode.peer_addr == peer_addr && episode.front_hash == front_hash => {
                episode
            }
            previous => {
                if previous.is_some() {
                    // Predicate still holds but for a different
                    // (peer, front_hash): the front advanced (or rotated
                    // owner) and the episode re-keyed.
                    count_stall_episode_cleared("front_moved");
                }
                metrics::counter!("node.sync.stall_episodes_started").increment(1);
                let episode = StallEpisode {
                    peer_addr,
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
        // appear in run logs. Emitted regardless of EWMA cold start: a
        // suppressed-conviction episode is exactly what must be observable.
        let effective_timeout = self.stall_timeout.max(self.stall_decay_floor());
        if !episode.info_logged && now.duration_since(episode.since) >= STALL_EPISODE_LOG_AGE {
            if let Some(stored) = self.stall.as_mut() {
                stored.info_logged = true;
            }
            tracing::info!(
                peer_addr = %episode.peer_addr,
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
        // Cold start: while the front-cadence EWMA has no sample the decay
        // floor cannot distinguish a slow network from a staller, so
        // conviction defers to the 60s pending-timeout fallback — the
        // pre-U7 status quo. The episode above still forms so the stall
        // stays observable (`stalling_peer`, the stall_seconds gauge); only
        // the fire is suppressed until the estimate has one real sample.
        self.front_interval_ewma_ms?;
        // The fire threshold (`effective_timeout` above) is the stored
        // adaptive value, never below the ADV-DRIP-1 decay floor: on a
        // network whose demonstrated front cadence exceeds
        // `stall_timeout_initial`, an episode younger than twice that
        // cadence is the uniform-slow steady state, not a stall.
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
        self.recent_stallers.insert(peer_addr, now);
        Some(peer_addr)
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
    ///   holds only because of two qualifications: same-chunk batch
    ///   arrivals are filtered out of the EWMA (sub-[`EWMA_MIN_SAMPLE_MS`]
    ///   samples share one chunk timestamp and would otherwise deflate the
    ///   floor back to the static 2s), and a cold-start window (no sample
    ///   yet) does not trust the floor at all — [`Self::observe_stall`]
    ///   suppresses conviction and defers to the 60s pending-timeout
    ///   fallback until the cadence estimate has one real sample.
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
    /// in-flight front block is why. All terms derive from window state:
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
    ///    arm of this term — see [`Self::observe_stall`].
    fn window_blocked_on(&self, next_apply_height: u32) -> Option<(SocketAddr, Hash256)> {
        let (front_hash, front) = self
            .pending
            .iter()
            .min_by_key(|(_, pending)| pending.height)?;
        if front.height != next_apply_height {
            return None;
        }
        if !self
            .received
            .values()
            .any(|received| received.height > front.height)
        {
            return None;
        }
        if self.received.len() < self.budget.max_received_blocks / 2 {
            return None;
        }
        Some((front.peer_addr, *front_hash))
    }

    /// Current stall observation, if one is running: the blamed peer and when
    /// the episode started. The R10 slow-trickle observability surface — a
    /// peer delivering each front block just under the adaptive threshold is
    /// never disconnected (same exposure as Core) but is visible here and on
    /// the `node.sync.stall_seconds` gauge.
    pub(super) fn stalling_peer(&self) -> Option<(SocketAddr, Instant)> {
        self.stall.map(|episode| (episode.peer_addr, episode.since))
    }

    /// Current adaptive stalling threshold (2s doubling to 64s).
    #[cfg(test)]
    pub(super) const fn stall_timeout(&self) -> Duration {
        self.stall_timeout
    }

    /// Whether `peer_addr` was disconnected for stalling within the cooldown.
    /// Such a peer is not fan-out eligible and gets no block requests unless
    /// it is the last-resort peer — without this, a staller reconnecting on
    /// the same address immediately re-acquires the window front and restarts
    /// the cycle (the RE-ADV-2 recurrence).
    pub(super) fn peer_in_staller_cooldown(&self, peer_addr: SocketAddr, now: Instant) -> bool {
        self.recent_stallers
            .get(&peer_addr)
            .is_some_and(|fired_at| now.duration_since(*fired_at) < self.budget.staller_cooldown)
    }

    #[cfg(test)]
    pub(super) fn received_len(&self) -> usize {
        self.received.len()
    }

    #[cfg(test)]
    pub(super) fn contains_pending(&self, hash: &Hash256) -> bool {
        self.pending.contains_key(hash)
    }

    fn pending_deadline(&self, requested_at: Instant) -> Instant {
        requested_at
            .checked_add(self.budget.pending_timeout)
            .unwrap_or(requested_at)
    }

    fn record_pending_deadline(&mut self, requested_at: Instant) {
        let deadline = self.pending_deadline(requested_at);
        if self
            .next_pending_deadline
            .is_none_or(|current| deadline < current)
        {
            self.next_pending_deadline = Some(deadline);
        }
    }

    fn refresh_next_pending_deadline(&mut self) {
        self.next_pending_deadline = self
            .pending
            .values()
            .map(|pending| self.pending_deadline(pending.requested_at))
            .min();
    }

    pub(super) fn release_disconnected_peers(
        &mut self,
        mut is_live_peer: impl FnMut(&SocketAddr) -> bool,
    ) {
        let mut retry_height = self.next_request_height;
        let mut removed_earliest_deadline = false;
        let pending_timeout = self.budget.pending_timeout;
        let next_pending_deadline = self.next_pending_deadline;
        self.pending.retain(|_hash, pending| {
            if is_live_peer(&pending.peer_addr) {
                return true;
            }
            retry_height = retry_height.min(pending.height);
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
            let deadline = pending
                .requested_at
                .checked_add(pending_timeout)
                .unwrap_or(pending.requested_at);
            if Some(deadline) == next_pending_deadline {
                removed_earliest_deadline = true;
            }
            false
        });
        self.peer_inflight
            .retain(|peer, _inflight| is_live_peer(peer));
        if removed_earliest_deadline {
            self.refresh_next_pending_deadline();
        }
        self.next_request_height = retry_height;
    }

    pub(super) fn next_peer_request(
        &mut self,
        peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
        peer_best_height: u32,
        tree: &BlockTree,
        now: Instant,
    ) -> Option<PeerRequest> {
        if self.staged_bytes_exhausted() {
            return None;
        }
        if !allow_expired_retry_from_peer
            && (self.peer_has_expired_pending(peer_addr, now)
                || self.peer_in_staller_cooldown(peer_addr, now))
        {
            return None;
        }
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let peer_inflight = self
            .peer_inflight
            .get(&peer_addr)
            .map_or(0, |inflight| inflight.blocks);
        let peer_capacity = self.effective_peer_inflight().saturating_sub(peer_inflight);
        // Expiry already ran above, so the count headroom needs no expired
        // credit here: `pending` reflects only live in-flight requests.
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len())
            .min(self.staged_count_headroom(0));
        let mut byte_capacity = self
            .budget
            .max_pending_bytes
            .saturating_sub(self.pending_bytes)
            .min(self.staged_byte_headroom());
        let batch_limit = self
            .budget
            .getdata_batch_limit
            .min(peer_capacity)
            .min(block_capacity);
        if batch_limit == 0 || byte_capacity < self.ewma_block_bytes {
            return None;
        }

        let mut entries = self.expired_request_entries(expired, batch_limit, &mut byte_capacity);
        let selected_hashes = SelectedHashes::from_entries(&entries);

        let Some(mut height) = applied_tip.height.checked_add(1) else {
            return non_empty_request(peer_addr, entries, self.next_request_height);
        };
        height = height.max(self.next_request_height);
        let mut next_request_height = self.next_request_height;
        let request_tip_height = chain_tip.height.min(peer_best_height);
        let remaining_limit = batch_limit
            .saturating_sub(entries.len())
            .min(byte_capacity / self.ewma_block_bytes);
        if height <= request_tip_height && remaining_limit > 0 {
            if entries.is_empty() {
                if let Some(request) = self.clean_contiguous_peer_request(
                    peer_addr,
                    chain_tip,
                    tree,
                    height,
                    request_tip_height,
                    remaining_limit,
                    next_request_height,
                ) {
                    return Some(request);
                }
            }

            next_request_height = self.extend_request_by_reverse_scan(
                chain_tip,
                tree,
                RequestScan {
                    height,
                    request_tip_height,
                    remaining_limit,
                    next_request_height,
                },
                selected_hashes.as_ref(),
                &mut entries,
            );
        }
        non_empty_request(peer_addr, entries, next_request_height)
    }

    fn extend_request_by_reverse_scan(
        &self,
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
            .saturating_add(self.received.len())
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
                && !self.received.contains_key(&node.hash)
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
        expired: Vec<PeerRequestEntry>,
        batch_limit: usize,
        byte_capacity: &mut usize,
    ) -> Vec<PeerRequestEntry> {
        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || *byte_capacity < self.ewma_block_bytes {
                break;
            }
            if self.received.contains_key(&entry.hash) || self.pending.contains_key(&entry.hash) {
                continue;
            }
            *byte_capacity = byte_capacity.saturating_sub(self.ewma_block_bytes);
            entries.push(entry);
        }
        entries
    }

    fn clean_contiguous_peer_request(
        &self,
        peer_addr: SocketAddr,
        chain_tip: &TipSnapshot,
        tree: &BlockTree,
        height: u32,
        request_tip_height: u32,
        remaining_limit: usize,
        next_request_height: u32,
    ) -> Option<PeerRequest> {
        if !self.pending.is_empty() || !self.received.is_empty() {
            return None;
        }
        let request_end_height = height
            .saturating_add(u32::try_from(remaining_limit.saturating_sub(1)).unwrap_or(u32::MAX))
            .min(request_tip_height);
        let entries =
            contiguous_request_entries(tree, chain_tip.tip_id, height, request_end_height)?;
        let next_request_height = next_request_height.max(request_end_height.saturating_add(1));
        non_empty_request(peer_addr, entries, next_request_height)
    }

    pub(super) fn mark_requested(&mut self, request: &PeerRequest, now: Instant) -> bool {
        let estimated_bytes = self.ewma_block_bytes;
        let inflight = self.peer_inflight.entry(request.peer_addr).or_default();
        for entry in &request.entries {
            debug_assert!(!self.pending.contains_key(&entry.hash));
            debug_assert!(!self.received.contains_key(&entry.hash));
            let previous = self.pending.insert(
                entry.hash,
                PendingBlock {
                    peer_addr: request.peer_addr,
                    requested_at: now,
                    height: entry.height,
                    estimated_bytes,
                },
            );
            debug_assert!(previous.is_none());
            self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);
            inflight.blocks = inflight.blocks.saturating_add(1);
        }
        if !request.entries.is_empty() {
            self.record_pending_deadline(now);
        }
        self.next_request_height = self.next_request_height.max(request.next_request_height);
        self.has_request_capacity()
    }

    pub(super) fn mark_received(&mut self, hash: Hash256, bytes: usize, now: Instant) -> bool {
        let (height, needs_height_lookup) = if let Some(pending) = self.remove_pending(&hash) {
            self.record_delivery_progress(pending.peer_addr, hash, pending.height, now);
            (pending.height, false)
        } else {
            (0, true)
        };
        let previous = self.received.insert(hash, ReceivedBlock { height, bytes });
        if let Some(previous) = previous {
            self.received_bytes = self.received_bytes.saturating_sub(previous.bytes);
        }
        self.received_bytes = self.received_bytes.saturating_add(bytes);
        self.ewma_block_bytes = self
            .ewma_block_bytes
            .saturating_mul(7)
            .saturating_add(bytes)
            / 8;
        self.ewma_block_bytes = self.ewma_block_bytes.max(80);
        needs_height_lookup
    }

    /// Delivery progress for the stall state machine, charged per peer
    /// (Core's `RemoveBlockRequest`: "this peer delivered, so it's not
    /// stalling"). Called after `hash` was removed from `pending`.
    ///
    /// Any requested block arriving from the episode peer clears the running
    /// episode, so blame accumulates only against a peer that delivers
    /// *nothing* while owning the front and others stream past it. In the
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
        peer_addr: SocketAddr,
        hash: Hash256,
        height: u32,
        now: Instant,
    ) {
        if self
            .stall
            .is_some_and(|episode| episode.peer_addr == peer_addr || episode.front_hash == hash)
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
    #[cfg(test)]
    pub(super) const fn front_interval_ewma_ms(&self) -> Option<u64> {
        self.front_interval_ewma_ms
    }

    /// Test-only cold-start disarm: installs a front-cadence estimate as if
    /// the network had demonstrated `ewma_ms` with its last front advance at
    /// `now`. Sync-layer tests whose fixtures never advance the window front
    /// (the recorded wedge constructions) use this instead of replaying two
    /// real front deliveries; the real sampling path is pinned by the window
    /// tests.
    #[cfg(test)]
    pub(super) const fn seed_front_cadence_for_test(&mut self, ewma_ms: u64, now: Instant) {
        self.front_interval_ewma_ms = Some(ewma_ms);
        self.last_front_advance = Some(now);
    }

    pub(super) fn update_received_height(&mut self, hash: &Hash256, height: u32) {
        if let Some(received) = self.received.get_mut(hash) {
            received.height = height;
        }
    }

    #[cfg(test)]
    pub(super) fn mark_applied(&mut self, hash: &Hash256) {
        self.mark_received_applied(hash);
        self.remove_pending(hash);
    }

    pub(super) fn mark_received_applied(&mut self, hash: &Hash256) {
        self.remove_received(hash);
    }

    pub(super) fn drop_received_for_retry(&mut self, hash: &Hash256) {
        if let Some(received) = self.remove_received(hash) {
            self.next_request_height = self.next_request_height.min(received.height);
        }
    }

    pub(super) fn drop_for_retry(&mut self, hash: &Hash256) {
        self.drop_received_for_retry(hash);
        if let Some(pending) = self.remove_pending(hash) {
            self.next_request_height = self.next_request_height.min(pending.height);
        }
    }

    fn expire_pending(&mut self, now: Instant) -> Vec<PeerRequestEntry> {
        if self
            .next_pending_deadline
            .is_none_or(|deadline| now < deadline)
        {
            return Vec::new();
        }
        let pending_timeout = self.budget.pending_timeout;
        let mut entries = Vec::new();
        {
            let peer_inflight = &mut self.peer_inflight;
            let pending_bytes = &mut self.pending_bytes;
            let next_request_height = &mut self.next_request_height;
            for (hash, pending) in self.pending.extract_if(|_hash, pending| {
                now.duration_since(pending.requested_at) >= pending_timeout
            }) {
                *pending_bytes = pending_bytes.saturating_sub(pending.estimated_bytes);
                release_peer_block(peer_inflight, pending.peer_addr);
                *next_request_height = (*next_request_height).min(pending.height);
                entries.push(PeerRequestEntry {
                    hash,
                    height: pending.height,
                });
            }
        }
        self.refresh_next_pending_deadline();
        entries
    }

    fn remove_received(&mut self, hash: &Hash256) -> Option<ReceivedBlock> {
        let received = self.received.remove(hash)?;
        self.received_bytes = self.received_bytes.saturating_sub(received.bytes);
        Some(received)
    }

    fn remove_pending(&mut self, hash: &Hash256) -> Option<PendingBlock> {
        let pending = self.pending.remove(hash)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
        self.release_peer_block(pending.peer_addr);
        if Some(self.pending_deadline(pending.requested_at)) == self.next_pending_deadline {
            self.refresh_next_pending_deadline();
        }
        Some(pending)
    }

    fn release_peer_block(&mut self, peer_addr: SocketAddr) {
        release_peer_block(&mut self.peer_inflight, peer_addr);
    }
}

fn release_peer_block(
    peer_inflight: &mut HashMap<SocketAddr, PeerInflight>,
    peer_addr: SocketAddr,
) {
    let Some(inflight) = peer_inflight.get_mut(&peer_addr) else {
        return;
    };
    inflight.blocks = inflight.blocks.saturating_sub(1);
    if inflight.blocks == 0 {
        peer_inflight.remove(&peer_addr);
    }
}

fn non_empty_request(
    peer_addr: SocketAddr,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
) -> Option<PeerRequest> {
    (!entries.is_empty()).then_some(PeerRequest {
        peer_addr,
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

    use super::{DownloadWindow, SyncBudget};

    #[test]
    fn request_peer_scan_limit_accounts_for_pending_bytes_and_inflight_peers() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 8,
            max_pending_bytes: 4 * 256 * 1024,
            max_peer_inflight: 2,
            getdata_batch_limit: 4,
            ..test_budget()
        });
        window.pending_bytes = 256 * 1024;
        window.peer_inflight.insert(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            super::PeerInflight { blocks: 2 },
        );

        assert_eq!(window.request_peer_scan_limit(Instant::now()), 3);
    }

    #[test]
    fn request_peer_scan_limit_counts_expired_pending_capacity() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 2,
            max_pending_bytes: 2 * 256 * 1024,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            ..test_budget()
        });
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        for (byte, height) in [(1, 1_u32), (2, 2)] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    peer_addr,
                    requested_at: now,
                    height,
                    estimated_bytes: 256 * 1024,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(256 * 1024);
        }
        window.next_pending_deadline = Some(now);
        window
            .peer_inflight
            .insert(peer_addr, super::PeerInflight { blocks: 2 });

        assert_eq!(window.request_peer_scan_limit(now), 2);
    }

    #[test]
    fn default_budget_keeps_full_request_window_for_large_blocks() {
        let mut window = DownloadWindow::new(crate::sync::default_sync_budget());
        window.ewma_block_bytes = 2 * 1024 * 1024;
        window.pending_bytes = window
            .budget
            .max_pending_blocks
            .saturating_sub(1)
            .saturating_mul(window.ewma_block_bytes);

        assert!(window.has_request_capacity());
    }

    #[test]
    fn release_disconnected_peers_refreshes_pending_deadline() {
        let mut window = DownloadWindow::new(SyncBudget {
            pending_timeout: Duration::from_secs(10),
            ..test_budget()
        });
        let now = Instant::now();
        let stale_peer = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let live_peer = std::net::SocketAddr::from(([127, 0, 0, 2], 8333));
        let stale_requested_at = now
            .checked_sub(Duration::from_secs(9))
            .unwrap_or_else(|| panic!("test instant underflow"));
        let estimated_bytes = 256 * 1024;
        for (peer_addr, requested_at, height, byte) in [
            (stale_peer, stale_requested_at, 1_u32, 0x81),
            (live_peer, now, 2_u32, 0x82),
        ] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    peer_addr,
                    requested_at,
                    height,
                    estimated_bytes,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(estimated_bytes);
            window.record_pending_deadline(requested_at);
        }

        window.release_disconnected_peers(|peer| *peer == live_peer);

        assert_eq!(window.pending_len(), 1);
        assert_eq!(window.pending_bytes(), estimated_bytes);
        assert_eq!(window.next_request_height, 1);
        assert_eq!(
            window.next_pending_deadline,
            Some(now + Duration::from_secs(10))
        );
    }

    #[test]
    fn mark_received_refreshes_pending_deadline_after_earliest_pending() {
        let mut window = DownloadWindow::new(SyncBudget {
            pending_timeout: Duration::from_secs(10),
            ..test_budget()
        });
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
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
                    peer_addr,
                    requested_at,
                    height,
                    estimated_bytes,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(estimated_bytes);
            window.record_pending_deadline(requested_at);
        }
        window
            .peer_inflight
            .insert(peer_addr, super::PeerInflight { blocks: 2 });

        let needs_height_lookup = window.mark_received(earliest, 80, now);

        assert!(!needs_height_lookup);
        assert_eq!(window.pending_len(), 1);
        assert!(window.contains_pending(&later));
        assert_eq!(
            window.next_pending_deadline,
            Some(now + Duration::from_secs(10))
        );
    }

    #[test]
    fn mark_received_applied_removes_only_received_accounting() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        let applied = hash(0xa1);
        let pending = hash(0xa2);
        let pending_bytes = 256 * 1024;
        let received_bytes = 80;
        window.pending.insert(
            pending,
            super::PendingBlock {
                peer_addr,
                requested_at: now,
                height: 2,
                estimated_bytes: pending_bytes,
            },
        );
        window.pending_bytes = pending_bytes;
        window.received.insert(
            applied,
            super::ReceivedBlock {
                height: 1,
                bytes: received_bytes,
            },
        );
        window.received_bytes = received_bytes;

        window.mark_received_applied(&applied);

        assert_eq!(window.received_len(), 0);
        assert_eq!(window.received_bytes, 0);
        assert_eq!(window.pending_len(), 1);
        assert!(window.contains_pending(&pending));
        assert_eq!(window.pending_bytes(), pending_bytes);
    }

    #[test]
    fn staged_byte_exhaustion_stops_new_requests_until_applied() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_received_bytes: 100,
            ..test_budget()
        });
        let staged = hash(0xb1);
        assert!(window.has_request_capacity());
        assert_ne!(window.request_peer_scan_limit(Instant::now()), 0);

        window.mark_received(staged, 100, Instant::now());

        // Staged bytes at the budget: stop issuing new block requests instead
        // of letting arrivals bounce off the exhausted stager.
        assert!(!window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 0);

        window.mark_received_applied(&staged);

        // Applying the staged block releases its bytes and reopens the window.
        assert!(window.has_request_capacity());
        assert_ne!(window.request_peer_scan_limit(Instant::now()), 0);
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
        let now = Instant::now();

        // Below the threshold: single-peer deep window — one peer can take
        // the full 128, so only one peer needs scanning.
        window.set_fanout_eligible_peers(7);
        assert!(!window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(now), 1);

        // At the threshold: shallow per-peer cap engages and the scan fans
        // out to enough peers to fill the window (128 / 16 = 8).
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(now), 8);
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
        for byte in [0xc1, 0xc2, 0xc3] {
            window.mark_received(hash(byte), slot, Instant::now());
        }

        assert!(window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 1);

        // The fourth staged block consumes the last slot: headroom hits zero
        // and request capacity closes before any eviction can happen.
        window.mark_received(hash(0xc4), slot, Instant::now());
        assert!(!window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 0);
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
        for byte in [0xd1, 0xd2, 0xd3] {
            window.mark_received(hash(byte), 80, Instant::now());
        }

        assert!(window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 1);

        // The fourth staged block consumes the last slot: count headroom hits
        // zero and requests stop — overflow becomes request backpressure
        // before the stager's count budget could ever evict.
        window.mark_received(hash(0xd4), 80, Instant::now());
        assert!(!window.has_request_capacity());
        assert_eq!(window.request_peer_scan_limit(Instant::now()), 0);
    }

    #[test]
    fn expired_pendings_reopen_scan_limit_through_count_headroom() {
        // Count wedge: staged (2) + pending (2) at the count budget (4), with
        // the pendings held by a stalled peer. While the pendings are live
        // the scan limit must be zero; once they pass the re-request timeout
        // the credit must reopen the scan limit so the request path can
        // expire and re-request the front (otherwise the wedge can only be
        // broken by pruning every staged block into re-download).
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 4,
            max_received_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            pending_timeout: Duration::from_secs(10),
            ..test_budget()
        });
        let now = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333));
        for (byte, height) in [(0xe1, 1_u32), (0xe2, 2)] {
            window.pending.insert(
                hash(byte),
                super::PendingBlock {
                    peer_addr,
                    requested_at: now,
                    height,
                    estimated_bytes: 256 * 1024,
                },
            );
            window.pending_bytes = window.pending_bytes.saturating_add(256 * 1024);
            window.record_pending_deadline(now);
        }
        window
            .peer_inflight
            .insert(peer_addr, super::PeerInflight { blocks: 2 });
        for byte in [0xe3, 0xe4] {
            window.mark_received(hash(byte), 80, now);
        }

        assert_eq!(window.request_peer_scan_limit(now), 0);

        let after_timeout = now + Duration::from_secs(10);
        assert_ne!(window.request_peer_scan_limit(after_timeout), 0);
    }

    #[test]
    fn fanout_engagement_has_one_peer_hysteresis() {
        let mut window = DownloadWindow::new(SyncBudget {
            min_peers_for_fanout: 8,
            ..test_budget()
        });

        // Fresh window: disengaged until the threshold is reached.
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());

        // One transient demotion at the threshold must not flap the mode.
        window.set_fanout_eligible_peers(7);
        assert!(window.fanout_active());
        window.set_fanout_eligible_peers(8);
        assert!(window.fanout_active());

        // A second peer dropping out is structural: disengage, and stay
        // disengaged at one-below until the full threshold returns.
        window.set_fanout_eligible_peers(6);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8);
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
        peer_addr: std::net::SocketAddr,
        block_hash: Hash256,
        height: u32,
        now: Instant,
    ) {
        window.pending.insert(
            block_hash,
            super::PendingBlock {
                peer_addr,
                requested_at: now,
                height,
                estimated_bytes: 80,
            },
        );
        window.pending_bytes = window.pending_bytes.saturating_add(80);
        window.record_pending_deadline(now);
        let inflight = window.peer_inflight.entry(peer_addr).or_default();
        inflight.blocks = inflight.blocks.saturating_add(1);
    }

    /// Seeds the front-cadence EWMA through the real delivery path: heights
    /// 1 and 2 arrive from `peer` `gap` apart (must be >=
    /// `EWMA_MIN_SAMPLE_MS` or the second advance is skipped as a batch
    /// artifact) and apply immediately. Disarms `observe_stall`'s cold-start
    /// fire suppression and returns the instant of the second front advance
    /// — the anchor for the next interval sample.
    fn seed_front_cadence(
        window: &mut DownloadWindow,
        peer: std::net::SocketAddr,
        t0: Instant,
        gap: Duration,
    ) -> Instant {
        insert_pending(window, peer, hash(0x01), 1, t0);
        window.mark_received(hash(0x01), 80, t0);
        window.mark_applied(&hash(0x01));
        let t1 = t0 + gap;
        insert_pending(window, peer, hash(0x02), 2, t1);
        window.mark_received(hash(0x02), 80, t1);
        window.mark_applied(&hash(0x02));
        t1
    }

    /// A fully window-blocked construction with a seeded front-cadence EWMA:
    /// heights 1-2 first seed the EWMA at a 100ms cadence (the decay floor
    /// stays clamped at the static `stall_timeout_initial`, so the fire
    /// arithmetic matches a fast network while the cold-start suppression is
    /// disarmed), then the front (height 3) is in flight to `staller` while
    /// `healthy` delivered heights 4..=6, leaving zero staged-count headroom
    /// — every stall-predicate term holds. Returns the window and the
    /// construction instant (100ms after `t0`); observe with
    /// `next_apply_height` 3.
    fn window_blocked_on_staller(
        staller: std::net::SocketAddr,
        healthy: std::net::SocketAddr,
        t0: Instant,
    ) -> (DownloadWindow, Instant) {
        let mut window = DownloadWindow::new(stall_budget());
        let t1 = seed_front_cadence(&mut window, healthy, t0, Duration::from_millis(100));
        assert_eq!(window.front_interval_ewma_ms(), Some(100));
        insert_pending(&mut window, staller, hash(0x03), 3, t1);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5), (0x06, 6)] {
            insert_pending(&mut window, healthy, hash(byte), height, t1);
            window.mark_received(hash(byte), 80, t1);
        }
        (window, t1)
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
        insert_pending(&mut window, staller_addr(), hash(0x01), 1, now);

        assert_eq!(window.observe_stall(1, false, now), None);
        assert_eq!(
            window.observe_stall(1, false, now + Duration::from_mins(1)),
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
        insert_pending(&mut window, staller_addr(), hash(0x02), 2, now);
        for (byte, height) in [(0x03_u8, 3_u32), (0x04, 4), (0x05, 5)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, now);
            window.mark_received(hash(byte), 80, now);
        }

        assert_eq!(window.observe_stall(1, false, now), None);
        assert_eq!(
            window.observe_stall(1, false, now + Duration::from_mins(1)),
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
        insert_pending(&mut window, staller_addr(), hash(0x01), 1, now);
        insert_pending(&mut window, healthy_addr(), hash(0x02), 2, now);
        window.mark_received(hash(0x02), 80, now);
        assert!(window.has_request_capacity());

        assert_eq!(window.observe_stall(1, false, now), None);
        assert!(window.stalling_peer().is_none());

        // Chain-tail decision (ADV-2): this same state at the header tip
        // (nothing above the window left to request) must NOT arm the clock
        // either — a caught-up peer taking >2s on one tip block is the
        // normal tip regime, owned by the 60s pending-timeout machinery.
        // Below the staged fraction the predicate stays false no matter how
        // much time passes.
        assert_eq!(
            window.observe_stall(1, false, now + Duration::from_mins(1)),
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
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, staller_addr(), hash(0x03), 3, now);
        // Exactly half the 4-slot staged window (2 blocks) above the front.
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, now);
            window.mark_received(hash(byte), 80, now);
        }
        assert!(
            window.has_request_capacity(),
            "the construction must keep request capacity open: arming no longer reads it"
        );

        // U7 no-blame guard, under the new arming term: while the apply
        // side is busy the armed-shaped window must not start an episode.
        assert_eq!(window.observe_stall(3, true, now), None);
        assert!(window.stalling_peer().is_none());

        // Apply idle: the staged fraction arms, and the unchanged
        // conviction clock fires at the unchanged threshold.
        assert_eq!(window.observe_stall(3, false, now), None);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));
        assert!(window.has_request_capacity());
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(2)),
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
            let now = seed_front_cadence(
                &mut window,
                healthy_addr(),
                Instant::now(),
                Duration::from_millis(100),
            );
            insert_pending(&mut window, staller_addr(), hash(0x03), 3, now);
            let half = depth / 2;
            // One below the fraction: no episode, no matter the depth.
            for offset in 0..half - 1 {
                let byte = u8::try_from(4 + offset).unwrap_or_else(|_| panic!("height fits u8"));
                insert_pending(
                    &mut window,
                    healthy_addr(),
                    hash(byte),
                    u32::from(byte),
                    now,
                );
                window.mark_received(hash(byte), 80, now);
            }
            assert!(window.has_request_capacity());
            assert_eq!(window.observe_stall(3, false, now), None);
            assert!(
                window.stalling_peer().is_none(),
                "one below half the window must not arm (depth {depth})"
            );

            // At the fraction: the episode arms.
            let byte = u8::try_from(4 + half - 1).unwrap_or_else(|_| panic!("height fits u8"));
            insert_pending(
                &mut window,
                healthy_addr(),
                hash(byte),
                u32::from(byte),
                now,
            );
            window.mark_received(hash(byte), 80, now);
            assert!(window.has_request_capacity());
            assert_eq!(window.observe_stall(3, false, now), None);
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
            max_received_bytes: 4 * 80,
            ..stall_budget()
        });
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, staller_addr(), hash(0x03), 3, now);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5), (0x06, 6), (0x07, 7)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, now);
            window.mark_received(hash(byte), 80, now);
        }
        assert!(
            !window.has_request_capacity(),
            "the staged-byte clamp must close request capacity (the old arming trigger)"
        );

        assert_eq!(window.observe_stall(3, false, now), None);
        assert!(window.stalling_peer().is_none());
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_mins(1)),
            None,
            "capacity-closed below the staged fraction must never arm"
        );
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn stall_fires_after_threshold_and_starts_cooldown() {
        let (mut window, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());

        // Episode starts on first observation; no fire before the threshold.
        assert_eq!(window.observe_stall(3, false, now), None);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(1)),
            None
        );

        let fired = window.observe_stall(3, false, now + Duration::from_secs(2));

        assert_eq!(fired, Some(staller_addr()));
        assert!(window.stalling_peer().is_none());
        assert!(window.peer_in_staller_cooldown(staller_addr(), now + Duration::from_secs(2)));
        assert!(!window.peer_in_staller_cooldown(healthy_addr(), now + Duration::from_secs(2)));
        // Cooldown expires after `staller_cooldown`.
        assert!(!window.peer_in_staller_cooldown(staller_addr(), now + Duration::from_secs(33)));
    }

    #[test]
    fn stall_timeout_doubles_per_fire_caps_and_decays_on_front_arrival() {
        let (mut window, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));

        // Fire 1 at +2s: threshold doubles to 4s.
        window.observe_stall(3, false, now);
        let mut at = now + Duration::from_secs(2);
        assert_eq!(window.observe_stall(3, false, at), Some(staller_addr()));
        assert_eq!(window.stall_timeout(), Duration::from_secs(4));

        // The window state still satisfies the predicate (the disconnect and
        // re-queue are the sync layer's job), so a fresh episode starts and
        // must now survive the doubled threshold: fire 2 doubles to the 8s
        // cap, fire 3 stays capped.
        window.observe_stall(3, false, at);
        at += Duration::from_secs(4);
        assert_eq!(window.observe_stall(3, false, at), Some(staller_addr()));
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));
        window.observe_stall(3, false, at);
        at += Duration::from_secs(8);
        assert_eq!(window.observe_stall(3, false, at), Some(staller_addr()));
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
        window.observe_stall(3, false, at);
        window.mark_received(hash(0x03), 80, at);
        assert_eq!(window.front_interval_ewma_ms(), Some(3575));
        assert_eq!(window.stall_timeout(), Duration::from_millis(7150));
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn successor_arrival_does_not_reset_stall_clock() {
        // Mid-window deliveries are data progress but not front progress: the
        // episode keeps running and fires on schedule. Heights 1-2 seed the
        // cadence EWMA first (cold start would otherwise defer the fire to
        // the pending-timeout fallback); the 100ms cadence keeps the decay
        // floor at the static 2s.
        let mut window = DownloadWindow::new(stall_budget());
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, staller_addr(), hash(0x03), 3, now);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, now);
            window.mark_received(hash(byte), 80, now);
        }
        insert_pending(&mut window, healthy_addr(), hash(0x06), 6, now);

        window.observe_stall(3, false, now);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));

        window.mark_received(hash(0x06), 80, now + Duration::from_secs(1));

        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(2)),
            Some(staller_addr())
        );
    }

    #[test]
    fn no_blame_guard_keeps_stall_clock_idle_while_apply_side_is_busy() {
        let (mut window, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());

        // With the apply side busy the clock never runs, no matter how long
        // the state persists.
        assert_eq!(window.observe_stall(3, true, now), None);
        assert!(window.stalling_peer().is_none());
        let later = now + Duration::from_mins(1);
        assert_eq!(window.observe_stall(3, true, later), None);
        assert!(window.stalling_peer().is_none());

        // Once the apply side drains, blame starts from scratch — the busy
        // interval is never retroactively charged to the peer.
        assert_eq!(window.observe_stall(3, false, later), None);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), later)));
        assert_eq!(
            window.observe_stall(3, false, later + Duration::from_secs(1)),
            None
        );
        assert_eq!(
            window.observe_stall(3, false, later + Duration::from_secs(2)),
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
            let (mut window, now) =
                window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());

            // No running episode: the guard paths must not count a clear.
            assert_eq!(window.observe_stall(3, true, now), None);
            assert_eq!(window.observe_stall(4, false, now), None);
            assert_eq!(recorder.cleared("apply_busy"), 0);
            assert_eq!(recorder.cleared("predicate"), 0);
            assert_eq!(recorder.started(), 0);

            // apply_busy: a running episode cleared by the no-blame guard.
            assert_eq!(window.observe_stall(3, false, now), None);
            assert_eq!(recorder.started(), 1);
            assert_eq!(window.observe_stall(3, true, now), None);
            assert_eq!(recorder.cleared("apply_busy"), 1);

            // predicate: re-arm, then a predicate term goes false (the
            // frontier moves past the pending front, so term 1 fails).
            assert_eq!(window.observe_stall(3, false, now), None);
            assert_eq!(recorder.started(), 2);
            assert_eq!(window.observe_stall(4, false, now), None);
            assert_eq!(recorder.cleared("predicate"), 1);

            // front_moved: re-arm, then re-key the front to another peer at
            // the same frontier while every predicate term still holds — the
            // old episode clears as front_moved and a new one starts.
            assert_eq!(window.observe_stall(3, false, now), None);
            assert_eq!(recorder.started(), 3);
            window.remove_pending(&hash(0x03));
            insert_pending(&mut window, healthy_addr(), hash(0x07), 3, now);
            assert_eq!(window.observe_stall(3, false, now), None);
            assert_eq!(recorder.cleared("front_moved"), 1);
            assert_eq!(recorder.started(), 4);

            // peer_delivery: the blamed peer (now `healthy`, owning the
            // re-keyed front) delivers a requested block.
            window.mark_received(hash(0x07), 80, now + Duration::from_millis(100));
            assert_eq!(recorder.cleared("peer_delivery"), 1);

            // fired: a fresh construction runs an episode to conviction.
            let (mut window, now) =
                window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
            assert_eq!(window.observe_stall(3, false, now), None);
            assert_eq!(recorder.started(), 5);
            assert_eq!(
                window.observe_stall(3, false, now + Duration::from_secs(2)),
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
    /// `observe_stall` emits the INFO line in exactly the branch that flips
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
        let (mut window, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());

        // Below the 1s log age: episode running, nothing emitted.
        assert_eq!(window.observe_stall(3, false, now), None);
        assert_eq!(info_logged(&window), Some(false));
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_millis(500)),
            None
        );
        assert_eq!(info_logged(&window), Some(false));

        // Past 1s: the latch flips on the emitting tick and stays latched —
        // one line, no matter how many further ticks the episode survives.
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(1)),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_millis(1500)),
            None
        );
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_millis(1900)),
            None
        );
        assert_eq!(info_logged(&window), Some(true));

        // Fire ends the episode; the replacement episode (judged against the
        // doubled threshold) carries a fresh latch and re-emits once at 1s.
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(2)),
            Some(staller_addr())
        );
        assert_eq!(info_logged(&window), None);
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(2)),
            None
        );
        assert_eq!(info_logged(&window), Some(false));
        assert_eq!(
            window.observe_stall(3, false, now + Duration::from_secs(4)),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
    }

    /// Cold start (front-cadence EWMA unseeded): conviction is suppressed
    /// but the episode still forms and the observability line still fires —
    /// a suppressed-conviction episode is exactly what must be visible in
    /// run logs (the `front_interval_ewma_ms=None` shape).
    #[test]
    fn stall_episode_logs_info_during_ewma_cold_start_without_firing() {
        let now = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        insert_pending(&mut window, staller_addr(), hash(0x01), 1, now);
        for (byte, height) in [(0x02_u8, 2_u32), (0x03, 3), (0x04, 4)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, now);
            window.mark_received(hash(byte), 80, now);
        }
        assert_eq!(window.front_interval_ewma_ms(), None);

        assert_eq!(window.observe_stall(1, false, now), None);
        assert_eq!(info_logged(&window), Some(false));
        // The episode ages far past every threshold: the INFO latch flips at
        // 1s, but cold-start suppression keeps the fire from ever happening.
        assert_eq!(
            window.observe_stall(1, false, now + Duration::from_secs(1)),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
        assert_eq!(
            window.observe_stall(1, false, now + Duration::from_mins(1)),
            None
        );
        assert_eq!(info_logged(&window), Some(true));
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

        // Pre-seed: the network has already demonstrated its 3s front
        // cadence — two front advances 3s apart seed the interval EWMA at
        // 3000ms and lift the decay floor to 2x3s = 6s before the saturated
        // rounds begin. An unseeded window cannot fire at all (cold-start
        // conviction is suppressed and deferred to the pending-timeout
        // fallback — `cold_start_unseeded_ewma_never_fires_and_defers_to_
        // fallback`), and in real IBD the EWMA has tracked the cadence since
        // the first two blocks of the session anyway, long before blocks
        // grow past one threshold of transfer time.
        insert_pending(&mut window, peer_addr(0), hash(0x01), 1, t0);
        window.mark_received(hash(0x01), 80, t0);
        window.mark_applied(&hash(0x01));
        let t1 = t0 + Duration::from_secs(3);
        insert_pending(&mut window, peer_addr(0), hash(0x02), 2, t1);
        window.mark_received(hash(0x02), 80, t1);
        window.mark_applied(&hash(0x02));
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
                    peer_addr(peer),
                    hash(height),
                    u32::from(height),
                    t1,
                );
            }
        }
        // Nothing staged yet: download-bound, no episode regardless of time.
        assert_eq!(window.observe_stall(3, false, t1), None);

        for round in 0..3u8 {
            let at = t1 + Duration::from_secs(3) * (u32::from(round) + 1);
            for peer in 0..8u8 {
                // Highest remaining block of the stripe first: the front
                // (height 3, peer 0) arrives only in the last round.
                let height = peer * 3 + 5 - round;
                window.mark_received(hash(height), 80, at);
            }
            assert_eq!(
                window.observe_stall(3, false, at),
                None,
                "a streaming peer must never fire (round {round})"
            );
            // ADV-DRIP-1 mid-gap wake, 2s into the 3s gap between the front
            // owner's deliveries: the saturated fan-out predicate holds and
            // the episode is 2s old — past the static 2s floor (the
            // pre-fix drip fired exactly here) but under the 6s adaptive
            // floor.
            assert_eq!(
                window.observe_stall(3, false, at + Duration::from_secs(2)),
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
        insert_pending(&mut window, peer_addr(0), hash(27), 27, end);
        insert_pending(&mut window, peer_addr(1), hash(28), 28, end);
        window.mark_received(hash(28), 80, end);
        assert_eq!(window.observe_stall(27, false, end), None);
        assert_eq!(
            window.stalling_peer().map(|(addr, _)| addr),
            Some(peer_addr(0))
        );
        assert_eq!(
            window.observe_stall(27, false, end + Duration::from_secs(7)),
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
        // the cadence EWMA first (cold start would otherwise defer the fire
        // to the pending-timeout fallback); the 100ms cadence keeps the
        // decay floor at the static 2s.
        let mut window = DownloadWindow::new(stall_budget());
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
        insert_pending(&mut window, staller_addr(), hash(0x03), 3, now);
        insert_pending(&mut window, staller_addr(), hash(0x06), 6, now);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, now);
            window.mark_received(hash(byte), 80, now);
        }

        assert_eq!(window.observe_stall(3, false, now), None);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), now)));

        // The episode peer delivers its mid-window block at +1.5s: progress,
        // episode cleared (and no threshold decay — not the front).
        window.mark_received(hash(0x06), 80, now + Duration::from_millis(1500));
        assert!(window.stalling_peer().is_none());
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));

        // +2.5s (past the original episode's threshold): blame restarts from
        // the delivery, no fire.
        let restarted = now + Duration::from_millis(2500);
        assert_eq!(window.observe_stall(3, false, restarted), None);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), restarted)));

        // No deliveries for a full threshold after that: a true staller now,
        // and it fires.
        assert_eq!(
            window.observe_stall(3, false, restarted + Duration::from_secs(2)),
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
        let (mut window, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        assert_eq!(window.observe_stall(3, false, now), None);
        let fired_at = now + Duration::from_secs(2);
        assert_eq!(
            window.observe_stall(3, false, fired_at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(4));

        // Rotation: the sync layer drops the staller and re-queues the front
        // to the healthy peer, which delivers it. The 2s wedge gap is a real
        // sample: EWMA 100 -> 100 + (2000-100)/4 = 575ms, floor still 2s.
        window.release_disconnected_peers(|peer| *peer != staller_addr());
        insert_pending(&mut window, healthy_addr(), hash(0x03), 3, fired_at);
        window.mark_received(hash(0x03), 80, fired_at);
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
        insert_pending(&mut window, honest, hash(0x07), 7, fired_at);
        for (byte, height) in [(0x08_u8, 8_u32), (0x09, 9)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, fired_at);
            window.mark_received(hash(byte), 80, fired_at);
        }
        assert_eq!(window.observe_stall(7, false, fired_at), None);
        assert_eq!(
            window.observe_stall(7, false, fired_at + Duration::from_secs(3)),
            None,
            "a ~3s honest front owner must not fire while the threshold is elevated"
        );
        window.mark_received(hash(0x07), 80, fired_at);

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
            insert_pending(&mut window, honest, hash(byte), u32::from(byte), fired_at);
            window.mark_received(hash(byte), 80, fired_at);
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
        // The session's first two blocks seed the EWMA at the 3s cadence
        // (cold start no longer convicts at all — the fire suppression
        // defers an unseeded window to the pending-timeout fallback, pinned
        // by `cold_start_unseeded_ewma_never_fires_and_defers_to_fallback`),
        // so even the FIRST conviction is judged at the 6s adaptive floor.
        let (mut window, front, at, _silent) = limit_cycle_window_state();
        assert_eq!(window.front_interval_ewma_ms(), Some(3239));
        // No re-fire: the honest 3s owner must never cross the adaptive floor.
        assert_eq!(window.observe_stall(u32::from(front), false, at), None);
        assert_eq!(
            window.observe_stall(u32::from(front), false, at + Duration::from_secs(3)),
            None,
            "honest front owner must not fire after limit cycle stops"
        );
    }

    #[test]
    fn adaptive_floor_still_convicts_true_staller_after_limit_cycle() {
        // Companion to `stall_decay_limit_cycle_stops_at_adaptive_floor`:
        // once the decay floor stabilises at 2g, a genuinely silent peer that
        // holds the front must still convict at the elevated threshold.
        let (mut window, front, at, silent) = limit_cycle_window_state();

        // A true staller now owns the front: zero deliveries while the
        // healthy peer keeps streaming successors. The episode survives the
        // successor arrival (different peer, not the front hash) and convicts
        // at the adaptive ~2g threshold — 6.478s, far inside the 60s
        // pending-timeout fallback.
        assert_eq!(window.observe_stall(u32::from(front), false, at), None);
        insert_pending(
            &mut window,
            healthy_addr(),
            hash(front + 4),
            u32::from(front) + 4,
            at,
        );
        window.mark_received(hash(front + 4), 80, at + Duration::from_secs(2));
        assert_eq!(
            window.observe_stall(u32::from(front), false, at + Duration::from_secs(3)),
            None,
            "a true staller is judged at the adaptive floor, not the static 2s"
        );
        assert_eq!(
            window.observe_stall(u32::from(front), false, at + Duration::from_millis(6478)),
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
    /// adaptive floor. Returns `(window, front_height, now, silent_peer)`.
    fn limit_cycle_window_state() -> (DownloadWindow, u8, Instant, std::net::SocketAddr) {
        let mut window = DownloadWindow::new(stall_budget());
        let t1 = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_secs(3),
        );

        // First conviction: staller takes height 3 at the 6s adaptive floor.
        insert_pending(&mut window, staller_addr(), hash(0x03), 3, t1);
        for (byte, height) in [(0x04_u8, 4_u32), (0x05, 5), (0x06, 6)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, t1);
            window.mark_received(hash(byte), 80, t1);
        }
        assert_eq!(window.observe_stall(3, false, t1), None);
        assert_eq!(
            window.observe_stall(3, false, t1 + Duration::from_secs(3)),
            None,
            "one honest-cadence gap of blame must stay under the adaptive floor"
        );
        let fired_at = t1 + Duration::from_secs(6);
        assert_eq!(
            window.observe_stall(3, false, fired_at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));
        window.release_disconnected_peers(|peer| *peer != staller_addr());

        // Healthy peer resumes; four 3s cycles walk the EWMA back with the
        // decay clamped at the adaptive floor — the limit cycle never re-fires.
        insert_pending(&mut window, healthy_addr(), hash(0x03), 3, fired_at);
        window.mark_received(hash(0x03), 80, fired_at);
        for offset in 0..4u8 {
            window.mark_received_applied(&hash(3 + offset));
        }
        let silent = peer_addr(9);
        insert_pending(&mut window, healthy_addr(), hash(0x07), 7, fired_at);
        for offset in 1..4u8 {
            insert_pending(
                &mut window,
                healthy_addr(),
                hash(7 + offset),
                u32::from(7 + offset),
                fired_at,
            );
            window.mark_received(hash(7 + offset), 80, fired_at);
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
            assert_eq!(window.observe_stall(u32::from(front), false, at), None);
            assert_eq!(window.observe_stall(u32::from(front), false, arrive), None);
            window.mark_received(hash(front), 80, arrive);
            assert_eq!(
                window.stall_timeout(),
                expected_timeout,
                "the decay must stop at the adaptive floor, never re-crossing the 3s cadence"
            );
            for offset in 0..4u8 {
                window.mark_received_applied(&hash(front + offset));
            }
            let next_front = front + 4;
            let owner = if next_front == 23 {
                silent
            } else {
                healthy_addr()
            };
            insert_pending(
                &mut window,
                owner,
                hash(next_front),
                u32::from(next_front),
                arrive,
            );
            for offset in 1..4u8 {
                let height = next_front + offset;
                insert_pending(
                    &mut window,
                    healthy_addr(),
                    hash(height),
                    u32::from(height),
                    arrive,
                );
                window.mark_received(hash(height), 80, arrive);
            }
            front = next_front;
            at = arrive;
        }
        assert_eq!(window.front_interval_ewma_ms(), Some(3239));
        (window, front, at, silent)
    }

    #[test]
    fn cold_start_unseeded_ewma_never_fires_and_defers_to_fallback() {
        // Cold-start suppression: while the front-cadence EWMA has no sample
        // the decay floor cannot distinguish a slow network from a staller,
        // so `observe_stall` never convicts — conviction belongs to the 60s
        // pending-timeout fallback (the pre-U7 status quo) until the
        // estimate seeds. The episode still forms: the stall must stay
        // observable (gauge / `stalling_peer`) even while unconvictable.
        let t0 = Instant::now();
        let mut window = DownloadWindow::new(stall_budget());
        insert_pending(&mut window, staller_addr(), hash(0x01), 1, t0);
        for (byte, height) in [(0x02_u8, 2_u32), (0x03, 3), (0x04, 4)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, t0);
            window.mark_received(hash(byte), 80, t0);
        }
        assert_eq!(window.front_interval_ewma_ms(), None);

        assert_eq!(window.observe_stall(1, false, t0), None);
        assert_eq!(window.stalling_peer(), Some((staller_addr(), t0)));
        // Well past `stall_timeout_initial` (2s) — pre-fix this convicted.
        assert_eq!(
            window.observe_stall(1, false, t0 + Duration::from_secs(2)),
            None
        );
        assert_eq!(
            window.observe_stall(1, false, t0 + Duration::from_secs(30)),
            None,
            "an unseeded window must defer conviction to the pending-timeout fallback"
        );
        assert_eq!(window.stalling_peer(), Some((staller_addr(), t0)));
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));
        assert!(!window.peer_in_staller_cooldown(staller_addr(), t0 + Duration::from_secs(30)));

        // The wedge resolves (the front finally arrives — first advance,
        // anchor only) and a later front advance 3s after it seeds the EWMA:
        // the cadence estimate now exists and conviction re-arms.
        let t1 = t0 + Duration::from_secs(30);
        window.mark_received(hash(0x01), 80, t1);
        assert_eq!(window.front_interval_ewma_ms(), None);
        for byte in [0x01_u8, 0x02, 0x03, 0x04] {
            window.mark_received_applied(&hash(byte));
        }
        let t2 = t1 + Duration::from_secs(3);
        insert_pending(&mut window, healthy_addr(), hash(0x05), 5, t1);
        window.mark_received(hash(0x05), 80, t2);
        window.mark_received_applied(&hash(0x05));
        assert_eq!(window.front_interval_ewma_ms(), Some(3000));

        // A true staller (silent on the front while the healthy peer's
        // staged successors wait) now fires at the effective threshold —
        // the 6s adaptive floor (2x the demonstrated 3s cadence).
        let silent = peer_addr(9);
        insert_pending(&mut window, silent, hash(0x06), 6, t2);
        for (byte, height) in [(0x07_u8, 7_u32), (0x08, 8), (0x09, 9)] {
            insert_pending(&mut window, healthy_addr(), hash(byte), height, t2);
            window.mark_received(hash(byte), 80, t2);
        }
        assert_eq!(window.observe_stall(6, false, t2), None);
        assert_eq!(
            window.observe_stall(6, false, t2 + Duration::from_secs(3)),
            None
        );
        assert_eq!(
            window.observe_stall(6, false, t2 + Duration::from_secs(6)),
            Some(silent),
            "a seeded window must convict a true staller at the effective threshold"
        );
    }

    fn test_budget() -> SyncBudget {
        SyncBudget {
            max_pending_blocks: 128,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 128,
            max_received_bytes: usize::MAX,
            max_peer_inflight: 128,
            // Fan-out disengaged: these unit tests pin the legacy single-mode
            // mechanics where `max_peer_inflight` is always the binding cap.
            fanout_peer_inflight: 128,
            min_peers_for_fanout: usize::MAX,
            getdata_batch_limit: 16,
            pending_timeout: Duration::from_secs(30),
            received_timeout: Duration::from_secs(30),
            stall_timeout_initial: Duration::from_secs(2),
            stall_timeout_max: Duration::from_secs(64),
            staller_cooldown: Duration::from_secs(64),
        }
    }

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_le_bytes(&[byte; 32])
    }
}
