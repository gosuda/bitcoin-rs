use std::time::{Duration, Instant};

use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_execution::chain::{BlockTree, TipSnapshot};
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

use crate::p2p::BlockStager;
use bitcoin_rs_wire::connection::PeerSource;

pub(crate) mod policy;

pub use policy::*;

#[derive(Clone, Copy, Debug)]
#[expect(missing_docs)]
pub struct SyncBudget {
    pub max_pending_blocks: usize,
    pub max_pending_bytes: usize,
    pub max_received_blocks: usize,
    pub max_received_bytes: usize,
    pub max_retained_bytes: usize,
    pub max_peer_inflight: usize,
    pub fanout_peer_inflight: usize,
    pub min_peers_for_fanout: usize,
    pub getdata_batch_limit: usize,
    pub block_spacing: Duration,
    #[cfg(test)]
    pub(crate) pending_timeout_override: Option<Duration>,
    pub received_timeout: Duration,
    pub stall_timeout_initial: Duration,
    pub stall_timeout_max: Duration,
    pub staller_cooldown: Duration,
}

impl SyncBudget {
    #[must_use]
    pub fn with_byte_ceiling(mut self, ceiling: usize) -> Self {
        self.max_pending_bytes = self.max_pending_bytes.min(ceiling);
        self.max_received_bytes = self.max_received_bytes.min(ceiling);
        self.max_retained_bytes = self.max_retained_bytes.min(ceiling);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_pending_timeout_override(mut self, timeout: Duration) -> Self {
        self.pending_timeout_override = Some(timeout);
        self
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PeerRequest {
    owner: PeerSource,
    entries: Vec<PeerRequestEntry>,
    next_request_height: u32,
}

impl PeerRequest {
    pub(crate) fn owner(&self) -> PeerSource {
        self.owner
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (u32, Hash256)> + '_ {
        self.entries.iter().map(|entry| (entry.height, entry.hash))
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

pub(crate) struct RefusalFilter<'a> {
    is_refused: &'a dyn Fn(Hash256) -> bool,
    min_refused: Option<u32>,
}

impl<'a> RefusalFilter<'a> {
    pub(crate) fn new(is_refused: &'a dyn Fn(Hash256) -> bool) -> Self {
        Self {
            is_refused,
            min_refused: None,
        }
    }

    pub(crate) fn keep(&mut self, hash: Hash256, height: u32) -> bool {
        if (self.is_refused)(hash) {
            self.min_refused = Some(self.min_refused.map_or(height, |floor| floor.min(height)));
            false
        } else {
            true
        }
    }

    pub(crate) fn min_refused(&self) -> Option<u32> {
        self.min_refused
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

const EWMA_MIN_SAMPLE_MS: u64 = 50;

#[derive(Clone, Copy, Debug)]
struct PendingBlock {
    owner: PeerSource,
    requested_at: Instant,
    height: u32,
    estimated_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct PendingTimeoutObservation {
    owner: PeerSource,
    hash: Hash256,
    expired_release: bool,
}

#[derive(Clone, Copy, Debug)]
struct StallEpisode {
    owner: PeerSource,
    front_hash: Hash256,
    since: Instant,
    info_logged: bool,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockedContext {
    pub next_apply_height: Option<u32>,
    pub frontier_hash: Option<Hash256>,
    pub apply_side_busy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlameReason {
    Staller,
    PendingTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockedDecision {
    Blame {
        owner: PeerSource,
        reason: BlameReason,
    },
    EvictStaged {
        height: u32,
        hash: Hash256,
        suppressed_for: Duration,
    },
    HedgeColdFront {
        owner: PeerSource,
        front_hash: Hash256,
    },
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

const STALL_EPISODE_LOG_AGE: Duration = Duration::from_secs(1);
const MAX_COLD_FRONT_HEDGES: usize = 2;
const PREFIX_PROBE_BLOCK_LIMIT: usize = 8;
const PREFIX_PROBE_WIN_BLOCKS: usize = 4;
const _: () = assert!(PREFIX_PROBE_WIN_BLOCKS > 0);
const _: () = assert!(PREFIX_PROBE_WIN_BLOCKS <= PREFIX_PROBE_BLOCK_LIMIT);
const _: () = assert!(PREFIX_PROBE_BLOCK_LIMIT <= 8);
const PREFIX_PROBE_WIN_MASK: u8 = (1_u8 << PREFIX_PROBE_WIN_BLOCKS) - 1;
const PREFIX_PROBE_ESTIMATED_BYTES: usize = 2 * 1024 * 1024;

fn count_stall_episode_cleared(reason: &'static str) {
    metrics::counter!("node.sync.stall_episodes_cleared", "reason" => reason).increment(1);
}

#[derive(Debug)]
pub(crate) struct DownloadWindow {
    budget: SyncBudget,
    pending: HashMap<Hash256, PendingBlock>,
    pending_bytes: usize,
    pending_blocks_high_water: usize,
    pending_bytes_high_water: usize,
    apply_idle_since: Option<Instant>,
    download_blocked_by_apply_since: Option<Instant>,
    ewma_block_bytes: usize,
    next_request_height: u32,
    request_tip: Option<(Hash256, u32)>,
    owner_downloading_since: HashMap<PeerSource, Instant>,
    owner_last_body_at: HashMap<PeerSource, Instant>,
    fanout_eligible_peers: usize,
    fanout_engaged: bool,
    stall: Option<StallEpisode>,
    apply_side_stuck: Option<ApplySideStuck>,
    stall_timeout: Duration,
    front_interval_ewma_ms: Option<u64>,
    last_front_advance: Option<Instant>,
    cold_front: Option<ColdFrontState>,
    cold_hedged_fronts: SmallVec<[Hash256; MAX_COLD_FRONT_HEDGES]>,
    preferred_peer: Option<PeerSource>,
    prefix_probe: Option<PrefixProbe>,
    prefix_probe_attempted_owner: Option<PeerSource>,
    pending_timeout_observation: Option<PendingTimeoutObservation>,
    recent_stallers: HashMap<StallerKey, Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum StallerKey {
    Endpoint(bitcoin_rs_wire::PeerEndpoint),
    Unidentified(bitcoin_rs_wire::ConnectionId),
}

impl From<PeerSource> for StallerKey {
    fn from(source: PeerSource) -> Self {
        match source.endpoint() {
            Some(endpoint) => Self::Endpoint(endpoint),
            None => Self::Unidentified(source.connection_id()),
        }
    }
}

impl DownloadWindow {
    pub(crate) fn new(budget: SyncBudget) -> Self {
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
            owner_last_body_at: HashMap::with_capacity(budget.max_pending_blocks),
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

    pub(crate) fn set_fanout_eligible_peers(&mut self, count: usize, now: Instant) {
        let was_engaged = self.fanout_engaged;
        self.fanout_eligible_peers = count;
        let would_engage = count >= self.budget.min_peers_for_fanout;
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

    pub(crate) const fn fanout_active(&self) -> bool {
        self.fanout_engaged
    }

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

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) const fn max_pending_blocks(&self) -> usize {
        self.budget.max_pending_blocks
    }

    pub(crate) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub(crate) fn has_request_capacity(&self, stager: &BlockStager) -> bool {
        self.pending.len() < self.budget.max_pending_blocks
            && self.pending_bytes.saturating_add(self.ewma_block_bytes)
                <= self.budget.max_pending_bytes
            && self.staged_byte_headroom(stager) >= self.ewma_block_bytes
            && self.staged_count_headroom(stager, 0) > 0
    }

    fn staged_bytes_exhausted(&self, stager: &BlockStager) -> bool {
        stager.received_bytes() >= self.budget.max_received_bytes
    }

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

    fn staged_count_headroom(&self, stager: &BlockStager, expired_pending_blocks: usize) -> usize {
        if stager.received_len() == 0 {
            return usize::MAX;
        }
        self.budget
            .max_received_blocks
            .saturating_sub(stager.received_len())
            .saturating_sub(self.pending.len().saturating_sub(expired_pending_blocks))
    }

    pub(crate) fn request_peer_scan_limit(&self, stager: &BlockStager, now: Instant) -> usize {
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

    pub(crate) fn peer_has_expired_pending(&self, source: PeerSource, now: Instant) -> bool {
        self.owner_download_expired(source, self.active_downloading_peers(), now)
    }

    pub(crate) fn observe_blocked(
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
                self.mark_peer_unresponsive(observation.owner, now);
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

    fn advance_apply_side_stuck(
        &mut self,
        next_apply_height: u32,
        frontier_hash: Option<Hash256>,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<(Hash256, Duration)> {
        let Some(frontier_hash) = frontier_hash else {
            self.apply_side_stuck = None;
            return None;
        };
        match self.apply_side_stuck {
            Some(stuck)
                if stuck.height == next_apply_height && stuck.frontier_hash == frontier_hash => {}
            _ if apply_side_busy => {
                self.apply_side_stuck = Some(ApplySideStuck {
                    height: next_apply_height,
                    frontier_hash,
                    since: now,
                });
            }
            _ => {
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
        if let Some(stuck) = self.apply_side_stuck.as_mut() {
            stuck.since = now;
        }
        Some((frontier_hash, suppressed_for))
    }

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
        let effective_timeout = self.stall_timeout.max(self.stall_decay_floor());
        if !episode.info_logged && now.duration_since(episode.since) >= STALL_EPISODE_LOG_AGE {
            if let Some(stored) = self.stall.as_mut() {
                stored.info_logged = true;
            }
            tracing::info!(
                peer_addr = ?episode.owner.endpoint,
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
        self.stall = None;
        self.stall_timeout = effective_timeout
            .saturating_mul(2)
            .min(self.budget.stall_timeout_max);
        self.mark_peer_unresponsive(owner, now);
        Some(owner)
    }

    fn close_apply_idle(&mut self, now: Instant) {
        if let Some(since) = self.apply_idle_since.take() {
            metrics::histogram!("node.sync.apply_idle_seconds")
                .record(now.duration_since(since).as_secs_f64());
        }
    }

    fn close_download_blocked_by_apply(&mut self, now: Instant) {
        if let Some(since) = self.download_blocked_by_apply_since.take() {
            metrics::histogram!("node.sync.download_blocked_by_apply_seconds")
                .record(now.duration_since(since).as_secs_f64());
        }
    }

    pub(crate) const fn pending_high_water(&self) -> (usize, usize) {
        (
            self.pending_blocks_high_water,
            self.pending_bytes_high_water,
        )
    }

    fn stall_decay_floor(&self) -> Duration {
        self.front_interval_ewma_ms
            .map_or(Duration::ZERO, |ewma_ms| {
                Duration::from_millis(ewma_ms.saturating_mul(2))
            })
            .max(self.budget.stall_timeout_initial)
            .min(self.budget.stall_timeout_max)
    }

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

    pub(crate) fn stalling_peer(&self) -> Option<(Option<bitcoin_rs_wire::PeerEndpoint>, Instant)> {
        self.stall
            .map(|episode| (episode.owner.endpoint, episode.since))
    }
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

    pub(crate) fn confirm_cold_front_hedge(
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

    pub(crate) const fn preferred_peer(&self) -> Option<PeerSource> {
        self.preferred_peer
    }

    pub(crate) const fn min_peers_for_fanout(&self) -> usize {
        self.budget.min_peers_for_fanout
    }

    pub(crate) fn clear_preferred_peer(&mut self) {
        self.preferred_peer = None;
    }

    pub(crate) fn probe_offered(&self, source: PeerSource, hash: &Hash256) -> bool {
        self.prefix_probe
            .as_ref()
            .is_some_and(|probe| probe.hashes.contains(hash) && probe.racers.contains_key(&source))
    }

    pub(crate) fn hedge_offered(&self, source: PeerSource, hash: &Hash256) -> bool {
        matches!(
            self.cold_front,
            Some(ColdFrontState::Racing {
                alternate,
                hash: front,
                owner: _,
            }) if alternate == source && front == *hash
        )
    }
    pub(crate) fn prefix_probe_plan(
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

    pub(crate) fn confirm_prefix_probe(
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

    #[cfg(test)]
    pub(crate) const fn stall_timeout(&self) -> Duration {
        self.stall_timeout
    }

    pub(crate) fn mark_peer_unresponsive(&mut self, source: PeerSource, now: Instant) {
        let cooldown = self.budget.staller_cooldown;
        self.recent_stallers
            .retain(|_, fired_at| now.duration_since(*fired_at) < cooldown);
        self.recent_stallers.insert(StallerKey::from(source), now);
    }

    pub(crate) fn peer_in_staller_cooldown(&self, source: PeerSource, now: Instant) -> bool {
        self.recent_stallers
            .get(&StallerKey::from(source))
            .is_some_and(|fired_at| now.duration_since(*fired_at) < self.budget.staller_cooldown)
    }

    pub(crate) fn contains_pending(&self, hash: &Hash256) -> bool {
        self.pending.contains_key(hash)
    }

    pub(crate) fn pending_owner(&self, hash: &Hash256) -> Option<PeerSource> {
        self.pending.get(hash).map(|pending| pending.owner)
    }

    #[cfg(test)]
    pub(crate) fn active_prefix_probe_started_at(&self) -> Option<Instant> {
        self.prefix_probe.as_ref().map(|probe| probe.started_at)
    }

    fn active_downloading_peers(&self) -> usize {
        self.owner_downloading_since.len()
    }

    #[must_use]
    pub(crate) fn is_downloading(&self, owner: PeerSource) -> bool {
        self.owner_downloading_since.contains_key(&owner)
    }

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
                self.owner_last_body_at.remove(&owner);
            }
            Some(oldest) if removed_requested_at < oldest => {
                self.owner_downloading_since.insert(owner, now);
            }
            Some(oldest) if removed_requested_at == oldest => {
                self.owner_downloading_since
                    .entry(owner)
                    .and_modify(|since| *since = (*since).max(oldest))
                    .or_insert(oldest);
            }
            Some(_) => {}
        }
    }

    pub(crate) fn retain_owned_by(&mut self, owns: impl Fn(&PeerSource) -> bool) {
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

    pub(crate) fn retire_before(
        &mut self,
        stager: &mut BlockStager,
        height: u32,
        tree: &BlockTree,
        now: Instant,
    ) {
        let retired = self
            .pending
            .iter()
            .filter_map(|(hash, pending)| (pending.height < height).then_some(*hash))
            .collect::<Vec<_>>();
        for hash in retired {
            self.remove_pending(&hash, now);
        }
        let retired = stager
            .staged_hashes()
            .filter(|hash| {
                tree.lookup(*hash)
                    .and_then(|id| tree.node(id).ok())
                    .is_some_and(|node| node.height < height)
            })
            .collect::<Vec<_>>();
        for hash in retired {
            stager.discard(&hash);
        }
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
        self.owner_downloading_since
            .retain(|owner, _| retain_owner(owner));
        self.owner_last_body_at
            .retain(|owner, _| retain_owner(owner));
        self.next_request_height = retry_height;
    }

    pub(crate) fn next_peer_request(
        &mut self,
        stager: &mut BlockStager,
        source: PeerSource,
        chain_tip: &TipSnapshot,
        request_start_height: u32,
        peer_best_height: u32,
        servable_floor: u32,
        tree: &BlockTree,
        now: Instant,
        refusals: &mut RefusalFilter,
    ) -> Option<PeerRequest> {
        if self.peer_has_expired_pending(source, now) || self.peer_in_staller_cooldown(source, now)
        {
            return None;
        }
        self.next_peer_request_allowing_retry(
            stager,
            source,
            chain_tip,
            request_start_height,
            peer_best_height,
            servable_floor,
            tree,
            now,
            refusals,
        )
    }

    pub(crate) fn next_peer_request_allowing_retry(
        &mut self,
        stager: &mut BlockStager,
        source: PeerSource,
        chain_tip: &TipSnapshot,
        request_start_height: u32,
        peer_best_height: u32,
        servable_floor: u32,
        tree: &BlockTree,
        now: Instant,
        refusals: &mut RefusalFilter,
    ) -> Option<PeerRequest> {
        self.retarget_request_branch(stager, chain_tip, request_start_height, tree, now);
        if self.staged_bytes_exhausted(stager) {
            return None;
        }
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let (batch_limit, mut byte_capacity) = self.compute_request_capacity(stager, source)?;

        let mut entries = self.expired_request_entries(
            stager,
            expired,
            batch_limit,
            servable_floor,
            &mut byte_capacity,
            refusals,
        );
        let selected_hashes = SelectedHashes::from_entries(&entries);

        self.maybe_rewind_request_frontier(request_start_height, chain_tip, stager, tree);
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
                && let Some(request) = self
                    .clean_contiguous_peer_request(stager, source, chain_tip, tree, scan, refusals)
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
                refusals,
            );
        }
        if let Some(refused_height) = refusals.min_refused() {
            next_request_height = next_request_height
                .min(refused_height)
                .max(self.next_request_height);
        }
        non_empty_request(source, entries, next_request_height)
    }
    fn compute_request_capacity(
        &self,
        stager: &BlockStager,
        source: PeerSource,
    ) -> Option<(usize, usize)> {
        let owned = self.pending_count_for(source);
        let peer_capacity = self.effective_peer_inflight().saturating_sub(owned);
        let block_capacity = self
            .budget
            .max_pending_blocks
            .saturating_sub(self.pending.len())
            .min(self.staged_count_headroom(stager, 0));
        let byte_capacity = self
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
            None
        } else {
            Some((batch_limit, byte_capacity))
        }
    }

    fn maybe_rewind_request_frontier(
        &mut self,
        request_start_height: u32,
        chain_tip: &TipSnapshot,
        stager: &BlockStager,
        tree: &BlockTree,
    ) {
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
        refusals: &mut RefusalFilter,
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
                if refusals.keep(node.hash, node.height) {
                    candidates.push(PeerRequestEntry {
                        hash: node.hash,
                        height: node.height,
                    });
                }
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
        refusals: &mut RefusalFilter,
    ) -> Vec<PeerRequestEntry> {
        let mut entries = Vec::with_capacity(batch_limit);
        for entry in expired {
            if entries.len() >= batch_limit || *byte_capacity < self.ewma_block_bytes {
                break;
            }
            if !refusals.keep(entry.hash, entry.height) {
                continue;
            }
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
        refusals: &mut RefusalFilter,
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
        let mut has_refused = false;
        for entry in &entries {
            has_refused |= !refusals.keep(entry.hash, entry.height);
        }
        if has_refused {
            return None;
        }
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
            self.mark_peer_unresponsive(owner, now);
        }
        self.preferred_peer = Some(winner);
        tracing::info!(
            owner = ?owner.endpoint,
            winner = ?winner.endpoint,
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
                self.mark_peer_unresponsive(owner, now);
                self.preferred_peer = Some(alternate);
                tracing::info!(
                    owner = ?owner.endpoint,
                    winner = ?alternate.endpoint,
                    %hash,
                    "block sync: cold-front hedge elected alternate"
                );
            }
            _ => {}
        }
    }

    pub(crate) fn mark_requested(
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

    pub(crate) fn mark_received_from(
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

    pub(crate) fn requeue_for_retry(&mut self, hash: &Hash256, height: Option<u32>, now: Instant) {
        let pending_height = self.remove_pending(hash, now).map(|pending| pending.height);
        let target = match (height, pending_height) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (known, None) | (None, known) => known,
        };
        if let Some(target) = target {
            self.next_request_height = self.next_request_height.min(target);
        }
    }

    #[cfg(test)]
    pub(crate) fn request_cursor(&self) -> u32 {
        self.next_request_height
    }

    #[cfg(test)]
    pub(crate) fn owner_queue_start_for_test(&self, owner: PeerSource) -> Option<Instant> {
        self.owner_downloading_since.get(&owner).copied()
    }

    pub(crate) fn credit_delivery_from(
        &mut self,
        hash: Hash256,
        source: PeerSource,
        pending_height: Option<u32>,
        now: Instant,
    ) {
        self.owner_last_body_at.insert(source, now);
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

    pub(crate) fn credit_duplicate_delivery(&mut self, hash: Hash256, source: PeerSource) {
        if self
            .pending_timeout_observation
            .is_some_and(|observation| observation.hash == hash && observation.owner == source)
        {
            self.pending_timeout_observation = None;
        }
    }

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
                let sample_ms =
                    u64::try_from(now.duration_since(previous).as_millis()).unwrap_or(u64::MAX);
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

    #[cfg(test)]
    pub(crate) const fn front_interval_ewma_ms(&self) -> Option<u64> {
        self.front_interval_ewma_ms
    }

    #[cfg(test)]
    pub(crate) const fn seed_front_cadence_for_test(&mut self, ewma_ms: u64, now: Instant) {
        self.front_interval_ewma_ms = Some(ewma_ms);
        self.last_front_advance = Some(now);
    }

    #[cfg(test)]
    pub(crate) fn backdate_stall_for_test(&mut self, elapsed: Duration) {
        if let Some(episode) = self.stall.as_mut() {
            episode.since = episode.since.checked_sub(elapsed).unwrap_or(episode.since);
        }
        for since in self.owner_downloading_since.values_mut() {
            *since = since.checked_sub(elapsed).unwrap_or(*since);
        }
    }

    pub(crate) fn reject_delivery(
        &mut self,
        hash: Hash256,
        source_peer: Option<PeerSource>,
        now: Instant,
    ) -> RejectDelivery {
        if self.pending_timeout_observation.is_some_and(|observation| {
            observation.hash == hash && Some(observation.owner) == source_peer
        }) {
            self.pending_timeout_observation = None;
        }

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
        // INVARIANT: an item unanswered beyond the owner's backoff is
        // re-eligible only with proof the owner skipped it: a body from
        // the same owner delivered after this item was requested. A peer
        // busy sending this very block has no later delivery, so its item
        // stays; a peer that moved on while this one was outstanding gets
        // the item re-queued.
        let backoff = self.stall_timeout;
        let last_body_at = &self.owner_last_body_at;
        let skipped = |pending: &PendingBlock| {
            now.saturating_duration_since(pending.requested_at) >= backoff
                && last_body_at
                    .get(&pending.owner)
                    .is_some_and(|last| *last > pending.requested_at)
        };
        if expired_owners.is_empty() && !self.pending.values().any(&skipped) {
            return Vec::new();
        }
        let mut entries = Vec::new();
        let mut removed: Vec<(PeerSource, Instant)> = Vec::new();
        let armed_observation = &mut self.pending_timeout_observation;
        {
            let pending_bytes = &mut self.pending_bytes;
            let next_request_height = &mut self.next_request_height;
            for (hash, pending) in self.pending.extract_if(|_hash, pending| {
                expired_owners.contains(&pending.owner) || skipped(pending)
            }) {
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

    pub(crate) fn mark_owned_fetch(
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
            stager.clear_gate_pending(&hash);
            return true;
        }
        if !self.has_request_capacity(stager)
            || self.pending_count_for(owner) >= self.effective_peer_inflight()
        {
            return false;
        }
        let request = PeerRequest {
            owner,
            entries: vec![PeerRequestEntry { hash, height }],
            next_request_height: 0,
        };
        let attempted_owner = self.prefix_probe_attempted_owner;
        self.mark_requested(stager, &request, owner, now);
        self.prefix_probe_attempted_owner = attempted_owner;
        true
    }

    pub(crate) fn release_pending(&mut self, hash: &Hash256, now: Instant) {
        let _ = self.remove_pending(hash, now);
    }

    fn remove_pending(&mut self, hash: &Hash256, now: Instant) -> Option<PendingBlock> {
        let pending = self.pending.remove(hash)?;
        self.pending_bytes = self.pending_bytes.saturating_sub(pending.estimated_bytes);
        self.reset_owner_queue_start(pending.owner, pending.requested_at, now);
        Some(pending)
    }

    fn pending_count_for(&self, source: PeerSource) -> usize {
        self.pending
            .values()
            .filter(|pending| pending.owner == source)
            .count()
    }

    fn owner_address_count(&self) -> usize {
        let mut owners: SmallVec<[Option<bitcoin_rs_wire::PeerEndpoint>; 16]> = SmallVec::new();
        for pending in self.pending.values() {
            if !owners.contains(&pending.owner.endpoint) {
                owners.push(pending.owner.endpoint);
            }
        }
        owners.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectDelivery {
    ReleasedPending,
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
    tip_id: bitcoin_rs_execution::chain::NodeId,
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

    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Witness,
    };

    use super::{
        BlameReason, BlockStager, BlockedContext, BlockedDecision, DownloadWindow,
        FAST_BLOCKS_IN_TRANSIT_PER_PEER, FAST_MIN_PEERS_FOR_FANOUT, FAST_OUTBOUND_PEER_TARGET,
        PENDING_BUDGET, SyncBudget, fast_sync_budget,
    };
    use bitcoin_rs_wire::connection::PeerSource;

    fn test_stager(window: &DownloadWindow) -> BlockStager {
        BlockStager::new(window.budget)
    }

    static TEST_CHAIN: std::sync::LazyLock<Vec<bitcoin_rs_consensus::primitives::Header>> =
        std::sync::LazyLock::new(|| {
            let genesis = Network::Regtest.genesis_block().header;
            std::iter::successors(Some(genesis), |prev| {
                let height = prev.time.saturating_sub(genesis.time).saturating_add(1);
                let mut merkle = [0_u8; 32];
                merkle[..4].copy_from_slice(&height.to_le_bytes());
                Some(bitcoin_rs_consensus::primitives::Header {
                    prev_blockhash: prev.compute_hash(),
                    merkle_root: Hash256::from_le_bytes(&merkle),
                    time: prev.time.saturating_add(1),
                    ..*prev
                })
            })
            .take(256)
            .collect()
        });

    fn test_tree() -> bitcoin_rs_execution::chain::BlockTree {
        let mut tree = bitcoin_rs_execution::chain::BlockTree::new();
        let mut parent = None;
        for header in TEST_CHAIN.iter() {
            let inserted = tree.insert_node(
                parent,
                *header,
                bitcoin_rs_execution::chain::NodeStatus::HeaderValid,
            );
            parent = Some(inserted.unwrap_or_else(|error| panic!("test chain header: {error}")));
        }
        tree
    }

    const SMALL_BODY: usize = 141;

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

    fn stage_body(
        stager: &mut BlockStager,
        hash: Hash256,
        total_bytes: usize,
        source: Option<PeerSource>,
        now: Instant,
    ) {
        let block = padded_regtest_block(total_bytes);
        match stager.insert(hash, None, BlockImage::from_local(block), source, now) {
            crate::p2p::block_stager::StagedBlock::Memory { .. } => {}
            other => panic!("stage_body refused: {other:?}"),
        }
    }

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

    fn apply_staged(stager: &mut BlockStager, hash: &Hash256) {
        stager.retire_applied(hash);
    }

    fn test_source(addr: bitcoin_rs_wire::PeerEndpoint) -> PeerSource {
        PeerSource::for_test_endpoint(addr)
    }

    fn stall_owner(
        window: &mut DownloadWindow,
        stager: &BlockStager,
        tree: &bitcoin_rs_execution::chain::BlockTree,
        next_apply_height: u32,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<bitcoin_rs_wire::PeerEndpoint> {
        if apply_side_busy {
            assert_eq!(observe_apply_busy(window, now), BlockedDecision::None);
            return None;
        }
        window
            .advance_stall(next_apply_height, stager, tree, now)
            .and_then(|owner| owner.endpoint)
    }

    fn timeout_owner(
        window: &mut DownloadWindow,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<bitcoin_rs_wire::PeerEndpoint> {
        if apply_side_busy {
            assert_eq!(observe_apply_busy(window, now), BlockedDecision::None);
            return None;
        }
        let active = window.active_downloading_peers();
        window
            .advance_pending_timeout(now, active)
            .and_then(|owner| owner.endpoint)
    }

    fn cold_front_owner(
        window: &mut DownloadWindow,
        next_apply_height: u32,
        apply_side_busy: bool,
        now: Instant,
    ) -> Option<(bitcoin_rs_wire::PeerEndpoint, Hash256)> {
        if apply_side_busy {
            assert_eq!(observe_apply_busy(window, now), BlockedDecision::None);
            return None;
        }
        window
            .advance_cold_front(next_apply_height, now)
            .and_then(|(owner, hash)| owner.endpoint.map(|endpoint| (endpoint, hash)))
    }

    fn observe_apply_busy(window: &mut DownloadWindow, now: Instant) -> BlockedDecision {
        window.observe_blocked(
            BlockedContext {
                next_apply_height: None,
                frontier_hash: None,
                apply_side_busy: true,
            },
            &test_stager(window),
            &test_tree(),
            now,
        )
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
        let owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
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
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
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
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
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
        assert!(
            !window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(peer_addr), observed_at)
        );
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
        assert!(
            !window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(peer_addr), observed_at)
        );
    }

    #[test]
    fn retry_delivery_resolves_original_peer_timeout_without_blame() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let requested_at = Instant::now();
        let observed_at = requested_at + Duration::from_secs(10);
        let original_peer = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
        let retry_peer = std::net::SocketAddr::from(([127, 0, 0, 2], 8333)).into();
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

        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_some());

        window.mark_received_from(block_hash, 80, Some(test_source(retry_peer)), observed_at);
        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_none());
        assert!(
            !window.peer_in_staller_cooldown(
                PeerSource::for_test_endpoint(original_peer),
                observed_at
            )
        );
        assert!(
            !window
                .peer_in_staller_cooldown(PeerSource::for_test_endpoint(retry_peer), observed_at)
        );
    }

    #[test]
    fn batched_non_front_deliveries_do_not_postpone_the_owner_timeout() {
        let mut window = DownloadWindow::new(test_budget());
        let stager = test_stager(&window);
        let now = Instant::now();
        let owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
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

        for byte in [0xe6, 0xe7] {
            window.mark_received_from(hash(byte), SMALL_BODY, Some(owner), second_at);
            assert_eq!(window.owner_downloading_since.get(&owner), Some(&now));
        }

        let front_removed_at = second_at + Duration::from_millis(1);
        window.mark_received_from(front, SMALL_BODY, Some(owner), front_removed_at);
        assert_eq!(
            window.owner_downloading_since.get(&owner),
            Some(&front_removed_at)
        );
    }

    #[test]
    fn tied_removal_never_rewinds_the_owner_queue_clock() {
        let mut window = DownloadWindow::new(test_budget());
        let stager = test_stager(&window);
        let t0 = Instant::now();
        let owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
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

        window.mark_received_from(hash(0xf1), SMALL_BODY, Some(owner), t5);
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&t0));
        let t9 = t5 + Duration::from_secs(4);
        window.mark_received_from(hash(0xf2), SMALL_BODY, Some(owner), t9);
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&t9));

        window.mark_received_from(hash(0xf3), SMALL_BODY, Some(owner), t9);
        assert_eq!(window.owner_downloading_since.get(&owner), Some(&t9));
    }

    #[test]
    fn requeue_of_the_observed_block_clears_the_suspicion_without_blame() {
        let mut window = DownloadWindow::new(
            test_budget().with_pending_timeout_override(Duration::from_secs(10)),
        );
        let requested_at = Instant::now();
        let observed_at = requested_at + Duration::from_secs(10);
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
        let block_hash = hash(0x93);
        let owner = insert_pending(
            &mut window,
            test_source(peer_addr),
            block_hash,
            1,
            requested_at,
        );

        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_some());

        window.requeue_for_retry(&block_hash, Some(1), observed_at);
        assert_eq!(window.pending_owner(&block_hash), None);
        assert_eq!(window.owner_queue_start_for_test(owner), None);

        assert_eq!(timeout_owner(&mut window, false, observed_at), None);
        assert!(window.pending_timeout_observation.is_none());
        assert!(
            !window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(peer_addr), observed_at)
        );
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
        let stale_owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
        let live_owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 2], 8333)),
        ));
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

        window.retain_owned_by(|p| p.endpoint == live_owner.endpoint);

        assert_eq!(window.pending_len(), 1);
        assert_eq!(window.pending_bytes(), estimated_bytes);
        assert_eq!(window.next_request_height, 1);
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
        let owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
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

    #[test]
    fn slow_peer_timeout_uses_spacing_and_other_downloaders() {
        let spacing = Duration::from_secs(10);
        let requested_at = Instant::now();

        let mut window = DownloadWindow::new(SyncBudget {
            block_spacing: spacing,
            pending_timeout_override: None,
            ..test_budget()
        });
        let solo = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
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
            solo.endpoint
        );

        let mut window = DownloadWindow::new(SyncBudget {
            block_spacing: spacing,
            pending_timeout_override: None,
            ..test_budget()
        });
        let owners: Vec<PeerSource> = (1..=3_u8)
            .map(|byte| {
                let owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
                    std::net::SocketAddr::from(([127, 0, 0, 20 + byte], 8333)),
                ));
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
            owners[0].endpoint,
            "the second observation convicts the pinned owner"
        );
    }

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
        let owner = test_source(bitcoin_rs_wire::PeerEndpoint::Ip(
            std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        ));
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
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
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

        assert!(!window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 0);

        apply_staged(&mut stager, &staged);

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

        window.set_fanout_eligible_peers(7, now);
        assert!(!window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(&stager, now), 1);

        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(&stager, now), 8);
    }

    #[test]
    fn fast_sync_budget_stripes_window_across_fast_outbound_target() {
        let mut window = DownloadWindow::new(fast_sync_budget(Network::Regtest));
        let stager = test_stager(&window);
        let now = Instant::now();

        window.set_fanout_eligible_peers(1, now);
        assert!(!window.fanout_active());
        assert_eq!(window.request_peer_scan_limit(&stager, now), 1);

        window.set_fanout_eligible_peers(FAST_MIN_PEERS_FOR_FANOUT, now);
        assert!(window.fanout_active());
        assert_eq!(window.effective_peer_inflight(), PENDING_BUDGET / 2);

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

        receive_staged(&mut window, &mut stager, hash(0xc4), slot, Instant::now());
        assert!(!window.has_request_capacity(&stager));
        assert_eq!(window.request_peer_scan_limit(&stager, Instant::now()), 0);
    }

    #[test]
    fn request_sizing_clamped_to_staged_count_headroom() {
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
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
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

        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7, now);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());

        window.set_fanout_eligible_peers(7, now);
        assert!(window.fanout_active());
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());

        window.set_fanout_eligible_peers(6, now);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(7, now);
        assert!(!window.fanout_active());
        window.set_fanout_eligible_peers(8, now);
        assert!(window.fanout_active());
    }

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

    fn seed_front_cadence(
        window: &mut DownloadWindow,
        peer: bitcoin_rs_wire::PeerEndpoint,
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

    fn window_blocked_on_staller(
        staller: bitcoin_rs_wire::PeerEndpoint,
        healthy: bitcoin_rs_wire::PeerEndpoint,
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

    fn staller_addr() -> bitcoin_rs_wire::PeerEndpoint {
        bitcoin_rs_wire::PeerEndpoint::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)))
    }

    fn healthy_addr() -> bitcoin_rs_wire::PeerEndpoint {
        bitcoin_rs_wire::PeerEndpoint::Ip(std::net::SocketAddr::from(([127, 0, 0, 2], 8333)))
    }

    #[test]
    fn stall_clock_idle_without_staged_successors() {
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
        assert!(
            window.has_request_capacity(&stager),
            "the construction must keep request capacity open: arming no longer reads it"
        );

        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
        assert!(window.stalling_peer().is_none());

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert_eq!(window.stalling_peer(), Some((Some(staller_addr()), now)));
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
                Some((Some(staller_addr()), now)),
                "half the window must arm (depth {depth})"
            );
        }
    }

    #[test]
    fn below_fraction_staged_backlog_never_arms_even_with_capacity_closed() {
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

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, now),
            None
        );
        assert_eq!(window.stalling_peer(), Some((Some(staller_addr()), now)));
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
        assert!(window.peer_in_staller_cooldown(
            PeerSource::for_test_endpoint(staller_addr()),
            now + Duration::from_secs(2)
        ));
        assert!(!window.peer_in_staller_cooldown(
            PeerSource::for_test_endpoint(healthy_addr()),
            now + Duration::from_secs(2)
        ));
        assert!(!window.peer_in_staller_cooldown(
            PeerSource::for_test_endpoint(staller_addr()),
            now + Duration::from_secs(33)
        ));
    }

    #[test]
    fn stall_timeout_doubles_per_fire_caps_and_decays_on_front_arrival() {
        let (mut window, mut stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));

        stall_owner(&mut window, &stager, &tree, 3, false, now);
        let mut at = now + Duration::from_secs(2);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, at),
            Some(staller_addr())
        );
        assert_eq!(window.stall_timeout(), Duration::from_secs(4));

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

        stall_owner(&mut window, &stager, &tree, 3, false, at);
        receive_staged(&mut window, &mut stager, hash(0x03), SMALL_BODY, at);
        assert_eq!(window.front_interval_ewma_ms(), Some(3575));
        assert_eq!(window.stall_timeout(), Duration::from_millis(7150));
        assert!(window.stalling_peer().is_none());
    }

    #[test]
    fn successor_arrival_does_not_reset_stall_clock() {
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
        assert_eq!(window.stalling_peer(), Some((Some(staller_addr()), now)));

        receive_staged(
            &mut window,
            &mut stager,
            hash(0x06),
            SMALL_BODY,
            now + Duration::from_secs(1),
        );

        assert_eq!(window.stalling_peer(), Some((Some(staller_addr()), now)));
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

        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
        assert!(window.stalling_peer().is_none());
        let later = now + Duration::from_mins(1);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, true, later),
            None
        );
        assert!(window.stalling_peer().is_none());

        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, later),
            None
        );
        assert_eq!(window.stalling_peer(), Some((Some(staller_addr()), later)));
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

    #[test]
    fn stall_episode_counters_cover_every_clear_path() {
        let recorder = CounterRecorder::default();
        metrics::with_local_recorder(&recorder, || {
            let (mut window, mut stager, now) =
                window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
            let tree = test_tree();

            assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 4, false, now),
                None
            );
            assert_eq!(recorder.cleared("apply_busy"), 0);
            assert_eq!(recorder.cleared("predicate"), 0);
            assert_eq!(recorder.started(), 0);

            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, now),
                None
            );
            assert_eq!(recorder.started(), 1);
            assert_eq!(stall_owner(&mut window, &stager, &tree, 3, true, now), None);
            assert_eq!(recorder.cleared("apply_busy"), 1);

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

            receive_staged(
                &mut window,
                &mut stager,
                hash(0x07),
                SMALL_BODY,
                now + Duration::from_millis(100),
            );
            assert_eq!(recorder.cleared("peer_delivery"), 1);

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

    fn info_logged(window: &DownloadWindow) -> Option<bool> {
        window.stall.map(|episode| episode.info_logged)
    }

    #[test]
    fn stall_episode_logs_info_once_per_episode_after_one_second() {
        let (mut window, stager, now) =
            window_blocked_on_staller(staller_addr(), healthy_addr(), Instant::now());
        let tree = test_tree();

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
        };
        assert_eq!(
            window.observe_blocked(ctx, &stager, &tree, now),
            BlockedDecision::None
        );
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

    fn peer_addr(idx: u8) -> bitcoin_rs_wire::PeerEndpoint {
        bitcoin_rs_wire::PeerEndpoint::Ip(std::net::SocketAddr::from(([10, 0, 0, idx], 8333)))
    }

    #[test]
    fn uniform_slow_streaming_saturated_fanout_never_fires() {
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
        assert_eq!(stall_owner(&mut window, &stager, &tree, 3, false, t1), None);

        for round in 0..3u8 {
            let at = t1 + Duration::from_secs(3) * (u32::from(round) + 1);
            for peer in 0..8u8 {
                let height = peer * 3 + 5 - round;
                receive_staged(&mut window, &mut stager, hash(height), SMALL_BODY, at);
            }
            assert_eq!(
                stall_owner(&mut window, &stager, &tree, 3, false, at),
                None,
                "a streaming peer must never fire (round {round})"
            );
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
        assert_eq!(window.front_interval_ewma_ms(), Some(4500));
        for peer in 0..8u8 {
            assert!(
                !window
                    .peer_in_staller_cooldown(PeerSource::for_test_endpoint(peer_addr(peer)), end),
                "no staller cooldown may exist after uniform-slow streaming"
            );
        }

        insert_pending(&mut window, test_source(peer_addr(0)), hash(27), 27, end);
        insert_pending(&mut window, test_source(peer_addr(1)), hash(28), 28, end);
        receive_staged(&mut window, &mut stager, hash(28), SMALL_BODY, end);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 27, false, end),
            None
        );
        assert_eq!(
            window.stalling_peer().map(|(addr, _)| addr),
            Some(Some(peer_addr(0)))
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
        let mut window = DownloadWindow::new(stall_budget());
        let mut stager = test_stager(&window);
        let tree = test_tree();
        let now = seed_front_cadence(
            &mut window,
            healthy_addr(),
            Instant::now(),
            Duration::from_millis(100),
        );
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
        assert_eq!(window.stalling_peer(), Some((Some(staller_addr()), now)));

        receive_staged(
            &mut window,
            &mut stager,
            hash(0x06),
            SMALL_BODY,
            now + Duration::from_millis(1500),
        );
        assert!(window.stalling_peer().is_none());
        assert_eq!(window.stall_timeout(), Duration::from_secs(2));

        let restarted = now + Duration::from_millis(2500);
        assert_eq!(
            stall_owner(&mut window, &stager, &tree, 3, false, restarted),
            None
        );
        assert_eq!(
            window.stalling_peer(),
            Some((Some(staller_addr()), restarted))
        );

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

        window.retain_owned_by(|p| p.endpoint != Some(staller_addr()));
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
        let (mut window, stager, front, at, _silent) = limit_cycle_window_state();
        let tree = test_tree();
        assert_eq!(window.front_interval_ewma_ms(), Some(3239));
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
        let (mut window, mut stager, front, at, silent) = limit_cycle_window_state();
        let tree = test_tree();

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
        assert_eq!(window.stall_timeout(), Duration::from_secs(8));
        let end = at + Duration::from_millis(6478);
        assert!(window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(silent), end));
        assert!(
            !window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(healthy_addr()), end)
        );
    }

    fn limit_cycle_window_state() -> (
        DownloadWindow,
        BlockStager,
        u8,
        Instant,
        bitcoin_rs_wire::PeerEndpoint,
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
        window.retain_owned_by(|p| p.endpoint != Some(staller_addr()));

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
        assert!(!window.peer_in_staller_cooldown(
            PeerSource::for_test_endpoint(staller_addr()),
            t0 + Duration::from_secs(30)
        ));

        let t1 = t0 + Duration::from_secs(30);
        window.pending_timeout_observation = Some(super::PendingTimeoutObservation {
            owner,
            hash: hash(0x01),
            expired_release: false,
        });
        window.mark_received_from(hash(0x01), 80, Some(alternate), t1);
        assert_eq!(window.preferred_peer(), Some(alternate));
        assert!(window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(staller_addr()), t1));
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

        window.retain_owned_by(|p| p.endpoint != Some(healthy_addr()));
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
            Some(super::ColdFrontState::Racing { alternate, .. }) if alternate.endpoint == Some(peer_addr(2))
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
    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
    }
    type TestResult = Result<(), TestError>;

    #[test]
    fn mixed_prefix_sources_do_not_elect_a_winner() -> TestResult {
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
    fn prefix_probe_respects_estimated_byte_cutoff() -> TestResult {
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

    #[test]
    fn fanout_cancels_prefix_probe_without_rearming_it() -> TestResult {
        let now = Instant::now();
        let owner = test_source(staller_addr());
        let alternate = test_source(healthy_addr());
        let budget = SyncBudget {
            min_peers_for_fanout: 2,
            ..stall_budget()
        };
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
        let now = now + stall_timeout_initial;

        window.set_fanout_eligible_peers(2, now);

        assert!(window.prefix_probe.is_none());
        window.set_fanout_eligible_peers(0, now);
        assert!(window.prefix_probe_plan().is_none());
        Ok(())
    }

    #[test]
    fn fanout_threshold_during_fresh_probe_defers_engagement() -> TestResult {
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

    #[test]
    fn probe_resolution_before_deadline_allows_fanout_immediately() -> TestResult {
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

        window.set_fanout_eligible_peers(2, now);
        assert!(
            !window.fanout_active(),
            "a fresh live probe must defer the threshold transition"
        );
        assert!(
            window.prefix_probe.is_some(),
            "a fresh live probe must survive the threshold transition"
        );

        window.retain_owned_by(|p| p.endpoint != alternate.endpoint);
        assert!(window.prefix_probe.is_none(), "the probe must be cancelled");
        assert!(
            window.preferred_peer().is_none(),
            "cancellation must not elect a winner"
        );

        window.set_fanout_eligible_peers(2, now);
        assert!(
            window.fanout_active(),
            "fanout must engage once the probe is cancelled"
        );
        Ok(())
    }

    #[test]
    fn disconnected_prefix_racer_queued_deliveries_cannot_win() -> TestResult {
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
        window.retain_owned_by(|p| p.endpoint != disconnected.endpoint);

        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(disconnected), now);
        }

        assert_eq!(window.preferred_peer(), None);
        assert!(window.prefix_probe.is_none());
        Ok(())
    }

    #[test]
    fn dead_owner_prefix_probe_is_released_even_with_live_alternates() -> TestResult {
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

        window.retain_owned_by(|p| p.endpoint != owner.endpoint);
        assert!(window.prefix_probe.is_none());

        for byte in 1..=4_u8 {
            window.mark_received_from(hash(byte), 80, Some(alternate_a), now);
        }

        assert!(window.prefix_probe.is_none());
        assert_eq!(window.preferred_peer(), None);
        assert!(!window.peer_in_staller_cooldown(owner, now));
        Ok(())
    }

    #[test]
    fn late_prefix_loser_cannot_replace_winner() -> TestResult {
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
        window.retain_owned_by(|p| p.endpoint != winner.endpoint);
        assert_eq!(window.preferred_peer(), None);
        assert!(!window.peer_in_staller_cooldown(loser, now));
        Ok(())
    }

    #[test]
    fn prefix_owner_win_keeps_unrelated_peer_requests() -> TestResult {
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
        assert!(!window.peer_in_staller_cooldown(owner, now));
        Ok(())
    }

    #[test]
    fn prefix_alternate_win_releases_only_probe_losers() -> TestResult {
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
        assert!(window.peer_in_staller_cooldown(owner, now));
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
        assert!(!window.peer_in_staller_cooldown(owner, now));
    }

    #[test]
    fn stale_prefix_confirmation_after_release_does_not_install_probe_or_gate() -> TestResult {
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
    fn anonymous_staller_cools_down_per_connection_not_globally() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let first = PeerSource::for_test_unidentified();
        let second = PeerSource::for_test_unidentified();
        window.mark_peer_unresponsive(first, now);
        assert!(window.peer_in_staller_cooldown(first, now));
        assert!(!window.peer_in_staller_cooldown(second, now));
        assert!(!window.peer_in_staller_cooldown(first, now + Duration::from_secs(3600)));
    }

    #[test]
    fn release_of_a_dead_connection_clears_state_but_preserves_cooldown() {
        let mut window = DownloadWindow::new(test_budget());
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8333)).into();
        let now = Instant::now();
        let source = test_source(peer_addr);
        insert_pending(&mut window, source, hash(1), 1, now);
        window.preferred_peer = Some(source);
        window.mark_peer_unresponsive(PeerSource::for_test_endpoint(peer_addr), now);

        window.retain_owned_by(|p| *p != source);

        assert_eq!(window.pending_count_for(source), 0);
        assert!(window.preferred_peer.is_none());
        assert!(window.peer_in_staller_cooldown(PeerSource::for_test_endpoint(peer_addr), now));
    }

    #[test]
    fn reject_delivery_releases_only_the_owners_pending() {
        let owner = test_source(peer_addr(1));
        let other = test_source(peer_addr(2));
        let cases = [
            (
                true,
                Some(owner),
                hash(0x42),
                super::RejectDelivery::ReleasedPending,
            ),
            (
                true,
                Some(other),
                hash(0x42),
                super::RejectDelivery::DiscardedUnsolicited,
            ),
            (
                true,
                None,
                hash(0x42),
                super::RejectDelivery::DiscardedUnsolicited,
            ),
            (
                false,
                Some(owner),
                hash(0x99),
                super::RejectDelivery::DiscardedUnsolicited,
            ),
        ];
        for (pending, deliverer, block_hash, expected) in cases {
            for cursor in [1, 150] {
                let now = Instant::now();
                let mut window = DownloadWindow::new(test_budget());
                if pending {
                    insert_pending(&mut window, owner, block_hash, 100, now);
                }
                window.next_request_height = cursor;
                assert_eq!(window.contains_pending(&block_hash), pending);
                assert_eq!(window.pending_len(), usize::from(pending));

                assert_eq!(window.reject_delivery(block_hash, deliverer, now), expected);

                let released = expected == super::RejectDelivery::ReleasedPending;
                assert_eq!(window.contains_pending(&block_hash), pending && !released);
                assert_eq!(window.pending_len(), usize::from(pending && !released));
                if released {
                    assert!(window.next_request_height <= 100);
                    assert_eq!(window.next_request_height, cursor.min(100));
                } else {
                    assert_eq!(window.next_request_height, cursor);
                }
            }
        }
    }

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
        assert!(!window.peer_in_staller_cooldown(owner, now));
    }

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
            owner.endpoint.map(|endpoint| (endpoint, block_hash))
        );

        assert_eq!(
            window.reject_delivery(block_hash, Some(owner), now),
            super::RejectDelivery::ReleasedPending
        );
        assert!(window.cold_front.is_none());
        assert!(!window.contains_pending(&block_hash));
    }

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
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);

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
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let frontier = hash(0x07);

        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), false, start),
            None
        );
        let delivered = start + bound + Duration::from_secs(10);
        assert_eq!(
            apply_side_bound(&mut window, 7, Some(frontier), false, delivered),
            None
        );

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
        let mut window = DownloadWindow::new(test_budget());
        let start = Instant::now();
        let bound = test_budget().received_timeout.saturating_mul(2);
        let branch_a = hash(0xA1);
        let branch_b = hash(0xB2);

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
            max_retained_bytes: usize::MAX,
            max_peer_inflight: 128,
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

    fn hash(byte: u8) -> Hash256 {
        Hash256::from(TEST_CHAIN[usize::from(byte)].compute_hash())
    }

    #[test]
    fn owned_fetch_preserves_prefix_probe_attempted_owner() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let stall_owner = super::PeerSource::for_test_endpoint(staller_addr());
        let compact_peer = super::PeerSource::for_test_endpoint(healthy_addr());
        window.prefix_probe_attempted_owner = Some(stall_owner);

        window.mark_owned_fetch(&mut test_stager(&window), compact_peer, hash(0xf1), 7, now);
        assert_eq!(window.prefix_probe_attempted_owner, Some(stall_owner));
        assert!(window.contains_pending(&hash(0xf1)));

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
    fn owned_fetch_installs_active_height_below_cursor() {
        let mut window = DownloadWindow::new(SyncBudget {
            max_pending_blocks: 1,
            ..test_budget()
        });
        let now = Instant::now();
        let owner = super::PeerSource::for_test_endpoint(healthy_addr());

        window.mark_owned_fetch(&mut test_stager(&window), owner, hash(0xa1), 9, now);
        assert!(window.contains_pending(&hash(0xa1)));
        window.mark_owned_fetch(&mut test_stager(&window), owner, hash(0xa2), 10, now);
        assert!(!window.contains_pending(&hash(0xa2)));

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
        assert!(window.contains_pending(&hash(0xb1)));
        assert_eq!(window.next_request_height, 11);
    }

    #[test]
    fn skipped_item_reissued_after_later_delivery() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let owner = test_source(healthy_addr());
        let request = super::non_empty_request(
            owner,
            vec![
                super::PeerRequestEntry {
                    hash: hash(0xd3),
                    height: 3,
                },
                super::PeerRequestEntry {
                    hash: hash(0xd4),
                    height: 4,
                },
                super::PeerRequestEntry {
                    hash: hash(0xd5),
                    height: 5,
                },
            ],
            6,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        window.mark_requested(&test_stager(&window), &request, owner, now);
        let delivered_at = now + Duration::from_secs(1);
        window.mark_received_from(hash(0xd4), 80, Some(owner), delivered_at);
        window.mark_received_from(hash(0xd5), 80, Some(owner), delivered_at);
        assert!(
            window.expire_pending(delivered_at).is_empty(),
            "the earlier item must stay pending before the backoff elapses"
        );
        assert!(window.contains_pending(&hash(0xd3)));
        let past_backoff = now + Duration::from_secs(3);
        assert!(
            !window.owner_download_expired(owner, window.active_downloading_peers(), past_backoff),
            "the 30 s owner override must still hold the owner live"
        );
        let expired = window.expire_pending(past_backoff);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].hash, hash(0xd3));
        assert!(!window.contains_pending(&hash(0xd3)));
    }

    #[test]
    fn silent_item_without_later_delivery_never_expires() {
        let mut window = DownloadWindow::new(test_budget());
        let now = Instant::now();
        let owner = test_source(healthy_addr());
        let request = super::non_empty_request(
            owner,
            vec![super::PeerRequestEntry {
                hash: hash(0xd3),
                height: 3,
            }],
            4,
        )
        .unwrap_or_else(|| panic!("non-empty request"));
        window.mark_requested(&test_stager(&window), &request, owner, now);
        let past_backoff = now + Duration::from_secs(3);
        assert!(
            window.expire_pending(past_backoff).is_empty(),
            "a peer busy sending this very block has no later delivery, so the item stays"
        );
        assert!(window.contains_pending(&hash(0xd3)));
    }

    #[test]
    fn fanout_eligibility_requires_block_service_flags() {
        use bitcoin_rs_wire::{PeerCounters, PeerEndpoint, PeerInfo, PeerRemote};
        use std::net::{IpAddr, Ipv4Addr};

        fn peer(services: u64, inbound: bool) -> PeerInfo {
            let addr =
                PeerRemote::Endpoint(PeerEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333));
            PeerInfo {
                addr,
                endpoint: addr.endpoint(),
                network: addr.network().into(),
                version: 70_016,
                wtxid_relay: false,
                relay_transactions: true,
                compact_block_relay: false,
                send_headers: false,
                services,
                user_agent: String::from("/test/"),
                start_height: 0,
                best_known_height: 0,
                conn_time: 0,
                inbound,
                addr_bind: bitcoin_rs_wire::TransportRemote::new(
                    addr.endpoint()
                        .and_then(bitcoin_rs_wire::PeerEndpoint::socket_addr)
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                ),
                time_offset: 0,
                counters: std::sync::Arc::new(PeerCounters::default()),
                transport: bitcoin_rs_wire::TransportProtocol::V1,
            }
        }

        fn policy(requested_height: u32) -> super::BlockDownloadPolicy {
            super::BlockDownloadPolicy {
                ibd: crate::p2p::sync::test_support::synced_ibd_latch(),
                requested_height,
                network: Network::Regtest,
            }
        }

        const WITNESS: u64 = 1_u64 << 3;
        const NETWORK: u64 = 1_u64;
        const LIMITED: u64 = 1_u64 << 10;
        assert!(!super::statically_fanout_eligible(
            &peer(WITNESS, false),
            &policy(0)
        ));
        assert!(super::statically_fanout_eligible(
            &peer(WITNESS | NETWORK, false),
            &policy(0)
        ));
        assert!(super::statically_fanout_eligible(
            &peer(WITNESS | LIMITED, false),
            &policy(0)
        ));
        assert!(!super::statically_fanout_eligible(
            &peer(WITNESS | NETWORK, true),
            &policy(0)
        ));
        assert!(!super::statically_fanout_eligible(
            &peer(NETWORK, false),
            &policy(0)
        ));
    }
}
