//! Block download window, peer-assignment, stall, and scheduling policy.

use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashSet};
use smallvec::SmallVec;

use crate::BlockStager;
use crate::connection::PeerSource;

mod policy;

pub use policy::*;

#[derive(Clone, Copy, Debug)]
#[expect(missing_docs)]
pub struct SyncBudget {
    pub max_pending_blocks: usize,
    pub max_pending_bytes: usize,
    pub max_received_blocks: usize,
    pub max_received_bytes: usize,
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
    Endpoint(crate::PeerEndpoint),
    Unidentified(crate::ConnectionId),
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

    pub(crate) fn stalling_peer(&self) -> Option<(Option<crate::PeerEndpoint>, Instant)> {
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
        self.next_request_height = retry_height;
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn next_peer_request(
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
        refusals: &mut RefusalFilter,
    ) -> Option<PeerRequest> {
        self.retarget_request_branch(stager, chain_tip, request_start_height, tree, now);
        if self.staged_bytes_exhausted(stager) {
            return None;
        }
        if !allow_expired_retry_from_peer
            && (self.peer_has_expired_pending(source, now)
                || self.peer_in_staller_cooldown(source, now))
        {
            return None;
        }
        let mut expired = self.expire_pending(now);
        expired.sort_by_key(|entry| entry.height);

        let owned = self.pending_count_for(source);
        let peer_capacity = self.effective_peer_inflight().saturating_sub(owned);
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
            refusals,
        );
        let selected_hashes = SelectedHashes::from_entries(&entries);

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
        let mut owners: SmallVec<[Option<crate::PeerEndpoint>; 16]> = SmallVec::new();
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
