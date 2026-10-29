//! Block download orchestrator.

mod branches;
pub mod chain;
mod commit;
mod frontier;
mod headers;
mod headers_presync;
mod historical;
mod peers;
mod receive;
mod requests;
mod stale_tips;
mod telemetry;

#[cfg(test)]
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::Receiver;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
#[cfg(test)]
use telemetry::metric_count;

use crate::BlockStager;
use crate::InboundHeaders;
use crate::PeerSource;
use crate::PeerTable;
#[cfg(test)]
use crate::download_window::BLOCK_STALLING_TIMEOUT;
use crate::download_window::DownloadWindow;
#[cfg(test)]
use crate::download_window::GETDATA_BATCH_SIZE;
#[cfg(test)]
use crate::download_window::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
#[cfg(test)]
use crate::download_window::PEER_INFLIGHT_BUDGET;
#[cfg(test)]
use crate::download_window::PENDING_BUDGET;
use crate::download_window::RECEIVED_BLOCK_BUDGET;
#[cfg(test)]
use crate::download_window::RECEIVED_BLOCK_TIMEOUT;
#[cfg(test)]
use commit::restore_split;

pub use chain::SyncChain;
pub use stale_tips::StaleTipRetainer;

pub use headers_presync::{
    HeaderAnchor, HeaderSyncError, HeaderSyncResult, HeadersSyncPhase, HeadersSyncState,
};

pub(crate) use frontier::{
    BodyState, ChainFrontier, HeaderAction, NoProgressReason, RequiredBody, SyncFrontier,
    UsablePeer, header_request_live,
};

pub(crate) use crate::download_window::SyncBudget;
pub use crate::download_window::default_sync_budget;

#[cfg(test)]
pub(crate) use crate::download_window::MIN_PEERS_FOR_FANOUT;

const LOCATOR_MAX_ENTRIES: usize = 32;

const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

const STALE_CHECK_INTERVAL: Duration = Duration::from_mins(10);

#[derive(Clone, Debug, Default)]
struct StaleTipState {
    last_seen_tip: Option<(u32, Hash256)>,
    last_update: Option<Instant>,
    next_check: Option<Instant>,
    extra_dial_allowed: bool,
}

impl StaleTipState {
    /// INVARIANT: the allowance is this record's only output, so the
    ///   connection manager never reads a staleness clock of its own.
    fn follow(
        &mut self,
        tip_height: u32,
        tip_hash: Hash256,
        blocks_in_flight: usize,
        block_spacing: Duration,
        now: Instant,
    ) {
        let identity = (tip_height, tip_hash);
        if self.last_seen_tip.is_none_or(|seen| seen != identity) {
            self.last_seen_tip = Some(identity);
            self.last_update = Some(now);
            self.extra_dial_allowed = false;
            return;
        }
        if self.next_check.is_some_and(|due| now < due) {
            return;
        }
        self.next_check = Some(now + STALE_CHECK_INTERVAL);
        self.extra_dial_allowed = tip_may_be_stale(self, blocks_in_flight, block_spacing, now);
    }
}

/// INVARIANT: this is Core's `TipMayBeStale` (`net_processing.cpp`),
///   which weighs the last tip update against `3 * nPowTargetSpacing` with
///   nothing in flight.
fn tip_may_be_stale(
    state: &mut StaleTipState,
    blocks_in_flight: usize,
    block_spacing: Duration,
    now: Instant,
) -> bool {
    if blocks_in_flight > 0 {
        return false;
    }
    let last_update = state.last_update.get_or_insert(now);
    now.saturating_duration_since(*last_update) > block_spacing * 3
}

type ExpectedBlockHashes = SmallVec<[Hash256; RECEIVED_BLOCK_BUDGET]>;

pub struct BlockSync {
    historical: Mutex<historical::HistoricalDownload>,
    historical_work: Mutex<()>,
    pub(crate) chain: Arc<dyn SyncChain>,
    peer_table: Arc<PeerTable>,
    ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    inbound_headers_rx: Receiver<InboundHeaders>,
    inbound_blocks_rx: Receiver<crate::InboundBlock>,
    scheduler: Mutex<SchedulerState>,
    refused_rerequest_at: Mutex<Option<Instant>>,
    block_announcements: Mutex<hashbrown::HashMap<PeerSource, Hash256>>,
    apply_halted: std::sync::atomic::AtomicBool,
    /// Recent stale tips for BIP332 relay, kept across [`BlockSync::install_budget`]
    stale_tips: Arc<StaleTipRetainer>,
}

const MAX_DEFERRED_OWNED_FETCHES: usize = 16;

const COMPACT_RECONSTRUCTION_MAX_AHEAD: u32 = 2;

fn defer_owned_body_fetch(scheduler: &mut SchedulerState, source: PeerSource, hash: Hash256) {
    if scheduler
        .owned_body_fetches
        .iter()
        .any(|(owner, owned)| *owner == source && *owned == hash)
    {
        return;
    }
    if scheduler.owned_body_fetches.len() >= MAX_DEFERRED_OWNED_FETCHES {
        scheduler.owned_body_fetches.remove(0);
    }
    scheduler.owned_body_fetches.push((source, hash));
}

struct SchedulerState {
    window: DownloadWindow,
    stager: BlockStager,
    header_request_owner: Option<PeerSource>,
    owned_body_fetches: Vec<(PeerSource, Hash256)>,
    /// [`requests::BODY_UNAVAILABLE_RETRY`] with a safety ceiling, and
    /// independent of the window's pending budget.
    body_unavailable: requests::UnavailableBodies,
    chain_sync: hashbrown::HashMap<PeerSource, peers::ChainSyncState>,
    headers_sync: hashbrown::HashMap<PeerSource, PeerHeadersSync>,
    stale_tip: StaleTipState,
    expected_apply_cache: Option<ExpectedApplyCache>,
}

impl SchedulerState {
    fn populate_expected_apply_cache(&mut self, cache: ExpectedApplyCache) {
        if cache.hashes.is_empty() {
            return;
        }
        self.expected_apply_cache = Some(cache);
    }

    fn header_request(&self) -> Option<HeaderRequest> {
        self.header_request_owner
            .and_then(|source| self.headers_sync.get(&source)?.request)
    }

    /// INVARIANT: ownership is compared by connection identity, never by
    ///   address alone.
    fn release_unowned(&mut self, live: &[PeerSource]) {
        let owns = |source: &PeerSource| live.contains(source);
        self.window.retain_owned_by(owns);
        if self
            .header_request_owner
            .is_some_and(|source| !owns(&source))
        {
            self.header_request_owner = None;
        }
        self.owned_body_fetches.retain(|(source, _)| owns(source));
        self.body_unavailable.retain_owned_by(owns);
        self.chain_sync.retain(|source, _| owns(source));
        self.headers_sync.retain(|source, _| owns(source));
    }

    /// INVARIANT: only the chain-sync sweep writes this map outside its own
    ///   decision, and it writes it back the way it found it.
    fn restore_chain_sync(&mut self, source: PeerSource, prior: Option<peers::ChainSyncState>) {
        match prior {
            Some(state) => {
                self.chain_sync.insert(source, state);
            }
            None => {
                self.chain_sync.remove(&source);
            }
        }
    }
}

#[derive(Default)]
struct PeerHeadersSync {
    request: Option<HeaderRequest>,
    presync: Option<headers_presync::HeadersSyncState>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HeaderRequest {
    source: PeerSource,
    kind: HeaderRequestKind,
    locator_tip_hash: Hash256,
    target_height: u32,
    requested_at: Instant,
    state: HeaderRequestState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HeaderRequestKind {
    Frontier,
    ChainSyncProbe,
}

impl HeaderRequest {
    fn timeout(self) -> Duration {
        match (self.kind, self.state) {
            (HeaderRequestKind::ChainSyncProbe, HeaderRequestState::AwaitingResponse) => {
                peers::HEADERS_RESPONSE_TIME
            }
            _ => HEADER_REQUEST_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HeaderRequestState {
    AwaitingResponse,
    Answered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GetheadersOutcome {
    Sent,
    Suppressed,
    FrontierOwned,
    Failed,
}

#[derive(Clone, Debug)]
struct ExpectedApplyCache {
    chain_tip_hash: Hash256,
    applied_tip_hash: Hash256,
    applied_tip_height: u32,
    offset: usize,
    hashes: ExpectedBlockHashes,
}

#[derive(Clone, Copy, Debug, Default)]
struct GetdataRequestOutcome {
    sent: bool,
    has_request_capacity: bool,
}

impl BlockSync {
    /// INVARIANT: the latch is never replaced and never copied into a cached
    ///   boolean.
    #[must_use]
    pub fn new(
        chain: Arc<dyn SyncChain>,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Receiver<InboundHeaders>,
        inbound_blocks_rx: Receiver<crate::InboundBlock>,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    ) -> Self {
        let budget = default_sync_budget(chain.network());
        let stale_tips = Arc::new(StaleTipRetainer::seed(&chain.block_tree()));
        Self {
            historical: Mutex::new(historical::HistoricalDownload::new(budget)),
            historical_work: Mutex::new(()),
            chain,
            peer_table,
            ibd,
            inbound_headers_rx,
            inbound_blocks_rx,
            scheduler: Mutex::new(SchedulerState {
                window: DownloadWindow::new(budget),
                stager: BlockStager::new(budget),
                header_request_owner: None,
                owned_body_fetches: Vec::new(),
                body_unavailable: requests::UnavailableBodies::new(),
                chain_sync: hashbrown::HashMap::new(),
                headers_sync: hashbrown::HashMap::new(),
                stale_tip: StaleTipState::default(),
                expected_apply_cache: None,
            }),
            refused_rerequest_at: Mutex::new(None),
            block_announcements: Mutex::new(hashbrown::HashMap::new()),
            apply_halted: std::sync::atomic::AtomicBool::new(false),
            stale_tips,
        }
    }

    pub fn install_budget(&self, budget: SyncBudget) {
        *self.historical.lock() = historical::HistoricalDownload::new(budget);
        *self.scheduler.lock() = SchedulerState {
            window: DownloadWindow::new(budget),
            stager: BlockStager::new(budget),
            header_request_owner: None,
            owned_body_fetches: Vec::new(),
            body_unavailable: requests::UnavailableBodies::new(),
            chain_sync: hashbrown::HashMap::new(),
            headers_sync: hashbrown::HashMap::new(),
            stale_tip: StaleTipState::default(),
            expected_apply_cache: None,
        };
    }

    /// INVARIANT: one entry per connection — the first unprocessed
    /// announcement wins, so a later vector cannot replace an unknown tip
    /// before header sync drains it — and a flooding peer cannot grow the
    /// queue past the live session set.
    pub(crate) fn announce_block(&self, source: PeerSource, hash: Hash256) {
        self.block_announcements
            .lock()
            .entry(source)
            .or_insert(hash);
    }

    /// INVARIANT: `send_then` is not used here because it would charge a new
    /// budget credit instead of spending the held reply reservation; the
    /// `with_current` guard plus the reserved-credit `enqueue` is the
    /// linearizable path.
    pub(crate) fn enqueue_owned_body_fetch(
        &self,
        source: PeerSource,
        hash: Hash256,
        enqueue: impl FnOnce() -> bool,
    ) -> bool {
        let mut published = false;
        let admitted = self.peer_table.with_current(source, || {
            let mut scheduler = self.scheduler.lock();
            if !enqueue() {
                return;
            }
            defer_owned_body_fetch(&mut scheduler, source, hash);
            published = true;
        });
        admitted && published
    }

    /// INVARIANT: ownership is compared by connection identity, never by
    ///   address alone, so a same-address replacement cannot claim its
    ///   predecessor's request.
    #[must_use]
    pub(crate) fn owns_body_fetch(&self, source: PeerSource, hash: Hash256) -> bool {
        if self.historical.lock().window.pending_owner(&hash) == Some(source) {
            return true;
        }
        let scheduler = self.scheduler.lock();
        scheduler.window.pending_owner(&hash) == Some(source)
            || scheduler
                .owned_body_fetches
                .iter()
                .any(|(owner, owned)| *owner == source && *owned == hash)
    }

    /// INVARIANT: the tree read is released before the scheduler lock is
    ///   taken, keeping the `tree -> scheduler` order without nesting.
    ///
    #[must_use]
    pub(crate) fn compact_reconstruction_admissible(
        &self,
        source: PeerSource,
        header: &bitcoin_rs_primitives::Header,
    ) -> bool {
        let hash = Hash256::from(header.compute_hash());
        let network = self.chain.network();
        if bitcoin_rs_chain::validate_pow(header, hash, network).is_err() {
            return false;
        }
        let (candidate_work, candidate_height) = {
            let tree = self.chain.block_tree();
            let invalid = |id: NodeId| {
                tree.node(id)
                    .is_ok_and(|node| node.status == bitcoin_rs_chain::NodeStatus::Invalid)
            };
            let known = tree.lookup(hash);
            if known.is_some_and(invalid) {
                return false;
            }
            let Some(parent_id) = tree
                .lookup(Hash256::from(header.prev_blockhash))
                .filter(|&id| !invalid(id))
            else {
                return false;
            };
            if known.is_none()
                && bitcoin_rs_chain::validate_contextual_header(
                    &tree,
                    parent_id,
                    header,
                    network,
                    bitcoin_rs_chain::current_unix_seconds(),
                    bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
                )
                .is_err()
            {
                return false;
            }
            let Ok(parent) = tree.node(parent_id) else {
                return false;
            };
            (
                parent.chainwork + bitcoin_rs_chain::block_work(header),
                parent.height.saturating_add(1),
            )
        };
        let extends_applied = self.chain.applied_tip().is_none_or(|tip| {
            candidate_work > tip.chainwork
                && candidate_height <= tip.height.saturating_add(COMPACT_RECONSTRUCTION_MAX_AHEAD)
        });
        extends_applied || self.owns_body_fetch(source, hash)
    }

    pub fn tick(&self) {
        self.retire_timed_out_header_syncs(Instant::now());
        self.drain_inbound_headers();
        self.chain.bootstrap_genesis();
        self.reconcile_peer_sessions();
        self.advance_historical();
        self.drain_inbound_blocks();
        self.advance_historical();

        let now = Instant::now();
        let chain = self.observe_chain_frontier();
        self.reconcile_window_recovery(&chain, now);
        self.reconcile_peer_sessions();
        let mut frontier = self.observe_frontier(chain.clone(), now);
        let peers_changed = self.sweep_chain_sync(&frontier, now);
        self.follow_tip_progress(&frontier, now);
        if peers_changed {
            self.reconcile_peer_sessions();
            frontier = self.observe_frontier(chain, now);
        }
        let plan = frontier.plan();

        if !frontier.usable_peers.is_empty() {
            let selection = self.sync_peer_selection(&frontier, now);
            let mut sent_getdata = false;
            if plan.schedule_bodies {
                let request_peer_count = selection.request_peers.len();
                for (peer_idx, peer) in selection.request_peers.iter().enumerate() {
                    let peer_best_height = u32::try_from(peer.best_known_height).unwrap_or(0);
                    let request_outcome = self.send_getdata_for_pending_blocks(
                        peer.source,
                        peer_idx + 1 == request_peer_count,
                        peer_best_height,
                        &frontier.chain,
                    );
                    sent_getdata |= request_outcome.sent;
                    if request_outcome.sent && !request_outcome.has_request_capacity {
                        break;
                    }
                }
            }
            self.send_prefix_probes(&selection.probe_peers, now);
            if sent_getdata {
                self.record_pending_sync_metrics();
            }
        }
        match plan.header_action {
            HeaderAction::Idle | HeaderAction::AwaitPending => {}
            HeaderAction::Probe(source) => match self.probe_frontier_peer(&frontier, source) {
                GetheadersOutcome::Failed => {
                    self.request_headers_from_best_peer(&frontier, Some(source));
                }
                GetheadersOutcome::Suppressed | GetheadersOutcome::FrontierOwned => {
                    self.request_headers_from_best_peer(&frontier, None);
                }
                GetheadersOutcome::Sent => {}
            },
            HeaderAction::Extend => {
                self.request_headers_from_best_peer(&frontier, None);
            }
        }
        if let Some(reason) = plan.no_progress {
            Self::note_no_progress(&frontier, reason);
        }
    }

    /// INVARIANT: the staleness question is asked at most once per
    ///   `STALE_CHECK_INTERVAL`, so a stalled tip costs one dial rather than
    ///   one decision per tick.
    fn follow_tip_progress(&self, frontier: &SyncFrontier, now: Instant) {
        let Some(tip) = frontier.chain.applied_tip.as_ref() else {
            return;
        };
        let block_spacing =
            Duration::from_secs(u64::from(self.chain.network().target_spacing_seconds()));
        let mut scheduler = self.scheduler.lock();
        let blocks_in_flight = scheduler.window.pending_len();
        scheduler
            .stale_tip
            .follow(tip.height, tip.hash, blocks_in_flight, block_spacing, now);
    }

    /// INVARIANT: the connection manager is the only reader, because it is the
    ///   only part of the node that can dial.
    #[must_use]
    pub(crate) fn allow_extra_full_relay_dial(&self) -> bool {
        self.scheduler.lock().stale_tip.extra_dial_allowed
    }

    /// INVARIANT: the answer comes from the same window the fetch budget
    ///   reads, so a peer never both downloads and is retired as idle.
    #[must_use]
    pub(crate) fn is_downloading_bodies(&self, source: PeerSource) -> bool {
        self.scheduler.lock().window.is_downloading(source)
    }

    fn is_ancestor_at_height(
        tree: &BlockTree,
        ancestor: NodeId,
        height: u32,
        descendant: NodeId,
    ) -> bool {
        tree.node_at_height_from(descendant, height) == Some(ancestor)
    }

    fn first_connect_height(
        tree: &BlockTree,
        applied_hash: Hash256,
        target: NodeId,
    ) -> Option<u32> {
        let applied_id = tree.lookup(applied_hash)?;
        let height = tree.node(applied_id).ok()?.height;
        if Self::is_ancestor_at_height(tree, applied_id, height, target)
            && let Some(successor_height) = height.checked_add(1)
            && tree.node_at_height_from(target, successor_height).is_some()
        {
            return Some(successor_height);
        }
        let ancestor = tree.find_common_ancestor(applied_id, target)?;
        if ancestor == target {
            return None;
        }
        let mut first = target;
        loop {
            let node = tree.node(first).ok()?;
            if node.parent? == ancestor {
                return Some(node.height);
            }
            first = node.parent?;
        }
    }

    pub(super) fn next_required_body(&self) -> Option<RequiredBody> {
        let chain_tip = self.chain.chain_tip()?;
        let applied_tip = self.chain.applied_tip()?;
        let tree = self.chain.block_tree();
        Self::required_body_from_tips(&tree, applied_tip.hash, chain_tip.tip_id)
    }

    fn required_body_from_tips(
        tree: &BlockTree,
        applied_hash: Hash256,
        chain_tip: NodeId,
    ) -> Option<RequiredBody> {
        let height = Self::first_connect_height(tree, applied_hash, chain_tip)?;
        let node_id = tree.node_at_height_from(chain_tip, height)?;
        let node = tree.node(node_id).ok()?;
        Some(RequiredBody {
            height: node.height,
            hash: node.hash,
        })
    }

    pub(super) fn observe_chain_frontier(&self) -> ChainFrontier {
        let applied_tip = self.chain.applied_tip();
        let chain_tip = self.chain.chain_tip();
        let next_required = match (&applied_tip, &chain_tip) {
            (Some(applied), Some(chain)) => {
                let tree = self.chain.block_tree();
                Self::required_body_from_tips(&tree, applied.hash, chain.tip_id)
            }
            _ => None,
        };
        ChainFrontier {
            applied_tip,
            chain_tip,
            next_required,
            apply_halted: self.apply_halted.load(std::sync::atomic::Ordering::Acquire),
        }
    }

    pub(super) fn observe_frontier(&self, chain: ChainFrontier, now: Instant) -> SyncFrontier {
        let sessions = self.peer_table.usable_peers();
        let mut usable_peers = Vec::with_capacity(sessions.len());
        {
            let tree = self.chain.block_tree();
            let active_tip = chain.chain_tip.as_ref().map(|tip| tip.tip_id);
            for session in sessions {
                let demonstrated_tips = session.demonstrated_tips;
                let info = match session.info {
                    Some(info) => info,
                    None => continue,
                };
                let active_height = if demonstrated_tips.is_empty() {
                    u32::try_from(info.best_known_height).ok()
                } else {
                    active_tip.and_then(|tip| {
                        peers::active_demonstrated_height(&tree, tip, &demonstrated_tips)
                    })
                };
                usable_peers.push(UsablePeer {
                    source: session.lease.source(session.endpoint),
                    info,
                    demonstrated_tips,
                    active_height,
                    headers_horizon: session.headers_horizon,
                    role: session.lease.role(),
                    manual: session.lease.is_manual(),
                    connected_at: session.lease.connected_at(),
                });
            }
        }
        let scheduler = self.scheduler.lock();
        let body_state = chain.next_required.map(|required| {
            if scheduler.stager.contains(&required.hash) {
                BodyState::Staged
            } else if let Some(owner) = scheduler.window.pending_owner(&required.hash) {
                BodyState::InFlight(owner)
            } else {
                BodyState::Unowned
            }
        });
        let header_request = scheduler.header_request();
        SyncFrontier {
            chain,
            body_state,
            header_request,
            header_request_live: header_request_live(header_request, &usable_peers, now),
            usable_peers,
        }
    }

    fn note_no_progress(frontier: &SyncFrontier, reason: NoProgressReason) {
        if reason == NoProgressReason::AtTip {
            return;
        }
        metrics::counter!("node.sync.no_progress_ticks", "reason" => reason.as_str()).increment(1);
        let (applied_height, header_height) = frontier.heights();
        tracing::debug!(
            applied_height,
            header_height,
            %reason,
            peers = frontier.usable_peers.len(),
            "block sync: no apply-frontier progress possible this tick"
        );
    }
}

impl NoProgressReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AtTip => "at_tip",
            Self::ApplyHalted => "apply_halted",
            Self::ChainViewUnavailable => "chain_view_unavailable",
            Self::FrontierUnresolvable => "frontier_unresolvable",
            Self::NoUsablePeers => "no_usable_peers",
            Self::NoCapablePeer => "no_capable_peer",
        }
    }
}

impl std::fmt::Display for NoProgressReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_support;

/// INVARIANT: test-only. Production wires the node's chain-owned latch; a test
///   that exercises the block-service clause builds its own fixture.
#[cfg(test)]
#[must_use]
pub(crate) fn syncing_ibd_latch() -> Arc<bitcoin_rs_chain::InitialBlockDownload> {
    Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
        bitcoin_rs_chain::TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty())),
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(
            parking_lot::RwLock::new(BlockTree::new()),
        )),
    ))
}
