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
pub(crate) mod stale_tips;
mod telemetry;

#[cfg(test)]
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_execution::chain::BlockTree;
use bitcoin_rs_execution::chain::NodeId;
use crossbeam_channel::Receiver;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
#[cfg(test)]
use telemetry::metric_count;

use crate::p2p::BlockStager;
#[cfg(test)]
use crate::p2p::download_window::BLOCK_STALLING_TIMEOUT;
use crate::p2p::download_window::DownloadWindow;
#[cfg(test)]
use crate::p2p::download_window::GETDATA_BATCH_SIZE;
#[cfg(test)]
use crate::p2p::download_window::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
#[cfg(test)]
use crate::p2p::download_window::PEER_INFLIGHT_BUDGET;
#[cfg(test)]
use crate::p2p::download_window::PENDING_BUDGET;
use crate::p2p::download_window::RECEIVED_BLOCK_BUDGET;
#[cfg(test)]
use crate::p2p::download_window::RECEIVED_BLOCK_TIMEOUT;
use bitcoin_rs_wire::{InboundBlock, InboundHeaders, PeerSource, PeerTable};
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

pub(crate) use crate::p2p::download_window::SyncBudget;
pub use crate::p2p::download_window::default_sync_budget;

#[cfg(test)]
pub(crate) use crate::p2p::download_window::MIN_PEERS_FOR_FANOUT;

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
    ibd: Arc<bitcoin_rs_execution::chain::InitialBlockDownload>,
    inbound_headers_rx: Receiver<InboundHeaders>,
    inbound_blocks_rx: Receiver<InboundBlock>,
    scheduler: Mutex<SchedulerState>,
    refused_rerequest_at: Mutex<Option<Instant>>,
    block_announcements: Mutex<hashbrown::HashMap<PeerSource, Hash256>>,
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
pub(crate) struct HeaderRequest {
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
    fn is_live(self, now: Instant) -> bool {
        self.state == HeaderRequestState::ResponseQueued
            || now.saturating_duration_since(self.requested_at) < self.timeout()
    }

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
    ResponseQueued,
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
    #[must_use]
    pub fn new(
        chain: Arc<dyn SyncChain>,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Receiver<InboundHeaders>,
        inbound_blocks_rx: Receiver<InboundBlock>,
        ibd: Arc<bitcoin_rs_execution::chain::InitialBlockDownload>,
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

    pub(crate) fn announce_block(&self, source: PeerSource, hash: Hash256) {
        self.block_announcements
            .lock()
            .entry(source)
            .or_insert(hash);
    }

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
        header: &bitcoin_rs_consensus::primitives::Header,
    ) -> bool {
        let hash = Hash256::from(header.compute_hash());
        let network = self.chain.network();
        if bitcoin_rs_execution::chain::validate_pow(header, hash, network).is_err() {
            return false;
        }
        let (candidate_work, candidate_height) = {
            let tree = self.chain.block_tree();
            let invalid = |id: NodeId| {
                tree.node(id).is_ok_and(|node| {
                    node.status == bitcoin_rs_execution::chain::NodeStatus::Invalid
                })
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
                && bitcoin_rs_execution::chain::validate_contextual_header(
                    &tree,
                    parent_id,
                    header,
                    network,
                    bitcoin_rs_execution::chain::current_unix_seconds(),
                    bitcoin_rs_execution::chain::HeaderValidationMode::LiveAdmission,
                )
                .is_err()
            {
                return false;
            }
            let Ok(parent) = tree.node(parent_id) else {
                return false;
            };
            (
                parent.chainwork + bitcoin_rs_execution::chain::block_work(header),
                parent.height.saturating_add(1),
            )
        };
        let extends_applied = self.chain.applied_tip().is_none_or(|tip| {
            candidate_work > tip.chainwork
                && candidate_height <= tip.height.saturating_add(COMPACT_RECONSTRUCTION_MAX_AHEAD)
        });
        extends_applied || self.owns_body_fetch(source, hash)
    }

    #[must_use]
    pub fn closed_for_recovery(&self) -> bool {
        self.chain.closed_for_recovery()
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
                    let request_outcome = if peer_idx + 1 == request_peer_count {
                        self.send_getdata_for_pending_blocks_allowing_retry(
                            peer.source,
                            peer_best_height,
                            &frontier.chain,
                        )
                    } else {
                        self.send_getdata_for_pending_blocks(
                            peer.source,
                            peer_best_height,
                            &frontier.chain,
                        )
                    };
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

    #[must_use]
    pub(crate) fn allow_extra_full_relay_dial(&self) -> bool {
        self.scheduler.lock().stale_tip.extra_dial_allowed
    }

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
            closed_for_recovery: self.chain.closed_for_recovery(),
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
mod tests {
    use super::test_support::{ScriptedBranchSwitch, TestChain, mined_chain, synced_ibd_latch};
    use crate::test_support::{TestError, TestResult};
    use bitcoin_rs_wire::PeerRemote;
    use bitcoin_rs_wire::test_support::{
        OrFail, connect_peer, current_source, synthetic_peer, test_addr,
    };
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash;
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::{
        Block, BlockHash, BlockImage, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
        consensus_bytes,
    };
    use bitcoin_rs_execution::chain::{
        BlockTree, HeaderRefusal, InitialBlockDownload, NodeId, NodeStatus, TipSnapshot,
        regtest_fixture,
    };
    use bitcoin_rs_storage::split_chainstate_cache_budget;
    use crossbeam_channel::unbounded;
    use hashbrown::HashMap;
    use metrics::Counter;
    use metrics::CounterFn;
    use metrics::Gauge;
    use metrics::GaugeFn;
    use metrics::Histogram;
    use metrics::HistogramFn;
    use metrics::Key;
    use metrics::KeyName;
    use metrics::Metadata;
    use metrics::Recorder;
    use metrics::SharedString;
    use metrics::Unit;
    use parking_lot::Mutex;
    use parking_lot::RwLock;

    mod historical {
        use super::*;
        use crate::p2p::download_window::default_sync_budget;

        type HistoricalFixture = (SyncHarness, Arc<TestChain>, Vec<Block>);

        fn fixture(count: u32) -> Result<HistoricalFixture, TestError> {
            let (tree, blocks) = mined_chain(count, 0)?;
            let mut harness = SyncHarness::new(tree);
            let chain = Arc::new(TestChain::new(
                harness.block_tree.write().tip_handle(),
                harness.applied_tip.clone(),
                harness.block_tree.clone(),
            ));
            chain
                .historical
                .lock()
                .extend((1..=count).zip(blocks.iter().map(|block| block.block_hash().0)));
            harness.sync.chain = chain.clone();
            Ok((harness, chain, blocks))
        }

        fn deliver(sync: &BlockSync, block: &Block, source: PeerSource) {
            assert!(
                sync.receive_historical({
                    let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                    inbound.source = Some(source);
                    inbound
                })
                .is_none()
            );
        }

        #[test]
        fn local_replay_budget_does_not_send_getdata() -> TestResult {
            let (harness, chain, _blocks) = fixture(3)?;
            let addr = test_addr(28211, 0)?;
            let rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
            *chain.historical_replay_pending.lock() = true;

            harness.sync.advance_historical();
            assert!(
                rx.try_recv().is_err(),
                "local replay must not trigger getdata"
            );
            assert_eq!(harness.sync.historical.lock().window.pending_len(), 0);

            harness.sync.advance_historical();
            assert!(matches!(rx.try_recv()?, Message::GetData(_)));
            Ok(())
        }

        #[test]
        fn anonymous_peer_serves_historical_bodies() -> TestResult {
            let (harness, chain, _blocks) = fixture(3)?;
            let addr = test_addr(28211, 0)?;
            let rx = connect_anonymous_peer(&harness.peers, synthetic_peer(addr, 3));
            *chain.historical_replay_pending.lock() = true;

            harness.sync.advance_historical();
            assert!(
                rx.try_recv().is_err(),
                "local replay must not trigger getdata"
            );
            assert_eq!(harness.sync.historical.lock().window.pending_len(), 0);

            harness.sync.advance_historical();
            assert!(
                matches!(rx.try_recv()?, Message::GetData(_)),
                "an endpoint-less session must serve historical bodies like any peer"
            );
            Ok(())
        }

        #[test]
        fn historical_pipeline_bounds_pending_and_staged_and_applies_in_order() -> TestResult {
            let (harness, chain, blocks) = fixture(40)?;
            let first = test_addr(28200, 0)?;
            let second = test_addr(28200, 1)?;
            let receivers = [
                connect_peer(&harness.peers, synthetic_peer(first, 40)),
                connect_peer(&harness.peers, synthetic_peer(second, 40)),
            ];
            harness.sync.advance_historical();
            for rx in &receivers {
                let Message::GetData(items) = rx.try_recv()? else {
                    panic!("expected batch")
                };
                assert_eq!(items.len(), 16);
                assert!(rx.try_recv().is_err());
            }
            assert_eq!(harness.sync.historical.lock().window.pending_len(), 32);
            for block in blocks[1..32].iter().rev() {
                let source = harness
                    .sync
                    .historical
                    .lock()
                    .window
                    .pending_owner(&block.block_hash().0)
                    .ok_or("missing owner")?;
                deliver(&harness.sync, block, source);
            }
            harness.sync.advance_historical();
            assert!(chain.historical_connected.lock().is_empty());
            {
                let historical = harness.sync.historical.lock();
                assert_eq!(historical.window.pending_len(), 1);
                assert_eq!(historical.stager.received_len(), 31);
            }
            let source = harness
                .sync
                .historical
                .lock()
                .window
                .pending_owner(&blocks[0].block_hash().0)
                .ok_or("missing front")?;
            deliver(&harness.sync, &blocks[0], source);
            harness.sync.advance_historical();
            {
                let historical = harness.sync.historical.lock();
                assert_eq!(
                    historical.window.pending_len(),
                    8,
                    "refill while earlier bodies remain staged"
                );
                assert_eq!(historical.stager.received_len(), 24);
            }
            for _ in 0..4 {
                harness.sync.advance_historical();
            }
            assert_eq!(
                *chain.historical_connected.lock(),
                blocks[..32]
                    .iter()
                    .map(|block| block.block_hash().0)
                    .collect::<Vec<_>>()
            );
            for block in blocks[32..].iter().rev() {
                let source = harness
                    .sync
                    .historical
                    .lock()
                    .window
                    .pending_owner(&block.block_hash().0)
                    .ok_or("missing tail")?;
                deliver(&harness.sync, block, source);
            }
            harness.sync.advance_historical();
            harness.sync.advance_historical();
            assert_eq!(
                *chain.historical_connected.lock(),
                blocks
                    .iter()
                    .map(|block| block.block_hash().0)
                    .collect::<Vec<_>>()
            );
            let historical = harness.sync.historical.lock();
            assert_eq!(historical.window.pending_len(), 0);
            assert_eq!(historical.stager.received_len(), 0);
            Ok(())
        }

        #[test]
        fn historical_archive_replay_retires_overtaken_downloads() -> TestResult {
            let (harness, chain, blocks) = fixture(6)?;
            let addr = test_addr(28204, 0)?;
            let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 6));
            harness.sync.advance_historical();
            let source = current_source(&harness.peers, addr);
            deliver(&harness.sync, &blocks[1], source);
            for _ in 0..3 {
                chain.historical.lock().pop_front();
            }
            harness.sync.advance_historical();
            let historical = harness.sync.historical.lock();
            assert_eq!(historical.window.pending_len(), 3);
            assert_eq!(historical.stager.received_len(), 0);
            for block in &blocks[..3] {
                assert!(
                    historical
                        .window
                        .pending_owner(&block.block_hash().0)
                        .is_none()
                );
            }
            Ok(())
        }

        #[test]
        fn late_retired_history_cannot_enter_foreground_staging() -> TestResult {
            let (harness, chain, blocks) = fixture(6)?;
            chain.bootstrap_genesis();
            let owned_payloads: Vec<BlockImage> =
                blocks.iter().cloned().map(BlockImage::from_local).collect();
            let payloads: Vec<&BlockImage> = owned_payloads.iter().collect();
            chain
                .commit_window(&payloads)
                .map_err(|error| crate::test_support::TestError::Commit(format!("{error:?}")))?;
            let addr = test_addr(28205, 0)?;
            let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 7));
            harness.sync.advance_historical();
            let source = current_source(&harness.peers, addr);
            chain.historical.lock().pop_front();
            harness.sync.advance_historical();
            assert!(
                !harness
                    .sync
                    .owns_body_fetch(source, blocks[0].block_hash().0)
            );

            for competing_headers in [false, true] {
                if competing_headers {
                    let mut tree = harness.block_tree.write();
                    let mut parent = tree
                        .lookup(Network::Regtest.genesis_block().block_hash().0)
                        .ok_or("missing genesis")?;
                    for height in 1..=7 {
                        let block = regtest_fixture::mined_block_with_prev_hash(
                            BlockHash(tree.node(parent)?.hash),
                            height,
                            vec![regtest_fixture::coinbase(10_000 + height)],
                        )?;
                        parent =
                            tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
                    }
                    assert_ne!(
                        tree.tip().ok_or("missing header tip")?.hash,
                        blocks[5].block_hash().0
                    );
                }
                let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone());
                inbound.source = Some(source);
                let inbound = harness
                    .sync
                    .receive_historical(inbound)
                    .ok_or("retired lease must not retain ownership")?;
                let mut deliveries = vec![inbound];
                assert_eq!(
                    harness
                        .sync
                        .buffer_received_block_chunk(&mut deliveries, None),
                    0
                );
                assert_eq!(harness.sync.scheduler.lock().stager.received_len(), 0);
                assert_eq!(
                    harness
                        .applied_tip
                        .load_full()
                        .ok_or("missing foreground tip")?
                        .hash,
                    blocks[5].block_hash().0
                );
                assert!(chain.historical_connected.lock().is_empty());
            }
            Ok(())
        }

        #[test]
        fn historical_pipeline_retries_expired_owner_on_another_connection() -> TestResult {
            let (harness, _, blocks) = fixture(4)?;
            harness.sync.install_budget(
                default_sync_budget(Network::Regtest)
                    .with_pending_timeout_override(Duration::from_secs(1)),
            );
            let old_addr = test_addr(28201, 0)?;
            let old_rx = connect_peer(&harness.peers, synthetic_peer(old_addr, 4));
            harness.sync.advance_historical();
            assert!(matches!(old_rx.try_recv()?, Message::GetData(_)));
            let new_addr = test_addr(28201, 1)?;
            let new_rx = connect_peer(&harness.peers, synthetic_peer(new_addr, 4));
            harness
                .sync
                .request_historical(1, Instant::now() + Duration::from_secs(2));
            assert!(matches!(new_rx.try_recv()?, Message::GetData(items) if items.len() == 4));
            let new_source = current_source(&harness.peers, new_addr);
            for block in blocks {
                assert!(
                    harness
                        .sync
                        .owns_body_fetch(new_source, block.block_hash().0)
                );
            }
            assert!(old_rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn historical_pipeline_bounds_bytes_and_keeps_front_admissible() -> TestResult {
            let (harness, chain, blocks) = fixture(6)?;
            let body_bytes = consensus_bytes(&blocks[0]).len();
            let mut budget = default_sync_budget(Network::Regtest);
            budget.max_received_bytes = body_bytes * 2;
            harness.sync.install_budget(budget);
            let addr = test_addr(28202, 0)?;
            let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 6));
            harness.sync.advance_historical();
            let source = current_source(&harness.peers, addr);
            for block in blocks[1..].iter().rev() {
                deliver(&harness.sync, block, source);
            }
            assert!(
                harness.sync.historical.lock().stager.received_bytes() <= budget.max_received_bytes
            );
            deliver(&harness.sync, &blocks[0], source);
            assert!(
                harness.sync.historical.lock().stager.received_bytes()
                    <= budget.max_received_bytes + body_bytes
            );
            harness.sync.advance_historical();
            assert_eq!(
                chain.historical_connected.lock().first(),
                Some(&blocks[0].block_hash().0)
            );
            Ok(())
        }

        fn witness_inventory(block: &Block) -> Inventory {
            Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                block.block_hash().0.to_le_bytes(),
            ))
        }

        fn historical_owner(sync: &BlockSync, block: &Block) -> Option<PeerSource> {
            sync.historical
                .lock()
                .window
                .pending_owner(&block.block_hash().0)
        }

        #[test]
        fn historical_notfound_releases_the_exact_owner_and_the_alternate_serves_it_once()
        -> TestResult {
            let (harness, chain, blocks) = fixture(3)?;
            let addrs = [test_addr(28230, 0)?, test_addr(28230, 1)?];
            let receivers = [
                connect_peer(&harness.peers, synthetic_peer(addrs[0], 3)),
                connect_peer(&harness.peers, synthetic_peer(addrs[1], 3)),
            ];
            let sources = [
                current_source(&harness.peers, addrs[0]),
                current_source(&harness.peers, addrs[1]),
            ];
            let first = witness_inventory(&blocks[0]);

            harness.sync.advance_historical();
            let owner_source = historical_owner(&harness.sync, &blocks[0])
                .ok_or("the first body must be requested")?;
            let owner = usize::from(owner_source != sources[0]);
            let alternate = 1 - owner;
            let alternate_source = sources[alternate];
            let initial: Vec<Vec<Inventory>> = receivers.iter().map(drain_getdata_items).collect();
            assert_eq!(
                initial
                    .iter()
                    .flatten()
                    .filter(|item| **item == first)
                    .count(),
                1,
                "the first body is requested once, from its owner"
            );
            assert!(initial[owner].contains(&first));

            assert!(
                !harness
                    .sync
                    .block_not_found(alternate_source, std::slice::from_ref(&first))
            );
            assert_eq!(
                historical_owner(&harness.sync, &blocks[0]),
                Some(owner_source)
            );

            assert!(
                harness
                    .sync
                    .block_not_found(owner_source, std::slice::from_ref(&first))
            );
            assert_eq!(historical_owner(&harness.sync, &blocks[0]), None);
            for _ in 0..3 {
                harness.sync.advance_historical();
            }
            assert!(
                !drain_getdata_items(&receivers[owner]).contains(&first),
                "an owner that answered notfound is not asked for the body again"
            );
            assert_eq!(
                drain_getdata_items(&receivers[alternate])
                    .iter()
                    .filter(|item| **item == first)
                    .count(),
                1,
                "the alternate is asked for the released body exactly once"
            );
            assert_eq!(
                historical_owner(&harness.sync, &blocks[0]),
                Some(alternate_source)
            );
            assert!(
                harness.peers.is_connected(addrs[owner]),
                "a peer that lacks a body is not punished"
            );

            for block in &blocks {
                let source = historical_owner(&harness.sync, block)
                    .ok_or("every body must still be pending")?;
                deliver(&harness.sync, block, source);
            }
            for _ in 0..4 {
                harness.sync.advance_historical();
            }
            assert_eq!(
                *chain.historical_connected.lock(),
                blocks
                    .iter()
                    .map(|block| block.block_hash().0)
                    .collect::<Vec<_>>()
            );
            Ok(())
        }

        #[test]
        fn historical_notfound_only_peer_is_not_polled_and_is_retried_after_the_interval()
        -> TestResult {
            let (harness, _chain, blocks) = fixture(3)?;
            let addr = test_addr(28231, 0)?;
            let rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
            let source = current_source(&harness.peers, addr);
            let first = witness_inventory(&blocks[0]);

            harness.sync.advance_historical();
            assert!(drain_getdata_items(&rx).contains(&first));
            assert!(
                harness
                    .sync
                    .block_not_found(source, std::slice::from_ref(&first))
            );
            assert_eq!(historical_owner(&harness.sync, &blocks[0]), None);

            for _ in 0..4 {
                harness.sync.advance_historical();
            }
            assert!(
                drain_getdata_items(&rx).is_empty(),
                "no wake-up-paced getdata/notfound loop against the only peer"
            );
            assert!(harness.peers.is_connected(addr));

            let aged = Instant::now()
                .checked_sub(BODY_UNAVAILABLE_RETRY + Duration::from_secs(1))
                .ok_or("monotonic clock is younger than the retry interval")?;
            harness.sync.scheduler.lock().body_unavailable.note(
                source,
                blocks[0].block_hash().0,
                aged,
            );
            harness.sync.advance_historical();
            assert_eq!(
                drain_getdata_items(&rx)
                    .iter()
                    .filter(|item| **item == first)
                    .count(),
                1
            );
            harness.sync.advance_historical();
            assert_eq!(drain_getdata_items(&rx), Vec::<Inventory>::new());

            assert!(
                harness
                    .sync
                    .block_not_found(source, std::slice::from_ref(&first))
            );
            assert!(harness.sync.scheduler.lock().body_unavailable.refuses(
                source,
                blocks[0].block_hash().0,
                Instant::now()
            ));
            assert!(harness.peers.disconnect_source(source));
            harness.sync.reconcile_peer_sessions();
            assert!(!harness.sync.scheduler.lock().body_unavailable.refuses(
                source,
                blocks[0].block_hash().0,
                Instant::now()
            ));
            Ok(())
        }

        #[test]
        fn historical_delivery_ends_the_notfound_record() -> TestResult {
            let (harness, _chain, blocks) = fixture(3)?;
            let addr = test_addr(28232, 0)?;
            let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
            let source = current_source(&harness.peers, addr);
            let hash = blocks[0].block_hash().0;

            harness.sync.advance_historical();
            assert_eq!(historical_owner(&harness.sync, &blocks[0]), Some(source));
            harness
                .sync
                .scheduler
                .lock()
                .body_unavailable
                .note(source, hash, Instant::now());
            assert!(harness.sync.scheduler.lock().body_unavailable.refuses(
                source,
                hash,
                Instant::now()
            ));

            deliver(&harness.sync, &blocks[0], source);
            assert!(
                !harness.sync.scheduler.lock().body_unavailable.refuses(
                    source,
                    hash,
                    Instant::now()
                ),
                "a delivered historical body ends the record"
            );
            Ok(())
        }

        #[test]
        fn historical_pipeline_follows_snapshot_branch_instead_of_best_header() -> TestResult {
            let (harness, chain, _) = fixture(5)?;
            let mut tree = harness.block_tree.write();
            let mut parent = tree
                .lookup(Network::Regtest.genesis_block().block_hash().0)
                .ok_or("missing genesis")?;
            let mut pinned = Vec::new();
            for height in 1..=3 {
                let prev = BlockHash(tree.node(parent)?.hash);
                let block = regtest_fixture::mined_block_with_prev_hash(
                    prev,
                    height,
                    vec![regtest_fixture::coinbase(9_000 + height)],
                )?;
                parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
                pinned.push(block);
            }
            assert_ne!(
                tree.tip().ok_or("missing header tip")?.hash,
                pinned[2].block_hash().0
            );
            drop(tree);
            *chain.historical.lock() = (1..)
                .zip(pinned.iter().map(|block| block.block_hash().0))
                .collect();
            let addr = test_addr(28203, 0)?;
            let rx = connect_peer(&harness.peers, synthetic_peer(addr, 5));
            harness.sync.advance_historical();
            let Message::GetData(items) = rx.try_recv()? else {
                panic!("expected batch")
            };
            assert_eq!(
                items,
                pinned
                    .iter()
                    .map(
                        |block| Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                            block.block_hash().0.to_le_bytes()
                        ))
                    )
                    .collect::<Vec<_>>()
            );
            let source = current_source(&harness.peers, addr);
            for block in pinned.iter().rev() {
                deliver(&harness.sync, block, source);
            }
            harness.sync.advance_historical();
            assert_eq!(
                *chain.historical_connected.lock(),
                pinned
                    .iter()
                    .map(|block| block.block_hash().0)
                    .collect::<Vec<_>>()
            );
            Ok(())
        }
    }

    use super::chain::{
        HeaderAdmission, ReorgError, SyncChain, SyncChainError, WindowApplyDisposition,
        WindowCommitError,
    };
    use super::receive::unrequested_body_admissible;
    use super::requests::BODY_UNAVAILABLE_RETRY;
    use super::{BlockSync, Inventory};
    use crate::p2p::block_stager::StagedBlock;
    use bitcoin_rs_wire::{InboundHeaders, Message, PeerInfo, PeerLease, PeerSource, PeerTable};

    struct RefusingChain(Arc<TestChain>);

    impl SyncChain for RefusingChain {
        fn network(&self) -> Network {
            self.0.network()
        }

        fn block_tree(&self) -> parking_lot::RwLockReadGuard<'_, BlockTree> {
            self.0.block_tree()
        }

        fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.0.chain_tip()
        }

        fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.0.applied_tip()
        }

        fn bootstrap_genesis(&self) {
            self.0.bootstrap_genesis();
        }

        fn admit_headers(&self, _headers: &[Header]) -> HeaderAdmission {
            HeaderAdmission::Refused(HeaderRefusal::from_cause(&"scripted admission refusal"))
        }

        fn minimum_chain_work(&self) -> ChainWork {
            self.0.minimum_chain_work()
        }

        fn check_body_binding(&self, block: &BlockImage) -> Result<(), SyncChainError> {
            self.0.check_body_binding(block)
        }

        fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
            self.0.window_len(serialized_sizes)
        }

        fn commit_window(&self, payloads: &[&BlockImage]) -> Result<usize, WindowCommitError> {
            self.0.commit_window(payloads)
        }

        fn switch_to_branch(
            &self,
            target: NodeId,
            staged_body: &mut dyn FnMut(Hash256) -> Option<BlockImage>,
            connected_body: &mut dyn FnMut(Hash256),
        ) -> Result<(), ReorgError> {
            self.0.switch_to_branch(target, staged_body, connected_body)
        }
    }

    #[test]
    fn body_forwarded_batch_does_not_consume_the_pending_header_gate() -> TestResult {
        for build_fixture in [header_sync_with_genesis, header_sync_with_refusing_chain] {
            let HeaderSyncFixture {
                genesis,
                sync,
                inbound_headers_tx,
                peers,
            } = build_fixture()?;
            let a = test_addr(9771, 0)?;
            let b = test_addr(9771, 1)?;
            let a_rx = connect_peer(&peers, synthetic_peer(a, 8));
            let b_rx = connect_peer(&peers, synthetic_peer(b, 8));
            let a_source = current_source(&peers, a);

            sync.tick();
            assert!(
                a_rx.try_iter()
                    .any(|message| matches!(message, Message::GetHeaders(_))),
                "the first tick must ask `a`",
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![far_future_header(genesis.compute_hash(), 1)?],
                source: Some(a_source),
                wire_response: false,
            })?;
            sync.tick();

            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(|request| request.source == a_source),
                "a body-forwarded batch is not an answer: the gate stays with `a`",
            );

            let timeout = sync
                .scheduler
                .lock()
                .header_request()
                .map(super::HeaderRequest::timeout)
                .ok_or("the request must still be registered")?;
            let almost = Instant::now()
                .checked_sub(timeout.saturating_sub(Duration::from_millis(1)))
                .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
            sync.scheduler
                .lock()
                .headers_sync
                .get_mut(&a_source)
                .and_then(|owned| owned.request.as_mut())
                .ok_or("the request must still be registered")?
                .requested_at = almost;
            sync.tick();
            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(
                        |request| request.source == a_source && request.requested_at == almost
                    ),
                "a request short of its deadline keeps its owner and stamp",
            );
            assert!(
                !a_rx
                    .try_iter()
                    .chain(b_rx.try_iter())
                    .any(|message| matches!(message, Message::GetHeaders(_))),
                "no header request re-issues before the deadline",
            );

            let backdated = Instant::now()
                .checked_sub(timeout)
                .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
            sync.scheduler
                .lock()
                .headers_sync
                .get_mut(&a_source)
                .and_then(|owned| owned.request.as_mut())
                .ok_or("the request must still be registered")?
                .requested_at = backdated;
            sync.tick();

            let reasked_a = a_rx
                .try_iter()
                .any(|message| matches!(message, Message::GetHeaders(_)));
            let reasked_b = b_rx
                .try_iter()
                .any(|message| matches!(message, Message::GetHeaders(_)));
            assert!(
                reasked_a || reasked_b,
                "an expired gate must re-issue a header request this tick",
            );
            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(|request| request.requested_at > backdated),
                "the re-issued request must carry a fresh deadline",
            );
        }
        Ok(())
    }

    #[test]
    fn tick_allows_demoted_peer_when_it_is_the_only_eligible_peer() -> TestResult {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                ..super::default_sync_budget(Network::Regtest)
            }
            .with_pending_timeout_override(Duration::ZERO),
        );
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        let Message::GetData(first_inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
        let headers = rx.try_recv()?;
        if !matches!(headers, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders").into());
        }

        sync.tick();

        let Message::GetData(retry_inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
        Ok(())
    }

    #[test]
    fn purge_of_one_invalidated_batch_keeps_the_owner_queue_start_at_one_instant() -> TestResult {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 4,
                getdata_batch_limit: 4,
                ..super::default_sync_budget(Network::Regtest)
            },
        );
        let addr = test_addr(9345, 0)?;
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        let requested = witness_block_inventory(next_getdata(&rx)?)?;
        assert_eq!(requested, expected[..4]);
        let to_hash = |block: &BlockHash| Hash256::from_le_bytes(block.as_bytes());
        let all: Vec<Hash256> = requested.iter().map(to_hash).collect();
        let owner = current_source(&peers, addr);
        let queue_start = |sync: &BlockSync| {
            sync.scheduler
                .lock()
                .window
                .owner_queue_start_for_test(owner)
        };
        let before =
            queue_start(&sync).or_fail("the batched request stamps the owner's queue start");

        sync.purge_invalidated(&all[..2]);
        assert_eq!(
            queue_start(&sync),
            Some(before),
            "one purge must not re-stamp the owner's queue age per removed hash"
        );
        assert_eq!(
            sync.scheduler.lock().window.pending_owner(&all[2]),
            Some(owner)
        );

        sync.purge_invalidated(&all[2..]);
        assert_eq!(queue_start(&sync), None);
        Ok(())
    }

    #[test]
    fn getdata_uses_compact_flavor_only_for_relaying_peers_near_tip() -> TestResult {
        let assert_flavor = |inventory: &[Inventory], compact: bool| {
            assert_ne!(inventory, []);
            for item in inventory {
                if compact {
                    assert!(matches!(item, Inventory::CompactBlock(_)), "got {item:?}");
                } else {
                    assert!(matches!(item, Inventory::WitnessBlock(_)), "got {item:?}");
                }
            }
        };
        let first_getdata =
            |rx: &bitcoin_rs_wire::test_support::MessageReceiver| -> Vec<Inventory> {
                loop {
                    match rx.try_recv() {
                        Ok(Message::GetData(inventory)) => return inventory,
                        Ok(_) => continue,
                        Err(error) => panic!("expected a getdata batch: {error}"),
                    }
                }
            };

        let (sync, peers, _block_tree, _applied, _expected) = sync_with_header_chain(4)?;
        install_budget(&sync, super::default_sync_budget(Network::Regtest));
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9_101,
        ));
        let mut relaying = synthetic_peer(addr, 100);
        relaying.compact_block_relay = true;
        let rx = connect_peer(&peers, relaying);
        sync.tick();
        assert_flavor(&first_getdata(&rx), true);

        let (sync, peers, _block_tree, _applied, _expected) = sync_with_header_chain(4)?;
        install_budget(&sync, super::default_sync_budget(Network::Regtest));
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9_102,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));
        sync.tick();
        assert_flavor(&first_getdata(&rx), false);

        let (sync, peers, _block_tree, _applied, _expected) = sync_with_header_chain(9)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 9,
                max_peer_inflight: 9,
                getdata_batch_limit: 9,
                ..super::default_sync_budget(Network::Regtest)
            },
        );
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9_103,
        ));
        let mut relaying = synthetic_peer(addr, 100);
        relaying.compact_block_relay = true;
        let rx = connect_peer(&peers, relaying);
        sync.tick();
        assert_flavor(&first_getdata(&rx), false);
        Ok(())
    }

    #[test]
    fn unsolicited_stale_block_retries_from_resolved_header_height() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )
        .or_fail("regtest fixture block");
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            block1.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .or_fail("regtest fixture block");
        let block1_hash = block1.block_hash();
        let expected_hash = block2.block_hash();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block1_id =
            tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);
        install_budget(
            &sync,
            super::SyncBudget {
                getdata_batch_limit: 2,
                received_timeout: Duration::ZERO,
                ..super::default_sync_budget(Network::Regtest)
            },
        );
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        let Message::GetData(initial) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial getdata").into());
        };
        assert_eq!(
            witness_block_inventory(initial)?,
            std::vec![block1_hash, expected_hash]
        );
        let _headers = rx.try_recv()?;
        apply_fixture_block(&sync, block1)?;
        {
            let hash = Hash256::from(expected_hash);
            let height = {
                let tree = sync.chain.block_tree();
                tree.lookup(hash)
                    .and_then(|id| tree.node(id).ok())
                    .map(|node| node.height)
            };
            sync.scheduler
                .lock()
                .window
                .requeue_for_retry(&hash, height, Instant::now());
        }

        inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block2))?;
        sync.drain_inbound_blocks();

        assert_eq!(sync.scheduler.lock().stager.received_len(), 0);

        sync.tick();

        let Message::GetData(retry) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected height-2 retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry)?, std::vec![expected_hash]);
        Ok(())
    }

    #[test]
    fn inv_delivered_block_admits_carried_header_and_applies() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let block = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )
        .or_fail("regtest fixture block");
        let block_hash = block.block_hash();
        let mut tree = BlockTree::new();
        tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);
        install_budget(&sync, super::default_sync_budget(Network::Regtest));
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 0));

        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree)?;
        assert!(
            rx.try_recv().is_err(),
            "nothing to send before any announcement"
        );

        let source = current_source(&peers, addr);
        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block);
        inbound.source = Some(source);
        inbound_blocks_tx.send(inbound)?;
        sync.tick();

        let applied = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied.hash, Hash256::from(block_hash));
        assert_eq!(applied.height, 1);
        let best_known = peers
            .sessions()
            .iter()
            .find(|session| session.addr == addr)
            .and_then(|session| session.info.as_ref())
            .map(|info| info.best_known_height)
            .ok_or_else(|| std::io::Error::other("missing peer info"))?;
        assert_eq!(best_known, 1);
        assert!(
            peers
                .announcement_state(source)
                .is_some_and(|state| state.useful_block_sequence > 0),
            "a validated and committed delivery must become high-bandwidth selection evidence"
        );
        assert_no_getdata(&rx)?;
        Ok(())
    }

    #[test]
    fn out_of_order_delivered_blocks_admit_and_apply() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )
        .or_fail("regtest fixture block");
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            block1.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .or_fail("regtest fixture block");
        let mut tree = BlockTree::new();
        tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);
        install_budget(&sync, super::default_sync_budget(Network::Regtest));
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 0));
        let source = current_source(&peers, addr);

        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree)?;

        for block in [block2, block1] {
            let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block);
            inbound.source = Some(source);
            inbound_blocks_tx.send(inbound)?;
        }

        sync.tick();
        sync.tick();

        let applied = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied.height, 2);
        for message in std::iter::from_fn(|| rx.try_recv().ok()) {
            assert!(
                matches!(message, Message::GetHeaders(_)),
                "a same-drain admission may only fire a benign getheaders, never a body retry"
            );
        }
        Ok(())
    }

    // BUD-06
    #[test]
    fn staged_images_charge_follows_retained_images() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )
        .or_fail("regtest fixture block");
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            block1.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .or_fail("regtest fixture block");
        let mut tree = BlockTree::new();
        tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);
        install_budget(&sync, super::default_sync_budget(Network::Regtest));
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8_334,
        ));
        let _rx = connect_peer(&peers, synthetic_peer(addr, 0));
        let source = current_source(&peers, addr);
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree)?;

        let budget = Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
            split_chainstate_cache_budget(64 * 1024 * 1024),
            4,
        ));
        let ledger = Arc::new(crate::budget::BudgetedIngressLedger::new(Arc::clone(
            &budget,
        )));
        let block_memory = Arc::new(bitcoin_rs_wire::inbound::block_memory::BlockMemory::new(
            ledger,
        ));

        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block2);
        inbound.source = Some(source);
        let retained = inbound
            .payload()
            .bytes()
            .len()
            .saturating_add(inbound.payload().retained_heap_bytes());
        let hash = Hash256::from(inbound.payload().block_hash());
        let mut credit = block_memory
            .reserve(retained, || false)
            .map_err(|error| TestError::message(error.to_string()))?;
        credit
            .retain(retained)
            .map_err(|error| TestError::message(error.to_string()))?;
        inbound.memory_credit = Some(credit);
        inbound_blocks_tx.send(inbound)?;
        sync.tick();

        assert!(
            sync.scheduler.lock().stager.contains(&hash),
            "the future body must stay staged without its predecessor"
        );
        let charged = budget.charged_bytes(bitcoin_rs_storage::budget::BudgetOwner::StagedImages);
        assert_eq!(
            charged,
            u64::try_from(retained).map_err(|_| TestError::message("size overflow"))?,
            "the retained image must own its staged-image charge"
        );
        Ok(())
    }

    #[test]
    fn missing_parent_block_delivery_recovers_with_getheaders() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )
        .or_fail("regtest fixture block");
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            block1.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .or_fail("regtest fixture block");
        let mut tree = BlockTree::new();
        tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx,
        } = SyncHarness::new(tree);
        install_budget(&sync, super::default_sync_budget(Network::Regtest));
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 0));
        let source = current_source(&peers, addr);

        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree)?;

        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block2.clone());
        inbound.source = Some(source);
        inbound_blocks_tx.send(inbound)?;
        sync.tick();
        let Message::GetHeaders(_) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected recovery getheaders").into());
        };
        assert!(
            block_tree
                .read()
                .lookup(Hash256::from(block2.block_hash()))
                .is_none(),
            "unattachable header must not be admitted"
        );

        inbound_headers_tx.send(InboundHeaders {
            headers: vec![block1.header, block2.header],
            source: Some(source),
            wire_response: true,
        })?;
        sync.tick();
        assert_eq!(
            witness_block_inventory(next_getdata(&rx)?)?,
            std::vec![block1.block_hash()]
        );
        assert_eq!(
            {
                let hash = Hash256::from(block2.block_hash());
                let tree = sync.chain.block_tree();
                tree.lookup(hash)
                    .and_then(|id| tree.node(id).ok())
                    .map(|node| node.height)
            },
            Some(2),
            "header admission must reconcile the staged child's height"
        );

        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block1);
        inbound.source = Some(source);
        inbound_blocks_tx.send(inbound)?;
        sync.tick();
        sync.tick();
        let applied = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied.hash, Hash256::from(block2.block_hash()));
        assert_eq!(applied.height, 2);
        Ok(())
    }

    #[test]
    fn tick_fanout_deferred_for_fresh_probe_engages_at_deadline() -> TestResult {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(16)?;
        install_budget(&sync, super::default_sync_budget(Network::Regtest));

        let owner_addr = test_addr(9401, 0)?;
        let alternate_addr = test_addr(9401, 1)?;
        let owner_rx = connect_peer(&peers, synthetic_peer(owner_addr, 201));
        let alternate_rx = connect_peer(&peers, synthetic_peer(alternate_addr, 200));

        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree)?;
        assert_eq!(
            witness_block_inventory(next_getdata(&owner_rx)?)?,
            expected,
            "the deep owner must receive the full window"
        );
        assert_eq!(
            witness_block_inventory(next_getdata(&alternate_rx)?)?,
            expected[..8],
            "the alternate must receive the one-shot probe prefix"
        );
        assert!(
            !sync.scheduler.lock().window.fanout_active(),
            "below the threshold fanout must stay off"
        );

        for idx in 2..super::MIN_PEERS_FOR_FANOUT {
            connect_peer(&peers, synthetic_peer(test_addr(9401, idx)?, 200));
        }
        sync.tick();
        assert!(
            !sync.scheduler.lock().window.fanout_active(),
            "a fresh prefix probe must defer the threshold-crossing tick"
        );

        let mut scheduler = sync.scheduler.lock();
        let window = &mut scheduler.window;
        let started_at = window
            .active_prefix_probe_started_at()
            .ok_or_else(|| std::io::Error::other("probe must remain active after deferral"))?;
        let budget = super::default_sync_budget(Network::Regtest);
        let planned_duration = budget.stall_timeout_initial;
        let deadline = started_at + planned_duration;
        assert_eq!(
            deadline - started_at,
            planned_duration,
            "planned deadline must be exactly stall_timeout_initial after probe start"
        );
        window.set_fanout_eligible_peers(super::MIN_PEERS_FOR_FANOUT, deadline);
        assert!(
            window.fanout_active(),
            "fanout must engage at the stall_timeout_initial deadline"
        );
        assert!(
            window.prefix_probe_plan().is_none(),
            "no probe plan may remain once fanout engages"
        );
        Ok(())
    }

    fn assert_fallback_with_ineligible_candidate(
        ineligible: PeerInfo,
        serves_fallback: bool,
    ) -> TestResult {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let ineligible_rx = connect_peer(&peers, ineligible);
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
            let addr = test_addr(9230, idx)?;
            rxs.push(connect_peer(
                &peers,
                synthetic_peer(addr, 300 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        let deep_rx = if serves_fallback {
            &ineligible_rx
        } else {
            &rxs[0]
        };
        let Message::GetData(inventory) = deep_rx.try_recv()? else {
            return Err(std::io::Error::other("expected one deep fallback getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected);
        if !serves_fallback {
            assert_no_getdata(&ineligible_rx)?;
        }
        for rx in &rxs[usize::from(!serves_fallback)..] {
            assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
        }
        Ok(())
    }

    fn assert_fallback_served_by_candidate(candidate: PeerInfo) -> TestResult {
        assert_fallback_with_ineligible_candidate(candidate, true)
    }

    fn assert_fallback_refused_to_candidate(candidate: PeerInfo) -> TestResult {
        assert_fallback_with_ineligible_candidate(candidate, false)
    }

    #[test]
    fn stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued() -> TestResult
    {
        let budget = super::SyncBudget {
            stall_timeout_initial: Duration::from_millis(100),
            ..wedge_budget(Duration::from_mins(1))
        };
        let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
        let staller = test_addr(9320, 0)?;

        sync.scheduler
            .lock()
            .window
            .seed_front_cadence_for_test(50, Instant::now());

        sync.tick();
        {
            let scheduler = sync.scheduler.lock();
            assert_eq!(scheduler.stager.received_len(), 14);
            assert_eq!(scheduler.window.pending_len(), 2);
            assert_eq!(
                scheduler.window.stalling_peer().map(|(addr, _)| addr),
                Some(staller.endpoint()),
                "the front-stripe owner must be the observed staller"
            );
        }

        std::thread::sleep(Duration::from_millis(150));
        sync.tick();

        assert!(
            !peers.is_connected(staller),
            "staller's outbound lease must be revoked"
        );
        assert!(
            sync.scheduler.lock().window.peer_in_staller_cooldown(
                bitcoin_rs_wire::PeerSource::for_test(staller),
                Instant::now()
            ),
            "disconnected staller must enter the cooldown"
        );
        assert_no_getdata(&rxs[0])?;
        let mut rerequested = Vec::new();
        for rx in &rxs[1..] {
            while let Ok(message) = rx.try_recv() {
                if let Message::GetData(inventory) = message {
                    rerequested.extend(witness_block_inventory(inventory)?);
                }
            }
        }
        assert_eq!(
            rerequested,
            expected[..2],
            "the stalled front stripe must be re-requested from a healthy peer"
        );
        assert_eq!(
            sync.scheduler.lock().stager.received_len(),
            14,
            "staged progress must survive the staller disconnect"
        );
        {
            let scheduler = sync.scheduler.lock();
            let window = &scheduler.window;
            assert_eq!(window.pending_len(), 2);
            for front in &expected[..2] {
                assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
            }
        }
        Ok(())
    }

    #[test]
    fn clean_fast_path_caps_request_at_peer_height() -> TestResult {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 4,
                getdata_batch_limit: 4,
                ..super::default_sync_budget(Network::Regtest)
            },
        );
        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let rx = connect_peer(&peers, synthetic_peer(addr, 2));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
        assert!(rx.try_recv().is_err());

        sync.tick();

        assert!(rx.try_recv().is_err());
        Ok(())
    }

    struct ExhaustionFixture {
        sync: BlockSync,
        stalled_rx: bitcoin_rs_wire::test_support::MessageReceiver,
        healthy_rx: bitcoin_rs_wire::test_support::MessageReceiver,
        block1_hash: BlockHash,
        block2_hash: BlockHash,
    }

    fn staging_exhaustion_fixture() -> Result<ExhaustionFixture, TestError> {
        let genesis = Network::Regtest.genesis_block();
        let block1 = regtest_fixture::mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![regtest_fixture::coinbase(1)],
        )
        .or_fail("regtest fixture block");
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            block1.block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .or_fail("regtest fixture block");
        let block3 = regtest_fixture::mined_block_with_prev_hash(
            block2.block_hash(),
            3,
            vec![regtest_fixture::coinbase(3)],
        )
        .or_fail("regtest fixture block");
        let block1_hash = block1.block_hash();
        let block2_hash = block2.block_hash();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block1_id =
            tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
        let block2_id =
            tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;

        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);

        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: consensus_bytes(&block2).len(),
                getdata_batch_limit: 2,
                received_timeout: Duration::from_millis(100),
                ..super::default_sync_budget(Network::Regtest)
            }
            .with_pending_timeout_override(Duration::ZERO),
        );
        let stalled_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let healthy_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8334,
        ));
        let stalled_rx = connect_peer(&peers, synthetic_peer(stalled_addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        let Message::GetData(inventory) = stalled_rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            std::vec![block1_hash, block2_hash]
        );
        let _headers = stalled_rx.try_recv()?;

        inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block2))?;
        sync.drain_inbound_blocks();
        assert!(!{
            let scheduler = sync.scheduler.lock();
            scheduler.window.has_request_capacity(&scheduler.stager)
        });

        let healthy_rx = connect_peer(&peers, synthetic_peer(healthy_addr, 100));

        Ok(ExhaustionFixture {
            sync,
            stalled_rx,
            healthy_rx,
            block1_hash,
            block2_hash,
        })
    }

    const DETERMINISTIC_PROXY_BLOCKS: usize = 24;
    const DETERMINISTIC_PROXY_TIP_HEIGHT: u32 = 24;
    const DETERMINISTIC_PROXY_HEADER_HEIGHT: u32 = 96;

    struct DeterministicProxyFixture {
        sync: BlockSync,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_wire::InboundBlock>,
        outbound_rx: bitcoin_rs_wire::test_support::MessageReceiver,
        blocks: Vec<Block>,
    }

    fn deterministic_proxy_fixture() -> Result<DeterministicProxyFixture, TestError> {
        let (tree, blocks) = mined_chain(
            DETERMINISTIC_PROXY_TIP_HEIGHT,
            DETERMINISTIC_PROXY_HEADER_HEIGHT - DETERMINISTIC_PROXY_TIP_HEIGHT,
        )?;
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: DETERMINISTIC_PROXY_BLOCKS,
                max_pending_bytes: usize::MAX,
                max_received_blocks: DETERMINISTIC_PROXY_BLOCKS,
                max_received_bytes: usize::MAX,
                max_peer_inflight: DETERMINISTIC_PROXY_BLOCKS,
                getdata_batch_limit: DETERMINISTIC_PROXY_BLOCKS,
                ..super::default_sync_budget(Network::Regtest)
            },
        );

        let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8333,
        ));
        let outbound_rx = connect_peer(&peers, synthetic_peer(addr, 100));

        Ok(DeterministicProxyFixture {
            sync,
            applied_tip,
            block_tree,
            inbound_blocks_tx,
            outbound_rx,
            blocks,
        })
    }

    struct ApplyCacheFixture {
        sync: BlockSync,
        blocks: Vec<Block>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    }

    fn apply_cache_fixture(
        body_height: u32,
        header_only: u32,
    ) -> Result<ApplyCacheFixture, TestError> {
        let (tree, blocks) = mined_chain(body_height, header_only)?;
        let SyncHarness {
            sync,
            block_tree,
            applied_tip,
            inbound_headers_tx: _inbound_headers_tx,
            inbound_blocks_tx: _inbound_blocks_tx,
            ..
        } = SyncHarness::new(tree);
        let chain_tip = block_tree.write().tip_handle();

        sync.chain.bootstrap_genesis();
        assert_eq!(
            applied_tip.load_full().map(|tip| tip.height),
            Some(0),
            "fixture must apply genesis before staging bodies"
        );

        Ok(ApplyCacheFixture {
            sync,
            blocks,
            applied_tip,
            chain_tip,
        })
    }

    fn stage_body(sync: &BlockSync, block: &Block) {
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        sync.scheduler.lock().stager.insert(
            hash,
            None,
            BlockImage::from_local(block.clone()),
            None,
            Instant::now(),
        );
    }

    fn cache_snapshot(sync: &BlockSync) -> Option<super::ExpectedApplyCache> {
        sync.scheduler.lock().expected_apply_cache.clone()
    }

    fn apply_fixture_block(sync: &BlockSync, block: Block) -> TestResult {
        let hash = Hash256::from(block.block_hash());
        sync.buffer_received_block_chunk(
            &mut vec![bitcoin_rs_wire::InboundBlock::from_local(block)],
            Some(hash),
        );
        assert_eq!(sync.apply_buffered_blocks(Some(hash)), (1, 0));
        assert_eq!(
            sync.chain.applied_tip().ok_or("missing applied tip")?.hash,
            hash
        );
        Ok(())
    }

    #[test]
    fn permanent_rejection_keeps_the_request_cursor_off_the_invalidated_block() -> TestResult {
        let (mut tree, mut blocks) = mined_chain(1, 0)?;
        let tip_id = tree.tip_id().ok_or("missing mined tip")?;
        let extra_coinbase = regtest_fixture::mined_block_with_prev_hash(
            blocks[0].block_hash(),
            2,
            vec![regtest_fixture::coinbase(90), regtest_fixture::coinbase(91)],
        )
        .or_fail("regtest fixture");
        let extra_id =
            tree.insert_node(Some(tip_id), extra_coinbase.header, NodeStatus::HeaderValid)?;
        let follower = regtest_fixture::mined_block_with_prev_hash(
            extra_coinbase.block_hash(),
            3,
            vec![regtest_fixture::coinbase(92)],
        )
        .or_fail("regtest fixture");
        tree.insert_node(Some(extra_id), follower.header, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            inbound_blocks_tx: _inbound_blocks_tx,
            ..
        } = SyncHarness::new(tree);
        sync.chain.bootstrap_genesis();
        let peer = test_addr(9789, 0)?;
        let _rx = connect_peer(&peers, synthetic_peer(peer, 3));
        sync.tick();
        let failing_hash = Hash256::from(extra_coinbase.block_hash());

        let staged = sync.buffer_received_block_chunk(
            &mut vec![
                bitcoin_rs_wire::InboundBlock::from_local(blocks.remove(0)),
                bitcoin_rs_wire::InboundBlock::from_local(extra_coinbase),
                bitcoin_rs_wire::InboundBlock::from_local(follower),
            ],
            None,
        );
        assert_eq!(staged, 3, "all three delivered bodies must stage");
        let cursor_before = sync.scheduler.lock().window.request_cursor();
        assert!(
            cursor_before > 2,
            "the request frontier must sit above the failing height for the rewind to be observable"
        );

        assert_eq!(sync.apply_buffered_blocks(None), (1, 1));
        assert_eq!(
            sync.scheduler.lock().window.request_cursor(),
            cursor_before,
            "a Permanent rejection must not rewind the request cursor onto the invalidated block"
        );
        assert!(
            !sync.scheduler.lock().stager.contains(&failing_hash),
            "the invalidated block and its descendants must leave the stager"
        );
        Ok(())
    }

    #[test]
    fn unrequested_body_admission_matches_core_acceptance() -> TestResult {
        let (mut tree, blocks) = mined_chain(300, 0)?;
        let fork_parent = tree
            .lookup(Hash256::from(blocks[4].block_hash()))
            .ok_or("missing height 5")?;
        let fork_body = regtest_fixture::mined_block_with_prev_hash(
            blocks[4].block_hash(),
            606,
            vec![regtest_fixture::coinbase(606)],
        )
        .or_fail("regtest fixture block");
        tree.insert_node(Some(fork_parent), fork_body.header, NodeStatus::HeaderValid)?;
        let applied = {
            let node = tree.node(fork_parent)?;
            TipSnapshot {
                tip_id: fork_parent,
                chain_tx_count: node.chain_tx_count,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        let SyncHarness {
            sync,
            applied_tip,
            inbound_headers_tx: _inbound_headers_tx,
            inbound_blocks_tx: _inbound_blocks_tx,
            ..
        } = SyncHarness::new(tree);
        applied_tip.store(Some(Arc::new(applied)));
        let mut blocks = blocks.into_iter();
        let successor = blocks.nth(5).ok_or("missing height 6")?;
        let far_body = blocks.nth(288).ok_or("missing height 295")?;
        let successor_hash = Hash256::from(successor.block_hash());
        let far_hash = Hash256::from(far_body.block_hash());
        let fork_hash = Hash256::from(fork_body.block_hash());
        let mut delivery = vec![
            bitcoin_rs_wire::InboundBlock::from_local(successor),
            bitcoin_rs_wire::InboundBlock::from_local(far_body),
            bitcoin_rs_wire::InboundBlock::from_local(fork_body),
        ];
        sync.buffer_received_block_chunk(&mut delivery, None);

        let scheduler = sync.scheduler.lock();
        assert!(
            scheduler.stager.contains(&successor_hash),
            "an active-branch successor passes every clause"
        );
        assert!(
            !scheduler.stager.contains(&far_hash),
            "a body more than 288 blocks above the applied tip is too far ahead"
        );
        assert!(
            !scheduler.stager.contains(&fork_hash),
            "a body off the active branch is discarded"
        );
        assert_eq!(scheduler.stager.received_len(), 1);
        Ok(())
    }

    #[test]
    fn unrequested_body_gate_rejects_below_floor_and_below_applied_work() -> TestResult {
        fn snapshot(tree: &BlockTree, hash: Hash256) -> Result<TipSnapshot, TestError> {
            let node_id = tree.lookup(hash).ok_or("missing fixture block")?;
            let node = tree.node(node_id)?;
            Ok(TipSnapshot {
                tip_id: node_id,
                chain_tx_count: node.chain_tx_count,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            })
        }
        let (tree, blocks) = mined_chain(8, 0)?;
        let chain_tip = snapshot(&tree, Hash256::from(blocks[7].block_hash()))?;
        let applied_tip = snapshot(&tree, Hash256::from(blocks[3].block_hash()))?;
        let floor = {
            let node_id = tree
                .lookup(Hash256::from(blocks[7].block_hash()))
                .ok_or("missing tip fixture block")?;
            tree.node(node_id)?.chainwork.to_be_bytes()
        };

        let above_applied = Hash256::from(blocks[5].block_hash());
        assert!(
            !unrequested_body_admissible(
                &tree,
                above_applied,
                Some(&chain_tip),
                Some(&applied_tip),
                floor,
            ),
            "a candidate below the work floor must be rejected even on-branch above the applied tip"
        );
        assert!(
            unrequested_body_admissible(
                &tree,
                above_applied,
                Some(&chain_tip),
                Some(&applied_tip),
                [0; 32],
            ),
            "the same candidate passes with the regtest zero floor, isolating the floor clause"
        );

        let below_applied = Hash256::from(blocks[1].block_hash());
        assert!(
            !unrequested_body_admissible(
                &tree,
                below_applied,
                Some(&chain_tip),
                Some(&applied_tip),
                [0; 32],
            ),
            "a candidate with less work than the applied tip must be rejected"
        );
        Ok(())
    }

    struct SyncHarness {
        sync: BlockSync,
        peers: Arc<PeerTable>,
        block_tree: Arc<RwLock<BlockTree>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        inbound_headers_tx: crossbeam_channel::Sender<InboundHeaders>,
        inbound_blocks_tx: InboundBlockSender,
    }

    impl SyncHarness {
        fn new(tree: BlockTree) -> Self {
            Self::with_ibd(tree, crate::p2p::sync::syncing_ibd_latch())
        }

        fn with_ibd(tree: BlockTree, ibd: Arc<InitialBlockDownload>) -> Self {
            Self::with_chain_work(
                tree,
                ibd,
                ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work()),
            )
        }

        fn with_chain_work(
            mut tree: BlockTree,
            ibd: Arc<InitialBlockDownload>,
            minimum_chain_work: ChainWork,
        ) -> Self {
            let chain_tip = tree.tip_handle();
            let block_tree = Arc::new(RwLock::new(tree));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let peers = Arc::new(PeerTable::new());
            let (inbound_headers_tx, inbound_headers_rx) = unbounded();
            let (inbound_blocks_tx, inbound_blocks_rx) = unbounded();
            let chain = Arc::new(
                TestChain::new(chain_tip, Arc::clone(&applied_tip), Arc::clone(&block_tree))
                    .with_minimum_chain_work(minimum_chain_work),
            );
            let sync = BlockSync::new(
                chain,
                Arc::clone(&peers),
                inbound_headers_rx,
                inbound_blocks_rx,
                ibd,
            );
            Self {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
            }
        }
    }

    pub(crate) fn sync_with_header_chain_and_ibd(
        height: u32,
        ibd: Arc<InitialBlockDownload>,
    ) -> Result<SyncFixture, TestError> {
        let (tree, blocks) = mined_chain(height, 0)?;
        let expected = blocks.iter().map(Block::block_hash).collect();
        let harness = SyncHarness::with_ibd(tree, ibd);
        Ok((
            harness.sync,
            harness.peers,
            harness.block_tree,
            harness.applied_tip,
            expected,
        ))
    }

    type SyncFixture = (
        BlockSync,
        Arc<PeerTable>,
        Arc<RwLock<BlockTree>>,
        Arc<ArcSwapOption<TipSnapshot>>,
        Vec<BlockHash>,
    );

    type InboundBlockSender = crossbeam_channel::Sender<bitcoin_rs_wire::InboundBlock>;

    fn sync_with_header_chain(height: u32) -> Result<SyncFixture, TestError> {
        let (fixture, _inbound_blocks_tx) = sync_with_header_chain_and_blocks(height)?;
        Ok(fixture)
    }

    fn sync_with_header_chain_and_blocks(
        height: u32,
    ) -> Result<(SyncFixture, InboundBlockSender), TestError> {
        let (tree, blocks) = mined_chain(height, 0)?;
        let expected = blocks.iter().map(Block::block_hash).collect();
        let SyncHarness {
            sync,
            peers,
            block_tree,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);

        Ok((
            (sync, peers, block_tree, applied_tip, expected),
            inbound_blocks_tx,
        ))
    }

    type MinedChainFixture = (
        BlockSync,
        Arc<PeerTable>,
        Arc<ArcSwapOption<TipSnapshot>>,
        Vec<Block>,
        InboundBlockSender,
    );

    fn sync_with_mined_chain(count: u32) -> Result<MinedChainFixture, TestError> {
        let (tree, blocks) = mined_chain(count, 0)?;
        let SyncHarness {
            sync,
            peers,
            block_tree: _,
            applied_tip,
            inbound_blocks_tx,
            inbound_headers_tx: _inbound_headers_tx,
        } = SyncHarness::new(tree);

        Ok((sync, peers, applied_tip, blocks, inbound_blocks_tx))
    }

    #[test]
    fn historical_delivery_retries_corruption_and_does_not_rewind_foreground() -> TestResult {
        let (tree, blocks) = mined_chain(3, 0)?;
        let mut harness = SyncHarness::new(tree);
        let chain = Arc::new(TestChain::new(
            harness.block_tree.write().tip_handle(),
            harness.applied_tip.clone(),
            harness.block_tree.clone(),
        ));

        chain.bootstrap_genesis();
        for block in &blocks[..2] {
            let fixture_payload = BlockImage::from_local(block.clone());
            chain
                .commit_window(&[&fixture_payload])
                .map_err(|error| crate::test_support::TestError::Commit(format!("{error:?}")))?;
        }
        chain
            .historical
            .lock()
            .push_back((1, blocks[0].block_hash().0));
        harness.sync.chain = chain.clone();
        let addr = test_addr(28000, 0)?;
        let rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
        harness.sync.tick();
        let source = current_source(&harness.peers, addr);
        assert!(
            harness
                .sync
                .owns_body_fetch(source, blocks[0].block_hash().0)
        );
        assert!(rx.try_iter().any(|message| matches!(message, Message::GetData(ref items) if items.contains(&Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(blocks[0].block_hash().0.to_le_bytes()))))));
        let mut corrupt = blocks[0].clone();
        corrupt.txs[0].outputs[0].value = bitcoin_rs_consensus::primitives::Amount::from_sat(1);
        for block in [corrupt, blocks[2].clone()] {
            let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block);
            inbound.source = Some(source);
            harness.inbound_blocks_tx.send(inbound)?;
        }
        harness.sync.tick();
        assert!(chain.historical_connected.lock().is_empty());
        assert_eq!(
            harness
                .applied_tip
                .load_full()
                .ok_or("missing active tip")?
                .height,
            3
        );
        assert!(
            !harness
                .sync
                .owns_body_fetch(source, blocks[0].block_hash().0)
        );
        assert!(
            harness
                .sync
                .historical
                .lock()
                .window
                .peer_in_staller_cooldown(
                    bitcoin_rs_wire::PeerSource::for_test(addr),
                    Instant::now()
                )
        );
        let retry_addr = test_addr(28001, 0)?;
        let retry_rx = connect_peer(&harness.peers, synthetic_peer(retry_addr, 3));
        harness.sync.advance_historical();
        let retry_source = current_source(&harness.peers, retry_addr);
        assert!(
            harness
                .sync
                .owns_body_fetch(retry_source, blocks[0].block_hash().0)
        );
        assert!(
            retry_rx
                .try_iter()
                .any(|message| matches!(message, Message::GetData(_)))
        );
        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone());
        inbound.source = Some(retry_source);
        harness.inbound_blocks_tx.send(inbound)?;
        harness.sync.tick();
        assert_eq!(
            *chain.historical_connected.lock(),
            vec![blocks[0].block_hash().0]
        );
        assert_eq!(
            harness
                .applied_tip
                .load_full()
                .ok_or("missing active tip")?
                .height,
            3
        );
        assert_eq!(harness.sync.historical.lock().window.pending_len(), 0);
        Ok(())
    }

    #[test]
    fn historical_requests_use_archive_peers_and_replace_disconnected_leases() -> TestResult {
        let (tree, blocks) = mined_chain(1, 0)?;
        let mut harness = SyncHarness::new(tree);
        let chain = Arc::new(TestChain::new(
            harness.block_tree.write().tip_handle(),
            harness.applied_tip.clone(),
            harness.block_tree.clone(),
        ));
        chain
            .historical
            .lock()
            .push_back((1, blocks[0].block_hash().0));
        harness.sync.chain = chain;
        let limited_addr = test_addr(28100, 0)?;
        let mut limited = synthetic_peer(limited_addr, 1000);
        limited.services = (bitcoin::p2p::ServiceFlags::NETWORK_LIMITED
            | bitcoin::p2p::ServiceFlags::WITNESS)
            .to_u64();
        let limited_rx = connect_peer(&harness.peers, limited);
        harness.sync.advance_historical();
        assert!(limited_rx.try_recv().is_err());
        assert_eq!(harness.sync.historical.lock().window.pending_len(), 0);
        let addr = test_addr(28100, 1)?;
        let old_rx = connect_peer(&harness.peers, synthetic_peer(addr, 1000));
        harness.sync.advance_historical();
        let old = current_source(&harness.peers, addr);
        assert!(harness.sync.owns_body_fetch(old, blocks[0].block_hash().0));
        assert!(matches!(old_rx.try_recv()?, Message::GetData(_)));
        harness.sync.advance_historical();
        assert!(
            old_rx.try_recv().is_err(),
            "one outstanding historical request"
        );
        let replacement_rx = connect_peer(&harness.peers, synthetic_peer(addr, 1000));
        harness.sync.advance_historical();
        let replacement = current_source(&harness.peers, addr);
        assert!(!harness.sync.owns_body_fetch(old, blocks[0].block_hash().0));
        assert!(
            harness
                .sync
                .owns_body_fetch(replacement, blocks[0].block_hash().0)
        );
        assert!(matches!(replacement_rx.try_recv()?, Message::GetData(_)));
        Ok(())
    }

    type WedgeFixture = (
        BlockSync,
        Arc<PeerTable>,
        Vec<BlockHash>,
        Vec<bitcoin_rs_wire::test_support::MessageReceiver>,
        InboundBlockSender,
    );

    fn wedge_budget(pending_timeout: Duration) -> super::SyncBudget {
        super::SyncBudget {
            max_pending_blocks: 16,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 16,
            max_received_bytes: usize::MAX,
            max_peer_inflight: 16,
            fanout_peer_inflight: 2,
            min_peers_for_fanout: 8,
            getdata_batch_limit: 16,
            ..super::default_sync_budget(Network::Regtest)
        }
        .with_pending_timeout_override(pending_timeout)
    }

    fn staged_count_wedge(budget: super::SyncBudget) -> Result<WedgeFixture, TestError> {
        let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
            sync_with_header_chain_and_blocks(64)?;
        let peer_count = budget.min_peers_for_fanout;
        install_budget(&sync, budget);
        let mut rxs = Vec::new();
        for idx in 0..peer_count {
            let addr = test_addr(9320, idx)?;
            rxs.push(connect_peer(
                &peers,
                synthetic_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree)?;
        for (idx, rx) in rxs.iter().enumerate() {
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected a striped getdata per peer").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                expected[idx * 2..(idx + 1) * 2]
            );
        }
        for height in 3..=16_u32 {
            blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                header_chain_block(&expected, height)?,
            ))?;
        }
        Ok((sync, peers, expected, rxs, blocks_tx))
    }

    fn next_getdata(
        rx: &bitcoin_rs_wire::test_support::MessageReceiver,
    ) -> Result<Vec<Inventory>, TestError> {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                return Ok(inventory);
            }
        }
        Err(std::io::Error::other("expected a queued getdata").into())
    }

    fn assert_no_getdata(rx: &bitcoin_rs_wire::test_support::MessageReceiver) -> TestResult {
        while let Ok(message) = rx.try_recv() {
            if matches!(message, Message::GetData(_)) {
                return Err(std::io::Error::other("unexpected getdata").into());
            }
        }
        Ok(())
    }

    fn header_chain_block(expected: &[BlockHash], height: u32) -> Result<Block, TestError> {
        let index = usize::try_from(height.checked_sub(1).ok_or("height must be >= 1")?)?;
        let prev_blockhash = if index == 0 {
            genesis_header().compute_hash()
        } else {
            expected[index - 1]
        };
        let block = regtest_fixture::mined_block_with_prev_hash(
            prev_blockhash,
            height,
            vec![regtest_fixture::coinbase(height)],
        )
        .or_fail("regtest fixture block");
        assert_eq!(
            block.block_hash(),
            expected[index],
            "reconstructed block must hash to the fixture's header-chain node"
        );
        Ok(block)
    }

    fn install_budget(sync: &BlockSync, budget: super::SyncBudget) {
        sync.install_budget(budget);
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum TestMetric {
        Counter(u64),
        Gauge(f64),
        Histogram { count: u64, sum: f64 },
    }

    #[derive(Clone, Debug, Default)]
    struct TestRecorder {
        values: Arc<Mutex<HashMap<String, TestMetric>>>,
    }

    impl TestRecorder {
        fn metric_key(key: &Key) -> String {
            key.name().to_owned()
        }

        fn snapshot(&self) -> HashMap<String, TestMetric> {
            self.values.lock().clone()
        }
    }

    impl Recorder for TestRecorder {
        fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {
        }

        fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

        fn describe_histogram(
            &self,
            _key: KeyName,
            _unit: Option<Unit>,
            _description: SharedString,
        ) {
        }

        fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
            Counter::from_arc(Arc::new(TestCounter {
                key: Self::metric_key(key),
                recorder: self.clone(),
            }))
        }

        fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
            Gauge::from_arc(Arc::new(TestGauge {
                key: Self::metric_key(key),
                recorder: self.clone(),
            }))
        }

        fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(Arc::new(TestHistogram {
                key: Self::metric_key(key),
                recorder: self.clone(),
            }))
        }
    }

    struct TestCounter {
        key: String,
        recorder: TestRecorder,
    }

    impl CounterFn for TestCounter {
        fn increment(&self, value: u64) {
            let mut values = self.recorder.values.lock();
            let entry = values
                .entry(self.key.clone())
                .or_insert(TestMetric::Counter(0));
            if let TestMetric::Counter(current) = entry {
                *current = current.saturating_add(value);
            }
        }

        fn absolute(&self, value: u64) {
            self.recorder
                .values
                .lock()
                .insert(self.key.clone(), TestMetric::Counter(value));
        }
    }

    struct TestGauge {
        key: String,
        recorder: TestRecorder,
    }

    impl GaugeFn for TestGauge {
        fn increment(&self, value: f64) {
            let mut values = self.recorder.values.lock();
            let entry = values
                .entry(self.key.clone())
                .or_insert(TestMetric::Gauge(0.0));
            if let TestMetric::Gauge(current) = entry {
                *current += value;
            }
        }

        fn decrement(&self, value: f64) {
            let mut values = self.recorder.values.lock();
            let entry = values
                .entry(self.key.clone())
                .or_insert(TestMetric::Gauge(0.0));
            if let TestMetric::Gauge(current) = entry {
                *current -= value;
            }
        }

        fn set(&self, value: f64) {
            self.recorder
                .values
                .lock()
                .insert(self.key.clone(), TestMetric::Gauge(value));
        }
    }

    struct TestHistogram {
        key: String,
        recorder: TestRecorder,
    }

    impl HistogramFn for TestHistogram {
        fn record(&self, value: f64) {
            let mut values = self.recorder.values.lock();
            let entry = values
                .entry(self.key.clone())
                .or_insert(TestMetric::Histogram { count: 0, sum: 0.0 });
            if let TestMetric::Histogram { count, sum } = entry {
                *count = count.saturating_add(1);
                *sum += value;
            }
        }
    }

    fn assert_gauge(recorder: &TestRecorder, name: &str, expected: usize) {
        let expected = super::metric_count(expected);
        assert_eq!(
            recorder.snapshot().get(name),
            Some(&TestMetric::Gauge(expected)),
            "{name} gauge must match deterministic sync pipeline state",
        );
    }

    fn assert_metric_absent(recorder: &TestRecorder, name: &str) {
        assert!(
            !recorder.snapshot().contains_key(name),
            "{name} metric should not be recorded"
        );
    }

    fn assert_histogram(recorder: &TestRecorder, name: &str) {
        match recorder.snapshot().get(name) {
            Some(TestMetric::Histogram { count, sum }) => {
                assert_ne!(
                    *count, 0,
                    "{name} histogram must record at least one sample"
                );
                assert!(sum.is_finite(), "{name} histogram sum must be finite");
            }
            value => panic!("{name} histogram missing or wrong type: {value:?}"),
        }
    }

    fn witness_block_inventory(inventory: Vec<Inventory>) -> Result<Vec<BlockHash>, TestError> {
        inventory
            .into_iter()
            .map(|item| match item {
                Inventory::WitnessBlock(hash) => {
                    Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
                }
                _ => Err(std::io::Error::other("expected witness block inventory").into()),
            })
            .collect()
    }

    fn nbits_mismatch_header(prev_blockhash: BlockHash, height: u32) -> Header {
        use bitcoin_rs_consensus::primitives::CompactTarget;
        let mut header = regtest_fixture::mined_regtest_header(prev_blockhash, height)
            .or_fail("regtest fixture header");
        header.bits = CompactTarget::from_consensus(0x207f_fffe);
        regtest_fixture::mine_header_to_declared_target(&mut header)
            .or_fail("regtest fixture grind");
        header
    }

    fn far_future_header(prev_blockhash: BlockHash, height: u32) -> Result<Header, TestError> {
        let mut header = regtest_fixture::mined_regtest_header(prev_blockhash, height)?;
        header.time =
            bitcoin_rs_execution::chain::current_unix_seconds().saturating_add(3 * 60 * 60);
        regtest_fixture::mine_header_to_declared_target(&mut header)?;
        Ok(header)
    }

    struct HeaderSyncFixture {
        genesis: Header,
        sync: BlockSync,
        inbound_headers_tx: crossbeam_channel::Sender<InboundHeaders>,
        peers: Arc<PeerTable>,
    }

    fn header_sync_with_genesis() -> Result<HeaderSyncFixture, TestError> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            peers,
            inbound_headers_tx,
            inbound_blocks_tx: _inbound_blocks_tx,
            ..
        } = SyncHarness::new(tree);
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget(Network::Regtest)
            },
        );
        Ok(HeaderSyncFixture {
            genesis,
            sync,
            inbound_headers_tx,
            peers,
        })
    }

    fn genesis_header() -> Header {
        Network::Regtest.genesis_block().header
    }

    fn header_sync_with_refusing_chain() -> Result<HeaderSyncFixture, TestError> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx) = unbounded();
        let (inbound_blocks_tx, inbound_blocks_rx) = unbounded();
        let sync = BlockSync::new(
            Arc::new(RefusingChain(Arc::new(TestChain::new(
                chain_tip,
                Arc::clone(&applied_tip),
                Arc::clone(&block_tree),
            )))),
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        );
        drop(inbound_blocks_tx);
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget(Network::Regtest)
            },
        );
        Ok(HeaderSyncFixture {
            genesis,
            sync,
            inbound_headers_tx,
            peers,
        })
    }

    fn transaction(seed: u8) -> Tx {
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    Txid(Hash256::from_le_bytes(&[seed; 32])),
                    u32::from(seed),
                ),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn assert_applied_genesis(
        applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: &Arc<RwLock<BlockTree>>,
    ) -> TestResult {
        let genesis_hash = Network::Regtest.genesis_block_hash();
        let tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied genesis tip"))?;
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis_hash);
        assert_eq!(block_tree.read().height_of_hash(genesis_hash), Some(0));
        Ok(())
    }

    fn test_frontier(sync: &BlockSync) -> super::ChainFrontier {
        sync.observe_chain_frontier()
    }

    fn register_info(peer_table: &Arc<PeerTable>, info: PeerInfo) {
        let (tx, _rx) = bitcoin_rs_wire::test_support::message_channel();
        let lease = PeerLease::new(tx);
        let Some(endpoint) = info.endpoint else {
            panic!("identified peer endpoint");
        };
        peer_table.register(endpoint, lease.clone());
        peer_table.publish_info(endpoint, &lease, info);
    }
    pub(crate) fn ineligible_peer(addr: PeerRemote, start_height: i32) -> PeerInfo {
        PeerInfo {
            services: 0,
            inbound: true,
            ..synthetic_peer(addr, start_height)
        }
    }

    pub(crate) fn connect_anonymous_peer(
        peer_table: &Arc<PeerTable>,
        mut info: PeerInfo,
    ) -> bitcoin_rs_wire::test_support::MessageReceiver {
        let (tx, rx) = bitcoin_rs_wire::test_support::message_channel();
        let lease = PeerLease::new(tx);
        info.endpoint = None;
        info.network = bitcoin_rs_wire::NetworkLabel::Onion;
        info.inbound = true;
        peer_table.register_unidentified(lease.clone());
        assert!(peer_table.publish_info_unidentified(&lease, info));
        rx
    }

    #[test]
    fn service_and_range_gate_both_request_paths() -> TestResult {
        use super::frontier::{BodyState, ChainFrontier, RequiredBody, SyncFrontier, UsablePeer};

        const WITNESS: u64 = 1 << 3;
        const NETWORK_LIMITED: u64 = 1 << 10;
        let mut tree = BlockTree::new();
        let mut parent = None;
        let mut previous = BlockHash::default();
        let mut historical_hash = None;
        let mut recent_hash = None;
        for height in 0..=300 {
            let header = regtest_fixture::mined_regtest_header(previous, height)?;
            previous = header.compute_hash();
            let height_hash = Hash256::from_le_bytes(previous.as_bytes());
            parent = Some(tree.insert_node(parent, header, NodeStatus::HeaderValid)?);
            if height == 14 {
                historical_hash = Some(height_hash);
            } else if height == 15 {
                recent_hash = Some(height_hash);
            }
        }
        let historical_hash = historical_hash.ok_or("missing historical header")?;
        let recent_hash = recent_hash.ok_or("missing recent header")?;
        let SyncHarness { sync, peers, .. } = SyncHarness::with_ibd(tree, synced_ibd_latch());

        let owner_addr = test_addr(18_900, 0)?;
        let owner_info = synthetic_peer(owner_addr, 300);
        let _owner_rx = connect_peer(&peers, owner_info);
        let owner = current_source(&peers, owner_addr);
        let limited_addr = test_addr(18_900, 1)?;
        let mut limited_info = synthetic_peer(limited_addr, 300);
        limited_info.services = WITNESS | NETWORK_LIMITED;
        let limited_rx = connect_peer(&peers, limited_info.clone());
        let no_service_addr = test_addr(18_900, 2)?;
        let mut no_service_info = synthetic_peer(no_service_addr, 300);
        no_service_info.services = WITNESS;
        let no_service_rx = connect_peer(&peers, no_service_info.clone());
        let no_service = current_source(&peers, no_service_addr);
        let usable_of = |source, info| UsablePeer {
            source,
            info,
            demonstrated_tips: Vec::new(),
            active_height: None,
            headers_horizon: None,
            role: bitcoin_rs_wire::peer_info::PeerRole::FullRelay,
            manual: false,
            connected_at: Instant::now(),
        };
        let no_service_usable = usable_of(no_service, no_service_info);
        let limited = current_source(&peers, limited_addr);
        let usable = usable_of(limited, limited_info);
        let frontier = |height, hash, usable_peer| SyncFrontier {
            chain: ChainFrontier {
                applied_tip: None,
                chain_tip: None,
                next_required: Some(RequiredBody { height, hash }),
                closed_for_recovery: false,
            },
            body_state: Some(BodyState::Unowned),
            header_request: None,
            header_request_live: false,
            usable_peers: vec![usable_peer],
        };

        let historical = sync.sync_peer_selection(
            &frontier(14, historical_hash, usable.clone()),
            Instant::now(),
        );
        assert!(historical.request_peers.is_empty());
        let no_service_selection = sync.sync_peer_selection(
            &frontier(15, recent_hash, no_service_usable),
            Instant::now(),
        );
        assert!(no_service_selection.request_peers.is_empty());
        let recent = sync.sync_peer_selection(&frontier(15, recent_hash, usable), Instant::now());
        assert_eq!(recent.request_peers.len(), 1);
        assert_eq!(recent.request_peers[0].source, limited);

        assert_eq!(
            sync.send_cold_front_hedge(owner, historical_hash, 14, Instant::now()),
            None
        );
        assert!(limited_rx.try_recv().is_err());
        assert_eq!(
            sync.send_cold_front_hedge(owner, recent_hash, 15, Instant::now()),
            Some(limited)
        );
        let Message::GetData(items) = limited_rx.try_recv()? else {
            panic!("recent limited peer must receive the cold-front request");
        };
        assert_eq!(
            items,
            vec![Inventory::WitnessBlock(
                bitcoin::BlockHash::from_byte_array(*recent_hash.as_byte_array())
            )]
        );
        assert!(no_service_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn cold_front_hedge_skips_a_saturated_candidate_without_cancelling_it() -> TestResult {
        let mut tree = BlockTree::new();
        let mut parent = None;
        let mut previous = BlockHash::default();
        let mut front_hash = None;
        for height in 0..=300 {
            let header = regtest_fixture::mined_regtest_header(previous, height)?;
            previous = header.compute_hash();
            parent = Some(tree.insert_node(parent, header, NodeStatus::HeaderValid)?);
            if height == 15 {
                front_hash = Some(Hash256::from_le_bytes(previous.as_bytes()));
            }
        }
        let front_hash = front_hash.ok_or("missing front header")?;
        let SyncHarness { sync, peers, .. } = SyncHarness::with_ibd(tree, synced_ibd_latch());

        let owner_addr = test_addr(18_910, 0)?;
        let _owner_rx = connect_peer(&peers, synthetic_peer(owner_addr, 300));
        let owner = current_source(&peers, owner_addr);

        let aggregate =
            Arc::new(bitcoin_rs_wire::connection::SharedOutboundBudget::with_limits(512, 0));
        let hold = bitcoin_rs_wire::test_support::hog(&aggregate, 512);
        let saturated_addr = test_addr(18_910, 1)?;
        let (saturated_tx, saturated_rx) = bitcoin_rs_wire::test_support::message_channel();
        let saturated_lease = PeerLease::new(saturated_tx).with_shared_budget(&aggregate);
        peers.register(saturated_addr, saturated_lease.clone());
        peers.publish_info(
            saturated_addr,
            &saturated_lease,
            synthetic_peer(saturated_addr, 300),
        );

        assert_eq!(
            sync.send_cold_front_hedge(owner, front_hash, 15, Instant::now()),
            None,
            "the aggregate's refusal sends nothing"
        );
        assert!(saturated_rx.is_empty());
        assert!(
            !saturated_lease.is_cancelled(),
            "a full aggregate never cancels a healthy candidate"
        );
        assert!(peers.is_connected(saturated_addr));

        let healthy_addr = test_addr(18_910, 2)?;
        let healthy_rx = connect_peer(&peers, synthetic_peer(healthy_addr, 300));
        let healthy = current_source(&peers, healthy_addr);
        assert_eq!(
            sync.send_cold_front_hedge(owner, front_hash, 15, Instant::now()),
            Some(healthy),
        );
        assert!(matches!(healthy_rx.try_recv()?, Message::GetData(_)));
        assert!(saturated_rx.is_empty());
        assert!(!saturated_lease.is_cancelled());
        assert!(peers.is_connected(saturated_addr));
        drop(hold);
        Ok(())
    }

    #[cfg(test)]
    mod download_frontier {
        use super::*;

        #[test]
        fn chain_frontier_uses_captured_applied_tip_during_advance() -> TestResult {
            let (tree, blocks) = mined_chain(2, 1)?;
            let mut harness = SyncHarness::new(tree);
            harness.sync.chain.bootstrap_genesis();
            let header_tip = harness.block_tree.write().tip_handle();
            let old_header = header_tip.load_full().ok_or("missing header tip")?;
            let old_applied = harness.applied_tip.load_full().ok_or("missing genesis")?;
            let advanced = {
                let tree = harness.block_tree.read();
                let id = tree
                    .lookup(Hash256::from(blocks[0].block_hash()))
                    .ok_or("missing child")?;
                let node = tree.node(id)?;
                Arc::new(TipSnapshot {
                    tip_id: id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                })
            };
            let chain = TestChain::new(
                header_tip,
                Arc::clone(&harness.applied_tip),
                Arc::clone(&harness.block_tree),
            );
            *chain.scripted_tip_update.lock() = Some((old_header, Arc::clone(&advanced)));
            harness.sync.chain = Arc::new(chain);

            let frontier = harness.sync.observe_chain_frontier();

            assert_eq!(
                frontier.applied_tip.as_ref().map(|tip| tip.hash),
                Some(old_applied.hash)
            );
            assert_eq!(
                harness.applied_tip.load_full().as_ref().map(|tip| tip.hash),
                Some(advanced.hash)
            );
            assert_eq!(
                frontier.next_required.map(|body| (body.height, body.hash)),
                Some((1, Hash256::from(blocks[0].block_hash()))),
                "the required body must follow the captured applied tip, not the later publication"
            );
            Ok(())
        }

        #[test]
        fn request_frontier_retains_parent_plan_on_height_gaps() -> TestResult {
            let mut tree = BlockTree::new();
            let root = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
            let root_hash = tree.node(root)?.hash;
            let header = regtest_fixture::mined_regtest_header(BlockHash::from(root_hash), 1)
                .or_fail("regtest fixture header");
            let child = tree.insert_node(Some(root), header, NodeStatus::HeaderValid)?;
            tree.node_mut(child)?.height = 2;
            assert_eq!(
                BlockSync::first_connect_height(&tree, root_hash, child),
                Some(2),
            );
            Ok(())
        }

        #[test]
        fn fork_getdata_starts_at_common_ancestor_child() -> TestResult {
            let genesis = genesis_header();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;

            let losing1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let losing1_id =
                tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
            let losing2 = regtest_fixture::mined_regtest_header(losing1.compute_hash(), 2)
                .or_fail("regtest fixture header");
            let losing2_id =
                tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
            let applied = {
                let node = tree.node(losing2_id)?;
                TipSnapshot {
                    tip_id: losing2_id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                }
            };

            let winning1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)
                .or_fail("regtest fixture header");
            let winning1_id =
                tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
            let winning2 = regtest_fixture::mined_regtest_header(winning1.compute_hash(), 102)
                .or_fail("regtest fixture header");
            let winning2_id =
                tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
            let winning3 = regtest_fixture::mined_regtest_header(winning2.compute_hash(), 103)
                .or_fail("regtest fixture header");
            tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
            let expected = vec![
                winning1.compute_hash(),
                winning2.compute_hash(),
                winning3.compute_hash(),
            ];

            let SyncHarness {
                sync,
                peers,
                block_tree: _,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
            } = SyncHarness::new(tree);
            applied_tip.store(Some(Arc::new(applied)));
            let peer = PeerRemote::from(([127, 0, 0, 1], 18_460));
            let rx = connect_peer(&peers, synthetic_peer(peer, 100));

            assert!(
                sync.send_getdata_for_pending_blocks(
                    current_source(&sync.peer_table, peer),
                    100,
                    &test_frontier(&sync),
                )
                .sent
            );
            assert_eq!(
                witness_block_inventory(next_getdata(&rx)?)?,
                expected,
                "the fork request must begin immediately after the common ancestor"
            );
            Ok(())
        }

        fn pending_reorg_fixture() -> Result<(SyncHarness, TipSnapshot, Vec<Block>), TestError> {
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
            let losing1 = regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
                .or_fail("regtest fixture header");
            let losing1_id =
                tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
            let losing2 = regtest_fixture::mined_regtest_header(losing1.compute_hash(), 2)
                .or_fail("regtest fixture header");
            let losing2_id =
                tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
            let applied = {
                let node = tree.node(losing2_id)?;
                TipSnapshot {
                    tip_id: losing2_id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                }
            };

            let mut winning = Vec::new();
            let mut parent = genesis_id;
            let mut prev = genesis_header().compute_hash();
            for tag in 101..=103_u32 {
                let block = regtest_fixture::mined_block_with_prev_hash(
                    prev,
                    tag,
                    vec![regtest_fixture::coinbase(tag)],
                )
                .or_fail("regtest fixture block");
                parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
                prev = block.block_hash();
                winning.push(block);
            }

            let harness = SyncHarness::new(tree);
            harness.applied_tip.store(Some(Arc::new(applied.clone())));
            Ok((harness, applied, winning))
        }

        #[test]
        fn pending_reorg_frontier_is_first_connect_node() -> TestResult {
            let (harness, _applied, winning) = pending_reorg_fixture()?;
            let first_connect = Hash256::from(winning[0].block_hash());
            assert_eq!(
                harness.sync.next_expected_block(),
                Some((1, first_connect)),
                "the connect frontier must name the winner's first block, not the winner at applied+1"
            );
            Ok(())
        }

        #[test]
        fn chain_frontier_uses_captured_header_tip_during_branch_change() -> TestResult {
            let (mut harness, applied, winning) = pending_reorg_fixture()?;
            let header_tip = harness.block_tree.write().tip_handle();
            let captured = header_tip.load_full().ok_or("missing winning header tip")?;
            let replacement = Arc::new(applied);
            let chain = TestChain::new(
                header_tip,
                Arc::clone(&harness.applied_tip),
                Arc::clone(&harness.block_tree),
            );
            *chain.scripted_tip_update.lock() =
                Some((Arc::clone(&replacement), Arc::clone(&replacement)));
            harness.sync.chain = Arc::new(chain);

            let frontier = harness.sync.observe_chain_frontier();

            assert_eq!(
                frontier.chain_tip.as_ref().map(|tip| tip.hash),
                Some(captured.hash)
            );
            assert_eq!(
                harness.sync.chain.chain_tip().as_ref().map(|tip| tip.hash),
                Some(replacement.hash)
            );
            assert_eq!(
                frontier.next_required.map(|body| (body.height, body.hash)),
                Some((1, Hash256::from(winning[0].block_hash()))),
                "the captured winning branch must retain its first connect body"
            );
            Ok(())
        }

        #[test]
        fn apply_buffered_blocks_waits_for_pending_reorg() -> TestResult {
            let (harness, applied, winning) = pending_reorg_fixture()?;
            let sync = &harness.sync;
            let head = &winning[2];
            let head_hash = Hash256::from(head.block_hash());

            sync.buffer_received_block_chunk(
                &mut vec![bitcoin_rs_wire::InboundBlock::from_local(head.clone())],
                Some(head_hash),
            );
            assert!(sync.scheduler.lock().stager.contains(&head_hash));

            let first_connect = Hash256::from(winning[0].block_hash());
            assert_eq!(sync.apply_buffered_blocks(Some(first_connect)), (0, 0));
            assert!(
                sync.scheduler.lock().stager.contains(&head_hash),
                "an uncommittable winner body must stay staged for the branch switch"
            );
            assert_eq!(
                sync.chain.applied_tip().ok_or("missing applied tip")?.hash,
                applied.hash,
                "the losing applied tip must not be displaced by the extension path"
            );
            Ok(())
        }

        #[test]
        fn tick_does_not_resend_same_getheaders_while_pending() -> TestResult {
            let (sync, peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(3)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 8));

            sync.tick();
            let first = rx.try_recv()?;
            if !matches!(first, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected first getheaders").into());
            }

            sync.tick();
            assert!(rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn inbound_headers_response_releases_getheaders_gate() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                block_tree,
                inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            let chain_tip = block_tree.write().tip_handle();
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 8));

            sync.tick();
            let first = rx.try_recv()?;
            if !matches!(first, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected first getheaders").into());
            }

            let header = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![header],
                source: Some(current_source(&peers, addr)),

                wire_response: true,
            })?;
            sync.tick();
            let second = rx.try_recv()?;
            if !matches!(second, Message::GetHeaders(_)) {
                return Err(
                    std::io::Error::other("expected second getheaders after response").into(),
                );
            }
            let accepted_tip = chain_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("missing accepted header tip"))?;
            assert_eq!(accepted_tip.height, 1);
            assert_ne!(accepted_tip.tip_id, genesis_id);
            Ok(())
        }

        #[test]
        fn rejected_matching_peer_headers_release_gate_and_retry_immediately() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                block_tree,
                inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            let chain_tip = block_tree.write().tip_handle();
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 8));

            sync.tick();
            let first = rx.try_recv()?;
            if !matches!(first, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected first getheaders").into());
            }

            let orphan_prev = BlockHash(Hash256::from_le_bytes(&[0x11; 32]));
            let orphan = regtest_fixture::mined_regtest_header(orphan_prev, 5)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![orphan],
                source: Some(current_source(&peers, addr)),

                wire_response: true,
            })?;
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            assert!(rx.try_recv().is_err());
            let tip = chain_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("missing header tip"))?;
            assert_eq!(tip.tip_id, genesis_id, "orphan header must not advance tip");
            Ok(())
        }

        #[test]
        fn orphan_headers_keep_source_peer_connected() -> TestResult {
            let HeaderSyncFixture {
                sync,
                inbound_headers_tx,
                peers,
                ..
            } = header_sync_with_genesis()?;
            let peer_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let _rx = connect_peer(&peers, synthetic_peer(peer_addr, 8));
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![
                    regtest_fixture::mined_regtest_header(
                        BlockHash(Hash256::from_le_bytes(&[0x11; 32])),
                        1,
                    )
                    .or_fail("regtest fixture header"),
                ],
                source: Some(current_source(&peers, peer_addr)),

                wire_response: true,
            })?;

            sync.tick();

            assert!(
                peers.is_connected(peer_addr),
                "orphan announcements are not evidence of a bad peer"
            );
            assert!(
                peers.is_connected(peer_addr),
                "orphan announcements must not revoke the peer lease"
            );
            Ok(())
        }

        #[test]
        fn tick_bounded_request_peer_selection_skips_inflight_saturated_prefix() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 4,
                    max_peer_inflight: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let first_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let first_rx = connect_peer(&peers, synthetic_peer(first_addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(first_inventory) = first_rx.try_recv()? else {
                return Err(std::io::Error::other("expected first peer getdata").into());
            };
            assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
            let first_headers = first_rx.try_recv()?;
            if !matches!(first_headers, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected first peer getheaders").into());
            }

            let second_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8334,
            ));
            let second_rx = connect_peer(&peers, synthetic_peer(second_addr, 100));

            sync.tick();

            let Message::GetData(second_inventory) = second_rx.try_recv()? else {
                return Err(std::io::Error::other("expected second peer getdata").into());
            };
            assert_eq!(witness_block_inventory(second_inventory)?, expected[2..4]);
            while let Ok(message) = second_rx.try_recv() {
                if matches!(message, Message::GetData(_)) {
                    return Err(std::io::Error::other(
                        "a saturated prefix must not receive additional getdata",
                    )
                    .into());
                }
            }
            assert!(first_rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 2,
                    max_peer_inflight: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                }
                .with_pending_timeout_override(Duration::ZERO),
            );
            let stale_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let healthy_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8334,
            ));
            let stale_rx = connect_peer(&peers, synthetic_peer(stale_addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(first_inventory) = stale_rx.try_recv()? else {
                return Err(std::io::Error::other("expected stale peer getdata").into());
            };
            assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
            let stale_headers = stale_rx.try_recv()?;
            if !matches!(stale_headers, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected stale peer getheaders").into());
            }

            let healthy_rx = connect_peer(&peers, synthetic_peer(healthy_addr, 100));

            sync.tick();

            let Message::GetData(retry_inventory) = healthy_rx.try_recv()? else {
                return Err(std::io::Error::other("expected healthy peer retry getdata").into());
            };
            assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
            while let Ok(message) = healthy_rx.try_recv() {
                if matches!(message, Message::GetData(_)) {
                    return Err(std::io::Error::other(
                        "healthy peer must not receive another getdata request",
                    )
                    .into());
                }
            }
            while let Ok(message) = stale_rx.try_recv() {
                if matches!(message, Message::GetData(_)) {
                    return Err(std::io::Error::other(
                        "stale peer should not receive retry getdata",
                    )
                    .into());
                }
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod download_batches {
        use super::*;

        use bitcoin_rs_consensus::primitives::BlockImage;

        #[test]
        fn tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let mut tip_id = genesis_id;
            let mut expected = Vec::new();
            let batch_size = 16_u32;

            for height in 1_u32..=batch_size + 4 {
                let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
                let header = regtest_fixture::mined_regtest_header(parent_hash, height)
                    .or_fail("regtest fixture header");
                tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
                if height <= batch_size {
                    expected.push(BlockHash::from(tree.node(tip_id)?.hash));
                }
            }

            let SyncHarness {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
            } = SyncHarness::new(tree);
            install_budget(
                &sync,
                super::super::SyncBudget {
                    getdata_batch_limit: usize::try_from(batch_size)?,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let first = rx.try_recv()?;
            let Message::GetData(inventory) = first else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            let requested = inventory
                .into_iter()
                .map(|item| match item {
                    Inventory::WitnessBlock(hash) => {
                        Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
                    }
                    _ => Err(std::io::Error::other("expected witness block inventory")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(requested, expected);
            Ok(())
        }

        #[test]
        fn second_tick_does_not_re_request_already_pending_blocks() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let mut tip_id = genesis_id;

            for height in 1_u32..=3 {
                let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
                let header = regtest_fixture::mined_regtest_header(parent_hash, height)
                    .or_fail("regtest fixture header");
                tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            }

            let SyncHarness {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
            } = SyncHarness::new(tree);
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let first = rx.try_recv()?;
            if !matches!(first, Message::GetData(_)) {
                return Err(std::io::Error::other("expected first tick getdata").into());
            }
            let second = rx.try_recv()?;
            if !matches!(second, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected first tick getheaders").into());
            }

            sync.tick();

            match rx.try_recv() {
                Ok(Message::GetData(_)) => {
                    Err(std::io::Error::other("second tick re-requested pending blocks").into())
                }
                Ok(Message::GetHeaders(_)) => {
                    Err(std::io::Error::other("second tick resent in-flight getheaders").into())
                }
                Ok(_) => {
                    Err(std::io::Error::other("unexpected extra message after second tick").into())
                }
                Err(crossbeam_channel::TryRecvError::Empty) => Ok(()),
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    Err(std::io::Error::other("outbound channel disconnected").into())
                }
            }
        }

        #[test]
        fn successful_getdata_send_marks_requested_blocks_pending() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let first = rx.try_recv()?;
            let Message::GetData(inventory) = first else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected);

            let scheduler = sync.scheduler.lock();
            let window = &scheduler.window;
            assert_eq!(window.pending_len(), expected.len());
            for hash in expected {
                let hash =
                    bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(hash.as_bytes());
                assert!(window.contains_pending(&hash));
            }
            Ok(())
        }

        #[test]
        fn drain_inbound_blocks_prunes_stale_received_blocks_without_new_arrivals() -> TestResult {
            let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
            let block = Network::Regtest.genesis_block();
            let hash = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                block.block_hash().as_bytes(),
            );
            let received_at = Instant::now()
                .checked_sub(super::super::RECEIVED_BLOCK_TIMEOUT + Duration::from_secs(1))
                .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
            let payload = BlockImage::from_local(block);
            let staged =
                sync.scheduler
                    .lock()
                    .stager
                    .insert(hash, None, payload, None, received_at);
            let StagedBlock::Memory { bytes, .. } = staged else {
                return Err(std::io::Error::other("test block should stage in memory").into());
            };
            sync.scheduler
                .lock()
                .window
                .mark_received_from(hash, bytes, None, Instant::now());

            sync.drain_inbound_blocks();

            assert_eq!(sync.scheduler.lock().stager.received_len(), 0);
            Ok(())
        }

        #[test]
        fn tick_respects_pending_byte_budget() -> TestResult {
            let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_bytes: 256 * 1024,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(inventory.len(), 1);
            assert_eq!(sync.scheduler.lock().window.pending_len(), 1);
            Ok(())
        }

        #[test]
        fn tick_limits_inflight_per_peer() -> TestResult {
            let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(5)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_peer_inflight: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(inventory.len(), 2);
            let _headers = rx.try_recv()?;

            sync.tick();

            assert!(rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn tick_falls_back_to_single_deep_peer_below_fanout_threshold() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            let mut rxs = Vec::new();
            for idx in 0..super::super::MIN_PEERS_FOR_FANOUT - 1 {
                let addr = test_addr(9021, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 300 - i32::try_from(idx)?),
                ));
            }

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rxs[0].try_recv()? else {
                return Err(std::io::Error::other("expected deep getdata for highest peer").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected);
            for rx in &rxs[1..] {
                assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
            }
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                super::super::PENDING_BUDGET
            );
            Ok(())
        }

        #[test]
        fn inbound_peer_not_counted_toward_fanout_threshold() -> TestResult {
            let ineligible = PeerInfo {
                inbound: true,
                ..synthetic_peer(test_addr(9200, 0)?, 300)
            };
            assert_fallback_served_by_candidate(ineligible)
        }

        #[test]
        fn low_chain_peer_not_counted_toward_fanout_threshold() -> TestResult {
            let ineligible = synthetic_peer(test_addr(9220, 0)?, 0);
            assert_fallback_refused_to_candidate(ineligible)
        }

        #[test]
        fn demoted_peer_not_counted_toward_fanout_threshold() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            install_budget(
                &sync,
                super::super::default_sync_budget(Network::Regtest)
                    .with_pending_timeout_override(Duration::ZERO),
            );
            let demoted_rx = connect_peer(&peers, synthetic_peer(test_addr(9240, 0)?, 300));
            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(initial) = demoted_rx.try_recv()? else {
                return Err(std::io::Error::other("expected initial deep getdata").into());
            };
            assert_eq!(initial.len(), super::super::PENDING_BUDGET);
            if !matches!(demoted_rx.try_recv()?, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected getheaders for lone peer").into());
            }

            let mut rxs = Vec::new();
            for idx in 0..super::super::MIN_PEERS_FOR_FANOUT - 1 {
                let addr = test_addr(9241, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 200 - i32::try_from(idx)?),
                ));
            }
            sync.tick();

            let Message::GetData(retry) = rxs[0].try_recv()? else {
                return Err(std::io::Error::other("expected deep retry getdata").into());
            };
            assert_eq!(witness_block_inventory(retry)?, expected);
            assert!(
                demoted_rx.try_recv().is_err(),
                "demoted peer must receive no new block requests"
            );
            for rx in &rxs[1..] {
                assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
            }
            Ok(())
        }

        #[test]
        fn ineligible_peers_receive_no_block_requests_during_fanout() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            install_budget(
                &sync,
                super::super::default_sync_budget(Network::Regtest)
                    .with_pending_timeout_override(Duration::from_millis(250)),
            );
            let demoted_rx = connect_peer(&peers, synthetic_peer(test_addr(9250, 0)?, 290));
            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(initial) = demoted_rx.try_recv()? else {
                return Err(std::io::Error::other("expected initial deep getdata").into());
            };
            assert_eq!(initial.len(), super::super::PENDING_BUDGET);
            if !matches!(demoted_rx.try_recv()?, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected getheaders for lone peer").into());
            }

            let inbound_rx = connect_peer(
                &peers,
                PeerInfo {
                    inbound: true,
                    ..synthetic_peer(test_addr(9251, 0)?, 310)
                },
            );
            let non_witness_rx = connect_peer(
                &peers,
                PeerInfo {
                    services: 1,
                    ..synthetic_peer(test_addr(9252, 0)?, 305)
                },
            );
            let low_chain_rx = connect_peer(&peers, synthetic_peer(test_addr(9253, 0)?, 0));
            let mut rxs = Vec::new();
            for idx in 0..super::super::MIN_PEERS_FOR_FANOUT {
                let addr = test_addr(9254, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 300 - i32::try_from(idx)?),
                ));
            }

            std::thread::sleep(Duration::from_millis(300));
            sync.tick();
            sync.tick();
            assert!(
                !peers.is_connected(test_addr(9250, 0)?),
                "a peer that misses the request timeout must release its outbound slot"
            );
            assert!(
                sync.scheduler.lock().window.peer_in_staller_cooldown(
                    bitcoin_rs_wire::PeerSource::for_test(test_addr(9250, 0)?),
                    Instant::now()
                ),
                "a timed-out peer must not immediately reacquire the same block stripe"
            );

            let cap = super::super::PENDING_BUDGET
                .div_ceil(super::super::MIN_PEERS_FOR_FANOUT)
                .clamp(
                    super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
                    super::super::PEER_INFLIGHT_BUDGET,
                );
            for (idx, rx) in rxs.iter().enumerate() {
                let Message::GetData(inventory) = rx.try_recv()? else {
                    return Err(std::io::Error::other("expected getdata for eligible peer").into());
                };
                assert_eq!(
                    witness_block_inventory(inventory)?,
                    expected[idx * cap..(idx + 1) * cap]
                );
                assert!(rx.try_recv().is_err());
            }
            if !matches!(inbound_rx.try_recv()?, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected getheaders to header peer").into());
            }
            assert!(inbound_rx.try_recv().is_err());
            assert!(non_witness_rx.try_recv().is_err());
            assert!(low_chain_rx.try_recv().is_err());
            assert!(demoted_rx.try_recv().is_err());
            Ok(())
        }
    }

    #[cfg(test)]
    mod headroom_throttling {
        use super::*;
        use bitcoin_rs_consensus::primitives::BlockImage;

        #[test]
        fn tick_caps_requests_at_staged_byte_headroom() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
            let slot = 256 * 1024;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_bytes: 3 * slot,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            {
                let mut scheduler = sync.scheduler.lock();
                let now = Instant::now();
                for seed in [0xEE, 0xEF] {
                    let block = padded_block_exact(slot, seed);
                    scheduler.stager.insert(
                        Hash256::from_le_bytes(&[seed; 32]),
                        None,
                        BlockImage::from_local(block),
                        None,
                        now,
                    );
                }
            }
            let addr = test_addr(9270, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, 200));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, expected[..1]);

            sync.tick();

            assert_no_getdata(&rx)?;
            Ok(())
        }

        #[test]
        fn stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn() -> TestResult {
            let (sync, _peers, expected, rxs, _blocks_tx) =
                staged_count_wedge(wedge_budget(Duration::from_mins(1)))?;

            sync.tick();

            {
                let scheduler = sync.scheduler.lock();
                assert_eq!(scheduler.stager.received_len(), 14);
                assert_eq!(scheduler.window.pending_len(), 2);
                for front in &expected[..2] {
                    assert!(
                        scheduler
                            .window
                            .contains_pending(&Hash256::from_le_bytes(front.as_bytes())),
                        "stalled front stripe must stay pending, not churn through retry"
                    );
                }
            }

            sync.tick();

            for rx in &rxs {
                assert_no_getdata(rx)?;
            }
            let scheduler = sync.scheduler.lock();
            let stager = &scheduler.stager;
            assert_eq!(stager.received_len(), 14, "no evictions may occur");
            for height in 3..=16_u32 {
                let hash =
                    Hash256::from_le_bytes(expected[usize::try_from(height)? - 1].as_bytes());
                assert!(
                    stager.contains(&hash),
                    "every delivered block must remain staged (height {height})"
                );
            }
            assert_eq!(scheduler.window.pending_len(), 2);
            Ok(())
        }

        #[test]
        fn cold_start_stall_hedges_front_without_reassigning_owner() -> TestResult {
            let budget = super::super::SyncBudget {
                stall_timeout_initial: Duration::from_millis(100),
                ..wedge_budget(Duration::from_mins(1))
            };
            let ((sync, peers, _block_tree, _applied_tip, expected), _blocks_tx) =
                sync_with_header_chain_and_blocks(64)?;
            install_budget(&sync, budget);
            let mut rxs = Vec::new();
            for idx in 0..budget.min_peers_for_fanout {
                let addr = test_addr(9320, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 200 - i32::try_from(idx)?),
                ));
            }
            let owner = test_addr(9320, 0)?;
            let alternate = test_addr(9320, 1)?;

            sync.tick();
            assert_eq!(sync.scheduler.lock().window.pending_len(), 16);
            for (idx, rx) in rxs.iter().enumerate() {
                let Message::GetData(inventory) = rx.try_recv()? else {
                    return Err(std::io::Error::other("expected a striped getdata per peer").into());
                };
                assert_eq!(
                    witness_block_inventory(inventory)?,
                    expected[idx * 2..(idx + 1) * 2]
                );
            }

            let alternate_lease = peers
                .lease(alternate)
                .ok_or_else(|| std::io::Error::other("alternate peer lease missing"))?;
            let mut alternate_info = peers
                .infos()
                .into_iter()
                .find(|info| info.endpoint == alternate.endpoint())
                .ok_or_else(|| std::io::Error::other("alternate peer info missing"))?;
            alternate_info.start_height = 0;
            alternate_info.best_known_height = 0;
            assert!(peers.publish_info(alternate, &alternate_lease, alternate_info));
            assert!(peers.note_announced_tip(
                current_source(&peers, alternate),
                Hash256::from_le_bytes(expected[0].as_bytes()),
                Some(1),
            ));
            sync.tick();
            std::thread::sleep(Duration::from_millis(150));
            sync.tick();

            assert!(
                peers.is_connected(owner),
                "a cold-start hedge must not disconnect the pending owner"
            );
            let mut hedged = Vec::new();
            for rx in &rxs[1..] {
                while let Ok(message) = rx.try_recv() {
                    if let Message::GetData(inventory) = message {
                        hedged.extend(witness_block_inventory(inventory)?);
                    }
                }
            }
            assert_eq!(hedged, expected[..1]);
            assert_eq!(
                sync.scheduler
                    .lock()
                    .window
                    .pending_owner(&Hash256::from_le_bytes(expected[0].as_bytes())),
                Some(current_source(&peers, owner)),
                "the hedge must not reassign the front's owner"
            );

            std::thread::sleep(Duration::from_millis(50));
            sync.tick();
            for rx in &rxs[1..] {
                assert_no_getdata(rx)?;
            }
            Ok(())
        }

        #[test]
        fn fanout_replaces_preferred_peer_when_eligible_pool_recovers() -> TestResult {
            let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(48)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 16,
                    max_pending_bytes: usize::MAX,
                    max_peer_inflight: 16,
                    fanout_peer_inflight: 2,
                    min_peers_for_fanout: super::super::MIN_PEERS_FOR_FANOUT,
                    getdata_batch_limit: 16,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let owner = test_addr(9322, 0)?;
            let alternate = test_addr(9322, 1)?;
            let owner_rx = connect_peer(&peers, synthetic_peer(owner, 200));
            let alternate_rx = connect_peer(&peers, synthetic_peer(alternate, 100));

            sync.tick();
            let _ = next_getdata(&owner_rx)?;
            let _ = next_getdata(&alternate_rx)?;
            for block in &blocks[..4] {
                let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                inbound.source = Some(current_source(&peers, alternate));
                blocks_tx.send(inbound)?;
            }
            sync.tick();
            let _ = next_getdata(&alternate_rx)?;
            assert_eq!(
                sync.scheduler.lock().window.preferred_peer(),
                Some(current_source(&peers, alternate))
            );

            let mut recovered_rxs = Vec::new();
            for idx in 2..=8 {
                recovered_rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(test_addr(9322, idx)?, 100),
                ));
            }
            for block in &blocks[4..8] {
                let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                inbound.source = Some(current_source(&peers, alternate));
                blocks_tx.send(inbound)?;
            }
            sync.tick();

            let scheduler = sync.scheduler.lock();

            let window = &scheduler.window;
            assert!(window.preferred_peer().is_none());
            assert!(window.fanout_active());
            drop(scheduler);
            assert!(
                recovered_rxs.iter().any(|rx| rx.try_recv().is_ok()),
                "a recovered eligible peer must receive a fanout request"
            );
            Ok(())
        }

        #[test]
        fn applied_ancestry_lookup_uses_active_index_only_for_applied_prefix() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let main1 = regtest_fixture::mined_block_with_prev_hash(
                genesis.block_hash(),
                1,
                vec![regtest_fixture::coinbase(1)],
            )
            .or_fail("regtest fixture block");
            let main2 = regtest_fixture::mined_block_with_prev_hash(
                main1.block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let main3 = regtest_fixture::mined_block_with_prev_hash(
                main2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(3)],
            )
            .or_fail("regtest fixture block");
            let main4 = regtest_fixture::mined_block_with_prev_hash(
                main3.block_hash(),
                4,
                vec![regtest_fixture::coinbase(4)],
            )
            .or_fail("regtest fixture block");
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let main1_id =
                tree.insert_node(Some(genesis_id), main1.header, NodeStatus::HeaderValid)?;
            let main2_id =
                tree.insert_node(Some(main1_id), main2.header, NodeStatus::HeaderValid)?;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("main tip was not published"))?;
            let main3_id =
                tree.insert_node(Some(main2_id), main3.header, NodeStatus::HeaderValid)?;
            tree.insert_node(Some(main3_id), main4.header, NodeStatus::HeaderValid)?;
            let active_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("extended main tip was not published"))?;

            assert_eq!(
                BlockSync::indexed_applied_ancestry_tip(&tree, &applied_tip),
                Some(active_tip.tip_id),
                "an applied prefix must use the indexed active tip"
            );

            let mut fork_parent = genesis_id;
            let mut fork_prev = genesis.block_hash();
            for height in 1_u32..=5 {
                let fork = regtest_fixture::mined_block_with_prev_hash(
                    fork_prev,
                    height.saturating_add(100),
                    vec![regtest_fixture::coinbase(height.saturating_add(100))],
                )
                .or_fail("regtest fixture block");
                fork_prev = fork.block_hash();
                fork_parent =
                    tree.insert_node(Some(fork_parent), fork.header, NodeStatus::HeaderValid)?;
            }
            assert_ne!(
                tree.tip()
                    .ok_or_else(|| std::io::Error::other("fork tip was not published"))?
                    .tip_id,
                active_tip.tip_id
            );
            assert_eq!(
                BlockSync::indexed_applied_ancestry_tip(&tree, &applied_tip),
                None,
                "an applied tip outside the active header chain must retain side-chain bodies"
            );
            Ok(())
        }

        #[test]
        fn apply_side_backpressure_never_blamed_on_front_peer() -> TestResult {
            let (sync, peers, _block_tree, _applied_tip, expected) = sync_with_header_chain(4)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 2,
                    max_received_blocks: 2,
                    max_peer_inflight: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let staller = test_addr(9450, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(staller, 100));

            sync.scheduler
                .lock()
                .window
                .seed_front_cadence_for_test(50, Instant::now());

            sync.tick();
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
            let successor = Hash256::from_le_bytes(expected[1].as_bytes());
            {
                let block = Network::Regtest.genesis_block();
                sync.scheduler.lock().stager.insert(
                    successor,
                    None,
                    BlockImage::from_local(block),
                    None,
                    Instant::now(),
                );
            }
            sync.scheduler
                .lock()
                .window
                .mark_received_from(successor, 80, None, Instant::now());

            let frontier = Hash256::from_le_bytes(expected[0].as_bytes());
            {
                let block = Network::Regtest.genesis_block();
                sync.scheduler.lock().stager.insert(
                    frontier,
                    None,
                    BlockImage::from_local(block),
                    None,
                    Instant::now(),
                );
            }

            let far_future = Instant::now() + Duration::from_mins(1);

            sync.reconcile_window_recovery(&sync.observe_chain_frontier(), far_future);
            assert!(sync.scheduler.lock().window.stalling_peer().is_none());
            assert!(peers.is_connected(staller));

            let drained = sync
                .scheduler
                .lock()
                .stager
                .drain_expected_prefix(&[frontier]);
            assert_eq!(drained.len(), 1);
            sync.reconcile_window_recovery(&sync.observe_chain_frontier(), far_future);
            assert_eq!(
                sync.scheduler
                    .lock()
                    .window
                    .stalling_peer()
                    .map(|(addr, _)| addr),
                Some(staller.endpoint())
            );
            assert!(peers.is_connected(staller));
            sync.reconcile_window_recovery(
                &sync.observe_chain_frontier(),
                far_future + super::super::BLOCK_STALLING_TIMEOUT,
            );
            assert!(
                !peers.is_connected(staller),
                "with the apply side idle the same state must fire normally"
            );
            Ok(())
        }

        #[test]
        fn staged_frontier_stuck_past_bound_escalates_without_blame() -> TestResult {
            let (sync, peers, _block_tree, _applied_tip, expected) = sync_with_header_chain(4)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 2,
                    max_received_blocks: 2,
                    max_peer_inflight: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let staller = test_addr(9470, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(staller, 100));

            sync.scheduler
                .lock()
                .window
                .seed_front_cadence_for_test(50, Instant::now());

            sync.tick();
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected[..2]);

            let frontier = Hash256::from_le_bytes(expected[0].as_bytes());
            let successor = Hash256::from_le_bytes(expected[1].as_bytes());
            for hash in [frontier, successor] {
                let block = Network::Regtest.genesis_block();
                sync.scheduler.lock().stager.insert(
                    hash,
                    None,
                    BlockImage::from_local(block),
                    None,
                    Instant::now(),
                );
            }
            let staged_at = Instant::now();
            sync.scheduler.lock().window.mark_received_from(
                frontier,
                80,
                Some(current_source(&peers, staller)),
                staged_at,
            );
            sync.scheduler
                .lock()
                .window
                .mark_received_from(successor, 80, None, staged_at);

            let bound = super::super::default_sync_budget(Network::Regtest)
                .received_timeout
                .saturating_mul(2);
            let start = Instant::now();

            sync.reconcile_window_recovery(&sync.observe_chain_frontier(), start);
            sync.reconcile_window_recovery(
                &sync.observe_chain_frontier(),
                bound
                    .checked_sub(Duration::from_secs(1))
                    .map_or(start, |just_below| start + just_below),
            );
            assert!(
                sync.scheduler.lock().stager.contains(&frontier),
                "below the bound the staged frontier must stay put"
            );
            assert!(peers.is_connected(staller));
            assert!(sync.scheduler.lock().window.stalling_peer().is_none());

            sync.reconcile_window_recovery(
                &sync.observe_chain_frontier(),
                start + bound + Duration::from_secs(1),
            );
            assert!(
                !sync.scheduler.lock().stager.contains(&frontier),
                "past the bound the stuck staged frontier must be evicted for refetch"
            );
            assert!(
                peers.is_connected(staller),
                "the apply-side escalation must never blame or disconnect the front peer"
            );
            assert!(sync.scheduler.lock().window.stalling_peer().is_none());

            sync.tick();
            let requeued = witness_block_inventory(next_getdata(&rx)?)?;
            assert!(
                requeued.contains(&expected[0]),
                "the escalation must requeue the evicted frontier for refetch, got {requeued:?}"
            );

            sync.reconcile_window_recovery(
                &sync.observe_chain_frontier(),
                start + bound + Duration::from_secs(1) + super::super::BLOCK_STALLING_TIMEOUT,
            );
            assert_eq!(
                sync.scheduler
                    .lock()
                    .window
                    .stalling_peer()
                    .map(|(addr, _)| addr),
                Some(staller.endpoint())
            );
            sync.reconcile_window_recovery(
                &sync.observe_chain_frontier(),
                start + bound + Duration::from_secs(1) + super::super::BLOCK_STALLING_TIMEOUT * 2,
            );
            assert!(
                !peers.is_connected(staller),
                "after the escalation a genuinely stalling peer must be convictable"
            );
            Ok(())
        }

        #[test]
        fn transient_demotion_does_not_flap_fanout_mode() -> TestResult {
            const PEER_COUNT: usize = 8;
            let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
                sync_with_header_chain_and_blocks(64)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 16,
                    max_pending_bytes: usize::MAX,
                    max_received_blocks: 64,
                    max_received_bytes: usize::MAX,
                    max_peer_inflight: 16,
                    fanout_peer_inflight: 2,
                    min_peers_for_fanout: 8,
                    getdata_batch_limit: 16,
                    ..super::super::default_sync_budget(Network::Regtest)
                }
                .with_pending_timeout_override(Duration::from_millis(250)),
            );
            let mut rxs = Vec::new();
            for idx in 0..PEER_COUNT {
                let addr = test_addr(9340, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 200 - i32::try_from(idx)?),
                ));
            }

            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            assert!(sync.scheduler.lock().window.fanout_active());
            for (idx, rx) in rxs.iter().enumerate() {
                let Message::GetData(inventory) = rx.try_recv()? else {
                    return Err(std::io::Error::other("expected striped getdata").into());
                };
                assert_eq!(
                    witness_block_inventory(inventory)?,
                    expected[idx * 2..(idx + 1) * 2]
                );
            }

            for height in 3..=16_u32 {
                blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                    header_chain_block(&expected, height)?,
                ))?;
            }
            std::thread::sleep(Duration::from_millis(300));
            sync.tick();

            assert!(
                sync.scheduler.lock().window.fanout_active(),
                "one demotion below the threshold must not disengage fan-out"
            );
            assert_no_getdata(&rxs[0])?;
            let mut redistributed = Vec::new();
            let redistributed_cap = 16_usize.div_ceil(PEER_COUNT - 1);
            for rx in &rxs[1..] {
                while let Ok(message) = rx.try_recv() {
                    if let Message::GetData(inventory) = message {
                        let hashes = witness_block_inventory(inventory)?;
                        assert!(
                            hashes.len() <= redistributed_cap,
                            "per-peer batches must stay at the dynamic cap; a deep \
                     batch is the mode-flap signature"
                        );
                        redistributed.extend(hashes);
                    }
                }
            }
            assert!(
                expected[..2]
                    .iter()
                    .all(|hash| redistributed.contains(hash)),
                "the stalled front stripe must move to healthy peers under the cap"
            );

            sync.tick();
            assert!(sync.scheduler.lock().window.fanout_active());
            Ok(())
        }

        fn padded_block_exact(size: usize, seed: u8) -> Block {
            let mut block = regtest_fixture::mined_block_with_prev_hash(
                BlockHash(Hash256::from_le_bytes(&[seed; 32])),
                1,
                vec![super::transaction(seed)],
            )
            .or_fail("regtest fixture block");
            block.txs[0].outputs[0].script_pubkey = Vec::new().into();
            let prefix_growth = |len: usize| match len {
                0..=252 => 0,
                253..=0xffff => 2,
                _ => 4,
            };
            let wanted = size - consensus_bytes(&block).len();
            let script_len = wanted - prefix_growth(wanted - prefix_growth(wanted));
            block.txs[0].outputs[0].script_pubkey = vec![0_u8; script_len].into();
            assert_eq!(consensus_bytes(&block).len(), size);
            block
        }
    }

    #[cfg(test)]
    mod pending_retries {
        use super::*;

        #[test]
        fn tick_retries_expired_pending_before_new_heights() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(5)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                }
                .with_pending_timeout_override(Duration::ZERO),
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(first) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected first getdata").into());
            };
            assert_eq!(witness_block_inventory(first)?, expected[..2]);
            let _headers = rx.try_recv()?;

            sync.tick();

            let Message::GetData(second) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected retry getdata").into());
            };
            assert_eq!(witness_block_inventory(second)?, expected[..2]);
            Ok(())
        }

        #[test]
        fn tick_fills_mixed_retry_and_new_height_batch() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 3,
                    max_pending_bytes: 3 * 256 * 1024,
                    max_peer_inflight: 3,
                    getdata_batch_limit: 3,
                    ..super::super::default_sync_budget(Network::Regtest)
                }
                .with_pending_timeout_override(Duration::ZERO),
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(first) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected first getdata").into());
            };
            assert_eq!(witness_block_inventory(first)?, expected[..3]);
            let _headers = rx.try_recv()?;
            apply_fixture_block(&sync, header_chain_block(&expected, 1)?)?;

            sync.tick();

            let Message::GetData(second) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected mixed retry getdata").into());
            };
            assert_eq!(
                witness_block_inventory(second)?,
                vec![expected[1], expected[2], expected[3]]
            );
            Ok(())
        }

        #[test]
        fn tick_applies_contiguous_blocks_before_requesting_more() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let child = regtest_fixture::mined_regtest_header(genesis.block_hash(), 1)
                .or_fail("regtest fixture header");
            let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
            let expected = BlockHash::from(tree.node(child_id)?.hash);

            let SyncHarness {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx,
            } = SyncHarness::new(tree);
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(genesis))?;

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, std::vec![expected]);
            Ok(())
        }

        #[test]
        fn oversized_received_block_releases_pending_budget_for_retry() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let block = regtest_fixture::mined_block_with_prev_hash(
                genesis.block_hash(),
                1,
                vec![regtest_fixture::coinbase(1), transaction(0x41)],
            )
            .or_fail("regtest fixture block");
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let block_id =
                tree.insert_node(Some(genesis_id), block.header, NodeStatus::HeaderValid)?;
            let expected_hash = BlockHash::from(tree.node(block_id)?.hash);

            let SyncHarness {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx,
            } = SyncHarness::new(tree);
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_bytes: 1,
                    max_peer_inflight: 1,
                    getdata_batch_limit: 1,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                std::vec![expected_hash]
            );
            let _headers = rx.try_recv()?;
            assert_eq!(sync.scheduler.lock().window.pending_len(), 1);

            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block))?;
            sync.drain_inbound_blocks();

            {
                let scheduler = sync.scheduler.lock();
                let window = &scheduler.window;
                assert_eq!(window.pending_len(), 0);
                assert_eq!(window.pending_bytes(), 0);
            }

            sync.tick();

            let Message::GetData(retry) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected retry getdata").into());
            };
            assert_eq!(witness_block_inventory(retry)?, std::vec![expected_hash]);
            Ok(())
        }

        #[test]
        fn staging_byte_exhaustion_backpressures_requests_then_recovers() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let block1 = regtest_fixture::mined_block_with_prev_hash(
                genesis.block_hash(),
                1,
                vec![regtest_fixture::coinbase(1)],
            )
            .or_fail("regtest fixture block");
            let block2 = regtest_fixture::mined_block_with_prev_hash(
                block1.block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let block3 = regtest_fixture::mined_block_with_prev_hash(
                block2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(3)],
            )
            .or_fail("regtest fixture block");
            let block1_hash = block1.block_hash();
            let block2_hash = block2.block_hash();
            let block3_hash = block3.block_hash();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
            let block1_id =
                tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
            let block2_id =
                tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
            tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;

            let SyncHarness {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx,
            } = SyncHarness::new(tree);
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_bytes: consensus_bytes(&block2).len(),
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                std::vec![block1_hash, block2_hash]
            );
            let _headers = rx.try_recv()?;

            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block2.clone()))?;
            sync.drain_inbound_blocks();
            assert_eq!(
                sync.scheduler.lock().stager.received_bytes(),
                consensus_bytes(&block2).len()
            );

            sync.tick();
            assert!(rx.try_recv().is_err());
            assert_eq!(sync.scheduler.lock().stager.received_len(), 1);

            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block1))?;
            sync.tick();

            let applied_height = applied_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
                .height;
            assert_eq!(applied_height, 2);
            assert_eq!(sync.scheduler.lock().stager.received_len(), 0);
            let Message::GetData(recovered) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected recovery getdata").into());
            };
            assert_eq!(witness_block_inventory(recovered)?, std::vec![block3_hash]);
            Ok(())
        }

        #[test]
        fn staging_byte_exhaustion_blocks_all_requests() -> TestResult {
            let ExhaustionFixture {
                sync,
                stalled_rx,
                healthy_rx,
                ..
            } = staging_exhaustion_fixture()?;

            sync.tick();
            while let Ok(message) = stalled_rx.try_recv() {
                if matches!(message, Message::GetData(_)) {
                    return Err(std::io::Error::other(
                        "exhausted staging must not request from the stalled peer",
                    )
                    .into());
                }
            }
            while let Ok(message) = healthy_rx.try_recv() {
                if matches!(message, Message::GetData(_)) {
                    return Err(std::io::Error::other(
                        "exhausted staging must not request getdata from the healthy peer",
                    )
                    .into());
                }
            }
            assert_eq!(sync.scheduler.lock().stager.received_len(), 1);
            Ok(())
        }

        #[test]
        fn staging_byte_exhaustion_recovers_via_staged_block_expiry() -> TestResult {
            let ExhaustionFixture {
                sync,
                stalled_rx,
                healthy_rx,
                block1_hash,
                block2_hash,
                ..
            } = staging_exhaustion_fixture()?;

            sync.tick();
            while stalled_rx.try_recv().is_ok() {}

            std::thread::sleep(Duration::from_millis(125));
            sync.tick();

            assert_eq!(sync.scheduler.lock().stager.received_len(), 0);
            {
                let scheduler = sync.scheduler.lock();
                assert!(scheduler.window.has_request_capacity(&scheduler.stager));
                assert!(
                    scheduler
                        .window
                        .contains_pending(&Hash256::from_le_bytes(block1_hash.as_bytes()))
                );
            }
            let Message::GetData(retry) = healthy_rx.try_recv()? else {
                return Err(std::io::Error::other("expected healthy peer retry getdata").into());
            };
            assert_eq!(
                witness_block_inventory(retry)?,
                std::vec![block1_hash, block2_hash]
            );
            while let Ok(message) = stalled_rx.try_recv() {
                if matches!(message, Message::GetData(_)) {
                    return Err(std::io::Error::other(
                        "stalled peer should not receive retry getdata",
                    )
                    .into());
                }
            }
            Ok(())
        }

        #[test]
        fn deterministic_initial_sync_proxy_reports_pipeline_budgets() -> TestResult {
            let recorder = TestRecorder::default();
            metrics::with_local_recorder(&recorder, || {
                let fixture = deterministic_proxy_fixture()?;
                let DeterministicProxyFixture {
                    sync,
                    applied_tip,
                    block_tree,
                    inbound_blocks_tx,
                    outbound_rx,
                    blocks,
                } = fixture;

                sync.tick();

                assert_applied_genesis(&applied_tip, &block_tree)?;
                let Message::GetData(inventory) = outbound_rx.try_recv()? else {
                    return Err(std::io::Error::other("expected proxy getdata").into());
                };
                let pending_count = inventory.len();
                assert_eq!(pending_count, DETERMINISTIC_PROXY_BLOCKS);
                assert_gauge(&recorder, "node.sync.pending_blocks", pending_count);
                assert_metric_absent(&recorder, "node.sync.received_blocks");
                assert_metric_absent(&recorder, "node.sync.received_bytes");
                let _headers = outbound_rx.try_recv()?;

                for block in blocks[1..].iter().rev() {
                    inbound_blocks_tx
                        .send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))?;
                }
                sync.drain_inbound_blocks();
                let (received_count, peak_staged_bytes) = {
                    let scheduler = sync.scheduler.lock();
                    let stager = &scheduler.stager;
                    (stager.received_len(), stager.received_bytes())
                };
                assert_eq!(received_count, DETERMINISTIC_PROXY_BLOCKS.saturating_sub(1));
                assert!(peak_staged_bytes > 0);
                assert_gauge(&recorder, "node.sync.received_blocks", received_count);
                assert_gauge(&recorder, "node.sync.received_bytes", peak_staged_bytes);

                inbound_blocks_tx
                    .send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
                let apply_started = Instant::now();
                sync.drain_inbound_blocks();
                let apply_elapsed = apply_started.elapsed();
                let applied_height = applied_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("proxy apply did not publish tip"))?
                    .height;
                assert_eq!(applied_height, DETERMINISTIC_PROXY_TIP_HEIGHT);
                assert_eq!(sync.scheduler.lock().stager.received_len(), 0);
                assert_eq!(sync.scheduler.lock().window.pending_len(), 0);
                assert_histogram(&recorder, "node.sync.apply_buffered_blocks_seconds");

                println!(
                    "deterministic_sync_apply_proxy peak_staged_bytes={peak_staged_bytes} pending_count={pending_count} received_count={received_count} contiguous_apply_latency_us={}",
                    apply_elapsed.as_micros(),
                );
                Ok(())
            })
        }
    }

    #[cfg(test)]
    mod settlement_faults {
        use super::*;

        #[test]
        fn fatal_settlement_halts_further_apply_attempts() -> TestResult {
            let (mut tree, blocks) = mined_chain(1, 0)?;
            let chain_tip = tree.tip_handle();
            let block_tree = Arc::new(RwLock::new(tree));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let peers = Arc::new(PeerTable::new());
            let (_headers_tx, headers_rx) = unbounded();
            let (_blocks_tx, blocks_rx) = unbounded();
            let chain = Arc::new(TestChain::new(
                chain_tip,
                Arc::clone(&applied_tip),
                Arc::clone(&block_tree),
            ));
            let chain_ref: Arc<dyn SyncChain> = chain.clone();
            let sync = BlockSync::new(
                chain_ref,
                peers,
                headers_rx,
                blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            );
            chain.bootstrap_genesis();
            stage_body(&sync, &blocks[0]);
            assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
            let staged = sync.scheduler.lock().stager.received_len();
            assert!(
                !chain.closed_for_recovery(),
                "a fresh sync must not start halted"
            );

            chain.close_for_recovery();
            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 0),
                "a closed chain must not start another transition"
            );
            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                staged,
                "halted ticks must preserve staged blocks for recreation"
            );
            assert_eq!(applied_tip.load_full().map(|tip| tip.height), Some(1));
            Ok(())
        }

        // SYNC-04, SYNC-06
        #[test]
        fn fatal_settlement_raises_the_halt_signal_exactly_once() -> TestResult {
            let (mut tree, blocks) = mined_chain(3, 0)?;
            let chain_tip = tree.tip_handle();
            let block_tree = Arc::new(RwLock::new(tree));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let peers = Arc::new(PeerTable::new());
            let (_headers_tx, headers_rx) = unbounded();
            let (_blocks_tx, blocks_rx) = unbounded();
            let chain = Arc::new(TestChain::new(
                chain_tip,
                Arc::clone(&applied_tip),
                Arc::clone(&block_tree),
            ));
            let chain_handle: Arc<TestChain> = Arc::clone(&chain);
            let chain_ref: Arc<dyn SyncChain> = chain;
            let sync = BlockSync::new(
                chain_ref,
                peers,
                headers_rx,
                blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            );
            sync.tick();
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.height),
                Some(0),
                "genesis must be applied before the scripted failure"
            );

            let failed = Hash256::from_le_bytes(blocks[0].block_hash().as_bytes());
            let suffix = Hash256::from_le_bytes(blocks[1].block_hash().as_bytes());
            *chain_handle.scripted_commit_failure.lock() =
                Some((failed, super::super::chain::WindowApplyDisposition::Fatal));
            stage_body(&sync, &blocks[0]);
            stage_body(&sync, &blocks[1]);
            let staged = sync.scheduler.lock().stager.received_len();
            let cursor = sync.scheduler.lock().window.request_cursor();

            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 1),
                "the fatal settlement stops the window at the failed block"
            );
            assert!(
                chain_handle.closed_for_recovery(),
                "a fatal settlement must close the chain for recovery"
            );
            assert!(
                !sync.scheduler.lock().stager.contains(&failed),
                "the fatally settled block must not be restored for an in-process retry"
            );
            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                staged - 1,
                "the drained suffix is preserved in the stager for restart recreation"
            );
            assert_eq!(
                sync.scheduler.lock().window.request_cursor(),
                cursor,
                "a fatal settlement must not rewind the request cursor"
            );

            *chain_handle.scripted_commit_failure.lock() =
                Some((suffix, super::super::chain::WindowApplyDisposition::Fatal));
            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 0),
                "a halted sync must not re-enter commit_window"
            );
            let scripted = chain_handle.scripted_commit_failure.lock().take();
            assert!(
                scripted.is_some(),
                "the halt latched after one settlement: commit_window never consumed a second fatal script"
            );
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.height),
                Some(0),
                "no block of the settled window commits"
            );
            Ok(())
        }

        #[test]
        fn fatal_window_failure_schedules_no_retry() -> TestResult {
            let (mut tree, blocks) = mined_chain(5, 0)?;
            let chain_tip = tree.tip_handle();
            let block_tree = Arc::new(RwLock::new(tree));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let peers = Arc::new(PeerTable::new());
            let (_headers_tx, headers_rx) = unbounded();
            let (_blocks_tx, blocks_rx) = unbounded();
            let chain = Arc::new(TestChain::new(
                chain_tip,
                Arc::clone(&applied_tip),
                Arc::clone(&block_tree),
            ));
            let chain_ref: Arc<dyn SyncChain> = chain.clone();
            let sync = BlockSync::new(
                chain_ref,
                Arc::clone(&peers),
                headers_rx,
                blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            );
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let _rx = connect_peer(&peers, synthetic_peer(addr, 100));
            sync.tick();
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                2,
                "the first tick must hold two requested bodies as pending"
            );
            stage_body(&sync, &blocks[0]);
            stage_body(&sync, &blocks[1]);
            let failed = Hash256::from_le_bytes(blocks[0].block_hash().as_bytes());
            *chain.scripted_commit_failure.lock() =
                Some((failed, super::super::chain::WindowApplyDisposition::Fatal));
            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 1),
                "the fatal settlement stops the window at the failed block"
            );
            assert!(
                chain.closed_for_recovery(),
                "a fatal settlement must close the chain for recovery"
            );
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                2,
                "a fatal settlement must keep pending bodies instead of scheduling a retry"
            );
            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 0),
                "a halted sync must not re-enter commit_window"
            );
            Ok(())
        }

        #[test]
        fn drain_inbound_blocks_keeps_oversized_burst_within_received_budget() -> TestResult {
            let fixture = deterministic_proxy_fixture()?;
            let max_received_blocks = 2;
            install_budget(
                &fixture.sync,
                super::super::SyncBudget {
                    max_received_blocks,
                    max_received_bytes: usize::MAX,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );

            for block in fixture.blocks[1..6].iter().rev() {
                fixture
                    .inbound_blocks_tx
                    .send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))?;
            }

            fixture.sync.drain_inbound_blocks();

            assert!(
                fixture.sync.scheduler.lock().stager.received_len() <= max_received_blocks,
                "block stager must enforce received block count budget"
            );
            assert!(
                fixture.applied_tip.load_full().is_none(),
                "missing next expected block should prevent out-of-order apply"
            );
            Ok(())
        }

        #[test]
        fn apply_cache_miss_populates_and_then_hits() -> TestResult {
            let fixture = apply_cache_fixture(8, 0)?;
            install_budget(
                &fixture.sync,
                super::super::SyncBudget {
                    max_pending_blocks: 5,
                    max_pending_bytes: usize::MAX,
                    max_received_blocks: 64,
                    max_received_bytes: usize::MAX,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            assert!(
                cache_snapshot(&fixture.sync).is_none(),
                "cache starts empty so the first apply round is a miss"
            );

            for block in &fixture.blocks[..3] {
                stage_body(&fixture.sync, block);
            }
            let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
            assert_eq!((applied, failed), (3, 0), "three staged bodies apply");
            assert_eq!(
                fixture.applied_tip.load_full().map(|tip| tip.height),
                Some(3)
            );

            let cache = cache_snapshot(&fixture.sync)
                .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
            assert_eq!(
                cache.hashes.len(),
                5,
                "horizon capped at max_pending_blocks"
            );
            assert_eq!(cache.offset, 3, "advance moved offset past applied blocks");
            assert_eq!(cache.applied_tip_height, 3);
            assert_eq!(
                cache.applied_tip_hash,
                Hash256::from_le_bytes(fixture.blocks[2].block_hash().as_bytes())
            );
            assert_eq!(
                cache.chain_tip_hash,
                fixture
                    .chain_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("missing chain tip"))?
                    .hash
            );
            let cached_suffix = cache.hashes[cache.offset..].to_vec();

            stage_body(&fixture.sync, &fixture.blocks[3]);
            let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
            assert_eq!(
                (applied, failed),
                (1, 0),
                "fourth body applies on the hit path"
            );
            assert_eq!(
                fixture.applied_tip.load_full().map(|tip| tip.height),
                Some(4)
            );
            let cache = cache_snapshot(&fixture.sync)
                .ok_or_else(|| std::io::Error::other("hit path dropped the apply cache"))?;
            assert_eq!(
                cache.offset, 4,
                "hit path advanced offset within the same run"
            );
            assert_eq!(
                cached_suffix.first().copied(),
                Some(Hash256::from_le_bytes(
                    fixture.blocks[3].block_hash().as_bytes()
                )),
                "fourth applied block was already present in the populated horizon"
            );
            Ok(())
        }

        #[test]
        fn apply_cache_horizon_capped_by_pending_budget() -> TestResult {
            let fixture = apply_cache_fixture(12, 0)?;
            let cap = 4;
            install_budget(
                &fixture.sync,
                super::super::SyncBudget {
                    max_pending_blocks: cap,
                    max_pending_bytes: usize::MAX,
                    max_received_blocks: 64,
                    max_received_bytes: usize::MAX,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );

            stage_body(&fixture.sync, &fixture.blocks[0]);
            let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
            assert_eq!((applied, failed), (1, 0));
            let cache = cache_snapshot(&fixture.sync)
                .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
            assert_eq!(
                cache.hashes.len(),
                cap,
                "horizon must be capped at max_pending_blocks even with more headers available"
            );
            assert_eq!(
                cache.hashes[0],
                Hash256::from_le_bytes(fixture.blocks[0].block_hash().as_bytes())
            );
            assert_eq!(
                cache.hashes[cap - 1],
                Hash256::from_le_bytes(fixture.blocks[cap - 1].block_hash().as_bytes())
            );
            Ok(())
        }

        #[test]
        fn on_peer_ready_sweeps_dead_predecessor_header_request() -> TestResult {
            let HeaderSyncFixture { sync, .. } = header_sync_with_genesis()?;
            let peer_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let source = bitcoin_rs_wire::PeerSource::for_test(peer_addr);
            {
                let mut scheduler = sync.scheduler.lock();
                scheduler.headers_sync.entry(source).or_default().request =
                    Some(super::super::HeaderRequest {
                        source,
                        kind: super::super::HeaderRequestKind::Frontier,
                        locator_tip_hash: Hash256::default(),
                        target_height: 1,
                        requested_at: Instant::now(),
                        state: super::super::HeaderRequestState::AwaitingResponse,
                    });
                scheduler.header_request_owner = Some(source);
            }
            register_info(&sync.peer_table, synthetic_peer(peer_addr, 1));
            let source = current_source(&sync.peer_table, peer_addr);
            sync.on_peer_ready(source);
            assert!(
                sync.scheduler.lock().header_request().is_none(),
                "replacement readiness must release the dead predecessor's request"
            );
            assert!(sync.scheduler.lock().headers_sync.is_empty());
            Ok(())
        }

        #[test]
        fn on_peer_ready_sweep_releases_dead_owned_requests_only() -> TestResult {
            let HeaderSyncFixture { sync, .. } = header_sync_with_genesis()?;
            let peer_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8334,
            ));
            let (stale_tx, _stale_rx) = bitcoin_rs_wire::test_support::message_channel();
            let stale = PeerLease::new(stale_tx);
            sync.peer_table.register(peer_addr, stale.clone());
            register_info(&sync.peer_table, synthetic_peer(peer_addr, 2));
            let replacement = current_source(&sync.peer_table, peer_addr);
            {
                let mut scheduler = sync.scheduler.lock();
                scheduler
                    .headers_sync
                    .entry(replacement)
                    .or_default()
                    .request = Some(super::super::HeaderRequest {
                    source: replacement,
                    kind: super::super::HeaderRequestKind::Frontier,
                    locator_tip_hash: Hash256::default(),
                    target_height: 1,
                    requested_at: Instant::now(),
                    state: super::super::HeaderRequestState::AwaitingResponse,
                });
                scheduler.header_request_owner = Some(replacement);
            }
            sync.on_peer_ready(stale.source(peer_addr.endpoint()));
            sync.on_peer_ready(replacement);
            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(|request| request.source == replacement),
                "neither a stale callback nor the sweep may release the live connection's request"
            );
            Ok(())
        }

        #[test]
        fn far_future_matching_peer_retries_without_peer_blame() -> TestResult {
            let HeaderSyncFixture {
                genesis,
                sync,
                inbound_headers_tx,
                peers,
            } = header_sync_with_genesis()?;
            let peer_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let (tx, rx) = bitcoin_rs_wire::test_support::message_channel();
            let lease = PeerLease::new(tx);
            peers.register(peer_addr, lease.clone());
            peers.publish_info(peer_addr, &lease, synthetic_peer(peer_addr, 8));
            let tip_before = sync
                .chain
                .chain_tip()
                .ok_or_else(|| std::io::Error::other("missing genesis tip"))?;

            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![far_future_header(genesis.compute_hash(), 1)?],
                source: Some(current_source(&peers, peer_addr)),

                wire_response: true,
            })?;
            sync.tick();

            assert_eq!(sync.chain.chain_tip().as_deref(), Some(tip_before.as_ref()));
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            assert!(rx.try_recv().is_err());
            assert!(
                !lease.is_cancelled(),
                "local-clock rejection must not cancel the peer lease"
            );
            assert!(peers.is_connected(peer_addr));
            assert!(peers.is_connected(peer_addr));
            assert!(
                !sync.scheduler.lock().window.peer_in_staller_cooldown(
                    bitcoin_rs_wire::PeerSource::for_test(peer_addr),
                    Instant::now()
                ),
                "local-clock rejection must not blame the peer"
            );
            Ok(())
        }

        #[test]
        fn tick_sorts_out_of_order_peers_before_requesting_blocks() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
            let low_addr = test_addr(9500, 0)?;
            let high_addr = test_addr(9500, 1)?;
            let low_rx = connect_peer(&peers, synthetic_peer(low_addr, 2));
            let high_rx = connect_peer(&peers, synthetic_peer(high_addr, 8));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = high_rx.try_recv()? else {
                return Err(std::io::Error::other("expected high peer getdata").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected);
            assert!(matches!(high_rx.try_recv()?, Message::GetHeaders(_)));
            assert!(low_rx.try_recv().is_err());
            Ok(())
        }

        // P2P-05
        #[test]
        fn same_address_registration_clears_getheaders_gate_and_routes_replacement() -> TestResult {
            let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = test_addr(9501, 0)?;
            let old_rx = connect_peer(&peers, synthetic_peer(addr, 8));
            sync.tick();
            assert!(matches!(old_rx.try_recv()?, Message::GetHeaders(_)));

            let (new_tx, new_rx) = bitcoin_rs_wire::test_support::message_channel();
            let new_lease = PeerLease::new(new_tx);
            peers.register(addr, new_lease.clone());
            peers.publish_info(addr, &new_lease, synthetic_peer(addr, 8));
            sync.tick();

            assert!(old_rx.try_recv().is_err());
            assert!(matches!(new_rx.try_recv()?, Message::GetHeaders(_)));
            Ok(())
        }

        #[test]
        fn tick_uses_highest_peer_for_headers_when_request_capacity_is_zero() -> TestResult {
            let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let low_rx = connect_peer(&peers, ineligible_peer(test_addr(9502, 0)?, 5));
            let high_rx = connect_peer(&peers, ineligible_peer(test_addr(9502, 1)?, 9));

            sync.tick();

            assert!(matches!(high_rx.try_recv()?, Message::GetHeaders(_)));
            assert!(low_rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn tick_bounded_request_peer_selection_preserves_equal_height_order() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 4,
                    max_peer_inflight: 2,
                    getdata_batch_limit: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let first_rx = connect_peer(&peers, synthetic_peer(test_addr(9503, 0)?, 100));
            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            assert_eq!(
                witness_block_inventory(match first_rx.try_recv()? {
                    Message::GetData(inventory) => inventory,
                    _ => return Err(std::io::Error::other("expected first getdata").into()),
                })?,
                expected[..2]
            );
            let _ = first_rx.try_recv()?;

            let second_rx = connect_peer(&peers, synthetic_peer(test_addr(9503, 1)?, 100));
            sync.tick();
            assert_eq!(
                witness_block_inventory(match second_rx.try_recv()? {
                    Message::GetData(inventory) => inventory,
                    _ => return Err(std::io::Error::other("expected second getdata").into()),
                })?,
                expected[2..4]
            );
            Ok(())
        }

        pub(crate) fn deliver_headers(
            tx: &crossbeam_channel::Sender<InboundHeaders>,
            headers: Vec<Header>,
            source: PeerSource,
        ) -> TestResult {
            tx.send(InboundHeaders {
                headers,
                source: Some(source),
                wire_response: true,
            })?;
            Ok(())
        }

        pub(crate) fn locator_of(message: &Message) -> Option<Vec<[u8; 32]>> {
            match message {
                Message::GetHeaders(request) => Some(
                    request
                        .locator_hashes
                        .iter()
                        .map(|hash| *hash.as_byte_array())
                        .collect(),
                ),
                _ => None,
            }
        }

        pub(crate) fn next_locator(
            rx: &bitcoin_rs_wire::test_support::MessageReceiver,
        ) -> Option<Vec<[u8; 32]>> {
            rx.try_iter().find_map(|message| locator_of(&message))
        }
    }

    #[cfg(test)]
    mod peer_fanout {
        use super::*;

        #[test]
        fn tick_retries_when_all_selected_peers_have_expired_pending() -> TestResult {
            let (sync, peers, _tree, _applied, expected) = sync_with_header_chain(3)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    getdata_batch_limit: 1,
                    ..super::super::default_sync_budget(Network::Regtest)
                }
                .with_pending_timeout_override(Duration::ZERO),
            );
            let rx = connect_peer(&peers, synthetic_peer(test_addr(9504, 0)?, 100));
            sync.tick();
            let _ = rx.try_recv()?;
            let _ = rx.try_recv()?;
            sync.tick();
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected expired-pending retry").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected[..1]);
            Ok(())
        }

        #[test]
        fn tick_fans_out_getdata_across_eligible_peers() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            let mut receivers = Vec::new();
            for idx in 0..super::super::MIN_PEERS_FOR_FANOUT {
                receivers.push(connect_peer(
                    &peers,
                    synthetic_peer(test_addr(9505, idx)?, 300 - i32::try_from(idx)?),
                ));
            }
            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            let cap = super::super::PENDING_BUDGET
                .div_ceil(super::super::MIN_PEERS_FOR_FANOUT)
                .clamp(
                    super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
                    super::super::PEER_INFLIGHT_BUDGET,
                );
            for (idx, receiver) in receivers.iter().enumerate() {
                let Message::GetData(inventory) = receiver.try_recv()? else {
                    return Err(std::io::Error::other("expected fanout getdata").into());
                };
                assert_eq!(
                    witness_block_inventory(inventory)?,
                    expected[idx * cap..(idx + 1) * cap]
                );
                if idx == 0 {
                    assert!(matches!(receiver.try_recv()?, Message::GetHeaders(_)));
                }
                assert!(receiver.try_recv().is_err());
            }
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                super::super::PENDING_BUDGET
            );
            Ok(())
        }

        #[test]
        fn stale_invalid_headers_cannot_evict_or_clear_replacement() -> TestResult {
            let table = Arc::new(PeerTable::new());
            let addr = test_addr(9507, 0)?;
            let (old_tx, _old_rx) = bitcoin_rs_wire::test_support::message_channel();
            let old = PeerLease::new(old_tx);
            table.register(addr, old.clone());
            let (new_tx, _new_rx) = bitcoin_rs_wire::test_support::message_channel();
            let new = PeerLease::new(new_tx);
            table.register(addr, new.clone());
            assert!(!table.disconnect_source(old.source(addr.endpoint())));
            assert!(table.is_current(new.source(addr.endpoint())));
            assert!(!new.is_cancelled());
            Ok(())
        }

        #[test]
        fn mutated_forward_body_preserves_descendant_for_retry() -> TestResult {
            use bitcoin_rs_consensus::primitives::Amount;
            let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
            sync.chain.bootstrap_genesis();
            stage_body(&sync, &main[0]);
            assert_eq!(sync.apply_buffered_blocks(None), (1, 0));

            let main_hash = main[0].block_hash();
            let bad = regtest_fixture::mined_block_with_prev_hash(
                main_hash,
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let mut bad_body = bad.clone();
            bad_body.txs[0].outputs[0].value = Amount::from_sat(2);
            let descendant = regtest_fixture::mined_block_with_prev_hash(
                bad.block_hash(),
                3,
                vec![regtest_fixture::coinbase(3)],
            )
            .or_fail("regtest fixture block");
            assert!(matches!(
                sync.chain.admit_headers(&[bad.header, descendant.header]),
                HeaderAdmission::Accepted { .. }
            ));
            stage_body(&sync, &bad_body);
            stage_body(&sync, &descendant);

            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 1),
                "the mutated body must stop the window with nothing committed"
            );
            let bad_hash = Hash256::from_le_bytes(bad.block_hash().as_bytes());
            let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
            assert!(!sync.scheduler.lock().stager.contains(&bad_hash));
            let descendant_staged = sync.scheduler.lock().stager.contains(&descendant_hash);
            assert!(
                descendant_staged,
                "valid descendant must remain staged for retry"
            );
            assert_eq!(
                sync.apply_buffered_blocks(None),
                (0, 0),
                "without a replacement body the frontier must wait for re-download"
            );
            assert_eq!(applied_tip.load_full().map(|tip| tip.height), Some(1));
            Ok(())
        }
    }

    #[cfg(test)]
    mod header_progress {
        use super::*;

        // SYNC-06
        #[test]
        fn tick_sends_getdata_for_headers_above_applied_tip() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let mut tip_id = genesis_id;
            let mut expected = Vec::new();

            for height in 1_u32..=3 {
                let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
                let header = regtest_fixture::mined_regtest_header(parent_hash, height)
                    .or_fail("regtest fixture header");
                tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
                expected.push(BlockHash::from(tree.node(tip_id)?.hash));
            }

            let SyncHarness {
                sync,
                peers,
                block_tree,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
            } = SyncHarness::new(tree);
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let first = rx.try_recv()?;
            let Message::GetData(inventory) = first else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(inventory.len(), 3);
            let requested = inventory
                .into_iter()
                .map(|item| match item {
                    Inventory::WitnessBlock(hash) => {
                        Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
                    }
                    _ => Err(std::io::Error::other("expected witness block inventory")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(requested, expected);

            let second = rx.try_recv()?;
            if !matches!(second, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected getheaders").into());
            }
            Ok(())
        }

        // SYNC-06
        #[test]
        fn tick_fetches_new_tip_headers_from_at_tip_peers() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let mut tip_id = genesis_id;
            for height in 1_u32..=2 {
                let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
                let header = regtest_fixture::mined_regtest_header(parent_hash, height)
                    .or_fail("regtest fixture header");
                tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            }
            let applied = {
                let node = tree.node(tip_id)?;
                TipSnapshot {
                    tip_id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                    chain_tx_count: node.chain_tx_count,
                }
            };
            let announced_header =
                regtest_fixture::mined_regtest_header(BlockHash::from(tree.node(tip_id)?.hash), 3)
                    .or_fail("regtest fixture header");
            let expected = announced_header.compute_hash();

            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            applied_tip.store(Some(Arc::new(applied)));
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 2));

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![announced_header],
                source: Some(current_source(&peers, addr)),

                wire_response: true,
            })?;

            sync.tick();

            let first = rx
                .try_recv()
                .map_err(|_| std::io::Error::other("no getdata sent for the new tip header"))?;
            let Message::GetData(inventory) = first else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(
                inventory.len(),
                1,
                "only the unapplied new block is requested"
            );
            match &inventory[0] {
                Inventory::WitnessBlock(hash) => {
                    assert_eq!(
                        Hash256::from_le_bytes(hash.as_byte_array()),
                        expected.into()
                    );
                }
                _ => return Err(std::io::Error::other("expected witness block inventory").into()),
            }
            Ok(())
        }

        #[test]
        fn tick_fetches_reorg_fork_announced_by_at_tip_peer() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let losing1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let losing1_id =
                tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
            let losing2 = regtest_fixture::mined_regtest_header(losing1.compute_hash(), 2)
                .or_fail("regtest fixture header");
            let losing2_id =
                tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
            let applied = {
                let node = tree.node(losing2_id)?;
                TipSnapshot {
                    tip_id: losing2_id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                }
            };

            let winning1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)
                .or_fail("regtest fixture header");
            let winning2 = regtest_fixture::mined_regtest_header(winning1.compute_hash(), 102)
                .or_fail("regtest fixture header");
            let winning3 = regtest_fixture::mined_regtest_header(winning2.compute_hash(), 103)
                .or_fail("regtest fixture header");
            let expected: Vec<Hash256> = [&winning1, &winning2, &winning3]
                .iter()
                .map(|header| header.compute_hash().into())
                .collect();

            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            applied_tip.store(Some(Arc::new(applied)));
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 2));

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![winning1, winning2, winning3],
                source: Some(current_source(&peers, addr)),

                wire_response: true,
            })?;

            sync.tick();

            assert_eq!(
                peers.infos()[0].best_known_height,
                3,
                "the announced winning fork must earn credit on the reselected best chain"
            );
            let first = rx
                .try_recv()
                .map_err(|_| std::io::Error::other("no getdata sent for the announced fork"))?;
            let Message::GetData(inventory) = first else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            let requested = inventory
                .into_iter()
                .map(|item| match item {
                    Inventory::WitnessBlock(hash) => {
                        Ok(Hash256::from_le_bytes(hash.as_byte_array()))
                    }
                    _ => Err(std::io::Error::other("expected witness block inventory")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                requested, expected,
                "the reorg connect set must be requested after the common ancestor"
            );
            Ok(())
        }

        #[test]
        fn losing_fork_credit_survives_winner_disconnect() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let losing1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let losing1_id =
                tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
            let losing2 = regtest_fixture::mined_regtest_header(losing1.compute_hash(), 2)
                .or_fail("regtest fixture header");
            tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
            let genesis_node = tree.node(genesis_id)?;
            let applied = TipSnapshot {
                tip_id: genesis_id,
                chain_tx_count: genesis_node.chain_tx_count,
                height: genesis_node.height,
                chainwork: genesis_node.chainwork,
                hash: genesis_node.hash,
            };

            let fork1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)
                .or_fail("regtest fixture header");
            let fork2 = regtest_fixture::mined_regtest_header(fork1.compute_hash(), 102)
                .or_fail("regtest fixture header");
            let fork3 = regtest_fixture::mined_regtest_header(fork2.compute_hash(), 103)
                .or_fail("regtest fixture header");
            let expected = [fork1, fork2, fork3];
            let expected_hashes: Vec<Hash256> = expected
                .iter()
                .map(|header| header.compute_hash().into())
                .collect();

            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            applied_tip.store(Some(Arc::new(applied)));

            let peer_a = test_addr(8333, 0)?;
            let peer_b = test_addr(8333, 1)?;
            let rx_a = connect_peer(&peers, synthetic_peer(peer_a, 0));
            let _rx_b = connect_peer(&peers, synthetic_peer(peer_b, 0));

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork1, fork2],
                source: Some(current_source(&peers, peer_a)),

                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            assert_eq!(
                peers
                    .infos()
                    .into_iter()
                    .find(|info| info.endpoint == peer_a.endpoint())
                    .ok_or("peer A info missing")?
                    .best_known_height,
                0,
                "a losing fork must not receive scalar credit yet"
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork3],
                source: Some(current_source(&peers, peer_b)),

                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            assert_eq!(
                peers
                    .infos()
                    .into_iter()
                    .find(|info| info.endpoint == peer_a.endpoint())
                    .ok_or("peer A info missing after reorg")?
                    .best_known_height,
                2,
                "peer A's retained fork tip must be credited after the fork wins"
            );
            assert!(peers.disconnect_source(current_source(&peers, peer_b)));

            sync.tick();

            let requested = next_getdata(&rx_a)?
                .into_iter()
                .map(|item| match item {
                    Inventory::WitnessBlock(hash) => {
                        Ok(Hash256::from_le_bytes(hash.as_byte_array()))
                    }
                    _ => Err(std::io::Error::other("expected witness block inventory")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                requested,
                expected_hashes[..2],
                "the surviving peer must serve the bodies it demonstrated"
            );
            Ok(())
        }
    }

    mod header_ingress {
        use super::super::headers::{MAX_HEADER_BATCHES_PER_TICK, MAX_HEADERS_PER_TICK};
        use super::*;

        // P2P-07
        #[test]
        fn header_backlog_yields_to_block_apply_and_request_scheduling() -> TestResult {
            let (tree, blocks) = mined_chain(2, 0)?;
            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            let peer = test_addr(9790, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let old_peer = test_addr(9791, 0)?;
            let _old_rx = connect_peer(&peers, synthetic_peer(old_peer, 2));
            let stale = current_source(&peers, old_peer);
            assert!(peers.disconnect_source(stale));

            for n in 0..2 * MAX_HEADER_BATCHES_PER_TICK {
                inbound_headers_tx.send(InboundHeaders {
                    headers: Vec::new(),
                    source: n.is_multiple_of(2).then_some(stale),
                    wire_response: true,
                })?;
            }
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            let started = Instant::now();
            sync.tick();
            eprintln!(
                "tick with empty/stale header backlog: {:?}",
                started.elapsed()
            );
            assert_eq!(sync.inbound_headers_rx.len(), MAX_HEADER_BATCHES_PER_TICK);
            assert_eq!(applied_tip.load_full().ok_or("no applied block")?.height, 1);
            assert!(
        next_getdata(&rx)?.iter().any(|item| {
            matches!(item, Inventory::WitnessBlock(hash) if Hash256::from_le_bytes(hash.as_byte_array()) == Hash256::from(blocks[1].block_hash()))
        }),
        "the same tick must schedule the next body despite queued headers"
    );
            sync.tick();
            assert!(sync.inbound_headers_rx.is_empty());
            Ok(())
        }

        #[test]
        fn header_work_budget_keeps_whole_batches_in_order() -> TestResult {
            let page = bitcoin_rs_wire::wire::MAX_HEADERS_MESSAGE_COUNT;
            for lengths in [vec![page, page, 1], vec![page - 1, page, page, 0]] {
                let mut tree = BlockTree::new();
                let genesis = genesis_header();
                tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
                let SyncHarness {
                    sync,
                    inbound_headers_tx,
                    ..
                } = SyncHarness::new(tree);
                for len in &lengths {
                    inbound_headers_tx.send(InboundHeaders {
                        headers: vec![genesis; *len],
                        source: None,
                        wire_response: true,
                    })?;
                }
                sync.drain_inbound_headers();
                assert_eq!(sync.inbound_headers_rx.len(), 1);
                let last = sync.inbound_headers_rx.try_recv()?;
                assert_eq!(last.headers.len(), *lengths.last().ok_or("empty lengths")?);
                let processed: usize = lengths[..lengths.len() - 1].iter().sum();
                assert!((MAX_HEADERS_PER_TICK..MAX_HEADERS_PER_TICK + page).contains(&processed));
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod fork_retargeting {
        use super::*;

        struct TwoBranches {
            sync: BlockSync,
            rx: bitcoin_rs_wire::test_support::MessageReceiver,
            source: PeerSource,
            chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
            losing_hashes: Vec<BlockHash>,
            losing_bodies: Vec<Block>,
            winning_tip: TipSnapshot,
            winning_hashes: Vec<BlockHash>,
        }

        fn two_branches() -> Result<TwoBranches, TestError> {
            let snapshot = |tree: &BlockTree, tip_id| -> Result<TipSnapshot, TestError> {
                let node = tree.node(tip_id)?;
                Ok(TipSnapshot {
                    tip_id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                    chain_tx_count: node.chain_tx_count,
                })
            };
            let genesis = genesis_header();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let genesis_tip = snapshot(&tree, genesis_id)?;

            let losing_body1 = regtest_fixture::mined_block_with_prev_hash(
                genesis.compute_hash(),
                1,
                vec![regtest_fixture::coinbase(1)],
            )
            .or_fail("regtest fixture block");
            let losing_body2 = regtest_fixture::mined_block_with_prev_hash(
                losing_body1.block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let losing1_id = tree.insert_node(
                Some(genesis_id),
                losing_body1.header,
                NodeStatus::HeaderValid,
            )?;
            let losing2_id = tree.insert_node(
                Some(losing1_id),
                losing_body2.header,
                NodeStatus::HeaderValid,
            )?;
            let losing_tip = snapshot(&tree, losing2_id)?;
            let losing_hashes = vec![losing_body1.block_hash(), losing_body2.block_hash()];
            let losing_bodies = vec![losing_body1, losing_body2];

            let winning1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)
                .or_fail("regtest fixture header");
            let winning1_id =
                tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
            let winning2 = regtest_fixture::mined_regtest_header(winning1.compute_hash(), 102)
                .or_fail("regtest fixture header");
            let winning2_id =
                tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
            let winning3 = regtest_fixture::mined_regtest_header(winning2.compute_hash(), 103)
                .or_fail("regtest fixture header");
            let winning3_id =
                tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
            let winning_tip = snapshot(&tree, winning3_id)?;
            let winning_hashes = vec![
                winning1.compute_hash(),
                winning2.compute_hash(),
                winning3.compute_hash(),
            ];

            let chain_tip = Arc::new(ArcSwapOption::empty());
            chain_tip.store(Some(Arc::new(losing_tip)));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            applied_tip.store(Some(Arc::new(genesis_tip)));
            let block_tree = Arc::new(RwLock::new(tree));
            let peers = Arc::new(PeerTable::new());
            let (_inbound_headers_tx, inbound_headers_rx) = unbounded::<InboundHeaders>();
            let (_inbound_blocks_tx, inbound_blocks_rx) =
                unbounded::<bitcoin_rs_wire::InboundBlock>();
            let sync = BlockSync::new(
                std::sync::Arc::new(TestChain::new(
                    Arc::clone(&chain_tip),
                    Arc::clone(&applied_tip),
                    block_tree,
                )),
                Arc::clone(&peers),
                inbound_headers_rx,
                inbound_blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            );
            let peer = PeerRemote::from(([127, 0, 0, 1], 18_461));
            let rx = connect_peer(&peers, synthetic_peer(peer, 100));
            let source = current_source(&sync.peer_table, peer);

            assert!(
                sync.send_getdata_for_pending_blocks(source, 100, &test_frontier(&sync))
                    .sent
            );
            assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, losing_hashes);
            Ok(TwoBranches {
                sync,
                rx,
                source,
                chain_tip,
                losing_hashes,
                losing_bodies,
                winning_tip,
                winning_hashes,
            })
        }

        #[test]
        fn retargeting_pending_requests_drops_losing_branch_hashes() -> TestResult {
            let TwoBranches {
                sync,
                rx,
                source,
                chain_tip,
                losing_hashes,
                winning_tip,
                winning_hashes,
                ..
            } = two_branches()?;

            chain_tip.store(Some(Arc::new(winning_tip)));
            assert!(
                sync.send_getdata_for_pending_blocks(source, 100, &test_frontier(&sync))
                    .sent
            );
            let requested = witness_block_inventory(next_getdata(&rx)?)?;
            assert_eq!(requested, winning_hashes);
            assert!(
                requested.iter().all(|hash| !losing_hashes.contains(hash)),
                "retargeted requests must not retain hashes from the losing branch"
            );
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                winning_hashes.len(),
                "retargeting must release losing-branch pending capacity"
            );
            Ok(())
        }

        #[test]
        fn retarget_purges_staged_off_branch_bodies() -> TestResult {
            let TwoBranches {
                sync,
                rx,
                source,
                chain_tip,
                losing_hashes,
                losing_bodies,
                winning_tip,
                winning_hashes,
            } = two_branches()?;
            let [losing1, losing2]: [Block; 2] = losing_bodies
                .try_into()
                .map_err(|_| "the fixture has two losing bodies")?;
            let mut delivery = vec![bitcoin_rs_wire::InboundBlock::from_local(losing1)];
            assert_eq!(sync.buffer_received_block_chunk(&mut delivery, None), 1);
            assert_eq!(sync.scheduler.lock().stager.received_len(), 1);

            chain_tip.store(Some(Arc::new(winning_tip)));
            assert!(
                sync.send_getdata_for_pending_blocks(source, 100, &test_frontier(&sync))
                    .sent
            );
            assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, winning_hashes);
            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                0,
                "the retarget must purge the staged losing-branch body"
            );

            let mut late = vec![bitcoin_rs_wire::InboundBlock::from_local(losing2)];
            assert_eq!(
                sync.buffer_received_block_chunk(&mut late, None),
                0,
                "the late losing-branch delivery must be discarded, not staged"
            );
            let scheduler = sync.scheduler.lock();
            assert_eq!(
                scheduler.stager.received_len(),
                0,
                "a late losing-branch delivery must not stage"
            );
            assert!(
                losing_hashes
                    .iter()
                    .all(|hash| !scheduler.window.contains_pending(&Hash256::from(*hash))),
                "no losing-branch hash may be pending after the retarget"
            );
            Ok(())
        }

        #[test]
        fn outweighed_branch_target_accepts_shorter_higher_work_branch() -> TestResult {
            use bitcoin_rs_consensus::primitives::CompactTarget;
            let genesis = genesis_header();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let main1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let main1_id = tree.insert_node(Some(genesis_id), main1, NodeStatus::HeaderValid)?;
            let main2 = regtest_fixture::mined_regtest_header(main1.compute_hash(), 2)
                .or_fail("regtest fixture header");
            let main2_id = tree.insert_node(Some(main1_id), main2, NodeStatus::HeaderValid)?;
            let applied = {
                let node = tree.node(main2_id)?;
                TipSnapshot {
                    tip_id: main2_id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                }
            };

            let mut high_work = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)
                .or_fail("regtest fixture header");
            high_work.bits = CompactTarget::from_consensus(0x2000_ffff);
            high_work.nonce = 0;
            regtest_fixture::mine_header_to_declared_target(&mut high_work)
                .or_fail("regtest fixture grind");
            let high_work_id =
                tree.insert_node(Some(genesis_id), high_work, NodeStatus::HeaderValid)?;
            let winning = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing higher-work tip"))?;
            assert_eq!(winning.tip_id, high_work_id);
            assert!(winning.height < applied.height);
            assert!(winning.chainwork > applied.chainwork);

            let SyncHarness {
                sync,
                applied_tip,
                inbound_headers_tx: _inbound_headers_tx,
                inbound_blocks_tx: _inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            applied_tip.store(Some(Arc::new(applied)));

            assert_eq!(sync.outweighed_branch_target(), Some(high_work_id));
            Ok(())
        }

        #[test]
        fn retarget_runs_before_the_peer_budget_truncates() -> TestResult {
            const LOSING_LEN: usize = 4;
            let genesis = genesis_header();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let snapshot = |tree: &BlockTree, tip_id| -> Result<TipSnapshot, TestError> {
                let node = tree.node(tip_id)?;
                Ok(TipSnapshot {
                    tip_id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                    chain_tx_count: node.chain_tx_count,
                })
            };
            let genesis_tip = snapshot(&tree, genesis_id)?;

            let mut losing_tip_id = genesis_id;
            let mut prev_hash = genesis.compute_hash();
            for index in 0..LOSING_LEN {
                let header =
                    regtest_fixture::mined_regtest_header(prev_hash, u32::try_from(index + 1)?)?;
                losing_tip_id =
                    tree.insert_node(Some(losing_tip_id), header, NodeStatus::HeaderValid)?;
                prev_hash = header.compute_hash();
            }
            let losing_tip = snapshot(&tree, losing_tip_id)?;

            let winning_header =
                regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)?;
            let winning_id =
                tree.insert_node(Some(genesis_id), winning_header, NodeStatus::HeaderValid)?;
            let winning_tip = snapshot(&tree, winning_id)?;

            let chain_tip = Arc::new(ArcSwapOption::empty());
            chain_tip.store(Some(Arc::new(losing_tip)));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            applied_tip.store(Some(Arc::new(genesis_tip)));
            let block_tree = Arc::new(RwLock::new(tree));
            let peers = Arc::new(PeerTable::new());
            let (_inbound_headers_tx, inbound_headers_rx) = unbounded::<InboundHeaders>();
            let (_inbound_blocks_tx, inbound_blocks_rx) =
                unbounded::<bitcoin_rs_wire::InboundBlock>();
            let sync = BlockSync::new(
                std::sync::Arc::new(TestChain::new(
                    Arc::clone(&chain_tip),
                    Arc::clone(&applied_tip),
                    block_tree,
                )),
                Arc::clone(&peers),
                inbound_headers_rx,
                inbound_blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            );
            sync.install_budget(crate::p2p::sync::SyncBudget {
                max_pending_blocks: LOSING_LEN,
                ..crate::p2p::sync::default_sync_budget(Network::Regtest)
            });
            let peer = PeerRemote::from(([127, 0, 0, 1], 18_462));
            let _rx = connect_peer(&peers, synthetic_peer(peer, 100));
            let source = current_source(&sync.peer_table, peer);
            assert!(
                sync.send_getdata_for_pending_blocks(source, 100, &test_frontier(&sync))
                    .sent
            );
            assert_eq!(sync.scheduler.lock().window.pending_len(), LOSING_LEN);

            chain_tip.store(Some(Arc::new(winning_tip)));
            let now = Instant::now();
            let frontier = sync.observe_frontier(test_frontier(&sync), now);
            let selection = sync.sync_peer_selection(&frontier, now);
            let scheduler = sync.scheduler.lock();
            assert_eq!(
                scheduler.window.pending_len(),
                0,
                "peer selection must purge the losing branch before measuring capacity"
            );
            drop(scheduler);
            assert!(
                !selection.request_peers.is_empty(),
                "freed capacity must leave a request peer this tick, not wait out the pending timeout"
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod tip_alignment {
        use super::*;

        #[test]
        fn tick_skips_getheaders_when_header_tip_matches_peer_height() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
            let applied_snapshot = {
                let tree = block_tree.read();
                let chain_tip = sync
                    .chain
                    .chain_tip()
                    .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
                let node_id = tree
                    .node_at_height_from(chain_tip.tip_id, 1)
                    .ok_or_else(|| std::io::Error::other("missing height one node"))?;
                let node = tree.node(node_id)?;
                TipSnapshot {
                    tip_id: node_id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                }
            };
            applied_tip.store(Some(Arc::new(applied_snapshot)));
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 3));

            sync.tick();

            let first = rx.try_recv()?;
            let Message::GetData(inventory) = first else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(witness_block_inventory(inventory)?, expected[1..]);
            assert!(rx.try_recv().is_err());
            Ok(())
        }
    }

    #[cfg(test)]
    mod header_rotation {
        use super::*;

        #[test]
        fn invalid_nbits_headers_disconnect_source_and_rotate_getheaders() -> TestResult {
            let HeaderSyncFixture {
                genesis,
                sync,
                inbound_headers_tx,
                peers,
            } = header_sync_with_genesis()?;
            let invalid_peer = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let other_peer = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8334,
            ));
            let (invalid_tx, invalid_rx) = bitcoin_rs_wire::test_support::message_channel();
            let (other_tx, other_rx) = bitcoin_rs_wire::test_support::message_channel();

            let invalid_lease = bitcoin_rs_wire::PeerLease::new(invalid_tx);
            peers.register(invalid_peer, invalid_lease.clone());
            peers.publish_info(
                invalid_peer,
                &invalid_lease,
                synthetic_peer(invalid_peer, 9),
            );

            sync.tick();
            assert!(
                matches!(invalid_rx.try_recv()?, Message::GetHeaders(_)),
                "the first getheaders must target the invalid peer"
            );
            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(|request| request.source.endpoint == invalid_peer.endpoint()),
                "a pending getheaders must name the invalid peer before its batch arrives"
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
                source: Some(current_source(&peers, invalid_peer)),

                wire_response: false,
            })?;
            sync.tick();

            assert!(
                sync.scheduler.lock().header_request().is_none(),
                "an attributed invalid-header fault must release the pending header request"
            );
            assert!(
                !peers.is_connected(invalid_peer),
                "invalid header source must be removed from peer selection"
            );
            assert!(
                !peers.is_connected(invalid_peer),
                "invalid header source must lose its outbound lease"
            );

            let other_lease = bitcoin_rs_wire::PeerLease::new(other_tx);
            peers.register(other_peer, other_lease.clone());
            peers.publish_info(other_peer, &other_lease, synthetic_peer(other_peer, 8));
            sync.tick();
            assert!(
                peers.is_connected(other_peer),
                "healthy peer must remain eligible for rotation"
            );
            assert!(
                peers.is_connected(other_peer),
                "healthy peer must retain its outbound lease"
            );
            assert!(
                invalid_rx.try_recv().is_err(),
                "the invalid peer must not receive another getheaders"
            );
            assert!(
                matches!(other_rx.try_recv()?, Message::GetHeaders(_)),
                "the next getheaders must rotate to the remaining peer"
            );
            Ok(())
        }

        #[test]
        fn unattributed_invalid_headers_do_not_disconnect_any_peer() -> TestResult {
            let HeaderSyncFixture {
                genesis,
                sync,
                inbound_headers_tx,
                peers,
            } = header_sync_with_genesis()?;
            let peer_addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let _rx = connect_peer(&peers, synthetic_peer(peer_addr, 8));
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
                source: None,

                wire_response: true,
            })?;

            sync.tick();

            assert!(
                peers.is_connected(peer_addr),
                "local injection must not identify an arbitrary peer as faulty"
            );
            assert!(
                peers.is_connected(peer_addr),
                "local injection must preserve peer outbound leases"
            );
            Ok(())
        }

        #[test]
        fn disconnected_outbound_channel_does_not_mark_blocks_pending() -> TestResult {
            let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            register_info(&peers, synthetic_peer(addr, 100));
            let (tx, rx) = bitcoin_rs_wire::test_support::message_channel();
            drop(rx);
            peers.register(addr, bitcoin_rs_wire::PeerLease::new(tx));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            assert_eq!(sync.scheduler.lock().window.pending_len(), 0);
            Ok(())
        }

        #[test]
        fn tick_fanout_distributes_window_front_first_across_eligible_peers() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            let mut rxs = Vec::new();
            for idx in 0..super::super::MIN_PEERS_FOR_FANOUT {
                let addr = test_addr(9001, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 300 - i32::try_from(idx)?),
                ));
            }

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let cap = super::super::PENDING_BUDGET
                .div_ceil(super::super::MIN_PEERS_FOR_FANOUT)
                .clamp(
                    super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
                    super::super::PEER_INFLIGHT_BUDGET,
                );
            for (idx, rx) in rxs.iter().enumerate() {
                let Message::GetData(inventory) = rx.try_recv()? else {
                    return Err(
                        std::io::Error::other("expected getdata for every eligible peer").into(),
                    );
                };
                assert_eq!(
                    witness_block_inventory(inventory)?,
                    expected[idx * cap..(idx + 1) * cap]
                );
                if idx == 0 {
                    if !matches!(rx.try_recv()?, Message::GetHeaders(_)) {
                        return Err(
                            std::io::Error::other("expected getheaders for header peer").into()
                        );
                    }
                }
                assert!(rx.try_recv().is_err(), "no peer may exceed the fan-out cap");
            }
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                super::super::PENDING_BUDGET,
                "fan-out must fill the deep window"
            );
            Ok(())
        }

        #[test]
        fn wedged_window_expires_stalled_front_and_rerequests_through_count_clamp() -> TestResult {
            let (sync, _peers, expected, rxs, _blocks_tx) =
                staged_count_wedge(wedge_budget(Duration::from_millis(250)))?;

            sync.tick();
            assert_eq!(sync.scheduler.lock().window.pending_len(), 2);

            sync.scheduler
                .lock()
                .window
                .backdate_stall_for_test(Duration::from_millis(500));
            sync.tick();

            assert_no_getdata(&rxs[0])?;
            let mut rerequested = Vec::new();
            for rx in &rxs[1..] {
                while let Ok(message) = rx.try_recv() {
                    if let Message::GetData(inventory) = message {
                        rerequested.extend(witness_block_inventory(inventory)?);
                    }
                }
            }
            assert_eq!(
                rerequested,
                expected[..2],
                "the stalled front stripe must be re-requested from a healthy peer"
            );
            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                14,
                "staged progress must survive the wedge"
            );
            {
                let scheduler = sync.scheduler.lock();
                let window = &scheduler.window;
                assert_eq!(window.pending_len(), 2);
                for front in &expected[..2] {
                    assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
                }
            }
            Ok(())
        }

        #[test]
        fn common_prefix_winner_takes_over_deep_window() -> TestResult {
            let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(16)?;
            let owner = test_addr(9321, 0)?;
            let alternate = test_addr(9321, 1)?;
            let owner_rx = connect_peer(&peers, synthetic_peer(owner, 200));
            let alternate_rx = connect_peer(&peers, synthetic_peer(alternate, 100));

            sync.tick();
            assert_eq!(
                witness_block_inventory(next_getdata(&owner_rx)?)?,
                blocks.iter().map(Block::block_hash).collect::<Vec<_>>()
            );
            assert_eq!(
                witness_block_inventory(next_getdata(&alternate_rx)?)?,
                blocks[..8]
                    .iter()
                    .map(Block::block_hash)
                    .collect::<Vec<_>>()
            );

            for block in &blocks[..4] {
                let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                inbound.source = Some(current_source(&peers, alternate));
                blocks_tx.send(inbound)?;
            }
            sync.tick();

            assert_eq!(
                sync.scheduler.lock().window.preferred_peer(),
                Some(current_source(&peers, alternate))
            );
            assert!(sync.scheduler.lock().window.peer_in_staller_cooldown(
                bitcoin_rs_wire::PeerSource::for_test(owner),
                Instant::now()
            ));
            assert_eq!(
                witness_block_inventory(next_getdata(&alternate_rx)?)?,
                blocks[4..]
                    .iter()
                    .map(Block::block_hash)
                    .collect::<Vec<_>>()
            );
            assert!(peers.is_connected(owner));
            sync.scheduler.lock().window.mark_peer_unresponsive(
                bitcoin_rs_wire::PeerSource::for_test(alternate),
                Instant::now(),
            );
            sync.tick();
            assert_eq!(
                sync.scheduler.lock().window.preferred_peer(),
                Some(current_source(&peers, alternate)),
                "a temporary soft block skips the winner without erasing its election"
            );
            Ok(())
        }

        #[test]
        fn same_address_reconnect_does_not_inherit_stalled_inflight() -> TestResult {
            let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(16)?;
            let owner = test_addr(9322, 0)?;
            let winner = test_addr(9322, 1)?;
            let owner_rx = connect_peer(&peers, synthetic_peer(owner, 200));
            let winner_rx = connect_peer(&peers, synthetic_peer(winner, 100));
            sync.tick();
            let _ = next_getdata(&owner_rx)?;
            let _ = next_getdata(&winner_rx)?;
            let predecessor = current_source(&peers, winner);
            for block in &blocks[..4] {
                let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                inbound.source = Some(predecessor);
                blocks_tx.send(inbound)?;
            }
            sync.tick();
            let _ = next_getdata(&winner_rx)?;
            let pending_owner = |hash: &BlockHash| {
                sync.scheduler
                    .lock()
                    .window
                    .pending_owner(&Hash256::from_le_bytes(hash.as_bytes()))
            };
            assert!(sync.scheduler.lock().window.preferred_peer().is_some());
            assert!(
                blocks[4..]
                    .iter()
                    .any(|block| pending_owner(&block.block_hash()) == Some(predecessor)),
                "the elected winner must hold the deep window in flight"
            );

            let (replacement_tx, replacement_rx) = bitcoin_rs_wire::test_support::message_channel();
            let lease = PeerLease::new(replacement_tx);
            peers.register(winner, lease.clone());
            peers.publish_info(winner, &lease, synthetic_peer(winner, 100));
            let replacement = lease.source(winner.endpoint());
            sync.on_peer_ready(replacement);
            assert!(
                sync.scheduler.lock().window.preferred_peer().is_none(),
                "the dead connection's election must not pass to its replacement"
            );
            sync.tick();

            let rerequested = witness_block_inventory(next_getdata(&replacement_rx)?)?;
            assert_ne!(rerequested, []);
            for hash in &rerequested {
                assert_eq!(pending_owner(hash), Some(replacement));
            }

            sync.on_peer_ready(replacement);
            for hash in &rerequested {
                assert_eq!(
                    pending_owner(hash),
                    Some(replacement),
                    "readiness must not release the replacement's own in-flight work"
                );
            }
            sync.tick();
            for hash in &rerequested {
                assert_eq!(pending_owner(hash), Some(replacement));
            }
            Ok(())
        }

        #[test]
        fn stall_eviction_does_not_disconnect_replacement_connection() -> TestResult {
            let budget = super::super::SyncBudget {
                stall_timeout_initial: Duration::from_millis(100),
                ..wedge_budget(Duration::from_mins(1))
            };
            let (sync, peers, _expected, _rxs, _blocks_tx) = staged_count_wedge(budget)?;
            let staller = test_addr(9320, 0)?;
            sync.scheduler
                .lock()
                .window
                .seed_front_cadence_for_test(50, Instant::now());

            sync.tick();
            let frontier = sync.observe_chain_frontier();
            let next_apply_height = frontier
                .next_required
                .as_ref()
                .map(|required| required.height);
            let frontier_hash = frontier
                .next_required
                .as_ref()
                .map(|required| required.hash);
            let selected = {
                let tree = sync.chain.block_tree();
                let mut scheduler = sync.scheduler.lock();
                let state = &mut *scheduler;
                match state.window.observe_blocked(
                    crate::p2p::download_window::BlockedContext {
                        next_apply_height,
                        frontier_hash,
                        apply_side_busy: frontier_hash
                            .is_some_and(|hash| state.stager.contains(&hash)),
                    },
                    &state.stager,
                    &tree,
                    Instant::now() + Duration::from_millis(150),
                ) {
                    crate::p2p::download_window::BlockedDecision::Blame {
                        owner,
                        reason: crate::p2p::download_window::BlameReason::Staller,
                    } => Some(owner),
                    _ => None,
                }
            };
            let (replacement_tx, _replacement_rx) =
                bitcoin_rs_wire::test_support::message_channel();
            let replacement = PeerLease::new(replacement_tx);
            peers.register(staller, replacement.clone());
            peers.publish_info(staller, &replacement, synthetic_peer(staller, 200));
            let evicted = selected.is_some_and(|owner| sync.peer_table.disconnect_source(owner));

            assert!(selected.is_some());
            assert!(!evicted);
            assert!(peers.is_connected(staller));
            assert!(!replacement.is_cancelled());
            Ok(())
        }

        #[test]
        fn byte_wedged_window_recovers_via_staller_disconnect_before_received_timeout() -> TestResult
        {
            let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(2)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_bytes: 256 * 1024 + consensus_bytes(&blocks[1]).len(),
                    max_received_blocks: 2,
                    getdata_batch_limit: 2,
                    stall_timeout_initial: Duration::from_millis(100),
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let staller = test_addr(9430, 0)?;
            let honest = test_addr(9430, 1)?;
            let staller_rx = connect_peer(&peers, synthetic_peer(staller, 200));
            let honest_rx = connect_peer(&peers, synthetic_peer(honest, 100));

            sync.scheduler
                .lock()
                .window
                .seed_front_cadence_for_test(50, Instant::now());

            sync.tick();
            let Message::GetData(inventory) = staller_rx.try_recv()? else {
                return Err(std::io::Error::other("expected staller getdata").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                std::vec![blocks[0].block_hash(), blocks[1].block_hash()]
            );

            blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[1].clone()))?;
            sync.tick();
            {
                let scheduler = sync.scheduler.lock();
                assert!(!scheduler.window.has_request_capacity(&scheduler.stager));
                assert_eq!(
                    scheduler.window.stalling_peer().map(|(addr, _)| addr),
                    Some(staller.endpoint())
                );
            }
            assert!(honest_rx.try_recv().is_err());

            sync.scheduler
                .lock()
                .window
                .backdate_stall_for_test(Duration::from_millis(500));
            sync.tick();
            assert!(!peers.is_connected(staller));
            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                1,
                "recovery must not discard staged progress (prune-free)"
            );
            let Message::GetData(retry) = honest_rx.try_recv()? else {
                return Err(std::io::Error::other("expected honest peer front retry").into());
            };
            assert_eq!(
                witness_block_inventory(retry)?,
                std::vec![blocks[0].block_hash()]
            );

            blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            sync.tick();
            let applied_height = applied_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
                .height;
            assert_eq!(applied_height, 2, "the byte wedge must fully recover");
            Ok(())
        }
    }

    #[cfg(test)]
    mod trickle_peers {
        use super::*;

        #[test]
        fn slow_trickle_front_peer_observable_but_never_disconnected() -> TestResult {
            let recorder = TestRecorder::default();
            metrics::with_local_recorder(&recorder, || {
                let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(6)?;
                install_budget(
                    &sync,
                    super::super::SyncBudget {
                        max_pending_blocks: 3,
                        max_received_blocks: 3,
                        max_peer_inflight: 3,
                        getdata_batch_limit: 3,
                        ..super::super::default_sync_budget(Network::Regtest)
                    },
                );
                let trickler = test_addr(9440, 0)?;
                let rx = connect_peer(&peers, synthetic_peer(trickler, 100));

                for round in 0..2_usize {
                    let offset = round * 3;
                    sync.tick();
                    let inventory = next_getdata(&rx)?;
                    assert_eq!(inventory.len(), 3);
                    blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                        blocks[offset + 1].clone(),
                    ))?;
                    blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                        blocks[offset + 2].clone(),
                    ))?;
                    sync.tick();
                    assert_eq!(
                        sync.scheduler
                            .lock()
                            .window
                            .stalling_peer()
                            .map(|(addr, _)| addr),
                        Some(trickler.endpoint()),
                        "the stall episode must be observable while the front trickles"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                    sync.tick();
                    assert!(peers.is_connected(trickler));
                    match recorder.snapshot().get("node.sync.stall_seconds") {
                        Some(TestMetric::Gauge(seconds)) => {
                            assert!(
                                *seconds > 0.0,
                                "stall age must be exported while an episode runs"
                            );
                        }
                        value => panic!("stall_seconds gauge missing or wrong type: {value:?}"),
                    }
                    blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                        blocks[offset].clone(),
                    ))?;
                    sync.tick();
                    assert!(sync.scheduler.lock().window.stalling_peer().is_none());
                    assert_eq!(
                        sync.scheduler.lock().window.stall_timeout(),
                        super::super::BLOCK_STALLING_TIMEOUT,
                        "front progress must keep the adaptive threshold at its floor"
                    );
                }

                let applied_height = applied_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
                    .height;
                assert_eq!(applied_height, 6);
                assert!(
                    peers.is_connected(trickler),
                    "a trickler under the threshold must never be disconnected"
                );
                assert!(
                    !recorder
                        .snapshot()
                        .contains_key("node.sync.staller_disconnects"),
                    "no staller disconnect may fire for an under-threshold trickler"
                );
                Ok(())
            })
        }

        #[test]
        fn uniform_slow_saturated_fanout_disconnects_no_peer_and_completes() -> TestResult {
            let recorder = TestRecorder::default();
            metrics::with_local_recorder(&recorder, || {
                let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(32)?;
                install_budget(
                    &sync,
                    super::super::SyncBudget {
                        max_pending_blocks: 24,
                        max_pending_bytes: usize::MAX,
                        max_received_blocks: 24,
                        max_received_bytes: usize::MAX,
                        max_peer_inflight: 24,
                        fanout_peer_inflight: 3,
                        min_peers_for_fanout: 8,
                        getdata_batch_limit: 24,
                        stall_timeout_initial: Duration::from_millis(100),
                        ..super::super::default_sync_budget(Network::Regtest)
                    },
                );
                let mut rxs = Vec::new();
                let mut sources = Vec::new();
                for idx in 0..8_usize {
                    let addr = test_addr(9470, idx)?;
                    rxs.push(connect_peer(
                        &peers,
                        synthetic_peer(addr, 200 - i32::try_from(idx)?),
                    ));
                    sources.push(current_source(&peers, addr));
                }

                sync.tick();
                let mut stripes = Vec::new();
                for rx in &rxs {
                    let stripe = witness_block_inventory(next_getdata(rx)?)?;
                    assert_eq!(stripe.len(), 3, "each peer must own a 3-block stripe");
                    stripes.push(stripe);
                }
                let by_hash: HashMap<BlockHash, Block> = blocks
                    .iter()
                    .map(|block| (block.block_hash(), block.clone()))
                    .collect();

                for round in 0..3_usize {
                    if round == 2 {
                        std::thread::sleep(Duration::from_millis(5));
                        sync.tick();
                        std::thread::sleep(Duration::from_millis(120));
                        sync.tick();
                        assert_eq!(
                            peers.len(),
                            8,
                            "a mid-gap wake must not disconnect a streaming peer"
                        );
                        std::thread::sleep(Duration::from_millis(25));
                    } else {
                        std::thread::sleep(Duration::from_millis(150));
                    }
                    for (idx, stripe) in stripes.iter().enumerate() {
                        let block = by_hash
                            .get(&stripe[round])
                            .ok_or_else(|| std::io::Error::other("unknown getdata hash"))?;
                        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                        inbound.source = Some(sources[idx]);
                        blocks_tx.send(inbound)?;
                    }
                    sync.tick();
                    assert_eq!(
                        peers.len(),
                        8,
                        "no streaming peer may be disconnected (round {round})"
                    );
                }
                let mut tail = blocks[24..].iter();
                for _ in 0..40_usize {
                    let applied = applied_tip.load_full().map_or(0, |tip| tip.height);
                    if applied == 32 {
                        break;
                    }
                    if let Some(block) = tail.next() {
                        blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))?;
                    }
                    sync.tick();
                }

                let applied_height = applied_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
                    .height;
                assert_eq!(applied_height, 32, "uniform-slow sync must complete");
                assert_eq!(peers.len(), 8);
                assert!(
                    !recorder
                        .snapshot()
                        .contains_key("node.sync.staller_disconnects"),
                    "zero staller fires in the uniform-slow regime"
                );
                Ok(())
            })
        }

        #[test]
        fn single_peer_can_fill_default_pending_window() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 300));

            let mut requested = Vec::new();
            let ticks = super::super::PENDING_BUDGET / super::super::GETDATA_BATCH_SIZE;
            assert_eq!(
                ticks, 1,
                "default getdata batch should fill the pending window in one tick"
            );
            for tick in 0..ticks {
                sync.tick();
                if tick == 0 {
                    assert_applied_genesis(&applied_tip, &block_tree)?;
                }
                let Message::GetData(inventory) = rx.try_recv()? else {
                    return Err(std::io::Error::other("expected getdata").into());
                };
                requested.extend(witness_block_inventory(inventory)?);
                let _headers = rx.try_recv()?;
            }

            assert_eq!(requested, expected);
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                super::super::PENDING_BUDGET
            );
            Ok(())
        }

        #[test]
        fn tick_preserves_partial_window_order_across_pending_gap() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(5)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 4,
                    max_pending_bytes: 4 * 256 * 1024,
                    max_peer_inflight: 4,
                    getdata_batch_limit: 4,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 100));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(first) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected first getdata").into());
            };
            assert_eq!(witness_block_inventory(first)?, expected[..4]);
            let _headers = rx.try_recv()?;
            apply_fixture_block(&sync, header_chain_block(&expected, 1)?)?;
            {
                let mut scheduler = sync.scheduler.lock();
                let window = &mut scheduler.window;
                window.requeue_for_retry(
                    &Hash256::from_le_bytes(expected[1].as_bytes()),
                    Some(2),
                    Instant::now(),
                );
            }

            sync.tick();

            let Message::GetData(second) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected gap-filling getdata").into());
            };
            assert_eq!(
                witness_block_inventory(second)?,
                vec![expected[1], expected[4]]
            );
            assert_eq!(sync.scheduler.lock().window.pending_len(), 4);
            Ok(())
        }
    }

    #[cfg(test)]
    mod window_recovery {
        use super::*;

        #[test]
        fn apply_cache_invalidated_on_chain_tip_move() -> TestResult {
            let fixture = apply_cache_fixture(4, 0)?;
            install_budget(
                &fixture.sync,
                super::super::SyncBudget {
                    max_pending_blocks: 4,
                    max_pending_bytes: usize::MAX,
                    max_received_blocks: 64,
                    max_received_bytes: usize::MAX,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );

            stage_body(&fixture.sync, &fixture.blocks[0]);
            let (applied, _failed) = fixture.sync.apply_buffered_blocks(None);
            assert_eq!(applied, 1);
            let cache = cache_snapshot(&fixture.sync)
                .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
            let original_chain_tip_hash = cache.chain_tip_hash;
            assert_eq!(cache.offset, 1);

            let moved_tip = {
                let current = fixture
                    .chain_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
                let mut hash_bytes = current.hash.to_le_bytes();
                hash_bytes[0] ^= 0xff;
                TipSnapshot {
                    tip_id: current.tip_id,
                    chain_tx_count: current.chain_tx_count,
                    height: current.height,
                    chainwork: current.chainwork,
                    hash: Hash256::from_le_bytes(&hash_bytes),
                }
            };
            fixture.chain_tip.store(Some(Arc::new(moved_tip)));
            assert_ne!(
                fixture
                    .chain_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("missing chain tip"))?
                    .hash,
                original_chain_tip_hash,
                "chain tip must move for this test to be meaningful"
            );

            assert!(
                fixture.sync.drain_cached_expected_blocks(1).is_none(),
                "stale cache keyed to the old chain tip must not serve a drain"
            );

            stage_body(&fixture.sync, &fixture.blocks[1]);
            let _ = fixture.sync.apply_buffered_blocks(None);
            let after = cache_snapshot(&fixture.sync)
                .ok_or_else(|| std::io::Error::other("miss did not repopulate apply cache"))?;
            assert_ne!(
                after.chain_tip_hash, original_chain_tip_hash,
                "repopulated cache must be keyed to the moved tip"
            );
            Ok(())
        }

        #[test]
        fn window_failure_applies_prefix_and_restores_suffix() -> TestResult {
            let fixture = apply_cache_fixture(4, 0)?;

            let mut corrupted = fixture.blocks[1].clone();
            corrupted.txs.push(regtest_fixture::coinbase(99));
            assert_eq!(
                corrupted.block_hash(),
                fixture.blocks[1].block_hash(),
                "corruption must not move the header hash or the drain never sees it"
            );

            stage_body(&fixture.sync, &fixture.blocks[0]);
            stage_body(&fixture.sync, &corrupted);
            stage_body(&fixture.sync, &fixture.blocks[2]);
            stage_body(&fixture.sync, &fixture.blocks[3]);

            let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
            assert_eq!(
                (applied, failed),
                (1, 1),
                "only the block before the corrupt one commits"
            );
            assert_eq!(
                fixture.applied_tip.load_full().map(|tip| tip.height),
                Some(1),
                "the chain stops at the last good block"
            );

            let restored = fixture.sync.scheduler.lock().stager.received_len();
            assert_eq!(
                restored, 0,
                "invalidated blocks and their descendants are purged, not restored"
            );
            Ok(())
        }

        #[test]
        fn restore_split_pins_off_by_one() {
            assert_eq!(super::super::restore_split(2, 2, 2), 4);
            assert_eq!(super::super::restore_split(2, 1, 2), 4);
            assert_eq!(super::super::restore_split(0, 0, 0), 0);
        }

        #[test]
        fn mutated_window_moves_the_uncommitted_tail_back_without_copying_decoded_blocks()
        -> TestResult {
            let fixture = apply_cache_fixture(4, 0)?;
            let mut mutated = fixture.blocks[1].clone();
            mutated.txs[0].outputs[0].value = bitcoin_rs_consensus::primitives::Amount::from_sat(1);
            stage_body(&fixture.sync, &fixture.blocks[0]);
            stage_body(&fixture.sync, &mutated);

            let payload = BlockImage::from_local(fixture.blocks[2].clone());
            let bytes_ptr = payload.bytes().as_ptr();
            let script_ptr = payload.tx(0).input_script_sig(0).as_ptr();
            let hash = payload.block_hash().0;
            fixture
                .sync
                .scheduler
                .lock()
                .stager
                .insert(hash, None, payload, None, Instant::now());
            stage_body(&fixture.sync, &fixture.blocks[3]);

            assert_eq!(fixture.sync.apply_buffered_blocks(None), (1, 1));
            assert_eq!(
                fixture.applied_tip.load_full().map(|tip| tip.height),
                Some(1)
            );
            let hashes = [hash, fixture.blocks[3].block_hash().0];
            let restored = fixture
                .sync
                .scheduler
                .lock()
                .stager
                .drain_expected_prefix(&hashes);
            assert_eq!(restored.len(), 2);
            assert_eq!(restored[0].payload().bytes().as_ptr(), bytes_ptr);
            assert_eq!(
                restored[0].payload().tx(0).input_script_sig(0).as_ptr(),
                script_ptr
            );
            assert_eq!(
                restored[0].payload().bytes().as_ref(),
                consensus_bytes(&fixture.blocks[2])
            );
            fixture.sync.scheduler.lock().stager.restore_many(restored);

            stage_body(&fixture.sync, &fixture.blocks[1]);
            assert_eq!(fixture.sync.apply_buffered_blocks(None), (3, 0));
            assert_eq!(
                fixture.applied_tip.load_full().map(|tip| tip.height),
                Some(4)
            );
            assert_eq!(
                fixture
                    .sync
                    .scheduler
                    .lock()
                    .stager
                    .retained_attributed_bytes(),
                0
            );
            Ok(())
        }

        #[test]
        fn peer_disconnect_mid_window_requeues_blocks_to_remaining_peers() -> TestResult {
            const PEER_COUNT: usize = 9;
            const SELECTED_PEERS: usize = super::super::MIN_PEERS_FOR_FANOUT;
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
            install_budget(&sync, super::super::default_sync_budget(Network::Regtest));
            let mut receivers = Vec::new();
            let mut addrs = Vec::new();
            for idx in 0..PEER_COUNT {
                let addr = test_addr(9506, idx)?;
                addrs.push(addr);
                receivers.push(connect_peer(
                    &peers,
                    synthetic_peer(addr, 300 - i32::try_from(idx)?),
                ));
            }
            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            let cap = super::super::PENDING_BUDGET.div_ceil(PEER_COUNT).clamp(
                super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
                super::super::PEER_INFLIGHT_BUDGET,
            );
            for (idx, receiver) in receivers[..SELECTED_PEERS].iter().enumerate() {
                let Message::GetData(inventory) = receiver.try_recv()? else {
                    return Err(std::io::Error::other("expected initial stripe").into());
                };
                assert_eq!(
                    witness_block_inventory(inventory)?,
                    expected[idx * cap..(idx + 1) * cap]
                );
            }
            let _ = receivers[0].try_recv()?;
            let Message::GetData(remainder) = receivers[SELECTED_PEERS].try_recv()? else {
                return Err(
                    std::io::Error::other("expected remainder getdata for spare peer").into(),
                );
            };
            assert_eq!(
                witness_block_inventory(remainder)?,
                expected[SELECTED_PEERS * cap..]
            );
            let dropped = addrs[1];
            peers.disconnect(dropped);
            sync.tick();
            let Message::GetData(inventory) = receivers[SELECTED_PEERS].try_recv()? else {
                return Err(std::io::Error::other("expected requeued getdata").into());
            };
            let mut requeued = witness_block_inventory(inventory)?;
            for (idx, rx) in receivers.iter().enumerate() {
                if idx == 1 || idx == SELECTED_PEERS {
                    continue;
                }
                requeued.extend(witness_block_inventory(next_getdata(rx)?)?);
            }
            requeued.sort();
            let mut freed = expected[cap..2 * cap].to_vec();
            freed.sort();
            assert_eq!(requeued, freed, "every freed block must be re-requested");
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                super::super::PENDING_BUDGET
            );
            Ok(())
        }

        #[test]
        fn same_address_registration_after_window_eviction_keeps_replacement() -> TestResult {
            let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
            let addr = test_addr(9508, 0)?;
            let (old_tx, old_rx) = bitcoin_rs_wire::test_support::message_channel();
            let old = PeerLease::new(old_tx);
            peers.register(addr, old.clone());
            peers.publish_info(addr, &old, synthetic_peer(addr, 100));
            sync.tick();
            let _ = old_rx.try_recv()?;
            let _ = old_rx.try_recv()?;
            let (new_tx, new_rx) = bitcoin_rs_wire::test_support::message_channel();
            let new = PeerLease::new(new_tx);
            peers.register(addr, new.clone());
            peers.publish_info(addr, &new, synthetic_peer(addr, 100));
            sync.tick();
            assert!(peers.is_current(new.source(addr.endpoint())));
            assert!(old.is_cancelled());
            assert!(peers.is_connected(addr));
            assert!(new_rx.try_recv().is_ok());
            Ok(())
        }

        #[test]
        fn reconcile_forgets_window_state_only_when_connection_identity_changes() -> TestResult {
            let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let addr = test_addr(9509, 0)?;
            let (tx, _rx) = bitcoin_rs_wire::test_support::message_channel();
            let lease = PeerLease::new(tx);
            peers.register(addr, lease.clone());
            peers.publish_info(addr, &lease, synthetic_peer(addr, 8));
            sync.tick();
            assert!(sync.scheduler.lock().header_request().is_some());

            assert!(!peers.register(addr, lease));
            sync.reconcile_peer_sessions();
            assert!(sync.scheduler.lock().header_request().is_some());

            let (new_tx, _new_rx) = bitcoin_rs_wire::test_support::message_channel();
            let replacement = PeerLease::new(new_tx);
            peers.register(addr, replacement.clone());
            peers.publish_info(addr, &replacement, synthetic_peer(addr, 8));
            sync.reconcile_peer_sessions();
            assert!(sync.scheduler.lock().header_request().is_none());
            assert!(sync.scheduler.lock().headers_sync.is_empty());
            Ok(())
        }
    }

    #[cfg(test)]
    mod peer_qualification {
        use super::*;

        #[test]
        fn non_witness_peer_not_counted_toward_fanout_threshold() -> TestResult {
            let ineligible = PeerInfo {
                services: 1,
                ..synthetic_peer(test_addr(9210, 0)?, 300)
            };
            assert_fallback_refused_to_candidate(ineligible)
        }

        #[test]
        fn far_behind_duplicate_of_applied_block_is_not_staged() -> TestResult {
            let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(64)?;
            let peer = test_addr(9321, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 100));

            sync.tick();
            let requested = next_getdata(&rx)?;
            assert_eq!(
                witness_block_inventory(requested)?,
                blocks.iter().map(Block::block_hash).collect::<Vec<_>>()
            );
            for block in &blocks {
                blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))?;
            }
            sync.tick();
            assert_eq!(
                applied_tip
                    .load_full()
                    .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
                    .height,
                64
            );
            let stale_hash = Hash256::from_le_bytes(blocks[0].block_hash().as_bytes());
            assert!(
                !sync.scheduler.lock().window.contains_pending(&stale_hash),
                "the replay must be unsolicited after its request was applied"
            );

            blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();

            assert!(!sync.scheduler.lock().stager.contains(&stale_hash));
            let scheduler = sync.scheduler.lock();
            let window = &scheduler.window;
            assert_eq!(window.pending_len(), 0);
            assert!(!window.contains_pending(&stale_hash));
            Ok(())
        }

        #[test]
        fn received_only_state_uses_scan_path_without_duplicate_request() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
            let (_, blocks) = mined_chain(3, 0)?;
            stage_body(&sync, &blocks[1]);
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8333,
            ));
            let rx = connect_peer(&peers, synthetic_peer(addr, 3));

            sync.tick();

            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                std::vec![expected[0], expected[2]]
            );
            assert!(rx.try_recv().is_err());
            Ok(())
        }
    }

    #[cfg(test)]
    mod aggregate_saturation {
        use super::*;
        use bitcoin_rs_wire::connection::SharedOutboundBudget;
        use bitcoin_rs_wire::test_support::hog;

        fn connect_on(
            peers: &Arc<PeerTable>,
            aggregate: &Arc<SharedOutboundBudget>,
            info: PeerInfo,
        ) -> (PeerLease, bitcoin_rs_wire::test_support::MessageReceiver) {
            let (queue, receiver) = bitcoin_rs_wire::test_support::message_channel();
            let lease = PeerLease::new(queue).with_shared_budget(aggregate);
            let Some(endpoint) = info.endpoint else {
                panic!("identified peer endpoint");
            };
            peers.register(endpoint, lease.clone());
            peers.publish_info(endpoint, &lease, info);
            (lease, receiver)
        }

        #[test]
        fn getheaders_saturated_no_disconnect() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let harness = SyncHarness::with_ibd(tree, crate::p2p::sync::syncing_ibd_latch());
            let (sync, peers) = (harness.sync, harness.peers);
            let aggregate = Arc::new(SharedOutboundBudget::with_limits(512, 0));
            let hold = hog(&aggregate, 512);
            let addr = test_addr(9_700, 0)?;
            let (lease, rx) = connect_on(&peers, &aggregate, synthetic_peer(addr, 10));
            let source = lease.source(addr.endpoint());
            let locator = || vec![Hash256::from(genesis.compute_hash())];

            assert_eq!(
                sync.send_getheaders(source, 0, 10, locator()),
                super::super::GetheadersOutcome::Failed,
                "the refused request fails this tick only"
            );
            assert!(
                !lease.is_cancelled() && peers.is_current(source),
                "a full aggregate is not a dead connection"
            );
            assert!(rx.is_empty(), "nothing was queued");
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&source)
                    .and_then(|owned| owned.request)
                    .is_none(),
                "nothing was stamped, so the next tick rebuilds the request"
            );

            drop(hold);
            assert_eq!(
                sync.send_getheaders(source, 0, 10, locator()),
                super::super::GetheadersOutcome::Sent
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&source)
                    .is_some_and(|owned| owned.request.is_some()),
                "the sent request is stamped under the connection's identity"
            );
            Ok(())
        }

        #[test]
        fn block_getdata_saturated_marks_nothing_and_is_replanned() -> TestResult {
            let (sync, peers, _block_tree, _applied_tip, expected) =
                sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
            let aggregate = Arc::new(SharedOutboundBudget::with_limits(4_096, 0));
            let hold = hog(&aggregate, 4_096);
            let addr = test_addr(9_701, 0)?;
            let (lease, rx) = connect_on(&peers, &aggregate, synthetic_peer(addr, 286));

            sync.tick();

            assert_no_getdata(&rx)?;
            assert!(
                !lease.is_cancelled() && peers.is_connected(addr),
                "a full aggregate does not disconnect the peer being asked"
            );
            assert_eq!(
                sync.scheduler.lock().window.pending_len(),
                0,
                "a refused request marks no block in flight"
            );

            drop(hold);
            sync.tick();

            assert_eq!(
                witness_block_inventory(next_getdata(&rx)?)?,
                expected,
                "the next tick plans the same request again"
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod witness_staging_gate {
        use super::*;
        use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
        use bitcoin_rs_wire::InboundBlock;

        const WITNESS_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

        const ZERO_RESERVED_COMMITMENT: [u8; 32] = [
            0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69,
            0x53, 0x75, 0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36,
            0x97, 0x4e, 0x8c, 0xf9,
        ];

        fn segwit_coinbase(height: u32, witness: Witness) -> Tx {
            let mut script_sig = regtest_fixture::script_num_push(i64::from(height));
            script_sig.extend_from_slice(&regtest_fixture::script_num_push(1));
            let mut commitment_script = WITNESS_PREFIX.to_vec();
            commitment_script.extend_from_slice(&ZERO_RESERVED_COMMITMENT);
            Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(script_sig),
                    sequence: Sequence::MAX,
                    witness,
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat(1),
                        script_pubkey: Script::new(),
                    },
                    TxOut {
                        value: Amount::from_sat(0),
                        script_pubkey: Script::from_bytes(commitment_script),
                    },
                ],
                lock_time: LockTime::ZERO,
            }
        }

        fn segwit_coinbase_with_witness(height: u32) -> Tx {
            segwit_coinbase(height, Witness::from_stack(vec![vec![0; 32]]))
        }

        fn segwit_coinbase_without_witness(height: u32) -> Tx {
            segwit_coinbase(height, Witness::new())
        }

        fn segwit_block_with_witness(prev_blockhash: BlockHash, height: u32) -> Block {
            regtest_fixture::mined_block_with_prev_hash(
                prev_blockhash,
                height,
                vec![segwit_coinbase_with_witness(height)],
            )
            .or_fail("regtest fixture block")
        }

        fn segwit_block_without_witness(prev_blockhash: BlockHash, height: u32) -> Block {
            regtest_fixture::mined_block_with_prev_hash(
                prev_blockhash,
                height,
                vec![segwit_coinbase_without_witness(height)],
            )
            .or_fail("regtest fixture block")
        }

        type SegwitSyncFixture = (
            BlockSync,
            Hash256,
            Block,
            Block,
            crossbeam_channel::Sender<InboundHeaders>,
        );

        fn segwit_sync_fixture() -> Result<SegwitSyncFixture, TestError> {
            let (tree, _blocks) = mined_chain(0, 0)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let headers_tx = harness.inbound_headers_tx;
            sync.chain.bootstrap_genesis();
            install_budget(&sync, super::super::default_sync_budget(Network::Regtest));

            let genesis = Network::Regtest.genesis_block();
            let prev_hash = genesis.block_hash();

            let correct_block = segwit_block_with_witness(prev_hash, 1);
            let block_hash = Hash256::from_le_bytes(correct_block.block_hash().as_bytes());

            assert!(matches!(
                sync.chain.admit_headers(&[correct_block.header]),
                HeaderAdmission::Accepted { .. }
            ));

            let stripped_block = segwit_block_without_witness(prev_hash, 1);
            assert_eq!(
                stripped_block.block_hash(),
                correct_block.block_hash(),
                "stripped and correct blocks must share the same hash"
            );

            Ok((sync, block_hash, correct_block, stripped_block, headers_tx))
        }

        #[test]
        fn malformed_body_dropped_then_correct_body_staged() -> TestResult {
            let (sync, block_hash, correct_block, stripped_block, _) = segwit_sync_fixture()?;

            let mut batch = vec![InboundBlock::from_local(stripped_block)];
            let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
            assert_eq!(received, 1, "malformed body should be processed (rejected)");
            assert!(
                batch.is_empty(),
                "buffer_received_block_chunk should drain the batch"
            );
            assert!(
                !sync.scheduler.lock().stager.contains(&block_hash),
                "malformed body must not be staged"
            );

            let mut batch = vec![InboundBlock::from_local(correct_block)];
            let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
            assert_eq!(received, 1, "correct body should be processed (staged)");
            assert!(
                sync.scheduler.lock().stager.contains(&block_hash),
                "correct body must be staged after malformed was rejected"
            );

            Ok(())
        }

        #[test]
        fn malformed_pending_owner_is_disconnected_and_other_peer_gets_same_hash() -> TestResult {
            let (sync, block_hash, _correct_block, stripped_block, _) = segwit_sync_fixture()?;
            let peer_a = test_addr(9750, 0)?;
            let peer_b = test_addr(9750, 1)?;
            let rx_a = connect_peer(&sync.peer_table, synthetic_peer(peer_a, 1));
            sync.tick();
            let first = next_getdata(&rx_a)?;
            assert_eq!(witness_block_inventory(first)?, vec![BlockHash(block_hash)]);
            let source_a = current_source(&sync.peer_table, peer_a);
            let rx_b = connect_peer(&sync.peer_table, synthetic_peer(peer_b, 1));

            let mut malformed = InboundBlock::from_local(stripped_block);
            malformed.source = Some(source_a);
            let mut batch = vec![malformed];
            assert_eq!(
                sync.buffer_received_block_chunk(&mut batch, Some(block_hash)),
                1
            );
            assert!(!sync.peer_table.is_current(source_a));
            assert!(sync.scheduler.lock().window.peer_in_staller_cooldown(
                bitcoin_rs_wire::PeerSource::for_test(peer_a),
                std::time::Instant::now()
            ));

            sync.tick();
            assert_eq!(
                witness_block_inventory(next_getdata(&rx_b)?)?,
                vec![BlockHash(block_hash)]
            );
            assert_no_getdata(&rx_a)?;
            Ok(())
        }

        #[test]
        fn altered_non_witness_body_dropped_then_correct_body_staged() -> TestResult {
            let (sync, block_hash, correct_block, _, _) = segwit_sync_fixture()?;
            let mut altered_block = correct_block.clone();
            altered_block.txs[0].outputs[0].value = Amount::from_sat(2);
            assert_eq!(
                Hash256::from_le_bytes(altered_block.block_hash().as_bytes()),
                block_hash,
                "altering body transaction bytes must retain the header-derived hash"
            );

            let mut batch = vec![InboundBlock::from_local(altered_block)];
            assert_eq!(
                sync.buffer_received_block_chunk(&mut batch, Some(block_hash)),
                1
            );
            assert!(!sync.scheduler.lock().stager.contains(&block_hash));

            let mut batch = vec![InboundBlock::from_local(correct_block)];
            assert_eq!(
                sync.buffer_received_block_chunk(&mut batch, Some(block_hash)),
                1
            );
            assert!(sync.scheduler.lock().stager.contains(&block_hash));

            Ok(())
        }

        #[test]
        fn correct_body_staged_then_malformed_duplicate_is_ignored() -> TestResult {
            let (sync, block_hash, correct_block, stripped_block, _) = segwit_sync_fixture()?;

            let mut batch = vec![InboundBlock::from_local(correct_block)];
            let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
            assert_eq!(received, 1, "correct body should be staged");
            assert!(
                sync.scheduler.lock().stager.contains(&block_hash),
                "correct body must be staged"
            );
            let staged_bytes = sync.scheduler.lock().stager.received_bytes();

            let mut batch = vec![InboundBlock::from_local(stripped_block)];
            let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
            assert_eq!(received, 1, "duplicate should be processed (AlreadyStaged)");

            assert!(
                sync.scheduler.lock().stager.contains(&block_hash),
                "correct body must still be staged after malformed duplicate"
            );
            assert_eq!(
                sync.scheduler.lock().stager.received_bytes(),
                staged_bytes,
                "staged byte count must not change from a duplicate"
            );
            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                1,
                "only one body should be staged"
            );

            Ok(())
        }

        #[test]
        fn idle_frontier_relearns_stale_peer_credit_after_rejected_body() -> TestResult {
            let (sync, hash, correct, stripped, headers_tx) = segwit_sync_fixture()?;
            let bad = test_addr(9765, 0)?;
            let good = test_addr(9765, 1)?;
            let bad_rx = connect_peer(&sync.peer_table, synthetic_peer(bad, 1));
            let good_rx = connect_peer(&sync.peer_table, synthetic_peer(good, 0));
            sync.tick();
            assert_eq!(
                witness_block_inventory(next_getdata(&bad_rx)?)?,
                vec![BlockHash(hash)]
            );
            let mut malformed = InboundBlock::from_local(stripped);
            malformed.source = Some(current_source(&sync.peer_table, bad));
            sync.buffer_received_block_chunk(&mut vec![malformed], Some(hash));
            sync.tick();

            let Message::GetHeaders(request) = good_rx.try_recv()? else {
                return Err(
                    "idle recovery must discover headers before assuming body capability".into(),
                );
            };
            let genesis = Network::Regtest.genesis_block().block_hash();
            assert_eq!(
                request.locator_hashes.first().map(|h| *h.as_byte_array()),
                Some(*genesis.as_bytes())
            );
            sync.tick();
            assert!(
                good_rx.try_recv().is_err(),
                "one pending probe suppresses duplicate work"
            );

            headers_tx.send(InboundHeaders {
                headers: vec![correct.header],
                source: Some(current_source(&sync.peer_table, good)),

                wire_response: true,
            })?;
            sync.tick();
            assert_eq!(
                witness_block_inventory(next_getdata(&good_rx)?)?,
                vec![BlockHash(hash)]
            );
            let mut delivered = InboundBlock::from_local(correct);
            delivered.source = Some(current_source(&sync.peer_table, good));
            sync.buffer_received_block_chunk(&mut vec![delivered], Some(hash));
            sync.tick();
            assert_eq!(
                sync.chain.applied_tip().ok_or("missing applied tip")?.hash,
                hash
            );
            assert_no_getdata(&good_rx)?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod headers_presync {
        use bitcoin_rs_wire::PeerRemote;
        use std::net::IpAddr;
        use std::net::Ipv4Addr;
        use std::time::Instant;

        use super::TestError;
        use super::settlement_faults::deliver_headers;
        use super::settlement_faults::next_locator;
        use bitcoin_rs_consensus::primitives::Hash256;

        use super::super::SyncBudget;
        use super::super::default_sync_budget;
        use super::super::headers_presync::HeadersSyncPhase;
        use super::super::headers_presync::HeadersSyncState;
        use super::*;
        use bitcoin_rs_wire::wire::MAX_HEADERS_MESSAGE_COUNT;

        const PAGE: usize = MAX_HEADERS_MESSAGE_COUNT;

        const WORK_PER_HEADER: u64 = 2;

        fn mine_header(prev_blockhash: BlockHash, height: u32) -> Header {
            regtest_fixture::mined_regtest_header(prev_blockhash, height)
                .or_fail("regtest fixture header")
        }

        fn test_header(prev_blockhash: BlockHash, height: u32) -> Header {
            use bitcoin_rs_consensus::primitives::CompactTarget;
            let mut merkle = [0_u8; 32];
            merkle[..4].copy_from_slice(&height.to_le_bytes());
            let mut header = Header {
                version: 4,
                prev_blockhash,
                merkle_root: Hash256::from_le_bytes(&merkle),
                time: regtest_fixture::genesis_time().saturating_add(height),
                bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                nonce: 0,
            };
            regtest_fixture::mine_header_to_declared_target(&mut header)
                .or_fail("regtest fixture header");
            header
        }

        fn chain_on(fork: &Header, fork_height: u32, len: usize) -> Vec<Header> {
            let mut headers = Vec::with_capacity(len);
            let mut prev = fork.compute_hash();
            for index in 0..len {
                let offset = u32::try_from(index).unwrap_or(u32::MAX);
                let header = mine_header(prev, fork_height + offset + 1);
                prev = header.compute_hash();
                headers.push(header);
            }
            headers
        }

        fn chain_work(headers: &[Header]) -> ChainWork {
            headers.iter().fold(ChainWork::ZERO, |total, header| {
                total + bitcoin_rs_execution::chain::block_work(header)
            })
        }

        type PresyncFixture = (
            Header,
            BlockSync,
            crossbeam_channel::Sender<InboundHeaders>,
            Arc<PeerTable>,
        );

        fn presync_fixture(minimum_work: ChainWork) -> Result<PresyncFixture, TestError> {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let harness = SyncHarness::with_chain_work(
                tree,
                crate::p2p::sync::syncing_ibd_latch(),
                minimum_work,
            );
            install_budget(
                &harness.sync,
                SyncBudget {
                    max_pending_blocks: 0,
                    ..default_sync_budget(Network::Regtest)
                },
            );
            Ok((
                genesis,
                harness.sync,
                harness.inbound_headers_tx,
                harness.peers,
            ))
        }

        fn connect(
            peers: &Arc<PeerTable>,
            port: u16,
            start_height: i32,
        ) -> (
            PeerRemote,
            PeerLease,
            bitcoin_rs_wire::test_support::MessageReceiver,
        ) {
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
            ));
            let (tx, rx) = bitcoin_rs_wire::test_support::message_channel();
            let lease = PeerLease::new(tx);
            peers.register(addr, lease.clone());
            peers.publish_info(addr, &lease, synthetic_peer(addr, start_height));
            (addr, lease, rx)
        }

        fn tree_node_count(sync: &BlockSync) -> usize {
            sync.chain.block_tree().len()
        }

        fn with_sync_state<T>(
            sync: &BlockSync,
            source: PeerSource,
            read: impl FnOnce(&HeadersSyncState) -> T,
        ) -> Option<T> {
            sync.scheduler
                .lock()
                .headers_sync
                .get(&source)
                .and_then(|owned| owned.presync.as_ref())
                .map(read)
        }

        fn sync_phase(sync: &BlockSync, source: PeerSource) -> Option<HeadersSyncPhase> {
            with_sync_state(sync, source, HeadersSyncState::phase)
        }

        fn pending_request(
            sync: &BlockSync,
            source: PeerSource,
        ) -> Option<super::super::HeaderRequest> {
            sync.scheduler
                .lock()
                .headers_sync
                .get(&source)
                .and_then(|owned| owned.request)
        }

        fn expire_request(sync: &BlockSync, source: PeerSource) -> TestResult {
            let mut scheduler = sync.scheduler.lock();
            let request = scheduler
                .headers_sync
                .get_mut(&source)
                .and_then(|owned| owned.request.as_mut())
                .ok_or("the request must still be registered")?;
            request.requested_at = Instant::now()
                .checked_sub(request.timeout())
                .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
            Ok(())
        }

        fn assert_no_getheaders(rx: &bitcoin_rs_wire::test_support::MessageReceiver) {
            assert!(
                !rx.try_iter()
                    .any(|message| matches!(message, Message::GetHeaders(_))),
                "no competing getheaders should reach the wire",
            );
        }

        fn assert_request_unchanged(
            sync: &BlockSync,
            source: PeerSource,
            expected: super::super::HeaderRequest,
        ) {
            assert_eq!(
                pending_request(sync, source).map(|request| {
                    (
                        request.locator_tip_hash,
                        request.target_height,
                        request.requested_at,
                        request.state,
                    )
                }),
                Some((
                    expected.locator_tip_hash,
                    expected.target_height,
                    expected.requested_at,
                    expected.state,
                )),
                "competing schedulers must not overwrite the owned request",
            );
        }

        fn assert_competing_requests_suppressed(
            sync: &BlockSync,
            source: PeerSource,
            rx: &bitcoin_rs_wire::test_support::MessageReceiver,
            locator: Vec<Hash256>,
            target_height: i32,
        ) -> TestResult {
            let expected =
                pending_request(sync, source).ok_or("owned request was not registered")?;
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            assert_eq!(
                sync.send_getheaders(source, 0, target_height, locator),
                super::super::GetheadersOutcome::Suppressed,
            );
            assert_eq!(
                sync.send_chain_sync_probe(&frontier, source),
                super::super::GetheadersOutcome::Suppressed,
            );
            assert!(
                !sync.probe_chain_sync(source, &frontier),
                "an owned request or live presync must not arm an eviction window",
            );
            assert_no_getheaders(rx);
            assert_request_unchanged(sync, source, expected);
            Ok(())
        }

        #[test]
        fn empty_below_floor_reply_preserves_pacing_and_rotates_without_retirement() -> TestResult {
            let floor =
                ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            sync.chain.bootstrap_genesis();
            let fork = chain_on(&genesis, 0, 1);
            assert!(matches!(
                sync.chain.admit_headers(&fork),
                super::super::chain::HeaderAdmission::Accepted { .. }
            ));
            let (first_addr, _first_lease, first_rx) = connect(&peers, 9710, 100_000);
            let (second_addr, _second_lease, second_rx) = connect(&peers, 9711, 100_000);
            let first = current_source(&peers, first_addr);
            let second = current_source(&peers, second_addr);

            sync.tick();
            assert!(matches!(first_rx.try_recv()?, Message::GetHeaders(_)));
            assert!(second_rx.try_recv().is_err());
            let initial =
                pending_request(&sync, first).ok_or("the first request was not registered")?;
            assert_eq!(
                initial.state,
                super::super::HeaderRequestState::AwaitingResponse
            );

            sync.note_header_response_received(first);
            inbound_headers_tx.send(InboundHeaders {
                headers: Vec::new(),
                source: Some(first),
                wire_response: true,
            })?;
            sync.tick();
            let answered =
                pending_request(&sync, first).ok_or("the empty reply lost its request")?;
            assert_eq!(answered.state, super::super::HeaderRequestState::Answered);
            assert_eq!(answered.requested_at, initial.requested_at);
            assert_eq!(answered.locator_tip_hash, initial.locator_tip_hash);
            assert_eq!(answered.target_height, initial.target_height);
            assert_no_getheaders(&first_rx);
            assert_no_getheaders(&second_rx);

            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            assert_eq!(
                sync.send_getheaders(first, 0, 1, vec![Hash256::from(genesis.compute_hash())],),
                super::super::GetheadersOutcome::Suppressed,
            );
            assert!(
                !sync.probe_chain_sync(first, &frontier),
                "an answered pacing gate must not arm an eviction window",
            );
            assert_request_unchanged(&sync, first, answered);
            assert_no_getheaders(&first_rx);

            expire_request(&sync, first)?;
            sync.tick();
            assert!(
                peers.is_current(first),
                "an answered request cannot retire its peer"
            );
            assert_eq!(
                pending_request(&sync, first).map(|request| request.state),
                Some(super::super::HeaderRequestState::Answered),
            );
            assert!(first_rx.try_recv().is_err());
            assert!(matches!(second_rx.try_recv()?, Message::GetHeaders(_)));
            assert_eq!(sync.scheduler.lock().header_request_owner, Some(second));

            let chain = chain_on(&genesis, 0, PAGE);
            deliver_headers(&inbound_headers_tx, chain, second)?;
            sync.tick();
            let _ =
                next_locator(&second_rx).ok_or("the second peer's presync request was not sent")?;
            let before_empty =
                pending_request(&sync, second).ok_or("the second request was not tracked")?;
            assert_eq!(sync_phase(&sync, second), Some(HeadersSyncPhase::Presync));
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&second)
                    .is_some_and(|owned| owned.presync.is_some()),
                "a live presync cursor shares the request's lifecycle entry",
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: Vec::new(),
                source: Some(second),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            let answered =
                pending_request(&sync, second).ok_or("the empty answer lost its pacing gate")?;
            assert_eq!(answered.state, super::super::HeaderRequestState::Answered);
            assert_eq!(answered.requested_at, before_empty.requested_at);
            assert_eq!(sync_phase(&sync, second), None);
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&second)
                    .is_some_and(|owned| owned.request.is_some() && owned.presync.is_none()),
                "an empty answer clears only the nested presync state",
            );
            Ok(())
        }

        #[test]
        fn unowned_below_floor_peer_receives_one_tracked_chain_sync_probe() -> TestResult {
            let floor =
                ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            sync.chain.bootstrap_genesis();
            let (addr, _lease, rx) = connect(&peers, 9712, 100_000);
            let source = current_source(&peers, addr);
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());

            assert!(
                sync.probe_chain_sync(source, &frontier),
                "an unowned source must receive its real below-floor probe",
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            let request = pending_request(&sync, source).ok_or("the probe was not tracked")?;
            assert_eq!(
                request.state,
                super::super::HeaderRequestState::AwaitingResponse
            );
            assert_eq!(
                sync.send_getheaders(source, 0, 100, vec![Hash256::from(genesis.compute_hash())],),
                super::super::GetheadersOutcome::Suppressed,
                "an unanswered below-floor request owns this exact connection",
            );
            assert!(
                !sync.probe_chain_sync(source, &frontier),
                "a second probe must not borrow the first request's response window",
            );
            assert_no_getheaders(&rx);

            inbound_headers_tx.send(InboundHeaders {
                headers: chain_on(&genesis, 0, PAGE),
                source: Some(source),
                wire_response: true,
            })?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "the real response must establish the download-twice owner",
            );
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&source)
                    .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
                "the presync continuation and request share one lifecycle entry",
            );
            let _ = rx.try_iter().collect::<Vec<_>>();
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            assert!(
                !sync.probe_chain_sync(source, &frontier),
                "a live PRESYNC cursor must not arm a chain-sync eviction window",
            );
            assert_no_getheaders(&rx);
            Ok(())
        }

        #[test]
        fn late_or_foreign_receipts_do_not_redeem_silent_header_sources() -> TestResult {
            let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE)?);
            let (genesis, sync, _inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, _lease, rx) = connect(&peers, 9740, 100_000);
            let source = current_source(&peers, addr);
            let (other_addr, _other_lease, _other_rx) = connect(&peers, 9741, 100_000);
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            sync.note_header_response_received(current_source(&peers, other_addr));
            expire_request(&sync, source)?;
            sync.note_header_response_received(source);
            sync.retire_timed_out_header_syncs(Instant::now());
            assert!(!peers.is_connected(addr));
            assert!(peers.is_connected(other_addr));

            let (_addr, _replacement, replacement_rx) = connect(&peers, 9740, 100_000);
            let replacement_source = current_source(&peers, addr);
            assert_eq!(
                sync.send_getheaders(
                    replacement_source,
                    0,
                    100_000,
                    vec![Hash256::from(genesis.compute_hash())],
                ),
                super::super::GetheadersOutcome::Sent,
            );
            assert!(matches!(replacement_rx.try_recv()?, Message::GetHeaders(_)));
            sync.note_header_response_received(source);
            expire_request(&sync, replacement_source)?;
            sync.retire_timed_out_header_syncs(Instant::now());
            assert!(!peers.is_connected(addr));
            assert!(pending_request(&sync, replacement_source).is_none());
            Ok(())
        }

        // P2P-10
        #[test]
        fn low_work_headers_do_not_reach_block_tree() -> TestResult {
            let floor =
                ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, lease, rx) = connect(&peers, 9701, 100_000);
            let source = current_source(&peers, addr);
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            let chain = chain_on(&genesis, 0, 2 * PAGE + 500);
            assert_eq!(
                bitcoin_rs_execution::chain::block_work(&chain[0]),
                ChainWork::from(WORK_PER_HEADER),
                "the fixture's work-per-header constant must hold"
            );
            assert!(
                chain_work(&chain) < floor,
                "the fixture chain must stay below the assumed-work floor"
            );
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();

            assert_eq!(
                tree_node_count(&sync),
                1,
                "a full page below the floor must not reach the tree"
            );
            let locator = next_locator(&rx).ok_or_else(|| {
                std::io::Error::other("the presync continuation getheaders was not sent")
            })?;
            assert_eq!(
                locator.first().copied(),
                Some(Hash256::from(chain[PAGE - 1].compute_hash()).to_le_bytes()),
                "the continuation must resume from the collected cursor"
            );

            deliver_headers(&inbound_headers_tx, chain[PAGE..2 * PAGE].to_vec(), source)?;
            sync.tick();

            assert_eq!(
                tree_node_count(&sync),
                1,
                "the continuation page must not reach the tree either"
            );
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "a live collection must keep the state"
            );
            let cursor =
                with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes());
            assert_eq!(
                cursor,
                Some(Hash256::from(chain[2 * PAGE - 1].compute_hash()).to_le_bytes()),
                "the second page must extend the same state's cursor"
            );
            assert!(
                !lease.is_cancelled() && peers.is_connected(addr),
                "collecting a low-work chain must not blame the peer"
            );
            Ok(())
        }

        // P2P-10
        #[test]
        fn sufficient_work_chain_syncs_presync_then_redownload() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, PAGE + 500);
            let threshold = chain_work(&chain);
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
            let (addr, _lease, rx) = connect(&peers, 9702, 100_000);
            let source = current_source(&peers, addr);
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "a page whose own claimed work is below the floor collects"
            );
            assert_eq!(
                next_locator(&rx).map(|locator| locator.first().copied()),
                Some(Some(
                    Hash256::from(chain[PAGE - 1].compute_hash()).to_le_bytes()
                )),
                "presync must request the continuation from the collected tip",
            );

            for _ in 0..super::super::headers::MAX_HEADER_BATCHES_PER_TICK {
                inbound_headers_tx.send(InboundHeaders {
                    headers: Vec::new(),
                    source: None,
                    wire_response: false,
                })?;
            }
            let cursor = with_sync_state(&sync, source, |state| state.next_locator()[0]);
            sync.note_header_response_received(source);
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
            expire_request(&sync, source)?;
            let pending = pending_request(&sync, source).ok_or("missing continuation request")?;
            assert_competing_requests_suppressed(
                &sync,
                source,
                &rx,
                vec![Hash256::from(genesis.compute_hash())],
                9,
            )?;
            let (silent_addr, _silent_lease, _silent_rx) = connect(&peers, 9742, 100_000);
            let silent_source = current_source(&peers, silent_addr);
            assert_eq!(
                sync.send_getheaders(silent_source, 0, 100_000, vec![pending.locator_tip_hash]),
                super::super::GetheadersOutcome::Sent,
            );
            assert_eq!(sync.scheduler.lock().header_request_owner, Some(source));
            expire_request(&sync, silent_source)?;
            sync.tick();
            assert!(
                !peers.is_connected(silent_addr),
                "silent sources still expire"
            );
            assert_eq!(sync.inbound_headers_rx.len(), 1);
            assert!(
                peers.is_connected(addr),
                "queued responses are not peer silence"
            );
            assert_request_unchanged(&sync, source, pending);
            assert_eq!(
                with_sync_state(&sync, source, |state| state.next_locator()[0]),
                cursor
            );
            sync.tick();

            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Redownload),
                "crossing must flip the sync to its second pass"
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "crossing the floor must not admit the collected pass"
            );
            assert_eq!(
                next_locator(&rx).map(|locator| locator.first().copied()),
                Some(Some(Hash256::from(genesis.compute_hash()).to_le_bytes())),
                "the second pass must be requested on the wire from the fork point",
            );
            assert_eq!(
                with_sync_state(&sync, source, |state| state.next_locator()[0]),
                Some(Hash256::from(genesis.compute_hash())),
                "the second pass must restart at the fork point"
            );

            let chain_last = chain[PAGE + 500 - 1].compute_hash();
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
            sync.tick();
            let tree = sync.chain.block_tree();
            assert_eq!(
                tree.height_of_hash(Hash256::from(chain_last)),
                Some(u32::try_from(PAGE + 500).unwrap_or(u32::MAX)),
                "the committed replay must admit the whole chain in wire order (len {})",
                tree.len(),
            );
            drop(tree);
            assert_eq!(
                sync_phase(&sync, source),
                None,
                "a spent sync state must be retired"
            );
            Ok(())
        }

        // P2P-10
        #[test]
        fn a_substituted_redownload_header_disconnects_the_connection() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, PAGE + 500);
            let threshold = chain_work(&chain);
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
            let (addr, lease, rx) = connect(&peers, 9703, 100_000);
            let source = current_source(&peers, addr);
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Redownload),
                "the fixture must reach its second pass"
            );

            let Some(commitment_height) =
                with_sync_state(&sync, source, |state| state.first_commitment_height(2))
            else {
                unreachable!("the sync state is live");
            };
            let chain_len = chain.len();
            let commitment_index = usize::try_from(commitment_height).unwrap_or(usize::MAX);
            assert!(commitment_index <= chain_len);
            let original_hash = chain[commitment_index - 1].compute_hash();
            let mut rogue = test_header(
                chain[commitment_index - 2].compute_hash(),
                commitment_height,
            );
            let original_bit = with_sync_state(&sync, source, |state| {
                state.commitment_bit(Hash256::from(original_hash))
            })
            .unwrap_or_else(|| unreachable!("the sync state is live"));
            loop {
                let hash = Hash256::from(rogue.compute_hash());
                let bit = with_sync_state(&sync, source, |state| state.commitment_bit(hash))
                    .unwrap_or_else(|| unreachable!("the sync state is live"));
                if hash != Hash256::from(original_hash)
                    && bit != original_bit
                    && bitcoin_rs_execution::chain::compact_is_met_by(rogue.bits, hash)
                {
                    break;
                }
                rogue.nonce = rogue.nonce.wrapping_add(1);
            }
            let mut substituted = chain;
            substituted[commitment_index - 1] = rogue;
            for index in commitment_index..chain_len {
                let mut header = substituted[index];
                header.prev_blockhash = substituted[index - 1].compute_hash();
                while !bitcoin_rs_execution::chain::compact_is_met_by(
                    header.bits,
                    Hash256::from(header.compute_hash()),
                ) {
                    header.nonce = header.nonce.wrapping_add(1);
                }
                substituted[index] = header;
            }

            deliver_headers(&inbound_headers_tx, substituted, source)?;
            sync.tick();

            assert!(
                lease.is_cancelled() || !peers.is_connected(addr),
                "a salted-commitment divergence must cost the connection its lease"
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "the mismatching batch must admit nothing"
            );
            assert_eq!(
                sync_phase(&sync, source),
                None,
                "the punished sync state must be retired"
            );
            Ok(())
        }

        #[test]
        fn owned_header_requests_suppress_competing_frontier_and_chain_sync_requests() -> TestResult
        {
            let chain = chain_on(&genesis_header(), 0, PAGE + 500);
            let threshold = chain_work(&chain);
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
            let (addr, _lease, rx) = connect(&peers, 9720, 100_000);
            let source = current_source(&peers, addr);
            let competing_locator = vec![Hash256::from(chain[0].compute_hash())];

            sync.tick();
            let _ = next_locator(&rx).ok_or("the initial getheaders was not sent")?;
            assert_competing_requests_suppressed(&sync, source, &rx, competing_locator.clone(), 7)?;

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            let _ = next_locator(&rx).ok_or("the presync continuation was not sent")?;
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "the first page must enter presync",
            );
            assert_competing_requests_suppressed(&sync, source, &rx, competing_locator.clone(), 8)?;

            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
            sync.tick();
            let _ = next_locator(&rx).ok_or("the redownload request was not sent")?;
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Redownload),
                "the crossing page must enter redownload",
            );
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&source)
                    .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
                "the redownload request and validation cursor share one lifecycle entry",
            );
            assert_competing_requests_suppressed(&sync, source, &rx, competing_locator, 9)?;
            Ok(())
        }

        #[test]
        fn expired_header_syncs_drop_delayed_pages_before_recovery() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, PAGE + 500);
            let threshold = chain_work(&chain);
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
            let (addr_a, _lease_a, rx_a) = connect(&peers, 9721, 100_000);
            let source_a = current_source(&peers, addr_a);
            let (addr_b, _lease_b, rx_b) = connect(&peers, 9722, 100_000);
            let source_b = current_source(&peers, addr_b);

            sync.tick();
            let _ = next_locator(&rx_a).ok_or("the initial request was not sent")?;
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_a)?;
            expire_request(&sync, source_a)?;
            sync.tick();
            let _ = next_locator(&rx_b).ok_or("the first recovery request was not sent")?;
            assert!(
                !peers.is_connected(addr_a),
                "the timed-out source must disconnect"
            );
            assert_eq!(sync_phase(&sync, source_a), None);
            assert!(pending_request(&sync, source_a).is_none());
            assert!(!sync.scheduler.lock().headers_sync.contains_key(&source_a));
            assert_eq!(
                tree_node_count(&sync),
                1,
                "a delayed response after initial timeout must not be admitted",
            );

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_b)?;
            sync.tick();
            let _ = next_locator(&rx_b).ok_or("the presync continuation was not sent")?;
            assert_eq!(sync_phase(&sync, source_b), Some(HeadersSyncPhase::Presync));
            let (addr_c, _lease_c, rx_c) = connect(&peers, 9723, 100_000);
            let source_c = current_source(&peers, addr_c);
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_b)?;
            expire_request(&sync, source_b)?;
            sync.tick();
            let _ = next_locator(&rx_c).ok_or("the presync recovery request was not sent")?;
            assert!(
                !peers.is_connected(addr_b),
                "the presync timeout must disconnect its source"
            );
            assert_eq!(sync_phase(&sync, source_b), None);
            assert!(pending_request(&sync, source_b).is_none());
            assert!(!sync.scheduler.lock().headers_sync.contains_key(&source_b));
            assert_eq!(
                tree_node_count(&sync),
                1,
                "a delayed presync page must not be admitted after timeout",
            );

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_c)?;
            sync.tick();
            let _ = next_locator(&rx_c).ok_or("the recovery presync continuation was not sent")?;
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_c)?;
            sync.tick();
            let _ = next_locator(&rx_c).ok_or("the recovery redownload request was not sent")?;
            assert_eq!(
                sync_phase(&sync, source_c),
                Some(HeadersSyncPhase::Redownload)
            );
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&source_c)
                    .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
            );
            let (addr_d, _lease_d, rx_d) = connect(&peers, 9724, 100_000);
            let source_d = current_source(&peers, addr_d);
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_c)?;
            expire_request(&sync, source_c)?;
            sync.tick();
            let _ = next_locator(&rx_d).ok_or("the redownload recovery request was not sent")?;
            assert!(
                !peers.is_connected(addr_c),
                "the redownload timeout must disconnect its source"
            );
            assert_eq!(sync_phase(&sync, source_c), None);
            assert!(pending_request(&sync, source_c).is_none());
            assert!(!sync.scheduler.lock().headers_sync.contains_key(&source_c));
            assert_eq!(
                tree_node_count(&sync),
                1,
                "the work floor must still block admission before replay",
            );

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_d)?;
            sync.tick();
            let _ = next_locator(&rx_d).ok_or("the final presync continuation was not sent")?;
            assert_eq!(sync_phase(&sync, source_d), Some(HeadersSyncPhase::Presync));
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_d)?;
            sync.tick();
            let _ = next_locator(&rx_d).ok_or("the final redownload request was not sent")?;
            assert_eq!(
                sync_phase(&sync, source_d),
                Some(HeadersSyncPhase::Redownload)
            );
            assert_eq!(tree_node_count(&sync), 1);
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_d)?;
            sync.tick();
            let _ = next_locator(&rx_d).ok_or("the replay continuation was not sent")?;
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_d)?;
            sync.tick();
            assert_eq!(
                sync.chain.block_tree().height_of_hash(Hash256::from(
                    chain.last().ok_or("empty chain")?.compute_hash()
                )),
                Some(u32::try_from(chain.len()).unwrap_or(u32::MAX)),
                "recovery must admit the replayed chain",
            );
            assert_eq!(sync_phase(&sync, source_d), None);
            Ok(())
        }

        #[test]
        fn replaced_connection_cannot_admit_queued_predecessor_headers() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, PAGE + 500);
            let threshold = chain_work(&chain);
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
            let (addr, old_lease, old_rx) = connect(&peers, 9725, 100_000);
            let old_source = current_source(&peers, addr);
            sync.tick();
            let _ = next_locator(&old_rx).ok_or("the predecessor request was not sent")?;
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), old_source)?;
            sync.tick();
            let _ = next_locator(&old_rx).ok_or("the predecessor presync request was not sent")?;
            assert_eq!(
                sync_phase(&sync, old_source),
                Some(HeadersSyncPhase::Presync)
            );
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&old_source)
                    .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
                "the predecessor has both lifecycle facts before replacement",
            );

            let (replacement_tx, replacement_rx) = bitcoin_rs_wire::test_support::message_channel();
            let replacement_lease = PeerLease::new(replacement_tx);
            peers.register(addr, replacement_lease.clone());
            peers.publish_info(addr, &replacement_lease, synthetic_peer(addr, 100_000));
            let replacement = current_source(&peers, addr);

            sync.tick();
            let _ = next_locator(&replacement_rx).ok_or("the replacement request was not sent")?;
            assert!(old_lease.is_cancelled());
            assert_eq!(sync_phase(&sync, old_source), None);
            assert!(pending_request(&sync, old_source).is_none());
            assert!(!sync.scheduler.lock().headers_sync.contains_key(&old_source));
            assert_eq!(
                pending_request(&sync, replacement).map(|request| request.source),
                Some(replacement),
                "replacement ownership must be published under its exact identity",
            );

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), replacement)?;
            sync.tick();
            let _ = next_locator(&replacement_rx)
                .ok_or("the replacement presync continuation was not sent")?;
            assert_eq!(
                sync_phase(&sync, replacement),
                Some(HeadersSyncPhase::Presync),
                "the replacement must retain its own presync state",
            );
            assert!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&replacement)
                    .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
                "the replacement owns its request and presync together",
            );
            let replacement_request = pending_request(&sync, replacement)
                .ok_or("replacement request was not registered")?;

            deliver_headers(&inbound_headers_tx, chain, old_source)?;
            sync.tick();
            assert_no_getheaders(&replacement_rx);
            assert_eq!(
                sync_phase(&sync, replacement),
                Some(HeadersSyncPhase::Presync),
                "a stale batch must leave the replacement's sync state intact",
            );
            assert_eq!(
                pending_request(&sync, replacement).map(|request| request.source),
                Some(replacement),
                "a stale predecessor delivery must not overwrite replacement request ownership",
            );
            assert_request_unchanged(&sync, replacement, replacement_request);
            assert_eq!(
                tree_node_count(&sync),
                1,
                "a queued directly-admissible predecessor batch must not enter the tree",
            );
            Ok(())
        }

        #[test]
        fn redownload_release_continues_from_the_state_cursor() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, 5 * PAGE);
            let threshold =
                ChainWork::from(WORK_PER_HEADER * u64::try_from(5 * PAGE).unwrap_or(u64::MAX));
            assert_eq!(
                chain_work(&chain),
                threshold,
                "the floor must sit exactly on the chain's last header"
            );
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
            let (addr, _lease, rx) = connect(&peers, 9704, 100_000);
            let source = current_source(&peers, addr);
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            for page in 0..5 {
                deliver_headers(
                    &inbound_headers_tx,
                    chain[page * PAGE..(page + 1) * PAGE].to_vec(),
                    source,
                )?;
                sync.tick();
            }
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Redownload),
                "the fixture must reach its second pass"
            );

            for page in 0..3 {
                deliver_headers(
                    &inbound_headers_tx,
                    chain[page * PAGE..(page + 1) * PAGE].to_vec(),
                    source,
                )?;
                sync.tick();
            }
            while rx.try_recv().is_ok() {}
            deliver_headers(
                &inbound_headers_tx,
                chain[3 * PAGE..4 * PAGE].to_vec(),
                source,
            )?;
            sync.tick();
            assert_eq!(
                tree_node_count(&sync),
                4 * PAGE - 7_017 + 1,
                "the overflow release must retire exactly the buffer's excess"
            );
            let locator = next_locator(&rx).ok_or_else(|| {
                std::io::Error::other("the release continuation getheaders was not sent")
            })?;
            assert_eq!(
                locator.first().copied(),
                Some(Hash256::from(chain[4 * PAGE - 1].compute_hash()).to_le_bytes()),
                "the continuation must leave from the state's redownload cursor, not the release point",
            );

            deliver_headers(
                &inbound_headers_tx,
                chain[4 * PAGE..5 * PAGE].to_vec(),
                source,
            )?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                None,
                "a completed second pass must retire the state"
            );
            assert_eq!(
                tree_node_count(&sync),
                5 * PAGE + 1,
                "the whole replayed chain must be admitted in wire order"
            );
            Ok(())
        }

        #[test]
        fn a_midbatch_continuity_break_spends_the_sync() -> TestResult {
            let floor = ChainWork::from(
                WORK_PER_HEADER * u64::try_from(2 * PAGE + 500).unwrap_or(u64::MAX),
            );
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, lease, _rx) = connect(&peers, 9705, 100_000);
            let source = current_source(&peers, addr);

            let chain = chain_on(&genesis, 0, 2 * PAGE);
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "the fixture must collect below the floor"
            );

            let mut midbreak = chain[PAGE..2 * PAGE - 1].to_vec();
            midbreak.push(mine_header(
                BlockHash(Hash256::from_le_bytes(&[0xa5; 32])),
                u32::try_from(2 * PAGE).unwrap_or(u32::MAX),
            ));
            deliver_headers(&inbound_headers_tx, midbreak, source)?;
            sync.tick();

            assert_eq!(
                sync_phase(&sync, source),
                None,
                "a batch that breaks continuity mid-way must spend the sync"
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "the disconnected branch must not reach the tree"
            );
            assert!(
                !lease.is_cancelled() && peers.is_connected(addr),
                "a lost continuation is possibly benign: the connection stays"
            );
            Ok(())
        }

        #[test]
        fn a_forwarded_body_header_leaves_the_live_sync_state_alone() -> TestResult {
            let floor =
                ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, lease, rx) = connect(&peers, 9706, 100_000);
            let source = current_source(&peers, addr);

            let chain = chain_on(&genesis, 0, PAGE);
            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "the fixture must collect below the floor"
            );
            let cursor =
                with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes());
            while rx.try_recv().is_ok() {}

            inbound_headers_tx
                .send(InboundHeaders {
                    headers: vec![mine_header(genesis.compute_hash(), 5_000)],
                    source: Some(source),
                    wire_response: false,
                })
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            sync.tick();

            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Presync),
                "a body-carried header must not touch the wire sync's state"
            );
            assert_eq!(
                with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes()),
                cursor,
                "the forwarded header must not advance the state's cursor"
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "a header below the floor must not reach the tree through a body either"
            );
            assert!(
                rx.try_recv().is_err() && !lease.is_cancelled() && peers.is_connected(addr),
                "a forwarded header sends nothing and blames no one"
            );
            Ok(())
        }

        fn presync_fixture_refusing(minimum_work: ChainWork) -> Result<PresyncFixture, TestError> {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let chain_tip = tree.tip_handle();
            let block_tree = Arc::new(RwLock::new(tree));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let peers = Arc::new(PeerTable::new());
            let (inbound_headers_tx, inbound_headers_rx) = unbounded();
            let (_inbound_blocks_tx, inbound_blocks_rx) = unbounded();
            let sync = BlockSync::new(
                Arc::new(RefusingChain(Arc::new(
                    TestChain::new(chain_tip, Arc::clone(&applied_tip), Arc::clone(&block_tree))
                        .with_minimum_chain_work(minimum_work),
                ))),
                Arc::clone(&peers),
                inbound_headers_rx,
                inbound_blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            );
            install_budget(
                &sync,
                SyncBudget {
                    max_pending_blocks: 0,
                    ..default_sync_budget(Network::Regtest)
                },
            );
            Ok((genesis, sync, inbound_headers_tx, peers))
        }

        #[test]
        fn a_refused_release_drops_the_sync() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, PAGE + 500);
            let threshold = chain_work(&chain);
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture_refusing(threshold)?;
            let (addr, _lease, rx) = connect(&peers, 9706, 100_000);
            let source = current_source(&peers, addr);
            sync.tick();
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            assert_eq!(sync_phase(&sync, source), Some(HeadersSyncPhase::Presync),);
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, source),
                Some(HeadersSyncPhase::Redownload),
            );
            let _ = rx.try_iter().count();

            deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
            sync.tick();
            deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
            sync.tick();

            assert_eq!(
                sync_phase(&sync, source),
                None,
                "a refused release drops the sync rather than requeueing the prefix",
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "a refused release admits nothing",
            );
            assert!(
                rx.try_iter()
                    .any(|message| matches!(message, Message::GetHeaders(_))),
                "the paced ancestry retry must be on the wire",
            );
            Ok(())
        }

        #[test]
        fn a_batch_crossing_the_floor_admits_without_presync() -> TestResult {
            let chain = chain_on(&genesis_header(), 0, 10);
            let floor = chain_work(&chain);
            let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, _lease, _rx) = connect(&peers, 9704, 100_000);
            let source = current_source(&peers, addr);

            deliver_headers(&inbound_headers_tx, chain.clone(), source)?;
            sync.tick();

            assert_eq!(
                tree_node_count(&sync),
                1 + chain.len(),
                "a batch whose claimed work reaches the floor must admit directly"
            );
            assert_eq!(
                sync_phase(&sync, source),
                None,
                "the fast path must not open a download-twice state"
            );
            Ok(())
        }

        #[test]
        fn an_invalid_anchor_refuses_without_presync() -> TestResult {
            let floor = ChainWork::from(u64::MAX);
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let doomed = chain_on(&genesis, 0, 3);
            let mut root = None;
            for header in &doomed {
                let id = tree.insert_header(*header, NodeStatus::HeaderValid)?;
                root = root.or(Some(id));
            }
            let root = root.ok_or_else(|| std::io::Error::other("no doomed root"))?;
            tree.invalidate_subtree(root)?;
            let doomed_len = tree.len();

            let harness =
                SyncHarness::with_chain_work(tree, crate::p2p::sync::syncing_ibd_latch(), floor);
            install_budget(
                &harness.sync,
                SyncBudget {
                    max_pending_blocks: 0,
                    ..default_sync_budget(Network::Regtest)
                },
            );
            let sync = harness.sync;
            let inbound_headers_tx = harness.inbound_headers_tx;
            let peers = harness.peers;

            let (addr, _lease, _rx) = connect(&peers, 9705, 100_000);
            let source = current_source(&peers, addr);
            let continuation = chain_on(&doomed[2], 3, 5);
            deliver_headers(&inbound_headers_tx, continuation, source)?;
            sync.tick();

            assert_eq!(
                sync_phase(&sync, source),
                None,
                "an invalid anchor must not open a download-twice state"
            );
            assert_eq!(
                tree_node_count(&sync),
                doomed_len,
                "the InvalidParent refusal must not grow the tree"
            );
            assert!(
                peers.is_connected(addr),
                "a refused anchor is not a peer fault"
            );
            Ok(())
        }

        #[test]
        fn a_terminal_low_work_page_demotes_the_source() -> TestResult {
            let floor = ChainWork::from(u64::MAX);
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, _lease, _rx) = connect(&peers, 9706, 100_000);
            let source = current_source(&peers, addr);
            assert_eq!(
                peers.info_of(addr).map(|info| info.best_known_height),
                Some(100_000)
            );

            let chain = chain_on(&genesis, 0, 5);
            deliver_headers(&inbound_headers_tx, chain, source)?;
            sync.tick();

            assert_eq!(
                sync_phase(&sync, source),
                None,
                "the terminal page spends the sync state"
            );
            let session = peers
                .sessions()
                .into_iter()
                .find(|session| session.endpoint == addr.endpoint())
                .ok_or_else(|| std::io::Error::other("session vanished"))?;
            assert_eq!(
                session.headers_horizon,
                Some(5),
                "the horizon must fall to the demonstrated cursor height"
            );
            assert_eq!(
                session.info.map(|info| info.best_known_height),
                Some(100_000),
                "best_known_height must not be lowered"
            );
            assert!(
                peers.is_connected(addr),
                "a short sync below the floor is not a peer fault"
            );
            Ok(())
        }

        #[test]
        fn unsolicited_presync_continuation_keeps_another_peers_pending_request() -> TestResult {
            let floor =
                ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
            let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (owner_addr, _owner_lease, owner_rx) = connect(&peers, 9707, 100_000);
            sync.tick();
            let _ = next_locator(&owner_rx)
                .ok_or_else(|| std::io::Error::other("the owner request was not sent"))?;
            let owner = current_source(&peers, owner_addr);
            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(|request| request.source == owner),
                "the pending header request must belong to the first peer"
            );

            let (sender_addr, _sender_lease, sender_rx) = connect(&peers, 9708, 100_000);
            let sender = current_source(&peers, sender_addr);
            deliver_headers(&inbound_headers_tx, chain_on(&genesis, 0, PAGE), sender)?;
            sync.tick();
            assert_eq!(
                sync_phase(&sync, sender),
                Some(HeadersSyncPhase::Presync),
                "the unsolicited full page must enter presync"
            );
            let _ = next_locator(&sender_rx)
                .ok_or_else(|| std::io::Error::other("the presync continuation was not sent"))?;

            assert!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .is_some_and(|request| request.source == owner),
                "an unsolicited low-work continuation must not replace another peer's request"
            );
            Ok(())
        }

        fn assert_invalid_body_header_is_discarded(block: Block, port: u16) -> TestResult {
            let floor = ChainWork::from(u64::MAX);
            let (_genesis, sync, _inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, _lease, _rx) = connect(&peers, port, 100_000);
            let source = current_source(&peers, addr);
            let hash = Hash256::from(block.block_hash());
            let mut batch = vec![bitcoin_rs_wire::InboundBlock::from_local(block)];
            batch[0].source = Some(source);
            assert_eq!(sync.buffer_received_block_chunk(&mut batch, None), 1);
            assert!(
                sync.scheduler.lock().stager.contains(&hash),
                "the unresolved body must stage before its carried header is retried"
            );

            sync.drain_inbound_blocks();

            assert!(
                !sync.scheduler.lock().stager.contains(&hash),
                "an inadmissible carried header must release its staged body"
            );
            assert!(
                !peers.is_connected(addr),
                "a permanent header fault must disconnect the delivering peer"
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "the invalid header must not be admitted"
            );
            Ok(())
        }

        #[test]
        fn body_carried_low_work_bad_pow_is_discarded_and_faults_peer() -> TestResult {
            let genesis = Network::Regtest.genesis_block().header;
            let mut block = regtest_fixture::mined_block_with_prev_hash(
                genesis.compute_hash(),
                1,
                vec![regtest_fixture::coinbase(1)],
            )?;
            while bitcoin_rs_execution::chain::compact_is_met_by(
                block.header.bits,
                Hash256::from(block.block_hash()),
            ) {
                block.header.nonce = block.header.nonce.wrapping_add(1);
            }

            assert_invalid_body_header_is_discarded(block, 9711)
        }

        #[test]
        fn body_carried_low_work_bad_nbits_is_discarded_and_faults_peer() -> TestResult {
            let genesis = Network::Regtest.genesis_block().header;
            let mut block = regtest_fixture::mined_block_with_prev_hash(
                genesis.compute_hash(),
                1,
                vec![regtest_fixture::coinbase(2)],
            )?;
            block.header.bits =
                bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x207f_fffe);
            while !bitcoin_rs_execution::chain::compact_is_met_by(
                block.header.bits,
                Hash256::from(block.block_hash()),
            ) {
                block.header.nonce = block.header.nonce.wrapping_add(1);
            }

            assert_invalid_body_header_is_discarded(block, 9712)
        }

        #[test]
        fn body_carried_low_work_valid_header_stays_deferred() -> TestResult {
            let floor = ChainWork::from(u64::MAX);
            let (_genesis, sync, _inbound_headers_tx, peers) = presync_fixture(floor)?;
            let (addr, _lease, _rx) = connect(&peers, 9713, 100_000);
            let source = current_source(&peers, addr);
            let genesis = Network::Regtest.genesis_block();
            let block = regtest_fixture::mined_block_with_prev_hash(
                genesis.block_hash(),
                1,
                vec![regtest_fixture::coinbase(3)],
            )?;
            let hash = Hash256::from(block.block_hash());
            let mut batch = vec![bitcoin_rs_wire::InboundBlock::from_local(block)];
            batch[0].source = Some(source);
            assert_eq!(sync.buffer_received_block_chunk(&mut batch, None), 1);

            sync.drain_inbound_blocks();

            assert!(
                sync.scheduler.lock().stager.contains(&hash),
                "a valid below-floor body must wait for the wire presync admission"
            );
            assert!(
                peers.is_connected(addr),
                "valid carried headers do not fault the peer"
            );
            assert_eq!(
                tree_node_count(&sync),
                1,
                "the low-work header remains unadmitted"
            );
            Ok(())
        }
    }

    mod frontier_recovery {
        use super::*;

        fn next_getheaders(
            rx: &bitcoin_rs_wire::test_support::MessageReceiver,
        ) -> Result<bitcoin::p2p::message_blockdata::GetHeadersMessage, TestError> {
            while let Ok(message) = rx.try_recv() {
                if let Message::GetHeaders(request) = message {
                    return Ok(request);
                }
            }
            Err(std::io::Error::other("expected getheaders").into())
        }

        // P2P-05
        #[test]
        fn applied_rewind_with_unchanged_headers_refetches_the_missing_prefix() -> TestResult {
            let (sync, peers, applied, blocks, incoming) = sync_with_mined_chain(3)?;
            let peer = test_addr(9760, 0)?;
            let outbound = connect_peer(&peers, synthetic_peer(peer, 3));
            sync.tick();
            let genesis = applied.load_full().ok_or("missing genesis")?;
            let hashes: Vec<_> = blocks.iter().map(Block::block_hash).collect();
            assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
            for block in blocks {
                incoming.send(bitcoin_rs_wire::InboundBlock::from_local(block))?;
            }
            sync.tick();
            assert_eq!(applied.load_full().ok_or("missing applied tip")?.height, 3);
            assert_no_getdata(&outbound)?;

            applied.store(Some(genesis));
            sync.tick();
            assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
            sync.tick();
            assert_no_getdata(&outbound)?;
            Ok(())
        }

        #[test]
        fn cancelled_ready_event_does_not_wait_for_an_unrelated_body_writer() -> TestResult {
            let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
            let peer = test_addr(9760, 1)?;
            let _old = connect_peer(&peers, synthetic_peer(peer, 1));
            let stale = current_source(&peers, peer);
            let _replacement = connect_peer(&peers, synthetic_peer(peer, 1));
            let sync = Arc::new(sync);
            let body = sync.scheduler.lock();
            let (finished, completed) = crossbeam_channel::bounded(1);
            let worker_sync = Arc::clone(&sync);
            let worker = std::thread::spawn(move || {
                worker_sync.on_peer_ready(stale);
                let _ = finished.send(());
            });
            let result = completed.recv_timeout(Duration::from_secs(1));
            drop(body);
            worker.join().map_err(|_| "ready handler panicked")?;
            result?;
            assert!(peers.is_current(current_source(&peers, peer)));
            Ok(())
        }

        // P2P-05
        #[test]
        fn empty_header_probe_is_paced_then_rotates_to_another_peer() -> TestResult {
            let (tree, _blocks) = mined_chain(1, 0)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let peers = harness.peers;
            let headers = harness.inbound_headers_tx;
            let first = test_addr(9760, 2)?;
            let second = test_addr(9760, 3)?;
            let first_rx = connect_peer(&peers, synthetic_peer(first, 0));
            let second_rx = connect_peer(&peers, synthetic_peer(second, 0));
            sync.tick();
            assert!(matches!(first_rx.try_recv()?, Message::GetHeaders(_)));
            assert!(second_rx.try_recv().is_err());
            headers.send(InboundHeaders {
                headers: vec![],
                source: Some(current_source(&peers, first)),

                wire_response: true,
            })?;
            sync.tick();
            assert!(first_rx.try_recv().is_err());
            assert!(second_rx.try_recv().is_err());
            {
                let mut scheduler = sync.scheduler.lock();
                let request = scheduler
                    .headers_sync
                    .get_mut(&current_source(&peers, first))
                    .and_then(|owned| owned.request.as_mut())
                    .ok_or("probe lost its deadline")?;
                request.requested_at -= request.timeout();
            }
            sync.tick();
            assert!(matches!(second_rx.try_recv()?, Message::GetHeaders(_)));
            assert!(first_rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn staged_successors_behind_a_rejected_frontier_still_probe() -> TestResult {
            use bitcoin_rs_consensus::primitives::Amount;
            let (sync, peers, _, blocks, incoming) = sync_with_mined_chain(3)?;
            let peer = test_addr(9761, 0)?;
            let outbound = connect_peer(&peers, synthetic_peer(peer, 0));

            let mut malformed_frontier = blocks[0].clone();
            malformed_frontier.txs[0].outputs[0].value = Amount::from_sat(2);
            assert_eq!(
                malformed_frontier.block_hash(),
                blocks[0].block_hash(),
                "altering body transaction bytes must retain the header-derived hash"
            );
            incoming.send(bitcoin_rs_wire::InboundBlock::from_local(
                malformed_frontier,
            ))?;
            incoming.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[1].clone()))?;
            incoming.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[2].clone()))?;

            sync.tick();

            let probe = next_getheaders(&outbound)?;
            assert_eq!(
                probe
                    .locator_hashes
                    .first()
                    .map(|hash| *hash.as_byte_array()),
                Some(*Network::Regtest.genesis_block().block_hash().as_bytes()),
                "the probe must start from the applied chain"
            );

            let body = sync.scheduler.lock();
            assert_eq!(body.stager.received_len(), 2);
            assert!(!body.stager.contains(&Hash256::from(blocks[0].block_hash())));
            drop(body);

            Ok(())
        }

        #[test]
        fn superseded_session_gets_no_probe_and_cannot_send_getheaders() -> TestResult {
            let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
            let peer = test_addr(9762, 0)?;
            let old_rx = connect_peer(&peers, synthetic_peer(peer, 1));
            let old_source = current_source(&peers, peer);

            let (replacement_tx, replacement_rx) = bitcoin_rs_wire::test_support::message_channel();
            peers.register(peer, PeerLease::new(replacement_tx));

            sync.tick();

            let mut saw_getheaders = false;
            while let Ok(message) = replacement_rx.try_recv() {
                if matches!(message, Message::GetHeaders(_)) {
                    saw_getheaders = true;
                }
            }
            assert!(
                !saw_getheaders,
                "handshaking replacement must receive no probe"
            );
            let mut stale_getheaders = false;
            while let Ok(message) = old_rx.try_recv() {
                if matches!(message, Message::GetHeaders(_)) {
                    stale_getheaders = true;
                }
            }
            assert!(
                !stale_getheaders,
                "superseded session must receive no probe"
            );

            let genesis = Network::Regtest.genesis_block().block_hash();
            let locator = vec![Hash256::from_le_bytes(genesis.as_bytes())];
            assert!(
                sync.send_getheaders(old_source, 0, 10, locator)
                    != super::super::GetheadersOutcome::Sent,
                "lease_source must reject a superseded session identity"
            );
            assert!(
                sync.scheduler.lock().header_request().is_none(),
                "a rejected send must not leave scheduler state behind"
            );
            Ok(())
        }

        #[test]
        fn frontier_probe_preserves_another_live_header_request() -> TestResult {
            let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
            let first = test_addr(9764, 0)?;
            let second = test_addr(9764, 1)?;
            let first_rx = connect_peer(&peers, synthetic_peer(first, 1));
            let second_rx = connect_peer(&peers, synthetic_peer(second, 1));
            let first_source = current_source(&peers, first);
            let second_source = current_source(&peers, second);

            sync.chain.bootstrap_genesis();
            let now = Instant::now();
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), now);
            let probe_source = match frontier.plan().header_action {
                super::super::HeaderAction::Probe(source) => source,
                action => {
                    return Err(crate::test_support::TestError::Unexpected(format!(
                        "expected a frontier probe, got {action:?}"
                    )));
                }
            };
            let (existing_source, existing_rx, probe_rx) = if probe_source == first_source {
                (second_source, &second_rx, &first_rx)
            } else {
                (first_source, &first_rx, &second_rx)
            };

            let genesis = Network::Regtest.genesis_block().block_hash();
            assert_eq!(
                sync.send_getheaders(
                    existing_source,
                    0,
                    1,
                    vec![Hash256::from_le_bytes(genesis.as_bytes())],
                ),
                super::super::GetheadersOutcome::Sent,
                "the other peer must own a live request before the stale probe runs"
            );
            assert!(matches!(existing_rx.try_recv()?, Message::GetHeaders(_)));

            assert_eq!(
                sync.probe_frontier_peer(&frontier, probe_source),
                super::super::GetheadersOutcome::Sent,
                "the frontier probe must send its request"
            );
            assert!(
                matches!(probe_rx.try_recv()?, Message::GetHeaders(_)),
                "the probe peer must receive the probe getheaders"
            );

            assert_eq!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .map(|request| request.source),
                Some(existing_source),
                "the frontier probe must not replace the other peer's live request"
            );
            Ok(())
        }

        #[test]
        fn failed_probe_send_falls_back_to_best_peer_in_the_same_tick() -> TestResult {
            let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_bytes: 0,
                    max_received_bytes: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let low = test_addr(9763, 0)?;
            let high = test_addr(9763, 1)?;
            let dead_rx = connect_peer(&peers, synthetic_peer(low, 1));
            drop(dead_rx);
            let high_rx = connect_peer(&peers, synthetic_peer(high, 5));

            sync.tick();
            assert!(
                !peers
                    .sessions()
                    .iter()
                    .any(|session| session.endpoint == low.endpoint()),
                "the failed probe source must be evicted instead of lingering table-resident",
            );

            let request = next_getheaders(&high_rx)?;
            assert_eq!(
                request
                    .locator_hashes
                    .first()
                    .map(|hash| *hash.as_byte_array()),
                Some(*expected[0].as_bytes()),
                "the fallback request must start at the header tip"
            );

            assert_eq!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .map(|request| request.source.endpoint),
                Some(high.endpoint()),
                "the fallback owner must hold the pending request"
            );
            assert!(high_rx.try_recv().is_err());

            Ok(())
        }

        #[test]
        fn failed_probe_send_excludes_dead_highest_peer_from_header_fallback() -> TestResult {
            let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_bytes: 0,
                    max_received_bytes: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let dead = test_addr(9764, 0)?;
            let live = test_addr(9764, 1)?;
            let dead_rx = connect_peer(&peers, synthetic_peer(dead, 5));
            drop(dead_rx);
            let live_rx = connect_peer(&peers, synthetic_peer(live, 3));

            sync.tick();

            let request = next_getheaders(&live_rx)?;
            assert_eq!(
                request
                    .locator_hashes
                    .first()
                    .map(|hash| *hash.as_byte_array()),
                Some(*expected[0].as_bytes()),
                "the fallback request must start at the header tip"
            );
            assert_eq!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .map(|request| request.source.endpoint),
                Some(live.endpoint()),
                "the lower live peer must own the fallback request"
            );
            assert!(live_rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn dead_probe_peer_is_evicted_and_not_repicked_on_the_next_tick() -> TestResult {
            let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_bytes: 0,
                    max_received_bytes: 0,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let dead = test_addr(9766, 0)?;
            let live = test_addr(9766, 1)?;
            let dead_rx = connect_peer(&peers, synthetic_peer(dead, 5));
            drop(dead_rx);
            let live_rx = connect_peer(&peers, synthetic_peer(live, 3));

            sync.tick();
            let request = next_getheaders(&live_rx)?;
            assert_eq!(
                request
                    .locator_hashes
                    .first()
                    .map(|hash| *hash.as_byte_array()),
                Some(*expected[0].as_bytes()),
                "the fallback request must start at the header tip"
            );

            {
                let mut scheduler = sync.scheduler.lock();
                let request = scheduler
                    .headers_sync
                    .get_mut(&current_source(&peers, live))
                    .and_then(|owned| owned.request.as_mut())
                    .ok_or("fallback lost its deadline")?;
                request.requested_at -= request.timeout();
            }

            sync.tick();
            assert!(
                !peers
                    .sessions()
                    .iter()
                    .any(|session| session.endpoint == dead.endpoint()),
                "the dead peer session must not survive into the next tick",
            );
            assert_ne!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .map(|request| request.source.endpoint),
                Some(dead.endpoint()),
                "the pending request must not be keyed to the dead addr",
            );
            let request = next_getheaders(&live_rx)?;
            assert_eq!(
                request
                    .locator_hashes
                    .first()
                    .map(|hash| *hash.as_byte_array()),
                Some(*Network::Regtest.genesis_block().block_hash().as_bytes()),
                "the live peer must own the follow-up header request",
            );
            assert!(live_rx.try_recv().is_err());
            Ok(())
        }

        #[test]
        fn reconciler_sweeps_cancelled_lease_sessions_within_one_tick() -> TestResult {
            let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
            let addr = test_addr(9767, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(addr, 5));
            peers.lease(addr).ok_or("peer missing from table")?.cancel();
            assert!(
                peers
                    .sessions()
                    .iter()
                    .any(|session| session.endpoint == addr.endpoint())
            );
            sync.tick();
            assert!(
                !peers
                    .sessions()
                    .iter()
                    .any(|session| session.endpoint == addr.endpoint()),
                "the reconciler must sweep cancelled-lease sessions",
            );
            Ok(())
        }

        #[test]
        fn reorg_probe_anchors_locator_on_active_chain_at_applied_height() -> TestResult {
            let genesis = Network::Regtest.genesis_block();
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;

            let common = regtest_fixture::mined_block_with_prev_hash(
                genesis.block_hash(),
                1,
                vec![regtest_fixture::coinbase(1)],
            )
            .or_fail("regtest fixture block");
            let common_id =
                tree.insert_node(Some(genesis_id), common.header, NodeStatus::HeaderValid)?;

            let losing_2 = regtest_fixture::mined_block_with_prev_hash(
                common.block_hash(),
                2,
                vec![regtest_fixture::coinbase(2_002)],
            )
            .or_fail("regtest fixture block");
            let losing_2_id =
                tree.insert_node(Some(common_id), losing_2.header, NodeStatus::HeaderValid)?;
            let losing_3 = regtest_fixture::mined_block_with_prev_hash(
                losing_2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(2_003)],
            )
            .or_fail("regtest fixture block");
            let losing_3_id =
                tree.insert_node(Some(losing_2_id), losing_3.header, NodeStatus::HeaderValid)?;

            let winning_2 = regtest_fixture::mined_block_with_prev_hash(
                common.block_hash(),
                2,
                vec![regtest_fixture::coinbase(1_002)],
            )
            .or_fail("regtest fixture block");
            let winning_2_id =
                tree.insert_node(Some(common_id), winning_2.header, NodeStatus::HeaderValid)?;
            let winning_3 = regtest_fixture::mined_block_with_prev_hash(
                winning_2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(1_003)],
            )
            .or_fail("regtest fixture block");
            let winning_3_id = tree.insert_node(
                Some(winning_2_id),
                winning_3.header,
                NodeStatus::HeaderValid,
            )?;
            let winning_4 = regtest_fixture::mined_block_with_prev_hash(
                winning_3.block_hash(),
                4,
                vec![regtest_fixture::coinbase(1_004)],
            )
            .or_fail("regtest fixture block");
            let winning_4_id = tree.insert_node(
                Some(winning_3_id),
                winning_4.header,
                NodeStatus::HeaderValid,
            )?;

            let active_tip = tree.tip().ok_or("missing active tip")?;
            assert_eq!(active_tip.tip_id, winning_4_id);
            let active_anchor = tree
                .node_at_height_from(winning_4_id, 3)
                .ok_or("missing active height-3 anchor")?;
            assert_eq!(active_anchor, winning_3_id);
            let active_anchor_hash = tree.node(active_anchor)?.hash;
            let losing_tip = tree.node(losing_3_id)?;
            let losing_snapshot = TipSnapshot {
                tip_id: losing_3_id,
                chain_tx_count: losing_tip.chain_tx_count,
                height: losing_tip.height,
                chainwork: losing_tip.chainwork,
                hash: losing_tip.hash,
            };

            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx: _headers_tx,
                inbound_blocks_tx: _blocks_tx,
                ..
            } = SyncHarness::new(tree);
            applied_tip.store(Some(Arc::new(losing_snapshot)));

            let peer = test_addr(9765, 0)?;
            let outbound = connect_peer(&peers, synthetic_peer(peer, 0));
            sync.tick();

            let probe = next_getheaders(&outbound)?;
            let locator_tip = probe
                .locator_hashes
                .first()
                .ok_or("probe locator is empty")?;
            assert_eq!(
                *locator_tip.as_byte_array(),
                active_anchor_hash.to_le_bytes(),
                "idle recovery must anchor at the active-chain node at applied height",
            );
            assert_ne!(
                *locator_tip.as_byte_array(),
                *losing_3.block_hash().as_bytes(),
                "the losing applied tip must never anchor a deep-reorg recovery probe",
            );
            Ok(())
        }

        #[test]
        fn unsolicited_staged_body_never_rewinds_request_cursor() -> TestResult {
            let (sync, peers, applied, blocks, incoming) = sync_with_mined_chain(4)?;
            let peer = test_addr(9766, 0)?;
            let outbound = connect_peer(&peers, synthetic_peer(peer, 4));
            sync.tick();
            let hashes: Vec<_> = blocks.iter().map(Block::block_hash).collect();
            assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
            for block in blocks.into_iter().take(3) {
                incoming.send(bitcoin_rs_wire::InboundBlock::from_local(block))?;
            }
            sync.tick();
            assert_eq!(applied.load_full().ok_or("missing applied tip")?.height, 3);
            let cursor = sync.scheduler.lock().window.request_cursor();
            assert!(cursor > 3, "the cursor advanced past the requested heights");

            sync.scheduler.lock().stager = crate::p2p::BlockStager::new(super::super::SyncBudget {
                received_timeout: Duration::ZERO,
                ..super::super::default_sync_budget(Network::Regtest)
            });
            let orphan = regtest_fixture::mined_block_with_prev_hash(
                BlockHash::from(Hash256::from_le_bytes(&[0x5a; 32])),
                9,
                vec![regtest_fixture::coinbase(9)],
            )
            .or_fail("regtest fixture block");
            let orphan_hash = Hash256::from(orphan.block_hash());
            let mut inbound = vec![bitcoin_rs_wire::InboundBlock::from_local(orphan)];
            assert_eq!(sync.buffer_received_block_chunk(&mut inbound, None), 1);
            assert!(sync.scheduler.lock().stager.contains(&orphan_hash));

            sync.tick();

            let scheduler = sync.scheduler.lock();
            assert!(
                !scheduler.stager.contains(&orphan_hash),
                "expiry pruned the body"
            );
            assert_eq!(
                scheduler.window.request_cursor(),
                cursor,
                "a pruned body of unknown height must not move the request cursor"
            );
            drop(scheduler);
            assert_no_getdata(&outbound)?;
            Ok(())
        }
    }

    mod chain_sync {
        use std::time::Duration;

        use super::*;
        use crate::p2p::download_window::MINIMUM_CONNECT_TIME;
        use crate::p2p::sync::GetheadersOutcome;
        use crate::p2p::sync::frontier::UsablePeer;
        use crate::p2p::sync::peers::{
            ChainSyncAction, ChainSyncState, HEADERS_RESPONSE_TIME, chain_sync_subject,
            consider_eviction,
        };
        use bitcoin_rs_wire::peer_info::PeerRole;

        fn outbound(port: u16, height: u32, role: PeerRole, at: Instant) -> UsablePeer {
            let addr = PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
            ));
            UsablePeer {
                source: PeerSource::for_test(addr),
                info: synthetic_peer(addr, i32::try_from(height).unwrap_or(i32::MAX)),
                demonstrated_tips: vec![Hash256::from_le_bytes(&[0x7c; 32])],
                active_height: Some(height),
                headers_horizon: None,
                role,
                manual: false,
                connected_at: at,
            }
        }

        fn inbound(port: u16, height: u32, at: Instant) -> UsablePeer {
            let mut peer = outbound(port, height, PeerRole::FullRelay, at);
            peer.info.inbound = true;
            peer
        }

        fn claiming(port: u16, height: u32, at: Instant) -> UsablePeer {
            let mut peer = outbound(port, height, PeerRole::FullRelay, at);
            peer.demonstrated_tips.clear();
            peer
        }

        fn pinned(port: u16, height: u32, at: Instant) -> UsablePeer {
            let mut peer = outbound(port, height, PeerRole::FullRelay, at);
            peer.manual = true;
            peer
        }

        #[test]
        fn a_claimed_height_without_headers_is_probed_then_retired() {
            let t0 = Instant::now();
            let peer = claiming(9_603, 100, t0);
            let mut state = ChainSyncState::default();
            let mut protected = 0;

            assert_eq!(
                consider_eviction(&peer, &mut state, 100, t0, &mut protected),
                None,
                "the first tick arms the silent claimant"
            );
            assert!(
                !state.is_protected(),
                "a height the peer only claimed earns no protection"
            );
            assert_eq!(protected, 0, "the protection pool is untouched");
            assert_eq!(
                consider_eviction(
                    &peer,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(20),
                    &mut protected
                ),
                Some(ChainSyncAction::Probe),
                "the claimant answers to the timeout"
            );
            assert_eq!(
                consider_eviction(
                    &peer,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(22),
                    &mut protected
                ),
                Some(ChainSyncAction::Evict),
                "and it is retired when the probe goes unanswered"
            );
        }

        #[test]
        fn behind_tip_connection_is_probed_then_retired() {
            let t0 = Instant::now();
            let peer = outbound(9_601, 99, PeerRole::FullRelay, t0);
            let mut state = ChainSyncState::default();
            let mut protected = 0;

            assert_eq!(
                consider_eviction(&peer, &mut state, 100, t0, &mut protected),
                None,
                "the first sight of a lagging connection only arms it"
            );
            assert_eq!(
                consider_eviction(
                    &peer,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(19),
                    &mut protected
                ),
                None,
                "nineteen minutes of silence is still inside the timeout"
            );
            assert_eq!(
                consider_eviction(
                    &peer,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(20),
                    &mut protected
                ),
                Some(ChainSyncAction::Probe),
                "at the timeout the connection gets exactly one probe"
            );
            assert_eq!(
                consider_eviction(
                    &peer,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(21),
                    &mut protected
                ),
                None,
                "the response window is still open"
            );
            assert_eq!(
                consider_eviction(
                    &peer,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(22),
                    &mut protected
                ),
                Some(ChainSyncAction::Evict),
                "a window later, with nothing to show, it is retired"
            );
            assert_eq!(protected, 0, "a lagging connection earns no protection");
        }

        #[test]
        fn tip_reaching_connection_is_protected_from_the_timer() {
            let t0 = Instant::now();
            let at_tip = outbound(9_602, 100, PeerRole::FullRelay, t0);
            let mut state = ChainSyncState::default();
            let mut protected = 0;

            assert_eq!(
                consider_eviction(&at_tip, &mut state, 100, t0, &mut protected),
                None
            );
            assert_eq!(protected, 1, "the connection took a protection slot");

            for minutes in [30, 60, 120] {
                assert_eq!(
                    consider_eviction(
                        &at_tip,
                        &mut state,
                        500,
                        t0 + Duration::from_secs(minutes * 60),
                        &mut protected
                    ),
                    None,
                    "a protected connection is never probed or retired at {minutes} minutes"
                );
            }
            assert_eq!(protected, 1, "protection is not counted twice");
        }

        #[test]
        fn protection_is_bounded_to_four_connections() {
            let t0 = Instant::now();
            let mut protected = 0;
            let mut states = Vec::new();
            for idx in 0..4_u16 {
                let peer = outbound(9_610 + idx, 100, PeerRole::FullRelay, t0);
                let mut state = ChainSyncState::default();
                assert_eq!(
                    consider_eviction(&peer, &mut state, 100, t0, &mut protected),
                    None
                );
                states.push(state);
            }
            assert_eq!(protected, 4, "the protection pool is full");
            assert!(
                states.iter().all(ChainSyncState::is_protected),
                "each of the four holds protection"
            );

            let fifth = outbound(9_614, 99, PeerRole::FullRelay, t0);
            let mut state = ChainSyncState::default();
            assert_eq!(
                consider_eviction(&fifth, &mut state, 100, t0, &mut protected),
                None,
                "the fifth connection is armed, not protected"
            );
            assert_eq!(
                consider_eviction(
                    &fifth,
                    &mut state,
                    100,
                    t0 + Duration::from_mins(20),
                    &mut protected
                ),
                Some(ChainSyncAction::Probe),
                "and it answers to the timer"
            );
        }

        #[test]
        fn only_aged_outbound_full_relay_connections_are_subjects() {
            let t0 = Instant::now();
            let aged = t0 + MINIMUM_CONNECT_TIME;
            assert!(chain_sync_subject(
                &outbound(9_620, 1, PeerRole::FullRelay, t0),
                aged
            ));
            assert!(
                !chain_sync_subject(
                    &outbound(9_621, 1, PeerRole::FullRelay, t0),
                    t0 + Duration::from_secs(29)
                ),
                "a connection younger than the minimum is not judged"
            );
            assert!(
                !chain_sync_subject(&outbound(9_622, 1, PeerRole::BlockRelayOnly, t0), aged),
                "a block-relay-only connection is never asked to bring a chain"
            );
            assert!(
                !chain_sync_subject(&inbound(9_623, 1, t0), aged),
                "an inbound connection is never timed out"
            );
            assert!(
                !chain_sync_subject(&pinned(9_624, 1, t0), aged),
                "the operator asked for this one by name, so the timer never judges it"
            );
        }

        #[test]
        fn progress_to_the_benchmark_re_arms_the_timeout() {
            let t0 = Instant::now();
            let mut state = ChainSyncState::default();
            let mut protected = 0;
            let lagging = outbound(9_604, 99, PeerRole::FullRelay, t0);
            assert_eq!(
                consider_eviction(&lagging, &mut state, 100, t0, &mut protected),
                None,
                "the first sight of the lag arms it with the tip-100 benchmark"
            );

            let at_benchmark = outbound(9_604, 100, PeerRole::FullRelay, t0);
            assert_eq!(
                consider_eviction(
                    &at_benchmark,
                    &mut state,
                    150,
                    t0 + Duration::from_mins(19),
                    &mut protected
                ),
                None,
                "reaching the benchmark is progress, not a conviction"
            );
            assert_eq!(
                consider_eviction(
                    &at_benchmark,
                    &mut state,
                    150,
                    t0 + Duration::from_mins(20),
                    &mut protected
                ),
                None,
                "the re-armed window runs twenty minutes from the progress, not the first arm"
            );
            assert_eq!(
                consider_eviction(
                    &at_benchmark,
                    &mut state,
                    150,
                    t0 + Duration::from_mins(39),
                    &mut protected
                ),
                Some(ChainSyncAction::Probe),
                "twenty minutes after the re-arm it owes the probe"
            );
            assert_eq!(
                consider_eviction(
                    &at_benchmark,
                    &mut state,
                    150,
                    t0 + Duration::from_mins(41),
                    &mut protected
                ),
                Some(ChainSyncAction::Evict),
                "and the response window still closes on it"
            );
        }

        #[test]
        #[expect(clippy::expect_used)]
        fn an_unsent_chain_sync_probe_arms_no_response_window() {
            let t0 = Instant::now();
            let (mut tree, blocks) = mined_chain(1, 1).expect("fixture chain mines");
            let chain_tip = tree.tip_handle();
            let sync = Arc::new(BlockSync::new(
                Arc::new(TestChain::new(
                    chain_tip,
                    Arc::new(ArcSwapOption::empty()),
                    Arc::new(RwLock::new(tree)),
                )),
                Arc::new(PeerTable::new()),
                {
                    let (_tx, rx) = unbounded::<bitcoin_rs_wire::InboundHeaders>();
                    rx
                },
                {
                    let (_tx, rx) = unbounded::<bitcoin_rs_wire::InboundBlock>();
                    rx
                },
                super::synced_ibd_latch(),
            ));
            sync.chain.bootstrap_genesis();
            stage_body(&sync, &blocks[0]);

            let chain_frontier = sync.observe_chain_frontier();
            let frontier = sync.observe_frontier(chain_frontier, t0);
            let subject = outbound(9_630, 0, PeerRole::FullRelay, t0);

            assert!(
                frontier.chain.next_required.is_some(),
                "premise: the fixture owes a body, so the frontier can be owned"
            );
            assert!(
                !sync.probe_chain_sync(subject.source, &frontier),
                "a probe that never reached the wire is not a probe"
            );
            assert!(
                !sync
                    .scheduler
                    .lock()
                    .chain_sync
                    .contains_key(&subject.source),
                "no response window is armed for a probe the connection never received"
            );
        }

        #[test]
        #[expect(clippy::expect_used)]
        fn chain_sync_probe_locator_anchors_at_the_header_tips_parent() {
            let t0 = Instant::now();
            let (tree, _blocks) = mined_chain(1, 2).expect("fixture chain mines");
            let SyncHarness {
                sync,
                peers,
                block_tree,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let chain_frontier = sync.observe_chain_frontier();
            let frontier = sync.observe_frontier(chain_frontier, t0);
            let tip = frontier
                .chain
                .chain_tip
                .as_ref()
                .expect("the fixture mines a header tip")
                .clone();
            assert_eq!(tip.height, 3, "premise: header tip is height 3");

            let addr = test_addr(9_900, 0).expect("test address builds");
            let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
            let outcome = sync.send_chain_sync_probe(&frontier, current_source(&peers, addr));
            assert_eq!(outcome, GetheadersOutcome::Sent);

            let Ok(Message::GetHeaders(getheaders)) = rx.try_recv() else {
                panic!("the probe enqueues one getheaders");
            };
            let parent = block_tree
                .read()
                .node(tip.tip_id)
                .expect("tip is in the tree")
                .parent
                .expect("a height-3 tip has a parent");
            let expected = block_tree
                .read()
                .node(parent)
                .expect("parent is in the tree")
                .hash;
            assert_eq!(
                getheaders.locator_hashes.first(),
                Some(&bitcoin::BlockHash::from_byte_array(
                    *expected.as_byte_array()
                )),
                "the locator roots at the header tip's parent so the answer carries the tip"
            );
        }

        #[test]
        fn frontier_and_eviction_probes_do_not_overwrite_live_requests() -> TestResult {
            let (tree, blocks) = mined_chain(1, 2)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let peers = harness.peers;
            let inbound_headers_tx = harness.inbound_headers_tx;
            sync.chain.bootstrap_genesis();

            let addr = test_addr(9_940, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
            let source = current_source(&peers, addr);
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            let request_snapshot = || {
                let scheduler = sync.scheduler.lock();
                let request = scheduler.headers_sync.get(&source)?.request?;
                Some((
                    request.locator_tip_hash,
                    request.target_height,
                    request.requested_at,
                    request.state,
                    request.kind,
                ))
            };
            let header_tip = frontier
                .chain
                .chain_tip
                .as_ref()
                .ok_or("the fixture must have a header tip")?;
            let chain_probe_locator = {
                let tree = sync.chain.block_tree();
                let parent = tree
                    .node(header_tip.tip_id)
                    .ok()
                    .and_then(|node| node.parent)
                    .ok_or("the header tip must have a parent")?;
                tree.node(parent)
                    .ok()
                    .map(|node| node.hash)
                    .ok_or("the parent must be in the tree")?
            };

            assert_eq!(
                sync.probe_frontier_peer(&frontier, source),
                GetheadersOutcome::Sent,
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            let frontier_request =
                request_snapshot().ok_or("the frontier request was not registered")?;
            assert_ne!(
                frontier_request.0, chain_probe_locator,
                "the two probe classes ask from different locators",
            );
            assert_eq!(
                (frontier_request.3, frontier_request.4),
                (
                    super::super::HeaderRequestState::AwaitingResponse,
                    super::super::HeaderRequestKind::Frontier,
                ),
            );
            assert!(
                !sync.probe_chain_sync(source, &frontier),
                "an eviction probe cannot borrow a frontier request's response",
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(request_snapshot(), Some(frontier_request));

            inbound_headers_tx.send(bitcoin_rs_wire::InboundHeaders {
                headers: vec![blocks[0].header],
                source: Some(source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            let _ = rx.try_iter().collect::<Vec<_>>();
            assert!(
                !sync.scheduler.lock().headers_sync.contains_key(&source),
                "the real wire answer must consume the frontier request",
            );

            assert!(
                sync.probe_chain_sync(source, &frontier),
                "an unowned source can receive its eviction probe",
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            let eviction_request =
                request_snapshot().ok_or("the eviction probe was not registered")?;
            assert_eq!(eviction_request.0, chain_probe_locator);
            assert_eq!(
                (eviction_request.3, eviction_request.4),
                (
                    super::super::HeaderRequestState::AwaitingResponse,
                    super::super::HeaderRequestKind::ChainSyncProbe,
                ),
            );
            assert_eq!(
                sync.send_getheaders(
                    source,
                    0,
                    i32::try_from(frontier_request.1).unwrap_or(i32::MAX),
                    vec![frontier_request.0],
                ),
                GetheadersOutcome::Suppressed,
                "a frontier request cannot overwrite the live eviction probe",
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(request_snapshot(), Some(eviction_request));
            Ok(())
        }

        #[test]
        fn chain_sync_probe_holds_request_for_its_response_window() -> TestResult {
            let (tree, blocks) = mined_chain(1, 2)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let peers = harness.peers;
            let inbound_headers_tx = harness.inbound_headers_tx;
            sync.chain.bootstrap_genesis();

            let addr = test_addr(9_942, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
            let source = current_source(&peers, addr);
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            assert!(sync.probe_chain_sync(source, &frontier));
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            let request_snapshot = || {
                let scheduler = sync.scheduler.lock();
                let request = scheduler.headers_sync.get(&source)?.request?;
                Some((
                    request.locator_tip_hash,
                    request.target_height,
                    request.requested_at,
                    request.state,
                    request.kind,
                ))
            };
            let probe_request = request_snapshot().ok_or("the probe request was not registered")?;
            assert_eq!(
                probe_request.4,
                super::super::HeaderRequestKind::ChainSyncProbe,
            );
            let competing_locator = Hash256::default();
            let competing_target = i32::MAX;
            assert_ne!(probe_request.0, competing_locator);
            assert_ne!(
                probe_request.1,
                u32::try_from(competing_target).unwrap_or(0),
            );
            let request_age = HEADERS_RESPONSE_TIME
                .checked_sub(Duration::from_secs(10))
                .ok_or("the probe response window must exceed its margin")?;
            assert!(request_age > super::super::HEADER_REQUEST_TIMEOUT);
            {
                let mut scheduler = sync.scheduler.lock();
                let request = scheduler
                    .headers_sync
                    .get_mut(&source)
                    .and_then(|owned| owned.request.as_mut())
                    .ok_or("the probe request must still be registered")?;
                request.requested_at = Instant::now()
                    .checked_sub(request_age)
                    .ok_or("the test instant must allow the probe age")?;
            }
            let aged_request = request_snapshot().ok_or("the aged probe must remain registered")?;
            assert_eq!(
                sync.send_getheaders(source, 0, competing_target, vec![competing_locator],),
                GetheadersOutcome::Suppressed,
                "an unanswered chain-sync probe owns its connection for two minutes",
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(request_snapshot(), Some(aged_request));

            inbound_headers_tx.send(bitcoin_rs_wire::InboundHeaders {
                headers: vec![blocks[0].header],
                source: Some(source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            let _ = rx.try_iter().collect::<Vec<_>>();
            assert!(
                !sync.scheduler.lock().headers_sync.contains_key(&source),
                "the nonempty wire answer must release the probe request",
            );
            assert_eq!(
                sync.send_getheaders(source, 0, competing_target, vec![competing_locator],),
                GetheadersOutcome::Sent,
                "a real answer frees the connection for frontier work",
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            assert_eq!(
                sync.scheduler
                    .lock()
                    .headers_sync
                    .get(&source)
                    .and_then(|owned| owned.request)
                    .map(|request| request.kind),
                Some(super::super::HeaderRequestKind::Frontier),
            );
            Ok(())
        }

        #[test]
        fn queued_probe_answer_defers_eviction_until_admission() -> TestResult {
            let (tree, blocks) = mined_chain(1, 2)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let addr = test_addr(9_943, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
            let source = current_source(&peers, addr);
            let now = Instant::now();
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), now);
            let peer = frontier
                .usable_peers
                .iter()
                .find(|peer| peer.source == source)
                .ok_or("missing probe source")?;
            let height = frontier
                .chain
                .chain_tip
                .as_ref()
                .ok_or("missing tip")?
                .height;
            let mut state = ChainSyncState::default();
            let mut protected = 0;
            assert_eq!(
                consider_eviction(
                    peer,
                    &mut state,
                    height,
                    now.checked_sub(Duration::from_mins(20))
                        .ok_or("clock underflow")?,
                    &mut protected
                ),
                None,
            );
            assert_eq!(
                consider_eviction(peer, &mut state, height, now, &mut protected),
                Some(ChainSyncAction::Probe),
            );
            sync.scheduler.lock().chain_sync.insert(source, state);
            assert!(sync.probe_chain_sync(source, &frontier));
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            sync.note_header_response_received(source);
            inbound_headers_tx.send(bitcoin_rs_wire::InboundHeaders {
                headers: vec![blocks[0].header],
                source: Some(source),
                wire_response: true,
            })?;
            let expired = now + HEADERS_RESPONSE_TIME;
            sync.retire_timed_out_header_syncs(expired);
            assert!(!sync.sweep_chain_sync(&frontier, expired));
            assert!(peers.is_connected(addr));
            sync.drain_inbound_headers();
            assert!(!sync.scheduler.lock().headers_sync.contains_key(&source));
            assert!(peers.is_connected(addr));
            Ok(())
        }

        #[test]
        fn replacing_expired_frontier_with_chain_sync_probe_releases_owner() -> TestResult {
            let (tree, _blocks) = mined_chain(1, 2)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let peers = harness.peers;
            sync.chain.bootstrap_genesis();

            let frontier_addr = test_addr(9_943, 0)?;
            let other_addr = test_addr(9_944, 0)?;
            let frontier_rx = connect_peer(&peers, synthetic_peer(frontier_addr, i32::MAX));
            let other_rx = connect_peer(&peers, synthetic_peer(other_addr, i32::MAX));
            let frontier_source = current_source(&peers, frontier_addr);
            let other_source = current_source(&peers, other_addr);
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());

            assert_eq!(
                sync.probe_frontier_peer(&frontier, frontier_source),
                GetheadersOutcome::Sent,
            );
            assert!(matches!(frontier_rx.try_recv()?, Message::GetHeaders(_)));
            {
                let mut scheduler = sync.scheduler.lock();
                let request = scheduler
                    .headers_sync
                    .get_mut(&frontier_source)
                    .and_then(|owned| owned.request.as_mut())
                    .ok_or("the frontier request must be registered")?;
                assert_eq!(request.kind, super::super::HeaderRequestKind::Frontier,);
                request.requested_at = Instant::now()
                    .checked_sub(request.timeout())
                    .ok_or("the frontier request must be expired")?;
            }

            assert!(sync.probe_chain_sync(frontier_source, &frontier));
            assert!(matches!(frontier_rx.try_recv()?, Message::GetHeaders(_)));
            let probe_snapshot = {
                let scheduler = sync.scheduler.lock();
                assert_eq!(scheduler.header_request_owner, None);
                assert!(scheduler.header_request().is_none());
                let request = scheduler
                    .headers_sync
                    .get(&frontier_source)
                    .and_then(|owned| owned.request)
                    .ok_or("the unanswered chain-sync probe must remain registered")?;
                assert_eq!(
                    (request.kind, request.state),
                    (
                        super::super::HeaderRequestKind::ChainSyncProbe,
                        super::super::HeaderRequestState::AwaitingResponse,
                    ),
                );
                (
                    request.locator_tip_hash,
                    request.target_height,
                    request.requested_at,
                    request.state,
                    request.kind,
                )
            };

            assert_eq!(
                sync.send_getheaders(other_source, 0, i32::MAX, vec![Hash256::default()]),
                GetheadersOutcome::Sent,
            );
            assert!(matches!(other_rx.try_recv()?, Message::GetHeaders(_)));
            let scheduler = sync.scheduler.lock();
            assert_eq!(
                scheduler.header_request_owner,
                Some(other_source),
                "frontier pacing must move off the connection now owned by the probe",
            );
            assert_eq!(
                scheduler.header_request().map(|request| request.source),
                Some(other_source),
            );
            let request = scheduler
                .headers_sync
                .get(&frontier_source)
                .and_then(|owned| owned.request)
                .ok_or("the probe must remain outstanding")?;
            assert_eq!(
                (
                    request.locator_tip_hash,
                    request.target_height,
                    request.requested_at,
                    request.state,
                    request.kind,
                ),
                probe_snapshot,
            );
            Ok(())
        }

        #[test]
        fn empty_chain_sync_probe_keeps_original_five_second_pacing() -> TestResult {
            let (tree, _blocks) = mined_chain(1, 2)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let peers = harness.peers;
            let inbound_headers_tx = harness.inbound_headers_tx;
            sync.chain.bootstrap_genesis();

            let addr = test_addr(9_945, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
            let source = current_source(&peers, addr);
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            assert!(sync.probe_chain_sync(source, &frontier));
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            let original_request = sync
                .scheduler
                .lock()
                .headers_sync
                .get(&source)
                .and_then(|owned| owned.request)
                .ok_or("the chain-sync request must be registered")?;
            assert_eq!(
                (original_request.kind, original_request.state),
                (
                    super::super::HeaderRequestKind::ChainSyncProbe,
                    super::super::HeaderRequestState::AwaitingResponse,
                ),
            );
            assert_eq!(
                original_request.timeout(),
                HEADERS_RESPONSE_TIME,
                "only an unanswered probe uses the eviction response window",
            );

            inbound_headers_tx.send(bitcoin_rs_wire::InboundHeaders {
                headers: Vec::new(),
                source: Some(source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();

            let answered_request = sync
                .scheduler
                .lock()
                .headers_sync
                .get(&source)
                .and_then(|owned| owned.request)
                .ok_or("an empty answer retains the pacing request")?;
            assert_eq!(
                answered_request.state,
                super::super::HeaderRequestState::Answered,
            );
            assert_eq!(answered_request.requested_at, original_request.requested_at);
            assert_eq!(
                answered_request.timeout(),
                super::super::HEADER_REQUEST_TIMEOUT,
                "an empty answer returns to ordinary frontier pacing",
            );
            let locator = vec![answered_request.locator_tip_hash];
            let target = i32::try_from(answered_request.target_height).unwrap_or(i32::MAX);
            assert_eq!(
                sync.send_getheaders(source, 0, target, locator.clone()),
                GetheadersOutcome::Suppressed,
            );
            assert!(rx.try_recv().is_err());

            let request_age = answered_request
                .timeout()
                .checked_add(Duration::from_secs(1))
                .ok_or("the test age must fit in a duration")?;
            assert!(request_age < HEADERS_RESPONSE_TIME);
            let expired_at = Instant::now()
                .checked_sub(request_age)
                .ok_or("the test instant must allow the answered age")?;
            {
                let mut scheduler = sync.scheduler.lock();
                scheduler
                    .headers_sync
                    .get_mut(&source)
                    .and_then(|owned| owned.request.as_mut())
                    .ok_or("the answered request must remain registered")?
                    .requested_at = expired_at;
            }
            sync.retire_timed_out_header_syncs(Instant::now());
            let retained_request = sync
                .scheduler
                .lock()
                .headers_sync
                .get(&source)
                .and_then(|owned| owned.request)
                .ok_or("an answered request is not a silence timeout")?;
            assert_eq!(
                retained_request.state,
                super::super::HeaderRequestState::Answered
            );
            assert_eq!(retained_request.requested_at, expired_at);
            assert_eq!(
                sync.send_getheaders(source, 0, target, locator),
                GetheadersOutcome::Sent,
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            Ok(())
        }

        #[test]
        fn expired_chain_sync_probe_does_not_suppress_frontier_request() -> TestResult {
            let (tree, _blocks) = mined_chain(1, 2)?;
            let harness = SyncHarness::new(tree);
            let sync = harness.sync;
            let peers = harness.peers;
            sync.chain.bootstrap_genesis();

            let addr = test_addr(9_941, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
            let source = current_source(&peers, addr);
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            assert!(sync.probe_chain_sync(source, &frontier));
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

            {
                let mut scheduler = sync.scheduler.lock();
                let request = scheduler
                    .headers_sync
                    .get_mut(&source)
                    .and_then(|owned| owned.request.as_mut())
                    .ok_or("the eviction request must be registered")?;
                assert_eq!(
                    request.kind,
                    super::super::HeaderRequestKind::ChainSyncProbe,
                );
                request.requested_at = Instant::now()
                    .checked_sub(HEADERS_RESPONSE_TIME)
                    .ok_or("the test instant must allow the full response window")?;
            }

            assert_eq!(
                sync.send_getheaders(source, 0, 1, vec![Hash256::default()]),
                GetheadersOutcome::Sent,
                "an expired response window must release the request gate",
            );
            assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
            let scheduler = sync.scheduler.lock();
            let request_kind = scheduler
                .headers_sync
                .get(&source)
                .and_then(|owned| owned.request)
                .map(|request| request.kind);
            assert_eq!(
                request_kind,
                Some(super::super::HeaderRequestKind::Frontier),
            );
            Ok(())
        }

        #[test]
        fn failed_sweep_probe_requests_headers_from_live_peer_in_same_tick() -> TestResult {
            let (tree, _) = mined_chain(0, 0)?;
            let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let now = Instant::now();
            let dead = test_addr(9_921, 0)?;
            let live = test_addr(9_921, 1)?;
            let (tx, dead_rx) = bitcoin_rs_wire::test_support::message_channel();
            let connected_at = now.checked_sub(MINIMUM_CONNECT_TIME).ok_or("connect age")?;
            let lease = PeerLease::new_connected_at(tx, connected_at);
            peers.register(dead, lease.clone());
            peers.publish_info(dead, &lease, synthetic_peer(dead, 5));
            let source = current_source(&peers, dead);
            let live_rx = connect_peer(&peers, synthetic_peer(live, 3));

            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), now);
            let peer = frontier
                .usable_peers
                .iter()
                .find(|peer| peer.source == source)
                .ok_or("missing probe peer")?;
            let mut state = ChainSyncState::default();
            let mut protected = 0;
            assert_eq!(
                consider_eviction(
                    peer,
                    &mut state,
                    0,
                    now.checked_sub(Duration::from_mins(20))
                        .ok_or("timeout start")?,
                    &mut protected,
                ),
                None,
            );
            sync.scheduler.lock().chain_sync.insert(source, state);
            drop(dead_rx);

            sync.tick();

            assert!(
                !peers.is_current(source),
                "the failed sweep probe removes its connection"
            );
            assert!(
                live_rx
                    .try_iter()
                    .any(|message| matches!(message, Message::GetHeaders(_))),
                "the same tick must select the live peer after the sweep probe disconnects the highest claimant"
            );
            assert_eq!(
                sync.scheduler
                    .lock()
                    .header_request()
                    .map(|request| request.source),
                Some(current_source(&peers, live)),
            );
            Ok(())
        }

        #[test]
        fn failed_sweep_probe_reassigns_fresh_inflight_body_in_same_tick() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_pending_blocks: 1,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let now = Instant::now();
            let dead = test_addr(9_922, 0)?;
            let live = test_addr(9_922, 1)?;
            let (tx, dead_rx) = bitcoin_rs_wire::test_support::message_channel();
            let connected_at = now.checked_sub(MINIMUM_CONNECT_TIME).ok_or("connect age")?;
            let lease = PeerLease::new_connected_at(tx, connected_at);
            peers.register(dead, lease.clone());
            peers.publish_info(dead, &lease, synthetic_peer(dead, 5));
            let source = current_source(&peers, dead);
            let chain = sync.observe_chain_frontier();
            assert!(sync.send_getdata_for_pending_blocks(source, 5, &chain).sent);
            assert_eq!(
                witness_block_inventory(next_getdata(&dead_rx)?)?,
                vec![blocks[0].block_hash()]
            );
            let required = Hash256::from(blocks[0].block_hash());
            assert_eq!(
                sync.scheduler.lock().window.pending_owner(&required),
                Some(source)
            );
            let live_rx = connect_peer(&peers, synthetic_peer(live, 3));
            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), now);
            let peer = frontier
                .usable_peers
                .iter()
                .find(|peer| peer.source == source)
                .ok_or("probe peer")?;
            let mut state = ChainSyncState::default();
            let mut protected = 0;
            assert_eq!(
                consider_eviction(
                    peer,
                    &mut state,
                    1,
                    now.checked_sub(Duration::from_mins(20)).ok_or("timeout")?,
                    &mut protected
                ),
                None
            );
            sync.scheduler.lock().chain_sync.insert(source, state);
            drop(dead_rx);

            sync.tick();

            assert!(!peers.is_current(source));
            assert_eq!(
                witness_block_inventory(next_getdata(&live_rx)?)?,
                vec![blocks[0].block_hash()],
                "same tick must reassign the disconnected peer's fresh block request"
            );
            assert_eq!(
                sync.scheduler.lock().window.pending_owner(&required),
                Some(current_source(&peers, live))
            );
            assert!(!sync.scheduler.lock().chain_sync.contains_key(&source));
            Ok(())
        }

        #[test]
        #[expect(clippy::expect_used)]
        fn a_failed_sweep_probe_restores_the_armed_record() {
            let t0 = Instant::now();
            let (tree, _blocks) = mined_chain(1, 1).expect("chain fixture builds");
            let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();

            let addr = test_addr(9_920, 0).expect("test address");
            let (tx, rx) = bitcoin_rs_wire::test_support::message_channel();
            let connected_at = t0
                .checked_sub(MINIMUM_CONNECT_TIME)
                .expect("the test clock predates the connect age");
            let lease = PeerLease::new_connected_at(tx, connected_at);
            peers.register(addr, lease.clone());
            peers.publish_info(addr, &lease, synthetic_peer(addr, 0));
            let source = current_source(&peers, addr);

            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), t0);
            sync.sweep_chain_sync(&frontier, t0);
            {
                let scheduler = sync.scheduler.lock();
                let state = scheduler
                    .chain_sync
                    .get(&source)
                    .expect("the first sweep arms the lagging claimant");
                assert!(
                    !state.probe_sent(),
                    "an armed window has not yet owed a probe"
                );
            }

            drop(rx);
            let stale = sync.observe_frontier(sync.observe_chain_frontier(), t0);
            sync.sweep_chain_sync(&stale, t0 + Duration::from_mins(20));

            let scheduler = sync.scheduler.lock();
            let state = scheduler
                .chain_sync
                .get(&source)
                .expect("a failed probe restores the armed record rather than advancing it");
            assert!(
                !state.probe_sent(),
                "the probe never reached the wire, so no response window is running"
            );
        }
    }
    mod frontier_liveness {
        use super::*;

        fn answer_requests(
            rx: &bitcoin_rs_wire::test_support::MessageReceiver,
            source: PeerSource,
            headers: &[Header],
            bodies: &HashMap<Hash256, Block>,
            inbound_headers_tx: &crossbeam_channel::Sender<InboundHeaders>,
            inbound_blocks_tx: &crossbeam_channel::Sender<bitcoin_rs_wire::InboundBlock>,
        ) -> TestResult {
            while let Ok(message) = rx.try_recv() {
                match message {
                    Message::GetHeaders(_) => {
                        inbound_headers_tx.send(InboundHeaders {
                            headers: headers.to_vec(),
                            source: Some(source),
                            wire_response: true,
                        })?;
                    }
                    Message::GetData(inventory) => {
                        for hash in witness_block_inventory(inventory)? {
                            if let Some(block) = bodies.get(&hash.0) {
                                let mut inbound =
                                    bitcoin_rs_wire::InboundBlock::from_local(block.clone());
                                inbound.source = Some(source);
                                inbound_blocks_tx.send(inbound)?;
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        #[test]
        fn replacements_carry_frontier_after_serving_peer_timeouts() -> TestResult {
            let (tree, mut blocks) = mined_chain(6, 0)?;
            let mut prev = blocks[5].block_hash();
            for height in 7..=8_u32 {
                let block = regtest_fixture::mined_block_with_prev_hash(
                    prev,
                    height,
                    vec![regtest_fixture::coinbase(height)],
                )?;
                prev = block.block_hash();
                blocks.push(block);
            }
            let bodies: HashMap<Hash256, Block> = blocks
                .iter()
                .map(|block| (Hash256::from(block.block_hash()), block.clone()))
                .collect();
            let active: Vec<Header> = blocks[1..6].iter().map(|block| block.header).collect();
            let beyond: Vec<Header> = blocks[6..8].iter().map(|block| block.header).collect();

            let SyncHarness {
                sync,
                peers,
                block_tree: _,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
            } = SyncHarness::new(tree);
            install_budget(
                &sync,
                super::super::SyncBudget {
                    pending_timeout_override: Some(Duration::from_millis(200)),
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );

            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;

            let s1 = test_addr(9821, 0)?;
            let s2 = test_addr(9821, 1)?;
            let _s1_rx = connect_peer(&peers, synthetic_peer(s1, 6));
            let _s2_rx = connect_peer(&peers, synthetic_peer(s2, 6));
            for addr in [s1, s2] {
                let source = current_source(&peers, addr);
                inbound_headers_tx.send(InboundHeaders {
                    headers: active.clone(),
                    source: Some(source),
                    wire_response: false,
                })?;
            }

            sync.tick();
            for _ in 0..24 {
                std::thread::sleep(Duration::from_millis(250));
                sync.tick();
                if !peers.is_connected(s1) && !peers.is_connected(s2) {
                    break;
                }
            }
            assert!(
                !peers.is_connected(s1) && !peers.is_connected(s2),
                "both serving peers must be convicted of the block-request timeout"
            );
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.height),
                Some(1),
                "the fixture must reach the stall state: applied frozen behind the header tip",
            );

            let r1 = test_addr(9821, 2)?;
            let r2 = test_addr(9821, 3)?;
            let r1_rx = connect_peer(&peers, synthetic_peer(r1, 8));
            let r2_rx = connect_peer(&peers, synthetic_peer(r2, 8));
            let r1_source = current_source(&peers, r1);
            let r2_source = current_source(&peers, r2);

            let mut advanced = false;
            for _ in 0..120 {
                std::thread::sleep(Duration::from_millis(50));
                sync.tick();
                answer_requests(
                    &r1_rx,
                    r1_source,
                    &beyond,
                    &bodies,
                    &inbound_headers_tx,
                    &inbound_blocks_tx,
                )?;
                answer_requests(
                    &r2_rx,
                    r2_source,
                    &beyond,
                    &bodies,
                    &inbound_headers_tx,
                    &inbound_blocks_tx,
                )?;
                if applied_tip.load_full().is_some_and(|tip| tip.height >= 6) {
                    advanced = true;
                    break;
                }
            }
            assert!(
                advanced,
                "the apply frontier must advance through the replacements; applied tip: {:?}",
                applied_tip.load_full().map(|tip| tip.height)
            );
            Ok(())
        }

        #[test]
        fn losing_fork_evidence_never_revokes_the_height_a_peer_was_asked_at() -> TestResult {
            let (tree, blocks) = mined_chain(6, 0)?;
            let bodies: HashMap<Hash256, Block> = blocks
                .iter()
                .map(|block| (Hash256::from(block.block_hash()), block.clone()))
                .collect();
            let SyncHarness {
                sync,
                peers,
                block_tree: _,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
            } = SyncHarness::new(tree);
            install_budget(&sync, super::super::default_sync_budget(Network::Regtest));
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().map(|tip| tip.height),
                Some(1),
                "the fixture applies block 1, so the frontier needs block 2's body",
            );

            let p = test_addr(9823, 0)?;
            let p_rx = connect_peer(&peers, synthetic_peer(p, 6));
            let p_source = current_source(&peers, p);
            let fork2 = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)?;
            let fork: Vec<Header> = vec![
                fork2,
                regtest_fixture::mined_regtest_header(fork2.compute_hash(), 3)?,
            ];
            inbound_headers_tx.send(InboundHeaders {
                headers: fork.clone(),
                source: Some(p_source),
                wire_response: false,
            })?;
            sync.tick();

            let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
            let capability = frontier
                .usable_peers
                .iter()
                .find(|peer| peer.source == p_source)
                .and_then(super::super::frontier::UsablePeer::capability);
            assert_eq!(
                capability,
                Some(6),
                "a fork-only answer must not revoke the height the peer was asked at",
            );
            assert_eq!(
                frontier.plan().no_progress,
                None,
                "a peer that claimed the frontier must not leave the frontier reporting no_capable_peer",
            );

            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(20));
                sync.tick();
                answer_requests(
                    &p_rx,
                    p_source,
                    &fork,
                    &bodies,
                    &inbound_headers_tx,
                    &inbound_blocks_tx,
                )?;
                if applied_tip.load_full().is_some_and(|tip| tip.height >= 2) {
                    return Ok(());
                }
            }
            Err(crate::test_support::TestError::Liveness(format!(
                "a peer that holds the frontier block and answers every request must be asked for it; \
         applied tip stayed at {:?}",
                applied_tip.load_full().map(|tip| tip.height)
            )))
        }
    }
    #[cfg(test)]
    mod frontier_model {
        use super::*;

        use super::super::frontier::{
            BodyState, ChainFrontier, HeaderAction, NoProgressReason, RequiredBody, SyncFrontier,
            UsablePeer,
        };
        use crate::p2p::BlockStager;
        use crate::p2p::download_window::{
            BlameReason, BlockedContext, BlockedDecision, DownloadWindow,
        };
        use bitcoin_rs_consensus::header_rules::ChainWork;
        use bitcoin_rs_execution::chain::NodeId;

        fn stall_blame(
            window: &mut DownloadWindow,
            stager: &BlockStager,
            tree: &bitcoin_rs_execution::chain::BlockTree,
            next_apply: u32,
            at: Instant,
        ) -> Option<PeerSource> {
            match window.observe_blocked(
                BlockedContext {
                    next_apply_height: Some(next_apply),
                    frontier_hash: None,
                    apply_side_busy: false,
                },
                stager,
                tree,
                at,
            ) {
                BlockedDecision::Blame {
                    owner,
                    reason: BlameReason::Staller,
                } => Some(owner),
                other @ BlockedDecision::Blame { .. } => {
                    panic!("stall_blame convicted for another reason: {other:?}")
                }
                _ => None,
            }
        }
        fn snap(tip_id: u32, height: u32, hash_byte: u8) -> Arc<TipSnapshot> {
            Arc::new(TipSnapshot {
                tip_id: NodeId::new(tip_id),
                chain_tx_count: bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
                height,
                chainwork: ChainWork::from(u64::from(height) + 1),
                hash: Hash256::from_le_bytes(&[hash_byte; 32]),
            })
        }

        fn hash(byte: u8) -> Hash256 {
            Hash256::from_le_bytes(&[byte; 32])
        }

        fn addr_of(port: u16) -> PeerRemote {
            PeerRemote::Endpoint(bitcoin_rs_wire::PeerEndpoint::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
            ))
        }

        fn usable(port: u16, best_known: i32, active_height: Option<u32>) -> UsablePeer {
            UsablePeer {
                source: PeerSource::for_test(addr_of(port)),
                info: synthetic_peer(addr_of(port), best_known),
                demonstrated_tips: Vec::new(),
                active_height,
                headers_horizon: None,
                role: bitcoin_rs_wire::peer_info::PeerRole::FullRelay,
                manual: false,
                connected_at: Instant::now(),
            }
        }

        fn chain_frontier(required_height: u32, closed_for_recovery: bool) -> ChainFrontier {
            ChainFrontier {
                applied_tip: Some(snap(1, required_height.saturating_sub(1), 0x01)),
                chain_tip: Some(snap(2, required_height + 4, 0x02)),
                next_required: Some(RequiredBody {
                    height: required_height,
                    hash: hash(0x03),
                }),
                closed_for_recovery,
            }
        }

        fn frontier(
            chain: ChainFrontier,
            body_state: Option<BodyState>,
            usable_peers: Vec<UsablePeer>,
        ) -> SyncFrontier {
            SyncFrontier {
                chain,
                body_state,
                header_request: None,
                header_request_live: false,
                usable_peers,
            }
        }

        fn assert_invariant(frontier: &SyncFrontier) -> super::super::frontier::FrontierPlan {
            let plan = frontier.plan();
            if frontier.chain.next_required.is_some() {
                assert!(
                    plan.schedule_bodies || plan.no_progress.is_some(),
                    "unowned/owned body with no scheduled recovery must carry a \
             NoProgressReason: {plan:?}"
                );
            }
            plan
        }

        #[test]
        fn unowned_frontier_schedules_recovery_when_a_capable_peer_exists() {
            let plan = assert_invariant(&frontier(
                chain_frontier(5, false),
                Some(BodyState::Unowned),
                vec![usable(9001, 100, None)],
            ));
            assert!(plan.schedule_bodies);
            assert_eq!(plan.no_progress, None);
            match plan.header_action {
                HeaderAction::Probe(source) => {
                    assert_eq!(source.endpoint, addr_of(9001).endpoint())
                }
                action => panic!("expected Probe, got {action:?}"),
            }
        }

        #[test]
        fn unowned_frontier_with_no_peers_reports_no_usable_peers() {
            let plan = assert_invariant(&frontier(
                chain_frontier(5, false),
                Some(BodyState::Unowned),
                Vec::new(),
            ));
            assert!(!plan.schedule_bodies);
            assert_eq!(plan.no_progress, Some(NoProgressReason::NoUsablePeers));
            assert_eq!(plan.header_action, HeaderAction::Idle);
        }

        #[test]
        fn unowned_frontier_with_only_incapable_peers_reports_no_capable_peer() {
            let plan = assert_invariant(&frontier(
                chain_frontier(5, false),
                Some(BodyState::Unowned),
                vec![usable(9001, 2, None)],
            ));
            assert!(plan.schedule_bodies);
            assert_eq!(plan.no_progress, Some(NoProgressReason::NoCapablePeer));
        }

        #[test]
        fn unowned_frontier_while_apply_halted_reports_apply_halted() {
            let plan = assert_invariant(&frontier(
                chain_frontier(5, true),
                Some(BodyState::Unowned),
                vec![usable(9001, 100, None)],
            ));
            assert!(!plan.schedule_bodies);
            assert_eq!(plan.no_progress, Some(NoProgressReason::ApplyHalted));
        }

        #[test]
        fn in_flight_frontier_on_a_dead_connection_recovers_as_unowned() {
            let dead = PeerSource::for_test(addr_of(9010));
            let plan = assert_invariant(&frontier(
                chain_frontier(5, false),
                Some(BodyState::InFlight(dead)),
                vec![usable(9011, 100, None)],
            ));
            assert!(plan.schedule_bodies);
            assert_eq!(plan.no_progress, None);
        }

        #[test]
        fn in_flight_frontier_on_a_live_owner_is_progress() {
            let live = usable(9010, 100, None);
            let owner = live.source;
            let plan = assert_invariant(&frontier(
                chain_frontier(5, false),
                Some(BodyState::InFlight(owner)),
                vec![live],
            ));
            assert!(plan.schedule_bodies);
            assert_eq!(plan.no_progress, None);
            assert_eq!(plan.header_action, HeaderAction::Extend);
        }

        #[test]
        fn staged_frontier_is_progress_without_recovery() {
            let plan = assert_invariant(&frontier(
                chain_frontier(5, false),
                Some(BodyState::Staged),
                vec![usable(9001, 100, None)],
            ));
            assert!(plan.schedule_bodies);
            assert_eq!(plan.no_progress, None);
        }

        #[test]
        fn at_tip_reports_at_tip() {
            let tip = snap(1, 7, 0x09);
            let plan = assert_invariant(&SyncFrontier {
                chain: ChainFrontier {
                    applied_tip: Some(Arc::clone(&tip)),
                    chain_tip: Some(tip),
                    next_required: None,
                    closed_for_recovery: false,
                },
                body_state: None,
                header_request: None,
                header_request_live: false,
                usable_peers: vec![usable(9001, 100, None)],
            });
            assert!(!plan.schedule_bodies);
            assert_eq!(plan.no_progress, Some(NoProgressReason::AtTip));
        }

        #[test]
        fn diverged_tips_with_unresolvable_frontier_report_frontier_unresolvable() {
            let plan = assert_invariant(&frontier(
                ChainFrontier {
                    applied_tip: Some(snap(1, 0, 0x01)),
                    chain_tip: Some(snap(2, 9, 0x02)),
                    next_required: None,
                    closed_for_recovery: false,
                },
                None,
                vec![usable(9001, 100, None)],
            ));
            assert!(!plan.schedule_bodies);
            assert_eq!(
                plan.no_progress,
                Some(NoProgressReason::FrontierUnresolvable)
            );
        }

        #[test]
        fn missing_tip_snapshot_reports_chain_view_unavailable() {
            let plan = assert_invariant(&frontier(
                ChainFrontier {
                    applied_tip: None,
                    chain_tip: Some(snap(2, 9, 0x02)),
                    next_required: None,
                    closed_for_recovery: false,
                },
                None,
                vec![usable(9001, 100, None)],
            ));
            assert_eq!(
                plan.no_progress,
                Some(NoProgressReason::ChainViewUnavailable)
            );
        }

        #[test]
        fn live_pending_header_request_awaits_its_connection() {
            let source = PeerSource::for_test(addr_of(9001));
            let mut frontier = frontier(
                chain_frontier(5, false),
                Some(BodyState::Unowned),
                vec![usable(9001, 100, None)],
            );
            frontier.usable_peers[0].source = source;
            frontier.header_request = Some(super::super::HeaderRequest {
                source,
                kind: super::super::HeaderRequestKind::Frontier,
                locator_tip_hash: hash(0x01),
                target_height: 6,
                requested_at: Instant::now(),
                state: super::super::HeaderRequestState::AwaitingResponse,
            });
            frontier.header_request_live = true;
            assert_eq!(frontier.plan().header_action, HeaderAction::AwaitPending);
        }

        #[test]
        fn probe_rotates_past_the_dead_pending_owner() {
            let dead_owner = PeerSource::for_test(addr_of(9005));
            let mut frontier = frontier(
                chain_frontier(5, false),
                Some(BodyState::Unowned),
                vec![usable(9001, 100, None), usable(9007, 100, None)],
            );
            frontier.header_request = Some(super::super::HeaderRequest {
                source: dead_owner,
                kind: super::super::HeaderRequestKind::Frontier,
                locator_tip_hash: hash(0x01),
                target_height: 6,
                requested_at: Instant::now(),
                state: super::super::HeaderRequestState::AwaitingResponse,
            });
            frontier.header_request_live = super::super::frontier::header_request_live(
                frontier.header_request,
                &frontier.usable_peers,
                Instant::now(),
            );
            assert!(!frontier.header_request_live);
            match frontier.plan().header_action {
                HeaderAction::Probe(source) => {
                    assert_eq!(source.endpoint, addr_of(9001).endpoint());
                    assert_ne!(source, dead_owner);
                }
                action => panic!("expected Probe, got {action:?}"),
            }
        }

        #[test]
        fn non_serving_peers_are_never_probe_picks() {
            let mut non_serving = usable(9001, 100, None);
            non_serving.info.services = 0;
            let frontier = frontier(
                chain_frontier(5, false),
                Some(BodyState::Unowned),
                vec![non_serving, usable(9002, 100, None)],
            );
            match frontier.plan().header_action {
                HeaderAction::Probe(source) => {
                    assert_eq!(source.endpoint, addr_of(9002).endpoint())
                }
                action => panic!("expected Probe, got {action:?}"),
            }
        }

        fn naive_plan(frontier: &SyncFrontier) -> super::super::frontier::FrontierPlan {
            let mut plan = super::super::frontier::FrontierPlan::default();
            let peers_exist = !frontier.usable_peers.is_empty();
            let body_state = match frontier.body_state {
                Some(BodyState::InFlight(owner))
                    if !frontier
                        .usable_peers
                        .iter()
                        .any(|peer| peer.source == owner) =>
                {
                    Some(BodyState::Unowned)
                }
                state => state,
            };
            let body_unowned = matches!(body_state, Some(BodyState::Unowned))
                && !frontier.chain.closed_for_recovery;

            plan.header_action = if frontier.header_request_live {
                HeaderAction::AwaitPending
            } else if !peers_exist {
                HeaderAction::Idle
            } else if body_unowned {
                if frontier.usable_peers.is_empty() {
                    HeaderAction::Extend
                } else {
                    HeaderAction::Probe(frontier.usable_peers[0].source)
                }
            } else {
                HeaderAction::Extend
            };

            let Some(required) = frontier.chain.next_required else {
                plan.no_progress = Some(if frontier.chain.closed_for_recovery {
                    NoProgressReason::ApplyHalted
                } else if frontier.chain.applied_tip.is_none() || frontier.chain.chain_tip.is_none()
                {
                    NoProgressReason::ChainViewUnavailable
                } else if frontier.chain.applied_tip.as_ref() == frontier.chain.chain_tip.as_ref() {
                    NoProgressReason::AtTip
                } else {
                    NoProgressReason::FrontierUnresolvable
                });
                return plan;
            };

            if frontier.chain.closed_for_recovery {
                plan.no_progress = Some(NoProgressReason::ApplyHalted);
                return plan;
            }

            if !peers_exist {
                plan.no_progress = Some(NoProgressReason::NoUsablePeers);
                return plan;
            }

            plan.schedule_bodies = true;
            if matches!(body_state, Some(BodyState::Unowned)) {
                let has_capable = frontier.usable_peers.iter().any(|peer| {
                    let claimed = u32::try_from(peer.info.best_known_height).ok();
                    let resolved = peer.active_height;
                    let capable = match (claimed, resolved) {
                        (Some(c), Some(r)) => Some(c.max(r)),
                        (Some(c), None) => Some(c),
                        (None, r) => r,
                    };
                    capable.is_some_and(|h| h >= required.height)
                });
                if !has_capable {
                    plan.no_progress = Some(NoProgressReason::NoCapablePeer);
                }
            }
            plan
        }

        fn frontier_cases() -> u32 {
            std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|c| c.parse().ok())
                .unwrap_or(1024)
        }

        fn frontier_peak_schedule_universal_invariant(
            chain: ChainFrontier,
            body_state: Option<BodyState>,
            usable_peers: Vec<UsablePeer>,
            header_request_live: bool,
        ) {
            let frontier = SyncFrontier {
                header_request_live,
                chain,
                body_state,
                header_request: None,
                usable_peers,
            };
            let plan = frontier.plan();
            if frontier.chain.next_required.is_some() {
                assert!(
                    plan.schedule_bodies || plan.no_progress.is_some(),
                    "required body must schedule recovery or name the reason: {plan:?}"
                );
            }
            if let Some(BodyState::InFlight(owner)) = frontier.body_state
                && !frontier.chain.closed_for_recovery
                && frontier
                    .usable_peers
                    .iter()
                    .any(|peer| peer.source == owner)
            {
                assert!(plan.schedule_bodies, "live owner is progress: {plan:?}");
                assert_eq!(plan.no_progress, None);
            }
            if let Some(BodyState::InFlight(owner)) = frontier.body_state
                && !frontier.usable_peers.is_empty()
                && !frontier
                    .usable_peers
                    .iter()
                    .any(|peer| peer.source == owner)
                && !frontier.chain.closed_for_recovery
                && !frontier
                    .usable_peers
                    .iter()
                    .any(|peer| peer.capability().is_some())
            {
                assert_eq!(plan.no_progress, Some(NoProgressReason::NoCapablePeer));
            }
            if plan.no_progress == Some(NoProgressReason::NoUsablePeers) {
                assert!(frontier.usable_peers.is_empty());
            }
            if frontier.usable_peers.is_empty()
                && frontier.chain.next_required.is_some()
                && !frontier.chain.closed_for_recovery
            {
                assert_eq!(plan.no_progress, Some(NoProgressReason::NoUsablePeers));
            }
        }

        proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            failure_persistence: Some(std::boxed::Box::new(
                proptest::test_runner::FileFailurePersistence::Direct(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../testdata/node/regressions/p2p/sync.txt"
                )),
            )),
            ..(proptest::prelude::ProptestConfig {
                cases: frontier_cases(),
                ..proptest::prelude::ProptestConfig::default()
            })
        })]

                #[test]
                fn frontier_plan_matches_naive_reference(
                    applied_ahead in proptest::bool::ANY,
                    next_required in proptest::option::of(0_u32..16),
                    closed_for_recovery in proptest::bool::ANY,
                    body_case in 0_u8..3,
                    in_flight_live in proptest::bool::ANY,
                    peers in proptest::collection::vec(
                        (0_i32..32, proptest::bool::ANY, proptest::bool::ANY),
                        0..5usize,
                    ),
                    pending_live in proptest::bool::ANY,
                ) {
                    let applied = snap(1, 8, 0x01);
                    let chain_tip = if applied_ahead {
                        Arc::clone(&applied)
                    } else {
                        snap(2, 12, 0x02)
                    };
                    let usable_peers = peers
                        .iter()
                        .enumerate()
                        .map(|(idx, (height, evidenced, resolved))| {
                            let mut peer = usable(
                                u16::try_from(9100 + idx).unwrap_or(9100),
                                *height,
                                resolved.then_some(u32::try_from(*height).unwrap_or(0)),
                            );
                            if *evidenced {
                                peer.demonstrated_tips = vec![hash(0x77)];
                            }
                            peer
                        })
                        .collect::<Vec<_>>();
                    let body_state = next_required.map(|_height| match body_case {
                        0 => BodyState::Unowned,
                        1 => BodyState::Staged,
                        _ => {
                            if in_flight_live {
                                usable_peers.first().map_or(BodyState::Unowned, |peer| {
                                    BodyState::InFlight(peer.source)
                                })
                            } else {
                                BodyState::InFlight(PeerSource::for_test(addr_of(9999)))
                            }
                        }
                    });
                    let owner = usable_peers.first().map(|peer| peer.source);
                    let header_request = if let (true, Some(source)) = (pending_live, owner) {
                        Some(super::super::HeaderRequest {
                            source,
                            kind: super::super::HeaderRequestKind::Frontier,
                            locator_tip_hash: hash(0x01),
                            target_height: 9,
                            requested_at: Instant::now(),
                            state: super::super::HeaderRequestState::AwaitingResponse,
                        })
                    } else {
                        None
                    };
                    let frontier = SyncFrontier {
                        chain: ChainFrontier {
                            applied_tip: Some(applied),
                            chain_tip: Some(chain_tip),
                            next_required: next_required.map(|height| RequiredBody {
                                height,
                                hash: hash(0x03),
                            }),
                            closed_for_recovery,
                        },
                        body_state,
                        header_request,
                        header_request_live: header_request.is_some(),
                        usable_peers,
                    };
                    let expected = naive_plan(&frontier);
                    let actual = frontier.plan();
                    proptest::prop_assert_eq!(actual.schedule_bodies, expected.schedule_bodies);
                    proptest::prop_assert_eq!(actual.no_progress, expected.no_progress);
                    proptest::prop_assert!(
                        std::mem::discriminant(&actual.header_action)
                            == std::mem::discriminant(&expected.header_action),
                        "header action class matches naive reference: actual {:?} expected {:?}",
                        actual.header_action,
                        expected.header_action
                    );
                }

                #[test]
                fn frontier_peak_schedule_universal_invariant_prop(
                    applied_ahead in proptest::bool::ANY,
                    next_required in proptest::option::of(0_u32..16),
                    closed_for_recovery in proptest::bool::ANY,
                    body_case in 0_u8..3,
                    in_flight_live in proptest::bool::ANY,
                    peers in proptest::collection::vec(
                        (0_i32..32, proptest::bool::ANY),
                        0..5usize,
                    ),
                    pending_live in proptest::bool::ANY,
                ) {
                    let applied = snap(1, 8, 0x01);
                    let chain_tip = if applied_ahead {
                        Arc::clone(&applied)
                    } else {
                        snap(2, 12, 0x02)
                    };
                    let usable_peers = peers
                        .iter()
                        .enumerate()
                        .map(|(idx, (height, evidenced))| {
                            let mut peer = usable(
                                u16::try_from(9100 + idx).unwrap_or(9100),
                                *height,
                                Some(u32::try_from(*height).unwrap_or(0)),
                            );
                            if *evidenced {
                                peer.demonstrated_tips = vec![hash(0x77)];
                            }
                            peer
                        })
                        .collect::<Vec<_>>();
                    let body_state = next_required.map(|_height| match body_case {
                        0 => BodyState::Unowned,
                        1 => BodyState::Staged,
                        _ => {
                            if in_flight_live {
                                usable_peers.first().map_or(BodyState::Unowned, |peer| {
                                    BodyState::InFlight(peer.source)
                                })
                            } else {
                                BodyState::InFlight(PeerSource::for_test(addr_of(9999)))
                            }
                        }
                    });
                    let chain = ChainFrontier {
                        applied_tip: Some(applied),
                        chain_tip: Some(chain_tip),
                        next_required: next_required.map(|height| RequiredBody {
                            height,
                            hash: hash(0x03),
                        }),
                        closed_for_recovery,
                    };
                    frontier_peak_schedule_universal_invariant(
                        chain,
                        body_state,
                        usable_peers,
                        pending_live,
                    );
                }
            }

        #[test]
        fn convicted_connection_cannot_pass_its_stall_to_a_replacement() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_blocks: 2,
                    ..super::super::default_sync_budget(Network::Regtest)
                },
            );
            let staller = test_addr(9810, 0)?;
            let (tx, rx) = bitcoin_rs_wire::test_support::message_channel();
            let conn1 = PeerLease::new(tx);
            peers.register(staller, conn1.clone());
            peers.publish_info(staller, &conn1, synthetic_peer(staller, 200));

            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected the window getdata").into());
            };
            assert!(witness_block_inventory(inventory)?.contains(&expected[0]));

            let tail = Hash256::from_le_bytes(expected[3].as_bytes());
            let now = Instant::now();
            {
                let mut scheduler = sync.scheduler.lock();
                let block = regtest_fixture::mined_block_with_prev_hash(
                    BlockHash(Hash256::from_le_bytes(expected[2].as_bytes())),
                    4,
                    vec![super::transaction(0xEE)],
                )
                .or_fail("regtest fixture block");
                let payload = BlockImage::from_local(block);
                scheduler.window.seed_front_cadence_for_test(50, now);
                scheduler.stager.insert(
                    tail,
                    None,
                    payload,
                    Some(conn1.source(staller.endpoint())),
                    now,
                );
                scheduler.window.mark_received_from(
                    tail,
                    80,
                    Some(conn1.source(staller.endpoint())),
                    now,
                );
            }

            let next_apply = sync
                .observe_chain_frontier()
                .next_required
                .ok_or_else(|| std::io::Error::other("missing next required"))?
                .height;
            {
                let mut scheduler = sync.scheduler.lock();
                let tree = sync.chain.block_tree();
                let state = &mut *scheduler;
                stall_blame(&mut state.window, &state.stager, &tree, next_apply, now);
            }
            let owner = {
                let mut scheduler = sync.scheduler.lock();
                let tree = sync.chain.block_tree();
                let state = &mut *scheduler;
                stall_blame(
                    &mut state.window,
                    &state.stager,
                    &tree,
                    next_apply,
                    now + super::super::BLOCK_STALLING_TIMEOUT,
                )
            };
            let (tx2, rx2) = bitcoin_rs_wire::test_support::message_channel();
            let conn2 = PeerLease::new(tx2);
            peers.register(staller, conn2.clone());
            peers.publish_info(staller, &conn2, synthetic_peer(staller, 200));

            let owner = owner.ok_or_else(|| std::io::Error::other("missing stall owner"))?;
            assert!(
                !peers.disconnect_source(owner),
                "convicting a replaced connection must not disconnect its successor"
            );
            let conn2_source = conn2.source(staller.endpoint());
            assert!(peers.is_current(conn2_source));
            assert!(!conn2.is_cancelled());
            sync.reconcile_peer_sessions();

            sync.tick();
            let Message::GetData(reissued) = rx2.try_recv()? else {
                return Err(std::io::Error::other(
                    "the replacement must inherit the released frontier work",
                )
                .into());
            };
            assert!(
                witness_block_inventory(reissued)?.contains(&expected[0]),
                "conn1's released front must be re-requested from conn2"
            );
            Ok(())
        }

        #[test]
        fn release_sweep_is_connection_exact_at_the_same_address() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
            let addr = test_addr(9820, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(addr, 200));
            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected the window getdata").into());
            };
            assert!(witness_block_inventory(inventory)?.contains(&expected[0]));
            let owner = current_source(&peers, addr);
            let front = Hash256::from_le_bytes(expected[0].as_bytes());
            assert_eq!(
                sync.scheduler.lock().window.pending_owner(&front),
                Some(owner)
            );

            sync.scheduler
                .lock()
                .window
                .retain_owned_by(|source| *source == owner);
            assert_eq!(
                sync.scheduler.lock().window.pending_owner(&front),
                Some(owner),
                "the live connection's pending must survive a release sweep"
            );
            sync.scheduler.lock().window.retain_owned_by(|_| false);
            assert_eq!(
                sync.scheduler.lock().window.pending_owner(&front),
                None,
                "a sweep missing the connection must release its pending"
            );
            Ok(())
        }
    }
    mod head_sync {
        use super::*;

        use bitcoin_rs_consensus::primitives::BlockImage;

        fn next_getheaders(
            rx: &bitcoin_rs_wire::test_support::MessageReceiver,
        ) -> Result<bitcoin::p2p::message_blockdata::GetHeadersMessage, TestError> {
            while let Ok(message) = rx.try_recv() {
                if let Message::GetHeaders(request) = message {
                    return Ok(request);
                }
            }
            Err(std::io::Error::other("expected getheaders").into())
        }

        // P2P-06
        #[test]
        fn body_delivered_without_headers_announcement_admits_and_applies() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                applied_tip,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(blocks[0].block_hash()),
            );

            let unannounced = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let expected = unannounced.block_hash();
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(unannounced))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(expected),
                "the body-carried header must admit and the body must apply"
            );
            Ok(())
        }

        // P2P-06
        #[test]
        fn body_arriving_ahead_of_its_header_chain_requests_the_gap() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(blocks[0].block_hash()),
            );

            let peer = test_addr(9700, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 3));

            let block2 = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let block3 = regtest_fixture::mined_block_with_prev_hash(
                block2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(3)],
            )
            .or_fail("regtest fixture block");
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block3.clone()))?;
            sync.drain_inbound_blocks();
            sync.drain_inbound_blocks();
            next_getheaders(&rx)?;

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![block2.header, block3.header],
                source: Some(current_source(&peers, peer)),

                wire_response: true,
            })?;
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block2))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(block3.block_hash()),
                "the staged tip body must apply once its parent headers land"
            );
            Ok(())
        }

        #[test]
        fn queued_body_from_replaced_source_cannot_enter_staging() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            let original_tip = applied_tip.load_full().ok_or("missing applied tip")?.hash;

            let peer = test_addr(9781, 0)?;
            let _old_rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let old_source = current_source(&peers, peer);
            let block = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let hash = Hash256::from(block.block_hash());
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![block.header],
                source: Some(old_source),
                wire_response: false,
            })?;
            let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(block.clone());
            inbound.source = Some(old_source);
            inbound_blocks_tx.send(inbound)?;

            assert!(peers.disconnect_source(old_source));
            let _replacement_rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let replacement = current_source(&peers, peer);
            assert_ne!(replacement, old_source);
            sync.drain_inbound_headers();
            sync.drain_inbound_blocks();

            assert!(sync.chain.block_tree().lookup(hash).is_none());
            assert!(!sync.scheduler.lock().stager.contains(&hash));
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                original_tip,
                "a retired delivery must not enter through its body-carried header",
            );

            let mut current_inbound = bitcoin_rs_wire::InboundBlock::from_local(block);
            current_inbound.source = Some(replacement);
            inbound_blocks_tx.send(current_inbound)?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                hash,
                "the same body from a current connection remains admissible",
            );
            Ok(())
        }

        #[test]
        fn staged_body_retries_after_source_replacement_without_replacement_credit() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(blocks[0].block_hash()),
            );

            let peer = test_addr(9780, 0)?;
            let old_rx = connect_peer(&peers, synthetic_peer(peer, 3));
            let old_source = current_source(&peers, peer);
            let block2 = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let block3 = regtest_fixture::mined_block_with_prev_hash(
                block2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(3)],
            )
            .or_fail("regtest fixture block");
            let block3_hash = Hash256::from(block3.block_hash());

            let mut orphan_body = bitcoin_rs_wire::InboundBlock::from_local(block3);
            orphan_body.source = Some(old_source);
            inbound_blocks_tx.send(orphan_body)?;
            sync.drain_inbound_blocks();
            sync.drain_inbound_blocks();
            next_getheaders(&old_rx)?;
            {
                let scheduler = sync.scheduler.lock();
                assert!(scheduler.stager.contains(&block3_hash));
                assert_eq!(
                    scheduler.stager.staged_source(&block3_hash),
                    Some(old_source),
                    "the staged body must retain its delivering connection",
                );
            }

            assert!(peers.disconnect_source(old_source));
            let _replacement_rx = connect_peer(&peers, synthetic_peer(peer, 3));
            let replacement_source = current_source(&peers, peer);
            assert_ne!(replacement_source, old_source);

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![block2.header],
                source: Some(replacement_source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            let mut parent_body = bitcoin_rs_wire::InboundBlock::from_local(block2);
            parent_body.source = Some(replacement_source);
            inbound_blocks_tx.send(parent_body)?;
            sync.tick();
            sync.tick();

            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                block3_hash,
                "the retained body must apply after its parent header arrives",
            );
            assert!(!sync.scheduler.lock().stager.contains(&block3_hash));
            let replacement_session = peers
                .sessions()
                .into_iter()
                .find(|session| session.endpoint == peer.endpoint())
                .ok_or("replacement peer session missing")?;
            assert!(
                !replacement_session.demonstrated_tips.contains(&block3_hash),
                "a predecessor's staged body must not credit its replacement",
            );
            Ok(())
        }

        #[test]
        fn headers_batch_missing_parent_requests_ancestry() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);

            let peer = test_addr(9701, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 10));

            let gap_parent = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let orphan_tip = regtest_fixture::mined_regtest_header(gap_parent.compute_hash(), 2)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![orphan_tip],
                source: Some(current_source(&peers, peer)),

                wire_response: true,
            })?;

            sync.drain_inbound_headers();

            next_getheaders(&rx)?;
            Ok(())
        }

        #[test]
        fn body_carried_rejection_keeps_the_live_pending_gate() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);

            let peer = test_addr(9768, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 10));

            let gap_parent = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)?;
            let orphan_tip = regtest_fixture::mined_regtest_header(gap_parent.compute_hash(), 2)?;
            let batch = || InboundHeaders {
                headers: vec![orphan_tip],
                source: Some(current_source(&peers, peer)),
                wire_response: false,
            };

            inbound_headers_tx.send(batch())?;
            sync.drain_inbound_headers();
            next_getheaders(&rx)?;
            let first_requested_at = sync
                .scheduler
                .lock()
                .header_request()
                .map(|request| request.requested_at)
                .ok_or("the first rejection must install the pending gate")?;

            std::thread::sleep(Duration::from_millis(20));
            while rx.try_recv().is_ok() {}
            inbound_headers_tx.send(batch())?;
            sync.drain_inbound_headers();
            assert!(
                rx.try_recv().is_err(),
                "a live pending gate must suppress the identical re-request"
            );
            let second_requested_at = sync
                .scheduler
                .lock()
                .header_request()
                .map(|request| request.requested_at)
                .ok_or("the suppressed re-request must leave the gate installed")?;
            assert_eq!(
                first_requested_at, second_requested_at,
                "the pending deadline must survive an identical body-carried rejection"
            );
            Ok(())
        }

        #[test]
        fn known_header_batch_still_credits_the_announcer() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let tip1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            let peer = test_addr(9702, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![tip1],
                source: Some(current_source(&peers, peer)),

                wire_response: true,
            })?;
            sync.drain_inbound_headers();

            assert_eq!(
                peers
                    .infos()
                    .into_iter()
                    .find(|info| info.endpoint == peer.endpoint())
                    .ok_or("peer info missing")?
                    .best_known_height,
                1,
                "a known tip still credits the announcer"
            );
            Ok(())
        }

        #[test]
        fn headers_batch_too_far_ahead_does_not_replay_a_request() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);

            let peer = test_addr(9704, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 0));

            let future_tip = far_future_header(genesis.compute_hash(), 1)?;
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![future_tip],
                source: Some(current_source(&peers, peer)),

                wire_response: true,
            })?;
            sync.drain_inbound_headers();

            assert!(
                next_getheaders(&rx).is_err(),
                "a future-dated rejection must not re-request the same batch"
            );
            Ok(())
        }

        #[test]
        fn staged_body_with_permanently_inadmissible_header_is_discarded() -> TestResult {
            use bitcoin_rs_consensus::primitives::CompactTarget;
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                applied_tip,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(blocks[0].block_hash()),
            );

            let mut bad = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            bad.header.bits = CompactTarget::from_consensus(0x1e0f_ff00);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(bad))?;
            sync.tick();
            sync.tick();

            assert_eq!(
                sync.scheduler.lock().stager.received_len(),
                0,
                "the inadmissible body must be discarded, not retried"
            );
            Ok(())
        }

        #[test]
        fn staged_body_whose_resolved_header_is_inadmissible_is_evicted() -> TestResult {
            let (tree, blocks) = mined_chain(2, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let peer = test_addr(9709, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let source = current_source(&peers, peer);
            assert!(
                sync.send_getdata_for_pending_blocks(source, 100, &test_frontier(&sync))
                    .sent,
                "the fixture must put requested bodies in flight"
            );
            assert_eq!(sync.scheduler.lock().window.pending_len(), 2);

            let fork = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(60)],
            )
            .or_fail("regtest fixture");
            let fork_hash = Hash256::from(fork.block_hash());
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(fork))?;
            sync.tick();
            sync.tick();

            let scheduler = sync.scheduler.lock();
            assert!(
                !scheduler.stager.contains(&fork_hash),
                "a body that resolves inadmissible must not survive header resolution"
            );
            assert_eq!(
                scheduler.window.pending_len(),
                2,
                "evicting the inadmissible body must not touch the pending requested bodies"
            );
            Ok(())
        }

        #[test]
        fn staged_body_gated_when_the_headers_drain_resolves_its_header() -> TestResult {
            let (tree, _blocks) = mined_chain(2, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_blocks_tx,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let peer = test_addr(9711, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 2));

            let fork_root =
                regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
                    .or_fail("regtest fixture");
            let orphan_body = regtest_fixture::mined_block_with_prev_hash(
                fork_root.compute_hash(),
                2,
                vec![regtest_fixture::coinbase(70)],
            )
            .or_fail("regtest fixture");
            let orphan_hash = Hash256::from(orphan_body.block_hash());
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                orphan_body.clone(),
            ))?;
            sync.tick();
            assert!(
                sync.scheduler.lock().stager.contains(&orphan_hash),
                "the body must stage while its header is unknown"
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork_root, orphan_body.header],
                source: None,
                wire_response: true,
            })?;
            sync.tick();

            assert!(
                !sync.scheduler.lock().stager.contains(&orphan_hash),
                "a body whose header resolves off-branch must not survive the drain"
            );
            Ok(())
        }

        #[test]
        fn deferred_owned_body_fetch_settles_the_staged_gate() -> TestResult {
            let (tree, _blocks) = mined_chain(2, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_blocks_tx,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let peer = test_addr(9712, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let source = current_source(&peers, peer);

            let fork_root =
                regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
                    .or_fail("regtest fixture");
            let orphan_body = regtest_fixture::mined_block_with_prev_hash(
                fork_root.compute_hash(),
                2,
                vec![regtest_fixture::coinbase(71)],
            )
            .or_fail("regtest fixture");
            let orphan_hash = Hash256::from(orphan_body.block_hash());

            assert!(sync.enqueue_owned_body_fetch(source, orphan_hash, || true));
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![orphan_body.header],
                source: Some(source),
                wire_response: true,
            })?;
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                orphan_body.clone(),
            ))?;
            sync.tick();

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork_root, orphan_body.header],
                source: None,
                wire_response: true,
            })?;
            sync.tick();

            assert!(
                sync.scheduler.lock().stager.contains(&orphan_hash),
                "a body the peer already fetches must be exempt from the recheck"
            );
            Ok(())
        }

        #[test]
        fn failed_enqueue_publishes_no_owned_body_fetch() -> TestResult {
            let (tree, _blocks) = mined_chain(2, 0)?;
            let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let peer = test_addr(9713, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let source = current_source(&peers, peer);
            let hash = Hash256::from_le_bytes(&[7_u8; 32]);

            assert!(!sync.enqueue_owned_body_fetch(source, hash, || false));
            assert!(
                sync.scheduler.lock().owned_body_fetches.is_empty(),
                "a failed enqueue must publish no ownership mark"
            );
            assert!(!sync.owns_body_fetch(source, hash));
            Ok(())
        }

        #[test]
        fn stale_source_never_reaches_the_enqueue_closure() -> TestResult {
            let (tree, _blocks) = mined_chain(2, 0)?;
            let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let peer = test_addr(9714, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let stale = current_source(&peers, peer);
            let _rx2 = connect_peer(&peers, synthetic_peer(peer, 2));
            let hash = Hash256::from_le_bytes(&[9_u8; 32]);

            let called = std::cell::Cell::new(false);
            assert!(!sync.enqueue_owned_body_fetch(stale, hash, || {
                called.set(true);
                true
            }));
            assert!(!called.get(), "stale source must not reach the send");
            assert!(
                sync.scheduler.lock().owned_body_fetches.is_empty(),
                "stale source must publish no ownership mark"
            );
            Ok(())
        }

        #[test]
        fn unrequested_body_at_the_count_budget_is_refused() -> TestResult {
            let (tree, blocks) = mined_chain(3, 0)?;
            let SyncHarness {
                sync,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_blocks: 2,
                    ..super::super::default_sync_budget(
                        bitcoin_rs_consensus::primitives::Network::Regtest,
                    )
                },
            );
            {
                let mut scheduler = sync.scheduler.lock();
                let now = Instant::now();
                for (idx, block) in blocks[..2].iter().enumerate() {
                    let mut key = [0_u8; 32];
                    key[0] = 0x71_u8.saturating_add(idx.try_into()?);
                    scheduler.stager.insert(
                        Hash256::from_le_bytes(&key),
                        None,
                        BlockImage::from_local(block.clone()),
                        None,
                        now,
                    );
                }
            }

            let refused_hash = Hash256::from(blocks[2].block_hash());
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[2].clone()))?;
            sync.drain_inbound_blocks();

            let scheduler = sync.scheduler.lock();
            assert_eq!(
                scheduler.stager.received_len(),
                2,
                "a refused body must not evict staged entries to make room"
            );
            assert!(
                !scheduler.stager.contains(&refused_hash),
                "the unrequested body is refused, not staged"
            );
            Ok(())
        }

        #[test]
        fn stale_owned_fetch_source_does_not_settle_the_gate() -> TestResult {
            let (tree, _blocks) = mined_chain(2, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_blocks_tx,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            let peer = test_addr(9713, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
            let source = current_source(&peers, peer);

            let fork_root =
                regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
                    .or_fail("regtest fixture");
            let orphan_body = regtest_fixture::mined_block_with_prev_hash(
                fork_root.compute_hash(),
                2,
                vec![regtest_fixture::coinbase(72)],
            )
            .or_fail("regtest fixture");
            let orphan_hash = Hash256::from(orphan_body.block_hash());

            assert!(sync.enqueue_owned_body_fetch(source, orphan_hash, || true));
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![orphan_body.header],
                source: Some(source),
                wire_response: true,
            })?;
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                orphan_body.clone(),
            ))?;
            sync.tick();
            peers.disconnect_source(source);

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork_root, orphan_body.header],
                source: None,
                wire_response: true,
            })?;
            sync.tick();

            assert!(
                !sync.scheduler.lock().stager.contains(&orphan_hash),
                "a stale owner's mark must not exempt the staged body from the gate"
            );
            Ok(())
        }

        #[test]
        fn binding_failure_does_not_burn_the_last_staging_slot() -> TestResult {
            let (tree, blocks) = mined_chain(3, 0)?;
            let SyncHarness {
                sync,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            install_budget(
                &sync,
                super::super::SyncBudget {
                    max_received_blocks: 1,
                    ..super::super::default_sync_budget(
                        bitcoin_rs_consensus::primitives::Network::Regtest,
                    )
                },
            );

            let mut bad = blocks[2].clone();
            bad.txs.push(regtest_fixture::coinbase(90));
            let bad_hash = Hash256::from(bad.block_hash());
            let good_hash = Hash256::from(blocks[1].block_hash());
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(bad))?;
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[1].clone()))?;
            sync.drain_inbound_blocks();

            let scheduler = sync.scheduler.lock();
            assert_eq!(
                scheduler.stager.received_len(),
                1,
                "the binding-failed body must not consume the single staging slot"
            );
            assert!(!scheduler.stager.contains(&bad_hash));
            assert!(
                scheduler.stager.contains(&good_hash),
                "the admissible unrequested body stages into the freed slot"
            );
            Ok(())
        }

        #[test]
        fn gate_pending_body_survives_a_pending_branch_switch() -> TestResult {
            let (tree, blocks) = mined_chain(3, 0)?;
            let SyncHarness {
                sync,
                inbound_blocks_tx,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            sync.chain.bootstrap_genesis();
            for block in &blocks {
                inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))?;
            }
            sync.tick();
            assert_eq!(
                sync.chain.applied_tip().ok_or("missing applied tip")?.hash,
                Hash256::from(blocks[2].block_hash()),
                "the losing branch must be applied to height 3"
            );

            let fork_root =
                regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
                    .or_fail("regtest fixture");
            let winner_body = regtest_fixture::mined_block_with_prev_hash(
                fork_root.compute_hash(),
                2,
                vec![regtest_fixture::coinbase(73)],
            )
            .or_fail("regtest fixture");
            let winner_hash = Hash256::from(winner_body.block_hash());
            let fork_h3 =
                regtest_fixture::mined_regtest_header(winner_body.header.compute_hash(), 3)
                    .or_fail("regtest fixture");
            let fork_h4 = regtest_fixture::mined_regtest_header(fork_h3.compute_hash(), 4)
                .or_fail("regtest fixture");
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(
                winner_body.clone(),
            ))?;
            sync.tick();
            assert!(
                sync.scheduler.lock().stager.contains(&winner_hash),
                "the body must stage while its header is unknown"
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork_root, winner_body.header, fork_h3, fork_h4],
                source: None,
                wire_response: true,
            })?;
            sync.tick();

            let applied = sync.chain.applied_tip().ok_or("missing applied tip")?;
            assert_eq!(
                applied.hash,
                Hash256::from(blocks[2].block_hash()),
                "the switch must still be pending on the missing fork bodies"
            );
            assert!(
                sync.scheduler.lock().stager.contains(&winner_hash),
                "a winning-branch body must survive a pending branch switch"
            );
            Ok(())
        }

        // P2P-06
        #[test]
        fn body_carried_header_does_not_consume_a_pending_getheaders() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);

            let peer = test_addr(9705, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
            let source = current_source(&peers, peer);
            {
                let mut scheduler = sync.scheduler.lock();
                scheduler.headers_sync.entry(source).or_default().request =
                    Some(super::super::HeaderRequest {
                        source,
                        kind: super::super::HeaderRequestKind::Frontier,
                        locator_tip_hash: Hash256::default(),
                        target_height: 1,
                        requested_at: Instant::now(),
                        state: super::super::HeaderRequestState::AwaitingResponse,
                    });
                scheduler.header_request_owner = Some(source);
            }

            let body_tip = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![body_tip],
                source: Some(source),
                wire_response: false,
            })?;
            sync.drain_inbound_headers();
            assert!(
                sync.scheduler.lock().header_request().is_some(),
                "a body-carried header must not consume the pending request"
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![body_tip],
                source: Some(source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            assert!(
                sync.scheduler.lock().header_request().is_none(),
                "a wire `headers` response consumes the pending request"
            );
            Ok(())
        }

        #[test]
        fn staged_retry_acceptance_credits_the_delivering_peer() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();

            let peer = test_addr(9706, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

            let unannounced = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            let expected = unannounced.block_hash();
            let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(unannounced);
            inbound.source = Some(current_source(&peers, peer));
            inbound_blocks_tx.send(inbound)?;
            sync.tick();
            sync.tick();

            let session = peers
                .sessions()
                .into_iter()
                .find(|session| session.endpoint == peer.endpoint())
                .ok_or("peer session missing")?;
            assert_eq!(
                session.demonstrated_tips,
                vec![Hash256::from(expected)],
                "the delivering peer's demonstrated tip must record the admitted header"
            );
            Ok(())
        }

        // P2P-03
        #[test]
        fn fork_tip_attests_its_shared_active_ancestor() -> TestResult {
            let (tree, blocks) = mined_chain(3, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);

            let peer = test_addr(9707, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

            let fork1 = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)
                .or_fail("regtest fixture header");
            let fork2 = regtest_fixture::mined_regtest_header(fork1.compute_hash(), 3)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork1, fork2],
                source: Some(current_source(&peers, peer)),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();

            assert_eq!(
                peers
                    .infos()
                    .into_iter()
                    .find(|info| info.endpoint == peer.endpoint())
                    .ok_or("peer info missing")?
                    .best_known_height,
                1,
                "an off-active tip attests the shared prefix it proves"
            );
            Ok(())
        }

        #[test]
        fn fork_evidence_cannot_credit_a_tainted_ancestor_height() -> TestResult {
            let (tree, blocks) = mined_chain(3, 0)?;
            let SyncHarness {
                sync,
                peers,
                block_tree,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            let peer = test_addr(9707, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
            let fork = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork],
                source: Some(current_source(&peers, peer)),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            let peer_height = || {
                peers
                    .infos()
                    .into_iter()
                    .find(|info| info.endpoint == peer.endpoint())
                    .map(|info| info.best_known_height)
            };
            assert_eq!(peer_height(), Some(1));
            {
                let mut tree = block_tree.write();
                let ancestor = tree
                    .lookup(Hash256::from(blocks[0].block_hash()))
                    .ok_or("ancestor")?;
                tree.node_mut(ancestor)?.height = 100;
            }
            sync.refresh_active_peer_credit();
            assert_eq!(peer_height(), Some(1));
            Ok(())
        }

        // P2P-03
        #[test]
        fn retained_unresolved_tips_are_deduplicated_and_capped() -> TestResult {
            let (tree, blocks) = mined_chain(10, 0)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);

            let peer = test_addr(9708, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
            let source = current_source(&peers, peer);

            let fork_base = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)
                .or_fail("regtest fixture header");
            let fork_tip = regtest_fixture::mined_regtest_header(fork_base.compute_hash(), 3)
                .or_fail("regtest fixture header");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork_base],
                source: Some(source),
                wire_response: true,
            })?;
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![fork_tip],
                source: Some(source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            assert_eq!(
                peers
                    .sessions()
                    .into_iter()
                    .find(|session| session.endpoint == peer.endpoint())
                    .ok_or("peer session missing")?
                    .demonstrated_tips,
                vec![Hash256::from(fork_tip.compute_hash())],
                "an ancestor tip subsumed by a kept descendant is dropped"
            );

            let mut branch_tips = Vec::new();
            for (index, parent) in blocks.iter().enumerate().skip(1).take(8) {
                let height = u32::try_from(index + 2)?;
                let tip = regtest_fixture::mined_regtest_header(parent.block_hash(), height)
                    .or_fail("regtest fixture header");
                branch_tips.push(tip);
                inbound_headers_tx.send(InboundHeaders {
                    headers: vec![tip],
                    source: Some(source),
                    wire_response: true,
                })?;
            }
            sync.drain_inbound_headers();

            let retained = peers
                .sessions()
                .into_iter()
                .find(|session| session.endpoint == peer.endpoint())
                .ok_or("peer session missing")?
                .demonstrated_tips;
            assert_eq!(
                retained.len(),
                8,
                "unresolved tips are bounded by the per-session cap"
            );
            assert_eq!(
                retained[0],
                Hash256::from(branch_tips[7].compute_hash()),
                "the deepest unresolved tip is retained first"
            );
            Ok(())
        }

        // P2P-03
        #[test]
        fn delivered_tip_evidence_is_compacted_to_the_max_resolving_tip() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let tip1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let tip1_id = tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
            let tip2 = regtest_fixture::mined_regtest_header(tip1.compute_hash(), 2)
                .or_fail("regtest fixture header");
            tree.insert_node(Some(tip1_id), tip2, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            let peer = test_addr(9703, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![tip1],
                source: Some(current_source(&peers, peer)),

                wire_response: true,
            })?;
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![tip2],
                source: Some(current_source(&peers, peer)),

                wire_response: true,
            })?;
            sync.drain_inbound_headers();

            assert_eq!(
                peers
                    .sessions()
                    .into_iter()
                    .find(|session| session.endpoint == peer.endpoint())
                    .ok_or("peer session missing")?
                    .demonstrated_tips,
                vec![Hash256::from(tip2.compute_hash())],
                "retained evidence compacts to the max-resolving tip"
            );
            Ok(())
        }

        #[test]
        fn compact_owned_body_fetch_marks_the_tip_pending() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            let peer = test_addr(9706, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
            let tip = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let tip_hash = Hash256::from(tip.compute_hash());

            assert!(
                sync.enqueue_owned_body_fetch(current_source(&peers, peer), tip_hash, || true,)
            );
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![tip],
                source: Some(current_source(&peers, peer)),
                wire_response: false,
            })?;
            sync.drain_inbound_headers();

            assert!(
                sync.scheduler.lock().window.contains_pending(&tip_hash),
                "a compact-owned tip body must be recorded pending, not re-requested"
            );
            Ok(())
        }

        type CompactGateFixture = (
            SyncHarness,
            Vec<Block>,
            bitcoin_rs_wire::PeerSource,
            bitcoin_rs_wire::test_support::MessageReceiver,
        );

        fn compact_gate_fixture(port: usize) -> Result<CompactGateFixture, TestError> {
            let (tree, blocks) = mined_chain(2, 0)?;
            let harness = SyncHarness::new(tree);
            let peer = test_addr(port, 0)?;
            let rx = connect_peer(&harness.peers, synthetic_peer(peer, 0));
            let source = current_source(&harness.peers, peer);
            Ok((harness, blocks, source, rx))
        }

        fn tip_child(
            tip: &Block,
            coinbase_height: u32,
        ) -> Result<bitcoin_rs_consensus::primitives::Header, TestError> {
            Ok(regtest_fixture::mined_block_with_prev_hash(
                tip.block_hash(),
                3,
                vec![regtest_fixture::coinbase(coinbase_height)],
            )?
            .header)
        }

        #[test]
        fn compact_reconstruction_admission_follows_cores_header_gate() -> TestResult {
            let (harness, blocks, source, _rx) = compact_gate_fixture(9707)?;
            let other = test_addr(9708, 0)?;
            let _other_rx = connect_peer(&harness.peers, synthetic_peer(other, 0));
            let sync = &harness.sync;
            let tip = blocks.last().ok_or("chain has a tip")?;

            let extending = tip_child(tip, 3)?;
            let replayed = blocks.first().ok_or("chain has block 1")?.header;
            assert!(
                sync.compact_reconstruction_admissible(source, &replayed),
                "with nothing applied yet, any valid connected header carries more work"
            );
            harness.applied_tip.store(harness.block_tree.read().tip());
            assert!(
                sync.compact_reconstruction_admissible(source, &extending),
                "a mined child of the applied tip"
            );
            let mut wrong_target = extending;
            wrong_target.bits =
                bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x2000_ffff);
            regtest_fixture::mine_header_to_declared_target(&mut wrong_target)?;
            assert!(
                !sync.compact_reconstruction_admissible(source, &wrong_target),
                "a target other than the required one"
            );
            let mut no_work = extending;
            no_work.bits =
                bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1d00_ffff);
            assert!(
                !sync.compact_reconstruction_admissible(source, &no_work),
                "no proof of work"
            );
            let orphan = regtest_fixture::mined_regtest_header(no_work.compute_hash(), 4)?;
            assert!(
                !sync.compact_reconstruction_admissible(source, &orphan),
                "unknown parent"
            );

            let replayed_hash = Hash256::from(replayed.compute_hash());
            assert!(
                !sync.compact_reconstruction_admissible(source, &replayed),
                "no more work than the applied tip"
            );
            assert!(sync.enqueue_owned_body_fetch(
                current_source(&harness.peers, other),
                replayed_hash,
                || true,
            ));
            assert!(
                !sync.compact_reconstruction_admissible(source, &replayed),
                "another connection's fetch"
            );
            assert!(sync.enqueue_owned_body_fetch(source, replayed_hash, || true,));
            assert!(
                sync.compact_reconstruction_admissible(source, &replayed),
                "this connection's fetch"
            );
            Ok(())
        }

        #[test]
        fn compact_reconstruction_admission_reads_admitted_tree_state() -> TestResult {
            let (harness, blocks, source, _rx) = compact_gate_fixture(9709)?;
            let sync = &harness.sync;
            let tip = blocks.last().ok_or("chain has a tip")?;
            harness.applied_tip.store(harness.block_tree.read().tip());
            let admit = |header, status| -> TestResult {
                let mut tree = harness.block_tree.write();
                let parent = tree
                    .lookup(Hash256::from(tip.block_hash()))
                    .ok_or("tip is in the tree")?;
                tree.insert_node(Some(parent), header, status)?;
                Ok(())
            };

            let mut ahead = tip_child(tip, 43)?;
            ahead.time =
                bitcoin_rs_execution::chain::current_unix_seconds().saturating_add(3 * 60 * 60);
            regtest_fixture::mine_header_to_declared_target(&mut ahead)?;
            assert!(
                !sync.compact_reconstruction_admissible(source, &ahead),
                "unknown and too far ahead"
            );
            admit(ahead, NodeStatus::HeaderValid)?;
            assert!(
                sync.compact_reconstruction_admissible(source, &ahead),
                "admitted, not rechecked"
            );

            let invalid = tip_child(tip, 33)?;
            admit(invalid, NodeStatus::Invalid)?;
            assert!(
                !sync.compact_reconstruction_admissible(source, &invalid),
                "a block marked invalid"
            );
            let invalid_child = regtest_fixture::mined_regtest_header(invalid.compute_hash(), 4)?;
            assert!(
                !sync.compact_reconstruction_admissible(source, &invalid_child),
                "a child of an invalid block"
            );
            Ok(())
        }

        #[test]
        fn compact_reconstruction_admission_stays_near_the_applied_tip() -> TestResult {
            let (tree, blocks) = mined_chain(6, 0)?;
            let applied = {
                let id = tree
                    .lookup(Hash256::from(blocks[0].block_hash()))
                    .ok_or("block 1 is in the tree")?;
                let node = tree.node(id)?;
                TipSnapshot {
                    tip_id: id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                }
            };
            let harness = SyncHarness::new(tree);
            harness.applied_tip.store(Some(Arc::new(applied)));
            let peer = test_addr(9790, 0)?;
            let _rx = connect_peer(&harness.peers, synthetic_peer(peer, 0));
            let source = current_source(&harness.peers, peer);
            let sync = &harness.sync;

            assert!(
                sync.compact_reconstruction_admissible(source, &blocks[1].header),
                "one block above the applied tip"
            );
            assert!(
                sync.compact_reconstruction_admissible(source, &blocks[2].header),
                "two blocks above the applied tip"
            );
            assert!(
                !sync.compact_reconstruction_admissible(source, &blocks[3].header),
                "three blocks above the applied tip"
            );
            assert!(
                !sync.compact_reconstruction_admissible(source, &blocks[5].header),
                "five blocks above the applied tip"
            );
            assert!(sync.enqueue_owned_body_fetch(
                source,
                Hash256::from(blocks[3].block_hash()),
                || true
            ));
            assert!(
                sync.compact_reconstruction_admissible(source, &blocks[3].header),
                "a fetch this connection owns"
            );
            Ok(())
        }

        #[test]
        fn owned_fetch_mark_survives_until_its_tip_header_attaches() -> TestResult {
            let mut tree = BlockTree::new();
            let genesis = genesis_header();
            tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
            let SyncHarness {
                sync,
                peers,
                inbound_headers_tx,
                ..
            } = SyncHarness::new(tree);
            let peer = test_addr(9707, 0)?;
            let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
            let mid = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
                .or_fail("regtest fixture header");
            let tip = regtest_fixture::mined_regtest_header(mid.compute_hash(), 2)
                .or_fail("regtest fixture header");
            let tip_hash = Hash256::from(tip.compute_hash());

            assert!(
                sync.enqueue_owned_body_fetch(current_source(&peers, peer), tip_hash, || true,)
            );
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![tip],
                source: Some(current_source(&peers, peer)),
                wire_response: false,
            })?;
            sync.drain_inbound_headers();
            assert!(
                !sync.scheduler.lock().window.contains_pending(&tip_hash),
                "an unattached tip cannot be window-pending yet"
            );

            inbound_headers_tx.send(InboundHeaders {
                headers: vec![mid, tip],
                source: Some(current_source(&peers, peer)),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            assert!(
                sync.scheduler.lock().window.contains_pending(&tip_hash),
                "the retained owned fetch must mark once its tip attaches"
            );
            Ok(())
        }

        #[test]
        fn announced_near_tip_is_direct_fetched_before_tick() -> TestResult {
            let (tree, blocks) = mined_chain(1, 0)?;
            let SyncHarness {
                sync,
                peers,
                applied_tip,
                inbound_headers_tx,
                inbound_blocks_tx,
                ..
            } = SyncHarness::new(tree);
            inbound_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
            sync.tick();
            assert_eq!(
                applied_tip.load_full().ok_or("missing applied tip")?.hash,
                Hash256::from(blocks[0].block_hash()),
            );

            let peer = test_addr(9740, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(peer, 3));
            let source = current_source(&peers, peer);
            let block2 = regtest_fixture::mined_block_with_prev_hash(
                blocks[0].block_hash(),
                2,
                vec![regtest_fixture::coinbase(2)],
            )
            .or_fail("regtest fixture block");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![block2.header],
                source: Some(source),
                wire_response: true,
            })?;

            sync.drain_inbound_headers();
            assert_eq!(
                witness_block_inventory(next_getdata(&rx)?)?,
                vec![block2.block_hash()],
                "the announcing connection is asked for the body without another tick"
            );
            assert!(
                sync.scheduler
                    .lock()
                    .window
                    .contains_pending(&Hash256::from(block2.block_hash())),
                "the window owns the body the direct fetch requested"
            );

            peers.note_compact_relay(source);
            let block3 = regtest_fixture::mined_block_with_prev_hash(
                block2.block_hash(),
                3,
                vec![regtest_fixture::coinbase(3)],
            )
            .or_fail("regtest fixture block");
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![block3.header],
                source: Some(source),
                wire_response: true,
            })?;
            sync.drain_inbound_headers();
            assert!(
                matches!(
                    next_getdata(&rx)?.first(),
                    Some(Inventory::CompactBlock(hash))
                        if Hash256::from_le_bytes(hash.as_byte_array())
                            == Hash256::from(block3.block_hash())
                ),
                "a compact-relay peer's single near-tip fetch rides the compact flavor for the announced block"
            );
            Ok(())
        }
    }
    mod limited_peers {
        use std::sync::Arc;

        use bitcoin::p2p::ServiceFlags;

        use super::*;
        use crate::p2p::download_window::{
            BlockDownloadPolicy, MIN_PEERS_FOR_FANOUT, PENDING_BUDGET, statically_fanout_eligible,
        };

        fn limited_peer(addr: PeerRemote, height: i32) -> PeerInfo {
            PeerInfo {
                services: ServiceFlags::WITNESS.to_u64() | ServiceFlags::NETWORK_LIMITED.to_u64(),
                ..synthetic_peer(addr, height)
            }
        }

        fn full_peer(addr: PeerRemote, height: i32) -> PeerInfo {
            synthetic_peer(addr, height)
        }

        fn policy(ibd: Arc<InitialBlockDownload>, requested_height: u32) -> BlockDownloadPolicy {
            BlockDownloadPolicy {
                ibd,
                requested_height,
                network: Network::Regtest,
            }
        }

        fn sent_messages(rx: &bitcoin_rs_wire::test_support::MessageReceiver) -> Vec<Message> {
            rx.try_iter().collect()
        }

        // P2P-09
        #[test]
        fn predicate_excludes_limited_peer_during_initial_block_download() -> TestResult {
            let addr = test_addr(9600, 0)?;
            let syncing = crate::p2p::sync::syncing_ibd_latch();
            assert!(
                !statically_fanout_eligible(&limited_peer(addr, 300), &policy(syncing.clone(), 1)),
                "a pruned peer must never serve bodies while the node is still syncing"
            );
            assert!(
                statically_fanout_eligible(&full_peer(addr, 300), &policy(syncing, 1)),
                "a full-history peer serves bodies during initial block download"
            );
            Ok(())
        }

        // P2P-09
        #[test]
        fn predicate_limits_pruned_peer_to_the_retained_window() -> TestResult {
            let addr = test_addr(9601, 0)?;
            for (height, requested, accepted) in [
                (288_i32, 1_u32, true),
                (289, 1, false),
                (300, 13, true),
                (288, 288, true),
                (287, 288, false),
                (300, 1, false),
            ] {
                assert_eq!(
                    statically_fanout_eligible(
                        &limited_peer(addr, height),
                        &policy(synced_ibd_latch(), requested),
                    ),
                    accepted,
                    "pruned peer at {height} asked for height {requested}"
                );
            }
            Ok(())
        }

        #[test]
        fn predicate_refuses_witness_only_peer_inside_the_window() -> TestResult {
            let addr = test_addr(9603, 0)?;
            let witness_only = PeerInfo {
                services: ServiceFlags::WITNESS.to_u64(),
                ..synthetic_peer(addr, 300)
            };
            for requested in [1_u32, 13, 288] {
                assert!(
                    !statically_fanout_eligible(
                        &witness_only,
                        &policy(synced_ibd_latch(), requested)
                    ),
                    "a WITNESS-only peer must not be sent a getdata for height {requested}"
                );
            }
            Ok(())
        }

        #[test]
        fn predicate_keeps_full_service_peer_at_any_height() -> TestResult {
            let addr = test_addr(9602, 0)?;
            for ibd in [crate::p2p::sync::syncing_ibd_latch(), synced_ibd_latch()] {
                assert!(statically_fanout_eligible(
                    &full_peer(addr, 300),
                    &policy(Arc::clone(&ibd), 1),
                ));
                assert!(statically_fanout_eligible(
                    &full_peer(addr, 300),
                    &policy(ibd, 300),
                ));
            }
            Ok(())
        }

        // P2P-09
        #[test]
        fn tick_asks_no_bodies_from_limited_peer_during_initial_block_download() -> TestResult {
            let (sync, peers, _tree, _applied, _expected) =
                sync_with_header_chain_and_ibd(4, crate::p2p::sync::syncing_ibd_latch())?;
            let rx = connect_peer(&peers, limited_peer(test_addr(9603, 0)?, 300));

            sync.tick();
            sync.tick();

            let messages = sent_messages(&rx);
            assert!(
                !messages
                    .iter()
                    .any(|message| matches!(message, Message::GetData(_))),
                "a pruned peer must not be asked for bodies while the node is still syncing"
            );
            assert!(
                messages
                    .iter()
                    .any(|message| matches!(message, Message::GetHeaders(_))),
                "header requests stay open to a pruned peer, got {messages:?}"
            );
            Ok(())
        }

        #[test]
        fn tick_asks_bodies_from_limited_peer_inside_retained_window() -> TestResult {
            let (sync, peers, block_tree, applied_tip, expected) =
                sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
            let rx = connect_peer(&peers, limited_peer(test_addr(9604, 0)?, 286));

            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;

            let inventory = next_getdata(&rx)?;
            assert_eq!(
                witness_block_inventory(inventory)?,
                expected,
                "the pruned peer keeps the last 288 blocks, so the near-tip range is its own"
            );
            Ok(())
        }

        #[test]
        fn tick_asks_no_bodies_from_limited_peer_beyond_retained_window() -> TestResult {
            let (sync, peers, block_tree, applied_tip, _expected) =
                sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
            let rx = connect_peer(&peers, limited_peer(test_addr(9605, 0)?, 287));

            sync.tick();
            assert_applied_genesis(&applied_tip, &block_tree)?;

            assert_no_getdata(&rx)?;
            Ok(())
        }

        #[test]
        fn limited_peer_is_not_counted_toward_fanout_during_initial_block_download() -> TestResult {
            let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain_and_ibd(
                u32::try_from(PENDING_BUDGET)?,
                crate::p2p::sync::syncing_ibd_latch(),
            )?;
            let limited_rx = connect_peer(&peers, limited_peer(test_addr(9606, 0)?, 400));
            let mut rxs = Vec::new();
            for idx in 0..MIN_PEERS_FOR_FANOUT {
                let addr = test_addr(9607, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    full_peer(addr, 300 - i32::try_from(idx)?),
                ));
            }

            sync.tick();
            sync.tick();

            assert_no_getdata(&limited_rx)?;
            for rx in &rxs {
                assert!(
                    next_getdata(rx).is_ok(),
                    "every full-service peer must be asked for bodies"
                );
            }
            Ok(())
        }
    }
    mod stale_tip {
        use std::io;
        use std::net::TcpListener;
        use std::thread;

        use super::super::stale_tips::{MAX_ADVERTISED_STALETIPS, StaleTipRetainer};
        use super::super::{StaleTipState, tip_may_be_stale};
        use super::*;
        use bitcoin_rs_consensus::primitives::Hash256;
        use bitcoin_rs_wire::listener::ListenerExtras;
        use bitcoin_rs_wire::service::{P2pService, P2pServiceConfig};

        const SPACING: Duration = Duration::from_mins(10);

        const GENESIS_HASH: Hash256 = Hash256::from_le_bytes(&[7u8; 32]);

        const REPLACEMENT_HASH: Hash256 = Hash256::from_le_bytes(&[9u8; 32]);

        #[test]
        #[expect(
            clippy::expect_used,
            reason = "a test that cannot wire its fake peers has nothing to report"
        )]
        fn the_stale_tip_allowance_dials_past_the_slot_cap() {
            let t0 = Instant::now();
            let mut tree = BlockTree::new();
            let chain_tip = tree.tip_handle();
            let (_headers_tx, headers_rx) = unbounded();
            let (_blocks_tx, blocks_rx) = unbounded();
            let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
                chain_tip,
                Arc::new(ArcSwapOption::empty()),
                Arc::new(RwLock::new(tree)),
            ));
            let sync = Arc::new(BlockSync::new(
                chain,
                Arc::new(PeerTable::new()),
                headers_rx,
                blocks_rx,
                crate::p2p::sync::syncing_ibd_latch(),
            ));
            {
                let mut scheduler = sync.scheduler.lock();
                scheduler
                    .stale_tip
                    .follow(100, GENESIS_HASH, 0, SPACING, t0);
                scheduler.stale_tip.follow(
                    100,
                    GENESIS_HASH,
                    0,
                    SPACING,
                    t0 + Duration::from_mins(35),
                );
            }
            assert!(
                sync.allow_extra_full_relay_dial(),
                "premise: the stale tip armed the extra dial"
            );

            let service = P2pService::new(
                P2pServiceConfig {
                    listen_addrs: Vec::new(),
                    outbound_full_relay_slots: 1,
                    outbound_block_relay_slots: 1,
                    ..P2pServiceConfig::default()
                },
                bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
            );
            let ready: Arc<dyn Fn(PeerSource) + Send + Sync> = Arc::new(|_| {});
            service
                .start(None, None, &ready, {
                    let block_sync_obs: Arc<dyn bitcoin_rs_wire::listener::BlockSyncObserver> =
                        sync.clone();
                    ListenerExtras {
                        block_sync: Some(block_sync_obs),
                        ..ListenerExtras::default()
                    }
                })
                .expect("the service starts");

            let listeners: Vec<TcpListener> = (0..3)
                .map(|_| {
                    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                        .expect("bind a fake peer listener");
                    listener
                        .set_nonblocking(true)
                        .expect("nonblocking fake peer listener");
                    listener
                })
                .collect();
            for listener in &listeners {
                let addr = listener.local_addr().expect("fake peer address");
                service
                    .test_queue_automatic_dial(addr.into())
                    .expect("queue the automatic dial");
            }

            let mut held = Vec::new();
            for (index, listener) in listeners.iter().enumerate() {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match listener.accept() {
                        Ok((stream, _peer)) => {
                            held.push(stream);
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "dial {index} never arrived: the drain loop capped at the un-raised slot total"
                            );
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                }
            }
            assert_eq!(
                held.len(),
                3,
                "all three dials arrived and hold their slots"
            );

            drop(held);
            drop(listeners);
            service.shutdown();
            service.join().expect("clean join");
        }

        #[test]
        fn still_tip_buys_one_extra_dial_and_an_advance_withdraws_it() {
            let t0 = Instant::now();
            let mut state = StaleTipState::default();

            state.follow(100, GENESIS_HASH, 0, SPACING, t0);
            assert!(
                !state.extra_dial_allowed,
                "the first sight of a tip is progress, not staleness"
            );

            state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(29));
            assert!(
                !state.extra_dial_allowed,
                "twenty-nine minutes of standing still is inside the bound"
            );

            state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(40));
            assert!(
                state.extra_dial_allowed,
                "three intervals without a tip move is a stale tip"
            );

            state.follow(101, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(41));
            assert!(
                !state.extra_dial_allowed,
                "an advancing tip withdraws the allowance without waiting for the next check"
            );
        }

        #[test]
        fn a_same_height_tip_change_restarts_the_staleness_clock() {
            let t0 = Instant::now();
            let mut state = StaleTipState::default();

            state.follow(100, GENESIS_HASH, 0, SPACING, t0);
            state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(40));
            assert!(
                state.extra_dial_allowed,
                "premise: the stood-still tip armed the extra dial"
            );

            state.follow(
                100,
                REPLACEMENT_HASH,
                0,
                SPACING,
                t0 + Duration::from_mins(41),
            );
            assert!(
                !state.extra_dial_allowed,
                "a same-height tip change withdraws the allowance at once"
            );

            state.follow(
                100,
                REPLACEMENT_HASH,
                0,
                SPACING,
                t0 + Duration::from_mins(69),
            );
            assert!(
                !state.extra_dial_allowed,
                "the next check finds the new tip only 28 minutes old, inside the bound"
            );

            state.follow(99, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(71));
            assert!(
                !state.extra_dial_allowed,
                "a reorg to a lower tip withdraws the allowance at once"
            );
            state.follow(99, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(82));
            assert!(
                !state.extra_dial_allowed,
                "the due check finds the reorganized tip only 11 minutes old, inside the bound"
            );
            state.follow(99, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(102));
            assert!(
                state.extra_dial_allowed,
                "the next due check finds 31 minutes of stillness on the reorganized tip: stale"
            );
        }

        #[test]
        fn the_staleness_question_is_paced() {
            let t0 = Instant::now();
            let mut state = StaleTipState::default();
            state.follow(100, GENESIS_HASH, 0, SPACING, t0);

            state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(25));
            assert!(!state.extra_dial_allowed, "inside the bound");
            state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(31));
            assert!(
                !state.extra_dial_allowed,
                "past the bound but not yet due for a check"
            );
            state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(35));
            assert!(
                state.extra_dial_allowed,
                "the check that is due finds the tip stale"
            );
        }

        #[test]
        fn in_flight_bodies_hold_staleness_off() {
            let t0 = Instant::now();
            let mut state = StaleTipState {
                last_update: Some(t0),
                ..StaleTipState::default()
            };

            assert!(
                !tip_may_be_stale(&mut state, 0, SPACING, t0 + Duration::from_mins(30)),
                "exactly three intervals is not past the bound"
            );
            assert!(
                tip_may_be_stale(&mut state, 0, SPACING, t0 + Duration::from_mins(31)),
                "past three intervals with nothing in flight the tip is stale"
            );
            assert!(
                !tip_may_be_stale(&mut state, 4, SPACING, t0 + Duration::from_mins(31)),
                "bodies still arriving is progress, not a stalled tip"
            );
        }
        struct RetainerFixture {
            tree: BlockTree,
            genesis: NodeId,
            salt: u32,
        }

        impl RetainerFixture {
            fn new() -> Result<Self, TestError> {
                let mut tree = BlockTree::new();
                let genesis = tree.insert_node(
                    None,
                    Network::Regtest.genesis_block().header,
                    NodeStatus::HeaderValid,
                )?;
                Ok(Self {
                    tree,
                    genesis,
                    salt: 1,
                })
            }

            fn id(&self, hash: Hash256) -> Result<NodeId, TestError> {
                self.tree
                    .lookup(hash)
                    .ok_or_else(|| "an admitted hash is missing from the tree".into())
            }

            fn child(&mut self, parent: NodeId) -> Result<Hash256, TestError> {
                let prev = self.tree.node(parent)?.hash;
                self.salt += 1;
                let header =
                    regtest_fixture::mined_regtest_header(BlockHash::from(prev), self.salt)?;
                let id = self
                    .tree
                    .insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
                Ok(self.tree.node(id)?.hash)
            }

            fn branch(&mut self, from: NodeId, len: usize) -> Result<Vec<Hash256>, TestError> {
                let mut hashes = Vec::with_capacity(len);
                let mut parent = from;
                for _ in 0..len {
                    let hash = self.child(parent)?;
                    parent = self.id(hash)?;
                    hashes.push(hash);
                }
                Ok(hashes)
            }

            fn main_chain(&mut self, len: usize) -> Result<Vec<Hash256>, TestError> {
                let genesis = self.genesis;
                self.branch(genesis, len)
            }
        }

        fn retainer_peer(port: u16) -> PeerSource {
            PeerSource::for_test(SocketAddr::from(([127, 0, 0, 1], port)))
        }

        #[test]
        fn a_refused_initial_tip_stays_offerable_until_sent_or_retired() -> Result<(), TestError> {
            let mut fixture = RetainerFixture::new()?;
            let main = fixture.main_chain(20)?;
            let side = fixture.branch(fixture.id(main[9])?, 2)?;
            let tip = side[1];
            let retainer = StaleTipRetainer::default();
            assert!(retainer.learn(&fixture.tree, tip, None));
            let peer = retainer_peer(41);

            assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
            assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
            assert_eq!(
                retainer.pending_for(peer, |hash| hash != tip),
                Vec::<Hash256>::new()
            );
            assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
            retainer.mark_known(peer, tip);
            assert!(retainer.knows(peer, tip));
            assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
            Ok(())
        }

        #[test]
        fn multiple_refused_initial_tips_retry_in_rank_order() -> Result<(), TestError> {
            let mut fixture = RetainerFixture::new()?;
            let main = fixture.main_chain(20)?;
            let fork = fixture.id(main[9])?;
            let first = fixture.child(fork)?;
            let second = fixture.child(fork)?;
            let third = fixture.child(fork)?;
            let retainer = StaleTipRetainer::default();
            assert!(retainer.learn(&fixture.tree, first, None));
            assert!(retainer.learn(&fixture.tree, second, None));
            assert!(retainer.learn(&fixture.tree, third, None));
            let peer = retainer_peer(42);

            let opening = retainer.pending_for(peer, |hash| hash == first);
            assert_eq!(opening, vec![first]);
            assert_eq!(
                retainer.pending_for(peer, |_| true),
                vec![third, second, first]
            );
            for hash in [third, second, first] {
                retainer.mark_known(peer, hash);
            }
            assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
            Ok(())
        }

        #[test]
        fn deferred_initial_tips_never_exceed_the_opening_cap() -> Result<(), TestError> {
            let mut fixture = RetainerFixture::new()?;
            let main = fixture.main_chain(100)?;
            let fork = fixture.id(main[49])?;
            let retainer = StaleTipRetainer::default();
            let mut leaves = Vec::new();
            for _ in 0..MAX_ADVERTISED_STALETIPS + 3 {
                let leaf = fixture.child(fork)?;
                assert!(retainer.learn(&fixture.tree, leaf, None));
                leaves.push(leaf);
            }
            let peer = retainer_peer(43);

            assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
            let mut expected = leaves[3..].to_vec();
            expected.reverse();
            let retry = retainer.pending_for(peer, |_| true);
            assert_eq!(retry.len(), MAX_ADVERTISED_STALETIPS);
            assert_eq!(retry, expected);
            for hash in &leaves[..3] {
                assert!(!retry.contains(hash));
            }
            for hash in &retry {
                retainer.mark_known(peer, *hash);
            }
            assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
            Ok(())
        }

        #[test]
        fn known_sent_and_retired_tips_leave_the_deferred_backlog() -> Result<(), TestError> {
            let mut fixture = RetainerFixture::new()?;
            let main = fixture.main_chain(20)?;
            let tip = fixture.child(fixture.id(main[9])?)?;
            let retainer = StaleTipRetainer::default();

            let origin = retainer_peer(44);
            assert!(retainer.learn(&fixture.tree, tip, Some(origin)));
            assert_eq!(
                retainer.pending_for(origin, |_| true),
                Vec::<Hash256>::new()
            );

            let peer = retainer_peer(45);
            assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
            assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
            retainer.mark_known(peer, tip);
            assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());

            let late = retainer_peer(46);
            assert_eq!(retainer.pending_for(late, |_| false), Vec::<Hash256>::new());
            retainer.forget_peer(late);
            assert_eq!(retainer.pending_for(late, |_| true), vec![tip]);
            retainer.mark_known(late, tip);
            assert_eq!(retainer.pending_for(late, |_| true), Vec::<Hash256>::new());

            fixture.tree.invalidate_subtree(fixture.id(tip)?)?;
            retainer.prune(&fixture.tree);
            let last = retainer_peer(47);
            assert_eq!(retainer.pending_for(last, |_| true), Vec::<Hash256>::new());
            Ok(())
        }

        #[test]
        fn eligible_initial_offer_without_send_ack_is_offered_again() -> Result<(), TestError> {
            let mut fixture = RetainerFixture::new()?;
            let main = fixture.main_chain(20)?;
            let tip = fixture.child(fixture.id(main[9])?)?;
            let retainer = StaleTipRetainer::default();
            assert!(retainer.learn(&fixture.tree, tip, None));
            let peer = retainer_peer(48);

            assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
            assert!(
                !retainer.knows(peer, tip),
                "offering is not delivery: no send-Ok, no mark"
            );
            assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
            retainer.mark_known(peer, tip);
            assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
            Ok(())
        }

        #[test]
        fn saturated_batch_tail_retries_only_the_unacked_remainder() -> Result<(), TestError> {
            let mut fixture = RetainerFixture::new()?;
            let main = fixture.main_chain(20)?;
            let fork = fixture.id(main[9])?;
            let first = fixture.child(fork)?;
            let second = fixture.child(fork)?;
            let third = fixture.child(fork)?;
            let retainer = StaleTipRetainer::default();
            assert!(retainer.learn(&fixture.tree, first, None));
            assert!(retainer.learn(&fixture.tree, second, None));
            assert!(retainer.learn(&fixture.tree, third, None));
            let peer = retainer_peer(49);

            let opening = retainer.pending_for(peer, |_| true);
            assert_eq!(opening, vec![third, second, first]);
            retainer.mark_known(peer, third);

            assert_eq!(retainer.pending_for(peer, |_| true), vec![second, first]);
            assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
            assert_eq!(retainer.pending_for(peer, |_| true), vec![second, first]);
            retainer.mark_known(peer, second);
            retainer.mark_known(peer, first);
            assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
            Ok(())
        }
    }

    #[test]
    fn failed_branch_switch_reports_the_displaced_tip_once() -> TestResult {
        let genesis = genesis_header();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let side = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
            .or_fail("regtest fixture header");
        let side_id = tree.insert_node(Some(genesis_id), side, NodeStatus::HeaderValid)?;
        let first = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 101)
            .or_fail("regtest fixture header");
        let first_id = tree.insert_node(Some(genesis_id), first, NodeStatus::HeaderValid)?;
        let second = regtest_fixture::mined_regtest_header(first.compute_hash(), 102)
            .or_fail("regtest fixture header");
        tree.insert_node(Some(first_id), second, NodeStatus::HeaderValid)?;

        let other = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 201)
            .or_fail("regtest fixture header");
        tree.insert_node(Some(genesis_id), other, NodeStatus::HeaderValid)?;
        let applied = {
            let node = tree.node(side_id)?;
            TipSnapshot {
                tip_id: side_id,
                chain_tx_count: node.chain_tx_count,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        let displaced = Hash256::from(other.compute_hash());
        let invalidated = vec![
            Hash256::from(first.compute_hash()),
            Hash256::from(second.compute_hash()),
        ];

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::from_pointee(applied));
        let chain = Arc::new(TestChain::new(
            chain_tip,
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        ));
        *chain.scripted_branch_switch.lock() = Some(ScriptedBranchSwitch {
            connected: Vec::new(),
            error: ReorgError::ConnectFailed {
                disconnected: 1,
                connected: 0,
                hash: invalidated[0],
                stopped_at: 0,
                source: Box::new(bitcoin_rs_execution::ApplyError::Shutdown),
                disposition: WindowApplyDisposition::Permanent,
                invalidated: invalidated.into(),
                demoted_tip: Some(displaced),
            },
        });
        let (_inbound_headers_tx, inbound_headers_rx) = unbounded();
        let (_inbound_blocks_tx, inbound_blocks_rx) = unbounded();
        let sync = BlockSync::new(
            chain,
            Arc::new(PeerTable::new()),
            inbound_headers_rx,
            inbound_blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        );

        assert!(sync.outweighed_branch_target().is_some());
        assert_eq!(sync.switch_branch_if_outweighed(), Some(displaced));
        assert_eq!(
            sync.switch_branch_if_outweighed(),
            None,
            "the invalidated branch no longer outweighs the applied tip"
        );
        Ok(())
    }

    struct PunishmentFixture {
        sync: Arc<BlockSync>,
        peers: Arc<PeerTable>,
        chain: Arc<TestChain>,
        blocks_tx: crossbeam_channel::Sender<bitcoin_rs_wire::InboundBlock>,
        block2: Block,
        source: PeerSource,
        _peer_rx: bitcoin_rs_wire::test_support::MessageReceiver,
    }

    fn punishment_fixture() -> Result<PunishmentFixture, TestError> {
        let (mut tree, blocks) = mined_chain(1, 0)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let peers = Arc::new(PeerTable::new());
        let (headers_tx, headers_rx) = unbounded();
        let (blocks_tx, blocks_rx) = unbounded();
        let chain = Arc::new(TestChain::new(
            chain_tip,
            Arc::new(ArcSwapOption::empty()),
            Arc::clone(&block_tree),
        ));
        let chain_handle: Arc<TestChain> = Arc::clone(&chain);
        let chain_ref: Arc<dyn SyncChain> = chain_handle;
        let sync = Arc::new(BlockSync::new(
            chain_ref,
            Arc::clone(&peers),
            headers_rx,
            blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        ));
        blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
        sync.tick();

        let addr = test_addr(9770, 0)?;
        let peer_rx = connect_peer(&peers, synthetic_peer(addr, 2));
        let source = current_source(&peers, addr);
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            blocks[0].block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .or_fail("regtest fixture block");
        headers_tx.send(InboundHeaders {
            headers: vec![block2.header],
            source: Some(source),
            wire_response: true,
        })?;
        sync.tick();
        Ok(PunishmentFixture {
            sync,
            peers,
            chain,
            blocks_tx,
            block2,
            source,
            _peer_rx: peer_rx,
        })
    }

    fn deliver_attributed_body(fixture: &PunishmentFixture) -> TestResult {
        let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(fixture.block2.clone());
        inbound.source = Some(fixture.source);
        fixture.blocks_tx.send(inbound)?;
        fixture.sync.tick();
        Ok(())
    }

    #[test]
    fn permanent_consensus_body_disconnects_delivering_source() -> TestResult {
        let fixture = punishment_fixture()?;
        let hash = Hash256::from(fixture.block2.block_hash());
        *fixture.chain.scripted_commit_failure.lock() =
            Some((hash, WindowApplyDisposition::Permanent));

        deliver_attributed_body(&fixture)?;

        assert!(
            !fixture.peers.is_current(fixture.source),
            "the connection that served a consensus-invalid block must be disconnected"
        );
        Ok(())
    }

    #[test]
    fn binding_and_operational_failures_do_not_disconnect() -> TestResult {
        for disposition in [
            WindowApplyDisposition::BodyMutated,
            WindowApplyDisposition::Operational,
        ] {
            let fixture = punishment_fixture()?;
            let hash = Hash256::from(fixture.block2.block_hash());
            *fixture.chain.scripted_commit_failure.lock() = Some((hash, disposition));

            deliver_attributed_body(&fixture)?;

            assert!(
                fixture.peers.is_current(fixture.source),
                "a {disposition:?} settlement failure must not disconnect the delivering connection"
            );
        }
        Ok(())
    }

    #[test]
    fn telemetry_ibd_bit_agrees_with_the_shared_latch() -> TestResult {
        let now = bitcoin_rs_consensus::primitives::unix_time_secs();

        let syncing = SyncHarness::new(BlockTree::new());

        assert!(
            syncing.block_tree.read().tip().is_none(),
            "the active snapshot must run over a frontier with no header tip"
        );
        assert!(
            syncing.applied_tip.load_full().is_none(),
            "the active snapshot must run over a frontier with no applied tip"
        );
        assert!(
            syncing.sync.ibd.is_active(now, Network::Regtest),
            "the fixture latch must be active for this snapshot"
        );
        assert!(
            syncing.sync.in_initial_block_download(),
            "telemetry must report initial block download while the latch is active"
        );

        let (tree, _blocks) = mined_chain(0, 3)?;
        let synced = SyncHarness::with_ibd(tree, synced_ibd_latch());

        assert!(
            synced.applied_tip.load_full().is_none(),
            "the latched-off snapshot must leave the applied tip absent"
        );
        assert_eq!(
            synced.block_tree.read().tip().map(|tip| tip.height),
            Some(3),
            "the latched-off snapshot must carry a header tip at height 3"
        );
        assert!(
            !synced.sync.ibd.is_active(now, Network::Regtest),
            "the fixture latch must have left initial block download"
        );
        assert!(
            !synced.sync.in_initial_block_download(),
            "telemetry must stay out of initial block download once the latch \
         has left it, even with headers ahead of the applied tip"
        );
        Ok(())
    }

    struct NotFoundFixture {
        sync: BlockSync,
        peers: Arc<PeerTable>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        blocks: Vec<Block>,
        blocks_tx: InboundBlockSender,
        owner: PeerRemote,
        owner_rx: bitcoin_rs_wire::test_support::MessageReceiver,
        alternate: PeerRemote,
        alternate_rx: Option<bitcoin_rs_wire::test_support::MessageReceiver>,
    }

    impl NotFoundFixture {
        fn two_peers(budget: super::SyncBudget) -> Result<Self, TestError> {
            Self::connect(budget, true)
        }

        fn owner_only(budget: super::SyncBudget) -> Result<Self, TestError> {
            Self::connect(budget, false)
        }

        fn connect(budget: super::SyncBudget, with_alternate: bool) -> Result<Self, TestError> {
            let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(3)?;
            install_budget(&sync, budget);
            let owner = test_addr(9_810, 0)?;
            let alternate = test_addr(9_810, 1)?;
            let mut relaying = synthetic_peer(owner, 200);
            relaying.compact_block_relay = true;
            let owner_rx = connect_peer(&peers, relaying);
            let alternate_rx =
                with_alternate.then(|| connect_peer(&peers, synthetic_peer(alternate, 100)));
            Ok(Self {
                sync,
                peers,
                applied_tip,
                blocks,
                blocks_tx,
                owner,
                owner_rx,
                alternate,
                alternate_rx,
            })
        }

        fn hash(&self, index: usize) -> Hash256 {
            Hash256::from(self.blocks[index].block_hash())
        }

        fn inventory(&self, index: usize, compact: bool) -> Inventory {
            let hash = bitcoin::BlockHash::from_byte_array(*self.hash(index).as_byte_array());
            if compact {
                Inventory::CompactBlock(hash)
            } else {
                Inventory::WitnessBlock(hash)
            }
        }

        fn deliver(&self, source: PeerSource, index: usize) -> TestResult {
            let mut inbound = bitcoin_rs_wire::InboundBlock::from_local(self.blocks[index].clone());
            inbound.source = Some(source);
            self.blocks_tx.send(inbound)?;
            Ok(())
        }

        fn applied_height(&self) -> Option<u32> {
            self.applied_tip.load_full().map(|tip| tip.height)
        }

        fn alternate_getdata(&self) -> Vec<Inventory> {
            self.alternate_rx
                .as_ref()
                .map_or_else(Vec::new, drain_getdata_items)
        }

        fn owner_getdata(&self) -> Vec<Inventory> {
            drain_getdata_items(&self.owner_rx)
        }
    }

    fn one_request_peer_budget() -> super::SyncBudget {
        super::SyncBudget {
            max_pending_blocks: 1,
            max_peer_inflight: 1,
            getdata_batch_limit: 1,
            ..super::default_sync_budget(Network::Regtest)
        }
    }

    fn drain_getdata_items(rx: &bitcoin_rs_wire::test_support::MessageReceiver) -> Vec<Inventory> {
        let mut items = Vec::new();
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                items.extend(inventory);
            }
        }
        items
    }

    #[test]
    fn notfound_from_owner_replans_the_body_to_the_alternate_once_with_one_request_peer()
    -> TestResult {
        let fixture = NotFoundFixture::two_peers(one_request_peer_budget())?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let alternate_source = current_source(&fixture.peers, fixture.alternate);
        let x1 = fixture.hash(0);

        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);
        assert_eq!(fixture.alternate_getdata(), Vec::<Inventory>::new());
        assert!(fixture.sync.owns_body_fetch(owner_source, x1));

        assert!(
            fixture
                .sync
                .block_not_found(owner_source, &[fixture.inventory(0, true)])
        );
        assert!(!fixture.sync.owns_body_fetch(owner_source, x1));

        for _ in 0..4 {
            fixture.sync.tick();
        }
        assert!(
            fixture.owner_getdata().is_empty(),
            "an owner that answered notfound is not asked again at wake-up pace"
        );
        assert_eq!(
            fixture.alternate_getdata(),
            vec![fixture.inventory(0, false)]
        );
        assert!(fixture.sync.owns_body_fetch(alternate_source, x1));
        assert!(
            fixture.peers.is_connected(fixture.owner),
            "a peer that lacks a body is not punished"
        );

        fixture.deliver(alternate_source, 0)?;
        let mut requests: Vec<(usize, usize)> = Vec::new();
        for _ in 0..16 {
            fixture.sync.tick();
            if fixture.applied_height() == Some(3) {
                break;
            }
            for (peer, rx, source) in [
                (0, Some(&fixture.owner_rx), owner_source),
                (1, fixture.alternate_rx.as_ref(), alternate_source),
            ] {
                let Some(rx) = rx else { continue };
                for item in drain_getdata_items(rx) {
                    let (Inventory::CompactBlock(hash) | Inventory::WitnessBlock(hash)) = item
                    else {
                        return Err(std::io::Error::other("unexpected inventory flavor").into());
                    };
                    let hash = Hash256::from_le_bytes(hash.as_byte_array());
                    let index = (0..fixture.blocks.len())
                        .find(|index| fixture.hash(*index) == hash)
                        .ok_or("served an unknown body")?;
                    requests.push((peer, index));
                    fixture.deliver(source, index)?;
                }
            }
        }
        assert_eq!(fixture.applied_height(), Some(3), "sync must complete");
        assert_eq!(
            requests,
            [(0, 1), (0, 2)],
            "the released body was requested exactly once (from the alternate, above); \
         the owner serves the later bodies"
        );
        Ok(())
    }

    #[test]
    fn notfound_owner_with_request_headroom_is_skipped_and_the_alternate_serves_the_released_body()
    -> TestResult {
        let fixture = NotFoundFixture::two_peers(super::default_sync_budget(Network::Regtest))?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let alternate_source = current_source(&fixture.peers, fixture.alternate);

        fixture.sync.tick();
        assert_eq!(
            fixture.owner_getdata(),
            vec![
                fixture.inventory(0, true),
                fixture.inventory(1, true),
                fixture.inventory(2, true)
            ]
        );
        assert_eq!(fixture.alternate_getdata(), Vec::<Inventory>::new());

        assert!(
            fixture
                .sync
                .block_not_found(owner_source, &[fixture.inventory(0, true)])
        );
        assert!(fixture.sync.owns_body_fetch(owner_source, fixture.hash(1)));
        for _ in 0..3 {
            fixture.sync.tick();
        }
        assert_eq!(fixture.owner_getdata(), Vec::<Inventory>::new());
        assert_eq!(
            fixture.alternate_getdata(),
            vec![fixture.inventory(0, false)],
            "the alternate is asked for exactly the released body, once"
        );

        fixture.deliver(alternate_source, 0)?;
        fixture.deliver(owner_source, 1)?;
        fixture.deliver(owner_source, 2)?;
        for _ in 0..4 {
            fixture.sync.tick();
            if fixture.applied_height() == Some(3) {
                break;
            }
        }
        assert_eq!(fixture.applied_height(), Some(3), "sync must complete");
        Ok(())
    }

    #[test]
    fn two_refusing_peers_do_not_starve_a_lower_ranked_holder() -> TestResult {
        let fixture = NotFoundFixture::two_peers(one_request_peer_budget())?;

        let holder = test_addr(9_810, 2)?;
        let holder_rx = connect_peer(&fixture.peers, synthetic_peer(holder, 90));
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let alternate_source = current_source(&fixture.peers, fixture.alternate);
        let holder_source = current_source(&fixture.peers, holder);
        let x0 = fixture.hash(0);

        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);
        assert_eq!(fixture.alternate_getdata(), Vec::<Inventory>::new());
        assert_eq!(drain_getdata_items(&holder_rx), Vec::<Inventory>::new());
        assert!(
            fixture
                .sync
                .block_not_found(owner_source, &[fixture.inventory(0, true)])
        );

        fixture.sync.tick();
        assert_eq!(
            fixture.owner_getdata(),
            Vec::<Inventory>::new(),
            "a peer that answered notfound is not re-asked while its record lives"
        );
        assert_eq!(
            fixture.alternate_getdata(),
            vec![fixture.inventory(0, false)]
        );
        assert_eq!(drain_getdata_items(&holder_rx), Vec::<Inventory>::new());
        assert!(
            fixture
                .sync
                .block_not_found(alternate_source, &[fixture.inventory(0, true)])
        );

        let now = Instant::now();
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .body_unavailable
                .refuses(owner_source, x0, now),
            "the first refusal survives the second under retention bounding"
        );
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .body_unavailable
                .refuses(alternate_source, x0, now),
            "the second refusal is recorded"
        );
        for _ in 0..4 {
            fixture.sync.tick();
        }
        assert_eq!(
            fixture.owner_getdata(),
            Vec::<Inventory>::new(),
            "neither refuser is re-asked before the retry interval"
        );
        assert_eq!(
            fixture.alternate_getdata(),
            Vec::<Inventory>::new(),
            "neither refuser is re-asked before the retry interval"
        );
        assert_eq!(
            drain_getdata_items(&holder_rx),
            vec![fixture.inventory(0, false)],
            "the lower-ranked holder is asked exactly once"
        );
        assert!(fixture.sync.owns_body_fetch(holder_source, x0));
        for peer in [fixture.owner, fixture.alternate, holder] {
            assert!(
                fixture.peers.is_connected(peer),
                "a peer that lacks a body is not punished"
            );
        }
        Ok(())
    }

    #[test]
    fn notfound_only_releases_for_the_exact_current_owner_session() -> TestResult {
        let fixture = NotFoundFixture::two_peers(one_request_peer_budget())?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let alternate_source = current_source(&fixture.peers, fixture.alternate);
        let x1 = fixture.hash(0);
        let now = Instant::now();
        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);

        assert!(
            !fixture
                .sync
                .block_not_found(alternate_source, &[fixture.inventory(0, true)])
        );

        assert!(
            !fixture
                .sync
                .block_not_found(owner_source, &[fixture.inventory(1, true)])
        );

        let txid = bitcoin::Txid::from_byte_array([7; 32]);
        assert!(
            !fixture
                .sync
                .block_not_found(owner_source, &[Inventory::Transaction(txid)])
        );
        assert!(fixture.sync.owns_body_fetch(owner_source, x1));
        {
            let scheduler = fixture.sync.scheduler.lock();
            assert!(
                !scheduler
                    .body_unavailable
                    .refuses(alternate_source, x1, now)
            );
            assert!(!scheduler.body_unavailable.refuses(owner_source, x1, now));
            assert!(
                !scheduler
                    .body_unavailable
                    .refuses(owner_source, fixture.hash(1), now)
            );
        }

        let replacement_rx = connect_peer(&fixture.peers, synthetic_peer(fixture.owner, 200));
        let replacement_source = current_source(&fixture.peers, fixture.owner);
        assert_ne!(replacement_source, owner_source);
        assert!(
            !fixture
                .sync
                .block_not_found(owner_source, &[fixture.inventory(0, true)]),
            "a retired session cannot release"
        );
        assert!(
            !fixture
                .sync
                .block_not_found(replacement_source, &[fixture.inventory(0, true)]),
            "a replacement cannot release its predecessor's request"
        );
        assert!(fixture.sync.owns_body_fetch(owner_source, x1));
        {
            let scheduler = fixture.sync.scheduler.lock();
            assert!(!scheduler.body_unavailable.refuses(owner_source, x1, now));
            assert!(
                !scheduler
                    .body_unavailable
                    .refuses(replacement_source, x1, now)
            );
        }

        fixture.sync.tick();
        assert_eq!(
            drain_getdata_items(&replacement_rx),
            vec![fixture.inventory(0, false)]
        );
        assert_eq!(fixture.alternate_getdata(), Vec::<Inventory>::new());
        Ok(())
    }

    #[test]
    fn notfound_only_peer_is_retried_after_the_interval_and_not_starved_or_polled() -> TestResult {
        let fixture = NotFoundFixture::owner_only(one_request_peer_budget())?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let x1 = fixture.hash(0);
        let notfound = [fixture.inventory(0, true)];

        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);
        assert!(fixture.sync.block_not_found(owner_source, &notfound));

        for _ in 0..4 {
            fixture.sync.tick();
        }
        assert!(
            fixture.owner_getdata().is_empty(),
            "no wake-up-paced getdata/notfound loop against the only peer"
        );
        assert!(
            fixture.peers.is_connected(fixture.owner),
            "a peer that lacks a body is not disconnected"
        );

        let aged = Instant::now()
            .checked_sub(BODY_UNAVAILABLE_RETRY + Duration::from_secs(1))
            .ok_or("monotonic clock is younger than the retry interval")?;
        fixture
            .sync
            .scheduler
            .lock()
            .body_unavailable
            .note(owner_source, x1, aged);
        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);
        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), Vec::<Inventory>::new());

        assert!(fixture.sync.block_not_found(owner_source, &notfound));
        for _ in 0..3 {
            fixture.sync.tick();
        }
        assert_eq!(fixture.owner_getdata(), Vec::<Inventory>::new());
        assert!(fixture.sync.scheduler.lock().body_unavailable.refuses(
            owner_source,
            x1,
            Instant::now()
        ));

        assert!(fixture.peers.disconnect_source(owner_source));
        fixture.sync.tick();
        assert!(!fixture.sync.scheduler.lock().body_unavailable.refuses(
            owner_source,
            x1,
            Instant::now()
        ));
        Ok(())
    }

    #[test]
    fn delivering_the_body_ends_the_notfound_demotion() -> TestResult {
        let fixture = NotFoundFixture::owner_only(one_request_peer_budget())?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let x1 = fixture.hash(0);
        let notfound = [fixture.inventory(0, true)];

        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);
        assert!(fixture.sync.block_not_found(owner_source, &notfound));
        assert!(fixture.sync.scheduler.lock().body_unavailable.refuses(
            owner_source,
            x1,
            Instant::now()
        ));

        fixture.deliver(owner_source, 0)?;
        fixture.sync.tick();
        assert!(!fixture.sync.scheduler.lock().body_unavailable.refuses(
            owner_source,
            x1,
            Instant::now()
        ));
        Ok(())
    }

    #[test]
    fn notfound_releases_a_deferred_owned_fetch_only_for_its_exact_owner() -> TestResult {
        let fixture = NotFoundFixture::two_peers(one_request_peer_budget())?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let alternate_source = current_source(&fixture.peers, fixture.alternate);
        let x1 = fixture.hash(0);
        let notfound = [fixture.inventory(0, false)];

        assert!(
            fixture
                .sync
                .enqueue_owned_body_fetch(owner_source, x1, || true)
        );
        assert!(fixture.sync.owns_body_fetch(owner_source, x1));

        assert!(
            !fixture.sync.block_not_found(alternate_source, &notfound),
            "a connection that does not own the fetch cannot release it"
        );
        assert!(fixture.sync.owns_body_fetch(owner_source, x1));

        assert!(fixture.sync.block_not_found(owner_source, &notfound));
        assert!(
            !fixture.sync.owns_body_fetch(owner_source, x1),
            "the exact owner's notfound drops its deferred mark"
        );
        assert!(fixture.sync.scheduler.lock().body_unavailable.refuses(
            owner_source,
            x1,
            Instant::now()
        ));
        assert!(
            !fixture.sync.block_not_found(owner_source, &notfound),
            "a second notfound finds nothing left to release"
        );
        Ok(())
    }

    struct TreeReadHook {
        chain: Arc<TestChain>,
        on_next_tree_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl SyncChain for TreeReadHook {
        fn network(&self) -> Network {
            self.chain.network()
        }

        fn block_tree(&self) -> parking_lot::RwLockReadGuard<'_, BlockTree> {
            let action = self.on_next_tree_read.lock().take();
            if let Some(action) = action {
                action();
            }
            self.chain.block_tree()
        }

        fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.chain.chain_tip()
        }

        fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.chain.applied_tip()
        }

        fn bootstrap_genesis(&self) {
            self.chain.bootstrap_genesis();
        }

        fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
            self.chain.admit_headers(headers)
        }

        fn minimum_chain_work(&self) -> ChainWork {
            self.chain.minimum_chain_work()
        }

        fn check_body_binding(&self, block: &BlockImage) -> Result<(), SyncChainError> {
            self.chain.check_body_binding(block)
        }

        fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
            self.chain.window_len(serialized_sizes)
        }

        fn commit_window(&self, payloads: &[&BlockImage]) -> Result<usize, WindowCommitError> {
            self.chain.commit_window(payloads)
        }

        fn switch_to_branch(
            &self,
            target: NodeId,
            staged_body: &mut dyn FnMut(Hash256) -> Option<BlockImage>,
            connected_body: &mut dyn FnMut(Hash256),
        ) -> Result<(), ReorgError> {
            self.chain
                .switch_to_branch(target, staged_body, connected_body)
        }
    }

    #[test]
    fn notfound_landing_inside_a_deferred_fetch_resolve_still_releases_the_exact_owner_mark()
    -> TestResult {
        let (mut tree, blocks) = mined_chain(2, 0)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let test_chain = Arc::new(TestChain::new(
            chain_tip,
            Arc::new(ArcSwapOption::empty()),
            Arc::clone(&block_tree),
        ));
        let hooked = Arc::new(TreeReadHook {
            chain: test_chain,
            on_next_tree_read: Mutex::new(None),
        });
        let peers = Arc::new(PeerTable::new());
        let (_headers_tx, headers_rx) = unbounded();
        let (_blocks_tx, blocks_rx) = unbounded();
        let chain: Arc<dyn SyncChain> = hooked.clone();
        let sync = Arc::new(BlockSync::new(
            chain,
            Arc::clone(&peers),
            headers_rx,
            blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        ));
        let declining = test_addr(9_840, 0)?;
        let bystander = test_addr(9_840, 1)?;
        let _declining_rx = connect_peer(&peers, synthetic_peer(declining, 100));
        let _bystander_rx = connect_peer(&peers, synthetic_peer(bystander, 100));
        let declining_source = current_source(&peers, declining);
        let bystander_source = current_source(&peers, bystander);
        let declined = Hash256::from(blocks[0].block_hash());
        let kept = Hash256::from(blocks[1].block_hash());
        assert!(sync.enqueue_owned_body_fetch(declining_source, declined, || true));
        assert!(sync.enqueue_owned_body_fetch(bystander_source, kept, || true));

        let matched = Arc::new(Mutex::new(false));
        let action_sync = Arc::clone(&sync);
        let action_matched = Arc::clone(&matched);
        *hooked.on_next_tree_read.lock() = Some(Box::new(move || {
            let notfound = Inventory::CompactBlock(bitcoin::BlockHash::from_byte_array(
                *declined.as_byte_array(),
            ));
            *action_matched.lock() = action_sync.block_not_found(declining_source, &[notfound]);
        }));
        sync.resolve_owned_body_fetches();

        assert!(
            *matched.lock(),
            "a notfound during resolution must match the exact owner's mark"
        );
        assert!(
            !sync.owns_body_fetch(declining_source, declined),
            "the stale snapshot must not re-create a request the owner declined"
        );
        assert!(
            sync.scheduler.lock().body_unavailable.refuses(
                declining_source,
                declined,
                Instant::now()
            ),
            "the answer is recorded against the exact owner"
        );
        assert!(
            sync.owns_body_fetch(bystander_source, kept),
            "a mark nobody released still resolves"
        );

        sync.resolve_owned_body_fetches();
        assert!(!sync.owns_body_fetch(declining_source, declined));
        Ok(())
    }

    #[test]
    fn retired_generation_cannot_install_a_resolved_deferred_fetch_snapshot() -> TestResult {
        let fixture = punishment_fixture()?;
        let hash = Hash256::from_le_bytes(&[0x91; 32]);
        assert!(
            fixture
                .sync
                .enqueue_owned_body_fetch(fixture.source, hash, || true)
        );

        assert!(fixture.peers.disconnect_source(fixture.source));
        let addr = test_addr(9770, 0)?;
        let _replacement_rx = connect_peer(&fixture.peers, synthetic_peer(addr, 2));
        let replacement = current_source(&fixture.peers, addr);
        assert_ne!(replacement, fixture.source);
        assert!(
            fixture
                .sync
                .scheduler
                .lock()
                .owned_body_fetches
                .contains(&(fixture.source, hash))
        );

        fixture
            .sync
            .install_resolved_owned_body_fetch(fixture.source, hash, 2);

        let scheduler = fixture.sync.scheduler.lock();
        assert_eq!(scheduler.window.pending_owner(&hash), None);
        assert!(
            !scheduler
                .owned_body_fetches
                .contains(&(fixture.source, hash))
        );
        assert!(
            !scheduler
                .body_unavailable
                .refuses(replacement, hash, Instant::now()),
            "session invalidation must not fabricate a notfound for its replacement"
        );
        Ok(())
    }

    #[test]
    fn unavailable_body_ledger_is_bounded_exact_source_and_expires() {
        use super::requests::UnavailableBodies;

        let first = PeerSource::for_test(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_820));
        let second = PeerSource::for_test(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_821));
        let hash = |byte: u8| Hash256::from_le_bytes(&[byte; 32]);
        let base = Instant::now();
        let mut ledger = UnavailableBodies::new();

        ledger.note(first, hash(1), base);
        ledger.note(first, hash(2), base + Duration::from_secs(1));
        ledger.note(second, hash(3), base + Duration::from_secs(2));
        let now = base + Duration::from_secs(2);
        assert!(
            ledger.refuses(first, hash(1), now),
            "live records are retained regardless of pending-budget pressure"
        );
        assert!(ledger.refuses(first, hash(2), now));
        assert!(ledger.refuses(second, hash(3), now));
        assert!(
            !ledger.refuses(second, hash(2), now),
            "records are keyed by exact connection"
        );

        ledger.clear(first, hash(2));
        assert!(!ledger.refuses(first, hash(2), now));
        ledger.retain_owned_by(|source| *source != second);
        assert!(!ledger.refuses(second, hash(3), now));

        ledger.note(first, hash(4), now);
        assert!(ledger.refuses(first, hash(4), now));
        assert!(
            ledger.refuses(
                first,
                hash(4),
                now + BODY_UNAVAILABLE_RETRY.saturating_sub(Duration::from_millis(1)),
            ),
            "a record refuses until the interval has passed"
        );
        assert!(
            !ledger.refuses(first, hash(4), now + BODY_UNAVAILABLE_RETRY),
            "a record older than the interval refuses nothing"
        );
    }

    #[test]
    fn small_pending_budget_keeps_live_records_for_other_peers() -> TestResult {
        let fixture = NotFoundFixture::two_peers(one_request_peer_budget())?;
        let owner_source = current_source(&fixture.peers, fixture.owner);
        let alternate_source = current_source(&fixture.peers, fixture.alternate);
        let x1 = fixture.hash(0);
        let now = Instant::now();

        fixture.sync.tick();
        assert_eq!(fixture.owner_getdata(), vec![fixture.inventory(0, true)]);
        assert!(
            fixture
                .sync
                .block_not_found(owner_source, &[fixture.inventory(0, true)])
        );

        for _ in 0..4 {
            fixture.sync.tick();
        }
        assert_eq!(
            fixture.alternate_getdata(),
            vec![fixture.inventory(0, false)]
        );
        assert!(
            fixture
                .sync
                .block_not_found(alternate_source, &[fixture.inventory(0, false)])
        );

        let scheduler = fixture.sync.scheduler.lock();
        assert!(
            scheduler.body_unavailable.refuses(owner_source, x1, now),
            "the first refuser's live record survives the second refusal"
        );
        assert!(
            scheduler
                .body_unavailable
                .refuses(alternate_source, x1, now),
            "the second refuser's live record is kept"
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::chain::{
        HeaderAdmission, HistoricalAdvance, ReorgError, SyncChain, SyncChainError,
        WindowApplyDisposition, WindowCommitError,
    };
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::{Block, BlockImage, Hash256, Header, Network, Txid};
    use bitcoin_rs_execution::chain::{
        BlockTree, InitialBlockDownload, NodeId, NodeStatus, TipSnapshot, regtest_fixture,
    };
    use bitcoin_rs_wire::test_support::OrFail;
    use parking_lot::{Mutex, RwLock};
    use std::sync::Arc;

    pub(super) struct ScriptedBranchSwitch {
        pub(super) connected: Vec<Hash256>,
        pub(super) error: ReorgError,
    }

    pub(crate) struct TestChain {
        pub(super) network: Network,
        pub(super) block_tree: Arc<RwLock<BlockTree>>,
        pub(super) chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        pub(super) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        pub(super) minimum_chain_work: ChainWork,
        pub(super) scripted_commit_failure: Mutex<Option<(Hash256, WindowApplyDisposition)>>,
        pub(super) scripted_branch_switch: Mutex<Option<ScriptedBranchSwitch>>,
        pub(super) scripted_tip_update: Mutex<Option<(Arc<TipSnapshot>, Arc<TipSnapshot>)>>,
        pub(super) historical: Mutex<std::collections::VecDeque<(u32, Hash256)>>,
        pub(super) historical_connected: Mutex<Vec<Hash256>>,
        pub(super) historical_replay_pending: Mutex<bool>,
        closed_for_recovery: std::sync::atomic::AtomicBool,
    }

    impl TestChain {
        pub(crate) fn new(
            chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
            applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
            block_tree: Arc<RwLock<BlockTree>>,
        ) -> Self {
            Self {
                network: Network::Regtest,
                block_tree,
                chain_tip,
                applied_tip,
                minimum_chain_work: ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work()),
                scripted_commit_failure: Mutex::new(None),
                scripted_branch_switch: Mutex::new(None),
                scripted_tip_update: Mutex::new(None),
                historical: Mutex::new(std::collections::VecDeque::new()),
                historical_connected: Mutex::new(Vec::new()),
                historical_replay_pending: Mutex::new(false),
                closed_for_recovery: std::sync::atomic::AtomicBool::new(false),
            }
        }

        pub(crate) fn close_for_recovery(&self) {
            self.closed_for_recovery
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl TestChain {
        fn body_binding(&self, tree: &BlockTree, block: &BlockImage) -> Result<(), SyncChainError> {
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let segwit_active = tree
                .lookup(hash)
                .and_then(|node_id| tree.node(node_id).ok())
                .is_none_or(|node| {
                    bitcoin_rs_execution::chain::softfork_state(
                        tree,
                        self.network,
                        node.parent,
                        node.height,
                    )
                    .segwit_active
                });
            bitcoin_rs_consensus::check_image_body_binding(
                block,
                bitcoin_rs_consensus::BlockRuleContext { segwit_active },
            )
            .map_err(SyncChainError::from)
        }

        #[must_use]
        pub(crate) const fn with_minimum_chain_work(mut self, minimum: ChainWork) -> Self {
            self.minimum_chain_work = minimum;
            self
        }
    }

    impl SyncChain for TestChain {
        fn historical_base(&self) -> Option<Hash256> {
            self.historical.lock().back().map(|(_, hash)| *hash)
        }

        fn closed_for_recovery(&self) -> bool {
            self.closed_for_recovery
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn advance_historical(&self) -> Result<HistoricalAdvance, SyncChainError> {
            if std::mem::take(&mut *self.historical_replay_pending.lock()) {
                return Ok(HistoricalAdvance::ReplayPending);
            }
            Ok(self
                .historical
                .lock()
                .front()
                .copied()
                .map_or(HistoricalAdvance::Complete, |(height, hash)| {
                    HistoricalAdvance::MissingBody { height, hash }
                }))
        }

        fn connect_historical(&self, payload: &BlockImage) -> Result<(), SyncChainError> {
            let hash = payload.block_hash().0;
            assert_eq!(
                self.historical.lock().pop_front().map(|(_, hash)| hash),
                Some(hash)
            );
            self.historical_connected.lock().push(hash);
            Ok(())
        }
        fn network(&self) -> Network {
            self.network
        }

        fn block_tree(&self) -> parking_lot::RwLockReadGuard<'_, BlockTree> {
            self.block_tree.read()
        }

        fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
            let tip = self.chain_tip.load_full();
            let update = self.scripted_tip_update.lock().take();
            if let Some((chain, applied)) = update {
                self.chain_tip.store(Some(chain));
                self.applied_tip.store(Some(applied));
            }
            tip
        }

        fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
            self.applied_tip.load_full()
        }

        fn bootstrap_genesis(&self) {
            if self.applied_tip.load_full().is_some() {
                return;
            }
            let genesis = self.network.genesis_block();
            let hash = Hash256::from_le_bytes(genesis.block_hash().as_bytes());
            let tree = self.block_tree.read();
            let Some(id) = tree.lookup(hash) else {
                return;
            };
            let Ok(node) = tree.node(id) else {
                return;
            };
            let snapshot = Arc::new(TipSnapshot {
                tip_id: id,
                chain_tx_count: node.chain_tx_count,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            });
            self.applied_tip.store(Some(Arc::clone(&snapshot)));
            if self.chain_tip.load_full().is_none() {
                self.chain_tip.store(Some(snapshot));
            }
        }

        fn minimum_chain_work(&self) -> ChainWork {
            self.minimum_chain_work
        }

        fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
            let mut tree = self.block_tree.write();
            match bitcoin_rs_execution::chain::accept_headers(
                &mut tree,
                headers,
                self.network,
                bitcoin_rs_execution::chain::current_unix_seconds(),
                bitcoin_rs_execution::chain::HeaderValidationMode::LiveAdmission,
            ) {
                Ok(admitted) => {
                    let announced_tip = admitted
                        .ids
                        .last()
                        .and_then(|id| tree.node(*id).ok())
                        .map(|node| node.hash);
                    let active_height =
                        tree.tip()
                            .zip(announced_tip)
                            .and_then(|(active_tip, hash)| {
                                tree.active_height_of(active_tip.tip_id, hash)
                                    .and_then(|height| i32::try_from(height).ok())
                            });
                    HeaderAdmission::Accepted {
                        accepted: admitted.ids.len(),
                        announced_tip,
                        active_height,
                        demoted_tip: admitted.demoted_tip,
                    }
                }
                Err(error) => HeaderAdmission::Rejected(error),
            }
        }

        fn check_body_binding(&self, block: &BlockImage) -> Result<(), SyncChainError> {
            let tree = self.block_tree.read();
            self.body_binding(&tree, block)
        }

        fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
            const MAX_BLOCKS: usize = 1024;
            const MAX_BYTES: usize = 64 << 20;
            let mut count = 0_usize;
            let mut bytes = 0_usize;
            for size in serialized_sizes {
                if count == MAX_BLOCKS {
                    break;
                }
                let next = bytes.saturating_add(size);
                if count > 0 && next > MAX_BYTES {
                    break;
                }
                bytes = next;
                count += 1;
            }
            count
        }

        fn commit_window(&self, payloads: &[&BlockImage]) -> Result<usize, WindowCommitError> {
            let mut tree = self.block_tree.write();
            let mut applied = 0_usize;
            for payload in payloads {
                let hash = Hash256::from_le_bytes(payload.block_hash().as_bytes());
                let scripted = *self.scripted_commit_failure.lock();
                let failure = match scripted {
                    Some((fail_hash, _)) if fail_hash == hash => {
                        self.scripted_commit_failure.lock().take()
                    }
                    _ => None,
                };
                if let Some((_, disposition)) = failure {
                    if disposition == WindowApplyDisposition::Fatal {
                        self.closed_for_recovery
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    return Err(WindowCommitError {
                        applied,
                        disposition,
                        invalidated: Box::default(),
                        source: std::io::Error::other("scripted commit failure").into(),
                    });
                }
                let Some(node_id) = tree.lookup(hash) else {
                    return Err(WindowCommitError {
                        applied,
                        disposition: WindowApplyDisposition::Operational,
                        invalidated: Box::default(),
                        source: std::io::Error::other("commit block not in tree").into(),
                    });
                };
                if payload.tx_count() > 1
                    && (1..payload.tx_count()).any(|index| {
                        payload.tx(index).input_count() == 1
                            && payload.tx(index).input_outpoint(0).txid == Txid::default()
                            && payload.tx(index).input_outpoint(0).vout == u32::MAX
                    })
                {
                    let invalidated = tree
                        .invalidate_subtree(node_id)
                        .map(|outcome| outcome.invalid.into_boxed_slice())
                        .unwrap_or_default();
                    return Err(WindowCommitError {
                        applied,
                        disposition: WindowApplyDisposition::Permanent,
                        invalidated,
                        source: std::io::Error::other("extra coinbase").into(),
                    });
                }
                if payload.tx_count() > 0 {
                    if let Err(source) = self.body_binding(&tree, payload) {
                        return Err(WindowCommitError {
                            applied,
                            disposition: WindowApplyDisposition::BodyMutated,
                            invalidated: Box::default(),
                            source,
                        });
                    }
                }
                let Ok(node) = tree.node(node_id) else {
                    return Err(WindowCommitError {
                        applied,
                        disposition: WindowApplyDisposition::Operational,
                        invalidated: Box::default(),
                        source: std::io::Error::other("commit node missing").into(),
                    });
                };
                self.applied_tip.store(Some(Arc::new(TipSnapshot {
                    tip_id: node_id,
                    chain_tx_count: node.chain_tx_count,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                })));
                applied = applied.saturating_add(1);
            }
            Ok(applied)
        }

        fn switch_to_branch(
            &self,
            _target: NodeId,
            _staged_body: &mut dyn FnMut(Hash256) -> Option<BlockImage>,
            connected_body: &mut dyn FnMut(Hash256),
        ) -> Result<(), ReorgError> {
            let scripted = self.scripted_branch_switch.lock().take();
            if let Some(scripted) = scripted {
                for hash in &scripted.connected {
                    let tip = {
                        let tree = self.block_tree.read();
                        tree.lookup(*hash).and_then(|node_id| {
                            tree.node(node_id).ok().map(|node| {
                                Arc::new(TipSnapshot {
                                    tip_id: node_id,
                                    chain_tx_count: node.chain_tx_count,
                                    height: node.height,
                                    chainwork: node.chainwork,
                                    hash: node.hash,
                                })
                            })
                        })
                    };
                    if let Some(tip) = tip {
                        self.applied_tip.store(Some(tip));
                    }
                    connected_body(*hash);
                }
                if let ReorgError::ConnectFailed {
                    hash,
                    disposition: WindowApplyDisposition::Permanent,
                    ..
                } = &scripted.error
                {
                    let mut tree = self.block_tree.write();
                    if let Some(node_id) = tree.lookup(*hash) {
                        let _ = tree.invalidate_subtree(node_id);
                    }
                }
                return Err(scripted.error);
            }
            Err(ReorgError::NoAppliedTip)
        }
    }

    pub(crate) fn synced_ibd_latch() -> Arc<InitialBlockDownload> {
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let genesis = Network::Regtest.genesis_block();
        let recent = Header {
            prev_blockhash: genesis.block_hash(),
            time: u32::try_from(bitcoin_rs_consensus::primitives::unix_time_secs())
                .unwrap_or(u32::MAX),
            ..genesis.header
        };
        {
            let mut tree = block_tree.write();
            let Ok(genesis_id) = tree.insert_node(None, genesis.header, NodeStatus::Active) else {
                unreachable!("regtest genesis is always insertable");
            };
            if tree
                .insert_node(Some(genesis_id), recent, NodeStatus::Active)
                .is_err()
            {
                unreachable!("a valid regtest child is always insertable");
            }
        }
        let tip = block_tree
            .read()
            .tip()
            .unwrap_or_else(|| unreachable!("the chain has a tip"));
        applied_tip.store(Some(Arc::clone(&tip)));
        Arc::new(InitialBlockDownload::new(
            bitcoin_rs_execution::chain::TipReader::new(applied_tip),
            bitcoin_rs_execution::chain::BlockTreeReader::new(block_tree),
        ))
    }

    pub(crate) fn mined_chain(
        body_height: u32,
        header_only: u32,
    ) -> Result<(BlockTree, Vec<Block>), crate::test_support::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let mut tip_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let mut prev_hash = genesis.block_hash();
        let mut blocks = Vec::with_capacity(usize::try_from(body_height)?);
        for height in 1..=body_height {
            let block = regtest_fixture::mined_block_with_prev_hash(
                prev_hash,
                height,
                vec![regtest_fixture::coinbase(height)],
            )
            .or_fail("regtest fixture block");
            tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
            prev_hash = block.block_hash();
            blocks.push(block);
        }
        for height in body_height.saturating_add(1)..=body_height.saturating_add(header_only) {
            let header = regtest_fixture::mined_regtest_header(prev_hash, height)
                .or_fail("regtest fixture header");
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            prev_hash = header.compute_hash();
        }
        Ok((tree, blocks))
    }
}

#[cfg(test)]
#[must_use]
pub(crate) fn syncing_ibd_latch() -> Arc<bitcoin_rs_execution::chain::InitialBlockDownload> {
    Arc::new(bitcoin_rs_execution::chain::InitialBlockDownload::new(
        bitcoin_rs_execution::chain::TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty())),
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(parking_lot::RwLock::new(
            BlockTree::new(),
        ))),
    ))
}
