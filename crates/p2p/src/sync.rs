//! Block download orchestrator.
//!
//! Reads the applied-chain seam ([`SyncChain`]), the peer table, and the
//! inbound channels and, when a peer reports a longer chain, sends
//! `getheaders` toward that peer. Inbound `headers` batches are admitted
//! through [`SyncChain::admit_headers`]; inbound full blocks are staged in
//! the [`BlockStager`] and committed through [`SyncChain::commit_window`].
//! The download executor, window, staging, and peer policy are owned by this
//! crate; applied-tip mutation behind `SyncChain` remains a node-provided
//! ARCH-07 seam.
//!
//! Each tick runs one canonical frontier reconciliation (issue #1128):
//! observe the chain frontier and the identity-bearing usable-peer set,
//! convict or release what no longer holds work, then either schedule
//! concrete recovery or name the reason progress is impossible.

mod branches;
pub mod chain;
mod commit;
mod frontier;
mod headers;
mod peers;
mod receive;
mod requests;
mod telemetry;

#[cfg(test)]
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::plan_reorg;
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

pub use chain::{
    BranchSwitchError, HeaderAdmission, SyncChain, SyncChainError, WindowCommitDisposition,
    WindowCommitError,
};

pub(crate) use frontier::{
    BodyState, ChainFrontier, HeaderAction, NoProgressReason, RequiredBody, SyncFrontier,
    UsablePeer, header_request_live,
};

pub use crate::download_window::{SyncBudget, default_sync_budget};

#[cfg(test)]
pub(crate) use crate::download_window::MIN_PEERS_FOR_FANOUT;

/// Maximum number of locator entries we ever send.
const LOCATOR_MAX_ENTRIES: usize = 32;

/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;

/// Time after which an unanswered `getheaders` request may be retried.
const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

type ExpectedBlockHashes = SmallVec<[Hash256; RECEIVED_BLOCK_BUDGET]>;

/// Block download orchestrator.
///
/// Drives the P2P-owned [`DownloadWindow`] and [`BlockStager`] against the
/// applied-chain seam. See `docs/contracts/architecture.md` for the
/// download-window ownership contract.
pub struct BlockSync {
    /// Applied-chain seam: header admission, window commit, branch switch,
    /// and genesis bootstrap live behind it (node owns them, ARCH-07).
    #[doc(hidden)]
    pub chain: Arc<dyn SyncChain>,
    peer_table: Arc<PeerTable>,
    inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<crate::InboundBlock>>>,
    /// One lock owns the coupled download, staged-body, header-request, and
    /// session-reconciliation state. Consensus and chain I/O stay outside
    /// this lock; each component's policy remains in the P2P crate.
    scheduler: Mutex<SchedulerState>,
    /// Last time a `Refused` admission replayed a `getheaders` re-request;
    /// paces retries to the request timeout so a paused admission cannot
    /// re-issue the same locator at round-trip pace.
    refused_rerequest_at: Mutex<Option<Instant>>,
    /// Latest `MSG_BLOCK` inventory hash per announcing connection, drained
    /// by the next tick's header drain. One entry per connection keeps the
    /// queue bounded by the live session set, as Core keeps one best block
    /// per `inv` message.
    block_announcements: Mutex<hashbrown::HashMap<PeerSource, Hash256>>,
    expected_apply_cache: Arc<Mutex<Option<ExpectedApplyCache>>>,
    /// Latched by the first [`WindowCommitDisposition::Fatal`] settlement.
    /// While set, [`apply_buffered_blocks`] stages inbound blocks but starts
    /// no chain transition: the failed settlement left the implementation's
    /// admission closed, so every further attempt would churn staged state.
    /// Only recreating the sync object (restart path) clears it; there is no
    /// in-place recovery that reopens admission.
    apply_halted: std::sync::atomic::AtomicBool,
}

struct SchedulerState {
    window: DownloadWindow,
    stager: BlockStager,
    /// The one outstanding header request, owned by the exact connection it
    /// was sent to. Same-address replacement never inherits it.
    header_request: Option<PendingHeaderRequest>,
    /// Deferred body-fetch ownership: a compact `getblocktxn` or fallback
    /// `getdata` was issued for a tip hash whose header has not attached yet.
    /// Marks resolve against the tree each drain once ancestry admits the
    /// tip (P2P-06); bounded so announcements cannot grow it.
    owned_body_fetches: Vec<(PeerSource, Hash256)>,
}

impl SchedulerState {
    /// Releases every scheduling fact owned by a connection not in `live`.
    ///
    /// PRE: `live` is the peer table's live-session snapshot.
    /// POST: the window, the header request, and the deferred body fetches
    ///   hold only facts owned by a connection in `live`.
    /// INVARIANT: ownership is compared by connection identity, never by
    ///   address alone.
    fn release_unowned(&mut self, live: &[PeerSource]) {
        let owns = |source: &PeerSource| live.contains(source);
        self.window.retain_owned_by(owns);
        if self
            .header_request
            .is_some_and(|request| !owns(&request.source))
        {
            self.header_request = None;
        }
        self.owned_body_fetches.retain(|(source, _)| owns(source));
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingHeaderRequest {
    /// The exact connection the request was sent to.
    source: PeerSource,
    locator_tip_hash: Hash256,
    target_height: u32,
    requested_at: Instant,
}

/// Whether `send_getheaders` reached the wire this tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GetheadersOutcome {
    /// The request was sent and registered.
    Sent,
    /// An identical request is already pending on that connection; nothing
    /// was sent.
    Suppressed,
    /// The connection's outbound channel is gone (the send failed or the
    /// lease no longer exists).
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

/// A contiguous run of expected apply hashes together with the chain/applied
/// tip snapshot it was computed against.
///
/// The validity keys are captured at the moment the parent-walk reads the
/// block tree, so a cache built from this run is coherent with the hashes it
/// holds — no second `load_full` is taken (which would reopen a TOCTOU gap
/// between the hashes and the keys that guard them).
#[derive(Clone, Debug)]
struct ExpectedRun {
    chain_tip_hash: Hash256,
    applied_tip_hash: Hash256,
    applied_tip_height: u32,
    hashes: ExpectedBlockHashes,
}

#[derive(Clone, Copy, Debug, Default)]
struct GetdataRequestOutcome {
    sent: bool,
    has_request_capacity: bool,
}

impl BlockSync {
    /// Constructs a new orchestrator over the supplied shared handles.
    #[must_use]
    pub fn new(
        chain: Arc<dyn SyncChain>,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<crate::InboundBlock>>>,
    ) -> Self {
        let budget = default_sync_budget(chain.network());
        Self {
            chain,
            peer_table,
            inbound_headers_rx,
            inbound_blocks_rx,
            scheduler: Mutex::new(SchedulerState {
                window: DownloadWindow::new(budget),
                stager: BlockStager::new(budget),
                header_request: None,
                owned_body_fetches: Vec::new(),
            }),
            refused_rerequest_at: Mutex::new(None),
            block_announcements: Mutex::new(hashbrown::HashMap::new()),
            expected_apply_cache: Arc::new(Mutex::new(None)),
            apply_halted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Replaces the whole scheduler state with one configured by `budget`:
    /// the fast-sync opt-in at node open, and tests and benchmarks that
    /// exercise non-default capacity limits.
    pub fn install_budget(&self, budget: SyncBudget) {
        *self.scheduler.lock() = SchedulerState {
            window: DownloadWindow::new(budget),
            stager: BlockStager::new(budget),
            header_request: None,
            owned_body_fetches: Vec::new(),
        };
    }

    /// Records one block-typed inventory vector from `source` for the next
    /// header drain.
    ///
    /// PRE: `source` identifies the current connection and `hash` is a
    /// `MSG_BLOCK` or `MSG_WITNESS_BLOCK` inventory hash.
    /// POST: the announcement is queued and the sync loop is woken; no block
    /// body request is emitted here.
    /// INVARIANT: one entry per connection — the latest announcement wins, as
    /// Core keeps one best block per `inv` message — so a flooding peer
    /// cannot grow the queue past the live session set.
    pub fn announce_block(&self, source: PeerSource, hash: Hash256) {
        self.block_announcements.lock().insert(source, hash);
    }

    /// Whether `source` already owns the download of `hash`.
    ///
    /// PRE: `source` identifies a live connection and `hash` is a block hash.
    /// POST: `true` when the download window holds a pending request for
    ///   `hash` owned by this exact connection, or the compact path marked
    ///   the body as fetched by it.
    /// INVARIANT: ownership is compared by connection identity, never by
    ///   address alone, so a same-address replacement cannot claim its
    ///   predecessor's request.
    #[must_use]
    pub fn owns_body_fetch(&self, source: PeerSource, hash: Hash256) -> bool {
        let scheduler = self.scheduler.lock();
        scheduler.window.pending_owner(&hash) == Some(source)
            || scheduler
                .owned_body_fetches
                .iter()
                .any(|(owner, owned)| *owner == source && *owned == hash)
    }

    /// Runs one orchestrator tick as a single canonical frontier
    /// reconciliation: observe, recover what is unowned, then schedule or
    /// name why progress is impossible.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.chain.bootstrap_genesis();
        // Remove dead racers before queued blocks can affect peer election.
        self.reconcile_peer_sessions();
        self.drain_inbound_blocks();

        let now = Instant::now();
        // One frontier observation feeds recovery, selection, and planning;
        // the observation reads tips once and resolves the canonical
        // next-required body exactly once per tick.
        let chain = self.observe_chain_frontier();
        self.reconcile_window_recovery(&chain, now);
        // Convicted connections must release their work before selection so
        // the same tick can re-request it.
        self.reconcile_peer_sessions();
        let frontier = self.observe_frontier(chain, now);
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
                GetheadersOutcome::Suppressed => {
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

    /// Returns whether `ancestor` is the node at `height` on `descendant`'s branch.
    fn is_ancestor_at_height(
        tree: &BlockTree,
        ancestor: NodeId,
        height: u32,
        descendant: NodeId,
    ) -> bool {
        tree.node_at_height_from(descendant, height) == Some(ancestor)
    }

    /// Projects SYNC-FRONTIER-01 into the scheduler's first pending height.
    /// Keep fallible ancestry navigation separate from request publication.
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
        let first = plan_reorg(tree, applied_id, target)
            .ok()?
            .connect
            .into_iter()
            .next()?;
        Some(tree.node(first).ok()?.height)
    }

    /// The chain-side frontier: both tips and the canonical next-required
    /// body, resolved in one consistent tree read.
    pub(super) fn observe_chain_frontier(&self) -> ChainFrontier {
        let applied_tip = self.chain.applied_tip();
        let chain_tip = self.chain.chain_tip();
        let next_required = match (&applied_tip, &chain_tip) {
            (Some(applied), Some(chain)) => {
                let tree = self.chain.block_tree();
                Self::first_connect_height(&tree, applied.hash, chain.tip_id)
                    .and_then(|height| tree.node_at_height_from(chain.tip_id, height))
                    .and_then(|node_id| {
                        tree.node(node_id).ok().map(|node| RequiredBody {
                            height: node.height,
                            hash: node.hash,
                        })
                    })
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

    /// The full scheduler observation: the chain frontier joined to the
    /// body's scheduling state and the identity-bearing usable-peer set,
    /// all consistent for one tick.
    ///
    /// Lock order: the peer-table snapshot is taken first, then the chain
    /// tree read for capability resolution, then the scheduler lock — the
    /// established `peer_table -> tree -> scheduler` order.
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
                // The peer's demonstrated height on the active branch: only a
                // tip that intersects our chain is usable for bodies.
                let active_height = if demonstrated_tips.is_empty() {
                    u32::try_from(info.best_known_height).ok()
                } else {
                    active_tip.and_then(|tip| {
                        peers::active_demonstrated_height(&tree, tip, &demonstrated_tips)
                    })
                };
                usable_peers.push(UsablePeer {
                    source: session.lease.source(session.addr),
                    info,
                    demonstrated_tips,
                    active_height,
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
        let header_request = scheduler.header_request;
        SyncFrontier {
            chain,
            body_state,
            header_request,
            header_request_live: header_request_live(header_request, &usable_peers, now),
            usable_peers,
        }
    }

    /// Records why the frontier cannot advance this tick.
    fn note_no_progress(frontier: &SyncFrontier, reason: NoProgressReason) {
        if reason == NoProgressReason::AtTip {
            // At tip is the healthy terminal state, not a stall: counting it
            // would make the no-progress signal grow monotonically forever.
            return;
        }
        metrics::counter!("node.sync.no_progress_ticks", "reason" => reason.as_str()).increment(1);
        let applied_height = frontier
            .chain
            .applied_tip
            .as_ref()
            .map_or(0, |tip| tip.height);
        let header_height = frontier
            .chain
            .chain_tip
            .as_ref()
            .map_or(applied_height, |tip| tip.height);
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
    /// Metric label for the reason.
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
