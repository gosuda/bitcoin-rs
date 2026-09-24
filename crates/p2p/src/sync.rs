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

/// Headers a single `headers` message can carry. Core's
/// `MAX_HEADERS_RESULTS` (`net_processing.h:48-57`): a batch of exactly this
/// many is a full page, so the peer almost certainly has more.
const MAX_HEADERS_RESULTS: usize = 2_000;

/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;

/// Time after which an unanswered `getheaders` request may be retried.
const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the node asks whether its own tip has gone stale: Core's
/// `STALE_CHECK_INTERVAL` is 10 * 60 seconds (`net_processing.cpp:111`).
const STALE_CHECK_INTERVAL: Duration = Duration::from_mins(10);

/// The node's judgement of its own tip's progress, and the one extra
/// full-relay connection that judgement can buy.
///
/// A tip that stops moving while nothing is being downloaded means the
/// connections the node holds are not telling it about the network. Core
/// answers that with one more full-relay dial rather than with a different
/// download strategy, and takes the extra connection back as soon as the
/// chain moves again (`net_processing.cpp:5604-5668`).
#[derive(Clone, Debug, Default)]
struct StaleTipState {
    /// Highest header tip height seen so far.
    last_seen_height: u32,
    /// When the tip last advanced, `None` before the first observation.
    last_update: Option<Instant>,
    /// When the staleness question is next asked.
    next_check: Option<Instant>,
    /// Whether one extra full-relay dial is currently allowed.
    extra_dial_allowed: bool,
}

impl StaleTipState {
    /// Records what the tip did this tick and updates the extra-dial
    /// allowance.
    ///
    /// PRE: `tip_height` is this tick's header tip, `blocks_in_flight` the
    ///   bodies the window still expects, and `block_spacing` the network's
    ///   target spacing.
    /// POST: an advancing tip withdraws the allowance at once; a tip that has
    ///   not moved is re-judged no more often than `STALE_CHECK_INTERVAL`.
    /// INVARIANT: the allowance is this record's only output, so the
    ///   connection manager never reads a staleness clock of its own.
    fn follow(
        &mut self,
        tip_height: u32,
        blocks_in_flight: usize,
        block_spacing: Duration,
        now: Instant,
    ) {
        if tip_height > self.last_seen_height {
            self.last_seen_height = tip_height;
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

/// Whether the node's tip looks stale rather than merely quiet.
///
/// PRE: `block_spacing` is the network's target spacing.
/// POST: return false while any body is in flight, because the node is
///   downloading rather than stuck; otherwise return true once the tip has
///   stood still for three target spacings.
/// INVARIANT: this is Core's `TipMayBeStale` (`net_processing.cpp:1434-1448`),
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
    /// The node's one chain-owned initial-block-download latch, shared with
    /// RPC and the listener. Block-body peer choice reads it through
    /// [`crate::download_window::BlockDownloadPolicy`]; nothing else decides
    /// whether this node is still syncing.
    ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
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
    /// Chain-sync eviction state for every connection that has not yet shown
    /// it can bring us to the tip. Keyed by exact connection identity, so a
    /// replacement at the same address is judged on its own record.
    chain_sync: hashbrown::HashMap<PeerSource, peers::ChainSyncState>,
    /// Header requests each connection has failed to answer. Keyed by exact
    /// connection identity, so a same-address replacement starts clean and a
    /// timed-out peer is never blamed for its successor or the reverse.
    header_penalties: hashbrown::HashMap<PeerSource, u32>,
    /// Whether this node's own tip is still moving, and what that buys.
    stale_tip: StaleTipState,
}

impl SchedulerState {
    /// Releases every scheduling fact owned by a connection not in `live`.
    ///
    /// PRE: `live` is the peer table's live-session snapshot.
    /// POST: the window, the header request, the header-timeout penalties, and
    ///   the deferred body fetches hold only facts owned by a connection in
    ///   `live`.
    /// INVARIANT: ownership is compared by connection identity, never by
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
        self.chain_sync.retain(|source, _| owns(source));
        self.header_penalties.retain(|source, _| owns(source));
    }

    /// Puts one connection's chain-sync record back after a probe that never
    /// left the node.
    ///
    /// PRE: `prior` is the record the connection held before the probe was
    ///   attempted.
    /// POST: the connection's record is exactly `prior`, so the rule retries
    ///   on a later tick instead of starting the response window for a request
    ///   the connection never received.
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

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingHeaderRequest {
    /// The exact connection the request was sent to.
    source: PeerSource,
    locator_tip_hash: Hash256,
    target_height: u32,
    requested_at: Instant,
    /// Whether this connection already answered the request with a batch
    /// this node could not use. Such a request keeps its gate to pace the
    /// retry, but its deadline is not silence: expiry retires it without
    /// blame. A fresh send always starts unanswered.
    answered: bool,
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
    ///
    /// PRE: `ibd` is the node's chain-owned latch that RPC and the listener
    ///   also hold.
    /// POST: the orchestrator starts no download until a tick runs.
    /// INVARIANT: the latch is never replaced and never copied into a cached
    ///   boolean.
    #[must_use]
    pub fn new(
        chain: Arc<dyn SyncChain>,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<crate::InboundBlock>>>,
        ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
    ) -> Self {
        let budget = default_sync_budget(chain.network());
        Self {
            chain,
            peer_table,
            ibd,
            inbound_headers_rx,
            inbound_blocks_rx,
            scheduler: Mutex::new(SchedulerState {
                window: DownloadWindow::new(budget),
                stager: BlockStager::new(budget),
                header_request: None,
                owned_body_fetches: Vec::new(),
                chain_sync: hashbrown::HashMap::new(),
                header_penalties: hashbrown::HashMap::new(),
                stale_tip: StaleTipState::default(),
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
            chain_sync: hashbrown::HashMap::new(),
            header_penalties: hashbrown::HashMap::new(),
            stale_tip: StaleTipState::default(),
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

    /// Runs one orchestrator tick against the host clock.
    pub fn tick(&self) {
        self.tick_at(Instant::now());
    }

    /// Runs one orchestrator tick as a single canonical frontier
    /// reconciliation at the injected instant `now`: observe, recover what is
    /// unowned, then schedule or name why progress is impossible.
    ///
    /// PRE: `now` is the instant this tick judges every timeout against.
    /// POST: inbound headers and blocks are drained, dead connections are
    ///   released, the frontier is observed once, an unanswered header request
    ///   is rotated away, and the work that frontier names is scheduled — all
    ///   timed against `now`.
    /// INVARIANT: no expiry, blame, or selection path inside the tick reads the
    ///   wall clock; `now` is the tick's only time source.
    pub fn tick_at(&self, now: Instant) {
        self.drain_inbound_headers(now);
        self.chain.bootstrap_genesis();
        // Remove dead racers before queued blocks can affect peer election.
        self.reconcile_peer_sessions();
        self.drain_inbound_blocks(now);

        // One frontier observation feeds recovery, selection, and planning;
        // the observation reads tips once and resolves the canonical
        // next-required body exactly once per tick.
        let chain = self.observe_chain_frontier();
        self.reconcile_window_recovery(&chain, now);
        // Convicted connections must release their work before selection so
        // the same tick can re-request it.
        self.reconcile_peer_sessions();
        let frontier = self.observe_frontier(chain, now);
        // A `getheaders` that outlived its deadline is retired before any
        // selection this tick, so the scheduler cannot re-ask the connection
        // that ignored it.
        self.expire_header_request(now, &frontier.usable_peers);
        // A connection that has had twenty minutes to bring a better chain and
        // two more to answer a probe is retired before this tick plans any
        // further work with it.
        self.sweep_chain_sync(&frontier, now);
        self.follow_tip_progress(&frontier, now);
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
            HeaderAction::Probe(source) => match self.probe_frontier_peer(&frontier, source, now) {
                GetheadersOutcome::Failed => {
                    self.request_headers_from_best_peer(&frontier, Some(source), now);
                }
                GetheadersOutcome::Suppressed => {
                    self.request_headers_from_best_peer(&frontier, None, now);
                }
                GetheadersOutcome::Sent => {}
            },
            HeaderAction::Extend => {
                self.request_headers_from_best_peer(&frontier, None, now);
            }
        }
        if let Some(reason) = plan.no_progress {
            Self::note_no_progress(&frontier, reason);
        }
    }

    /// Lets the node's own tip govern the extra full-relay connection.
    ///
    /// PRE: `frontier` is the observation made at `now`.
    /// POST: the extra-dial allowance reflects this tick's tip.
    /// INVARIANT: the staleness question is asked at most once per
    ///   `STALE_CHECK_INTERVAL`, so a stalled tip costs one dial rather than
    ///   one decision per tick.
    fn follow_tip_progress(&self, frontier: &SyncFrontier, now: Instant) {
        let Some(tip_height) = frontier.chain.chain_tip.as_ref().map(|tip| tip.height) else {
            return;
        };
        let block_spacing =
            Duration::from_secs(u64::from(self.chain.network().target_spacing_seconds()));
        let mut scheduler = self.scheduler.lock();
        let blocks_in_flight = scheduler.window.pending_len();
        scheduler
            .stale_tip
            .follow(tip_height, blocks_in_flight, block_spacing, now);
    }

    /// Whether the stale tip still justifies one extra full-relay dial.
    ///
    /// PRE: none.
    /// POST: the answer is the scheduler's current judgement, and it changes
    ///   only when the tip moves or the staleness question is next asked.
    /// INVARIANT: the connection manager is the only reader, because it is the
    ///   only part of the node that can dial.
    #[must_use]
    pub fn allow_extra_full_relay_dial(&self) -> bool {
        self.scheduler.lock().stale_tip.extra_dial_allowed
    }

    /// Whether `source` holds a per-connection block-download slot right now.
    ///
    /// PRE: `source` names a connection of this node's epoch.
    /// POST: true exactly while the window counts that connection among the
    ///   peers it is fetching from.
    /// INVARIANT: the answer comes from the same window the fetch budget
    ///   reads, so a peer never both downloads and is retired as idle.
    #[must_use]
    pub fn is_downloading_bodies(&self, source: PeerSource) -> bool {
        self.scheduler.lock().window.is_downloading(source)
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
        let applied_tip = self.chain.applied_tip().load_full();
        let chain_tip = self.chain.chain_tip().load_full();
        let next_required = match (&applied_tip, &chain_tip) {
            (Some(applied), Some(chain)) => {
                let tree = self.chain.block_tree().read();
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
            let tree = self.chain.block_tree().read();
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
pub(crate) mod tests;

/// A latch that stays in initial block download: nothing is ever applied
/// behind it, so [`bitcoin_rs_chain::InitialBlockDownload::is_active`] answers
/// active for every time.
///
/// PRE: none.
/// POST: the returned latch is shared and never leaves initial block download.
/// INVARIANT: test-only. Production wires the node's chain-owned latch; a test
///   that exercises the block-service clause builds its own fixture.
#[cfg(test)]
#[must_use]
pub(crate) fn syncing_ibd_latch() -> Arc<bitcoin_rs_chain::InitialBlockDownload> {
    Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
        Arc::new(arc_swap::ArcSwapOption::empty()),
        Arc::new(parking_lot::RwLock::new(BlockTree::new())),
        bitcoin_rs_primitives::Network::Regtest,
    ))
}
