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

mod branches;
pub mod chain;
mod commit;
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
use hashbrown::HashMap;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
#[cfg(test)]
use telemetry::metric_count;

use crate::BlockStager;
use crate::InboundHeaders;
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
#[cfg(test)]
use crate::download_window::PENDING_TIMEOUT;
use crate::download_window::RECEIVED_BLOCK_BUDGET;
#[cfg(test)]
use crate::download_window::RECEIVED_BLOCK_TIMEOUT;
#[cfg(test)]
use commit::restore_split;

pub use chain::{
    BranchSwitchError, HeaderAdmission, SyncChain, SyncChainError, WindowCommitDisposition,
    WindowCommitError,
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
    /// Bounded request/staging policy; public for the apply-side tests that
    /// drive it through the real seam implementation.
    #[doc(hidden)]
    pub download_window: Arc<Mutex<DownloadWindow>>,
    /// Bounded staged bodies; public for the same tests.
    #[doc(hidden)]
    pub block_stager: Arc<Mutex<BlockStager>>,
    pending_getheaders: Arc<Mutex<Option<PendingHeaderRequest>>>,
    expected_apply_cache: Arc<Mutex<Option<ExpectedApplyCache>>>,
    known_sessions: Mutex<HashMap<SocketAddr, crate::ConnectionId>>,
    /// Latched by the first [`WindowCommitDisposition::Fatal`] settlement.
    /// While set, [`apply_buffered_blocks`] stages inbound blocks but starts
    /// no chain transition: the failed settlement left the implementation's
    /// admission closed, so every further attempt would churn staged state.
    /// Only recreating the sync object (restart path) clears it; there is no
    /// in-place recovery that reopens admission.
    apply_halted: std::sync::atomic::AtomicBool,
}

#[derive(Clone, Copy, Debug)]
struct PendingHeaderRequest {
    peer_addr: SocketAddr,
    locator_tip_hash: Hash256,
    target_height: u32,
    requested_at: Instant,
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
        Self {
            chain,
            peer_table,
            inbound_headers_rx,
            inbound_blocks_rx,
            download_window: Arc::new(Mutex::new(DownloadWindow::new(default_sync_budget()))),
            block_stager: Arc::new(Mutex::new(BlockStager::new(default_sync_budget()))),
            pending_getheaders: Arc::new(Mutex::new(None)),
            expected_apply_cache: Arc::new(Mutex::new(None)),
            known_sessions: Mutex::new(HashMap::new()),
            apply_halted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Replaces the download window and block stager with ones configured by
    /// `budget`: the fast-sync opt-in at node open, and tests and benchmarks
    /// that exercise non-default capacity limits.
    pub fn install_budget(&self, budget: SyncBudget) {
        *self.download_window.lock() = DownloadWindow::new(budget);
        *self.block_stager.lock() = BlockStager::new(budget);
    }

    /// Runs one orchestrator tick: requests pending blocks from eligible peers
    /// and asks them to extend the header chain.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.chain.bootstrap_genesis();
        // Remove dead racers before queued blocks can affect peer election.
        self.reconcile_peer_sessions();
        self.drain_inbound_blocks();

        let applied_tip = self.chain.applied_tip().load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let chain_tip = self.chain.chain_tip().load_full();
        let now = Instant::now();
        // Peer conviction runs after the apply drain and before peer release
        // so released blocks can be re-requested in the same tick. At most
        // one peer is disconnected per tick.
        if !self.disconnect_window_staller(applied_tip.as_deref(), now) {
            self.disconnect_timed_out_peer(now);
        }
        self.reconcile_peer_sessions();
        let sync_peer_selection = self.sync_peer_selection(applied_height, now);
        if sync_peer_selection.header_peer.is_none() {
            tracing::trace!(applied_height, "block sync: no peer above current height");
            return;
        }
        let mut sent_getdata = false;
        let request_peer_count = sync_peer_selection.request_peers.len();
        for (peer_idx, peer) in sync_peer_selection.request_peers.into_iter().enumerate() {
            let peer_best_height = u32::try_from(peer.best_known_height).unwrap_or(0);
            let request_outcome = match (&chain_tip, &applied_tip) {
                (Some(chain_tip), Some(applied_tip)) => self.send_getdata_for_pending_blocks(
                    peer.addr,
                    peer_idx + 1 == request_peer_count,
                    peer_best_height,
                    chain_tip,
                    applied_tip,
                ),
                _ => GetdataRequestOutcome::default(),
            };
            sent_getdata |= request_outcome.sent;
            if request_outcome.sent && !request_outcome.has_request_capacity {
                break;
            }
        }
        self.send_prefix_probes(&sync_peer_selection.probe_peers, now);
        self.request_headers_from_best_peer();
        if sent_getdata {
            self.record_pending_sync_metrics();
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
}

#[cfg(test)]
mod tests;
