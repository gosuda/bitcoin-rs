//! Block download orchestrator.
//!
//! Reads the shared chainstate facade, peer table, and inbound channels
//! and, when a peer reports a longer chain, sends `getheaders` toward
//! that peer. Inbound `headers` batches are drained into the shared
//! [`bitcoin_rs_chain::BlockTree`]; inbound full blocks are applied through
//! [`crate::apply::apply_block`].

use alloc::sync::Arc;

use bitcoin_rs_p2p::{InboundHeaders, PeerTable, download_window::DownloadWindow};

use crossbeam_channel::Receiver;

use expected::ExpectedApplyCache;

use hashbrown::HashMap;

use headers::PendingHeaderRequest;

use parking_lot::Mutex;

use peers::GetdataRequestOutcome;

use self::stage::BlockStager;

use std::{net::SocketAddr, time::Instant};

#[cfg(test)]
use apply::{restore_split, settle_window_failure, settle_window_success};

#[cfg(test)]
use bitcoin::p2p::message_blockdata::Inventory;

#[cfg(test)]
use bitcoin_rs_p2p::{
    Message,
    download_window::{
        BLOCK_STALLING_TIMEOUT, GETDATA_BATCH_SIZE, MAX_BLOCKS_IN_TRANSIT_PER_PEER,
        PEER_INFLIGHT_BUDGET, PENDING_BUDGET, PENDING_TIMEOUT, RECEIVED_BLOCK_TIMEOUT,
    },
};

#[cfg(test)]
use observability::metric_count;

#[cfg(test)]
use self::stage::StagedBlock;

#[cfg(test)]
pub(crate) use bitcoin_rs_p2p::download_window::MIN_PEERS_FOR_FANOUT;

/// Applied-chain handoff, prefix settlement, and reorg recovery.
mod apply;
/// Tip-pinned expected-block runs and cache advancement.
mod expected;
/// Session-bound header acquisition and peer-credit reconciliation.
mod headers;
/// Synchronization progress and metric projection.
mod observability;
/// Peer selection, request dispatch, hedging, and staller policy.
mod peers;
/// Bounded inbound body draining and staged-body admission.
mod receive;

pub use bitcoin_rs_p2p::download_window::{SyncBudget, default_sync_budget};

mod stage;

/// Block download orchestrator.
///
/// Owns the production [`DownloadWindow`]. Session identity stays on the
/// shared [`PeerTable`]; this orchestrator calls identity-checked table
/// methods. The P2P service does not hold a second window.
pub struct BlockSync {
    handles: crate::apply::Chainstate,
    followers: crate::chain_effects::ChainFollowers,
    peer_table: Arc<PeerTable>,
    inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    download_window: Arc<Mutex<DownloadWindow>>,
    block_stager: Arc<Mutex<BlockStager>>,
    pending_getheaders: Arc<Mutex<Option<PendingHeaderRequest>>>,
    expected_apply_cache: Arc<Mutex<Option<ExpectedApplyCache>>>,
    known_sessions: Mutex<HashMap<SocketAddr, bitcoin_rs_p2p::ConnectionId>>,
    /// Latched by the first [`WindowApplyDisposition::Fatal`] settlement.
    /// While set, [`apply_buffered_blocks`] stages inbound blocks but starts
    /// no chain transition: the failed `finish` left the gateway generation
    /// odd, so every further attempt would bounce off `AlreadyActive` and
    /// churn staged state. Only recreating the sync object (restart path)
    /// clears it; there is no in-place recovery that re-evens generation.
    apply_halted: std::sync::atomic::AtomicBool,
}

impl BlockSync {
    /// Constructs a new orchestrator over the supplied shared handles.
    #[must_use]
    pub fn new(
        handles: crate::apply::Chainstate,
        followers: crate::chain_effects::ChainFollowers,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    ) -> Self {
        Self {
            handles,
            followers,
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

    /// Test constructor with no derived consumers.
    #[cfg(test)]
    pub(crate) fn for_test(
        handles: crate::apply::Chainstate,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    ) -> Self {
        Self::new(
            handles,
            crate::chain_effects::ChainFollowers::noop(),
            peer_table,
            inbound_headers_rx,
            inbound_blocks_rx,
        )
    }

    /// Replaces the download window and block stager with ones configured by
    /// `budget`. Intended for tests and benchmarks that need to exercise
    /// non-default capacity limits.
    pub fn install_budget(&self, budget: SyncBudget) {
        *self.download_window.lock() = DownloadWindow::new(budget);
        *self.block_stager.lock() = BlockStager::new(budget);
    }

    /// Runs one orchestrator tick: requests pending blocks from eligible peers
    /// and asks them to extend the header chain.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.ensure_genesis_tip();
        // Remove dead racers before queued blocks can affect peer election.
        self.reconcile_peer_sessions();
        self.drain_inbound_blocks();

        let applied_tip = self.handles.applied_tip.load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let chain_tip = self.handles.chain_tip.load_full();
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
}

#[cfg(test)]
mod tests;
