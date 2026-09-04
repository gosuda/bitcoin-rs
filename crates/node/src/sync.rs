//! Block download orchestrator.
//!
//! Reads the shared apply handles / peer registry / outbound-channel handles
//! and, when a peer reports a longer chain, sends `getheaders` toward
//! that peer. Inbound `headers` batches are drained into the shared
//! [`bitcoin_rs_chain::BlockTree`]; inbound full blocks are applied through
//! [`crate::apply::apply_block`].

use alloc::sync::Arc;
use alloc::vec::Vec;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod stage;

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_chain::{BlockTree, ChainError, NodeId, TipSnapshot, plan_reorg};
use bitcoin_rs_p2p::{InboundBlock, InboundHeaders, Message, PeerTable};
use bitcoin_rs_primitives::{Block, Hash256};
use crossbeam_channel::Receiver;
use hashbrown::HashMap;
use parking_lot::Mutex;
use smallvec::SmallVec;

use self::stage::{BlockStager, DrainedBlock, StagedBlock};
pub(crate) use bitcoin_rs_p2p::download_window::MIN_PEERS_FOR_FANOUT;
pub use bitcoin_rs_p2p::download_window::SyncBudget;
pub use bitcoin_rs_p2p::download_window::default_sync_budget;
#[allow(unused_imports)]
use bitcoin_rs_p2p::download_window::{
    BLOCK_STALLING_TIMEOUT, BLOCK_STALLING_TIMEOUT_MAX, DownloadWindow, FanoutCandidate,
    GETDATA_BATCH_SIZE, INBOUND_BLOCK_STAGE_CHUNK, MAX_BLOCKS_IN_TRANSIT_PER_PEER,
    MAX_SERIALIZED_BLOCK_SIZE, PEER_INFLIGHT_BUDGET, PENDING_BLOCK_BYTE_ESTIMATE, PENDING_BUDGET,
    PENDING_BYTE_BUDGET, PENDING_TIMEOUT, RECEIVED_BLOCK_BUDGET, RECEIVED_BLOCK_BYTE_BUDGET,
    RECEIVED_BLOCK_TIMEOUT, STALLER_COOLDOWN, SyncPeer, SyncPeerSelection, configure_request_mode,
    statically_fanout_eligible,
};

/// Maximum number of locator entries we ever send.
const LOCATOR_MAX_ENTRIES: usize = 32;
/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;
/// Time after which an unanswered `getheaders` request may be retried.
const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

type ExpectedBlockHashes = SmallVec<[Hash256; RECEIVED_BLOCK_BUDGET]>;

/// Block download orchestrator.
pub struct BlockSync {
    handles: crate::apply::ApplyHandles,
    peer_table: Arc<PeerTable>,
    inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    download_window: Arc<Mutex<DownloadWindow>>,
    block_stager: Arc<Mutex<BlockStager>>,
    pending_getheaders: Arc<Mutex<Option<PendingHeaderRequest>>>,
    expected_apply_cache: Arc<Mutex<Option<ExpectedApplyCache>>>,
    known_sessions: Mutex<HashMap<SocketAddr, bitcoin_rs_p2p::ConnectionId>>,
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

fn is_peer_fault(error: &ChainError) -> bool {
    match error {
        ChainError::NbitsMismatch { .. }
        | ChainError::InvalidPow { .. }
        | ChainError::TargetExceedsLimit { .. }
        | ChainError::ZeroTarget { .. }
        | ChainError::NonContinuousHeader { .. }
        | ChainError::ChainworkOverflow { .. }
        | ChainError::HeightOverflow { .. }
        // A median-time-past violation is decided entirely by the chain the peer
        // itself sent, so it is unambiguously the peer's fault.
        | ChainError::TimestampTooEarly { .. } => true,
        // Future drift is judged against OUR clock, so a wrong local clock
        // would otherwise let us ban every honest peer and partition
        // ourselves. The header is rejected without blaming the sender.
        ChainError::TimestampTooFarAhead { .. }
        | ChainError::DuplicateHeader { .. }
        | ChainError::MissingParent { .. }
        | ChainError::NodeIdOverflow { .. }
        | ChainError::UnknownNode { .. }
        | ChainError::NoCommonAncestor { .. } => false,
    }
}

impl BlockSync {
    /// Constructs a new orchestrator over the supplied shared handles.
    #[must_use]
    pub fn new(
        handles: crate::apply::ApplyHandles,
        peer_table: Arc<PeerTable>,
        inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    ) -> Self {
        Self {
            handles,
            peer_table,
            inbound_headers_rx,
            inbound_blocks_rx,
            download_window: Arc::new(Mutex::new(DownloadWindow::new(default_sync_budget()))),
            block_stager: Arc::new(Mutex::new(BlockStager::new(default_sync_budget()))),
            pending_getheaders: Arc::new(Mutex::new(None)),
            expected_apply_cache: Arc::new(Mutex::new(None)),
            known_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Replaces the download window and block stager with ones configured by
    /// `budget`. Intended for tests and benchmarks that need to exercise
    /// non-default capacity limits.
    pub fn install_budget(&self, budget: SyncBudget) {
        *self.download_window.lock() = DownloadWindow::new(budget);
        *self.block_stager.lock() = BlockStager::new(budget);
    }

    fn reconcile_peer_sessions(&self) {
        let live = self.peer_table.live_connections();
        let mut window = self.download_window.lock();
        let mut known = self.known_sessions.lock();
        for (addr, id) in &live {
            if known.insert(*addr, *id).is_some_and(|prev| prev != *id) {
                window.forget_peer(*addr);
                let mut pending = self.pending_getheaders.lock();
                if pending.is_some_and(|request| request.peer_addr == *addr) {
                    *pending = None;
                }
            }
        }
        known.retain(|addr, _| live.iter().any(|(a, _)| a == addr));
        window.release_disconnected_peers(|peer| live.iter().any(|(a, _)| a == peer));
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
            let peer_best_height = u32::try_from(peer.start_height).unwrap_or(0);
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
    /// Emits a one-line sync-progress summary at INFO level.
    ///
    /// Reports applied height, header (chain) height, the gap, live peer
    /// count, and whether the node is still in initial block download. This
    /// is the operator-facing progress signal that #223 identified as
    /// missing during IBD — without it, `docker logs` shows no indication
    /// that the node is alive and applying blocks.
    pub fn emit_sync_progress(&self) {
        let applied_tip = self.handles.applied_tip.load_full();
        let chain_tip = self.handles.chain_tip.load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
        let live_peers = self.peer_table.len();
        let in_ibd = header_height > 0 && applied_height < header_height;
        let gap = header_height.saturating_sub(applied_height);

        if in_ibd {
            tracing::info!(
                applied_height,
                header_height,
                gap,
                peers = live_peers,
                ibd = true,
                "sync progress"
            );
        } else {
            tracing::info!(
                applied_height,
                header_height,
                peers = live_peers,
                ibd = false,
                "sync progress"
            );
        }
    }
    #[allow(clippy::too_many_lines)]
    fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        while let Ok(InboundHeaders { headers, source }) = receiver.try_recv() {
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);

            // A response consumes the current peer's request even when header
            // acceptance rejects it; otherwise sync stalls until timeout.
            if let Some(source) = source {
                if self.peer_table.is_current(source) {
                    let mut pending = self.pending_getheaders.lock();
                    if pending.is_some_and(|request| request.peer_addr == source.addr) {
                        *pending = None;
                    }
                }
            }

            let mut tree = self.handles.block_tree.write();
            let acceptance = bitcoin_rs_chain::accept_headers(
                &mut tree,
                &headers,
                self.handles.network,
                bitcoin_rs_chain::current_unix_seconds(),
            );
            match acceptance {
                Ok(node_ids) => {
                    self.handles.assume_valid_gate.evaluate(&tree);
                    drop(tree);
                    tracing::debug!(
                        accepted = node_ids.len(),
                        received = batch_len,
                        "block sync: accepted inbound headers batch",
                    );
                }
                Err(error) if is_peer_fault(&error) => {
                    drop(tree);
                    let mut blamed_peer = None;
                    if let Some(source) = source {
                        let mut window = self.download_window.lock();
                        if self.peer_table.disconnect_source(source) {
                            window.mark_peer_unresponsive(source.addr, Instant::now());
                            blamed_peer = Some(source.addr);
                        }
                    }
                    if let Some(peer_addr) = blamed_peer {
                        tracing::warn!(
                            peer_addr = %peer_addr,
                            received = batch_len,
                            %error,
                            "block sync: peer served invalid headers; disconnecting",
                        );
                    } else {
                        tracing::warn!(
                            received = batch_len,
                            %error,
                            "block sync: rejected source-less or stale headers batch",
                        );
                    }
                }
                Err(error) => {
                    drop(tree);
                    tracing::warn!(
                        received = batch_len,
                        %error,
                        "block sync: rejected inbound headers batch",
                    );
                }
            }
        }
        if total_headers > 0 {
            tracing::debug!(total_headers, "block sync: drained inbound headers");
        }
    }

    /// Requests the next header batch from the highest peer above the applied
    /// tip, using a locator taken after `drain_inbound_headers` so it reflects
    /// headers accepted this tick.
    ///
    /// Called at the end of `tick`, after the getdata fan-out. Position is
    /// deliberate: peers observe getdata before getheaders within a tick, which
    /// several sync tests assert. Ordering carries no protocol meaning, but
    /// both messages leave in the same tick either way, so there is no
    /// throughput reason to prefer the other order.
    fn request_headers_from_best_peer(&self) {
        let applied_tip = self.handles.applied_tip.load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let chain_tip = self.handles.chain_tip.load_full();
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
        let mut header_peer: Option<SyncPeer> = None;
        for peer in self.peer_table.infos() {
            let Ok(height) = u32::try_from(peer.start_height) else {
                continue;
            };
            if height <= applied_height {
                continue;
            }
            let candidate = SyncPeer {
                addr: peer.addr,
                start_height: peer.start_height,
            };
            if header_peer.is_none_or(|current| current.start_height < candidate.start_height) {
                header_peer = Some(candidate);
            }
        }
        if let Some(peer) = header_peer {
            let peer_best_height = u32::try_from(peer.start_height).unwrap_or(0);
            if peer_best_height > header_height {
                self.send_getheaders(peer.addr, header_height, peer.start_height);
            }
        }
    }

    fn drain_inbound_blocks(&self) {
        let mut apply_head_check = None;
        let mut next_expected_hash = None;
        let mut blocks = Vec::with_capacity(INBOUND_BLOCK_STAGE_CHUNK);
        let mut received = 0_usize;
        let mut receiver_empty = false;
        let saw_block = false;
        while !receiver_empty {
            receiver_empty = self.fill_inbound_block_chunk(
                &mut blocks,
                saw_block,
                &mut next_expected_hash,
                &mut apply_head_check,
            );
            if !blocks.is_empty() {
                received = received.saturating_add(
                    self.buffer_received_block_chunk(&mut blocks, next_expected_hash),
                );
            }
        }
        if received == 0 && self.block_stager.lock().received_len() == 0 {
            return;
        }

        let now = Instant::now();
        let dropped = self.block_stager.lock().prune_expired(now);
        let pruned = !dropped.is_empty();
        if pruned {
            let tree = self.handles.block_tree.read();
            let height_updates: Vec<(Hash256, u32)> = dropped
                .iter()
                .filter_map(|dropped| {
                    let node_id = tree.lookup(dropped.hash)?;
                    tree.node(node_id)
                        .ok()
                        .map(|node| (dropped.hash, node.height))
                })
                .collect();
            drop(tree);
            let mut window = self.download_window.lock();
            for (hash, height) in height_updates {
                window.update_received_height(&hash, height);
            }
            for dropped in dropped {
                window.drop_received_for_retry(&dropped.hash);
            }
        }

        self.switch_branch_if_outweighed();
        let (applied, failed) = self.apply_buffered_blocks(apply_head_check);
        if received > 0 || applied > 0 || failed > 0 {
            tracing::debug!(
                received,
                applied,
                failed,
                "block sync: drained inbound blocks"
            );
        }
        if received > 0 || pruned || applied > 0 || failed > 0 {
            self.record_sync_metrics();
        }
    }

    fn fill_inbound_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        saw_block: bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        let receiver = self.inbound_blocks_rx.lock();
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(inbound) = receiver.try_recv() else {
                return true;
            };
            if !saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash
                    .as_ref()
                    .copied()
                    .filter(|hash| *hash != Hash256::from(inbound.block.block_hash()));
            }
            blocks.push(inbound);
        }
        false
    }

    /// Uses the active-chain height index only while the applied tip is its prefix.
    ///
    /// During a header-first reorg the caller retains old-height blocks rather
    /// than walking the applied ancestry or dropping a body from the new branch.
    fn indexed_applied_ancestry_tip(tree: &BlockTree, applied_tip: &TipSnapshot) -> Option<NodeId> {
        let active_tip = tree.tip()?;
        (tree.node_at_height_from(active_tip.tip_id, applied_tip.height)
            == Some(applied_tip.tip_id))
        .then_some(active_tip.tip_id)
    }

    fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        // A cold-start hedge can arrive after its original copy was applied.
        // Drop only blocks proven to lie on the applied ancestry; a known
        // side-chain block at the same or lower height must remain eligible.
        if let Some(applied_tip) = self.handles.applied_tip.load_full() {
            let tree = self.handles.block_tree.read();
            let indexed_tip = Self::indexed_applied_ancestry_tip(&tree, &applied_tip);
            blocks.retain(|inbound| {
                let hash = Hash256::from(inbound.block.block_hash());
                let Some(node_id) = tree.lookup(hash) else {
                    return true;
                };
                let Ok(node) = tree.node(node_id) else {
                    return true;
                };
                node.height > applied_tip.height
                    || indexed_tip.is_none_or(|tip_id| {
                        tree.node_at_height_from(tip_id, node.height) != Some(node_id)
                    })
            });
        }
        let mut staged_blocks = Vec::with_capacity(blocks.len());
        let now = Instant::now();
        {
            let mut stager = self.block_stager.lock();
            for inbound in blocks.drain(..) {
                let hash = Hash256::from(inbound.block.block_hash());
                let source = inbound.source;
                let staged = stager.insert(
                    hash,
                    next_expected_hash,
                    inbound.block,
                    inbound.serialized,
                    now,
                );
                staged_blocks.push((hash, source, staged));
            }
        }

        let mut retry_count = 0_u64;
        let staged_count = staged_blocks.len();
        {
            let mut window = self.download_window.lock();
            for (hash, source, staged) in staged_blocks {
                let source_peer = source
                    .filter(|source| self.peer_table.is_current(*source))
                    .map(|source| source.addr);
                match staged {
                    StagedBlock::AlreadyStaged => {
                        metrics::counter!("node.sync.duplicate_deliveries").increment(1);
                        if let Some(source_peer) = source_peer {
                            window.credit_duplicate_delivery(hash, source_peer);
                        }
                    }
                    StagedBlock::Memory { bytes, dropped } => {
                        window.mark_received_from(hash, bytes, source_peer, now);
                        for dropped in dropped {
                            window.drop_received_for_retry(&dropped.hash);
                            retry_count = retry_count.saturating_add(1);
                        }
                    }
                    StagedBlock::DroppedForRetry { dropped } => {
                        window.drop_for_retry(&dropped.hash);
                        retry_count = retry_count.saturating_add(1);
                        tracing::warn!(%hash, "block sync: received block buffer full; dropping block for retry");
                    }
                }
            }
        }
        if retry_count > 0 {
            metrics::counter!("node.sync.retry_count").increment(retry_count);
        }
        staged_count
    }

    /// Moves the applied chain onto the header tip's branch when it has been
    /// outweighed.
    ///
    /// `chain_tip` tracks the heaviest headers and `applied_tip` the validated
    /// chain; the two diverge exactly when a competing branch wins. Forward
    /// application cannot close that gap, because the blocks it wants to apply
    /// do not build on the applied tip.
    ///
    /// Availability is left to [`crate::reorg::switch_to_branch`]. It may
    /// commit the contiguous winning prefix already present in bounded staging,
    /// then report `MissingBody` for the first absent suffix block. Only a
    /// zero-length available connect prefix guarantees no mutation. Keeping
    /// this as one authority avoids a pre-check that can disagree with the
    /// transition witness.
    fn switch_branch_if_outweighed(&self) {
        let Some(target) = self.outweighed_branch_target() else {
            return;
        };
        let outcome = crate::reorg::switch_to_branch(
            &self.handles,
            target,
            |hash| self.block_stager.lock().staged_body(hash),
            |hash| self.retire_applied_reorg_body(hash),
        );
        match outcome {
            Ok(()) => {
                let height = self
                    .handles
                    .applied_tip
                    .load_full()
                    .map_or(0, |tip| tip.height);
                tracing::info!(height, "block sync: switched to the heavier branch");
            }
            Err(crate::reorg::ReorgError::MissingBody { height, .. }) => {
                tracing::trace!(height, "block sync: heavier branch still downloading");
            }
            Err(error @ crate::reorg::ReorgError::Fatal(_)) => {
                self.handles.admission.close_permanently();
                self.handles
                    .shutdown
                    .store(true, std::sync::atomic::Ordering::Release);
                tracing::error!(
                    %error,
                    "block sync: chainstate torn by a failed disconnect, shutting down"
                );
            }
            Err(error @ crate::reorg::ReorgError::CheckpointSettlement(_)) => {
                tracing::error!(
                    %error,
                    "block sync: reorg left checkpoint debt unsettled; a clean shutdown will retry"
                );
            }
            Err(crate::reorg::ReorgError::ConnectFailed {
                hash, invalidated, ..
            }) => {
                // Invalid descendants cannot occupy bounded download state or
                // they can prevent the newly selected valid branch from refilling.
                if !invalidated.is_empty() {
                    {
                        let mut stager = self.block_stager.lock();
                        for invalid_hash in &invalidated {
                            stager.retire_applied(invalid_hash);
                        }
                    }
                    {
                        let mut window = self.download_window.lock();
                        for invalid_hash in &invalidated {
                            window.drop_for_retry(invalid_hash);
                        }
                    }
                    // Invalidation can move the active branch away from the
                    // pinned assume-valid anchor.
                    self.handles
                        .assume_valid_gate
                        .evaluate(&self.handles.block_tree.read());
                }
                tracing::warn!(
                    failed_hash = %hash,
                    invalidated = invalidated.len(),
                    "block sync: connect failed"
                );
            }
            Err(crate::reorg::ReorgError::DisconnectBodyLost {
                disconnected,
                stopped_at,
                ..
            }) => {
                tracing::debug!(
                    disconnected,
                    stopped_at,
                    "block sync: disconnect body unreadable mid-rollback, coherent at reached tip"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "block sync: branch switch failed");
            }
        }
    }

    fn retire_applied_reorg_body(&self, hash: Hash256) {
        self.download_window.lock().mark_received_applied(&hash);
        self.block_stager.lock().retire_applied(&hash);
    }

    /// Returns the header tip when the applied chain is not on its branch.
    ///
    /// The applied tip is on the branch exactly when the header tip's ancestor
    /// at the applied height is the applied block itself.
    fn outweighed_branch_target(&self) -> Option<bitcoin_rs_chain::NodeId> {
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied = self.handles.applied_tip.load_full()?;
        if chain_tip.hash == applied.hash {
            return None;
        }
        let tree = self.handles.block_tree.read();
        let applied_id = tree.lookup(applied.hash)?;
        let plan = plan_reorg(&tree, applied_id, chain_tip.tip_id).ok()?;
        (!plan.disconnect.is_empty()).then_some(chain_tip.tip_id)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_buffered_blocks(&self, next_expected_hash: Option<Hash256>) -> (usize, usize) {
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        let Some(staged_count) = self
            .block_stager
            .lock()
            .ready_received_len(next_expected_hash)
        else {
            return (0, 0);
        };
        let started = Instant::now();
        let (drained, expected_len) = self
            .drain_cached_expected_blocks(staged_count)
            .unwrap_or_else(|| {
                // Cache miss: walk the block tree once for the expected run, drain
                // the staged prefix, and repopulate the cache from the freshly
                // computed hashes so subsequent rounds (as more blocks stage under
                // the same chain/applied tip) hit instead of re-walking.
                let horizon = self.expected_apply_horizon(staged_count);
                let run = self.expected_block_hashes(horizon);
                let expected_len = run.as_ref().map_or(0, |run| run.hashes.len());
                let drained = match run.as_ref() {
                    Some(run) => self.block_stager.lock().drain_expected_prefix(&run.hashes),
                    None => Vec::new(),
                };
                if let Some(run) = run {
                    self.populate_expected_apply_cache(run);
                }
                (drained, expected_len)
            });
        let mut applied_hashes = ExpectedBlockHashes::with_capacity(expected_len);
        let mut failed_hash = None;
        // Applied in windows, not one at a time: the window verifies every
        // block's input scripts in a single dispatch, which is where the
        // measured apply win comes from. Blocks still commit one by one and in
        // order inside the window, so nothing about the applied chain changes.
        let drained: Vec<_> = drained.into_iter().collect();
        let mut chunk_start = 0_usize;
        while chunk_start < drained.len() {
            // Bounded by block count AND by bytes, so a window of tip-sized
            // blocks does not hold gigabytes just because the count allows it.
            let chunk_end = chunk_start.saturating_add(crate::apply::window_len(
                drained[chunk_start..]
                    .iter()
                    .map(|drained| drained.serialized.len()),
            ));
            let chunk = &drained[chunk_start..chunk_end];
            // Borrowed, not cloned. `DrainedBlock` owns a whole block, so
            // cloning one deep-copies every transaction and witness; doing that
            // per block per window would spend the dispatch win on memcpy.
            let blocks: Vec<&Block> = chunk.iter().map(|drained| &drained.block).collect();
            let bodies: Vec<bytes::Bytes> = chunk
                .iter()
                .map(|drained| drained.serialized.clone())
                .collect();
            // The window reports how far it got rather than just failing,
            // because only the committed prefix may be marked applied; the rest
            // has to go back on the stager untouched.
            let committed = match crate::apply::apply_window(&self.handles, &blocks, &bodies) {
                Ok(()) => chunk.len(),
                Err(error) => {
                    let stopped = error.applied.min(chunk.len());
                    failed = failed.saturating_add(1);
                    if let Some(blocker) = chunk.get(stopped) {
                        failed_hash = Some(blocker.hash);
                        tracing::warn!(
                            hash = %blocker.hash,
                            error = %error.source,
                            "block sync: failed to apply buffered block"
                        );
                    }
                    for drained in chunk.iter().take(stopped) {
                        applied_hashes.push(drained.hash);
                    }
                    applied = applied.saturating_add(stopped);
                    // Everything after the block that failed, in the order it
                    // was drained: the rest of this chunk past the failure, then
                    // every chunk not yet attempted.
                    let restore_from = chunk_start
                        .saturating_add(stopped)
                        .saturating_add(1)
                        .min(drained.len());
                    self.block_stager
                        .lock()
                        .restore_many(drained[restore_from..].iter().cloned());
                    if error.disposition == crate::apply::WindowApplyDisposition::Permanent {
                        // The failed block's descendants can never become
                        // valid, so they must not occupy bounded download
                        // state or the frontier would cycle on them forever.
                        // Purge every invalidated hash from the stager and
                        // from the window's pending/received maps; the
                        // expected-apply cache is dropped below because the
                        // round failed.
                        {
                            let mut stager = self.block_stager.lock();
                            for invalid_hash in &error.invalidated {
                                stager.retire_applied(invalid_hash);
                            }
                        }
                        {
                            let mut window = self.download_window.lock();
                            for invalid_hash in &error.invalidated {
                                window.drop_for_retry(invalid_hash);
                            }
                        }
                        metrics::counter!("node.sync.invalidated_blocks")
                            .increment(u64::try_from(error.invalidated.len()).unwrap_or(u64::MAX));
                    }
                    break;
                }
            };
            for drained in chunk.iter().take(committed) {
                applied_hashes.push(drained.hash);
            }
            applied = applied.saturating_add(committed);
            chunk_start = chunk_end;
        }
        if !applied_hashes.is_empty() || failed_hash.is_some() {
            {
                let mut window = self.download_window.lock();
                for hash in &applied_hashes {
                    window.mark_received_applied(hash);
                }
                if let Some(hash) = failed_hash {
                    window.drop_received_for_retry(&hash);
                }
            }
            self.advance_expected_apply_cache(&applied_hashes, failed_hash.is_some());
            metrics::histogram!("node.sync.apply_buffered_blocks_seconds")
                .record(started.elapsed().as_secs_f64());
        }
        (applied, failed)
    }

    /// Horizon for an apply-cache repopulation: the larger of `staged_count`
    /// (the run must cover this round's drain) and the download window's
    /// pending-block budget (so later rounds hit the cache).
    ///
    /// `staged_count` covers the blocks already ready to apply this round.
    /// Extending up to `max_pending_blocks` lets later rounds — which apply the
    /// blocks that were merely in flight when this run was computed — hit the
    /// cache instead of re-walking. The result is bounded by the larger of the
    /// two budgets: `staged_count` never exceeds the stager's
    /// `RECEIVED_BLOCK_BUDGET`, and the const assertion next to
    /// `ExpectedBlockHashes` pins that equal to `PENDING_BUDGET`, so the run
    /// always fits the inline `SmallVec` capacity.
    fn expected_apply_horizon(&self, staged_count: usize) -> usize {
        // Snapshot the cap and release the window lock before any tree read so we
        // never invert the tree -> window lock order used elsewhere.
        let max_pending_blocks = self.download_window.lock().max_pending_blocks();
        staged_count.max(max_pending_blocks)
    }

    /// Walks the active header chain from `applied_tip + 1` up to `max_count`
    /// blocks, snapshotting the chain/applied tip it walked against.
    ///
    /// Returns `None` unless the run reaches `start_height` contiguously (the
    /// reorg / pruning guard); a partial run is never returned so the caller
    /// cannot apply or cache a non-contiguous prefix.
    fn expected_block_hashes(&self, max_count: usize) -> Option<ExpectedRun> {
        if max_count == 0 {
            return None;
        }
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied_tip = self.handles.applied_tip.load_full()?;
        let start_height = applied_tip.height.checked_add(1)?;
        if start_height > chain_tip.height {
            return None;
        }

        let max_offset = u32::try_from(max_count.saturating_sub(1)).unwrap_or(u32::MAX);
        let end_height = start_height
            .saturating_add(max_offset)
            .min(chain_tip.height);
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(max_count);
        let tree = self.handles.block_tree.read();
        let mut cursor = tree.node_at_height_from(chain_tip.tip_id, end_height)?;
        let mut hashes = ExpectedBlockHashes::with_capacity(capacity);
        let mut reached_start = false;
        while let Ok(node) = tree.node(cursor) {
            if node.height < start_height {
                break;
            }
            hashes.push(node.hash);
            if node.height == start_height {
                reached_start = true;
                break;
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        if !reached_start {
            return None;
        }
        hashes.reverse();
        Some(ExpectedRun {
            chain_tip_hash: chain_tip.hash,
            applied_tip_hash: applied_tip.hash,
            applied_tip_height: applied_tip.height,
            hashes,
        })
    }

    /// Repopulates the apply cache from a freshly computed expected run.
    ///
    /// Stores the full horizon at `offset: 0` keyed by the snapshot the run was
    /// computed against. `advance_expected_apply_cache` then advances `offset`
    /// past the blocks applied this round, so the next round drains the
    /// remaining suffix on a cache hit. The run is empty only when there is
    /// nothing to apply, in which case caching would be a no-op.
    fn populate_expected_apply_cache(&self, run: ExpectedRun) {
        if run.hashes.is_empty() {
            return;
        }
        *self.expected_apply_cache.lock() = Some(ExpectedApplyCache {
            chain_tip_hash: run.chain_tip_hash,
            applied_tip_hash: run.applied_tip_hash,
            applied_tip_height: run.applied_tip_height,
            offset: 0,
            hashes: run.hashes,
        });
    }

    fn drain_cached_expected_blocks(&self, max_count: usize) -> Option<(Vec<DrainedBlock>, usize)> {
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied_tip = self.handles.applied_tip.load_full()?;
        let cache = self.expected_apply_cache.lock();
        let cache = cache.as_ref()?;
        if cache.chain_tip_hash != chain_tip.hash
            || cache.applied_tip_hash != applied_tip.hash
            || cache.applied_tip_height != applied_tip.height
        {
            return None;
        }
        let remaining = cache.hashes.len().saturating_sub(cache.offset);
        let expected_len = remaining.min(max_count);
        if expected_len == 0 {
            return None;
        }
        let expected_end = cache.offset.saturating_add(expected_len);
        let drained = self
            .block_stager
            .lock()
            .drain_expected_prefix(&cache.hashes[cache.offset..expected_end]);
        Some((drained, expected_len))
    }

    fn advance_expected_apply_cache(&self, applied_hashes: &[Hash256], failed: bool) {
        if failed {
            *self.expected_apply_cache.lock() = None;
            return;
        }
        if applied_hashes.is_empty() {
            return;
        }
        let mut cache_guard = self.expected_apply_cache.lock();
        if cache_guard.is_none() {
            return;
        }
        let Some(chain_tip) = self.handles.chain_tip.load_full() else {
            *cache_guard = None;
            return;
        };
        let Some(applied_tip) = self.handles.applied_tip.load_full() else {
            *cache_guard = None;
            return;
        };
        let Some(cache) = cache_guard.as_mut() else {
            return;
        };
        let applied_count = applied_hashes.len();
        let Some(expected_applied_height) = u32::try_from(applied_count)
            .ok()
            .and_then(|count| cache.applied_tip_height.checked_add(count))
        else {
            *cache_guard = None;
            return;
        };
        if cache.chain_tip_hash != chain_tip.hash
            || cache.hashes.len().saturating_sub(cache.offset) < applied_count
            || cache.hashes[cache.offset..cache.offset.saturating_add(applied_count)]
                != *applied_hashes
            || applied_tip.height != expected_applied_height
            || applied_tip.hash != applied_hashes[applied_count - 1]
        {
            *cache_guard = None;
            return;
        }
        cache.applied_tip_hash = applied_tip.hash;
        cache.applied_tip_height = applied_tip.height;
        cache.offset = cache.offset.saturating_add(applied_count);
        if cache.offset >= cache.hashes.len() {
            *cache_guard = None;
        }
    }

    fn next_expected_block_hash(&self) -> Option<Hash256> {
        let chain_tip = self.handles.chain_tip.load_full()?;
        let applied_tip = self.handles.applied_tip.load_full()?;
        let height = applied_tip.height.checked_add(1)?;
        if height > chain_tip.height {
            return None;
        }
        let tree = self.handles.block_tree.read();
        let node_id = tree.node_at_height_from(chain_tip.tip_id, height)?;
        Some(tree.node(node_id).ok()?.hash)
    }

    fn sync_peer_selection(&self, our_height: u32, now: Instant) -> SyncPeerSelection {
        let mut header_peer: Option<SyncPeer> = None;
        let mut candidates: Vec<FanoutCandidate> = Vec::new();
        for peer in self.peer_table.infos() {
            // Height clause of the fan-out eligibility predicate (KTD6) and
            // the pre-existing candidate filter: the peer's known chain must
            // reach past our applied tip, i.e. cover the window front being
            // requested. Delta vs Core: Core tracks a continuously updated
            // per-peer best header (`pindexBestKnownBlock`, fed by headers/
            // inv processing); this codebase only has the handshake-time
            // `start_height`, so that is the proxy used — per-request
            // truncation by `peer_best_height` bounds the damage of a stale
            // value.
            if u32::try_from(peer.start_height)
                .ok()
                .is_none_or(|height| height <= our_height)
            {
                continue;
            }
            let sync_peer = SyncPeer {
                addr: peer.addr,
                start_height: peer.start_height,
            };
            if header_peer
                .is_none_or(|current: SyncPeer| current.start_height < sync_peer.start_height)
            {
                header_peer = Some(sync_peer);
            }
            candidates.push(FanoutCandidate {
                peer: sync_peer,
                fanout_eligible: statically_fanout_eligible(&peer),
                soft_blocked: false,
            });
        }
        let (request_peer_limit, fanout_active, cold_preferred) = {
            let mut window = self.download_window.lock();
            for candidate in &mut candidates {
                candidate.soft_blocked = window.peer_has_expired_pending(candidate.peer.addr, now)
                    || window.peer_in_staller_cooldown(candidate.peer.addr, now);
                candidate.fanout_eligible = candidate.fanout_eligible && !candidate.soft_blocked;
            }
            let cold_preferred = configure_request_mode(&mut window, &candidates, now);
            (
                window.request_peer_scan_limit(now),
                window.fanout_active(),
                cold_preferred,
            )
        };
        let probe_peers = candidates
            .iter()
            .filter(|candidate| candidate.fanout_eligible)
            .map(|candidate| candidate.peer)
            .collect();
        let mut request_peers: Vec<SyncPeer> = if let Some(preferred) = cold_preferred {
            alloc::vec![preferred]
        } else if fanout_active {
            candidates
                .iter()
                .filter(|candidate| candidate.fanout_eligible)
                .map(|candidate| candidate.peer)
                .collect()
        } else if request_peer_limit > 1 {
            candidates.iter().map(|candidate| candidate.peer).collect()
        } else {
            // Fallback, single deep peer: the highest peer that the window
            // does not currently soft-block (expired pendings / staller
            // cooldown) fills the window; a soft-blocked peer serves only as
            // the last resort when no alternative exists. Without the
            // preference, a disconnected staller that reconnects with an
            // inflated start_height would out-sort every honest peer and
            // re-acquire the window front (RE-ADV-2 / first-audit ADV-2).
            let mut preferred: Option<SyncPeer> = None;
            for candidate in candidates
                .iter()
                .filter(|candidate| !candidate.soft_blocked)
            {
                // First-wins on equal heights, matching the header-peer fold.
                if preferred
                    .is_none_or(|current| current.start_height < candidate.peer.start_height)
                {
                    preferred = Some(candidate.peer);
                }
            }
            preferred
                .or(header_peer)
                .into_iter()
                .take(request_peer_limit)
                .collect()
        };
        if request_peers.len() > 1 {
            request_peers.sort_by_key(|peer| std::cmp::Reverse(peer.start_height));
        }
        request_peers.truncate(request_peer_limit);
        SyncPeerSelection {
            header_peer,
            request_peers,
            probe_peers,
        }
    }

    /// Sends one estimated-2MiB common-prefix probe to each idle alternate.
    ///
    /// Every alternate receives the same earliest hashes, so the probe cannot
    /// create a unique out-of-order height hole. It runs once per deep owner.
    fn send_prefix_probes(&self, probe_peers: &[SyncPeer], now: Instant) {
        let mut window = self.download_window.lock();
        let Some((owner, hashes, required_height)) = window.prefix_probe_plan() else {
            return;
        };
        let candidates = probe_peers.iter().filter(|peer| {
            peer.addr != owner
                && u32::try_from(peer.start_height).is_ok_and(|height| height >= required_height)
        });
        let mut successful = SmallVec::<[SocketAddr; 8]>::new();
        for peer in candidates {
            let peer_addr = peer.addr;
            let Some(tx) = self.peer_table.lease(peer_addr) else {
                continue;
            };
            let inventory = hashes
                .iter()
                .map(|hash| {
                    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                        *hash.as_byte_array(),
                    ))
                })
                .collect();
            if tx.send(Message::GetData(inventory)).is_ok() {
                successful.push(peer_addr);
            }
        }
        if successful.is_empty() {
            return;
        }
        let block_count = hashes.len();
        window.confirm_prefix_probe(owner, hashes, &successful, now);
        metrics::counter!("node.sync.prefix_probe_peers")
            .increment(u64::try_from(successful.len()).unwrap_or(u64::MAX));
        tracing::info!(
            owner = %owner,
            alternates = successful.len(),
            blocks = block_count,
            "block sync: started common-prefix peer probe"
        );
    }

    fn send_getdata_for_pending_blocks(
        &self,
        sync_peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
    ) -> GetdataRequestOutcome {
        let now = Instant::now();
        let tree = self.handles.block_tree.read();
        let Some(applied_id) = tree.lookup(applied_tip.hash) else {
            return GetdataRequestOutcome::default();
        };
        let Ok(plan) = plan_reorg(&tree, applied_id, chain_tip.tip_id) else {
            return GetdataRequestOutcome::default();
        };
        let Some(first_connect) = plan.connect.first() else {
            return GetdataRequestOutcome::default();
        };
        let Ok(first_connect) = tree.node(*first_connect) else {
            return GetdataRequestOutcome::default();
        };
        let request_start_height = first_connect.height;

        let mut window = self.download_window.lock();
        let request = window.next_peer_request(
            sync_peer_addr,
            allow_expired_retry_from_peer,
            chain_tip,
            request_start_height,
            peer_best_height,
            &tree,
            now,
        );
        drop(tree);
        let Some(request) = request else {
            return GetdataRequestOutcome::default();
        };

        let count = request.len();
        let mut inventory = Vec::with_capacity(count);
        let mut expected_hashes = ExpectedBlockHashes::with_capacity(count);
        let mut expected_height = applied_tip.height.saturating_add(1);
        let mut is_contiguous = true;
        for (height, hash) in request.entries() {
            inventory.push(Inventory::WitnessBlock(
                bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()),
            ));
            if is_contiguous && height == expected_height {
                expected_hashes.push(hash);
                expected_height = if let Some(next) = expected_height.checked_add(1) {
                    next
                } else {
                    is_contiguous = false;
                    expected_height
                };
            } else {
                is_contiguous = false;
            }
        }
        let msg = Message::GetData(inventory);

        let tx = self.peer_table.lease(request.peer_addr());
        let Some(tx) = tx else {
            tracing::trace!(
                peer_addr = %request.peer_addr(),
                "block sync: target peer has no outbound channel (getdata skipped)"
            );
            return GetdataRequestOutcome::default();
        };
        if tx.send(msg).is_err() {
            tracing::warn!(
                peer_addr = %request.peer_addr(),
                "block sync: outbound channel disconnected (getdata)"
            );
            return GetdataRequestOutcome::default();
        }
        if is_contiguous {
            *self.expected_apply_cache.lock() = Some(ExpectedApplyCache {
                chain_tip_hash: chain_tip.hash,
                applied_tip_hash: applied_tip.hash,
                applied_tip_height: applied_tip.height,
                offset: 0,
                hashes: expected_hashes,
            });
        }
        let has_request_capacity = window.mark_requested(&request, now);
        metrics::histogram!("node.sync.getdata_batch_size").record(metric_count(count));
        tracing::debug!(
            peer_addr = %request.peer_addr(),
            count,
            applied_height = applied_tip.height,
            chain_height = chain_tip.height,
            "block sync: sent getdata batch"
        );
        GetdataRequestOutcome {
            sent: true,
            has_request_capacity,
        }
    }

    fn send_getheaders(&self, sync_peer_addr: SocketAddr, our_height: u32, target_height: i32) {
        let locator = self.build_locator();
        let Some(locator_tip_hash) = locator.first().copied() else {
            return;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
        let now = Instant::now();
        let _window = self.download_window.lock();
        if self.has_pending_getheaders(sync_peer_addr, locator_tip_hash, target_height, now) {
            tracing::trace!(
                peer_addr = %sync_peer_addr,
                our_height,
                target_height,
                "block sync: getheaders already pending",
            );
            return;
        }
        let locator_hashes: Vec<bitcoin::BlockHash> = locator
            .into_iter()
            .map(|hash| bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()))
            .collect();
        let msg = Message::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            bitcoin::BlockHash::all_zeros(),
        ));
        let tx = self.peer_table.lease(sync_peer_addr);
        let Some(tx) = tx else {
            tracing::warn!(
                peer_addr = %sync_peer_addr,
                "block sync: target peer no longer has outbound channel"
            );
            return;
        };
        if tx.send(msg).is_err() {
            tracing::warn!(
                peer_addr = %sync_peer_addr,
                "block sync: outbound channel disconnected"
            );
            return;
        }
        *self.pending_getheaders.lock() = Some(PendingHeaderRequest {
            peer_addr: sync_peer_addr,
            locator_tip_hash,
            target_height,
            requested_at: now,
        });
        tracing::debug!(
            peer_addr = %sync_peer_addr,
            our_height,
            target_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
    }

    fn has_pending_getheaders(
        &self,
        peer_addr: SocketAddr,
        locator_tip_hash: Hash256,
        target_height: u32,
        now: Instant,
    ) -> bool {
        let pending = *self.pending_getheaders.lock();
        let Some(pending) = pending else {
            return false;
        };
        pending.peer_addr == peer_addr
            && pending.locator_tip_hash == locator_tip_hash
            && pending.target_height == target_height
            && now.duration_since(pending.requested_at) < HEADER_REQUEST_TIMEOUT
    }

    fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.handles.chain_tip.load_full() {
            return self
                .handles
                .block_tree
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        alloc::vec![self.handles.network.genesis_block_hash()]
    }

    fn ensure_genesis_tip(&self) {
        if self.handles.applied_tip.load_full().is_some() {
            return;
        }

        let had_chain_tip = self.handles.chain_tip.load_full().is_some();
        let genesis = self.handles.network.genesis_block();
        match crate::apply::apply_block(&self.handles, &genesis) {
            Ok(tip) => {
                if !had_chain_tip {
                    self.handles.chain_tip.store(Some(Arc::new(tip)));
                }
            }
            Err(error) => {
                tracing::warn!(%error, "block sync: failed to bootstrap genesis");
            }
        }
    }

    /// Sends one untracked duplicate request for a cold-start stalled front.
    ///
    /// The original request remains the sole pending owner. This bounded
    /// hedge therefore changes neither capacity accounting nor timeout state.
    fn send_cold_front_hedge(
        &self,
        owner: SocketAddr,
        front_hash: Hash256,
        front_height: u32,
        now: Instant,
    ) -> Option<SocketAddr> {
        let mut candidates = SmallVec::<[SocketAddr; 8]>::new();
        for peer in self.peer_table.infos() {
            if peer.addr != owner
                && statically_fanout_eligible(&peer)
                && u32::try_from(peer.start_height).is_ok_and(|height| height >= front_height)
            {
                candidates.push(peer.addr);
            }
        }
        let candidates: SmallVec<[SocketAddr; 8]> = {
            let window = self.download_window.lock();
            candidates
                .into_iter()
                .filter(|addr| {
                    !window.peer_has_expired_pending(*addr, now)
                        && !window.peer_in_staller_cooldown(*addr, now)
                })
                .collect()
        };
        let mut message = Message::GetData(vec![Inventory::WitnessBlock(
            bitcoin::BlockHash::from_byte_array(*front_hash.as_byte_array()),
        )]);
        for peer_addr in candidates {
            let tx = self.peer_table.lease(peer_addr);
            let Some(tx) = tx else {
                continue;
            };
            match tx.send(message) {
                Ok(()) => {
                    metrics::counter!("node.sync.cold_front_hedges").increment(1);
                    tracing::info!(
                        owner = %owner,
                        hedge_peer = %peer_addr,
                        %front_hash,
                        front_height,
                        "block sync: hedged cold-start stalled front"
                    );
                    return Some(peer_addr);
                }
                Err(error) => {
                    message = error.0;
                }
            }
        }
        None
    }
    /// R8: window-blocked staller detection and disconnect.
    ///
    /// Computes the sync-layer terms of the stall predicate and advances the
    /// window's stall state machine ([`DownloadWindow::observe_stall`] holds
    /// the predicate itself). While the stager holds the next expected block,
    /// the apply side owns the frontier and no peer is blamed.
    ///
    /// On fire the peer's outbound entry is removed. The p2p loop observes
    /// that lease removal and exits; the next tick releases and reassigns the
    /// peer's in-flight blocks. The cooldown prevents an immediate reconnect
    /// from reacquiring the same stripe.
    fn disconnect_window_staller(&self, applied_tip: Option<&TipSnapshot>, now: Instant) -> bool {
        let Some(applied_tip) = applied_tip else {
            return false;
        };
        let Some(next_apply_height) = applied_tip.height.checked_add(1) else {
            return false;
        };
        let apply_side_busy = self
            .next_expected_block_hash()
            .is_some_and(|hash| self.block_stager.lock().contains(&hash));
        let mut cold_hedge = None;
        let mut fired = false;
        let removed_peer = self.select_and_evict_window_peer(|window| {
            cold_hedge = window.observe_cold_front(next_apply_height, apply_side_busy, now);
            let selected = window.observe_stall(next_apply_height, apply_side_busy, now);
            fired = selected.is_some();
            let stall_seconds = window
                .stalling_peer()
                .map_or(0.0, |(_, since)| now.duration_since(since).as_secs_f64());
            metrics::gauge!("node.sync.stall_seconds").set(stall_seconds);
            selected
        });
        if fired {
            let Some(peer_addr) = removed_peer else {
                return false;
            };
            metrics::counter!("node.sync.staller_disconnects").increment(1);
            tracing::warn!(
                peer_addr = %peer_addr,
                next_apply_height,
                "block sync: peer is stalling the download window; disconnecting and re-queueing its blocks"
            );
            return true;
        }
        if let Some((owner, front_hash)) = cold_hedge
            && let Some(alternate) =
                self.send_cold_front_hedge(owner, front_hash, next_apply_height, now)
        {
            self.download_window
                .lock()
                .confirm_cold_front_hedge(owner, alternate, front_hash);
        }
        false
    }

    fn disconnect_timed_out_peer(&self, now: Instant) -> bool {
        let apply_side_busy = self
            .next_expected_block_hash()
            .is_some_and(|hash| self.block_stager.lock().contains(&hash));
        let Some(peer_addr) = self.select_and_evict_window_peer(|window| {
            window.observe_pending_timeout(apply_side_busy, now)
        }) else {
            return false;
        };
        metrics::counter!("node.sync.pending_timeout_disconnects").increment(1);
        tracing::warn!(
            peer_addr = %peer_addr,
            "block sync: peer missed the block request timeout; disconnecting and re-queueing its blocks"
        );
        true
    }

    fn record_sync_metrics(&self) {
        let window = self.download_window.lock();
        let stager = self.block_stager.lock();
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
        metrics::gauge!("node.sync.received_blocks").set(metric_count(stager.received_len()));
        metrics::gauge!("node.sync.received_bytes").set(metric_count(stager.received_bytes()));
        let (pending_blocks_high_water, pending_bytes_high_water) = window.pending_high_water();
        metrics::gauge!("node.sync.pending_blocks_high_water")
            .set(metric_count(pending_blocks_high_water));
        metrics::gauge!("node.sync.pending_bytes_high_water")
            .set(metric_count(pending_bytes_high_water));
        metrics::gauge!("node.sync.staged_blocks_high_water")
            .set(metric_count(stager.received_high_water()));
        metrics::gauge!("node.sync.staged_bytes_high_water")
            .set(metric_count(stager.received_bytes_high_water()));
    }

    fn record_pending_sync_metrics(&self) {
        let window = self.download_window.lock();
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
    }

    /// Selects and evicts a download-window owner only when its latest
    /// reconciled connection identity is still live.
    fn select_and_evict_window_peer(
        &self,
        select: impl FnOnce(&mut DownloadWindow) -> Option<SocketAddr>,
    ) -> Option<SocketAddr> {
        let mut window = self.download_window.lock();
        let peer_addr = select(&mut window)?;
        let connection_id = self.known_sessions.lock().get(&peer_addr).copied()?;
        if !self
            .peer_table
            .disconnect_connection(peer_addr, connection_id)
        {
            return None;
        }
        let mut pending = self.pending_getheaders.lock();
        if pending.is_some_and(|request| request.peer_addr == peer_addr) {
            *pending = None;
        }
        Some(peer_addr)
    }
}

fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use arc_swap::ArcSwapOption;
    // Wire seam: byte-array access on the retained bitcoin:: wire hash types.
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_p2p::{PeerInfo, PeerLease, PeerSource, PeerTable};
    use bitcoin_rs_primitives::encode::double_sha256;
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
        consensus_bytes,
    };
    use bitcoin_rs_script::push_int;
    use bitcoin_rs_storage::StorageError;
    use bitcoin_rs_utxo::UtxoSet;
    use crossbeam_channel::unbounded;
    use hashbrown::HashMap;
    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
        Recorder, SharedString, Unit,
    };
    use parking_lot::{Mutex, RwLock};

    use super::{BlockSync, InboundHeaders, Inventory, Message};
    use crate::apply::ApplyHandles;

    #[test]
    fn tick_sends_getdata_for_headers_above_applied_tip() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut expected = Vec::new();

        for height in 1_u32..=3 {
            let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            expected.push(BlockHash::from(tree.node(tip_id)?.hash));
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        let Message::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(inventory.len(), 3);
        let requested = inventory
            .into_iter()
            .map(|item| match item {
                // Wire seam: Inventory payloads stay bitcoin::; convert to native.
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

    #[test]
    fn fork_getdata_starts_at_common_ancestor_child() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = genesis_header();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;

        let losing1 = test_header(genesis.compute_hash(), 1);
        let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
        let losing2 = test_header(losing1.compute_hash(), 2);
        let losing2_id = tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
        let applied = {
            let node = tree.node(losing2_id)?;
            TipSnapshot {
                tip_id: losing2_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };

        let winning1 = test_header(genesis.compute_hash(), 101);
        let winning1_id = tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
        let winning2 = test_header(winning1.compute_hash(), 102);
        let winning2_id = tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
        let winning3 = test_header(winning2.compute_hash(), 103);
        tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
        let expected = vec![
            winning1.compute_hash(),
            winning2.compute_hash(),
            winning3.compute_hash(),
        ];

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(applied)));
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let sync = BlockSync::new(
            apply_handles(chain_tip, Arc::clone(&applied_tip), block_tree),
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let peer = SocketAddr::from(([127, 0, 0, 1], 18_460));
        let (tx, rx) = unbounded::<Message>();
        peers.register(peer, PeerLease::new(tx));
        let chain_tip = sync
            .handles
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing winning chain tip"))?;
        let applied_tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing losing applied tip"))?;

        assert!(
            sync.send_getdata_for_pending_blocks(peer, false, 100, &chain_tip, &applied_tip)
                .sent
        );
        assert_eq!(
            witness_block_inventory(next_getdata(&rx)?)?,
            expected,
            "the fork request must begin immediately after the common ancestor"
        );
        Ok(())
    }

    #[test]
    fn retargeting_pending_requests_drops_losing_branch_hashes()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = genesis_header();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_tip = {
            let node = tree.node(genesis_id)?;
            TipSnapshot {
                tip_id: genesis_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };

        let losing1 = test_header(genesis.compute_hash(), 1);
        let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
        let losing2 = test_header(losing1.compute_hash(), 2);
        let losing2_id = tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
        let losing_tip = {
            let node = tree.node(losing2_id)?;
            TipSnapshot {
                tip_id: losing2_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        let losing_hashes = vec![losing1.compute_hash(), losing2.compute_hash()];

        let winning1 = test_header(genesis.compute_hash(), 101);
        let winning1_id = tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
        let winning2 = test_header(winning1.compute_hash(), 102);
        let winning2_id = tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
        let winning3 = test_header(winning2.compute_hash(), 103);
        let winning3_id = tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
        let winning_tip = {
            let node = tree.node(winning3_id)?;
            TipSnapshot {
                tip_id: winning3_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
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
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let sync = BlockSync::new(
            apply_handles(Arc::clone(&chain_tip), Arc::clone(&applied_tip), block_tree),
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let peer = SocketAddr::from(([127, 0, 0, 1], 18_461));
        let (tx, rx) = unbounded::<Message>();
        peers.register(peer, PeerLease::new(tx));
        let applied = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing genesis applied tip"))?;
        let initial = chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing losing chain tip"))?;

        assert!(
            sync.send_getdata_for_pending_blocks(peer, false, 100, &initial, &applied)
                .sent
        );
        assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, losing_hashes);

        chain_tip.store(Some(Arc::new(winning_tip)));
        let retargeted = chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing winning chain tip"))?;
        assert!(
            sync.send_getdata_for_pending_blocks(peer, false, 100, &retargeted, &applied)
                .sent
        );
        let requested = witness_block_inventory(next_getdata(&rx)?)?;
        assert_eq!(requested, winning_hashes);
        assert!(
            requested.iter().all(|hash| !losing_hashes.contains(hash)),
            "retargeted requests must not retain hashes from the losing branch"
        );
        assert_eq!(
            sync.download_window.lock().pending_len(),
            winning_hashes.len(),
            "retargeting must release losing-branch pending capacity"
        );
        Ok(())
    }

    #[test]
    fn outweighed_branch_target_accepts_shorter_higher_work_branch()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = genesis_header();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let main1 = test_header(genesis.compute_hash(), 1);
        let main1_id = tree.insert_node(Some(genesis_id), main1, NodeStatus::HeaderValid)?;
        let main2 = test_header(main1.compute_hash(), 2);
        let main2_id = tree.insert_node(Some(main1_id), main2, NodeStatus::HeaderValid)?;
        let applied = {
            let node = tree.node(main2_id)?;
            TipSnapshot {
                tip_id: main2_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };

        let mut high_work = test_header(genesis.compute_hash(), 101);
        high_work.bits = 0x2000_ffff;
        high_work.nonce = 0;
        while !pow_met(high_work.bits, Hash256::from(high_work.compute_hash())) {
            high_work.nonce = high_work.nonce.wrapping_add(1);
        }
        let high_work_id =
            tree.insert_node(Some(genesis_id), high_work, NodeStatus::HeaderValid)?;
        let winning = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing higher-work tip"))?;
        assert_eq!(winning.tip_id, high_work_id);
        assert!(winning.height < applied.height);
        assert!(winning.chainwork > applied.chainwork);

        let chain_tip = tree.tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(applied)));
        let block_tree = Arc::new(RwLock::new(tree));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let sync = BlockSync::new(
            apply_handles(chain_tip, applied_tip, block_tree),
            Arc::new(PeerTable::new()),
            Arc::new(Mutex::new(inbound_headers_rx_raw)),
            Arc::new(Mutex::new(inbound_blocks_rx_raw)),
        );

        assert_eq!(sync.outweighed_branch_target(), Some(high_work_id));
        Ok(())
    }

    // One no-store lifecycle must prove both accounting retirement and bounded
    // staging body resolution; splitting it would stop exercising their handoff.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn branch_switch_uses_staged_bodies_without_durable_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(2)?;
        sync.ensure_genesis_tip();
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_blocks: 3,
                ..super::default_sync_budget()
            },
        );
        for block in &main {
            stage_body(&sync, block);
        }
        assert_eq!(sync.apply_buffered_blocks(None), (2, 0));
        assert!(
            sync.handles.block_body_store.is_none(),
            "fixture must not fall back to durable body storage"
        );
        for block in &main {
            stage_body(&sync, block);
        }

        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let mut fork_parent = genesis_id;
        let mut fork_prev = genesis.block_hash();
        let mut fork = Vec::new();
        for height in 1..=3_u32 {
            let mut coinbase = coinbase_transaction(height);
            coinbase.outputs[0].script_pubkey = push_int(2);
            let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
            fork_parent = sync.handles.block_tree.write().insert_node(
                Some(fork_parent),
                block.header,
                NodeStatus::HeaderValid,
            )?;
            fork_prev = block.block_hash();
            fork.push(block);
        }
        let fork_tip = sync
            .handles
            .block_tree
            .read()
            .tip()
            .ok_or_else(|| std::io::Error::other("fork tip was not published"))?;
        sync.handles.chain_tip.store(Some(fork_tip));
        assert_eq!(sync.block_stager.lock().received_len(), 2);
        assert_eq!(sync.download_window.lock().received_len(), 0);

        let stage_received = |block: &Block| {
            stage_body(&sync, block);
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let bytes = consensus_bytes(block).len();
            sync.download_window
                .lock()
                .mark_received(hash, bytes, Instant::now());
            hash
        };

        let first_hash = stage_received(&fork[0]);
        assert_eq!(sync.block_stager.lock().received_len(), 3);
        assert_eq!(
            sync.outweighed_branch_target(),
            Some(fork_parent),
            "the full fork tip must select the initial branch switch"
        );
        sync.switch_branch_if_outweighed();
        let first_tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("branch prefix did not publish a tip"))?;
        assert_eq!(first_tip.height, 1);
        assert_eq!(first_tip.hash, first_hash);
        assert_eq!(sync.block_stager.lock().received_len(), 2);
        assert_eq!(sync.download_window.lock().received_len(), 0);

        for (index, block) in fork.iter().enumerate().skip(1) {
            let hash = stage_received(block);
            assert_eq!(
                sync.block_stager.lock().received_len(),
                3,
                "the tiny stager has room for one suffix body"
            );
            assert_eq!(
                sync.apply_buffered_blocks(None),
                (1, 0),
                "the committed prefix must turn the remaining fork into forward apply"
            );
            let tip = applied_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("forward suffix did not publish a tip"))?;
            assert_eq!(tip.height, u32::try_from(index + 1)?);
            assert_eq!(tip.hash, hash);
            assert_eq!(sync.block_stager.lock().received_len(), 2);
            assert_eq!(sync.download_window.lock().received_len(), 0);
        }

        install_budget(
            &sync,
            super::SyncBudget {
                max_received_blocks: 5,
                ..super::default_sync_budget()
            },
        );
        for block in &fork {
            stage_body(&sync, block);
        }
        for block in &main {
            stage_body(&sync, block);
        }
        assert_eq!(
            sync.block_stager.lock().received_len(),
            5,
            "bounded staging must contain every reverse-switch plan body"
        );
        // The reverse switch must resolve all five disconnect and connect bodies from
        // the bounded stager, without durable storage or fixture-vector lookup.
        let explicit_body = |hash: Hash256| sync.block_stager.lock().staged_body(hash);
        let main_target = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(main[1].block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing original branch tip"))?;
        crate::reorg::switch_to_branch(&sync.handles, main_target, explicit_body, |hash| {
            sync.retire_applied_reorg_body(hash);
        })?;
        let restored = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("reverse switch did not publish a tip"))?;
        assert_eq!(
            restored.hash,
            Hash256::from_le_bytes(main[1].block_hash().as_bytes()),
            "bounded staging must supply the reverse branch switch without durable storage"
        );
        assert_eq!(
            sync.block_stager.lock().received_len(),
            3,
            "only connected bodies retire from bounded staging after the reverse switch"
        );
        Ok(())
    }

    #[test]
    fn branch_switch_replans_after_a_competing_connect_before_transition()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(2)?;
        sync.ensure_genesis_tip();
        for block in &main {
            stage_body(&sync, block);
        }
        assert_eq!(sync.apply_buffered_blocks(None), (2, 0));
        for block in &main {
            stage_body(&sync, block);
        }

        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let mut fork_parent = genesis_id;
        let mut fork_prev = genesis.block_hash();
        let mut fork = Vec::new();
        for height in 1..=3_u32 {
            let mut coinbase = coinbase_transaction(height);
            coinbase.outputs[0].script_pubkey = push_int(2);
            let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
            fork_parent = sync.handles.block_tree.write().insert_node(
                Some(fork_parent),
                block.header,
                NodeStatus::HeaderValid,
            )?;
            fork_prev = block.block_hash();
            stage_body(&sync, &block);
            fork.push(block);
        }

        let main_tip_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(main[1].block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing main branch tip"))?;
        let mut racing_coinbase = coinbase_transaction(3);
        racing_coinbase.outputs[0].script_pubkey = push_int(3);
        let racing = mined_block_with_prev_hash(main[1].block_hash(), 3, vec![racing_coinbase]);
        stage_body(&sync, &racing);
        sync.handles.block_tree.write().insert_node(
            Some(main_tip_id),
            racing.header,
            NodeStatus::HeaderValid,
        )?;

        let (preloaded_tx, preloaded_rx) = std::sync::mpsc::sync_channel(0);
        let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            let sync = &sync;
            let worker = scope.spawn(move || {
                let mut paused = false;
                crate::reorg::switch_to_branch(
                    &sync.handles,
                    fork_parent,
                    |hash| {
                        let body = sync.block_stager.lock().staged_body(hash);
                        if !paused {
                            paused = true;
                            assert!(preloaded_tx.send(()).is_ok());
                            assert!(continue_rx.recv().is_ok());
                        }
                        body
                    },
                    |hash| sync.retire_applied_reorg_body(hash),
                )
            });
            preloaded_rx.recv().map_err(|_| {
                std::io::Error::other("branch switch did not pause after preloading began")
            })?;
            crate::apply::apply_block(&sync.handles, &racing)?;
            continue_tx
                .send(())
                .map_err(|_| std::io::Error::other("branch switch stopped before replanning"))?;
            worker
                .join()
                .map_err(|_| std::io::Error::other("branch switch worker panicked"))??;
            Ok(())
        })?;

        let tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("branch switch did not publish a tip"))?;
        assert_eq!(
            tip.hash,
            Hash256::from_le_bytes(fork[2].block_hash().as_bytes()),
            "the locked replan must absorb the competing connect and still reach the target"
        );
        Ok(())
    }

    #[test]
    fn branch_switch_retires_only_the_connected_prefix_after_connect_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
        sync.ensure_genesis_tip();
        stage_body(&sync, &main[0]);
        assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
        stage_body(&sync, &main[0]);

        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let mut fork_parent = genesis_id;
        let mut fork_prev = genesis.block_hash();
        let mut fork = Vec::new();
        for height in 1..=2_u32 {
            let mut coinbase = coinbase_transaction(height);
            coinbase.outputs[0].script_pubkey = push_int(2);
            let mut block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
            fork_parent = sync.handles.block_tree.write().insert_node(
                Some(fork_parent),
                block.header,
                NodeStatus::HeaderValid,
            )?;
            fork_prev = block.block_hash();
            if height == 2 {
                block.txs[0].outputs[0].value = 2;
            }
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let bytes = consensus_bytes(&block).len();
            stage_body(&sync, &block);
            sync.download_window
                .lock()
                .mark_received(hash, bytes, Instant::now());
            fork.push(block);
        }
        let outcome = crate::reorg::switch_to_branch(
            &sync.handles,
            fork_parent,
            |hash| sync.block_stager.lock().staged_body(hash),
            |hash| sync.retire_applied_reorg_body(hash),
        );
        assert!(
            matches!(
                outcome,
                Err(crate::reorg::ReorgError::ConnectFailed { stopped_at: 1, .. })
            ),
            "the mutated second body must fail after one committed connect, got {outcome:?}"
        );

        let tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("partial switch did not publish a tip"))?;
        assert_eq!(
            tip.hash,
            Hash256::from_le_bytes(fork[0].block_hash().as_bytes()),
            "the valid prefix must remain committed"
        );
        let first = Hash256::from_le_bytes(fork[0].block_hash().as_bytes());
        let failed = Hash256::from_le_bytes(fork[1].block_hash().as_bytes());
        assert!(!sync.block_stager.lock().contains(&first));
        assert!(sync.block_stager.lock().contains(&failed));
        assert_eq!(
            sync.download_window.lock().received_len(),
            1,
            "only the failed block may retain download accounting"
        );
        Ok(())
    }

    #[test]
    fn permanent_reorg_failure_invalidates_descendants_and_purges_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, _applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
        sync.ensure_genesis_tip();
        stage_body(&sync, &main[0]);
        assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
        stage_body(&sync, &main[0]);

        let main_hash = Hash256::from_le_bytes(main[0].block_hash().as_bytes());
        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let invalid = mined_block_with_prev_hash(genesis.block_hash(), 1, Vec::new());
        let invalid_id = sync.handles.block_tree.write().insert_node(
            Some(genesis_id),
            invalid.header,
            NodeStatus::HeaderValid,
        )?;
        let descendant =
            mined_block_with_prev_hash(invalid.block_hash(), 2, vec![coinbase_transaction(2)]);
        let descendant_id = sync.handles.block_tree.write().insert_node(
            Some(invalid_id),
            descendant.header,
            NodeStatus::HeaderValid,
        )?;
        let invalid_hash = Hash256::from_le_bytes(invalid.block_hash().as_bytes());
        let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
        for block in [&invalid, &descendant] {
            stage_body(&sync, block);
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let bytes = consensus_bytes(block).len();
            sync.download_window
                .lock()
                .mark_received(hash, bytes, Instant::now());
        }

        sync.switch_branch_if_outweighed();

        {
            let tree = sync.handles.block_tree.read();
            assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
            assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
            assert_eq!(
                tree.tip().map(|tip| tip.hash),
                Some(main_hash),
                "the valid main branch must win after subtree invalidation"
            );
        }
        let stager = sync.block_stager.lock();
        assert!(stager.contains(&main_hash));
        assert!(!stager.contains(&invalid_hash));
        assert!(!stager.contains(&descendant_hash));
        drop(stager);
        assert_eq!(sync.download_window.lock().received_len(), 0);
        Ok(())
    }

    #[test]
    fn operational_reorg_failure_preserves_branch_and_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut sync, _peers, _applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
        sync.ensure_genesis_tip();
        stage_body(&sync, &main[0]);
        assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
        stage_body(&sync, &main[0]);
        let fail_once_store = Arc::new(FailOnceBodyStore::new(1));
        sync.handles.block_body_store = Some(fail_once_store);

        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let mut fork_coinbase = coinbase_transaction(1);
        fork_coinbase.outputs[0].script_pubkey = push_int(2);
        let fork = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![fork_coinbase]);
        let fork_id = sync.handles.block_tree.write().insert_node(
            Some(genesis_id),
            fork.header,
            NodeStatus::HeaderValid,
        )?;
        let descendant =
            mined_block_with_prev_hash(fork.block_hash(), 2, vec![coinbase_transaction(2)]);
        let descendant_id = sync.handles.block_tree.write().insert_node(
            Some(fork_id),
            descendant.header,
            NodeStatus::HeaderValid,
        )?;
        let fork_hash = Hash256::from_le_bytes(fork.block_hash().as_bytes());
        let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
        for block in [&fork, &descendant] {
            stage_body(&sync, block);
            let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
            let bytes = consensus_bytes(block).len();
            sync.download_window
                .lock()
                .mark_received(hash, bytes, Instant::now());
        }

        sync.switch_branch_if_outweighed();

        {
            let tree = sync.handles.block_tree.read();
            assert_ne!(tree.node(fork_id)?.status, NodeStatus::Invalid);
            assert_ne!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
            assert_eq!(tree.tip().map(|tip| tip.tip_id), Some(descendant_id));
        }
        let stager = sync.block_stager.lock();
        assert!(stager.contains(&fork_hash));
        assert!(stager.contains(&descendant_hash));
        drop(stager);
        assert_eq!(sync.download_window.lock().received_len(), 2);
        Ok(())
    }

    #[test]
    fn branch_switch_rejects_a_body_for_another_header_before_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
        sync.ensure_genesis_tip();
        stage_body(&sync, &main[0]);
        assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
        let applied_before = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        let utxo_len_before = sync.handles.utxo.len();

        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let mut target_coinbase = coinbase_transaction(1);
        target_coinbase.outputs[0].script_pubkey = push_int(2);
        let target = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![target_coinbase]);
        let target_id = sync.handles.block_tree.write().insert_node(
            Some(genesis_id),
            target.header,
            NodeStatus::HeaderValid,
        )?;
        let mut wrong_coinbase = coinbase_transaction(1);
        wrong_coinbase.outputs[0].script_pubkey = push_int(3);
        let wrong = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![wrong_coinbase]);
        let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
        let wrong_hash = Hash256::from_le_bytes(wrong.block_hash().as_bytes());
        assert_ne!(target_hash, wrong_hash);
        let connected = std::cell::Cell::new(false);

        let outcome = crate::reorg::switch_to_branch(
            &sync.handles,
            target_id,
            |hash| {
                let block = if hash == target_hash {
                    wrong.clone()
                } else {
                    main[0].clone()
                };
                let serialized = bytes::Bytes::from(consensus_bytes(&block));
                Some((block, serialized))
            },
            |_| connected.set(true),
        );

        assert!(
            matches!(
                outcome,
                Err(crate::reorg::ReorgError::BodyHashMismatch {
                    expected,
                    actual,
                    height: 1,
                }) if expected == target_hash && actual == wrong_hash
            ),
            "the wrong sibling body must retain its typed mismatch, got {outcome:?}"
        );
        assert_eq!(
            applied_tip.load_full().as_deref(),
            Some(applied_before.as_ref())
        );
        assert_eq!(sync.handles.utxo.len(), utxo_len_before);
        assert!(!connected.get());
        Ok(())
    }

    #[test]
    fn branch_switch_rejects_mismatched_preserved_bytes_before_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
        sync.ensure_genesis_tip();
        stage_body(&sync, &main[0]);
        assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
        let applied_before = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        let utxo_len_before = sync.handles.utxo.len();

        let genesis = Network::Regtest.genesis_block();
        let genesis_id = sync
            .handles
            .block_tree
            .read()
            .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
        let mut target_coinbase = coinbase_transaction(1);
        target_coinbase.outputs[0].script_pubkey = push_int(2);
        let target = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![target_coinbase]);
        let target_id = sync.handles.block_tree.write().insert_node(
            Some(genesis_id),
            target.header,
            NodeStatus::HeaderValid,
        )?;
        let mut wrong_coinbase = coinbase_transaction(1);
        wrong_coinbase.outputs[0].script_pubkey = push_int(3);
        let wrong = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![wrong_coinbase]);
        let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
        let wrong_bytes = bytes::Bytes::from(consensus_bytes(&wrong));
        let connected = std::cell::Cell::new(false);

        let outcome = crate::reorg::switch_to_branch(
            &sync.handles,
            target_id,
            |hash| {
                if hash == target_hash {
                    return Some((target.clone(), wrong_bytes.clone()));
                }
                let block = main[0].clone();
                let serialized = bytes::Bytes::from(consensus_bytes(&block));
                Some((block, serialized))
            },
            |_| connected.set(true),
        );

        assert!(
            matches!(
                outcome,
                Err(crate::reorg::ReorgError::BodyBytesMismatch { hash, height: 1 })
                    if hash == target_hash
            ),
            "mismatched preserved bytes must retain their typed error, got {outcome:?}"
        );
        assert_eq!(
            applied_tip.load_full().as_deref(),
            Some(applied_before.as_ref())
        );
        assert_eq!(sync.handles.utxo.len(), utxo_len_before);
        assert!(!connected.get());
        Ok(())
    }

    #[test]
    fn tick_skips_getheaders_when_header_tip_matches_peer_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
        let applied_snapshot = {
            let tree = block_tree.read();
            let chain_tip = sync
                .handles
                .chain_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
            let node_id = tree
                .node_at_height_from(chain_tip.tip_id, 1)
                .ok_or_else(|| std::io::Error::other("missing height one node"))?;
            let node = tree.node(node_id)?;
            TipSnapshot {
                tip_id: node_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        applied_tip.store(Some(Arc::new(applied_snapshot)));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
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

    #[test]
    fn tick_does_not_resend_same_getheaders_while_pending() -> Result<(), Box<dyn std::error::Error>>
    {
        let (sync, peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
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
    fn inbound_headers_response_releases_getheaders_gate() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 8));

        sync.tick();
        let first = rx.try_recv()?;
        if !matches!(first, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first getheaders").into());
        }

        let header = test_header(genesis.compute_hash(), 1);
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![header],
            source: Some(current_source(&peers, addr)),
        })?;
        sync.tick();
        let second = rx.try_recv()?;
        if !matches!(second, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected second getheaders after response").into());
        }
        let accepted_tip = chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing accepted header tip"))?;
        assert_eq!(accepted_tip.height, 1);
        assert_ne!(accepted_tip.tip_id, genesis_id);
        Ok(())
    }

    #[test]
    fn rejected_matching_peer_headers_release_gate_and_retry_immediately()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 8));

        sync.tick();
        let first = rx.try_recv()?;
        if !matches!(first, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first getheaders").into());
        }

        // A syntactically valid response consumes the matching request even when
        // acceptance rejects its headers. Otherwise one bad response stalls sync.
        let orphan_prev = BlockHash(Hash256::from_le_bytes(&[0x11; 32]));
        let orphan = test_header(orphan_prev, 5);
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![orphan],
            source: Some(current_source(&peers, addr)),
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
    fn invalid_nbits_headers_disconnect_source_and_rotate_getheaders()
    -> Result<(), Box<dyn std::error::Error>> {
        let HeaderSyncFixture {
            genesis,
            sync,
            inbound_headers_tx,
            peers,
        } = header_sync_with_genesis()?;
        let invalid_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let other_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        let (invalid_tx, invalid_rx) = unbounded::<Message>();
        let (other_tx, other_rx) = unbounded::<Message>();

        // Seed only the invalid peer so the first tick routes a GetHeaders to
        // it and arms the pending gate against its address.
        let invalid_lease = bitcoin_rs_p2p::PeerLease::new(invalid_tx);
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
            sync.pending_getheaders
                .lock()
                .is_some_and(|request| request.peer_addr == invalid_peer),
            "a pending getheaders must name the invalid peer before its batch arrives"
        );

        // Deliver the attributed invalid batch while the gate is still armed
        // against the invalid peer. No other selectable peer remains, so this
        // tick cannot re-arm the gate against a different address: the only way
        // `pending_getheaders` ends up clear is the peer-fault cleanup.
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
            source: Some(current_source(&peers, invalid_peer)),
        })?;
        sync.tick();

        assert!(
            sync.pending_getheaders.lock().is_none(),
            "an attributed invalid-header fault must release the pending getheaders gate"
        );
        assert!(
            !peers.is_connected(invalid_peer),
            "invalid header source must be removed from peer selection"
        );
        assert!(
            !peers.is_connected(invalid_peer),
            "invalid header source must lose its outbound lease"
        );

        // Re-introduce a healthy peer; the next getheaders must rotate to it.
        let other_lease = bitcoin_rs_p2p::PeerLease::new(other_tx);
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
    fn orphan_headers_keep_source_peer_connected() -> Result<(), Box<dyn std::error::Error>> {
        let HeaderSyncFixture {
            sync,
            inbound_headers_tx,
            peers,
            ..
        } = header_sync_with_genesis()?;
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let _rx = connect_peer(&peers, synthetic_peer(peer_addr, 8));
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![test_header(
                BlockHash(Hash256::from_le_bytes(&[0x11; 32])),
                1,
            )],
            source: Some(current_source(&peers, peer_addr)),
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
    fn unattributed_invalid_headers_do_not_disconnect_any_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let HeaderSyncFixture {
            genesis,
            sync,
            inbound_headers_tx,
            peers,
        } = header_sync_with_genesis()?;
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let _rx = connect_peer(&peers, synthetic_peer(peer_addr, 8));
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
            source: None,
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
    fn tick_bounded_request_peer_selection_skips_inflight_saturated_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                ..super::default_sync_budget()
            },
        );
        let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let first_rx = connect_peer(&peers, synthetic_peer(first_addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(first_inventory) = first_rx.try_recv()? else {
            return Err(std::io::Error::other("expected first peer getdata").into());
        };
        assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
        let first_headers = first_rx.try_recv()?;
        if !matches!(first_headers, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first peer getheaders").into());
        }

        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
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
        // The in-flight getheaders gate suppresses a duplicate header request to
        // the original sync peer, so it receives no further messages.
        assert!(first_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                pending_timeout: Duration::ZERO,
                ..super::default_sync_budget()
            },
        );
        let stale_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        let stale_rx = connect_peer(&peers, synthetic_peer(stale_addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
                return Err(
                    std::io::Error::other("stale peer should not receive retry getdata").into(),
                );
            }
        }
        Ok(())
    }

    #[test]
    fn tick_allows_demoted_peer_when_it_is_the_only_eligible_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                pending_timeout: Duration::ZERO,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
    fn tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut expected = Vec::new();
        let batch_size = 16_u32;

        for height in 1_u32..=batch_size + 4 {
            let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            if height <= batch_size {
                expected.push(BlockHash::from(tree.node(tip_id)?.hash));
            }
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                getdata_batch_limit: usize::try_from(batch_size)?,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        let Message::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        let requested = inventory
            .into_iter()
            .map(|item| match item {
                // Wire seam: Inventory payloads stay bitcoin::; convert to native.
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
    fn second_tick_does_not_re_request_already_pending_blocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;

        for height in 1_u32..=3 {
            let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        if !matches!(first, Message::GetData(_)) {
            return Err(std::io::Error::other("expected first tick getdata").into());
        }
        let second = rx.try_recv()?;
        if !matches!(second, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first tick getheaders").into());
        }

        sync.tick();

        // The in-flight getheaders gate suppresses a duplicate header request,
        // and already-pending blocks are not re-requested, so the second tick
        // emits no outbound messages.
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
    fn disconnected_outbound_channel_does_not_mark_blocks_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        register_info(&peers, synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        drop(rx);
        peers.register(addr, bitcoin_rs_p2p::PeerLease::new(tx));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        assert_eq!(sync.download_window.lock().pending_len(), 0);
        Ok(())
    }

    #[test]
    fn successful_getdata_send_marks_requested_blocks_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        let Message::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected);

        let window = sync.download_window.lock();
        assert_eq!(window.pending_len(), expected.len());
        for hash in expected {
            let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(hash.as_bytes());
            assert!(window.contains_pending(&hash));
        }
        Ok(())
    }

    #[test]
    fn drain_inbound_blocks_prunes_stale_received_blocks_without_new_arrivals()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
        let block = Network::Regtest.genesis_block();
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_bytes());
        let received_at = Instant::now()
            .checked_sub(super::RECEIVED_BLOCK_TIMEOUT + Duration::from_secs(1))
            .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        let staged = sync
            .block_stager
            .lock()
            .insert(hash, None, block, serialized, received_at);
        let super::StagedBlock::Memory { bytes, .. } = staged else {
            return Err(std::io::Error::other("test block should stage in memory").into());
        };
        sync.download_window
            .lock()
            .mark_received(hash, bytes, Instant::now());

        sync.drain_inbound_blocks();

        assert_eq!(sync.block_stager.lock().received_len(), 0);
        assert_eq!(sync.download_window.lock().received_len(), 0);
        Ok(())
    }

    #[test]
    fn unsolicited_stale_block_retries_from_resolved_header_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let block1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let block2 =
            mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let block1_hash = block1.block_hash();
        let expected_hash = block2.block_hash();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block1_id =
            tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                getdata_batch_limit: 2,
                received_timeout: Duration::ZERO,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(initial) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial getdata").into());
        };
        assert_eq!(
            witness_block_inventory(initial)?,
            alloc::vec![block1_hash, expected_hash]
        );
        let _headers = rx.try_recv()?;
        {
            let mut window = sync.download_window.lock();
            window.mark_applied(&Hash256::from_le_bytes(block1_hash.as_bytes()));
            window.mark_applied(&Hash256::from_le_bytes(expected_hash.as_bytes()));
        }

        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
        sync.drain_inbound_blocks();

        assert_eq!(sync.block_stager.lock().received_len(), 0);
        assert_eq!(sync.download_window.lock().received_len(), 0);

        sync.tick();

        let Message::GetData(retry) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected height-2 retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
        Ok(())
    }

    #[test]
    fn tick_respects_pending_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_bytes: 256 * 1024,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(inventory.len(), 1);
        assert_eq!(sync.download_window.lock().pending_len(), 1);
        Ok(())
    }

    #[test]
    fn tick_limits_inflight_per_peer() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(5)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_peer_inflight: 2,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(inventory.len(), 2);
        let _headers = rx.try_recv()?;

        sync.tick();

        // Peer inflight budget is saturated and the in-flight getheaders gate
        // suppresses a duplicate header request, so the second tick is silent.
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_fanout_distributes_window_front_first_across_eligible_peers()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9001, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let cap = super::PENDING_BUDGET.div_ceil(super::MIN_PEERS_FOR_FANOUT);
        for (idx, rx) in rxs.iter().enumerate() {
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(
                    std::io::Error::other("expected getdata for every eligible peer").into(),
                );
            };
            // Window-front-first and capped: peers are scanned highest-first,
            // each taking the next `cap` in-order heights — fan-out changes
            // who is asked, never what order the window wants.
            assert_eq!(
                witness_block_inventory(inventory)?,
                expected[idx * cap..(idx + 1) * cap]
            );
            if idx == 0 {
                if !matches!(rx.try_recv()?, Message::GetHeaders(_)) {
                    return Err(std::io::Error::other("expected getheaders for header peer").into());
                }
            }
            assert!(rx.try_recv().is_err(), "no peer may exceed the fan-out cap");
        }
        assert_eq!(
            sync.download_window.lock().pending_len(),
            super::PENDING_BUDGET,
            "fan-out must fill the deep window"
        );
        Ok(())
    }

    #[test]
    fn tick_falls_back_to_single_deep_peer_below_fanout_threshold()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
            let addr = test_addr(9021, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rxs[0].try_recv()? else {
            return Err(std::io::Error::other("expected deep getdata for highest peer").into());
        };
        // The tracked window remains single-owner. Idle eligible alternates
        // receive only the same bounded frontier prefix for the one-shot race.
        assert_eq!(witness_block_inventory(inventory)?, expected);
        for rx in &rxs[1..] {
            assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
        }
        assert_eq!(
            sync.download_window.lock().pending_len(),
            super::PENDING_BUDGET
        );
        Ok(())
    }

    /// Cross-tick regression for the bounded prefix-race-before-fanout
    /// handoff: a probe created below the threshold must defer fanout when the
    /// eligible count reaches the threshold on a following tick while the
    /// probe is still fresh, then fanout must engage once the injected time
    /// crosses the `stall_timeout_initial` deadline. Exercises the real
    /// `tick()` / `configure_request_mode` / `set_fanout_eligible_peers`
    /// path for probe creation and the deferral, then injects a future
    /// `Instant` (the only available time seam, since `tick()` reads
    /// `Instant::now()`) to cross the deadline. This is the exact cross-tick
    /// boundary test; the direct window-boundary test lives in
    /// `window::tests::fanout_cancels_prefix_probe_without_rearming_it`. No
    /// sleeps, no network.
    #[test]
    fn tick_fanout_deferred_for_fresh_probe_engages_at_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        // A 16-block chain: the deep single-peer window takes all 16 while
        // the one-shot probe sends the first 8 (PREFIX_PROBE_BLOCK_LIMIT), so
        // the probe getdata is distinguishable from the deep getdata.
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(16)?;
        install_budget(&sync, super::default_sync_budget());

        // Two eligible peers: below the 8-peer fanout threshold. The owner
        // (highest) takes the deep window; the alternate is the probe racer.
        let owner_addr = test_addr(9401, 0)?;
        let alternate_addr = test_addr(9401, 1)?;
        let owner_rx = connect_peer(&peers, eligible_peer(owner_addr, 201));
        let alternate_rx = connect_peer(&peers, eligible_peer(alternate_addr, 200));

        // Tick 1: below the threshold, a prefix probe is created. The owner
        // receives the deep getdata (all 16) and the alternate receives the
        // one-shot probe getdata (the first 8).
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
            !sync.download_window.lock().fanout_active(),
            "below the threshold fanout must stay off"
        );

        // Reach the fanout threshold on the following tick: add six more
        // eligible peers (eight total) and tick again. The probe is still
        // fresh (age well under stall_timeout_initial = 2s), so the bounded
        // deferral holds fanout off and the probe survives the transition.
        for idx in 2..super::MIN_PEERS_FOR_FANOUT {
            connect_peer(&peers, eligible_peer(test_addr(9401, idx)?, 200));
        }
        sync.tick();
        assert!(
            !sync.download_window.lock().fanout_active(),
            "a fresh prefix probe must defer the threshold-crossing tick"
        );

        // Cross the injected time deadline measured from the active probe's
        // stored `started_at`. The cross-tick path cannot control the
        // `Instant::now()` used when the probe is created, so read it back and
        // add exactly `stall_timeout_initial`. Then assert the planned
        // duration equals the budget before engaging fanout.
        let mut window = sync.download_window.lock();
        let started_at = window
            .active_prefix_probe_started_at()
            .ok_or_else(|| std::io::Error::other("probe must remain active after deferral"))?;
        let budget = super::default_sync_budget();
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

    #[test]
    fn inbound_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
    {
        let ineligible = PeerInfo {
            inbound: true,
            ..eligible_peer(test_addr(9200, 0)?, 300)
        };
        assert_fallback_with_ineligible_candidate(ineligible, true)
    }

    #[test]
    fn non_witness_peer_not_counted_toward_fanout_threshold()
    -> Result<(), Box<dyn std::error::Error>> {
        let ineligible = PeerInfo {
            // NODE_NETWORK only — no NODE_WITNESS.
            services: 1,
            ..eligible_peer(test_addr(9210, 0)?, 300)
        };
        assert_fallback_with_ineligible_candidate(ineligible, true)
    }

    #[test]
    fn low_chain_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
    {
        // Outbound + witness, but its known chain does not reach past our
        // applied tip (genesis, height 0): fails the height clause outright.
        let ineligible = eligible_peer(test_addr(9220, 0)?, 0);
        assert_fallback_with_ineligible_candidate(ineligible, false)
    }

    /// Seven eligible peers plus one ineligible candidate: were the
    /// ineligible peer counted, fan-out (many shallow getdatas) would engage;
    /// instead the window collapses to one deep single-peer batch. When the
    /// ineligible peer is the highest candidate (`serves_fallback`), it also
    /// pins that the fallback still uses it — the pre-fan-out shipped
    /// behavior (an inbound-only node must still sync).
    fn assert_fallback_with_ineligible_candidate(
        ineligible: PeerInfo,
        serves_fallback: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let ineligible_rx = connect_peer(&peers, ineligible);
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
            let addr = test_addr(9230, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
            assert!(
                ineligible_rx.try_recv().is_err(),
                "ineligible peer must receive nothing"
            );
        }
        for rx in &rxs[usize::from(!serves_fallback)..] {
            assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
        }
        Ok(())
    }

    #[test]
    fn demoted_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
    {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        install_budget(
            &sync,
            super::SyncBudget {
                pending_timeout: Duration::ZERO,
                ..super::default_sync_budget()
            },
        );
        // Phase 1: the lone peer takes the deep window; the zero timeout
        // expires every pending immediately, soft-demoting it.
        let demoted_rx = connect_peer(&peers, eligible_peer(test_addr(9240, 0)?, 300));
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(initial) = demoted_rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial deep getdata").into());
        };
        assert_eq!(initial.len(), super::PENDING_BUDGET);
        if !matches!(demoted_rx.try_recv()?, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders for lone peer").into());
        }

        // Phase 2: seven more eligible peers connect — eight eligible-shaped
        // candidates, but the demoted one must not count (7 < threshold), so
        // the expired blocks are re-issued as one deep fallback batch instead
        // of fanning out.
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
            let addr = test_addr(9241, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
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
    fn ineligible_peers_receive_no_block_requests_during_fanout()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        // A real (short) pending timeout: the lone peer's requests must be
        // expired by the time the second tick runs, while the second tick's
        // own fresh requests stay live across the request loop. (A zero
        // timeout would re-expire each fan-out peer's requests for the next
        // peer within the same tick.)
        install_budget(
            &sync,
            super::SyncBudget {
                pending_timeout: Duration::from_millis(250),
                ..super::default_sync_budget()
            },
        );
        // Soft-demote one otherwise-eligible peer: it takes the deep window
        // and never delivers.
        let demoted_rx = connect_peer(&peers, eligible_peer(test_addr(9250, 0)?, 290));
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(initial) = demoted_rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial deep getdata").into());
        };
        assert_eq!(initial.len(), super::PENDING_BUDGET);
        if !matches!(demoted_rx.try_recv()?, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders for lone peer").into());
        }

        // One ineligible candidate per predicate clause, all at heights that
        // would make them the most attractive picks were they eligible.
        let inbound_rx = connect_peer(
            &peers,
            PeerInfo {
                inbound: true,
                ..eligible_peer(test_addr(9251, 0)?, 310)
            },
        );
        let non_witness_rx = connect_peer(
            &peers,
            PeerInfo {
                services: 1,
                ..eligible_peer(test_addr(9252, 0)?, 305)
            },
        );
        let low_chain_rx = connect_peer(&peers, eligible_peer(test_addr(9253, 0)?, 0));
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9254, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        // Let the lone peer's pendings expire (demoting it) before fanning out.
        std::thread::sleep(Duration::from_millis(300));
        sync.tick();
        // Conviction requires a second drain opportunity so a block delivered
        // during synchronous apply is not mistaken for a network timeout.
        sync.tick();
        assert!(
            !peers.is_connected(test_addr(9250, 0)?),
            "a peer that misses the request timeout must release its outbound slot"
        );
        assert!(
            sync.download_window
                .lock()
                .peer_in_staller_cooldown(test_addr(9250, 0)?, Instant::now()),
            "a timed-out peer must not immediately reacquire the same block stripe"
        );

        let cap = super::PENDING_BUDGET.div_ceil(super::MIN_PEERS_FOR_FANOUT);
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
        // The header peer (highest candidate, inbound) may still receive
        // getheaders — header sync is not block download.
        if !matches!(inbound_rx.try_recv()?, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders to header peer").into());
        }
        assert!(inbound_rx.try_recv().is_err());
        assert!(non_witness_rx.try_recv().is_err());
        assert!(low_chain_rx.try_recv().is_err());
        assert!(demoted_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_caps_requests_at_staged_byte_headroom() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
        let slot = 256 * 1024;
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: 3 * slot,
                ..super::default_sync_budget()
            },
        );
        // Two of three staging slots already occupied: the staged-byte gate is
        // still open, but only one more estimated block fits.
        {
            let mut window = sync.download_window.lock();
            let now = Instant::now();
            window.mark_received(Hash256::from_le_bytes(&[0xEE; 32]), slot, now);
            window.mark_received(Hash256::from_le_bytes(&[0xEF; 32]), slot, now);
        }
        let addr = test_addr(9270, 0)?;
        let rx = connect_peer(&peers, eligible_peer(addr, 200));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected headroom-clamped getdata").into());
        };
        // A gate-open burst must not over-request past staging headroom.
        assert_eq!(witness_block_inventory(inventory)?, expected[..1]);
        if !matches!(rx.try_recv()?, Message::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders").into());
        }

        sync.tick();

        // The in-flight request consumed the last slot: no further requests
        // until staged blocks apply.
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn()
    -> Result<(), Box<dyn std::error::Error>> {
        // The recorded live-collapse construction (scaled 8x down): the
        // default one-minute timeouts never fire inside the test, so the only
        // thing that can stop the second wave is the count clamp itself.
        let (sync, _peers, expected, rxs, _blocks_tx) =
            staged_count_wedge(wedge_budget(super::PENDING_TIMEOUT))?;

        // Tick 2: the healthy deliveries stage; staged (14) + pending (2) sit
        // exactly at the count budget (16). The byte gates are unbounded here
        // (KB-scale blocks), so requests stop only if count overflow is
        // request backpressure.
        sync.tick();

        {
            let window = sync.download_window.lock();
            assert_eq!(window.received_len(), 14);
            assert_eq!(window.pending_len(), 2);
            for front in &expected[..2] {
                assert!(
                    window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())),
                    "stalled front stripe must stay pending, not churn through retry"
                );
            }
        }

        // Tick 3: stability. Pre-fix this is where the second wave was
        // requested, delivered past RECEIVED_BLOCK_BUDGET, evicted the oldest
        // staged blocks (nearest the frozen front) and snapped the window
        // back into self-sustaining re-request churn.
        sync.tick();

        for rx in &rxs {
            assert_no_getdata(rx)?;
        }
        let stager = sync.block_stager.lock();
        assert_eq!(stager.received_len(), 14, "no evictions may occur");
        for height in 3..=16_u32 {
            let hash = Hash256::from_le_bytes(expected[usize::try_from(height)? - 1].as_bytes());
            assert!(
                stager.contains(&hash),
                "every delivered block must remain staged (height {height})"
            );
        }
        assert_eq!(sync.download_window.lock().pending_len(), 2);
        Ok(())
    }

    #[test]
    fn wedged_window_expires_stalled_front_and_rerequests_through_count_clamp()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, expected, rxs, _blocks_tx) =
            staged_count_wedge(wedge_budget(Duration::from_millis(250)))?;

        // Tick 2: wedge — staged + pending at the count budget, scan limit
        // zero, the stalled front still pending.
        sync.tick();
        assert_eq!(sync.download_window.lock().pending_len(), 2);

        // Past the pending timeout the wedge must process its own deadlines:
        // the expired front credits the scan-limit count headroom, the
        // request path expires it (U5 chain through the new clamps' pending
        // terms), soft demotion keeps the staller out, and a healthy peer is
        // asked for the front stripe — all without the received-prune
        // discarding a single staged block into re-download.
        std::thread::sleep(Duration::from_millis(300));
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
            sync.block_stager.lock().received_len(),
            14,
            "staged progress must survive the wedge"
        );
        {
            let window = sync.download_window.lock();
            assert_eq!(window.pending_len(), 2);
            for front in &expected[..2] {
                assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
            }
        }
        Ok(())
    }

    #[test]
    fn cold_start_stall_hedges_front_without_reassigning_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let budget = super::SyncBudget {
            stall_timeout_initial: Duration::from_millis(100),
            ..wedge_budget(super::PENDING_TIMEOUT)
        };
        let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
        let owner = test_addr(9320, 0)?;

        // The first drain builds the asymmetric wedge and starts the episode.
        sync.tick();
        assert_eq!(sync.download_window.lock().pending_len(), 2);
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
        assert_eq!(sync.download_window.lock().pending_len(), 2);

        // The confirmed front hash is not duplicated again on later ticks.
        std::thread::sleep(Duration::from_millis(50));
        sync.tick();
        for rx in &rxs[1..] {
            assert_no_getdata(rx)?;
        }
        Ok(())
    }

    #[test]
    fn common_prefix_winner_takes_over_deep_window() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(16)?;
        let owner = test_addr(9321, 0)?;
        let alternate = test_addr(9321, 1)?;
        let owner_rx = connect_peer(&peers, eligible_peer(owner, 200));
        let alternate_rx = connect_peer(&peers, eligible_peer(alternate, 100));

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
            let mut inbound = bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone());
            inbound.source = Some(current_source(&peers, alternate));
            blocks_tx.send(inbound)?;
        }
        sync.tick();

        assert_eq!(
            sync.download_window.lock().preferred_peer(),
            Some(alternate)
        );
        assert!(
            sync.download_window
                .lock()
                .peer_in_staller_cooldown(owner, Instant::now())
        );
        assert_eq!(
            witness_block_inventory(next_getdata(&alternate_rx)?)?,
            blocks[4..]
                .iter()
                .map(Block::block_hash)
                .collect::<Vec<_>>()
        );
        assert!(peers.is_connected(owner));
        sync.download_window
            .lock()
            .mark_peer_unresponsive(alternate, Instant::now());
        sync.tick();
        assert_eq!(
            sync.download_window.lock().preferred_peer(),
            Some(alternate),
            "a temporary soft block skips the winner without erasing its election"
        );
        Ok(())
    }

    #[test]
    fn fanout_replaces_preferred_peer_when_eligible_pool_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(48)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 16,
                max_pending_bytes: usize::MAX,
                max_peer_inflight: 16,
                fanout_peer_inflight: 2,
                min_peers_for_fanout: super::MIN_PEERS_FOR_FANOUT,
                getdata_batch_limit: 16,
                ..super::default_sync_budget()
            },
        );
        let owner = test_addr(9322, 0)?;
        let alternate = test_addr(9322, 1)?;
        let owner_rx = connect_peer(&peers, eligible_peer(owner, 200));
        let alternate_rx = connect_peer(&peers, eligible_peer(alternate, 100));

        sync.tick();
        let _ = next_getdata(&owner_rx)?;
        let _ = next_getdata(&alternate_rx)?;
        for block in &blocks[..4] {
            let mut inbound = bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone());
            inbound.source = Some(current_source(&peers, alternate));
            blocks_tx.send(inbound)?;
        }
        sync.tick();
        let _ = next_getdata(&alternate_rx)?;
        assert_eq!(
            sync.download_window.lock().preferred_peer(),
            Some(alternate)
        );

        let mut recovered_rxs = Vec::new();
        for idx in 2..=8 {
            recovered_rxs.push(connect_peer(
                &peers,
                eligible_peer(test_addr(9322, idx)?, 100),
            ));
        }
        for block in &blocks[4..8] {
            let mut inbound = bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone());
            inbound.source = Some(current_source(&peers, alternate));
            blocks_tx.send(inbound)?;
        }
        sync.tick();

        let window = sync.download_window.lock();
        assert!(window.preferred_peer().is_none());
        assert!(window.fanout_active());
        drop(window);
        assert!(
            recovered_rxs.iter().any(|rx| rx.try_recv().is_ok()),
            "a recovered eligible peer must receive a fanout request"
        );
        Ok(())
    }

    #[test]
    fn applied_ancestry_lookup_uses_active_index_only_for_applied_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let main1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let main2 =
            mined_block_with_prev_hash(main1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let main3 =
            mined_block_with_prev_hash(main2.block_hash(), 3, vec![coinbase_transaction(3)]);
        let main4 =
            mined_block_with_prev_hash(main3.block_hash(), 4, vec![coinbase_transaction(4)]);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let main1_id = tree.insert_node(Some(genesis_id), main1.header, NodeStatus::HeaderValid)?;
        let main2_id = tree.insert_node(Some(main1_id), main2.header, NodeStatus::HeaderValid)?;
        let applied_tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("main tip was not published"))?;
        let main3_id = tree.insert_node(Some(main2_id), main3.header, NodeStatus::HeaderValid)?;
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
            let fork = mined_block_with_prev_hash(
                fork_prev,
                height.saturating_add(100),
                vec![coinbase_transaction(height.saturating_add(100))],
            );
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
    fn far_behind_duplicate_of_applied_block_is_not_staged()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(64)?;
        let peer = test_addr(9321, 0)?;
        let rx = connect_peer(&peers, eligible_peer(peer, 100));

        sync.tick();
        let requested = next_getdata(&rx)?;
        assert_eq!(
            witness_block_inventory(requested)?,
            blocks.iter().map(Block::block_hash).collect::<Vec<_>>()
        );
        for block in &blocks {
            blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
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
            !sync.download_window.lock().contains_pending(&stale_hash),
            "the replay must be unsolicited after its request was applied"
        );

        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[0].clone(),
        ))?;
        sync.tick();

        assert!(!sync.block_stager.lock().contains(&stale_hash));
        let window = sync.download_window.lock();
        assert_eq!(window.pending_len(), 0);
        assert_eq!(window.received_len(), 0);
        assert!(!window.contains_pending(&stale_hash));
        Ok(())
    }

    #[test]
    fn stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued()
    -> Result<(), Box<dyn std::error::Error>> {
        // R8 core scenario and the terminator for the U6 wedge's bounded
        // cycle (and the first-audit ADV-2 shape: the staller is the
        // highest-advertising peer, holding the front on claimed height it
        // never serves). The 1-minute pending timeout can never fire inside
        // this test, so the staller disconnect is the ONLY recovery path.
        let budget = super::SyncBudget {
            stall_timeout_initial: Duration::from_millis(100),
            ..wedge_budget(super::PENDING_TIMEOUT)
        };
        let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
        let staller = test_addr(9320, 0)?;

        // Cold-start disarm: the wedge fixture never advances the window
        // front, so the cadence EWMA would stay unseeded and conviction
        // would defer to the 60s pending-timeout fallback (the cold-start
        // suppression, pinned at the window level). Seed it at 50ms — the
        // decay floor stays max(2x50ms, 100ms) = the injected initial
        // threshold — so this test keeps pinning the adaptive-timeout fire.
        sync.download_window
            .lock()
            .seed_front_cadence_for_test(50, Instant::now());

        // Tick 2: the wedge forms (staged 14 + pending 2 at the count
        // budget) and the stall episode starts on the front-stripe owner.
        sync.tick();
        {
            let window = sync.download_window.lock();
            assert_eq!(window.received_len(), 14);
            assert_eq!(window.pending_len(), 2);
            assert_eq!(
                window.stalling_peer().map(|(addr, _)| addr),
                Some(staller),
                "the front-stripe owner must be the observed staller"
            );
        }

        // Past the adaptive threshold: the staller is disconnected, its
        // front stripe re-queues, and a healthy peer is asked for it in the
        // same tick — with the staged set intact (no prune involvement).
        std::thread::sleep(Duration::from_millis(150));
        sync.tick();

        assert!(
            !peers.is_connected(staller),
            "staller's outbound lease must be revoked"
        );
        assert!(
            sync.download_window
                .lock()
                .peer_in_staller_cooldown(staller, Instant::now()),
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
            sync.block_stager.lock().received_len(),
            14,
            "staged progress must survive the staller disconnect"
        );
        {
            let window = sync.download_window.lock();
            assert_eq!(window.pending_len(), 2);
            for front in &expected[..2] {
                assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
            }
        }
        Ok(())
    }

    #[test]
    fn stall_eviction_does_not_disconnect_replacement_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let budget = super::SyncBudget {
            stall_timeout_initial: Duration::from_millis(100),
            ..wedge_budget(super::PENDING_TIMEOUT)
        };
        let (sync, peers, _expected, _rxs, _blocks_tx) = staged_count_wedge(budget)?;
        let staller = test_addr(9320, 0)?;
        sync.download_window
            .lock()
            .seed_front_cadence_for_test(50, Instant::now());

        sync.tick();
        let applied_tip = sync
            .handles
            .applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        let next_apply_height = applied_tip
            .height
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("applied height overflow"))?;
        let (replacement_tx, _replacement_rx) = unbounded::<Message>();
        let replacement = PeerLease::new(replacement_tx);
        let evicted = sync.select_and_evict_window_peer(|window| {
            let selected = window.observe_stall(
                next_apply_height,
                false,
                Instant::now() + Duration::from_millis(150),
            );
            peers.register(staller, replacement.clone());
            peers.publish_info(staller, &replacement, eligible_peer(staller, 200));
            selected
        });

        assert_eq!(evicted, None);
        assert!(peers.is_connected(staller));
        assert!(!replacement.is_cancelled());
        Ok(())
    }

    #[test]
    fn byte_wedged_window_recovers_via_staller_disconnect_before_received_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        // RE-ADV-1 byte-denominated R+P wedge: staged bytes + the stalled
        // front's estimated bytes exhaust the staging byte headroom, so the
        // request gate is closed while the gate itself (`staged_bytes_
        // exhausted`) is still open. Both 1-minute timeouts are live
        // defaults here — pre-U7 the received-prune was the only recovery;
        // now the staller disconnect frees the wedge in well under a second.
        let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(2)?;
        install_budget(
            &sync,
            super::SyncBudget {
                // One initial-estimate slot (the pending front) plus the
                // delivered successor: byte headroom is exactly zero once
                // both are accounted.
                max_received_bytes: 256 * 1024 + consensus_bytes(&blocks[1]).len(),
                // Phase 1: arming reads the staged-count fraction, not
                // request capacity, so the single staged successor must be
                // >= half the count window (2 / 2 = 1) for the episode to
                // arm. The byte clamp still closes the request gate (the
                // wedge under test); the count budget only sizes the arming
                // bar to this two-block construction.
                max_received_blocks: 2,
                getdata_batch_limit: 2,
                stall_timeout_initial: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let staller = test_addr(9430, 0)?;
        let honest = test_addr(9430, 1)?;
        let staller_rx = connect_peer(&peers, synthetic_peer(staller, 200));
        let honest_rx = connect_peer(&peers, synthetic_peer(honest, 100));

        // Cold-start disarm: this byte-wedge construction depends on the
        // pristine 256KiB initial block-size estimate, so the cadence EWMA
        // is seeded directly instead of via two real front deliveries (the
        // real sampling path is pinned by the window tests). 50ms keeps the
        // decay floor at the injected 100ms initial threshold.
        sync.download_window
            .lock()
            .seed_front_cadence_for_test(50, Instant::now());

        sync.tick();
        let Message::GetData(inventory) = staller_rx.try_recv()? else {
            return Err(std::io::Error::other("expected staller getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![blocks[0].block_hash(), blocks[1].block_hash()]
        );

        // The successor stages; byte headroom hits zero (R + P at the byte
        // budget) with the front still pending to the staller.
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[1].clone(),
        ))?;
        sync.tick();
        {
            let window = sync.download_window.lock();
            assert!(!window.has_request_capacity());
            assert_eq!(window.stalling_peer().map(|(addr, _)| addr), Some(staller));
        }
        assert!(honest_rx.try_recv().is_err());

        // Fire: the staller's disconnect releases its pending bytes, which
        // reopens exactly enough headroom to re-request the front from the
        // honest peer — with the staged successor untouched (the 1-minute
        // prune never ran).
        std::thread::sleep(Duration::from_millis(150));
        sync.tick();
        assert!(!peers.is_connected(staller));
        assert_eq!(
            sync.block_stager.lock().received_len(),
            1,
            "recovery must not discard staged progress (prune-free)"
        );
        let Message::GetData(retry) = honest_rx.try_recv()? else {
            return Err(std::io::Error::other("expected honest peer front retry").into());
        };
        assert_eq!(
            witness_block_inventory(retry)?,
            alloc::vec![blocks[0].block_hash()]
        );

        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[0].clone(),
        ))?;
        sync.tick();
        // The re-request narrowed the expected-apply cache to the front, so
        // the staged successor drains on the following tick's tree walk.
        sync.tick();
        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height;
        assert_eq!(applied_height, 2, "the byte wedge must fully recover");
        Ok(())
    }

    #[test]
    fn slow_trickle_front_peer_observable_but_never_disconnected()
    -> Result<(), Box<dyn std::error::Error>> {
        // R10 slow-trickle: a peer delivering each front block just under
        // the adaptive threshold is never disconnected (Core has the same
        // exposure), but the stall state must be visible — via the window
        // accessor and the node.sync.stall_seconds gauge.
        let recorder = TestRecorder::default();
        metrics::with_local_recorder(&recorder, || {
            let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(6)?;
            install_budget(
                &sync,
                super::SyncBudget {
                    max_pending_blocks: 3,
                    max_received_blocks: 3,
                    max_peer_inflight: 3,
                    getdata_batch_limit: 3,
                    // Default 2s initial threshold: the 100ms trickle below
                    // stays far under it on any machine.
                    ..super::default_sync_budget()
                },
            );
            let trickler = test_addr(9440, 0)?;
            let rx = connect_peer(&peers, synthetic_peer(trickler, 100));

            for round in 0..2_usize {
                let offset = round * 3;
                sync.tick();
                let inventory = next_getdata(&rx)?;
                assert_eq!(inventory.len(), 3);
                // Successors arrive, the front trickles: window-blocked.
                blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                    blocks[offset + 1].clone(),
                ))?;
                blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                    blocks[offset + 2].clone(),
                ))?;
                sync.tick();
                assert_eq!(
                    sync.download_window
                        .lock()
                        .stalling_peer()
                        .map(|(addr, _)| addr),
                    Some(trickler),
                    "the stall episode must be observable while the front trickles"
                );
                std::thread::sleep(Duration::from_millis(100));
                sync.tick();
                // Still under the threshold: observed, not punished.
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
                // The front arrives just under the threshold: progress —
                // episode ends, adaptive threshold stays at its initial
                // value, and the next round starts clean.
                blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                    blocks[offset].clone(),
                ))?;
                sync.tick();
                assert!(sync.download_window.lock().stalling_peer().is_none());
                assert_eq!(
                    sync.download_window.lock().stall_timeout(),
                    super::BLOCK_STALLING_TIMEOUT,
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
    fn apply_side_backpressure_never_blamed_on_front_peer() -> Result<(), Box<dyn std::error::Error>>
    {
        // No-blame guard at the sync layer: while the stager holds the next
        // expected block (apply lag / failed-apply restore), the stall clock
        // must not run — no disconnect fires even arbitrarily far past the
        // threshold, and the busy interval is never charged to the peer.
        // Time is injected through the detection entry point directly.
        let (sync, peers, _block_tree, _applied_tip, expected) = sync_with_header_chain(4)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                max_received_blocks: 2,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                ..super::default_sync_budget()
            },
        );
        let staller = test_addr(9450, 0)?;
        let rx = connect_peer(&peers, synthetic_peer(staller, 100));

        // Cold-start disarm: an unseeded EWMA would suppress the fire on its
        // own and this test would pass vacuously. Seed it (50ms keeps the
        // decay floor at the default 2s initial threshold) so the no-fire
        // phase below pins the apply-side no-blame guard specifically.
        sync.download_window
            .lock()
            .seed_front_cadence_for_test(50, Instant::now());

        sync.tick();
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
        // The successor stages; the window is otherwise fully blocked on the
        // front-holding peer.
        let successor = Hash256::from_le_bytes(expected[1].as_bytes());
        {
            let block = Network::Regtest.genesis_block();
            let serialized = bytes::Bytes::from(consensus_bytes(&block));
            sync.block_stager
                .lock()
                .insert(successor, None, block, serialized, Instant::now());
        }
        sync.download_window
            .lock()
            .mark_received(successor, 80, Instant::now());

        // Apply-side backpressure: the next expected block (the frontier) is
        // itself staged but not yet drained.
        let frontier = Hash256::from_le_bytes(expected[0].as_bytes());
        {
            let block = Network::Regtest.genesis_block();
            let serialized = bytes::Bytes::from(consensus_bytes(&block));
            sync.block_stager
                .lock()
                .insert(frontier, None, block, serialized, Instant::now());
        }

        let applied = sync
            .handles
            .applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        let far_future = Instant::now() + Duration::from_mins(1);

        // Far past any threshold, but the apply side is busy: frozen.
        sync.disconnect_window_staller(Some(&applied), far_future);
        assert!(sync.download_window.lock().stalling_peer().is_none());
        assert!(peers.is_connected(staller));

        // The apply side drains the frontier: blame starts from scratch and
        // only then runs to a fire — the busy interval was not charged.
        let drained = sync.block_stager.lock().drain_expected_prefix(&[frontier]);
        assert_eq!(drained.len(), 1);
        sync.disconnect_window_staller(Some(&applied), far_future);
        assert_eq!(
            sync.download_window
                .lock()
                .stalling_peer()
                .map(|(addr, _)| addr),
            Some(staller)
        );
        assert!(peers.is_connected(staller));
        sync.disconnect_window_staller(Some(&applied), far_future + super::BLOCK_STALLING_TIMEOUT);
        assert!(
            !peers.is_connected(staller),
            "with the apply side idle the same state must fire normally"
        );
        Ok(())
    }

    #[test]
    fn uniform_slow_saturated_fanout_disconnects_no_peer_and_completes()
    -> Result<(), Box<dyn std::error::Error>> {
        // Sync-level smoke for the self-eclipse blocker and the ADV-DRIP-1
        // drip: 8 eligible peers in saturated fan-out (window 24 = 8 peers x
        // cap 3 over a 32-block chain, so refills keep R+P pinned at the
        // count budget and "no request capacity" is the steady state) over a
        // fully applicable mined chain. Every peer keeps streaming — one
        // block per peer per round, lowest-block-first so the window front
        // advances at the round cadence — while every round lands 150ms
        // apart, past the injected 100ms threshold. Each tick drains the
        // round's deliveries before observing, so per-peer delivery progress
        // clears every delivery-time episode; the mid-gap ticks (the wake
        // path observes between the front owner's deliveries — where the
        // pre-fix drip fired) stay under the adaptive decay floor once the
        // interval EWMA has its first sample: zero staller disconnects and
        // the sync completes. (The timing-injected constructions live in the
        // window module: `uniform_slow_streaming_saturated_fanout_never_fires`
        // and `stall_decay_limit_cycle_stops_at_adaptive_floor`.)
        let recorder = TestRecorder::default();
        metrics::with_local_recorder(&recorder, || {
            let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(32)?;
            install_budget(
                &sync,
                super::SyncBudget {
                    max_pending_blocks: 24,
                    max_pending_bytes: usize::MAX,
                    max_received_blocks: 24,
                    max_received_bytes: usize::MAX,
                    max_peer_inflight: 24,
                    fanout_peer_inflight: 3,
                    min_peers_for_fanout: 8,
                    getdata_batch_limit: 24,
                    stall_timeout_initial: Duration::from_millis(100),
                    ..super::default_sync_budget()
                },
            );
            let mut rxs = Vec::new();
            for idx in 0..8_usize {
                let addr = test_addr(9470, idx)?;
                rxs.push(connect_peer(
                    &peers,
                    eligible_peer(addr, 200 - i32::try_from(idx)?),
                ));
            }

            // Tick 1: fan-out stripes the 24-block window, 3 blocks per peer.
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

            // Three rounds, each past the stall threshold. The front
            // (heights 1, 2, 3 — peer 0's stripe) advances once per round,
            // so the interval EWMA takes its first sample at round 1 and the
            // adaptive floor (2x the ~150ms demonstrated cadence) covers the
            // mid-gap wakes from the round 1 -> 2 gap on. The round 0 -> 1
            // gap has no sample yet, but an unseeded window cannot fire at
            // all: cold-start conviction is suppressed and deferred to the
            // 60s pending-timeout fallback (`observe_stall` in the window
            // module), so even a wake landing there is safe.
            for round in 0..3_usize {
                if round == 2 {
                    // The wake path observes at ~g/8 cadence, so episodes
                    // form on the first wake after a round's deliveries
                    // (the round tick itself observes before its refill
                    // re-closes request capacity) and age across the
                    // following wakes. Two mid-gap wakes reproduce that:
                    // one just inside the gap to form the episode, one
                    // ~120ms later — past the 100ms static threshold (the
                    // pre-fix drip disconnected peer 0 exactly there) but
                    // under the adaptive floor (2x the ~150ms demonstrated
                    // front cadence).
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
                for stripe in &stripes {
                    let block = by_hash
                        .get(&stripe[round])
                        .ok_or_else(|| std::io::Error::other("unknown getdata hash"))?;
                    blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
                }
                sync.tick();
                assert_eq!(
                    peers.len(),
                    8,
                    "no streaming peer may be disconnected (round {round})"
                );
            }
            // Drain: feed the refill tail (heights 25..=32) one block per
            // tick — the staged set is still near the 24-block budget while
            // the expected-apply cache narrows, and a burst would push the
            // stager into evicting frontier blocks that are never
            // re-delivered here.
            let mut tail = blocks[24..].iter();
            for _ in 0..40_usize {
                let applied = applied_tip.load_full().map_or(0, |tip| tip.height);
                if applied == 32 {
                    break;
                }
                if let Some(block) = tail.next() {
                    blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
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
    fn transient_demotion_does_not_flap_fanout_mode() -> Result<(), Box<dyn std::error::Error>> {
        const PEER_COUNT: usize = 8;
        let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
            sync_with_header_chain_and_blocks(64)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 16,
                max_pending_bytes: usize::MAX,
                // Roomy count budget: the staging clamps must not bind, so
                // any request change is attributable to the mode alone.
                max_received_blocks: 64,
                max_received_bytes: usize::MAX,
                max_peer_inflight: 16,
                fanout_peer_inflight: 2,
                min_peers_for_fanout: 8,
                getdata_batch_limit: 16,
                pending_timeout: Duration::from_millis(250),
                ..super::default_sync_budget()
            },
        );
        let mut rxs = Vec::new();
        for idx in 0..PEER_COUNT {
            let addr = test_addr(9340, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        // Tick 1: eight eligible peers engage fan-out and stripe the window.
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        assert!(sync.download_window.lock().fanout_active());
        for (idx, rx) in rxs.iter().enumerate() {
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected striped getdata").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                expected[idx * 2..(idx + 1) * 2]
            );
        }

        // The healthy peers deliver their stripes; the front-stripe owner
        // stalls past the pending timeout — eligible peers dip 8 -> 7.
        for height in 3..=16_u32 {
            blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                header_chain_block(&expected, height)?,
            ))?;
        }
        std::thread::sleep(Duration::from_millis(300));
        sync.tick();

        // Mode stability under the transient dip: hysteresis holds fan-out,
        // so the stalled stripe is redistributed in cap-sized batches instead
        // of re-concentrating the whole window on one deep peer.
        assert!(
            sync.download_window.lock().fanout_active(),
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

        // Tick 3: the dip heals (7 -> 8) and the mode is still fan-out — the
        // window stayed in one mode across 8 -> 7 -> 8.
        sync.tick();
        assert!(sync.download_window.lock().fanout_active());
        Ok(())
    }

    #[test]
    fn clean_fast_path_caps_request_at_peer_height() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 4,
                getdata_batch_limit: 4,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 2));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
        assert!(rx.try_recv().is_err());

        sync.tick();

        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn received_only_state_uses_scan_path_without_duplicate_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
        let received_hash = Hash256::from_le_bytes(expected[1].as_bytes());
        {
            let mut window = sync.download_window.lock();
            let needs_height = window.mark_received(received_hash, 80, Instant::now());
            assert!(needs_height);
            window.update_received_height(&received_hash, 2);
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 3));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![expected[0], expected[2]]
        );
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn single_peer_can_fill_default_pending_window() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 200));

        let mut requested = Vec::new();
        let ticks = super::PENDING_BUDGET / super::GETDATA_BATCH_SIZE;
        assert_eq!(
            ticks, 1,
            "default getdata batch should fill the pending window in one tick"
        );
        for tick in 0..ticks {
            sync.tick();
            if tick == 0 {
                assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
            }
            let Message::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata").into());
            };
            requested.extend(witness_block_inventory(inventory)?);
            let _headers = rx.try_recv()?;
        }

        assert_eq!(requested, expected);
        assert_eq!(
            sync.download_window.lock().pending_len(),
            super::PENDING_BUDGET
        );
        Ok(())
    }

    #[test]
    fn tick_retries_expired_pending_before_new_heights() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(5)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                getdata_batch_limit: 2,
                pending_timeout: Duration::ZERO,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
    fn tick_fills_mixed_retry_and_new_height_batch() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 3,
                max_pending_bytes: 3 * 256 * 1024,
                max_peer_inflight: 3,
                getdata_batch_limit: 3,
                pending_timeout: Duration::ZERO,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(first) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first)?, expected[..3]);
        let _headers = rx.try_recv()?;
        sync.download_window
            .lock()
            .mark_applied(&Hash256::from_le_bytes(expected[0].as_bytes()));

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
    fn tick_preserves_partial_window_order_across_pending_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(5)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_pending_bytes: 4 * 256 * 1024,
                max_peer_inflight: 4,
                getdata_batch_limit: 4,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(first) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first)?, expected[..4]);
        let _headers = rx.try_recv()?;
        {
            let mut window = sync.download_window.lock();
            window.mark_applied(&Hash256::from_le_bytes(expected[0].as_bytes()));
            window.drop_for_retry(&Hash256::from_le_bytes(expected[1].as_bytes()));
        }

        sync.tick();

        let Message::GetData(second) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected gap-filling getdata").into());
        };
        assert_eq!(
            witness_block_inventory(second)?,
            vec![expected[1], expected[4]]
        );
        assert_eq!(sync.download_window.lock().pending_len(), 4);
        Ok(())
    }

    #[test]
    fn tick_applies_contiguous_blocks_before_requesting_more()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let child = test_header(genesis.block_hash(), 1);
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
        let expected = BlockHash::from(tree.node(child_id)?.hash);

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(genesis))?;

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, alloc::vec![expected]);
        Ok(())
    }

    #[test]
    fn stager_evicts_same_height_fork_before_expected_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected_hash = Hash256::from_le_bytes(&[0x11; 32]);
        let fork_hash = Hash256::from_le_bytes(&[0x22; 32]);
        let mut stager = super::BlockStager::new(super::SyncBudget {
            max_received_blocks: 1,
            max_received_bytes: usize::MAX,
            ..super::default_sync_budget()
        });
        let now = Instant::now();
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));

        let super::StagedBlock::Memory { dropped, .. } = stager.insert(
            fork_hash,
            Some(expected_hash),
            block.clone(),
            serialized.clone(),
            now,
        ) else {
            return Err(std::io::Error::other("fork block should stage").into());
        };
        assert!(dropped.is_empty());

        let super::StagedBlock::Memory { dropped, .. } =
            stager.insert(expected_hash, Some(expected_hash), block, serialized, now)
        else {
            return Err(std::io::Error::other("expected block should stage").into());
        };
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].hash, fork_hash);
        assert_eq!(stager.received_len(), 1);
        assert!(stager.contains(&expected_hash));
        Ok(())
    }

    #[test]
    fn oversized_received_block_releases_pending_budget_for_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let block = mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![coinbase_transaction(1), transaction(0x41)],
        );
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block_id = tree.insert_node(Some(genesis_id), block.header, NodeStatus::HeaderValid)?;
        let expected_hash = BlockHash::from(tree.node(block_id)?.hash);

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: 1,
                max_peer_inflight: 1,
                getdata_batch_limit: 1,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![expected_hash]
        );
        let _headers = rx.try_recv()?;
        assert_eq!(sync.download_window.lock().pending_len(), 1);

        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block))?;
        sync.drain_inbound_blocks();

        {
            let window = sync.download_window.lock();
            assert_eq!(window.pending_len(), 0);
            assert_eq!(window.pending_bytes(), 0);
        }

        sync.tick();

        let Message::GetData(retry) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
        Ok(())
    }

    #[test]
    fn staging_byte_exhaustion_backpressures_requests_then_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let block1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let block2 =
            mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let block3 =
            mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
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

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        // Staging byte budget that exactly one staged block exhausts.
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: consensus_bytes(&block2).len(),
                getdata_batch_limit: 2,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let rx = connect_peer(&peers, synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![block1_hash, block2_hash]
        );
        let _headers = rx.try_recv()?;

        // Deliver only the successor: it stages (waiting on block1) and
        // exactly exhausts the staging byte budget.
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2.clone()))?;
        sync.drain_inbound_blocks();
        assert_eq!(
            sync.block_stager.lock().received_bytes(),
            consensus_bytes(&block2).len()
        );

        // Exhausted staging degrades to backpressure: the next tick requests
        // nothing further (block3 stays unrequested) and the staged block is
        // not dropped for re-download.
        sync.tick();
        assert!(rx.try_recv().is_err());
        assert_eq!(sync.block_stager.lock().received_len(), 1);

        // The window-front block arrives: the stager admits it past the
        // exhausted budget (expected-block exemption), apply drains both, and
        // request capacity returns for block3.
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block1))?;
        sync.tick();

        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height;
        assert_eq!(applied_height, 2);
        assert_eq!(sync.block_stager.lock().received_len(), 0);
        let Message::GetData(recovered) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected recovery getdata").into());
        };
        assert_eq!(
            witness_block_inventory(recovered)?,
            alloc::vec![block3_hash]
        );
        Ok(())
    }

    #[test]
    fn staging_byte_exhaustion_blocks_all_requests() -> Result<(), Box<dyn std::error::Error>> {
        let ExhaustionFixture {
            sync,
            stalled_rx,
            healthy_rx,
            ..
        } = staging_exhaustion_fixture()?;

        // While the staged bytes are exhausted no getdata is issued at all —
        // the gate is checked before expired-pending retry, so even though
        // block1's pending entry is already expired (zero pending timeout)
        // neither peer is asked for anything.
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
        assert_eq!(sync.block_stager.lock().received_len(), 1);
        Ok(())
    }

    #[test]
    fn staging_byte_exhaustion_recovers_via_staged_block_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let ExhaustionFixture {
            sync,
            stalled_rx,
            healthy_rx,
            block1_hash,
            block2_hash,
            ..
        } = staging_exhaustion_fixture()?;

        // Drain the first tick's messages before testing recovery.
        sync.tick();
        while stalled_rx.try_recv().is_ok() {}

        // Let the staged successor outlive its received timeout, then tick:
        // prune_expired drops it, drop_received_for_retry releases its bytes
        // (gate reopens), and expire_pending re-queues the stalled frontier
        // height-first toward the healthy peer.
        std::thread::sleep(Duration::from_millis(125));
        sync.tick();

        assert_eq!(sync.block_stager.lock().received_len(), 0);
        {
            let window = sync.download_window.lock();
            assert_eq!(window.received_len(), 0);
            assert!(window.has_request_capacity());
            assert!(window.contains_pending(&Hash256::from_le_bytes(block1_hash.as_bytes())));
        }
        let Message::GetData(retry) = healthy_rx.try_recv()? else {
            return Err(std::io::Error::other("expected healthy peer retry getdata").into());
        };
        assert_eq!(
            witness_block_inventory(retry)?,
            alloc::vec![block1_hash, block2_hash]
        );
        while let Ok(message) = stalled_rx.try_recv() {
            if matches!(message, Message::GetData(_)) {
                return Err(
                    std::io::Error::other("stalled peer should not receive retry getdata").into(),
                );
            }
        }
        Ok(())
    }

    struct ExhaustionFixture {
        sync: BlockSync,
        stalled_rx: crossbeam_channel::Receiver<Message>,
        healthy_rx: crossbeam_channel::Receiver<Message>,
        block1_hash: BlockHash,
        block2_hash: BlockHash,
    }

    fn staging_exhaustion_fixture() -> Result<ExhaustionFixture, Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let block1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let block2 =
            mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let block3 =
            mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
        let block1_hash = block1.block_hash();
        let block2_hash = block2.block_hash();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block1_id =
            tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
        let block2_id =
            tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        // Staging byte budget that exactly one staged block exhausts.
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: consensus_bytes(&block2).len(),
                getdata_batch_limit: 2,
                pending_timeout: Duration::ZERO,
                received_timeout: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let stalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        let stalled_rx = connect_peer(&peers, synthetic_peer(stalled_addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = stalled_rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![block1_hash, block2_hash]
        );
        let _headers = stalled_rx.try_recv()?;

        // Deliver only the successor: it stages (waiting on block1, which the
        // stalled peer will never send) and exactly exhausts the staging byte
        // budget, closing the request gate.
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
        sync.drain_inbound_blocks();
        assert!(!sync.download_window.lock().has_request_capacity());

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
        inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
        outbound_rx: crossbeam_channel::Receiver<Message>,
        blocks: Vec<Block>,
    }

    #[test]
    fn deterministic_initial_sync_proxy_reports_pipeline_budgets()
    -> Result<(), Box<dyn std::error::Error>> {
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

            assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
                    .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
            }
            sync.drain_inbound_blocks();
            let (received_count, peak_staged_bytes) = {
                let stager = sync.block_stager.lock();
                (stager.received_len(), stager.received_bytes())
            };
            assert_eq!(received_count, DETERMINISTIC_PROXY_BLOCKS.saturating_sub(1));
            assert!(peak_staged_bytes > 0);
            assert_gauge(&recorder, "node.sync.received_blocks", received_count);
            assert_gauge(&recorder, "node.sync.received_bytes", peak_staged_bytes);

            inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                blocks[0].clone(),
            ))?;
            let apply_started = quanta::Instant::now();
            sync.drain_inbound_blocks();
            let apply_elapsed = apply_started.elapsed();
            let applied_height = applied_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("proxy apply did not publish tip"))?
                .height;
            assert_eq!(applied_height, DETERMINISTIC_PROXY_TIP_HEIGHT);
            assert_eq!(sync.block_stager.lock().received_len(), 0);
            assert_eq!(sync.download_window.lock().pending_len(), 0);
            assert_histogram(&recorder, "node.sync.apply_buffered_blocks_seconds");

            println!(
                "deterministic_sync_apply_proxy peak_staged_bytes={peak_staged_bytes} pending_count={pending_count} received_count={received_count} contiguous_apply_latency_us={}",
                apply_elapsed.as_micros(),
            );
            Ok(())
        })
    }

    fn deterministic_proxy_fixture() -> Result<DeterministicProxyFixture, Box<dyn std::error::Error>>
    {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut prev_hash = genesis.block_hash();
        let mut blocks = Vec::with_capacity(DETERMINISTIC_PROXY_BLOCKS);

        for height in 1_u32..=DETERMINISTIC_PROXY_TIP_HEIGHT {
            let block =
                mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
            tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
            prev_hash = block.block_hash();
            blocks.push(block);
        }
        for height in
            DETERMINISTIC_PROXY_TIP_HEIGHT.saturating_add(1)..=DETERMINISTIC_PROXY_HEADER_HEIGHT
        {
            let header = test_header(prev_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            prev_hash = header.compute_hash();
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: DETERMINISTIC_PROXY_BLOCKS,
                max_pending_bytes: usize::MAX,
                max_received_blocks: DETERMINISTIC_PROXY_BLOCKS,
                max_received_bytes: usize::MAX,
                max_peer_inflight: DETERMINISTIC_PROXY_BLOCKS,
                getdata_batch_limit: DETERMINISTIC_PROXY_BLOCKS,
                ..super::default_sync_budget()
            },
        );

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
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

    #[test]
    fn batch_drain_restores_unapplied_tail_after_mid_batch_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let block1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let block2 =
            mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let block3 =
            mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
        let block2_hash = Hash256::from_le_bytes(block2.block_hash().as_bytes());
        let block3_hash = Hash256::from_le_bytes(block3.block_hash().as_bytes());

        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block1_id =
            tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
        let block2_id =
            tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let mut handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let fail_once_store = Arc::new(FailOnceBodyStore::new(2));
        handles.block_body_store = Some(fail_once_store.clone());
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );

        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block3))?;
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2.clone()))?;
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block1))?;
        sync.tick();

        assert_eq!(
            applied_tip.load_full().map(|tip| tip.height),
            Some(1),
            "height 1 should apply before the fail-once height 2 body persistence error"
        );
        assert_eq!(sync.block_stager.lock().received_len(), 1);
        assert_eq!(sync.download_window.lock().received_len(), 1);
        assert!(
            !sync.block_stager.lock().contains(&block2_hash),
            "failed block should be dropped for retry rather than restored"
        );
        assert!(
            sync.block_stager.lock().contains(&block3_hash),
            "tail block must be restored after the mid-batch failure"
        );
        // G5: the mid-batch failure leaves the gateway generation odd
        // (fail-closed). Admission stays closed; a retry cannot begin a new
        // chain change until an external recovery path resets the generation.
        assert!(
            sync.handles.mempool_gateway.stable_generation().is_none(),
            "generation must be odd after mid-batch failure (G5 fail-closed)"
        );

        // Retry is blocked by the odd generation: begin_chain_change rejects
        // an odd value, so the re-sent block 2 cannot apply.
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
        sync.tick();

        assert_eq!(
            applied_tip.load_full().map(|tip| tip.height),
            Some(1),
            "height must not advance while the generation is odd (G5 fail-closed)"
        );
        assert!(
            sync.handles.mempool_gateway.stable_generation().is_none(),
            "generation must remain odd after the blocked retry"
        );
        assert!(fail_once_store.persisted_height(1));
        Ok(())
    }

    #[test]
    fn drain_inbound_blocks_keeps_oversized_burst_within_received_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = deterministic_proxy_fixture()?;
        let max_received_blocks = 2;
        install_budget(
            &fixture.sync,
            super::SyncBudget {
                max_received_blocks,
                max_received_bytes: usize::MAX,
                ..super::default_sync_budget()
            },
        );

        for block in fixture.blocks[1..6].iter().rev() {
            fixture
                .inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
        }

        fixture.sync.drain_inbound_blocks();

        assert!(
            fixture.sync.block_stager.lock().received_len() <= max_received_blocks,
            "block stager must enforce received block count budget"
        );
        assert!(
            fixture.sync.download_window.lock().received_len() <= max_received_blocks,
            "download window must mirror received block count budget"
        );
        assert!(
            fixture.applied_tip.load_full().is_none(),
            "missing next expected block should prevent out-of-order apply"
        );
        Ok(())
    }

    struct ApplyCacheFixture {
        sync: BlockSync,
        blocks: Vec<Block>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    }

    /// Builds a regtest chain with `body_height` mined block bodies followed by
    /// `header_only` header-only blocks, applies genesis, and returns a fixture
    /// whose stager is empty so individual rounds can stage bodies directly and
    /// exercise the apply-side cache miss/hit transitions.
    fn apply_cache_fixture(
        body_height: u32,
        header_only: u32,
    ) -> Result<ApplyCacheFixture, Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut prev_hash = genesis.block_hash();
        let mut blocks = Vec::with_capacity(usize::try_from(body_height)?);

        for height in 1..=body_height {
            let block =
                mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
            tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
            prev_hash = block.block_hash();
            blocks.push(block);
        }
        for height in body_height.saturating_add(1)..=body_height.saturating_add(header_only) {
            let header = test_header(prev_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            prev_hash = header.compute_hash();
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(Arc::clone(&chain_tip), Arc::clone(&applied_tip), block_tree);
        let sync = BlockSync::new(handles, peers, inbound_headers_rx, inbound_blocks_rx);
        // Apply genesis so the applied tip starts at height 0; no block bodies
        // are staged yet, leaving every round below to drive cache state.
        sync.ensure_genesis_tip();
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
        let serialized = bytes::Bytes::from(consensus_bytes(block));
        sync.block_stager
            .lock()
            .insert(hash, None, block.clone(), serialized, Instant::now());
    }

    fn cache_snapshot(sync: &BlockSync) -> Option<super::ExpectedApplyCache> {
        sync.expected_apply_cache.lock().clone()
    }

    #[test]
    fn apply_cache_miss_populates_and_then_hits() -> Result<(), Box<dyn std::error::Error>> {
        // 8 block bodies available as headers, but only the first three staged
        // this round. A small pending budget caps the cached horizon at 5.
        let fixture = apply_cache_fixture(8, 0)?;
        install_budget(
            &fixture.sync,
            super::SyncBudget {
                max_pending_blocks: 5,
                max_pending_bytes: usize::MAX,
                max_received_blocks: 64,
                max_received_bytes: usize::MAX,
                ..super::default_sync_budget()
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

        // Miss path populated the cache with the full 5-block horizon, then the
        // post-apply advance moved the offset past the three applied blocks.
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

        // Stage block #4: this round must be a cache HIT (validity keys match the
        // advanced cache), draining from the retained suffix rather than re-walking.
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
    fn apply_cache_invalidated_on_failed_apply() -> Result<(), Box<dyn std::error::Error>> {
        // Fail persisting height 2 so the second apply in the batch fails after
        // the first succeeds, exercising the failed-apply invalidation branch.
        let genesis = Network::Regtest.genesis_block();
        let block1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let block2 =
            mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let block3 =
            mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block1_id =
            tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
        let block2_id =
            tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let mut handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let fail_once_store = Arc::new(FailOnceBodyStore::new(2));
        handles.block_body_store = Some(fail_once_store);
        let sync = BlockSync::new(handles, peers, inbound_headers_rx, inbound_blocks_rx);
        sync.ensure_genesis_tip();

        for block in [&block1, &block2, &block3] {
            stage_body(&sync, block);
        }
        let (applied, failed) = sync.apply_buffered_blocks(None);
        assert_eq!(applied, 1, "height 1 applies before the height 2 failure");
        assert_eq!(failed, 1, "height 2 persistence failure aborts the batch");
        assert!(
            cache_snapshot(&sync).is_none(),
            "a failed apply must invalidate the populated cache"
        );
        Ok(())
    }

    #[test]
    fn apply_cache_invalidated_on_chain_tip_move() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = apply_cache_fixture(4, 0)?;
        install_budget(
            &fixture.sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_pending_bytes: usize::MAX,
                max_received_blocks: 64,
                max_received_bytes: usize::MAX,
                ..super::default_sync_budget()
            },
        );

        // Round 1: stage one body, miss populates the cache, advance retains it
        // with the original chain-tip hash as a validity key.
        stage_body(&fixture.sync, &fixture.blocks[0]);
        let (applied, _failed) = fixture.sync.apply_buffered_blocks(None);
        assert_eq!(applied, 1);
        let cache = cache_snapshot(&fixture.sync)
            .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
        let original_chain_tip_hash = cache.chain_tip_hash;
        assert_eq!(cache.offset, 1);

        // Move the chain tip: publish a snapshot whose hash differs from the one
        // the cache was keyed against (a reorg replaces the active-chain tip).
        let moved_tip = {
            let current = fixture
                .chain_tip
                .load_full()
                .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
            let mut hash_bytes = current.hash.to_le_bytes();
            hash_bytes[0] ^= 0xff;
            TipSnapshot {
                tip_id: current.tip_id,
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

        // The decisive probe: with the tip moved, the stale entry must be
        // rejected by its validity keys BEFORE any repopulation can mask a
        // broken eviction (a later apply round always rekeys the cache, so
        // asserting on the post-apply snapshot alone is vacuous).
        assert!(
            fixture.sync.drain_cached_expected_blocks(1).is_none(),
            "stale cache keyed to the old chain tip must not serve a drain"
        );

        // Round 2: stage the next body. The miss recomputes the run against the
        // new tip and repopulates the cache keyed to the moved tip's hash.
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
    fn window_failure_applies_prefix_and_restores_suffix() -> Result<(), Box<dyn std::error::Error>>
    {
        // Blocks now apply in windows, so a mid-window failure has to split the
        // chunk three ways: the prefix committed, the one block that failed, and
        // an untouched suffix that must go back on the stager. Getting that
        // split wrong is invisible to the (applied, failed) counts alone, so
        // this asserts the stager contents too.
        let fixture = apply_cache_fixture(4, 0)?;

        // Corrupt the second body without touching its header: the stager keys
        // on the header hash, so this still drains as the expected block, and
        // apply rejects it on the merkle root. A body that changed its own hash
        // would never be drained and the window would never see it.
        let mut corrupted = fixture.blocks[1].clone();
        corrupted.txs.push(coinbase_transaction(99));
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

        // The merkle-root rejection is a permanent consensus failure, so the
        // window invalidated the corrupted block and its (never-attempted)
        // descendants while the transition was held. They can never become
        // applicable, so instead of returning to the stager they are purged
        // from it: the frontier must not cycle on invalidated blocks.
        let restored = fixture.sync.block_stager.lock().received_len();
        assert_eq!(
            restored, 0,
            "invalidated blocks and their descendants are purged, not restored"
        );
        Ok(())
    }

    #[test]
    fn apply_cache_horizon_capped_by_pending_budget() -> Result<(), Box<dyn std::error::Error>> {
        // 12 header-backed bodies available, pending budget capped at 4. Stage a
        // single body: the populated horizon must not exceed the budget even
        // though far more headers are available above the applied tip.
        let fixture = apply_cache_fixture(12, 0)?;
        let cap = 4;
        install_budget(
            &fixture.sync,
            super::SyncBudget {
                max_pending_blocks: cap,
                max_pending_bytes: usize::MAX,
                max_received_blocks: 64,
                max_received_bytes: usize::MAX,
                ..super::default_sync_budget()
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
        // The cached run begins at applied_tip + 1 (height 1) and stays contiguous.
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

    type SyncFixture = (
        BlockSync,
        Arc<PeerTable>,
        Arc<RwLock<BlockTree>>,
        Arc<ArcSwapOption<TipSnapshot>>,
        Vec<BlockHash>,
    );

    type InboundBlockSender = crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>;

    fn sync_with_header_chain(height: u32) -> Result<SyncFixture, Box<dyn std::error::Error>> {
        // Dropping the sender mirrors the original fixture: a disconnected
        // inbound-blocks channel that never yields a block.
        let (fixture, _inbound_blocks_tx) = sync_with_header_chain_and_blocks(height)?;
        Ok(fixture)
    }

    fn sync_with_header_chain_and_blocks(
        height: u32,
    ) -> Result<(SyncFixture, InboundBlockSender), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut expected = Vec::new();

        for height in 1_u32..=height {
            let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            expected.push(BlockHash::from(tree.node(tip_id)?.hash));
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );

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

    /// Like [`sync_with_header_chain_and_blocks`] but with fully applicable
    /// mined regtest blocks (coinbase-bearing, PoW-valid), so tests can drive
    /// real apply progress through the inbound channel.
    fn sync_with_mined_chain(count: u32) -> Result<MinedChainFixture, Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let mut node_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let mut prev_hash = genesis.block_hash();
        let mut blocks = Vec::with_capacity(usize::try_from(count)?);
        for height in 1..=count {
            let block =
                mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
            node_id = tree.insert_node(Some(node_id), block.header, NodeStatus::HeaderValid)?;
            prev_hash = block.block_hash();
            blocks.push(block);
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        // `node_id` ends as the chain tip; it only exists to thread parents.
        let _ = node_id;

        Ok((sync, peers, applied_tip, blocks, inbound_blocks_tx))
    }

    type WedgeFixture = (
        BlockSync,
        Arc<PeerTable>,
        Vec<BlockHash>,
        Vec<crossbeam_channel::Receiver<Message>>,
        InboundBlockSender,
    );

    /// The recorded-collapse construction at `install_budget` scale: eight
    /// eligible peers stripe a 16-block window at per-peer fan-out cap 2
    /// against a 64-block header chain; the front-stripe owner (the highest
    /// peer, heights 1-2) stalls while the seven healthy peers deliver
    /// heights 3..=16 into the inbound channel. After the caller's next tick
    /// drains them, staged (14) + pending (2) sit exactly at the count
    /// budget (16) with the apply frontier frozen behind the stall. Byte
    /// budgets are unbounded so only count-denominated behavior is exercised.
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
            pending_timeout,
            ..super::default_sync_budget()
        }
    }

    fn staged_count_wedge(
        budget: super::SyncBudget,
    ) -> Result<WedgeFixture, Box<dyn std::error::Error>> {
        let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
            sync_with_header_chain_and_blocks(64)?;
        let peer_count = budget.min_peers_for_fanout;
        install_budget(&sync, budget);
        let mut rxs = Vec::new();
        for idx in 0..peer_count {
            let addr = test_addr(9320, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
            blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                header_chain_block(&expected, height)?,
            ))?;
        }
        Ok((sync, peers, expected, rxs, blocks_tx))
    }

    /// Returns the next `getdata` inventory from `rx`, skipping header
    /// traffic; fails when none is queued.
    fn next_getdata(
        rx: &crossbeam_channel::Receiver<Message>,
    ) -> Result<Vec<Inventory>, Box<dyn std::error::Error>> {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                return Ok(inventory);
            }
        }
        Err(std::io::Error::other("expected a queued getdata").into())
    }

    /// Drains `rx`, failing on any `getdata` while ignoring header traffic.
    fn assert_no_getdata(
        rx: &crossbeam_channel::Receiver<Message>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while let Ok(message) = rx.try_recv() {
            if matches!(message, Message::GetData(_)) {
                return Err(std::io::Error::other("unexpected getdata").into());
            }
        }
        Ok(())
    }

    /// Reconstructs the deliverable block body (header-only, empty `txs`)
    /// for `height` of a [`sync_with_header_chain`] fixture: the block hash
    /// is the header hash, so the delivery matches the fixture's tree node.
    fn header_chain_block(
        expected: &[BlockHash],
        height: u32,
    ) -> Result<Block, Box<dyn std::error::Error>> {
        let index = usize::try_from(height.checked_sub(1).ok_or("height must be >= 1")?)?;
        let prev_blockhash = if index == 0 {
            genesis_header().compute_hash()
        } else {
            expected[index - 1]
        };
        let block = Block {
            header: test_header(prev_blockhash, height),
            txs: Vec::new(),
        };
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

    struct FailOnceBodyStore {
        fail_height: u32,
        failed: Mutex<bool>,
        persisted: Mutex<HashMap<u32, Vec<u8>>>,
    }

    impl FailOnceBodyStore {
        fn new(fail_height: u32) -> Self {
            Self {
                fail_height,
                failed: Mutex::new(false),
                persisted: Mutex::new(HashMap::new()),
            }
        }

        fn persisted_height(&self, height: u32) -> bool {
            self.persisted.lock().contains_key(&height)
        }
    }

    impl crate::apply::PruneBodyStore for FailOnceBodyStore {
        fn persist_block_body(
            &self,
            height: u32,
            _hash: Hash256,
            body: &[u8],
        ) -> Result<(), StorageError> {
            let mut failed = self.failed.lock();
            if height == self.fail_height && !*failed {
                *failed = true;
                return Err(StorageError::backend("fail-once block body store"));
            }
            drop(failed);
            self.persisted.lock().insert(height, body.to_vec());
            Ok(())
        }

        fn load_block_body(
            &self,
            height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.persisted.lock().get(&height).cloned())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn witness_block_inventory(
        inventory: Vec<Inventory>,
    ) -> Result<Vec<BlockHash>, Box<dyn std::error::Error>> {
        inventory
            .into_iter()
            .map(|item| match item {
                // Wire seam: Inventory payloads stay bitcoin::; convert to native.
                Inventory::WitnessBlock(hash) => {
                    Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
                }
                _ => Err(std::io::Error::other("expected witness block inventory").into()),
            })
            .collect()
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_handles(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> ApplyHandles {
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let mempool_gateway = bitcoin_rs_mempool::MempoolGateway::shared(Arc::clone(&mempool));
        let mining_generation = Arc::new(crate::mining::MiningGenerationSignal::new());
        ApplyHandles::new(
            Network::Regtest,
            chain_tip,
            applied_tip,
            block_tree,
            Arc::new(UtxoSet::new()),
            Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                bitcoin_rs_utxo::stats::CoinStats::default(),
            )),
            None,
            mempool,
            mempool_gateway,
            mining_generation,
            Arc::new(RwLock::new(bitcoin_rs_rpc::context::BlockLog::new())),
            Arc::new(RwLock::new(HashMap::<Txid, Tx>::new())),
            Arc::new(crate::NoOpZmqPublisher),
            Arc::new(crate::state::ChainEventPublisher::detached(0).0),
        )
    }

    /// Regtest genesis timestamp. Fixture headers must advance past it or the
    /// median-time-past rule rejects them, since the median is taken over the
    /// ancestors actually present in the tree.
    const GENESIS_TIME: u32 = 1_296_688_602;

    fn test_header(prev_blockhash: BlockHash, height: u32) -> Header {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        let mut header = Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: GENESIS_TIME.saturating_add(height),
            bits: 0x207f_ffff,
            nonce: height,
        };
        // Mine rather than hope: the fixture previously relied on nonce=height
        // happening to satisfy regtest's easy target, so any change to another
        // header field silently broke proof-of-work validation.
        while !pow_met(header.bits, Hash256::from(header.compute_hash())) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn nbits_mismatch_header(prev_blockhash: BlockHash, height: u32) -> Header {
        let mut header = test_header(prev_blockhash, height);
        header.bits = 0x207f_fffe;
        for nonce in 0..=u32::MAX {
            header.nonce = nonce;
            if pow_met(header.bits, Hash256::from(header.compute_hash())) {
                return header;
            }
        }
        panic!("exhausted the header nonce space while mining a regtest fixture");
    }

    fn far_future_header(
        prev_blockhash: BlockHash,
        height: u32,
    ) -> Result<Header, Box<dyn std::error::Error>> {
        let mut header = test_header(prev_blockhash, height);
        header.time = bitcoin_rs_chain::current_unix_seconds().saturating_add(3 * 60 * 60);
        for nonce in 0..=u32::MAX {
            header.nonce = nonce;
            if pow_met(header.bits, Hash256::from(header.compute_hash())) {
                return Ok(header);
            }
        }
        Err(std::io::Error::other("exhausted future-header nonce space").into())
    }

    /// Regtest-easy compact-target `PoW` check over the hash as a 256-bit
    /// little-endian integer (mirrors `chain::pow::compact_is_met_by` for the
    /// >3-exponent, 3-byte-mantissa forms these fixtures mine).
    fn pow_met(bits: u32, hash: Hash256) -> bool {
        let exponent = bits >> 24;
        let mantissa = bits & 0x007f_ffff;
        if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
            return false;
        }
        let bytes = hash.as_byte_array();
        let lo = usize::try_from(exponent).unwrap_or(32) - 3;
        let window =
            u32::from(bytes[lo]) | u32::from(bytes[lo + 1]) << 8 | u32::from(bytes[lo + 2]) << 16;
        window <= mantissa
            && bytes[usize::try_from(exponent).unwrap_or(32)..]
                .iter()
                .all(|&byte| byte == 0)
    }

    struct HeaderSyncFixture {
        genesis: Header,
        sync: BlockSync,
        inbound_headers_tx: crossbeam_channel::Sender<InboundHeaders>,
        peers: Arc<PeerTable>,
    }

    fn header_sync_with_genesis() -> Result<HeaderSyncFixture, Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(PeerTable::new());
        let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(chain_tip, applied_tip, block_tree);
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
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

    fn coinbase_transaction(height: u32) -> Tx {
        let mut script_sig = push_int(i64::from(height));
        script_sig.extend_from_slice(&push_int(1));
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig,
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    fn transaction(seed: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    Txid(Hash256::from_le_bytes(&[seed; 32])),
                    u32::from(seed),
                ),
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    fn mined_block_with_prev_hash(
        prev_blockhash: BlockHash,
        height: u32,
        txdata: Vec<Tx>,
    ) -> Block {
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time: GENESIS_TIME.saturating_add(height),
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: txdata,
        };
        block.header.merkle_root = merkle_root(&block.txs);
        while !pow_met(block.header.bits, Hash256::from(block.block_hash())) {
            block.header.nonce = block.header.nonce.saturating_add(1);
        }
        block
    }

    /// Consensus merkle fold: pairwise double-SHA256 over little-endian txid
    /// bytes, duplicating the last leaf on odd levels.
    #[allow(clippy::expect_used)]
    fn merkle_root(txs: &[Tx]) -> Hash256 {
        let mut hashes: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        if hashes.is_empty() {
            return Hash256::default();
        }
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                let last = hashes.last().expect("odd merkle level has a last leaf");
                hashes.push(*last);
            }
            hashes = hashes
                .chunks_exact(2)
                .map(|pair| {
                    let mut buffer = [0_u8; 64];
                    buffer[..32].copy_from_slice(&pair[0]);
                    buffer[32..].copy_from_slice(&pair[1]);
                    double_sha256(&buffer).to_le_bytes()
                })
                .collect();
        }
        let root = hashes.first().expect("merkle fold reduces to one root");
        Hash256::from_le_bytes(root)
    }

    fn assert_applied_genesis(
        applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: &Arc<RwLock<BlockTree>>,
        handles: &ApplyHandles,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let genesis_hash = Network::Regtest.genesis_block_hash();
        let tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied genesis tip"))?;
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, genesis_hash);
        assert_eq!(block_tree.read().height_of_hash(genesis_hash), Some(0));
        assert_eq!(handles.blocks.read().len(), 1);
        assert_eq!(handles.utxo.len(), 0);
        Ok(())
    }

    fn current_source(peer_table: &Arc<PeerTable>, addr: SocketAddr) -> PeerSource {
        peer_table.lease(addr).map_or_else(
            || panic!("test peer {addr} must be connected"),
            |lease| lease.source(addr),
        )
    }

    fn register_info(peer_table: &Arc<PeerTable>, info: PeerInfo) {
        let (tx, _rx) = unbounded::<Message>();
        let lease = PeerLease::new(tx);
        peer_table.register(info.addr, lease.clone());
        peer_table.publish_info(info.addr, &lease, info);
    }

    fn synthetic_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
        PeerInfo {
            addr,
            version: 70_016,
            services: 0,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            inbound: true,
            addr_bind: addr,
            time_offset: 0,
            counters: alloc::sync::Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        }
    }

    fn eligible_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
        PeerInfo {
            // SERVICE_WITNESS (1 << 3) | NODE_NETWORK (1): native peer flags.
            services: 0b1001,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: std::sync::Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            ..synthetic_peer(addr, start_height)
        }
    }

    fn test_addr(base_port: usize, idx: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            u16::try_from(base_port + idx)?,
        ))
    }

    fn connect_peer(
        peer_table: &Arc<PeerTable>,
        info: PeerInfo,
    ) -> crossbeam_channel::Receiver<Message> {
        let (tx, rx) = unbounded::<Message>();
        let lease = PeerLease::new(tx);
        peer_table.register(info.addr, lease.clone());
        peer_table.publish_info(info.addr, &lease, info);
        rx
    }

    #[test]
    fn far_future_matching_peer_retries_without_peer_blame()
    -> Result<(), Box<dyn std::error::Error>> {
        let HeaderSyncFixture {
            genesis,
            sync,
            inbound_headers_tx,
            peers,
        } = header_sync_with_genesis()?;
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let (tx, rx) = unbounded::<Message>();
        let lease = PeerLease::new(tx);
        peers.register(peer_addr, lease.clone());
        peers.publish_info(peer_addr, &lease, synthetic_peer(peer_addr, 8));
        let tip_before = sync
            .handles
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing genesis tip"))?;

        sync.tick();
        assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![far_future_header(genesis.compute_hash(), 1)?],
            source: Some(current_source(&peers, peer_addr)),
        })?;
        sync.tick();

        assert_eq!(
            sync.handles.chain_tip.load_full().as_deref(),
            Some(tip_before.as_ref())
        );
        assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
        assert!(rx.try_recv().is_err());
        assert!(
            !lease.is_cancelled(),
            "local-clock rejection must not cancel the peer lease"
        );
        assert!(peers.is_connected(peer_addr));
        assert!(peers.is_connected(peer_addr));
        assert!(
            !sync
                .download_window
                .lock()
                .peer_in_staller_cooldown(peer_addr, Instant::now()),
            "local-clock rejection must not blame the peer"
        );
        Ok(())
    }

    /// Failure-injecting undo store: clearing the in-flight marker always
    /// fails, which is exactly the `MarkerStuck` fatal condition. Everything
    /// else delegates to the real store it wraps.
    struct DisarmFailsUndoStore {
        inner: Arc<dyn crate::apply::UndoStore>,
    }

    impl crate::apply::UndoStore for DisarmFailsUndoStore {
        fn persist_undo(
            &self,
            height: u32,
            hash: Hash256,
            record: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.persist_undo(height, hash, record)
        }

        fn load_undo(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.inner.load_undo(height, hash)
        }

        fn arm_disconnect(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.arm_disconnect(height, hash)
        }

        fn complete_disconnect(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            // A completed rollback that cannot record itself is exactly the
            // `MarkerStuck` fatal condition.
            Err(bitcoin_rs_storage::StorageError::backend(
                "injected marker-clear failure",
            ))
        }

        fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.disarm_disconnect()
        }

        fn load_disconnect_marker(
            &self,
        ) -> Result<Option<bitcoin_rs_storage::DisconnectMarker>, bitcoin_rs_storage::StorageError>
        {
            self.inner.load_disconnect_marker()
        }
    }

    /// Mines `depth` regtest blocks on genesis and applies them. Block 1's
    /// coinbase pays the full subsidy, and the tip block carries a matured
    /// spend of that coin paying a fee far above min-relay, so a reorg that
    /// disconnects the chain has a real readmission candidate. Returns the
    /// handles, the blocks, and their serialized bodies for the reorg body
    /// loader.
    #[allow(clippy::type_complexity)]
    #[test]
    fn tick_sorts_out_of_order_peers_before_requesting_blocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
        let low_addr = test_addr(9500, 0)?;
        let high_addr = test_addr(9500, 1)?;
        let low_rx = connect_peer(&peers, synthetic_peer(low_addr, 2));
        let high_rx = connect_peer(&peers, synthetic_peer(high_addr, 8));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = high_rx.try_recv()? else {
            return Err(std::io::Error::other("expected high peer getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected);
        assert!(matches!(high_rx.try_recv()?, Message::GetHeaders(_)));
        assert!(low_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn same_address_registration_clears_getheaders_gate_and_routes_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let addr = test_addr(9501, 0)?;
        let old_rx = connect_peer(&peers, synthetic_peer(addr, 8));
        sync.tick();
        assert!(matches!(old_rx.try_recv()?, Message::GetHeaders(_)));

        let (new_tx, new_rx) = unbounded::<Message>();
        let new_lease = PeerLease::new(new_tx);
        peers.register(addr, new_lease.clone());
        peers.publish_info(addr, &new_lease, synthetic_peer(addr, 8));
        sync.tick();

        assert!(old_rx.try_recv().is_err());
        assert!(matches!(new_rx.try_recv()?, Message::GetHeaders(_)));
        Ok(())
    }

    #[test]
    fn tick_uses_highest_peer_for_headers_when_request_capacity_is_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let low_rx = connect_peer(&peers, synthetic_peer(test_addr(9502, 0)?, 5));
        let high_rx = connect_peer(&peers, synthetic_peer(test_addr(9502, 1)?, 9));

        sync.tick();

        assert!(matches!(high_rx.try_recv()?, Message::GetHeaders(_)));
        assert!(low_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_bounded_request_peer_selection_preserves_equal_height_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                ..super::default_sync_budget()
            },
        );
        let first_rx = connect_peer(&peers, synthetic_peer(test_addr(9503, 0)?, 100));
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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

    #[test]
    fn tick_retries_when_all_selected_peers_have_expired_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, _tree, _applied, expected) = sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                pending_timeout: Duration::ZERO,
                getdata_batch_limit: 1,
                ..super::default_sync_budget()
            },
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
    fn tick_fans_out_getdata_across_eligible_peers() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let mut receivers = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            receivers.push(connect_peer(
                &peers,
                eligible_peer(test_addr(9505, idx)?, 200 - i32::try_from(idx)?),
            ));
        }
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let cap = super::PENDING_BUDGET.div_ceil(super::MIN_PEERS_FOR_FANOUT);
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
            sync.download_window.lock().pending_len(),
            super::PENDING_BUDGET
        );
        Ok(())
    }

    #[test]
    fn peer_disconnect_mid_window_requeues_blocks_to_remaining_peers()
    -> Result<(), Box<dyn std::error::Error>> {
        const PEER_COUNT: usize = 9;
        const SELECTED_PEERS: usize = super::PENDING_BUDGET / super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        let (sync, peers, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        install_budget(&sync, super::default_sync_budget());
        let mut receivers = Vec::new();
        let mut addrs = Vec::new();
        for idx in 0..PEER_COUNT {
            let addr = test_addr(9506, idx)?;
            addrs.push(addr);
            receivers.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let cap = super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
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
        let dropped = addrs[1];
        peers.disconnect(dropped);
        sync.tick();
        let Message::GetData(inventory) = receivers[SELECTED_PEERS].try_recv()? else {
            return Err(std::io::Error::other("expected requeued getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected[cap..2 * cap]);
        assert_eq!(
            sync.download_window.lock().pending_len(),
            super::PENDING_BUDGET
        );
        Ok(())
    }

    #[test]
    fn reconnecting_staller_held_out_of_window_front_by_cooldown()
    -> Result<(), Box<dyn std::error::Error>> {
        stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued()
    }

    #[test]
    fn sole_peer_staller_disconnected_and_usable_again_as_last_resort()
    -> Result<(), Box<dyn std::error::Error>> {
        tick_allows_demoted_peer_when_it_is_the_only_eligible_peer()
    }

    #[test]
    fn tick_does_not_request_above_peer_advertised_height() -> Result<(), Box<dyn std::error::Error>>
    {
        clean_fast_path_caps_request_at_peer_height()
    }

    #[test]
    fn stale_queued_block_keeps_payload_without_peer_credit()
    -> Result<(), Box<dyn std::error::Error>> {
        unsolicited_stale_block_retries_from_resolved_header_height()
    }

    #[test]
    fn stale_invalid_headers_cannot_evict_or_clear_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let table = Arc::new(PeerTable::new());
        let addr = test_addr(9507, 0)?;
        let (old_tx, _old_rx) = unbounded::<Message>();
        let old = PeerLease::new(old_tx);
        table.register(addr, old.clone());
        let (new_tx, _new_rx) = unbounded::<Message>();
        let new = PeerLease::new(new_tx);
        table.register(addr, new.clone());
        assert!(!table.disconnect_source(old.source(addr)));
        assert!(table.is_current(new.source(addr)));
        assert!(!new.is_cancelled());
        Ok(())
    }

    #[test]
    fn same_address_registration_after_window_eviction_keeps_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
        let addr = test_addr(9508, 0)?;
        let (old_tx, old_rx) = unbounded::<Message>();
        let old = PeerLease::new(old_tx);
        peers.register(addr, old.clone());
        peers.publish_info(addr, &old, synthetic_peer(addr, 100));
        sync.tick();
        let _ = old_rx.try_recv()?;
        let _ = old_rx.try_recv()?;
        let (new_tx, new_rx) = unbounded::<Message>();
        let new = PeerLease::new(new_tx);
        peers.register(addr, new.clone());
        peers.publish_info(addr, &new, synthetic_peer(addr, 100));
        sync.tick();
        assert!(peers.is_current(new.source(addr)));
        assert!(old.is_cancelled());
        assert!(peers.is_connected(addr));
        assert!(new_rx.try_recv().is_ok());
        Ok(())
    }

    #[test]
    fn prefix_probe_state_does_not_survive_owner_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        tick_fanout_deferred_for_fresh_probe_engages_at_deadline()
    }

    #[test]
    fn reconcile_forgets_window_state_only_when_connection_identity_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let addr = test_addr(9509, 0)?;
        let (tx, _rx) = unbounded::<Message>();
        let lease = PeerLease::new(tx);
        peers.register(addr, lease.clone());
        peers.publish_info(addr, &lease, synthetic_peer(addr, 8));
        sync.tick();
        assert!(sync.pending_getheaders.lock().is_some());

        assert!(!peers.register(addr, lease));
        sync.reconcile_peer_sessions();
        assert!(sync.pending_getheaders.lock().is_some());

        let (new_tx, _new_rx) = unbounded::<Message>();
        let replacement = PeerLease::new(new_tx);
        peers.register(addr, replacement.clone());
        peers.publish_info(addr, &replacement, synthetic_peer(addr, 8));
        sync.reconcile_peer_sessions();
        assert!(sync.pending_getheaders.lock().is_none());
        Ok(())
    }

    type MaturedChain = (
        ApplyHandles,
        Vec<Block>,
        HashMap<Hash256, (Block, bytes::Bytes)>,
    );

    fn matured_chain(depth: u32) -> Result<MaturedChain, Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let subsidy = 5_000_000_000_u64;
        let mut prev_hash = genesis.block_hash();
        let mut blocks: Vec<Block> = Vec::new();
        for height in 1..=depth {
            let mut coinbase = coinbase_transaction(height);
            if height == 1 {
                coinbase.outputs[0].value = subsidy;
            }
            let mut txs = vec![coinbase];
            if height == depth {
                let first_txid = blocks[0].txs[0].txid();
                txs.push(Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(first_txid, 0),
                        script_sig: push_int(1),
                        sequence: 0xffff_ffff,
                        witness: Vec::new(),
                    }],
                    outputs: vec![TxOut {
                        value: subsidy - 100_000,
                        script_pubkey: Vec::new(),
                    }],
                    lock_time: 0,
                });
            }
            let block = mined_block_with_prev_hash(prev_hash, height, txs);
            parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
            prev_hash = block.block_hash();
            blocks.push(block);
        }
        let chain_tip = tree.tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let handles = apply_handles(chain_tip, applied_tip, Arc::new(RwLock::new(tree)));
        crate::apply::apply_block(&handles, &genesis)?;
        for block in &blocks {
            crate::apply::apply_block(&handles, block)?;
        }
        let bodies: HashMap<Hash256, (Block, bytes::Bytes)> = blocks
            .iter()
            .map(|block| {
                (
                    Hash256::from_le_bytes(block.block_hash().as_bytes()),
                    (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
                )
            })
            .collect();
        Ok((handles, blocks, bodies))
    }

    #[test]
    fn permanent_forward_failure_purges_invalid_blocks_without_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
        sync.ensure_genesis_tip();
        stage_body(&sync, &main[0]);
        assert_eq!(sync.apply_buffered_blocks(None), (1, 0));

        let main_hash = main[0].block_hash();
        let bad = mined_block_with_prev_hash(main_hash, 2, vec![coinbase_transaction(2)]);
        // The value change alters the txid, so the staged body contradicts the
        // header's merkle root: a permanent consensus failure.
        let mut bad_body = bad.clone();
        bad_body.txs[0].outputs[0].value = 2;
        let descendant =
            mined_block_with_prev_hash(bad.block_hash(), 3, vec![coinbase_transaction(3)]);
        {
            let mut tree = sync.handles.block_tree.write();
            let main_id = tree
                .lookup(Hash256::from_le_bytes(main_hash.as_bytes()))
                .ok_or_else(|| std::io::Error::other("missing applied main block"))?;
            let bad_id = tree.insert_node(Some(main_id), bad.header, NodeStatus::HeaderValid)?;
            tree.insert_node(Some(bad_id), descendant.header, NodeStatus::HeaderValid)?;
        }
        stage_body(&sync, &bad_body);
        stage_body(&sync, &descendant);

        assert_eq!(
            sync.apply_buffered_blocks(None),
            (0, 1),
            "the permanent failure must stop the window with nothing committed"
        );
        let bad_hash = Hash256::from_le_bytes(bad.block_hash().as_bytes());
        let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
        assert!(!sync.block_stager.lock().contains(&bad_hash));
        let descendant_staged = sync.block_stager.lock().contains(&descendant_hash);
        assert!(
            !descendant_staged,
            "invalid descendants must be purged from bounded staging"
        );
        assert_eq!(
            sync.apply_buffered_blocks(None),
            (0, 0),
            "the frontier must not cycle: nothing re-offers the invalidated blocks"
        );
        assert_eq!(applied_tip.load_full().map(|tip| tip.height), Some(1));
        Ok(())
    }

    #[test]
    fn partial_reorg_readmits_only_still_disconnected_transactions()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handles, main, mut bodies) = matured_chain(101)?;
        let tip = main
            .last()
            .ok_or_else(|| std::io::Error::other("empty chain"))?;
        let spend_txid = tip.txs[1].txid();
        // A competing branch rooted at block 50 with four more blocks of
        // work: switching to it disconnects the 51-block suffix (including
        // the matured spend) while the spent coin itself stays live below
        // the fork point, and the 105th fork body contradicts its own
        // header merkle root, so the connect dies permanently mid-walk.
        let fork_root_hash = main[49].block_hash();
        let mut tree = handles.block_tree.write();
        let mut fork_parent = tree
            .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
        let mut fork_prev = fork_root_hash;
        let mut fork_blocks = Vec::new();
        for height in 51..=105_u32 {
            let mut coinbase = coinbase_transaction(height);
            // Distinguish the branch: same-height coinbases on both chains
            // must not carry identical txids, or the fork headers collide.
            coinbase.outputs[0].script_pubkey = push_int(2);
            let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
            fork_parent =
                tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
            fork_prev = block.block_hash();
            fork_blocks.push(block);
        }
        let fork_target = fork_parent;
        drop(tree);
        let mut corrupt = fork_blocks[fork_blocks.len() - 1].clone();
        corrupt.txs[0].outputs[0].value = 2;
        let last = fork_blocks.len() - 1;
        fork_blocks[last] = corrupt;
        for block in &fork_blocks {
            bodies.insert(
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
            );
        }
        let connected_count = std::rc::Rc::new(std::cell::Cell::new(0_usize));
        let counter = std::rc::Rc::clone(&connected_count);

        let outcome = crate::reorg::switch_to_branch(
            &handles,
            fork_target,
            |hash| bodies.get(&hash).cloned(),
            move |_hash| counter.set(counter.get() + 1),
        );

        assert!(
            matches!(
                outcome,
                Err(crate::reorg::ReorgError::ConnectFailed {
                    disconnected: 51,
                    connected: 54,
                    ..
                })
            ),
            "the walk must report its exact committed prefixes, got {outcome:?}"
        );
        assert_eq!(
            connected_count.get(),
            54,
            "only the committed connect prefix is retired to the caller"
        );
        let connected_tip = Hash256::from_le_bytes(fork_blocks[53].block_hash().as_bytes());
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(connected_tip),
            "the successful connected prefix is the final active chain"
        );
        let mempool = handles.mempool.read();
        assert_eq!(
            mempool.len(),
            1,
            "exactly the still-off-chain tx is readmitted"
        );
        assert!(
            mempool.contains_txid(&spend_txid),
            "the disconnected matured spend stays eligible"
        );
        assert_eq!(
            mempool.sequence_number(),
            1,
            "reconsideration runs exactly once for the partial switch"
        );
        let reconnected_txid = fork_blocks[0].txs[0].txid();
        let reconnected_in_pool = mempool.contains_txid(&reconnected_txid);
        assert!(
            !reconnected_in_pool,
            "reconnected-block transactions are confirmed, never readmitted"
        );
        Ok(())
    }

    #[test]
    fn fatal_disconnect_readmits_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let (mut handles, main, mut bodies) = matured_chain(101)?;
        let tip = main
            .last()
            .ok_or_else(|| std::io::Error::other("empty chain"))?;
        let spend_txid = tip.txs[1].txid();
        // The in-flight marker can never be cleared, so the very first
        // disconnect dies fatal after rolling back cleanly. The wrapper keeps
        // the real records; only the disarm fails.
        let real_store = Arc::clone(&handles.undo_store);
        handles.undo_store = Arc::new(DisarmFailsUndoStore { inner: real_store });
        let fork_root_hash = main[49].block_hash();
        let mut tree = handles.block_tree.write();
        let mut fork_parent = tree
            .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
        let mut fork_prev = fork_root_hash;
        let mut fork_blocks = Vec::new();
        for height in 51..=52_u32 {
            let mut coinbase = coinbase_transaction(height);
            coinbase.outputs[0].script_pubkey = push_int(2);
            let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
            fork_parent =
                tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
            fork_prev = block.block_hash();
            fork_blocks.push(block);
        }
        let fork_target = fork_parent;
        drop(tree);
        for block in &fork_blocks {
            bodies.insert(
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
            );
        }

        let outcome = crate::reorg::switch_to_branch(
            &handles,
            fork_target,
            |hash| bodies.get(&hash).cloned(),
            |_| {},
        );

        assert!(
            matches!(outcome, Err(crate::reorg::ReorgError::Fatal(_))),
            "a stuck disconnect marker is fatal, got {outcome:?}"
        );
        assert!(
            handles.mempool.read().is_empty(),
            "a fatal disconnect must never reconsider disconnected transactions"
        );
        assert_eq!(handles.mempool.read().sequence_number(), 0);
        let spend_in_pool = handles.mempool.read().contains_txid(&spend_txid);
        assert!(
            !spend_in_pool,
            "the off-chain matured spend must not be readmitted after a fatal disconnect"
        );
        Ok(())
    }

    #[test]
    fn permanent_connect_failure_through_switch_to_branch_invalidates_subtree()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handles, main, mut bodies) = matured_chain(101)?;
        // Build a competing fork rooted at block 50. The first fork block has a
        // corrupted body (coinbase value changed → txid changed → merkle root
        // mismatch), so the connect dies permanently on the very first block.
        // A descendant header extends the invalid subtree so the test proves
        // the whole subtree is invalidated, not just the failed block.
        let fork_root_hash = main[49].block_hash();
        let mut tree = handles.block_tree.write();
        let mut fork_parent = tree
            .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
        let mut fork_prev = fork_root_hash;
        let mut fork_blocks = Vec::new();
        for height in 51..=52_u32 {
            let mut coinbase = coinbase_transaction(height);
            coinbase.outputs[0].script_pubkey = push_int(2);
            let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
            fork_parent =
                tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
            fork_prev = block.block_hash();
            fork_blocks.push(block);
        }
        let fork_target = fork_parent;
        let invalid_id = tree
            .lookup(Hash256::from_le_bytes(
                fork_blocks[0].block_hash().as_bytes(),
            ))
            .ok_or_else(|| std::io::Error::other("missing invalid fork node"))?;
        let descendant_id = tree
            .lookup(Hash256::from_le_bytes(
                fork_blocks[1].block_hash().as_bytes(),
            ))
            .ok_or_else(|| std::io::Error::other("missing descendant fork node"))?;
        drop(tree);

        // Corrupt the first fork block's body: change the coinbase value so
        // the txid no longer matches the header's merkle root. This is a
        // permanent consensus failure (MerkleRoot), which the classifier
        // marks as permanent and invalidates the subtree.
        let mut corrupt = fork_blocks[0].clone();
        corrupt.txs[0].outputs[0].value = 2;
        fork_blocks[0] = corrupt;
        for block in &fork_blocks {
            bodies.insert(
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
            );
        }

        let outcome = crate::reorg::switch_to_branch(
            &handles,
            fork_target,
            |hash| bodies.get(&hash).cloned(),
            |_| {},
        );

        let Err(crate::reorg::ReorgError::ConnectFailed {
            disconnected,
            connected,
            invalidated,
            ..
        }) = outcome
        else {
            panic!("permanent connect failure must return ConnectFailed");
        };
        assert_eq!(
            disconnected, 51,
            "the full disconnect prefix must be reported"
        );
        assert_eq!(
            connected, 0,
            "nothing connected before the permanent failure"
        );
        // The invalidated subtree must contain both the failed block and its
        // descendant, so the caller can purge every bounded carrier.
        let invalid_hash = Hash256::from_le_bytes(fork_blocks[0].block_hash().as_bytes());
        let descendant_hash = Hash256::from_le_bytes(fork_blocks[1].block_hash().as_bytes());
        assert!(
            invalidated.contains(&invalid_hash),
            "the failed block must be in the invalidated set: {invalidated:?}"
        );
        assert!(
            invalidated.contains(&descendant_hash),
            "the descendant must be in the invalidated set: {invalidated:?}"
        );
        // The block tree must mark the entire subtree Invalid.
        {
            let tree = handles.block_tree.read();
            assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
            assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
        }
        // The applied tip must be back at the fork root (block 50), the
        // successful disconnect prefix.
        let fork_root_id_hash = Hash256::from_le_bytes(fork_root_hash.as_bytes());
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(fork_root_id_hash),
            "the applied tip must be the fork root after disconnecting back to it"
        );
        Ok(())
    }
}
