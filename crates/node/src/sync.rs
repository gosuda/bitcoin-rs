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
mod window;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_p2p::InboundBlock;
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use smallvec::SmallVec;

use self::stage::{BlockStager, DrainedBlock, StagedBlock};
use self::window::{DownloadWindow, SyncBudget};

/// Maximum number of locator entries we ever send.
const LOCATOR_MAX_ENTRIES: usize = 32;
/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;
/// Maximum number of block inventory entries we request per tick.
///
/// Keep the private default at the full pending window so a healthy peer can
/// fill it in one tick; `DownloadWindow` still caps requests by pending bytes,
/// block budget, and per-peer inflight budget.
const GETDATA_BATCH_SIZE: usize = PENDING_BUDGET;
/// Time after which an unanswered `getheaders` request may be retried.
const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Time after which a pending getdata is considered stuck and re-requestable.
const PENDING_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of in-flight getdata requests we'll track per `BlockSync`.
///
/// 256 = two full fan-out waves (8 peers x 16 in-flight): measured on live
/// IBD 0->150k, a window of exactly one wave (128) leaves zero pipelining
/// headroom — the scheduler cannot request wave N+1 while wave N stages, and
/// the download path (~256s of the 359.5s matched-assumption wall) was the
/// binding constraint with apply at only ~103s. Core's window is 1024 for the
/// same reason. Byte budgets and the fallback per-peer cap derive from this
/// and scale with it; `MIN_PEERS_FOR_FANOUT` deliberately does NOT (see its
/// doc).
const PENDING_BUDGET: usize = 256;
/// Time after which a received out-of-order block is discarded.
const RECEIVED_BLOCK_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of received blocks waiting for their predecessor.
const RECEIVED_BLOCK_BUDGET: usize = PENDING_BUDGET;
/// Mainnet-oriented block-size estimate for sizing the in-flight request window.
const PENDING_BLOCK_BYTE_ESTIMATE: usize = 2 * 1024 * 1024;
/// Maximum estimated bytes in the in-flight request window.
const PENDING_BYTE_BUDGET: usize = PENDING_BUDGET * PENDING_BLOCK_BYTE_ESTIMATE;
/// Maximum serialized bytes staged in memory while waiting for predecessors.
///
/// Defined as [`PENDING_BYTE_BUDGET`] so the in-flight and staged byte bounds
/// stay one consistent pair: a full download window (`PENDING_BUDGET` blocks
/// at the high-height `PENDING_BLOCK_BYTE_ESTIMATE`) always fits in staging
/// without eviction. At the 150k acceptance window this bound rarely binds —
/// blocks there are far below the per-slot estimate.
const RECEIVED_BLOCK_BYTE_BUDGET: usize = PENDING_BYTE_BUDGET;
/// Maximum decoded inbound blocks held before handing them to `BlockStager`,
/// sized from the same byte budget that bounds retained staged blocks.
const INBOUND_BLOCK_STAGE_CHUNK: usize =
    at_least_one(RECEIVED_BLOCK_BYTE_BUDGET / PENDING_BLOCK_BYTE_ESTIMATE);
/// Maximum block requests one peer may own at once outside fan-out.
///
/// Keep the fallback per-peer cap equal to the global cap so the bounded
/// scheduler needs only one healthy peer to fill the whole window — this IS
/// the shipped single-peer behavior and stays bit-identical when fewer than
/// [`MIN_PEERS_FOR_FANOUT`] eligible peers exist.
const PEER_INFLIGHT_BUDGET: usize = PENDING_BUDGET;
/// Per-peer in-flight cap while fan-out is active, mirroring Bitcoin Core's
/// `MAX_BLOCKS_IN_TRANSIT_PER_PEER` (16, `net_processing.cpp`). A deep
/// per-peer pipeline under fan-out reproduces the recorded head-of-line
/// collapse; a shallow stripe without the fallback reproduces the early-height
/// under-fill regression — both are pinned in
/// `docs/solutions/architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md`.
const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;
/// Minimum fan-out-eligible peers before block requests fan out. Pinned to
/// the outbound connection budget (`P2P_OUTBOUND_ACTIVE_LIMIT` = 8), NOT
/// derived from the window: when the window deepened past one fan-out wave
/// (`PENDING_BUDGET` 128 -> 256), the old `PENDING_BUDGET / 16` derivation
/// would have demanded 16 eligible peers — above the 8 outbound slots — and
/// silently disabled fan-out forever. Eight eligible peers at cap 16 fill one
/// 128-block wave; the window's extra depth is pipelining headroom, not a
/// reason to demand more peers. The threshold equals the outbound budget,
/// leaving zero slack: a single transient soft-demotion sits exactly at the
/// boundary, which is why engagement carries one-peer hysteresis in
/// [`DownloadWindow::set_fanout_eligible_peers`] instead of being re-derived
/// from the raw count each tick.
const MIN_PEERS_FOR_FANOUT: usize = 8;
// The window is exactly two fan-out waves deep: wave N+1 streams while wave N
// stages (see `PENDING_BUDGET`'s doc for the live-IBD measurement). One tick
// of fan-out fills at most one wave (`MIN_PEERS_FOR_FANOUT *
// MAX_BLOCKS_IN_TRANSIT_PER_PEER` blocks); the second wave is pipelining
// headroom. No runtime test can observe both waves in a single tick, so the
// relationship is pinned here.
const _: () = assert!(PENDING_BUDGET == 2 * MIN_PEERS_FOR_FANOUT * MAX_BLOCKS_IN_TRANSIT_PER_PEER);
/// Initial window-blocked stalling threshold, mirroring Bitcoin Core's
/// `BLOCK_STALLING_TIMEOUT_DEFAULT` (2s, `net_processing.cpp`): when the
/// window front has been in flight to one peer this long with the apply
/// frontier idle and no other download progress possible, that peer is
/// disconnected and its blocks re-queued (R8).
const BLOCK_STALLING_TIMEOUT: Duration = Duration::from_secs(2);
/// Adaptive ceiling for the stalling threshold, mirroring Core's
/// `BLOCK_STALLING_TIMEOUT_MAX` (64s): the threshold doubles per staller
/// disconnect so a sudden bandwidth drop cannot cascade into disconnecting
/// every peer at the 2s floor, and decays by x0.85 per window-front arrival
/// (never snapping back) so the elevation survives a peer rotation.
const BLOCK_STALLING_TIMEOUT_MAX: Duration = Duration::from_secs(64);
/// How long a disconnected staller stays excluded from fan-out eligibility
/// and non-last-resort block requests. Sized to the threshold ceiling: a
/// staller flapping through reconnects can capture the window front at most
/// once per cooldown, and the (window-global) doubled threshold bounds each
/// capture — Core has no equivalent only because its reconnecting peer
/// cannot re-acquire in-flight assignments this cheaply.
const STALLER_COOLDOWN: Duration = BLOCK_STALLING_TIMEOUT_MAX;

// The apply-side cache horizon (`expected_apply_horizon`) stays within the
// inline capacity below only because the staging budget equals the in-flight
// budget; a drift would silently spill every cached run to the heap. The
// byte-budget pair needs no twin assertion: `RECEIVED_BLOCK_BYTE_BUDGET` is
// `PENDING_BYTE_BUDGET` by definition.
const _: () = assert!(PENDING_BUDGET == RECEIVED_BLOCK_BUDGET);

type ExpectedBlockHashes = SmallVec<[Hash256; RECEIVED_BLOCK_BUDGET]>;

const fn at_least_one(value: usize) -> usize {
    if value == 0 { 1 } else { value }
}

/// Block download orchestrator.
pub struct BlockSync {
    handles: crate::apply::ApplyHandles,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
    inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    download_window: Arc<Mutex<DownloadWindow>>,
    block_stager: Arc<Mutex<BlockStager>>,
    pending_getheaders: Arc<Mutex<Option<PendingHeaderRequest>>>,
    expected_apply_cache: Arc<Mutex<Option<ExpectedApplyCache>>>,
}

#[derive(Clone, Copy, Debug)]
struct SyncPeer {
    addr: SocketAddr,
    start_height: i32,
}

#[derive(Clone, Debug, Default)]
struct SyncPeerSelection {
    header_peer: Option<SyncPeer>,
    request_peers: Vec<SyncPeer>,
}

/// A height-eligible sync candidate annotated with its fan-out eligibility
/// (KTD6 predicate, finalized across `statically_fanout_eligible` and the
/// window's soft-demotion check) and with whether the window currently
/// soft-blocks it for block requests (expired pendings or staller cooldown).
#[derive(Clone, Copy, Debug)]
struct FanoutCandidate {
    peer: SyncPeer,
    fanout_eligible: bool,
    soft_blocked: bool,
}

/// Connection-level clauses of the fan-out eligibility predicate (KTD6):
/// outbound and witness-serving (`NODE_WITNESS`), per Bitcoin Core's
/// block-download peer criteria in `net_processing.cpp` (Core requests blocks
/// only from witness peers post-segwit, and inbound peers are
/// attacker-chosen — counting them toward fan-out is the recorded under-fill
/// regression). The height clause lives in the candidate filter and the
/// soft-demotion clause in [`DownloadWindow::peer_has_expired_pending`].
fn statically_fanout_eligible(peer: &PeerInfo) -> bool {
    let witness = bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
    !peer.inbound && peer.services & witness != 0
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
        handles: crate::apply::ApplyHandles,
        peers: Arc<RwLock<Vec<PeerInfo>>>,
        peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
        inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    ) -> Self {
        Self {
            handles,
            peers,
            peer_outbound,
            inbound_headers_rx,
            inbound_blocks_rx,
            download_window: Arc::new(Mutex::new(DownloadWindow::new(default_sync_budget()))),
            block_stager: Arc::new(Mutex::new(BlockStager::new(default_sync_budget()))),
            pending_getheaders: Arc::new(Mutex::new(None)),
            expected_apply_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Runs one orchestrator tick: requests pending blocks from eligible peers
    /// and asks them to extend the header chain.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.ensure_genesis_tip();
        self.drain_inbound_blocks();

        let applied_tip = self.handles.applied_tip.load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let chain_tip = self.handles.chain_tip.load_full();
        let now = Instant::now();
        // Staller detection runs after the apply drain (so it sees real
        // frontier progress) and before peer release + selection, so a fired
        // disconnect re-queues the staller's blocks and re-requests them from
        // healthy peers within the same tick.
        self.disconnect_window_staller(applied_tip.as_deref(), now);
        self.release_disconnected_peer_budget();
        let sync_peer_selection = self.sync_peer_selection(applied_height, now);
        if sync_peer_selection.header_peer.is_none() {
            tracing::trace!(applied_height, "block sync: no peer above current height");
            return;
        }
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
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
        if let Some(peer) = sync_peer_selection.header_peer {
            let peer_best_height = u32::try_from(peer.start_height).unwrap_or(0);
            if peer_best_height > header_height {
                self.send_getheaders(peer.addr, header_height, peer.start_height);
            }
        }
        if sent_getdata {
            self.record_pending_sync_metrics();
        }
    }

    fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        while let Ok(batch) = receiver.try_recv() {
            let batch_len = batch.len();
            total_headers = total_headers.saturating_add(batch_len);
            let mut tree = self.handles.block_tree.write();
            match bitcoin_rs_chain::accept_headers(&mut tree, &batch, self.handles.network) {
                Ok(node_ids) => {
                    tracing::debug!(
                        accepted = node_ids.len(),
                        received = batch_len,
                        "block sync: accepted inbound headers batch",
                    );
                }
                Err(error) => {
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

    fn drain_inbound_blocks(&self) {
        let mut apply_head_check = None;
        let mut next_expected_hash = None;
        let mut blocks = Vec::with_capacity(INBOUND_BLOCK_STAGE_CHUNK);
        let mut received = 0_usize;
        let mut receiver_empty = false;
        let mut saw_block = false;
        while !receiver_empty {
            receiver_empty = self.fill_inbound_block_chunk(
                &mut blocks,
                &mut saw_block,
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
        saw_block: &mut bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        let receiver = self.inbound_blocks_rx.lock();
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(inbound) = receiver.try_recv() else {
                return true;
            };
            if !*saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash.as_ref().copied().filter(|hash| {
                    *hash != Hash256::from_le_bytes(inbound.block.block_hash().as_byte_array())
                });
                *saw_block = true;
            }
            blocks.push(inbound);
        }
        false
    }

    fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        let mut staged_blocks = Vec::with_capacity(blocks.len());
        let now = Instant::now();
        {
            let mut stager = self.block_stager.lock();
            for inbound in blocks.drain(..) {
                let hash = Hash256::from_le_bytes(inbound.block.block_hash().as_byte_array());
                let staged = stager.insert(
                    hash,
                    next_expected_hash,
                    inbound.block,
                    inbound.serialized,
                    now,
                );
                staged_blocks.push((hash, staged));
            }
        }

        let mut retry_count = 0_u64;
        let staged_count = staged_blocks.len();
        {
            let mut window = self.download_window.lock();
            for (hash, staged) in staged_blocks {
                match staged {
                    StagedBlock::AlreadyStaged => {}
                    StagedBlock::Memory { bytes, dropped } => {
                        window.mark_received(hash, bytes, now);
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
        let mut drained = drained.into_iter();
        while let Some(drained_block) = drained.next() {
            match crate::apply::apply_block_with_serialized(
                &self.handles,
                &drained_block.block,
                drained_block.serialized.clone(),
            ) {
                Ok(tip) => {
                    applied = applied.saturating_add(1);
                    tracing::debug!(
                        height = tip.height,
                        %tip.hash,
                        "block sync: applied buffered block"
                    );
                    applied_hashes.push(tip.hash);
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    failed_hash = Some(drained_block.hash);
                    tracing::warn!(
                        %drained_block.hash,
                        %error,
                        "block sync: failed to apply buffered block"
                    );
                    self.block_stager.lock().restore_many(drained);
                    break;
                }
            }
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
        {
            let peers = self.peers.read();
            candidates.reserve(peers.len());
            for peer in peers.iter() {
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
                    fanout_eligible: statically_fanout_eligible(peer),
                    soft_blocked: false,
                });
            }
        }
        let (request_peer_limit, fanout_active) = {
            let mut window = self.download_window.lock();
            for candidate in &mut candidates {
                // Final eligibility clauses (KTD6): not currently soft-demoted
                // for expired pendings, and not inside the staller cooldown.
                // Counting a stalled peer toward fan-out would let one dead
                // peer flip the mode and under-fill the window; counting a
                // just-disconnected staller that reconnected would hand it the
                // window front back (RE-ADV-2).
                candidate.soft_blocked = window.peer_has_expired_pending(candidate.peer.addr, now)
                    || window.peer_in_staller_cooldown(candidate.peer.addr, now);
                candidate.fanout_eligible = candidate.fanout_eligible && !candidate.soft_blocked;
            }
            let eligible = candidates
                .iter()
                .filter(|candidate| candidate.fanout_eligible)
                .count();
            window.set_fanout_eligible_peers(eligible);
            (window.request_peer_scan_limit(now), window.fanout_active())
        };
        let mut request_peers: Vec<SyncPeer> = if fanout_active {
            // Fan-out: only eligible peers receive block requests; ineligible
            // (inbound / non-witness / behind / demoted) peers neither count
            // toward the threshold nor get getdata.
            candidates
                .iter()
                .filter(|candidate| candidate.fanout_eligible)
                .map(|candidate| candidate.peer)
                .collect()
        } else if request_peer_limit > 1 {
            // Fallback, multi-scan: the pre-fan-out shipped behavior — any
            // candidate may serve (an inbound-only node must still sync).
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
        }
    }

    fn send_getdata_for_pending_blocks(
        &self,
        sync_peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
    ) -> GetdataRequestOutcome {
        let applied_height = applied_tip.height;
        if chain_tip.height <= applied_height {
            return GetdataRequestOutcome::default();
        }

        let now = Instant::now();
        let tree = self.handles.block_tree.read();
        let request = self.download_window.lock().next_peer_request(
            sync_peer_addr,
            allow_expired_retry_from_peer,
            chain_tip,
            applied_tip,
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
            inventory.push(Inventory::WitnessBlock(BlockHash::from_byte_array(
                hash.to_le_bytes(),
            )));
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
        let msg = NetworkMessage::GetData(inventory);

        let tx = {
            let outbound = self.peer_outbound.read();
            outbound.get(&request.peer_addr()).cloned()
        };
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
        let has_request_capacity = self.download_window.lock().mark_requested(&request, now);
        metrics::histogram!("node.sync.getdata_batch_size").record(metric_count(count));
        tracing::debug!(
            peer_addr = %request.peer_addr(),
            count,
            applied_height,
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
        if self.has_pending_getheaders(sync_peer_addr, locator_tip_hash, target_height, now) {
            tracing::trace!(
                peer_addr = %sync_peer_addr,
                our_height,
                target_height,
                "block sync: getheaders already pending",
            );
            return;
        }
        let locator_hashes: Vec<BlockHash> = locator
            .into_iter()
            .map(|hash| BlockHash::from_byte_array(hash.to_le_bytes()))
            .collect();
        let msg = NetworkMessage::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            BlockHash::all_zeros(),
        ));
        let tx = {
            let outbound = self.peer_outbound.read();
            outbound.get(&sync_peer_addr).cloned()
        };
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
        let genesis =
            bitcoin::blockdata::constants::genesis_block(bitcoin_network(self.handles.network));
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

    fn release_disconnected_peer_budget(&self) {
        let outbound = self.peer_outbound.read();
        self.download_window
            .lock()
            .release_disconnected_peers(|peer| outbound.contains_key(peer));
    }

    /// R8: window-blocked staller detection and disconnect.
    ///
    /// Computes the sync-layer terms of the stall predicate and advances the
    /// window's stall state machine ([`DownloadWindow::observe_stall`] holds
    /// the predicate itself):
    /// - the no-blame guard: while the stager holds the next expected block
    ///   the apply side owns the frontier, so the stall clock must not run —
    ///   no peer is blamed for our own apply lag or a failed-apply restore.
    ///
    /// There is deliberately no chain-tail arm: a caught-up peer taking >2s
    /// on one tip block is the normal tip regime, where Core's stalling
    /// logic does not engage; the last <window blocks of IBD fall back to
    /// the pre-existing 60s pending-timeout machinery instead.
    ///
    /// On fire the peer's outbound entry is removed. That entry is the
    /// connection's lease: the p2p message loop observes the removal within
    /// its 1s read-timeout poll and tears the connection down (thread exit
    /// also clears the peer registry), and the same removal makes
    /// [`Self::release_disconnected_peer_budget`] — which runs right after in
    /// the tick — re-queue the staller's in-flight blocks for healthy peers.
    /// Re-acquisition by an immediately-reconnecting staller is held off by
    /// the window's staller cooldown (fan-out ineligible, no requests except
    /// as last resort). Core-faithfully this fires regardless of how many
    /// peers remain: a stalled-forever peer is worse than no peer, the
    /// re-queue is what frees the wedge, and a reconnecting sole peer is
    /// still usable through the last-resort exemption.
    ///
    /// Net-layer boundary, stated honestly: this node has no autonomous peer
    /// rotation. `--connect` peers are re-dialed every 2s by the fixed-peer
    /// bootstrap, so a disconnected sole staller reconnects promptly; under
    /// DNS bootstrap (one-shot at startup) a disconnect is not followed by a
    /// replacement dial, and sync waits for an inbound peer or the staller's
    /// own reconnect. Reconnect handling itself lives in the p2p layer, out
    /// of reach here — the cooldown keys on the socket address, stable for
    /// outbound dials but rotating with the ephemeral port for inbound peers
    /// (inbound peers are never fan-out eligible, so that exposure is limited
    /// to the fallback last-resort path Core shares).
    fn disconnect_window_staller(&self, applied_tip: Option<&TipSnapshot>, now: Instant) {
        let Some(applied_tip) = applied_tip else {
            return;
        };
        let Some(next_apply_height) = applied_tip.height.checked_add(1) else {
            return;
        };
        let apply_side_busy = self
            .next_expected_block_hash()
            .is_some_and(|hash| self.block_stager.lock().contains(&hash));
        let fired = {
            let mut window = self.download_window.lock();
            let fired = window.observe_stall(next_apply_height, apply_side_busy, now);
            let stall_seconds = window
                .stalling_peer()
                .map_or(0.0, |(_, since)| now.duration_since(since).as_secs_f64());
            metrics::gauge!("node.sync.stall_seconds").set(stall_seconds);
            fired
        };
        let Some(peer_addr) = fired else {
            return;
        };
        self.peer_outbound.write().remove(&peer_addr);
        metrics::counter!("node.sync.staller_disconnects").increment(1);
        tracing::warn!(
            peer_addr = %peer_addr,
            next_apply_height,
            "block sync: peer is stalling the download window; disconnecting and re-queueing its blocks"
        );
    }

    fn record_sync_metrics(&self) {
        let window = self.download_window.lock();
        let stager = self.block_stager.lock();
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
        metrics::gauge!("node.sync.received_blocks").set(metric_count(stager.received_len()));
        metrics::gauge!("node.sync.received_bytes").set(metric_count(stager.received_bytes()));
    }

    fn record_pending_sync_metrics(&self) {
        let window = self.download_window.lock();
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
    }
}

fn bitcoin_network(network: bitcoin_rs_primitives::Network) -> bitcoin::Network {
    match network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    }
}

fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

const fn default_sync_budget() -> SyncBudget {
    SyncBudget {
        max_pending_blocks: PENDING_BUDGET,
        max_pending_bytes: PENDING_BYTE_BUDGET,
        max_received_blocks: RECEIVED_BLOCK_BUDGET,
        max_received_bytes: RECEIVED_BLOCK_BYTE_BUDGET,
        max_peer_inflight: PEER_INFLIGHT_BUDGET,
        fanout_peer_inflight: MAX_BLOCKS_IN_TRANSIT_PER_PEER,
        min_peers_for_fanout: MIN_PEERS_FOR_FANOUT,
        getdata_batch_limit: GETDATA_BATCH_SIZE,
        pending_timeout: PENDING_TIMEOUT,
        received_timeout: RECEIVED_BLOCK_TIMEOUT,
        stall_timeout_initial: BLOCK_STALLING_TIMEOUT,
        stall_timeout_max: BLOCK_STALLING_TIMEOUT_MAX,
        staller_cooldown: STALLER_COOLDOWN,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
        block::{Header as BlockHeader, Version},
        pow::CompactTarget,
        script::Builder,
    };
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
    use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
    use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_p2p::PeerInfo;
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_storage::StorageError;
    use bitcoin_rs_utxo::UtxoSet;
    use crossbeam_channel::unbounded;
    use hashbrown::HashMap;
    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
        Recorder, SharedString, Unit,
    };
    use parking_lot::{Mutex, RwLock};

    use super::{BlockHash, BlockSync, Inventory, Message, NetworkMessage};
    use crate::{Network, apply::ApplyHandles};

    #[test]
    fn tick_sends_getdata_for_headers_above_applied_tip() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut expected = Vec::new();

        for height in 1_u32..=3 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            expected.push(BlockHash::from_byte_array(
                tree.node(tip_id)?.hash.to_le_bytes(),
            ));
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(inventory.len(), 3);
        let requested = inventory
            .into_iter()
            .map(|item| match item {
                Inventory::WitnessBlock(hash) => Ok(hash),
                _ => Err(std::io::Error::other("expected witness block inventory")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(requested, expected);

        let second = rx.try_recv()?;
        if !matches!(second, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders").into());
        }
        Ok(())
    }

    #[test]
    fn tick_skips_getheaders_when_header_tip_matches_peer_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(3)?;
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
        peers.write().push(synthetic_peer(addr, 3));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        let first = rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected[1..]);
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_sorts_out_of_order_peers_before_requesting_blocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(3)?;
        let low_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let high_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers
            .write()
            .extend([synthetic_peer(low_addr, 2), synthetic_peer(high_addr, 8)]);
        let (low_tx, low_rx) = unbounded::<Message>();
        let (high_tx, high_rx) = unbounded::<Message>();
        peer_outbound
            .write()
            .extend([(low_addr, low_tx), (high_addr, high_tx)]);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = high_rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected high peer getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected);
        let second = high_rx.try_recv()?;
        if !matches!(second, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected high peer getheaders").into());
        }
        assert!(low_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_does_not_resend_same_getheaders_while_pending() -> Result<(), Box<dyn std::error::Error>>
    {
        let (sync, peers, peer_outbound, _block_tree, _applied_tip, _expected) =
            sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 8));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();
        let first = rx.try_recv()?;
        if !matches!(first, NetworkMessage::GetHeaders(_)) {
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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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
        peers.write().push(synthetic_peer(addr, 8));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();
        let first = rx.try_recv()?;
        if !matches!(first, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first getheaders").into());
        }

        let header = test_header(genesis.block_hash(), 1);
        inbound_headers_tx.send(vec![header])?;
        sync.tick();
        let second = rx.try_recv()?;
        if !matches!(second, NetworkMessage::GetHeaders(_)) {
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
    fn stale_inbound_headers_keep_getheaders_gate_pending() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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
        peers.write().push(synthetic_peer(addr, 8));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();
        let first = rx.try_recv()?;
        if !matches!(first, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first getheaders").into());
        }

        // An orphan header from any peer that does not connect to our tip must
        // not advance the header chain, so the gate stays pending and no
        // duplicate getheaders is sent before the request times out.
        let orphan_prev = BlockHash::from_byte_array([0x11; 32]);
        let orphan = test_header(orphan_prev, 5);
        inbound_headers_tx.send(vec![orphan])?;
        sync.tick();
        assert!(
            rx.try_recv().is_err(),
            "stale inbound headers must not release the getheaders gate"
        );
        let tip = chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing header tip"))?;
        assert_eq!(tip.tip_id, genesis_id, "orphan header must not advance tip");
        Ok(())
    }

    #[test]
    fn tick_uses_highest_peer_for_headers_when_request_capacity_is_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, _block_tree, _applied_tip, _expected) =
            sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 0,
                ..super::default_sync_budget()
            },
        );
        let low_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let high_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers
            .write()
            .extend([synthetic_peer(low_addr, 4), synthetic_peer(high_addr, 8)]);
        let (low_tx, low_rx) = unbounded::<Message>();
        let (high_tx, high_rx) = unbounded::<Message>();
        peer_outbound
            .write()
            .extend([(low_addr, low_tx), (high_addr, high_tx)]);

        sync.tick();

        let headers = high_rx.try_recv()?;
        if !matches!(headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected high peer getheaders").into());
        }
        assert!(high_rx.try_recv().is_err());
        assert!(low_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_bounded_request_peer_selection_preserves_equal_height_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        // Equal heights above the deep chain tip: both peers can serve the
        // full window (and headers past it), so list order alone decides.
        let equal_height = i32::try_from(super::PENDING_BUDGET)? + 100;
        peers.write().extend([
            synthetic_peer(first_addr, equal_height),
            synthetic_peer(second_addr, equal_height),
        ]);
        let (first_tx, first_rx) = unbounded::<Message>();
        let (second_tx, second_rx) = unbounded::<Message>();
        peer_outbound
            .write()
            .extend([(first_addr, first_tx), (second_addr, second_tx)]);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = first_rx.try_recv()? else {
            return Err(std::io::Error::other("expected first peer getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected);
        let headers = first_rx.try_recv()?;
        if !matches!(headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first peer getheaders").into());
        }
        assert!(first_rx.try_recv().is_err());
        assert!(second_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_bounded_request_peer_selection_skips_inflight_saturated_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(8)?;
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
        peers.write().push(synthetic_peer(first_addr, 100));
        let (first_tx, first_rx) = unbounded::<Message>();
        peer_outbound.write().insert(first_addr, first_tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first_inventory) = first_rx.try_recv()? else {
            return Err(std::io::Error::other("expected first peer getdata").into());
        };
        assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
        let first_headers = first_rx.try_recv()?;
        if !matches!(first_headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first peer getheaders").into());
        }

        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers.write().push(synthetic_peer(second_addr, 100));
        let (second_tx, second_rx) = unbounded::<Message>();
        peer_outbound.write().insert(second_addr, second_tx);

        sync.tick();

        let NetworkMessage::GetData(second_inventory) = second_rx.try_recv()? else {
            return Err(std::io::Error::other("expected second peer getdata").into());
        };
        assert_eq!(witness_block_inventory(second_inventory)?, expected[2..4]);
        assert!(second_rx.try_recv().is_err());
        // The in-flight getheaders gate suppresses a duplicate header request to
        // the original sync peer, so it receives no further messages.
        assert!(first_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(4)?;
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
        peers.write().push(synthetic_peer(stale_addr, 100));
        let (stale_tx, stale_rx) = unbounded::<Message>();
        peer_outbound.write().insert(stale_addr, stale_tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first_inventory) = stale_rx.try_recv()? else {
            return Err(std::io::Error::other("expected stale peer getdata").into());
        };
        assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
        let stale_headers = stale_rx.try_recv()?;
        if !matches!(stale_headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected stale peer getheaders").into());
        }

        peers.write().push(synthetic_peer(healthy_addr, 100));
        let (healthy_tx, healthy_rx) = unbounded::<Message>();
        peer_outbound.write().insert(healthy_addr, healthy_tx);

        sync.tick();

        let NetworkMessage::GetData(retry_inventory) = healthy_rx.try_recv()? else {
            return Err(std::io::Error::other("expected healthy peer retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
        assert!(healthy_rx.try_recv().is_err());
        while let Ok(message) = stale_rx.try_recv() {
            if matches!(message, NetworkMessage::GetData(_)) {
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
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(4)?;
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first_inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
        let headers = rx.try_recv()?;
        if !matches!(headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders").into());
        }

        sync.tick();

        let NetworkMessage::GetData(retry_inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
        Ok(())
    }

    #[test]
    fn tick_retries_when_all_selected_peers_have_expired_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(6)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                pending_timeout: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers.write().extend([
            synthetic_peer(first_addr, 100),
            synthetic_peer(second_addr, 100),
        ]);
        let (first_tx, first_rx) = unbounded::<Message>();
        let (second_tx, second_rx) = unbounded::<Message>();
        peer_outbound
            .write()
            .extend([(first_addr, first_tx), (second_addr, second_tx)]);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first_inventory) = first_rx.try_recv()? else {
            return Err(std::io::Error::other("expected first peer getdata").into());
        };
        assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
        let first_headers = first_rx.try_recv()?;
        if !matches!(first_headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first peer getheaders").into());
        }
        let NetworkMessage::GetData(second_inventory) = second_rx.try_recv()? else {
            return Err(std::io::Error::other("expected second peer getdata").into());
        };
        assert_eq!(witness_block_inventory(second_inventory)?, expected[2..4]);
        assert!(second_rx.try_recv().is_err());

        std::thread::sleep(Duration::from_millis(125));
        sync.tick();

        while let Ok(message) = first_rx.try_recv() {
            if matches!(message, NetworkMessage::GetData(_)) {
                return Err(
                    std::io::Error::other("first peer should not receive retry getdata").into(),
                );
            }
        }
        let NetworkMessage::GetData(retry_inventory) = second_rx.try_recv()? else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        let retry_hashes = witness_block_inventory(retry_inventory)?;
        assert_eq!(retry_hashes.len(), 2);
        assert!(retry_hashes.iter().all(|hash| expected[..4].contains(hash)));
        assert!(second_rx.try_recv().is_err());
        assert_eq!(sync.download_window.lock().pending_len(), 2);
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
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            if height <= batch_size {
                expected.push(BlockHash::from_byte_array(
                    tree.node(tip_id)?.hash.to_le_bytes(),
                ));
            }
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        let requested = inventory
            .into_iter()
            .map(|item| match item {
                Inventory::WitnessBlock(hash) => Ok(hash),
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
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        if !matches!(first, NetworkMessage::GetData(_)) {
            return Err(std::io::Error::other("expected first tick getdata").into());
        }
        let second = rx.try_recv()?;
        if !matches!(second, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected first tick getheaders").into());
        }

        sync.tick();

        // The in-flight getheaders gate suppresses a duplicate header request,
        // and already-pending blocks are not re-requested, so the second tick
        // emits no outbound messages.
        match rx.try_recv() {
            Ok(NetworkMessage::GetData(_)) => {
                Err(std::io::Error::other("second tick re-requested pending blocks").into())
            }
            Ok(NetworkMessage::GetHeaders(_)) => {
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
    fn missing_outbound_channel_does_not_mark_blocks_pending_and_retries_when_channel_appears()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(3)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        assert_eq!(sync.download_window.lock().pending_len(), 0);

        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        let first = rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        let requested = witness_block_inventory(inventory)?;
        assert_eq!(requested, expected);
        assert_eq!(sync.download_window.lock().pending_len(), expected.len());
        Ok(())
    }

    #[test]
    fn disconnected_outbound_channel_does_not_mark_blocks_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, _expected) =
            sync_with_header_chain(3)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        drop(rx);
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        assert_eq!(sync.download_window.lock().pending_len(), 0);
        Ok(())
    }

    #[test]
    fn successful_getdata_send_marks_requested_blocks_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(3)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let first = rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected);

        let window = sync.download_window.lock();
        assert_eq!(window.pending_len(), expected.len());
        for hash in expected {
            let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&hash.to_byte_array());
            assert!(window.contains_pending(&hash));
        }
        Ok(())
    }

    #[test]
    fn drain_inbound_blocks_prunes_stale_received_blocks_without_new_arrivals()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, _peers, _peer_outbound, _block_tree, _applied_tip, _expected) =
            sync_with_header_chain(1)?;
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let received_at = Instant::now()
            .checked_sub(super::RECEIVED_BLOCK_TIMEOUT + Duration::from_secs(1))
            .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
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
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(initial) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial getdata").into());
        };
        assert_eq!(
            witness_block_inventory(initial)?,
            alloc::vec![block1_hash, expected_hash]
        );
        let _headers = rx.try_recv()?;
        {
            let mut window = sync.download_window.lock();
            window.mark_applied(&Hash256::from_le_bytes(block1_hash.as_byte_array()));
            window.mark_applied(&Hash256::from_le_bytes(expected_hash.as_byte_array()));
        }

        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
        sync.drain_inbound_blocks();

        assert_eq!(sync.block_stager.lock().received_len(), 0);
        assert_eq!(sync.download_window.lock().received_len(), 0);

        sync.tick();

        let NetworkMessage::GetData(retry) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected height-2 retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
        Ok(())
    }

    #[test]
    fn tick_respects_pending_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, _expected) =
            sync_with_header_chain(3)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_bytes: 256 * 1024,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(inventory.len(), 1);
        assert_eq!(sync.download_window.lock().pending_len(), 1);
        Ok(())
    }

    #[test]
    fn tick_limits_inflight_per_peer() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, _expected) =
            sync_with_header_chain(5)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_peer_inflight: 2,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
    fn tick_fans_out_getdata_across_eligible_peers() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(8)?;
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
        let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers.write().extend([
            synthetic_peer(first_addr, 100),
            synthetic_peer(second_addr, 100),
        ]);
        let (first_tx, first_rx) = unbounded::<Message>();
        let (second_tx, second_rx) = unbounded::<Message>();
        peer_outbound
            .write()
            .extend([(first_addr, first_tx), (second_addr, second_tx)]);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first_inventory) = first_rx.try_recv()? else {
            return Err(std::io::Error::other("expected first peer getdata").into());
        };
        let first_requested = witness_block_inventory(first_inventory)?;
        let _first_headers = first_rx.try_recv()?;
        let NetworkMessage::GetData(second_inventory) = second_rx.try_recv()? else {
            return Err(std::io::Error::other("expected second peer getdata").into());
        };
        let second_requested = witness_block_inventory(second_inventory)?;

        assert_eq!(first_requested, expected[..2]);
        assert_eq!(second_requested, expected[2..4]);
        assert!(second_rx.try_recv().is_err());
        assert_eq!(sync.download_window.lock().pending_len(), 4);
        Ok(())
    }

    #[test]
    fn tick_fanout_distributes_window_front_first_across_eligible_peers()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let mut rxs = Vec::new();
        // Heights above the deep chain tip: every peer can serve any window
        // height (and the highest can serve headers past the tip).
        let peer_height_base = i32::try_from(super::PENDING_BUDGET)? + 100;
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9001, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, peer_height_base - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let cap = super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        for (idx, rx) in rxs.iter().enumerate() {
            let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
                if !matches!(rx.try_recv()?, NetworkMessage::GetHeaders(_)) {
                    return Err(std::io::Error::other("expected getheaders for header peer").into());
                }
            }
            assert!(rx.try_recv().is_err(), "no peer may exceed the fan-out cap");
        }
        assert_eq!(
            sync.download_window.lock().pending_len(),
            super::MIN_PEERS_FOR_FANOUT * super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
            "one fan-out wave fills exactly half the two-wave window; the \
             remaining depth is pipelining headroom for the next wave"
        );
        Ok(())
    }

    /// Verifies the "two-wave pipeline" behaviour that the compile-time assert
    /// (`PENDING_BUDGET == 2 * MIN_PEERS_FOR_FANOUT * MAX_BLOCKS_IN_TRANSIT_PER_PEER`)
    /// encodes structurally but cannot prove dynamically: after tick 1 fills
    /// wave N (128 in-flight blocks) and those blocks are received/staged,
    /// tick 2 issues wave N+1 (another 128 in-flight) while wave N remains in
    /// `window.received` — both waves simultaneously active, totalling
    /// `PENDING_BUDGET` blocks in the pipeline.
    ///
    /// Refutes the source comment "No runtime test can observe both waves in a
    /// single tick": two ticks suffice.
    #[test]
    fn two_tick_fanout_pipeline_issues_wave2_while_wave1_staged()
    -> Result<(), Box<dyn std::error::Error>> {
        let wave_size = super::MIN_PEERS_FOR_FANOUT * super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        let chain_len = u32::try_from(super::PENDING_BUDGET * 2 + 4)?;
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(chain_len)?;
        let peer_height = i32::try_from(super::PENDING_BUDGET * 2 + 100)?;
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9700, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, peer_height - i32::try_from(idx)?),
            ));
        }

        // Tick 1: wave N issues (MIN_PEERS_FOR_FANOUT × MAX_BLOCKS_IN_TRANSIT_PER_PEER
        // = half of PENDING_BUDGET blocks distributed across the eligible peers).
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        assert_eq!(
            sync.download_window.lock().pending_len(),
            wave_size,
            "tick 1: exactly one fan-out wave in-flight, window has headroom for wave N+1"
        );

        // Drain wave-N getdatas from peer channels so tick-2 output is clean.
        for rx in &rxs {
            while let Ok(msg) = rx.try_recv() {
                if matches!(msg, NetworkMessage::GetData(_)) {
                    break;
                }
            }
        }

        // Simulate wave-N block arrivals via window.mark_received: removes each
        // block from pending and decrements per-peer inflight (freeing capacity
        // for wave N+1), while adding it to window.received (the "staged but not
        // yet applied" accounting layer).  The block stager is intentionally left
        // empty so drain_inbound_blocks returns early in tick 2 and does not
        // apply — wave N stays staged.
        let now = Instant::now();
        {
            let mut window = sync.download_window.lock();
            for bh in &expected[..wave_size] {
                window.mark_received(
                    Hash256::from_le_bytes(bh.as_byte_array()),
                    80, // representative byte count; well within the staging budget
                    now,
                );
            }
        }
        assert_eq!(
            sync.download_window.lock().pending_len(),
            0,
            "wave N moved out of pending after arrivals"
        );
        assert_eq!(
            sync.download_window.lock().received_len(),
            wave_size,
            "wave N blocks staged in window.received (not yet applied)"
        );

        // Tick 2: drain_inbound_blocks returns early (block stager empty), then
        // the scheduler sees per-peer inflight cleared and issues wave N+1 into
        // the window's remaining headroom.
        sync.tick();

        // Both waves are simultaneously active: wave N in received (staged),
        // wave N+1 in pending (in-flight) — the two-wave pipeline is live.
        {
            let window = sync.download_window.lock();
            assert_eq!(
                window.pending_len(),
                wave_size,
                "tick 2: wave N+1 now in-flight"
            );
            assert_eq!(
                window.received_len(),
                wave_size,
                "wave N still staged while wave N+1 issues — two-wave pipeline confirmed"
            );
        }

        // Assert each peer received exactly one wave-N+1 getdata stripe.
        let cap = super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        for (idx, rx) in rxs.iter().enumerate() {
            let wave2_inventory = next_getdata(rx)?;
            let got = witness_block_inventory(wave2_inventory)?;
            assert_eq!(
                got,
                expected[wave_size + idx * cap..wave_size + (idx + 1) * cap],
                "peer {idx}: wave N+1 stripe must be the next {cap} in-order blocks"
            );
        }
        Ok(())
    }

    #[test]
    fn tick_falls_back_to_single_deep_peer_below_fanout_threshold()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let mut rxs = Vec::new();
        // Heights above the deep chain tip so the highest peer can serve the
        // entire window in one batch.
        let peer_height_base = i32::try_from(super::PENDING_BUDGET)? + 100;
        for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
            let addr = test_addr(9021, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, peer_height_base - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rxs[0].try_recv()? else {
            return Err(std::io::Error::other("expected deep getdata for highest peer").into());
        };
        // Below the threshold the shipped single-peer behavior holds: the
        // highest peer fills the entire deep window in one batch (no
        // under-fill regression).
        assert_eq!(witness_block_inventory(inventory)?, expected);
        for rx in &rxs[1..] {
            assert!(rx.try_recv().is_err());
        }
        assert_eq!(
            sync.download_window.lock().pending_len(),
            super::PENDING_BUDGET
        );
        Ok(())
    }

    #[test]
    fn inbound_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
    {
        let ineligible = PeerInfo {
            inbound: true,
            // Highest candidate by a margin over the helper's eligible peers,
            // so the fallback must pick it.
            ..eligible_peer(
                test_addr(9200, 0)?,
                i32::try_from(super::PENDING_BUDGET)? + 300,
            )
        };
        assert_fallback_with_ineligible_candidate(ineligible, true)
    }

    #[test]
    fn non_witness_peer_not_counted_toward_fanout_threshold()
    -> Result<(), Box<dyn std::error::Error>> {
        let ineligible = PeerInfo {
            // NODE_NETWORK only — no NODE_WITNESS.
            services: 1,
            // Highest candidate by a margin over the helper's eligible peers,
            // so the fallback must pick it.
            ..eligible_peer(
                test_addr(9210, 0)?,
                i32::try_from(super::PENDING_BUDGET)? + 300,
            )
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
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let ineligible_rx = connect_peer(&peers, &peer_outbound, ineligible);
        let mut rxs = Vec::new();
        // Heights above the deep chain tip (but below the `serves_fallback`
        // ineligible candidate) so whichever peer wins the fallback can serve
        // the entire window in one batch.
        let peer_height_base = i32::try_from(super::PENDING_BUDGET)? + 100;
        for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
            let addr = test_addr(9230, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, peer_height_base - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let deep_rx = if serves_fallback {
            &ineligible_rx
        } else {
            &rxs[0]
        };
        let NetworkMessage::GetData(inventory) = deep_rx.try_recv()? else {
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
            assert!(rx.try_recv().is_err(), "fallback is single-peer");
        }
        Ok(())
    }

    #[test]
    fn demoted_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
    {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
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
        let demoted_rx = connect_peer(
            &peers,
            &peer_outbound,
            eligible_peer(test_addr(9240, 0)?, 300),
        );
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(initial) = demoted_rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial deep getdata").into());
        };
        assert_eq!(initial.len(), super::PENDING_BUDGET);
        if !matches!(demoted_rx.try_recv()?, NetworkMessage::GetHeaders(_)) {
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
                &peer_outbound,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }
        sync.tick();

        let NetworkMessage::GetData(retry) = rxs[0].try_recv()? else {
            return Err(std::io::Error::other("expected deep retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry)?, expected);
        assert!(
            demoted_rx.try_recv().is_err(),
            "demoted peer must receive no new block requests"
        );
        for rx in &rxs[1..] {
            assert!(rx.try_recv().is_err());
        }
        Ok(())
    }

    #[test]
    fn ineligible_peers_receive_no_block_requests_during_fanout()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
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
        let demoted_rx = connect_peer(
            &peers,
            &peer_outbound,
            eligible_peer(test_addr(9250, 0)?, 290),
        );
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(initial) = demoted_rx.try_recv()? else {
            return Err(std::io::Error::other("expected initial deep getdata").into());
        };
        assert_eq!(initial.len(), super::PENDING_BUDGET);
        if !matches!(demoted_rx.try_recv()?, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders for lone peer").into());
        }

        // One ineligible candidate per predicate clause, all at heights that
        // would make them the most attractive picks were they eligible.
        let inbound_rx = connect_peer(
            &peers,
            &peer_outbound,
            PeerInfo {
                inbound: true,
                ..eligible_peer(test_addr(9251, 0)?, 310)
            },
        );
        let non_witness_rx = connect_peer(
            &peers,
            &peer_outbound,
            PeerInfo {
                services: 1,
                ..eligible_peer(test_addr(9252, 0)?, 305)
            },
        );
        let low_chain_rx = connect_peer(
            &peers,
            &peer_outbound,
            eligible_peer(test_addr(9253, 0)?, 0),
        );
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9254, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        // Let the lone peer's pendings expire (demoting it) before fanning out.
        std::thread::sleep(Duration::from_millis(300));
        sync.tick();

        let cap = super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        for (idx, rx) in rxs.iter().enumerate() {
            let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        if !matches!(inbound_rx.try_recv()?, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected getheaders to header peer").into());
        }
        assert!(inbound_rx.try_recv().is_err());
        assert!(non_witness_rx.try_recv().is_err());
        assert!(low_chain_rx.try_recv().is_err());
        assert!(demoted_rx.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn peer_disconnect_mid_window_requeues_blocks_to_remaining_peers()
    -> Result<(), Box<dyn std::error::Error>> {
        // Requeue-on-disconnect is geometry-independent, so pin it at a
        // one-wave window: under the production two-wave window the
        // request-peer scan width (pending capacity / fan-out cap) exceeds
        // `MIN_PEERS_FOR_FANOUT + 1`, leaving no peer spare on the first tick.
        let window = super::MIN_PEERS_FOR_FANOUT * super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(window)?)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: window,
                ..super::default_sync_budget()
            },
        );
        let peer_height_base = i32::try_from(window)? + 100;
        let mut rxs = Vec::new();
        let mut addrs = Vec::new();
        // One spare peer beyond the one-wave fan-out scan width: it gets
        // nothing on the first tick and picks up the re-queued blocks on the
        // second.
        for idx in 0..=super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9261, idx)?;
            addrs.push(addr);
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, peer_height_base - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let cap = super::MAX_BLOCKS_IN_TRANSIT_PER_PEER;
        for (idx, rx) in rxs[..super::MIN_PEERS_FOR_FANOUT].iter().enumerate() {
            let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
                return Err(std::io::Error::other("expected getdata for eligible peer").into());
            };
            assert_eq!(
                witness_block_inventory(inventory)?,
                expected[idx * cap..(idx + 1) * cap]
            );
        }
        let _headers = rxs[0].try_recv()?;
        let spare_rx = &rxs[super::MIN_PEERS_FOR_FANOUT];
        assert!(spare_rx.try_recv().is_err());

        // The second-highest peer disconnects mid-window, owning the second
        // 16-block stripe.
        let dropped = addrs[1];
        peers.write().retain(|peer| peer.addr != dropped);
        peer_outbound.write().remove(&dropped);

        sync.tick();

        // Its in-flight blocks are released and picked up by the remaining
        // eligible peers — the saturated ones have no capacity, so the spare
        // takes the whole stripe.
        let NetworkMessage::GetData(requeued) = spare_rx.try_recv()? else {
            return Err(std::io::Error::other("expected re-queued getdata for spare peer").into());
        };
        assert_eq!(witness_block_inventory(requeued)?, expected[cap..2 * cap]);
        assert_eq!(sync.download_window.lock().pending_len(), window);
        for rx in &rxs[..super::MIN_PEERS_FOR_FANOUT] {
            assert!(rx.try_recv().is_err());
        }
        Ok(())
    }

    #[test]
    fn tick_caps_requests_at_staged_byte_headroom() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(8)?;
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
        let rx = connect_peer(&peers, &peer_outbound, eligible_peer(addr, 200));

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected headroom-clamped getdata").into());
        };
        // A gate-open burst must not over-request past staging headroom.
        assert_eq!(witness_block_inventory(inventory)?, expected[..1]);
        if !matches!(rx.try_recv()?, NetworkMessage::GetHeaders(_)) {
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
        let (sync, _peers, _peer_outbound, expected, rxs, _blocks_tx) =
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
                    window.contains_pending(&Hash256::from_le_bytes(&front.to_byte_array())),
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
            let hash =
                Hash256::from_le_bytes(&expected[usize::try_from(height)? - 1].to_byte_array());
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
        let (sync, _peers, _peer_outbound, expected, rxs, _blocks_tx) =
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
                if let NetworkMessage::GetData(inventory) = message {
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
                assert!(window.contains_pending(&Hash256::from_le_bytes(&front.to_byte_array())));
            }
        }
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
        let (sync, _peers, peer_outbound, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
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
            !peer_outbound.read().contains_key(&staller),
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
                if let NetworkMessage::GetData(inventory) = message {
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
                assert!(window.contains_pending(&Hash256::from_le_bytes(&front.to_byte_array())));
            }
        }
        Ok(())
    }

    #[test]
    fn reconnecting_staller_held_out_of_window_front_by_cooldown()
    -> Result<(), Box<dyn std::error::Error>> {
        // RE-ADV-2 terminator: previously a staller could re-acquire the
        // front stripe across expiry-retry cycles; now it is disconnected,
        // and after an immediate reconnect the cooldown keeps the window
        // front on the honest peer even though the staller's inflated
        // start_height (ADV-2's capture vector) out-sorts everyone.
        //
        // The staller first DELIVERS two front blocks >= 50ms apart — real
        // end-to-end cadence samples seeding the interval EWMA through the
        // chunk path — before wedging the window; an unseeded window would
        // defer conviction to the 60s pending-timeout fallback (cold-start
        // suppression) and nothing here would fire.
        let (sync, peers, peer_outbound, applied_tip, blocks, blocks_tx) =
            sync_with_mined_chain(5)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                max_received_blocks: 2,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                stall_timeout_initial: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let staller = test_addr(9420, 0)?;
        let honest = test_addr(9420, 1)?;
        let staller_rx = connect_peer(&peers, &peer_outbound, synthetic_peer(staller, 10_000));
        let honest_rx = connect_peer(&peers, &peer_outbound, synthetic_peer(honest, 100));

        // Tick 1: the inflated height wins the deep fallback selection.
        sync.tick();
        let NetworkMessage::GetData(inventory) = staller_rx.try_recv()? else {
            return Err(std::io::Error::other("expected staller getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![blocks[0].block_hash(), blocks[1].block_hash()]
        );
        assert!(honest_rx.try_recv().is_err());

        // Seed: blocks 1 and 2 arrive as window fronts >= 60ms apart.
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[0].clone(),
        ))?;
        sync.tick();
        sync.tick();
        std::thread::sleep(Duration::from_millis(60));
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[1].clone(),
        ))?;
        sync.tick();
        sync.tick();
        let ewma_ms = sync
            .download_window
            .lock()
            .front_interval_ewma_ms()
            .ok_or_else(|| std::io::Error::other("front deliveries must seed the cadence EWMA"))?;

        // The successor (block 4) arrives, the new front (block 3) never
        // does: wedge + episode on the staller, which owns the whole stripe.
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[3].clone(),
        ))?;
        sync.tick();
        assert_eq!(
            sync.download_window
                .lock()
                .stalling_peer()
                .map(|(addr, _)| addr),
            Some(staller)
        );

        // Fire: disconnect, and the front re-request lands on the honest
        // peer despite its (much) lower advertised height. The effective
        // threshold is max(100ms, 2x the measured seed cadence), so the
        // wait is derived from the EWMA instead of hardcoded.
        std::thread::sleep(Duration::from_millis(
            ewma_ms.saturating_mul(2).saturating_add(150),
        ));
        sync.tick();
        assert!(!peer_outbound.read().contains_key(&staller));
        let retry = next_getdata(&honest_rx)?;
        assert_eq!(
            witness_block_inventory(retry)?,
            alloc::vec![blocks[2].block_hash()]
        );

        // Immediate reconnect on the same address (the net layer's re-dial):
        // the honest peer delivers the front, sync advances, and the NEW
        // window front (block 5) must again go to the honest peer — the
        // reconnected staller stays in cooldown and receives no block
        // requests.
        let (staller_tx2, staller_rx2) = unbounded::<Message>();
        peer_outbound.write().insert(staller, staller_tx2);
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[2].clone(),
        ))?;
        sync.tick();
        // The re-request narrowed the expected-apply cache to the front, so
        // the staged successor drains on the following tick's tree walk.
        sync.tick();

        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height;
        assert_eq!(applied_height, 4, "sync must proceed past the stall");
        let front = next_getdata(&honest_rx)?;
        assert_eq!(
            witness_block_inventory(front)?,
            alloc::vec![blocks[4].block_hash()]
        );
        assert_no_getdata(&staller_rx2)?;
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
        let (sync, peers, peer_outbound, applied_tip, blocks, blocks_tx) =
            sync_with_mined_chain(2)?;
        install_budget(
            &sync,
            super::SyncBudget {
                // One initial-estimate slot (the pending front) plus the
                // delivered successor: byte headroom is exactly zero once
                // both are accounted.
                max_received_bytes: 256 * 1024 + blocks[1].total_size(),
                getdata_batch_limit: 2,
                stall_timeout_initial: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let staller = test_addr(9430, 0)?;
        let honest = test_addr(9430, 1)?;
        let staller_rx = connect_peer(&peers, &peer_outbound, synthetic_peer(staller, 200));
        let honest_rx = connect_peer(&peers, &peer_outbound, synthetic_peer(honest, 100));

        // Cold-start disarm: this byte-wedge construction depends on the
        // pristine 256KiB initial block-size estimate, so the cadence EWMA
        // is seeded directly instead of via two real front deliveries (the
        // real sampling path is pinned by the window tests). 50ms keeps the
        // decay floor at the injected 100ms initial threshold.
        sync.download_window
            .lock()
            .seed_front_cadence_for_test(50, Instant::now());

        sync.tick();
        let NetworkMessage::GetData(inventory) = staller_rx.try_recv()? else {
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
        assert!(!peer_outbound.read().contains_key(&staller));
        assert_eq!(
            sync.block_stager.lock().received_len(),
            1,
            "recovery must not discard staged progress (prune-free)"
        );
        let NetworkMessage::GetData(retry) = honest_rx.try_recv()? else {
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
            let (sync, peers, peer_outbound, applied_tip, blocks, blocks_tx) =
                sync_with_mined_chain(6)?;
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
            let rx = connect_peer(&peers, &peer_outbound, synthetic_peer(trickler, 100));

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
                assert!(peer_outbound.read().contains_key(&trickler));
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
                peer_outbound.read().contains_key(&trickler),
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
        let (sync, peers, peer_outbound, _block_tree, _applied_tip, expected) =
            sync_with_header_chain(4)?;
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
        let rx = connect_peer(&peers, &peer_outbound, synthetic_peer(staller, 100));

        // Cold-start disarm: an unseeded EWMA would suppress the fire on its
        // own and this test would pass vacuously. Seed it (50ms keeps the
        // decay floor at the default 2s initial threshold) so the no-fire
        // phase below pins the apply-side no-blame guard specifically.
        sync.download_window
            .lock()
            .seed_front_cadence_for_test(50, Instant::now());

        sync.tick();
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
        // The successor stages; the window is otherwise fully blocked on the
        // front-holding peer.
        let successor = Hash256::from_le_bytes(&expected[1].to_byte_array());
        {
            let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
            sync.block_stager
                .lock()
                .insert(successor, None, block, serialized, Instant::now());
        }
        sync.download_window
            .lock()
            .mark_received(successor, 80, Instant::now());

        // Apply-side backpressure: the next expected block (the frontier) is
        // itself staged but not yet drained.
        let frontier = Hash256::from_le_bytes(&expected[0].to_byte_array());
        {
            let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
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
        assert!(peer_outbound.read().contains_key(&staller));

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
        assert!(peer_outbound.read().contains_key(&staller));
        sync.disconnect_window_staller(Some(&applied), far_future + super::BLOCK_STALLING_TIMEOUT);
        assert!(
            !peer_outbound.read().contains_key(&staller),
            "with the apply side idle the same state must fire normally"
        );
        Ok(())
    }

    #[test]
    fn sole_peer_staller_disconnected_and_usable_again_as_last_resort()
    -> Result<(), Box<dyn std::error::Error>> {
        // Few-peers design decision (R10): Core disconnects stallers
        // regardless of peer count — a stalled-forever peer is worse than no
        // peer, because the disconnect is what re-queues the wedged front.
        // This node's net layer re-dials `--connect` peers every 2s (DNS
        // bootstrap is one-shot; that boundary is documented in the staller
        // module docs), and a reconnected sole staller is usable again
        // through the last-resort exemption, so liveness is preserved.
        //
        // The sole peer first delivers two front blocks >= 50ms apart (real
        // cadence samples seeding the interval EWMA through the chunk path)
        // before going silent: an unseeded window would defer conviction to
        // the 60s pending-timeout fallback (cold-start suppression) and the
        // disconnect under test would never fire.
        let (sync, peers, peer_outbound, applied_tip, blocks, blocks_tx) =
            sync_with_mined_chain(4)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 2,
                max_received_blocks: 2,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                stall_timeout_initial: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let sole = test_addr(9460, 0)?;
        let rx = connect_peer(&peers, &peer_outbound, synthetic_peer(sole, 100));

        sync.tick();
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            alloc::vec![blocks[0].block_hash(), blocks[1].block_hash()]
        );

        // Seed: blocks 1 and 2 arrive as window fronts >= 60ms apart.
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[0].clone(),
        ))?;
        sync.tick();
        sync.tick();
        std::thread::sleep(Duration::from_millis(60));
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[1].clone(),
        ))?;
        sync.tick();
        sync.tick();
        let ewma_ms = sync
            .download_window
            .lock()
            .front_interval_ewma_ms()
            .ok_or_else(|| std::io::Error::other("front deliveries must seed the cadence EWMA"))?;

        // The successor (block 4) arrives, the new front (block 3) never
        // does: wedge + episode on the sole peer.
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[3].clone(),
        ))?;
        sync.tick();
        assert!(sync.download_window.lock().stalling_peer().is_some());

        // The disconnect fires even with no alternative peer. The effective
        // threshold is max(100ms, 2x the measured seed cadence), so the
        // wait is derived from the EWMA instead of hardcoded.
        std::thread::sleep(Duration::from_millis(
            ewma_ms.saturating_mul(2).saturating_add(150),
        ));
        sync.tick();
        assert!(
            !peer_outbound.read().contains_key(&sole),
            "the sole peer's staller disconnect must fire — the re-queue is the recovery"
        );

        // Net-layer re-dial: the same address reconnects and, being the only
        // candidate, serves as the last resort despite the cooldown.
        let (tx2, rx2) = unbounded::<Message>();
        peer_outbound.write().insert(sole, tx2);
        sync.tick();
        let retry = next_getdata(&rx2)?;
        assert_eq!(
            witness_block_inventory(retry)?,
            alloc::vec![blocks[2].block_hash()]
        );

        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[2].clone(),
        ))?;
        sync.tick();
        // The re-request narrowed the expected-apply cache to the front, so
        // the staged successor drains on the following tick's tree walk.
        sync.tick();
        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height;
        assert_eq!(
            applied_height, 4,
            "liveness must survive the sole-peer disconnect"
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
            let (sync, peers, peer_outbound, applied_tip, blocks, blocks_tx) =
                sync_with_mined_chain(32)?;
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
                    &peer_outbound,
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
            let by_hash: HashMap<BlockHash, bitcoin::Block> = blocks
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
                        peer_outbound.read().len(),
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
                    peer_outbound.read().len(),
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
            assert_eq!(peer_outbound.read().len(), 8);
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
        let ((sync, peers, peer_outbound, block_tree, applied_tip, expected), blocks_tx) =
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
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9340, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        // Tick 1: eight eligible peers engage fan-out and stripe the window.
        sync.tick();
        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        assert!(sync.download_window.lock().fanout_active());
        for (idx, rx) in rxs.iter().enumerate() {
            let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        for rx in &rxs[1..] {
            while let Ok(message) = rx.try_recv() {
                if let NetworkMessage::GetData(inventory) = message {
                    let hashes = witness_block_inventory(inventory)?;
                    assert!(
                        hashes.len() <= 2,
                        "per-peer batches must stay at the installed fan-out \
                         cap (2); a deep batch is the mode-flap signature"
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
    fn tick_does_not_request_above_peer_advertised_height() -> Result<(), Box<dyn std::error::Error>>
    {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(8)?;
        install_budget(
            &sync,
            super::SyncBudget {
                max_pending_blocks: 4,
                max_peer_inflight: 2,
                getdata_batch_limit: 2,
                ..super::default_sync_budget()
            },
        );
        let high_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let low_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers
            .write()
            .extend([synthetic_peer(high_addr, 8), synthetic_peer(low_addr, 2)]);
        let (high_tx, high_rx) = unbounded::<Message>();
        let (low_tx, low_rx) = unbounded::<Message>();
        peer_outbound
            .write()
            .extend([(high_addr, high_tx), (low_addr, low_tx)]);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(high_inventory) = high_rx.try_recv()? else {
            return Err(std::io::Error::other("expected high peer getdata").into());
        };
        assert_eq!(witness_block_inventory(high_inventory)?, expected[..2]);
        assert!(high_rx.try_recv().is_err());
        assert!(low_rx.try_recv().is_err());
        assert_eq!(sync.download_window.lock().pending_len(), 2);
        Ok(())
    }

    #[test]
    fn clean_fast_path_caps_request_at_peer_height() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(8)?;
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
        peers.write().push(synthetic_peer(addr, 2));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(3)?;
        let received_hash = Hash256::from_le_bytes(&expected[1].to_byte_array());
        {
            let mut window = sync.download_window.lock();
            let needs_height = window.mark_received(received_hash, 80, Instant::now());
            assert!(needs_height);
            window.update_received_height(&received_hash, 2);
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 3));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        // Height above the deep chain tip: the lone peer can serve the entire
        // window (and headers past it).
        peers.write().push(synthetic_peer(
            addr,
            i32::try_from(super::PENDING_BUDGET)? + 100,
        ));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

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
            let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(5)?;
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first)?, expected[..2]);
        let _headers = rx.try_recv()?;

        sync.tick();

        let NetworkMessage::GetData(second) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        assert_eq!(witness_block_inventory(second)?, expected[..2]);
        Ok(())
    }

    #[test]
    fn tick_fills_mixed_retry_and_new_height_batch() -> Result<(), Box<dyn std::error::Error>> {
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(4)?;
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first)?, expected[..3]);
        let _headers = rx.try_recv()?;
        sync.download_window
            .lock()
            .mark_applied(&Hash256::from_le_bytes(&expected[0].to_byte_array()));

        sync.tick();

        let NetworkMessage::GetData(second) = rx.try_recv()? else {
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
        let (sync, peers, peer_outbound, block_tree, applied_tip, expected) =
            sync_with_header_chain(5)?;
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(first) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected first getdata").into());
        };
        assert_eq!(witness_block_inventory(first)?, expected[..4]);
        let _headers = rx.try_recv()?;
        {
            let mut window = sync.download_window.lock();
            window.mark_applied(&Hash256::from_le_bytes(&expected[0].to_byte_array()));
            window.drop_for_retry(&Hash256::from_le_bytes(&expected[1].to_byte_array()));
        }

        sync.tick();

        let NetworkMessage::GetData(second) = rx.try_recv()? else {
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
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let child = test_header(genesis.block_hash(), 1);
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
        let expected = BlockHash::from_byte_array(tree.node(child_id)?.hash.to_le_bytes());

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);
        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(genesis))?;

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));

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
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block = mined_block_with_prev_hash(
            genesis.block_hash(),
            1,
            vec![coinbase_transaction(1), transaction(0x41)],
        );
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let block_id = tree.insert_node(Some(genesis_id), block.header, NodeStatus::HeaderValid)?;
        let expected_hash = BlockHash::from_byte_array(tree.node(block_id)?.hash.to_le_bytes());

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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

        let NetworkMessage::GetData(retry) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
        Ok(())
    }

    #[test]
    fn staging_byte_exhaustion_backpressures_requests_then_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        // Staging byte budget that exactly one staged block exhausts.
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: block2.total_size(),
                getdata_batch_limit: 2,
                ..super::default_sync_budget()
            },
        );
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
            block2.total_size()
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
        let NetworkMessage::GetData(recovered) = rx.try_recv()? else {
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
            if matches!(message, NetworkMessage::GetData(_)) {
                return Err(std::io::Error::other(
                    "exhausted staging must not request from the stalled peer",
                )
                .into());
            }
        }
        assert!(
            healthy_rx.try_recv().is_err(),
            "exhausted staging must not request from the healthy peer"
        );
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
            assert!(window.contains_pending(&Hash256::from_le_bytes(block1_hash.as_byte_array())));
        }
        let NetworkMessage::GetData(retry) = healthy_rx.try_recv()? else {
            return Err(std::io::Error::other("expected healthy peer retry getdata").into());
        };
        assert_eq!(
            witness_block_inventory(retry)?,
            alloc::vec![block1_hash, block2_hash]
        );
        while let Ok(message) = stalled_rx.try_recv() {
            if matches!(message, NetworkMessage::GetData(_)) {
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
        block1_hash: bitcoin::BlockHash,
        block2_hash: bitcoin::BlockHash,
    }

    fn staging_exhaustion_fixture() -> Result<ExhaustionFixture, Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        // Staging byte budget that exactly one staged block exhausts.
        install_budget(
            &sync,
            super::SyncBudget {
                max_received_bytes: block2.total_size(),
                getdata_batch_limit: 2,
                pending_timeout: Duration::ZERO,
                received_timeout: Duration::from_millis(100),
                ..super::default_sync_budget()
            },
        );
        let stalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
        peers.write().push(synthetic_peer(stalled_addr, 100));
        let (stalled_tx, stalled_rx) = unbounded::<Message>();
        peer_outbound.write().insert(stalled_addr, stalled_tx);

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let NetworkMessage::GetData(inventory) = stalled_rx.try_recv()? else {
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

        peers.write().push(synthetic_peer(healthy_addr, 100));
        let (healthy_tx, healthy_rx) = unbounded::<Message>();
        peer_outbound.write().insert(healthy_addr, healthy_tx);

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
        blocks: Vec<bitcoin::Block>,
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
            let NetworkMessage::GetData(inventory) = outbound_rx.try_recv()? else {
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
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
            prev_hash = header.block_hash();
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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
        peers.write().push(synthetic_peer(addr, 100));
        let (tx, outbound_rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

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
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block1 =
            mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
        let block2 =
            mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
        let block3 =
            mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
        let block1_hash = Hash256::from_le_bytes(block1.block_hash().as_byte_array());
        let block2_hash = Hash256::from_le_bytes(block2.block_hash().as_byte_array());
        let block3_hash = Hash256::from_le_bytes(block3.block_hash().as_byte_array());

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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
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

        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
        sync.tick();

        assert_eq!(
            applied_tip.load_full().map(|tip| tip.height),
            Some(3),
            "retry should apply the failed block and then the restored tail in order"
        );
        assert_eq!(sync.block_stager.lock().received_len(), 0);
        assert_eq!(sync.download_window.lock().received_len(), 0);
        assert!(fail_once_store.persisted_height(1));
        assert!(fail_once_store.persisted_height(2));
        assert!(fail_once_store.persisted_height(3));
        assert_eq!(
            sync.handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(block3_hash)
        );
        assert_eq!(
            sync.handles.block_tree.read().height_of_hash(block1_hash),
            Some(1)
        );
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
        blocks: Vec<bitcoin::Block>,
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
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
            prev_hash = header.block_hash();
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let handles = apply_handles(Arc::clone(&chain_tip), Arc::clone(&applied_tip), block_tree);
        let sync = BlockSync::new(
            handles,
            peers,
            peer_outbound,
            inbound_headers_rx,
            inbound_blocks_rx,
        );
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

    fn stage_body(sync: &BlockSync, block: &bitcoin::Block) {
        let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(block));
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
            Hash256::from_le_bytes(fixture.blocks[2].block_hash().as_byte_array())
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
                fixture.blocks[3].block_hash().as_byte_array()
            )),
            "fourth applied block was already present in the populated horizon"
        );
        Ok(())
    }

    #[test]
    fn apply_cache_invalidated_on_failed_apply() -> Result<(), Box<dyn std::error::Error>> {
        // Fail persisting height 2 so the second apply in the batch fails after
        // the first succeeds, exercising the failed-apply invalidation branch.
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let mut handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        handles.block_body_store = Some(Arc::new(FailOnceBodyStore::new(2)));
        let sync = BlockSync::new(
            handles,
            peers,
            peer_outbound,
            inbound_headers_rx,
            inbound_blocks_rx,
        );
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
            Hash256::from_le_bytes(fixture.blocks[0].block_hash().as_byte_array())
        );
        assert_eq!(
            cache.hashes[cap - 1],
            Hash256::from_le_bytes(fixture.blocks[cap - 1].block_hash().as_byte_array())
        );
        Ok(())
    }

    type SyncFixture = (
        BlockSync,
        Arc<RwLock<Vec<PeerInfo>>>,
        Arc<RwLock<HashMap<SocketAddr, crossbeam_channel::Sender<Message>>>>,
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
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            expected.push(BlockHash::from_byte_array(
                tree.node(tip_id)?.hash.to_le_bytes(),
            ));
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );

        Ok((
            (
                sync,
                peers,
                peer_outbound,
                block_tree,
                applied_tip,
                expected,
            ),
            inbound_blocks_tx,
        ))
    }

    type MinedChainFixture = (
        BlockSync,
        Arc<RwLock<Vec<PeerInfo>>>,
        Arc<RwLock<HashMap<SocketAddr, crossbeam_channel::Sender<Message>>>>,
        Arc<ArcSwapOption<TipSnapshot>>,
        Vec<bitcoin::Block>,
        InboundBlockSender,
    );

    /// Like [`sync_with_header_chain_and_blocks`] but with fully applicable
    /// mined regtest blocks (coinbase-bearing, PoW-valid), so tests can drive
    /// real apply progress through the inbound channel.
    fn sync_with_mined_chain(count: u32) -> Result<MinedChainFixture, Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<BlockHeader>>();
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
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );
        // `node_id` ends as the chain tip; it only exists to thread parents.
        let _ = node_id;

        Ok((
            sync,
            peers,
            peer_outbound,
            applied_tip,
            blocks,
            inbound_blocks_tx,
        ))
    }

    type WedgeFixture = (
        BlockSync,
        Arc<RwLock<Vec<PeerInfo>>>,
        Arc<RwLock<HashMap<SocketAddr, crossbeam_channel::Sender<Message>>>>,
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
        let ((sync, peers, peer_outbound, block_tree, applied_tip, expected), blocks_tx) =
            sync_with_header_chain_and_blocks(64)?;
        install_budget(&sync, budget);
        let mut rxs = Vec::new();
        for idx in 0..super::MIN_PEERS_FOR_FANOUT {
            let addr = test_addr(9320, idx)?;
            rxs.push(connect_peer(
                &peers,
                &peer_outbound,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        for (idx, rx) in rxs.iter().enumerate() {
            let NetworkMessage::GetData(inventory) = rx.try_recv()? else {
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
        Ok((sync, peers, peer_outbound, expected, rxs, blocks_tx))
    }

    /// Returns the next `getdata` inventory from `rx`, skipping header
    /// traffic; fails when none is queued.
    fn next_getdata(
        rx: &crossbeam_channel::Receiver<Message>,
    ) -> Result<Vec<Inventory>, Box<dyn std::error::Error>> {
        while let Ok(message) = rx.try_recv() {
            if let NetworkMessage::GetData(inventory) = message {
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
            if matches!(message, NetworkMessage::GetData(_)) {
                return Err(std::io::Error::other("unexpected getdata").into());
            }
        }
        Ok(())
    }

    /// Reconstructs the deliverable block body (header-only, empty `txdata`)
    /// for `height` of a [`sync_with_header_chain`] fixture: the block hash
    /// is the header hash, so the delivery matches the fixture's tree node.
    fn header_chain_block(
        expected: &[BlockHash],
        height: u32,
    ) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
        let index = usize::try_from(height.checked_sub(1).ok_or("height must be >= 1")?)?;
        let prev_blockhash = if index == 0 {
            genesis_header().block_hash()
        } else {
            expected[index - 1]
        };
        let block = bitcoin::Block {
            header: test_header(prev_blockhash, height),
            txdata: Vec::new(),
        };
        assert_eq!(
            block.block_hash(),
            expected[index],
            "reconstructed block must hash to the fixture's header-chain node"
        );
        Ok(block)
    }

    fn install_budget(sync: &BlockSync, budget: super::SyncBudget) {
        *sync.download_window.lock() = super::DownloadWindow::new(budget);
        *sync.block_stager.lock() = super::BlockStager::new(budget);
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
    }

    fn witness_block_inventory(
        inventory: Vec<Inventory>,
    ) -> Result<Vec<BlockHash>, Box<dyn std::error::Error>> {
        inventory
            .into_iter()
            .map(|item| match item {
                Inventory::WitnessBlock(hash) => Ok(hash),
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
        ApplyHandles::new(
            Network::Regtest,
            chain_tip,
            applied_tip,
            block_tree,
            Arc::new(UtxoSet::new()),
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            Some(noop_tx_index()),
            noop_filter_index(),
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(HashMap::<Txid, Transaction>::new())),
            Arc::new(crate::NoOpZmqPublisher),
        )
    }

    struct NoopIndexer;

    impl IndexerLike for NoopIndexer {
        fn ingest_block(
            &mut self,
            _block: &[u8],
            _height: u32,
        ) -> Result<IndexRowCounts, IndexError> {
            Ok(IndexRowCounts::default())
        }

        fn resolve_outpoint_value(
            &self,
            _outpoint: bitcoin::OutPoint,
            _source: &dyn BlockSource,
        ) -> Result<Option<u64>, IndexError> {
            Ok(None)
        }
    }

    fn noop_tx_index() -> Arc<Mutex<Box<dyn IndexerLike>>> {
        let indexer: Box<dyn IndexerLike> = Box::new(NoopIndexer);
        Arc::new(Mutex::new(indexer))
    }

    struct NoopFilterIndex;

    impl FilterIndexLike for NoopFilterIndex {
        fn wants_filters(&self) -> bool {
            false
        }

        fn put_filter(
            &self,
            _block_hash: bitcoin_rs_primitives::Hash256,
            _prev_header: bitcoin_rs_primitives::Hash256,
            _filter_bytes: &[u8],
        ) -> Result<bitcoin_rs_primitives::Hash256, FilterIndexError> {
            Ok(bitcoin_rs_primitives::Hash256::default())
        }

        fn filter_header(
            &self,
            _block_hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<Option<bitcoin_rs_primitives::Hash256>, FilterIndexError> {
            Ok(None)
        }
    }

    fn noop_filter_index() -> Arc<Box<dyn FilterIndexLike>> {
        let filter_index: Box<dyn FilterIndexLike> = Box::new(NoopFilterIndex);
        Arc::new(filter_index)
    }

    fn test_header(prev_blockhash: BlockHash, height: u32) -> BlockHeader {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        BlockHeader {
            version: Version::ONE,
            prev_blockhash,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        }
    }

    fn genesis_header() -> BlockHeader {
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header
    }

    fn coinbase_transaction(height: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: Builder::new()
                    .push_int(i64::from(height))
                    .push_int(1)
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn transaction(seed: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
                    vout: u32::from(seed),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn mined_block_with_prev_hash(
        prev_blockhash: BlockHash,
        height: u32,
        txdata: Vec<Transaction>,
    ) -> bitcoin::Block {
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(TxMerkleNode::all_zeros);
        let target = block.header.target();
        while block.header.validate_pow(target).is_err() {
            block.header.nonce = block.header.nonce.saturating_add(1);
        }
        block
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

    fn synthetic_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
        PeerInfo {
            addr,
            version: 70_016,
            services: 0,
            user_agent: String::from("/test/"),
            start_height,
            conn_time: 0,
            inbound: true,
        }
    }

    /// A fan-out-eligible synthetic peer: outbound and witness-serving
    /// (`NODE_NETWORK` | `NODE_WITNESS`), unlike [`synthetic_peer`] which models
    /// the ineligible (inbound, flagless) shape.
    fn eligible_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
        PeerInfo {
            services: bitcoin::p2p::ServiceFlags::WITNESS.to_u64() | 1,
            inbound: false,
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
        peers: &Arc<RwLock<Vec<PeerInfo>>>,
        peer_outbound: &Arc<RwLock<HashMap<SocketAddr, crossbeam_channel::Sender<Message>>>>,
        info: PeerInfo,
    ) -> crossbeam_channel::Receiver<Message> {
        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(info.addr, tx);
        peers.write().push(info);
        rx
    }
}
