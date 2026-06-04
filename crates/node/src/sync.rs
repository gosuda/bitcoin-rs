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
/// Time after which a pending getdata is considered stuck and re-requestable.
const PENDING_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of in-flight getdata requests we'll track per `BlockSync`.
const PENDING_BUDGET: usize = 128;
/// Time after which a received out-of-order block is discarded.
const RECEIVED_BLOCK_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of received blocks waiting for their predecessor.
const RECEIVED_BLOCK_BUDGET: usize = 128;
/// Mainnet-oriented block-size estimate for sizing the in-flight request window.
const PENDING_BLOCK_BYTE_ESTIMATE: usize = 2 * 1024 * 1024;
/// Maximum estimated bytes in the in-flight request window.
const PENDING_BYTE_BUDGET: usize = PENDING_BUDGET * PENDING_BLOCK_BYTE_ESTIMATE;
/// Maximum serialized bytes staged in memory while waiting for predecessors.
const RECEIVED_BLOCK_BYTE_BUDGET: usize = 128 * 256 * 1024;
/// Maximum decoded inbound blocks held before handing them to `BlockStager`.
const INBOUND_BLOCK_STAGE_CHUNK: usize = RECEIVED_BLOCK_BUDGET;
/// Maximum block requests one peer may own at once.
///
/// Keep the default per-peer cap equal to the global cap so the bounded
/// scheduler normally needs only one healthy peer to fill the whole window.
const PEER_INFLIGHT_BUDGET: usize = PENDING_BUDGET;

type ExpectedBlockHashes = SmallVec<[Hash256; RECEIVED_BLOCK_BUDGET]>;

/// Block download orchestrator.
pub struct BlockSync {
    handles: crate::apply::ApplyHandles,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
    inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
    download_window: Arc<Mutex<DownloadWindow>>,
    block_stager: Arc<Mutex<BlockStager>>,
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

#[derive(Clone, Debug)]
struct ExpectedApplyCache {
    chain_tip_hash: Hash256,
    applied_tip_hash: Hash256,
    applied_tip_height: u32,
    hashes: ExpectedBlockHashes,
}

impl BlockSync {
    /// Constructs a new orchestrator over the supplied shared handles.
    #[must_use]
    pub fn new(
        handles: crate::apply::ApplyHandles,
        peers: Arc<RwLock<Vec<PeerInfo>>>,
        peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
        inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
        inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
    ) -> Self {
        Self {
            handles,
            peers,
            peer_outbound,
            inbound_headers_rx,
            inbound_blocks_rx,
            download_window: Arc::new(Mutex::new(DownloadWindow::new(default_sync_budget()))),
            block_stager: Arc::new(Mutex::new(BlockStager::new(default_sync_budget()))),
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
        self.release_disconnected_peer_budget();
        let now = Instant::now();
        let sync_peer_selection = self.sync_peer_selection(applied_height, now);
        if sync_peer_selection.header_peer.is_none() {
            tracing::trace!(applied_height, "block sync: no peer above current height");
            return;
        }

        let chain_tip = self.handles.chain_tip.load_full();
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
        let mut sent_getdata = false;
        let request_peer_count = sync_peer_selection.request_peers.len();
        for (peer_idx, peer) in sync_peer_selection.request_peers.into_iter().enumerate() {
            let peer_best_height = u32::try_from(peer.start_height).unwrap_or(0);
            let requested_blocks = match (&chain_tip, &applied_tip) {
                (Some(chain_tip), Some(applied_tip)) => self.send_getdata_for_pending_blocks(
                    peer.addr,
                    peer_idx + 1 == request_peer_count,
                    peer_best_height,
                    chain_tip,
                    applied_tip,
                ),
                _ => false,
            };
            sent_getdata |= requested_blocks;
            if requested_blocks && !self.download_window.lock().has_request_capacity() {
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
            self.record_sync_metrics();
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

        let now = Instant::now();
        let dropped = self.block_stager.lock().prune_expired(now);
        let pruned = !dropped.is_empty();
        if pruned {
            let mut window = self.download_window.lock();
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
        blocks: &mut Vec<bitcoin::Block>,
        saw_block: &mut bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        let receiver = self.inbound_blocks_rx.lock();
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(block) = receiver.try_recv() else {
                return true;
            };
            if !*saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash.as_ref().copied().filter(|hash| {
                    *hash != Hash256::from_le_bytes(block.block_hash().as_byte_array())
                });
                *saw_block = true;
            }
            blocks.push(block);
        }
        false
    }

    fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<bitcoin::Block>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        let mut staged_blocks = Vec::with_capacity(blocks.len());
        {
            let mut stager = self.block_stager.lock();
            let now = Instant::now();
            for block in blocks.drain(..) {
                let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
                let staged = stager.insert(hash, next_expected_hash, block, now);
                staged_blocks.push((hash, staged));
            }
        }

        let mut height_lookups = Vec::new();
        let mut retry_count = 0_u64;
        let staged_count = staged_blocks.len();
        {
            let mut window = self.download_window.lock();
            for (hash, staged) in staged_blocks {
                match staged {
                    StagedBlock::AlreadyStaged => {}
                    StagedBlock::Memory { bytes, dropped } => {
                        if window.mark_received(hash, bytes) {
                            height_lookups.push(hash);
                        }
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

        if !height_lookups.is_empty() {
            let tree = self.handles.block_tree.read();
            let height_updates: Vec<(Hash256, u32)> = height_lookups
                .into_iter()
                .filter_map(|hash| {
                    let node_id = tree.lookup(hash)?;
                    tree.node(node_id).ok().map(|node| (hash, node.height))
                })
                .collect();
            drop(tree);
            if !height_updates.is_empty() {
                let mut window = self.download_window.lock();
                for (hash, height) in height_updates {
                    window.update_received_height(&hash, height);
                }
            }
        }
        staged_count
    }

    fn apply_buffered_blocks(&self, next_expected_hash: Option<Hash256>) -> (usize, usize) {
        let started = Instant::now();
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        let Some(staged_count) = self
            .block_stager
            .lock()
            .ready_received_len(next_expected_hash)
        else {
            return (0, 0);
        };
        let (drained, expected_len) = self
            .drain_cached_expected_blocks(staged_count)
            .unwrap_or_else(|| {
                let expected_hashes = self.expected_block_hashes(staged_count);
                let expected_len = expected_hashes.len();
                let drained = self
                    .block_stager
                    .lock()
                    .drain_expected_prefix(&expected_hashes);
                (drained, expected_len)
            });
        let mut applied_hashes = Vec::with_capacity(expected_len);
        let mut failed_hash = None;
        let mut drained = drained.into_iter();
        while let Some(drained_block) = drained.next() {
            match crate::apply::apply_block(&self.handles, &drained_block.block) {
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
            let mut window = self.download_window.lock();
            for hash in applied_hashes {
                window.mark_applied(&hash);
            }
            if let Some(hash) = failed_hash {
                window.drop_received_for_retry(&hash);
            }
            metrics::histogram!("node.sync.apply_buffered_blocks_seconds")
                .record(started.elapsed().as_secs_f64());
        }
        (applied, failed)
    }

    fn expected_block_hashes(&self, max_count: usize) -> ExpectedBlockHashes {
        if max_count == 0 {
            return ExpectedBlockHashes::new();
        }
        let Some(chain_tip) = self.handles.chain_tip.load_full() else {
            return ExpectedBlockHashes::new();
        };
        let Some(applied_tip) = self.handles.applied_tip.load_full() else {
            return ExpectedBlockHashes::new();
        };
        let Some(start_height) = applied_tip.height.checked_add(1) else {
            return ExpectedBlockHashes::new();
        };
        if start_height > chain_tip.height {
            return ExpectedBlockHashes::new();
        }

        let max_offset = u32::try_from(max_count.saturating_sub(1)).unwrap_or(u32::MAX);
        let end_height = start_height
            .saturating_add(max_offset)
            .min(chain_tip.height);
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(max_count);
        let tree = self.handles.block_tree.read();
        let Some(mut cursor) = tree.node_at_height_from(chain_tip.tip_id, end_height) else {
            return ExpectedBlockHashes::new();
        };
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
            return ExpectedBlockHashes::new();
        }
        hashes.reverse();
        hashes
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
        let expected_len = cache.hashes.len().min(max_count);
        let drained = self
            .block_stager
            .lock()
            .drain_expected_prefix(&cache.hashes[..expected_len]);
        Some((drained, expected_len))
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
        let request_peer_limit = self.download_window.lock().request_peer_scan_limit(now);
        let peers = self.peers.read();
        let mut selection = SyncPeerSelection {
            header_peer: None,
            request_peers: Vec::with_capacity(request_peer_limit.min(peers.len())),
        };
        let mut single_request_peer = None;
        for peer in peers.iter() {
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
            if selection
                .header_peer
                .is_none_or(|current| current.start_height < sync_peer.start_height)
            {
                selection.header_peer = Some(sync_peer);
            }
            match request_peer_limit {
                0 => {}
                1 => {
                    if single_request_peer.is_none_or(|current: SyncPeer| {
                        current.start_height < sync_peer.start_height
                    }) {
                        single_request_peer = Some(sync_peer);
                    }
                }
                _ => {
                    insert_request_peer(
                        &mut selection.request_peers,
                        request_peer_limit,
                        sync_peer,
                    );
                }
            }
        }
        if let Some(peer) = single_request_peer {
            selection.request_peers.push(peer);
        }
        selection
    }

    fn send_getdata_for_pending_blocks(
        &self,
        sync_peer_addr: SocketAddr,
        allow_expired_retry_from_peer: bool,
        peer_best_height: u32,
        chain_tip: &TipSnapshot,
        applied_tip: &TipSnapshot,
    ) -> bool {
        let applied_height = applied_tip.height;
        if chain_tip.height <= applied_height {
            return false;
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
            return false;
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
            return false;
        };
        if tx.send(msg).is_err() {
            tracing::warn!(
                peer_addr = %request.peer_addr(),
                "block sync: outbound channel disconnected (getdata)"
            );
            return false;
        }
        if is_contiguous {
            *self.expected_apply_cache.lock() = Some(ExpectedApplyCache {
                chain_tip_hash: chain_tip.hash,
                applied_tip_hash: applied_tip.hash,
                applied_tip_height: applied_tip.height,
                hashes: expected_hashes,
            });
        }
        self.download_window.lock().mark_requested(&request, now);
        metrics::histogram!("node.sync.getdata_batch_size").record(metric_count(count));
        tracing::debug!(
            peer_addr = %request.peer_addr(),
            count,
            applied_height,
            chain_height = chain_tip.height,
            "block sync: sent getdata batch"
        );
        true
    }

    fn send_getheaders(&self, sync_peer_addr: SocketAddr, our_height: u32, target_height: i32) {
        let locator = self.build_locator();
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
        tracing::debug!(
            peer_addr = %sync_peer_addr,
            our_height,
            target_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
    }

    fn build_locator(&self) -> Vec<Hash256> {
        self.ensure_genesis_tip();
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

    fn record_sync_metrics(&self) {
        let window = self.download_window.lock();
        let stager = self.block_stager.lock();
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
        metrics::gauge!("node.sync.received_blocks").set(metric_count(stager.received_len()));
        metrics::gauge!("node.sync.received_bytes").set(metric_count(stager.received_bytes()));
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

fn insert_request_peer(request_peers: &mut Vec<SyncPeer>, limit: usize, peer: SyncPeer) {
    if limit == 0 {
        return;
    }
    let insert_at = request_peers
        .iter()
        .position(|current| current.start_height < peer.start_height)
        .unwrap_or(request_peers.len());
    if request_peers.len() < limit {
        request_peers.insert(insert_at, peer);
    } else if insert_at < limit {
        request_peers.insert(insert_at, peer);
        request_peers.truncate(limit);
    }
}

const fn default_sync_budget() -> SyncBudget {
    SyncBudget {
        max_pending_blocks: PENDING_BUDGET,
        max_pending_bytes: PENDING_BYTE_BUDGET,
        max_received_blocks: RECEIVED_BLOCK_BUDGET,
        max_received_bytes: RECEIVED_BLOCK_BYTE_BUDGET,
        max_peer_inflight: PEER_INFLIGHT_BUDGET,
        getdata_batch_limit: GETDATA_BATCH_SIZE,
        pending_timeout: PENDING_TIMEOUT,
        received_timeout: RECEIVED_BLOCK_TIMEOUT,
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
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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
        peers.write().extend([
            synthetic_peer(first_addr, 200),
            synthetic_peer(second_addr, 200),
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
        let second_headers = first_rx.try_recv()?;
        if !matches!(second_headers, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected header refresh on first peer").into());
        }
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
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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

        let third = rx.try_recv()?;
        if !matches!(third, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected second tick getheaders only").into());
        }
        match rx.try_recv() {
            Ok(NetworkMessage::GetData(_)) => {
                Err(std::io::Error::other("second tick re-requested pending blocks").into())
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
        let staged = sync
            .block_stager
            .lock()
            .insert(hash, None, block, received_at);
        let super::StagedBlock::Memory { bytes, .. } = staged else {
            return Err(std::io::Error::other("test block should stage in memory").into());
        };
        sync.download_window.lock().mark_received(hash, bytes);

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
        let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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

        inbound_blocks_tx.send(block2)?;
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

        let second_tick = rx.try_recv()?;
        if !matches!(second_tick, NetworkMessage::GetHeaders(_)) {
            return Err(std::io::Error::other("expected second tick getheaders only").into());
        }
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
            let needs_height = window.mark_received(received_hash, 80);
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
        peers.write().push(synthetic_peer(addr, 200));
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
        let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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
        inbound_blocks_tx.send(genesis)?;

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

        let super::StagedBlock::Memory { dropped, .. } =
            stager.insert(fork_hash, Some(expected_hash), block.clone(), now)
        else {
            return Err(std::io::Error::other("fork block should stage").into());
        };
        assert!(dropped.is_empty());

        let super::StagedBlock::Memory { dropped, .. } =
            stager.insert(expected_hash, Some(expected_hash), block, now)
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
        let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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

        inbound_blocks_tx.send(block)?;
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

    const DETERMINISTIC_PROXY_BLOCKS: usize = 24;
    const DETERMINISTIC_PROXY_TIP_HEIGHT: u32 = 24;
    const DETERMINISTIC_PROXY_HEADER_HEIGHT: u32 = 96;

    struct DeterministicProxyFixture {
        sync: BlockSync,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        inbound_blocks_tx: crossbeam_channel::Sender<bitcoin::Block>,
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
            let _headers = outbound_rx.try_recv()?;

            for block in blocks[1..].iter().rev() {
                inbound_blocks_tx.send(block.clone())?;
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

            inbound_blocks_tx.send(blocks[0].clone())?;
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
        let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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
        let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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

        inbound_blocks_tx.send(block3)?;
        inbound_blocks_tx.send(block2.clone())?;
        inbound_blocks_tx.send(block1)?;
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

        inbound_blocks_tx.send(block2)?;
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
            fixture.inbound_blocks_tx.send(block.clone())?;
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

    type SyncFixture = (
        BlockSync,
        Arc<RwLock<Vec<PeerInfo>>>,
        Arc<RwLock<HashMap<SocketAddr, crossbeam_channel::Sender<Message>>>>,
        Arc<RwLock<BlockTree>>,
        Arc<ArcSwapOption<TipSnapshot>>,
        Vec<BlockHash>,
    );

    fn sync_with_header_chain(height: u32) -> Result<SyncFixture, Box<dyn std::error::Error>> {
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
        let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
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
            sync,
            peers,
            peer_outbound,
            block_tree,
            applied_tip,
            expected,
        ))
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
}
