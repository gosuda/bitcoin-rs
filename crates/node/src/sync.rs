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

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

/// Maximum number of locator entries we ever send.
const LOCATOR_MAX_ENTRIES: usize = 32;
/// Wire protocol version we advertise on outbound `getheaders`.
const PROTOCOL_VERSION: u32 = 70_016;
/// Maximum number of block inventory entries we request per tick.
const GETDATA_BATCH_SIZE: usize = 16;
/// Time after which a pending getdata is considered stuck and re-requestable.
const PENDING_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of in-flight getdata requests we'll track per `BlockSync`.
const PENDING_BUDGET: usize = 128;

/// Block download orchestrator.
pub struct BlockSync {
    handles: crate::apply::ApplyHandles,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
    inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
    pending_blocks: Arc<Mutex<HashMap<Hash256, Instant>>>,
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
            pending_blocks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Runs one orchestrator tick: picks a sync peer, requests pending
    /// blocks, and asks the peer to extend the header chain.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.drain_inbound_blocks();

        let applied_height = self
            .handles
            .applied_tip
            .load_full()
            .map_or(0, |tip| tip.height);
        let Some(target) = self.pick_sync_peer(applied_height) else {
            tracing::trace!(applied_height, "block sync: no peer above current height");
            return;
        };

        self.send_getdata_for_pending_blocks(target.addr);
        self.send_getheaders(target.addr, applied_height, target.start_height);
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
        let receiver = self.inbound_blocks_rx.lock();
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        while let Ok(block) = receiver.try_recv() {
            match crate::apply::apply_block(&self.handles, &block) {
                Ok(tip) => {
                    applied += 1;
                    tracing::debug!(
                        height = tip.height,
                        %tip.hash,
                        "block sync: applied inbound block"
                    );
                    self.pending_blocks.lock().remove(&tip.hash);
                }
                Err(error) => {
                    failed += 1;
                    tracing::warn!(
                        %error,
                        "block sync: failed to apply inbound block"
                    );
                }
            }
        }
        if applied > 0 || failed > 0 {
            tracing::debug!(applied, failed, "block sync: drained inbound blocks");
        }
    }

    fn pick_sync_peer(&self, our_height: u32) -> Option<PeerInfo> {
        let peers = self.peers.read();
        peers
            .iter()
            .filter(|peer| {
                u32::try_from(peer.start_height)
                    .ok()
                    .is_some_and(|height| height > our_height)
            })
            .max_by_key(|peer| peer.start_height)
            .cloned()
    }

    fn send_getdata_for_pending_blocks(&self, sync_peer_addr: SocketAddr) {
        let Some(chain_tip) = self.handles.chain_tip.load_full() else {
            return;
        };
        let applied_height = self
            .handles
            .applied_tip
            .load_full()
            .map_or(0, |tip| tip.height);
        if chain_tip.height <= applied_height {
            return;
        }

        let mut pending = self.pending_blocks.lock();
        let now = Instant::now();
        pending.retain(|_hash, ts| now.duration_since(*ts) < PENDING_TIMEOUT);

        let remaining_budget = PENDING_BUDGET.saturating_sub(pending.len());
        if remaining_budget == 0 {
            tracing::trace!(
                pending = pending.len(),
                "block sync: pending budget exhausted; skipping getdata"
            );
            return;
        }
        let batch_cap = remaining_budget.min(GETDATA_BATCH_SIZE);

        let mut hashes: Vec<Hash256> = Vec::with_capacity(batch_cap);
        let tree = self.handles.block_tree.read();
        let mut cursor = chain_tip.tip_id;
        while hashes.len() < batch_cap {
            let Ok(node) = tree.node(cursor) else {
                break;
            };
            if node.height <= applied_height {
                break;
            }
            if !pending.contains_key(&node.hash) {
                hashes.push(node.hash);
            }
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }
        drop(tree);

        if hashes.is_empty() {
            return;
        }

        hashes.reverse();
        let count = hashes.len();
        for hash in &hashes {
            pending.insert(*hash, now);
        }
        drop(pending);
        let inventory: Vec<Inventory> = hashes
            .into_iter()
            .map(|hash| Inventory::WitnessBlock(BlockHash::from_byte_array(hash.to_le_bytes())))
            .collect();
        let msg = NetworkMessage::GetData(inventory);

        let tx = {
            let outbound = self.peer_outbound.read();
            outbound.get(&sync_peer_addr).cloned()
        };
        let Some(tx) = tx else {
            tracing::trace!(
                peer_addr = %sync_peer_addr,
                "block sync: target peer has no outbound channel (getdata skipped)"
            );
            return;
        };
        if tx.send(msg).is_err() {
            tracing::warn!(
                peer_addr = %sync_peer_addr,
                "block sync: outbound channel disconnected (getdata)"
            );
            return;
        }
        tracing::debug!(
            peer_addr = %sync_peer_addr,
            count,
            applied_height,
            chain_height = chain_tip.height,
            "block sync: sent getdata batch"
        );
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
        if let Some(tip) = self.handles.chain_tip.load_full() {
            return self
                .handles
                .block_tree
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        alloc::vec![self.handles.network.genesis_block_hash()]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Transaction, TxMerkleNode, Txid,
        block::{Header as BlockHeader, Version},
        pow::CompactTarget,
    };
    use bitcoin_rs_chain::{BlockTree, ChainWork, NodeStatus, TipSnapshot};
    use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
    use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_p2p::PeerInfo;
    use bitcoin_rs_utxo::UtxoSet;
    use crossbeam_channel::unbounded;
    use hashbrown::HashMap;
    use parking_lot::{Mutex, RwLock};

    use super::{BlockHash, BlockSync, Inventory, Message, NetworkMessage};
    use crate::{Network, apply::ApplyHandles};

    #[test]
    fn tick_sends_getdata_for_headers_above_applied_tip() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
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
        let applied_tip = Arc::new(ArcSwapOption::from_pointee(TipSnapshot {
            tip_id: genesis_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash: genesis_hash,
        }));
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
    fn second_tick_does_not_re_request_already_pending_blocks()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        let mut tip_id = genesis_id;

        for height in 1_u32..=3 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::from_pointee(TipSnapshot {
            tip_id: genesis_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash: genesis_hash,
        }));
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

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_handles(
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
    ) -> ApplyHandles {
        ApplyHandles {
            network: Network::Regtest,
            chain_tip,
            applied_tip,
            block_tree,
            utxo: Arc::new(UtxoSet::new()),
            coin_stats: Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            tx_index: noop_tx_index(),
            filter_index: noop_filter_index(),
            mempool: Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            blocks: Arc::new(RwLock::new(Vec::new())),
            transactions: Arc::new(RwLock::new(HashMap::<Txid, Transaction>::new())),
            zmq_publisher: Arc::new(crate::NoOpZmqPublisher),
        }
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
