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
/// Time after which a received out-of-order block is discarded.
const RECEIVED_BLOCK_TIMEOUT: Duration = Duration::from_mins(1);
/// Maximum number of received blocks waiting for their predecessor.
const RECEIVED_BLOCK_BUDGET: usize = 128;

struct ReceivedBlock {
    block: bitcoin::Block,
    received_at: Instant,
}

/// Block download orchestrator.
pub struct BlockSync {
    handles: crate::apply::ApplyHandles,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: Arc<RwLock<HashMap<SocketAddr, Sender<Message>>>>,
    inbound_headers_rx: Arc<Mutex<Receiver<Vec<bitcoin::block::Header>>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin::Block>>>,
    pending_blocks: Arc<Mutex<HashMap<Hash256, Instant>>>,
    received_blocks: Arc<Mutex<HashMap<Hash256, ReceivedBlock>>>,
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
            received_blocks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Runs one orchestrator tick: picks a sync peer, requests pending
    /// blocks, and asks the peer to extend the header chain.
    pub fn tick(&self) {
        self.drain_inbound_headers();
        self.ensure_genesis_tip();
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
        let mut received = 0_usize;
        while let Ok(block) = receiver.try_recv() {
            received = received.saturating_add(1);
            self.buffer_received_block(block);
        }
        drop(receiver);

        let now = Instant::now();
        let mut received_blocks = self.received_blocks.lock();
        prune_received_blocks(&mut received_blocks, now);
        drop(received_blocks);

        let (applied, failed) = self.apply_buffered_blocks();
        if received > 0 || applied > 0 || failed > 0 {
            tracing::debug!(
                received,
                applied,
                failed,
                "block sync: drained inbound blocks"
            );
        }
    }

    fn buffer_received_block(&self, block: bitcoin::Block) {
        let now = Instant::now();
        let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let mut received = self.received_blocks.lock();
        prune_received_blocks(&mut received, now);
        if received.len() >= RECEIVED_BLOCK_BUDGET && !received.contains_key(&hash) {
            evict_oldest_received_block(&mut received);
        }
        if received.len() >= RECEIVED_BLOCK_BUDGET && !received.contains_key(&hash) {
            tracing::warn!(%hash, "block sync: received block buffer full; dropping block");
            return;
        }
        received.insert(
            hash,
            ReceivedBlock {
                block,
                received_at: now,
            },
        );
    }

    fn apply_buffered_blocks(&self) -> (usize, usize) {
        let mut applied = 0_usize;
        let mut failed = 0_usize;
        while let Some(expected_hash) = self.next_expected_block_hash() {
            let Some(received) = self.received_blocks.lock().remove(&expected_hash) else {
                break;
            };
            match crate::apply::apply_block(&self.handles, &received.block) {
                Ok(tip) => {
                    applied = applied.saturating_add(1);
                    tracing::debug!(
                        height = tip.height,
                        %tip.hash,
                        "block sync: applied buffered block"
                    );
                    self.pending_blocks.lock().remove(&tip.hash);
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    self.pending_blocks.lock().remove(&expected_hash);
                    tracing::warn!(
                        %expected_hash,
                        %error,
                        "block sync: failed to apply buffered block"
                    );
                    break;
                }
            }
        }
        (applied, failed)
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
        let Some(applied_tip) = self.handles.applied_tip.load_full() else {
            return;
        };
        let applied_height = applied_tip.height;
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
        let Some(mut height) = applied_height.checked_add(1) else {
            return;
        };
        while hashes.len() < batch_cap && height <= chain_tip.height {
            let Some(node_id) = tree.node_at_height_from(chain_tip.tip_id, height) else {
                break;
            };
            let Ok(node) = tree.node(node_id) else {
                break;
            };
            if !pending.contains_key(&node.hash) {
                hashes.push(node.hash);
            }
            height = height.saturating_add(1);
        }
        drop(tree);

        if hashes.is_empty() {
            return;
        }

        let count = hashes.len();
        drop(pending);
        let inventory: Vec<Inventory> = hashes
            .iter()
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
        let mut pending = self.pending_blocks.lock();
        for hash in &hashes {
            pending.insert(*hash, now);
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

fn prune_received_blocks(received: &mut HashMap<Hash256, ReceivedBlock>, now: Instant) {
    received.retain(|_hash, entry| now.duration_since(entry.received_at) < RECEIVED_BLOCK_TIMEOUT);
}

fn evict_oldest_received_block(received: &mut HashMap<Hash256, ReceivedBlock>) {
    let Some(oldest_hash) = received
        .iter()
        .min_by_key(|(_hash, entry)| entry.received_at)
        .map(|(hash, _entry)| *hash)
    else {
        return;
    };
    received.remove(&oldest_hash);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Transaction, TxMerkleNode, Txid,
        block::{Header as BlockHeader, Version},
        pow::CompactTarget,
    };
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
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
    fn tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut tip_id = genesis_id;
        let mut expected = Vec::new();
        let batch_size = u32::try_from(super::GETDATA_BATCH_SIZE)?;

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
        assert!(sync.pending_blocks.lock().is_empty());

        let (tx, rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, tx);

        sync.tick();

        let first = rx.try_recv()?;
        let NetworkMessage::GetData(inventory) = first else {
            return Err(std::io::Error::other("expected retry getdata").into());
        };
        let requested = witness_block_inventory(inventory)?;
        assert_eq!(requested, expected);
        assert_eq!(sync.pending_blocks.lock().len(), expected.len());
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
        assert!(sync.pending_blocks.lock().is_empty());
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

        let pending = sync.pending_blocks.lock();
        assert_eq!(pending.len(), expected.len());
        for hash in expected {
            let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&hash.to_byte_array());
            assert!(pending.contains_key(&hash));
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
        sync.received_blocks
            .lock()
            .insert(hash, super::ReceivedBlock { block, received_at });

        sync.drain_inbound_blocks();

        assert!(sync.received_blocks.lock().is_empty());
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
            Some(noop_filter_index()),
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
