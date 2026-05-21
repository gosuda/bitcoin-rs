//! Node-side adapter for server-side P2P active-chain requests.
//!
//! This is deliberately an in-memory view: headers come from `BlockTree`, and
//! block bodies come from the same `BlockRecord` cache used by RPC. Persisted
//! pruned body reads are not hidden here; absent or pruned bodies are reported
//! as unavailable to the P2P dispatcher.

use alloc::sync::Arc;

use bitcoin::block::{BlockHash, Header};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_p2p::{ChainQuery, InventoryResponse};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::BlockRecord;
use parking_lot::RwLock;

/// Read-only in-memory active-chain view for P2P `getheaders` / `getdata`.
#[derive(Clone)]
pub struct NodeP2pChainQuery {
    block_tree: Arc<RwLock<BlockTree>>,
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
}

impl NodeP2pChainQuery {
    /// Builds a P2P chain query view over the node's shared active-chain state.
    #[must_use]
    pub const fn new(
        block_tree: Arc<RwLock<BlockTree>>,
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
    ) -> Self {
        Self { block_tree, blocks }
    }
}

impl core::fmt::Debug for NodeP2pChainQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeP2pChainQuery").finish_non_exhaustive()
    }
}

impl ChainQuery for NodeP2pChainQuery {
    fn headers_after(
        &self,
        locator_hashes: &[BlockHash],
        stop_hash: BlockHash,
        limit: usize,
    ) -> Vec<Header> {
        let tree = self.block_tree.read();
        let Some(tip) = tree.tip() else {
            return Vec::new();
        };
        if limit == 0 {
            return Vec::new();
        }
        if locator_hashes.is_empty() {
            return header_for_active_stop(&tree, tip.tip_id, stop_hash)
                .into_iter()
                .take(limit)
                .collect();
        }

        let mut height = locator_hashes
            .iter()
            .find_map(|hash| active_height(&tree, tip.tip_id, *hash))
            .and_then(|height| height.checked_add(1))
            .unwrap_or(1);
        let has_stop = stop_hash != BlockHash::all_zeros();
        let mut headers = Vec::new();

        while height <= tip.height && headers.len() < limit {
            let Some(node_id) = tree.node_at_height_from(tip.tip_id, height) else {
                break;
            };
            let Ok(node) = tree.node(node_id) else {
                break;
            };
            let reached_stop = has_stop && node.header.block_hash() == stop_hash;
            headers.push(node.header);
            if reached_stop {
                break;
            }
            let Some(next_height) = height.checked_add(1) else {
                break;
            };
            height = next_height;
        }

        headers
    }

    fn blocks_for_inventory(&self, items: &[Inventory]) -> InventoryResponse {
        let mut response = InventoryResponse::default();
        for item in items {
            let Some(hash) = inventory_block_hash(item) else {
                response.not_found.push(*item);
                continue;
            };
            if let Some(block) = self.block_by_active_hash(hash) {
                response.blocks.push(block);
            } else {
                response.not_found.push(*item);
            }
        }
        response
    }
}

impl NodeP2pChainQuery {
    fn block_by_active_hash(&self, hash: BlockHash) -> Option<bitcoin::Block> {
        let current_height = {
            let tree = self.block_tree.read();
            active_height(&tree, tree.tip()?.tip_id, hash)?
        };
        let hash256 = hash256(hash);
        let blocks = self.blocks.read();
        let record = blocks
            .iter()
            .find(|record| record.height == current_height && record.hash == hash256)?;
        if record.block_hex.is_empty() {
            return None;
        }
        let bytes = Vec::<u8>::from_hex(&record.block_hex).ok()?;
        let block = deserialize::<bitcoin::Block>(&bytes).ok()?;
        if block.block_hash() != hash {
            return None;
        }
        let tree = self.block_tree.read();
        (active_height(&tree, tree.tip()?.tip_id, hash) == Some(current_height)).then_some(block)
    }
}

fn header_for_active_stop(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    stop_hash: BlockHash,
) -> Option<Header> {
    if stop_hash == BlockHash::all_zeros() {
        return None;
    }
    let height = active_height(tree, tip_id, stop_hash)?;
    let node_id = tree.node_at_height_from(tip_id, height)?;
    Some(tree.node(node_id).ok()?.header)
}

fn active_height(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    hash: BlockHash,
) -> Option<u32> {
    let hash = hash256(hash);
    let candidate = tree.node_by_hash(hash)?;
    let active_id = tree.node_at_height_from(tip_id, candidate.height)?;
    let active = tree.node(active_id).ok()?;
    (active.hash == hash).then_some(active.height)
}

fn inventory_block_hash(item: &Inventory) -> Option<BlockHash> {
    match *item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(hash),
        Inventory::Error
        | Inventory::Transaction(_)
        | Inventory::CompactBlock(_)
        | Inventory::WTx(_)
        | Inventory::WitnessTransaction(_)
        | Inventory::Unknown { .. } => None,
    }
}

fn hash256(hash: BlockHash) -> Hash256 {
    Hash256::from_le_bytes(hash.as_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{Block, TxMerkleNode, Txid};
    use bitcoin_rs_chain::NodeStatus;

    #[test]
    fn getheaders_empty_locator_returns_only_active_stop() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = seed_headers(3);
        let stop = headers[2].block_hash();
        let query = query_with(headers, Vec::new())?;

        let response = query.headers_after(&[], stop, 2);

        assert_eq!(header_hashes(&response), vec![stop]);
        Ok(())
    }

    #[test]
    fn getheaders_empty_locator_unknown_or_zero_stop_returns_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let query = query_with(headers, Vec::new())?;

        assert!(
            query
                .headers_after(&[], BlockHash::all_zeros(), 2)
                .is_empty()
        );
        assert!(
            query
                .headers_after(&[], BlockHash::from_byte_array([9; 32]), 2)
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn getheaders_unknown_locator_starts_after_genesis() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let expected = vec![headers[1].block_hash(), headers[2].block_hash()];
        let query = query_with(headers, Vec::new())?;

        let response = query.headers_after(
            &[BlockHash::from_byte_array([42; 32])],
            BlockHash::all_zeros(),
            10,
        );

        assert_eq!(header_hashes(&response), expected);
        Ok(())
    }

    #[test]
    fn getheaders_after_locator_stops_at_stop_hash() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(5);
        let locator = headers[1].block_hash();
        let stop = headers[3].block_hash();
        let expected = vec![headers[2].block_hash(), stop];
        let query = query_with(headers, Vec::new())?;

        let response = query.headers_after(&[locator], stop, 10);

        assert_eq!(header_hashes(&response), expected);
        Ok(())
    }

    #[test]
    fn getheaders_ignores_stale_fork_locator_and_stop() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let active1 = test_header(genesis.block_hash(), 1);
        let active2 = test_header(active1.block_hash(), 2);
        let fork1 = test_header(genesis.block_hash(), 42);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let active1_id = tree.insert_node(Some(genesis_id), active1, NodeStatus::Active)?;
        tree.insert_node(Some(active1_id), active2, NodeStatus::Active)?;
        tree.insert_node(Some(genesis_id), fork1, NodeStatus::Stale)?;
        let query = NodeP2pChainQuery::new(
            Arc::new(RwLock::new(tree)),
            Arc::new(RwLock::new(Vec::new())),
        );

        let response = query.headers_after(&[fork1.block_hash()], BlockHash::all_zeros(), 10);

        assert_eq!(
            header_hashes(&response),
            vec![active1.block_hash(), active2.block_hash()]
        );
        assert!(query.headers_after(&[], fork1.block_hash(), 10).is_empty());
        Ok(())
    }

    #[test]
    fn getdata_decodes_active_cached_body_and_reports_missing_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txdata: Vec::new(),
        };
        let record = BlockRecord::from_block(1, &block);
        let txid = Txid::all_zeros();
        let missing = Inventory::WitnessBlock(BlockHash::from_byte_array([8; 32]));
        let query = query_with(headers, vec![record])?;

        let response = query.blocks_for_inventory(&[
            Inventory::Block(block.block_hash()),
            Inventory::Transaction(txid),
            missing,
        ]);

        assert_eq!(response.blocks.len(), 1);
        assert_eq!(response.blocks[0].block_hash(), block.block_hash());
        assert_eq!(
            response.not_found,
            vec![Inventory::Transaction(txid), missing]
        );
        Ok(())
    }

    #[test]
    fn getdata_rejects_pruned_or_missing_body() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let hash = headers[1].block_hash();
        let record = BlockRecord::synthetic(1, hash256(hash));
        let query = query_with(headers, vec![record])?;

        let response = query.blocks_for_inventory(&[Inventory::Block(hash)]);

        assert!(response.blocks.is_empty());
        assert_eq!(response.not_found, vec![Inventory::Block(hash)]);
        Ok(())
    }

    fn query_with(
        headers: Vec<Header>,
        records: Vec<BlockRecord>,
    ) -> Result<NodeP2pChainQuery, bitcoin_rs_chain::ChainError> {
        let mut tree = BlockTree::new();
        let mut parent = None;
        for header in headers {
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        Ok(NodeP2pChainQuery::new(
            Arc::new(RwLock::new(tree)),
            Arc::new(RwLock::new(records)),
        ))
    }

    fn seed_headers(count: u32) -> Vec<Header> {
        let mut headers = Vec::new();
        let mut prev = BlockHash::all_zeros();
        for nonce in 0..count {
            let header = test_header(prev, nonce);
            prev = header.block_hash();
            headers.push(header);
        }
        headers
    }

    fn test_header(prev_blockhash: BlockHash, nonce: u32) -> Header {
        Header {
            version: Version::from_consensus(1),
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: nonce,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        }
    }

    fn header_hashes(headers: &[Header]) -> Vec<BlockHash> {
        headers.iter().map(Header::block_hash).collect()
    }
}
