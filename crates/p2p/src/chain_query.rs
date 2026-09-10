//! Active-chain serving for `getheaders` / `getdata`.
//!
//! Locator interpretation, header-walk policy, and inventory serving live
//! here. [`BlockTree`] answers active-chain identity; [`BlockBodySource`]
//! supplies bodies.

use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_chain::{BlockBodySource, BlockTree};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header};

#[cfg(test)]
use bitcoin_rs_primitives::CompactTarget;
use parking_lot::RwLock;

use crate::dispatch::{ChainQuery, InventoryServing};
use crate::wire::PeerError;

/// Read-only active-chain view for P2P `getheaders` / `getdata`.
#[derive(Clone)]
pub struct ActiveChainQuery {
    block_tree: Arc<RwLock<BlockTree>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
}

impl ActiveChainQuery {
    /// Builds a P2P chain query view over shared active-chain state.
    #[must_use]
    pub const fn new(block_tree: Arc<RwLock<BlockTree>>) -> Self {
        Self {
            block_tree,
            block_body_source: None,
        }
    }

    /// Returns `self` with a durable body source for metadata-only headers.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    fn load_active_block_at_height(&self, current_height: u32, hash: BlockHash) -> Option<Block> {
        let bytes = self
            .block_body_source
            .as_ref()?
            .block_body(current_height, hash)?;
        let block = Block::consensus_decode(&bytes).ok()?;
        if block.block_hash() != hash {
            return None;
        }
        let tree = self.block_tree.read();
        (tree.active_height_of(tree.tip()?.tip_id, hash.into()) == Some(current_height))
            .then_some(block)
    }
}

impl core::fmt::Debug for ActiveChainQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ActiveChainQuery").finish_non_exhaustive()
    }
}

impl ChainQuery for ActiveChainQuery {
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
            .find_map(|hash| tree.active_height_of(tip.tip_id, (*hash).into()))
            .and_then(|height| height.checked_add(1))
            .unwrap_or(1);
        let has_stop = stop_hash != BlockHash::default();
        let mut headers = Vec::new();

        while height <= tip.height && headers.len() < limit {
            let Some(node_id) = tree.node_at_height_from(tip.tip_id, height) else {
                break;
            };
            let Ok(node) = tree.node(node_id) else {
                break;
            };
            let reached_stop = has_stop && BlockHash::from(node.hash) == stop_hash;
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

    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Block) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        let mut outcome = InventoryServing::default();
        for item in items {
            let Some(hash) = inventory_block_hash(item) else {
                outcome.not_found.push(*item);
                continue;
            };
            let current_height = {
                let tree = self.block_tree.read();
                tree.tip()
                    .and_then(|tip| tree.active_height_of(tip.tip_id, hash.into()))
            };
            let Some(current_height) = current_height else {
                outcome.not_found.push(*item);
                continue;
            };
            if !headroom() {
                outcome.halted = true;
                return Ok(outcome);
            }
            if let Some(block) = self.load_active_block_at_height(current_height, hash) {
                serve(block)?;
            } else {
                outcome.not_found.push(*item);
            }
        }
        Ok(outcome)
    }
}

fn header_for_active_stop(
    tree: &BlockTree,
    tip_id: bitcoin_rs_chain::NodeId,
    stop_hash: BlockHash,
) -> Option<Header> {
    if stop_hash == BlockHash::default() {
        return None;
    }
    let height = tree.active_height_of(tip_id, stop_hash.into())?;
    let node_id = tree.node_at_height_from(tip_id, height)?;
    Some(tree.node(node_id).ok()?.header)
}

fn inventory_block_hash(item: &Inventory) -> Option<BlockHash> {
    match *item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(BlockHash::from(
            Hash256::from_le_bytes(hash.as_byte_array()),
        )),
        Inventory::Error
        | Inventory::Transaction(_)
        | Inventory::CompactBlock(_)
        | Inventory::WTx(_)
        | Inventory::WitnessTransaction(_)
        | Inventory::Unknown { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{BlockHash as WireBlockHash, Txid as WireTxid};
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::consensus_bytes;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SingleBlockSource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
    }

    impl BlockBodySource for SingleBlockSource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            (height == self.height && hash == self.hash).then(|| self.body.clone())
        }
    }

    struct CountingBodySource {
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        loads: AtomicUsize,
        tripwire: Option<usize>,
    }

    impl BlockBodySource for CountingBodySource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            if let Some(limit) = self.tripwire {
                assert!(
                    self.loads.load(Ordering::Relaxed) < limit,
                    "body loaded beyond the production-gate bound"
                );
            }
            self.loads.fetch_add(1, Ordering::Relaxed);
            self.bodies
                .iter()
                .find(|(entry_height, entry_hash, _)| {
                    *entry_height == height && *entry_hash == hash
                })
                .map(|(_, _, body)| body.clone())
        }
    }

    fn serve_collect(
        query: &ActiveChainQuery,
        items: &[Inventory],
    ) -> Result<(InventoryServing, Vec<Block>), PeerError> {
        let blocks = RefCell::new(Vec::new());
        let outcome = query.serve_inventory_blocks(items, &|| true, &mut |block| {
            blocks.borrow_mut().push(block);
            Ok(())
        })?;
        Ok((outcome, blocks.into_inner()))
    }

    fn wire_hash(hash: BlockHash) -> WireBlockHash {
        WireBlockHash::from_byte_array(*hash.as_bytes())
    }

    #[test]
    fn getheaders_empty_locator_returns_only_active_stop() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = seed_headers(3);
        let stop = headers[2].compute_hash();
        let query = query_with(headers)?;

        let response = query.headers_after(&[], stop, 2);

        assert_eq!(header_hashes(&response), vec![stop]);
        Ok(())
    }

    #[test]
    fn getheaders_empty_locator_unknown_or_zero_stop_returns_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let query = query_with(headers)?;

        assert!(query.headers_after(&[], BlockHash::default(), 2).is_empty());
        assert!(
            query
                .headers_after(&[], BlockHash::from(Hash256::from_le_bytes(&[9; 32])), 2)
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn getheaders_unknown_locator_starts_after_genesis() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let expected = vec![headers[1].compute_hash(), headers[2].compute_hash()];
        let query = query_with(headers)?;

        let response = query.headers_after(
            &[BlockHash::from(Hash256::from_le_bytes(&[42; 32]))],
            BlockHash::default(),
            10,
        );

        assert_eq!(header_hashes(&response), expected);
        Ok(())
    }

    #[test]
    fn getheaders_after_locator_stops_at_stop_hash() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(5);
        let locator = headers[1].compute_hash();
        let stop = headers[3].compute_hash();
        let expected = vec![headers[2].compute_hash(), stop];
        let query = query_with(headers)?;

        let response = query.headers_after(&[locator], stop, 10);

        assert_eq!(header_hashes(&response), expected);
        Ok(())
    }

    #[test]
    fn getheaders_ignores_stale_fork_locator_and_stop() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let active1 = test_header(genesis.compute_hash(), 1);
        let active2 = test_header(active1.compute_hash(), 2);
        let fork1 = test_header(genesis.compute_hash(), 42);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let active1_id = tree.insert_node(Some(genesis_id), active1, NodeStatus::Active)?;
        tree.insert_node(Some(active1_id), active2, NodeStatus::Active)?;
        tree.insert_node(Some(genesis_id), fork1, NodeStatus::Stale)?;
        let query = ActiveChainQuery::new(Arc::new(RwLock::new(tree)));

        let response = query.headers_after(&[fork1.compute_hash()], BlockHash::default(), 10);

        assert_eq!(
            header_hashes(&response),
            vec![active1.compute_hash(), active2.compute_hash()]
        );
        assert!(
            query
                .headers_after(&[], fork1.compute_hash(), 10)
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn getdata_decodes_active_body_from_source_and_reports_missing_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let body_source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        });
        let txid = WireTxid::all_zeros();
        let missing = Inventory::WitnessBlock(WireBlockHash::from_byte_array([8; 32]));
        let query = query_with(headers)?.with_block_body_source(body_source);

        let (outcome, blocks) = serve_collect(
            &query,
            &[
                Inventory::Block(wire_hash(block.block_hash())),
                Inventory::Transaction(txid),
                missing,
            ],
        )?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_hash(), block.block_hash());
        assert_eq!(
            outcome.not_found,
            vec![Inventory::Transaction(txid), missing]
        );
        assert!(!outcome.halted);
        Ok(())
    }

    #[test]
    fn getdata_rejects_pruned_or_missing_body() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let hash = headers[1].compute_hash();
        let query = query_with(headers)?;

        let (outcome, blocks) = serve_collect(&query, &[Inventory::Block(wire_hash(hash))])?;

        assert!(blocks.is_empty());
        assert_eq!(outcome.not_found, vec![Inventory::Block(wire_hash(hash))]);
        Ok(())
    }

    #[test]
    fn getdata_reads_metadata_only_body_from_source() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: Vec::new(),
        };
        let body_source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        });
        let query = query_with(headers)?.with_block_body_source(body_source);

        let (outcome, blocks) =
            serve_collect(&query, &[Inventory::Block(wire_hash(block.block_hash()))])?;

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_hash(), block.block_hash());
        assert!(outcome.not_found.is_empty());
        Ok(())
    }

    #[test]
    fn p2p_chain_streams_each_body_once_in_order() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(4);
        let blocks: Vec<Block> = headers[1..]
            .iter()
            .map(|header| Block {
                header: *header,
                txs: Vec::new(),
            })
            .collect();
        let bodies: Vec<(u32, BlockHash, Vec<u8>)> = (1_u32..)
            .zip(&blocks)
            .map(|(height, block)| (height, block.block_hash(), consensus_bytes(block)))
            .collect();
        let body_source = Arc::new(CountingBodySource {
            bodies,
            loads: AtomicUsize::new(0),
            tripwire: None,
        });
        let unknown_a = Inventory::WitnessBlock(WireBlockHash::from_byte_array([21; 32]));
        let unknown_b = Inventory::WitnessBlock(WireBlockHash::from_byte_array([22; 32]));
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let items = vec![
            unknown_a,
            Inventory::WitnessBlock(wire_hash(blocks[0].block_hash())),
            unknown_b,
            Inventory::WitnessBlock(wire_hash(blocks[1].block_hash())),
            Inventory::WitnessBlock(wire_hash(blocks[2].block_hash())),
        ];

        let (outcome, served) = serve_collect(&query, &items)?;

        let served_hashes: Vec<BlockHash> = served.iter().map(Block::block_hash).collect();
        assert_eq!(
            served_hashes,
            vec![
                blocks[0].block_hash(),
                blocks[1].block_hash(),
                blocks[2].block_hash(),
            ],
            "bodies stream in request order"
        );
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 3);
        assert_eq!(outcome.not_found, vec![unknown_a, unknown_b]);
        assert!(!outcome.halted);
        Ok(())
    }

    #[test]
    fn p2p_chain_does_not_gate_unknown_blocks() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let body_source = Arc::new(CountingBodySource {
            bodies: Vec::new(),
            loads: AtomicUsize::new(0),
            tripwire: Some(0),
        });
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let unknown = Inventory::WitnessBlock(WireBlockHash::from_byte_array([23; 32]));
        let headroom_calls = AtomicUsize::new(0);
        let served = RefCell::new(Vec::new());

        let outcome = query.serve_inventory_blocks(
            &[unknown],
            &|| {
                headroom_calls.fetch_add(1, Ordering::Relaxed);
                false
            },
            &mut |block| {
                served.borrow_mut().push(block);
                Ok(())
            },
        )?;

        assert_eq!(outcome.not_found, vec![unknown]);
        assert!(!outcome.halted);
        assert!(served.borrow().is_empty());
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 0);
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn p2p_chain_halts_at_gate_without_loading() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(4);
        let blocks: Vec<Block> = headers[1..]
            .iter()
            .map(|header| Block {
                header: *header,
                txs: Vec::new(),
            })
            .collect();
        let bodies: Vec<(u32, BlockHash, Vec<u8>)> = (1_u32..)
            .zip(&blocks)
            .map(|(height, block)| (height, block.block_hash(), consensus_bytes(block)))
            .collect();
        let body_source = Arc::new(CountingBodySource {
            bodies,
            loads: AtomicUsize::new(0),
            tripwire: Some(2),
        });
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let items: Vec<Inventory> = blocks
            .iter()
            .map(|block| Inventory::WitnessBlock(wire_hash(block.block_hash())))
            .collect();
        let headroom_calls = AtomicUsize::new(0);
        let served = RefCell::new(Vec::new());

        let outcome = query.serve_inventory_blocks(
            &items,
            &|| {
                let calls = headroom_calls.fetch_add(1, Ordering::Relaxed);
                calls < 2
            },
            &mut |block| {
                served.borrow_mut().push(block);
                Ok(())
            },
        )?;

        assert!(outcome.halted);
        assert_eq!(served.borrow().len(), 2);
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 2);
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 3);
        Ok(())
    }

    fn query_with(headers: Vec<Header>) -> Result<ActiveChainQuery, bitcoin_rs_chain::ChainError> {
        let mut tree = BlockTree::new();
        let mut parent = None;
        for header in headers {
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        Ok(ActiveChainQuery::new(Arc::new(RwLock::new(tree))))
    }

    fn seed_headers(count: u32) -> Vec<Header> {
        let mut headers = Vec::new();
        let mut prev = BlockHash::default();
        for nonce in 0..count {
            let header = test_header(prev, nonce);
            prev = header.compute_hash();
            headers.push(header);
        }
        headers
    }

    fn test_header(prev_blockhash: BlockHash, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: nonce,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        }
    }

    fn header_hashes(headers: &[Header]) -> Vec<BlockHash> {
        headers.iter().map(Header::compute_hash).collect()
    }
}
