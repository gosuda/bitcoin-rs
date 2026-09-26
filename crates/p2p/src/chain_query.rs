//! Active-chain serving for `getheaders` / `getdata`.
//!
//! Locator interpretation, header-walk policy, and inventory serving live
//! here. [`BlockTree`] answers active-chain identity; [`BlockBodySource`]
//! supplies bodies.

use std::sync::Arc;

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds};
use bitcoin::blockdata::block::Block as RegistryBlock;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin_rs_chain::{BlockBodySource, BlockTree, BlockTreeReader, ChainWork};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, Network};
#[cfg(test)]
use parking_lot::RwLock;

use crate::dispatch::{ChainQuery, InventoryServing};
use crate::wire::{Message, PeerError};

/// Depth from the active tip for which a `getdata` of a block is still worth
/// answering with a `cmpctblock`. Deeper, a peer's mempool has almost
/// certainly moved on, so the full witness-bearing body is served instead
/// (Core 31.1 `net_processing.cpp:141-145,2705-2721,4590-4624`).
const MAX_CMPCTBLOCK_DEPTH: u32 = 5;

/// Depth from the active tip for which a `getblocktxn` is still answered
/// with a `blocktxn`. Deeper, Core sends the whole block rather than let a
/// peer reconstruct one it cannot have hinted.
const MAX_BLOCKTXN_DEPTH: u32 = 10;

/// Read-only active-chain view for P2P `getheaders` / `getdata`.
#[derive(Clone)]
pub struct ActiveChainQuery {
    block_tree: BlockTreeReader,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    network: Network,
}

impl ActiveChainQuery {
    /// Builds a P2P chain query view over shared active-chain state of one
    /// network.
    ///
    /// PRE: `block_tree` holds only headers of `network`.
    /// POST: returns the view; serving queries refuse below the network's
    ///   minimum chain work.
    /// INVARIANT: the view's network never changes after construction.
    #[must_use]
    pub fn new(block_tree: BlockTreeReader, network: Network) -> Self {
        Self {
            block_tree,
            block_body_source: None,
            network,
        }
    }

    /// Returns `self` with a durable body source for metadata-only headers.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    /// The active height of one block with the tip height it was observed
    /// under, both read in one guard so a depth is a snapshot of one tree
    /// state. `None` when no tip exists or the hash is not on the active
    /// chain.
    fn active_position(&self, hash: BlockHash) -> Option<(u32, u32)> {
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        let height = tree.active_height_of(tip.tip_id, hash.into())?;
        Some((tip.height, height))
    }

    /// The validated stored body of one active block, with the tip height
    /// re-read in the guard that proved its membership after the load.
    ///
    /// PRE: `height` is the block's active height as first observed.
    /// POST: return the raw consensus payload and the observing tip height
    /// only while the block is still active at `height`; `None` leaves the
    /// request unanswered.
    /// INVARIANT: no body is served for a block that left the active chain,
    /// and the tip height comes from the same guard as that proof, so a
    /// depth decision is never made from two different tree states.
    fn load_active_block(&self, height: u32, hash: BlockHash) -> Option<(bytes::Bytes, u32)> {
        let bytes = self.block_body_source.as_ref()?.block_body(height, hash)?;
        let header = bytes
            .get(..80)
            .and_then(|header| Header::consensus_decode(header).ok())?;
        if header.compute_hash() != hash {
            return None;
        }
        // Validate the complete stored body before serving its raw bytes. This
        // preserves the wire-byte optimization without forwarding corruption.
        Block::consensus_decode(&bytes).ok()?;
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        (tree.active_height_of(tip.tip_id, hash.into()) == Some(height))
            .then(|| (bytes::Bytes::from(bytes), tip.height))
    }

    /// The stored body as a `block` payload, witnesses retained.
    fn full_block_response(&self, height: u32, hash: BlockHash) -> Option<Message> {
        self.load_active_block(height, hash)
            .map(|(body, _)| Message::BlockPayload(body))
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
        // A node whose active chain has not reached the network's minimum
        // work is still syncing: it answers `getheaders` with the empty
        // response rather than feeding a peer its low-work branch, exactly
        // as Core refuses to serve headers below the assumed-valid floor
        // (`net_processing.cpp:3010-3018,4648-4657`).
        if tip.chainwork < ChainWork::from_be_bytes(self.network.minimum_chain_work()) {
            return Vec::new();
        }
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

    /// The active tip's header time, read from the same tree the serving
    /// paths use.
    fn best_block_time(&self) -> Option<u32> {
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        tree.node(tip.tip_id).ok().map(|node| node.header.time)
    }

    fn serve_inventory_blocks(
        &self,
        items: &[Inventory],
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
        serve: &mut dyn FnMut(Message) -> Result<(), PeerError>,
    ) -> Result<InventoryServing, PeerError> {
        let mut outcome = InventoryServing::default();
        for item in items {
            let Some(request) = inventory_block_request(item) else {
                outcome.not_found.push(*item);
                continue;
            };
            let Some((tip_height, height)) = self.active_position(request.hash()) else {
                outcome.not_found.push(*item);
                continue;
            };
            if !headroom() {
                outcome.halted = true;
                return Ok(outcome);
            }
            let response = self.response_for(request, tip_height, height, compact_version);
            match response {
                Some(message) => serve(message)?,
                None => outcome.not_found.push(*item),
            }
        }
        Ok(outcome)
    }

    /// PRE: `request` carries decoded absolute, strictly increasing
    /// transaction indexes for one block.
    /// POST: return the `blocktxn` reply for a block within
    /// [`MAX_BLOCKTXN_DEPTH`] of the active tip, the whole witness-bearing
    /// `block` for a deeper one, and `None` for a block this node cannot
    /// serve; `Err` reports an index past the end of the body or a
    /// saturated `headroom` gate, matching the `getdata` production-halt
    /// disconnect.
    /// INVARIANT: a deep request is never answered with a small `blocktxn`
    /// and never left unanswered while its body is available (Core 31.1
    /// `net_processing.cpp:4590-4624`); `headroom` is evaluated immediately
    /// before the body load, so a saturated gate materializes no body.
    fn block_transactions(
        &self,
        request: &BlockTransactionsRequest,
        headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        let hash = native_block_hash(request.block_hash);
        let Some((tip_height, height)) = self.active_position(hash) else {
            return Ok(None);
        };
        let deep = beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH);
        if !headroom() {
            return Err(PeerError::Protocol(
                "getblocktxn serving halted: outbound production gate",
            ));
        }
        let Some((payload, tip_height)) = self.load_active_block(height, hash) else {
            return Ok(None);
        };
        // The tip may have moved while the body was read; the re-observed
        // depth decides the reply, so a moving tip cannot keep an old block
        // eligible for a compact answer.
        if deep || beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH) {
            return Ok(Some(Message::BlockPayload(payload)));
        }
        let Ok(block) = bitcoin::consensus::encode::deserialize::<RegistryBlock>(payload.as_ref())
        else {
            return Ok(None);
        };
        // Index bounds apply to both reply shapes: a deep request with an
        // out-of-range index disconnects the same as a shallow one.
        let tx_count = u64::try_from(block.txdata.len()).unwrap_or(u64::MAX);
        if request.indexes.last().is_some_and(|last| *last >= tx_count) {
            return Err(PeerError::Protocol("getblocktxn index out of range"));
        }
        // The tip may have moved while the body was read; the re-observed
        // depth decides the reply, so a moving tip cannot keep an old block
        // eligible for a compact answer.
        if deep || beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH) {
            return Ok(Some(Message::BlockPayload(payload)));
        }
        BlockTransactions::from_request(request, &block)
            .map(|transactions| Some(Message::BlockTxn(BlockTxn { transactions })))
            .map_err(|_| PeerError::Protocol("getblocktxn index out of range"))
    }
}

impl ActiveChainQuery {
    /// Builds one `cmpctblock` for an active-chain body at the requesting
    /// peer's negotiated BIP152 version. `None` (no negotiation, unknown
    /// version, undecodable or stale body) leaves the item in `not_found`.
    fn compact_block_for(
        &self,
        height: u32,
        hash: BlockHash,
        compact_version: Option<u64>,
    ) -> Option<Message> {
        let version = u32::try_from(compact_version?).ok()?;
        if version != 1 && version != 2 {
            return None;
        }
        let (payload, tip_height) = self.load_active_block(height, hash)?;
        if beyond_depth(tip_height, height, MAX_CMPCTBLOCK_DEPTH) {
            return Some(Message::BlockPayload(payload));
        }
        let block =
            bitcoin::consensus::encode::deserialize::<RegistryBlock>(payload.as_ref()).ok()?;
        let cmpct = HeaderAndShortIds::from_block(&block, fresh_nonce(), version, &[]).ok()?;
        Some(Message::CmpctBlock(CmpctBlock {
            compact_block: cmpct,
        }))
    }

    /// The reply for one resolved block request, or `None` when its body is
    /// unavailable and the item belongs in `not_found`.
    fn response_for(
        &self,
        request: BlockRequest,
        tip_height: u32,
        height: u32,
        compact_version: Option<u64>,
    ) -> Option<Message> {
        match request {
            BlockRequest::Full(hash) => self.full_block_response(height, hash),
            // A peer asking for an old block almost certainly cannot match it
            // against a useful mempool, so the compact request is served as
            // the whole body, whatever it negotiated.
            BlockRequest::Compact(hash)
                if beyond_depth(tip_height, height, MAX_CMPCTBLOCK_DEPTH) =>
            {
                self.full_block_response(height, hash)
            }
            BlockRequest::Compact(hash) => self.compact_block_for(height, hash, compact_version),
        }
    }
}

/// Whether one block sits deeper below the active tip than `limit`.
const fn beyond_depth(tip_height: u32, height: u32, limit: u32) -> bool {
    tip_height.saturating_sub(height) > limit
}

/// Which active-chain body one block-typed inventory item asks for.
#[derive(Clone, Copy, Debug)]
enum BlockRequest {
    Full(BlockHash),
    Compact(BlockHash),
}

impl BlockRequest {
    const fn hash(self) -> BlockHash {
        match self {
            Self::Full(hash) | Self::Compact(hash) => hash,
        }
    }
}

fn native_block_hash(hash: bitcoin::BlockHash) -> BlockHash {
    BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
}

fn inventory_block_request(item: &Inventory) -> Option<BlockRequest> {
    match *item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
            Some(BlockRequest::Full(native_block_hash(hash)))
        }
        Inventory::CompactBlock(hash) => Some(BlockRequest::Compact(native_block_hash(hash))),
        Inventory::Error
        | Inventory::Transaction(_)
        | Inventory::WTx(_)
        | Inventory::WitnessTransaction(_)
        | Inventory::Unknown { .. } => None,
    }
}

/// Fresh BIP152 serving nonce. `RandomState` draws fresh keys per call, so
/// two responses never share one (BIP152: SHOULD NOT reuse across blocks).
fn fresh_nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{BlockHash as WireBlockHash, Txid as WireTxid};
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::consensus_bytes;
    use bitcoin_rs_primitives::{Block, CompactTarget, Tx};
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
        let outcome = query.serve_inventory_blocks(items, None, &|| true, &mut |message| {
            let Message::BlockPayload(payload) = message else {
                return Ok(());
            };
            blocks.borrow_mut().push(Block::consensus_decode(&payload)?);
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
        let query = ActiveChainQuery::new(
            BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            Network::Regtest,
        );

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

    /// A node whose active chain sits below its network's assumed-work
    /// floor is still syncing: it must answer `getheaders` with the empty
    /// response rather than serve its low-work branch to the rest of the
    /// network (`net_processing.cpp:3010-3018,4648-4657`).
    #[test]
    fn low_work_chain_serves_no_headers() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = test_header(BlockHash::default(), 0);
        let first = test_header(genesis.compute_hash(), 1);
        let second = test_header(first.compute_hash(), 2);
        let low_work_tree = || -> Result<BlockTree, bitcoin_rs_chain::ChainError> {
            let mut tree = BlockTree::new();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let first_id = tree.insert_node(Some(genesis_id), first, NodeStatus::Active)?;
            tree.insert_node(Some(first_id), second, NodeStatus::Active)?;
            Ok(tree)
        };
        // Mainnet's floor is far above three regtest-easy headers: the
        // serving path must go quiet below it.
        let mainnet = ActiveChainQuery::new(
            BlockTreeReader::new(Arc::new(RwLock::new(low_work_tree()?))),
            Network::Mainnet,
        );
        assert!(
            mainnet
                .headers_after(&[genesis.compute_hash()], BlockHash::default(), 10)
                .is_empty(),
            "a below-floor node must answer getheaders with nothing"
        );
        assert!(
            mainnet
                .headers_after(&[], second.compute_hash(), 10)
                .is_empty(),
            "the empty-locator stop-hash path must refuse too"
        );

        let regtest = ActiveChainQuery::new(
            BlockTreeReader::new(Arc::new(RwLock::new(low_work_tree()?))),
            Network::Regtest,
        );
        assert_eq!(
            header_hashes(&regtest.headers_after(
                &[genesis.compute_hash()],
                BlockHash::default(),
                10
            )),
            vec![first.compute_hash(), second.compute_hash()],
            "a network with a zero floor must keep serving its chain"
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
            None,
            &|| {
                headroom_calls.fetch_add(1, Ordering::Relaxed);
                false
            },
            &mut |message| {
                served.borrow_mut().push(message);
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
            None,
            &|| {
                let calls = headroom_calls.fetch_add(1, Ordering::Relaxed);
                calls < 2
            },
            &mut |message| {
                served.borrow_mut().push(message);
                Ok(())
            },
        )?;

        assert!(outcome.halted);
        assert_eq!(served.borrow().len(), 2);
        assert_eq!(body_source.loads.load(Ordering::Relaxed), 2);
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 3);
        Ok(())
    }

    /// A `getblocktxn` for a deep block — the branch that would otherwise
    /// materialize the whole body — loads nothing and stays unanswered while
    /// the production gate is saturated, mirroring the `getdata` gate
    /// behaviour (`serve_inventory_blocks`).
    #[test]
    fn getblocktxn_halts_at_gate_without_loading() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(12);
        let deep_block = block_at(&headers, 0)?;
        let body_source = Arc::new(CountingBodySource {
            bodies: vec![(0, deep_block.block_hash(), consensus_bytes(&deep_block))],
            loads: AtomicUsize::new(0),
            tripwire: Some(0),
        });
        let query = query_with(headers)?.with_block_body_source(body_source.clone());
        let request = bitcoin::bip152::BlockTransactionsRequest {
            block_hash: wire_hash(deep_block.block_hash()),
            indexes: vec![1],
        };
        let headroom_calls = AtomicUsize::new(0);

        let reply = query.block_transactions(&request, &|| {
            headroom_calls.fetch_add(1, Ordering::Relaxed);
            false
        });

        assert!(
            matches!(reply, Err(PeerError::Protocol(_))),
            "a saturated gate disconnects like the getdata production halt"
        );
        assert_eq!(
            body_source.loads.load(Ordering::Relaxed),
            0,
            "a saturated gate must not load the block body"
        );
        assert_eq!(headroom_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[test]
    fn getdata_msg_cmpct_block_serves_negotiated_profile_and_notfound_without()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: vec![test_tx(1), test_tx(2)],
        };
        let body_source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        });
        let query = query_with(headers)?.with_block_body_source(body_source);
        let item = Inventory::CompactBlock(wire_hash(block.block_hash()));

        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], None, &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert_eq!(outcome.not_found, vec![item]);
        assert!(served.is_empty());

        let mut served = Vec::new();
        let outcome = query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        assert!(outcome.not_found.is_empty() && !outcome.halted);
        let [Message::CmpctBlock(cmpct)] = served.as_slice() else {
            panic!("expected exactly one cmpctblock response");
        };
        assert_eq!(
            native_block_hash(cmpct.compact_block.header.block_hash()),
            block.block_hash()
        );
        assert_eq!(cmpct.compact_block.prefilled_txs.len(), 1);
        assert_eq!(cmpct.compact_block.short_ids.len(), 1);
        Ok(())
    }

    /// A chain view over `headers` whose body source serves `block` at
    /// `height`.
    fn chain_at(
        headers: &[Header],
        height: u32,
        block: &Block,
    ) -> Result<ActiveChainQuery, bitcoin_rs_chain::ChainError> {
        let source = SingleBlockSource {
            height,
            hash: block.block_hash(),
            body: consensus_bytes(block),
        };
        Ok(query_with(headers.to_vec())?.with_block_body_source(Arc::new(source)))
    }

    /// The block at `height` of a `seed_headers` chain, with two transactions.
    fn block_at(headers: &[Header], height: u32) -> Result<Block, Box<dyn std::error::Error>> {
        let index = usize::try_from(height)?;
        Ok(Block {
            header: headers[index],
            txs: vec![test_tx(1), test_tx(2)],
        })
    }

    /// The reply to a `getblocktxn` for transaction index 1 of the block at
    /// `height`.
    fn blocktxn_reply(
        headers: &[Header],
        height: u32,
    ) -> Result<Message, Box<dyn std::error::Error>> {
        let block = block_at(headers, height)?;
        let query = chain_at(headers, height, &block)?;
        let request = bitcoin::bip152::BlockTransactionsRequest {
            block_hash: wire_hash(block.block_hash()),
            indexes: vec![1],
        };
        Ok(query
            .block_transactions(&request, &|| true)?
            .ok_or("an active body is always answered")?)
    }

    /// The reply to a compact `getdata` for the block at `height`, negotiated
    /// at v2.
    fn compact_reply(
        headers: &[Header],
        height: u32,
    ) -> Result<Message, Box<dyn std::error::Error>> {
        let block = block_at(headers, height)?;
        let query = chain_at(headers, height, &block)?;
        let item = Inventory::CompactBlock(wire_hash(block.block_hash()));
        let mut served = Vec::new();
        query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |message| {
            served.push(message);
            Ok(())
        })?;
        Ok(served.pop().ok_or("exactly one reply")?)
    }

    /// The body a served full-block payload carries, witnesses included.
    fn payload_body(payload: &bytes::Bytes) -> Result<RegistryBlock, Box<dyn std::error::Error>> {
        Ok(bitcoin::consensus::encode::deserialize::<RegistryBlock>(
            payload.as_ref(),
        )?)
    }

    /// A shallow `getblocktxn` is answered with the requested bodies, an
    /// index past the end of the block disconnects the peer, and a block
    /// this node cannot serve leaves the request unanswered.
    #[test]
    fn getblocktxn_answers_active_body_and_disconnects_on_out_of_range_index()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = block_at(&headers, 1)?;
        let query = chain_at(&headers, 1, &block)?;
        let wire = wire_hash(block.block_hash());

        let reply = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: wire,
                indexes: vec![1],
            },
            &|| true,
        )?;
        let Some(Message::BlockTxn(txn)) = &reply else {
            panic!("a shallow request is answered with blocktxn, got {reply:?}");
        };
        assert_eq!(txn.transactions.block_hash, wire);
        assert_eq!(txn.transactions.transactions.len(), 1);

        let out_of_range = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: wire,
                indexes: vec![7],
            },
            &|| true,
        );
        assert!(
            matches!(out_of_range, Err(PeerError::Protocol(_))),
            "an out-of-range index is a protocol disconnect"
        );

        let unknown = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([9; 32]),
                indexes: vec![0],
            },
            &|| true,
        )?;
        assert!(unknown.is_none(), "an unservable block stays unanswered");
        Ok(())
    }

    /// A block within [`MAX_BLOCKTXN_DEPTH`] of the active tip is answered
    /// with a `blocktxn`; a deeper one gets the whole witness-bearing
    /// `block`, never a small `blocktxn`, an inventory announcement, or
    /// silence (Core 31.1 `net_processing.cpp:4590-4624`).
    #[test]
    fn getblocktxn_depth_boundary_uses_full_block_beyond_ten()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(12);

        let at_the_bound = blocktxn_reply(&headers, 1)?;
        let Message::BlockTxn(txn) = &at_the_bound else {
            panic!("a block at the bound is answered with blocktxn, got {at_the_bound:?}");
        };
        assert_eq!(txn.transactions.transactions.len(), 1);

        let one_deeper = blocktxn_reply(&headers, 0)?;
        let Message::BlockPayload(payload) = &one_deeper else {
            panic!("a deeper block is answered with the whole block, got {one_deeper:?}");
        };
        assert_eq!(payload_body(payload)?.txdata.len(), 2, "witnesses retained");
        Ok(())
    }

    /// A compact `getdata` within [`MAX_CMPCTBLOCK_DEPTH`] of the tip is
    /// answered with a `cmpctblock`; a deeper one with the whole
    /// witness-bearing `block` (Core 31.1 `net_processing.cpp:2705-2721`).
    #[test]
    fn compact_depth_boundary_uses_full_block_beyond_five() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = seed_headers(12);

        let at_the_bound = compact_reply(&headers, 6)?;
        assert!(
            matches!(at_the_bound, Message::CmpctBlock(_)),
            "a block at the compact bound is served compact, got {at_the_bound:?}"
        );

        let one_deeper = compact_reply(&headers, 5)?;
        let Message::BlockPayload(payload) = &one_deeper else {
            panic!("a deeper block is served as the whole block, got {one_deeper:?}");
        };
        assert_eq!(payload_body(payload)?.txdata.len(), 2, "witnesses retained");
        Ok(())
    }

    /// A served compact block always prefills transaction zero — the coinbase
    /// — and short-ID-encodes the rest, under both identity versions
    /// (Core 31.1 `blockencodings.cpp:20-31`).
    #[test]
    fn compact_prefills_coinbase_under_both_v1_v2() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let block = block_at(&headers, 2)?;
        let expected = consensus_bytes(&block.txs[0]);

        for version in [1_u64, 2] {
            let query = chain_at(&headers, 2, &block)?;
            let item = Inventory::CompactBlock(wire_hash(block.block_hash()));
            let mut served = Vec::new();
            query.serve_inventory_blocks(&[item], Some(version), &|| true, &mut |message| {
                served.push(message);
                Ok(())
            })?;
            let [Message::CmpctBlock(cmpct)] = served.as_slice() else {
                panic!("v{version} must be served as a cmpctblock, got {served:?}");
            };
            let prefills = &cmpct.compact_block.prefilled_txs;
            assert_eq!(prefills.len(), 1, "v{version}: the coinbase is prefilled");
            assert_eq!(u64::from(prefills[0].idx), 0, "v{version}: at index zero");
            assert_eq!(
                bitcoin::consensus::encode::serialize(&prefills[0].tx),
                expected,
                "v{version}: the prefilled body is the block's coinbase"
            );
            assert_eq!(cmpct.compact_block.short_ids.len(), 1);
        }
        Ok(())
    }

    fn test_tx(byte: u8) -> Tx {
        use bitcoin_rs_primitives::{
            Amount, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        };
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn query_with(headers: Vec<Header>) -> Result<ActiveChainQuery, bitcoin_rs_chain::ChainError> {
        let mut tree = BlockTree::new();
        let mut parent = None;
        for header in headers {
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        Ok(ActiveChainQuery::new(
            BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            Network::Regtest,
        ))
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
