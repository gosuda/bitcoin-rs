//! Active-chain header walks and hash-addressed block serving.
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
use bitcoin_rs_chain::{
    BlockBodySource, BlockTree, BlockTreeReader, ChainWork, NodeStatus, TipReader,
};
use bitcoin_rs_primitives::layout::{ParsedBlock, ParsedTransaction};
use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Network, deserialize};
#[cfg(test)]
use parking_lot::RwLock;

use crate::dispatch::{ChainQuery, CommittedTip, InventoryServing};
use crate::wire::{Message, PeerError};

/// Depth from the active tip for which a `getdata` of a block is still worth
/// answering with a `cmpctblock`.
const MAX_CMPCTBLOCK_DEPTH: u32 = 5;

/// Depth from the active tip for which a `getblocktxn` is still answered with a
/// `blocktxn`.
const MAX_BLOCKTXN_DEPTH: u32 = 10;

/// Core 31.1 `BlockRequestAllowed`: stale-block fingerprinting bound, in seconds.
const STALE_RELAY_AGE_LIMIT: u32 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy)]
enum ServingPolicy {
    /// Unsolicited announcements must still name the applied, selected chain.
    Announcement,
    /// Full/compact inventory replies, including deep getblocktxn fallback.
    Inventory,
    /// Shallow getblocktxn uses stored data without the stale-age gate in Core.
    BlockTransactions,
}

/// Read-only active-chain view for P2P `getheaders` / `getdata`.
#[derive(Clone)]
pub struct ActiveChainQuery {
    block_tree: BlockTreeReader,
    applied_tip: TipReader,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    network: Network,
}

impl ActiveChainQuery {
    /// Builds a P2P chain query view over shared active-chain state of one
    /// network.
    ///
    /// PRE: `block_tree` holds only headers of `network`, and `applied_tip`
    ///   publishes the chain owner's fully-applied tip.
    /// POST: returns the view; serving queries refuse below the network's
    ///   minimum chain work, and tip-age reads (`best_block_time`) report
    ///   the applied tip, never a fresher-but-unapplied header.
    /// INVARIANT: the view's network never changes after construction.
    #[must_use]
    pub fn new(block_tree: BlockTreeReader, applied_tip: TipReader, network: Network) -> Self {
        Self {
            block_tree,
            applied_tip,
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

    /// Resolve a hash against one tree view and the applied frontier. Header
    /// selection alone is not evidence of body validation. Off-chain inventory
    /// replies require a count recorded by application (or authenticated restore)
    /// and Core's timestamp/proof-equivalent age checks. Shallow getblocktxn
    /// follows Core's `HAVE_DATA` path; the body source proves data availability.
    fn serving_position(&self, hash: BlockHash, policy: ServingPolicy) -> Option<(u32, u32)> {
        let tree = self.block_tree.read();
        let tip = self.applied_tip.load_full()?;
        let applied = tree.node(tip.tip_id).ok()?;
        if applied.hash != tip.hash || applied.height != tip.height {
            return None;
        }
        let node_id = tree.lookup(hash.into())?;
        let node = tree.node(node_id).ok()?;
        if node.status == NodeStatus::Invalid {
            return None;
        }
        let on_applied = tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id);
        let allowed = match policy {
            ServingPolicy::Announcement => {
                let best = tree.tip()?;
                on_applied && tree.active_height_of(best.tip_id, hash.into()) == Some(node.height)
            }
            ServingPolicy::BlockTransactions
                if !beyond_depth(tip.height, node.height, MAX_BLOCKTXN_DEPTH) =>
            {
                true
            }
            ServingPolicy::Inventory | ServingPolicy::BlockTransactions => {
                on_applied
                    || (node.chain_tx_count.get().is_some()
                        && stale_block_is_recent(&tree, node, self.network))
            }
        };
        allowed.then_some((tip.height, node.height))
    }

    /// Load the exact (height, hash) body outside the tree lock, validate its
    /// encoding and hash, then recheck eligibility and applied depth. A reorg
    /// may retain a servable stale block; removal, invalidation or aging out
    /// during I/O must still refuse it. Announcements remain active-only.
    fn load_block(
        &self,
        height: u32,
        hash: BlockHash,
        include_witness: bool,
        policy: ServingPolicy,
    ) -> Option<(bytes::Bytes, u32)> {
        let bytes = self.block_body_source.as_ref()?.block_body(height, hash)?;
        let header = bytes
            .get(..80)
            .and_then(|header| deserialize::<Header>(header).ok())?;
        if header.compute_hash() != hash {
            return None;
        }
        let block = ParsedBlock::parse_exact(&bytes).ok()?;
        let stripped = if !include_witness
            && block
                .transactions()
                .iter()
                .any(ParsedTransaction::is_segwit)
        {
            let mut payload = Vec::with_capacity(bytes.len());
            payload.extend_from_slice(block.span_bytes(block.header_span())?);
            payload.extend_from_slice(block.span_bytes(block.tx_count_span())?);
            for tx in block.transactions() {
                for part in tx.stripped_parts() {
                    payload.extend_from_slice(part);
                }
            }
            Some(payload)
        } else {
            None
        };
        drop(block);
        let bytes = stripped.unwrap_or(bytes);
        let (tip_height, current_height) = self.serving_position(hash, policy)?;
        (current_height == height).then(|| (bytes::Bytes::from(bytes), tip_height))
    }

    /// The stored body as a `block` payload, witnesses retained.
    fn full_block_response(
        &self,
        height: u32,
        hash: BlockHash,
        include_witness: bool,
    ) -> Option<Message> {
        self.load_block(height, hash, include_witness, ServingPolicy::Inventory)
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

    /// The applied tip's header time. Limited-peer admission derives the
    /// local depth from it, so it must read the fully-applied tip the
    /// download policy serves, not the header tip: fresh-but-unapplied
    /// headers would make a lagging node look current and admit
    /// `NODE_NETWORK_LIMITED` peers it cannot download bodies from.
    fn best_block_time(&self) -> Option<u32> {
        let tip = self.applied_tip.load_full()?;
        let tree = self.block_tree.read();
        tree.node(tip.tip_id).ok().map(|node| node.header.time)
    }

    fn active_height(&self, hash: BlockHash) -> Option<u32> {
        let tree = self.block_tree.read();
        let tip = tree.tip()?;
        tree.active_height_of(tip.tip_id, hash.into())
    }

    fn compact_block_for(
        &self,
        height: u32,
        hash: BlockHash,
        compact_version: Option<u64>,
    ) -> Option<Message> {
        self.compact_block_for(height, hash, compact_version, ServingPolicy::Announcement)
    }

    fn committed_tip(&self) -> Option<CommittedTip> {
        let tip = self.applied_tip.load_full()?;
        let tree = self.block_tree.read();
        let active_tip = tree.tip()?;
        let node = tree.node(tip.tip_id).ok()?;
        (node.hash == tip.hash
            && tree.active_height_of(active_tip.tip_id, tip.hash) == Some(tip.height))
        .then(|| CommittedTip {
            height: tip.height,
            hash: BlockHash::from(tip.hash),
            prev_hash: node.header.prev_blockhash,
        })
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
            let Some((tip_height, height)) =
                self.serving_position(request.hash(), ServingPolicy::Inventory)
            else {
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
    /// transaction indexes for one block. `compact_version` is the peer's
    /// servable BIP152 profile.
    /// POST: return the `blocktxn` reply for a block within
    /// [`MAX_BLOCKTXN_DEPTH`] of the active tip, encoded for
    /// `compact_version` (v1 strips witnesses, any other profile keeps
    /// them), the whole witness-bearing `block` for a deeper one, and
    /// `None` for a block this node cannot serve or while the `headroom`
    /// gate is saturated; `Err` reports an index past the end of the body.
    /// INVARIANT: deep requests use full-block inventory policy, including
    /// stale-block age/validation restrictions; shallow stored stale blocks
    /// remain reconstructible (Core 31.1 `net_processing.cpp:4333-4391`).
    /// `headroom` is evaluated immediately before loading, so a saturated
    /// gate materializes no body.
    fn block_transactions(
        &self,
        request: &BlockTransactionsRequest,
        compact_version: Option<u64>,
        headroom: &dyn Fn() -> bool,
    ) -> Result<Option<Message>, PeerError> {
        let hash = native_block_hash(request.block_hash);
        let Some((tip_height, height)) =
            self.serving_position(hash, ServingPolicy::BlockTransactions)
        else {
            return Ok(None);
        };
        let deep = beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH);
        if !headroom() {
            return Ok(None);
        }
        let policy = if deep {
            ServingPolicy::Inventory
        } else {
            ServingPolicy::BlockTransactions
        };
        let Some((payload, tip_height)) = self.load_block(height, hash, true, policy) else {
            return Ok(None);
        };
        if deep || beyond_depth(tip_height, height, MAX_BLOCKTXN_DEPTH) {
            return Ok(Some(Message::BlockPayload(payload)));
        }
        let Ok(block) = bitcoin::consensus::encode::deserialize::<RegistryBlock>(payload.as_ref())
        else {
            return Ok(None);
        };
        BlockTransactions::from_request(request, &block)
            .map(|mut transactions| {
                if compact_version == Some(1) {
                    strip_witnesses(&mut transactions);
                }
                Some(Message::BlockTxn(BlockTxn { transactions }))
            })
            .map_err(|_| PeerError::Misbehavior("getblocktxn index out of range"))
    }
}

/// Clear every witness in a `blocktxn` response for the v1 serving profile.
fn strip_witnesses(transactions: &mut BlockTransactions) {
    for tx in &mut transactions.transactions {
        for input in &mut tx.input {
            input.witness.clear();
        }
    }
}

impl ActiveChainQuery {
    /// Builds one compact response under the caller's announcement or
    /// inventory policy at the negotiated BIP152 version.
    fn compact_block_for(
        &self,
        height: u32,
        hash: BlockHash,
        compact_version: Option<u64>,
        policy: ServingPolicy,
    ) -> Option<Message> {
        self.serving_position(hash, policy)?;
        let version = u32::try_from(compact_version?).ok()?;
        if version != 1 && version != 2 {
            return None;
        }
        let (payload, tip_height) = self.load_block(height, hash, true, policy)?;
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
            BlockRequest::Full {
                hash,
                include_witness,
            } => self.full_block_response(height, hash, include_witness),
            BlockRequest::Compact(hash)
                if beyond_depth(tip_height, height, MAX_CMPCTBLOCK_DEPTH) =>
            {
                self.full_block_response(height, hash, true)
            }
            BlockRequest::Compact(hash) => {
                self.compact_block_for(height, hash, compact_version, ServingPolicy::Inventory)
            }
        }
    }
}

/// Bitcoin Core v31.1 `BlockRequestAllowed` and `GetBlockProofEquivalentTime`
/// at commit 9be056a8a72b624dae9623b2f7bded92c2a21c91. The proof-time difference
/// is signed: a block with at least best-header work is not too old. Overflow
/// in the positive work-time product fails closed, like Core's int64 saturation.
fn stale_block_is_recent(
    tree: &BlockTree,
    node: &bitcoin_rs_chain::BlockTreeNode,
    network: Network,
) -> bool {
    let Some(best_tip) = tree.tip() else {
        return false;
    };
    let Ok(best) = tree.node(best_tip.tip_id) else {
        return false;
    };
    if best.header.time.saturating_sub(node.header.time) >= STALE_RELAY_AGE_LIMIT {
        return false;
    }
    if node.chainwork >= best.chainwork {
        return true;
    }
    let work = bitcoin_rs_chain::block_work(&best.header);
    work != ChainWork::ZERO
        && (best.chainwork - node.chainwork)
            .checked_mul(ChainWork::from(network.target_spacing_seconds()))
            .is_some_and(|scaled| scaled / work < ChainWork::from(STALE_RELAY_AGE_LIMIT))
}

/// Whether one block sits deeper below the active tip than `limit`.
const fn beyond_depth(tip_height: u32, height: u32, limit: u32) -> bool {
    tip_height.saturating_sub(height) > limit
}

/// Which hash-addressed body one block-typed inventory item asks for.
#[derive(Clone, Copy, Debug)]
enum BlockRequest {
    Full {
        hash: BlockHash,
        include_witness: bool,
    },
    Compact(BlockHash),
}

impl BlockRequest {
    const fn hash(self) -> BlockHash {
        match self {
            Self::Full { hash, .. } | Self::Compact(hash) => hash,
        }
    }
}

fn native_block_hash(hash: bitcoin::BlockHash) -> BlockHash {
    BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
}

fn inventory_block_request(item: &Inventory) -> Option<BlockRequest> {
    match *item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => Some(BlockRequest::Full {
            hash: native_block_hash(hash),
            include_witness: matches!(item, Inventory::WitnessBlock(_)),
        }),
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
            blocks.borrow_mut().push(deserialize::<Block>(&payload)?);
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
    fn committed_tip_reads_applied_tip_when_headers_are_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(None, headers[0], NodeStatus::Active)?;
        let applied_id = tree.insert_node(Some(genesis), headers[1], NodeStatus::Active)?;
        let applied = tree.tip().ok_or("missing applied fixture tip")?;
        tree.insert_node(Some(applied_id), headers[2], NodeStatus::Active)?;
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(
            query.committed_tip(),
            Some(CommittedTip {
                height: 1,
                hash: headers[1].compute_hash(),
                prev_hash: headers[0].compute_hash(),
            })
        );
        Ok(())
    }

    #[test]
    fn committed_tip_rejects_an_applied_tip_off_the_active_header_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(None, headers[0], NodeStatus::Active)?;
        tree.insert_node(Some(genesis), headers[1], NodeStatus::Active)?;
        let applied = tree.tip().ok_or("missing applied fixture tip")?;

        let fork = test_header(headers[0].compute_hash(), 100);
        let fork_id = tree.insert_node(Some(genesis), fork, NodeStatus::Active)?;
        let fork_tip = test_header(fork.compute_hash(), 101);
        tree.insert_node(Some(fork_id), fork_tip, NodeStatus::Active)?;

        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(Some(applied));
        let query = ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest);

        assert_eq!(query.committed_tip(), None);
        Ok(())
    }

    #[test]
    fn getheaders_empty_locator_unknown_or_zero_stop_returns_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(3);
        let query = query_with(headers)?;

        assert_eq!(query.headers_after(&[], BlockHash::default(), 2), []);
        assert_eq!(
            query.headers_after(&[], BlockHash::from(Hash256::from_le_bytes(&[9; 32])), 2),
            []
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
        let query = query_over(tree, Network::Regtest);

        let response = query.headers_after(&[fork1.compute_hash()], BlockHash::default(), 10);

        assert_eq!(
            header_hashes(&response),
            vec![active1.compute_hash(), active2.compute_hash()]
        );
        assert_eq!(query.headers_after(&[], fork1.compute_hash(), 10), []);
        Ok(())
    }

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
        let mainnet = query_over(low_work_tree()?, Network::Mainnet);
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

        let regtest = query_over(low_work_tree()?, Network::Regtest);
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
    fn getdata_block_encoding_matches_requested_inventory_on_wire()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::p2p::Magic;
        use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};

        for (tx_count, witness_modulus) in [(2_u8, 0), (2, 1), (3, 2), (253, 2)] {
            let headers = seed_headers(2);
            let mut block = Block {
                header: headers[1],
                txs: (0..tx_count).map(test_tx).collect(),
            };
            for (index, tx) in block.txs.iter_mut().enumerate() {
                if witness_modulus != 0 && index % witness_modulus == 0 {
                    tx.inputs[0].witness = vec![vec![0x51; 32]].into();
                }
                if index % 2 == 0 {
                    tx.outputs.clear();
                } else {
                    tx.outputs[0].script_pubkey.clear();
                }
            }
            let body = consensus_bytes(&block);
            let source = Arc::new(SingleBlockSource {
                height: 1,
                hash: block.block_hash(),
                body: body.clone(),
            });
            let query = query_with(headers)?.with_block_body_source(source.clone());
            let full: RegistryBlock = bitcoin::consensus::deserialize(&body)?;
            let mut stripped = full.clone();
            for tx in &mut stripped.txdata {
                for input in &mut tx.input {
                    input.witness.clear();
                }
            }
            let legacy = Inventory::Block(wire_hash(block.block_hash()));
            let witness = Inventory::WitnessBlock(wire_hash(block.block_hash()));
            let missing = Inventory::Block(WireBlockHash::from_byte_array([9; 32]));
            for items in [[legacy, witness, legacy], [witness, legacy, witness]] {
                let mut served = Vec::new();
                let mut batch = items.to_vec();
                batch.insert(1, missing);
                let outcome =
                    query.serve_inventory_blocks(&batch, None, &|| true, &mut |message| {
                        let mut bytes = Vec::new();
                        crate::wire::write_message(&mut bytes, Magic::REGTEST, &message)?;
                        served.push(bytes);
                        Ok(())
                    })?;
                assert_eq!(outcome.not_found, vec![missing]);
                assert!(!outcome.halted);
                assert_eq!(served.len(), items.len());
                for (item, actual) in items.iter().zip(served) {
                    let expected = if matches!(item, Inventory::Block(_)) {
                        &stripped
                    } else {
                        &full
                    };
                    let envelope = RawNetworkMessage::new(
                        Magic::REGTEST,
                        NetworkMessage::Block(expected.clone()),
                    );
                    assert_eq!(actual, bitcoin::consensus::serialize(&envelope));
                    assert_eq!(expected.block_hash(), full.block_hash());
                    for (tx, original) in expected.txdata.iter().zip(&full.txdata) {
                        assert_eq!(tx.compute_txid(), original.compute_txid());
                    }
                }
                assert_eq!(
                    source.body, body,
                    "serving never rewrites retained witness data"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn getdata_block_encodings_keep_headroom_and_body_failure_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: vec![test_tx(1)],
        };
        let body = consensus_bytes(&block);
        for item in [
            Inventory::Block(wire_hash(block.block_hash())),
            Inventory::WitnessBlock(wire_hash(block.block_hash())),
        ] {
            let source = Arc::new(CountingBodySource {
                bodies: vec![(1, block.block_hash(), body.clone())],
                loads: AtomicUsize::new(0),
                tripwire: Some(0),
            });
            let query = query_with(headers.clone())?.with_block_body_source(source.clone());
            let outcome = query.serve_inventory_blocks(&[item], None, &|| false, &mut |_| {
                panic!("denied headroom cannot serve")
            })?;
            assert!(outcome.halted);
            assert_eq!(outcome.not_found, []);
            assert_eq!(source.loads.load(Ordering::Relaxed), 0);

            let mut corrupt = body.clone();
            corrupt.pop();
            let mut wrong_header = body.clone();
            wrong_header[0] ^= 1;
            let mut trailing = body.clone();
            trailing.push(0);
            let mut superfluous_witness = body.clone();
            superfluous_witness.splice(Header::LEN + 5..Header::LEN + 5, [0, 1]);
            superfluous_witness.insert(superfluous_witness.len() - 4, 0);
            let mut unknown_flag = superfluous_witness.clone();
            unknown_flag[Header::LEN + 6] = 2;
            for malformed in [&trailing, &superfluous_witness, &unknown_flag] {
                assert!(deserialize::<Block>(malformed).is_err());
                assert!(bitcoin::consensus::deserialize::<RegistryBlock>(malformed).is_err());
            }
            for unavailable in [
                None,
                Some(corrupt),
                Some(wrong_header),
                Some(trailing),
                Some(superfluous_witness),
                Some(unknown_flag),
            ] {
                let mut query = query_with(headers.clone())?;
                if let Some(body) = unavailable {
                    query = query.with_block_body_source(Arc::new(SingleBlockSource {
                        height: 1,
                        hash: block.block_hash(),
                        body,
                    }));
                }
                let outcome = query.serve_inventory_blocks(&[item], None, &|| true, &mut |_| {
                    panic!("unavailable body cannot serve")
                })?;
                assert_eq!(outcome.not_found, vec![item]);
                assert!(!outcome.halted);
            }
        }
        Ok(())
    }

    #[test]
    fn getdata_block_encodings_recheck_active_chain_after_body_load()
    -> Result<(), Box<dyn std::error::Error>> {
        struct SwitchingSource {
            tree: Arc<RwLock<BlockTree>>,
            body: Vec<u8>,
        }
        impl BlockBodySource for SwitchingSource {
            fn block_body(&self, _height: u32, _hash: BlockHash) -> Option<Vec<u8>> {
                *self.tree.write() = BlockTree::new();
                Some(self.body.clone())
            }
        }
        let header = seed_headers(1)[0];
        let mut block = Block {
            header,
            txs: vec![test_tx(1)],
        };
        block.txs[0].inputs[0].witness = vec![vec![0x51; 32]].into();
        for item in [
            Inventory::Block(wire_hash(block.block_hash())),
            Inventory::WitnessBlock(wire_hash(block.block_hash())),
        ] {
            let mut tree = BlockTree::new();
            tree.insert_node(None, header, NodeStatus::Active)?;
            let tree = Arc::new(RwLock::new(tree));
            let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
            applied_tip.store(tree.read().tip());
            let query = ActiveChainQuery::new(
                BlockTreeReader::new(tree.clone()),
                applied_tip,
                Network::Regtest,
            )
            .with_block_body_source(Arc::new(SwitchingSource {
                tree,
                body: consensus_bytes(&block),
            }));
            let outcome = query.serve_inventory_blocks(&[item], None, &|| true, &mut |_| {
                panic!("stale body cannot serve")
            })?;
            assert_eq!(outcome.not_found, vec![item]);
            assert!(!outcome.halted);
        }
        Ok(())
    }

    #[test]
    fn getdata_rejects_pruned_or_missing_body() -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let hash = headers[1].compute_hash();
        let query = query_with(headers)?;

        let (outcome, blocks) = serve_collect(&query, &[Inventory::Block(wire_hash(hash))])?;

        assert_eq!(blocks, []);
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
        assert_eq!(outcome.not_found, []);
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

        let reply = query.block_transactions(&request, None, &|| {
            headroom_calls.fetch_add(1, Ordering::Relaxed);
            false
        })?;

        assert!(
            reply.is_none(),
            "a saturated gate leaves the request unanswered"
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
        assert_eq!(served, []);

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
            .block_transactions(&request, None, &|| true)?
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
            None,
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
            None,
            &|| true,
        );
        assert!(
            matches!(out_of_range, Err(PeerError::Misbehavior(_))),
            "an out-of-range index is a protocol disconnect"
        );

        let unknown = query.block_transactions(
            &bitcoin::bip152::BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([9; 32]),
                indexes: vec![0],
            },
            None,
            &|| true,
        )?;
        assert!(unknown.is_none(), "an unservable block stays unanswered");
        Ok(())
    }

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

    #[test]
    fn compact_exchange_keeps_the_mutually_supported_version()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::dispatch::dispatch_inbound_full;
        use crate::peer::{Peer, PeerState};
        use bitcoin::p2p::Magic;
        use bitcoin::p2p::message::NetworkMessage;
        use bitcoin::p2p::message_compact_blocks::{GetBlockTxn, SendCmpct};

        let headers = seed_headers(2);
        let mut block = Block {
            header: headers[1],
            txs: vec![test_tx(1), test_tx(2), test_tx(3)],
        };
        for (index, tx) in block.txs.iter_mut().enumerate() {
            tx.inputs[0].witness = vec![vec![u8::try_from(index)?; 32]].into();
        }
        let body = consensus_bytes(&block);
        let original: RegistryBlock = bitcoin::consensus::deserialize(&body)?;
        let source = Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: body.clone(),
        });
        let query = query_with(headers)?.with_block_body_source(source.clone());
        let hash = wire_hash(block.block_hash());
        let compact_item = Inventory::CompactBlock(hash);
        for versions in [[Some(1), Some(2)], [Some(2), Some(1)], [None, Some(99)]] {
            let mut peer = Peer::new(std::io::Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
            peer.state = PeerState::Ready;
            let mut negotiated = None;
            for version in versions {
                if let Some(version) = version {
                    dispatch_inbound_full(
                        &mut peer,
                        &Message::SendCmpct(SendCmpct {
                            send_compact: false,
                            version,
                        }),
                        Some(&query),
                        None,
                        &|| true,
                        &|| true,
                        &mut |_| panic!("sendcmpct does not emit a response"),
                        &mut |_| {},
                    )?;
                    if version == crate::peer::COMPACT_BLOCK_VERSION {
                        negotiated = Some(version);
                    }
                }
                assert_eq!(peer.compact_blocks.servable_version(), negotiated);
                let compact = dispatched_wire_response(
                    &mut peer,
                    &query,
                    &Message::GetData(vec![compact_item]),
                )?;
                if negotiated.is_none() {
                    assert_eq!(
                        compact.payload(),
                        &NetworkMessage::NotFound(vec![compact_item])
                    );
                } else {
                    let NetworkMessage::CmpctBlock(compact) = compact.payload() else {
                        panic!("negotiated compact request must produce cmpctblock");
                    };
                    let prefill = &compact.compact_block.prefilled_txs[0].tx;
                    assert!(!prefill.input[0].witness.is_empty());
                    assert_eq!(prefill.compute_txid(), original.txdata[0].compute_txid());
                    assert_eq!(prefill.compute_wtxid(), original.txdata[0].compute_wtxid());
                }

                if negotiated.is_none() {
                    continue;
                }
                let indexes = vec![1, 2];
                let decoded = dispatched_wire_response(
                    &mut peer,
                    &query,
                    &Message::GetBlockTxn(GetBlockTxn {
                        txs_request: BlockTransactionsRequest {
                            block_hash: hash,
                            indexes: indexes.clone(),
                        },
                    }),
                )?;
                let NetworkMessage::BlockTxn(response) = decoded.payload() else {
                    panic!("available request must produce blocktxn");
                };
                assert_blocktxn_profile(&response.transactions, &original, &indexes, false)?;
                assert_eq!(
                    source.body, body,
                    "version selection leaves the stored body intact"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn getblocktxn_versions_preserve_missing_body_and_invalid_index_outcomes()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::dispatch::dispatch_inbound_full;
        use crate::peer::{Peer, PeerState};
        use bitcoin::p2p::Magic;
        use bitcoin::p2p::message_compact_blocks::{GetBlockTxn, SendCmpct};

        let headers = seed_headers(2);
        let block = Block {
            header: headers[1],
            txs: vec![test_tx(1)],
        };
        let query = query_with(headers)?.with_block_body_source(Arc::new(SingleBlockSource {
            height: 1,
            hash: block.block_hash(),
            body: consensus_bytes(&block),
        }));
        let hash = wire_hash(block.block_hash());
        for version in [None, Some(1), Some(2), Some(99)] {
            let mut peer = Peer::new(std::io::Cursor::new(Vec::<u8>::new()), Magic::REGTEST);
            peer.state = PeerState::Ready;
            if let Some(version) = version {
                dispatch_inbound_full(
                    &mut peer,
                    &Message::SendCmpct(SendCmpct {
                        send_compact: false,
                        version,
                    }),
                    Some(&query),
                    None,
                    &|| true,
                    &|| true,
                    &mut |_| panic!("sendcmpct does not emit a response"),
                    &mut |_| {},
                )?;
            }
            for (requested_hash, indexes, invalid) in [
                (hash, vec![7], true),
                (hash, Vec::new(), true),
                (WireBlockHash::from_byte_array([9; 32]), vec![1], false),
            ] {
                let expected = if invalid {
                    Some(if indexes.is_empty() {
                        "getblocktxn with empty index list"
                    } else {
                        "getblocktxn index out of range"
                    })
                } else {
                    None
                };
                let result = dispatch_inbound_full(
                    &mut peer,
                    &Message::GetBlockTxn(GetBlockTxn {
                        txs_request: BlockTransactionsRequest {
                            block_hash: requested_hash,
                            indexes,
                        },
                    }),
                    Some(&query),
                    None,
                    &|| true,
                    &|| true,
                    &mut |_| panic!("missing or invalid request cannot emit transactions"),
                    &mut |_| {},
                );
                if let Some(expected) = expected {
                    assert!(
                        matches!(result, Err(PeerError::Misbehavior(message)) if message == expected),
                        "invalid request must disconnect, got {result:?}"
                    );
                } else {
                    result?;
                }
            }
        }
        Ok(())
    }

    fn assert_blocktxn_profile(
        response: &BlockTransactions,
        original: &RegistryBlock,
        indexes: &[u64],
        strip_witness: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut expected = Vec::new();
        for index in indexes {
            let mut tx = original.txdata[usize::try_from(*index)?].clone();
            if strip_witness {
                for input in &mut tx.input {
                    input.witness.clear();
                }
            }
            expected.push(tx);
        }
        assert_eq!(response.block_hash, original.block_hash());
        assert_eq!(response.transactions, expected);
        for (tx, index) in response.transactions.iter().zip(indexes) {
            assert_eq!(
                tx.compute_txid(),
                original.txdata[usize::try_from(*index)?].compute_txid()
            );
        }
        Ok(())
    }

    fn dispatched_wire_response(
        peer: &mut crate::peer::Peer<std::io::Cursor<Vec<u8>>>,
        query: &ActiveChainQuery,
        request: &Message,
    ) -> Result<bitcoin::p2p::message::RawNetworkMessage, Box<dyn std::error::Error>> {
        let mut wire = Vec::new();
        crate::dispatch::dispatch_inbound_full(
            peer,
            request,
            Some(query),
            None,
            &|| true,
            &|| true,
            &mut |response| {
                crate::wire::write_message(&mut wire, bitcoin::p2p::Magic::REGTEST, &response)?;
                Ok(())
            },
            &mut |_| {},
        )?;
        Ok(bitcoin::consensus::deserialize(&wire)?)
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

    /// A query over `tree` whose applied tip publishes the tree tip:
    /// fixture trees mark every node `Active`, so the two tips coincide.
    fn query_over(tree: BlockTree, network: Network) -> ActiveChainQuery {
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(block_tree.read().tip());
        ActiveChainQuery::new(block_tree, applied_tip, network)
    }

    struct StaleFixture {
        query: ActiveChainQuery,
        stale: Block,
        winner: Block,
        source: Arc<CountingBodySource>,
    }

    /// A previously applied block at height one and a different applied winner
    /// at the same height. Counts are recorded through the chain owner's API.
    fn stale_query(depth: u32) -> Result<StaleFixture, Box<dyn std::error::Error>> {
        let headers = seed_headers(2);
        let stale = block_at(&headers, 1)?;
        let query = query_with(headers)?;
        let winner;
        {
            let mut tree = query.block_tree.write();
            let genesis = tree
                .node_at_height_from(tree.tip_id().ok_or("tip")?, 0)
                .ok_or("genesis")?;
            tree.record_applied_tx_count(genesis, 1)?;
            let stale_id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
            tree.record_applied_tx_count(stale_id, 2)?;
            let header = test_header(tree.node(genesis)?.hash.into(), 100);
            winner = Block {
                header,
                txs: vec![test_tx(3), test_tx(4)],
            };
            let mut parent = tree.insert_node(Some(genesis), header, NodeStatus::HeaderValid)?;
            tree.record_applied_tx_count(parent, 2)?;
            for nonce in 0..depth {
                let header = test_header(tree.node(parent)?.hash.into(), 101 + nonce);
                parent = tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
            }
            query.applied_tip.store(tree.tip());
        }
        let source = Arc::new(CountingBodySource {
            bodies: vec![
                (1, stale.block_hash(), consensus_bytes(&stale)),
                (1, winner.block_hash(), consensus_bytes(&winner)),
            ],
            loads: AtomicUsize::new(0),
            tripwire: None,
        });
        Ok(StaleFixture {
            query: query.with_block_body_source(source.clone()),
            stale,
            winner,
            source,
        })
    }

    #[test]
    fn stored_stale_blocks_are_hash_addressed_without_becoming_announcements()
    -> Result<(), Box<dyn std::error::Error>> {
        let StaleFixture {
            query,
            stale,
            winner,
            source,
        } = stale_query(1)?;
        for block in [&stale, &winner] {
            let wire = wire_hash(block.block_hash());
            for item in [
                Inventory::Block(wire),
                Inventory::WitnessBlock(wire),
                Inventory::CompactBlock(wire),
            ] {
                let mut messages = Vec::new();
                let result =
                    query.serve_inventory_blocks(&[item], Some(2), &|| true, &mut |m| {
                        messages.push(m);
                        Ok(())
                    })?;
                assert_eq!(result.not_found, []);
                match &messages[0] {
                    Message::BlockPayload(payload) => {
                        assert_eq!(payload_body(payload)?.block_hash(), wire);
                    }
                    Message::CmpctBlock(compact) => {
                        assert_eq!(compact.compact_block.header.block_hash(), wire);
                    }
                    other => panic!("unexpected response {other:?}"),
                }
            }
            let request = BlockTransactionsRequest {
                block_hash: wire,
                indexes: vec![1],
            };
            let Some(Message::BlockTxn(response)) =
                query.block_transactions(&request, Some(2), &|| true)?
            else {
                panic!("stored shallow block must answer");
            };
            assert_eq!(response.transactions.block_hash, wire);
            let expected: RegistryBlock = bitcoin::consensus::deserialize(&consensus_bytes(block))?;
            assert_eq!(
                response.transactions.transactions,
                vec![expected.txdata[1].clone()]
            );
        }
        let before = source.loads.load(Ordering::Relaxed);
        assert!(ChainQuery::compact_block_for(&query, 1, stale.block_hash(), Some(2)).is_none());
        assert_eq!(
            source.loads.load(Ordering::Relaxed),
            before,
            "stale announcements load no body"
        );
        Ok(())
    }

    #[test]
    fn stale_serving_keeps_depth_headroom_and_unknown_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        for (depth, blocktxn) in [(10, true), (11, false)] {
            let StaleFixture {
                query,
                stale,
                source,
                ..
            } = stale_query(depth)?;
            let request = BlockTransactionsRequest {
                block_hash: wire_hash(stale.block_hash()),
                indexes: vec![1],
            };
            assert!(
                query
                    .block_transactions(&request, Some(2), &|| false)?
                    .is_none()
            );
            let outcome = query.serve_inventory_blocks(
                &[Inventory::WitnessBlock(request.block_hash)],
                Some(2),
                &|| false,
                &mut |_| panic!("no headroom"),
            )?;
            assert!(outcome.halted);
            assert_eq!(source.loads.load(Ordering::Relaxed), 0);
            let reply = query
                .block_transactions(&request, Some(2), &|| true)?
                .ok_or("stale reply")?;
            assert_eq!(matches!(reply, Message::BlockTxn(_)), blocktxn);
            if let Message::BlockPayload(payload) = reply {
                assert_eq!(payload_body(&payload)?.block_hash(), request.block_hash);
            }
            let unknown = BlockTransactionsRequest {
                block_hash: WireBlockHash::from_byte_array([99; 32]),
                indexes: vec![0],
            };
            assert!(
                query
                    .block_transactions(&unknown, Some(2), &|| panic!(
                        "unknown must not ask for headroom"
                    ))?
                    .is_none()
            );
        }
        Ok(())
    }

    #[test]
    fn stale_inventory_requires_validation_and_core_age_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        // Core 31.1 BlockRequestAllowed uses strict < 30 days independently
        // for timestamp age and proof-equivalent age; regtest work is 2 and
        // spacing 600s, so 4320 blocks is exactly 30 days.
        for (time_age, work_blocks, validated, allowed) in [
            (2_591_999, 4_319, true, true),
            (2_592_000, 4_319, true, false),
            (2_591_999, 4_320, true, false),
            (0, 0, false, false),
        ] {
            let StaleFixture {
                query,
                stale,
                source,
                ..
            } = stale_query(1)?;
            {
                let mut tree = query.block_tree.write();
                let stale_id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
                if !validated {
                    tree.restore_chain_tx_count(stale_id, bitcoin_rs_chain::ChainTxCount::UNKNOWN)?;
                }
                let stale_work = tree.node(stale_id)?.chainwork;
                let best_id = tree.tip_id().ok_or("tip")?;
                let best = tree.node_mut(best_id)?;
                best.header.time = stale.header.time + time_age;
                best.chainwork = stale_work + ChainWork::from(work_blocks * 2_u32);
            }
            let hash = wire_hash(stale.block_hash());
            let outcome = query.serve_inventory_blocks(
                &[Inventory::WitnessBlock(hash)],
                None,
                &|| true,
                &mut |_| Ok(()),
            )?;
            assert_eq!(outcome.not_found.is_empty(), allowed);
            assert_eq!(source.loads.load(Ordering::Relaxed), usize::from(allowed));
            // Shallow HAVE_DATA requests intentionally do not inherit the
            // inventory age/validation filter (Core GETBLOCKTXN).
            assert!(
                query
                    .block_transactions(
                        &BlockTransactionsRequest {
                            block_hash: hash,
                            indexes: vec![1]
                        },
                        Some(2),
                        &|| true
                    )?
                    .is_some()
            );
        }
        // Deep getblocktxn takes inventory policy, including stale-age refusal.
        let StaleFixture {
            query,
            stale,
            source,
            ..
        } = stale_query(11)?;
        {
            let mut tree = query.block_tree.write();
            let tip = tree.tip_id().ok_or("tip")?;
            tree.node_mut(tip)?.header.time = stale.header.time + 2_592_000;
        }
        assert!(
            query
                .block_transactions(
                    &BlockTransactionsRequest {
                        block_hash: wire_hash(stale.block_hash()),
                        indexes: vec![1]
                    },
                    Some(2),
                    &|| true
                )?
                .is_none()
        );
        assert_eq!(source.loads.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn stale_invalid_or_missing_bodies_are_not_served() -> Result<(), Box<dyn std::error::Error>> {
        let StaleFixture {
            mut query, stale, ..
        } = stale_query(1)?;
        query.block_body_source = None;
        let request = BlockTransactionsRequest {
            block_hash: wire_hash(stale.block_hash()),
            indexes: vec![1],
        };
        assert!(
            query
                .block_transactions(&request, Some(2), &|| true)?
                .is_none()
        );
        let StaleFixture {
            query,
            stale,
            source,
            ..
        } = stale_query(1)?;
        {
            let mut tree = query.block_tree.write();
            let id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
            tree.invalidate_subtree(id)?;
        }
        assert!(
            query
                .block_transactions(&request, Some(2), &|| true)?
                .is_none()
        );
        let result = query.serve_inventory_blocks(
            &[Inventory::WitnessBlock(request.block_hash)],
            None,
            &|| true,
            &mut |_| panic!("invalid"),
        )?;
        assert_eq!(result.not_found.len(), 1);
        assert_eq!(source.loads.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn serving_depth_uses_applied_tip_when_headers_are_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let headers = seed_headers(15);
        let block = block_at(&headers, 1)?;
        let query = chain_at(&headers[..2], 1, &block)?;
        {
            let mut tree = query.block_tree.write();
            for header in &headers[2..] {
                tree.insert_header(*header, NodeStatus::HeaderValid)?;
            }
        }
        let request = BlockTransactionsRequest {
            block_hash: wire_hash(block.block_hash()),
            indexes: vec![1],
        };
        assert!(matches!(
            query.block_transactions(&request, Some(2), &|| true)?,
            Some(Message::BlockTxn(_))
        ));
        let mut messages = Vec::new();
        query.serve_inventory_blocks(
            &[Inventory::CompactBlock(request.block_hash)],
            Some(2),
            &|| true,
            &mut |m| {
                messages.push(m);
                Ok(())
            },
        )?;
        assert!(matches!(messages.as_slice(), [Message::CmpctBlock(_)]));
        Ok(())
    }

    #[test]
    fn serving_rechecks_reorg_invalidation_and_age_after_io()
    -> Result<(), Box<dyn std::error::Error>> {
        struct RacingSource {
            source: Arc<CountingBodySource>,
            tree: BlockTreeReader,
            applied: TipReader,
            change: u8,
        }
        impl BlockBodySource for RacingSource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                let mut tree = self.tree.write();
                match self.change {
                    1 => {
                        let id = tree.lookup(hash.into())?;
                        tree.invalidate_subtree(id).ok()?;
                    }
                    2 => {
                        let tip = tree.tip_id()?;
                        tree.node_mut(tip).ok()?.header.time = 2_592_001;
                    }
                    _ => {}
                }
                self.applied.store(tree.tip());
                drop(tree);
                self.source.block_body(height, hash)
            }
        }
        for change in 0..3 {
            let StaleFixture {
                mut query,
                stale,
                source,
                ..
            } = stale_query(1)?;
            // Capture the old applied tip while the competing headers already
            // lead. The body read publishes the reorg, invalidation, or age change.
            {
                let tree = query.block_tree.read();
                let id = tree.lookup(stale.block_hash().into()).ok_or("stale")?;
                let n = tree.node(id)?;
                query
                    .applied_tip
                    .store(Some(Arc::new(bitcoin_rs_chain::TipSnapshot {
                        tip_id: id,
                        height: n.height,
                        hash: n.hash,
                        chainwork: n.chainwork,
                        chain_tx_count: n.chain_tx_count,
                    })));
            }
            query.block_body_source = Some(Arc::new(RacingSource {
                source: source.clone(),
                tree: query.block_tree.clone(),
                applied: query.applied_tip.clone(),
                change,
            }));
            let hash = wire_hash(stale.block_hash());
            let mut messages = Vec::new();
            let outcome = query.serve_inventory_blocks(
                &[Inventory::WitnessBlock(hash)],
                None,
                &|| true,
                &mut |m| {
                    messages.push(m);
                    Ok(())
                },
            )?;
            assert_eq!(source.loads.load(Ordering::Relaxed), 1);
            if change == 0 {
                assert_eq!(outcome.not_found, []);
                let [Message::BlockPayload(payload)] = messages.as_slice() else {
                    panic!("reorg retains stored stale response");
                };
                assert_eq!(payload_body(payload)?.block_hash(), hash);
            } else {
                assert_eq!(messages, []);
                assert_eq!(outcome.not_found, vec![Inventory::WitnessBlock(hash)]);
            }
        }
        Ok(())
    }

    #[test]
    fn getblocktxn_rechecks_inventory_policy_when_io_crosses_depth_ten()
    -> Result<(), Box<dyn std::error::Error>> {
        struct AdvancingSource {
            source: Arc<CountingBodySource>,
            tree: BlockTreeReader,
            applied: TipReader,
            change: u8,
        }
        impl BlockBodySource for AdvancingSource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                let mut tree = self.tree.write();
                let old_tip = tree.tip_id()?;
                let mut header = test_header(tree.node(old_tip).ok()?.hash.into(), 200);
                if self.change == 2 {
                    header.time = 2_592_001;
                }
                tree.insert_node(Some(old_tip), header, NodeStatus::HeaderValid)
                    .ok()?;
                if self.change == 1 {
                    let stale_id = tree.lookup(hash.into())?;
                    tree.restore_chain_tx_count(stale_id, bitcoin_rs_chain::ChainTxCount::UNKNOWN)
                        .ok()?;
                }
                self.applied.store(tree.tip());
                drop(tree);
                self.source.block_body(height, hash)
            }
        }
        for change in 0..3 {
            let StaleFixture {
                mut query,
                stale,
                source,
                ..
            } = stale_query(10)?;
            query.block_body_source = Some(Arc::new(AdvancingSource {
                source: source.clone(),
                tree: query.block_tree.clone(),
                applied: query.applied_tip.clone(),
                change,
            }));
            let request = BlockTransactionsRequest {
                block_hash: wire_hash(stale.block_hash()),
                indexes: vec![1],
            };
            let result = query.block_transactions(&request, Some(2), &|| true)?;
            assert_eq!(source.loads.load(Ordering::Relaxed), 1);
            if change == 0 {
                let Some(Message::BlockPayload(payload)) = result else {
                    panic!("crossing depth ten must use full-block inventory policy");
                };
                assert_eq!(payload_body(&payload)?.block_hash(), request.block_hash);
            } else {
                assert!(
                    result.is_none(),
                    "deep fallback must reject absent validation or stale age"
                );
            }
        }
        Ok(())
    }

    fn query_with(headers: Vec<Header>) -> Result<ActiveChainQuery, bitcoin_rs_chain::ChainError> {
        let mut tree = BlockTree::new();
        let mut parent = None;
        for header in headers {
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        Ok(query_over(tree, Network::Regtest))
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
            bits: CompactTarget::from_consensus(bitcoin_rs_chain::regtest_fixture::REGTEST_BITS),
            nonce,
        }
    }

    fn header_hashes(headers: &[Header]) -> Vec<BlockHash> {
        headers.iter().map(Header::compute_hash).collect()
    }
}
