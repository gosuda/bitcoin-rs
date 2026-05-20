extern crate alloc;

use alloc::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashTable;
use slab::Slab;

use crate::{
    ChainError,
    node::{BlockHeader, BlockTreeNode, ChainWork, NodeId, NodeStatus},
    tip::TipSnapshot,
};

/// In-memory block tree keyed by compact slab ids and header hashes.
pub struct BlockTree {
    nodes: Slab<BlockTreeNode>,
    by_hash: HashTable<NodeId>,
    tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl BlockTree {
    /// Builds an empty block tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Slab::new(),
            by_hash: HashTable::new(),
            tip: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// Returns the number of nodes currently held by the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true when the tree has no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns a node by id.
    pub fn node(&self, id: NodeId) -> Result<&BlockTreeNode, ChainError> {
        let Some(index) = id.index() else {
            return Err(ChainError::UnknownNode { id });
        };
        self.nodes.get(index).ok_or(ChainError::UnknownNode { id })
    }

    /// Returns a mutable node by id.
    pub fn node_mut(&mut self, id: NodeId) -> Result<&mut BlockTreeNode, ChainError> {
        let Some(index) = id.index() else {
            return Err(ChainError::UnknownNode { id });
        };
        self.nodes
            .get_mut(index)
            .ok_or(ChainError::UnknownNode { id })
    }

    /// Returns the highest shared ancestor of `a` and `b`, walking parent pointers.
    ///
    /// Returns `None` when either node is unknown or the chains share no common
    /// ancestor (e.g. disconnected roots). Used by reorg planning to identify the
    /// rollback point.
    #[must_use]
    pub fn find_common_ancestor(&self, a: NodeId, b: NodeId) -> Option<NodeId> {
        let mut a_ancestors: hashbrown::HashSet<NodeId> = hashbrown::HashSet::new();

        let mut cursor = Some(a);
        while let Some(id) = cursor {
            let Ok(node) = self.node(id) else {
                return None;
            };
            a_ancestors.insert(id);
            cursor = node.parent;
        }

        let mut cursor = Some(b);
        while let Some(id) = cursor {
            let Ok(node) = self.node(id) else {
                return None;
            };
            if a_ancestors.contains(&id) {
                return Some(id);
            }
            cursor = node.parent;
        }

        None
    }

    /// Returns up to `limit` parent `NodeId`s of `start` (excluding `start` itself).
    ///
    /// Walks parent pointers in order from nearest to farthest. Stops at the root
    /// (no parent) or after `limit` ancestors. Used by header-distance queries and
    /// reorg cost analysis.
    #[must_use]
    pub fn ancestors(&self, start: NodeId, limit: usize) -> Vec<NodeId> {
        let mut out = Vec::with_capacity(limit);
        let mut cursor = start;
        while out.len() < limit {
            let Ok(node) = self.node(cursor) else {
                break;
            };
            let Some(parent_id) = node.parent else {
                break;
            };
            out.push(parent_id);
            cursor = parent_id;
        }
        out
    }

    /// Looks up a node id by header hash.
    #[must_use]
    pub fn lookup(&self, hash: Hash256) -> Option<NodeId> {
        self.by_hash
            .find(hash_table_key(hash), |id| {
                id.index()
                    .and_then(|index| self.nodes.get(index))
                    .is_some_and(|node| node.hash == hash)
            })
            .copied()
    }

    /// Returns the `NodeId`s of every node not referenced as a parent.
    ///
    /// A leaf is a tip of either the active chain (most common: 1 leaf, the
    /// canonical tip) or a stale/fork branch. Multi-tip RPCs like Bitcoin
    /// Core's `getchaintips` enumerate these.
    ///
    /// Order is iteration order of the underlying slab.
    #[must_use]
    pub fn leaf_node_ids(&self) -> Vec<NodeId> {
        let mut parents: hashbrown::HashSet<u32> = hashbrown::HashSet::new();
        for (_index, node) in &self.nodes {
            if let Some(parent_id) = node.parent
                && let Some(parent_index) = parent_id.index()
            {
                // NodeId stores a u32; track parent indices to skip them later.
                if let Ok(idx_u32) = u32::try_from(parent_index) {
                    parents.insert(idx_u32);
                }
            }
        }

        let mut leaves = Vec::new();
        for (index, _node) in &self.nodes {
            if let Ok(idx_u32) = u32::try_from(index)
                && !parents.contains(&idx_u32)
            {
                leaves.push(NodeId::new(idx_u32));
            }
        }
        leaves
    }

    /// Returns the currently published best tip snapshot.
    #[must_use]
    pub fn tip(&self) -> Option<Arc<TipSnapshot>> {
        self.tip.load_full()
    }

    /// Returns the chainwork of the published tip, or `None` if no tip is
    /// published yet.
    #[must_use]
    pub fn tip_chainwork(&self) -> Option<ChainWork> {
        self.tip().map(|tip| tip.chainwork)
    }

    /// Returns the height of the published tip, or `None` if no tip is
    /// published yet.
    #[must_use]
    pub fn tip_height(&self) -> Option<u32> {
        self.tip().map(|tip| tip.height)
    }

    /// Returns the hash of the published tip, or `None` if no tip is
    /// published yet.
    #[must_use]
    pub fn tip_hash(&self) -> Option<Hash256> {
        self.tip().map(|tip| tip.hash)
    }

    /// Returns a cheap-clonable handle to the canonical best-tip pointer.
    ///
    /// Sharing this handle lets lock-free readers observe tip advances
    /// without acquiring the `BlockTree`'s outer `RwLock`. Writes happen
    /// through `publish_tip_if_best` (called by `insert_header`).
    #[must_use]
    pub fn tip_handle(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.tip)
    }

    /// Builds a block locator starting from `tip_id`. Returns the chain of
    /// header hashes at offsets 0, 1, 2, ..., 9, 11, 15, 23, 39, ... walking
    /// back through parents with exponential backoff after the 10th entry.
    /// Stops at the genesis (no parent) or after `max_entries` hashes.
    #[must_use]
    pub fn block_locator(&self, tip_id: NodeId, max_entries: usize) -> Vec<Hash256> {
        let mut locator = Vec::with_capacity(max_entries.min(32));
        let mut current = tip_id;
        let mut step: u64 = 1;
        while locator.len() < max_entries {
            let Ok(node) = self.node(current) else {
                break;
            };
            locator.push(node.hash);

            let mut walker = current;
            let mut walked = false;
            for _ in 0..step {
                let Ok(walker_node) = self.node(walker) else {
                    break;
                };
                let Some(parent) = walker_node.parent else {
                    break;
                };
                walker = parent;
                walked = true;
            }
            if !walked {
                break;
            }
            current = walker;
            if locator.len() >= 10 {
                step = step.saturating_mul(2);
            }
        }
        locator
    }
    /// Walks backward from `start_id` via parent pointers to the node at
    /// `target_height`. Returns the `NodeId` at that height, or None if
    /// `target_height > start_id.height` or the chain is broken.
    #[must_use]
    pub fn node_at_height_from(&self, start_id: NodeId, target_height: u32) -> Option<NodeId> {
        let Ok(start_node) = self.node(start_id) else {
            return None;
        };
        if target_height > start_node.height {
            return None;
        }
        if target_height == start_node.height {
            return Some(start_id);
        }

        let mut cursor = start_id;
        loop {
            let Ok(node) = self.node(cursor) else {
                return None;
            };
            if node.height == target_height {
                return Some(cursor);
            }
            if node.height < target_height {
                return None;
            }
            let parent = node.parent?;
            cursor = parent;
        }
    }
    /// Returns the active-chain `BlockTreeNode` at `height`, looking up via the
    /// published tip. Returns `None` when no tip is published or no active-chain
    /// node exists at that height.
    #[must_use]
    pub fn active_node_at_height(&self, height: u32) -> Option<&BlockTreeNode> {
        let tip = self.tip()?;
        let node_id = self.node_at_height_from(tip.tip_id, height)?;
        self.node(node_id).ok()
    }

    /// Returns the `BlockHeader` at active-chain `height`, looking up via the
    /// published tip. Returns `None` when no tip is published or no active-chain
    /// node exists at that height.
    #[must_use]
    pub fn header_at_active_height(&self, height: u32) -> Option<&BlockHeader> {
        self.active_node_at_height(height).map(|node| &node.header)
    }

    /// Returns the median time of the most recent `window` blocks, inclusive
    /// of `start_id`, walking backward via parent pointers.
    ///
    /// BIP113 uses `window = 11`. When the chain has fewer than `window`
    /// blocks, the median is computed over however many exist. Returns `None`
    /// only when `start_id` is not in the tree.
    #[must_use]
    pub fn median_time_past_at(&self, start_id: NodeId, window: usize) -> Option<u32> {
        if window == 0 {
            return Some(0);
        }

        let mut times = Vec::with_capacity(window);
        let mut cursor = start_id;
        while times.len() < window {
            let Ok(node) = self.node(cursor) else {
                if times.is_empty() {
                    return None;
                }
                break;
            };
            times.push(node.header.time);
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
        }

        if times.is_empty() {
            return None;
        }
        times.sort_unstable();
        Some(times[times.len() / 2])
    }

    /// Inserts a header whose parent is inferred from `prev_blockhash`.
    pub fn insert_header(
        &mut self,
        header: BlockHeader,
        status: NodeStatus,
    ) -> Result<NodeId, ChainError> {
        let parent = if self.nodes.is_empty() {
            None
        } else {
            let prev_hash = prev_hash_from_header(&header);
            Some(
                self.lookup(prev_hash)
                    .ok_or(ChainError::MissingParent { prev_hash })?,
            )
        };
        self.insert_node(parent, header, status)
    }

    /// Inserts a header under an explicit parent.
    pub fn insert_node(
        &mut self,
        parent: Option<NodeId>,
        header: BlockHeader,
        status: NodeStatus,
    ) -> Result<NodeId, ChainError> {
        let hash = hash_from_header(&header);
        if self.lookup(hash).is_some() {
            return Err(ChainError::DuplicateHeader { hash });
        }

        let block_work = work_from_header(&header);
        let (height, chainwork) = match parent {
            Some(parent_id) => {
                let parent_node = self.node(parent_id)?;
                let expected_prev = parent_node.hash;
                let actual_prev = prev_hash_from_header(&header);
                if actual_prev != expected_prev {
                    return Err(ChainError::NonContinuousHeader {
                        expected_prev,
                        actual_prev,
                    });
                }
                let height = parent_node
                    .height
                    .checked_add(1)
                    .ok_or(ChainError::HeightOverflow { parent: parent_id })?;
                let chainwork = parent_node
                    .chainwork
                    .checked_add(block_work)
                    .ok_or(ChainError::ChainworkOverflow { hash })?;
                (height, chainwork)
            }
            None => (0, block_work),
        };

        let index = self.nodes.insert(BlockTreeNode {
            parent,
            height,
            hash,
            header,
            chainwork,
            status,
        });
        let id_u32 = u32::try_from(index).map_err(|_| ChainError::NodeIdOverflow { index })?;
        let node_id = NodeId::new(id_u32);
        let nodes = &self.nodes;
        self.by_hash
            .insert_unique(hash_table_key(hash), node_id, |id| {
                node_hash_key(nodes, *id)
            });
        self.publish_tip_if_best(node_id)?;
        Ok(node_id)
    }

    /// Returns all ancestors from `start` down to the root, including `start`.
    pub fn ancestor_chain(&self, start: NodeId) -> Result<Vec<NodeId>, ChainError> {
        let mut out = Vec::new();
        let mut cursor = Some(start);
        while let Some(id) = cursor {
            let node = self.node(id)?;
            out.push(id);
            cursor = node.parent;
        }
        Ok(out)
    }

    /// Returns the parent id for a node.
    pub fn parent_id(&self, id: NodeId) -> Result<Option<NodeId>, ChainError> {
        Ok(self.node(id)?.parent)
    }

    fn publish_tip_if_best(&mut self, node_id: NodeId) -> Result<(), ChainError> {
        let node = self.node(node_id)?;
        let should_publish = self
            .tip
            .load_full()
            .is_none_or(|tip| node.chainwork > tip.chainwork);
        if !should_publish {
            return Ok(());
        }

        if let Some(old_tip) = self.tip.load_full()
            && old_tip.tip_id != node_id
        {
            self.node_mut(old_tip.tip_id)?.status = NodeStatus::Stale;
        }
        self.node_mut(node_id)?.status = NodeStatus::Active;
        let node = self.node(node_id)?;
        self.tip.store(Some(Arc::new(TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })));
        Ok(())
    }
}

impl Default for BlockTree {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn hash_from_header(header: &BlockHeader) -> Hash256 {
    Hash256::from_le_bytes(header.block_hash().as_byte_array())
}

pub(crate) fn prev_hash_from_header(header: &BlockHeader) -> Hash256 {
    Hash256::from_le_bytes(header.prev_blockhash.as_byte_array())
}

pub(crate) fn hash_table_key(hash: Hash256) -> u64 {
    u64::from_le_bytes(hash.prefix8())
}

fn node_hash_key(nodes: &Slab<BlockTreeNode>, id: NodeId) -> u64 {
    id.index()
        .and_then(|index| nodes.get(index))
        .map_or(0, |node| hash_table_key(node.hash))
}

fn work_from_header(header: &BlockHeader) -> ChainWork {
    ChainWork::from_be_bytes(header.work().to_be_bytes())
}
#[cfg(test)]
mod tests {
    use bitcoin::{
        BlockHash, TxMerkleNode,
        block::{Header as BlockHeader, Version},
        hashes::Hash as _,
        pow::CompactTarget,
    };

    use std::sync::Arc;

    use super::{BlockTree, hash_from_header};
    use crate::{
        node::{ChainWork, NodeStatus},
        tip::TipSnapshot,
    };

    #[test]
    fn block_locator_walks_back_to_genesis_on_short_chain() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let mut tip_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut hashes = vec![hash_from_header(&genesis)];

        for height in 1..5 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            hashes.push(hash_from_header(&header));
        }

        let locator = tree.block_locator(tip_id, 32);

        assert_eq!(locator.len(), 5);
        assert_eq!(locator[0], hashes[4]);
        assert_eq!(locator[1], hashes[3]);
        assert_eq!(locator[2], hashes[2]);
        assert_eq!(locator[3], hashes[1]);
        assert_eq!(locator[4], hashes[0]);
        assert_eq!(locator.last(), hashes.first());
        Ok(())
    }

    #[test]
    fn median_time_past_at_returns_median_of_recent_timestamps()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let mut prev_hash = BlockHash::all_zeros();
        let mut tip = None;

        for i in 0..11_u32 {
            let header = BlockHeader {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000 + i * 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            prev_hash = header.block_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }

        let Some(tip) = tip else {
            panic!("chain has 11 blocks should yield a tip");
        };
        let Some(mtp) = tree.median_time_past_at(tip, 11) else {
            panic!("chain has 11 blocks should yield Some");
        };
        assert_eq!(mtp, 1_003_000);
        Ok(())
    }

    #[test]
    fn active_node_at_height_returns_none_when_no_tip() {
        let tree = BlockTree::new();
        assert!(tree.active_node_at_height(0).is_none());
    }

    #[test]
    fn tip_chainwork_returns_none_before_publish() {
        let tree = BlockTree::new();
        assert!(tree.tip_chainwork().is_none());
    }

    #[test]
    fn tip_height_returns_none_before_publish() {
        let tree = BlockTree::new();
        assert!(tree.tip_height().is_none());
    }

    #[test]
    fn tip_hash_returns_none_before_publish() {
        let tree = BlockTree::new();
        assert!(tree.tip_hash().is_none());
    }

    #[test]
    fn tip_chainwork_returns_published_tip_chainwork() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let cw = tree.node(genesis_id)?.chainwork;

        assert_eq!(tree.tip_chainwork(), Some(cw));
        Ok(())
    }

    #[test]
    fn tip_height_returns_published_tip_height() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        tree.tip_handle().store(Some(Arc::new(TipSnapshot {
            tip_id: genesis_id,
            height: 7,
            chainwork: ChainWork::ZERO,
            hash: genesis_hash,
        })));
        assert_eq!(tree.tip_height(), Some(7));
        Ok(())
    }

    #[test]
    fn tip_hash_returns_published_tip_hash() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        tree.tip_handle().store(Some(Arc::new(TipSnapshot {
            tip_id: genesis_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash: genesis_hash,
        })));
        assert_eq!(tree.tip_hash(), Some(genesis_hash));
        Ok(())
    }

    #[test]
    fn active_node_at_height_returns_genesis_after_insert() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

        let Some(node) = tree.active_node_at_height(0) else {
            panic!("expected node at height 0 after insert");
        };
        assert_eq!(node.height, 0);
        assert_eq!(node.hash, tree.node(genesis_id)?.hash);
        Ok(())
    }

    #[test]
    fn header_at_active_height_returns_genesis_header_after_publish_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        let Some(header) = tree.header_at_active_height(0) else {
            panic!("expected header at height 0");
        };

        assert_eq!(hash_from_header(header), genesis_hash);
        Ok(())
    }

    #[test]
    fn header_at_active_height_returns_none_above_tip() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let _genesis_hash = tree.node(genesis_id)?.hash;

        assert!(tree.header_at_active_height(1).is_none());
        Ok(())
    }

    #[test]
    fn node_at_height_from_walks_back_to_requested_height() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut tree = BlockTree::new();
        let mut prev_hash = BlockHash::all_zeros();
        let mut genesis_id = None;
        let mut tip_id = None;

        for height in 0..5_u32 {
            let header = BlockHeader {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000 + height * 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            };
            prev_hash = header.block_hash();
            let node_id = tree.insert_header(header, NodeStatus::HeaderValid)?;
            if height == 0 {
                genesis_id = Some(node_id);
            }
            tip_id = Some(node_id);
        }

        let Some(genesis_id) = genesis_id else {
            panic!("chain has 5 blocks should yield a genesis node");
        };
        let Some(tip_id) = tip_id else {
            panic!("chain has 5 blocks should yield a tip");
        };

        assert_eq!(tree.node_at_height_from(tip_id, 0), Some(genesis_id));
        assert_eq!(tree.node_at_height_from(tip_id, 4), Some(tip_id));
        assert_eq!(tree.node_at_height_from(tip_id, 99), None);
        Ok(())
    }

    #[test]
    fn ancestors_returns_empty_for_root() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let result = tree.ancestors(genesis_id, 10);
        assert!(result.is_empty());
        Ok(())
    }

    #[test]
    fn ancestors_walks_parent_chain_in_order() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let child = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            1,
        );
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
        let grandchild = test_header(
            BlockHash::from_byte_array(hash_from_header(&child).to_le_bytes()),
            2,
        );
        let grandchild_id =
            tree.insert_node(Some(child_id), grandchild, NodeStatus::HeaderValid)?;
        let result = tree.ancestors(grandchild_id, 10);
        assert_eq!(result, vec![child_id, genesis_id]);
        Ok(())
    }

    #[test]
    fn ancestors_respects_limit() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let child = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            1,
        );
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
        let grandchild = test_header(
            BlockHash::from_byte_array(hash_from_header(&child).to_le_bytes()),
            2,
        );
        let grandchild_id =
            tree.insert_node(Some(child_id), grandchild, NodeStatus::HeaderValid)?;
        let result = tree.ancestors(grandchild_id, 1);
        assert_eq!(result, vec![child_id]);
        Ok(())
    }

    #[test]
    fn leaf_node_ids_returns_only_tip_on_linear_chain() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let child = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            1,
        );
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;

        let leaves = tree.leaf_node_ids();

        assert_eq!(leaves.len(), 1, "expected single leaf, got {leaves:?}");
        assert_eq!(leaves[0], child_id);
        Ok(())
    }

    #[test]
    fn leaf_node_ids_returns_all_branches_when_forked() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut variant_a = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            1,
        );
        variant_a.nonce = 1;
        let mut variant_b = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            2,
        );
        variant_b.nonce = 2;
        let leaf_a = tree.insert_node(Some(genesis_id), variant_a, NodeStatus::HeaderValid)?;
        let leaf_b = tree.insert_node(Some(genesis_id), variant_b, NodeStatus::HeaderValid)?;

        let mut leaves = tree.leaf_node_ids();
        leaves.sort_by_key(|id| id.index().unwrap_or(usize::MAX));

        assert_eq!(
            leaves.len(),
            2,
            "expected two leaves on fork, got {leaves:?}"
        );
        assert!(leaves.contains(&leaf_a));
        assert!(leaves.contains(&leaf_b));
        Ok(())
    }

    #[test]
    fn find_common_ancestor_returns_genesis_on_linear_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let child = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            1,
        );
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;

        assert_eq!(
            tree.find_common_ancestor(genesis_id, genesis_id),
            Some(genesis_id)
        );
        assert_eq!(
            tree.find_common_ancestor(genesis_id, child_id),
            Some(genesis_id)
        );
        assert_eq!(
            tree.find_common_ancestor(child_id, genesis_id),
            Some(genesis_id)
        );
        Ok(())
    }

    #[test]
    fn find_common_ancestor_returns_parent_for_fork() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut variant_a = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            1,
        );
        variant_a.nonce = 1;
        let mut variant_b = test_header(
            BlockHash::from_byte_array(hash_from_header(&genesis).to_le_bytes()),
            2,
        );
        variant_b.nonce = 2;
        let leaf_a = tree.insert_node(Some(genesis_id), variant_a, NodeStatus::HeaderValid)?;
        let leaf_b = tree.insert_node(Some(genesis_id), variant_b, NodeStatus::HeaderValid)?;

        assert_eq!(tree.find_common_ancestor(leaf_a, leaf_b), Some(genesis_id));
        Ok(())
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
}
