extern crate alloc;

use alloc::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Hash256;
use hashbrown::HashTable;
use slab::Slab;

use crate::{
    Bip9Cache, CachedState, ChainError,
    node::{BlockHeader, BlockTreeNode, ChainWork, NodeId, NodeStatus},
    tip::TipSnapshot,
};

#[path = "active_index.rs"]
mod active_index;
use active_index::ActiveHeightIndex;

/// In-memory block tree keyed by compact slab ids and header hashes.
pub struct BlockTree {
    nodes: Slab<BlockTreeNode>,
    by_hash: HashTable<NodeId>,
    active_by_height: ActiveHeightIndex,
    tip: Arc<ArcSwapOption<TipSnapshot>>,
    bip9_cache: Bip9Cache,
}

impl BlockTree {
    /// Builds an empty block tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Slab::new(),
            by_hash: HashTable::new(),
            active_by_height: ActiveHeightIndex::new(),
            tip: Arc::new(ArcSwapOption::empty()),
            bip9_cache: Bip9Cache::new(),
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
    ///
    /// Invalidates the active-height index when callers mutate an indexed node,
    /// because they can change its parent or height.
    pub fn node_mut(&mut self, id: NodeId) -> Result<&mut BlockTreeNode, ChainError> {
        let is_indexed_active_node = {
            let node = self.node(id)?;
            self.active_by_height.contains_at_height(node.height, id)
        };
        if is_indexed_active_node {
            self.active_by_height.taint(); // BEFORE yielding mut
        }
        self.node_mut_without_index_invalidation(id)
    }

    fn node_mut_without_index_invalidation(
        &mut self,
        id: NodeId,
    ) -> Result<&mut BlockTreeNode, ChainError> {
        let Some(index) = id.index() else {
            return Err(ChainError::UnknownNode { id });
        };
        self.nodes
            .get_mut(index)
            .ok_or(ChainError::UnknownNode { id })
    }

    /// Records the cumulative transaction count after applying `id`'s block.
    ///
    /// Genesis establishes the count from its own block. Every other node derives
    /// from its actual parent, so side branches remain independent. A parent with
    /// an unknown count (`0`) keeps the child unknown rather than manufacturing a
    /// partial total.
    pub fn record_applied_tx_count(
        &mut self,
        id: NodeId,
        block_tx_count: u64,
    ) -> Result<(), ChainError> {
        let (height, parent) = {
            let node = self.node(id)?;
            (node.height, node.parent)
        };
        let chain_tx_count = match parent {
            None if height == 0 => block_tx_count,
            Some(parent_id) => {
                let parent_count = self.node(parent_id)?.chain_tx_count;
                if parent_count == 0 {
                    0
                } else {
                    parent_count.checked_add(block_tx_count).unwrap_or(0)
                }
            }
            None => 0,
        };
        self.node_mut_without_index_invalidation(id)?.chain_tx_count = chain_tx_count;
        Ok(())
    }

    /// Restores an authenticated cumulative transaction count for `id`.
    pub fn restore_chain_tx_count(
        &mut self,
        id: NodeId,
        chain_tx_count: u64,
    ) -> Result<(), ChainError> {
        self.node_mut_without_index_invalidation(id)?.chain_tx_count = chain_tx_count;
        Ok(())
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

    /// Returns a reference to the node whose header hash matches `hash`, or
    /// `None` if no such node exists.
    ///
    /// Composite of [`lookup`] + [`node`] for the common 2-step pattern.
    #[must_use]
    pub fn node_by_hash(&self, hash: Hash256) -> Option<&BlockTreeNode> {
        self.node(self.lookup(hash)?).ok()
    }

    /// Returns the height of the block at `hash`, or `None` if no node with
    /// that hash exists in the tree.
    ///
    /// Composes [`node_by_hash`] + `.height` projection.
    #[must_use]
    pub fn height_of_hash(&self, hash: Hash256) -> Option<u32> {
        self.node_by_hash(hash).map(|node| node.height)
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

    /// Returns the `NodeId` of the published tip, or `None` if no tip is
    /// published yet.
    #[must_use]
    pub fn tip_id(&self) -> Option<NodeId> {
        self.tip().map(|tip| tip.tip_id)
    }

    /// Returns a reference to the `BlockTreeNode` of the published tip, or
    /// `None` if no tip is published or the tip's `NodeId` is stale.
    #[must_use]
    pub fn tip_node(&self) -> Option<&BlockTreeNode> {
        self.node(self.tip_id()?).ok()
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

    /// Returns all hashes on the published active chain from tip down to root.
    ///
    /// Returns an empty vec if no tip is published. Walks parent pointers via
    /// `ancestor_chain(tip_id)`, then projects `.hash` per node.
    ///
    /// Cost: O(N) where N = active-chain length. For locator-style sampling
    /// prefer `block_locator(tip_id, max_entries)`.
    #[must_use]
    pub fn iter_active_chain_hashes(&self) -> Vec<Hash256> {
        let Some(tip) = self.tip() else {
            return Vec::new();
        };
        let Ok(ids) = self.ancestor_chain(tip.tip_id) else {
            return Vec::new();
        };
        ids.into_iter()
            .filter_map(|id| self.node(id).ok())
            .map(|node| node.hash)
            .collect()
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

    /// Returns the cached BIP9 deployment state for `(node_id, deployment_id)`, if any.
    #[must_use]
    pub fn cached_bip9_state(&self, node_id: NodeId, deployment_id: u32) -> Option<CachedState> {
        self.bip9_cache.get(node_id, deployment_id)
    }

    /// Stores the cached BIP9 deployment state for `(node_id, deployment_id)`.
    pub fn cache_bip9_state(&self, node_id: NodeId, deployment_id: u32, state: CachedState) {
        self.bip9_cache.insert(node_id, deployment_id, state);
    }

    /// Returns the number of cached BIP9 deployment-state entries.
    #[must_use]
    pub fn cached_bip9_state_len(&self) -> usize {
        self.bip9_cache.len()
    }

    /// Builds a block locator starting from `tip_id`. For active tips, returns
    /// header hashes at offsets 0, 1, 2, ..., 9, 10, 12, 16, 24, 40, ... by
    /// sampling the height index. Side-chain, malformed, and disconnected tips
    /// walk back through parents with exponential backoff. Stops at the genesis
    /// (no parent) or after `max_entries` hashes.
    #[must_use]
    pub fn block_locator(&self, tip_id: NodeId, max_entries: usize) -> Vec<Hash256> {
        let mut locator = Vec::with_capacity(max_entries.min(32));

        if max_entries > 0
            && self.active_by_height.is_trusted()
            && self.active_by_height.last() == Some(tip_id)
            && let Ok(tip) = self.node(tip_id)
        {
            let mut target_height = tip.height;
            let mut step = 1_u32;
            let mut indexed = true;

            while locator.len() < max_entries {
                let Some(node_id) = self.active_by_height.get(target_height) else {
                    indexed = false;
                    break;
                };
                let Ok(node) = self.node(node_id) else {
                    indexed = false;
                    break;
                };
                if (locator.is_empty() && node_id != tip_id) || node.height != target_height {
                    indexed = false;
                    break;
                }

                // O(1) local active-vector adjacency: parent must match the
                // entry at h-1 (or be absent at h=0), and if h+1 exists its
                // parent must be this node. Rejects same-height fork swaps.
                let parent_matches = if target_height == 0 {
                    node.parent.is_none()
                } else {
                    matches!(
                        (
                            node.parent,
                            self.active_by_height.get(target_height - 1),
                        ),
                        (Some(parent), Some(expected)) if parent == expected
                    )
                };
                if !parent_matches {
                    indexed = false;
                    break;
                }
                if let Some(child_height) = target_height.checked_add(1)
                    && let Some(child_id) = self.active_by_height.get(child_height)
                {
                    let Ok(child) = self.node(child_id) else {
                        indexed = false;
                        break;
                    };
                    if child.parent != Some(node_id) {
                        indexed = false;
                        break;
                    }
                }

                locator.push(node.hash);
                if target_height == 0 {
                    break;
                }
                target_height = target_height.saturating_sub(step);
                if locator.len() >= 10 {
                    step = step.saturating_mul(2);
                }
            }

            if indexed {
                return locator;
            }
            locator.clear();
        }

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
    ///
    /// Parent heights must strictly decrease on the fallback walk. A cycle or
    /// other public height/parent mutation that violates that bound returns
    /// `None` instead of hanging.
    #[must_use]
    pub fn node_at_height_from(&self, start_id: NodeId, target_height: u32) -> Option<NodeId> {
        let Ok(start_node) = self.node(start_id) else {
            return None;
        };
        if target_height > start_node.height {
            return None;
        }
        if self.active_by_height.is_trusted()
            && self.active_by_height.get(start_node.height) == Some(start_id)
        {
            return self.active_by_height.get(target_height);
        }
        if target_height == start_node.height {
            return Some(start_id);
        }

        let mut cursor = start_id;
        let mut prev_height = start_node.height;
        loop {
            let Ok(node) = self.node(cursor) else {
                return None;
            };
            if cursor != start_id && node.height >= prev_height {
                return None;
            }
            if node.height == target_height {
                return Some(cursor);
            }
            if node.height < target_height {
                return None;
            }
            prev_height = node.height;
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

        if window == 11 {
            let mut times = [0_u32; 11];
            let mut len = 0;
            let mut cursor = start_id;
            while len < times.len() {
                let Ok(node) = self.node(cursor) else {
                    if len == 0 {
                        return None;
                    }
                    break;
                };
                times[len] = node.header.time;
                len += 1;
                let Some(parent) = node.parent else {
                    break;
                };
                cursor = parent;
            }

            times[..len].sort_unstable();
            return Some(times[len / 2]);
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
        let hash = hash_from_header(&header);
        self.insert_header_with_hash(header, hash, status)
    }

    pub(crate) fn insert_header_with_hash(
        &mut self,
        header: BlockHeader,
        hash: Hash256,
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
        self.insert_node_with_hash(parent, header, hash, status)
    }

    /// Inserts a header under an explicit parent.
    pub fn insert_node(
        &mut self,
        parent: Option<NodeId>,
        header: BlockHeader,
        status: NodeStatus,
    ) -> Result<NodeId, ChainError> {
        let hash = hash_from_header(&header);
        self.insert_node_with_hash(parent, header, hash, status)
    }

    fn insert_node_with_hash(
        &mut self,
        parent: Option<NodeId>,
        header: BlockHeader,
        hash: Hash256,
        status: NodeStatus,
    ) -> Result<NodeId, ChainError> {
        if self.lookup(hash).is_some() {
            return Err(ChainError::DuplicateHeader { hash });
        }

        let block_work = work_from_header(&header);
        let (height, chainwork, status) = match parent {
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
                let status = if parent_node.status == NodeStatus::Invalid {
                    NodeStatus::Invalid
                } else {
                    status
                };
                (height, chainwork, status)
            }
            None => (0, block_work, status),
        };

        let index = self.nodes.insert(BlockTreeNode {
            parent,
            height,
            hash,
            header,
            chainwork,
            chain_tx_count: 0,
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

    /// Marks `root` and every descendant invalid, then republishes the best valid tip.
    ///
    /// The returned hashes are the complete invalid subtree in deterministic slab order;
    /// callers use them to purge bounded body and download state after releasing their
    /// chain-transition witness. Equal-work valid tips retain insertion order, matching
    /// normal tip publication.
    pub fn invalidate_subtree(&mut self, root: NodeId) -> Result<Vec<Hash256>, ChainError> {
        let (invalid, best) = self.invalidation_plan(root)?;

        // Demote the previous active tip to Stale if it is not the new best and is not
        // about to be marked invalid.
        if let Some(old_tip) = self.tip_id() {
            if let Some(best) = best {
                if best != old_tip {
                    let old_index = old_tip
                        .index()
                        .ok_or(ChainError::UnknownNode { id: old_tip })?;
                    if !invalid[old_index] {
                        self.node_mut_without_index_invalidation(old_tip)?.status =
                            NodeStatus::Stale;
                    }
                }
            }
        }

        // Wipe the published tip and active index before republishing.
        self.tip.store(None);
        self.active_by_height.clear_tainted();

        // Mark the subtree invalid and collect the hashes in deterministic slab order.
        // Permanently invalid blocks can never anchor a deployment-state lookup
        // again, so their memoized states go with them.
        let mut hashes = Vec::with_capacity(invalid.iter().filter(|&&b| b).count());
        for (index, node) in &mut self.nodes {
            if invalid[index] {
                node.status = NodeStatus::Invalid;
                hashes.push(node.hash);
                if let Ok(id) = u32::try_from(index) {
                    self.bip9_cache.invalidate_node(NodeId::new(id));
                }
            }
        }

        // Republish the best valid tip (if any), which also rebuilds the active index.
        if let Some(best) = best {
            self.publish_tip_if_best(best)?;
        }

        Ok(hashes)
    }

    /// Returns the tip that would become active after invalidating `root` and
    /// its descendants, without changing the tree.
    pub fn tip_after_invalidation(&self, root: NodeId) -> Result<Option<NodeId>, ChainError> {
        self.invalidation_plan(root).map(|(_, best)| best)
    }

    fn invalidation_plan(&self, root: NodeId) -> Result<(Vec<bool>, Option<NodeId>), ChainError> {
        let root_index = root.index().ok_or(ChainError::UnknownNode { id: root })?;
        self.node(root)?;

        // Build child adjacency in one forward pass over the slab.
        let node_count = self.nodes.capacity();
        let mut children: Vec<Vec<NodeId>> = (0..node_count).map(|_| Vec::new()).collect();
        for (index, node) in &self.nodes {
            if let Some(parent) = node.parent {
                let parent_index = parent
                    .index()
                    .ok_or(ChainError::UnknownNode { id: parent })?;
                let child_id = u32::try_from(index)
                    .map(NodeId::new)
                    .map_err(|_| ChainError::NodeIdOverflow { index })?;
                children[parent_index].push(child_id);
            }
        }

        // Worklist traversal of the child adjacency: each node is visited once.
        let mut invalid = vec![false; node_count];
        let mut worklist = vec![root];
        invalid[root_index] = true;
        while let Some(id) = worklist.pop() {
            let idx = id.index().ok_or(ChainError::UnknownNode { id })?;
            for &child in &children[idx] {
                let child_index = child.index().ok_or(ChainError::UnknownNode { id: child })?;
                if !invalid[child_index] {
                    invalid[child_index] = true;
                    worklist.push(child);
                }
            }
        }

        // Select the best remaining valid tip before mutating statuses, using the same
        // deterministic ordering `publish_tip_if_best` applies: greater chainwork wins,
        // and for equal work the earlier insertion (lower slab index) wins.
        let best = self
            .nodes
            .iter()
            .filter(|(index, _)| !invalid[*index])
            .filter(|(_, node)| node.status != NodeStatus::Invalid)
            .max_by(|(left_index, left), (right_index, right)| {
                left.chainwork
                    .cmp(&right.chainwork)
                    .then_with(|| right_index.cmp(left_index))
            })
            .map(|(index, _)| {
                u32::try_from(index)
                    .map(NodeId::new)
                    .map_err(|_| ChainError::NodeIdOverflow { index })
            })
            .transpose()?;

        Ok((invalid, best))
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
        if node.status == NodeStatus::Invalid {
            return Ok(());
        }
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
            self.node_mut_without_index_invalidation(old_tip.tip_id)?
                .status = NodeStatus::Stale;
        }
        self.node_mut_without_index_invalidation(node_id)?.status = NodeStatus::Active;
        let node = self.node(node_id)?;
        self.tip.store(Some(Arc::new(TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })));
        self.refresh_active_height_index(node_id);
        Ok(())
    }

    fn refresh_active_height_index(&mut self, tip_id: NodeId) {
        let Ok(tip) = self.node(tip_id) else {
            self.active_by_height.clear_tainted();
            return;
        };
        let tip_parent = tip.parent;
        let tip_height = tip.height;

        if let Some(parent) = tip_parent
            && self
                .active_by_height
                .extend_validated(parent, tip_height, tip_id)
        {
            return;
        }

        // Full rebuild into temporary Vec (do not mutate live index mid-validation)
        let mut rebuilt = Vec::new();
        let mut cursor = Some(tip_id);
        let mut seen: hashbrown::HashSet<NodeId> = hashbrown::HashSet::new();
        while let Some(id) = cursor {
            if !seen.insert(id) {
                self.active_by_height.clear_tainted();
                return;
            }
            let Ok(node) = self.node(id) else {
                self.active_by_height.clear_tainted();
                return;
            };
            let parent = node.parent;
            rebuilt.push(id);
            cursor = parent;
        }
        rebuilt.reverse();

        for (offset, id) in rebuilt.iter().enumerate() {
            let Ok(node) = self.node(*id) else {
                self.active_by_height.clear_tainted();
                return;
            };
            if usize::try_from(node.height).ok() != Some(offset) {
                self.active_by_height.clear_tainted();
                return;
            }
        }

        self.active_by_height.commit_validated_rebuild(rebuilt);
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

    use super::{BlockTree, Hash256, hash_from_header};
    use crate::{
        node::{ChainWork, NodeId, NodeStatus},
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
    fn block_locator_falls_back_after_active_parent_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let a = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let b_header = test_header(
            BlockHash::from_byte_array(tree.node(a)?.hash.to_le_bytes()),
            1,
        );
        let b = tree.insert_node(Some(a), b_header, NodeStatus::HeaderValid)?;
        let c_header = test_header(
            BlockHash::from_byte_array(tree.node(b)?.hash.to_le_bytes()),
            2,
        );
        let c = tree.insert_node(Some(b), c_header, NodeStatus::HeaderValid)?;

        // Mutating an indexed active node's parent invalidates the height
        // index, forcing block_locator onto the parent-walk fallback.
        tree.node_mut(c)?.parent = Some(a);

        let c_hash = tree.node(c)?.hash;
        let a_hash = tree.node(a)?.hash;
        assert_eq!(tree.block_locator(c, 3), vec![c_hash, a_hash]);
        Ok(())
    }

    #[test]
    fn block_locator_falls_back_on_same_height_fork_index_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = BlockHash::from_byte_array(tree.node(genesis_id)?.hash.to_le_bytes());

        let main_child = test_header(genesis_hash, 1);
        let main_child_id =
            tree.insert_node(Some(genesis_id), main_child, NodeStatus::HeaderValid)?;
        let main_child_hash =
            BlockHash::from_byte_array(tree.node(main_child_id)?.hash.to_le_bytes());
        let main_tip = test_header(main_child_hash, 2);
        let main_tip_id =
            tree.insert_node(Some(main_child_id), main_tip, NodeStatus::HeaderValid)?;

        // Same-height side fork (shares genesis parent with main_child).
        let fork_child = test_header(genesis_hash, 11);
        let fork_child_id =
            tree.insert_node(Some(genesis_id), fork_child, NodeStatus::HeaderValid)?;
        let fork_hash = tree.node(fork_child_id)?.hash;

        assert_eq!(tree.active_by_height.last(), Some(main_tip_id));
        assert_eq!(tree.active_by_height.get(1), Some(main_child_id));

        // Corrupt the height-1 index slot to the same-height fork node while
        // leaving the tip slot intact so the indexed path is still attempted.
        // Seam taints first; trust gate then forces parent-walk for both locators.
        assert!(
            tree.active_by_height
                .replace_slot_for_test(1, fork_child_id)
        );

        let corrupted_locator = tree.block_locator(main_tip_id, 32);
        tree.active_by_height.taint();
        let parent_walk_locator = tree.block_locator(main_tip_id, 32);

        assert_eq!(corrupted_locator, parent_walk_locator);
        assert!(!corrupted_locator.contains(&fork_hash));
        assert_eq!(
            corrupted_locator,
            vec![
                tree.node(main_tip_id)?.hash,
                tree.node(main_child_id)?.hash,
                tree.node(genesis_id)?.hash,
            ]
        );
        Ok(())
    }

    #[test]
    fn block_locator_rejects_coherent_side_fork_index_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let mut tip_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut main_ids = vec![tip_id];

        for height in 1..=40_u32 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            main_ids.push(tip_id);
        }

        // Side branch from main[18] at heights 19..=26; must not become tip.
        let mut side_parent_id = main_ids[18];
        let mut side_parent_hash =
            BlockHash::from_byte_array(tree.node(side_parent_id)?.hash.to_le_bytes());
        let mut side_ids = Vec::new();
        let mut side_hashes = Vec::new();
        for height in 19..=26_u32 {
            let header = test_header(side_parent_hash, height.wrapping_add(1000));
            let side_id =
                tree.insert_node(Some(side_parent_id), header, NodeStatus::HeaderValid)?;
            side_ids.push(side_id);
            side_hashes.push(tree.node(side_id)?.hash);
            side_parent_id = side_id;
            side_parent_hash = BlockHash::from_byte_array(tree.node(side_id)?.hash.to_le_bytes());
        }

        assert_eq!(tree.tip_id(), Some(main_ids[40]));
        assert!(tree.active_by_height.is_trusted());

        for (offset, side_id) in (0_u32..).zip(side_ids.iter()) {
            let height = 19 + offset;
            assert!(
                tree.active_by_height
                    .replace_slot_for_test(height, *side_id)
            );
        }
        assert!(tree.active_by_height.is_tainted_for_test());

        // Local neighborhood coherence at h=24 would pass the old adjacency guard.
        let i24 = tree.active_by_height.get(24).ok_or("corrupted slot 24")?;
        let i23 = tree.active_by_height.get(23).ok_or("corrupted slot 23")?;
        let i25 = tree.active_by_height.get(25).ok_or("corrupted slot 25")?;
        assert_eq!(tree.node(i24)?.height, 24);
        assert_eq!(tree.node(i24)?.parent, Some(i23));
        assert_eq!(tree.node(i25)?.parent, Some(i24));

        for (offset, &side_id) in side_ids.iter().enumerate() {
            let height = 19 + u32::try_from(offset).map_err(|_| "side chain offset fits u32")?;
            assert_eq!(tree.node(side_id)?.height, height);
            if height == 19 {
                assert_eq!(tree.node(side_id)?.parent, Some(main_ids[18]));
            } else {
                assert_eq!(tree.node(side_id)?.parent, Some(side_ids[offset - 1]));
            }
        }

        let expected = parent_walk_locator_schedule(&tree, main_ids[40], 32);
        assert_eq!(tree.block_locator(main_ids[40], 32), expected);
        for side_hash in &side_hashes {
            assert!(!expected.contains(side_hash));
            assert!(!tree.block_locator(main_ids[40], 32).contains(side_hash));
        }
        Ok(())
    }

    #[test]
    fn node_at_height_from_ignores_tainted_index_slot() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let mut tip_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut main_ids = vec![tip_id];

        for height in 1..=40_u32 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            main_ids.push(tip_id);
        }

        let side_header = test_header(
            BlockHash::from_byte_array(tree.node(main_ids[18])?.hash.to_le_bytes()),
            1019,
        );
        let side_id = tree.insert_node(Some(main_ids[18]), side_header, NodeStatus::HeaderValid)?;

        // Height 19 is not in the tip-40 locator sample set (40..30,28,24,16,0).
        assert!(tree.active_by_height.replace_slot_for_test(19, side_id));
        assert!(tree.active_by_height.is_tainted_for_test());

        assert_eq!(
            tree.node_at_height_from(main_ids[30], 19),
            Some(main_ids[19])
        );
        assert_ne!(tree.node_at_height_from(main_ids[30], 19), Some(side_id));
        Ok(())
    }

    #[test]
    fn node_at_height_from_indexes_active_prefix_but_walks_side_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let mut main_tip = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut main_ids = vec![main_tip];

        for height in 1..=5_u32 {
            let parent_hash = BlockHash::from_byte_array(tree.node(main_tip)?.hash.to_le_bytes());
            main_tip = tree.insert_node(
                Some(main_tip),
                test_header(parent_hash, height),
                NodeStatus::HeaderValid,
            )?;
            main_ids.push(main_tip);
        }

        let mut side_tip = main_ids[0];
        let mut side_ids = vec![side_tip];
        for nonce in 11..=13_u32 {
            let parent_hash = BlockHash::from_byte_array(tree.node(side_tip)?.hash.to_le_bytes());
            side_tip = tree.insert_node(
                Some(side_tip),
                test_header(parent_hash, nonce),
                NodeStatus::HeaderValid,
            )?;
            side_ids.push(side_tip);
        }

        assert_eq!(tree.node_at_height_from(side_ids[3], 1), Some(side_ids[1]));

        let active_prefix = main_ids[4];
        let active_prefix_index = usize::try_from(active_prefix.get())?;
        tree.nodes
            .get_mut(active_prefix_index)
            .ok_or("missing active prefix")?
            .parent = None;
        assert_eq!(
            tree.node_at_height_from(active_prefix, 1),
            Some(main_ids[1])
        );
        Ok(())
    }

    #[test]
    fn block_locator_preserves_schedule_at_exponential_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let mut tip_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut hashes = vec![hash_from_header(&genesis)];

        for height in 1..=40_u32 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            hashes.push(hash_from_header(&header));
        }

        let tip_h = 40_u32;
        let locator = tree.block_locator(tip_id, 32);
        let expected_heights = [
            tip_h,
            tip_h - 1,
            tip_h - 2,
            tip_h - 3,
            tip_h - 4,
            tip_h - 5,
            tip_h - 6,
            tip_h - 7,
            tip_h - 8,
            tip_h - 9,
            tip_h - 10,
            tip_h - 12,
            tip_h - 16,
            tip_h - 24,
            tip_h - 40,
        ];
        let expected: Vec<Hash256> = expected_heights
            .iter()
            .map(|&h| -> Result<Hash256, Box<dyn std::error::Error>> {
                let idx = usize::try_from(h).map_err(|_| "locator height fits usize")?;
                Ok(hashes[idx])
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(locator, expected);
        Ok(())
    }

    #[test]
    fn block_locator_indexed_path_matches_parent_walk() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let mut tip_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut mid_node = None;

        for height in 1..=25_u32 {
            let parent_hash = BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = test_header(parent_hash, height);
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
            if height == 10 {
                mid_node = Some(tip_id);
            }
        }

        let indexed = tree.block_locator(tip_id, 32);
        tree.active_by_height.taint();
        let walked = tree.block_locator(tip_id, 32);
        assert_eq!(indexed, walked);

        // A non-active-tip node still yields a non-empty locator via the
        // parent-walk fallback once the height index is cleared.
        let side = mid_node.ok_or("height 10 node was recorded")?;
        let side_locator = tree.block_locator(side, 32);
        assert!(!side_locator.is_empty());
        assert_eq!(side_locator[0], tree.node(side)?.hash);
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
    fn median_time_past_at_parity_across_zero_short_eleven_and_wider_windows()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let mut prev_hash = BlockHash::all_zeros();
        let mut tip = None;
        let mut times = Vec::new();
        let mut ids = Vec::new();

        for i in 0..15_u32 {
            let header = BlockHeader {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000 + i * 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            prev_hash = header.block_hash();
            times.push(header.time);
            let id = tree.insert_header(header, NodeStatus::HeaderValid)?;
            ids.push(id);
            tip = Some(id);
        }

        let Some(tip) = tip else {
            panic!("chain has 15 blocks should yield a tip");
        };

        assert_eq!(tree.median_time_past_at(tip, 0), Some(0));
        assert_eq!(
            tree.median_time_past_at(tip, 5),
            Some(expected_median_time_past(&times, 5))
        );
        assert_eq!(
            tree.median_time_past_at(tip, 11),
            Some(expected_median_time_past(&times, 11))
        );
        assert_eq!(
            tree.median_time_past_at(tip, 15),
            Some(expected_median_time_past(&times, 15))
        );

        let short_tip = ids[2];
        assert_eq!(
            tree.median_time_past_at(short_tip, 11),
            Some(expected_median_time_past(&times[..=2], 11))
        );

        assert_eq!(
            tree.median_time_past_at(crate::node::NodeId::new(u32::MAX), 11),
            None
        );
        assert_eq!(
            tree.median_time_past_at(crate::node::NodeId::new(u32::MAX), 5),
            None
        );
        Ok(())
    }

    fn expected_median_time_past(times_oldest_first: &[u32], window: usize) -> u32 {
        let take = window.min(times_oldest_first.len());
        let mut sample: Vec<u32> = times_oldest_first[times_oldest_first.len() - take..].to_vec();
        sample.sort_unstable();
        sample[sample.len() / 2]
    }

    #[test]
    fn node_by_hash_returns_none_for_unknown_hash() {
        let tree = BlockTree::new();
        let unknown = Hash256::from_le_bytes(&[0xab_u8; 32]);
        assert!(tree.node_by_hash(unknown).is_none());
    }

    #[test]
    fn node_by_hash_returns_inserted_node() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        let Some(node) = tree.node_by_hash(genesis_hash) else {
            panic!("node_by_hash returned None for inserted genesis");
        };
        assert_eq!(node.hash, genesis_hash);
        Ok(())
    }

    #[test]
    fn height_of_hash_returns_none_for_unknown_hash() {
        let tree = BlockTree::new();
        let unknown = Hash256::from_le_bytes(&[0xff_u8; 32]);
        assert!(tree.height_of_hash(unknown).is_none());
    }

    #[test]
    fn height_of_hash_returns_node_height_for_inserted_block()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        let expected_height = tree.node(genesis_id)?.height;

        assert_eq!(tree.height_of_hash(genesis_hash), Some(expected_height));
        Ok(())
    }

    #[test]
    fn active_node_at_height_returns_none_when_no_tip() {
        let tree = BlockTree::new();
        assert!(tree.active_node_at_height(0).is_none());
    }

    #[test]
    fn tip_id_returns_none_before_publish() {
        let tree = BlockTree::new();
        assert!(tree.tip_id().is_none());
        assert!(tree.tip_node().is_none());
    }

    #[test]
    fn tip_id_returns_published_tip() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        assert_eq!(tree.tip_id(), Some(genesis_id));
        let Some(node) = tree.tip_node() else {
            panic!("tip_node returned None for published tip");
        };
        assert_eq!(node.hash, genesis_hash);
        Ok(())
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
    fn iter_active_chain_hashes_returns_empty_for_no_tip() {
        let tree = BlockTree::new();
        assert!(tree.iter_active_chain_hashes().is_empty());
    }

    #[test]
    fn iter_active_chain_hashes_returns_genesis_only_for_singleton_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        let hashes = tree.iter_active_chain_hashes();

        assert_eq!(hashes, vec![genesis_hash]);
        Ok(())
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
    fn node_at_height_from_uses_rebuilt_active_height_index_after_fork_switch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = BlockHash::from_byte_array(tree.node(genesis_id)?.hash.to_le_bytes());

        let main_child = test_header(genesis_hash, 1);
        let main_child_id =
            tree.insert_node(Some(genesis_id), main_child, NodeStatus::HeaderValid)?;
        let main_child_hash =
            BlockHash::from_byte_array(tree.node(main_child_id)?.hash.to_le_bytes());
        let main_tip = test_header(main_child_hash, 2);
        let main_tip_id =
            tree.insert_node(Some(main_child_id), main_tip, NodeStatus::HeaderValid)?;

        assert_eq!(
            tree.node_at_height_from(main_tip_id, 1),
            Some(main_child_id)
        );

        let fork_child = test_header(genesis_hash, 11);
        let fork_child_id =
            tree.insert_node(Some(genesis_id), fork_child, NodeStatus::HeaderValid)?;
        let fork_child_hash =
            BlockHash::from_byte_array(tree.node(fork_child_id)?.hash.to_le_bytes());
        let fork_mid = test_header(fork_child_hash, 12);
        let fork_mid_id =
            tree.insert_node(Some(fork_child_id), fork_mid, NodeStatus::HeaderValid)?;
        let fork_mid_hash = BlockHash::from_byte_array(tree.node(fork_mid_id)?.hash.to_le_bytes());
        let fork_tip = test_header(fork_mid_hash, 13);
        let fork_tip_id = tree.insert_node(Some(fork_mid_id), fork_tip, NodeStatus::HeaderValid)?;

        assert_eq!(
            tree.node_at_height_from(fork_tip_id, 1),
            Some(fork_child_id)
        );
        assert_eq!(
            tree.active_node_at_height(1)
                .unwrap_or_else(|| panic!("missing active node at fork height"))
                .hash,
            tree.node(fork_child_id)?.hash
        );
        assert_eq!(
            tree.node_at_height_from(main_tip_id, 1),
            Some(main_child_id)
        );
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

    #[test]
    fn node_at_height_from_terminates_on_two_node_cycle_with_malformed_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let a = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let b_header = test_header(
            BlockHash::from_byte_array(tree.node(a)?.hash.to_le_bytes()),
            1,
        );
        let b = tree.insert_node(Some(a), b_header, NodeStatus::HeaderValid)?;

        // Two-node parent cycle with a non-decreasing height so the fallback
        // walk cannot reach the target by ordinary height descent.
        tree.node_mut(a)?.parent = Some(b);
        tree.node_mut(a)?.height = 2;

        assert_eq!(tree.node_at_height_from(b, 0), None);
        Ok(())
    }

    #[test]
    fn refresh_active_height_index_terminates_on_parent_cycle()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let a = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let b_header = test_header(
            BlockHash::from_byte_array(tree.node(a)?.hash.to_le_bytes()),
            1,
        );
        let b = tree.insert_node(Some(a), b_header, NodeStatus::HeaderValid)?;

        tree.node_mut(a)?.parent = Some(b);

        let c_header = test_header(
            BlockHash::from_byte_array(tree.node(b)?.hash.to_le_bytes()),
            2,
        );
        let c = tree.insert_node(Some(b), c_header, NodeStatus::HeaderValid)?;

        assert_eq!(tree.tip_id(), Some(c));
        assert!(tree.active_by_height.is_empty_for_test());
        Ok(())
    }

    #[test]
    fn refresh_active_height_index_clears_on_unknown_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let a = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let b_header = test_header(
            BlockHash::from_byte_array(tree.node(a)?.hash.to_le_bytes()),
            1,
        );
        let b = tree.insert_node(Some(a), b_header, NodeStatus::HeaderValid)?;
        let c_header = test_header(
            BlockHash::from_byte_array(tree.node(b)?.hash.to_le_bytes()),
            2,
        );
        let c = tree.insert_node(Some(b), c_header, NodeStatus::HeaderValid)?;

        tree.node_mut(b)?.parent = Some(crate::node::NodeId::new(u32::MAX));

        let d_header = test_header(
            BlockHash::from_byte_array(tree.node(c)?.hash.to_le_bytes()),
            3,
        );
        let d = tree.insert_node(Some(c), d_header, NodeStatus::HeaderValid)?;

        assert_eq!(tree.tip_id(), Some(d));
        assert!(tree.active_by_height.is_empty_for_test());
        Ok(())
    }

    #[test]
    fn refresh_active_height_index_clears_on_changed_height_republish()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let a = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let b_header = test_header(
            BlockHash::from_byte_array(tree.node(a)?.hash.to_le_bytes()),
            1,
        );
        let b = tree.insert_node(Some(a), b_header, NodeStatus::HeaderValid)?;
        let c_header = test_header(
            BlockHash::from_byte_array(tree.node(b)?.hash.to_le_bytes()),
            2,
        );
        let c = tree.insert_node(Some(b), c_header, NodeStatus::HeaderValid)?;

        tree.node_mut(b)?.height = 99;

        let d_header = test_header(
            BlockHash::from_byte_array(tree.node(c)?.hash.to_le_bytes()),
            3,
        );
        let d = tree.insert_node(Some(c), d_header, NodeStatus::HeaderValid)?;

        assert_eq!(tree.tip_id(), Some(d));
        assert!(tree.active_by_height.is_empty_for_test());
        assert!(
            tree.active_node_at_height(1)
                .is_none_or(|node| node.height == 1)
        );
        Ok(())
    }

    /// Independent parent-walk locator using the production exponential schedule.
    /// Used so expected locators are not tautological with a tainted `block_locator`.
    fn parent_walk_locator_schedule(
        tree: &BlockTree,
        tip_id: NodeId,
        max_entries: usize,
    ) -> Vec<Hash256> {
        let mut locator = Vec::with_capacity(max_entries.min(32));
        let mut current = tip_id;
        let mut step: u64 = 1;
        while locator.len() < max_entries {
            let Ok(node) = tree.node(current) else {
                break;
            };
            locator.push(node.hash);

            let mut walker = current;
            let mut walked = false;
            for _ in 0..step {
                let Ok(walker_node) = tree.node(walker) else {
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

    #[test]
    fn invalidate_subtree_marks_root_and_descendants_invalid_and_reselects_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        // Main chain: genesis -> a1 -> a2
        let a1_header = test_header(BlockHash::from_byte_array(genesis_hash.to_le_bytes()), 1);
        let a1_id = tree.insert_node(Some(genesis_id), a1_header, NodeStatus::HeaderValid)?;
        let a1_hash = tree.node(a1_id)?.hash;
        let a2_header = test_header(BlockHash::from_byte_array(a1_hash.to_le_bytes()), 2);
        let a2_id = tree.insert_node(Some(a1_id), a2_header, NodeStatus::HeaderValid)?;

        // Side chain: genesis -> b1 -> b2 -> b3 (longer, active)
        let mut side_parent = genesis_id;
        let mut side_parent_hash = genesis_hash;
        let mut side_ids = Vec::new();
        let mut side_hashes = Vec::new();
        for height in 1..=3 {
            let header = test_header(
                BlockHash::from_byte_array(side_parent_hash.to_le_bytes()),
                100 + height,
            );
            let id = tree.insert_node(Some(side_parent), header, NodeStatus::HeaderValid)?;
            side_ids.push(id);
            side_hashes.push(tree.node(id)?.hash);
            side_parent = id;
            side_parent_hash = tree.node(id)?.hash;
        }

        // The side chain is the active tip because it is longer.
        assert_eq!(tree.tip_id(), Some(side_ids[2]));
        assert_eq!(tree.active_by_height.get(1), Some(side_ids[0]));

        // Previewing the invalidation selects a2 without mutating status or tip.
        assert_eq!(tree.tip_after_invalidation(side_ids[0])?, Some(a2_id));
        assert_eq!(tree.tip_id(), Some(side_ids[2]));
        assert_eq!(tree.node(side_ids[0])?.status, NodeStatus::HeaderValid);

        // Invalidate the side root (b1). This must mark b1..b3 invalid and reselect a2.
        let invalid_hashes = tree.invalidate_subtree(side_ids[0])?;
        assert_eq!(invalid_hashes.len(), 3);
        for (id, hash) in side_ids.iter().zip(side_hashes.iter()) {
            assert_eq!(tree.node(*id)?.status, NodeStatus::Invalid);
            assert!(invalid_hashes.contains(hash));
        }

        assert_eq!(tree.tip_id(), Some(a2_id));
        assert_eq!(tree.node(a2_id)?.status, NodeStatus::Active);
        assert_eq!(tree.active_by_height.get(2), Some(a2_id));
        assert!(tree.active_by_height.is_trusted());
        assert_ne!(tree.node(genesis_id)?.status, NodeStatus::Invalid);
        Ok(())
    }

    #[test]
    fn invalidate_subtree_uses_insertion_order_for_equal_work_tie_break()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        // Three equal-length forks: a, b, c (inserted in that order).
        let mut fork_tips = Vec::new();
        for fork in 0..3 {
            let first = test_header(
                BlockHash::from_byte_array(genesis_hash.to_le_bytes()),
                10 + fork,
            );
            let first_id = tree.insert_node(Some(genesis_id), first, NodeStatus::HeaderValid)?;
            let first_hash = tree.node(first_id)?.hash;
            let second = test_header(
                BlockHash::from_byte_array(first_hash.to_le_bytes()),
                20 + fork,
            );
            let second_id = tree.insert_node(Some(first_id), second, NodeStatus::HeaderValid)?;
            fork_tips.push(second_id);
        }

        // a is active because it was inserted first and all forks have equal chainwork.
        assert_eq!(tree.tip_id(), Some(fork_tips[0]));

        // Invalidate the active a fork. The next earliest equal-work fork (b) wins.
        tree.invalidate_subtree(fork_tips[0])?;
        assert_eq!(tree.node(fork_tips[0])?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip_id(), Some(fork_tips[1]));
        assert_eq!(tree.node(fork_tips[1])?.status, NodeStatus::Active);

        // c is still valid but not active.
        assert_eq!(tree.node(fork_tips[2])?.status, NodeStatus::HeaderValid);
        Ok(())
    }

    #[test]
    fn insert_under_invalid_parent_is_invalid_and_does_not_publish()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        let a1 = test_header(BlockHash::from_byte_array(genesis_hash.to_le_bytes()), 1);
        let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::HeaderValid)?;
        let a1_hash = tree.node(a1_id)?.hash;
        let a2 = test_header(BlockHash::from_byte_array(a1_hash.to_le_bytes()), 2);
        let a2_id = tree.insert_node(Some(a1_id), a2, NodeStatus::HeaderValid)?;

        // Invalidate the active chain root a1, leaving only genesis valid.
        tree.invalidate_subtree(a1_id)?;
        assert_eq!(tree.node(a1_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.node(a2_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip_id(), Some(genesis_id));

        // Inserting a child under the invalid a1 must itself be invalid and cannot become tip.
        let a3 = test_header(BlockHash::from_byte_array(a1_hash.to_le_bytes()), 3);
        let a3_id = tree.insert_node(Some(a1_id), a3, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(a3_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip_id(), Some(genesis_id));
        Ok(())
    }

    #[test]
    fn applied_transaction_counts_follow_each_nodes_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(genesis_id)?.chain_tx_count, 0);

        tree.record_applied_tx_count(genesis_id, 1)?;
        assert_eq!(tree.node(genesis_id)?.chain_tx_count, 1);

        let genesis_hash = tree.node(genesis_id)?.hash;
        let main_header = test_header(BlockHash::from_byte_array(genesis_hash.to_le_bytes()), 1);
        let main_id = tree.insert_node(Some(genesis_id), main_header, NodeStatus::HeaderValid)?;
        let side_header = test_header(BlockHash::from_byte_array(genesis_hash.to_le_bytes()), 101);
        let side_id = tree.insert_node(Some(genesis_id), side_header, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(main_id)?.chain_tx_count, 0);
        assert_eq!(tree.node(side_id)?.chain_tx_count, 0);

        tree.record_applied_tx_count(main_id, 2)?;
        tree.record_applied_tx_count(side_id, 7)?;
        assert_eq!(tree.node(main_id)?.chain_tx_count, 3);
        assert_eq!(tree.node(side_id)?.chain_tx_count, 8);
        Ok(())
    }

    #[test]
    fn unknown_parent_count_stays_unknown_until_authenticated_restore()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::all_zeros(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let child_header = test_header(
            BlockHash::from_byte_array(tree.node(genesis_id)?.hash.to_le_bytes()),
            1,
        );
        let child_id = tree.insert_node(Some(genesis_id), child_header, NodeStatus::HeaderValid)?;

        tree.record_applied_tx_count(child_id, 3)?;
        assert_eq!(tree.node(child_id)?.chain_tx_count, 0);

        tree.restore_chain_tx_count(genesis_id, 11)?;
        tree.record_applied_tx_count(child_id, 3)?;
        assert_eq!(tree.node(child_id)?.chain_tx_count, 14);
        tree.restore_chain_tx_count(child_id, 42)?;
        assert_eq!(tree.node(child_id)?.chain_tx_count, 42);
        Ok(())
    }
}
