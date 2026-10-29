use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_primitives::Hash256;
use hashbrown::{HashMap, HashTable};
use parking_lot::RwLock;
use slab::Slab;

use crate::{
    ChainError, ChainTxCount, TipSnapshot,
    node::{BlockHeader, BlockTreeNode, NodeId, NodeStatus},
};

mod active_index;
use active_index::ActiveHeightIndex;

#[derive(Default)]
struct Bip9Cache {
    entries: RwLock<HashMap<(NodeId, u32), u8>>,
}

impl Bip9Cache {
    fn insert(&self, node_id: NodeId, deployment_id: u32, tag: u8) {
        self.entries.write().insert((node_id, deployment_id), tag);
    }

    #[must_use]
    fn get(&self, node_id: NodeId, deployment_id: u32) -> Option<u8> {
        self.entries.read().get(&(node_id, deployment_id)).copied()
    }

    fn invalidate_nodes(&self, invalid: &[bool]) {
        self.entries.write().retain(|(id, _), _| {
            id.index()
                .is_none_or(|index| invalid.get(index) != Some(&true))
        });
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidationOutcome {
    pub invalid: Vec<Hash256>,
    pub demoted_tip: Option<Hash256>,
}

#[derive(Clone, Copy)]
pub(crate) struct Inserted {
    pub(crate) id: NodeId,
    pub(crate) demoted_tip: Option<Hash256>,
}

pub struct BlockTree {
    nodes: Slab<BlockTreeNode>,
    by_hash: HashTable<NodeId>,
    active_by_height: ActiveHeightIndex,
    tip: Arc<ArcSwapOption<TipSnapshot>>,
    bip9_cache: Bip9Cache,
}

impl BlockTree {
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Slab::new(),
            by_hash: HashTable::new(),
            active_by_height: ActiveHeightIndex::new(),
            tip: Arc::new(ArcSwapOption::empty()),
            bip9_cache: Bip9Cache::default(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn node(&self, id: NodeId) -> Result<&BlockTreeNode, ChainError> {
        let Some(index) = id.index() else {
            return Err(ChainError::UnknownNode { id });
        };
        self.nodes.get(index).ok_or(ChainError::UnknownNode { id })
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn node_mut(&mut self, id: NodeId) -> Result<&mut BlockTreeNode, ChainError> {
        let is_indexed_active_node = {
            let node = self.node(id)?;
            self.active_by_height.contains_at_height(node.height, id)
        };
        if is_indexed_active_node {
            self.active_by_height.taint();
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

    pub fn record_applied_tx_count(
        &mut self,
        id: NodeId,
        block_tx_count: u64,
    ) -> Result<(), ChainError> {
        let (height, parent) = {
            let node = self.node(id)?;
            (node.height, node.parent)
        };
        let parent_count = match parent {
            Some(parent_id) => self.node(parent_id)?.chain_tx_count,
            None => ChainTxCount::UNKNOWN,
        };
        let chain_tx_count = parent_count.advance(height, block_tx_count);
        self.node_mut_without_index_invalidation(id)?.chain_tx_count = chain_tx_count;
        self.refresh_published_tip(id);
        Ok(())
    }

    pub fn restore_chain_tx_count(
        &mut self,
        id: NodeId,
        chain_tx_count: ChainTxCount,
    ) -> Result<(), ChainError> {
        self.node_mut_without_index_invalidation(id)?.chain_tx_count = chain_tx_count;
        self.refresh_published_tip(id);
        Ok(())
    }

    fn refresh_published_tip(&self, id: NodeId) {
        if self.tip.load_full().is_none_or(|tip| tip.tip_id != id) {
            return;
        }
        if let Ok(snapshot) = self.tip_snapshot(id) {
            self.tip.store(Some(Arc::new(snapshot)));
        }
    }

    fn tip_snapshot(&self, id: NodeId) -> Result<TipSnapshot, ChainError> {
        let node = self.node(id)?;
        Ok(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        })
    }

    #[must_use]
    pub fn find_common_ancestor(&self, a: NodeId, b: NodeId) -> Option<NodeId> {
        if self.active_by_height.is_trusted() {
            for (active, mut other) in [(a, b), (b, a)] {
                let height = self.node(active).ok()?.height;
                if self.active_by_height.get(height) != Some(active) {
                    continue;
                }
                for _ in 0..self.len() {
                    let node = self.node(other).ok()?;
                    if self.active_by_height.get(node.height) == Some(other) {
                        return self.active_by_height.get(height.min(node.height));
                    }
                    other = node.parent?;
                }
                return None;
            }
        }

        let ancestry = |mut id| {
            for depth in 0..self.len() {
                match self.node(id).ok()?.parent {
                    Some(parent) => id = parent,
                    None => return Some((id, depth)),
                }
            }
            None
        };
        let (a_root, a_depth) = ancestry(a)?;
        let (b_root, b_depth) = ancestry(b)?;
        if a_root != b_root {
            return None;
        }
        let (mut a, mut b) = (a, b);
        for _ in b_depth..a_depth {
            a = self.node(a).ok()?.parent?;
        }
        for _ in a_depth..b_depth {
            b = self.node(b).ok()?.parent?;
        }
        while a != b {
            a = self.node(a).ok()?.parent?;
            b = self.node(b).ok()?.parent?;
        }
        Some(a)
    }

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

    #[must_use]
    pub fn node_by_hash(&self, hash: Hash256) -> Option<&BlockTreeNode> {
        self.node(self.lookup(hash)?).ok()
    }

    #[must_use]
    pub fn height_of_hash(&self, hash: Hash256) -> Option<u32> {
        self.node_by_hash(hash).map(|node| node.height)
    }

    #[must_use]
    pub fn leaf_node_ids(&self) -> Vec<NodeId> {
        let mut parents: hashbrown::HashSet<usize> = hashbrown::HashSet::new();
        for (_index, node) in &self.nodes {
            if let Some(parent_index) = node.parent.and_then(NodeId::index) {
                parents.insert(parent_index);
            }
        }

        let mut leaves = Vec::new();
        for (index, _node) in &self.nodes {
            if !parents.contains(&index)
                && let Ok(id_u32) = u32::try_from(index)
            {
                leaves.push(NodeId::new(id_u32));
            }
        }
        leaves
    }

    #[must_use]
    pub fn tip(&self) -> Option<Arc<TipSnapshot>> {
        self.tip.load_full()
    }

    #[must_use]
    pub fn tip_id(&self) -> Option<NodeId> {
        self.tip().map(|tip| tip.tip_id)
    }

    #[must_use]
    pub fn tip_height(&self) -> Option<u32> {
        self.tip().map(|tip| tip.height)
    }

    #[must_use]
    pub fn tip_handle(&mut self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.tip)
    }

    #[must_use]
    pub(crate) fn cached_bip9_state(&self, node_id: NodeId, deployment_id: u32) -> Option<u8> {
        self.bip9_cache.get(node_id, deployment_id)
    }

    pub(crate) fn cache_bip9_state(&self, node_id: NodeId, deployment_id: u32, tag: u8) {
        self.bip9_cache.insert(node_id, deployment_id, tag);
    }

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
                if locator.len() > 10 {
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
            if locator.len() > 10 {
                step = step.saturating_mul(2);
            }
        }
        locator
    }
    #[must_use]
    pub fn node_at_height_from(&self, start_id: NodeId, target_height: u32) -> Option<NodeId> {
        let mut remaining = usize::MAX;
        self.node_at_height_from_bounded(start_id, target_height, &mut remaining)
            .ok()
            .flatten()
    }

    pub fn node_at_height_from_bounded(
        &self,
        start_id: NodeId,
        target_height: u32,
        remaining: &mut usize,
    ) -> Result<Option<NodeId>, crate::AncestryBudgetExceeded> {
        let Ok(start_node) = self.node(start_id) else {
            return Ok(None);
        };
        if target_height > start_node.height {
            return Ok(None);
        }
        let mut cursor = start_id;
        let mut prev_height = start_node.height;
        loop {
            let Ok(node) = self.node(cursor) else {
                return Ok(None);
            };
            if cursor != start_id && node.height >= prev_height {
                return Ok(None);
            }
            if node.height < target_height {
                return Ok(None);
            }
            if self.active_by_height.is_trusted()
                && self.active_by_height.get(node.height) == Some(cursor)
            {
                return Ok(self.active_by_height.get(target_height));
            }
            if node.height == target_height {
                return Ok(Some(cursor));
            }
            prev_height = node.height;
            let Some(parent) = node.parent else {
                return Ok(None);
            };
            *remaining = remaining
                .checked_sub(1)
                .ok_or(crate::AncestryBudgetExceeded)?;
            cursor = parent;
        }
    }
    #[must_use]
    pub fn active_node_at_height(&self, height: u32) -> Option<&BlockTreeNode> {
        let tip = self.tip()?;
        let node_id = self.node_at_height_from(tip.tip_id, height)?;
        self.node(node_id).ok()
    }

    #[must_use]
    pub fn active_height_of(&self, tip_id: crate::NodeId, hash: Hash256) -> Option<u32> {
        let candidate = self.node_by_hash(hash)?;
        let active_id = self.node_at_height_from(tip_id, candidate.height)?;
        let active = self.node(active_id).ok()?;
        (active.hash == hash).then_some(active.height)
    }

    #[must_use]
    pub fn median_time_past_before_height(&self, tip: NodeId, height: u32) -> Option<u32> {
        if height == 0 {
            return None;
        }
        let node = self.node_at_height_from(tip, height - 1)?;
        self.median_time_past_at(node)
    }

    #[must_use]
    pub fn median_time_past_at(&self, start_id: NodeId) -> Option<u32> {
        const WINDOW: usize = bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
        let mut times = [0_u32; WINDOW];
        let mut len = 0usize;
        let mut cursor = start_id;
        while len < WINDOW {
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

        let times = &mut times[..len];
        times.sort_unstable();
        Some(times[len / 2])
    }

    pub fn insert_header(
        &mut self,
        header: BlockHeader,
        status: NodeStatus,
    ) -> Result<NodeId, ChainError> {
        let hash = Hash256::from(header.compute_hash());
        self.insert_header_with_hash(header, hash, status)
            .map(|inserted| inserted.id)
    }

    pub(crate) fn insert_header_with_hash(
        &mut self,
        header: BlockHeader,
        hash: Hash256,
        status: NodeStatus,
    ) -> Result<Inserted, ChainError> {
        let parent = if self.nodes.is_empty() {
            None
        } else {
            let prev_hash = Hash256::from(header.prev_blockhash);
            Some(
                self.lookup(prev_hash)
                    .ok_or(ChainError::MissingParent { prev_hash })?,
            )
        };
        self.insert_node_with_hash(parent, header, hash, status)
    }

    pub fn insert_node(
        &mut self,
        parent: Option<NodeId>,
        header: BlockHeader,
        status: NodeStatus,
    ) -> Result<NodeId, ChainError> {
        let hash = Hash256::from(header.compute_hash());
        self.insert_node_with_hash(parent, header, hash, status)
            .map(|inserted| inserted.id)
    }

    fn insert_node_with_hash(
        &mut self,
        parent: Option<NodeId>,
        header: BlockHeader,
        hash: Hash256,
        status: NodeStatus,
    ) -> Result<Inserted, ChainError> {
        if self.lookup(hash).is_some() {
            return Err(ChainError::DuplicateHeader { hash });
        }

        let block_work = crate::block_work(&header);
        let (height, chainwork, status) = match parent {
            Some(parent_id) => {
                let parent_node = self.node(parent_id)?;
                let expected_prev = parent_node.hash;
                let actual_prev = Hash256::from(header.prev_blockhash);
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
            chain_tx_count: ChainTxCount::UNKNOWN,
            status,
        });
        let id_u32 = u32::try_from(index).map_err(|_| ChainError::NodeIdOverflow { index })?;
        let node_id = NodeId::new(id_u32);
        let nodes = &self.nodes;
        self.by_hash
            .insert_unique(hash_table_key(hash), node_id, |id| {
                node_hash_key(nodes, *id)
            });
        let demoted_tip = self.publish_tip_if_best(node_id)?;
        Ok(Inserted {
            id: node_id,
            demoted_tip,
        })
    }

    pub fn invalidate_subtree(&mut self, root: NodeId) -> Result<InvalidationOutcome, ChainError> {
        let (invalid, best) = self.invalidation_plan(root)?;

        let mut demoted_tip = None;
        if let Some(old_tip) = self.tip()
            && let Some(best) = best
            && best != old_tip.tip_id
        {
            let old_index = old_tip
                .tip_id
                .index()
                .ok_or(ChainError::UnknownNode { id: old_tip.tip_id })?;
            if !invalid[old_index] {
                if self.find_common_ancestor(old_tip.tip_id, best) != Some(old_tip.tip_id) {
                    demoted_tip = Some(old_tip.hash);
                }
                self.node_mut_without_index_invalidation(old_tip.tip_id)?
                    .status = NodeStatus::Stale;
            }
        }

        self.tip.store(None);
        self.active_by_height.clear_tainted();

        let mut hashes = Vec::with_capacity(invalid.iter().filter(|&&b| b).count());
        for (index, node) in &mut self.nodes {
            if invalid[index] {
                node.status = NodeStatus::Invalid;
                hashes.push(node.hash);
            }
        }
        self.bip9_cache.invalidate_nodes(&invalid);

        if let Some(best) = best {
            self.publish_tip_if_best(best)?;
        }

        Ok(InvalidationOutcome {
            invalid: hashes,
            demoted_tip,
        })
    }

    pub fn tip_after_invalidation(&self, root: NodeId) -> Result<Option<NodeId>, ChainError> {
        self.invalidation_plan(root).map(|(_, best)| best)
    }

    fn invalidation_plan(&self, root: NodeId) -> Result<(Vec<bool>, Option<NodeId>), ChainError> {
        let root_index = root.index().ok_or(ChainError::UnknownNode { id: root })?;
        self.node(root)?;

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

    pub fn replayable_side_nodes(&self, tip: NodeId) -> Result<Vec<NodeId>, ChainError> {
        let tip_work = self.node(tip)?.chainwork;
        let mut kept = vec![false; self.nodes.capacity()];
        let mut cursor = Some(tip);
        while let Some(id) = cursor {
            let index = id.index().ok_or(ChainError::UnknownNode { id })?;
            *kept.get_mut(index).ok_or(ChainError::UnknownNode { id })? = true;
            cursor = self.node(id)?.parent;
        }
        let mut side = Vec::new();
        for (index, node) in &self.nodes {
            let Some(parent) = node.parent else {
                continue;
            };
            let parent_index = parent
                .index()
                .ok_or(ChainError::UnknownNode { id: parent })?;
            if kept[index]
                || node.status == NodeStatus::Invalid
                || node.chainwork > tip_work
                || !kept.get(parent_index).copied().unwrap_or(false)
            {
                continue;
            }
            kept[index] = true;
            side.push(
                u32::try_from(index)
                    .map(NodeId::new)
                    .map_err(|_| ChainError::NodeIdOverflow { index })?,
            );
        }
        Ok(side)
    }

    pub fn parent_id(&self, id: NodeId) -> Result<Option<NodeId>, ChainError> {
        Ok(self.node(id)?.parent)
    }

    fn publish_tip_if_best(&mut self, node_id: NodeId) -> Result<Option<Hash256>, ChainError> {
        let node = self.node(node_id)?;
        if node.status == NodeStatus::Invalid {
            return Ok(None);
        }
        let parent = node.parent;
        let chainwork = node.chainwork;
        let old_tip = self.tip.load_full();
        if old_tip
            .as_ref()
            .is_some_and(|tip| chainwork <= tip.chainwork)
        {
            return Ok(None);
        }

        let mut demoted_tip = None;
        if let Some(old_tip) = old_tip
            && old_tip.tip_id != node_id
        {
            let extends_old_tip = parent == Some(old_tip.tip_id)
                || self.find_common_ancestor(old_tip.tip_id, node_id) == Some(old_tip.tip_id);
            if !extends_old_tip {
                demoted_tip = Some(old_tip.hash);
            }
            self.node_mut_without_index_invalidation(old_tip.tip_id)?
                .status = NodeStatus::Stale;
        }
        self.node_mut_without_index_invalidation(node_id)?.status = NodeStatus::Active;
        self.tip.store(Some(Arc::new(self.tip_snapshot(node_id)?)));
        self.refresh_active_height_index(node_id);
        Ok(demoted_tip)
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

pub(crate) fn hash_table_key(hash: Hash256) -> u64 {
    u64::from_le_bytes(hash.prefix8())
}

fn node_hash_key(nodes: &Slab<BlockTreeNode>, id: NodeId) -> u64 {
    id.index()
        .and_then(|index| nodes.get(index))
        .map_or(0, |node| hash_table_key(node.hash))
}

#[cfg(test)]
mod tests;
