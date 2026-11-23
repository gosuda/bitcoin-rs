use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::Hash256;
use hashbrown::{HashMap, HashTable};
use parking_lot::RwLock;
use slab::Slab;

use crate::chain::{
    ChainError, ChainTxCount, TipSnapshot,
    node::{BlockTreeNode, NodeId, NodeStatus},
};
use bitcoin_rs_consensus::header_rules::BlockHeader;

mod active_index;
use active_index::ActiveHeightIndex;

#[derive(Default)]
struct Bip9Cache {
    entries: RwLock<BTreeMap<(NodeId, u32), u8>>,
}

impl Bip9Cache {
    fn insert(&self, node_id: NodeId, deployment_id: u32, tag: u8) {
        self.entries.write().insert((node_id, deployment_id), tag);
    }

    #[must_use]
    fn get(&self, node_id: NodeId, deployment_id: u32) -> Option<u8> {
        self.entries.read().get(&(node_id, deployment_id)).copied()
    }

    fn invalidate_nodes(&self, invalid: &[bool], slots: &HashMap<NodeId, usize>) {
        self.entries
            .write()
            .retain(|(id, _), _| slots.get(id).is_none_or(|&index| !invalid[index]));
    }

    fn remove_node(&self, id: NodeId) {
        let mut entries = self.entries.write();
        loop {
            let key = entries
                .range((id, u32::MIN)..=(id, u32::MAX))
                .next()
                .map(|(&key, _)| key);
            let Some(key) = key else {
                break;
            };
            entries.remove(&key);
        }
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

struct ResidentNode {
    id: NodeId,
    node: BlockTreeNode,
    child_count: usize,
}

pub struct BlockTree {
    nodes: Slab<ResidentNode>,
    slots: HashMap<NodeId, usize>,
    leaves: BTreeSet<NodeId>,
    next_node_id: Option<NodeId>,
    by_hash: HashTable<NodeId>,
    active_by_height: ActiveHeightIndex,
    tip: Arc<ArcSwapOption<TipSnapshot>>,
    bip9_cache: Bip9Cache,
    #[cfg(any(test, feature = "test-seam"))]
    topology_dirty: bool,
}

impl BlockTree {
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Slab::new(),
            slots: HashMap::new(),
            leaves: BTreeSet::new(),
            next_node_id: Some(NodeId::new(0)),
            by_hash: HashTable::new(),
            active_by_height: ActiveHeightIndex::new(),
            tip: Arc::new(ArcSwapOption::empty()),
            bip9_cache: Bip9Cache::default(),
            #[cfg(any(test, feature = "test-seam"))]
            topology_dirty: false,
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
        Ok(&self.nodes[self.slot(id)?].node)
    }

    fn slot(&self, id: NodeId) -> Result<usize, ChainError> {
        self.slots
            .get(&id)
            .copied()
            .ok_or(ChainError::UnknownNode { id })
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
        self.topology_dirty = true;
        self.node_mut_without_index_invalidation(id)
    }

    fn node_mut_without_index_invalidation(
        &mut self,
        id: NodeId,
    ) -> Result<&mut BlockTreeNode, ChainError> {
        let slot = self.slot(id)?;
        Ok(&mut self.nodes[slot].node)
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
                self.nodes[self.slots[id]].node.hash == hash
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
        #[cfg(any(test, feature = "test-seam"))]
        if self.topology_dirty {
            let parents: BTreeSet<_> = self
                .nodes
                .iter()
                .filter_map(|(_, resident)| resident.node.parent)
                .collect();
            let mut leaves: Vec<_> = self
                .nodes
                .iter()
                .filter_map(|(_, resident)| {
                    (!parents.contains(&resident.id)).then_some(resident.id)
                })
                .collect();
            leaves.sort_unstable();
            return leaves;
        }
        self.leaves.iter().copied().collect()
    }

    pub(crate) fn reclaim_leaves(
        &mut self,
        required_roots: &[NodeId],
        max_resident: usize,
        max_removals: usize,
    ) -> Result<usize, ChainError> {
        let mut protected = BTreeSet::new();
        for id in required_roots.iter().copied().chain(self.tip_id()) {
            self.node(id)?;
            protected.insert(id);
        }
        if self.len() <= max_resident || max_removals == 0 {
            return Ok(0);
        }
        #[cfg(any(test, feature = "test-seam"))]
        self.rebuild_topology_if_dirty()?;

        let mut removed = 0;
        while self.len() > max_resident && removed < max_removals {
            let Some(id) = self
                .leaves
                .iter()
                .copied()
                .find(|id| !protected.contains(id))
            else {
                break;
            };
            let slot = self.slots[&id];
            let resident = &self.nodes[slot];
            assert_eq!(resident.child_count, 0);
            let Ok(entry) = self
                .by_hash
                .find_entry(hash_table_key(resident.node.hash), |candidate| {
                    *candidate == id
                })
            else {
                unreachable!("a resident leaf has a hash index entry");
            };
            entry.remove();
            self.bip9_cache.remove_node(id);
            let resident = self.nodes.remove(slot);
            assert_eq!(self.slots.remove(&id), Some(slot));
            assert!(self.leaves.remove(&id));
            if let Some(parent) = resident.node.parent {
                let parent_node = &mut self.nodes[self.slots[&parent]];
                assert!(parent_node.child_count > 0);
                parent_node.child_count -= 1;
                if parent_node.child_count == 0 {
                    self.leaves.insert(parent);
                }
            }
            removed += 1;
        }
        if removed > 0 {
            if self.nodes.capacity() / 2 > self.nodes.len() {
                let slots = &mut self.slots;
                self.nodes.compact(|resident, _from, to| {
                    let Some(slot) = slots.get_mut(&resident.id) else {
                        unreachable!("a resident node has a logical ID entry");
                    };
                    *slot = to;
                    true
                });
            }
            if self.slots.capacity() / 2 > self.slots.len() {
                self.slots.shrink_to_fit();
            }
            if self.by_hash.capacity() / 2 > self.by_hash.len() {
                let nodes = &self.nodes;
                let slots = &self.slots;
                self.by_hash
                    .shrink_to_fit(|id| node_hash_key(nodes, slots, *id));
            }
        }
        Ok(removed)
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn rebuild_topology_if_dirty(&mut self) -> Result<(), ChainError> {
        if !self.topology_dirty {
            return Ok(());
        }
        let mut counts = vec![0; self.nodes.capacity()];
        for (_, resident) in &self.nodes {
            if let Some(parent) = resident.node.parent {
                counts[self.slot(parent)?] += 1;
            }
        }
        self.leaves.clear();
        for (slot, resident) in &mut self.nodes {
            resident.child_count = counts[slot];
            if resident.child_count == 0 {
                self.leaves.insert(resident.id);
            }
        }
        self.topology_dirty = false;
        Ok(())
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
        if let Some(locator) = self.indexed_block_locator(tip_id, max_entries) {
            return locator;
        }
        self.walked_block_locator(tip_id, max_entries)
    }

    fn indexed_block_locator(&self, tip_id: NodeId, max_entries: usize) -> Option<Vec<Hash256>> {
        if max_entries == 0
            || !self.active_by_height.is_trusted()
            || self.active_by_height.last() != Some(tip_id)
        {
            return None;
        }
        let tip = self.node(tip_id).ok()?;
        let mut locator = Vec::with_capacity(max_entries.min(32));
        let mut target_height = tip.height;
        let mut step = 1_u32;
        while locator.len() < max_entries {
            let node_id = self.active_by_height.get(target_height)?;
            let node = self.node(node_id).ok()?;
            if (locator.is_empty() && node_id != tip_id)
                || node.height != target_height
                || !self.active_height_step_is_consistent(node_id, node, target_height)
            {
                return None;
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
        Some(locator)
    }

    fn active_height_step_is_consistent(
        &self,
        node_id: NodeId,
        node: &BlockTreeNode,
        height: u32,
    ) -> bool {
        let parent_matches = if height == 0 {
            node.parent.is_none()
        } else {
            matches!(
                (node.parent, self.active_by_height.get(height - 1)),
                (Some(parent), Some(expected)) if parent == expected
            )
        };
        if !parent_matches {
            return false;
        }
        let Some(child_height) = height.checked_add(1) else {
            return true;
        };
        let Some(child_id) = self.active_by_height.get(child_height) else {
            return true;
        };
        self.node(child_id)
            .is_ok_and(|child| child.parent == Some(node_id))
    }

    fn walked_block_locator(&self, tip_id: NodeId, max_entries: usize) -> Vec<Hash256> {
        let mut locator = Vec::with_capacity(max_entries.min(32));
        let mut current = tip_id;
        let mut step: u64 = 1;
        while locator.len() < max_entries {
            let Ok(node) = self.node(current) else {
                break;
            };
            locator.push(node.hash);
            let Some(walker) = self.walk_parent_steps(current, step) else {
                break;
            };
            current = walker;
            if locator.len() > 10 {
                step = step.saturating_mul(2);
            }
        }
        locator
    }

    fn walk_parent_steps(&self, from: NodeId, steps: u64) -> Option<NodeId> {
        let mut walker = from;
        let mut walked = false;
        for _ in 0..steps {
            let Ok(node) = self.node(walker) else {
                break;
            };
            let Some(parent) = node.parent else {
                break;
            };
            walker = parent;
            walked = true;
        }
        walked.then_some(walker)
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
    ) -> Result<Option<NodeId>, crate::chain::AncestryBudgetExceeded> {
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
                .ok_or(crate::chain::AncestryBudgetExceeded)?;
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
    pub fn active_height_of(&self, tip_id: crate::chain::NodeId, hash: Hash256) -> Option<u32> {
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

        let block_work = crate::chain::block_work(&header);
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

        let node_id = self.next_node_id.ok_or(ChainError::NodeIdOverflow {
            index: usize::try_from(u64::from(u32::MAX) + 1).unwrap_or(usize::MAX),
        })?;
        let slot = self.nodes.insert(ResidentNode {
            id: node_id,
            node: BlockTreeNode {
                parent,
                height,
                hash,
                header,
                chainwork,
                chain_tx_count: ChainTxCount::UNKNOWN,
                status,
            },
            child_count: 0,
        });
        self.next_node_id = node_id.checked_next();
        self.slots.insert(node_id, slot);
        self.leaves.insert(node_id);
        if let Some(parent) = parent {
            self.nodes[self.slots[&parent]].child_count += 1;
            self.leaves.remove(&parent);
        }
        let nodes = &self.nodes;
        let slots = &self.slots;
        self.by_hash
            .insert_unique(hash_table_key(hash), node_id, |id| {
                node_hash_key(nodes, slots, *id)
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
            let old_index = self.slot(old_tip.tip_id)?;
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

        let mut invalid_nodes = Vec::with_capacity(invalid.iter().filter(|&&b| b).count());
        for (index, resident) in &mut self.nodes {
            if invalid[index] {
                resident.node.status = NodeStatus::Invalid;
                invalid_nodes.push((resident.id, resident.node.hash));
            }
        }
        invalid_nodes.sort_unstable_by_key(|(id, _)| *id);
        self.bip9_cache.invalidate_nodes(&invalid, &self.slots);

        if let Some(best) = best {
            self.publish_tip_if_best(best)?;
        }

        Ok(InvalidationOutcome {
            invalid: invalid_nodes.into_iter().map(|(_, hash)| hash).collect(),
            demoted_tip,
        })
    }

    pub fn tip_after_invalidation(&self, root: NodeId) -> Result<Option<NodeId>, ChainError> {
        self.invalidation_plan(root).map(|(_, best)| best)
    }

    fn invalidation_plan(&self, root: NodeId) -> Result<(Vec<bool>, Option<NodeId>), ChainError> {
        let root_index = self.slot(root)?;

        let node_count = self.nodes.capacity();
        let mut children: Vec<Vec<NodeId>> = (0..node_count).map(|_| Vec::new()).collect();
        for (_, resident) in &self.nodes {
            if let Some(parent) = resident.node.parent {
                children[self.slot(parent)?].push(resident.id);
            }
        }

        let mut invalid = vec![false; node_count];
        let mut worklist = vec![root];
        invalid[root_index] = true;
        while let Some(id) = worklist.pop() {
            let idx = self.slot(id)?;
            for &child in &children[idx] {
                let child_index = self.slot(child)?;
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
            .filter(|(_, resident)| resident.node.status != NodeStatus::Invalid)
            .max_by(|(_, left), (_, right)| {
                left.node
                    .chainwork
                    .cmp(&right.node.chainwork)
                    .then_with(|| right.id.cmp(&left.id))
            })
            .map(|(_, resident)| resident.id);

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
            let index = self.slot(id)?;
            kept[index] = true;
            cursor = self.node(id)?.parent;
        }
        let mut ordered: Vec<_> = self
            .nodes
            .iter()
            .map(|(slot, resident)| (resident.id, slot))
            .collect();
        ordered.sort_unstable_by_key(|(id, _)| *id);
        let mut side = Vec::new();
        for (id, index) in ordered {
            let node = &self.nodes[index].node;
            let Some(parent) = node.parent else {
                continue;
            };
            let parent_index = self.slot(parent)?;
            if kept[index]
                || node.status == NodeStatus::Invalid
                || node.chainwork > tip_work
                || !kept[parent_index]
            {
                continue;
            }
            kept[index] = true;
            side.push(id);
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

fn node_hash_key(nodes: &Slab<ResidentNode>, slots: &HashMap<NodeId, usize>, id: NodeId) -> u64 {
    hash_table_key(nodes[slots[&id]].node.hash)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget};

    use super::{BlockTree, Hash256};
    use crate::chain::test_error::TestError;
    use crate::chain::{
        ChainError, ChainTxCount,
        node::{NodeId, NodeStatus},
    };
    use bitcoin_rs_consensus::header_rules::BlockHeader;

    fn extend(tree: &mut BlockTree, parent: NodeId, nonce: u32) -> Result<NodeId, ChainError> {
        let header = test_header(BlockHash(tree.node(parent)?.hash), nonce);
        tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)
    }

    fn extend_with_fact(
        tree: &mut BlockTree,
        parent: NodeId,
        nonce: u32,
    ) -> Result<(NodeId, Option<Hash256>), ChainError> {
        let header = test_header(BlockHash(tree.node(parent)?.hash), nonce);
        let hash = Hash256::from(header.compute_hash());
        let inserted =
            tree.insert_node_with_hash(Some(parent), header, hash, NodeStatus::HeaderValid)?;
        Ok((inserted.id, inserted.demoted_tip))
    }

    fn extend_branch_with_facts(
        tree: &mut BlockTree,
        parent: NodeId,
        nonces: impl IntoIterator<Item = u32>,
    ) -> Result<Vec<(NodeId, Option<Hash256>)>, ChainError> {
        let mut cursor = parent;
        let mut steps = Vec::new();
        for nonce in nonces {
            let step = extend_with_fact(tree, cursor, nonce)?;
            cursor = step.0;
            steps.push(step);
        }
        Ok(steps)
    }

    fn demoted_facts(steps: &[(NodeId, Option<Hash256>)]) -> Vec<Option<Hash256>> {
        steps.iter().map(|(_, demoted)| *demoted).collect()
    }

    fn extend_branch(
        tree: &mut BlockTree,
        parent: NodeId,
        nonces: impl IntoIterator<Item = u32>,
    ) -> Result<Vec<NodeId>, ChainError> {
        let mut cursor = parent;
        let mut ids = Vec::new();
        for nonce in nonces {
            cursor = extend(tree, cursor, nonce)?;
            ids.push(cursor);
        }
        Ok(ids)
    }

    fn linear_chain(count: u32) -> Result<(BlockTree, Vec<NodeId>), ChainError> {
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(
            None,
            test_header(BlockHash::default(), 0),
            NodeStatus::HeaderValid,
        )?;
        let mut ids = vec![genesis];
        ids.extend(extend_branch(&mut tree, genesis, 1..=count)?);
        Ok((tree, ids))
    }

    fn timed_chain(count: u32) -> Result<(BlockTree, Vec<NodeId>, Vec<u32>), ChainError> {
        let mut tree = BlockTree::new();
        let mut prev_blockhash = BlockHash::default();
        let (mut ids, mut times) = (Vec::new(), Vec::new());
        for i in 0..count {
            let header = BlockHeader {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time: 1_000_000 + i * 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            prev_blockhash = header.compute_hash();
            times.push(header.time);
            ids.push(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        Ok((tree, ids, times))
    }

    // SYNC-03, SYNC-05
    #[test]
    fn reclaimed_ids_never_alias_reused_slots_or_cached_states() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let evicted = extend(&mut tree, main[0], 100)?;
        let hash = tree.node(evicted)?.hash;
        let slot = tree.slot(evicted)?;
        let retained = extend(&mut tree, main[0], 101)?;
        for deployment in [u32::MIN, 1, u32::MAX] {
            tree.cache_bip9_state(evicted, deployment, 3);
            tree.cache_bip9_state(main[0], deployment, 4);
            tree.cache_bip9_state(retained, deployment, 5);
        }

        assert_eq!(tree.reclaim_leaves(&[], main.len() + 1, 1)?, 1);
        assert_eq!(tree.lookup(hash), None);
        assert!(matches!(tree.node(evicted), Err(ChainError::UnknownNode { id }) if id == evicted));

        let replacement = extend(&mut tree, main[0], 102)?;
        assert!(replacement > evicted);
        assert_eq!(tree.slot(replacement)?, slot);
        assert_eq!(tree.parent_id(replacement)?, Some(main[0]));
        assert!(
            matches!(tree.parent_id(evicted), Err(ChainError::UnknownNode { id }) if id == evicted)
        );
        assert_eq!(tree.lookup(hash), None);
        for deployment in [u32::MIN, 1, u32::MAX] {
            assert_eq!(tree.cached_bip9_state(evicted, deployment), None);
            assert_eq!(tree.cached_bip9_state(replacement, deployment), None);
            assert_eq!(tree.cached_bip9_state(main[0], deployment), Some(4));
            assert_eq!(tree.cached_bip9_state(retained, deployment), Some(5));
        }
        Ok(())
    }

    // SYNC-03
    #[test]
    fn reclamation_bounds_resident_slots_across_repeated_forks() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let first = extend(&mut tree, main[0], 100)?;
        let capacity = tree.nodes.capacity();
        assert_eq!(tree.reclaim_leaves(&[], main.len(), 1)?, 1);

        for nonce in 101..=4_196 {
            let leaf = extend(&mut tree, main[0], nonce)?;
            tree.cache_bip9_state(leaf, 1, 2);
            assert!(leaf > first);
            assert_eq!(tree.reclaim_leaves(&[], main.len(), 1)?, 1);
            assert_eq!(tree.len(), main.len());
            assert!(tree.nodes.capacity() <= capacity);
            assert_eq!(tree.slots.len(), main.len());
            assert_eq!(tree.by_hash.len(), main.len());
            assert_eq!(tree.leaf_node_ids(), [main[2]]);
            assert_eq!(tree.cached_bip9_state(leaf, 1), None);
        }
        assert!(matches!(tree.node(first), Err(ChainError::UnknownNode { id }) if id == first));
        Ok(())
    }

    // SYNC-01, SYNC-02, SYNC-03
    #[test]
    fn reclamation_preserves_required_roots_and_their_ancestors() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(6)?;
        let applied = extend_branch(&mut tree, main[0], 100..=102)?;
        let historical = extend_branch(&mut tree, main[0], 200..=203)?;
        let replay = extend_branch(&mut tree, main[0], 300..=302)?;
        let operator_header = test_header(BlockHash(tree.node(main[0])?.hash), 400);
        let operator = tree.insert_node(Some(main[0]), operator_header, NodeStatus::Invalid)?;
        let invalid_descendants = extend_branch(&mut tree, operator, 401..=402)?;
        let unused = extend_branch(&mut tree, main[0], 500..=502)?;
        let roots = [applied[2], historical[3], replay[1], operator];

        assert_eq!(tree.reclaim_leaves(&roots, 0, 1)?, 1);
        assert!(matches!(
            tree.node(replay[2]),
            Err(ChainError::UnknownNode { .. })
        ));
        assert_eq!(tree.reclaim_leaves(&roots, 0, 100)?, 5);
        assert_eq!(tree.reclaim_leaves(&roots, 0, 100)?, 0);
        assert_eq!(tree.tip_id(), Some(main[6]));
        assert_eq!(tree.node(operator)?.status, NodeStatus::Invalid);

        let expected: Vec<_> = main
            .iter()
            .chain(&applied)
            .chain(&historical)
            .chain(&replay[..2])
            .copied()
            .chain([operator])
            .collect();
        assert_eq!(tree.len(), expected.len());
        for id in expected {
            let node = tree.node(id)?;
            assert_eq!(tree.lookup(node.hash), Some(id));
            if let Some(parent) = node.parent {
                assert!(tree.node(parent).is_ok());
            }
        }
        for id in invalid_descendants.into_iter().chain(unused) {
            assert!(matches!(tree.node(id), Err(ChainError::UnknownNode { .. })));
        }
        assert_eq!(
            tree.leaf_node_ids(),
            [main[6], applied[2], historical[3], replay[1], operator]
        );
        Ok(())
    }

    // SYNC-03, SYNC-05
    #[test]
    fn unknown_required_root_prevents_all_reclamation() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let leaf = extend(&mut tree, main[0], 100)?;
        let hash = tree.node(leaf)?.hash;
        tree.cache_bip9_state(leaf, 1, 3);
        let count = tree.len();
        let leaves = tree.leaf_node_ids();
        let cursor = tree.next_node_id;
        let unknown = NodeId::new(u32::MAX);

        for removals in [0, 10] {
            assert_eq!(
                tree.reclaim_leaves(&[main[0], unknown], 0, removals),
                Err(ChainError::UnknownNode { id: unknown })
            );
            assert_eq!(tree.len(), count);
            assert_eq!(tree.leaf_node_ids(), leaves);
            assert_eq!(tree.next_node_id, cursor);
            assert_eq!(tree.lookup(hash), Some(leaf));
            assert_eq!(tree.cached_bip9_state(leaf, 1), Some(3));
            assert_eq!(tree.tip_id(), Some(main[2]));
        }
        Ok(())
    }

    // SYNC-03, SYNC-05
    #[test]
    fn reclamation_compacts_sparse_storage_without_rekeying_public_ids() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let mut branches = Vec::new();
        for nonce in 100..=199 {
            let id = extend(&mut tree, main[0], nonce)?;
            branches.push((id, tree.node(id)?.hash));
            tree.cache_bip9_state(id, 1, 3);
        }
        let (pinned, pinned_hash) = branches[99];
        let old_slot = tree.slot(pinned)?;
        let capacity = tree.nodes.capacity();

        assert_eq!(tree.reclaim_leaves(&[pinned], main.len() + 1, 99)?, 99);
        assert!(tree.nodes.capacity() < capacity);
        assert!(tree.slot(pinned)? < old_slot);
        assert_eq!(tree.node(pinned)?.hash, pinned_hash);
        assert_eq!(tree.lookup(pinned_hash), Some(pinned));
        assert_eq!(tree.cached_bip9_state(pinned, 1), Some(3));
        assert_eq!(tree.leaf_node_ids(), [main[2], pinned]);
        for &(id, hash) in &branches[..99] {
            assert_eq!(tree.lookup(hash), None);
            assert!(matches!(tree.node(id), Err(ChainError::UnknownNode { .. })));
            assert_eq!(tree.cached_bip9_state(id, 1), None);
        }
        for (height, &id) in main.iter().enumerate() {
            let node = tree.node(id)?;
            assert_eq!(tree.lookup(node.hash), Some(id));
            assert_eq!(
                tree.active_node_at_height(u32::try_from(height)?)
                    .map(|active| active.hash),
                Some(node.hash)
            );
        }
        let child = extend(&mut tree, pinned, 200)?;
        assert_eq!(tree.replayable_side_nodes(main[2])?, [pinned, child]);
        Ok(())
    }

    // SYNC-02, SYNC-05
    #[test]
    fn replay_keeps_parents_before_children_after_slot_reuse() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(6)?;
        let discarded = extend_branch(&mut tree, main[0], 100..=101)?;
        let parent = extend(&mut tree, main[0], 200)?;
        assert_eq!(tree.reclaim_leaves(&[parent], main.len() + 1, 2)?, 2);
        for id in discarded {
            assert!(matches!(tree.node(id), Err(ChainError::UnknownNode { .. })));
        }
        let child = extend(&mut tree, parent, 201)?;
        let grandchild = extend(&mut tree, child, 202)?;
        assert!(tree.slot(child)? < tree.slot(parent)?);
        assert_eq!(
            tree.replayable_side_nodes(main[6])?,
            [parent, child, grandchild]
        );
        Ok(())
    }

    // SYNC-04, SYNC-05
    #[test]
    fn invalidation_uses_logical_order_and_resident_slots_after_reuse() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        extend_branch(&mut tree, main[0], 100..=101)?;
        let older = extend_branch(&mut tree, main[0], 200..=201)?;
        assert_eq!(
            tree.reclaim_leaves(&[older[1]], main.len() + older.len(), 2)?,
            2
        );
        let newer = extend_branch(&mut tree, main[0], 300..=301)?;
        assert!(older[1] < newer[1]);
        assert!(tree.slot(newer[1])? < tree.slot(older[1])?);
        for &id in older.iter().chain(&newer) {
            tree.cache_bip9_state(id, 1, 3);
        }

        assert_eq!(tree.tip_after_invalidation(main[1])?, Some(older[1]));
        tree.invalidate_subtree(main[1])?;
        assert_eq!(tree.tip_id(), Some(older[1]));
        let expected_hashes = newer
            .iter()
            .map(|&id| tree.node(id).map(|node| node.hash))
            .collect::<Result<Vec<_>, _>>()?;
        let outcome = tree.invalidate_subtree(newer[0])?;
        assert_eq!(outcome.invalid, expected_hashes);
        assert_eq!(tree.tip_id(), Some(older[1]));
        for id in newer {
            assert_eq!(tree.node(id)?.status, NodeStatus::Invalid);
            assert_eq!(tree.cached_bip9_state(id, 1), None);
        }
        for id in older {
            assert_ne!(tree.node(id)?.status, NodeStatus::Invalid);
            assert_eq!(tree.cached_bip9_state(id, 1), Some(3));
        }
        Ok(())
    }

    // SYNC-03, SYNC-05
    #[test]
    fn exhausted_logical_ids_refuse_insert_before_mutation_even_with_free_slots()
    -> crate::test_fixtures::TestResult {
        let (mut tree, main) = linear_chain(2)?;
        tree.next_node_id = Some(NodeId::new(u32::MAX - 1));
        let first = extend(&mut tree, main[0], 100)?;
        let last = extend(&mut tree, main[0], 101)?;
        assert_eq!(first, NodeId::new(u32::MAX - 1));
        assert_eq!(last, NodeId::new(u32::MAX));
        assert_eq!(tree.next_node_id, None);
        assert_eq!(tree.reclaim_leaves(&[last], main.len() + 1, 1)?, 1);
        let remaining = tree.slots.clone();
        let leaves = tree.leaf_node_ids();
        let hashes: Vec<_> = tree
            .nodes
            .iter()
            .map(|(_, resident)| (resident.id, resident.node.hash))
            .collect();
        tree.cache_bip9_state(last, 1, 3);

        for nonce in [102, 103] {
            assert!(matches!(
                extend(&mut tree, main[0], nonce),
                Err(ChainError::NodeIdOverflow { .. })
            ));
            assert_eq!(tree.slots, remaining);
            assert_eq!(tree.len(), main.len() + 1);
            assert_eq!(tree.leaf_node_ids(), leaves);
            assert_eq!(tree.next_node_id, None);
            assert_eq!(tree.tip_id(), Some(main[2]));
            assert_eq!(tree.cached_bip9_state(last, 1), Some(3));
            for &(id, hash) in &hashes {
                assert_eq!(tree.node(id)?.hash, hash);
                assert_eq!(tree.lookup(hash), Some(id));
            }
        }
        assert!(matches!(tree.node(first), Err(ChainError::UnknownNode { id }) if id == first));
        #[cfg(feature = "test-seam")]
        {
            use crate::chain::regtest_fixture::mined_regtest_child_at;
            use crate::{HeaderAdmissionError, HeaderResourceError};
            use bitcoin_rs_consensus::primitives::Network;
            use bitcoin_rs_storage::utxo::UtxoSet;
            use std::sync::Arc;

            let chain = crate::test_fixtures::handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let genesis = Network::Regtest.genesis_block();
            chain.admit_headers(&[genesis.header])?;
            chain.block_tree.write().next_node_id = Some(NodeId::new(u32::MAX));
            let last_block = mined_regtest_child_at(genesis.block_hash(), 1)?;
            chain.admit_headers(&[last_block.header])?;
            let last_hash = Hash256::from(last_block.block_hash());
            let refused = mined_regtest_child_at(last_block.block_hash(), 2)?;
            let refused_hash = Hash256::from(refused.block_hash());
            for _ in 0..2 {
                assert!(matches!(
                    chain.admit_headers(&[refused.header]),
                    Err(HeaderAdmissionError::Resource(
                        HeaderResourceError::CapacityOverflow
                    ))
                ));
                let tree = chain.block_tree.read();
                assert_eq!(tree.len(), 2);
                assert_eq!(tree.next_node_id, None);
                assert_eq!(tree.tip_id(), Some(NodeId::new(u32::MAX)));
                assert_eq!(tree.node(NodeId::new(u32::MAX))?.hash, last_hash);
                assert_eq!(tree.lookup(refused_hash), None);
            }
        }
        Ok(())
    }

    // SYNC-03
    #[test]
    fn reclamation_rebuilds_test_mutated_topology_without_losing_ancestors() -> Result<(), TestError>
    {
        let (mut tree, main) = linear_chain(4)?;
        let branch = extend_branch(&mut tree, main[0], 100..=101)?;
        let moved = extend(&mut tree, main[0], 200)?;
        tree.node_mut(moved)?.parent = Some(branch[0]);
        assert_eq!(tree.leaf_node_ids(), [main[4], branch[1], moved]);

        assert_eq!(tree.reclaim_leaves(&[moved], 0, 10)?, 1);
        assert!(tree.node(branch[0]).is_ok());
        assert!(tree.node(moved).is_ok());
        assert!(matches!(
            tree.node(branch[1]),
            Err(ChainError::UnknownNode { .. })
        ));
        assert_eq!(tree.leaf_node_ids(), [main[4], moved]);
        Ok(())
    }

    // SYNC-03, SYNC-05
    #[test]
    fn reclamation_refuses_unknown_test_parent_before_removing_any_leaf() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let side = extend(&mut tree, main[0], 100)?;
        let unknown = NodeId::new(u32::MAX);
        tree.node_mut(side)?.parent = Some(unknown);
        let slots = tree.slots.clone();
        let leaves = tree.leaf_node_ids();

        assert_eq!(
            tree.reclaim_leaves(&[], 0, 10),
            Err(ChainError::UnknownNode { id: unknown })
        );
        assert_eq!(tree.slots, slots);
        assert_eq!(tree.len(), main.len() + 1);
        assert_eq!(tree.leaf_node_ids(), leaves);
        assert_eq!(tree.node(side)?.parent, Some(unknown));
        assert!(tree.topology_dirty);
        Ok(())
    }

    #[test]
    fn block_locator_falls_back_after_active_parent_mutation() -> Result<(), TestError> {
        let (mut tree, ids) = linear_chain(2)?;
        let (a, c) = (ids[0], ids[2]);

        tree.node_mut(c)?.parent = Some(a);

        let expected = vec![tree.node(c)?.hash, tree.node(a)?.hash];
        assert_eq!(tree.block_locator(c, 3), expected);
        Ok(())
    }

    #[test]
    fn block_locator_falls_back_on_same_height_fork_index_corruption() -> Result<(), TestError> {
        let (mut tree, ids) = linear_chain(2)?;
        let (genesis_id, main_child_id, main_tip_id) = (ids[0], ids[1], ids[2]);

        let fork_child_id = extend(&mut tree, genesis_id, 11)?;
        let fork_hash = tree.node(fork_child_id)?.hash;

        assert_eq!(tree.active_by_height.last(), Some(main_tip_id));
        assert_eq!(tree.active_by_height.get(1), Some(main_child_id));

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
    fn block_locator_rejects_coherent_side_fork_index_substitution() -> Result<(), TestError> {
        let (mut tree, main_ids) = linear_chain(40)?;

        let side_ids = extend_branch(&mut tree, main_ids[18], 1019..=1026)?;
        let side_hashes = side_ids
            .iter()
            .map(|id| tree.node(*id).map(|node| node.hash))
            .collect::<Result<Vec<_>, _>>()?;

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

        let expected = locator_hashes_at_heights(&tree, &main_ids, &CORE_LOCATOR_HEIGHTS_40)?;
        assert_eq!(tree.block_locator(main_ids[40], 32), expected);
        for side_hash in &side_hashes {
            assert!(!expected.contains(side_hash));
        }
        Ok(())
    }

    #[test]
    fn node_at_height_from_ignores_tainted_index_slot() -> Result<(), TestError> {
        let (mut tree, main_ids) = linear_chain(40)?;
        let side_id = extend(&mut tree, main_ids[18], 1019)?;

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
    fn bounded_ancestry_rejects_side_parent_gap_before_index_shortcut() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(5)?;
        let side = extend_branch(&mut tree, main[0], 11..=13)?;
        let tip = *side.last().ok_or("no side tip")?;
        tree.node_mut(tip)?.parent = Some(main[0]);
        assert!(tree.active_by_height.is_trusted());
        assert_eq!(tree.node_at_height_from(tip, 1), None);
        assert_eq!(tree.node_at_height_from_bounded(tip, 1, &mut 8)?, None);
        Ok(())
    }

    #[test]
    fn bounded_ancestry_counts_only_unindexed_parent_hops() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(10_000)?;
        let side = extend_branch(&mut tree, main[4000], 20_000..=24_095)?;
        let tip = *side.last().ok_or("no side tip")?;
        let mut short = 4095;
        assert_eq!(
            tree.node_at_height_from_bounded(tip, 0, &mut short),
            Err(crate::chain::AncestryBudgetExceeded)
        );
        assert_eq!(short, 0);
        let mut exact = 4096;
        assert_eq!(
            tree.node_at_height_from_bounded(tip, 0, &mut exact)?,
            Some(main[0])
        );
        assert_eq!(exact, 0, "the indexed prefix requires no parent walk");
        assert_eq!(
            tree.node_at_height_from_bounded(main[10_000], 0, &mut exact)?,
            Some(main[0])
        );
        Ok(())
    }

    #[test]
    fn node_at_height_from_indexes_active_prefix_but_walks_side_chain() -> Result<(), TestError> {
        let (mut tree, main_ids) = linear_chain(5)?;
        let mut side_ids = vec![main_ids[0]];
        side_ids.extend(extend_branch(&mut tree, main_ids[0], 11..=13)?);

        assert_eq!(tree.node_at_height_from(side_ids[3], 1), Some(side_ids[1]));

        let active_prefix = main_ids[4];
        tree.node_mut_without_index_invalidation(active_prefix)?
            .parent = None;
        assert_eq!(
            tree.node_at_height_from(active_prefix, 1),
            Some(main_ids[1])
        );
        Ok(())
    }

    #[test]
    fn median_time_past_matches_an_independent_median_over_every_prefix() -> Result<(), TestError> {
        let (tree, ids, times) = timed_chain(15)?;
        let tip = *ids.last().ok_or("chain has a tip")?;

        assert_eq!(tree.median_time_past_at(ids[10]), Some(1_003_000));
        for (height, &id) in ids.iter().enumerate() {
            assert_eq!(
                tree.median_time_past_at(id),
                Some(expected_median_time_past(&times[..=height], 11)),
                "height {height}"
            );
            assert_eq!(
                tree.median_time_past_before_height(tip, u32::try_from(height + 1)?),
                tree.median_time_past_at(id),
                "before height {}",
                height + 1
            );
        }
        assert_eq!(
            tree.median_time_past_at(crate::chain::node::NodeId::new(u32::MAX)),
            None
        );

        assert_eq!(tree.median_time_past_before_height(tip, 0), None);
        assert_eq!(tree.median_time_past_before_height(tip, 1), Some(times[0]));
        Ok(())
    }

    fn expected_median_time_past(times_oldest_first: &[u32], window: usize) -> u32 {
        let take = window.min(times_oldest_first.len());
        let mut sample: Vec<u32> = times_oldest_first[times_oldest_first.len() - take..].to_vec();
        sample.sort_unstable();
        sample[sample.len() / 2]
    }

    #[test]
    fn tip_id_returns_published_tip() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(
            None,
            test_header(BlockHash::default(), 0),
            NodeStatus::Active,
        )?;

        assert_eq!(tree.tip_id(), Some(genesis_id));
        assert_eq!(tree.tip_height(), Some(0));
        assert_eq!(
            tree.tip().map(|tip| tip.hash),
            Some(tree.node(genesis_id)?.hash)
        );
        Ok(())
    }

    #[test]
    fn node_at_height_from_uses_rebuilt_active_height_index_after_fork_switch()
    -> Result<(), TestError> {
        let (mut tree, main_ids) = linear_chain(2)?;
        let (genesis_id, main_child_id, main_tip_id) = (main_ids[0], main_ids[1], main_ids[2]);
        assert_eq!(
            tree.node_at_height_from(main_tip_id, 1),
            Some(main_child_id)
        );

        let fork_ids = extend_branch(&mut tree, genesis_id, 11..=13)?;
        let (fork_child_id, fork_tip_id) = (fork_ids[0], fork_ids[2]);

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
    fn a_fork_has_two_leaves_whose_common_ancestor_is_the_fork_point() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::default(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let mut variant_a = test_header(genesis.compute_hash(), 1);
        variant_a.nonce = 1;
        let mut variant_b = test_header(genesis.compute_hash(), 2);
        variant_b.nonce = 2;
        let leaf_a = tree.insert_node(Some(genesis_id), variant_a, NodeStatus::HeaderValid)?;
        let leaf_b = tree.insert_node(Some(genesis_id), variant_b, NodeStatus::HeaderValid)?;

        assert_eq!(tree.find_common_ancestor(leaf_a, leaf_b), Some(genesis_id));

        let leaves = tree.leaf_node_ids();
        assert_eq!(
            leaves.len(),
            2,
            "expected two leaves on fork, got {leaves:?}"
        );
        assert!(leaves.contains(&leaf_a) && leaves.contains(&leaf_b));
        Ok(())
    }

    #[test]
    fn find_common_ancestor_resolves_uneven_branches_after_index_taint() -> Result<(), TestError> {
        let (mut tree, trunk) = linear_chain(8)?;
        let side = extend_branch(&mut tree, trunk[2], 101..=103)?;
        let other = extend_branch(&mut tree, trunk[4], 201..=202)?;
        let cases = [
            (trunk[8], trunk[4], trunk[4]),
            (trunk[1], side[2], trunk[1]),
            (trunk[8], side[2], trunk[2]),
            (side[2], other[1], trunk[2]),
            (side[1], side[2], side[1]),
            (side[2], side[2], side[2]),
        ];
        assert!(tree.active_by_height.is_trusted());
        for tainted in [false, true] {
            if tainted {
                tree.node_mut(trunk[4])?.height = 100;
            }
            for (a, b, expected) in cases {
                assert_eq!(tree.find_common_ancestor(a, b), Some(expected));
                assert_eq!(tree.find_common_ancestor(b, a), Some(expected));
            }
        }
        Ok(())
    }

    #[test]
    fn find_common_ancestor_refuses_disconnected_and_broken_chains() -> Result<(), TestError> {
        let (mut tree, a) = linear_chain(3)?;
        let b_root = tree.insert_node(
            None,
            test_header(BlockHash::default(), 101),
            NodeStatus::HeaderValid,
        )?;
        let b_tip = extend_branch(&mut tree, b_root, 102..=103)?[1];
        let unknown = NodeId::new(u32::MAX);
        for (left, right) in [(a[3], b_tip), (a[3], unknown), (unknown, a[3])] {
            assert_eq!(tree.find_common_ancestor(left, right), None);
        }
        tree.node_mut(a[1])?.parent = Some(unknown);
        assert_eq!(tree.find_common_ancestor(a[3], a[2]), None);
        tree.node_mut(a[1])?.parent = Some(a[2]);
        assert_eq!(tree.find_common_ancestor(a[3], b_tip), None);
        assert_eq!(tree.find_common_ancestor(b_tip, a[3]), None);
        Ok(())
    }

    #[test]
    fn node_at_height_from_terminates_on_two_node_cycle_with_malformed_height()
    -> Result<(), TestError> {
        let (mut tree, ids) = linear_chain(1)?;
        let (a, b) = (ids[0], ids[1]);

        tree.node_mut(a)?.parent = Some(b);
        tree.node_mut(a)?.height = 2;

        assert_eq!(tree.node_at_height_from(b, 0), None);
        Ok(())
    }

    #[test]
    fn refresh_active_height_index_clears_on_every_untrustworthy_chain_shape()
    -> Result<(), TestError> {
        type Corruption = fn(&mut BlockTree, &[NodeId]) -> Result<(), ChainError>;
        let corruptions: [(&str, u32, Corruption); 3] = [
            ("parent cycle", 1, |tree, ids| {
                tree.node_mut(ids[0])?.parent = Some(ids[1]);
                Ok(())
            }),
            ("parent not in the tree", 2, |tree, ids| {
                tree.node_mut(ids[1])?.parent = Some(crate::chain::node::NodeId::new(u32::MAX));
                Ok(())
            }),
            ("height disagrees with the walk", 2, |tree, ids| {
                tree.node_mut(ids[1])?.height = 99;
                Ok(())
            }),
        ];

        for (name, height, corrupt) in corruptions {
            let (mut tree, ids) = linear_chain(height)?;
            assert!(tree.active_by_height.is_trusted(), "{name} precondition");
            corrupt(&mut tree, &ids)?;
            let next = extend(&mut tree, ids[usize::try_from(height)?], height + 1)?;

            assert_eq!(tree.tip_id(), Some(next), "{name}");
            assert!(tree.active_by_height.is_empty_for_test(), "{name}");
            assert!(
                tree.active_node_at_height(1)
                    .is_none_or(|node| node.height == 1),
                "{name}"
            );
        }
        Ok(())
    }

    const CORE_LOCATOR_HEIGHTS_40: [u32; 16] = [
        40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 27, 23, 15, 0,
    ];

    fn locator_hashes_at_heights(
        tree: &BlockTree,
        nodes: &[NodeId],
        heights: &[u32],
    ) -> Result<Vec<Hash256>, TestError> {
        let mut out = Vec::with_capacity(heights.len());
        for &height in heights {
            let idx = usize::try_from(height)?;
            let id = *nodes.get(idx).ok_or("node exists at height")?;
            out.push(tree.node(id)?.hash);
        }
        Ok(out)
    }

    #[test]
    fn locator_doubles_only_after_more_than_ten() -> Result<(), TestError> {
        let (short, ids) = linear_chain(4)?;
        let mut short_expected: Vec<_> = (0..=4)
            .scan(BlockHash::default(), |prev, height| {
                let header = test_header(*prev, height);
                *prev = header.compute_hash();
                Some(Hash256::from(header.compute_hash()))
            })
            .collect();
        short_expected.reverse();
        assert_eq!(short.block_locator(ids[4], 32), short_expected);
        let (mut medium, ids) = linear_chain(25)?;
        let indexed = medium.block_locator(ids[25], 32);
        medium.active_by_height.taint();
        assert_eq!(medium.block_locator(ids[25], 32), indexed);
        let side = medium.block_locator(ids[10], 32);
        assert_eq!(side.first(), Some(&medium.node(ids[10])?.hash));
        let (mut tree, main_ids) = linear_chain(40)?;
        let tip_id = main_ids[40];
        assert_eq!(tree.tip_id(), Some(tip_id));

        let expected = locator_hashes_at_heights(&tree, &main_ids, &CORE_LOCATOR_HEIGHTS_40)?;

        assert!(tree.active_by_height.is_trusted());
        assert_eq!(tree.block_locator(tip_id, 32), expected);

        tree.active_by_height.taint();
        assert_eq!(tree.block_locator(tip_id, 32), expected);

        let side = *main_ids.get(10).ok_or("node exists at height 10")?;
        let side_locator = tree.block_locator(side, 32);
        assert_eq!(side_locator.first(), Some(&tree.node(side)?.hash));
        assert_eq!(side_locator.last(), Some(&tree.node(main_ids[0])?.hash));
        Ok(())
    }

    fn test_header(prev_blockhash: BlockHash, height: u32) -> BlockHeader {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&height.to_le_bytes());
        BlockHeader {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        }
    }

    #[test]
    fn invalidate_subtree_marks_root_and_descendants_invalid_and_reselects_tip()
    -> Result<(), TestError> {
        use bitcoin_rs_consensus::{CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID};

        let (mut tree, main_ids) = linear_chain(2)?;
        let (genesis_id, a2_id) = (main_ids[0], main_ids[2]);

        let side_ids = extend_branch(&mut tree, genesis_id, 101..=103)?;
        let side_hashes = side_ids
            .iter()
            .map(|id| tree.node(*id).map(|node| node.hash))
            .collect::<Result<Vec<_>, _>>()?;

        for &id in main_ids.iter().chain(&side_ids) {
            for deployment_id in [CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID] {
                tree.cache_bip9_state(id, deployment_id, 1);
            }
        }

        assert_eq!(tree.tip_id(), Some(side_ids[2]));
        assert_eq!(tree.active_by_height.get(1), Some(side_ids[0]));

        assert_eq!(tree.tip_after_invalidation(side_ids[0])?, Some(a2_id));
        assert_eq!(tree.tip_id(), Some(side_ids[2]));
        assert_eq!(tree.node(side_ids[0])?.status, NodeStatus::HeaderValid);

        let outcome = tree.invalidate_subtree(side_ids[0])?;
        let invalid_hashes = outcome.invalid;
        assert_eq!(
            outcome.demoted_tip, None,
            "the displaced tip sat in the invalid subtree: invalid, not stale"
        );
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
        for deployment_id in [CSV_DEPLOYMENT_ID, SEGWIT_DEPLOYMENT_ID] {
            for &id in &side_ids {
                assert_eq!(tree.cached_bip9_state(id, deployment_id), None);
            }
            for &id in &main_ids {
                assert_eq!(tree.cached_bip9_state(id, deployment_id), Some(1));
            }
        }
        Ok(())
    }

    #[test]
    fn invalidate_subtree_uses_insertion_order_for_equal_work_tie_break() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_node(
            None,
            test_header(BlockHash::default(), 0),
            NodeStatus::HeaderValid,
        )?;

        let mut fork_tips = Vec::new();
        for fork in 0..3 {
            let branch = extend_branch(&mut tree, genesis_id, [10 + fork, 20 + fork])?;
            fork_tips.push(branch[1]);
        }

        assert_eq!(tree.tip_id(), Some(fork_tips[0]));

        tree.invalidate_subtree(fork_tips[0])?;
        assert_eq!(tree.node(fork_tips[0])?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip_id(), Some(fork_tips[1]));
        assert_eq!(tree.node(fork_tips[1])?.status, NodeStatus::Active);

        assert_eq!(tree.node(fork_tips[2])?.status, NodeStatus::HeaderValid);
        Ok(())
    }

    #[test]
    fn insert_under_invalid_parent_is_invalid_and_does_not_publish() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::default(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        let a1 = test_header(BlockHash(genesis_hash), 1);
        let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::HeaderValid)?;
        let a1_hash = tree.node(a1_id)?.hash;
        let a2 = test_header(BlockHash(a1_hash), 2);
        let a2_id = tree.insert_node(Some(a1_id), a2, NodeStatus::HeaderValid)?;

        tree.invalidate_subtree(a1_id)?;
        assert_eq!(tree.node(a1_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.node(a2_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip_id(), Some(genesis_id));

        let a3 = test_header(BlockHash(a1_hash), 3);
        let a3_id = tree.insert_node(Some(a1_id), a3, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(a3_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip_id(), Some(genesis_id));
        Ok(())
    }

    #[test]
    fn linear_extension_reports_no_demotion() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(
            None,
            test_header(BlockHash::default(), 0),
            NodeStatus::HeaderValid,
        )?;
        let steps = extend_branch_with_facts(&mut tree, genesis, 1..=4)?;

        assert_eq!(demoted_facts(&steps), vec![None; 4]);
        assert_eq!(tree.tip_id(), Some(steps[3].0));
        assert_eq!(tree.node(steps[2].0)?.status, NodeStatus::Stale);
        assert_eq!(tree.node(genesis)?.status, NodeStatus::Stale);
        Ok(())
    }

    #[test]
    fn side_branch_that_is_not_best_reports_no_demotion() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let side = extend_branch_with_facts(&mut tree, main[0], 101..=102)?;

        assert_eq!(demoted_facts(&side), vec![None, None]);
        assert_eq!(tree.tip_id(), Some(main[2]));
        assert_eq!(tree.node(main[2])?.status, NodeStatus::Active);
        assert_eq!(tree.node(side[1].0)?.status, NodeStatus::HeaderValid);
        Ok(())
    }

    #[test]
    fn branch_switch_reports_the_displaced_tip() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let displaced = tree.node(main[2])?.hash;
        let side = extend_branch_with_facts(&mut tree, main[0], 101..=103)?;

        assert_eq!(demoted_facts(&side), vec![None, None, Some(displaced)]);
        assert_eq!(tree.tip_id(), Some(side[2].0));
        assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
        Ok(())
    }

    #[test]
    fn nested_reorg_reports_the_tip_active_before_each_switch() -> Result<(), TestError> {
        let (mut tree, main) = linear_chain(2)?;
        let first_old = tree.node(main[2])?.hash;
        let second = extend_branch_with_facts(&mut tree, main[0], 101..=103)?;
        let second_tip = tree.node(second[2].0)?.hash;
        let third = extend_branch_with_facts(&mut tree, second[1].0, 201..=202)?;
        let third_tip = tree.node(third[1].0)?.hash;
        let fourth = extend_branch_with_facts(&mut tree, main[0], 301..=305)?;

        assert_eq!(demoted_facts(&second), vec![None, None, Some(first_old)]);
        assert_eq!(demoted_facts(&third), vec![None, Some(second_tip)]);
        assert_eq!(
            demoted_facts(&fourth),
            vec![None, None, None, None, Some(third_tip)],
            "each switch reports the tip active just before it, never an earlier one"
        );
        assert_eq!(tree.tip_id(), Some(fourth[4].0));
        Ok(())
    }

    #[test]
    fn descendant_reached_through_a_zero_work_node_is_not_a_displacement() -> Result<(), TestError>
    {
        let (mut tree, main) = linear_chain(2)?;
        let tip_hash = tree.node(main[2])?.hash;
        let zero_work = BlockHeader {
            bits: CompactTarget::from_consensus(0),
            ..test_header(BlockHash(tip_hash), 50)
        };
        let zero_id = tree.insert_node(Some(main[2]), zero_work, NodeStatus::HeaderValid)?;
        assert_eq!(tree.tip_id(), Some(main[2]));

        let (descendant, demoted) = extend_with_fact(&mut tree, zero_id, 51)?;

        assert_eq!(demoted, None, "the old tip is the common ancestor");
        assert_eq!(tree.tip_id(), Some(descendant));
        assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
        Ok(())
    }

    #[test]
    fn invalidation_reports_a_valid_tip_it_displaces_onto_another_branch() -> Result<(), TestError>
    {
        let (mut tree, main) = linear_chain(2)?;
        let displaced = tree.node(main[2])?.hash;
        let mut heavy = Vec::new();
        let mut parent = main[0];
        for nonce in 101..=103 {
            let header = test_header(BlockHash(tree.node(parent)?.hash), nonce);
            parent = tree.insert_node(Some(parent), header, NodeStatus::Invalid)?;
            heavy.push(parent);
        }
        for &id in &heavy {
            tree.node_mut(id)?.status = NodeStatus::HeaderValid;
        }
        assert_eq!(tree.tip_id(), Some(main[2]));
        let doomed = extend(&mut tree, main[0], 201)?;
        let doomed_hash = tree.node(doomed)?.hash;

        let outcome = tree.invalidate_subtree(doomed)?;

        assert_eq!(outcome.invalid, vec![doomed_hash]);
        assert_eq!(outcome.demoted_tip, Some(displaced));
        assert_eq!(tree.tip_id(), Some(heavy[2]));
        assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
        Ok(())
    }

    #[test]
    fn invalidation_selecting_a_descendant_of_the_old_tip_reports_nothing() -> Result<(), TestError>
    {
        let (mut tree, main) = linear_chain(2)?;
        let held = test_header(BlockHash(tree.node(main[2])?.hash), 101);
        let descendant = tree.insert_node(Some(main[2]), held, NodeStatus::Invalid)?;
        tree.node_mut(descendant)?.status = NodeStatus::HeaderValid;
        let doomed = extend(&mut tree, main[0], 201)?;

        let outcome = tree.invalidate_subtree(doomed)?;

        assert_eq!(outcome.demoted_tip, None, "the old tip is an ancestor");
        assert_eq!(tree.tip_id(), Some(descendant));
        assert_eq!(tree.node(main[2])?.status, NodeStatus::Stale);
        Ok(())
    }

    #[test]
    fn applied_transaction_counts_follow_each_nodes_parent() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::default(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(genesis_id)?.chain_tx_count, ChainTxCount::UNKNOWN);

        tree.record_applied_tx_count(genesis_id, 1)?;
        assert_eq!(
            tree.node(genesis_id)?.chain_tx_count,
            ChainTxCount::established(1)
        );

        let genesis_hash = tree.node(genesis_id)?.hash;
        let main_header = test_header(BlockHash(genesis_hash), 1);
        let main_id = tree.insert_node(Some(genesis_id), main_header, NodeStatus::HeaderValid)?;
        let side_header = test_header(BlockHash(genesis_hash), 101);
        let side_id = tree.insert_node(Some(genesis_id), side_header, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(main_id)?.chain_tx_count, ChainTxCount::UNKNOWN);
        assert_eq!(tree.node(side_id)?.chain_tx_count, ChainTxCount::UNKNOWN);

        tree.record_applied_tx_count(main_id, 2)?;
        tree.record_applied_tx_count(side_id, 7)?;
        assert_eq!(
            tree.node(main_id)?.chain_tx_count,
            ChainTxCount::established(3)
        );
        assert_eq!(
            tree.node(side_id)?.chain_tx_count,
            ChainTxCount::established(8)
        );
        Ok(())
    }

    #[test]
    fn unknown_parent_count_stays_unknown_until_authenticated_restore() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::default(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let child_header = test_header(BlockHash(tree.node(genesis_id)?.hash), 1);
        let child_id = tree.insert_node(Some(genesis_id), child_header, NodeStatus::HeaderValid)?;

        tree.record_applied_tx_count(child_id, 3)?;
        assert_eq!(tree.node(child_id)?.chain_tx_count, ChainTxCount::UNKNOWN);

        tree.restore_chain_tx_count(genesis_id, ChainTxCount::established(11))?;
        tree.record_applied_tx_count(child_id, 3)?;
        assert_eq!(
            tree.node(child_id)?.chain_tx_count,
            ChainTxCount::established(14)
        );
        tree.restore_chain_tx_count(child_id, ChainTxCount::established(42))?;
        assert_eq!(
            tree.node(child_id)?.chain_tx_count,
            ChainTxCount::established(42)
        );
        Ok(())
    }

    #[test]
    fn a_restored_wire_zero_stays_unknown_at_the_boundary() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::default(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        tree.restore_chain_tx_count(genesis_id, ChainTxCount::from_wire(0))?;
        assert_eq!(tree.node(genesis_id)?.chain_tx_count, ChainTxCount::UNKNOWN);
        assert_eq!(tree.node(genesis_id)?.chain_tx_count.to_wire(), 0);
        Ok(())
    }

    #[test]
    fn recording_a_count_refreshes_only_the_published_tip() -> Result<(), TestError> {
        let mut tree = BlockTree::new();
        let genesis = test_header(BlockHash::default(), 0);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let genesis_hash = tree.node(genesis_id)?.hash;

        let main_header = test_header(BlockHash(genesis_hash), 1);
        let main_id = tree.insert_node(Some(genesis_id), main_header, NodeStatus::HeaderValid)?;
        let side_header = test_header(BlockHash(genesis_hash), 101);
        let side_id = tree.insert_node(Some(genesis_id), side_header, NodeStatus::HeaderValid)?;
        assert_eq!(tree.tip_id(), Some(main_id));
        assert_eq!(
            tree.tip().map(|tip| tip.chain_tx_count),
            Some(ChainTxCount::UNKNOWN)
        );

        tree.record_applied_tx_count(genesis_id, 1)?;
        assert_eq!(
            tree.tip().map(|tip| (tip.tip_id, tip.chain_tx_count)),
            Some((main_id, ChainTxCount::UNKNOWN))
        );

        tree.record_applied_tx_count(main_id, 2)?;
        assert_eq!(
            tree.tip().map(|tip| (tip.tip_id, tip.chain_tx_count)),
            Some((main_id, ChainTxCount::established(3)))
        );

        tree.restore_chain_tx_count(side_id, ChainTxCount::established(9))?;
        assert_eq!(
            tree.tip().map(|tip| (tip.tip_id, tip.chain_tx_count)),
            Some((main_id, ChainTxCount::established(3)))
        );

        tree.restore_chain_tx_count(main_id, ChainTxCount::established(5))?;
        assert_eq!(
            tree.tip().map(|tip| tip.chain_tx_count),
            Some(ChainTxCount::established(5))
        );
        Ok(())
    }
}
