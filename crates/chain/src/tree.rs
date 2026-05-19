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

    /// Returns the currently published best tip snapshot.
    #[must_use]
    pub fn tip(&self) -> Option<Arc<TipSnapshot>> {
        self.tip.load_full()
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
