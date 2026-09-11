//! Canonical index block-source adaptation.

use bitcoin_rs_chain::{BlockBodySource, BlockTree};
use bitcoin_rs_index::BlockSource;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, deserialize};
use bitcoin_rs_rpc::{context::BlockLog, context::record_at_height};
use parking_lot::RwLock;
use std::sync::Arc;

/// Node adapter for the index-owned `BlockSource` contract: active-chain
/// identity from the tree and bodies from the chain body store.
#[derive(Clone)]
pub(crate) struct IndexBlockSource {
    blocks: Arc<RwLock<BlockLog>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    block_tree: Option<Arc<RwLock<BlockTree>>>,
}

impl IndexBlockSource {
    #[must_use]
    pub(crate) const fn new(blocks: Arc<RwLock<BlockLog>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
            block_tree: None,
        }
    }

    #[must_use]
    pub(crate) fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    #[must_use]
    pub(crate) fn with_block_tree(mut self, tree: Arc<RwLock<BlockTree>>) -> Self {
        self.block_tree = Some(tree);
        self
    }

    pub(crate) fn block_body_bytes_for(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.block_body_source.as_ref()?.block_body(height, hash)
    }

    pub(super) fn resolve_block_by_hash(&self, height: u32, active_hash: Hash256) -> Option<Block> {
        let bytes = self.block_body_bytes_for(height, BlockHash::from(active_hash))?;
        let block = deserialize::<Block>(&bytes).ok()?;
        (block.block_hash() == BlockHash::from(active_hash)).then_some(block)
    }
}

impl core::fmt::Debug for IndexBlockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndexBlockSource").finish_non_exhaustive()
    }
}

impl BlockSource for IndexBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let active_hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            Hash256::from(record_at_height(&guard, height)?.hash)
        };
        self.resolve_block_by_hash(height, active_hash)
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let source = self.block_body_source.as_ref()?;
        let hash = if let Some(tree) = &self.block_tree {
            BlockHash::from(tree.read().active_node_at_height(height)?.hash)
        } else {
            let guard = self.blocks.read();
            record_at_height(&guard, height)?.hash
        };
        source.block_body_range(height, hash, offset, len)
    }
}
