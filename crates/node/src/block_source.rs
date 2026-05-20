//! Adapter that bridges in-memory block records into the index crate's
//! `BlockSource` trait, enabling resolvers like `Indexer::resolve_script_history`
//! to recover full transactions from lossy prefix rows.
//!
//! The adapter does a linear scan over the blocks Vec for each lookup. This
//! is acceptable while the block log is short (early IBD) but should be
//! replaced with a height-indexed view once block-by-height queries become
//! a hot path.

use alloc::sync::Arc;

use bitcoin::Block;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_index::BlockSource;
use bitcoin_rs_rpc::BlockRecord;
use parking_lot::RwLock;

/// Reads decoded Bitcoin blocks from the shared in-memory log.
///
/// Cheap-clonable; the inner Arc is shared with `NodeState`'s record store.
#[derive(Clone)]
pub struct NodeBlockSource {
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
}

impl NodeBlockSource {
    /// Builds a source over the shared block-record vector.
    #[must_use]
    pub const fn new(blocks: Arc<RwLock<Vec<BlockRecord>>>) -> Self {
        Self { blocks }
    }
}

impl core::fmt::Debug for NodeBlockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeBlockSource").finish_non_exhaustive()
    }
}

impl BlockSource for NodeBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let guard = self.blocks.read();
        let record = guard.iter().find(|record| record.height == height)?;
        let bytes = Vec::<u8>::from_hex(&record.block_hex).ok()?;
        deserialize::<Block>(&bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;

    #[test]
    fn block_at_height_returns_some_after_record_added() {
        let genesis = genesis_block(Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let blocks = Arc::new(RwLock::new(vec![record]));
        let source = NodeBlockSource::new(blocks);
        let Some(decoded) = source.block_at_height(0) else {
            panic!("expected block at height 0");
        };
        assert_eq!(decoded.block_hash(), genesis.block_hash());
    }

    #[test]
    fn block_at_height_returns_none_when_missing() {
        let blocks: Arc<RwLock<Vec<BlockRecord>>> = Arc::new(RwLock::new(Vec::new()));
        let source = NodeBlockSource::new(blocks);
        assert!(source.block_at_height(0).is_none());
    }
}
