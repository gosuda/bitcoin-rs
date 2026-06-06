//! Adapter that bridges in-memory block records into the index crate's
//! `BlockSource` trait, enabling resolvers like `Indexer::resolve_script_history`
//! to recover full transactions from lossy prefix rows.
//!
//! The adapter uses height-ordered block records, matching the active-chain
//! append order maintained by block application.

use alloc::sync::Arc;

use bitcoin::Block;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_index::BlockSource;
use bitcoin_rs_rpc::{BlockBodySource, BlockRecord};
use parking_lot::RwLock;

/// Reads decoded Bitcoin blocks from the shared in-memory log.
///
/// Cheap-clonable; the inner Arc is shared with `NodeState`'s record store.
#[derive(Clone)]
pub struct NodeBlockSource {
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
}

impl NodeBlockSource {
    /// Builds a source over the shared block-record vector.
    #[must_use]
    pub const fn new(blocks: Arc<RwLock<Vec<BlockRecord>>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
        }
    }

    /// Returns `self` with a durable body source for metadata-only block records.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
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
        let record = record_at_height(&guard, height)?;
        let bytes = self.block_body_bytes(record)?;
        deserialize::<Block>(&bytes).ok()
    }
}

impl NodeBlockSource {
    fn block_body_bytes(&self, record: &BlockRecord) -> Option<Vec<u8>> {
        if !record.block_hex.is_empty() {
            return Vec::<u8>::from_hex(&record.block_hex).ok();
        }
        self.block_body_source
            .as_ref()?
            .block_body(record.height, record.hash)
    }
}

fn record_at_height(records: &[BlockRecord], height: u32) -> Option<&BlockRecord> {
    if let Ok(index) = usize::try_from(height)
        && let Some(record) = records.get(index)
        && record.height == height
        && index
            .checked_sub(1)
            .and_then(|previous| records.get(previous))
            .is_none_or(|previous| previous.height < height)
    {
        return Some(record);
    }

    let mut index = records
        .binary_search_by_key(&height, |record| record.height)
        .ok()?;
    while index > 0 && records[index.saturating_sub(1)].height == height {
        index = index.saturating_sub(1);
    }
    records.get(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin_rs_primitives::Hash256;

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

    #[test]
    fn block_at_height_reads_metadata_only_record_from_body_source() {
        struct SingleBlockSource {
            height: u32,
            hash: Hash256,
            bytes: Vec<u8>,
        }

        impl BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                (self.height == height && self.hash == hash).then(|| self.bytes.clone())
            }
        }

        let genesis = genesis_block(Network::Regtest);
        let record = BlockRecord::from_block_metadata(0, &genesis);
        let body_source = Arc::new(SingleBlockSource {
            height: record.height,
            hash: record.hash,
            bytes: serialize(&genesis),
        });
        let blocks = Arc::new(RwLock::new(vec![record]));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);

        let Some(decoded) = source.block_at_height(0) else {
            panic!("expected block at height 0");
        };
        assert_eq!(decoded.block_hash(), genesis.block_hash());
    }

    #[test]
    fn block_at_height_returns_first_record_for_duplicate_height() {
        let anchor = genesis_block(Network::Regtest);
        let mut first = anchor.clone();
        first.header.nonce = first.header.nonce.saturating_add(1);
        let mut second = first.clone();
        second.header.nonce = second.header.nonce.saturating_add(1);
        let records = vec![
            BlockRecord::from_block(0, &anchor),
            BlockRecord::from_block(2, &first),
            BlockRecord::from_block(2, &second),
        ];
        let source = NodeBlockSource::new(Arc::new(RwLock::new(records)));

        let Some(decoded) = source.block_at_height(2) else {
            panic!("expected duplicate height record");
        };
        assert_eq!(decoded.block_hash(), first.block_hash());
    }
}
