//! Adapter bridging in-memory block records into the index crate's
//! `BlockSource` trait.
//!
//! The adapter uses height-ordered block records, matching the active-chain
//! append order maintained by block application.

use alloc::sync::Arc;

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_index::BlockSource;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::{Block, BlockHash, deserialize};
use bitcoin_rs_rpc::context::{BlockBodySource, BlockLog, record_at_height};
use parking_lot::RwLock;

/// Reads decoded Bitcoin blocks from the shared in-memory log.
///
/// Cheap-clonable; the inner Arc is shared with `NodeState`'s record store.
#[derive(Clone)]
pub struct NodeBlockSource {
    blocks: Arc<RwLock<BlockLog>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    block_tree: Option<Arc<RwLock<BlockTree>>>,
}

impl NodeBlockSource {
    /// Builds a source over the shared block-record vector.
    #[must_use]
    pub const fn new(blocks: Arc<RwLock<BlockLog>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
            block_tree: None,
        }
    }

    /// Returns `self` with a durable body source for metadata-only block records.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    /// Returns `self` with a shared block tree for authoritative height→hash resolution.
    ///
    /// When attached, the tree's active chain determines which block hash is valid
    /// at each height. Records then carry identity only; body bytes always come
    /// from [`BlockBodySource`].
    #[must_use]
    pub fn with_block_tree(mut self, tree: Arc<RwLock<BlockTree>>) -> Self {
        self.block_tree = Some(tree);
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
        let active_hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            Hash256::from(record_at_height(&guard, height)?.hash)
        };
        self.resolve_block_by_hash(height, active_hash)
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        // Records hold no body; only the body source can slice a range. A
        // source without range capability declines, sending the caller to
        // `block_at_height` for the whole block.
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

impl NodeBlockSource {
    /// Returns serialized bytes for an exact `(height, hash)` pair from the
    /// authoritative body source.
    pub(crate) fn block_body_bytes_for(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.block_body_source.as_ref()?.block_body(height, hash)
    }

    fn resolve_block_by_hash(&self, height: u32, active_hash: Hash256) -> Option<Block> {
        let bytes = self.block_body_bytes_for(height, BlockHash::from(active_hash))?;
        let block = deserialize::<Block>(&bytes).ok()?;
        (block.block_hash() == BlockHash::from(active_hash)).then_some(block)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::{Network, consensus_bytes};
    use bitcoin_rs_rpc::context::BlockRecord;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    struct TestBodySource {
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    }

    impl BlockBodySource for TestBodySource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            self.bodies
                .iter()
                .find(|(record_height, record_hash, _)| {
                    *record_height == height && *record_hash == hash
                })
                .map(|(_, _, bytes)| bytes.clone())
        }
    }

    /// Serves the full body but declines range reads via the trait default.
    struct FullBodyOnlySource {
        height: u32,
        hash: BlockHash,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for FullBodyOnlySource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            (self.height == height && self.hash == hash).then(|| self.bytes.clone())
        }
    }

    #[test]
    fn block_at_height_returns_some_after_record_added() {
        let genesis = Network::Regtest.genesis_block();
        let record = BlockRecord::from_block(0, &genesis);
        let body_source = Arc::new(TestBodySource {
            bodies: vec![(record.height, record.hash, consensus_bytes(&genesis))],
        });
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);
        let Some(decoded) = source.block_at_height(0) else {
            panic!("expected block at height 0");
        };
        assert_eq!(decoded.block_hash(), genesis.block_hash());
    }

    /// Body source that can slice, backed by one in-memory body.
    struct RangedBody {
        height: u32,
        hash: BlockHash,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for RangedBody {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            (self.height == height && self.hash == hash).then(|| self.bytes.clone())
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: BlockHash,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            if self.height != height || self.hash != hash {
                return None;
            }
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            self.bytes.get(start..end).map(<[u8]>::to_vec)
        }
    }

    #[test]
    fn block_bytes_at_height_agrees_with_slicing_the_whole_block() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let bytes = consensus_bytes(&genesis);
        let record = BlockRecord::from_block(0, &genesis);
        let body_source = Arc::new(RangedBody {
            height: record.height,
            hash: record.hash,
            bytes: bytes.clone(),
        });
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);

        for offset in 0..u32::try_from(bytes.len())? {
            for len in [0_u32, 1, 7] {
                let end = offset.saturating_add(len);
                let ranged = source.block_bytes_at_height(0, offset, len);
                if usize::try_from(end)? > bytes.len() {
                    assert_eq!(
                        ranged, None,
                        "a range past the end must not be served short"
                    );
                    continue;
                }
                assert_eq!(
                    ranged.as_deref(),
                    Some(&bytes[usize::try_from(offset)?..usize::try_from(end)?]),
                    "range ({offset}, {len}) diverged from the serialized block"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn block_bytes_at_height_declines_when_the_source_cannot_slice() {
        let genesis = Network::Regtest.genesis_block();
        let record = BlockRecord::from_block(0, &genesis);
        let body_source = Arc::new(FullBodyOnlySource {
            height: record.height,
            hash: record.hash,
            bytes: consensus_bytes(&genesis),
        });
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);

        assert!(source.block_bytes_at_height(0, 0, 4).is_none());
        assert!(
            source.block_at_height(0).is_some(),
            "declining a range must not mean the block is unavailable"
        );
    }

    #[test]
    fn block_at_height_returns_none_when_missing() {
        let blocks: Arc<RwLock<BlockLog>> = Arc::new(RwLock::new(BlockLog::new()));
        let source = NodeBlockSource::new(blocks);
        assert!(source.block_at_height(0).is_none());
    }

    #[test]
    fn block_at_height_reads_metadata_only_record_from_body_source() {
        struct SingleBlockSource {
            height: u32,
            hash: BlockHash,
            bytes: Vec<u8>,
        }

        impl BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                (self.height == height && self.hash == hash).then(|| self.bytes.clone())
            }
        }

        let genesis = Network::Regtest.genesis_block();
        let record = BlockRecord::from_block(0, &genesis);
        let body_source = Arc::new(SingleBlockSource {
            height: record.height,
            hash: record.hash,
            bytes: consensus_bytes(&genesis),
        });
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);

        let Some(decoded) = source.block_at_height(0) else {
            panic!("expected block at height 0");
        };
        assert_eq!(decoded.block_hash(), genesis.block_hash());
    }

    #[test]
    fn block_at_height_returns_first_record_for_duplicate_height() {
        let anchor = Network::Regtest.genesis_block();
        let mut first = anchor.clone();
        first.header.nonce = first.header.nonce.saturating_add(1);
        let mut second = first.clone();
        second.header.nonce = second.header.nonce.saturating_add(1);
        let first_record = BlockRecord::from_block(2, &first);
        let second_record = BlockRecord::from_block(2, &second);
        let body_source = Arc::new(TestBodySource {
            bodies: vec![
                (
                    first_record.height,
                    first_record.hash,
                    consensus_bytes(&first),
                ),
                (
                    second_record.height,
                    second_record.hash,
                    consensus_bytes(&second),
                ),
            ],
        });
        let records = vec![
            BlockRecord::from_block(0, &anchor),
            first_record,
            second_record,
        ];
        let source = NodeBlockSource::new(Arc::new(RwLock::new(
            records.into_iter().collect::<BlockLog>(),
        )))
        .with_block_body_source(body_source);

        let Some(decoded) = source.block_at_height(2) else {
            panic!("expected duplicate height record");
        };
        assert_eq!(decoded.block_hash(), first.block_hash());
    }

    #[test]
    fn block_at_height_resolves_from_tree_with_empty_records() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        let body_bytes = consensus_bytes(&genesis);

        // Seed an active tree with the genesis header.
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));

        // Empty record vector — simulates post-checkpoint-restore state.
        let blocks: Arc<RwLock<BlockLog>> = Arc::new(RwLock::new(BlockLog::new()));
        let source = NodeBlockSource::new(blocks)
            .with_block_body_source(Arc::new(TestBodySource {
                bodies: vec![(0, genesis_hash, body_bytes)],
            }))
            .with_block_tree(tree);

        let decoded = source.block_at_height(0).ok_or_else(|| {
            std::io::Error::other("tree-authoritative resolution must succeed with empty records")
        })?;
        assert_eq!(decoded.block_hash(), genesis.block_hash());
        Ok(())
    }

    #[test]
    fn block_at_height_tree_rejects_stale_cache_entry() -> TestResult {
        let genesis = Network::Regtest.genesis_block();
        let mut stale_block = genesis.clone();
        stale_block.header.nonce = stale_block.header.nonce.wrapping_add(1);
        let stale_hash = stale_block.block_hash();
        let correct_hash = genesis.block_hash();
        assert_ne!(stale_hash, correct_hash);

        // Tree says height 0 = correct_hash.
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));

        // Record vector has a STALE entry at height 0 (different hash).
        let stale_record = BlockRecord::from_block(0, &stale_block);
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([stale_record])));

        let body_source = Arc::new(TestBodySource {
            bodies: vec![(0, correct_hash, consensus_bytes(&genesis))],
        });

        let source = NodeBlockSource::new(blocks)
            .with_block_body_source(body_source)
            .with_block_tree(tree);

        // Must resolve via body source (stale record hash does not match tree).
        let decoded = source.block_at_height(0).ok_or_else(|| {
            std::io::Error::other(
                "must fall through to body source when record hash mismatches tree",
            )
        })?;
        assert_eq!(decoded.block_hash(), genesis.block_hash());
        Ok(())
    }
}
