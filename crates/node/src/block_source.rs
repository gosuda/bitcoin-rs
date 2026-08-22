//! Adapter that bridges in-memory block records into the index crate's
//! `BlockSource` trait, enabling resolvers like `Indexer::resolve_script_history`
//! to recover full transactions from lossy prefix rows.
//!
//! The adapter uses height-ordered block records, matching the active-chain
//! append order maintained by block application.

use alloc::sync::Arc;

use bitcoin::Block;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot};
use bitcoin_rs_index::BlockSource;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockBodySource, BlockRecord, record_at_height, record_at_height_hash};
use parking_lot::RwLock;

/// Reads decoded Bitcoin blocks from the shared in-memory log.
///
/// Cheap-clonable; the inner Arc is shared with `NodeState`'s record store.
#[derive(Clone)]
pub struct NodeBlockSource {
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    block_tree: Option<Arc<RwLock<BlockTree>>>,
    applied_tip: Option<Arc<arc_swap::ArcSwapOption<TipSnapshot>>>,
}

impl NodeBlockSource {
    /// Builds a source over the shared block-record vector.
    #[must_use]
    pub const fn new(blocks: Arc<RwLock<Vec<BlockRecord>>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
            block_tree: None,
            applied_tip: None,
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
    /// at each height. The session record vector is used only as a payload cache
    /// for matching `(height, hash)` pairs; otherwise the body is loaded from
    /// [`BlockBodySource`].
    #[must_use]
    pub fn with_block_tree(mut self, tree: Arc<RwLock<BlockTree>>) -> Self {
        self.block_tree = Some(tree);
        self
    }

    /// Returns `self` with the committed applied-tip publisher used by Electrum.
    #[must_use]
    pub fn with_applied_tip(
        mut self,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    ) -> Self {
        self.applied_tip = Some(applied_tip);
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
            record_at_height(&guard, height)?.hash
        };
        self.resolve_block_by_hash(height, active_hash)
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        // Only the durable body source can slice. A session record holds its
        // body as a hex string, so serving a range from it would mean decoding
        // the whole thing first — exactly the work the range read exists to
        // avoid. Returning `None` sends the caller to `block_at_height`, which
        // is correct and no slower than it is today.
        let source = self.block_body_source.as_ref()?;
        let hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            record_at_height(&guard, height)?.hash
        };
        source.block_body_range(height, hash, offset, len)
    }
}

impl NodeBlockSource {
    fn captured_applied_tip(
        &self,
    ) -> Result<Arc<TipSnapshot>, bitcoin_rs_electrum::methods::ElectrumError> {
        self.applied_tip
            .as_ref()
            .ok_or_else(|| {
                bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                    "applied chain tip unavailable".into(),
                )
            })?
            .load_full()
            .ok_or(bitcoin_rs_electrum::methods::ElectrumError::NotFound(
                "no applied chain tip",
            ))
    }

    fn applied_node_at_height(
        tree: &BlockTree,
        tip: &TipSnapshot,
        height: u32,
    ) -> Result<NodeId, bitcoin_rs_electrum::methods::ElectrumError> {
        if height > tip.height {
            return Err(bitcoin_rs_electrum::methods::ElectrumError::NotFound(
                "applied-chain header",
            ));
        }
        tree.node_at_height_from(tip.tip_id, height).ok_or(
            bitcoin_rs_electrum::methods::ElectrumError::NotFound("applied-chain header"),
        )
    }
    fn cached_body_bytes(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        let block_hex = {
            let guard = self.blocks.read();
            let record = record_at_height_hash(&guard, height, hash)?;
            (!record.block_hex.is_empty()).then(|| record.block_hex.clone())
        }?;
        Vec::<u8>::from_hex(&block_hex).ok()
    }

    /// Returns the serialized block bytes for an exact `(height, hash)` pair
    /// from the authoritative body source, falling back to the in-memory record
    /// cache. The caller is responsible for hashing the bytes and checking
    /// identity. No shared read guard is held over body-source I/O.
    pub(crate) fn block_body_bytes_for(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        if let Some(body_source) = self.block_body_source.as_ref()
            && let Some(bytes) = body_source.block_body(height, hash)
        {
            return Some(bytes);
        }
        self.cached_body_bytes(height, hash)
    }

    fn resolve_block_by_hash(&self, height: u32, active_hash: Hash256) -> Option<Block> {
        let bytes = self.block_body_bytes_for(height, active_hash)?;
        let block = deserialize::<Block>(&bytes).ok()?;
        let decoded_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        (decoded_hash == active_hash).then_some(block)
    }
}

impl bitcoin_rs_electrum::methods::BlockTreeAdapter for NodeBlockSource {
    fn tip(&self) -> Result<(u32, [u8; 80]), bitcoin_rs_electrum::methods::ElectrumError> {
        let tip = self.captured_applied_tip()?;
        let tree = self.block_tree.as_ref().ok_or_else(|| {
            bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "authoritative block tree unavailable".into(),
            )
        })?;
        let tree = tree.read();
        let node_id = Self::applied_node_at_height(&tree, &tip, tip.height)?;
        let node = tree.node(node_id).map_err(|_| {
            bitcoin_rs_electrum::methods::ElectrumError::NotFound("applied-chain tip")
        })?;
        if node.hash != tip.hash {
            return Err(bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "applied chain tip changed".into(),
            ));
        }
        Ok((tip.height, serialized_header(&node.header)?))
    }

    fn header_at(
        &self,
        height: u32,
    ) -> Result<[u8; 80], bitcoin_rs_electrum::methods::ElectrumError> {
        let tip = self.captured_applied_tip()?;
        let tree = self.block_tree.as_ref().ok_or_else(|| {
            bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "authoritative block tree unavailable".into(),
            )
        })?;
        let tree = tree.read();
        let node_id = Self::applied_node_at_height(&tree, &tip, height)?;
        let node = tree.node(node_id).map_err(|_| {
            bitcoin_rs_electrum::methods::ElectrumError::NotFound("applied-chain header")
        })?;
        serialized_header(&node.header)
    }

    fn headers_range(
        &self,
        start: u32,
        count: usize,
    ) -> Result<Vec<[u8; 80]>, bitcoin_rs_electrum::methods::ElectrumError> {
        let tip = self.captured_applied_tip()?;
        let tree = self.block_tree.as_ref().ok_or_else(|| {
            bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "authoritative block tree unavailable".into(),
            )
        })?;
        let tree = tree.read();
        let available = tip
            .height
            .checked_sub(start)
            .and_then(|remaining| remaining.checked_add(1))
            .and_then(|remaining| usize::try_from(remaining).ok())
            .unwrap_or(0);
        let capacity = count.min(available);
        let mut headers = Vec::with_capacity(capacity);
        for offset in 0..capacity {
            let offset = u32::try_from(offset).map_err(|_| {
                bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                    "header range overflow".into(),
                )
            })?;
            let height = start.checked_add(offset).ok_or_else(|| {
                bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                    "header range overflow".into(),
                )
            })?;
            let node_id = Self::applied_node_at_height(&tree, &tip, height)?;
            let node = tree.node(node_id).map_err(|_| {
                bitcoin_rs_electrum::methods::ElectrumError::NotFound("applied-chain header")
            })?;
            headers.push(serialized_header(&node.header)?);
        }
        Ok(headers)
    }

    fn block_at(&self, height: u32) -> Result<Block, bitcoin_rs_electrum::methods::ElectrumError> {
        let tip = self.captured_applied_tip()?;
        let tree = self.block_tree.as_ref().ok_or_else(|| {
            bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "authoritative block tree unavailable".into(),
            )
        })?;
        let hash = {
            let tree = tree.read();
            let node_id = Self::applied_node_at_height(&tree, &tip, height)?;
            tree.node(node_id)
                .map_err(|_| {
                    bitcoin_rs_electrum::methods::ElectrumError::NotFound("applied-chain block")
                })?
                .hash
        };
        self.resolve_block_by_hash(height, hash).ok_or_else(|| {
            bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "applied-chain block body unavailable".into(),
            )
        })
    }

    fn genesis_hash(
        &self,
    ) -> Result<bitcoin::BlockHash, bitcoin_rs_electrum::methods::ElectrumError> {
        let tip = self.captured_applied_tip()?;
        let tree = self.block_tree.as_ref().ok_or_else(|| {
            bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
                "authoritative block tree unavailable".into(),
            )
        })?;
        let tree = tree.read();
        let node_id = Self::applied_node_at_height(&tree, &tip, 0)?;
        tree.node(node_id)
            .map(|node| node.header.block_hash())
            .map_err(|_| {
                bitcoin_rs_electrum::methods::ElectrumError::NotFound(
                    "applied-chain genesis header",
                )
            })
    }
}

fn serialized_header(
    header: &bitcoin::block::Header,
) -> Result<[u8; 80], bitcoin_rs_electrum::methods::ElectrumError> {
    serialize(header).try_into().map_err(|_| {
        bitcoin_rs_electrum::methods::ElectrumError::Unavailable(
            "invalid serialized block header length".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Hash256;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    struct FixedBody {
        height: u32,
        hash: Hash256,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for FixedBody {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (self.height == height && self.hash == hash).then(|| self.bytes.clone())
        }
    }

    struct CorrectBody {
        hash: Hash256,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for CorrectBody {
        fn block_body(&self, _height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (hash == self.hash).then(|| self.bytes.clone())
        }
    }

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

    /// Body source that can slice, backed by one in-memory body.
    struct RangedBody {
        height: u32,
        hash: Hash256,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for RangedBody {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (self.height == height && self.hash == hash).then(|| self.bytes.clone())
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: Hash256,
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
        let genesis = genesis_block(Network::Regtest);
        let bytes = serialize(&genesis);
        let record = BlockRecord::from_block_metadata(0, &genesis);
        let body_source = Arc::new(RangedBody {
            height: record.height,
            hash: record.hash,
            bytes: bytes.clone(),
        });
        let blocks = Arc::new(RwLock::new(vec![record]));
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
    fn block_bytes_at_height_declines_without_a_durable_body_source() {
        // A session record holds its body as hex, so slicing it would mean
        // decoding the whole thing first. `None` sends the caller to
        // `block_at_height`, which is what it would have done anyway.
        let genesis = genesis_block(Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let blocks = Arc::new(RwLock::new(vec![record]));
        let source = NodeBlockSource::new(blocks);

        assert!(source.block_bytes_at_height(0, 0, 4).is_none());
        assert!(
            source.block_at_height(0).is_some(),
            "declining a range must not mean the block is unavailable"
        );
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

    #[test]
    fn block_at_height_resolves_from_tree_with_empty_records() -> TestResult {
        let genesis = genesis_block(Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let body_bytes = serialize(&genesis);

        // Seed an active tree with the genesis header.
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));

        // Empty record vector — simulates post-checkpoint-restore state.
        let blocks: Arc<RwLock<Vec<BlockRecord>>> = Arc::new(RwLock::new(Vec::new()));
        let source = NodeBlockSource::new(blocks)
            .with_block_body_source(Arc::new(FixedBody {
                height: 0,
                hash: genesis_hash,
                bytes: body_bytes,
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
        let genesis = genesis_block(Network::Regtest);
        let mut stale_block = genesis.clone();
        stale_block.header.nonce = stale_block.header.nonce.wrapping_add(1);
        let stale_hash = Hash256::from_le_bytes(stale_block.block_hash().as_byte_array());
        let correct_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        assert_ne!(stale_hash, correct_hash);

        // Tree says height 0 = correct_hash.
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));

        // Record vector has a STALE entry at height 0 (different hash).
        let stale_record = BlockRecord::from_block(0, &stale_block);
        let blocks = Arc::new(RwLock::new(vec![stale_record]));

        let body_source = Arc::new(CorrectBody {
            hash: correct_hash,
            bytes: serialize(&genesis),
        });

        let source = NodeBlockSource::new(blocks)
            .with_block_body_source(body_source)
            .with_block_tree(tree);

        // Must resolve via body source (stale cache hash doesn’t match tree).
        let decoded = source.block_at_height(0).ok_or_else(|| {
            std::io::Error::other(
                "must fall through to body source when cache hash mismatches tree",
            )
        })?;
        assert_eq!(decoded.block_hash(), genesis.block_hash());
        Ok(())
    }

    #[test]
    fn electrum_block_tree_adapter_stops_at_applied_tip() -> TestResult {
        use bitcoin_rs_electrum::methods::BlockTreeAdapter;

        let genesis = genesis_block(Network::Regtest);
        let expected_header: [u8; 80] = serialize(&genesis.header)
            .try_into()
            .map_err(|_| std::io::Error::other("genesis header must serialize to 80 bytes"))?;
        let expected_hash = genesis.block_hash();

        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let genesis_node = tree.node(genesis_id)?;
        let applied = TipSnapshot {
            tip_id: genesis_id,
            height: genesis_node.height,
            chainwork: genesis_node.chainwork,
            hash: genesis_node.hash,
        };
        let mut header_only = genesis.header;
        header_only.prev_blockhash = genesis.block_hash();
        header_only.time = header_only.time.saturating_add(1);
        header_only.nonce = header_only.nonce.wrapping_add(1);
        let header_only_id = tree.insert_header(header_only, NodeStatus::HeaderValid)?;
        assert_eq!(tree.node(header_only_id)?.height, 1);
        assert_eq!(tree.tip().map(|tip| tip.height), Some(1));
        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(applied)));

        let record = BlockRecord::from_block(0, &genesis);
        let blocks = Arc::new(RwLock::new(vec![record]));
        let source = NodeBlockSource::new(blocks)
            .with_block_tree(tree)
            .with_applied_tip(applied_tip);

        let (tip_height, tip_header) = source.tip()?;
        assert_eq!(tip_height, 0);
        assert_eq!(tip_header, expected_header);

        let header_at_zero = source.header_at(0)?;
        assert_eq!(header_at_zero, expected_header);
        assert!(matches!(
            source.header_at(1),
            Err(bitcoin_rs_electrum::methods::ElectrumError::NotFound(_))
        ));

        let genesis_hash = source.genesis_hash()?;
        assert_eq!(genesis_hash, expected_hash);

        let headers = source.headers_range(0, 2)?;
        assert_eq!(headers, vec![expected_header]);

        let block_at_zero = source.block_at(0)?;
        assert_eq!(block_at_zero.block_hash(), expected_hash);

        Ok(())
    }
}
