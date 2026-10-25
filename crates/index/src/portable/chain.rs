//! Chain identity capture and exact-identity transaction reads for bundles.
//!
//! Both export and restore resolve a recorded locator the same way: take the
//! block hash at the row's height from the applied-tip ancestry, read the
//! transaction bytes at the recorded position through the existing body
//! source, decode them, and compare the full 32-byte transaction id. A
//! prefix match alone never resolves a locator.

use super::IndexBundleError;
use crate::types::TxPosition;
use bitcoin_rs_chain::{
    BlockBodySource, BlockTreeReader, ChainWork, NodeId, NodeStatus, TipSnapshot,
};
use bitcoin_rs_primitives::{BlockHash, Hash256, Tx, deserialize};

/// The applied-tip ancestry up to a bundle base, with the base's identity.
///
/// Holds one `NodeId` per height (4 bytes each), never the headers, so even
/// a mainnet-height path is a few megabytes.
pub(super) struct ChainBase {
    pub(super) height: u32,
    /// Base block hash, little-endian bytes.
    pub(super) hash: [u8; 32],
    pub(super) chainwork: ChainWork,
    pub(super) chain_tx_count: u64,
    /// Genesis block hash, little-endian bytes.
    pub(super) genesis: [u8; 32],
    /// Whether the base block is free of invalidation marks.
    pub(super) validated: bool,
    nodes: Vec<NodeId>,
}

impl ChainBase {
    /// Captures the ancestry of `tip` for heights `0..=base_height` under one
    /// short shared block-tree lock.
    ///
    /// Refuses a base above the tip, an ancestry that is not one contiguous
    /// run of heights from genesis, and a base whose cumulative transaction
    /// count was never established.
    pub(super) fn capture(
        tree: &BlockTreeReader,
        tip: &TipSnapshot,
        base_height: u32,
    ) -> Result<Self, IndexBundleError> {
        let identity = |reason: &str| IndexBundleError::Identity(reason.to_owned());
        if base_height > tip.height {
            return Err(identity("bundle base is above the applied tip"));
        }
        let guard = tree.read();
        let mut nodes = Vec::new();
        let mut cursor = tip.tip_id;
        let mut expected = tip.height;
        loop {
            let node = guard
                .node(cursor)
                .map_err(|_| identity("applied-tip ancestry is missing from the block tree"))?;
            if node.height != expected {
                return Err(identity("applied-tip ancestry is not contiguous"));
            }
            nodes.push(cursor);
            let Some(parent) = node.parent else {
                break;
            };
            cursor = parent;
            expected = expected
                .checked_sub(1)
                .ok_or_else(|| identity("applied-tip ancestry passes below genesis"))?;
        }
        if expected != 0 {
            return Err(identity("applied-tip ancestry does not reach genesis"));
        }
        nodes.reverse();
        let keep =
            usize::try_from(base_height).map_or(usize::MAX, |height| height.saturating_add(1));
        nodes.truncate(keep);
        let base = nodes
            .last()
            .and_then(|&id| guard.node(id).ok())
            .ok_or_else(|| identity("bundle base is missing from the applied-tip ancestry"))?;
        let genesis = nodes
            .first()
            .and_then(|&id| guard.node(id).ok())
            .ok_or_else(|| identity("genesis is missing from the applied-tip ancestry"))?;
        let chain_tx_count = base
            .chain_tx_count
            .get()
            .ok_or_else(|| identity("chain transaction count is unknown at the base"))?;
        Ok(Self {
            height: base_height,
            hash: base.hash.to_le_bytes(),
            chainwork: base.chainwork,
            chain_tx_count,
            genesis: genesis.hash.to_le_bytes(),
            validated: base.status != NodeStatus::Invalid,
            nodes,
        })
    }

    /// Block hash at `height` on the captured ancestry.
    pub(super) fn hash_at(&self, tree: &BlockTreeReader, height: u32) -> Option<Hash256> {
        let id = *self.nodes.get(usize::try_from(height).ok()?)?;
        tree.read().node(id).ok().map(|node| node.hash)
    }

    /// 80-byte header at `height` on the captured ancestry.
    pub(super) fn header_at(&self, tree: &BlockTreeReader, height: u32) -> Option<[u8; 80]> {
        let id = *self.nodes.get(usize::try_from(height).ok()?)?;
        tree.read().node(id).ok().map(|node| node.header.to_bytes())
    }
}

/// How one recorded locator resolved.
pub(super) enum Located {
    /// The bytes at the position decode to this transaction.
    Found(Tx),
    /// The block body is not available: absent or pruned, not corrupt.
    BodyMissing,
    /// The body exists but the position is out of range or does not decode.
    Mismatch,
}

/// Reads single transactions through the existing body source, with a
/// one-body memo, keyed by block identity, for sources that cannot slice.
pub(super) struct BodyReader<'a> {
    source: &'a dyn BlockBodySource,
    whole_body: Option<(u32, Hash256, Vec<u8>)>,
}

impl<'a> BodyReader<'a> {
    pub(super) fn new(source: &'a dyn BlockBodySource) -> Self {
        Self {
            source,
            whole_body: None,
        }
    }

    /// Resolves `position` inside the block `(height, hash)`.
    ///
    /// A ranged read answering `None` is ambiguous (unsupported, out of
    /// range, or missing), so it falls back to the whole body, which alone can
    /// tell a missing body from an out-of-range position.
    pub(super) fn transaction(
        &mut self,
        height: u32,
        hash: Hash256,
        position: TxPosition,
    ) -> Result<Located, IndexBundleError> {
        let (offset, len) = (position.offset(), position.byte_len());
        if let Some(bytes) =
            self.source
                .block_body_range(height, BlockHash::from(hash), offset, len)
        {
            return Ok(decode(&bytes, len));
        }
        if self
            .whole_body
            .as_ref()
            .is_none_or(|(held_height, held_hash, _)| *held_height != height || *held_hash != hash)
        {
            let body = match self.source.block_body(height, BlockHash::from(hash)) {
                Ok(Some(body)) => body,
                Ok(None) => return Ok(Located::BodyMissing),
                Err(error) => {
                    return Err(IndexBundleError::BodyRead {
                        height,
                        reason: error.to_string(),
                    });
                }
            };
            self.whole_body = Some((height, hash, body));
        }
        let Some((_, _, body)) = self.whole_body.as_ref() else {
            return Ok(Located::BodyMissing);
        };
        let slice = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(len).ok())
            .and_then(|(start, len)| body.get(start..start.checked_add(len)?));
        Ok(slice.map_or(Located::Mismatch, |bytes| decode(bytes, len)))
    }
}

fn decode(bytes: &[u8], expected_len: u32) -> Located {
    if usize::try_from(expected_len) != Ok(bytes.len()) {
        return Located::Mismatch;
    }
    deserialize::<Tx>(bytes).map_or(Located::Mismatch, Located::Found)
}
