//! Chain identity capture and exact-identity transaction reads for bundles.
//!
//! Both export and restore resolve a recorded locator the same way: take the
//! block hash at the row's height from the applied-tip ancestry, read the
//! transaction bytes at the recorded position through the existing body
//! source, decode them, and compare the full 32-byte transaction id. A
//! prefix match alone never resolves a locator.

use super::artifact::CANCEL_POLL_RECORDS;
use super::{IndexBundleError, Withheld};
use crate::types::TxPosition;
use bitcoin_rs_chain::{
    BlockBodySource, BlockTreeReader, ChainTxCount, ChainWork, NodeId, NodeStatus, TipSnapshot,
};
use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Tx, deserialize, varint};

/// The applied-tip ancestry up to a bundle base, with the base's identity.
///
/// Holds one `NodeId` per height (4 bytes each), never the headers, so even
/// a mainnet-height path is a few megabytes.
pub(super) struct ChainBase {
    pub(super) height: u32,
    /// Base block hash, little-endian bytes.
    pub(super) hash: [u8; 32],
    pub(super) chainwork: ChainWork,
    /// Genesis block hash, little-endian bytes.
    pub(super) genesis: [u8; 32],
    /// Whether the base block is free of invalidation marks.
    pub(super) validated: bool,
    /// The receiver's cumulative transaction count at the last node of
    /// `above`, or at the base itself when `above` is empty.
    anchor_count: u64,
    /// The blocks above the base, ascending, up to and including the nearest
    /// one whose cumulative count the receiver holds. Empty when the base
    /// itself is counted.
    above: Vec<NodeId>,
    nodes: Vec<NodeId>,
}

/// The receiver's cumulative transaction count at the base.
pub(super) enum BaseCount {
    /// Counted by the receiver, directly or through its own blocks above the
    /// base.
    Known(u64),
    /// Counting needs a block body above the base that this node cannot
    /// serve. Absent or pruned bodies are not corruption.
    Withheld(Withheld),
}

impl ChainBase {
    /// Captures the ancestry of `tip` for heights `0..=base_height` under one
    /// short shared block-tree lock.
    ///
    /// Refuses a base above the tip, an ancestry that is not one contiguous
    /// run of heights from genesis, and a chain whose cumulative transaction
    /// count is unknown from the base up to the tip.
    ///
    /// A restart restores the cumulative count on the applied tip only, so a
    /// base below the tip is usually uncounted in the tree. Capture then
    /// remembers the blocks up to the nearest counted node;
    /// [`Self::base_count`] derives the base's count from them.
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
        let mut above = nodes.split_off(keep.min(nodes.len()));
        let base_id = nodes
            .last()
            .copied()
            .ok_or_else(|| identity("bundle base is missing from the applied-tip ancestry"))?;
        let base = guard
            .node(base_id)
            .map_err(|_| identity("bundle base is missing from the applied-tip ancestry"))?;
        let genesis = nodes
            .first()
            .and_then(|&id| guard.node(id).ok())
            .ok_or_else(|| identity("genesis is missing from the applied-tip ancestry"))?;
        // The tree's own count first, then the count published with the tip
        // for the tip node alone.
        let counted = |id: NodeId, count: ChainTxCount| {
            count.get().or_else(|| {
                (id == tip.tip_id)
                    .then_some(tip.chain_tx_count.get())
                    .flatten()
            })
        };
        let anchor_count = if let Some(count) = counted(base_id, base.chain_tx_count) {
            above.clear();
            count
        } else {
            let mut found = None;
            for (index, &id) in above.iter().enumerate() {
                let node = guard
                    .node(id)
                    .map_err(|_| identity("applied-tip ancestry is missing from the block tree"))?;
                if let Some(count) = counted(id, node.chain_tx_count) {
                    found = Some((index, count));
                    break;
                }
            }
            let (last, count) =
                found.ok_or_else(|| identity("chain transaction count is unknown at the base"))?;
            above.truncate(last.saturating_add(1));
            count
        };
        Ok(Self {
            height: base_height,
            hash: base.hash.to_le_bytes(),
            chainwork: base.chainwork,
            genesis: genesis.hash.to_le_bytes(),
            validated: base.status != NodeStatus::Invalid,
            anchor_count,
            above,
            nodes,
        })
    }

    /// The base's cumulative transaction count when the receiver holds it
    /// directly, without reading any block. Always `Some` for a base that is
    /// the applied tip itself.
    pub(super) fn counted_base(&self) -> Option<u64> {
        self.above.is_empty().then_some(self.anchor_count)
    }

    /// The receiver's cumulative transaction count at the base.
    ///
    /// A counted base answers from the tree. Otherwise the count is the
    /// nearest counted node's count minus the transactions of every block
    /// between, each read through the existing body source: its metadata
    /// when it has any, else the whole body. No count comes from the bundle,
    /// an underflow refuses (it never clamps), and a body this node cannot
    /// serve withholds. The cost is one body read per block between the base
    /// and that node, polled for cancellation like every other bundle loop.
    pub(super) fn base_count(
        &self,
        tree: &BlockTreeReader,
        source: Option<&dyn BlockBodySource>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<BaseCount, IndexBundleError> {
        if self.above.is_empty() {
            return Ok(BaseCount::Known(self.anchor_count));
        }
        let Some(source) = source else {
            return Ok(BaseCount::Withheld(Withheld::NoBodySource));
        };
        let mut count = self.anchor_count;
        let mut visited = 0_u64;
        for &id in &self.above {
            if visited.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            visited = visited.saturating_add(1);
            let (height, hash) = {
                let guard = tree.read();
                let node = guard.node(id).map_err(|_| {
                    IndexBundleError::Identity(
                        "applied-tip ancestry is missing from the block tree".to_owned(),
                    )
                })?;
                (node.height, node.hash)
            };
            let Some(block_txs) = block_tx_count(source, height, hash)? else {
                return Ok(BaseCount::Withheld(Withheld::BodyUnavailable { height }));
            };
            count = ChainTxCount::established(count)
                .rewind(block_txs)
                .get()
                .ok_or_else(|| {
                    IndexBundleError::Identity(
                        "the receiver's chain transaction counts disagree above the bundle base"
                            .to_owned(),
                    )
                })?;
        }
        Ok(BaseCount::Known(count))
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

/// Transactions in the block `(height, hash)`, or `None` when the body is
/// absent or pruned.
///
/// Metadata that answers `None` is ambiguous (unsupported, absent, or
/// pruned), so it falls back to the whole body, which alone can tell them
/// apart.
fn block_tx_count(
    source: &dyn BlockBodySource,
    height: u32,
    hash: Hash256,
) -> Result<Option<u64>, IndexBundleError> {
    let hash = BlockHash::from(hash);
    let malformed = |reason: &str| IndexBundleError::BodyRead {
        height,
        reason: reason.to_owned(),
    };
    if let Some(metadata) = source.block_body_metadata(height, hash) {
        return u64::try_from(metadata.tx_count)
            .map(Some)
            .map_err(|_| malformed("the transaction count does not fit u64"));
    }
    let body = match source.block_body(height, hash) {
        Ok(Some(body)) => body,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(IndexBundleError::BodyRead {
                height,
                reason: error.to_string(),
            });
        }
    };
    let (count, _) = body
        .get(Header::LEN..)
        .and_then(|rest| varint::decode(rest).ok())
        .ok_or_else(|| malformed("the body carries no transaction count"))?;
    Ok(Some(count))
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
