use bitcoin::block::Header as BitcoinBlockHeader;
use bitcoin_rs_primitives::Hash256;
use bytemuck::{Pod, Zeroable};
use ruint::Uint;

/// 256-bit accumulated proof-of-work for a block-tree node.
pub type ChainWork = Uint<256, 4>;

/// Bitcoin block header type stored in block-tree nodes.
pub type BlockHeader = BitcoinBlockHeader;

/// Stable slab key for a block-tree node.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct NodeId(u32);

impl NodeId {
    /// Builds a node id from its compact integer representation.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the compact integer representation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    pub(crate) fn index(self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }
}

/// Validation and chain-selection state for a block-tree node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    /// Header-level checks passed but the block is not the active tip.
    HeaderValid,
    /// Node is currently considered part of the best chain.
    Active,
    /// Node is valid but currently off the best chain.
    Stale,
    /// Node or one of its ancestors is invalid.
    Invalid,
}

/// One block in the in-memory block tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTreeNode {
    /// Parent node id, or `None` for a root header.
    pub parent: Option<NodeId>,
    /// Block height, with roots at height zero.
    pub height: u32,
    /// Header hash in consensus little-endian byte order.
    pub hash: Hash256,
    /// Full Bitcoin block header.
    pub header: BlockHeader,
    /// Accumulated work through this header.
    pub chainwork: ChainWork,
    /// Node validation and chain-selection status.
    pub status: NodeStatus,
}
