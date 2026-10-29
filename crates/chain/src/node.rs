use crate::ChainTxCount;
use bitcoin_rs_primitives::{Hash256, Header};
use ruint::Uint;

pub type ChainWork = Uint<256, 4>;

pub type BlockHeader = Header;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NodeId(u32);

impl NodeId {
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub(crate) fn index(self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    HeaderValid,
    Active,
    Stale,
    Invalid,
}

#[derive(Debug)]
pub struct BlockTreeNode {
    pub parent: Option<NodeId>,
    pub height: u32,
    pub hash: Hash256,
    pub header: BlockHeader,
    pub chainwork: ChainWork,
    pub chain_tx_count: ChainTxCount,
    pub status: NodeStatus,
}
