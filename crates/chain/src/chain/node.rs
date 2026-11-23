use crate::chain::ChainTxCount;
use bitcoin_rs_consensus::primitives::Hash256;

use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NodeId(u32);

impl NodeId {
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub(crate) const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(id) => Some(Self(id)),
            None => None,
        }
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
