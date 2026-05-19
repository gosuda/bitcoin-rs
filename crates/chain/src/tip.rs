use bitcoin_rs_primitives::Hash256;

use crate::node::{ChainWork, NodeId};

/// Atomic best-tip snapshot published to lock-free readers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipSnapshot {
    /// Node id of the best tip.
    pub tip_id: NodeId,
    /// Best tip height.
    pub height: u32,
    /// Accumulated work through the best tip.
    pub chainwork: ChainWork,
    /// Best tip header hash.
    pub hash: Hash256,
}
