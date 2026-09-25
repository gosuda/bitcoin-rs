use bitcoin_rs_primitives::Hash256;

use crate::count::ChainTxCount;
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
    /// Cumulative transaction count through this tip.
    ///
    /// An applied-tip snapshot carries the count its durable commit
    /// certified. A header-tip snapshot copies its tree node's
    /// known-or-unknown count, so a header tip may legitimately be ahead of
    /// the applied chain and count differently.
    pub chain_tx_count: ChainTxCount,
}
