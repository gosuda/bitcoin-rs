//! Experimental LDK adapter over the production public Node surface.
//!
//! Run the consumer on an application-owned blocking thread, without node
//! locks held. Node's async storage/admission operations currently perform
//! synchronous work when polled; these futures do not offload that work.
//! This adapter neither owns a runtime nor spawns a second node service graph.
//! See the README for integration limits and runtime requirements.

use bitcoin::{BlockHash, Transaction, consensus, hashes::Hash};
use bitcoin_rs_node::{Node, NodeError};
use bitcoin_rs_primitives::{BlockHash as NativeBlockHash, Hash256, Tx, deserialize};
use lightning::chain::chaininterface::{
    BroadcasterInterface, ConfirmationTarget, FEERATE_FLOOR_SATS_PER_KW, FeeEstimator,
};
use lightning_block_sync::{
    AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError,
};

/// Refusals at the experimental adapter edge, before or during canonical admission.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("transaction conversion failed: {0}")]
    TransactionDecode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error(transparent)]
    Node(#[from] NodeError),
}

/// Borrowed adapter; the application retains the one owned Node lifecycle.
///
/// Channel state and persistence remain owned by the external LDK application.
pub struct NativeBackend<'a> {
    node: &'a Node,
    fallback_sat_per_kw: u32,
}

impl<'a> NativeBackend<'a> {
    /// `fallback_sat_per_kw` is explicit application policy for missing history,
    /// clamped to LDK's floor. It is not an estimate from the node.
    pub fn new(node: &'a Node, fallback_sat_per_kw: u32) -> Self {
        Self {
            node,
            fallback_sat_per_kw: fallback_sat_per_kw.max(FEERATE_FLOOR_SATS_PER_KW),
        }
    }

    /// Synchronous submission for callers that need to observe admission errors.
    ///
    /// Call only on the application's blocking thread, outside a runtime task or
    /// any node locks. Multi-transaction submissions use one gateway package
    /// operation, never individual submissions in a loop.
    pub fn try_broadcast_transactions(&self, txs: &[&Transaction]) -> Result<(), AdapterError> {
        if txs.is_empty() {
            return Ok(());
        }
        let mut native = txs
            .iter()
            .map(|tx| deserialize::<Tx>(&consensus::serialize(*tx)))
            .collect::<Result<Vec<_>, _>>()?;
        if native.len() == 1 {
            futures_executor::block_on(self.node.broadcast(native.remove(0)))?;
        } else {
            futures_executor::block_on(self.node.broadcast_package(native))?;
        }
        Ok(())
    }
}

impl BroadcasterInterface for NativeBackend<'_> {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        // LDK's callback cannot return admission errors. Expose them to the
        // application's tracing subscriber and keep no parallel retry state.
        if let Err(error) = self.try_broadcast_transactions(txs) {
            tracing::error!(%error, "experimental LDK broadcast refused");
        }
    }
}

impl FeeEstimator for NativeBackend<'_> {
    fn get_est_sat_per_1000_weight(&self, target: ConfirmationTarget) -> u32 {
        // Illustrative consumer policy, bounded to the node estimator's 25-block
        // horizon. There is no separate estimator or cache in this spike.
        let blocks = match target {
            ConfirmationTarget::MaximumFeeEstimate => 1,
            ConfirmationTarget::UrgentOnChainSweep | ConfirmationTarget::NonAnchorChannelFee => 6,
            ConfirmationTarget::MinAllowedAnchorChannelRemoteFee
            | ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee
            | ConfirmationTarget::AnchorChannelFee
            | ConfirmationTarget::ChannelCloseMinimum
            | ConfirmationTarget::OutputSpendingFee => 25,
        };
        self.node
            .fee_estimate(blocks)
            .map_or(self.fallback_sat_per_kw, |rate| {
                sat_per_kvb_to_kw(rate.as_sat_per_kvb())
            })
    }
}

impl BlockSource for NativeBackend<'_> {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a BlockHash,
        _height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            let hash = NativeBlockHash::from(Hash256::from_le_bytes(&header_hash.to_byte_array()));
            let data = self
                .node
                .block_header(hash)
                .map_err(BlockSourceError::transient)?;
            let header = consensus::deserialize(&data.header.to_bytes())
                .map_err(BlockSourceError::persistent)?;
            Ok(BlockHeaderData {
                header,
                height: data.height,
                chainwork: bitcoin::Work::from_be_bytes(data.chainwork),
            })
        })
    }

    fn get_block<'a>(&'a self, hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, BlockData> {
        Box::pin(async move {
            let native_hash = NativeBlockHash::from(Hash256::from_le_bytes(&hash.to_byte_array()));
            let block = self
                .node
                .block_by_hash(native_hash)
                .await
                // A known block's pruned, corrupt or mismatched body needs
                // data recovery; retrying this source cannot repair it.
                .map_err(BlockSourceError::persistent)?
                .ok_or_else(|| BlockSourceError::transient("block is not known to Node"))?;
            let bytes = bitcoin_rs_primitives::consensus_bytes(&block);
            let block = consensus::deserialize(&bytes).map_err(BlockSourceError::persistent)?;
            Ok(BlockData::FullBlock(block))
        })
    }

    fn get_best_block(&self) -> AsyncBlockSourceResult<'_, (BlockHash, Option<u32>)> {
        Box::pin(async {
            let snapshot = self
                .node
                .settled_snapshot()
                .map_err(BlockSourceError::transient)?;
            Ok((
                BlockHash::from_byte_array(*snapshot.tip_hash.as_byte_array()),
                Some(snapshot.tip_height),
            ))
        })
    }
}

fn sat_per_kvb_to_kw(rate: u64) -> u32 {
    // Round upward before narrowing, including values near u64::MAX.
    u32::try_from(rate.div_ceil(4))
        .unwrap_or(u32::MAX)
        .max(FEERATE_FLOOR_SATS_PER_KW)
}

#[cfg(test)]
mod tests {
    use super::sat_per_kvb_to_kw;

    #[test]
    fn fee_conversion_preserves_units_rounding_floor_and_range() {
        assert_eq!(sat_per_kvb_to_kw(4_000), 1_000);
        assert_eq!(sat_per_kvb_to_kw(4_001), 1_001);
        assert_eq!(sat_per_kvb_to_kw(0), 253);
        assert_eq!(sat_per_kvb_to_kw(u64::MAX), u32::MAX);
    }
}
