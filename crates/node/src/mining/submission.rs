//! Proposal and solved-block submission through the authoritative chainstate.

use super::MiningCoordinator;
use crate::ApplyError;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use compact_str::CompactString;

impl MiningCoordinator {
    pub(super) fn propose(&self, block: &Block) -> BlockValidationResult {
        match self.apply_handles.validate_block(block) {
            Ok(()) => BlockValidationResult::Accepted,
            Err(error) => map_apply_error(error),
        }
    }

    pub(super) fn submit(
        &self,
        block: &Block,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let block_hash: Hash256 = block.block_hash().into();
        {
            let tree = self.block_tree.read();
            if let Some(node_id) = tree.lookup(block_hash) {
                let node = tree.node(node_id).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
                if node.status == bitcoin_rs_chain::NodeStatus::Invalid {
                    return Ok(BlockValidationResult::DuplicateInvalid);
                }
                let on_applied = self.applied_tip.load_full().is_some_and(|tip| {
                    tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id)
                });
                if on_applied {
                    return Ok(BlockValidationResult::Duplicate);
                }
                return Ok(BlockValidationResult::DuplicateInconclusive);
            }
        }

        match self.followers.apply_connect(&self.apply_handles, block) {
            Ok(outcome) => {
                let tip = outcome.tip;
                let visible = self.applied_tip.load_full().ok_or_else(|| {
                    MiningControlError::Failed(CompactString::from(
                        "applied tip missing after accepted submission",
                    ))
                })?;
                if visible.hash != tip.hash {
                    return Err(MiningControlError::Failed(CompactString::from(
                        "applied tip was not published before submit_block returned",
                    )));
                }
                Ok(BlockValidationResult::Accepted)
            }
            Err(error) => Ok(map_apply_error(error)),
        }
    }
}

pub(super) fn map_apply_error(error: ApplyError) -> BlockValidationResult {
    match error {
        ApplyError::ProofOfWork { .. } => {
            BlockValidationResult::Rejected(CompactString::from("high-hash"))
        }
        ApplyError::PrevHashMismatch { .. } => {
            BlockValidationResult::Rejected(CompactString::from("inconclusive-not-best-prevblk"))
        }
        ApplyError::TargetAboveLimit | ApplyError::NbitsNonRetargetMismatch { .. } => {
            BlockValidationResult::Rejected(CompactString::from("bad-diffbits"))
        }
        ApplyError::BlockOutputsExceedInputs
        | ApplyError::BlockValueOverflow
        | ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { .. }) => {
            BlockValidationResult::Rejected(CompactString::from("bad-cb-amount"))
        }
        ApplyError::Shutdown | ApplyError::JournalBackpressure(_) => {
            BlockValidationResult::Inconclusive
        }
        other => BlockValidationResult::Rejected(CompactString::from(other.to_string())),
    }
}
