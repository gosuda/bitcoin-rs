//! Candidate construction, single-flight assembly, and bounded template caching.

use super::MiningCoordinator;
use super::hex_encode;
use super::submission::test_block_validity_error;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::GeneratedBlock;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::solve_block;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::consensus_bytes;
use compact_str::CompactString;
use std::sync::atomic::Ordering;

impl MiningCoordinator {
    /// Assemble, solve, and optionally persist `request.count` blocks (`API-05`).
    ///
    /// `generateblock` (`GenerateSelection::Ordered`) runs Core's
    /// `TestBlockValidity` before the nonce search (`API-30`).
    /// `generatetoaddress` (`Mempool`) does not. Each submitted block is
    /// applied through `apply::apply_block` before the next iteration; that
    /// is the commit point (`ARCH-07`). Failure after *N* accepted submissions
    /// leaves those *N* blocks durable at the applied tip. `submit = false`
    /// dry-validates through `apply::validate_block` and does not persist.
    /// The result vector grows one block at a time, so `count` cannot force a
    /// large allocation up front. Callers own retry after inspecting the tip.
    /// [`MiningControlError::InvalidRequest`] is not retriable without changing
    /// the request; `Unavailable` and `Failed` may be retried.
    pub(super) fn generate_blocks(
        &self,
        request: &GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        if request.count == 0 {
            return Ok(Vec::new());
        }
        if !request.submit && request.count != 1 {
            return Err(MiningControlError::InvalidRequest(CompactString::from(
                "submit=false requires nblocks=1",
            )));
        }
        let mut generated = Vec::new();
        for _ in 0..request.count {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let candidate = self.service.assemble_fresh(&request.payout, &request.selection)?;
            let mut block = candidate.into_unsolved_block();
            if matches!(request.selection, GenerateSelection::Ordered(_)) {
                // CONTRACT: docs/contracts/external-api.md#API-30
                self.test_generateblock_validity(&block)?;
            }
            solve_block(&mut block, request.max_tries).map_err(|error| {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            })?;
            if request.submit {
                match self.submit(&block)? {
                    BlockValidationResult::Accepted => {}
                    other => {
                        return Err(MiningControlError::Failed(CompactString::from(format!(
                            "generated block was not accepted: {other:?}"
                        ))));
                    }
                }
            } else {
                let validation = self.propose(&block);
                if validation != BlockValidationResult::Accepted {
                    return Err(MiningControlError::Failed(CompactString::from(format!(
                        "generated block failed validation: {validation:?}"
                    ))));
                }
            }
            generated.push(GeneratedBlock {
                hash: block.block_hash(),
                hex: hex_encode(&consensus_bytes(&block)),
            });
        }
        Ok(generated)
    }

    /// Core `generateblock` `TestBlockValidity` before `GenerateBlock`.
    ///
    /// `ApplyIntent::Propose` already skips hash-meets-target. This path does
    /// not use [`Self::propose`], which owns GBT `LookupBlockIndex` duplicate
    /// vocabulary (`API-18`).
    /// CONTRACT: docs/contracts/external-api.md#API-30
    fn test_generateblock_validity(&self, block: &Block) -> Result<(), MiningControlError> {
        match self.apply_handles.validate_block(block) {
            Ok(()) => Ok(()),
            Err(error) => Err(test_block_validity_error(error)),
        }
    }

}
