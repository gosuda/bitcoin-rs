//! Proposal and solved-block submission through the authoritative chainstate.

use super::MiningCoordinator;
use crate::ApplyError;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::update_uncommitted_block_structures;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use compact_str::CompactString;

impl MiningCoordinator {
    pub(super) fn propose(&self, block: &Block) -> BlockValidationResult {
        // Core GBT proposal looks the hash up before TestBlockValidity.
        if let Some(known) = self.known_block_result(block.block_hash().into()) {
            return known;
        }
        match self.apply_handles.validate_block(block) {
            Ok(()) => BlockValidationResult::Accepted,
            Err(error) => map_apply_error(error),
        }
    }

    /// Core `LookupBlockIndex` / BIP22 proposal vocabulary.
    ///
    /// A node on the applied chain has had its body connected (Core
    /// `BLOCK_VALID_SCRIPTS`). `Invalid` is `BLOCK_FAILED_VALID`. Any other
    /// tree entry, including a header-only `Active` tip, is still
    /// inconclusive — `NodeStatus::Active` is the header chain, not scripts.
    pub(super) fn known_block_result(&self, block_hash: Hash256) -> Option<BlockValidationResult> {
        let tree = self.block_tree.read();
        let node_id = tree.lookup(block_hash)?;
        let node = tree.node(node_id).ok()?;
        if node.status == NodeStatus::Invalid {
            return Some(BlockValidationResult::DuplicateInvalid);
        }
        let on_applied = self
            .applied_tip
            .load_full()
            .is_some_and(|tip| tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id));
        if on_applied {
            return Some(BlockValidationResult::Duplicate);
        }
        Some(BlockValidationResult::DuplicateInconclusive)
    }

    /// Core `submitblock` fills the coinbase reserved nonce when the block
    /// already has a BIP141 commitment but no coinbase witness. Proposal skips this.
    pub(super) fn fill_uncommitted_witness(&self, block: &mut Block) {
        let tree = self.block_tree.read();
        let Some(prev_id) = tree.lookup(block.header.prev_blockhash.into()) else {
            return;
        };
        let Ok(prev) = tree.node(prev_id) else {
            return;
        };
        let height = prev.height.saturating_add(1);
        let segwit_active = self.network.is_segwit_active(height);
        drop(tree);
        update_uncommitted_block_structures(block, segwit_active);
    }

    pub(super) fn submit(
        &self,
        block: &Block,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let block_hash: Hash256 = block.block_hash().into();
        // Core v31 `submitblock` dropped the index pre-check. `ProcessNewBlock`
        // returns `duplicate` only when the block was already accepted
        // (`!new_block && accepted`). A header-only tree entry must still
        // receive the body so `submitheader` then `submitblock` works.
        if matches!(
            self.known_block_result(block_hash),
            Some(BlockValidationResult::Duplicate)
        ) {
            return Ok(BlockValidationResult::Duplicate);
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
        ApplyError::Shutdown | ApplyError::JournalBackpressure(_) => {
            BlockValidationResult::Inconclusive
        }
        other => BlockValidationResult::Rejected(bip22_reject_reason(&other)),
    }
}

/// Core `GetRejectReason` strings used by `BIP22ValidationResult`.
fn bip22_reject_reason(error: &ApplyError) -> CompactString {
    match error {
        ApplyError::ProofOfWork { .. } => CompactString::from("high-hash"),
        ApplyError::PrevHashMismatch { .. } => CompactString::from("inconclusive-not-best-prevblk"),
        ApplyError::TargetAboveLimit | ApplyError::NbitsNonRetargetMismatch { .. } => {
            CompactString::from("bad-diffbits")
        }
        ApplyError::BlockOutputsExceedInputs | ApplyError::BlockValueOverflow => {
            CompactString::from("bad-cb-amount")
        }
        ApplyError::UndoPrevoutMissing { .. } => {
            CompactString::from("bad-txns-inputs-missingorspent")
        }
        ApplyError::Consensus(consensus) => bip22_consensus_reason(consensus),
        ApplyError::Chain(chain) => bip22_chain_reason(chain),
        other => CompactString::from(other.to_string()),
    }
}

fn bip22_consensus_reason(error: &ConsensusError) -> CompactString {
    CompactString::from(match error {
        ConsensusError::EmptyInputs => "bad-txns-vin-empty",
        ConsensusError::EmptyOutputs => "bad-txns-vout-empty",
        ConsensusError::CoinbaseScriptSigSize { .. } => "bad-cb-length",
        ConsensusError::NullPrevout { .. } => "bad-txns-prevout-null",
        ConsensusError::DuplicateInput { .. } => "bad-txns-inputs-duplicate",
        ConsensusError::MissingPrevout { .. } => "bad-txns-inputs-missingorspent",
        ConsensusError::OutputValueOverflow => "bad-txns-txouttotal-toolarge",
        ConsensusError::InputsLessThanOutputs { .. } => "bad-txns-in-belowout",
        ConsensusError::SigopsLimit { .. } => "bad-blk-sigops",
        ConsensusError::EmptyBlock | ConsensusError::MissingCoinbase => "bad-cb-missing",
        ConsensusError::ExtraCoinbase { .. } => "bad-cb-multiple",
        ConsensusError::MerkleMutation => "bad-txns-duplicate",
        ConsensusError::MerkleRoot => "bad-txnmrklroot",
        ConsensusError::CoinbaseAmount { .. } => "bad-cb-amount",
        ConsensusError::BlockValueOverflow => "bad-txns-accumulated-fee-outofrange",
        ConsensusError::WitnessNonceSize => "bad-witness-nonce-size",
        ConsensusError::UnexpectedWitness => "unexpected-witness",
        ConsensusError::WitnessCommitment => "bad-witness-merkle-match",
        ConsensusError::BlockWeight { .. } => "bad-blk-weight",
        ConsensusError::Script { reason, .. } => {
            return CompactString::from(format!("block-script-verify-flag-failed ({reason})"));
        }
        ConsensusError::Bip { bip, reason } => return bip22_bip_reason(bip, reason),
        ConsensusError::PrevoutMatrixSize { .. }
        | ConsensusError::Kernel(_)
        | ConsensusError::Encoding(_) => return CompactString::from(error.to_string()),
    })
}

fn bip22_bip_reason(bip: &str, reason: &str) -> CompactString {
    CompactString::from(match bip {
        "BIP30" => "bad-txns-BIP30",
        "BIP34" => "bad-cb-height",
        "BIP68" | "BIP113" => "bad-txns-nonfinal",
        "COINBASE_MATURITY" => "bad-txns-premature-spend-of-coinbase",
        _ => {
            return CompactString::from(format!(
                "block-script-verify-flag-failed ({bip}: {reason})"
            ));
        }
    })
}

fn bip22_chain_reason(error: &ChainError) -> CompactString {
    CompactString::from(match error {
        ChainError::InvalidPow { .. } => "high-hash",
        ChainError::ZeroTarget { .. }
        | ChainError::TargetExceedsLimit { .. }
        | ChainError::NbitsMismatch { .. } => "bad-diffbits",
        ChainError::TimestampTooEarly { .. } => "time-too-old",
        ChainError::TimestampTooFarAhead { .. } => "time-too-new",
        ChainError::MissingParent { .. } => "prev-blk-not-found",
        ChainError::DuplicateHeader { .. } => "duplicate",
        _ => return CompactString::from(error.to_string()),
    })
}
