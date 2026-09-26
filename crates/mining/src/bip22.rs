//! BIP22 reject-reason vocabulary for submission and header admission.

use bitcoin_rs_chain::ChainError;
use bitcoin_rs_consensus::ConsensusError;
use compact_str::CompactString;

use crate::{MiningControlError, MiningError};

const SIGOPS_LIMIT_REASON: &str = "bad-blk-sigops";

/// Core `GetRejectReason` strings for consensus failures (API-19).
pub fn consensus_reject_reason(error: &ConsensusError) -> CompactString {
    CompactString::from(match error {
        ConsensusError::EmptyInputs => "bad-txns-vin-empty",
        ConsensusError::EmptyOutputs => "bad-txns-vout-empty",
        ConsensusError::CoinbaseScriptSigSize { .. } => "bad-cb-length",
        ConsensusError::NullPrevout { .. } => "bad-txns-prevout-null",
        ConsensusError::DuplicateInput { .. } => "bad-txns-inputs-duplicate",
        ConsensusError::MissingPrevout { .. } => "bad-txns-inputs-missingorspent",
        ConsensusError::OutputValueOverflow => "bad-txns-txouttotal-toolarge",
        ConsensusError::InputsLessThanOutputs { .. } => "bad-txns-in-belowout",
        ConsensusError::SigopsLimit { .. } => SIGOPS_LIMIT_REASON,
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
        ConsensusError::Bip { bip, reason } => {
            return CompactString::from(match *bip {
                "BIP30" => "bad-txns-BIP30",
                "BIP34" => "bad-cb-height",
                "BIP68" | "BIP113" => "bad-txns-nonfinal",
                "COINBASE_MATURITY" => "bad-txns-premature-spend-of-coinbase",
                // Any other BIP rule keeps the flag-failure envelope.
                _ => {
                    return CompactString::from(format!(
                        "block-script-verify-flag-failed ({bip}: {reason})"
                    ));
                }
            });
        }
        ConsensusError::PrevoutMatrixSize { .. }
        | ConsensusError::Kernel(_)
        | ConsensusError::Encoding(_) => return CompactString::from(error.to_string()),
    })
}

/// Core `GetRejectReason` strings for header/chain failures (API-19).
pub fn chain_reject_reason(error: &ChainError) -> CompactString {
    CompactString::from(match error {
        ChainError::InvalidPow { .. } => "high-hash",
        ChainError::ZeroTarget { .. }
        | ChainError::TargetExceedsLimit { .. }
        | ChainError::NbitsMismatch { .. } => "bad-diffbits",
        ChainError::TimestampTooEarly { .. } => "time-too-old",
        ChainError::TimestampTooFarAhead { .. } => "time-too-new",
        ChainError::MissingParent { .. } => "prev-blk-not-found",
        ChainError::InvalidParent { .. } => "bad-prevblk",
        ChainError::KnownInvalidHeader { .. } => "duplicate-invalid",
        ChainError::DuplicateHeader { .. } => "duplicate",
        _ => return CompactString::from(error.to_string()),
    })
}

/// `submitheader` rejection projection (API-13).
pub fn header_reject_reason(error: ChainError) -> MiningControlError {
    MiningControlError::Rejected(match error {
        ChainError::MissingParent { prev_hash } => {
            CompactString::from(format!("Must submit previous header ({prev_hash}) first"))
        }
        other => chain_reject_reason(&other),
    })
}

/// Keeps ordered-generate sigop preflight refusals in the API-30 error vocabulary.
pub(crate) fn ordered_assembly_error(error: &MiningError) -> MiningControlError {
    if matches!(error, MiningError::CapacityExhausted { field: "sigops" }) {
        MiningControlError::Rejected(CompactString::from(format!(
            "TestBlockValidity failed: {SIGOPS_LIMIT_REASON}"
        )))
    } else {
        MiningControlError::Failed(CompactString::from(error.to_string()))
    }
}

#[cfg(test)]
mod tests;
