use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_execution::chain::ChainError;
use compact_str::CompactString;

use crate::mining::{MiningControlError, MiningError};

const SIGOPS_LIMIT_REASON: &str = "bad-blk-sigops";

pub const STALE_PARENT_REASON: &str = "inconclusive-not-best-prevblk";

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
        ConsensusError::EmptyBlock
        | ConsensusError::MissingCoinbase
        | ConsensusError::SixtyFourByteMutation => "bad-cb-missing",
        ConsensusError::ExtraCoinbase { .. } => "bad-cb-multiple",
        ConsensusError::MerkleMutation => "bad-txns-duplicate",
        ConsensusError::MerkleRoot => "bad-txnmrklroot",
        ConsensusError::CoinbaseAmount { .. } => "bad-cb-amount",
        ConsensusError::BlockValueOverflow => "bad-txns-accumulated-fee-outofrange",
        ConsensusError::WitnessNonceSize => "bad-witness-nonce-size",
        ConsensusError::UnexpectedWitness => "unexpected-witness",
        ConsensusError::WitnessCommitment => "bad-witness-merkle-match",
        ConsensusError::BlockWeight { .. } => "bad-blk-weight",
        ConsensusError::BlockBaseSize { .. } => "bad-blk-length",
        ConsensusError::SignetSolution => "bad-signet-blksig",
        ConsensusError::Script { reason, .. } => {
            return CompactString::from(format!("block-script-verify-flag-failed ({reason})"));
        }
        ConsensusError::Bip { bip, reason } => {
            return CompactString::from(match *bip {
                "BIP30" => "bad-txns-BIP30",
                "BIP34" => "bad-cb-height",
                "BIP68" | "BIP113" => "bad-txns-nonfinal",
                "COINBASE_MATURITY" => "bad-txns-premature-spend-of-coinbase",
                _ => {
                    return CompactString::from(format!(
                        "block-script-verify-flag-failed ({bip}: {reason})"
                    ));
                }
            });
        }
        ConsensusError::PrevoutMatrixSize { .. }
        | ConsensusError::PrevoutCount { .. }
        | ConsensusError::PrevoutMismatch { .. }
        | ConsensusError::UnsupportedEngine { .. }
        | ConsensusError::Kernel(_)
        | ConsensusError::Encoding(_) => return CompactString::from(error.to_string()),
    })
}

pub fn chain_reject_reason(error: &ChainError) -> CompactString {
    CompactString::from(match error {
        ChainError::InvalidPow { .. }
        | ChainError::ZeroTarget { .. }
        | ChainError::TargetExceedsLimit { .. }
        | ChainError::TargetBitsOverflow { .. } => "high-hash",
        ChainError::NbitsMismatch { .. } => "bad-diffbits",
        ChainError::TimestampTooEarly { .. } => "time-too-old",
        ChainError::TimestampTooFarAhead { .. } => "time-too-new",
        ChainError::MissingParent { .. } => "prev-blk-not-found",
        ChainError::InvalidParent { .. } => "bad-prevblk",
        ChainError::KnownInvalidHeader { .. } => "duplicate-invalid",
        ChainError::DuplicateHeader { .. } => "duplicate",
        ChainError::BadVersion { version, .. } => {
            return CompactString::from(format!(
                "bad-version(0x{:08x})",
                (*version).cast_unsigned()
            ));
        }
        ChainError::TimewarpAttack { .. } => return CompactString::from("time-timewarp-attack"),
        _ => return CompactString::from(error.to_string()),
    })
}

pub fn header_reject_reason(error: ChainError) -> MiningControlError {
    MiningControlError::Rejected(match error {
        ChainError::MissingParent { prev_hash } => {
            CompactString::from(format!("Must submit previous header ({prev_hash}) first"))
        }
        other => chain_reject_reason(&other),
    })
}

pub fn ordered_assembly_error(error: &MiningError) -> MiningControlError {
    if matches!(error, MiningError::CapacityExhausted { field: "sigops" }) {
        MiningControlError::Rejected(CompactString::from(format!(
            "TestBlockValidity failed: {SIGOPS_LIMIT_REASON}"
        )))
    } else {
        MiningControlError::Failed(CompactString::from(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{chain_reject_reason, consensus_reject_reason, header_reject_reason};
    use crate::mining::MiningControlError;
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_consensus::{ConsensusError, ScriptEngine};
    use bitcoin_rs_execution::chain::{ChainError, NodeId};

    // API-19
    #[test]
    fn consensus_failures_use_core_bip22_reasons() {
        let bip = |bip| ConsensusError::Bip {
            bip,
            reason: "x".to_owned(),
        };
        let script = |reason: &str| ConsensusError::Script {
            input_index: 0,
            reason: reason.to_owned(),
            engine: ScriptEngine::Native,
        };
        for (error, want) in [
            (
                ConsensusError::CoinbaseAmount {
                    paid: 1,
                    allowed: 0,
                },
                "bad-cb-amount",
            ),
            (ConsensusError::MissingCoinbase, "bad-cb-missing"),
            (ConsensusError::SixtyFourByteMutation, "bad-cb-missing"),
            (ConsensusError::EmptyBlock, "bad-cb-missing"),
            (
                ConsensusError::ExtraCoinbase { tx_index: 1 },
                "bad-cb-multiple",
            ),
            (ConsensusError::MerkleRoot, "bad-txnmrklroot"),
            (ConsensusError::MerkleMutation, "bad-txns-duplicate"),
            (ConsensusError::WitnessNonceSize, "bad-witness-nonce-size"),
            (ConsensusError::UnexpectedWitness, "unexpected-witness"),
            (
                ConsensusError::WitnessCommitment,
                "bad-witness-merkle-match",
            ),
            (
                ConsensusError::BlockWeight { weight: 5, max: 4 },
                "bad-blk-weight",
            ),
            (ConsensusError::SignetSolution, "bad-signet-blksig"),
            (ConsensusError::EmptyInputs, "bad-txns-vin-empty"),
            (
                ConsensusError::BlockBaseSize {
                    size: 1_000_001,
                    max: 1_000_000,
                },
                "bad-blk-length",
            ),
            (
                ConsensusError::MissingPrevout { input_index: 0 },
                "bad-txns-inputs-missingorspent",
            ),
            (
                ConsensusError::InputsLessThanOutputs {
                    input_value: 1,
                    output_value: 2,
                },
                "bad-txns-in-belowout",
            ),
            (bip("BIP34"), "bad-cb-height"),
            (bip("BIP68"), "bad-txns-nonfinal"),
            (bip("BIP113"), "bad-txns-nonfinal"),
            (
                bip("COINBASE_MATURITY"),
                "bad-txns-premature-spend-of-coinbase",
            ),
            (
                script("EVAL_FALSE"),
                "block-script-verify-flag-failed (EVAL_FALSE)",
            ),
            (
                ConsensusError::PrevoutCount {
                    input_count: 2,
                    prevout_count: 1,
                },
                "transaction has 2 inputs but 1 prevouts",
            ),
            (
                ConsensusError::UnsupportedEngine {
                    engine: bitcoin_rs_consensus::ValidationEngine::Kernel,
                },
                "unsupported validation engine: kernel",
            ),
            (
                ConsensusError::PrevoutMismatch { input_index: 1 },
                "prevout does not match transaction input 1",
            ),
        ] {
            assert_eq!(consensus_reject_reason(&error), want, "{error:?}");
        }
    }

    // API-19
    #[test]
    fn header_failures_use_core_bip22_reasons() {
        let hash = Hash256::default();
        for (error, want) in [
            (
                ChainError::InvalidPow {
                    hash,
                    target: ChainWork::ZERO,
                },
                "high-hash",
            ),
            (
                ChainError::TargetBitsOverflow { bits: 0x2300_0001 },
                "high-hash",
            ),
            (ChainError::ZeroTarget { hash }, "high-hash"),
            (
                ChainError::TargetExceedsLimit {
                    hash,
                    target: ChainWork::from_be_bytes([0xff_u8; 32]),
                    max_target: ChainWork::ZERO,
                },
                "high-hash",
            ),
            (
                ChainError::TimestampTooEarly {
                    hash,
                    timestamp: 1,
                    median: 2,
                },
                "time-too-old",
            ),
            (
                ChainError::TimestampTooFarAhead {
                    hash,
                    timestamp: 9,
                    max_allowed: 1,
                },
                "time-too-new",
            ),
            (
                ChainError::MissingParent { prev_hash: hash },
                "prev-blk-not-found",
            ),
            (ChainError::KnownInvalidHeader { hash }, "duplicate-invalid"),
            (
                ChainError::InvalidParent {
                    parent: NodeId::new(7),
                },
                "bad-prevblk",
            ),
            (
                ChainError::BadVersion {
                    version: 1,
                    required: 2,
                    height: 500,
                },
                "bad-version(0x00000001)",
            ),
            (
                ChainError::BadVersion {
                    version: -1,
                    required: 4,
                    height: 104,
                },
                "bad-version(0xffffffff)",
            ),
            (
                ChainError::TimewarpAttack {
                    height: 2016,
                    timestamp: 999_399,
                    minimum: 999_400,
                },
                "time-timewarp-attack",
            ),
        ] {
            assert_eq!(chain_reject_reason(&error), want, "{error:?}");
        }
    }

    #[test]
    fn header_reject_reason_uses_chain_vocabulary() {
        let hash = Hash256::default();
        for (error, want) in [
            (
                ChainError::InvalidPow {
                    hash,
                    target: ChainWork::ZERO,
                },
                "high-hash",
            ),
            (
                ChainError::NbitsMismatch {
                    actual: 1,
                    expected: 2,
                    height: 1,
                },
                "bad-diffbits",
            ),
        ] {
            assert!(matches!(
                header_reject_reason(error),
                MiningControlError::Rejected(reason) if reason == want
            ));
        }
        assert!(matches!(
            header_reject_reason(ChainError::MissingParent { prev_hash: hash }),
            MiningControlError::Rejected(reason)
                if reason.starts_with("Must submit previous header")
        ));
    }
}
