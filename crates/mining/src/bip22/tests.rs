// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; the BIP22 reject vocabulary is
// the in-code mapping contract from consensus/chain refusal to reject
// reason strings.
use super::{chain_reject_reason, consensus_reject_reason, header_reject_reason};
use crate::MiningControlError;
use bitcoin_rs_chain::{ChainError, ChainWork};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::Hash256;

#[test]
fn consensus_failures_use_core_bip22_reasons() {
    let bip = |bip| ConsensusError::Bip {
        bip,
        reason: "x".to_owned(),
    };
    let script = |reason: &str| ConsensusError::Script {
        input_index: 0,
        reason: reason.to_owned(),
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
        (ConsensusError::EmptyInputs, "bad-txns-vin-empty"),
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
        (bip("BIP113"), "bad-txns-nonfinal"),
        (
            bip("COINBASE_MATURITY"),
            "bad-txns-premature-spend-of-coinbase",
        ),
        (
            script("EVAL_FALSE"),
            "block-script-verify-flag-failed (EVAL_FALSE)",
        ),
    ] {
        assert_eq!(consensus_reject_reason(&error), want, "{error:?}");
    }
}

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
    ] {
        assert_eq!(chain_reject_reason(&error), want, "{error:?}");
    }
}

// CONTRACT: docs/contracts/external-api.md#API-13
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
