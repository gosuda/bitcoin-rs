// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; `map_apply_error` is the in-code
// mapping contract from chainstate refusal to BIP22/BIP23 validation results.
use super::BlockValidationResult;
use super::map_apply_error;
use super::submission::test_block_validity_error;
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Txid;
use compact_str::CompactString;

fn rejected(error: ApplyError) -> CompactString {
    match map_apply_error(error) {
        BlockValidationResult::Rejected(reason) => reason,
        other => panic!("expected rejected, got {other:?}"),
    }
}

#[test]
fn journal_backpressure_is_operational() {
    assert!(matches!(
        map_apply_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
        BlockValidationResult::Inconclusive
    ));
}

// CONTRACT: docs/contracts/external-api.md#API-30
#[test]
fn generateblock_validity_wraps_bip22_reason() {
    let error = test_block_validity_error(ApplyError::UndoPrevoutMissing {
        txid: Txid::from(Hash256::from_le_bytes(&[0x11; 32])),
        vout: 0,
    });
    match error {
        MiningControlError::Rejected(reason) => {
            assert_eq!(
                reason.as_str(),
                "TestBlockValidity failed: bad-txns-inputs-missingorspent"
            );
        }
        other => panic!("expected rejected, got {other:?}"),
    }
}

// CONTRACT: docs/contracts/external-api.md#API-30
#[test]
fn generateblock_validity_keeps_shutdown_operational() {
    assert!(matches!(
        test_block_validity_error(ApplyError::Shutdown),
        MiningControlError::Unavailable(_)
    ));
    assert!(matches!(
        test_block_validity_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
        MiningControlError::Unavailable(_)
    ));
}

#[test]
fn consensus_failures_use_core_bip22_reasons() {
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::CoinbaseAmount {
            paid: 1,
            allowed: 0,
        })),
        "bad-cb-amount"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::MissingCoinbase)),
        "bad-cb-missing"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::EmptyBlock)),
        "bad-cb-missing"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::ExtraCoinbase {
            tx_index: 1
        })),
        "bad-cb-multiple"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::MerkleRoot)),
        "bad-txnmrklroot"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::MerkleMutation)),
        "bad-txns-duplicate"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::WitnessNonceSize)),
        "bad-witness-nonce-size"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::UnexpectedWitness)),
        "unexpected-witness"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::WitnessCommitment)),
        "bad-witness-merkle-match"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::BlockWeight {
            weight: 5,
            max: 4,
        })),
        "bad-blk-weight"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::EmptyInputs)),
        "bad-txns-vin-empty"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::MissingPrevout {
            input_index: 0
        })),
        "bad-txns-inputs-missingorspent"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(
            ConsensusError::InputsLessThanOutputs {
                input_value: 1,
                output_value: 2,
            }
        )),
        "bad-txns-in-belowout"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::Bip {
            bip: "BIP34",
            reason: "x".to_owned(),
        })),
        "bad-cb-height"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::Bip {
            bip: "BIP113",
            reason: "x".to_owned(),
        })),
        "bad-txns-nonfinal"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::Bip {
            bip: "COINBASE_MATURITY",
            reason: "x".to_owned(),
        })),
        "bad-txns-premature-spend-of-coinbase"
    );
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::Script {
            input_index: 0,
            reason: "EVAL_FALSE".to_owned(),
        })),
        "block-script-verify-flag-failed (EVAL_FALSE)"
    );
}

#[test]
fn header_failures_use_core_bip22_reasons() {
    let hash = Hash256::default();
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::InvalidPow {
            hash,
            target: ChainWork::ZERO,
        })),
        "high-hash"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::TimestampTooEarly {
            hash,
            timestamp: 1,
            median: 2,
        })),
        "time-too-old"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::TimestampTooFarAhead {
            hash,
            timestamp: 9,
            max_allowed: 1,
        })),
        "time-too-new"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::MissingParent {
            prev_hash: hash
        })),
        "prev-blk-not-found"
    );
}
