// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; `map_apply_error` is the in-code
// mapping contract from chainstate refusal to BIP22/BIP23 validation results.
use super::{map_apply_error, test_block_validity_error};
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_chainstate::ApplyError;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Txid;
use compact_str::CompactString;

#[test]
fn operational_failures_are_not_block_rejections() {
    fn failures() -> Vec<ApplyError> {
        use bitcoin_rs_storage::StorageError;
        vec![
            ApplyError::UtxoCommit(bitcoin_rs_utxo::UtxoError::CorruptRecord),
            ApplyError::BlockBodyPersistence(StorageError::InvalidOperation("body write failed")),
            ApplyError::UndoPersistence(StorageError::InvalidOperation("undo write failed")),
            ApplyError::DurableHeadCommit(StorageError::InvalidOperation("head write failed")),
            ApplyError::DurableHeadLineage {
                head: Hash256::default(),
                prev: Hash256::from_le_bytes(&[1; 32]),
            },
            ApplyError::Consensus(ConsensusError::Kernel("verifier unavailable".to_owned())),
            ApplyError::Consensus(ConsensusError::PrevoutMatrixSize {
                expected: 1,
                actual: 0,
            }),
        ]
    }

    for error in failures() {
        let result = map_apply_error(error);
        assert!(
            matches!(result, Err(MiningControlError::Failed(_))),
            "operational failure became a block verdict: {result:?}"
        );
    }
    for error in failures() {
        let result = test_block_validity_error(&error);
        assert!(
            matches!(result, MiningControlError::Failed(_)),
            "generateblock hid an operational error: {result:?}"
        );
    }
}

fn rejected(error: ApplyError) -> CompactString {
    match map_apply_error(error) {
        Ok(BlockValidationResult::Rejected(reason)) => reason,
        other => panic!("expected rejected, got {other:?}"),
    }
}

#[test]
fn journal_backpressure_is_operational() {
    assert!(matches!(
        map_apply_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
        Ok(BlockValidationResult::Inconclusive)
    ));
}

// CONTRACT: docs/contracts/external-api.md#API-30
#[test]
fn generateblock_validity_wraps_bip22_reason() {
    let error = test_block_validity_error(&ApplyError::UndoPrevoutMissing {
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
        test_block_validity_error(&ApplyError::Shutdown),
        MiningControlError::Unavailable(_)
    ));
    assert!(matches!(
        test_block_validity_error(&ApplyError::JournalBackpressure("test pressure".to_owned())),
        MiningControlError::Unavailable(_)
    ));
}

#[test]
fn apply_errors_delegate_consensus_and_chain_reasons() {
    assert_eq!(
        rejected(ApplyError::Consensus(ConsensusError::MissingCoinbase)),
        "bad-cb-missing"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::InvalidPow {
            hash: Hash256::default(),
            target: ChainWork::ZERO,
        })),
        "high-hash"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::KnownInvalidHeader {
            hash: Hash256::default(),
        })),
        "duplicate-invalid"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::BadVersion {
            version: 1,
            required: 2,
            height: 500,
        })),
        "bad-version(0x00000001)"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::TimewarpAttack {
            height: 2016,
            timestamp: 1,
            minimum: 601,
        })),
        "time-timewarp-attack"
    );
    assert_eq!(
        rejected(ApplyError::Chain(ChainError::InvalidParent {
            prev_hash: Hash256::default(),
        })),
        "bad-prevblk"
    );
}

#[test]
fn generation_overflow_is_terminal_unavailability_is_transient() {
    assert!(
        matches!(
            map_apply_error(ApplyError::ChainChangeGenerationOverflow),
            Err(MiningControlError::Failed(_))
        ),
        "a generation overflow requires restart, not a retry hint"
    );
    assert!(matches!(
        test_block_validity_error(&ApplyError::ChainChangeGenerationOverflow),
        MiningControlError::Failed(_)
    ));
    assert!(
        matches!(
            map_apply_error(ApplyError::ConcurrentChainChange),
            Err(MiningControlError::Unavailable(_))
        ),
        "an in-flight chain change is a transient refusal"
    );
}
