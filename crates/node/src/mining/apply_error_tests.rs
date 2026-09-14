// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; `map_apply_error` is the in-code
// mapping contract from chainstate refusal to BIP22/BIP23 validation results.
use super::submission::{map_apply_error, test_block_validity_error};
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_mining::BlockValidationResult;
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
}
