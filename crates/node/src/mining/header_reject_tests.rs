use super::header_reject_reason;
use bitcoin_rs_chain::{ChainError, ChainWork};
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;

// CONTRACT: docs/contracts/external-api.md#API-13
#[test]
fn pow_failure_is_high_hash() {
    assert!(matches!(
        header_reject_reason(ChainError::InvalidPow {
            hash: Hash256::default(),
            target: ChainWork::default(),
        }),
        MiningControlError::Rejected(reason) if reason == "high-hash"
    ));
}

#[test]
fn nbits_mismatch_is_bad_diffbits() {
    assert!(matches!(
        header_reject_reason(ChainError::NbitsMismatch {
            actual: 1,
            expected: 2,
            height: 1,
        }),
        MiningControlError::Rejected(reason) if reason == "bad-diffbits"
    ));
}
