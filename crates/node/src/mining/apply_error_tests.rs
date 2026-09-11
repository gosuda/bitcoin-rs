use super::BlockValidationResult;
use super::map_apply_error;
use crate::apply::error::ApplyError;

// Contract: `MiningCoordinator::map_apply_error` treats journal pressure as a
// retryable operational condition, rather than a block rejection.
#[test]
fn journal_backpressure_is_operational() {
    assert!(matches!(
        map_apply_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
        BlockValidationResult::Inconclusive
    ));
}

// Contract: `bitcoin_rs_consensus::ConsensusError::CoinbaseAmount` documents
// Bitcoin Core's `bad-cb-amount` consensus result.
#[test]
fn coinbase_amount_is_bad_cb_amount() {
    assert!(matches!(
        map_apply_error(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::CoinbaseAmount {
                paid: 1,
                allowed: 0,
            }
        )),
        BlockValidationResult::Rejected(reason) if reason == "bad-cb-amount"
    ));
}
