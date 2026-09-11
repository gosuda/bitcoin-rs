// CONTRACT: `docs/contracts/external-api.md#API-05` and `#API-11` own
// mining validation/submission projection; `map_apply_error` is the in-code
// mapping contract from chainstate refusal to BIP22/BIP23 validation results.
use super::BlockValidationResult;
use super::map_apply_error;
use crate::apply::error::ApplyError;

#[test]
fn journal_backpressure_is_operational() {
    assert!(matches!(
        map_apply_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
        BlockValidationResult::Inconclusive
    ));
}

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
