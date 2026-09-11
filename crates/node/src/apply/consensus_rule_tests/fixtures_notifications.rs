//! Shared contract-test fixture construction.

use super::super::*;
use super::fixtures_behavior::apply_height_one_block;
use super::fixtures_behavior::fixture_txid;
use super::fixtures_validation::op_true_script;
use super::fixtures_validation::spending_transaction_to_script;
use bitcoin_rs_primitives::OutPoint;
use std::sync::Arc;

/// The same, plus a transaction spending a seeded 1000-satoshi output and
/// paying 1 satoshi onward, so the block earns a 999-satoshi fee.
#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn apply_block_with_a_fee_paying_transaction(
    coinbase_value: u64,
) -> Result<TipSnapshot, ApplyError> {
    let funded = OutPoint::new(fixture_txid(0x71), 0);
    let spend = spending_transaction_to_script(funded, u32::MAX, op_true_script());
    apply_height_one_block(vec![spend], coinbase_value)
}

pub(super) fn zmq_followers(
    publisher: Arc<dyn crate::ZmqPublisher>,
) -> crate::chain_effects::ChainFollowers {
    crate::chain_effects::ChainFollowers::new(
        crate::chain_effects::ChainEffects::noop().with_zmq_publisher(publisher),
        Arc::new(crate::mining::MiningGenerationSignal::new()),
        None,
    )
}
