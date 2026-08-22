//! Block subsidy schedule and the coinbase-amount rule.

use bitcoin_rs_consensus::{ConsensusError, block_subsidy, verify_coinbase_amount};
use bitcoin_rs_primitives::Network;

const MAINNET: u32 = 210_000;
const REGTEST: u32 = 150;
const FIFTY_BTC: u64 = 50 * 100_000_000;

#[test]
fn the_subsidy_halves_on_schedule() {
    assert_eq!(block_subsidy(0, MAINNET), FIFTY_BTC);
    assert_eq!(block_subsidy(209_999, MAINNET), FIFTY_BTC);
    assert_eq!(block_subsidy(210_000, MAINNET), FIFTY_BTC / 2);
    assert_eq!(block_subsidy(419_999, MAINNET), FIFTY_BTC / 2);
    assert_eq!(block_subsidy(420_000, MAINNET), FIFTY_BTC / 4);
    // The first halving that lands on an odd satoshi count, which is where an
    // implementation using floating point or rounding would diverge.
    assert_eq!(block_subsidy(630_000, MAINNET), 625_000_000);
}

/// Regtest halves every 150 blocks, and using the mainnet interval there
/// over-states the subsidy by a factor of 2^1400.
#[test]
fn the_halving_interval_is_the_network_s() {
    assert_eq!(Network::Regtest.subsidy_halving_interval(), REGTEST);
    assert_eq!(Network::Mainnet.subsidy_halving_interval(), MAINNET);
    assert_eq!(Network::Signet.subsidy_halving_interval(), MAINNET);

    assert_eq!(block_subsidy(150, REGTEST), FIFTY_BTC / 2);
    assert_eq!(
        block_subsidy(150, MAINNET),
        FIFTY_BTC,
        "the mainnet interval must not have halved yet at height 150"
    );
}

/// Past 64 halvings the subsidy is zero, and shifting a `u64` that far is
/// undefined rather than merely zero.
#[test]
fn the_subsidy_reaches_zero_without_overflowing() {
    assert_eq!(block_subsidy(64 * MAINNET, MAINNET), 0);
    assert_eq!(block_subsidy(u32::MAX, MAINNET), 0);
    assert_eq!(block_subsidy(u32::MAX, REGTEST), 0);
}

#[test]
fn a_coinbase_may_claim_the_subsidy_plus_the_fees() {
    let allowed = FIFTY_BTC + 999;

    assert_eq!(verify_coinbase_amount(allowed, 999, 1, MAINNET), Ok(()));
    // Claiming less is fine; the difference is destroyed, as in Core.
    assert_eq!(verify_coinbase_amount(0, 999, 1, MAINNET), Ok(()));
    assert_eq!(
        verify_coinbase_amount(allowed + 1, 999, 1, MAINNET),
        Err(ConsensusError::CoinbaseAmount {
            paid: allowed + 1,
            allowed,
        })
    );
}

/// The allowance follows the halving, so a post-halving block cannot claim the
/// pre-halving subsidy.
#[test]
fn the_allowance_follows_the_halving() {
    assert_eq!(
        verify_coinbase_amount(FIFTY_BTC, 0, 209_999, MAINNET),
        Ok(())
    );
    assert_eq!(
        verify_coinbase_amount(FIFTY_BTC, 0, 210_000, MAINNET),
        Err(ConsensusError::CoinbaseAmount {
            paid: FIFTY_BTC,
            allowed: FIFTY_BTC / 2,
        })
    );
}

#[test]
fn an_overflowing_allowance_is_refused_rather_than_wrapped() {
    assert_eq!(
        verify_coinbase_amount(0, u64::MAX, 1, MAINNET),
        Err(ConsensusError::BlockValueOverflow)
    );
}
