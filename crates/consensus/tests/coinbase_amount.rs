//! Block subsidy schedule and the coinbase-amount rule.

use bitcoin_rs_consensus::{ConsensusError, block_subsidy, verify_coinbase_amount};
use bitcoin_rs_primitives::Network;

const MAINNET: u32 = 210_000;
const REGTEST: u32 = 150;
const FIFTY_BTC: u64 = 50 * 100_000_000;

/// The schedule halves on the interval the *network* declares, keeps integer
/// satoshis at the first odd halving, and saturates to zero rather than
/// shifting a `u64` past 63 places.
#[test]
fn the_subsidy_halves_on_the_network_s_schedule_and_saturates_to_zero() {
    assert_eq!(Network::Mainnet.subsidy_halving_interval(), MAINNET);
    assert_eq!(Network::Signet.subsidy_halving_interval(), MAINNET);
    assert_eq!(Network::Regtest.subsidy_halving_interval(), REGTEST);

    // (height, interval, subsidy)
    let cases: [(u32, u32, u64); 11] = [
        (0, MAINNET, FIFTY_BTC),
        (209_999, MAINNET, FIFTY_BTC),
        (210_000, MAINNET, FIFTY_BTC / 2),
        (419_999, MAINNET, FIFTY_BTC / 2),
        (420_000, MAINNET, FIFTY_BTC / 4),
        // The first halving landing on an odd satoshi count, where rounding
        // or floating point would diverge.
        (630_000, MAINNET, 625_000_000),
        (64 * MAINNET, MAINNET, 0),
        (u32::MAX, MAINNET, 0),
        // Regtest halves every 150 blocks; the mainnet interval has not.
        (150, REGTEST, FIFTY_BTC / 2),
        (150, MAINNET, FIFTY_BTC),
        (u32::MAX, REGTEST, 0),
    ];
    for (height, interval, subsidy) in cases {
        assert_eq!(
            block_subsidy(height, interval),
            subsidy,
            "height {height} interval {interval}"
        );
    }
}

/// A coinbase may claim the subsidy for its height plus the block's fees, and
/// no more. Claiming less is allowed and the difference is destroyed, as in
/// Core; an allowance that leaves the satoshi range is refused, not wrapped.
#[test]
fn a_coinbase_may_claim_the_halved_subsidy_plus_the_fees_and_no_more() {
    // (claimed, fees, height, verdict)
    let cases: [(u64, u64, u32, Result<(), ConsensusError>); 6] = [
        (FIFTY_BTC + 999, 999, 1, Ok(())),
        (0, 999, 1, Ok(())),
        (
            FIFTY_BTC + 1_000,
            999,
            1,
            Err(ConsensusError::CoinbaseAmount {
                paid: FIFTY_BTC + 1_000,
                allowed: FIFTY_BTC + 999,
            }),
        ),
        (FIFTY_BTC, 0, 209_999, Ok(())),
        (
            FIFTY_BTC,
            0,
            210_000,
            Err(ConsensusError::CoinbaseAmount {
                paid: FIFTY_BTC,
                allowed: FIFTY_BTC / 2,
            }),
        ),
        (0, u64::MAX, 1, Err(ConsensusError::BlockValueOverflow)),
    ];
    for (paid, fees, height, expected) in cases {
        assert_eq!(
            verify_coinbase_amount(paid, fees, height, MAINNET),
            expected,
            "paid {paid} fees {fees} height {height}"
        );
    }
}
