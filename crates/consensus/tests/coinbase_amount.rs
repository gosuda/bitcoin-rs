use bitcoin_rs_consensus::{ConsensusError, block_subsidy, verify_coinbase_amount};
use bitcoin_rs_primitives::Network;

const MAINNET: u32 = 210_000;
const REGTEST: u32 = 150;
const FIFTY_BTC: u64 = 50 * 100_000_000;

#[test]
fn the_subsidy_halves_on_the_network_s_schedule_and_saturates_to_zero() {
    assert_eq!(Network::Mainnet.subsidy_halving_interval(), MAINNET);
    assert_eq!(Network::Signet.subsidy_halving_interval(), MAINNET);
    assert_eq!(Network::Regtest.subsidy_halving_interval(), REGTEST);

    let cases: [(u32, u32, u64); 11] = [
        (0, MAINNET, FIFTY_BTC),
        (209_999, MAINNET, FIFTY_BTC),
        (210_000, MAINNET, FIFTY_BTC / 2),
        (419_999, MAINNET, FIFTY_BTC / 2),
        (420_000, MAINNET, FIFTY_BTC / 4),
        (630_000, MAINNET, 625_000_000),
        (64 * MAINNET, MAINNET, 0),
        (u32::MAX, MAINNET, 0),
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

#[test]
fn a_coinbase_may_claim_the_halved_subsidy_plus_the_fees_and_no_more() {
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
