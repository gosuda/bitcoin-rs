//! Coin selection strategy coverage.
use bdk_coin_select::FeeRate;
use bitcoin_rs_wallet::{Candidate, SelectStrategy, Target, select_coins};

#[test]
fn every_strategy_funds_target_plus_minimum_fee() -> Result<(), Box<dyn std::error::Error>> {
    let target = Target::new(9_000, 500, FeeRate::from_sat_per_vb(1.0));
    let candidates = [
        Candidate {
            value: 3_000,
            satisfaction_weight: 108,
            is_segwit: true,
        },
        Candidate {
            value: 4_000,
            satisfaction_weight: 108,
            is_segwit: true,
        },
        Candidate {
            value: 6_000,
            satisfaction_weight: 108,
            is_segwit: true,
        },
    ];

    for strategy in [
        SelectStrategy::BnB,
        SelectStrategy::Knapsack,
        SelectStrategy::WasteMetric,
    ] {
        let selection = select_coins(&target, &candidates, strategy)?;
        assert!(selection.selected_value >= target.value + target.minimum_fee);
        assert!(selection.fee >= target.minimum_fee);
        assert!(!selection.selected_indices.is_empty());
    }

    Ok(())
}
