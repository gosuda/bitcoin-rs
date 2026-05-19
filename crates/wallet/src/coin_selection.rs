use bdk_coin_select::metrics::{Changeless, LowestFee};
use bdk_coin_select::{
    Candidate as BdkCandidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate,
    Target as BdkTarget, TargetFee, TargetOutputs,
};
use serde::{Deserialize, Serialize};

use crate::WalletError;

/// Candidate input for wallet coin selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Candidate value in satoshis.
    pub value: u64,
    /// Estimated satisfaction weight in weight units.
    pub satisfaction_weight: u64,
    /// Whether spending this candidate uses segwit witness data.
    pub is_segwit: bool,
}

impl Candidate {
    /// Converts into the upstream selector candidate type.
    #[must_use]
    pub fn to_bdk(self) -> BdkCandidate {
        BdkCandidate::new(self.value, self.satisfaction_weight, self.is_segwit)
    }
}

/// Funding target for coin selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// Output value that must be funded.
    pub value: u64,
    /// Minimum absolute fee in satoshis.
    pub minimum_fee: u64,
    /// Target feerate for input-weight-aware selection.
    pub fee_rate: FeeRate,
}

impl Target {
    /// Creates a target from value, minimum fee, and feerate.
    #[must_use]
    pub const fn new(value: u64, minimum_fee: u64, fee_rate: FeeRate) -> Self {
        Self {
            value,
            minimum_fee,
            fee_rate,
        }
    }

    fn to_bdk(self) -> Result<BdkTarget, WalletError> {
        let value_sum = self
            .value
            .checked_add(self.minimum_fee)
            .ok_or_else(|| WalletError::Psbt("target value overflow".to_owned()))?;
        Ok(BdkTarget {
            fee: TargetFee::from_feerate(self.fee_rate),
            outputs: TargetOutputs {
                value_sum,
                weight_sum: 0,
                n_outputs: 1,
            },
        })
    }
}

/// Coin selection strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectStrategy {
    /// Branch-and-bound changeless-first selection.
    BnB,
    /// Greedy knapsack-style selection.
    Knapsack,
    /// Waste metric selection using long-term feerate accounting.
    WasteMetric,
}

/// Selected input set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    /// Indices selected from the candidate slice.
    pub selected_indices: Vec<usize>,
    /// Sum of selected candidate values.
    pub selected_value: u64,
    /// Fee implied by selected value minus target output value.
    pub fee: u64,
}

/// Selects coins with the requested strategy.
pub fn select_coins(
    target: &Target,
    candidates: &[Candidate],
    strategy: SelectStrategy,
) -> Result<Selection, WalletError> {
    let bdk_candidates: Vec<BdkCandidate> =
        candidates.iter().copied().map(Candidate::to_bdk).collect();
    let bdk_target = target.to_bdk()?;
    let mut selector = CoinSelector::new(&bdk_candidates);

    match strategy {
        SelectStrategy::BnB => select_bnb(&mut selector, bdk_target)?,
        SelectStrategy::Knapsack => select_knapsack(&mut selector, bdk_target)?,
        SelectStrategy::WasteMetric => select_waste(&mut selector, bdk_target)?,
    }

    to_selection(&selector, target)
}

fn select_bnb(selector: &mut CoinSelector<'_>, target: BdkTarget) -> Result<(), WalletError> {
    let change_policy = ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, 0);
    selector.sort_candidates_by_descending_value_pwu();
    let metric = Changeless {
        target,
        change_policy,
    };
    if selector.run_bnb(metric, 100_000).is_ok() {
        return Ok(());
    }
    selector
        .select_until_target_met(target)
        .map_err(|error| WalletError::InsufficientFunds {
            missing: error.missing,
        })
}

fn select_knapsack(selector: &mut CoinSelector<'_>, target: BdkTarget) -> Result<(), WalletError> {
    selector.sort_candidates_by_key(|(_index, candidate)| core::cmp::Reverse(candidate.value));
    selector
        .select_until_target_met(target)
        .map_err(|error| WalletError::InsufficientFunds {
            missing: error.missing,
        })
}

fn select_waste(selector: &mut CoinSelector<'_>, target: BdkTarget) -> Result<(), WalletError> {
    selector.sort_candidates_by_descending_value_pwu();
    let change_policy = ChangePolicy::min_value_and_waste(
        DrainWeights::TR_KEYSPEND,
        0,
        target.fee.rate,
        FeeRate::DEFAULT_MIN_RELAY,
    );
    let metric = LowestFee {
        target,
        long_term_feerate: FeeRate::DEFAULT_MIN_RELAY,
        change_policy,
    };
    if let Err(error) = selector.run_bnb(metric, 100_000) {
        selector.select_until_target_met(target).map_err(|funds| {
            WalletError::InsufficientFunds {
                missing: funds.missing,
            }
        })?;
        if !selector.is_target_met(target) {
            return Err(WalletError::NoBnbSolution {
                rounds: error.rounds,
                max_rounds: error.max_rounds,
            });
        }
    }
    Ok(())
}

fn to_selection(selector: &CoinSelector<'_>, target: &Target) -> Result<Selection, WalletError> {
    let selected_value = selector.selected_value();
    let target_with_fee = target
        .value
        .checked_add(target.minimum_fee)
        .ok_or_else(|| WalletError::Psbt("target value overflow".to_owned()))?;
    if selected_value < target_with_fee {
        return Err(WalletError::InsufficientFunds {
            missing: target_with_fee - selected_value,
        });
    }
    Ok(Selection {
        selected_indices: selector.selected_indices().iter().copied().collect(),
        selected_value,
        fee: selected_value - target.value,
    })
}
