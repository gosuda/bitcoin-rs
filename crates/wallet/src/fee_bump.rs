use bdk_coin_select::FeeRate;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, Txid};

use crate::WalletError;

/// In-memory fee-bump plan for one replaceable PSBT.
#[derive(Clone, Debug)]
pub struct FeeBumpPlan {
    base: Psbt,
}

impl FeeBumpPlan {
    /// Creates a plan from a base PSBT.
    #[must_use]
    pub const fn new(base: Psbt) -> Self {
        Self { base }
    }

    /// Bumps the plan's transaction when `txid` matches the base transaction id.
    pub fn bump_fee(&self, txid: Txid, new_fee_rate: FeeRate) -> Result<Psbt, WalletError> {
        if self.base.unsigned_tx.compute_txid() != txid {
            return Err(WalletError::MissingTransaction { txid });
        }
        bump_psbt(&self.base, new_fee_rate)
    }
}

/// Stateless fee-bump entry point for callers with persistent wallet state.
///
/// This crate is watch-only and does not keep a global transaction store. Use
/// [`FeeBumpPlan`] or [`bump_psbt`] when the base PSBT is already in memory.
pub const fn bump_fee(txid: Txid, _new_fee_rate: FeeRate) -> Result<Psbt, WalletError> {
    Err(WalletError::MissingTransaction { txid })
}

/// Returns a replacement PSBT that satisfies the core BIP125 fee rules.
pub fn bump_psbt(base: &Psbt, new_fee_rate: FeeRate) -> Result<Psbt, WalletError> {
    if !base.unsigned_tx.is_explicitly_rbf() {
        return Err(WalletError::Bip125(
            "base transaction does not opt in to replacement".to_owned(),
        ));
    }
    if base.unsigned_tx.output.is_empty() {
        return Err(WalletError::Bip125(
            "replacement needs at least one output to reduce".to_owned(),
        ));
    }

    let original_fee = base
        .fee()
        .map_err(|error| WalletError::Bip125(error.to_string()))?
        .to_sat();
    let mut replacement = base.clone();
    clear_input_signatures(&mut replacement);

    let current_weight = replacement.unsigned_tx.weight().to_wu();
    let minimum_relay_delta = FeeRate::DEFUALT_RBF_INCREMENTAL_RELAY.implied_fee(current_weight);
    let minimum_replacement_fee = original_fee
        .checked_add(minimum_relay_delta)
        .ok_or_else(|| WalletError::Bip125("replacement fee overflow".to_owned()))?;
    let requested_fee = new_fee_rate.implied_fee(current_weight);
    let required_fee = requested_fee.max(minimum_replacement_fee);
    if required_fee <= original_fee {
        return Err(WalletError::Bip125(
            "replacement fee must exceed the original fee".to_owned(),
        ));
    }

    let additional_fee = required_fee - original_fee;
    let last_output = replacement
        .unsigned_tx
        .output
        .last_mut()
        .ok_or_else(|| WalletError::Bip125("replacement has no outputs".to_owned()))?;
    let new_value = last_output
        .value
        .checked_sub(Amount::from_sat(additional_fee))
        .ok_or_else(|| WalletError::Bip125("replacement output would be negative".to_owned()))?;
    last_output.value = new_value;

    let replacement_fee = replacement
        .fee()
        .map_err(|error| WalletError::Bip125(error.to_string()))?
        .to_sat();
    if replacement_fee < required_fee {
        return Err(WalletError::Bip125(
            "replacement fee is below required fee".to_owned(),
        ));
    }
    if !same_unconfirmed_inputs(base, &replacement) {
        return Err(WalletError::Bip125(
            "replacement must spend the same unconfirmed inputs".to_owned(),
        ));
    }
    Ok(replacement)
}

fn clear_input_signatures(psbt: &mut Psbt) {
    for input in &mut psbt.inputs {
        input.partial_sigs.clear();
        input.tap_key_sig = None;
        input.tap_script_sigs.clear();
        input.final_script_sig = None;
        input.final_script_witness = None;
    }
}

fn same_unconfirmed_inputs(base: &Psbt, replacement: &Psbt) -> bool {
    base.unsigned_tx.input.len() == replacement.unsigned_tx.input.len()
        && base
            .unsigned_tx
            .input
            .iter()
            .zip(&replacement.unsigned_tx.input)
            .all(|(left, right)| left.previous_output == right.previous_output)
}

/// Wrapper around [`bump_psbt`] that accepts a raw sat/kvB fee rate from RPC
/// callers without exposing the `bdk_coin_select::FeeRate` type.
pub fn bump_psbt_with_rate_sat_per_kvb(base: &Psbt, sat_per_kvb: u64) -> Result<Psbt, WalletError> {
    let sat_per_vb_u64 = sat_per_kvb / 1_000;
    let sat_per_vb_f32 = if let Ok(small) = u32::try_from(sat_per_vb_u64) {
        let inner = u16::try_from(small.min(u32::from(u16::MAX))).unwrap_or(u16::MAX);
        f32::from(inner)
    } else {
        f32::from(u16::MAX)
    };
    let rate = FeeRate::from_sat_per_vb(sat_per_vb_f32);
    bump_psbt(base, rate)
}
