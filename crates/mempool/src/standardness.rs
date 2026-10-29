use alloc::vec::Vec;

use hashbrown::{HashMap, HashSet};

use bitcoin_rs_consensus::bip68;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, Wtxid};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
use bitcoin_rs_script::{
    is_op_return, is_p2a, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only,
    minimal_non_dust, multisig_key_count,
};
use thiserror::Error;

use crate::{Mempool, PolicyError, PrevoutMeta, RbfError};

const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardnessPolicy {
    /// Fee rate used to classify outputs as dust, in sat/kvB.
    pub dust_relay_fee: u64,
    /// Maximum aggregate serialized nulldata script bytes, or `None` to disable nulldata.
    pub max_datacarrier_bytes: Option<usize>,
}

impl Default for StandardnessPolicy {
    fn default() -> Self {
        Self {
            dust_relay_fee: 3_000,
            max_datacarrier_bytes: Some(83),
        }
    }
}

const TX_VERSION_MIN: u32 = 1;

const TX_VERSION_MAX: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StandardnessError {
    #[error("non-standard transaction version")]
    Version,
    #[error("transaction weight exceeds maximum standard weight")]
    Weight,
    #[error("scriptSig is not push-only")]
    ScriptSigNotPushOnly,
    #[error("scriptSig exceeds maximum standard size")]
    ScriptSigTooLarge,
    #[error("non-standard output script")]
    NonStandardOutput,
    #[error("nulldata outputs are disabled")]
    DataCarrierDisabled,
    #[error("aggregate nulldata script bytes exceed the policy limit")]
    DataCarrierBytesExceeded,
    #[error("aggregate nulldata script length overflowed")]
    DataCarrierSizeOverflow,
    #[error("transaction non-witness size is below the relay minimum")]
    TransactionTooSmall,
    #[error("dust")]
    DustOutput,
}

pub fn is_standard_tx(tx: &Tx, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
    check_version(tx)?;
    check_weight(tx)?;
    check_script_sigs(tx)?;
    check_outputs(tx, policy)?;
    check_min_size(tx)?;
    Ok(())
}

/// Bitcoin Core `MAX_PACKAGE_COUNT` for package acceptance / `testmempoolaccept`.
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Bitcoin Core `MAX_PACKAGE_WEIGHT`: the aggregate weight-unit bound of a
/// multi-transaction package.
pub const MAX_PACKAGE_WEIGHT: u64 = 404_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTxContext {
    pub fee: u64,
    pub vsize: u32,
    pub sigop_cost: u32,
    pub missing_inputs: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxAcceptanceFact {
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub allowed: Option<bool>,
    pub vsize: u32,
    pub weight: u64,
    pub sigop_cost: u32,
    pub base_fee: Option<u64>,
    pub modified_fee: Option<i128>,
    pub effective_fee_rate: Option<u64>,
    pub reject_reason: Option<AcceptanceRejectReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAcceptanceFacts {
    pub package_error: Option<AcceptanceRejectReason>,
    pub results: Vec<TxAcceptanceFact>,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Bip68Admission<'a> {
    pub csv_active: bool,
    pub next_height: u32,
    pub next_mtp: u32,
    pub prevout_meta: Option<&'a HashMap<OutPoint, PrevoutMeta>>,
    pub resolved_prevouts: Option<&'a HashSet<OutPoint>>,
}

/// Per-transaction relay sigop limit: one fifth of the block limit,
/// matching Core v31.1's `MAX_STANDARD_TX_SIGOPS_COST`.
pub const MAX_STANDARD_TX_SIGOPS_COST: u32 = 16_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceRejectReason {
    #[error("package-too-many-transactions")]
    PackageCount,
    #[error("package-too-large")]
    PackageTooLarge,
    #[error("package-contains-duplicates")]
    PackageDuplicates,
    #[error("package-not-sorted")]
    PackageOrder,
    #[error("package-not-child-with-parents")]
    PackageTopology,
    #[error("package submission supports at most one parent and one child")]
    PackageUnsupported,
    #[error("conflict-in-package")]
    PackageConflict,
    #[error("bip125-replacement-disallowed")]
    MempoolConflict,
    #[error("too-large-cluster")]
    PackageCluster,
    #[error(transparent)]
    Truc(#[from] crate::TrucError),
    #[error("missing-ephemeral-spends")]
    MissingEphemeralSpends,
    #[error("txn-already-in-mempool")]
    AlreadyInMempool,
    #[error("missing-inputs")]
    MissingInputs,
    #[error("min relay fee not met")]
    MinRelayFeeNotMet,
    #[error("max-fee-exceeded")]
    MaxFeeExceeded,
    #[error(transparent)]
    NonStandard(#[from] StandardnessError),
    #[error(transparent)]
    Replacement(#[from] RbfError),
    #[error(transparent)]
    Mempool(#[from] crate::MempoolError),
    #[error(transparent)]
    PackageLimit(#[from] PolicyError),
    #[error("too-many-sigops")]
    TooManySigops,
    #[error("non-BIP68-final")]
    NonBip68Final,
    #[error("script-verify-flag-failed")]
    ScriptVerify,
}

pub(crate) fn exceeds_max_feerate(fee: u64, vsize: u32, maximum: Option<u64>) -> bool {
    maximum.is_some_and(|max| {
        crate::rbf::required_fee(max, vsize)
            .is_ok_and(|limit| limit != 0 && i128::from(fee) > limit)
    })
}
pub(crate) fn bip68_final(pool: &Mempool, tx: &Tx, finality: &Bip68Admission<'_>) -> bool {
    if !finality.csv_active || tx.version < 2 {
        return true;
    }
    let empty_meta = HashMap::new();
    let empty_set = HashSet::new();
    let prevout_meta = finality.prevout_meta.unwrap_or(&empty_meta);
    let resolved = finality.resolved_prevouts.unwrap_or(&empty_set);
    for input in &tx.inputs {
        let sequence = input.sequence.to_consensus();
        if sequence & bip68::SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        let (prevout_height, prevout_mtp) =
            if let Some(meta) = prevout_meta.get(&input.previous_output) {
                (meta.height, meta.mtp)
            } else if resolved.contains(&input.previous_output)
                || pool.contains_txid(&input.previous_output.txid)
            {
                (finality.next_height, finality.next_mtp)
            } else {
                continue;
            };
        if !bip68::sequence_lock_satisfied(
            tx.version,
            sequence,
            prevout_height,
            prevout_mtp,
            finality.next_height,
            finality.next_mtp,
        ) {
            return false;
        }
    }
    true
}

pub(crate) fn evaluate_one(
    pool: &Mempool,
    policy: &StandardnessPolicy,
    tx: &Tx,
    context: PackageTxContext,
    max_feerate_sat_per_kvb: Option<u64>,
    mempool_min_fee_sat_per_kvb: Option<u64>,
    finality: &Bip68Admission<'_>,
) -> TxAcceptanceFact {
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    let weight = tx.weight();
    let vsize = context.vsize;
    let modified_fee_res = pool.modified_fee_for(txid, context.fee);
    let modified_fee = modified_fee_res.as_ref().ok().copied();
    let fee_for_max = context.fee;

    let fee_rejection = match mempool_min_fee_sat_per_kvb {
        None => None,
        Some(floor) => match (modified_fee_res, crate::rbf::required_fee(floor, vsize)) {
            (Ok(fee), Ok(required)) => {
                (fee < required).then_some(AcceptanceRejectReason::MinRelayFeeNotMet)
            }
            _ => Some(AcceptanceRejectReason::Replacement(
                RbfError::ArithmeticOverflow,
            )),
        },
    };

    let reject = if pool.contains_txid(&txid) {
        Some(AcceptanceRejectReason::AlreadyInMempool)
    } else if tx.is_coinbase() || context.missing_inputs {
        Some(AcceptanceRejectReason::MissingInputs)
    } else if let Err(err) = is_standard_tx(tx, policy) {
        Some(AcceptanceRejectReason::NonStandard(err))
    } else if tx_has_dust_outputs(tx, policy.dust_relay_fee)
        && (context.fee != 0 || pool.modified_fee_for(txid, context.fee) != Ok(0))
    {
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::DustOutput,
        ))
    } else if context.sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
        Some(AcceptanceRejectReason::TooManySigops)
    } else if let Some(reason) = fee_rejection {
        Some(reason)
    } else if exceeds_max_feerate(fee_for_max, vsize, max_feerate_sat_per_kvb) {
        Some(AcceptanceRejectReason::MaxFeeExceeded)
    } else if !bip68_final(pool, tx, finality) {
        Some(AcceptanceRejectReason::NonBip68Final)
    } else {
        None
    };

    let effective_fee_rate = modified_fee.and_then(|fee| {
        let clamped = fee.max(0);
        (vsize != 0)
            .then(|| {
                clamped
                    .checked_mul(1_000)
                    .map(|prod| prod / i128::from(vsize))
            })
            .flatten()
            .and_then(|rate| u64::try_from(rate).ok())
    });

    TxAcceptanceFact {
        txid,
        wtxid,
        allowed: Some(reject.is_none()),
        vsize,
        weight,
        sigop_cost: context.sigop_cost,
        base_fee: Some(context.fee),
        modified_fee,
        effective_fee_rate,
        reject_reason: reject,
    }
}

const MIN_NON_WITNESS_TX_SIZE: usize = 65;

fn check_min_size(tx: &Tx) -> Result<(), StandardnessError> {
    if tx.base_size() < MIN_NON_WITNESS_TX_SIZE {
        return Err(StandardnessError::TransactionTooSmall);
    }
    Ok(())
}

fn check_version(tx: &Tx) -> Result<(), StandardnessError> {
    if (TX_VERSION_MIN..=TX_VERSION_MAX).contains(&tx.version) {
        Ok(())
    } else {
        Err(StandardnessError::Version)
    }
}

fn check_weight(tx: &Tx) -> Result<(), StandardnessError> {
    if tx.weight() > MAX_STANDARD_TX_WEIGHT {
        Err(StandardnessError::Weight)
    } else {
        Ok(())
    }
}

fn check_script_sigs(tx: &Tx) -> Result<(), StandardnessError> {
    for input in &tx.inputs {
        let script_sig = &input.script_sig;
        if !is_push_only(script_sig) {
            return Err(StandardnessError::ScriptSigNotPushOnly);
        }
        if script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(StandardnessError::ScriptSigTooLarge);
        }
    }
    Ok(())
}

fn check_outputs(tx: &Tx, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
    let mut datacarrier_bytes = 0_usize;
    let mut dust_outputs = 0_usize;
    for output in &tx.outputs {
        let script = &output.script_pubkey;
        if is_op_return(script) {
            if !is_push_only(&script[1..]) {
                return Err(StandardnessError::NonStandardOutput);
            }
            let Some(limit) = policy.max_datacarrier_bytes else {
                return Err(StandardnessError::DataCarrierDisabled);
            };
            let serialized_script_bytes = bitcoin_rs_primitives::varint::encoded_len(
                u64::try_from(script.len()).unwrap_or(u64::MAX),
            )
            .checked_add(script.len())
            .ok_or(StandardnessError::DataCarrierSizeOverflow)?;
            datacarrier_bytes = datacarrier_bytes
                .checked_add(serialized_script_bytes)
                .ok_or(StandardnessError::DataCarrierSizeOverflow)?;
            if datacarrier_bytes > limit {
                return Err(StandardnessError::DataCarrierBytesExceeded);
            }
            continue;
        }
        if !is_standard_output_script(script) {
            return Err(StandardnessError::NonStandardOutput);
        }
        dust_outputs += usize::from(is_dust(output, policy.dust_relay_fee));
    }
    if dust_outputs > 1 {
        return Err(StandardnessError::DustOutput);
    }
    Ok(())
}

fn is_standard_output_script(script: &[u8]) -> bool {
    is_p2pkh(script)
        || is_p2sh(script)
        || is_p2pk(script)
        || is_p2wpkh(script)
        || is_p2wsh(script)
        || is_p2tr(script)
        || is_p2a(script)
        || is_standard_multisig(script)
}

fn is_standard_multisig(script: &[u8]) -> bool {
    multisig_key_count(script).is_some_and(|n| n <= 3)
}

pub(crate) fn is_dust(output: &TxOut, dust_relay_fee: u64) -> bool {
    output.value.to_sat() < minimal_non_dust(&output.script_pubkey, dust_relay_fee)
}

#[must_use]
pub(crate) fn tx_has_dust_outputs(tx: &Tx, dust_relay_fee: u64) -> bool {
    tx.outputs
        .iter()
        .any(|output| is_dust(output, dust_relay_fee))
}

#[cfg(test)]
mod tests;
