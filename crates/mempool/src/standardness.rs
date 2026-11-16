use alloc::vec::Vec;

use hashbrown::{HashMap, HashSet};

use bitcoin_rs_consensus::bip68;
use bitcoin_rs_consensus::primitives::{OutPoint, Tx, TxOut, Txid, Witness, Wtxid};

#[cfg(test)]
use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence};
use bitcoin_rs_consensus::script::sigops::count_accurate;
use bitcoin_rs_consensus::script::{
    Instruction, instructions, is_op_return, is_p2a, is_p2pk, is_p2pkh, is_p2sh, is_p2tr,
    is_p2wpkh, is_p2wsh, is_push_only, minimal_non_dust, multisig_key_count, opcode,
    witness_program,
};
use thiserror::Error;

use crate::{Mempool, PolicyError, PrevoutMeta, RbfError};

pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

const MAX_P2SH_SIGOPS: u32 = 15;

const MAX_TX_LEGACY_SIGOPS: u32 = 2_500;

const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;

const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;

const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;

const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3_600;

const WITNESS_V0_KEYHASH_SIZE: usize = 20;

const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

const WITNESS_V1_TAPROOT_SIZE: usize = 32;

const ANNEX_TAG: u8 = 0x50;

const TAPROOT_LEAF_MASK: u8 = 0xfe;

const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardnessPolicy {
    pub dust_relay_fee: u64,
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
    #[error("bad-txns-oversize")]
    Oversize,
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
    #[error("bad-txns-nonstandard-inputs")]
    NonStandardInput,
    #[error("bad-witness-nonstandard")]
    NonStandardWitness,
}

pub fn is_standard_tx(tx: &Tx, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
    check_version(tx)?;
    check_weight(tx)?;
    check_script_sigs(tx)?;
    check_outputs(tx, policy)?;
    check_min_size(tx)?;
    Ok(())
}

pub fn is_standard_spend(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> Result<(), StandardnessError> {
    if tx.is_coinbase() {
        return Ok(());
    }
    let prevouts = prevout_lookup(prevouts);
    check_inputs_standardness(tx, &prevouts)?;
    check_witness_standardness(tx, &prevouts)
}

pub const MAX_PACKAGE_COUNT: usize = 25;

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
    #[error("coinbase")]
    Coinbase,
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
        if sequence & bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
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
    prevouts: &[(OutPoint, TxOut)],
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
    } else if exceeds_block_weight(tx) {
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::Oversize,
        ))
    } else if tx.is_coinbase() {
        Some(AcceptanceRejectReason::Coinbase)
    } else if let Err(err) = is_standard_tx(tx, policy) {
        Some(AcceptanceRejectReason::NonStandard(err))
    } else if context.missing_inputs {
        Some(AcceptanceRejectReason::MissingInputs)
    } else if tx_has_dust_outputs(tx, policy.dust_relay_fee)
        && (context.fee != 0 || pool.modified_fee_for(txid, context.fee) != Ok(0))
    {
        Some(AcceptanceRejectReason::NonStandard(
            StandardnessError::DustOutput,
        ))
    } else if prevouts.len() == tx.inputs.len()
        && let Err(err) = is_standard_spend(tx, prevouts)
    {
        Some(AcceptanceRejectReason::NonStandard(err))
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

fn exceeds_block_weight(tx: &Tx) -> bool {
    u64::try_from(tx.base_size())
        .unwrap_or(u64::MAX)
        .saturating_mul(bitcoin_rs_consensus::WITNESS_SCALE_FACTOR)
        > bitcoin_rs_consensus::MAX_BLOCK_WEIGHT
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
            let serialized_script_bytes = bitcoin_rs_consensus::primitives::varint::encoded_len(
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

fn prevout_lookup(prevouts: &[(OutPoint, TxOut)]) -> HashMap<OutPoint, &TxOut> {
    prevouts
        .iter()
        .map(|(outpoint, output)| (*outpoint, output))
        .collect()
}

fn check_inputs_standardness(
    tx: &Tx,
    prevouts: &HashMap<OutPoint, &TxOut>,
) -> Result<(), StandardnessError> {
    if legacy_sigops(tx, prevouts) > MAX_TX_LEGACY_SIGOPS {
        return Err(StandardnessError::NonStandardInput);
    }
    for input in &tx.inputs {
        let Some(prevout) = prevouts.get(&input.previous_output) else {
            return Err(StandardnessError::NonStandardInput);
        };
        let script = prevout.script_pubkey.as_bytes();
        if is_p2sh(script) {
            let Some(redeem_script) = push_only_stack_top(&input.script_sig) else {
                return Err(StandardnessError::NonStandardInput);
            };
            if stack_top_sigops(redeem_script) > MAX_P2SH_SIGOPS {
                return Err(StandardnessError::NonStandardInput);
            }
        } else if !is_standard_prevout_script(script) {
            return Err(StandardnessError::NonStandardInput);
        }
    }
    Ok(())
}

fn legacy_sigops(tx: &Tx, prevouts: &HashMap<OutPoint, &TxOut>) -> u32 {
    let mut sigops = 0_u32;
    for input in &tx.inputs {
        let script_sig = input.script_sig.as_bytes();
        sigops = sigops.saturating_add(count_accurate(script_sig));
        if let Some(prevout) = prevouts.get(&input.previous_output) {
            let script = prevout.script_pubkey.as_bytes();
            sigops = sigops.saturating_add(if is_p2sh(script) {
                push_only_stack_top(script_sig).map_or(0, stack_top_sigops)
            } else {
                count_accurate(script)
            });
        }
        if sigops > MAX_TX_LEGACY_SIGOPS {
            return sigops;
        }
    }
    sigops
}

fn is_standard_prevout_script(script: &[u8]) -> bool {
    if is_p2pkh(script) || is_p2sh(script) || is_p2pk(script) || is_p2a(script) {
        return true;
    }
    if is_op_return(script) {
        return is_push_only(&script[1..]);
    }
    if multisig_key_count(script).is_some() {
        return true;
    }
    match witness_program(script) {
        Some((0, program)) => {
            matches!(
                program.len(),
                WITNESS_V0_KEYHASH_SIZE | WITNESS_V0_SCRIPTHASH_SIZE
            )
        }
        Some((1, program)) => program.len() == WITNESS_V1_TAPROOT_SIZE,
        Some(_) | None => false,
    }
}

#[derive(Clone, Copy)]
enum StackTop<'a> {
    Data(&'a [u8]),
    SmallInt,
}

fn stack_top_sigops(top: StackTop<'_>) -> u32 {
    match top {
        StackTop::Data(script) => count_accurate(script),
        StackTop::SmallInt => 0,
    }
}

fn push_only_stack_top(script: &[u8]) -> Option<StackTop<'_>> {
    let mut top = None;
    for instruction in instructions(script) {
        top = match instruction.ok()? {
            Instruction::PushBytes(bytes) => Some(StackTop::Data(bytes)),
            Instruction::Op(operand)
                if operand == opcode::OP_1NEGATE
                    || (opcode::OP_PUSHNUM_1..=opcode::OP_PUSHNUM_16).contains(&operand) =>
            {
                Some(StackTop::SmallInt)
            }
            Instruction::Op(_) => return None,
        };
    }
    top
}

fn check_witness_standardness(
    tx: &Tx,
    prevouts: &HashMap<OutPoint, &TxOut>,
) -> Result<(), StandardnessError> {
    for input in &tx.inputs {
        let witness = &input.witness;
        if witness.is_empty() {
            continue;
        }
        let Some(prevout) = prevouts.get(&input.previous_output) else {
            return Err(StandardnessError::NonStandardWitness);
        };
        let script = prevout.script_pubkey.as_bytes();
        if is_p2a(script) {
            return Err(StandardnessError::NonStandardWitness);
        }
        let wrapped = is_p2sh(script);
        let (version, program) = if wrapped {
            let Some(top) = push_only_stack_top(&input.script_sig) else {
                return Err(StandardnessError::NonStandardWitness);
            };
            let StackTop::Data(redeem_script) = top else {
                return Err(StandardnessError::NonStandardWitness);
            };
            let Some(program) = witness_program(redeem_script) else {
                return Err(StandardnessError::NonStandardWitness);
            };
            program
        } else {
            let Some(program) = witness_program(script) else {
                return Err(StandardnessError::NonStandardWitness);
            };
            program
        };
        if version == 0 && program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            check_p2wsh_witness(witness)?;
        }
        if version == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !wrapped {
            check_taproot_witness(witness)?;
        }
    }
    Ok(())
}

fn check_p2wsh_witness(witness: &Witness) -> Result<(), StandardnessError> {
    let Some(witness_script) = witness.last() else {
        return Err(StandardnessError::NonStandardWitness);
    };
    if witness_script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
        return Err(StandardnessError::NonStandardWitness);
    }
    let stack_items = witness.len() - 1;
    if stack_items > MAX_STANDARD_P2WSH_STACK_ITEMS {
        return Err(StandardnessError::NonStandardWitness);
    }
    if witness
        .iter()
        .take(stack_items)
        .any(|item| item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
    {
        return Err(StandardnessError::NonStandardWitness);
    }
    Ok(())
}

fn check_taproot_witness(witness: &Witness) -> Result<(), StandardnessError> {
    match witness.len() {
        0 => Err(StandardnessError::NonStandardWitness),
        1 => Ok(()),
        count => {
            let annex = witness
                .last()
                .ok_or(StandardnessError::NonStandardWitness)?;
            if !annex.is_empty() && annex[0] == ANNEX_TAG {
                return Err(StandardnessError::NonStandardWitness);
            }
            let control_block = witness
                .get(count - 1)
                .ok_or(StandardnessError::NonStandardWitness)?;
            if control_block.is_empty() {
                return Err(StandardnessError::NonStandardWitness);
            }
            if control_block[0] & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT
                && witness
                    .iter()
                    .take(count - 2)
                    .any(|item| item.len() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE)
            {
                return Err(StandardnessError::NonStandardWitness);
            }
            Ok(())
        }
    }
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
mod tests {
    use super::*;

    #[test]
    fn maximum_fee_uses_core_amount_rounding_including_one_satoshi_boundaries() {
        for (fee, vsize, rate, rejects) in [
            (2_000, 2_000, 1_000, false),
            (2_001, 2_000, 1_000, true),
            (u64::MAX, 1_000, u64::MAX - 1, true),
            (1, 999, 1, false),
            (2, 999, 1, true),
            (10_000, 200, 0, false),
            (1, 0, 1_000, false),
            (2_100_000_000_000_000, u32::MAX, u64::MAX, false),
        ] {
            assert_eq!(exceeds_max_feerate(fee, vsize, Some(rate)), rejects);
        }
    }
    use bitcoin_rs_consensus::primitives::{OutPoint, Tx, TxIn, TxOut};
    use bitcoin_rs_consensus::script::{is_multisig, minimal_non_dust, opcode, push_data};

    const DUST_RELAY_FEE_SAT_PER_KVB: u64 = 3_000;
    const BROADCAST_MIN_FEE_SAT_PER_KVB: u64 = 1_000;

    fn p2pkh(hash20: &[u8; 20]) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.push(opcode::OP_DUP);
        out.push(opcode::OP_HASH160);
        out.push(0x14);
        out.extend_from_slice(hash20);
        out.push(opcode::OP_EQUALVERIFY);
        out.push(opcode::OP_CHECKSIG);
        out
    }

    fn standard_tx(version: u32) -> Tx {
        Tx {
            version,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: p2pkh(&[7_u8; 20]).into(),
            }],
        }
    }

    fn policy() -> StandardnessPolicy {
        StandardnessPolicy {
            dust_relay_fee: DUST_RELAY_FEE_SAT_PER_KVB,
            max_datacarrier_bytes: Some(83),
        }
    }

    #[test]
    fn only_versions_one_through_three_are_standard() {
        for (version, expected) in [
            (0_u32, Err(StandardnessError::Version)),
            (1, Ok(())),
            (2, Ok(())),
            (3, Ok(())),
            (4, Err(StandardnessError::Version)),
        ] {
            assert_eq!(
                is_standard_tx(&standard_tx(version), &policy()),
                expected,
                "version {version}"
            );
        }
    }

    #[test]
    fn accepts_op_return_followed_by_a_numeric_push() {
        for op in [opcode::OP_PUSHNUM_1, opcode::OP_RESERVED] {
            let mut tx = standard_tx(1);
            tx.outputs[0].value = Amount::ZERO;
            tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN, op].into();
            tx.outputs.push(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: p2pkh(&[9_u8; 20]).into(),
            });
            assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
        }
    }

    #[test]
    fn rejects_op_return_followed_by_an_opcode() {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = Amount::ZERO;
        tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN, opcode::OP_DUP].into();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    #[test]
    fn rejects_bare_multisig_whose_key_is_not_a_pubkey() {
        let mut script = vec![opcode::OP_PUSHNUM_1];
        script.extend(push_data(&[0_u8; 4]));
        script.extend([opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG]);
        assert!(
            is_multisig(&script),
            "the shape check must accept this, or the length check is never reached"
        );

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script.into();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    #[test]
    fn accepts_a_well_formed_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut script = vec![opcode::OP_PUSHNUM_1];
        script.extend(push_data(&key));
        script.extend([opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG]);

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script.into();
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn accepts_three_of_three_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut script = vec![opcode::OP_PUSHNUM_1 + 2];
        for _ in 0..3 {
            script.extend(push_data(&key));
        }
        script.extend([opcode::OP_PUSHNUM_1 + 2, opcode::OP_CHECKMULTISIG]);

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script.into();
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_one_of_four_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut script = vec![opcode::OP_PUSHNUM_1];
        for _ in 0..4 {
            script.extend(push_data(&key));
        }
        script.extend([opcode::OP_PUSHNUM_1 + 3, opcode::OP_CHECKMULTISIG]);

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script.into();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    #[test]
    fn accepts_a_pay_to_anchor_output() {
        let mut tx = standard_tx(1);
        tx.outputs.push(TxOut {
            value: Amount::from_sat(240),
            script_pubkey: vec![0x51, 0x02, 0x4e, 0x73].into(),
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_a_transaction_below_the_non_witness_minimum() {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = Amount::ZERO;
        tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN].into();
        assert!(
            tx.base_size() < super::MIN_NON_WITNESS_TX_SIZE,
            "the fixture must be undersized or this test proves nothing"
        );
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::TransactionTooSmall)
        );
    }

    #[test]
    fn rejects_non_pushonly_scriptsig() {
        let mut tx = standard_tx(1);
        tx.inputs[0].script_sig = vec![opcode::OP_DUP].into();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::ScriptSigNotPushOnly)
        );
    }

    #[test]
    fn rejects_oversized_scriptsig() {
        let mut tx = standard_tx(1);
        let big = vec![0_u8; super::MAX_STANDARD_SCRIPTSIG_SIZE];
        tx.inputs[0].script_sig = push_data(&big).into();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::ScriptSigTooLarge)
        );
    }

    #[test]
    fn accepts_two_nulldata_outputs_within_the_aggregate_limit() {
        let mut tx = standard_tx(1);
        let first = [vec![opcode::OP_RETURN], push_data(b"first")].concat();
        let second = [vec![opcode::OP_RETURN], push_data(b"second")].concat();
        let limit = [&first, &second]
            .into_iter()
            .fold(0_usize, |total, script| {
                total
                    + bitcoin_rs_consensus::primitives::varint::encoded_len(
                        u64::try_from(script.len()).unwrap_or(u64::MAX),
                    )
                    + script.len()
            });
        tx.outputs = vec![
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: first.into(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: second.into(),
            },
        ];
        let aggregate = StandardnessPolicy {
            max_datacarrier_bytes: Some(limit),
            ..policy()
        };

        assert_eq!(is_standard_tx(&tx, &aggregate), Ok(()));
        let over = StandardnessPolicy {
            max_datacarrier_bytes: Some(limit - 1),
            ..aggregate
        };
        assert_eq!(
            is_standard_tx(&tx, &over),
            Err(StandardnessError::DataCarrierBytesExceeded)
        );
        let disabled = StandardnessPolicy {
            max_datacarrier_bytes: None,
            ..aggregate
        };
        assert_eq!(
            is_standard_tx(&tx, &disabled),
            Err(StandardnessError::DataCarrierDisabled)
        );
    }

    #[test]
    fn dust_relay_fee_changes_the_boundary() {
        let mut tx = standard_tx(1);
        let threshold = minimal_non_dust(&tx.outputs[0].script_pubkey, DUST_RELAY_FEE_SAT_PER_KVB);
        tx.outputs[0].value = Amount::from_sat(threshold - 1);

        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
        let lower_fee = StandardnessPolicy {
            dust_relay_fee: BROADCAST_MIN_FEE_SAT_PER_KVB,
            ..policy()
        };
        assert_eq!(is_standard_tx(&tx, &lower_fee), Ok(()));
        assert!(tx_has_dust_outputs(&tx, DUST_RELAY_FEE_SAT_PER_KVB));
        assert!(!tx_has_dust_outputs(&tx, BROADCAST_MIN_FEE_SAT_PER_KVB));
    }

    #[test]
    fn accepts_single_op_return_within_limit() {
        let mut tx = standard_tx(1);
        let script = [vec![opcode::OP_RETURN], push_data(b"ok")].concat();
        tx.outputs.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: script.into(),
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn only_one_ephemeral_dust_output_is_standard() {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = Amount::from_sat(1);
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
        tx.outputs.push(tx.outputs[0].clone());
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::DustOutput)
        );
    }

    #[test]
    fn rejects_non_standard_output_script() {
        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = vec![0x74].into();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    #[test]
    fn signed_delta_clamp_prevents_maxfeerate_rejection_and_retains_effective_rate()
    -> Result<(), crate::test_error::TestError> {
        let mut pool = Mempool::new(crate::MempoolLimits::default());
        let tx = standard_tx(2);
        let prevouts = [(
            tx.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: p2pkh(&[7_u8; 20]).into(),
            },
        )];
        let txid = tx.txid();

        pool.prioritise(txid, -3_000)?;
        assert_eq!(pool.modified_fee_for(txid, 1_000)?, -2_000);

        let context = PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: false,
        };

        let fact = evaluate_one(
            &pool,
            &policy(),
            &tx,
            &prevouts,
            context,
            Some(10_000),
            None,
            &Bip68Admission::default(),
        );

        assert_ne!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::MaxFeeExceeded)
        );
        assert_eq!(fact.modified_fee, Some(-2_000));
        assert_eq!(fact.effective_fee_rate, Some(0));
        Ok(())
    }

    #[test]
    fn three_vsize_meanings_on_sigop_heavy_tx() -> Result<(), crate::test_error::TestError> {
        use crate::accounting::prepared_context;
        use crate::entry::MempoolEntry;
        use alloc::sync::Arc;

        let mut tx = standard_tx(2);
        let sigop_script = Script::from_bytes(vec![opcode::OP_CHECKSIG; 50]);
        tx.outputs.push(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: sigop_script,
        });

        let prevout = (
            tx.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: p2pkh(&[7_u8; 20]).into(),
            },
        );

        let context = prepared_context(&tx, &[prevout], false);
        assert_eq!(context.sigop_cost, 204);

        let unadjusted_weight = tx.weight();
        let vsize_bip141 = u32::try_from(tx.vsize())?;
        assert_eq!(
            vsize_bip141,
            u32::try_from(Tx::vsize_from_weight(unadjusted_weight))?
        );

        let vsize_adjusted = context.vsize;
        assert_eq!(vsize_adjusted, 1_020);
        assert!(vsize_adjusted > vsize_bip141);

        let entry = MempoolEntry::new(
            Arc::new(tx.clone()),
            vsize_adjusted,
            context.fee,
            1,
            1,
            context.sigop_cost,
        );

        assert_eq!(entry.vsize, vsize_adjusted);
        assert_eq!(entry.vsize, 1_020);
        assert_eq!(entry.bip141_vsize, vsize_bip141);
        assert_eq!(entry.bip141_vsize, u32::try_from(tx.vsize())?);
        assert_eq!(entry.weight, unadjusted_weight);
        Ok(())
    }

    fn oversize_script_sig_tx(script_bytes: usize) -> Tx {
        let mut tx = standard_tx(2);
        tx.inputs[0].script_sig = Script::from_bytes(vec![0x01; script_bytes]);
        tx
    }

    // POL-03
    #[test]
    fn unfunded_over_block_weight_tx_answers_bad_txns_oversize() {
        let pool = Mempool::new(crate::MempoolLimits::default());
        let tx = oversize_script_sig_tx(1_100_000);
        let context = PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: true,
        };
        let fact = evaluate_one(
            &pool,
            &policy(),
            &tx,
            &[],
            context,
            None,
            None,
            &Bip68Admission::default(),
        );
        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::NonStandard(
                StandardnessError::Oversize
            )),
            "Core CheckTransaction answers bad-txns-oversize before the missing-inputs scan"
        );
    }

    // POL-03
    #[test]
    fn unfunded_over_standard_weight_tx_answers_tx_size_before_missing_inputs() {
        let pool = Mempool::new(crate::MempoolLimits::default());
        let tx = oversize_script_sig_tx(120_000);
        let context = PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: true,
        };
        let fact = evaluate_one(
            &pool,
            &policy(),
            &tx,
            &[],
            context,
            None,
            None,
            &Bip68Admission::default(),
        );
        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::NonStandard(
                StandardnessError::Weight
            )),
            "Core IsStandardTx answers tx-size before bad-txns-inputs-missingorspent"
        );
    }

    // POL-03
    #[test]
    fn unfunded_dust_tx_answers_missing_inputs_before_ephemeral_dust() {
        let pool = Mempool::new(crate::MempoolLimits::default());
        let mut tx = standard_tx(1);
        tx.inputs[0].previous_output = OutPoint::new(
            bitcoin_rs_consensus::primitives::Txid(
                bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[9; 32]),
            ),
            0,
        );
        tx.outputs[0].value = Amount::from_sat(1);
        let context = PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: true,
        };
        let fact = evaluate_one(
            &pool,
            &policy(),
            &tx,
            &[],
            context,
            None,
            None,
            &Bip68Admission::default(),
        );
        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::MissingInputs),
            "Core PreChecks answers bad-txns-inputs-missingorspent before PreCheckEphemeralTx"
        );
        let resolved = PackageTxContext {
            missing_inputs: false,
            ..context
        };
        let fact = evaluate_one(
            &pool,
            &policy(),
            &tx,
            &[],
            resolved,
            None,
            None,
            &Bip68Admission::default(),
        );
        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::NonStandard(
                StandardnessError::DustOutput
            )),
            "PreCheckEphemeralTx refuses a nonzero-fee dust transaction once its inputs resolve"
        );
    }

    // POL-03
    #[test]
    fn coinbase_transaction_answers_core_coinbase_reason() {
        let pool = Mempool::new(crate::MempoolLimits::default());
        let mut tx = standard_tx(1);
        tx.inputs[0].previous_output = OutPoint::null();
        let context = PackageTxContext {
            fee: 0,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: true,
        };
        let fact = evaluate_one(
            &pool,
            &policy(),
            &tx,
            &[],
            context,
            None,
            None,
            &Bip68Admission::default(),
        );
        assert_eq!(
            fact.reject_reason,
            Some(AcceptanceRejectReason::Coinbase),
            "Core PreChecks refuses a loose coinbase with reason coinbase"
        );
        assert_eq!(AcceptanceRejectReason::Coinbase.to_string(), "coinbase");
    }
}
