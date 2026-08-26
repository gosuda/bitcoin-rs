//! Bitcoin Core `IsStandardTx` / `IsStandard` policy checks.
//!
//! These are mempool/relay policy checks, not consensus rules. A transaction
//! that fails these checks may still be valid; it simply will not be accepted
//! to the mempool or relayed by default.

use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin::blockdata::script::Instruction;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16, OP_PUSHNUM_NEG1};
use bitcoin::{FeeRate, Script, Transaction, TxOut, Txid, VarInt, Wtxid};
use thiserror::Error;

use crate::{Mempool, RbfError, ReplacementCandidate};

/// Maximum weight of a standard transaction (400 000 weight units).
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Maximum length of a standard `scriptSig` in bytes.
const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

/// Standard relay policy values that are configurable by the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardnessPolicy {
    /// Fee rate used to classify outputs as dust.
    pub dust_relay_fee: FeeRate,
    /// Maximum aggregate serialized nulldata script bytes, or `None` to disable nulldata.
    pub max_datacarrier_bytes: Option<usize>,
}

/// Minimum transaction version considered standard.
const TX_VERSION_MIN: i32 = 1;

/// Maximum transaction version considered standard.
///
/// Current Bitcoin Core accepts version 3 at the `IsStandardTx` gate and
/// enforces TRUC's extra restrictions — the ancestor and descendant limits,
/// the sibling rules, the size cap — at the transaction and package policy
/// layers.
///
/// This node has no such layer. Accepting v3 here would copy the permissive
/// half of Core's design without the half that constrains it, so whoever wires
/// this gate to mempool admission would be relaying v3 transactions Core
/// rejects. Raise this to 3 in the same change that adds TRUC policy, not
/// before.
const TX_VERSION_MAX: i32 = 2;

/// Standardness policy rejection reason for a single transaction.
///
/// Each variant corresponds to a distinct `IsStandardTx` / `IsStandard`
/// failure in Bitcoin Core's mempool policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StandardnessError {
    /// Transaction version is outside the standard range (1 or 2).
    #[error("non-standard transaction version")]
    Version,
    /// Transaction weight exceeds `MAX_STANDARD_TX_WEIGHT` (400 000).
    #[error("transaction weight exceeds maximum standard weight")]
    Weight,
    /// A `scriptSig` contains non-push opcodes.
    #[error("scriptSig is not push-only")]
    ScriptSigNotPushOnly,
    /// A `scriptSig` exceeds 1650 bytes.
    #[error("scriptSig exceeds maximum standard size")]
    ScriptSigTooLarge,
    /// An output script is not a recognized standard type.
    #[error("non-standard output script")]
    NonStandardOutput,
    /// Nulldata outputs are disabled by policy.
    #[error("nulldata outputs are disabled")]
    DataCarrierDisabled,
    /// Aggregate serialized nulldata script bytes exceed the policy limit.
    #[error("aggregate nulldata script bytes exceed the policy limit")]
    DataCarrierBytesExceeded,
    /// Aggregate serialized nulldata script length overflowed.
    #[error("aggregate nulldata script length overflowed")]
    DataCarrierSizeOverflow,
    /// Non-witness serialization is below the relay minimum.
    #[error("transaction non-witness size is below the relay minimum")]
    TransactionTooSmall,
    /// A non-`OP_RETURN` output value is below the dust threshold.
    #[error("dust output")]
    DustOutput,
}

/// Checks whether a transaction satisfies Bitcoin Core's standardness policy.
///
/// This mirrors `IsStandardTx` in Bitcoin Core's `policy/policy.cpp`:
/// version, weight, `scriptSig` push-only/size, output script type,
/// aggregate nulldata script bytes, and dust.
///
/// Returns `Ok(())` if the transaction is standard, or the first
/// `StandardnessError` encountered.
pub fn is_standard_tx(
    tx: &Transaction,
    policy: &StandardnessPolicy,
) -> Result<(), StandardnessError> {
    check_version(tx)?;
    check_weight(tx)?;
    check_script_sigs(tx)?;
    check_outputs(tx, policy)?;
    // Last, matching Core: `IsStandardTx` runs first and `PreChecks` applies
    // `tx-size-small` after it, so a transaction that is both undersized and
    // carries a non-standard output reports the output.
    check_min_size(tx)?;
    Ok(())
}

/// Bitcoin Core `MAX_PACKAGE_COUNT` for package acceptance / `testmempoolaccept`.
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Caller-resolved fee and prevout context for one package transaction.
///
/// Prevout lookup and fee accounting live outside this module. The acceptance
/// seam records the already-computed prevout-aware `sigop_cost` so RPC and
/// admission can project it without recomputing script costs here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTxContext {
    /// Actual fee in satoshis.
    pub fee: u64,
    /// Policy virtual size in vbytes.
    pub vsize: u32,
    /// Prevout-aware sigop cost.
    pub sigop_cost: u32,
    /// At least one input is neither confirmed nor satisfied by the mempool /
    /// earlier package transactions.
    pub missing_inputs: bool,
}

/// Per-transaction package acceptance fact for RPC / admission consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxAcceptanceFact {
    /// Transaction id.
    pub txid: Txid,
    /// Witness transaction id.
    pub wtxid: Wtxid,
    /// Whether the transaction was accepted or rejected. `None` means package
    /// evaluation stopped before this row was validated.
    pub allowed: Option<bool>,
    /// Policy virtual size in vbytes.
    pub vsize: u32,
    /// Consensus weight.
    pub weight: u64,
    /// Prevout-aware sigop cost supplied by the caller.
    pub sigop_cost: u32,
    /// Base fee when acceptance accounting succeeded far enough to know it.
    pub base_fee: Option<u64>,
    /// Rejection reason when `allowed` is false.
    pub reject_reason: Option<AcceptanceRejectReason>,
}

/// Package-level acceptance facts: optional package error plus per-tx rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAcceptanceFacts {
    /// Package-wide failure (for example package count bounds).
    pub package_error: Option<AcceptanceRejectReason>,
    /// One row per submitted transaction, in input order.
    pub results: Vec<TxAcceptanceFact>,
}

/// Policy rejection reason for dry-run package acceptance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceRejectReason {
    /// Package length is outside `1..=MAX_PACKAGE_COUNT`.
    #[error("package-too-large")]
    PackageTooLarge,
    /// Transaction is already present in the mempool.
    #[error("txn-already-in-mempool")]
    AlreadyInMempool,
    /// One or more inputs are unavailable.
    #[error("missing-inputs")]
    MissingInputs,
    /// Fee rate is below the live min-relay / mempool-min floor.
    #[error("min relay fee not met")]
    MinRelayFeeNotMet,
    /// Fee rate exceeds the caller-supplied maximum.
    #[error("max-fee-exceeded")]
    MaxFeeExceeded,
    /// Transaction fails standardness policy.
    #[error(transparent)]
    NonStandard(#[from] StandardnessError),
    /// Conflicting replacement fails BIP125.
    #[error(transparent)]
    Replacement(#[from] RbfError),
    /// Next-block BIP68 relative sequence locks are unmet.
    #[error("non-BIP68-final")]
    NonBip68Final,
    /// Consensus script verification failed.
    #[error("script-verify-flag-failed")]
    ScriptVerify,
}

/// Evaluates non-mutating package acceptance policy facts.
///
/// This is the mempool-owned seam behind `testmempoolaccept`: it composes
/// standardness, presence, missing-input, min-relay / max-fee, and BIP125
/// replacement checks against the live pool without inserting anything.
/// Consensus script verification remains outside this module.
///
/// `contexts` must have the same length as `txs`. `incremental_relay_fee_sat_per_kvb`
/// feeds the size-pressure mempool-min floor and BIP125 rule 4.
#[must_use]
pub fn evaluate_package_acceptance(
    pool: &Mempool,
    policy: &StandardnessPolicy,
    txs: &[Transaction],
    contexts: &[PackageTxContext],
    max_feerate_sat_per_kvb: Option<u64>,
    incremental_relay_fee_sat_per_kvb: u64,
) -> PackageAcceptanceFacts {
    assert_eq!(
        txs.len(),
        contexts.len(),
        "package txs and contexts must align"
    );

    if txs.is_empty() || txs.len() > MAX_PACKAGE_COUNT {
        return PackageAcceptanceFacts {
            package_error: Some(AcceptanceRejectReason::PackageTooLarge),
            results: Vec::new(),
        };
    }

    let mempool_min_fee =
        crate::eviction::mempool_min_fee_sat_per_kvb(pool, incremental_relay_fee_sat_per_kvb);

    let mut results = Vec::with_capacity(txs.len());
    let mut package_failed = false;

    for (tx, context) in txs.iter().zip(contexts.iter()) {
        if package_failed {
            results.push(TxAcceptanceFact {
                txid: tx.compute_txid(),
                wtxid: tx.compute_wtxid(),
                allowed: None,
                vsize: context.vsize,
                weight: tx.weight().to_wu(),
                sigop_cost: context.sigop_cost,
                base_fee: None,
                reject_reason: None,
            });
            continue;
        }

        let fact = evaluate_one(
            pool,
            policy,
            tx,
            *context,
            max_feerate_sat_per_kvb,
            mempool_min_fee,
            incremental_relay_fee_sat_per_kvb,
        );
        if fact.allowed == Some(false) {
            package_failed = true;
        }
        results.push(fact);
    }

    PackageAcceptanceFacts {
        package_error: None,
        results,
    }
}

fn evaluate_one(
    pool: &Mempool,
    policy: &StandardnessPolicy,
    tx: &Transaction,
    context: PackageTxContext,
    max_feerate_sat_per_kvb: Option<u64>,
    mempool_min_fee_sat_per_kvb: u64,
    incremental_relay_fee_sat_per_kvb: u64,
) -> TxAcceptanceFact {
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    let weight = tx.weight().to_wu();
    let vsize = context.vsize;
    let fee_rate = if vsize == 0 {
        0
    } else {
        context.fee.saturating_mul(1_000) / u64::from(vsize)
    };

    let reject = if pool.contains_txid(&txid) {
        Some(AcceptanceRejectReason::AlreadyInMempool)
    } else if context.missing_inputs {
        Some(AcceptanceRejectReason::MissingInputs)
    } else if let Err(err) = is_standard_tx(tx, policy) {
        Some(AcceptanceRejectReason::NonStandard(err))
    } else if fee_rate < mempool_min_fee_sat_per_kvb {
        Some(AcceptanceRejectReason::MinRelayFeeNotMet)
    } else if max_feerate_sat_per_kvb.is_some_and(|max| fee_rate > max) {
        Some(AcceptanceRejectReason::MaxFeeExceeded)
    } else if !pool.conflicts_for(tx).is_empty() {
        let candidate = ReplacementCandidate::new(
            Arc::new(tx.clone()),
            vsize,
            context.fee,
            incremental_relay_fee_sat_per_kvb,
        );
        match pool.check_replacement(&candidate) {
            Ok(_) => None,
            Err(err) => Some(AcceptanceRejectReason::Replacement(err)),
        }
    } else {
        None
    };

    TxAcceptanceFact {
        txid,
        wtxid,
        allowed: Some(reject.is_none()),
        vsize,
        weight,
        sigop_cost: context.sigop_cost,
        base_fee: Some(context.fee),
        reject_reason: reject,
    }
}

/// Minimum non-witness serialization Core relays, `tx-size-small`.
///
/// The bound is on the stripped size. A one-input `SegWit` spend with an empty
/// scriptSig and a minimal `OP_RETURN` output serializes to 61 bytes without
/// its witness while carrying its authorization inside one, so a weight check
/// alone lets it through.
const MIN_NON_WITNESS_TX_SIZE: usize = 65;

fn check_min_size(tx: &Transaction) -> Result<(), StandardnessError> {
    if tx.base_size() < MIN_NON_WITNESS_TX_SIZE {
        return Err(StandardnessError::TransactionTooSmall);
    }
    Ok(())
}

fn check_version(tx: &Transaction) -> Result<(), StandardnessError> {
    let v = tx.version.0;
    if (TX_VERSION_MIN..=TX_VERSION_MAX).contains(&v) {
        Ok(())
    } else {
        Err(StandardnessError::Version)
    }
}

fn check_weight(tx: &Transaction) -> Result<(), StandardnessError> {
    if tx.weight().to_wu() > MAX_STANDARD_TX_WEIGHT {
        Err(StandardnessError::Weight)
    } else {
        Ok(())
    }
}

fn check_script_sigs(tx: &Transaction) -> Result<(), StandardnessError> {
    for input in &tx.input {
        let script_sig = &input.script_sig;
        if !script_sig.is_push_only() {
            return Err(StandardnessError::ScriptSigNotPushOnly);
        }
        if script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(StandardnessError::ScriptSigTooLarge);
        }
    }
    Ok(())
}

fn check_outputs(tx: &Transaction, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
    let mut datacarrier_bytes = 0_usize;
    for output in &tx.output {
        let script = &output.script_pubkey;
        if script.is_op_return() {
            if !is_standard_nulldata(script) {
                return Err(StandardnessError::NonStandardOutput);
            }
            let Some(limit) = policy.max_datacarrier_bytes else {
                return Err(StandardnessError::DataCarrierDisabled);
            };
            let serialized_script_bytes = VarInt::from(script.len())
                .size()
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
        if is_dust(output, policy.dust_relay_fee) {
            return Err(StandardnessError::DustOutput);
        }
    }
    Ok(())
}

/// Returns `true` if `script` is one of the standard output script types.
///
/// Standard types: P2PKH, P2SH, P2PK, P2WPKH, P2WSH, P2TR, bare multisig
/// (up to 3 keys), and `OP_RETURN` (checked separately by the caller).
fn is_standard_output_script(script: &Script) -> bool {
    script.is_p2pkh()
        || script.is_p2sh()
        || script.is_p2pk()
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || script.is_p2tr()
        || is_p2a(script)
        || is_standard_multisig(script)
}

/// Returns `true` for the pay-to-anchor output template.
///
/// `OP_1` followed by a two-byte push of `0x4e73`. Core treats this distinct
/// short witness program as standard under TRUC and ephemeral-anchor policy,
/// and none of the predicates above match it: `is_p2tr` wants a 32-byte
/// version-1 program. Its dust and package restrictions live at the policy
/// layer that owns them, not here.
fn is_p2a(script: &Script) -> bool {
    script.as_bytes() == [0x51, 0x02, 0x4e, 0x73]
}

/// Returns `true` if `script` is a bare multisig with at most 3 pubkeys.
///
/// Bitcoin Core's `IsStandard` allows bare multisig with up to 3 keys.
fn is_standard_multisig(script: &Script) -> bool {
    if !script.is_multisig() {
        return false;
    }
    multisig_key_count(script).is_some_and(|n| n <= 3)
}

/// Counts the pubkeys in a bare multisig script, or `None` if any push in it
/// is not a serialized pubkey.
///
/// Deliberately narrow. `Script::is_multisig` was measured against this exact
/// surface and it already rejects a declared count that disagrees with the keys
/// present, an `m` greater than `n`, and a script with no keys at all. The one
/// thing it does not check is the length of each push, so
/// `OP_1 <4 bytes> OP_1 OP_CHECKMULTISIG` passes it. That is the gap, and this
/// closes exactly that; duplicating the rest would be checks that can never
/// fire.
fn multisig_key_count(script: &Script) -> Option<u8> {
    let mut count: u8 = 0;
    for inst in script.instructions() {
        match inst {
            // 33 bytes compressed, 65 uncompressed. Anything else is not a key.
            Ok(Instruction::PushBytes(bytes)) => {
                if bytes.len() != 33 && bytes.len() != 65 {
                    return None;
                }
                count = count.checked_add(1)?;
            }
            Ok(Instruction::Op(_)) => {}
            Err(_) => return None,
        }
    }
    Some(count)
}

/// Returns `true` if a non-`OP_RETURN` output is dust.
fn is_dust(output: &TxOut, dust_relay_fee: FeeRate) -> bool {
    output.value.to_sat()
        < output
            .script_pubkey
            .minimal_non_dust_custom(dust_relay_fee)
            .to_sat()
}

/// Extracts the payload length from an `OP_RETURN` script.
///
/// An `OP_RETURN` script is `OP_RETURN` followed by zero or more push
/// operations. The payload length is the total number of bytes pushed.
/// Returns `None` if the script is not `OP_RETURN`.
/// Returns `true` if everything after the leading `OP_RETURN` is a data push.
///
/// Standard nulldata is `OP_RETURN` followed by pushes and nothing else. A
/// script that merely starts with `OP_RETURN` and then carries an opcode, or
/// that fails to parse partway, is not standard — and the old code accepted
/// both, because it ignored opcodes and treated a parse error as the end of
/// the payload.
fn is_standard_nulldata(script: &Script) -> bool {
    let mut instructions = script.instructions();
    // The leading OP_RETURN itself, already established by `is_op_return`.
    if instructions.next().is_none() {
        return false;
    }
    instructions.all(|inst| match inst {
        Ok(Instruction::PushBytes(_)) => true,
        // `OP_1` through `OP_16` and `OP_1NEGATE` are pushes too, and
        // rust-bitcoin reports them as `Op` rather than `PushBytes`. Core's
        // push-only nulldata rule accepts every push opcode, so rejecting
        // `OP_RETURN OP_1` would call a standard output non-standard.
        Ok(Instruction::Op(op)) => {
            op == OP_PUSHNUM_NEG1
                || (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&op.to_u8())
        }
        Err(_) => false,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_3, OP_PUSHNUM_4};
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, PubkeyHash, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn standard_tx(version: Version) -> Transaction {
        Transaction {
            version,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([7_u8; 20])),
            }],
        }
    }

    fn policy() -> StandardnessPolicy {
        StandardnessPolicy {
            dust_relay_fee: FeeRate::DUST,
            max_datacarrier_bytes: Some(83),
        }
    }

    #[test]
    fn accepts_standard_version_one() {
        let tx = standard_tx(Version::ONE);
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn accepts_standard_version_two() {
        let tx = standard_tx(Version::TWO);
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_version_zero() {
        let tx = standard_tx(Version(0));
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::Version)
        );
    }

    /// Rejected until a TRUC policy layer exists to carry its restrictions.
    /// Core accepts v3 here and constrains it elsewhere; this node has only
    /// the "here".
    #[test]
    fn rejects_version_three_while_truc_policy_is_absent() {
        let tx = standard_tx(Version(3));
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::Version)
        );
    }

    #[test]
    fn rejects_version_four() {
        let tx = standard_tx(Version(4));
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::Version)
        );
    }

    /// Numeric push opcodes are pushes, and standard nulldata accepts them.
    ///
    /// rust-bitcoin reports `OP_1` through `OP_16` as `Op` rather than
    /// `PushBytes`, so a naive push-only check calls `OP_RETURN OP_1`
    /// non-standard when Core relays it.
    #[test]
    fn accepts_op_return_followed_by_a_numeric_push() {
        let mut tx = standard_tx(Version::ONE);
        tx.output[0].value = Amount::ZERO;
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_opcode(OP_PUSHNUM_1)
            .into_script();
        // Padded to clear the relay minimum, which is a different rule.
        tx.output.push(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([9_u8; 20])),
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    /// `OP_RETURN` followed by a non-push opcode is not standard nulldata.
    #[test]
    fn rejects_op_return_followed_by_an_opcode() {
        let mut tx = standard_tx(Version::ONE);
        tx.output[0].value = Amount::ZERO;
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .into_script();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// A push that is not a pubkey length still passes `Script::is_multisig`.
    ///
    /// That predicate was measured against this surface: it already rejects a
    /// declared count that disagrees with the keys present, an `m` greater than
    /// `n`, and a keyless script. Push length is the one thing it does not
    /// check, so it is the only thing worth checking here.
    #[test]
    fn rejects_bare_multisig_whose_key_is_not_a_pubkey() {
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice([0_u8; 4])
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert!(
            script.is_multisig(),
            "the shape check must accept this, or the length check is never reached"
        );

        let mut tx = standard_tx(Version::ONE);
        tx.output[0].script_pubkey = script;
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// The same shape, honestly declared, stays standard.
    #[test]
    fn accepts_a_well_formed_bare_multisig() {
        let key = [0x02_u8; 33];
        let Ok(pushable) = <&bitcoin::script::PushBytes>::try_from(key.as_slice()) else {
            panic!("33 bytes must be pushable");
        };
        let mut tx = standard_tx(Version::ONE);
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(pushable)
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn accepts_three_of_three_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut tx = standard_tx(Version::ONE);
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(OP_PUSHNUM_3)
            .push_slice(key)
            .push_slice(key)
            .push_slice(key)
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_one_of_four_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut tx = standard_tx(Version::ONE);
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(key)
            .push_slice(key)
            .push_slice(key)
            .push_slice(key)
            .push_opcode(OP_PUSHNUM_4)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// The pay-to-anchor template, `OP_1` plus a two-byte push of 0x4e73.
    ///
    /// Carries a second, ordinary output: a lone 4-byte anchor script makes the
    /// transaction smaller than the relay minimum, and this test is about the
    /// script being recognised, not about that.
    #[test]
    fn accepts_a_pay_to_anchor_output() {
        let mut tx = standard_tx(Version::ONE);
        tx.output.push(TxOut {
            value: Amount::from_sat(240),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    /// A `SegWit` spend can be consensus-valid and still below the relay
    /// minimum once its witness is stripped, which a weight check alone
    /// cannot see.
    #[test]
    fn rejects_a_transaction_below_the_non_witness_minimum() {
        let mut tx = standard_tx(Version::ONE);
        tx.output[0].value = Amount::ZERO;
        tx.output[0].script_pubkey = ScriptBuf::new_op_return([]);
        assert!(
            tx.base_size() < MIN_NON_WITNESS_TX_SIZE,
            "the fixture must be undersized or this test proves nothing"
        );
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::TransactionTooSmall)
        );
    }

    #[test]
    fn rejects_non_pushonly_scriptsig() {
        let mut tx = standard_tx(Version::ONE);
        // OP_DUP is not a push opcode.
        tx.input[0].script_sig = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .into_script();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::ScriptSigNotPushOnly)
        );
    }

    #[test]
    fn rejects_oversized_scriptsig() {
        let mut tx = standard_tx(Version::ONE);
        // Build a push-only scriptSig that exceeds 1650 bytes.
        let big_data = PushBytesBuf::try_from(vec![0_u8; MAX_STANDARD_SCRIPTSIG_SIZE])
            .expect("push payload fits");
        tx.input[0].script_sig = Builder::new().push_slice(big_data).into_script();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::ScriptSigTooLarge)
        );
    }

    #[test]
    fn accepts_two_nulldata_outputs_within_the_aggregate_limit() {
        let mut tx = standard_tx(Version::ONE);
        let first = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"first")
            .into_script();
        let second = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"second")
            .into_script();
        let limit = [&first, &second]
            .into_iter()
            .fold(0_usize, |total, script| {
                total + VarInt::from(script.len()).size() + script.len()
            });
        tx.output = vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: first,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: second,
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
        let mut tx = standard_tx(Version::ONE);
        let threshold = tx.output[0]
            .script_pubkey
            .minimal_non_dust_custom(FeeRate::DUST);
        tx.output[0].value = threshold - Amount::ONE_SAT;

        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::DustOutput)
        );
        let lower_fee = StandardnessPolicy {
            dust_relay_fee: FeeRate::BROADCAST_MIN,
            ..policy()
        };
        assert_eq!(is_standard_tx(&tx, &lower_fee), Ok(()));
    }

    #[test]
    fn accepts_single_op_return_within_limit() {
        let mut tx = standard_tx(Version::ONE);
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"ok")
            .into_script();
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_dust_output() {
        let mut tx = standard_tx(Version::ONE);
        // 1 sat to a P2PKH output is dust.
        tx.output[0].value = Amount::from_sat(1);
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::DustOutput)
        );
    }

    #[test]
    fn rejects_non_standard_output_script() {
        let mut tx = standard_tx(Version::ONE);
        // A random non-standard script.
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DEPTH)
            .into_script();
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    fn ctx(fee: u64, vsize: u32, missing_inputs: bool) -> PackageTxContext {
        PackageTxContext {
            fee,
            vsize,
            sigop_cost: 2,
            missing_inputs,
        }
    }

    #[test]
    fn package_acceptance_rejects_empty_and_oversized_packages() {
        let pool = crate::Mempool::new(crate::MempoolLimits::default());
        let empty = evaluate_package_acceptance(&pool, &policy(), &[], &[], None, 1_000);
        assert_eq!(
            empty.package_error,
            Some(AcceptanceRejectReason::PackageTooLarge)
        );

        let txs: Vec<Transaction> = (0..=MAX_PACKAGE_COUNT)
            .map(|i| {
                let mut tx = standard_tx(Version::ONE);
                tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![
                    0x51,
                    u8::try_from(i).expect("package index fits u8"),
                ]);
                tx
            })
            .collect();
        let contexts: Vec<PackageTxContext> = txs.iter().map(|_| ctx(1_000, 100, false)).collect();
        let oversized = evaluate_package_acceptance(&pool, &policy(), &txs, &contexts, None, 1_000);
        assert_eq!(
            oversized.package_error,
            Some(AcceptanceRejectReason::PackageTooLarge)
        );
        assert!(oversized.results.is_empty());
    }

    #[test]
    fn package_acceptance_allows_standard_tx_and_records_sigop_cost() {
        let pool = crate::Mempool::new(crate::MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            ..crate::MempoolLimits::default()
        });
        let tx = standard_tx(Version::ONE);
        let facts = evaluate_package_acceptance(
            &pool,
            &policy(),
            std::slice::from_ref(&tx),
            &[ctx(1_000, 100, false)],
            None,
            1_000,
        );
        assert!(facts.package_error.is_none());
        let row = &facts.results[0];
        assert_eq!(row.allowed, Some(true));
        assert_eq!(row.sigop_cost, 2);
        assert_eq!(row.base_fee, Some(1_000));
        assert_eq!(row.txid, tx.compute_txid());
        assert_eq!(row.wtxid, tx.compute_wtxid());
    }

    #[test]
    fn package_acceptance_rejects_missing_inputs_and_stops_later_rows() {
        let pool = crate::Mempool::new(crate::MempoolLimits::default());
        let first = standard_tx(Version::ONE);
        let mut second = standard_tx(Version::ONE);
        second.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51, 0x99]);
        let facts = evaluate_package_acceptance(
            &pool,
            &policy(),
            &[first, second.clone()],
            &[ctx(1_000, 100, true), ctx(1_000, 100, false)],
            None,
            1_000,
        );
        assert_eq!(
            facts.results[0].reject_reason,
            Some(AcceptanceRejectReason::MissingInputs)
        );
        assert_eq!(facts.results[0].allowed, Some(false));
        assert_eq!(facts.results[1].allowed, None);
        assert_eq!(facts.results[1].reject_reason, None);
        assert_eq!(facts.results[1].base_fee, None);
    }

    #[test]
    fn package_acceptance_rejects_max_feerate_and_already_in_mempool() {
        let mut pool = crate::Mempool::new(crate::MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..crate::MempoolLimits::default()
        });
        let tx = standard_tx(Version::ONE);
        let over = evaluate_package_acceptance(
            &pool,
            &policy(),
            std::slice::from_ref(&tx),
            &[ctx(10_000, 100, false)],
            Some(50_000),
            1_000,
        );
        // fee_rate = 100_000 sat/kvB > 50_000
        assert_eq!(
            over.results[0].reject_reason,
            Some(AcceptanceRejectReason::MaxFeeExceeded)
        );

        pool.insert_entry(crate::MempoolEntry::new(
            alloc::sync::Arc::new(tx.clone()),
            100,
            1_000,
            1,
            1,
        ))
        .expect("insert");
        let dup = evaluate_package_acceptance(
            &pool,
            &policy(),
            &[tx],
            &[ctx(1_000, 100, false)],
            None,
            1_000,
        );
        assert_eq!(
            dup.results[0].reject_reason,
            Some(AcceptanceRejectReason::AlreadyInMempool)
        );
    }
}
