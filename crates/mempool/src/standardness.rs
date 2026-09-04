//! Bitcoin Core `IsStandardTx` / `IsStandard` policy checks.
//!
//! These are mempool/relay policy checks, not consensus rules. A transaction
//! that fails these checks may still be valid; it simply will not be accepted
//! to the mempool or relayed by default.

use bitcoin_rs_primitives::{Tx, TxOut};
use bitcoin_rs_script::{
    Instruction, is_multisig, is_op_return, is_p2a, is_p2pk, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh,
    is_p2wsh, is_push_only, minimal_non_dust, opcode, script::instructions,
};
use thiserror::Error;

/// Maximum weight of a standard transaction (400 000 weight units).
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Maximum length of a standard `scriptSig` in bytes.
const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

/// Standard relay policy values that are configurable by the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardnessPolicy {
    /// Fee rate used to classify outputs as dust, in sat/kvB.
    pub dust_relay_fee: u64,
    /// Maximum aggregate serialized nulldata script bytes, or `None` to disable nulldata.
    pub max_datacarrier_bytes: Option<usize>,
}

impl Default for StandardnessPolicy {
    /// The enforced defaults: Core's dust-relay rate (3 000 sat/kvB) and an
    /// 83-byte aggregate nulldata budget. Admission consumes these through
    /// [`crate::Mempool::policy_snapshot`]; `getmempoolinfo` projects them.
    fn default() -> Self {
        Self {
            dust_relay_fee: 3_000,
            max_datacarrier_bytes: Some(83),
        }
    }
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
pub fn is_standard_tx(tx: &Tx, policy: &StandardnessPolicy) -> Result<(), StandardnessError> {
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

/// Minimum non-witness serialization Core relays, `tx-size-small`.
///
/// The bound is on the stripped size. A one-input `SegWit` spend with an empty
/// scriptSig and a minimal `OP_RETURN` output serializes to 61 bytes without
/// its witness while carrying its authorization inside one, so a weight check
/// alone lets it through.
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
    for output in &tx.outputs {
        let script = &output.script_pubkey;
        if is_op_return(script) {
            if !is_standard_nulldata(script) {
                return Err(StandardnessError::NonStandardOutput);
            }
            let Some(limit) = policy.max_datacarrier_bytes else {
                return Err(StandardnessError::DataCarrierDisabled);
            };
            let serialized_script_bytes = compact_size_len(script.len())
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

/// Returns `true` if `script` is a bare multisig with at most 3 pubkeys.
///
/// Bitcoin Core's `IsStandard` allows bare multisig with up to 3 keys.
fn is_standard_multisig(script: &[u8]) -> bool {
    is_multisig(script) && multisig_key_count(script).is_some_and(|n| n <= 3)
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
fn multisig_key_count(script: &[u8]) -> Option<u8> {
    let mut count: u8 = 0;
    for inst in instructions(script) {
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
fn is_dust(output: &TxOut, dust_relay_fee: u64) -> bool {
    output.value < minimal_non_dust(&output.script_pubkey, dust_relay_fee)
}

#[inline]
const fn compact_size_len(len: usize) -> usize {
    if len < 0xfd {
        1
    } else if len <= 0xffff {
        3
    } else if len <= 0xffff_ffff {
        5
    } else {
        9
    }
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
fn is_standard_nulldata(script: &[u8]) -> bool {
    let mut instructions = instructions(script);
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
            op == opcode::OP_1NEGATE || (opcode::OP_PUSHNUM_1..=opcode::OP_PUSHNUM_16).contains(&op)
        }
        Err(_) => false,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};
    use bitcoin_rs_script::{is_multisig, minimal_non_dust, opcode, push_data};

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

    fn standard_tx(version: i32) -> Tx {
        Tx {
            version,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: p2pkh(&[7_u8; 20]),
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
    fn accepts_standard_version_one() {
        let tx = standard_tx(1);
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn accepts_standard_version_two() {
        let tx = standard_tx(2);
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_version_zero() {
        let tx = standard_tx(0);
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
        let tx = standard_tx(3);
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::Version)
        );
    }

    #[test]
    fn rejects_version_four() {
        let tx = standard_tx(4);
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::Version)
        );
    }

    /// Numeric push opcodes are pushes, and standard nulldata accepts them.
    ///
    /// The native script iterator reports `OP_1` through `OP_16` as `Op` rather
    /// than `PushBytes`, so a naive push-only check calls `OP_RETURN OP_1`
    /// non-standard when Core relays it.
    #[test]
    fn accepts_op_return_followed_by_a_numeric_push() {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = 0;
        tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN, opcode::OP_PUSHNUM_1];
        // Padded to clear the relay minimum, which is a different rule.
        tx.outputs.push(TxOut {
            value: 50_000,
            script_pubkey: p2pkh(&[9_u8; 20]),
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    /// `OP_RETURN` followed by a non-push opcode is not standard nulldata.
    #[test]
    fn rejects_op_return_followed_by_an_opcode() {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = 0;
        tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN, opcode::OP_DUP];
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// A push that is not a pubkey length still passes `is_multisig`.
    ///
    /// That predicate was measured against this surface: it already rejects a
    /// declared count that disagrees with the keys present, an `m` greater than
    /// `n`, and a keyless script. Push length is the one thing it does not
    /// check, so it is the only thing worth checking here.
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
        tx.outputs[0].script_pubkey = script;
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// The same shape, honestly declared, stays standard.
    #[test]
    fn accepts_a_well_formed_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut script = vec![opcode::OP_PUSHNUM_1];
        script.extend(push_data(&key));
        script.extend([opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG]);

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script;
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn accepts_three_of_three_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut script = vec![opcode::OP_PUSHNUM_1 + 2 /* OP_PUSHNUM_3 */];
        for _ in 0..3 {
            script.extend(push_data(&key));
        }
        script.extend([
            opcode::OP_PUSHNUM_1 + 2, /* OP_PUSHNUM_3 */
            opcode::OP_CHECKMULTISIG,
        ]);

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script;
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_one_of_four_bare_multisig() {
        let key = [0x02_u8; 33];
        let mut script = vec![opcode::OP_PUSHNUM_1];
        for _ in 0..4 {
            script.extend(push_data(&key));
        }
        script.extend([
            opcode::OP_PUSHNUM_1 + 3, /* OP_PUSHNUM_4 */
            opcode::OP_CHECKMULTISIG,
        ]);

        let mut tx = standard_tx(1);
        tx.outputs[0].script_pubkey = script;
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
        let mut tx = standard_tx(1);
        tx.outputs.push(TxOut {
            value: 240,
            script_pubkey: vec![0x51, 0x02, 0x4e, 0x73],
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    /// A `SegWit` spend can be consensus-valid and still below the relay
    /// minimum once its witness is stripped, which a weight check alone
    /// cannot see.
    #[test]
    fn rejects_a_transaction_below_the_non_witness_minimum() {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = 0;
        tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN];
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
        // OP_DUP is not a push opcode.
        tx.inputs[0].script_sig = vec![opcode::OP_DUP];
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::ScriptSigNotPushOnly)
        );
    }

    #[test]
    fn rejects_oversized_scriptsig() {
        let mut tx = standard_tx(1);
        // Build a push-only scriptSig that exceeds 1650 bytes.
        let big = vec![0_u8; super::MAX_STANDARD_SCRIPTSIG_SIZE];
        tx.inputs[0].script_sig = push_data(&big);
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
                total + super::compact_size_len(script.len()) + script.len()
            });
        tx.outputs = vec![
            TxOut {
                value: 0,
                script_pubkey: first,
            },
            TxOut {
                value: 0,
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
        let mut tx = standard_tx(1);
        let threshold = minimal_non_dust(&tx.outputs[0].script_pubkey, DUST_RELAY_FEE_SAT_PER_KVB);
        tx.outputs[0].value = threshold - 1;

        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::DustOutput)
        );
        let lower_fee = StandardnessPolicy {
            dust_relay_fee: BROADCAST_MIN_FEE_SAT_PER_KVB,
            ..policy()
        };
        assert_eq!(is_standard_tx(&tx, &lower_fee), Ok(()));
    }

    #[test]
    fn accepts_single_op_return_within_limit() {
        let mut tx = standard_tx(1);
        let script = [vec![opcode::OP_RETURN], push_data(b"ok")].concat();
        tx.outputs.push(TxOut {
            value: 0,
            script_pubkey: script,
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }

    #[test]
    fn rejects_dust_output() {
        let mut tx = standard_tx(1);
        // 1 sat to a P2PKH output is dust.
        tx.outputs[0].value = 1;
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::DustOutput)
        );
    }

    #[test]
    fn rejects_non_standard_output_script() {
        let mut tx = standard_tx(1);
        // A random non-standard script.
        tx.outputs[0].script_pubkey = vec![0x74]; // OP_DEPTH
        assert_eq!(
            is_standard_tx(&tx, &policy()),
            Err(StandardnessError::NonStandardOutput)
        );
    }
}
