//! Core mandatory-flag transaction vectors against the production kernel seam.
//! BADTX and policy-only rows are excluded; omitted pre-segwit amounts are zero.

#![cfg(feature = "kernel")]

use std::error::Error;
use std::path::Path;
use std::str::FromStr;

use bitcoin::hex::FromHex;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, consensus_bytes, deserialize};
use bitcoin_rs_script::{VerifyFlags, push_int};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

fn kernel_verdict(
    tx: &Tx,
    prevouts: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
) -> Result<Verdict, ConsensusError> {
    match bitcoin_rs_consensus::kernel::verify_tx_scripts(
        tx,
        prevouts,
        flags,
        bitcoin_rs_consensus::ValidationEngine::Kernel,
    ) {
        Ok(()) => Ok(Verdict::Accept),
        Err(ConsensusError::Script { .. }) => Ok(Verdict::Reject),
        Err(err) => Err(err),
    }
}

/// Core ASM: literal hex bytes, named opcodes and minimally pushed integers.
fn parse_core_asm(asm: &str) -> Result<Vec<u8>, String> {
    let mut script = Vec::new();
    for token in asm.split_whitespace() {
        if let Some(hex) = token.strip_prefix("0x") {
            let bytes =
                hex_to_bytes(hex).map_err(|e| format!("invalid hex in token {token}: {e}"))?;
            script.extend_from_slice(&bytes);
        } else if let Ok(n) = token.parse::<i64>() {
            script.extend_from_slice(&push_int(n));
        } else {
            let byte =
                resolve_opcode(token).ok_or_else(|| format!("unknown opcode token: {token}"))?;
            script.push(byte);
        }
    }
    Ok(script)
}

#[expect(
    clippy::too_many_lines,
    reason = "flat opcode-name table mirroring Core's script.h; splitting it by \
              category would hide which names are covered"
)]
fn resolve_opcode(name: &str) -> Option<u8> {
    use bitcoin_rs_script::opcode::*;
    let bare = name.strip_prefix("OP_").unwrap_or(name);
    Some(match bare {
        // Push opcodes
        "0" | "EMPTY" => OP_0,
        "PUSHDATA1" => 0x4c,
        "PUSHDATA2" => 0x4d,
        "PUSHDATA4" => 0x4e,
        "1NEGATE" => OP_1NEGATE,
        "1" | "PUSHNUM_1" => OP_PUSHNUM_1,
        "2" | "PUSHNUM_2" => 0x52,
        "3" | "PUSHNUM_3" => 0x53,
        "4" | "PUSHNUM_4" => 0x54,
        "5" | "PUSHNUM_5" => 0x55,
        "6" | "PUSHNUM_6" => 0x56,
        "7" | "PUSHNUM_7" => 0x57,
        "8" | "PUSHNUM_8" => 0x58,
        "9" | "PUSHNUM_9" => 0x59,
        "10" | "PUSHNUM_10" => 0x5a,
        "11" | "PUSHNUM_11" => 0x5b,
        "12" | "PUSHNUM_12" => 0x5c,
        "13" | "PUSHNUM_13" => 0x5d,
        "14" | "PUSHNUM_14" => 0x5e,
        "15" | "PUSHNUM_15" => 0x5f,
        "16" | "PUSHNUM_16" => OP_PUSHNUM_16,
        // Control flow
        "NOP" => 0x61,
        "VER" => 0x62,
        "IF" => 0x63,
        "NOTIF" => 0x64,
        "VERIF" => 0x65,
        "VERNOTIF" => 0x66,
        "ELSE" => 0x67,
        "ENDIF" => 0x68,
        "VERIFY" => 0x69,
        "RETURN" => OP_RETURN,
        // Stack
        "TOALTSTACK" => 0x6b,
        "FROMALTSTACK" => 0x6c,
        "2DROP" => 0x6d,
        "2DUP" => 0x6e,
        "3DUP" => 0x6f,
        "2OVER" => 0x70,
        "2ROT" => 0x71,
        "2SWAP" => 0x72,
        "IFDUP" => 0x73,
        "DEPTH" => 0x74,
        "DROP" => 0x75,
        "DUP" => OP_DUP,
        "NIP" => 0x77,
        "OVER" => 0x78,
        "PICK" => 0x79,
        "ROLL" => 0x7a,
        "ROT" => 0x7b,
        "SWAP" => 0x7c,
        "TUCK" => 0x7d,
        // Splice
        "CAT" => 0x7e,
        "SUBSTR" => 0x7f,
        "LEFT" => 0x80,
        "RIGHT" => 0x81,
        // Bitwise
        "SIZE" => 0x82,
        "INVERT" => 0x83,
        "AND" => 0x84,
        "OR" => 0x85,
        "XOR" => 0x86,
        "EQUAL" => OP_EQUAL,
        "EQUALVERIFY" => OP_EQUALVERIFY,
        // Arithmetic
        "1ADD" => 0x8b,
        "1SUB" => 0x8c,
        "2MUL" => 0x8d,
        "2DIV" => 0x8e,
        "NEGATE" => 0x8f,
        "ABS" => 0x90,
        "NOT" => 0x91,
        "0NOTEQUAL" => 0x92,
        "ADD" => 0x93,
        "SUB" => 0x94,
        "MUL" => 0x95,
        "DIV" => 0x96,
        "MOD" => 0x97,
        "LSHIFT" => 0x98,
        "RSHIFT" => 0x99,
        "BOOLAND" => 0x9a,
        "BOOLOR" => 0x9b,
        "NUMEQUAL" => 0x9c,
        "NUMEQUALVERIFY" => 0x9d,
        "NUMNOTEQUAL" => 0x9e,
        "LESSTHAN" => 0x9f,
        "GREATERTHAN" => 0xa0,
        "LESSTHANOREQUAL" => 0xa1,
        "GREATERTHANOREQUAL" => 0xa2,
        "MIN" => 0xa3,
        "MAX" => 0xa4,
        "WITHIN" => 0xa5,
        // Crypto
        "RIPEMD160" => 0xa6,
        "SHA1" => 0xa7,
        "SHA256" => 0xa8,
        "HASH160" => OP_HASH160,
        "HASH256" => 0xaa,
        "CODESEPARATOR" => 0xab,
        "CHECKSIG" => OP_CHECKSIG,
        "CHECKSIGVERIFY" => 0xad,
        "CHECKMULTISIG" => OP_CHECKMULTISIG,
        "CHECKMULTISIGVERIFY" => 0xaf,
        // Locktime/sequence
        "CHECKLOCKTIMEVERIFY" => 0xb1,
        "CHECKSEQUENCEVERIFY" => 0xb2,
        // Witness
        "CHECKSIGADD" => 0xba,
        _ => return None,
    })
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    Vec::from_hex(hex).map_err(|error| error.to_string())
}

struct VectorRow {
    tx: Tx,
    prevouts: Vec<(OutPoint, TxOut)>,
    flags: VerifyFlags,
    expected: Verdict,
    row_index: usize,
}

// A row is policy-only if it rejects only because of policy flags, but passes
// under mandatory consensus flags alone. The kernel only enforces mandatory flags.
fn is_policy_only_tx(row: &VectorRow) -> bool {
    if row.expected == Verdict::Accept {
        return false;
    }
    if row.flags.bits() & !VerifyFlags::MANDATORY.bits() == 0 {
        return false;
    }
    let mand_flags =
        VerifyFlags::from_bits_retain(row.flags.filled().bits() & VerifyFlags::MANDATORY.bits());
    let Ok(prepared) = bitcoin_rs_script::PreparedTransaction::new(&row.tx, &row.prevouts) else {
        return false;
    };
    for input_idx in 0..row.tx.inputs.len() {
        let result = prepared.verify_input(input_idx, mand_flags);
        if !matches!(result, Ok(true)) {
            return false;
        }
    }
    true
}

const FULL_FLAGS: VerifyFlags = VerifyFlags::STANDARD
    .union(VerifyFlags::SIGPUSHONLY)
    .union(VerifyFlags::CONST_SCRIPTCODE)
    .union(VerifyFlags::MINIMALIF);

/// `tx_valid.json` names the flags Core turns OFF: it verifies with the
/// complement (`transaction_tests.cpp:224`).
fn tx_valid_flags(names: &str) -> Result<VerifyFlags, String> {
    let parsed = VerifyFlags::from_core_names(names).map_err(|e| e.to_string())?;
    let effective = VerifyFlags::from_bits_retain(FULL_FLAGS.bits() & !parsed.bits());
    if effective != effective.filled() {
        return Err(format!(
            "bad test flags (not a filled combination): {names}"
        ));
    }
    Ok(effective)
}

/// `tx_invalid.json` names the flags Core turns ON, unfilled and unedited, so
/// an invalid combination is detected rather than repaired
/// (`transaction_tests.cpp:310-315`).
fn tx_invalid_flags(names: &str) -> Result<VerifyFlags, String> {
    let parsed = VerifyFlags::from_core_names(names).map_err(|e| e.to_string())?;
    if parsed != parsed.filled() {
        return Err(format!(
            "bad test flags (not a filled combination): {names}"
        ));
    }
    Ok(parsed)
}

/// Malformed transactions are skipped only for invalid vectors.
fn load_vectors(name: &str, expected: Verdict) -> Result<Vec<VectorRow>, Box<dyn Error>> {
    let path = Path::new("tests/vectors").join(name);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{} should be readable: {e}", path.display()))?;
    let root: Vec<Value> = sonic_rs::from_str(&text)
        .map_err(|e| format!("{} should parse as JSON array: {e}", path.display()))?;

    let mut rows = Vec::new();
    for (index, row) in root.iter().enumerate() {
        let Some(arr) = row.as_array() else {
            continue; // comment row
        };
        if arr.len() < 3 || !arr[0].is_array() || arr[1].as_str().is_none() {
            continue;
        }

        let flags_str = arr[2].as_str().unwrap_or("NONE");
        if flags_str.contains("BADTX") {
            continue; // fails CheckTransaction, not script verification
        }

        let tx_hex = arr[1]
            .as_str()
            .ok_or_else(|| format!("row {index}: tx hex should be string"))?;
        let tx_bytes = hex_to_bytes(tx_hex).map_err(|e| format!("row {index}: bad tx hex: {e}"))?;
        let tx: Tx = deserialize(&tx_bytes)
            .map_err(|e| format!("row {index}: tx should deserialize: {e}"))?;

        let flags = match expected {
            Verdict::Accept => tx_valid_flags(flags_str),
            Verdict::Reject => tx_invalid_flags(flags_str),
        }
        .map_err(|e| format!("row {index}: bad flags: {e}"))?;

        let prevout_specs = arr[0]
            .as_array()
            .ok_or_else(|| format!("row {index}: prevout specs should be array"))?;
        let mut available_prevouts = Vec::with_capacity(prevout_specs.len());
        for spec in prevout_specs {
            let spec = spec
                .as_array()
                .ok_or_else(|| format!("row {index}: bad prevout spec"))?;
            let hash_hex = spec[0]
                .as_str()
                .ok_or_else(|| format!("row {index}: bad prevout hash"))?;
            let vout_signed = spec[1]
                .as_i64()
                .ok_or_else(|| format!("row {index}: bad prevout vout"))?;
            // Core writes the null prevout index as -1 in these vectors, the
            // signed reading of COutPoint's 0xffffffff sentinel.
            let vout = if vout_signed == -1 {
                u32::MAX
            } else {
                u32::try_from(vout_signed)
                    .map_err(|_| format!("row {index}: prevout vout does not fit in u32"))?
            };
            let script_asm = spec[2]
                .as_str()
                .ok_or_else(|| format!("row {index}: bad prevout script"))?;
            let amount = spec
                .get(3)
                .and_then(sonic_rs::JsonValueTrait::as_u64)
                .unwrap_or(0);

            let script_pubkey = parse_core_asm(script_asm)
                .map_err(|e| format!("row {index}: bad prevout script asm: {e}"))?;

            let txid = Txid::from_str(hash_hex)
                .map_err(|e| format!("row {index}: bad prevout txid: {e}"))?;
            let outpoint = OutPoint::new(txid, vout);

            available_prevouts.push((
                outpoint,
                TxOut {
                    value: bitcoin_rs_primitives::Amount::from_sat(amount),
                    script_pubkey: script_pubkey.into(),
                },
            ));
        }

        // Core's transaction_tests.cpp populates a map of UTXOs from arr[0].
        // Transaction verification resolves them in input order.
        let mut prevouts = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let Some((_, spent)) = available_prevouts
                .iter()
                .find(|(op, _)| *op == input.previous_output)
            else {
                return Err(format!(
                    "row {index}: missing prevout for input {:?}",
                    input.previous_output
                )
                .into());
            };
            prevouts.push((input.previous_output, spent.clone()));
        }

        rows.push(VectorRow {
            tx,
            prevouts,
            flags,
            expected,
            row_index: index + 1,
        });
    }
    Ok(rows)
}

#[test]
fn kernel_verdict_matches_mandatory_core_catalogs() -> TestResult {
    for (name, expected) in [
        ("tx_valid.json", Verdict::Accept),
        ("tx_invalid.json", Verdict::Reject),
    ] {
        let rows = load_vectors(name, expected)?;
        require_non_empty(&rows, name)?;
        let runnable: Vec<&VectorRow> = rows.iter().filter(|row| !is_policy_only_tx(row)).collect();
        assert!(!runnable.is_empty(), "{name}: zero runnable rows");
        let mismatches: Vec<String> = runnable
            .iter()
            .filter_map(|row| match kernel_verdict(&row.tx, &row.prevouts, row.flags) {
                Ok(actual) => (actual != row.expected).then(|| {
                    format!(
                        "{name} row {}: expected {:?}, got {actual:?}",
                        row.row_index, row.expected
                    )
                }),
                Err(err) => Some(format!(
                    "{name} row {}: kernel oracle infrastructure error (must fail closed): {err}",
                    row.row_index
                )),
            })
            .collect();
        println!(
            "{name}: {} executed rows, {} policy rows skipped",
            runnable.len(),
            rows.len() - runnable.len()
        );
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }
    Ok(())
}

fn require_non_empty(rows: &[VectorRow], name: &str) -> Result<(), Box<dyn Error>> {
    if rows.is_empty() {
        return Err(format!("{name}: zero vectors loaded — gate is vacuous").into());
    }
    Ok(())
}

#[test]
fn non_vacuous_wrong_verdict_goes_red() -> TestResult {
    // 1. Positive baseline: valid transaction is accepted.
    let valid_rows = load_vectors("tx_valid.json", Verdict::Accept)?;
    require_non_empty(&valid_rows, "tx_valid.json")?;
    let valid_row = &valid_rows[0];
    let actual_valid = kernel_verdict(&valid_row.tx, &valid_row.prevouts, valid_row.flags)
        .map_err(|err| format!("oracle infrastructure error on valid tx: {err}"))?;
    assert_eq!(
        actual_valid,
        Verdict::Accept,
        "tx_valid row must be accepted"
    );

    // 2. Negative control (fault injection): mutating the valid transaction's scriptSig
    // must make the kernel reject it with a genuine Script rejection.
    let mut tampered_tx = valid_row.tx.clone();
    tampered_tx.inputs[0].script_sig = bitcoin_rs_primitives::Script::from_bytes(vec![0x00]);
    let tampered_verdict = kernel_verdict(&tampered_tx, &valid_row.prevouts, valid_row.flags)
        .map_err(|err| format!("oracle infrastructure error on tampered tx: {err}"))?;
    assert_eq!(
        tampered_verdict,
        Verdict::Reject,
        "tampered transaction must be rejected by kernel oracle"
    );

    // 3. Baseline invalid: mandatory-invalid transaction is rejected.
    let invalid_rows = load_vectors("tx_invalid.json", Verdict::Reject)?;
    require_non_empty(&invalid_rows, "tx_invalid.json")?;
    let invalid_row = invalid_rows
        .iter()
        .find(|row| !is_policy_only_tx(row))
        .ok_or("no runnable invalid rows found")?;
    let actual_invalid = kernel_verdict(&invalid_row.tx, &invalid_row.prevouts, invalid_row.flags)
        .map_err(|err| format!("oracle infrastructure error on invalid tx: {err}"))?;
    assert_eq!(
        actual_invalid,
        Verdict::Reject,
        "tx_invalid row must be rejected"
    );

    Ok(())
}

#[test]
fn kernel_infrastructure_error_fails_closed() -> TestResult {
    let rows = load_vectors("tx_invalid.json", Verdict::Reject)?;
    require_non_empty(&rows, "tx_invalid.json")?;
    let row = rows
        .iter()
        .find(|row| !is_policy_only_tx(row))
        .ok_or("no runnable invalid rows found")?;

    // Case 1: Supplying empty prevouts causes ConsensusError::PrevoutCount rather than a script rejection.
    let empty_prevouts: Vec<(OutPoint, TxOut)> = Vec::new();
    let verdict_result = kernel_verdict(&row.tx, &empty_prevouts, row.flags);
    assert!(
        matches!(verdict_result, Err(ConsensusError::PrevoutCount { .. })),
        "empty prevouts must produce an infrastructure error, got {verdict_result:?}"
    );
    assert_ne!(
        verdict_result.as_ref().ok(),
        Some(&Verdict::Reject),
        "infrastructure error must never masquerade as expected consensus Reject"
    );

    // Case 2: Out of bounds input index causes bitcoinkernel::verify to return
    // ScriptVerifyError::TxInputIndex, proving real kernel API errors are not Script rejections.
    let tx_bytes = consensus_bytes(&row.tx);
    let kernel_tx =
        bitcoinkernel::Transaction::new(&tx_bytes).map_err(|e| format!("kernel_tx new: {e}"))?;
    let kernel_prevouts = row
        .prevouts
        .iter()
        .map(|(_, prevout)| {
            let script = bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey)
                .map_err(|e| format!("script new: {e}"))?;
            let amount =
                i64::try_from(prevout.value.to_sat()).map_err(|e| format!("amount: {e}"))?;
            Ok(bitcoinkernel::TxOut::new(&script, amount))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let precomputed = bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, &kernel_prevouts)
        .map_err(|e| format!("precomputed new: {e}"))?;
    let script = bitcoinkernel::ScriptPubkey::new(&row.prevouts[0].1.script_pubkey)
        .map_err(|e| format!("script new: {e}"))?;
    let amount =
        i64::try_from(row.prevouts[0].1.value.to_sat()).map_err(|e| format!("amount: {e}"))?;
    let kernel_verify_err = bitcoinkernel::verify(
        &script,
        Some(amount),
        &kernel_tx,
        999, // out-of-bounds input index
        Some(bitcoinkernel::VERIFY_ALL),
        &precomputed,
    );
    assert!(
        matches!(
            kernel_verify_err,
            Err(bitcoinkernel::KernelError::ScriptVerify(
                bitcoinkernel::ScriptVerifyError::TxInputIndex
            ))
        ),
        "out of bounds index must produce ScriptVerifyError::TxInputIndex from kernel, got: {kernel_verify_err:?}"
    );

    Ok(())
}
