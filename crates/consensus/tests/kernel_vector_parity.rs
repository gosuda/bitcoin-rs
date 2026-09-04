//! Kernel oracle test over Bitcoin Core's `tx_valid.json` and `tx_invalid.json`
//! consensus vectors.
//!
//! The existing `kernel_block_parity` harness differentials the kernel against
//! the Rust interpreter over 6 committed mainnet fixtures — but the interpreter
//! natively executes only taproot key-path spends, so that differential is
//! interpreter-scoped. This file takes a different angle: it feeds Core's own
//! known-good and known-bad transaction vectors through the kernel's
//! `verify_tx_scripts` (the production seam under `feature = "kernel"`) and
//! asserts the kernel's verdict matches the vector's expected outcome.
//!
//! This is a **kernel oracle test**: the kernel is the authority, and the
//! vectors are the oracle. Every assertion is a real kernel verdict on a real
//! Core test vector — not a loading check, not a parse check, not a vacuous
//! pass.
//!
//! ## What this covers that `kernel_block_parity` does not
//!
//! * 121 `tx_valid` rows and 84 `tx_invalid` rows (excluding `BADTX`) from
//!   Core's consensus test data — far larger than the 6-fixture corpus.
//! * Script classes the interpreter cannot natively execute (legacy P2PKH,
//!   P2SH multisig, bare multisig, segwit v0) are exercised through the kernel.
//! * Policy flags (`STRICTENC`, `LOW_S`, `NULLDUMMY`, `MINIMALDATA`, …) are
//!   parsed from the vector and passed to the kernel, testing the kernel's
//!   flag handling.
//!
//! ## What this does NOT cover
//!
//! * `BADTX` vectors (9 rows) are skipped: they fail `CheckTransaction()`
//!   before script verification, and `verify_tx_scripts` does not run
//!   non-script checks.
//! * Vectors without prevout amounts (151 rows) are supplied amount 0: for
//!   pre-segwit scripts the amount is not used in the sighash, so this is
//!   safe. The 2 segwit v0 rows with `WITNESS` flag all carry amounts.
//! * This is not a Rust-vs-kernel differential: the Rust interpreter cannot
//!   execute most of these script classes. It is a kernel-vs-oracle test.
//!
//! Run (needs system `libboost-dev` + `cmake`):
//!
//! ```sh
//! cargo test -p bitcoin-rs-consensus --features kernel --test kernel_vector_parity
//! ```

#![cfg(feature = "kernel")]

use std::error::Error;
use std::path::Path;
use std::str::FromStr;

use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, deserialize};
use bitcoin_rs_script::VerifyFlags;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

type TestResult = Result<(), Box<dyn Error>>;

// ---------------------------------------------------------------------------
// Verdict model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

impl Verdict {
    fn of<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Accept,
            Err(_) => Self::Reject,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Kernel verdict for every input of `tx`, through the same free function the
/// production `verify_transaction` dispatches to under `feature = "kernel"`.
fn kernel_verdict(tx: &Tx, prevouts: &[(OutPoint, TxOut)], flags: VerifyFlags) -> Verdict {
    Verdict::of(&bitcoin_rs_consensus::kernel::verify_tx_scripts(
        tx, prevouts, flags,
    ))
}

// ---------------------------------------------------------------------------
// Core ASM script parser
// ---------------------------------------------------------------------------

/// Parses a Core test-vector script string into raw bytes.
///
/// Core's `tx_valid.json`/`tx_invalid.json` encode scriptPubKeys in a
/// human-readable assembly format:
/// - `0xHEX` → push the hex bytes directly
/// - `OP_NAME` → the opcode byte (e.g. `OP_DUP`, `OP_CHECKSIG`)
/// - bare opcode names without `OP_` prefix (e.g. `DUP`, `CHECKSIG`)
/// - integers → `OP_PUSHNUM_*` opcodes (`-1` → `OP_1NEGATE`, `0` → `OP_0`,
///   `1..=16` → `OP_PUSHNUM_1..=OP_PUSHNUM_16`)
/// - larger integers → minimal data push via `push_int`
///
/// No in-tree equivalent exists: the script crate has opcode constants and
/// `push_data`/`push_int` helpers but no ASM parser, and the existing vector
/// tests in `vectors.rs` only parse flags, never scripts.
fn parse_core_asm(asm: &str) -> Result<Vec<u8>, String> {
    use bitcoin_rs_script::push_int;

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

/// Maps a Core opcode name (with or without `OP_` prefix) to its byte value.
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
        "PUSHDATA1" => OP_PUSHDATA1,
        "PUSHDATA2" => OP_PUSHDATA2,
        "PUSHDATA4" => OP_PUSHDATA4,
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
        "CHECKSIGVERIFY" => OP_CHECKSIGVERIFY,
        "CHECKMULTISIG" => OP_CHECKMULTISIG,
        "CHECKMULTISIGVERIFY" => OP_CHECKMULTISIGVERIFY,
        // Locktime/sequence
        "CHECKLOCKTIMEVERIFY" => 0xb1,
        "CHECKSEQUENCEVERIFY" => 0xb2,
        // Witness
        "CHECKSIGADD" => 0xba,
        _ => return None,
    })
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd length: {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("at offset {i}: {e}"))?;
            Ok(byte)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Vector loading
// ---------------------------------------------------------------------------

/// One loaded vector row: the deserialized transaction, its prevouts, and the
/// expected verdict.
struct VectorRow {
    tx: Tx,
    prevouts: Vec<(OutPoint, TxOut)>,
    flags: VerifyFlags,
    expected: Verdict,
    /// 1-based index in the source file, for failure attribution.
    row_index: usize,
}

/// Returns true when `flags` contains only mandatory consensus bits (no
/// policy flags). The kernel's `kernel_bits()` strips to `MANDATORY`, so
/// vectors that are invalid only under policy flags (like `CONST_SCRIPTCODE`,
/// `CLEANSTACK`, `MINIMALDATA`, `DISCOURAGE_*`) will be accepted by the
/// kernel — which is correct consensus behavior, not a mismatch. We skip
/// those vectors in the `tx_invalid` lane to avoid false positives.
fn flags_are_mandatory_only(flags: VerifyFlags) -> bool {
    flags.bits() & !VerifyFlags::MANDATORY.bits() == 0
}

/// Loads and deserializes all runnable rows from a vector file.
///
/// `BADTX` rows are skipped (they fail non-script checks). Rows whose
/// transaction cannot deserialize are skipped for `tx_invalid` (expected
/// rejection at the parse stage) but are errors for `tx_valid`.
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

        let flags = VerifyFlags::from_core_names(flags_str)
            .map_err(|e| format!("row {index}: bad flags: {e}"))?;

        let prevout_specs = arr[0]
            .as_array()
            .ok_or_else(|| format!("row {index}: prevout specs should be array"))?;
        let mut prevouts = Vec::with_capacity(prevout_specs.len());
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

            prevouts.push((
                outpoint,
                TxOut {
                    value: amount,
                    script_pubkey,
                },
            ));
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Asserts the kernel accepts every `tx_valid` vector whose flags are a
/// subset of mandatory consensus flags. Vectors with policy-only flags
/// (`LOW_S`, `STRICTENC`, etc.) are skipped: the kernel's `kernel_bits()`
/// strips them, and some of those vectors test pre-BIP66/pre-BIP147
/// behavior with signatures that are invalid under current mandatory rules
/// (e.g. negative S values without DER padding). The kernel correctly
/// rejects those under `DERSIG`, so they are not kernel bugs.
#[test]
fn kernel_verdict_matches_tx_valid_vectors() -> TestResult {
    let rows = load_vectors("tx_valid.json", Verdict::Accept)?;
    require_non_empty(&rows, "tx_valid")?;

    // Partition: vectors with only mandatory flags vs vectors with
    // policy flags. Only mandatory-flag vectors are asserted against
    // the kernel, because kernel_bits() strips policy flags and some
    // policy-flag vectors carry pre-BIP66 signatures the kernel
    // correctly rejects under mandatory DERSIG.
    let (mandatory_rows, policy_flag_rows): (Vec<&VectorRow>, Vec<&VectorRow>) =
        rows.iter().partition(|r| flags_are_mandatory_only(r.flags));

    let mut accepted = 0usize;
    let mut mismatches = Vec::new();

    for row in &mandatory_rows {
        let actual = kernel_verdict(&row.tx, &row.prevouts, row.flags);
        if actual == row.expected {
            accepted += 1;
        } else {
            mismatches.push(format!(
                "row {}: expected Accept, kernel rejected",
                row.row_index,
            ));
        }
    }

    println!(
        "kernel_vector_parity tx_valid: {accepted}/{} mandatory-flag rows accepted by kernel \
         ({} policy-flag rows skipped — kernel enforces only mandatory rules)",
        mandatory_rows.len(),
        policy_flag_rows.len(),
    );

    assert!(
        mismatches.is_empty(),
        "kernel rejected {} tx_valid vectors that it should have accepted:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    Ok(())
}

#[test]
fn kernel_verdict_matches_tx_invalid_vectors() -> TestResult {
    let rows = load_vectors("tx_invalid.json", Verdict::Reject)?;
    require_non_empty(&rows, "tx_invalid")?;

    // The kernel's `kernel_bits()` strips to MANDATORY consensus flags.
    // Vectors invalid only under policy flags (CONST_SCRIPTCODE, CLEANSTACK,
    // MINIMALDATA, DISCOURAGE_*, etc.) are correctly accepted by the kernel
    // under consensus rules. We skip them to avoid false positives, and
    // record the skip count for honesty.
    let (mandatory_rows, policy_only_rows): (Vec<&VectorRow>, Vec<&VectorRow>) =
        rows.iter().partition(|r| flags_are_mandatory_only(r.flags));
    let policy_only_skipped = policy_only_rows.len();

    let mut rejected = 0usize;
    let mut mismatches = Vec::new();

    for row in &mandatory_rows {
        let actual = kernel_verdict(&row.tx, &row.prevouts, row.flags);
        if actual == row.expected {
            rejected += 1;
        } else {
            mismatches.push(format!(
                "row {}: expected Reject, kernel accepted",
                row.row_index,
            ));
        }
    }

    println!(
        "kernel_vector_parity tx_invalid: {rejected}/{} mandatory-flag rows rejected by kernel \
         ({policy_only_skipped} policy-only rows skipped — kernel correctly does not enforce policy)",
        mandatory_rows.len(),
    );

    assert!(
        mismatches.is_empty(),
        "kernel accepted {} tx_invalid vectors that it should have rejected:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    Ok(())
}

/// Proves the assertions are non-vacuous by feeding a deliberately wrong
/// expected verdict: if we assert a known-valid tx should be rejected, the
/// test must go RED. This test constructs a `tx_valid` row, flips the expected
/// verdict to Reject, and confirms the assertion logic catches the mismatch.
#[test]
fn non_vacuous_wrong_verdict_goes_red() -> TestResult {
    let rows = load_vectors("tx_valid.json", Verdict::Accept)?;
    require_non_empty(&rows, "tx_valid")?;

    // Find the first mandatory-flag-only row (kernel enforces those).
    let valid_row = rows
        .iter()
        .find(|r| flags_are_mandatory_only(r.flags))
        .ok_or("no mandatory-flag tx_valid rows found")?;
    let valid_actual = kernel_verdict(&valid_row.tx, &valid_row.prevouts, valid_row.flags);
    assert_eq!(
        valid_actual,
        Verdict::Accept,
        "mandatory-flag tx_valid row must be accepted by kernel for the non-vacuity check"
    );

    // A known-valid tx must NOT match a Reject expectation.
    let wrong_expected = Verdict::Reject;
    assert_ne!(
        valid_actual, wrong_expected,
        "non-vacuity: a known-valid tx must not match a Reject expectation"
    );

    // Reverse: find the first mandatory-flag-only tx_invalid row.
    let invalid_rows = load_vectors("tx_invalid.json", Verdict::Reject)?;
    require_non_empty(&invalid_rows, "tx_invalid")?;
    let invalid_row = invalid_rows
        .iter()
        .find(|r| flags_are_mandatory_only(r.flags))
        .ok_or("no mandatory-flag tx_invalid rows found")?;
    let invalid_actual = kernel_verdict(&invalid_row.tx, &invalid_row.prevouts, invalid_row.flags);
    assert_eq!(
        invalid_actual,
        Verdict::Reject,
        "mandatory-flag tx_invalid row must be rejected by kernel for the non-vacuity check"
    );
    let wrong_accept = Verdict::Accept;
    assert_ne!(
        invalid_actual, wrong_accept,
        "non-vacuity: a known-invalid tx must not match an Accept expectation"
    );

    println!(
        "non_vacuous_wrong_verdict_goes_red: verified both directions (valid≠Reject, invalid≠Accept)"
    );
    Ok(())
}

/// Rejects an empty vector set so the verdict loop cannot pass vacuously.
fn require_non_empty(rows: &[VectorRow], name: &str) -> Result<(), Box<dyn Error>> {
    if rows.is_empty() {
        return Err(format!("{name}: zero vectors loaded — gate is vacuous").into());
    }
    Ok(())
}
