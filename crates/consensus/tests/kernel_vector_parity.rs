//! Core mandatory-flag transaction vectors against the production kernel seam.
//! BADTX and policy-only rows are excluded; omitted pre-segwit amounts are zero.

#![cfg(feature = "kernel")]

use std::error::Error;
use std::path::Path;
use std::str::FromStr;

use bitcoin::hex::FromHex;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, deserialize};
use bitcoin_rs_script::{VerifyFlags, push_int};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

type TestResult = Result<(), Box<dyn Error>>;

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

fn kernel_verdict(tx: &Tx, prevouts: &[(OutPoint, TxOut)], flags: VerifyFlags) -> Verdict {
    Verdict::of(&bitcoin_rs_consensus::kernel::verify_tx_scripts(
        tx,
        prevouts,
        flags,
        bitcoin_rs_consensus::ValidationEngine::Kernel,
    ))
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

// The kernel strips policy bits; policy-only rejections are not consensus failures.
fn flags_are_mandatory_only(flags: VerifyFlags) -> bool {
    flags.bits() & !VerifyFlags::MANDATORY.bits() == 0
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
                    value: bitcoin_rs_primitives::Amount::from_sat(amount),
                    script_pubkey: script_pubkey.into(),
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

#[test]
fn kernel_verdict_matches_mandatory_core_catalogs() -> TestResult {
    for (name, expected) in [
        ("tx_valid.json", Verdict::Accept),
        ("tx_invalid.json", Verdict::Reject),
    ] {
        let rows = load_vectors(name, expected)?;
        require_non_empty(&rows, name)?;
        let mandatory: Vec<&VectorRow> = rows
            .iter()
            .filter(|row| flags_are_mandatory_only(row.flags))
            .collect();
        assert!(!mandatory.is_empty(), "{name}: zero mandatory-flag rows");
        let mismatches: Vec<String> = mandatory
            .iter()
            .filter_map(|row| {
                let actual = kernel_verdict(&row.tx, &row.prevouts, row.flags);
                (actual != row.expected).then(|| {
                    format!(
                        "{name} row {}: expected {:?}, got {actual:?}",
                        row.row_index, row.expected
                    )
                })
            })
            .collect();
        println!(
            "{name}: {} mandatory rows, {} policy rows skipped",
            mandatory.len(),
            rows.len() - mandatory.len()
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
    for (name, expected) in [
        ("tx_valid.json", Verdict::Accept),
        ("tx_invalid.json", Verdict::Reject),
    ] {
        let rows = load_vectors(name, expected)?;
        require_non_empty(&rows, name)?;
        let row = rows
            .iter()
            .find(|row| flags_are_mandatory_only(row.flags))
            .ok_or("no mandatory-flag rows found")?;
        let actual = kernel_verdict(&row.tx, &row.prevouts, row.flags);
        assert_eq!(actual, expected, "{name}");
    }
    Ok(())
}
