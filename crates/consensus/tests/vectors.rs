//! Consensus vector loading and hash-computation tests.

use std::path::Path;

use bitcoin::consensus;
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::SighashCache;
use bitcoin::{Script, Transaction};
use bitcoin_rs_primitives::Hash256;
use serde_json::Value;

#[test]
fn tx_valid_vectors_deserialize() {
    let (total, parsed) = parse_tx_vectors("tx_valid.json", true);
    println!("tx_valid.json: parsed {parsed}/{total} transaction vectors");
    assert!(total > 0);
    assert_eq!(parsed, total);
}

#[test]
fn tx_invalid_vectors_load() {
    let (total, parsed) = parse_tx_vectors("tx_invalid.json", false);
    println!(
        "tx_invalid.json: parsed {parsed}/{total} transaction vectors before expected rejection"
    );
    assert!(total > 0);
    assert!(parsed > 0);
}

#[test]
fn script_tests_vectors_load_and_flags_parse() {
    let root = read_json("script_tests.json");
    let rows = root
        .as_array()
        .unwrap_or_else(|| panic!("script_tests root must be array"));
    let mut total = 0usize;
    let mut parsed_flags = 0usize;
    for row in rows {
        let Some(row) = row.as_array() else {
            continue;
        };
        if row.len() < 4 {
            continue;
        }
        total = total.saturating_add(1);
        let flags_index = if row.first().is_some_and(Value::is_array) {
            3
        } else {
            2
        };
        let Some(flags) = row.get(flags_index).and_then(Value::as_str) else {
            continue;
        };
        if bitcoin_rs_script::VerifyFlags::from_core_names(flags).is_ok() {
            parsed_flags = parsed_flags.saturating_add(1);
        }
    }
    println!("script_tests.json: parsed flags for {parsed_flags}/{total} runnable script vectors");
    assert!(total > 0);
    assert_eq!(parsed_flags, total);
}

#[test]
fn sighash_vectors_match_bitcoin_cache() {
    let root = read_json("sighash.json");
    let rows = root
        .as_array()
        .unwrap_or_else(|| panic!("sighash root must be array"));
    let mut total = 0usize;
    let mut matched = 0usize;
    let mut skipped_codeseparator = 0usize;
    for row in rows {
        let Some(row) = row.as_array() else {
            continue;
        };
        if row.len() != 5 || !row.first().is_some_and(Value::is_string) {
            continue;
        }
        total = total.saturating_add(1);
        let tx_hex = string_at(row, 0);
        let script_hex = string_at(row, 1);
        let input_index = usize_at(row, 2);
        let hash_type = raw_u32_at(row, 3);
        let expected = hash_at(row, 4);
        let tx: Transaction = deserialize_hex(tx_hex);
        let script = decode_hex(script_hex);
        if script.contains(&0xab) {
            skipped_codeseparator = skipped_codeseparator.saturating_add(1);
            continue;
        }
        let cache = SighashCache::new(&tx);
        let actual = match cache.legacy_signature_hash(
            input_index,
            Script::from_bytes(&script),
            hash_type,
        ) {
            Ok(hash) => Hash256::from_le_bytes(hash.as_byte_array()),
            Err(error) => panic!("sighash vector should compute: {error}"),
        };
        assert_eq!(actual, expected);
        matched = matched.saturating_add(1);
    }
    println!(
        "sighash.json: matched {matched}/{total} legacy sighash vectors; skipped {skipped_codeseparator} OP_CODESEPARATOR vectors unsupported by bitcoin 0.32 cache"
    );
    assert!(total > 0);
    assert!(matched > 0);
}

fn parse_tx_vectors(name: &str, must_deserialize_all: bool) -> (usize, usize) {
    let root = read_json(name);
    let rows = root
        .as_array()
        .unwrap_or_else(|| panic!("tx vector root must be array"));
    let mut total = 0usize;
    let mut parsed = 0usize;
    for row in rows {
        let Some(row) = row.as_array() else {
            continue;
        };
        if row.len() < 3 || !row.first().is_some_and(Value::is_array) {
            continue;
        }
        total = total.saturating_add(1);
        let Some(tx_hex) = row.get(1).and_then(Value::as_str) else {
            continue;
        };
        let bytes = decode_hex(tx_hex);
        if consensus::deserialize::<Transaction>(&bytes).is_ok() {
            parsed = parsed.saturating_add(1);
        } else if must_deserialize_all {
            panic!("valid tx vector failed to deserialize");
        }
    }
    (total, parsed)
}

fn read_json(name: &str) -> Value {
    let path = Path::new("tests/vectors").join(name);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => panic!("{} should be readable: {error}", path.display()),
    };
    match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => panic!("{} should parse as JSON: {error}", path.display()),
    }
}

fn deserialize_hex<T: consensus::Decodable>(hex: &str) -> T {
    let bytes = decode_hex(hex);
    match consensus::deserialize(&bytes) {
        Ok(value) => value,
        Err(error) => panic!("hex consensus payload should deserialize: {error}"),
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let Some(high) = chars.next() {
        let low = chars
            .next()
            .unwrap_or_else(|| panic!("hex string has odd length"));
        let high = hex_nibble(high);
        let low = hex_nibble(low);
        bytes.push((high << 4) | low);
    }
    bytes
}

fn hex_nibble(ch: char) -> u8 {
    let Some(value) = ch.to_digit(16) else {
        panic!("invalid hex digit {ch}");
    };
    u8::try_from(value).unwrap_or_else(|error| panic!("hex digit should fit in u8: {error}"))
}

fn string_at(row: &[Value], index: usize) -> &str {
    row.get(index)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector column {index} should be a string"))
}

fn usize_at(row: &[Value], index: usize) -> usize {
    let value = row
        .get(index)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("vector column {index} should be an unsigned integer"));
    usize::try_from(value).unwrap_or_else(|error| panic!("usize vector column should fit: {error}"))
}

fn raw_u32_at(row: &[Value], index: usize) -> u32 {
    let value = row
        .get(index)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("vector column {index} should be an integer"));
    let signed =
        i32::try_from(value).unwrap_or_else(|error| panic!("hash type should fit i32: {error}"));
    u32::from_ne_bytes(signed.to_ne_bytes())
}

fn hash_at(row: &[Value], index: usize) -> Hash256 {
    Hash256::from_str_be(string_at(row, index))
        .unwrap_or_else(|error| panic!("sighash vector result should parse: {error}"))
}

#[cfg(feature = "kernel")]
#[test]
fn kernel_feature_vectors_parse_before_parity() {
    let root = read_json("tx_valid.json");
    assert!(root.as_array().is_some_and(|rows| rows.len() > 1));
}
