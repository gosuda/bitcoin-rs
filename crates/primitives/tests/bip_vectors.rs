//! Authoritative BIP sighash vectors: the pinned expectations in
//! `tests/vectors/` decide, not this crate's own re-derivations.
//!
//! - BIP143 "Alternative Signing Procedure" examples (P2WPKH and P2SH-P2WSH
//!   6-of-6 multisig) pin the segwit-v0 digest for every base SIGHASH mode.
//! - BIP341 wallet test vectors pin the key-path signature message for every
//!   base SIGHASH mode plus `SIGHASH_DEFAULT`.
//!
//! Provenance and the script-path coverage story live in
//! `tests/vectors/PROVENANCE.md`.
#![expect(clippy::expect_used, reason = "test assertions")]

use std::path::PathBuf;

use bitcoin_rs_primitives::{
    Amount, Script, Sequence, Sighash, SighashCache, Tx as NativeTx, TxOut, Witness,
    encode::deserialize,
};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn load_json(name: &str) -> Result<serde_json::Value> {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    Ok(serde_json::from_str(&text)?)
}

/// BIP341 wire hash type byte -> the crate's typed SIGHASH mode.
fn taproot_hash_type(byte: u8) -> Sighash {
    match byte {
        0 => Sighash::Default,
        1 => Sighash::All,
        2 => Sighash::None,
        3 => Sighash::Single,
        0x81 => Sighash::AllAnyoneCanPay,
        0x82 => Sighash::NoneAnyoneCanPay,
        0x83 => Sighash::SingleAnyoneCanPay,
        other => panic!("unexpected BIP341 hash type {other:#x}"),
    }
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|error| panic!("bad hex at {index}: {error}"))
        })
        .collect()
}

/// BIP test vectors publish digests in computation (internal) byte order.
fn digest_hex(digest: &bitcoin_rs_primitives::Hash256) -> String {
    digest
        .as_byte_array()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// BIP143 examples: the `SighashCache` must reproduce the spec digests for
/// both the P2WPKH and the P2SH-P2WSH 6-of-6 multisig examples, across all
/// six base `SIGHASH` modes of the multisig example.
#[test]
fn bip143_examples_match_spec_digests() -> Result<()> {
    let vectors = load_json("bip143.json")?;
    for example in ["p2wpkh_example", "p2wsh_multisig_example"] {
        let example = vectors
            .get(example)
            .unwrap_or_else(|| panic!("bip143.json missing {example}"));
        let tx_bytes = hex_decode(example["unsigned_tx"].as_str().expect("tx hex"));
        let tx = deserialize::<NativeTx>(&tx_bytes)
            .unwrap_or_else(|error| panic!("{example}: native decode failed: {error}"));
        // The cache API takes the raw script bytes and writes the compactSize
        // prefix itself; the checked-in vectors store scriptCode raw.
        let script_code = hex_decode(example["script_code"].as_str().expect("script code"));
        let value_sats = example["value_sats"].as_u64().expect("value sats");
        let input_index = usize::try_from(example["input_index"].as_u64().expect("input index"))
            .expect("input index fits usize");
        let mut cache = SighashCache::new(&tx);

        for vector in example["vectors"].as_array().expect("vectors array") {
            let hash_type = u32::try_from(vector["hash_type"].as_u64().expect("hash type"))
                .expect("hash type fits u32");
            let expected = vector["sighash"].as_str().expect("sighash hex");
            let ty =
                Sighash::from_consensus_u8(u8::try_from(hash_type).expect("hash type fits u8"))
                    .unwrap_or_else(|error| panic!("bip143: hash type {hash_type:#x}: {error}"));

            // Typed cache path.
            let cached = cache
                .segwit_v0_signature_hash(
                    input_index,
                    &script_code,
                    Amount::from_sat(value_sats),
                    ty,
                )
                .unwrap_or_else(|error| panic!("bip143 {example}: cache failed: {error}"));
            assert_eq!(
                digest_hex(&cached),
                expected,
                "bip143 {example} hash type {hash_type:#x}"
            );

            // Raw path (BIP143 appends the full 32-bit flag word): the base
            // types serialize identically to their raw encoding.
            let raw = cache
                .segwit_v0_signature_hash_raw(
                    input_index,
                    &script_code,
                    Amount::from_sat(value_sats),
                    hash_type,
                )
                .unwrap_or_else(|error| panic!("bip143 {example}: raw failed: {error}"));
            assert_eq!(
                digest_hex(&raw),
                expected,
                "bip143 {example} raw hash type {hash_type:#x}"
            );

            // One-shot helpers must agree with the spec too (they are the
            // forms consensus/src/bip143.rs and the script checker call).
            let one_shot = Sighash::compute_bip143(
                &tx,
                input_index,
                &script_code,
                Amount::from_sat(value_sats),
                ty,
            )
            .unwrap_or_else(|error| panic!("bip143 {example}: one-shot failed: {error}"));
            assert_eq!(
                digest_hex(&one_shot),
                expected,
                "bip143 {example} one-shot {hash_type:#x}"
            );
        }
    }
    Ok(())
}

/// BIP341 wallet test vectors: every keyPathSpending input-spending case pins
/// the signature message for one SIGHASH mode; the cache must reproduce it
/// from the unsigned transaction and the spent outputs alone.
#[test]
fn bip341_keypath_vectors_match_spec_digests() -> Result<()> {
    let vectors = load_json("bip341-wallet-test-vectors.json")?;
    let spending = vectors["keyPathSpending"]
        .as_array()
        .expect("keyPathSpending array");

    let mut checked = 0_usize;
    for case in spending {
        let tx_bytes = hex_decode(case["given"]["rawUnsignedTx"].as_str().expect("raw tx"));
        let tx = deserialize::<NativeTx>(&tx_bytes)
            .unwrap_or_else(|error| panic!("bip341: native decode failed: {error}"));
        let prevouts: Vec<TxOut> = case["given"]["utxosSpent"]
            .as_array()
            .expect("utxosSpent array")
            .iter()
            .map(|utxo| TxOut {
                value: Amount::from_sat(utxo["amountSats"].as_u64().expect("amount sats")),
                script_pubkey: Script::from_bytes(hex_decode(
                    utxo["scriptPubKey"].as_str().expect("script pubkey"),
                )),
            })
            .collect();

        let mut cache = SighashCache::new(&tx);
        for input in case["inputSpending"]
            .as_array()
            .expect("inputSpending array")
        {
            let index = usize::try_from(input["given"]["txinIndex"].as_u64().expect("txin index"))
                .expect("txin index fits usize");
            let hash_type = input["given"]["hashType"].as_u64().expect("hash type");
            let expected = input["intermediary"]["sigHash"]
                .as_str()
                .expect("sigHash hex");
            let ty = taproot_hash_type(u8::try_from(hash_type).expect("hash type fits u8"));

            let digest = cache
                .taproot_signature_hash(index, &prevouts, None, None, ty)
                .unwrap_or_else(|error| {
                    panic!("bip341 keypath input {index} type {hash_type:#x}: {error}")
                });
            assert_eq!(
                digest_hex(&digest),
                expected,
                "bip341 keypath input {index} hash type {hash_type:#x}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "bip341 keypath vectors must not be vacuous");
    Ok(())
}

/// The wallet vectors never construct a non-default transaction; build one
/// fixture transaction for the structural sweep so the vector gate cannot
/// silently degrade into a no-op when testdata moves.
#[test]
fn bip_vectors_fixture_transaction_round_trip() -> Result<()> {
    let tx = fixture_tx();
    let bytes = bitcoin_rs_primitives::consensus_bytes(&tx);
    let decoded = deserialize::<NativeTx>(&bytes)?;
    assert_eq!(decoded, tx);
    Ok(())
}

fn fixture_tx() -> NativeTx {
    NativeTx {
        version: 2,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::new(
                bitcoin_rs_primitives::Txid::default(),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: bitcoin_rs_primitives::LockTime::ZERO,
    }
}
