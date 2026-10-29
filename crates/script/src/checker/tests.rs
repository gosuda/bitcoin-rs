#![expect(clippy::expect_used, reason = "test assertions")]
use bitcoin::hex::FromHex;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, SighashCache, Tx, TxIn, TxOut, Txid,
    Witness, deserialize,
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};

use super::{
    LOCKTIME_THRESHOLD, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_TYPE_FLAG, SigVersion, TxSignatureChecker,
};
use crate::eval::{OP_CODESEPARATOR, remove_all};
use crate::interpreter::{ScriptErrCode, ScriptError, VerifyFlags};

fn make_tx(version: u32, lock_time: u32, sequence: u32) -> Tx {
    Tx {
        version,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(lock_time),
    }
}

fn make_prevouts() -> Vec<TxOut> {
    vec![TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::new(),
    }]
}

fn low_s_der(hashtype: u8) -> Vec<u8> {
    let mut sig = vec![0x30, 0x44, 0x02, 0x20];
    sig.extend_from_slice(&[0x01; 32]);
    sig.extend_from_slice(&[0x02, 0x20]);
    sig.extend_from_slice(&[0x01; 32]);
    sig.push(hashtype);
    sig
}

fn high_s_der() -> Vec<u8> {
    let mut sig = vec![0x30, 0x45, 0x02, 0x20];
    sig.extend_from_slice(&[0x01; 32]);
    sig.extend_from_slice(&[0x02, 0x21, 0x00, 0x80]);
    sig.extend_from_slice(&[0x00; 31]);
    sig.push(0x01);
    sig
}

fn invalid(code: ScriptErrCode) -> Result<bool, ScriptError> {
    Err(ScriptError::Invalid { code })
}

type EcdsaCase = (
    &'static str,
    Vec<u8>,
    Vec<u8>,
    SigVersion,
    VerifyFlags,
    Result<bool, ScriptError>,
);

fn ecdsa_encoding_cases() -> [EcdsaCase; 10] {
    const COMPRESSED: [u8; 33] = [0x02; 33];
    const UNCOMPRESSED: [u8; 65] = [0x04; 65];
    const BAD_PREFIX: [u8; 33] = [0x05; 33];
    let dersig = VerifyFlags::DERSIG;
    [
        (
            "DERSIG rejects a non-DER signature",
            vec![0x00, 0x01, 0x02, 0x03, 0x01],
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig,
            invalid(ScriptErrCode::SigDer),
        ),
        (
            "LOW_S rejects a high-S signature",
            high_s_der(),
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig.union(VerifyFlags::LOW_S),
            invalid(ScriptErrCode::SigHighS),
        ),
        (
            "STRICTENC rejects an undefined hashtype",
            low_s_der(0x05),
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig.union(VerifyFlags::STRICTENC),
            invalid(ScriptErrCode::SigHashtype),
        ),
        (
            "STRICTENC rejects an unknown pubkey prefix",
            low_s_der(0x01),
            BAD_PREFIX.to_vec(),
            SigVersion::Base,
            dersig.union(VerifyFlags::STRICTENC),
            invalid(ScriptErrCode::PubkeyType),
        ),
        (
            "WITNESS_PUBKEYTYPE rejects an uncompressed key in segwit",
            low_s_der(0x01),
            UNCOMPRESSED.to_vec(),
            SigVersion::WitnessV0,
            dersig.union(VerifyFlags::WITNESS_PUBKEYTYPE),
            invalid(ScriptErrCode::WitnessPubkeyType),
        ),
        (
            "an uncompressed key is fine in segwit without the flag",
            low_s_der(0x01),
            UNCOMPRESSED.to_vec(),
            SigVersion::WitnessV0,
            dersig,
            Ok(false),
        ),
        (
            "an empty signature is a clean false under DERSIG",
            Vec::new(),
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig,
            Ok(false),
        ),
        (
            "an empty signature is a clean false under NULLFAIL",
            Vec::new(),
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig.union(VerifyFlags::NULLFAIL),
            Ok(false),
        ),
        (
            "a failing signature is false without NULLFAIL",
            low_s_der(0x01),
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig.union(VerifyFlags::LOW_S),
            Ok(false),
        ),
        (
            "the checker does not enforce NULLFAIL for a failing signature",
            low_s_der(0x01),
            COMPRESSED.to_vec(),
            SigVersion::Base,
            dersig
                .union(VerifyFlags::LOW_S)
                .union(VerifyFlags::NULLFAIL),
            Ok(false),
        ),
    ]
}

#[test]
fn ecdsa_encoding_rules_match_core_per_flag() {
    for (name, sig, pubkey, sigversion, flags, expected) in ecdsa_encoding_cases() {
        for script_code in [[].as_slice(), &[0x51]] {
            let tx = make_tx(2, 0, SEQUENCE_FINAL);
            let prevouts = make_prevouts();
            let cache = SighashCache::new(&tx);
            let checker =
                TxSignatureChecker::new(&tx, 0, Amount::from_sat(50_000), &prevouts, &cache, None);
            let got = checker.check_ecdsa_signature(&sig, &pubkey, script_code, sigversion, flags);
            assert_eq!(got, expected, "{name}");
        }
    }
}

#[test]
fn check_locktime_follows_bip65() {
    let timestamp = i64::from(LOCKTIME_THRESHOLD) + 100;
    let cases = [
        (
            "a lower block-height locktime is satisfied",
            100_u32,
            0_u32,
            50_i64,
            true,
        ),
        (
            "an equal block-height locktime is satisfied",
            100,
            0,
            100,
            true,
        ),
        (
            "a locktime above the transaction's fails",
            100,
            0,
            101,
            false,
        ),
        (
            "a timestamp request against a height locktime fails",
            100,
            0,
            timestamp,
            false,
        ),
        (
            "a height request against a timestamp locktime fails",
            u32::try_from(timestamp).unwrap_or(0),
            0,
            50,
            false,
        ),
        ("a finalized input fails", 100, SEQUENCE_FINAL, 50, false),
    ];

    for (name, tx_locktime, sequence, required, expected) in cases {
        let tx = make_tx(2, tx_locktime, sequence);
        let prevouts = make_prevouts();
        let cache = SighashCache::new(&tx);
        let checker =
            TxSignatureChecker::new(&tx, 0, Amount::from_sat(50_000), &prevouts, &cache, None);
        assert_eq!(checker.check_locktime(required), expected, "{name}");
    }
}

#[test]
fn check_sequence_follows_bip112() {
    let cases = [
        (
            "a lower relative locktime is satisfied",
            2_u32,
            100_u32,
            50_i64,
            true,
        ),
        ("an equal relative locktime is satisfied", 2, 100, 100, true),
        (
            "a relative locktime above the input's fails",
            2,
            100,
            101,
            false,
        ),
        ("version 1 disables relative locktime", 1, 100, 50, false),
        (
            "the input's disable bit fails the check",
            2,
            0x64 | SEQUENCE_LOCKTIME_DISABLE_FLAG,
            50,
            false,
        ),
        (
            "a time-based request against a height-based input fails",
            2,
            100,
            i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG) + 50,
            false,
        ),
    ];

    for (name, version, sequence, required, expected) in cases {
        let tx = make_tx(version, 0, sequence);
        let prevouts = make_prevouts();
        let cache = SighashCache::new(&tx);
        let checker =
            TxSignatureChecker::new(&tx, 0, Amount::from_sat(50_000), &prevouts, &cache, None);
        assert_eq!(checker.check_sequence(required), expected, "{name}");
    }
}

#[test]
fn sighash_json_corpus_legacy_path() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../consensus/tests/vectors/sighash.json");
    let json_str = std::fs::read_to_string(&corpus)
        .unwrap_or_else(|error| panic!("sighash.json unreadable at {}: {error}", corpus.display()));
    let json_str = json_str.as_str();
    let data: sonic_rs::Value =
        sonic_rs::from_str(json_str).unwrap_or_else(|e| panic!("sighash.json parse: {e}"));

    let rows = data.as_array().expect("sighash.json is an array");
    let mut tested = 0_u32;

    for row in rows {
        let Some(arr) = row.as_array().filter(|a| a.len() == 5) else {
            continue;
        };

        let tx_hex = arr
            .first()
            .and_then(sonic_rs::Value::as_str)
            .expect("tx hex");
        let script_hex = arr
            .get(1)
            .and_then(sonic_rs::Value::as_str)
            .expect("script hex");
        let input_index = usize::try_from(
            arr.get(2)
                .and_then(sonic_rs::Value::as_u64)
                .expect("input index"),
        )
        .expect("input index fits in usize");
        let hashtype_raw = arr
            .get(3)
            .and_then(sonic_rs::Value::as_i64)
            .expect("hashtype");
        let expected_hex = arr
            .get(4)
            .and_then(sonic_rs::Value::as_str)
            .expect("expected hash");

        let tx_bytes = hex_decode(tx_hex);
        let tx = deserialize::<Tx>(&tx_bytes)
            .unwrap_or_else(|e| panic!("tx decode at row {tested}: {e}"));

        let script_code = remove_all(&hex_decode(script_hex), &[OP_CODESEPARATOR]).0;

        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "Core casts int nHashType to uint32_t (bit-preserving)"
        )]
        let hashtype_u32 = hashtype_raw as i32 as u32;

        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(input_index, &script_code, hashtype_u32)
            .unwrap_or_else(|e| panic!("legacy sighash at row {tested}: {e}"));

        let expected = Hash256::from_str_be(expected_hex)
            .unwrap_or_else(|e| panic!("expected hash parse at row {tested}: {e}"));

        assert_eq!(
            sighash.to_le_bytes(),
            expected.to_le_bytes(),
            "sighash mismatch at row {tested} (hashtype={hashtype_raw:#x}, index={input_index})"
        );

        tested += 1;
    }

    assert!(tested > 0, "no sighash.json rows were tested");
}

#[test]
fn script_err_code_display_matches_core_names() {
    use super::super::interpreter::ScriptErrCode as E;
    assert_eq!(E::EvalFalse.to_string(), "EVAL_FALSE");
    assert_eq!(E::SigDer.to_string(), "SIG_DER");
    assert_eq!(
        E::WitnessProgramMismatch.to_string(),
        "WITNESS_PROGRAM_MISMATCH"
    );
    assert_eq!(E::SigHighS.to_string(), "SIG_HIGH_S");
    assert_eq!(E::SigNullFail.to_string(), "SIG_NULLFAIL");
    assert_eq!(E::SchnorrSig.to_string(), "SCHNORR_SIG");
    assert_eq!(E::ScriptNum.to_string(), "SCRIPTNUM");
}

fn hex_decode(s: &str) -> Vec<u8> {
    Vec::from_hex(s).unwrap_or_else(|error| panic!("bad hex: {error}"))
}
