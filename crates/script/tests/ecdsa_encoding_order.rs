//! ECDSA encoding-order regressions against Bitcoin Core.
//!
//! Empty ECDSA signatures are a clean verification failure, but Core still
//! applies public-key encoding checks before reaching cryptographic verification.

#![expect(clippy::expect_used, reason = "fixed regression fixtures")]

use bitcoin_rs_primitives::{Tx, TxOut, deserialize};
use bitcoin_rs_script::checker::{SigVersion, TxSignatureChecker};
use bitcoin_rs_script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use sha2::{Digest, Sha256};

const TX_HEX: &str = concat!(
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57",
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85",
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2",
    "f0167faa815988ac11000000",
);
const TEST_KEY: &str = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const PROGRAM: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
const VALUE: u64 = 600_000_000;
const INPUT: usize = 1;

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("hex byte")
        })
        .collect()
}

fn fixture() -> Tx {
    deserialize(&hex(TX_HEX)).expect("native fixture decode")
}

fn test_key() -> SecretKey {
    SecretKey::from_slice(&hex(TEST_KEY)).expect("public BIP143 test key")
}

fn p2wpkh_prevout() -> TxOut {
    TxOut {
        value: VALUE,
        script_pubkey: hex(PROGRAM),
    }
}

fn negative_check_script(pubkey: &[u8], multisig: bool) -> Vec<u8> {
    assert!(pubkey.len() <= 75);
    let mut script = Vec::new();
    if multisig {
        script.push(0x51); // one signature
    }
    script.push(u8::try_from(pubkey.len()).expect("short test pubkey"));
    script.extend_from_slice(pubkey);
    if multisig {
        script.push(0x51); // one key
    }
    script.push(if multisig { 0xae } else { 0xac }); // CHECKMULTISIG / CHECKSIG
    script.push(0x91); // NOT: clean signature failure succeeds; encoding errors do not.
    script
}

#[test]
fn empty_signature_cannot_bypass_legacy_key_encoding() {
    let tx = fixture();
    for multisig in [false, true] {
        let script = negative_check_script(&[], multisig);
        let prevout = TxOut {
            value: VALUE,
            script_pubkey: script.clone(),
        };
        let script_sig = if multisig {
            vec![0x00, 0x00]
        } else {
            vec![0x00]
        };
        assert_eq!(
            Interpreter.execute(
                &script,
                &script_sig,
                &[],
                VerifyFlags::NONE,
                &prevout,
                &tx,
                INPUT,
            ),
            Ok(true),
        );
        assert_eq!(
            Interpreter.execute(
                &script,
                &script_sig,
                &[],
                VerifyFlags::STRICTENC,
                &prevout,
                &tx,
                INPUT,
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::PubkeyType,
            }),
        );
    }
}

#[test]
fn empty_signature_cannot_bypass_witness_compressed_key_policy() {
    let tx = fixture();
    let uncompressed =
        PublicKey::from_secret_key(SECP256K1, &test_key()).serialize_uncompressed();
    for multisig in [false, true] {
        let script = negative_check_script(&uncompressed, multisig);
        let mut program = vec![0x00, 0x20]; // witness v0, 32-byte script hash
        program.extend_from_slice(&Sha256::digest(&script));
        let prevout = TxOut {
            value: VALUE,
            script_pubkey: program,
        };
        let mut witness = vec![Vec::new()];
        if multisig {
            witness.push(Vec::new());
        }
        witness.push(script);
        assert_eq!(
            Interpreter.execute(
                &prevout.script_pubkey,
                &[],
                &witness,
                VerifyFlags::MANDATORY,
                &prevout,
                &tx,
                INPUT,
            ),
            Ok(true),
        );
        assert_eq!(
            Interpreter.execute(
                &prevout.script_pubkey,
                &[],
                &witness,
                VerifyFlags::MANDATORY.union(VerifyFlags::WITNESS_PUBKEYTYPE),
                &prevout,
                &tx,
                INPUT,
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::WitnessPubkeyType,
            }),
        );
    }
}

#[test]
fn encoding_error_precedence_matches_core() {
    let tx = fixture();
    let prevouts = vec![p2wpkh_prevout(); tx.inputs.len()];
    let mut checker = TxSignatureChecker::new(&tx, INPUT, VALUE, &prevouts);
    for version in [SigVersion::Base, SigVersion::WitnessV0] {
        assert_eq!(
            checker.check_ecdsa_signature(&[], &[], &[], version, VerifyFlags::DERSIG),
            Ok(false),
        );
        assert_eq!(
            checker.check_ecdsa_signature(&[], &[], &[], version, VerifyFlags::STRICTENC),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::PubkeyType,
            }),
        );
        assert_eq!(
            checker.check_ecdsa_signature(&[0], &[], &[], version, VerifyFlags::STRICTENC),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::SigDer,
            }),
        );
    }
    let flags = VerifyFlags::STRICTENC.union(VerifyFlags::WITNESS_PUBKEYTYPE);
    assert_eq!(
        checker.check_ecdsa_signature(&[], &[], &[], SigVersion::WitnessV0, flags),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::PubkeyType,
        }),
    );
}
