//! ECDSA encoding-order regressions against Bitcoin Core.
//!
//! Originally anchored to Core v29.0; rechecked against v31.1 below.
//! Empty ECDSA signatures are a clean verification failure, but Core still
//! applies public-key encoding checks before reaching cryptographic verification.
//!
//! Reference: bitcoin/bitcoin v31.1, src/script/interpreter.cpp, Git blob
//! 443714ceedaf6b0cc695316882080f79fb50316e: CheckSignatureEncoding,
//! CheckPubKeyEncoding, EvalChecksigPreTapscript, and EvalScript's
//! OP_CHECKMULTISIG loop. Assertions follow that reference's ordering and
//! distinguish structural key policy from elliptic-curve point validity.

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

fn verify_witness(
    tx: &Tx,
    prevout: &TxOut,
    witness: &[Vec<u8>],
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    Interpreter.execute(
        &prevout.script_pubkey,
        &[],
        witness,
        flags,
        prevout,
        tx,
        INPUT,
    )
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
    script.push(0x91); // NOT: a clean signature failure succeeds; an encoding error cannot.
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
                &script, &script_sig, &[], VerifyFlags::NONE, &prevout, &tx, INPUT,
            ),
            Ok(true),
        );
        assert_eq!(
            Interpreter.execute(
                &script, &script_sig, &[], VerifyFlags::STRICTENC, &prevout, &tx, INPUT,
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
            verify_witness(&tx, &prevout, &witness, VerifyFlags::MANDATORY),
            Ok(true),
        );
        assert_eq!(
            verify_witness(
                &tx,
                &prevout,
                &witness,
                VerifyFlags::MANDATORY.union(VerifyFlags::WITNESS_PUBKEYTYPE),
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

#[test]
fn empty_signature_key_policy_matrix_preserves_clean_false_and_error_order() {
    let tx = fixture();
    let prevouts = vec![p2wpkh_prevout(); tx.inputs.len()];
    let public = PublicKey::from_secret_key(SECP256K1, &test_key());
    let mut hybrid = public.serialize_uncompressed().to_vec();
    hybrid[0] = 0x06 | (hybrid[64] & 1);
    let mut invalid_point = vec![0xff; 33];
    invalid_point[0] = 0x02; // structurally compressed; x is outside the curve field
    // Columns are STRICTENC shape validity and compressed-key shape validity.
    let keys = [
        (Vec::new(), false, false),
        (vec![0x02; 32], false, false),
        (vec![0x05; 33], false, false),
        (public.serialize().to_vec(), true, true),
        (public.serialize_uncompressed().to_vec(), true, false),
        (hybrid, false, false),
        (invalid_point, true, true),
    ];
    let policy_bits = [
        VerifyFlags::STRICTENC,
        VerifyFlags::WITNESS_PUBKEYTYPE,
        VerifyFlags::DERSIG,
        VerifyFlags::LOW_S,
        VerifyFlags::NULLFAIL,
    ];
    let mut checked = 0;
    for version in [SigVersion::Base, SigVersion::WitnessV0] {
        for mask in 0_u32..32 {
            let mut flags = VerifyFlags::NONE;
            for (bit, flag) in policy_bits.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    flags = flags.union(*flag);
                }
            }
            for (key, strict_shape, compressed) in &keys {
                let expected = if flags.contains(VerifyFlags::STRICTENC) && !*strict_shape {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::PubkeyType,
                    })
                } else if version == SigVersion::WitnessV0
                    && flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
                    && !*compressed
                {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::WitnessPubkeyType,
                    })
                } else {
                    Ok(false)
                };
                let mut checker = TxSignatureChecker::new(&tx, INPUT, VALUE, &prevouts);
                assert_eq!(
                    checker.check_ecdsa_signature(&[], key, &[], version, flags),
                    expected,
                    "version={version:?}, flags={flags:?}, key={key:02x?}",
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 448);
}

#[test]
fn undefined_hashtype_precedes_bad_pubkey_encoding() {
    let tx = fixture();
    let prevouts = vec![p2wpkh_prevout(); tx.inputs.len()];
    // DER r=1, s=1 is structurally valid and low-S; 0x05 is undefined.
    let signature = hex("300602010102010105");
    let flags = VerifyFlags::STRICTENC
        .union(VerifyFlags::WITNESS_PUBKEYTYPE)
        .union(VerifyFlags::LOW_S);
    for version in [SigVersion::Base, SigVersion::WitnessV0] {
        let mut checker = TxSignatureChecker::new(&tx, INPUT, VALUE, &prevouts);
        assert_eq!(
            checker.check_ecdsa_signature(&signature, &[], &[], version, flags),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::SigHashtype,
            }),
        );
    }
}

#[test]
fn unvisited_keys_and_unexecuted_sigops_do_not_trigger_encoding_checks() {
    let tx = fixture();
    let flags = VerifyFlags::MANDATORY
        .union(VerifyFlags::STRICTENC)
        .union(VerifyFlags::WITNESS_PUBKEYTYPE)
        .union(VerifyFlags::NULLFAIL);
    // Zero-of-one CHECKMULTISIG never visits the empty pubkey. An inactive
    // CHECKSIG branch must not check either encoding or stack operands.
    let cases = [
        (vec![0x00, 0x00, 0x51, 0xae], vec![Vec::new()]),
        (vec![0x00, 0x63, 0xac, 0x68, 0x51], Vec::new()),
    ];
    for (script, arguments) in cases {
        let prevout = TxOut {
            value: VALUE,
            script_pubkey: script.clone(),
        };
        let script_sig = vec![0x00; arguments.len()];
        assert_eq!(
            Interpreter.execute(&script, &script_sig, &[], flags, &prevout, &tx, INPUT),
            Ok(true),
        );
        let mut program = vec![0x00, 0x20];
        program.extend_from_slice(&Sha256::digest(&script));
        let witness_prevout = TxOut {
            value: VALUE,
            script_pubkey: program,
        };
        let mut witness = arguments;
        witness.push(script);
        assert_eq!(
            Interpreter.execute(
                &witness_prevout.script_pubkey,
                &[],
                &witness,
                flags,
                &witness_prevout,
                &tx,
                INPUT,
            ),
            Ok(true),
        );
    }
}
