//! ECDSA encoding-order regressions against Bitcoin Core v31.1.
//!
//! Empty ECDSA signatures are a clean verification failure, but Core still
//! applies public-key encoding checks before reaching cryptographic verification.
//!
//! Contract: Bitcoin Core v31.1, commit
//! `9be056a8a72b624dae9623b2f7bded92c2a21c91`, `src/script/interpreter.cpp`
//! (blob `443714ceedaf6b0cc695316882080f79fb50316e`): `CheckSignatureEncoding`,
//! `CheckPubKeyEncoding`, `EvalChecksigPreTapscript`, and `OP_CHECKMULTISIG`.
//! The zero-signature multisig case also pins the latter's lazy key checks:
//! keys are checked only while a signature is being matched, not up front.

#![expect(clippy::expect_used, reason = "fixed regression fixtures")]

use bitcoin_rs_primitives::{Amount, Script, Tx, TxOut, deserialize};
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
const VALUE: u64 = 600_000_000;
const INPUT: usize = 1;

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("hex byte")
        })
        .collect()
}

fn fixture() -> Tx {
    deserialize(&hex(TX_HEX)).expect("native fixture decode")
}

fn test_key() -> SecretKey {
    SecretKey::from_slice(&hex(TEST_KEY)).expect("public BIP143 test key")
}

fn verify_witness(
    tx: &Tx,
    prevout: &TxOut,
    witness: &[Vec<u8>],
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    // These legacy/v0 checks read only the selected input's prevout.
    let prevouts = vec![prevout.clone(); tx.inputs.len()];
    Interpreter.execute_with_prevouts(
        &prevout.script_pubkey,
        &[],
        witness,
        flags,
        &prevouts,
        tx,
        INPUT,
    )
}

/// The script context a signature check runs under: a bare `scriptPubKey`
/// exercises the base lane; the same script wrapped in a P2WSH program
/// exercises the witness-v0 lane.
#[derive(Clone, Copy, Debug)]
enum Lane {
    Base,
    WitnessV0,
}

/// Runs `key OP_CHECKSIG OP_NOT` so a clean false becomes script success and
/// an encoding failure surfaces as the checker's `ScriptError` unchanged.
fn check_via_script(
    tx: &Tx,
    key: &[u8],
    sig: &[u8],
    lane: Lane,
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    assert!(key.len() <= 75);
    let mut script = Vec::with_capacity(key.len() + 3);
    script.push(u8::try_from(key.len()).expect("short test pubkey"));
    script.extend_from_slice(key);
    script.push(0xac); // CHECKSIG
    script.push(0x91); // NOT: a clean signature failure succeeds; an encoding error cannot.
    let (script_pubkey, script_sig, witness, effective_flags) = match lane {
        Lane::Base => {
            let mut script_sig = Vec::with_capacity(sig.len() + 1);
            script_sig.push(u8::try_from(sig.len()).expect("short test signature"));
            script_sig.extend_from_slice(sig);
            (script, script_sig, Vec::new(), flags)
        }
        Lane::WitnessV0 => {
            let mut program = vec![0x00, 0x20];
            program.extend_from_slice(&Sha256::digest(&script));
            (
                program,
                Vec::new(),
                vec![sig.to_vec(), script],
                flags.union(VerifyFlags::WITNESS),
            )
        }
    };
    let prevout = TxOut {
        value: Amount::from_sat(VALUE),
        script_pubkey: Script::from_bytes(script_pubkey),
    };
    // These checks read only the selected input's prevout.
    let prevouts = vec![prevout.clone(); tx.inputs.len()];
    Interpreter.execute_with_prevouts(
        &prevout.script_pubkey,
        &script_sig,
        &witness,
        effective_flags,
        &prevouts,
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
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(script.clone()),
        };
        // The test changes only INPUT's script; fill the other slot for the full-set API.
        let prevouts = vec![prevout.clone(); tx.inputs.len()];
        let script_sig = if multisig {
            vec![0x00, 0x00]
        } else {
            vec![0x00]
        };
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &script,
                &script_sig,
                &[],
                VerifyFlags::NONE,
                &prevouts,
                &tx,
                INPUT,
            ),
            Ok(true),
        );
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &script,
                &script_sig,
                &[],
                VerifyFlags::STRICTENC,
                &prevouts,
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
    let uncompressed = PublicKey::from_secret_key(SECP256K1, &test_key()).serialize_uncompressed();
    for multisig in [false, true] {
        let script = negative_check_script(&uncompressed, multisig);
        let mut program = vec![0x00, 0x20]; // witness v0, 32-byte script hash
        program.extend_from_slice(&Sha256::digest(&script));
        let prevout = TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(program),
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
    for lane in [Lane::Base, Lane::WitnessV0] {
        assert_eq!(
            check_via_script(&tx, &[], &[], lane, VerifyFlags::DERSIG),
            Ok(true),
        );
        assert_eq!(
            check_via_script(&tx, &[], &[], lane, VerifyFlags::STRICTENC),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::PubkeyType,
            }),
        );
        assert_eq!(
            check_via_script(&tx, &[], &[0], lane, VerifyFlags::STRICTENC),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::SigDer,
            }),
        );
    }
    let flags = VerifyFlags::STRICTENC.union(VerifyFlags::WITNESS_PUBKEYTYPE);
    assert_eq!(
        check_via_script(&tx, &[], &[], Lane::WitnessV0, flags),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::PubkeyType,
        }),
    );
}

#[test]
fn empty_signature_policy_matrix_preserves_error_order_and_clean_false() {
    let tx = fixture();
    let public = PublicKey::from_secret_key(SECP256K1, &test_key());
    // The last entry is deliberately off-curve but correctly encoded. Empty
    // signatures must not require cryptographic parsing of an unused key.
    let mut off_curve = vec![0xff; 33];
    off_curve[0] = 0x02;
    let keys = [
        (Vec::new(), false, false),
        (vec![0x05; 33], false, false),
        (vec![0x02; 32], false, false),
        (vec![0x02; 65], false, false),
        (public.serialize().to_vec(), true, true),
        (public.serialize_uncompressed().to_vec(), true, false),
        (off_curve, true, true),
    ];
    let policies = [
        VerifyFlags::DERSIG,
        VerifyFlags::LOW_S,
        VerifyFlags::STRICTENC,
        VerifyFlags::WITNESS_PUBKEYTYPE,
        VerifyFlags::NULLFAIL,
        VerifyFlags::NULLDUMMY,
    ];
    for mask in 0..(1_u32 << policies.len()) {
        let mut flags = VerifyFlags::NONE;
        for (index, policy) in policies.iter().enumerate() {
            if mask & (1 << index) != 0 {
                flags = flags.union(*policy);
            }
        }
        for lane in [Lane::Base, Lane::WitnessV0] {
            for (key, strict_valid, compressed) in &keys {
                let expected = if flags.contains(VerifyFlags::STRICTENC) && !strict_valid {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::PubkeyType,
                    })
                } else if matches!(lane, Lane::WitnessV0)
                    && flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE)
                    && !compressed
                {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::WitnessPubkeyType,
                    })
                } else {
                    Ok(true)
                };
                assert_eq!(
                    check_via_script(&tx, key, &[], lane, flags),
                    expected,
                    "mask={mask:#x}, lane={lane:?}, key={key:?}",
                );
            }
        }
    }
}

#[test]
fn zero_signature_multisig_does_not_validate_unexamined_keys() {
    let tx = fixture();
    // 0-of-1 with an empty (invalidly encoded) key; only the dummy is consumed.
    // Hoisting key checks into a pre-scan would incorrectly reject this script.
    let script = vec![0x00, 0x00, 0x51, 0xae];
    let flags = VerifyFlags::MANDATORY
        .union(VerifyFlags::STRICTENC)
        .union(VerifyFlags::WITNESS_PUBKEYTYPE)
        .union(VerifyFlags::NULLFAIL);
    let legacy_prevout = TxOut {
        value: Amount::from_sat(VALUE),
        script_pubkey: Script::from_bytes(script.clone()),
    };
    // The fixture has two inputs, but these checks exercise only INPUT.
    let legacy_prevouts = vec![legacy_prevout; tx.inputs.len()];
    assert_eq!(
        Interpreter.execute_with_prevouts(
            &script,
            &[0x00],
            &[],
            flags,
            &legacy_prevouts,
            &tx,
            INPUT,
        ),
        Ok(true),
    );
    let mut program = vec![0x00, 0x20];
    program.extend_from_slice(&Sha256::digest(&script));
    let witness_prevout = TxOut {
        value: Amount::from_sat(VALUE),
        script_pubkey: Script::from_bytes(program),
    };
    let witness_prevouts = vec![witness_prevout.clone(); tx.inputs.len()];
    assert_eq!(
        Interpreter.execute_with_prevouts(
            &witness_prevout.script_pubkey,
            &[],
            &[Vec::new(), script],
            flags,
            &witness_prevouts,
            &tx,
            INPUT,
        ),
        Ok(true),
    );
}
