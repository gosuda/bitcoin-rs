//! Zero-signature multisig boundaries, derived from Bitcoin Core v31.1
//! `src/script/interpreter.cpp`, `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY`.
//!
//! Key count is bounded before matching; zero required signatures never visit
//! a key, but still consume a dummy and enforce NULLDUMMY. This guards against
//! applying the empty-signature encoding fix to keys Core does not examine.

#![expect(clippy::expect_used, reason = "fixed regression fixtures")]

use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut, Txid};
use bitcoin_rs_script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use sha2::{Digest, Sha256};

fn fixture() -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 49_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

fn zero_signature_script(pubkey: &[u8], count: u8, verify_only: bool) -> Vec<u8> {
    assert!(pubkey.len() <= 75);
    let mut script = vec![0x00]; // zero required signatures
    for _ in 0..count {
        script.push(u8::try_from(pubkey.len()).expect("short test key"));
        script.extend_from_slice(pubkey);
    }
    match count {
        0 => script.push(0x00),
        1..=16 => script.push(0x50 + count),
        _ => script.extend_from_slice(&[0x01, count]),
    }
    if verify_only {
        script.extend_from_slice(&[0xaf, 0x51]); // CHECKMULTISIGVERIFY, TRUE
    } else {
        script.push(0xae); // CHECKMULTISIG
    }
    script
}

fn execute_case(
    tx: &Tx,
    script: &[u8],
    dummy: &[u8],
    witness_v0: bool,
) -> Result<bool, ScriptError> {
    let flags = VerifyFlags::MANDATORY
        .union(VerifyFlags::STRICTENC)
        .union(VerifyFlags::WITNESS_PUBKEYTYPE)
        .union(VerifyFlags::NULLFAIL);
    let (script_pubkey, script_sig, witness) = if witness_v0 {
        let mut program = vec![0x00, 0x20];
        program.extend_from_slice(&Sha256::digest(script));
        (program, Vec::new(), vec![dummy.to_vec(), script.to_vec()])
    } else {
        assert!(dummy.len() <= 75);
        let mut unlocking = vec![u8::try_from(dummy.len()).expect("short dummy")];
        unlocking.extend_from_slice(dummy);
        (script.to_vec(), unlocking, Vec::new())
    };
    let prevout = TxOut {
        value: 50_000,
        script_pubkey,
    };
    Interpreter.execute(
        &prevout.script_pubkey,
        &script_sig,
        &witness,
        flags,
        &prevout,
        tx,
        0,
    )
}

#[test]
fn zero_signatures_skip_key_encoding_without_waiving_nulldummy() {
    let tx = fixture();
    let key = SecretKey::from_slice(&[1; 32]).expect("public test key");
    let uncompressed = PublicKey::from_secret_key(SECP256K1, &key)
        .serialize_uncompressed()
        .to_vec();
    let mut checked = 0;
    for pubkey in [Vec::new(), vec![0x05; 33], uncompressed] {
        for count in [0, 1, 2, 20] {
            for verify_only in [false, true] {
                let script = zero_signature_script(&pubkey, count, verify_only);
                for witness_v0 in [false, true] {
                    assert_eq!(
                        execute_case(&tx, &script, &[], witness_v0),
                        Ok(true),
                        "unused keys: count={count}, verify={verify_only}, witness={witness_v0}",
                    );
                    assert_eq!(
                        execute_case(&tx, &script, &[1], witness_v0),
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::SigNullDummy,
                        }),
                        "zero signatures must not waive NULLDUMMY",
                    );
                    checked += 2;
                }
            }
        }
    }
    assert_eq!(checked, 96);
}

#[test]
fn zero_signatures_do_not_waive_the_twenty_key_limit() {
    let tx = fixture();
    for verify_only in [false, true] {
        let script = zero_signature_script(&[], 21, verify_only);
        for witness_v0 in [false, true] {
            assert_eq!(
                execute_case(&tx, &script, &[], witness_v0),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::PubkeyCount,
                }),
            );
        }
    }
}
