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
    bitcoin::hex::FromHex::from_hex(text).expect("valid fixture hex")
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

#[derive(Clone, Copy, Debug)]
enum Lane {
    Base,
    WitnessV0,
}

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
    script.push(0xac);
    script.push(0x91);
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
        script.push(0x51);
    }
    script.push(u8::try_from(pubkey.len()).expect("short test pubkey"));
    script.extend_from_slice(pubkey);
    if multisig {
        script.push(0x51);
    }
    script.push(if multisig { 0xae } else { 0xac });
    script.push(0x91);
    script
}

#[test]
fn empty_signature_cannot_bypass_key_encoding_policy() {
    let tx = fixture();
    let uncompressed = PublicKey::from_secret_key(SECP256K1, &test_key()).serialize_uncompressed();
    let cases = [
        (
            Vec::new(),
            VerifyFlags::STRICTENC,
            ScriptErrCode::PubkeyType,
            false,
        ),
        (
            uncompressed.to_vec(),
            VerifyFlags::WITNESS_PUBKEYTYPE,
            ScriptErrCode::WitnessPubkeyType,
            true,
        ),
    ];
    for (key, policy, code, witness) in cases {
        for multisig in [false, true] {
            let script = negative_check_script(&key, multisig);
            let mut witness_stack = vec![Vec::new()];
            if multisig {
                witness_stack.push(Vec::new());
            }
            witness_stack.push(script.clone());
            let script_sig = if multisig {
                vec![0x00, 0x00]
            } else {
                vec![0x00]
            };
            let baseline = if witness {
                VerifyFlags::MANDATORY
            } else {
                VerifyFlags::NONE
            };
            let run = |flags: VerifyFlags| {
                if witness {
                    let mut program = vec![0x00, 0x20];
                    program.extend_from_slice(&Sha256::digest(&script));
                    let prevout = TxOut {
                        value: Amount::from_sat(VALUE),
                        script_pubkey: Script::from_bytes(program),
                    };
                    verify_witness(&tx, &prevout, &witness_stack, flags)
                } else {
                    let prevout = TxOut {
                        value: Amount::from_sat(VALUE),
                        script_pubkey: Script::from_bytes(script.clone()),
                    };
                    let prevouts = vec![prevout; tx.inputs.len()];
                    Interpreter.execute_with_prevouts(
                        &script,
                        &script_sig,
                        &[],
                        flags,
                        &prevouts,
                        &tx,
                        INPUT,
                    )
                }
            };
            assert_eq!(run(baseline), Ok(true), "multisig={multisig}, {code:?}");
            assert_eq!(
                run(baseline.union(policy)),
                Err(ScriptError::Invalid { code }),
                "multisig={multisig}, {code:?}",
            );
        }
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
                if flags.contains(VerifyFlags::DERSIG)
                    || flags.contains(VerifyFlags::LOW_S)
                    || flags.contains(VerifyFlags::STRICTENC)
                {
                    assert_eq!(
                        check_via_script(&tx, key, &[0], lane, flags),
                        Err(ScriptError::Invalid {
                            code: ScriptErrCode::SigDer,
                        }),
                        "mask={mask:#x}, lane={lane:?}, key={key:?}",
                    );
                }
            }
        }
    }
}

#[test]
fn zero_signature_multisig_does_not_validate_unexamined_keys() {
    let tx = fixture();
    let script = vec![0x00, 0x00, 0x51, 0xae];
    let flags = VerifyFlags::MANDATORY
        .union(VerifyFlags::STRICTENC)
        .union(VerifyFlags::WITNESS_PUBKEYTYPE)
        .union(VerifyFlags::NULLFAIL);
    let legacy_prevout = TxOut {
        value: Amount::from_sat(VALUE),
        script_pubkey: Script::from_bytes(script.clone()),
    };
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
