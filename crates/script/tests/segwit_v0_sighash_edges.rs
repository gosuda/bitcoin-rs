//! SegWit-v0 ECDSA sighash regressions against BIP143 and Bitcoin Core.
//!
//! The reference preimage uses rust-bitcoin's wire encoders and the BIP143
//! field-selection rules, never the native sighash implementation. The published
//! BIP143 P2WPKH digest and signature independently anchor that reference.
//! Sources: bitcoin/bips bip-0143.mediawiki blob
//! 5d451c221fa9ef052325c42086b8a7097b942556; bitcoin/bitcoin
//! src/script/interpreter.cpp blob 98b16eca6bcdfb5c98b5f51f6afc42062efb5f01.

#![expect(clippy::expect_used, reason = "fixed regression fixtures")]

use bitcoin::consensus::{deserialize as oracle_decode, encode::VarInt, serialize};
use bitcoin_rs_primitives::{
    Amount, Script, Sighash, SighashCache, SighashError, Tx, TxOut, deserialize,
};
use bitcoin_rs_script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
use secp256k1::{Message, PublicKey, SECP256K1, SecretKey};
use sha2::{Digest, Sha256};

// Public test key and unsigned transaction from the BIP143 native-P2WPKH example.
const TX_HEX: &str = concat!(
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57",
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85",
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2",
    "f0167faa815988ac11000000",
);
const TEST_KEY: &str = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const SCRIPT_CODE: &str = "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac";
const PROGRAM: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
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

fn fixture(outputs: usize) -> (Tx, bitcoin::Transaction) {
    let bytes = hex(TX_HEX);
    let mut native: Tx = deserialize(&bytes).expect("native fixture decode");
    let mut oracle: bitcoin::Transaction = oracle_decode(&bytes).expect("oracle fixture decode");
    native.outputs.truncate(outputs);
    oracle.output.truncate(outputs);
    (native, oracle)
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(bytes)).into()
}

/// BIP143 reference serialization. Raw hash-type bits select fields using the
/// low five bits and bit 7, but ALL 32 bits are appended to the preimage.
fn reference_bip143(
    tx: &bitcoin::Transaction,
    input: usize,
    script: &[u8],
    value: u64,
    raw: u32,
) -> [u8; 32] {
    let anyone = raw & 0x80 != 0;
    let base = raw & 0x1f;
    let mut prevouts = [0_u8; 32];
    let mut sequences = [0_u8; 32];
    let mut outputs = [0_u8; 32];
    if !anyone {
        let bytes: Vec<u8> = tx
            .input
            .iter()
            .flat_map(|input| serialize(&input.previous_output))
            .collect();
        prevouts = double_sha256(&bytes);
    }
    if !anyone && base != 2 && base != 3 {
        let bytes: Vec<u8> = tx
            .input
            .iter()
            .flat_map(|input| serialize(&input.sequence))
            .collect();
        sequences = double_sha256(&bytes);
    }
    if base != 2 && base != 3 {
        let bytes: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
        outputs = double_sha256(&bytes);
    } else if base == 3 {
        if let Some(output) = tx.output.get(input) {
            outputs = double_sha256(&serialize(output));
        }
    }
    let selected = &tx.input[input];
    let mut preimage = serialize(&tx.version);
    preimage.extend_from_slice(&prevouts);
    preimage.extend_from_slice(&sequences);
    preimage.extend(serialize(&selected.previous_output));
    let script_len = u64::try_from(script.len()).expect("script length");
    preimage.extend(serialize(&VarInt(script_len)));
    preimage.extend_from_slice(script);
    preimage.extend_from_slice(&value.to_le_bytes());
    preimage.extend(serialize(&selected.sequence));
    preimage.extend_from_slice(&outputs);
    preimage.extend(serialize(&tx.lock_time));
    preimage.extend_from_slice(&raw.to_le_bytes());
    double_sha256(&preimage)
}

fn test_key() -> SecretKey {
    SecretKey::from_slice(&hex(TEST_KEY)).expect("public BIP143 test key")
}

fn p2wpkh_prevout() -> TxOut {
    TxOut {
        value: Amount::from_sat(VALUE),
        script_pubkey: Script::from_bytes(hex(PROGRAM)),
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

// The optional oracle is a real kernel call, not an availability-based skip.
// Failure to parse or prepare the transaction fails the positive assertion.
// Policy-only flags are intentionally excluded: the wrapper masks them off.
#[cfg(feature = "kernel")]
fn kernel_witness_parity(tx: &Tx, prevout: &TxOut, witness: &[Vec<u8>]) {
    use bitcoin_rs_consensus::{ConsensusError, kernel::verify_tx_scripts};

    let mut signed = tx.clone();
    signed.inputs[INPUT].witness = witness.to_vec();
    // The other input has a synthetic OP_TRUE prevout. This is script-verdict
    // parity, not contextual block validation or a claim about historical UTXOs.
    let mut spent: Vec<_> = signed
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let output = if index == INPUT {
                prevout.clone()
            } else {
                TxOut {
                    value: VALUE,
                    script_pubkey: vec![0x51],
                }
            };
            (input.previous_output, output)
        })
        .collect();
    verify_tx_scripts(&signed, &spent, VerifyFlags::MANDATORY)
        .expect("kernel accepts independently signed BIP143 input");
    // Every BIP143 mode commits to this amount. Ensure the oracle is not
    // vacuously accepting, and require a script rejection, not an engine error.
    spent[INPUT].1.value += 1;
    assert!(matches!(
        verify_tx_scripts(&signed, &spent, VerifyFlags::MANDATORY),
        Err(ConsensusError::Script {
            input_index: INPUT,
            ..
        })
    ));
}

#[test]
fn published_bip143_digest_and_signature_anchor_reference() {
    let (tx, oracle) = fixture(2);
    let script = hex(SCRIPT_CODE);
    let expected = hex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
    assert_eq!(
        reference_bip143(&oracle, INPUT, &script, VALUE, 1).as_slice(),
        expected,
    );
    let mut cache = SighashCache::new(&tx);
    assert_eq!(
        cache
            .segwit_v0_signature_hash_raw(INPUT, &script, Amount::from_sat(VALUE), 1)
            .expect("BIP143 digest")
            .as_byte_array()
            .as_slice(),
        expected,
    );
    let witness = vec![
        hex(concat!(
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a",
            "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
        )),
        hex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"),
    ];
    assert_eq!(
        verify_witness(&tx, &p2wpkh_prevout(), &witness, VerifyFlags::MANDATORY),
        Ok(true),
    );
}

#[test]
fn every_segwit_hashtype_byte_matches_reference_and_verifies() {
    let key = test_key();
    let pubkey = PublicKey::from_secret_key(SECP256K1, &key)
        .serialize()
        .to_vec();
    let script = hex(SCRIPT_CODE);
    let prevout = p2wpkh_prevout();
    for output_count in [1, 2] {
        // input 1 has no matching output in the one-output fixture. SINGLE
        // must still hash a complete BIP143 preimage and allow a valid signature.
        let (tx, oracle) = fixture(output_count);
        let mut cache = SighashCache::new(&tx);
        for byte in 0_u8..=u8::MAX {
            let raw = u32::from(byte);
            let expected = reference_bip143(&oracle, INPUT, &script, VALUE, raw);
            assert_eq!(
                cache
                    .segwit_v0_signature_hash_raw(INPUT, &script, Amount::from_sat(VALUE), raw)
                    .expect("raw BIP143 digest")
                    .as_byte_array(),
                &expected,
                "outputs={output_count}, raw={raw:#x}",
            );
            let message = Message::from_digest(expected);
            let mut signature = SECP256K1
                .sign_ecdsa(&message, &key)
                .serialize_der()
                .to_vec();
            signature.push(byte);
            let witness = vec![signature, pubkey.clone()];
            assert_eq!(
                verify_witness(&tx, &prevout, &witness, VerifyFlags::MANDATORY),
                Ok(true),
                "consensus: outputs={output_count}, raw={raw:#x}",
            );
            let mut wrong_amount = prevout.clone();
            wrong_amount.value = Amount::from_sat(wrong_amount.value.to_sat() + 1);
            assert_eq!(
                verify_witness(&tx, &wrong_amount, &witness, VerifyFlags::MANDATORY),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::EvalFalse,
                }),
                "amount commitment: outputs={output_count}, raw={raw:#x}",
            );
            #[cfg(feature = "kernel")]
            kernel_witness_parity(&tx, &prevout, &witness);
            let strict = VerifyFlags::MANDATORY.union(VerifyFlags::STRICTENC);
            let result = verify_witness(&tx, &prevout, &witness, strict);
            if matches!(byte, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
                assert_eq!(result, Ok(true));
            } else {
                assert_eq!(
                    result,
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::SigHashtype,
                    }),
                );
            }
        }
    }
}

#[test]
fn raw_segwit_hash_commits_all_32_bits_and_checks_input_bounds() {
    let script = hex(SCRIPT_CODE);
    for output_count in [1, 2] {
        let (tx, oracle) = fixture(output_count);
        let mut cache = SighashCache::new(&tx);
        for raw in [0x100, 0x101, 0x1234_5682, 0x8000_0083, u32::MAX] {
            let expected = reference_bip143(&oracle, INPUT, &script, VALUE, raw);
            let actual = cache
                .segwit_v0_signature_hash_raw(INPUT, &script, Amount::from_sat(VALUE), raw)
                .expect("raw u32 digest");
            assert_eq!(actual.as_byte_array(), &expected);
            assert_ne!(
                actual.as_byte_array(),
                &reference_bip143(&oracle, INPUT, &script, VALUE, raw & 0xff),
            );
        }
        assert_eq!(
            cache.segwit_v0_signature_hash_raw(
                tx.inputs.len(),
                &script,
                Amount::from_sat(VALUE),
                0
            ),
            Err(SighashError::InputOutOfRange {
                index: tx.inputs.len(),
                total: tx.inputs.len(),
            }),
        );
    }
}

#[test]
fn typed_segwit_api_preserves_named_modes_and_default_rejection() {
    let script = hex(SCRIPT_CODE);
    let modes = [
        (Sighash::All, 1),
        (Sighash::None, 2),
        (Sighash::Single, 3),
        (Sighash::AllAnyoneCanPay, 0x81),
        (Sighash::NoneAnyoneCanPay, 0x82),
        (Sighash::SingleAnyoneCanPay, 0x83),
    ];
    for output_count in [1, 2] {
        let (tx, oracle) = fixture(output_count);
        let mut cache = SighashCache::new(&tx);
        for (mode, raw) in modes {
            assert_eq!(
                cache
                    .segwit_v0_signature_hash(INPUT, &script, Amount::from_sat(VALUE), mode)
                    .expect("named mode")
                    .as_byte_array(),
                &reference_bip143(&oracle, INPUT, &script, VALUE, raw),
            );
        }
        for input in [INPUT, tx.inputs.len()] {
            assert_eq!(
                cache.segwit_v0_signature_hash(
                    input,
                    &script,
                    Amount::from_sat(VALUE),
                    Sighash::Default
                ),
                Err(SighashError::DefaultOnlyTaproot),
            );
        }
    }
}

// Each script executes its first separator, retains separator-valued pushed
// data, and leaves a later separator in an unexecuted branch. BIP143 commits
// the suffix after the executed separator verbatim (bip-0143, Specification).
fn separator_witness_script(pubkey: &[u8], multisig: bool, verify: bool) -> Vec<u8> {
    let mut script = vec![0xab, 0x02, 0xab, 0xab, 0x75]; // CODESEPARATOR, push, DROP
    if multisig {
        script.push(0x51);
    }
    script.push(u8::try_from(pubkey.len()).expect("short public key"));
    script.extend_from_slice(pubkey);
    if multisig {
        script.push(0x51);
    }
    script.push(match (multisig, verify) {
        (false, false) => 0xac, // CHECKSIG
        (false, true) => 0xad,  // CHECKSIGVERIFY
        (true, false) => 0xae,  // CHECKMULTISIG
        (true, true) => 0xaf,   // CHECKMULTISIGVERIFY
    });
    if verify {
        script.push(0x51); // successful VERIFY still needs a true final stack
    }
    script.extend_from_slice(&[0x00, 0x63, 0xab, 0x68]); // false IF CODESEPARATOR ENDIF
    script
}

#[test]
fn every_hashtype_verifies_all_witness_ecdsa_opcodes_with_separators() {
    let key = test_key();
    let pubkey = PublicKey::from_secret_key(SECP256K1, &key).serialize();
    for (multisig, verify) in [(false, false), (false, true), (true, false), (true, true)] {
        let script = separator_witness_script(&pubkey, multisig, verify);
        let mut program = vec![0x00, 0x20];
        program.extend_from_slice(&Sha256::digest(&script));
        let prevout = TxOut {
            value: Amount::from_sat(VALUE),
            script_pubkey: Script::from_bytes(program),
        };
        let failure = match (multisig, verify) {
            (false, true) => ScriptErrCode::CheckSigVerify,
            (true, true) => ScriptErrCode::CheckMultisigVerify,
            (_, false) => ScriptErrCode::EvalFalse,
        };
        for output_count in [1, 2] {
            let (tx, oracle) = fixture(output_count);
            for byte in 0_u8..=u8::MAX {
                let digest = reference_bip143(&oracle, INPUT, &script[1..], VALUE, u32::from(byte));
                let mut signature = SECP256K1
                    .sign_ecdsa(&Message::from_digest(digest), &key)
                    .serialize_der()
                    .to_vec();
                signature.push(byte);
                let mut witness = Vec::new();
                if multisig {
                    witness.push(Vec::new()); // CHECKMULTISIG dummy, not a signature
                }
                witness.extend([signature, script.clone()]);
                assert_eq!(
                    verify_witness(&tx, &prevout, &witness, VerifyFlags::MANDATORY),
                    Ok(true),
                    "multisig={multisig}, verify={verify}, outputs={output_count}, raw={byte:#x}",
                );
                let mut wrong_amount = prevout.clone();
                wrong_amount.value = Amount::from_sat(wrong_amount.value.to_sat() + 1);
                assert_eq!(
                    verify_witness(&tx, &wrong_amount, &witness, VerifyFlags::MANDATORY),
                    Err(ScriptError::Invalid { code: failure }),
                    "wrong amount: multisig={multisig}, verify={verify}, raw={byte:#x}",
                );
                let strict = VerifyFlags::MANDATORY.union(VerifyFlags::STRICTENC);
                let expected = if matches!(byte, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
                    Ok(true)
                } else {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::SigHashtype,
                    })
                };
                assert_eq!(verify_witness(&tx, &prevout, &witness, strict), expected);
                #[cfg(feature = "kernel")]
                kernel_witness_parity(&tx, &prevout, &witness);
            }
        }
    }
}

#[test]
fn raw_segwit_script_code_is_verbatim_across_compactsize_boundaries() {
    // These are digest-API inputs, not necessarily executable scripts. Mixing
    // scripts, amounts, and modes on one cache must not reuse script-dependent
    // or amount-dependent state. Both CompactSize encodings around 253 matter.
    for output_count in [1, 2] {
        let (tx, oracle) = fixture(output_count);
        let mut cache = SighashCache::new(&tx);
        for size in [0, 1, 252, 253, 520, 10_000] {
            let script = vec![0xab; size];
            for value in [VALUE, VALUE + 1] {
                for raw in [0, 1, 3, 0x83, 0xc2, u32::MAX] {
                    let expected = reference_bip143(&oracle, INPUT, &script, value, raw);
                    assert_eq!(
                        cache
                            .segwit_v0_signature_hash_raw(
                                INPUT,
                                &script,
                                Amount::from_sat(value),
                                raw
                            )
                            .expect("raw script-code digest")
                            .as_byte_array(),
                        &expected,
                        "outputs={output_count}, script_len={size}, value={value}, raw={raw:#x}",
                    );
                }
            }
        }
    }
}
