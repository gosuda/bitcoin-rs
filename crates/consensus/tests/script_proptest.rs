use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount as OracleAmount, OutPoint, ScriptBuf, Sequence as OracleSequence, Transaction, TxIn,
    TxOut as OracleTxOut, Txid, Witness as OracleWitness, absolute, transaction,
};
use bitcoin_rs_consensus::primitives::{Tx, TxOut};
use bitcoin_rs_consensus::script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
use proptest::prelude::*;

fn to_native(tx: &Transaction) -> Tx {
    let bytes = bitcoin::consensus::serialize(tx);
    bitcoin_rs_consensus::primitives::deserialize(&bytes)
        .unwrap_or_else(|error| panic!("oracle transaction must decode natively: {error}"))
}

fn to_native_prevout(prevout: &OracleTxOut) -> TxOut {
    TxOut {
        value: bitcoin_rs_consensus::primitives::Amount::from_sat(prevout.value.to_sat()),
        script_pubkey: prevout.script_pubkey.as_bytes().to_vec().into(),
    }
}

fn proptest_config(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(default_cases);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

fn sighash_type_strategy() -> impl Strategy<Value = TapSighashType> {
    prop_oneof![
        Just(TapSighashType::Default),
        Just(TapSighashType::All),
        Just(TapSighashType::None),
        Just(TapSighashType::Single),
        Just(TapSighashType::AllPlusAnyoneCanPay),
        Just(TapSighashType::NonePlusAnyoneCanPay),
        Just(TapSighashType::SinglePlusAnyoneCanPay),
    ]
}

fn valid_secret_key_strategy() -> impl Strategy<Value = SecretKey> {
    (1u8..=250u8).prop_filter_map("valid key", secret_key)
}

fn taproot_sighash_byte(sighash_type: TapSighashType) -> u8 {
    match sighash_type {
        TapSighashType::Default => 0x00,
        TapSighashType::All => 0x01,
        TapSighashType::None => 0x02,
        TapSighashType::Single => 0x03,
        TapSighashType::AllPlusAnyoneCanPay => 0x81,
        TapSighashType::NonePlusAnyoneCanPay => 0x82,
        TapSighashType::SinglePlusAnyoneCanPay => 0x83,
    }
}

fn serialize_taproot_signature(
    sig: bitcoin::secp256k1::schnorr::Signature,
    sighash_type: TapSighashType,
) -> Vec<u8> {
    let mut bytes = sig.serialize().to_vec();
    if sighash_type != TapSighashType::Default {
        bytes.push(taproot_sighash_byte(sighash_type));
    }
    bytes
}

struct MultiInputFixture {
    tx: Tx,
    prevouts: Vec<TxOut>,
}

fn signed_multi_input_p2tr_with_types(
    keys: &[SecretKey],
    sighash_types: &[TapSighashType],
) -> MultiInputFixture {
    let secp = Secp256k1::new();
    let mut keypairs = Vec::with_capacity(keys.len());
    let mut oracle_prevouts = Vec::with_capacity(keys.len());
    for secret in keys {
        let keypair = Keypair::from_secret_key(&secp, secret);
        let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
        let (output_key, _) = tweaked.public_parts();
        oracle_prevouts.push(OracleTxOut {
            value: OracleAmount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        });
        keypairs.push(tweaked);
    }

    let mut tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: keys
            .iter()
            .enumerate()
            .map(|(index, secret)| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(secret.secret_bytes()),
                    vout: u32::try_from(index).unwrap_or(0),
                },
                script_sig: ScriptBuf::new(),
                sequence: OracleSequence::MAX,
                witness: OracleWitness::new(),
            })
            .collect(),
        output: vec![
            OracleTxOut {
                value: OracleAmount::from_sat(40_000),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
            OracleTxOut {
                value: OracleAmount::from_sat(40_000),
                script_pubkey: Builder::new().push_int(2).into_script(),
            },
            OracleTxOut {
                value: OracleAmount::from_sat(10_000),
                script_pubkey: Builder::new().push_int(3).into_script(),
            },
        ],
    };

    for (input_idx, keypair) in keypairs.iter().enumerate() {
        let sighash_type = sighash_types
            .get(input_idx)
            .copied()
            .unwrap_or(TapSighashType::Default);
        let mut cache = SighashCache::new(&tx);
        let sighash = match cache.taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(&oracle_prevouts),
            sighash_type,
        ) {
            Ok(hash) => hash,
            Err(err) => panic!("oracle taproot sighash failed: {err}"),
        };
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = secp.sign_schnorr(&message, keypair.as_keypair());
        let sig_bytes = serialize_taproot_signature(signature, sighash_type);
        tx.input[input_idx].witness = OracleWitness::from_slice(&[sig_bytes]);
    }

    let native_prevouts = oracle_prevouts.iter().map(to_native_prevout).collect();
    MultiInputFixture {
        tx: to_native(&tx),
        prevouts: native_prevouts,
    }
}

proptest! {
    #![proptest_config(proptest_config(256))]

    #[test]
    fn offensive_p2tr_keypath_spends_execute_with_diverse_sighash_and_inputs(
        keys in prop::collection::vec(valid_secret_key_strategy(), 1..=3),
        sighash_types in prop::collection::vec(sighash_type_strategy(), 1..=3),
        use_standard_flags in any::<bool>(),
    ) {
        let fixture = signed_multi_input_p2tr_with_types(&keys, &sighash_types);
        let interpreter = Interpreter;
        let flags = if use_standard_flags {
            VerifyFlags::STANDARD
        } else {
            VerifyFlags::MANDATORY
        };

        for (input_idx, input) in fixture.tx.inputs.iter().enumerate() {
            let prevout = &fixture.prevouts[input_idx];
            let ok = interpreter.execute_with_prevouts(
                &prevout.script_pubkey,
                &input.script_sig,
                &input.witness,
                flags,
                &fixture.prevouts,
                &fixture.tx,
                input_idx,
            );
            prop_assert_eq!(ok, Ok(true));
        }
    }

    #[test]
    fn offensive_p2tr_keypath_spends_refuse_corrupted_witnesses(
        key in valid_secret_key_strategy(),
        sighash_type in sighash_type_strategy(),
        corruption_mode in 0u8..=7u8,
        extra_bytes in prop::collection::vec(any::<u8>(), 0..=80),
    ) {
        let fixture = signed_multi_input_p2tr_with_types(&[key], &[sighash_type]);
        let interpreter = Interpreter;
        let input = &fixture.tx.inputs[0];
        let prevout = &fixture.prevouts[0];

        let mut mutated_witness = input.witness.clone();
        let mut mutated_script_sig = input.script_sig.clone();
        let expected_code = match corruption_mode {
            0 => {
                mutated_witness.clear();
                ScriptErrCode::WitnessProgramWitnessEmpty
            }
            1 => {
                mutated_witness.clear();
                mutated_witness.push(&[]);
                ScriptErrCode::SchnorrSigSize
            }
            2 => {
                let sig = &input.witness[0];
                let truncated = &sig[..sig.len().saturating_sub(2).min(63)];
                mutated_witness.clear();
                mutated_witness.push(truncated);
                ScriptErrCode::SchnorrSigSize
            }
            3 => {
                let mut overlong = input.witness[0].to_vec();
                overlong.extend_from_slice(&[0x01, 0x02]);
                mutated_witness.clear();
                mutated_witness.push(&overlong);
                ScriptErrCode::SchnorrSigSize
            }
            4 => {
                let mut bad_hashtype = input.witness[0][..64].to_vec();
                bad_hashtype.push(0x00);
                mutated_witness.clear();
                mutated_witness.push(&bad_hashtype);
                ScriptErrCode::SchnorrSigHashtype
            }
            5 => {
                let mut bad_hashtype = input.witness[0][..64].to_vec();
                bad_hashtype.push(0x04);
                mutated_witness.clear();
                mutated_witness.push(&bad_hashtype);
                ScriptErrCode::SchnorrSigHashtype
            }
            6 => {
                let mut corrupted_sig = input.witness[0].to_vec();
                corrupted_sig[0] ^= 0xff;
                mutated_witness.clear();
                mutated_witness.push(&corrupted_sig);
                ScriptErrCode::SchnorrSig
            }
            _ => {
                mutated_script_sig = bitcoin_rs_consensus::primitives::Script::from_bytes(vec![0x51]);
                ScriptErrCode::WitnessMalleated
            }
        };

        let result = interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &mutated_script_sig,
            &mutated_witness,
            VerifyFlags::MANDATORY,
            &fixture.prevouts,
            &fixture.tx,
            0,
        );
        prop_assert_eq!(
            result,
            Err(ScriptError::Invalid { code: expected_code }),
            "corruption_mode={}",
            corruption_mode
        );

        let mut extra_witness = input.witness.clone();
        extra_witness.push(&extra_bytes);
        let extra_result = interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &input.script_sig,
            &extra_witness,
            VerifyFlags::MANDATORY,
            &fixture.prevouts,
            &fixture.tx,
            0,
        );
        prop_assert!(
            matches!(
                extra_result,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::TaprootWrongControlSize
                        | ScriptErrCode::WitnessProgramMismatch
                        | ScriptErrCode::WitnessProgramWitnessEmpty
                        | ScriptErrCode::SchnorrSig,
                })
            ),
            "expected extra witness rejection, got {extra_result:?}"
        );
    }
}

fn secret_key(byte: u8) -> Option<SecretKey> {
    SecretKey::from_slice(&[byte; 32]).ok()
}
