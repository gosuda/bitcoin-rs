//! Property tests for native taproot key-path execution over signed spends.
//!
//! The signing side deliberately uses rust-bitcoin's sighash + Schnorr APIs as
//! an independent oracle: if the native interpreter's BIP341 digest diverged,
//! these spends would stop verifying.

use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount as OracleAmount, OutPoint, ScriptBuf, Sequence as OracleSequence, Transaction, TxIn,
    TxOut as OracleTxOut, Txid, Witness as OracleWitness, absolute, transaction,
};
use bitcoin_rs_primitives::{Tx, TxOut};
use bitcoin_rs_script::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
use proptest::prelude::*;

/// Consensus-bytes round-trip from the rust-bitcoin oracle types to native types.
fn to_native(tx: &Transaction) -> Tx {
    let bytes = bitcoin::consensus::serialize(tx);
    bitcoin_rs_primitives::deserialize(&bytes)
        .unwrap_or_else(|error| panic!("oracle transaction must decode natively: {error}"))
}

fn to_native_prevout(prevout: &OracleTxOut) -> TxOut {
    TxOut {
        value: bitcoin_rs_primitives::Amount::from_sat(prevout.value.to_sat()),
        script_pubkey: prevout.script_pubkey.as_bytes().to_vec().into(),
    }
}

proptest! {
    #[test]
    fn random_valid_p2tr_keypath_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2tr(byte) else {
            return Ok(());
        };
        let input = &fixture.tx.inputs[0];
        let witness = input.witness.clone();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            &fixture.prevout.script_pubkey,
            &input.script_sig,
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx,
            0,
        );
        prop_assert_eq!(ok, Ok(true));
    }

    #[test]
    fn random_p2tr_keypath_spends_with_extra_witness_items_fail(
        byte in 1u8..=127,
        extra in prop::collection::vec(any::<u8>(), 0..=80),
    ) {
        let Some(fixture) = signed_p2tr(byte) else {
            return Ok(());
        };
        let mut witness = fixture.tx.inputs[0].witness.clone();
        witness.push(extra);
        let input = &fixture.tx.inputs[0];
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            &fixture.prevout.script_pubkey,
            &input.script_sig,
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx,
            0,
        );
        // With script-path now implemented, a two-element witness with a
        // bogus extra element is rejected. When the extra starts with 0x50
        // (ANNEX_TAG) it is stripped as an annex, leaving a key-path spend
        // whose signature fails verification. Otherwise it is treated as a
        // control block and rejected for wrong size or commitment mismatch.
        prop_assert!(
            matches!(
                ok,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::TaprootWrongControlSize
                        | ScriptErrCode::WitnessProgramMismatch
                        | ScriptErrCode::WitnessProgramWitnessEmpty,
                }
                | ScriptError::Verification(_))
            ),
            "expected rejection, got {ok:?}"
        );
    }

}

/// Valid multi-input taproot key-path spend must verify once all prevouts are supplied.
///
/// Before the prevout-threading fix this fails with `TaprootPrevoutsUnavailable` because
/// `Interpreter::execute` only receives the single input's prevout.
#[test]
fn valid_multi_input_taproot_keypath_spend_executes() {
    let Some((oracle_tx, oracle_prevouts)) = signed_multi_input_p2tr([1, 2]) else {
        return;
    };
    let tx = to_native(&oracle_tx);
    let prevouts: Vec<TxOut> = oracle_prevouts.iter().map(to_native_prevout).collect();
    let interpreter = Interpreter;
    for (input_idx, prevout) in prevouts.iter().enumerate() {
        let witness = tx.inputs[input_idx].witness.clone();
        let ok = interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &tx.inputs[input_idx].script_sig,
            &witness,
            VerifyFlags::MANDATORY,
            &prevouts,
            &tx,
            input_idx,
        );
        assert_eq!(ok, Ok(true), "input {input_idx}");
    }
}

struct SpendFixture {
    prevout: TxOut,
    tx: Tx,
}

fn signed_p2tr(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
    let (output_key, _) = tweaked.public_parts();
    let prevout = OracleTxOut {
        value: OracleAmount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
    };
    let mut tx = unsigned_spend(byte);
    let prevouts = [prevout.clone()];
    let mut cache = SighashCache::new(&tx);
    let Ok(sighash) = cache.taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        TapSighashType::Default,
    ) else {
        return None;
    };
    let message = Message::from_digest(*sighash.as_byte_array());
    let signature = secp.sign_schnorr(&message, tweaked.as_keypair());
    tx.input[0].witness = OracleWitness::from_slice(&[signature.serialize().to_vec()]);
    Some(SpendFixture {
        prevout: to_native_prevout(&prevout),
        tx: to_native(&tx),
    })
}

/// Builds a two-input taproot key-path transaction signed with BIP341 `Prevouts::All`.
///
/// Signatures are produced with rust-bitcoin sighash/schnorr APIs independently of the
/// interpreter under test.
fn signed_multi_input_p2tr(seeds: [u8; 2]) -> Option<(Transaction, Vec<OracleTxOut>)> {
    let secp = Secp256k1::new();
    let mut keypairs = Vec::with_capacity(seeds.len());
    let mut prevouts = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let secret = secret_key(seed)?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
        let (output_key, _) = tweaked.public_parts();
        prevouts.push(OracleTxOut {
            value: OracleAmount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        });
        keypairs.push(tweaked);
    }

    let mut tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: seeds
            .iter()
            .enumerate()
            .map(|(index, seed)| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([*seed; 32]),
                    vout: u32::try_from(index).unwrap_or_else(|_| panic!("input index fits u32")),
                },
                script_sig: ScriptBuf::new(),
                sequence: OracleSequence::MAX,
                witness: OracleWitness::new(),
            })
            .collect(),
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(99_000),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }],
    };

    for (input_idx, keypair) in keypairs.iter().enumerate() {
        let mut cache = SighashCache::new(&tx);
        let Ok(sighash) = cache.taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        ) else {
            return None;
        };
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = secp.sign_schnorr(&message, keypair.as_keypair());
        tx.input[input_idx].witness = OracleWitness::from_slice(&[signature.serialize().to_vec()]);
    }

    Some((tx, prevouts))
}

fn unsigned_spend(byte: u8) -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([byte; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(49_000),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }],
    }
}

fn secret_key(byte: u8) -> Option<SecretKey> {
    SecretKey::from_slice(&[byte; 32]).ok()
}
