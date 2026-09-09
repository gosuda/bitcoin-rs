//! BIP341 signature-message and interpreter input-boundary regressions.
//!
//! rust-bitcoin constructs and signs the transactions independently of the
//! native interpreter. Every negative case first verifies its positive control;
//! fixture construction failures panic rather than silently skipping coverage.
//! These tests protect the restored verifier API without reintroducing the
//! removed shared-cache entry point or changing validation defaults.

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut as OracleTxOut, Txid, Witness,
    absolute, transaction,
};
use bitcoin_rs_primitives::{Tx, TxOut};
use bitcoin_rs_script::{Interpreter, ScriptError, VerifyFlags};

fn signed_spend() -> (Tx, Vec<TxOut>) {
    let secp = Secp256k1::new();
    let seeds = [11_u8, 12];
    let mut keys = Vec::new();
    let mut prevouts = Vec::new();
    for seed in seeds {
        let secret = SecretKey::from_slice(&[seed; 32])
            .unwrap_or_else(|error| panic!("fixed secret key: {error}"));
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
        let (output_key, _) = tweaked.public_parts();
        prevouts.push(OracleTxOut {
            value: Amount::from_sat(u64::from(seed) * 10_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        });
        keys.push(tweaked);
    }
    let mut oracle = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: seeds
            .iter()
            .map(|seed| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([*seed; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![OracleTxOut {
            value: Amount::from_sat(229_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    for (index, key) in keys.iter().enumerate() {
        let hash = SighashCache::new(&oracle)
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .unwrap_or_else(|error| panic!("oracle BIP341 digest: {error}"));
        let signature = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(*hash.as_byte_array()),
            key.as_keypair(),
        );
        oracle.input[index].witness = Witness::from_slice(&[signature.serialize()]);
    }
    let tx = bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&oracle))
        .unwrap_or_else(|error| panic!("native decode of oracle transaction: {error}"));
    let prevouts = prevouts
        .iter()
        .map(|prevout| TxOut {
            value: prevout.value.to_sat(),
            script_pubkey: prevout.script_pubkey.as_bytes().to_vec(),
        })
        .collect();
    (tx, prevouts)
}

fn verify(tx: &Tx, prevouts: &[TxOut], index: usize) -> Result<bool, ScriptError> {
    let input = &tx.inputs[index];
    Interpreter.execute_with_prevouts(
        &prevouts[index].script_pubkey,
        &input.script_sig,
        &input.witness,
        VerifyFlags::MANDATORY,
        prevouts,
        tx,
        index,
    )
}

/// BIP341 commits to all ordered spent outputs, including the other input.
#[test]
fn bip341_binds_all_prevouts_and_the_transaction() {
    let (tx, prevouts) = signed_spend();
    for index in 0..tx.inputs.len() {
        assert_eq!(verify(&tx, &prevouts, index), Ok(true), "input {index}");
    }

    let mut altered_prevouts = prevouts.clone();
    altered_prevouts[1].value += 1;
    assert!(verify(&tx, &altered_prevouts, 0).is_err());

    let mut reordered_prevouts = prevouts.clone();
    reordered_prevouts.swap(0, 1);
    // Keep the spent script fixed: only the ordered sighash inputs change.
    let input = &tx.inputs[0];
    assert!(
        Interpreter
            .execute_with_prevouts(
                &prevouts[0].script_pubkey,
                &input.script_sig,
                &input.witness,
                VerifyFlags::MANDATORY,
                &reordered_prevouts,
                &tx,
                0,
            )
            .is_err()
    );

    let mut altered_tx = tx.clone();
    altered_tx.outputs[0].value -= 1;
    assert!(verify(&altered_tx, &prevouts, 0).is_err());
}

/// The replacement-byte contract is documented by [`Interpreter::execute`] in
/// `crates/script/src/interpreter.rs`: supplied witness bytes are verified without
/// changing the caller's transaction.
#[test]
fn supplied_witness_is_verified_without_mutating_the_transaction() {
    let (tx, prevouts) = signed_spend();
    assert_eq!(verify(&tx, &prevouts, 0), Ok(true));
    let witness = tx.inputs[0].witness.clone();
    let mut corrupted_tx = tx.clone();
    corrupted_tx.inputs[0].witness[0][0] ^= 1;
    assert!(verify(&corrupted_tx, &prevouts, 0).is_err());
    let stored_witness = corrupted_tx.inputs[0].witness.clone();
    assert_eq!(
        Interpreter.execute_with_prevouts(
            &prevouts[0].script_pubkey,
            &corrupted_tx.inputs[0].script_sig,
            &witness,
            VerifyFlags::MANDATORY,
            &prevouts,
            &corrupted_tx,
            0,
        ),
        Ok(true)
    );
    assert_eq!(corrupted_tx.inputs[0].witness, stored_witness);
}

/// The [`ScriptError::InputIndexOutOfRange`] contract in
/// `crates/script/src/interpreter.rs` requires [`Interpreter::execute_with_prevouts`]
/// to return the typed error before indexing prevouts.
#[test]
fn invalid_input_index_is_a_typed_error() {
    let (tx, prevouts) = signed_spend();
    assert_eq!(verify(&tx, &prevouts, 0), Ok(true));
    for index in [tx.inputs.len(), usize::MAX] {
        assert_eq!(
            Interpreter.execute_with_prevouts(
                &prevouts[0].script_pubkey,
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &prevouts,
                &tx,
                index,
            ),
            Err(ScriptError::InputIndexOutOfRange {
                index,
                inputs: tx.inputs.len(),
            })
        );
    }
}
