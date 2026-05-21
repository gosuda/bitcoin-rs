//! Property tests for delegated script execution over signed synthetic spends.

use bitcoin::hashes::Hash as _;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute, transaction,
};
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::{Interpreter, ScriptError, VerifyFlags};
use proptest::prelude::*;

proptest! {
    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn random_valid_p2pkh_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2pkh(byte) else {
            return Ok(());
        };
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &[],
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert_eq!(ok, Ok(true));
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn random_valid_p2wpkh_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2wpkh(byte) else {
            return Ok(());
        };
        let witness = fixture.tx.0.input[0].witness.to_vec();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert_eq!(ok, Ok(true));
    }

    #[test]
    fn random_valid_p2tr_keypath_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2tr(byte) else {
            return Ok(());
        };
        let witness = fixture.tx.0.input[0].witness.to_vec();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
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
        let mut witness = fixture.tx.0.input[0].witness.to_vec();
        witness.push(extra);
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert!(
            matches!(
                ok,
                Err(ScriptError::TaprootUnsupportedWitness { elements: 2 })
            ),
            "expected TaprootUnsupportedWitness with elements=2"
        );
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn random_invalid_empty_witness_fails_for_p2wpkh(byte in 1u8..=127) {
        let Some(mut fixture) = signed_p2wpkh(byte) else {
            return Ok(());
        };
        fixture.tx.0.input[0].witness = Witness::new();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &[],
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert!(matches!(ok, Err(bitcoin_rs_script::ScriptError::Verification(_))));
    }
}

struct SpendFixture {
    prevout: TxOut,
    tx: Tx,
}

fn signed_p2pkh(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let public_key = PublicKey::new(secp_public);
    let script_pubkey = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    };
    let mut tx = unsigned_spend(byte);
    let cache = SighashCache::new(&tx);
    let Ok(sighash) = cache.legacy_signature_hash(
        0,
        prevout.script_pubkey.as_script(),
        EcdsaSighashType::All.to_u32(),
    ) else {
        return None;
    };
    let message = Message::from_digest(*sighash.as_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &secret));
    tx.input[0].script_sig = Builder::new()
        .push_slice(push_bytes(signature.to_vec())?)
        .push_key(&public_key)
        .into_script();
    Some(SpendFixture {
        prevout,
        tx: Tx(tx),
    })
}

fn signed_p2wpkh(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let public_key = PublicKey::new(secp_public);
    let Ok(wpubkey_hash) = public_key.wpubkey_hash() else {
        return None;
    };
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&wpubkey_hash),
    };
    let mut tx = unsigned_spend(byte);
    let mut cache = SighashCache::new(&tx);
    let Ok(sighash) = cache.p2wpkh_signature_hash(
        0,
        prevout.script_pubkey.as_script(),
        prevout.value,
        EcdsaSighashType::All,
    ) else {
        return None;
    };
    let message = Message::from_digest(*sighash.as_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &secret));
    tx.input[0].witness = Witness::from_slice(&[signature.to_vec(), public_key.to_bytes()]);
    Some(SpendFixture {
        prevout,
        tx: Tx(tx),
    })
}

fn signed_p2tr(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
    let (output_key, _) = tweaked.public_parts();
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
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
    tx.input[0].witness = Witness::from_slice(&[signature.serialize().to_vec()]);
    Some(SpendFixture {
        prevout,
        tx: Tx(tx),
    })
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
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }],
    }
}

fn secret_key(byte: u8) -> Option<SecretKey> {
    SecretKey::from_slice(&[byte; 32]).ok()
}

fn push_bytes(bytes: Vec<u8>) -> Option<PushBytesBuf> {
    PushBytesBuf::try_from(bytes).ok()
}
