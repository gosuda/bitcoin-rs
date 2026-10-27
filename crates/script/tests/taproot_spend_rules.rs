//! BIP341 wire signature and native witness-program dispatch rules.
#![expect(clippy::expect_used)]

#[path = "support/taproot_spends.rs"]
mod fixture;

use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{Script, Tx, TxOut};
use bitcoin_rs_script::{
    Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, SignatureCache, VerifyFlags,
};

fn prepared(
    tx: &bitcoin::Transaction,
    output: &bitcoin::TxOut,
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    let tx: Tx = bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(tx))
        .expect("native decode");
    let output = TxOut {
        value: bitcoin_rs_primitives::Amount::from_sat(output.value.to_sat()),
        script_pubkey: Script::from_bytes(output.script_pubkey.to_bytes()),
    };
    let rows = vec![(tx.inputs[0].previous_output, output.clone())];
    let result = PreparedTransaction::new(&tx, &rows)
        .expect("ordered complete prevouts")
        .verify_input(0, flags, None);
    let input = &tx.inputs[0];
    assert_eq!(
        result,
        Interpreter.execute_with_prevouts(
            &output.script_pubkey,
            &input.script_sig,
            &input.witness,
            flags,
            std::slice::from_ref(&output),
            &tx,
            0
        )
    );
    result
}

fn output() -> bitcoin::TxOut {
    bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: fixture::funding_script(),
    }
}
fn outpoint() -> bitcoin::OutPoint {
    bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([17; 32]), 0)
}

#[test]
fn native_complete_spends_match_independent_bip341_cases() {
    let prevout = output();
    let mut mismatches = Vec::new();
    for case in fixture::cases(outpoint(), &prevout) {
        for flags in [VerifyFlags::MANDATORY, VerifyFlags::STANDARD] {
            let result = prepared(&case.tx, &prevout, flags);
            if result.is_ok() != case.accepted {
                mismatches.push(format!("{} flags={:?}: {:?}", case.name, flags, result));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "BIP341 mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn appended_default_and_malformed_sighash_bytes_are_explicit_errors() {
    let prevout = output();
    for case in fixture::cases(outpoint(), &prevout) {
        if case.name.starts_with("key-suffix-") {
            assert_eq!(
                prepared(&case.tx, &prevout, VerifyFlags::MANDATORY),
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::SchnorrSigHashtype
                }),
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn script_sig_errors_keep_existing_verification_order() {
    let prevout = output();
    let mut tx = fixture::cases(outpoint(), &prevout).remove(0).tx;
    tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x6a]);
    assert_eq!(
        prepared(&tx, &prevout, VerifyFlags::STANDARD),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::OpReturn
        })
    );
    assert_eq!(
        prepared(
            &tx,
            &prevout,
            VerifyFlags::STANDARD.union(VerifyFlags::SIGPUSHONLY)
        ),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::SigPushonly
        })
    );
    tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x00]);
    assert_eq!(
        prepared(&tx, &prevout, VerifyFlags::STANDARD),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::WitnessMalleated
        })
    );
}

#[test]
fn inactive_taproot_and_wrapped_v1_keep_their_witness_rules() {
    let prevout = output();
    let mut tx = fixture::cases(outpoint(), &prevout).remove(0).tx;
    tx.input[0].witness = bitcoin::Witness::from_slice(&[vec![0_u8]]);
    assert_eq!(prepared(&tx, &prevout, VerifyFlags::WITNESS), Ok(true));
    assert_eq!(
        prepared(
            &tx,
            &prevout,
            VerifyFlags::WITNESS.union(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        ),
        Ok(true),
        "recognized native Taproot is inactive, not an unknown witness program"
    );
    // No witness rules are active; neither annex nor Schnorr encoding is consulted.
    tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x00]);
    assert_eq!(prepared(&tx, &prevout, VerifyFlags::NONE), Ok(true));
    assert_eq!(
        prepared(&tx, &prevout, VerifyFlags::TAPROOT),
        Ok(true),
        "Taproot dispatch still requires witness verification"
    );
    let wrapped = bitcoin::TxOut {
        value: prevout.value,
        script_pubkey: prevout.script_pubkey.to_p2sh(),
    };
    tx.input[0].script_sig = bitcoin::script::Builder::new()
        .push_slice(
            bitcoin::script::PushBytesBuf::try_from(prevout.script_pubkey.to_bytes())
                .expect("witness program push"),
        )
        .into_script();
    assert_eq!(
        prepared(&tx, &wrapped, VerifyFlags::MANDATORY),
        Ok(true),
        "wrapped v1 is not native Taproot"
    );
    assert_eq!(
        prepared(
            &tx,
            &wrapped,
            VerifyFlags::MANDATORY.union(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        ),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::DiscourageUpgradableWitnessProgram
        }),
        "wrapped v1 still follows upgradeable-witness policy"
    );
    let mut unknown = prevout;
    unknown.script_pubkey = bitcoin::ScriptBuf::from_bytes([vec![0x51, 20], vec![1; 20]].concat());
    tx.input[0].script_sig = bitcoin::ScriptBuf::new();
    assert_eq!(
        prepared(
            &tx,
            &unknown,
            VerifyFlags::WITNESS.union(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        ),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::DiscourageUpgradableWitnessProgram
        }),
        "v1 with another program size remains upgradeable"
    );
}

#[test]
fn op_success_overrides_stack_limits_and_final_truth_checks() {
    let prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: fixture::success_funding_script(),
    };
    let mut mismatches = Vec::new();
    for case in fixture::success_cases(outpoint(), &prevout) {
        let result = prepared(&case.tx, &prevout, VerifyFlags::MANDATORY);
        if result.is_ok() != case.accepted {
            mismatches.push(format!("{}: {:?}", case.name, result));
        }
    }
    assert!(
        mismatches.is_empty(),
        "OP_SUCCESS mismatches: {}",
        mismatches.join("\n")
    );
}

/// First accepted key-path spend: a real BIP341 signature over the fixture
/// funding output, usable as-is for cache warm/cold comparisons.
fn first_accepted_key_spend() -> (Tx, TxOut) {
    let prevout = output();
    let case = fixture::cases(outpoint(), &prevout)
        .into_iter()
        .find(|case| case.accepted && case.name.starts_with("key-Default"))
        .expect("fixture carries an accepted key-path Default spend");
    let tx: Tx = bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&case.tx))
        .expect("native decode");
    let output = TxOut {
        value: bitcoin_rs_primitives::Amount::from_sat(prevout.value.to_sat()),
        script_pubkey: Script::from_bytes(prevout.script_pubkey.to_bytes()),
    };
    (tx, output)
}

fn verify_cached(
    tx: &Tx,
    output: &TxOut,
    flags: VerifyFlags,
    cache: Option<&SignatureCache>,
) -> Result<bool, ScriptError> {
    let rows = vec![(tx.inputs[0].previous_output, output.clone())];
    PreparedTransaction::new(tx, &rows)
        .expect("ordered complete prevouts")
        .verify_input(0, flags, cache)
}

#[test]
fn signature_cache_hit_matches_uncached_across_flags() {
    let (tx, output) = first_accepted_key_spend();
    let cache = SignatureCache::new();
    assert_eq!(
        verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
        Ok(true),
        "warmup under MANDATORY"
    );
    assert_eq!(
        verify_cached(&tx, &output, VerifyFlags::STANDARD, Some(&cache)),
        Ok(true),
        "hit under STANDARD matches the uncached accept"
    );
    assert_eq!(
        verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
        Ok(true),
        "repeat hit stays accepting"
    );
}

#[test]
fn signature_cache_warmed_still_rejects_flipped_signature_byte() {
    let (tx, output) = first_accepted_key_spend();
    let cache = SignatureCache::new();
    assert_eq!(
        verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
        Ok(true),
        "warmup"
    );
    let mut bad = tx;
    bad.inputs[0].witness[0][0] ^= 0x01;
    let uncached = verify_cached(&bad, &output, VerifyFlags::MANDATORY, None);
    assert!(
        uncached != Ok(true),
        "flipped Schnorr byte must break uncached verification (else the test is vacuous)"
    );
    assert_eq!(
        verify_cached(&bad, &output, VerifyFlags::MANDATORY, Some(&cache)),
        uncached,
        "cached verdict matches uncached after warming"
    );
}

#[test]
fn signature_cache_warmed_still_rejects_mutated_sighash_input() {
    let (tx, output) = first_accepted_key_spend();
    let cache = SignatureCache::new();
    assert_eq!(
        verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
        Ok(true),
        "warmup"
    );
    // The output value is committed by the BIP341 outputs digest
    // (sha_outputs), so paying one more satoshi to the same output retargets
    // the message without touching encodings.
    let mut retargeted = tx;
    let paid = retargeted.outputs[0].value.to_sat();
    retargeted.outputs[0].value = bitcoin_rs_primitives::Amount::from_sat(paid + 1);
    let uncached = verify_cached(&retargeted, &output, VerifyFlags::MANDATORY, None);
    assert!(
        uncached != Ok(true),
        "retargeted sighash must break uncached verification (else the test is vacuous)"
    );
    assert_eq!(
        verify_cached(&retargeted, &output, VerifyFlags::MANDATORY, Some(&cache)),
        uncached,
        "cached verdict matches uncached after warming"
    );
}

/// Key-path Default spend under a genuinely different key (seed 77; the shared
/// fixture tree uses seed 37), signed by the rust-bitcoin oracle exactly as the
/// bench and `verifier_boundaries.rs` do. Returns the oracle spend and its own
/// funding prevout so the test proves both sources valid before transplant.
fn accepted_spend_under_different_key() -> (bitcoin::Transaction, bitcoin::TxOut) {
    use bitcoin::secp256k1::{Keypair, Message as OracleMessage, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache as OracleCache, TapSighashType};

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[77; 32]).expect("second fixture key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
    let (output_key, _) = tweaked.public_parts();
    let prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(output_key),
    };
    let mut tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([78; 32]), 0),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(90_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let hash = OracleCache::new(&tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            TapSighashType::Default,
        )
        .expect("second-key BIP341 digest");
    let signature = secp.sign_schnorr_no_aux_rand(
        &OracleMessage::from_digest(*bitcoin::hashes::Hash::as_byte_array(&hash)),
        tweaked.as_keypair(),
    );
    tx.input[0].witness = bitcoin::Witness::from_slice(&[signature.serialize()]);
    (tx, prevout)
}

#[test]
fn signature_cache_warmed_still_rejects_wrong_key_signature() {
    let (tx, output) = first_accepted_key_spend();
    let cache = SignatureCache::new();
    assert_eq!(
        verify_cached(&tx, &output, VerifyFlags::MANDATORY, Some(&cache)),
        Ok(true),
        "warmup"
    );
    // A real signature under a genuinely different x-only key: valid under its
    // own funding prevout, but bound to another key and message.
    let (other_oracle, other_oracle_prevout) = accepted_spend_under_different_key();
    assert_ne!(
        other_oracle_prevout.script_pubkey.to_bytes(),
        output.script_pubkey.as_bytes(),
        "funding programs (hence tweaked keys) must differ"
    );
    assert_eq!(
        prepared(&other_oracle, &other_oracle_prevout, VerifyFlags::MANDATORY),
        Ok(true),
        "second source valid under its own key"
    );
    let other_tx: Tx =
        bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&other_oracle))
            .expect("native decode");
    let mut wrong_key = tx;
    wrong_key.inputs[0].witness = other_tx.inputs[0].witness.clone();
    let uncached = verify_cached(&wrong_key, &output, VerifyFlags::MANDATORY, None);
    assert!(
        uncached != Ok(true),
        "wrong-key signature must break uncached verification (else the test is vacuous)"
    );
    assert_eq!(
        verify_cached(&wrong_key, &output, VerifyFlags::MANDATORY, Some(&cache)),
        uncached,
        "cached verdict matches uncached after warming"
    );
}

#[test]
fn op_success_policy_rejection_precedes_stack_limits() {
    let prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: fixture::success_funding_script(),
    };
    for case in fixture::success_cases(outpoint(), &prevout)
        .into_iter()
        .filter(|case| case.accepted)
    {
        assert_eq!(
            prepared(
                &case.tx,
                &prevout,
                VerifyFlags::MANDATORY.union(VerifyFlags::DISCOURAGE_OP_SUCCESS)
            ),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::DiscourageOpSuccess
            }),
            "{}",
            case.name
        );
    }
}
