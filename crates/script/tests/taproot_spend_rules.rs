//! BIP341 wire signature and native witness-program dispatch rules.
#![expect(clippy::expect_used)]

#[path = "support/taproot_spends.rs"]
mod fixture;

use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{Script, Tx, TxOut};
use bitcoin_rs_script::{
    Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags,
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
        .verify_input(0, flags);
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
}
