//! ecash-fork `OP_DRIVECHAIN` behavior: the 4-byte whole-script form pushes
//! the drivechain marker and halts evaluation successfully, every other
//! `0xb7` shape stays `OP_NOP8`, and networks without the
//! [`VerifyFlags::ECASH`] activation see none of it.

use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::checker::{SigVersion, TxSignatureChecker};
use bitcoin_rs_script::eval;
use bitcoin_rs_script::{Interpreter, ScriptErrCode, ScriptError, ScriptItem, Stack, VerifyFlags};

/// The drivechain whole-script form under test: `OP_DRIVECHAIN`, then three
/// trailing bytes whose ordinary `OP_NOP8` interpretation ends the script with
/// a false top (so mainnet rejects what betanet accepts).
const DRIVECHAIN_FORM: &[u8] = &[0xb7, 0x51, 0x51, 0x00];
const DRIVECHAIN_MARKER: &[u8] = &[0xDC];

fn betanet_flags() -> VerifyFlags {
    VerifyFlags::MANDATORY.union(VerifyFlags::ECASH)
}

/// A spend of a prevout whose scriptPubKey is the drivechain form.
fn drivechain_spend() -> (Tx, TxOut) {
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(DRIVECHAIN_FORM.to_vec()),
    };
    let tx = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[0x2a; 32])),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: Script::new(),
        }],
    };
    (tx, prevout)
}

/// Evaluates `script` from an empty stack and returns the stack.
fn eval_stack(script: &[u8], flags: VerifyFlags) -> Stack {
    let (tx, prevout) = drivechain_spend();
    let mut checker =
        TxSignatureChecker::new(&tx, 0, prevout.value, std::slice::from_ref(&prevout));
    let mut stack = Stack::new();
    let mut validation_weight_left: Option<i64> = None;
    eval::eval_script(
        &mut stack,
        script,
        flags,
        &mut checker,
        SigVersion::Base,
        &mut validation_weight_left,
        None,
    )
    .unwrap_or_else(|error| panic!("fixture script must evaluate: {error}"));
    stack
}

#[test]
fn drivechain_form_pushes_marker_and_ends_evaluation() {
    let mut stack = eval_stack(DRIVECHAIN_FORM, betanet_flags());
    assert_eq!(stack.len(), 1, "the drivechain form pushes one marker");
    let item = stack
        .pop()
        .unwrap_or_else(|error| panic!("stack must hold the marker: {error}"));
    match item {
        ScriptItem::Bytes(bytes) => assert_eq!(&bytes[..], DRIVECHAIN_MARKER),
        ScriptItem::Num(value) => panic!("expected the raw 0xDC marker, got Num({value})"),
    }
}

#[test]
fn without_ecash_activation_the_form_is_plain_nop8() {
    // Mainnet: NOP8 executes, then OP_TRUE OP_TRUE OP_0 leave a false top -
    // untouched `OP_NOP8` behavior, three items instead of one marker.
    let mut stack = eval_stack(DRIVECHAIN_FORM, VerifyFlags::MANDATORY);
    assert_eq!(stack.len(), 3);
    for expected in [[].as_slice(), [0x01].as_slice(), [0x01].as_slice()] {
        let item = stack
            .pop()
            .unwrap_or_else(|error| panic!("stack depth must reach {expected:?}: {error}"));
        match item {
            ScriptItem::Bytes(bytes) => assert_eq!(&bytes[..], expected),
            ScriptItem::Num(value) => panic!("expected {expected:?}, got Num({value})"),
        }
    }
}

#[test]
fn non_four_byte_0xb7_scripts_stay_nop8_under_ecash() {
    // A >4-byte script starting with 0xb7 is not the drivechain form: the same
    // script evaluates identically with and without the ECASH activation.
    let five_bytes = &[0xb7, 0x51, 0x51, 0x00, 0x51];
    let mut betanet = eval_stack(five_bytes, betanet_flags());
    let mut mainnet = eval_stack(five_bytes, VerifyFlags::MANDATORY);
    assert_eq!(betanet.len(), mainnet.len());
    while !betanet.is_empty() {
        assert_eq!(betanet.pop(), mainnet.pop());
    }

    // A shorter script likewise stays a plain NOP8.
    let two_bytes = &[0xb7, 0x51];
    let betanet = eval_stack(two_bytes, betanet_flags());
    let mainnet = eval_stack(two_bytes, VerifyFlags::MANDATORY);
    assert_eq!(betanet, mainnet);
    assert_eq!(betanet.len(), 1);
}

#[test]
fn interpreter_accepts_on_betanet_and_rejects_on_mainnet() {
    let (tx, prevout) = drivechain_spend();
    let interpreter = Interpreter;

    let betanet = interpreter.execute(
        prevout.script_pubkey.as_bytes(),
        &[],
        &[],
        betanet_flags(),
        &prevout,
        &tx,
        0,
    );
    assert_eq!(betanet, Ok(true), "betanet accepts the drivechain spend");

    let mainnet = interpreter.execute(
        prevout.script_pubkey.as_bytes(),
        &[],
        &[],
        VerifyFlags::MANDATORY,
        &prevout,
        &tx,
        0,
    );
    assert_eq!(
        mainnet,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::EvalFalse,
        }),
        "mainnet still rejects the same spend as a plain OP_NOP8 script"
    );
}

#[test]
fn ecash_flag_is_activation_only_and_never_reaches_the_kernel_mask() {
    let flags = VerifyFlags::MANDATORY.union(VerifyFlags::ECASH);
    assert!(flags.contains(VerifyFlags::ECASH));
    assert_eq!(
        flags.kernel_bits(),
        VerifyFlags::MANDATORY.kernel_bits(),
        "the activation bit must not leak into bitcoinkernel's flag mask"
    );
}
