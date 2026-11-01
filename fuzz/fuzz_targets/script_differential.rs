#![no_main]

use bitcoin_rs_primitives::{
    Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::{Interpreter, VerifyFlags};
use libfuzzer_sys::fuzz_target;

fn push_boundary(size: usize, fill_byte: u8) -> Vec<u8> {
    let mut script = Vec::with_capacity(size + 3);
    if let Ok(len_u8) = u8::try_from(size) {
        script.push(0x4c);
        script.push(len_u8);
    } else if let Ok(len_u16) = u16::try_from(size) {
        script.push(0x4d);
        let len = len_u16.to_le_bytes();
        script.push(len[0]);
        script.push(len[1]);
    }
    script.resize(script.len() + size, fill_byte);
    script
}

fn append_boundary_chunk(script: &mut Vec<u8>, tag: u8) {
    let size = match tag % 3 {
        0 => 519,
        1 => 520,
        _ => 521,
    };
    script.extend_from_slice(&push_boundary(size, tag));
}

fn append_repeated_op(script: &mut Vec<u8>, op: u8, count: usize) {
    for _ in 0..count {
        script.push(op);
    }
}

fn append_pattern(script: &mut Vec<u8>, tag: u8) {
    match tag % 5 {
        0 => append_boundary_chunk(script, tag),
        1 => {
            let count = 200 + usize::from(tag % 3);
            append_repeated_op(script, 0x61, count);
        }
        2 => {
            let count = 999 + usize::from(tag % 3);
            append_repeated_op(script, 0x51, count);
        }
        3 => script.extend_from_slice(&[0x63, 0x51, 0x67, 0x52, 0x68]),
        _ => script.extend_from_slice(&[0x51, 0x51, 0x93, 0x52, 0x87]),
    }
}

fn build_script_pair(mut bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut script_pubkey = Vec::new();
    let mut script_sig = Vec::new();

    while !bytes.is_empty() {
        let tag = bytes[0];
        bytes = &bytes[1..];

        if tag.is_multiple_of(2) {
            append_pattern(&mut script_pubkey, tag);
        } else {
            let len = usize::from(tag % 32);
            if bytes.len() >= len {
                if let Ok(len_u8) = u8::try_from(len) {
                    script_sig.push(len_u8);
                    script_sig.extend_from_slice(&bytes[..len]);
                }
                bytes = &bytes[len..];
            } else {
                append_boundary_chunk(&mut script_sig, tag);
            }
        }

        if script_pubkey.len() > 10_000 || script_sig.len() > 10_000 {
            break;
        }
    }

    (script_pubkey, script_sig)
}

fn build_spending_tx(pubkey: &[u8], sig: &[u8]) -> (Tx, Vec<TxOut>) {
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: Script::from_bytes(sig.to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::from_bytes(pubkey.to_vec()),
    }];
    (tx, prevouts)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let (script_pubkey, script_sig) = build_script_pair(data);
    let (tx, prevouts) = build_spending_tx(&script_pubkey, &script_sig);

    let interpreter = Interpreter;
    let base_flags = VerifyFlags::MANDATORY;

    let res1 = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &tx.inputs[0].witness,
        base_flags,
        &prevouts,
        &tx,
        0,
    );
    let res2 = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &tx.inputs[0].witness,
        base_flags,
        &prevouts,
        &tx,
        0,
    );
    assert_eq!(res1, res2);

    let cleanstack_flags = base_flags.union(VerifyFlags::CLEANSTACK);
    let res_cleanstack = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &tx.inputs[0].witness,
        cleanstack_flags,
        &prevouts,
        &tx,
        0,
    );
    if res_cleanstack == Ok(true) {
        assert_eq!(res1, Ok(true));
    }

    let minimalif_flags = base_flags.union(VerifyFlags::MINIMALIF);
    let res_minimalif = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &tx.inputs[0].witness,
        minimalif_flags,
        &prevouts,
        &tx,
        0,
    );
    if res_minimalif == Ok(true) {
        assert_eq!(res1, Ok(true));
    }
});
