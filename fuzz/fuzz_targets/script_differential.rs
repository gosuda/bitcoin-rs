#![no_main]

use bitcoin::hashes::{Hash as _, hash160, sha256};
use bitcoin_rs_consensus::primitives::{
    Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_consensus::script::{Interpreter, VerifyFlags};
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

fn cycled(seed: &[u8], len: usize, fill: u8) -> Vec<u8> {
    if seed.is_empty() {
        return vec![fill; len];
    }
    (0..len).map(|index| seed[index % seed.len()]).collect()
}

fn push(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00);
    } else if len <= 75 {
        script.push(u8::try_from(len).unwrap_or(u8::MAX));
    } else if let Ok(len_u8) = u8::try_from(len) {
        script.push(0x4c);
        script.push(len_u8);
    } else if let Ok(len_u16) = u16::try_from(len) {
        script.push(0x4d);
        script.extend_from_slice(&len_u16.to_le_bytes());
    } else {
        script.push(0x4e);
        script.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
    }
    script.extend_from_slice(data);
}

fn flip_byte(bytes: &[u8], seed: &[u8]) -> Vec<u8> {
    let mut flipped = bytes.to_vec();
    if let Some(first) = flipped.first_mut() {
        *first ^= seed.first().copied().unwrap_or(0x01) | 0x01;
    }
    flipped
}

fn witness_program(version_byte: u8, program: &[u8]) -> Vec<u8> {
    let mut script = vec![version_byte];
    push(&mut script, program);
    script
}

fn build_spending_tx(script_pubkey: &[u8], script_sig: &[u8], witness: Witness) -> (Tx, Vec<TxOut>) {
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: Script::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    let prevouts = vec![TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: Script::from_bytes(script_pubkey.to_vec()),
    }];
    (tx, prevouts)
}

#[derive(Clone, Copy)]
enum Commitment {
    Matched,
    Mismatched,
}

fn committed_program(digest: &[u8], body: &[u8], commitment: Commitment) -> Vec<u8> {
    match commitment {
        Commitment::Matched => digest.to_vec(),
        Commitment::Mismatched => flip_byte(digest, body),
    }
}

fn build_case(data: &[u8]) -> (Vec<u8>, Vec<u8>, Witness, VerifyFlags, Option<Commitment>) {
    let shape = data[0] % 7;
    let body = &data[1..];
    let commitment = if body.first().is_some_and(|byte| byte % 2 == 1) {
        Commitment::Mismatched
    } else {
        Commitment::Matched
    };

    match shape {
        0 => {
            let (script_pubkey, script_sig) = build_script_pair(body);
            (
                script_pubkey,
                script_sig,
                Witness::new(),
                VerifyFlags::MANDATORY,
                None,
            )
        }
        1 => {
            let pubkey = cycled(body, 33, 0x02);
            let sig = cycled(body, 71, 0x30);
            let mut script_sig = Vec::new();
            push(&mut script_sig, &sig);
            push(&mut script_sig, &pubkey);
            let program = committed_program(
                hash160::Hash::hash(&pubkey).as_byte_array(),
                body,
                commitment,
            );
            let mut script_pubkey = vec![0x76, 0xa9, 0x14];
            script_pubkey.extend_from_slice(&program);
            script_pubkey.extend_from_slice(&[0x88, 0xac]);
            (
                script_pubkey,
                script_sig,
                Witness::new(),
                VerifyFlags::MANDATORY,
                Some(commitment),
            )
        }
        2 => {
            let (redeem, _) = build_script_pair(body);
            let mut script_sig = Vec::new();
            push(&mut script_sig, &redeem);
            let program = committed_program(
                hash160::Hash::hash(&redeem).as_byte_array(),
                body,
                commitment,
            );
            let mut script_pubkey = vec![0xa9, 0x14];
            script_pubkey.extend_from_slice(&program);
            script_pubkey.push(0x87);
            (
                script_pubkey,
                script_sig,
                Witness::new(),
                VerifyFlags::MANDATORY.union(VerifyFlags::P2SH),
                Some(commitment),
            )
        }
        3 => {
            let pubkey = cycled(body, 33, 0x02);
            let sig = cycled(body, 71, 0x30);
            let witness = Witness::from_stack(vec![sig, pubkey.clone()]);
            let program = committed_program(
                hash160::Hash::hash(&pubkey).as_byte_array(),
                body,
                commitment,
            );
            let script_pubkey = witness_program(0x00, &program);
            (
                script_pubkey,
                Vec::new(),
                witness,
                VerifyFlags::MANDATORY
                    .union(VerifyFlags::P2SH)
                    .union(VerifyFlags::WITNESS),
                Some(commitment),
            )
        }
        4 => {
            let (wscript, _) = build_script_pair(body);
            let item = cycled(body, 32, 0x01);
            let witness = Witness::from_stack(vec![item, wscript.clone()]);
            let program = committed_program(
                sha256::Hash::hash(&wscript).as_byte_array(),
                body,
                commitment,
            );
            let script_pubkey = witness_program(0x00, &program);
            (
                script_pubkey,
                Vec::new(),
                witness,
                VerifyFlags::MANDATORY
                    .union(VerifyFlags::P2SH)
                    .union(VerifyFlags::WITNESS),
                Some(commitment),
            )
        }
        5 => {
            let program = cycled(body, 32, 0x02);
            let annex = cycled(body, 4, 0x50);
            let witness = Witness::from_stack(vec![annex]);
            let script_pubkey = witness_program(0x51, &program);
            (
                script_pubkey,
                Vec::new(),
                witness,
                VerifyFlags::MANDATORY
                    .union(VerifyFlags::P2SH)
                    .union(VerifyFlags::WITNESS)
                    .union(VerifyFlags::TAPROOT),
                None,
            )
        }
        _ => {
            let pubkey = cycled(body, 33, 0x02);
            let program = hash160::Hash::hash(&pubkey).as_byte_array().to_vec();
            let script_pubkey = witness_program(0x00, &program);
            let mut script_sig = Vec::new();
            push(&mut script_sig, body);
            (
                script_pubkey,
                script_sig,
                Witness::new(),
                VerifyFlags::MANDATORY
                    .union(VerifyFlags::P2SH)
                    .union(VerifyFlags::WITNESS),
                Some(Commitment::Mismatched),
            )
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let (script_pubkey, script_sig, witness, flags, commitment) = build_case(data);
    let (tx, prevouts) = build_spending_tx(&script_pubkey, &script_sig, witness.clone());

    let interpreter = Interpreter;

    let res = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &witness,
        flags,
        &prevouts,
        &tx,
        0,
    );
    let res_again = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &witness,
        flags,
        &prevouts,
        &tx,
        0,
    );
    assert_eq!(res, res_again);

    let cleanstack_flags = flags.union(VerifyFlags::CLEANSTACK);
    let res_cleanstack = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &witness,
        cleanstack_flags,
        &prevouts,
        &tx,
        0,
    );
    if res_cleanstack == Ok(true) {
        assert_eq!(res, Ok(true));
    }

    let minimalif_flags = flags.union(VerifyFlags::MINIMALIF);
    let res_minimalif = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &witness,
        minimalif_flags,
        &prevouts,
        &tx,
        0,
    );
    if res_minimalif == Ok(true) {
        assert_eq!(res, Ok(true));
    }

    if let Some(Commitment::Mismatched) = commitment {
        assert_ne!(
            res,
            Ok(true),
            "spend succeeded with a commitment mismatch: pubkey {:02x?} sig {:02x?}",
            script_pubkey,
            script_sig
        );
    }
});
