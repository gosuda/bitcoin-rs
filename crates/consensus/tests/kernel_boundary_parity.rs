#![cfg(feature = "kernel")]
#![expect(clippy::expect_used, reason = "test assertions")]

use std::str::FromStr;

use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::{
    Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::VerifyFlags;

use crate::support::error::TestError;

type TestResult = Result<(), TestError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

struct BoundaryCase {
    name: &'static str,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    script_pubkey: Vec<u8>,
    expected: Verdict,
}

fn push_data2(payload_len: usize, fill: u8) -> Vec<u8> {
    let len = u16::try_from(payload_len).expect("boundary pushes fit PUSHDATA2");
    let mut script = Vec::with_capacity(3 + payload_len);
    script.push(0x4d);
    script.extend_from_slice(&len.to_le_bytes());
    script.resize(3 + payload_len, fill);
    script
}

fn repeats(opcode_byte: u8, count: usize) -> Vec<u8> {
    vec![opcode_byte; count]
}

fn multisig_script(keys: usize) -> Vec<u8> {
    let mut script = vec![0x00];
    for _ in 0..keys {
        script.push(0x21);
        script.push(0x02);
        script.extend_from_slice(&[0x11u8; 32]);
    }
    script.push(0xae);
    script
}

fn p2tr_program() -> Vec<u8> {
    let mut program = vec![0x51, 0x20];
    program.extend_from_slice(&[0x02u8; 32]);
    program
}

fn control_block(size: usize) -> Vec<u8> {
    let mut control = vec![0xc0];
    control.resize(size, 0x02);
    control
}

fn script_size_boundary_bytes(extra_tail: usize) -> Vec<u8> {
    let mut script = Vec::new();
    for _ in 0..19 {
        script.push(0x4d);
        script.extend_from_slice(&520u16.to_le_bytes());
        script.resize(script.len() + 520, 0x01);
    }
    script.push(0x3e);
    script.resize(script.len() + 62, 0x01);
    script.resize(script.len() + extra_tail, 0x00);
    script
}

fn nop_count_then_op1(nop_count: usize) -> Vec<u8> {
    let mut script = repeats(0x61, nop_count);
    script.push(0x51);
    script
}

fn legacy_boundary_cases() -> Vec<BoundaryCase> {
    vec![
        BoundaryCase {
            name: "script_size_at_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: script_size_boundary_bytes(0),
            expected: Verdict::Accept,
        },
        BoundaryCase {
            name: "script_size_over_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: script_size_boundary_bytes(1),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "op_count_at_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: nop_count_then_op1(201),
            expected: Verdict::Accept,
        },
        BoundaryCase {
            name: "op_count_over_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: nop_count_then_op1(202),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "push_element_at_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: push_data2(520, 0x01),
            expected: Verdict::Accept,
        },
        BoundaryCase {
            name: "push_element_over_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: push_data2(521, 0x01),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "stack_depth_at_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: repeats(0x51, 1000),
            expected: Verdict::Accept,
        },
        BoundaryCase {
            name: "stack_depth_over_limit",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: repeats(0x51, 1001),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "multisig_key_count_over_limit",
            script_sig: vec![0x00],
            witness: Vec::new(),
            script_pubkey: multisig_script(21),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "multisig_at_key_limit_without_signatures",
            script_sig: vec![0x00],
            witness: Vec::new(),
            script_pubkey: multisig_script(20),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "nonstandard_nop_is_consensus_valid",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: vec![0xb0, 0x51],
            expected: Verdict::Accept,
        },
        BoundaryCase {
            name: "codeseparator_then_value_accepts",
            script_sig: Vec::new(),
            witness: Vec::new(),
            script_pubkey: vec![0xab, 0x51],
            expected: Verdict::Accept,
        },
    ]
}

fn taproot_boundary_cases() -> Vec<BoundaryCase> {
    vec![
        BoundaryCase {
            name: "taproot_control_size_shape_invalid",
            script_sig: Vec::new(),
            witness: vec![vec![0x51], control_block(64)],
            script_pubkey: p2tr_program(),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "taproot_control_tampered_at_valid_shape",
            script_sig: Vec::new(),
            witness: vec![vec![0x51], control_block(65)],
            script_pubkey: p2tr_program(),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "annex_only_witness_invalid",
            script_sig: Vec::new(),
            witness: vec![vec![0x50]],
            script_pubkey: p2tr_program(),
            expected: Verdict::Reject,
        },
        BoundaryCase {
            name: "script_path_annex_without_signature_invalid",
            script_sig: Vec::new(),
            witness: vec![vec![0x51], control_block(65), vec![0x50]],
            script_pubkey: p2tr_program(),
            expected: Verdict::Reject,
        },
    ]
}

fn boundary_cases() -> Vec<BoundaryCase> {
    let mut cases = legacy_boundary_cases();
    cases.extend(taproot_boundary_cases());
    cases
}

fn boundary_tx(case: &BoundaryCase) -> (Tx, Vec<(OutPoint, TxOut)>) {
    let txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
        .expect("boundary prevout txid");
    let outpoint = OutPoint::new(txid, 0);
    let tx = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: case.script_sig.clone().into(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(case.witness.clone()),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::new(),
        }],
    };
    let prevouts = vec![(
        outpoint,
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(case.script_pubkey.clone()),
        },
    )];
    (tx, prevouts)
}

fn engine_verdict(
    tx: &Tx,
    prevouts: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
    engine: ValidationEngine,
) -> Result<Verdict, ConsensusError> {
    match bitcoin_rs_consensus::kernel::verify_tx_scripts(tx, prevouts, flags, engine, None) {
        Ok(()) => Ok(Verdict::Accept),
        Err(ConsensusError::Script { .. }) => Ok(Verdict::Reject),
        Err(error) => Err(error),
    }
}

#[test]
fn consensus_limit_boundaries_parity() -> TestResult {
    let cases = boundary_cases();
    assert!(!cases.is_empty(), "boundary parity case table is empty");

    for case in &cases {
        let (tx, prevouts) = boundary_tx(case);
        let native = engine_verdict(
            &tx,
            &prevouts,
            VerifyFlags::MANDATORY,
            ValidationEngine::Native,
        )
        .map_err(TestError::Consensus)?;
        let kernel = engine_verdict(
            &tx,
            &prevouts,
            VerifyFlags::MANDATORY,
            ValidationEngine::Kernel,
        )
        .map_err(TestError::Consensus)?;
        assert_eq!(
            native, kernel,
            "engine divergence on boundary {}: native={native:?} kernel={kernel:?}",
            case.name,
        );
        assert_eq!(
            kernel, case.expected,
            "kernel oracle disagrees with the Core boundary semantics of {}",
            case.name,
        );
        if case.expected == Verdict::Reject {
            let verdict = engine_verdict(
                &tx,
                &prevouts,
                VerifyFlags::MANDATORY,
                ValidationEngine::Kernel,
            )
            .map_err(TestError::Consensus)?;
            assert_eq!(
                verdict,
                Verdict::Reject,
                "reject boundary {} must stay a verdict, not infrastructure",
                case.name,
            );
        }
    }
    Ok(())
}
