use bitcoin::hashes::Hash as _;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{ScriptBuf, absolute, transaction};
use bitcoin_rs_consensus::primitives::{Amount, OutPoint, Script, Tx, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_consensus::script::{
    PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags, opcode, push_data,
};

const OP_1: u8 = opcode::OP_PUSHNUM_1;
const OP_NOP: u8 = 0x61;
const OP_ELSE: u8 = 0x67;
const OP_PUSHDATA1: u8 = 0x4c;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    TaprootBuilder(#[from] bitcoin::taproot::TaprootBuilderError),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
    #[error(transparent)]
    Prevout(#[from] bitcoin_rs_consensus::script::PrevoutError),
    #[error("{0}")]
    Message(&'static str),
}

impl From<&'static str> for TestError {
    fn from(s: &'static str) -> Self {
        Self::Message(s)
    }
}

type TestResult = Result<(), TestError>;

fn make_legacy_tx(script_sig: Vec<u8>, script_pubkey: Vec<u8>) -> (Tx, TxOut) {
    let prevout_point = OutPoint::new(Txid::default(), 0);
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: prevout_point,
            script_sig: Script::from_bytes(script_sig),
            sequence: bitcoin_rs_consensus::primitives::Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::new(),
        }],
        lock_time: bitcoin_rs_consensus::primitives::LockTime::ZERO,
    };
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(script_pubkey),
    };
    (tx, prevout)
}

fn check_legacy(
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    let (tx, prevout) = make_legacy_tx(script_sig, script_pubkey);
    let rows = [(tx.inputs[0].previous_output, prevout)];
    let prepared = match PreparedTransaction::new(&tx, &rows) {
        Ok(p) => p,
        Err(_) => {
            return Err(ScriptError::Invalid {
                code: ScriptErrCode::BadOpcode,
            });
        }
    };
    prepared.verify_input(0, flags, None)
}

fn make_tapscript_tx(
    script: Vec<u8>,
    witness_stack: Vec<Vec<u8>>,
    annex: Option<Vec<u8>>,
) -> Result<(Tx, TxOut), TestError> {
    let script_buf = ScriptBuf::from_bytes(script);
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[17; 32])?);
    let info = TaprootBuilder::new()
        .add_leaf(0, script_buf.clone())?
        .finalize(&secp, key.x_only_public_key().0)
        .map_err(|_| "complete taproot tree")?;
    let control_block = info
        .control_block(&(script_buf.clone(), LeafVersion::TapScript))
        .ok_or("taproot control block")?
        .serialize();

    let mut full_witness = witness_stack;
    full_witness.push(script_buf.to_bytes());
    full_witness.push(control_block);
    if let Some(annex_bytes) = annex {
        full_witness.push(annex_bytes);
    }

    let oracle = bitcoin::Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([42; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&full_witness),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let tx =
        bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&oracle))?;
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(
            ScriptBuf::new_p2tr_tweaked(info.output_key()).to_bytes(),
        ),
    };
    Ok((tx, prevout))
}

fn verify_taproot_witness(
    output_key: TweakedPublicKey,
    full_witness: Vec<Vec<u8>>,
) -> Result<Result<bool, ScriptError>, TestError> {
    let oracle = bitcoin::Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([42; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&full_witness),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let tx: Tx =
        bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(&oracle))?;
    let prevout = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(ScriptBuf::new_p2tr_tweaked(output_key).to_bytes()),
    };
    let rows = [(tx.inputs[0].previous_output, prevout)];
    let prepared = PreparedTransaction::new(&tx, &rows)?;
    Ok(prepared.verify_input(0, VerifyFlags::MANDATORY, None))
}

fn build_clean_sized_script(target_len: usize) -> Vec<u8> {
    let mut script = Vec::with_capacity(target_len);
    while script.len() + 524 <= target_len.saturating_sub(1) {
        script.extend(push_data(&[0x01; 520]));
        script.push(opcode::OP_DROP);
    }
    let remaining = target_len - script.len();
    if remaining > 1 {
        let push_needed = remaining - 1;
        if push_needed == 2 {
            script.push(opcode::OP_0);
            script.push(opcode::OP_DROP);
        } else if push_needed >= 3 {
            let data_len = push_needed - 2;
            script.extend(push_data(&vec![0x01; data_len]));
            script.push(opcode::OP_DROP);
        }
    }
    while script.len() < target_len - 1 {
        script.push(opcode::OP_0);
        script.push(opcode::OP_DROP);
    }
    script.push(OP_1);
    assert_eq!(script.len(), target_len);
    script
}

#[test]
fn script_size_limits_enforced_at_boundary() -> TestResult {
    let exact_10000 = build_clean_sized_script(10_000);
    assert_eq!(
        check_legacy(vec![], exact_10000, VerifyFlags::MANDATORY),
        Ok(true)
    );

    let script_10001 = build_clean_sized_script(10_001);
    assert_eq!(
        check_legacy(vec![], script_10001.clone(), VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::ScriptSize
        })
    );

    let (tx, prevout) = make_tapscript_tx(script_10001, vec![], None)?;
    let rows = [(tx.inputs[0].previous_output, prevout)];
    let prep = PreparedTransaction::new(&tx, &rows)?;
    assert_eq!(prep.verify_input(0, VerifyFlags::MANDATORY, None), Ok(true));
    Ok(())
}

#[test]
fn opcode_count_limit_201_enforced_at_boundary() -> TestResult {
    let op_201 = [vec![OP_NOP; 201], vec![OP_1]].concat();
    assert_eq!(
        check_legacy(vec![], op_201, VerifyFlags::MANDATORY),
        Ok(true)
    );

    let op_202 = [vec![OP_NOP; 202], vec![OP_1]].concat();
    assert_eq!(
        check_legacy(vec![], op_202, VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::OpCount
        })
    );

    let mut unexecuted_ops = vec![opcode::OP_0, opcode::OP_IF];
    unexecuted_ops.extend(vec![OP_NOP; 202]);
    unexecuted_ops.push(opcode::OP_ENDIF);
    unexecuted_ops.push(OP_1);
    assert_eq!(
        check_legacy(vec![], unexecuted_ops, VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::OpCount
        })
    );

    let tap_op_202 = [vec![OP_NOP; 202], vec![OP_1]].concat();
    let (tx, prevout) = make_tapscript_tx(tap_op_202, vec![], None)?;
    let rows = [(tx.inputs[0].previous_output, prevout)];
    let prep = PreparedTransaction::new(&tx, &rows)?;
    assert_eq!(prep.verify_input(0, VerifyFlags::MANDATORY, None), Ok(true));
    Ok(())
}

#[test]
fn push_size_limit_520_enforced_at_boundary() {
    let mut script_520 = push_data(&vec![0x42; 520]);
    script_520.push(opcode::OP_DROP);
    script_520.push(OP_1);
    assert_eq!(
        check_legacy(vec![], script_520, VerifyFlags::MANDATORY),
        Ok(true)
    );

    let mut script_521 = push_data(&vec![0x42; 521]);
    script_521.push(opcode::OP_DROP);
    script_521.push(OP_1);
    assert_eq!(
        check_legacy(vec![], script_521, VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::PushSize
        })
    );

    let mut unexecuted_521 = vec![opcode::OP_0, opcode::OP_IF];
    unexecuted_521.extend(push_data(&vec![0x42; 521]));
    unexecuted_521.push(opcode::OP_ENDIF);
    unexecuted_521.push(OP_1);
    assert_eq!(
        check_legacy(vec![], unexecuted_521, VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::PushSize
        })
    );
}

#[test]
fn disabled_opcodes_rejected_everywhere() {
    let disabled = [
        0x7e_u8, 0x7f, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98, 0x99,
    ];
    for op in disabled {
        assert_eq!(
            check_legacy(vec![], vec![op], VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::DisabledOpcode
            })
        );
        let unexecuted = vec![opcode::OP_0, opcode::OP_IF, op, opcode::OP_ENDIF, OP_1];
        assert_eq!(
            check_legacy(vec![], unexecuted, VerifyFlags::MANDATORY),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::DisabledOpcode
            })
        );
    }
}

#[test]
fn minimal_push_data_rules_enforced() {
    let non_minimal_one = vec![0x01, 0x01];
    let flags = VerifyFlags::MANDATORY.union(VerifyFlags::MINIMALDATA);
    assert_eq!(
        check_legacy(vec![], non_minimal_one, flags),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::MinimalData
        })
    );

    let non_minimal_neg_one = vec![0x01, 0x81];
    assert_eq!(
        check_legacy(vec![], non_minimal_neg_one, flags),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::MinimalData
        })
    );

    let mut pd1_75 = vec![OP_PUSHDATA1, 75];
    pd1_75.extend(vec![0x00; 75]);
    pd1_75.push(opcode::OP_DROP);
    pd1_75.push(OP_1);
    assert_eq!(
        check_legacy(vec![], pd1_75, flags),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::MinimalData
        })
    );

    assert_eq!(check_legacy(vec![], vec![OP_1], flags), Ok(true));
    assert_eq!(
        check_legacy(
            vec![],
            vec![opcode::OP_1NEGATE, opcode::OP_DROP, OP_1],
            flags
        ),
        Ok(true)
    );
}

#[test]
fn conditional_nesting_and_unbalanced_branches() {
    assert_eq!(
        check_legacy(vec![], vec![OP_1, opcode::OP_IF], VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::UnbalancedConditional
        })
    );

    assert_eq!(
        check_legacy(vec![], vec![OP_ELSE], VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::UnbalancedConditional
        })
    );

    assert_eq!(
        check_legacy(vec![], vec![opcode::OP_ENDIF], VerifyFlags::MANDATORY),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::UnbalancedConditional
        })
    );

    let nested = vec![
        opcode::OP_0,
        opcode::OP_IF,
        opcode::OP_0,
        opcode::OP_IF,
        OP_1,
        OP_ELSE,
        OP_1,
        opcode::OP_ENDIF,
        OP_ELSE,
        OP_1,
        opcode::OP_ENDIF,
    ];
    assert_eq!(
        check_legacy(vec![], nested, VerifyFlags::MANDATORY),
        Ok(true)
    );
}

#[test]
fn taproot_control_block_size_boundaries() -> TestResult {
    let secp = Secp256k1::new();
    let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[17; 32])?)
        .x_only_public_key()
        .0;
    let script = ScriptBuf::from_bytes(vec![OP_1]);

    let depth_zero = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, internal)
        .map_err(|_| "complete taproot tree")?;
    let depth_zero_control = depth_zero
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or("depth-zero control block")?
        .serialize();
    assert_eq!(depth_zero_control.len(), 33);
    assert_eq!(
        verify_taproot_witness(
            depth_zero.output_key(),
            vec![script.to_bytes(), depth_zero_control.clone()]
        )?,
        Ok(true)
    );

    let depth_one = TaprootBuilder::new()
        .add_leaf(1, ScriptBuf::from_bytes(vec![OP_NOP, OP_1]))?
        .add_leaf(1, script.clone())?
        .finalize(&secp, internal)
        .map_err(|_| "complete taproot tree")?;
    let depth_one_control = depth_one
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or("depth-one control block")?
        .serialize();
    assert_eq!(depth_one_control.len(), 65);
    assert_eq!(
        verify_taproot_witness(
            depth_one.output_key(),
            vec![script.to_bytes(), depth_one_control]
        )?,
        Ok(true)
    );

    let extended = |extra: usize| {
        let mut control = depth_zero_control.clone();
        control.extend(std::iter::repeat_n(0x01, extra));
        control
    };
    let below_base = vec![0xc0; 32];
    let misaligned = extended(1);
    let at_max = extended(32 * 128);
    let over_max = extended(32 * 128 + 1);
    let node_over_max = extended(32 * 129);
    assert_eq!(
        [
            below_base.len(),
            misaligned.len(),
            at_max.len(),
            over_max.len(),
            node_over_max.len()
        ],
        [32, 34, 4_129, 4_130, 4_161]
    );

    let wrong_size = || {
        Err(ScriptError::Invalid {
            code: ScriptErrCode::TaprootWrongControlSize,
        })
    };
    for control in [below_base, misaligned, over_max, node_over_max] {
        assert_eq!(
            verify_taproot_witness(depth_zero.output_key(), vec![script.to_bytes(), control])?,
            wrong_size()
        );
    }
    assert_eq!(
        verify_taproot_witness(depth_zero.output_key(), vec![script.to_bytes(), at_max])?,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::WitnessProgramMismatch,
        })
    );
    Ok(())
}

#[test]
fn annex_stripping_respects_witness_stack_size() -> TestResult {
    let (tx_two, prevout_two) =
        make_tapscript_tx(vec![OP_1], vec![], Some(vec![0x50, 0x01, 0x02]))?;
    let rows_two = [(tx_two.inputs[0].previous_output, prevout_two)];
    let prep_two = PreparedTransaction::new(&tx_two, &rows_two)?;
    assert_eq!(
        prep_two.verify_input(0, VerifyFlags::MANDATORY, None),
        Ok(true)
    );
    Ok(())
}
