use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{ScriptBuf, absolute, transaction};
use bitcoin_rs_primitives::{Amount, Script, Tx, TxOut};
use bitcoin_rs_script::{
    Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags, opcode, push_data,
};

#[derive(Clone, Copy, Debug)]
enum Spend {
    Legacy,
    P2sh,
    WitnessV0,
    Tapscript,
}

const SPENDS: [Spend; 4] = [
    Spend::Legacy,
    Spend::P2sh,
    Spend::WitnessV0,
    Spend::Tapscript,
];
#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    TaprootBuilder(#[from] bitcoin::taproot::TaprootBuilderError),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error(transparent)]
    Prevout(#[from] bitcoin_rs_script::PrevoutError),
    #[cfg(feature = "kernel")]
    #[error(transparent)]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error("{0}")]
    Message(&'static str),
}

impl From<&'static str> for TestError {
    fn from(s: &'static str) -> Self {
        Self::Message(s)
    }
}

type TestResult = Result<(), TestError>;

fn fixture(spend: Spend, initial: usize, script: Vec<u8>) -> Result<(Tx, TxOut), TestError> {
    let script = ScriptBuf::from_bytes(script);
    let mut script_sig = vec![opcode::OP_0; initial];
    let mut witness = vec![Vec::new(); initial];
    let script_pubkey = match spend {
        Spend::Legacy => {
            witness.clear();
            script
        }
        Spend::P2sh => {
            witness.clear();
            script_sig.extend(push_data(script.as_bytes()));
            script.to_p2sh()
        }
        Spend::WitnessV0 => {
            script_sig.clear();
            witness.push(script.to_bytes());
            script.to_p2wsh()
        }
        Spend::Tapscript => {
            script_sig.clear();
            let secp = Secp256k1::new();
            let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[17; 32])?);
            let info = TaprootBuilder::new()
                .add_leaf(0, script.clone())?
                .finalize(&secp, key.x_only_public_key().0)
                .map_err(|_| "complete taproot tree")?;
            witness.push(script.to_bytes());
            witness.push(
                info.control_block(&(script, LeafVersion::TapScript))
                    .ok_or("taproot control block")?
                    .serialize(),
            );
            ScriptBuf::new_p2tr_tweaked(info.output_key())
        }
    };
    let oracle = bitcoin::Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([42; 32]), 0),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&witness),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    Ok((
        bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&oracle))?,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(script_pubkey.to_bytes()),
        },
    ))
}

fn check(
    spend: Spend,
    initial: usize,
    script: Vec<u8>,
    expected: &Result<bool, ScriptError>,
) -> TestResult {
    let (tx, prevout) = fixture(spend, initial, script)?;
    let rows = [(tx.inputs[0].previous_output, prevout.clone())];
    assert_eq!(
        PreparedTransaction::new(&tx, &rows)?.verify_input(0, VerifyFlags::MANDATORY, None),
        *expected,
        "{spend:?}, initial={initial}, prepared"
    );
    assert_eq!(
        Interpreter.execute_with_prevouts(
            &prevout.script_pubkey,
            &tx.inputs[0].script_sig,
            &tx.inputs[0].witness,
            VerifyFlags::MANDATORY,
            std::slice::from_ref(&prevout),
            &tx,
            0,
        ),
        *expected,
        "{spend:?}, initial={initial}, interpreter"
    );
    #[cfg(feature = "kernel")]
    {
        use bitcoin_rs_consensus::{ConsensusError, ValidationEngine, kernel::verify_tx_scripts};
        let result = verify_tx_scripts(
            &tx,
            &rows,
            VerifyFlags::MANDATORY,
            ValidationEngine::Kernel,
            None,
        );
        match result {
            Ok(()) => assert!(expected.is_ok(), "{spend:?}: kernel accepted"),
            Err(ConsensusError::Script { .. }) => {
                assert!(expected.is_err(), "{spend:?}: kernel rejected")
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[test]
fn combined_stack_limit_after_pushes() -> TestResult {
    // #1745: both stacks stay individually <= 1000. Only their sum overflows.
    // Exercise direct pushes and each PUSHDATA encoding without MINIMALDATA.
    for spend in SPENDS {
        for push in [
            vec![1, 0x42],
            vec![0x4c, 1, 0x42],
            vec![0x4d, 1, 0, 0x42],
            vec![0x4e, 1, 0, 0, 0, 0x42],
        ] {
            for initial in [995, 996, 997] {
                let mut script = vec![
                    bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                    opcode::OP_0,
                    opcode::OP_0,
                    opcode::OP_0,
                ];
                script.extend(&push);
                let expected = if initial == 997 {
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::StackSize,
                    })
                } else if matches!(spend, Spend::WitnessV0 | Spend::Tapscript) {
                    // At sums 999/1000 evaluation reaches the separate final
                    // clean-stack rule; those large final stacks are not valid witnesses.
                    Err(ScriptError::Invalid {
                        code: ScriptErrCode::CleanStack,
                    })
                } else {
                    Ok(true)
                };
                check(spend, initial, script, &expected)?;
            }
        }
    }
    Ok(())
}

#[test]
fn combined_stack_overflow_cannot_be_hidden_by_a_later_drop() -> TestResult {
    for spend in SPENDS {
        check(
            spend,
            997,
            vec![
                bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                opcode::OP_0,
                opcode::OP_0,
                opcode::OP_0,
                1,
                0x42,
                opcode::OP_DROP,
            ],
            &Err(ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            }),
        )?;
    }
    Ok(())
}

#[test]
fn empty_push_also_enforces_combined_stack_limit() -> TestResult {
    for spend in SPENDS {
        check(
            spend,
            997,
            vec![
                bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
                opcode::OP_0,
                opcode::OP_0,
                opcode::OP_0,
                opcode::OP_0,
            ],
            &Err(ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            }),
        )?;
    }
    Ok(())
}

#[test]
fn tapscript_combined_limit_is_checked_before_cleaning_the_stack() -> TestResult {
    for initial in [996, 997] {
        let mut script = vec![
            bitcoin::opcodes::all::OP_TOALTSTACK.to_u8(),
            opcode::OP_0,
            opcode::OP_0,
            opcode::OP_0,
            1,
            0x42,
        ];
        // Tapscript has no legacy opcode-count limit, so remove all items
        // below the true top. A transient sum of 1000 is a valid full spend;
        // a transient sum of 1001 must fail before the first NIP can hide it.
        script.extend(std::iter::repeat_n(
            bitcoin::opcodes::all::OP_NIP.to_u8(),
            initial + 2,
        ));
        let expected = if initial == 996 {
            Ok(true)
        } else {
            Err(ScriptError::Invalid {
                code: ScriptErrCode::StackSize,
            })
        };
        check(Spend::Tapscript, initial, script, &expected)?;
    }
    Ok(())
}

#[test]
fn unexecuted_pushes_do_not_increase_combined_stack_size() -> TestResult {
    for spend in SPENDS {
        check(
            spend,
            1,
            vec![
                opcode::OP_IF,
                opcode::OP_0,
                opcode::OP_ENDIF,
                opcode::OP_PUSHNUM_1,
            ],
            &Ok(true),
        )?;
    }
    Ok(())
}
