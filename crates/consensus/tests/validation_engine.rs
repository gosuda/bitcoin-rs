//! Native selection always uses the Rust interpreter; kernel selection fails
//! closed when the kernel backend is not compiled.

use bitcoin_rs_consensus::kernel::BlockParse;
#[cfg(feature = "kernel")]
use bitcoin_rs_consensus::{BlockFacts, BlockView, ScriptStageTimings, verify_block_input_scripts};
use bitcoin_rs_consensus::{ConsensusError, UtxoView, ValidationEngine, verify_transaction};
use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_script::opcode::OP_EQUAL;
use bitcoin_rs_script::{VerifyFlags, push_int};

struct Coins(hashbrown::HashMap<OutPoint, TxOut>);

impl UtxoView for Coins {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(outpoint).cloned()
    }
}

fn mismatched_equal_spend() -> (Tx, Coins) {
    let outpoint = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[8; 32])),
        vout: 0,
    };
    let tx = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: [push_int(7), push_int(8)].concat().into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
    };
    let prevout = TxOut {
        value: Amount::from_sat(100),
        script_pubkey: vec![OP_EQUAL].into(),
    };
    let coins = Coins(hashbrown::HashMap::from([(outpoint, prevout)]));
    (tx, coins)
}

fn single_tx_block(tx: &Tx) -> Block {
    Block {
        header: Header {
            version: 1,
            bits: CompactTarget::from_consensus(0x2000_ffff),
            ..Header::default()
        },
        txs: vec![tx.clone()],
    }
}

#[cfg(feature = "kernel")]
fn script_reason(result: Result<(), ConsensusError>) -> String {
    match result {
        Err(ConsensusError::Script { reason, .. }) => reason,
        other => panic!("expected a script verdict, got {other:?}"),
    }
}

#[test]
#[cfg(feature = "kernel")]
fn native_engine_remains_available_when_kernel_is_compiled() {
    let (tx, coins) = mismatched_equal_spend();

    let native = verify_transaction(
        &tx,
        &coins,
        0,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Native,
    );
    let native_reason = script_reason(native);
    assert!(
        native_reason.starts_with("script failed:"),
        "native engine must run the interpreter, got {native_reason}"
    );

    let kernel = verify_transaction(
        &tx,
        &coins,
        0,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Kernel,
    );
    let kernel_reason = script_reason(kernel);
    assert!(
        kernel_reason.starts_with("kernel script verification failed:"),
        "kernel engine must run the kernel, got {kernel_reason}"
    );

    let block = single_tx_block(&tx);
    let parsed = BlockParse::parse(&consensus_bytes(&block), ValidationEngine::Native)
        .unwrap_or_else(|error| panic!("native parse: {error}"));
    let mut view = BlockView::from_facts(
        &block.txs,
        BlockFacts::from_txids(&block.txs, vec![tx.txid()]),
    );
    view.set_resolved(vec![vec![coins.lookup(&tx.inputs[0].previous_output)]]);
    let native_block = verify_block_input_scripts(
        &mut view,
        0,
        0,
        VerifyFlags::MANDATORY,
        &mut ScriptStageTimings::default(),
        &parsed,
    );
    assert!(
        script_reason(native_block).starts_with("script failed:"),
        "native engine must run the interpreter on the block seam"
    );
}

#[test]
#[cfg(not(feature = "kernel"))]
fn kernel_engine_fails_closed_without_the_kernel_feature() {
    let (tx, coins) = mismatched_equal_spend();

    let tx_verdict = verify_transaction(
        &tx,
        &coins,
        0,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Kernel,
    );
    match tx_verdict {
        Err(ConsensusError::UnsupportedEngine { engine }) => {
            assert_eq!(engine, ValidationEngine::Kernel);
        }
        other => panic!("kernel engine must fail closed without the feature, got {other:?}"),
    }

    // A coinbase returns from the pre-phase before any engine dispatch; the
    // selection check must still fire.
    let coinbase = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![1, 1].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
    };
    match verify_transaction(
        &coinbase,
        &coins,
        0,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Kernel,
    ) {
        Err(ConsensusError::UnsupportedEngine { engine }) => {
            assert_eq!(engine, ValidationEngine::Kernel);
        }
        other => {
            panic!("coinbase under kernel must fail closed without the feature, got {other:?}")
        }
    }

    let block = single_tx_block(&tx);
    match BlockParse::parse(&consensus_bytes(&block), ValidationEngine::Kernel) {
        Err(ConsensusError::UnsupportedEngine { engine }) => {
            assert_eq!(engine, ValidationEngine::Kernel);
        }
        other => panic!("kernel parse must fail closed without the feature, got {other:?}"),
    }
}

#[test]
fn prevout_count_mismatch_is_rejected_under_every_engine() {
    let (tx, coins) = mismatched_equal_spend();
    let one_prevout = coins.0.into_iter().collect::<Vec<_>>();

    let engines = ValidationEngine::ALL
        .iter()
        .copied()
        .filter(|engine| engine.is_supported())
        .collect::<Vec<_>>();

    for engine in engines {
        let two_input = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![
                tx.inputs[0].clone(),
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid(Hash256::from_le_bytes(&[9; 32])),
                        vout: 0,
                    },
                    sequence: Sequence::MAX,
                    ..TxIn::default()
                },
            ],
            outputs: tx.outputs.clone(),
        };

        let short = bitcoin_rs_consensus::kernel::verify_tx_scripts(
            &two_input,
            &one_prevout,
            VerifyFlags::MANDATORY,
            engine,
        );
        assert!(
            matches!(
                short,
                Err(ConsensusError::PrevoutCount {
                    input_count: 2,
                    prevout_count: 1
                })
            ),
            "{engine:?} must reject a short prevout slice, got {short:?}"
        );

        let mut long = one_prevout.clone();
        long.push((
            OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[10; 32])),
                vout: 0,
            },
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            },
        ));
        let long = bitcoin_rs_consensus::kernel::verify_tx_scripts(
            &tx,
            &long,
            VerifyFlags::MANDATORY,
            engine,
        );
        assert!(
            matches!(
                long,
                Err(ConsensusError::PrevoutCount {
                    input_count: 1,
                    prevout_count: 2
                })
            ),
            "{engine:?} must reject a long prevout slice, got {long:?}"
        );
    }
}
