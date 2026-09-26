//! Capability is not selection: `engine = native` must reach the Rust
//! interpreter in every build, including builds where bitcoinkernel support is
//! compiled in, and a build without the `kernel` feature must fail closed on
//! `engine = kernel` instead of silently substituting another engine.

use bitcoin_rs_consensus::kernel::BlockParse;
#[cfg(feature = "kernel")]
use bitcoin_rs_consensus::{BlockView, ScriptStageTimings, verify_block_input_scripts};
use bitcoin_rs_consensus::{ConsensusError, UtxoView, ValidationEngine, verify_transaction};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_script::opcode::OP_EQUAL;
use bitcoin_rs_script::{VerifyFlags, push_int};

/// Resolved coins for the standalone transaction seam.
struct Coins(hashbrown::HashMap<OutPoint, TxOut>);

impl UtxoView for Coins {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(outpoint).cloned()
    }
}

/// One input spending an `OP_EQUAL` prevout with a mismatched `7 8` scriptSig.
/// Every compiled engine must reject the spend; no engine may accept it.
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
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0x2000_ffff),
            nonce: 0,
        },
        txs: vec![tx.clone()],
    }
}

fn script_reason(result: Result<(), ConsensusError>) -> String {
    match result {
        Err(ConsensusError::Script { reason, .. }) => reason,
        other => panic!("expected a script verdict, got {other:?}"),
    }
}

/// The native interpreter stays compiled when the kernel feature is enabled:
/// `engine = native` must produce the interpreter's verdict for both the
/// transaction seam and the block seam, not the kernel dispatch marker.
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

    // The block seam dispatches the same way: the parse carries the engine.
    let block = single_tx_block(&tx);
    let parsed = BlockParse::parse(&consensus_bytes(&block), ValidationEngine::Native)
        .unwrap_or_else(|error| panic!("native parse: {error}"));
    let mut view = BlockView::new(&block.txs, vec![tx.txid()]);
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

/// A build without `kernel` compiled in must fail closed on `engine = kernel`
/// with a clear unsupported-build error, never a silent engine substitution.
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

    let block = single_tx_block(&tx);
    match BlockParse::parse(&consensus_bytes(&block), ValidationEngine::Kernel) {
        Err(ConsensusError::UnsupportedEngine { engine }) => {
            assert_eq!(engine, ValidationEngine::Kernel);
        }
        other => panic!("kernel parse must fail closed without the feature, got {other:?}"),
    }
}

/// `native` resolves and runs in every build, kernel capability or not.
#[test]
fn native_engine_is_supported_and_default_in_every_build() {
    assert!(ValidationEngine::Native.is_supported());
    assert_eq!(ValidationEngine::default(), ValidationEngine::Native);

    let (tx, coins) = mismatched_equal_spend();
    let verdict = verify_transaction(
        &tx,
        &coins,
        0,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Native,
    );
    assert!(
        script_reason(verdict).starts_with("script failed:"),
        "native engine must reach the interpreter in this build"
    );
}

/// A prevout set that does not cover exactly the transaction's inputs is
/// rejected before any backend runs, under every compiled engine. A short
/// slice would otherwise leave trailing inputs silently unverified
/// (fail-open); a long one would index past `tx.inputs` in the native
/// interpreter. The check is shared, so no engine can disagree about it.
#[test]
fn prevout_count_mismatch_is_rejected_under_every_engine() {
    let (tx, coins) = mismatched_equal_spend();
    let one_prevout = coins.0.into_iter().collect::<Vec<_>>();

    // Every engine this build can execute, derived from the single engine
    // list so this and other engine-parameterized tests cannot drift apart.
    let engines = ValidationEngine::ALL
        .iter()
        .copied()
        .filter(|engine| engine.is_supported())
        .collect::<Vec<_>>();

    for engine in engines {
        // Short: one prevout for one input is exact; two inputs are needed for
        // a short slice to be a real fail-open case, so use a two-input tx.
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
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
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
