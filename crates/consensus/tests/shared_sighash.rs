//! Shared native aggregates retain the BIP143/BIP341 input context. Digests and
//! signatures come from the independent rust-bitcoin engine; Core transaction
//! vectors in the script crate separately exercise the prepared interpreter.

#![expect(clippy::expect_used, reason = "fixed independent-reference fixtures")]

use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{
    Annex, EcdsaSighashType, Prevouts, SighashCache as OracleCache, TapSighashType,
};
use bitcoin_rs_consensus::kernel::{BlockParse, verify_tx_scripts};
use bitcoin_rs_consensus::{
    BlockFacts, BlockView, ConsensusError, ScriptStageTimings, ValidationEngine,
    verify_block_input_scripts,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Network, OutPoint, Script, Sequence, Sighash, SighashCache,
    SighashError, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_script::{
    PreparedTransaction, PrevoutError, ScriptErrCode, ScriptError, VerifyFlags, opcode, push_data,
};
use secp256k1::{Keypair, Message, PublicKey, SECP256K1, SecretKey};

const MODES: [Sighash; 7] = [
    Sighash::Default,
    Sighash::All,
    Sighash::None,
    Sighash::Single,
    Sighash::AllAnyoneCanPay,
    Sighash::NoneAnyoneCanPay,
    Sighash::SingleAnyoneCanPay,
];

fn resolved_prevouts(tx: &Tx, prevouts: &[TxOut]) -> Vec<(OutPoint, TxOut)> {
    tx.inputs
        .iter()
        .zip(prevouts)
        .map(|(input, output)| (input.previous_output, output.clone()))
        .collect()
}

fn fixture(inputs: u8, outputs: usize) -> (Tx, Vec<TxOut>) {
    let prevouts: Vec<TxOut> = (0..inputs)
        .map(|index| TxOut {
            value: Amount::from_sat(10_000 + u64::from(index)),
            script_pubkey: Script::from_bytes(vec![opcode::OP_PUSHNUM_1, index]),
        })
        .collect();
    let tx = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(7),
        inputs: (0..inputs)
            .map(|index| TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[index + 1; 32])), 0),
                sequence: Sequence::from_consensus(0xffff_ff00 + u32::from(index)),
                ..TxIn::default()
            })
            .collect(),
        outputs: prevouts.iter().take(outputs).cloned().collect(),
    };
    (tx, prevouts)
}

fn oracle_tx(tx: &Tx) -> bitcoin::Transaction {
    bitcoin::consensus::deserialize(&consensus_bytes(tx)).expect("oracle transaction")
}

fn oracle_prevouts(prevouts: &[TxOut]) -> Vec<bitcoin::TxOut> {
    prevouts
        .iter()
        .map(|output| {
            bitcoin::consensus::deserialize(&consensus_bytes(output)).expect("oracle output")
        })
        .collect()
}

#[test]
fn parallel_shared_digests_match_reference_for_each_input_context() {
    // The last input has no SINGLE output: legacy's uint256-one, BIP143's
    // zero hashOutputs and BIP341's typed failure must remain distinct.
    let (tx, prevouts) = fixture(3, 2);
    let reference = oracle_tx(&tx);
    let reference_prevouts = oracle_prevouts(&prevouts);
    let cache = SighashCache::new(&tx);
    std::thread::scope(|scope| {
        for input in 0..tx.inputs.len() {
            let (cache, tx, prevouts, reference, reference_prevouts) =
                (&cache, &tx, &prevouts, &reference, &reference_prevouts);
            scope.spawn(move || {
                let mut oracle = OracleCache::new(reference);
                for mode in MODES {
                    let raw = u32::from(mode.to_u8());
                    let legacy_script = bitcoin::Script::from_bytes(&[0x51, 0x52]);
                    assert_eq!(
                        cache
                            .legacy_signature_hash(input, legacy_script.as_bytes(), raw)
                            .expect("legacy"),
                        Hash256::from_le_bytes(
                            oracle
                                .legacy_signature_hash(input, legacy_script, raw)
                                .expect("oracle legacy")
                                .as_byte_array()
                        ),
                    );
                    if mode != Sighash::Default {
                        // BIP143 receives a selected suffix verbatim, including
                        // any later unexecuted CODESEPARATOR.
                        let script = bitcoin::Script::from_bytes(&[0x51, 0xab, 0x52]);
                        let value = prevouts[input].value;
                        assert_eq!(
                            cache
                                .segwit_v0_signature_hash(input, script.as_bytes(), value, mode)
                                .expect("BIP143"),
                            Hash256::from_le_bytes(
                                oracle
                                    .p2wsh_signature_hash(
                                        input,
                                        script,
                                        bitcoin::Amount::from_sat(value.to_sat()),
                                        EcdsaSighashType::from_consensus(raw)
                                    )
                                    .expect("oracle BIP143")
                                    .as_byte_array()
                            ),
                        );
                    }
                    for annex in [None, Some(&[0x50, 0x01][..]), Some(&[0x50, 0x02, 0x03][..])] {
                        let leaf = bitcoin::TapLeafHash::from_script(
                            bitcoin::Script::from_bytes(&[0x51, 0xab, 0xac]),
                            bitcoin::taproot::LeafVersion::TapScript,
                        );
                        for separator in [None, Some(u32::MAX), Some(0), Some(2)] {
                            let native_leaf = separator.map(|position| {
                                (Hash256::from_le_bytes(leaf.as_byte_array()), position)
                            });
                            let result = cache.taproot_signature_hash(
                                input,
                                prevouts,
                                annex,
                                native_leaf,
                                mode,
                            );
                            let expected = oracle.taproot_signature_hash(
                                input,
                                &Prevouts::All(reference_prevouts),
                                annex.map(|bytes| Annex::new(bytes).expect("annex")),
                                separator.map(|position| (leaf, position)),
                                TapSighashType::from_consensus_u8(mode.to_u8()).expect("mode"),
                            );
                            if input >= tx.outputs.len()
                                && matches!(mode, Sighash::Single | Sighash::SingleAnyoneCanPay)
                            {
                                assert!(expected.is_err());
                                assert_eq!(
                                    result,
                                    Err(SighashError::SingleMissingOutput {
                                        input_index: input,
                                        outputs_length: tx.outputs.len()
                                    })
                                );
                            } else {
                                assert_eq!(
                                    result.expect("BIP341"),
                                    Hash256::from_le_bytes(
                                        expected.expect("oracle BIP341").as_byte_array()
                                    )
                                );
                            }
                        }
                    }
                }
            });
        }
    });
}

/// Sign legacy, `SegWit` and both Taproot spend paths with the independent engine.
/// Forty-two checks exceed the production Rayon threshold and reuse every aggregate.
#[expect(
    clippy::too_many_lines,
    reason = "one mixed independently signed transaction fixture"
)]
fn signed_fixture() -> (Tx, Vec<TxOut>) {
    let (mut tx, mut prevouts) = fixture(42, 42);
    tx.lock_time = LockTime::ZERO;
    let key = SecretKey::from_slice(&[7; 32]).expect("test key");
    let pubkey = PublicKey::from_secret_key(SECP256K1, &key);
    let keypair = Keypair::from_secret_key(SECP256K1, &key);
    let mut script = push_data(&pubkey.serialize());
    script.push(opcode::OP_CHECKSIG);
    let mut witness_script = vec![0xab];
    witness_script.extend_from_slice(&script);
    let mut tapscript = Vec::new();
    tapscript.extend(push_data(&keypair.x_only_public_key().0.serialize()));
    tapscript.push(opcode::OP_CHECKSIG);
    let tapscript = bitcoin::ScriptBuf::from_bytes(tapscript);
    let leaf =
        bitcoin::TapLeafHash::from_script(&tapscript, bitcoin::taproot::LeafVersion::TapScript);
    let tree = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, tapscript.clone())
        .expect("single leaf")
        .finalize(SECP256K1, keypair.x_only_public_key().0)
        .expect("taproot tree");
    let control = tree
        .control_block(&(tapscript.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .expect("control block")
        .serialize();
    for (index, output) in prevouts.iter_mut().enumerate() {
        output.script_pubkey = match index % 4 {
            0 => Script::from_bytes(script.clone()),
            1 => {
                let mut program = vec![0, 32];
                program
                    .extend_from_slice(bitcoin::WScriptHash::hash(&witness_script).as_byte_array());
                Script::from_bytes(program)
            }
            _ => {
                let mut program = vec![opcode::OP_PUSHNUM_1, 32];
                let output_key = if index % 4 == 2 {
                    keypair.x_only_public_key().0.serialize()
                } else {
                    tree.output_key().serialize()
                };
                program.extend_from_slice(&output_key);
                Script::from_bytes(program)
            }
        };
    }
    let reference = oracle_tx(&tx);
    let reference_prevouts = oracle_prevouts(&prevouts);
    let mut oracle = OracleCache::new(&reference);
    for (index, input) in tx.inputs.iter_mut().enumerate() {
        let mode = MODES[index % MODES.len()];
        if index % 4 >= 2 {
            let scriptpath = index % 4 == 3;
            // Keypath acceptance here uses its existing 64-byte DEFAULT form;
            // tapscript exercises every explicit mode in the same prepared tx.
            let mode = if scriptpath { mode } else { Sighash::Default };
            let annex = [0x50, u8::try_from(index).expect("small index")];
            let digest = oracle
                .taproot_signature_hash(
                    index,
                    &Prevouts::All(&reference_prevouts),
                    Some(Annex::new(&annex).expect("annex")),
                    scriptpath.then_some((leaf, u32::MAX)),
                    TapSighashType::from_consensus_u8(mode.to_u8()).expect("mode"),
                )
                .expect("taproot digest");
            let mut signature = SECP256K1
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest.to_byte_array()), &keypair)
                .serialize()
                .to_vec();
            if mode != Sighash::Default {
                signature.push(mode.to_u8());
            }
            input.witness = if scriptpath {
                Witness::from_stack(vec![
                    signature,
                    tapscript.to_bytes(),
                    control.clone(),
                    annex.to_vec(),
                ])
            } else {
                Witness::from_stack(vec![signature, annex.to_vec()])
            };
        } else {
            let mode = if mode == Sighash::Default {
                Sighash::All
            } else {
                mode
            };
            let script = bitcoin::Script::from_bytes(&script);
            let digest = if index % 4 == 0 {
                oracle
                    .legacy_signature_hash(index, script, u32::from(mode.to_u8()))
                    .expect("legacy digest")
                    .to_byte_array()
            } else {
                oracle
                    .p2wsh_signature_hash(
                        index,
                        script,
                        reference_prevouts[index].value,
                        EcdsaSighashType::from_consensus(u32::from(mode.to_u8())),
                    )
                    .expect("BIP143 digest")
                    .to_byte_array()
            };
            let mut signature = SECP256K1
                .sign_ecdsa(&Message::from_digest(digest), &key)
                .serialize_der()
                .to_vec();
            signature.push(mode.to_u8());
            if index % 4 == 0 {
                input.script_sig = Script::from_bytes(push_data(&signature));
            } else {
                input.witness = Witness::from_stack(vec![signature, witness_script.clone()]);
            }
        }
    }
    (tx, prevouts)
}

fn verify_block(
    tx: &Tx,
    prevouts: &[TxOut],
    engine: ValidationEngine,
) -> Result<(), ConsensusError> {
    let mut block = Network::Regtest.genesis_block();
    block.txs = vec![tx.clone()];
    let parsed = BlockParse::parse(&consensus_bytes(&block), engine)?;
    let mut view = BlockView::from_facts(
        &block.txs,
        BlockFacts::from_txids(&block.txs, vec![tx.txid()]),
    );
    view.set_resolved(vec![prevouts.iter().cloned().map(Some).collect()]);
    verify_block_input_scripts(
        &mut view,
        0,
        0,
        VerifyFlags::MANDATORY,
        &mut ScriptStageTimings::default(),
        &parsed,
    )
}

#[test]
fn prepared_block_and_transaction_accept_reference_signatures_and_order_failures() {
    let (tx, prevouts) = signed_fixture();
    let mut changed_tx = tx.clone();
    // Inputs 1 and 41 are SegWit spends. Exchange their independently valid
    // DER signatures: witness bytes do not change any sibling's digest, unlike
    // prevout amounts, which also affect non-ANYONECANPAY Taproot inputs.
    for (failed_input, signature_input) in [(1, 41), (41, 1)] {
        let mut isolated = tx.clone();
        isolated.inputs[failed_input].witness[0].clone_from(&tx.inputs[signature_input].witness[0]);
        let prepared =
            PreparedTransaction::new(&isolated, &resolved_prevouts(&isolated, &prevouts))
                .expect("ordered prevouts");
        for input_index in 0..tx.inputs.len() {
            let expected = if input_index == failed_input {
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::EvalFalse,
                })
            } else {
                Ok(true)
            };
            assert_eq!(
                prepared.verify_input(input_index, VerifyFlags::MANDATORY),
                expected,
                "isolated signature substitution at {failed_input}, checking {input_index}"
            );
        }
        changed_tx.inputs[failed_input].witness[0]
            .clone_from(&tx.inputs[signature_input].witness[0]);
    }
    for engine in std::iter::once(ValidationEngine::Native).chain(if cfg!(feature = "kernel") {
        Some(ValidationEngine::Kernel)
    } else {
        None
    }) {
        let spent: Vec<_> = tx
            .inputs
            .iter()
            .zip(&prevouts)
            .map(|(input, output)| (input.previous_output, output.clone()))
            .collect();
        assert_eq!(
            verify_tx_scripts(&tx, &spent, VerifyFlags::MANDATORY, engine),
            Ok(())
        );
        assert_eq!(verify_block(&tx, &prevouts, engine), Ok(()));
        let sequential = verify_tx_scripts(&changed_tx, &spent, VerifyFlags::MANDATORY, engine);
        let parallel = verify_block(&changed_tx, &prevouts, engine);
        assert_eq!(parallel, sequential);
        assert!(matches!(
            parallel,
            Err(ConsensusError::Script { input_index: 1, .. })
        ));
    }
}

#[test]
fn prepared_input_preserves_typed_bounds_and_count_precedence() {
    let (tx, prevouts) = fixture(3, 2);
    let wrong_count = PreparedTransaction::new(&tx, &[]);
    assert_eq!(
        wrong_count.err(),
        Some(PrevoutError::Count {
            input_count: 3,
            prevout_count: 0
        })
    );
    let prepared = PreparedTransaction::new(&tx, &resolved_prevouts(&tx, &prevouts))
        .expect("ordered prevouts");
    assert_eq!(
        prepared.verify_input(999, VerifyFlags::MANDATORY),
        Err(ScriptError::InputIndexOutOfRange {
            index: 999,
            inputs: 3
        })
    );
}

#[test]
fn preparation_rejects_swapped_and_foreign_prevout_identities_before_scripts() {
    let (tx, mut outputs) = fixture(3, 2);
    // Identical, always-true scripts cannot expose wrong row identities during
    // execution. Preparation must reject the wiring independently of scripts.
    for output in &mut outputs {
        *output = TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![opcode::OP_PUSHNUM_1]),
        };
    }
    let rows = resolved_prevouts(&tx, &outputs);
    let prepared = PreparedTransaction::new(&tx, &rows).expect("ordered identities");
    for index in 0..tx.inputs.len() {
        assert_eq!(prepared.verify_input(index, VerifyFlags::NONE), Ok(true));
    }
    let mut swapped = rows.clone();
    swapped.swap(0, 1);
    let mut foreign = rows.clone();
    foreign[1].0.vout += 1;
    for (bad_rows, input_index) in [(swapped, 0), (foreign, 1)] {
        assert_eq!(
            PreparedTransaction::new(&tx, &bad_rows).err(),
            Some(PrevoutError::Mismatch { input_index })
        );
        // Even an unavailable backend rejects caller wiring before dispatch.
        for engine in [ValidationEngine::Native, ValidationEngine::Kernel] {
            assert_eq!(
                verify_tx_scripts(&tx, &bad_rows, VerifyFlags::NONE, engine),
                Err(ConsensusError::PrevoutMismatch { input_index })
            );
        }
    }
    let mut short = rows;
    short.swap(0, 1);
    short.pop();
    assert_eq!(
        PreparedTransaction::new(&tx, &short).err(),
        Some(PrevoutError::Count {
            input_count: 3,
            prevout_count: 2
        })
    );
}
