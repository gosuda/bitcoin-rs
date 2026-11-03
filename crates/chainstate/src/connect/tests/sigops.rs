//! Block budgets must survive script-proof and execution-skip paths (#1728).

use super::*;
use crate::test_fixtures::TestError;
use crate::{AssumeValidGate, ValidationMode, WindowApplyDisposition};
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::regtest_fixture::merkle_root;
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_script::{opcode::*, push_data};
use sha2::{Digest, Sha256};

fn funded_chain() -> TestResult<(crate::Chainstate, Tx, BlockHash)> {
    let chain = handles(Network::Regtest, Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
    seed_genesis(&chain)?;
    let mut funding = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
    funding.txs[0].outputs = (0..11)
        .map(|_| TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: vec![OP_PUSHNUM_1].into(),
        })
        .collect();
    remine(&mut funding)?;
    chain.apply_block(&BlockPayload::from_local(funding.clone()))?;
    let mut parent = funding.block_hash();
    for height in 2..=100 {
        let child = mined_child(parent, height)?;
        chain.apply_block(&BlockPayload::from_local(child.clone()))?;
        parent = child.block_hash();
    }
    Ok((chain, funding.txs.remove(0), parent))
}

fn remine(block: &mut Block) -> TestResult {
    block.header.merkle_root =
        merkle_root(&block.txs).ok_or(TestError::Missing("missing merkle root"))?;
    mine_block_to_declared_target(block)?;
    Ok(())
}

fn spend(inputs: Vec<TxIn>) -> Tx {
    Tx {
        version: 2,
        inputs,
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: vec![OP_PUSHNUM_1].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn input(outpoint: OutPoint, script_sig: Vec<u8>, witness: Witness) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: script_sig.into(),
        sequence: Sequence::MAX,
        witness,
    }
}

fn legacy_block(parent: BlockHash, funding: &Tx, transactions: u32) -> TestResult<Block> {
    let mut block = legacy_block_body(parent, funding, transactions)?;
    remine(&mut block)?;
    Ok(block)
}

fn legacy_block_with_coinbase_sigop(
    parent: BlockHash,
    funding: &Tx,
    transactions: u32,
) -> TestResult<Block> {
    let mut block = legacy_block_body(parent, funding, transactions)?;
    block.txs[0].outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: vec![OP_CHECKSIG].into(),
    });
    remine(&mut block)?;
    Ok(block)
}

fn legacy_sigop_heavy_script() -> Vec<u8> {
    (0..100)
        .flat_map(|_| [OP_0, OP_0, OP_0, OP_CHECKMULTISIG, OP_DROP])
        .chain([OP_PUSHNUM_1])
        .collect()
}

fn dead_branch_multisig_script() -> Vec<u8> {
    [
        vec![OP_0, OP_IF],
        vec![OP_CHECKMULTISIG; 100],
        vec![OP_ENDIF, OP_PUSHNUM_1],
    ]
    .concat()
}

fn legacy_block_body(parent: BlockHash, funding: &Tx, transactions: u32) -> TestResult<Block> {
    let mut block = mined_child(parent, 101)?;
    let script = legacy_sigop_heavy_script();
    for vout in 0..transactions {
        block.txs.push(spend(vec![input(
            OutPoint::new(funding.txid(), vout),
            script.clone(),
            Witness::new(),
        )]));
    }
    Ok(block)
}

#[derive(Clone, Copy)]
enum Path {
    Direct,
    Proposal,
    Window,
    AssumeValid,
}

fn check_budget(
    chain: &mut crate::Chainstate,
    block: Block,
    path: Path,
    expected: &Result<(), ConsensusError>,
) -> TestResult {
    let hash = block.block_hash().0;
    if matches!(path, Path::Window | Path::AssumeValid) {
        chain
            .block_tree
            .write()
            .insert_header(block.header, NodeStatus::HeaderValid)?;
    }
    if matches!(path, Path::AssumeValid) {
        chain.validation_mode = ValidationMode::AssumeValid;
        chain.assume_valid_height = 101;
        chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((101, hash))));
        chain.assume_valid_gate.evaluate(&chain.block_tree.read());
        assert!(chain.scripts_verified_upstream(crate::BlockProvenance::Network, 101, hash));
    }
    let snapshot = chain.chain_snapshot();
    let tip = chain
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("missing applied tip"))?
        .hash;
    let head = chain.durable_head.load()?;
    let stats = chain.coin_stats.snapshot().to_bytes();
    let utxo_len = chain.utxo.len();
    let inputs: Vec<_> = block
        .txs
        .iter()
        .flat_map(|tx| &tx.inputs)
        .map(|input| {
            (
                input.previous_output,
                chain.utxo.get(&input.previous_output),
            )
        })
        .collect();
    let outputs: Vec<_> = block
        .txs
        .iter()
        .map(|tx| OutPoint::new(tx.txid(), 0))
        .collect();
    let payload = BlockPayload::from_local(block);
    let result = match path {
        Path::Proposal => chain.validate_block(&payload),
        Path::Direct | Path::AssumeValid => chain.apply_block(&payload).map(|_| ()),
        Path::Window => chain
            .apply_window(&[&payload])
            .map(|_| ())
            .map_err(|error| {
                assert_eq!(error.applied, 0);
                assert!(error.committed.is_empty());
                assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
                assert!(error.invalidated.contains(&hash));
                error.source
            }),
    };
    match &expected {
        Ok(()) => {
            result?;
        }
        Err(expected_error) => match &result {
            Err(ApplyError::Consensus(err)) => assert_eq!(err, expected_error, "{result:?}"),
            other => {
                panic!("expected Err(ApplyError::Consensus({expected_error:?})), got {other:?}")
            }
        },
    }
    if expected.is_err() || matches!(path, Path::Proposal) {
        assert_eq!(chain.chain_snapshot(), snapshot);
        assert_eq!(
            chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing applied tip"))?
                .hash,
            tip
        );
        assert_eq!(chain.durable_head.load()?, head);
        assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
        assert_eq!(chain.utxo.len(), utxo_len);
        for (outpoint, output) in inputs {
            assert_eq!(chain.utxo.get(&outpoint), output);
        }
        for outpoint in outputs {
            assert!(chain.utxo.get(&outpoint).is_none());
        }
    } else {
        assert_eq!(
            chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing applied tip"))?
                .hash,
            hash
        );
    }
    Ok(())
}

#[test]
fn aggregate_sigops_enforce_the_inclusive_budget_on_every_connect_path() -> TestResult {
    for path in [
        Path::Direct,
        Path::Proposal,
        Path::Window,
        Path::AssumeValid,
    ] {
        for (transactions, cost) in [(10, 80_000), (11, 88_000)] {
            let (mut chain, funding, parent) = funded_chain()?;
            let block = legacy_block(parent, &funding, transactions)?;
            let expected = if cost > 80_000 {
                Err(ConsensusError::SigopsLimit { cost, max: 80_000 })
            } else {
                Ok(())
            };
            check_budget(&mut chain, block, path, &expected)?;
        }
        let (mut chain, funding, parent) = funded_chain()?;
        let block = legacy_block_with_coinbase_sigop(parent, &funding, 10)?;
        check_budget(
            &mut chain,
            block,
            path,
            &Err(ConsensusError::SigopsLimit {
                cost: 80_004,
                max: 80_000,
            }),
        )?;
    }
    Ok(())
}

#[test]
fn coinbase_only_blocks_obey_the_sigop_budget() -> TestResult {
    for (count, cost) in [(1_000, 80_000), (1_001, 80_080)] {
        let mut chain = handles(Network::Regtest, Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
        seed_genesis(&chain)?;
        let mut block = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
        block.txs[0].outputs[0].script_pubkey = vec![OP_CHECKMULTISIG; count].into();
        remine(&mut block)?;
        let expected = if cost > 80_000 {
            Err(ConsensusError::SigopsLimit { cost, max: 80_000 })
        } else {
            Ok(())
        };
        check_budget(&mut chain, block, Path::Direct, &expected)?;
    }
    Ok(())
}

#[test]
fn same_block_p2sh_and_witness_sigops_count_toward_the_budget() -> TestResult {
    let script = dead_branch_multisig_script();
    for witness in [false, true] {
        for extra in [false, true] {
            let (mut chain, funding, parent) = funded_chain()?;
            let program = if witness {
                [vec![0, 32], Sha256::digest(&script).to_vec()].concat()
            } else {
                let hash = vec![
                    0x60, 0xdc, 0xe5, 0xf8, 0x78, 0x81, 0x19, 0xd9, 0x6e, 0x0d, 0x6e, 0xf6, 0x8b,
                    0x00, 0x72, 0x63, 0x85, 0xdc, 0x39, 0xe5,
                ];
                [vec![OP_HASH160, 20], hash, vec![OP_EQUAL]].concat()
            };
            let count: u32 = if witness { 40 } else { 10 };
            let mut create = spend(vec![input(
                OutPoint::new(funding.txid(), 0),
                Vec::new(),
                Witness::new(),
            )]);
            create.outputs = (0..count)
                .map(|_| TxOut {
                    value: Amount::from_sat(100),
                    script_pubkey: program.clone().into(),
                })
                .collect();
            let inputs = (0..count)
                .map(|vout| {
                    input(
                        OutPoint::new(create.txid(), vout),
                        if witness {
                            Vec::new()
                        } else {
                            push_data(&script)
                        },
                        if witness {
                            Witness::from_stack(vec![script.clone()])
                        } else {
                            Witness::new()
                        },
                    )
                })
                .collect();
            let mut block = mined_child(parent, 101)?;
            block.txs.extend([create, spend(inputs)]);
            if extra {
                block.txs[0].outputs.push(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: vec![OP_CHECKSIG].into(),
                });
            }
            if witness {
                block.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
                let mut leaves = vec![[0; 32]];
                leaves.extend(
                    block
                        .txs
                        .iter()
                        .skip(1)
                        .map(|tx| *tx.wtxid().0.as_byte_array()),
                );
                let root = bitcoin_rs_consensus::compute_merkle_root(&mut leaves)
                    .ok_or(TestError::Missing("missing witness root"))?;
                let commitment = double_sha256(&[root, [0; 32]].concat());
                block.txs[0].outputs.push(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: [
                        vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
                        commitment.as_byte_array().to_vec(),
                    ]
                    .concat()
                    .into(),
                });
            }
            remine(&mut block)?;
            let expected = if extra {
                Err(ConsensusError::SigopsLimit {
                    cost: 80_004,
                    max: 80_000,
                })
            } else {
                Ok(())
            };
            check_budget(&mut chain, block, Path::Window, &expected)?;
        }
    }
    Ok(())
}

#[test]
fn empty_coinbase_outputs_rejected_on_every_connect_path() -> TestResult {
    for path in [
        Path::Direct,
        Path::Proposal,
        Path::Window,
        Path::AssumeValid,
    ] {
        let (mut chain, _funding, parent) = funded_chain()?;
        let mut block = mined_child(parent, 101)?;
        block.txs[0].outputs.clear();
        remine(&mut block)?;
        check_budget(&mut chain, block, path, &Err(ConsensusError::EmptyOutputs))?;
    }
    Ok(())
}
