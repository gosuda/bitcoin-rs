//! Context-free transaction rules survive every script execution policy (#1737).

use super::*;
use crate::{AssumeValidGate, BlockProvenance, ValidationMode, WindowApplyDisposition};

#[derive(Clone, Copy, Debug)]
enum Path {
    Direct,
    Proposal,
    Window,
}

fn remine(block: &mut Block) -> TestResult {
    block.header.merkle_root =
        bitcoin_rs_chain::regtest_fixture::merkle_root(&block.txs).ok_or("missing merkle root")?;
    mine_block_to_declared_target(block)?;
    Ok(())
}

#[test]
fn zero_output_coinbase_never_publishes_under_any_script_policy() -> TestResult {
    for height in [1, 101] {
        for mode in [
            ValidationMode::Full,
            ValidationMode::Fast,
            ValidationMode::AssumeValid,
        ] {
            for path in [Path::Direct, Path::Proposal, Path::Window] {
                // Coinbase only, an independent spend, and a same-block spend
                // cover the shortcut, parallel, and local-overlay dispatches.
                for spends in 0..=if height == 101 { 2 } else { 0 } {
                    let mut chain =
                        handles(Network::Regtest, Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
                    seed_genesis(&chain)?;
                    let parent = apply_regtest_chain_to_height(&chain, height - 1)?;
                    let funding = OutPoint::new(coinbase(1).txid(), 0);
                    let funding_before = chain.utxo.get(&funding);
                    let mut block = mined_child(parent, height)?;
                    block.txs[0].outputs.clear();
                    if spends > 0 {
                        let first = op_true_spend(funding, 1_000);
                        if spends == 2 {
                            let second = op_true_spend(OutPoint::new(first.txid(), 0), 900);
                            block.txs.extend([first, second]);
                        } else {
                            block.txs.push(first);
                        }
                    }
                    remine(&mut block)?;
                    let hash = block.block_hash().0;
                    let successor = mined_child(block.block_hash(), height + 1)?;
                    chain.admit_headers(&[block.header, successor.header])?;
                    chain.validation_mode = mode;
                    if mode == ValidationMode::AssumeValid {
                        chain.assume_valid_height = height;
                        chain.assume_valid_gate =
                            Arc::new(AssumeValidGate::with_anchor(Some((height, hash))));
                        chain.assume_valid_gate.evaluate(&chain.block_tree.read());
                    }
                    assert_eq!(
                        chain.scripts_verified_upstream(BlockProvenance::Network, height, hash),
                        mode != ValidationMode::Full
                    );
                    let tip = chain.applied_tip_snapshot().ok_or("missing tip")?;
                    let snapshot = chain.chain_snapshot();
                    let head = chain.durable_head.load()?;
                    let stats = chain.coin_stats.snapshot().to_bytes();
                    let utxo_len = chain.utxo.len();
                    let outputs: Vec<_> = block
                        .txs
                        .iter()
                        .skip(1)
                        .map(|tx| OutPoint::new(tx.txid(), 0))
                        .collect();
                    let payload = BlockPayload::from_local(block);
                    let result = match path {
                        Path::Direct => chain.apply_block(&payload).map(|_| ()),
                        Path::Proposal => chain.validate_block(&payload),
                        Path::Window => {
                            chain
                                .apply_window(&[&payload])
                                .map(|_| ())
                                .map_err(|error| {
                                    assert_eq!(error.applied, 0);
                                    assert!(error.committed.is_empty());
                                    assert_eq!(
                                        error.disposition,
                                        WindowApplyDisposition::Permanent
                                    );
                                    assert!(error.invalidated.contains(&hash));
                                    error.source
                                })
                        }
                    };
                    assert!(
                        matches!(
                            result,
                            Err(ApplyError::Consensus(ConsensusError::EmptyOutputs))
                        ),
                        "height={height}, mode={mode:?}, path={path:?}, spends={spends}: {result:?}"
                    );
                    assert_eq!(chain.chain_snapshot(), snapshot);
                    assert_eq!(
                        chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
                        tip.hash
                    );
                    assert_eq!(chain.durable_head.load()?, head);
                    assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
                    assert_eq!(chain.utxo.len(), utxo_len);
                    assert_eq!(chain.utxo.get(&funding), funding_before);
                    for outpoint in outputs {
                        assert!(chain.utxo.get(&outpoint).is_none());
                    }
                    assert!(chain.undo_store.load_undo(height, hash)?.is_none());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn proposal_and_commit_agree_on_coinbase_finality_without_proposal_side_effects() -> TestResult {
    let non_final_time = Network::Regtest.genesis_block().header.time + 101;
    for (locktime, is_final) in [(100, true), (101, false), (non_final_time, false)] {
        let chain = handles(Network::Regtest, Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
        seed_genesis(&chain)?;
        let parent = apply_regtest_chain_to_height(&chain, 100)?;
        let mut block = mined_child(parent, 101)?;
        block.txs[0].lock_time = LockTime::from_consensus(locktime);
        block.txs[0].inputs[0].sequence = Sequence::ZERO;
        remine(&mut block)?;
        let payload = BlockPayload::from_local(block);
        let tip = chain.applied_tip_snapshot().ok_or("missing tip")?;
        let snapshot = chain.chain_snapshot();
        let head = chain.durable_head.load()?;
        let stats = chain.coin_stats.snapshot().to_bytes();
        let utxo_len = chain.utxo.len();
        let proposed = chain.validate_block(&payload);
        assert_eq!(chain.chain_snapshot(), snapshot);
        assert_eq!(
            chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
            tip.hash
        );
        assert_eq!(chain.durable_head.load()?, head);
        assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
        assert_eq!(chain.utxo.len(), utxo_len);
        let committed = chain.apply_block(&payload);
        if is_final {
            proposed?;
            committed?;
        } else {
            for result in [proposed, committed.map(|_| ())] {
                assert!(
                    matches!(
                        result,
                        Err(ApplyError::Consensus(ConsensusError::Bip {
                            bip: "BIP113",
                            ..
                        }))
                    ),
                    "{result:?}"
                );
            }
            assert_eq!(chain.chain_snapshot(), snapshot);
            assert_eq!(
                chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
                tip.hash
            );
            assert_eq!(chain.durable_head.load()?, head);
            assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
            assert_eq!(chain.utxo.len(), utxo_len);
        }
    }
    Ok(())
}
