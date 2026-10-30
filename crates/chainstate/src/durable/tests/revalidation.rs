//! Cold recovery must not inherit script trust from Fast commits (#1730).

use std::path::Path;
use std::sync::Arc;

use super::*;
use crate::{
    ValidationMode,
    recovery::{ResumeSource, prepare_initial_chainstate},
};
use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};
use bitcoin_rs_primitives::{
    Amount, Block, BlockPayload, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
    consensus_bytes,
};
use bitcoin_rs_script::{
    VerifyFlags,
    opcode::{OP_PUSHNUM_1, OP_RETURN},
};
use bitcoin_rs_storage::chainstate_journal::{FULL_REVALIDATION_MARKER, JOURNAL_DIR_NAME};
use bitcoin_rs_utxo::stats::CoinStatsListener;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct SpendView(OutPoint, TxOut);

impl bitcoin_rs_consensus::UtxoView for SpendView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        (*outpoint == self.0).then(|| self.1.clone())
    }
}

fn write_accepted_checkpoint(dir: &Path, chain: &Chainstate) -> TestResult {
    let store = bitcoin_rs_storage::checkpoint::open_data_dir(dir)?;
    let config = crate::checkpoint::headers::HeaderCheckpointConfig {
        network: Network::Regtest,
        genesis: Network::Regtest.genesis_block_hash(),
    };
    crate::checkpoint::write_checkpoint_from_dir(
        &store,
        config,
        &chain.block_tree,
        &chain.utxo,
        &chain.coin_stats,
        chain.applied_tip_snapshot().as_deref(),
    )?;
    Ok(())
}

fn commit_chain(
    opcode: u8,
    save_checkpoint_at_100: bool,
) -> TestResult<(Chainstate, Block, OutPoint, Option<tempfile::TempDir>)> {
    let (mut chain, first) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    let genesis = Network::Regtest.genesis_block();
    bodies.persist_block_body(0, genesis.block_hash().0, &consensus_bytes(&genesis))?;
    chain.block_body_store = Some(bodies);
    chain.apply_block(&BlockPayload::from_local(first.clone()))?;
    let funding = OutPoint::new(first.txs[0].txid(), 0);
    let mut parent = first.block_hash();
    for height in 2..=100 {
        let child = mined_child(parent, height)?;
        chain.apply_block(&BlockPayload::from_local(child.clone()))?;
        parent = child.block_hash();
    }
    let checkpoint_dir = if save_checkpoint_at_100 {
        let dir = tempfile::tempdir()?;
        crate::events::initialize_data_dir(dir.path())?;
        write_accepted_checkpoint(dir.path(), &chain)?;
        Some(dir)
    } else {
        None
    };
    let mut spend_block = mined_child(parent, 101)?;
    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: vec![opcode].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![OP_PUSHNUM_1].into(),
        }],
        lock_time: LockTime::ZERO,
    };
    // An independent transaction-verification boundary confirms the fixture's
    // script verdict before Fast deliberately skips it during block connect.
    let verdict = bitcoin_rs_consensus::verify_transaction(
        &spend,
        &SpendView(funding, first.txs[0].outputs[0].clone()),
        101,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Native,
        None,
    );
    if opcode == OP_RETURN {
        assert!(matches!(verdict, Err(ConsensusError::Script { .. })));
    } else {
        verdict?;
    }
    spend_block.txs.push(spend);
    spend_block.header.merkle_root =
        bitcoin_rs_chain::regtest_fixture::merkle_root(&spend_block.txs)
            .ok_or("missing merkle root")?;
    bitcoin_rs_chain::regtest_fixture::mine_block_to_declared_target(&mut spend_block)?;
    let successor = mined_child(spend_block.block_hash(), 102)?;
    chain.admit_headers(&[spend_block.header, successor.header])?;
    chain.validation_mode = ValidationMode::Fast;
    chain.apply_block(&BlockPayload::from_local(spend_block.clone()))?;
    chain.apply_block(&BlockPayload::from_local(successor))?;
    Ok((chain, spend_block, funding, checkpoint_dir))
}

fn prepare_cold(
    chain: &mut Chainstate,
    checkpoint_dir: Option<tempfile::TempDir>,
    marker: bool,
    mode: ValidationMode,
) -> TestResult<tempfile::TempDir> {
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let journal_config = crate::ChainstateJournalConfig {
        enabled: false,
        ..crate::ChainstateJournalConfig::default()
    };
    let dir = match checkpoint_dir {
        Some(dir) => {
            if marker {
                // Prove selector validity: without the marker, this accepted checkpoint
                // restores as ResumeSource::Checkpoint with applied_tip at height 100.
                let baseline = prepare_initial_chainstate(
                    dir.path(),
                    Network::Regtest,
                    journal_config,
                    Some(&head),
                )?;
                assert_eq!(baseline.resume_source, ResumeSource::Checkpoint);
                assert_eq!(baseline.applied_tip.as_ref().map(|t| t.height), Some(100));

                let journal = dir.path().join(JOURNAL_DIR_NAME);
                std::fs::create_dir_all(&journal)?;
                std::fs::write(
                    journal.join(FULL_REVALIDATION_MARKER),
                    b"journal fork crossed below checkpoint base\n",
                )?;
            }
            dir
        }
        None => {
            let dir = tempfile::tempdir()?;
            crate::events::initialize_data_dir(dir.path())?;
            if marker {
                let journal = dir.path().join(JOURNAL_DIR_NAME);
                std::fs::create_dir_all(&journal)?;
                std::fs::write(
                    journal.join(FULL_REVALIDATION_MARKER),
                    b"journal fork crossed below checkpoint base\n",
                )?;
            }
            dir
        }
    };
    let initial =
        prepare_initial_chainstate(dir.path(), Network::Regtest, journal_config, Some(&head))?;
    assert_eq!(initial.resume_source, ResumeSource::Cold);
    assert!(initial.applied_tip.is_none());
    chain.validation_mode = mode;
    chain.coin_stats = Arc::new(CoinStatsListener::new(initial.coin_stats));
    let mut utxo = initial.utxo;
    utxo.track_coin_stats((*chain.coin_stats).clone());
    chain.utxo = Arc::new(utxo);
    *chain.block_tree.write() = initial.tree;
    chain.applied_tip.store(None);
    chain.chain_tip.store(None);
    chain.chain_events = Arc::new(crate::events::ChainEventPublisher::detached(1));
    Ok(dir)
}

fn prepare_warm(
    chain: &mut Chainstate,
    checkpoint_dir: tempfile::TempDir,
    mode: ValidationMode,
) -> TestResult<tempfile::TempDir> {
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let initial = prepare_initial_chainstate(
        checkpoint_dir.path(),
        Network::Regtest,
        crate::ChainstateJournalConfig {
            enabled: false,
            ..crate::ChainstateJournalConfig::default()
        },
        Some(&head),
    )?;
    assert_eq!(initial.resume_source, ResumeSource::Checkpoint);
    let tip = initial
        .applied_tip
        .clone()
        .ok_or("missing checkpoint tip")?;
    assert_eq!(tip.height, 100);
    chain.validation_mode = mode;
    chain.coin_stats = Arc::new(CoinStatsListener::new(initial.coin_stats));
    let mut utxo = initial.utxo;
    utxo.track_coin_stats((*chain.coin_stats).clone());
    chain.utxo = Arc::new(utxo);
    *chain.block_tree.write() = initial.tree;
    let tip_arc = Some(Arc::new(tip));
    chain.applied_tip.store(tip_arc.clone());
    chain.chain_tip.store(tip_arc);
    chain.chain_events = Arc::new(crate::events::ChainEventPublisher::detached(1));
    Ok(checkpoint_dir)
}

#[test]
fn cold_revalidation_rejects_script_invalid_commits_and_preserves_recovery_evidence() -> TestResult
{
    for (mode, marker) in [
        (ValidationMode::Full, true),
        (ValidationMode::AssumeValid, true),
        (ValidationMode::Fast, true),
        (ValidationMode::Full, false),
        (ValidationMode::AssumeValid, false),
        (ValidationMode::Fast, false),
    ] {
        let (mut chain, invalid, funding, checkpoint_dir) = commit_chain(OP_RETURN, marker)?;
        let head = chain.durable_head.load()?;
        let hash = invalid.block_hash().0;
        let undo = chain.undo_store.load_undo(101, hash)?;
        let dir = prepare_cold(&mut chain, checkpoint_dir, marker, mode)?;
        let error = super::super::reconcile_at_boot(&chain)
            .err()
            .ok_or("a cold rebuild must verify scripts")?;
        assert!(
            matches!(error, ApplyError::Consensus(ConsensusError::Script { .. })),
            "{error:?}"
        );
        let tip = chain
            .applied_tip_snapshot()
            .ok_or("missing replay prefix")?;
        assert_eq!(
            (tip.height, tip.hash),
            (100, invalid.header.prev_blockhash.0)
        );
        assert_eq!(chain.chain_snapshot().tip_hash, tip.hash);
        assert_eq!(chain.chain_snapshot().tip_height, 100);
        assert_eq!(chain.coin_stats.snapshot().height, 100);
        assert!(chain.utxo.get(&funding).is_some());
        assert!(
            chain
                .utxo
                .get(&OutPoint::new(invalid.txs[1].txid(), 0))
                .is_none()
        );
        assert_eq!(chain.durable_head.load()?, head);
        assert_eq!(chain.undo_store.load_undo(101, hash)?, undo);
        assert_eq!(
            chain
                .block_body_store
                .as_ref()
                .ok_or("missing body store")?
                .load_block_body(101, hash)?,
            Some(consensus_bytes(&invalid))
        );
        assert!(matches!(
            chain.begin_transition(),
            Err(ApplyError::Shutdown)
        ));
        if marker {
            assert_eq!(
                std::fs::read(
                    dir.path()
                        .join(JOURNAL_DIR_NAME)
                        .join(FULL_REVALIDATION_MARKER)
                )?,
                b"journal fork crossed below checkpoint base\n"
            );
        }
    }
    Ok(())
}

#[test]
fn valid_cold_revalidation_reuses_the_durable_receipt() -> TestResult {
    for marker in [false, true] {
        let (mut chain, valid, funding, checkpoint_dir) = commit_chain(OP_PUSHNUM_1, marker)?;
        let head = chain.durable_head.load()?.ok_or("missing durable head")?;
        let dir = prepare_cold(&mut chain, checkpoint_dir, marker, ValidationMode::Full)?;
        super::super::reconcile_at_boot(&chain)?;
        let tip = chain.applied_tip_snapshot().ok_or("missing replay tip")?;
        assert_eq!((tip.height, tip.hash), (head.height, head.tip));
        assert_eq!(tip.chain_tx_count.to_wire(), head.chain_tx_count);
        assert_eq!(chain.durable_head.load()?, Some(head));
        assert_eq!(chain.chain_snapshot().tip_hash, head.tip);
        assert!(chain.utxo.get(&funding).is_none());
        assert!(
            chain
                .utxo
                .get(&OutPoint::new(valid.txs[1].txid(), 0))
                .is_some()
        );
        assert!(chain.begin_transition().is_ok());
        // Replay alone cannot retire the marker: publication owns retirement.
        assert_eq!(
            crate::recovery::requires_full_revalidation(dir.path()),
            marker
        );
    }
    Ok(())
}

#[test]
fn cold_revalidation_still_refuses_corrupt_undo_instead_of_replacing_it() -> TestResult {
    let (mut chain, valid, _, checkpoint_dir) = commit_chain(OP_PUSHNUM_1, true)?;
    let head = chain.durable_head.load()?;
    let hash = valid.block_hash().0;
    chain.undo_store.persist_undo(101, hash, b"corrupt")?;
    let dir = prepare_cold(&mut chain, checkpoint_dir, true, ValidationMode::Full)?;
    let error = super::super::reconcile_at_boot(&chain)
        .err()
        .ok_or("corrupt undo must fail closed")?;
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable {
            reason: "a committed gap undo record does not load",
            ..
        }
    ));
    assert_eq!(chain.durable_head.load()?, head);
    assert_eq!(
        chain.undo_store.load_undo(101, hash)?,
        Some(b"corrupt".to_vec())
    );
    assert!(crate::recovery::requires_full_revalidation(dir.path()));
    assert!(matches!(
        chain.begin_transition(),
        Err(ApplyError::Shutdown)
    ));
    Ok(())
}

#[test]
fn valid_warm_revalidation_reuses_the_durable_receipt_and_undo_preparation() -> TestResult {
    let (mut chain, valid, funding, checkpoint_dir) = commit_chain(OP_PUSHNUM_1, true)?;
    let checkpoint_dir = checkpoint_dir.ok_or("missing checkpoint dir")?;
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let _dir = prepare_warm(&mut chain, checkpoint_dir, ValidationMode::Full)?;
    super::super::reconcile_at_boot(&chain)?;
    let tip = chain.applied_tip_snapshot().ok_or("missing replay tip")?;
    assert_eq!((tip.height, tip.hash), (head.height, head.tip));
    assert_eq!(tip.chain_tx_count.to_wire(), head.chain_tx_count);
    assert_eq!(chain.durable_head.load()?, Some(head));
    assert_eq!(chain.chain_snapshot().tip_hash, head.tip);
    assert!(chain.utxo.get(&funding).is_none());
    assert!(
        chain
            .utxo
            .get(&OutPoint::new(valid.txs[1].txid(), 0))
            .is_some()
    );
    assert!(chain.begin_transition().is_ok());
    Ok(())
}

#[test]
fn warm_accepted_base_control_preserves_trust_and_reuses_durable_receipt() -> TestResult {
    let (mut chain, invalid, funding, checkpoint_dir) = commit_chain(OP_RETURN, true)?;
    let checkpoint_dir = checkpoint_dir.ok_or("missing checkpoint dir")?;
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let _dir = prepare_warm(&mut chain, checkpoint_dir, ValidationMode::Full)?;
    // Warm replay trusts the committed gap above an accepted checkpoint,
    // so scripts are not re-verified and the gap replays to the stored head.
    super::super::reconcile_at_boot(&chain)?;
    let tip = chain.applied_tip_snapshot().ok_or("missing replay tip")?;
    assert_eq!((tip.height, tip.hash), (head.height, head.tip));
    assert_eq!(tip.chain_tx_count.to_wire(), head.chain_tx_count);
    assert_eq!(chain.durable_head.load()?, Some(head));
    assert_eq!(chain.chain_snapshot().tip_hash, head.tip);
    assert!(chain.utxo.get(&funding).is_none());
    assert!(
        chain
            .utxo
            .get(&OutPoint::new(invalid.txs[1].txid(), 0))
            .is_some()
    );
    assert!(chain.begin_transition().is_ok());
    Ok(())
}
