//! Cold recovery must not inherit script trust from `AssumeValid` commits (#1730).

use std::path::Path;
use std::sync::Arc;

use super::*;
use crate::{
    ValidationMode,
    recovery::{
        ResumeSource, prepare_initial_chainstate, require_full_script_attestation,
        requires_full_revalidation,
    },
};
use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut,
    Witness, consensus_bytes,
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

fn chain_at_height_100() -> TestResult<(Chainstate, OutPoint, TxOut, BlockHash)> {
    let (mut chain, first) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    let genesis = Network::Regtest.genesis_block();
    bodies.persist_block_body(0, genesis.block_hash().0, &consensus_bytes(&genesis))?;
    chain.block_body_store = Some(bodies);
    chain.apply_block(&BlockPayload::from_local(first.clone()))?;
    let funding = OutPoint::new(first.txs[0].txid(), 0);
    let funding_output = first.txs[0].outputs[0].clone();
    let mut parent = first.block_hash();
    for height in 2..=100 {
        let child = mined_child(parent, height)?;
        chain.apply_block(&BlockPayload::from_local(child.clone()))?;
        parent = child.block_hash();
    }
    Ok((chain, funding, funding_output, parent))
}
fn commit_chain(
    opcode: u8,
) -> TestResult<(Chainstate, Block, OutPoint, Option<tempfile::TempDir>)> {
    let (chain, funding, funding_output, parent) = chain_at_height_100()?;
    commit_spent_script(chain, funding, funding_output, parent, opcode, None)
}
fn commit_chain_with_checkpoint(
    opcode: u8,
) -> TestResult<(Chainstate, Block, OutPoint, tempfile::TempDir)> {
    let (chain, funding, funding_output, parent) = chain_at_height_100()?;
    let checkpoint_dir = tempfile::tempdir()?;
    crate::events::initialize_data_dir(checkpoint_dir.path())?;
    write_accepted_checkpoint(checkpoint_dir.path(), &chain)?;
    let (chain, block, funding, checkpoint_dir) = commit_spent_script(
        chain,
        funding,
        funding_output,
        parent,
        opcode,
        Some(checkpoint_dir),
    )?;
    let checkpoint_dir =
        checkpoint_dir.ok_or("the accepted checkpoint directory must survive the commit")?;
    Ok((chain, block, funding, checkpoint_dir))
}
fn commit_spent_script(
    mut chain: Chainstate,
    funding: OutPoint,
    funding_output: TxOut,
    parent: BlockHash,
    opcode: u8,
    checkpoint_dir: Option<tempfile::TempDir>,
) -> TestResult<(Chainstate, Block, OutPoint, Option<tempfile::TempDir>)> {
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
    // script verdict before AssumeValid deliberately skips it during block connect.
    let verdict = bitcoin_rs_consensus::verify_transaction(
        &spend,
        &SpendView(funding, funding_output),
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
    chain.validation_mode = ValidationMode::AssumeValid;
    chain.assume_valid_height = 102;
    chain.assume_valid_gate = std::sync::Arc::new(crate::AssumeValidGate::with_anchor(Some((
        102,
        successor.block_hash().0,
    ))));
    chain.assume_valid_gate.evaluate(&chain.block_tree.read());
    chain.apply_block(&BlockPayload::from_local(spend_block.clone()))?;
    chain.apply_block(&BlockPayload::from_local(successor))?;
    Ok((chain, spend_block, funding, checkpoint_dir))
}

const FULL_REVALIDATION_MARKER_TEXT: &[u8] = b"journal fork crossed below checkpoint base\n";

fn write_full_revalidation_marker(dir: &Path, marker: &[u8]) -> TestResult {
    let journal = dir.join(JOURNAL_DIR_NAME);
    std::fs::create_dir_all(&journal)?;
    std::fs::write(journal.join(FULL_REVALIDATION_MARKER), marker)?;
    Ok(())
}

fn prepare_cold(
    chain: &mut Chainstate,
    checkpoint_dir: Option<tempfile::TempDir>,
    mode: ValidationMode,
) -> TestResult<tempfile::TempDir> {
    prepare_cold_with_optional_marker(chain, checkpoint_dir, mode, None)
}

fn prepare_cold_with_marker(
    chain: &mut Chainstate,
    checkpoint_dir: Option<tempfile::TempDir>,
    mode: ValidationMode,
) -> TestResult<tempfile::TempDir> {
    prepare_cold_with_optional_marker(
        chain,
        checkpoint_dir,
        mode,
        Some(FULL_REVALIDATION_MARKER_TEXT),
    )
}

fn prepare_cold_with_optional_marker(
    chain: &mut Chainstate,
    checkpoint_dir: Option<tempfile::TempDir>,
    mode: ValidationMode,
    marker: Option<&[u8]>,
) -> TestResult<tempfile::TempDir> {
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let journal_config = crate::ChainstateJournalConfig {
        enabled: false,
        ..crate::ChainstateJournalConfig::default()
    };
    let dir = if let Some(dir) = checkpoint_dir {
        if let Some(marker) = marker {
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
            write_full_revalidation_marker(dir.path(), marker)?;
        }
        dir
    } else {
        let dir = tempfile::tempdir()?;
        crate::events::initialize_data_dir(dir.path())?;
        if let Some(marker) = marker {
            write_full_revalidation_marker(dir.path(), marker)?;
        }
        dir
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
    for mode in [ValidationMode::Full, ValidationMode::AssumeValid] {
        for marker in [false, true] {
            let (mut chain, invalid, funding, checkpoint_dir) = if marker {
                let (chain, invalid, funding, checkpoint_dir) =
                    commit_chain_with_checkpoint(OP_RETURN)?;
                (chain, invalid, funding, Some(checkpoint_dir))
            } else {
                commit_chain(OP_RETURN)?
            };
            let head = chain.durable_head.load()?;
            let hash = invalid.block_hash().0;
            let undo = chain.undo_store.load_undo(101, hash)?;
            let dir = if marker {
                prepare_cold_with_marker(&mut chain, checkpoint_dir, mode)?
            } else {
                prepare_cold(&mut chain, checkpoint_dir, mode)?
            };
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
    }
    Ok(())
}

#[test]
fn valid_cold_revalidation_reuses_the_durable_receipt() -> TestResult {
    for marker in [false, true] {
        let (mut chain, valid, funding, checkpoint_dir) = if marker {
            let (chain, valid, funding, checkpoint_dir) =
                commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
            (chain, valid, funding, Some(checkpoint_dir))
        } else {
            commit_chain(OP_PUSHNUM_1)?
        };
        let head = chain.durable_head.load()?.ok_or("missing durable head")?;
        let dir = if marker {
            prepare_cold_with_marker(&mut chain, checkpoint_dir, ValidationMode::Full)?
        } else {
            prepare_cold(&mut chain, checkpoint_dir, ValidationMode::Full)?
        };
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
    let (mut chain, valid, _, checkpoint_dir) = commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
    let head = chain.durable_head.load()?;
    let hash = valid.block_hash().0;
    chain.undo_store.persist_undo(101, hash, b"corrupt")?;
    let dir = prepare_cold_with_marker(&mut chain, Some(checkpoint_dir), ValidationMode::Full)?;
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
    let (mut chain, valid, funding, checkpoint_dir) = commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
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
fn warm_assume_valid_start_over_an_accepted_checkpoint_reuses_the_durable_receipt() -> TestResult {
    let (mut chain, invalid, funding, checkpoint_dir) = commit_chain_with_checkpoint(OP_RETURN)?;
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let _dir = prepare_warm(&mut chain, checkpoint_dir, ValidationMode::AssumeValid)?;
    // An AssumeValid start trusts the committed gap above an accepted checkpoint,
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

fn journal_off() -> crate::ChainstateJournalConfig {
    crate::ChainstateJournalConfig {
        enabled: false,
        ..crate::ChainstateJournalConfig::default()
    }
}

// RCV-02
#[test]
fn full_start_over_an_assume_valid_commit_rebuilds_cold_and_rejects_the_invalid_script()
-> TestResult {
    let (mut chain, invalid, funding, checkpoint_dir) = commit_chain_with_checkpoint(OP_RETURN)?;
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    assert_eq!(
        chain.durable_head.load_attestation(&head)?,
        bitcoin_rs_storage::ScriptAttestation::AssumeValid,
        "the block committed with scripts skipped, so the head attests AssumeValid at best"
    );

    require_full_script_attestation(
        checkpoint_dir.path(),
        ValidationMode::AssumeValid,
        Some(&head),
        chain.durable_head.as_ref(),
        false,
    )?;
    assert!(!requires_full_revalidation(checkpoint_dir.path()));
    let warm = prepare_initial_chainstate(
        checkpoint_dir.path(),
        Network::Regtest,
        journal_off(),
        Some(&head),
    )?;
    assert_eq!(
        warm.resume_source,
        ResumeSource::Checkpoint,
        "an AssumeValid restart of the same datadir keeps the warm checkpoint replay"
    );

    require_full_script_attestation(
        checkpoint_dir.path(),
        ValidationMode::Full,
        Some(&head),
        chain.durable_head.as_ref(),
        false,
    )?;
    assert!(requires_full_revalidation(checkpoint_dir.path()));
    let dir = prepare_cold(&mut chain, Some(checkpoint_dir), ValidationMode::Full)?;
    let error = super::super::reconcile_at_boot(&chain)
        .err()
        .ok_or("a Full restart must execute the skipped script")?;
    assert!(
        matches!(error, ApplyError::Consensus(ConsensusError::Script { .. })),
        "{error:?}"
    );
    let tip = chain
        .applied_tip_snapshot()
        .ok_or("missing replay prefix")?;
    assert_eq!(
        (tip.height, tip.hash),
        (100, invalid.header.prev_blockhash.0),
        "nothing publishes at the invalid height"
    );
    assert!(chain.utxo.get(&funding).is_some());
    drop(dir);
    Ok(())
}

// RCV-02
#[test]
fn a_completed_full_cold_rebuild_attests_the_head_as_fully_executed() -> TestResult {
    let (mut chain, _valid, _funding, checkpoint_dir) = commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    assert_eq!(
        chain.durable_head.load_attestation(&head)?,
        bitcoin_rs_storage::ScriptAttestation::AssumeValid
    );
    require_full_script_attestation(
        checkpoint_dir.path(),
        ValidationMode::Full,
        Some(&head),
        chain.durable_head.as_ref(),
        false,
    )?;
    let _dir = prepare_cold(&mut chain, Some(checkpoint_dir), ValidationMode::Full)?;
    super::super::reconcile_at_boot(&chain)?;
    assert_eq!(
        chain.durable_head.load_attestation(&head)?,
        bitcoin_rs_storage::ScriptAttestation::Full,
        "a cold rebuild executed every script, so the next Full start needs no rebuild"
    );
    Ok(())
}

// RCV-02
#[test]
fn full_start_over_a_pruned_datadir_names_the_way_out() -> TestResult {
    let (chain, _block, _funding, checkpoint_dir) = commit_chain_with_checkpoint(OP_PUSHNUM_1)?;
    let head = chain.durable_head.load()?.ok_or("missing durable head")?;
    let error = require_full_script_attestation(
        checkpoint_dir.path(),
        ValidationMode::Full,
        Some(&head),
        chain.durable_head.as_ref(),
        true,
    )
    .err()
    .ok_or("a pruned datadir cannot rebuild with full validation")?;
    assert!(
        error.to_string().contains("--validation-mode assume-valid"),
        "{error}"
    );
    assert!(!requires_full_revalidation(checkpoint_dir.path()));
    Ok(())
}
