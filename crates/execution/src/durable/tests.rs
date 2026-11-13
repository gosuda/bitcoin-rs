use crate::chain::current_unix_seconds;
use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
use bitcoin_rs_consensus::primitives::{
    Block, BlockHash, BlockImage, Hash256, Network, consensus_bytes,
};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_storage::{
    CoinKey, ColumnFamily, CommitRecords, DurableHead, DurableHeadStore, InMemoryDurableHeadStore,
    KvStore, StorageError,
};
use parking_lot::Mutex;
use proptest::prelude::*;
use std::sync::Arc;

use crate::test_fixtures::{TestError, TestResult, handles, handles_with_store, seed_genesis};
use crate::test_support::MemoryBodies;
use crate::{ApplyError, Chainstate};

mod revalidation;

#[test]
fn replay_refuses_zero_output_coinbase_and_preserves_committed_evidence() -> TestResult {
    // RCV-04
    for cold in [false, true] {
        for mode in [
            crate::ValidationMode::Full,
            crate::ValidationMode::AssumeValid,
        ] {
            let (mut chain, mut child) = restored_chainstate()?;
            chain.validation_mode = mode;
            child.txs[0].outputs.clear();
            child.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&child.txs)
                .ok_or(TestError::Missing("merkle root"))?;
            crate::chain::regtest_fixture::mine_block_to_declared_target(&mut child)?;
            let bodies = Arc::new(MemoryBodies::default());
            let genesis = Network::Regtest.genesis_block();
            bodies.persist_block_body(0, genesis.block_hash().0, &consensus_bytes(&genesis))?;
            let hash = child.block_hash().0;
            let bytes = consensus_bytes(&child);
            bodies.persist_block_body(1, hash, &bytes)?;
            let head = install_head(&mut chain, &child, Arc::clone(&bodies))?;
            let stats = chain.coin_stats.snapshot().to_bytes();
            if cold {
                chain.applied_tip.store(None);
                chain.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
            }
            let result = super::reconcile_at_boot(&chain);
            assert!(
                matches!(
                    result,
                    Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::EmptyOutputs
                    ))
                ),
                "cold={cold}, mode={mode:?}: {result:?}"
            );
            let tip = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("valid prefix remains published"))?;
            assert_eq!((tip.height, tip.hash), (0, genesis.block_hash().0));
            assert_ne!(chain.chain_snapshot().tip_hash, hash);
            assert_eq!(chain.utxo.len(), 0);
            assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
            assert_eq!(chain.durable_head.load()?, Some(head));
            assert_eq!(bodies.load_block_body(1, hash)?, Some(bytes));
            assert!(chain.undo_store.load_undo(1, hash)?.is_none());
            assert!(
                chain.begin_transition().is_err(),
                "replay failure closes admission"
            );
        }
    }
    Ok(())
}

fn restored_chainstate() -> TestResult<(Chainstate, Block)> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis_tip = seed_genesis(&handles)?;
    handles.coin_stats.finish_block(0, 1);
    let child = mined_child(BlockHash(genesis_tip.hash), 1)?;
    Ok((handles, child))
}

fn install_head(
    handles: &mut Chainstate,
    child: &Block,
    bodies: Arc<MemoryBodies>,
) -> Result<DurableHead, StorageError> {
    let hash = Hash256::from(child.block_hash());
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 7,
        height: 1,
        tip: hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(handles, &head, bodies)?;
    Ok(head)
}

fn install_arbitrary_head(
    handles: &mut Chainstate,
    head: &DurableHead,
    bodies: Arc<MemoryBodies>,
) -> Result<(), StorageError> {
    let durable = Arc::new(InMemoryDurableHeadStore::new());
    durable.commit(None, head, &CommitRecords::default())?;
    handles.durable_head = durable;
    handles.block_body_store = Some(bodies);
    Ok(())
}

// RCV-04, RCV-14
#[test]
fn committed_gap_replays_to_head_without_recommitting_it() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = install_head(&mut handles, &child, bodies)?;

    super::reconcile_at_boot(&handles)?;

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::UnexpectedSuccess(
            "replay did not publish an applied tip",
        ))?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    assert_eq!(
        landed.chain_tx_count,
        crate::chain::ChainTxCount::established(2)
    );
    assert_eq!(handles.durable_head.load()?, Some(head));
    assert_eq!(
        handles.durable_head.load()?.map(|head| head.commit_id),
        Some(7),
        "replay must consume the durable receipt rather than creating a new one"
    );
    Ok(())
}

#[test]
fn replay_of_a_committed_gap_never_fires_the_staged_tip_hook() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = install_head(&mut handles, &child, bodies)?;

    let fires: Arc<Mutex<Vec<(Hash256, Hash256)>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&fires);
    handles
        .set_tip_staged(Arc::new(
            move |staged: &crate::chain::TipSnapshot, block: &BlockImage| {
                recorder
                    .lock()
                    .push((staged.hash, Hash256::from(block.block_hash())));
            },
        ))
        .map_err(|_| TestError::HookAlreadyInstalled("staged-tip"))?;

    super::reconcile_at_boot(&handles)?;

    assert!(
        fires.lock().is_empty(),
        "replay of a committed gap schedules no speculative preparation work"
    );
    let landed = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::UnexpectedSuccess(
            "replay did not publish an applied tip",
        ))?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    Ok(())
}

#[test]
fn replay_publishes_the_receipt_certified_count() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 7,
        height: 1,
        tip: Hash256::from(child.block_hash()),
        chain_tx_count: 5,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(&mut handles, &head, bodies)?;

    super::reconcile_at_boot(&handles)?;

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::UnexpectedSuccess(
            "replay did not publish an applied tip",
        ))?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    assert_eq!(
        landed.chain_tx_count,
        crate::chain::ChainTxCount::established(5),
        "the published count is the receipt's, not the derivation's"
    );
    Ok(())
}

#[test]
fn replay_gap_skips_the_live_future_drift_recheck() -> TestResult {
    let (mut handles, mut child) = restored_chainstate()?;
    child.header.time = current_unix_seconds().saturating_add(4 * 60 * 60);
    crate::chain::regtest_fixture::mine_header_to_declared_target(&mut child.header)?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = install_head(&mut handles, &child, bodies)?;

    super::reconcile_at_boot(&handles)?;

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::UnexpectedSuccess(
            "replay did not publish an applied tip",
        ))?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    Ok(())
}

#[test]
fn committed_gap_with_missing_body_fails_closed() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    let head = install_head(&mut handles, &child, Arc::new(MemoryBodies::default()))?;

    let Err(error) = super::reconcile_at_boot(&handles) else {
        panic!("missing committed body must fail");
    };
    let ApplyError::DurableHeadGapUnrecoverable {
        head_tip,
        head_height,
        restored_tip,
        restored_height,
        ..
    } = error
    else {
        panic!("expected DurableHeadGapUnrecoverable, got {error:?}");
    };
    assert_eq!(head_tip, head.tip);
    assert_eq!(head_height, 1);
    assert_eq!(restored_tip, Some(Network::Regtest.genesis_block_hash()));
    assert_eq!(restored_height, Some(0));
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .map(|tip| (tip.height, tip.hash)),
        Some((0, Network::Regtest.genesis_block_hash()))
    );
    assert_eq!(handles.durable_head.load()?, Some(head));
    Ok(())
}

// RCV-15
#[test]
fn cold_chainstate_replays_head_chain_from_genesis() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    handles.applied_tip.store(None);
    handles.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let genesis = Network::Regtest.genesis_block();
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        0,
        Hash256::from(genesis.block_hash()),
        &consensus_bytes(&genesis),
    )?;
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = install_head(&mut handles, &child, bodies)?;

    super::reconcile_at_boot(&handles)?;

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::UnexpectedSuccess(
            "cold replay did not publish an applied tip",
        ))?;
    assert_eq!((landed.height, landed.hash), (1, head.tip));
    assert_eq!(
        landed.chain_tx_count,
        crate::chain::ChainTxCount::established(2)
    );
    assert_eq!(
        handles.durable_head.load()?,
        Some(head),
        "replay must consume the durable receipt rather than creating a new one"
    );
    Ok(())
}

#[test]
fn cold_chainstate_with_missing_genesis_body_fails_closed() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    handles.applied_tip.store(None);
    handles.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    let head = install_head(&mut handles, &child, bodies)?;

    let Err(error) = super::reconcile_at_boot(&handles) else {
        panic!("a missing committed body must fail even on a cold chainstate");
    };
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable {
            restored_tip: None,
            restored_height: None,
            ..
        }
    ));
    assert!(handles.applied_tip.load_full().is_none());
    assert_eq!(handles.durable_head.load()?, Some(head));
    Ok(())
}

#[test]
fn matching_durable_head_requires_no_replay() -> TestResult {
    let (mut handles, _) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::Missing("restored tip missing"))?;
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 3,
        height: restored.height,
        tip: restored.hash,
        chain_tx_count: 1,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(&mut handles, &head, Arc::new(MemoryBodies::default()))?;

    super::reconcile_at_boot(&handles)?;

    assert_eq!(handles.durable_head.load()?, Some(head));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(restored.hash)
    );
    Ok(())
}

// RCV-14
#[test]
fn durable_head_at_or_below_restored_tip_is_not_a_replay_gap() -> TestResult {
    let (handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::Missing("restored tip missing"))?;
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 4,
        height: restored.height,
        tip: Hash256::from(child.block_hash()),
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, &head, Some(&restored)) else {
        panic!("head at restored height is not a publication gap");
    };
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable { .. }
    ));
    Ok(())
}

#[test]
fn wide_authenticated_gap_replays_to_durable_head() -> TestResult {
    let (mut handles, first) = restored_chainstate()?;
    let width = crate::window::DURABLE_HEAD_GROUP_BLOCKS + 1;
    let bodies = Arc::new(MemoryBodies::default());
    let mut tip_hash = Hash256::from(first.block_hash());
    bodies.persist_block_body(1, tip_hash, &consensus_bytes(&first))?;
    for height in 2..=u32::try_from(width)? {
        let block = mined_child(BlockHash(tip_hash), height)?;
        tip_hash = Hash256::from(block.block_hash());
        bodies.persist_block_body(height, tip_hash, &consensus_bytes(&block))?;
    }
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 5,
        height: u32::try_from(width)?,
        tip: tip_hash,
        chain_tx_count: u64::try_from(width)? + 1,
        body_extent: None,
        undo_extent: None,
    };
    let certified = (head.height, head.tip, head.chain_tx_count);
    install_arbitrary_head(&mut handles, &head, bodies)?;

    super::reconcile_at_boot(&handles)?;

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::UnexpectedSuccess(
            "wide replay did not publish an applied tip",
        ))?;
    assert_eq!(
        (landed.height, landed.hash, landed.chain_tx_count.to_wire()),
        certified
    );
    assert_eq!(handles.coin_stats.snapshot().tx_count, certified.2);
    assert_eq!(
        handles.durable_head.load()?.map(|head| head.commit_id),
        Some(5),
        "replay must consume the durable receipt rather than creating a new one"
    );
    Ok(())
}

#[test]
fn committed_gap_body_must_hash_to_the_head_identity() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::Missing("restored tip missing"))?;
    let claimed = Hash256::from_le_bytes(&[0x55; 32]);
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(1, claimed, &consensus_bytes(&child))?;
    handles.block_body_store = Some(bodies);
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 6,
        height: 1,
        tip: claimed,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, &head, Some(&restored)) else {
        panic!("body/hash mismatch must fail");
    };
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable { .. }
    ));
    Ok(())
}

#[test]
fn committed_gap_must_descend_from_restored_tip() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::Missing("restored tip missing"))?;
    let mut wrong_restored = (*restored).clone();
    wrong_restored.hash = Hash256::from_le_bytes(&[0x44; 32]);
    let child_hash = Hash256::from(child.block_hash());
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(1, child_hash, &consensus_bytes(&child))?;
    handles.block_body_store = Some(bodies);
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 7,
        height: 1,
        tip: child_hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, &head, Some(&wrong_restored)) else {
        panic!("head chain rooted elsewhere must fail");
    };
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable { .. }
    ));
    Ok(())
}

#[test]
fn committed_gap_replay_failure_fails_closed() -> TestResult {
    let (mut handles, mut child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or(TestError::Missing("restored tip missing"))?;
    child.header.merkle_root = Hash256::from_le_bytes(&[0x77; 32]);
    let child_hash = Hash256::from(child.block_hash());
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(1, child_hash, &consensus_bytes(&child))?;
    let head = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 9,
        height: 1,
        tip: child_hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(&mut handles, &head, bodies)?;

    let Err(error) = super::replay_committed_gap(&handles, &head, Some(&restored)) else {
        panic!("a gap body that fails apply must fail the replay");
    };
    assert!(
        handles.shutdown_reader().is_triggered(),
        "a failed replay must fail closed, got: {error}"
    );
    assert!(
        matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
        "admission must stay closed after a failed replay"
    );
    Ok(())
}

struct AttestFailHeadStore {
    inner: Arc<dyn DurableHeadStore>,
}

impl DurableHeadStore for AttestFailHeadStore {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.inner.load()
    }

    fn load_attestation(
        &self,
        head: &DurableHead,
    ) -> Result<bitcoin_rs_storage::ScriptAttestation, StorageError> {
        self.inner.load_attestation(head)
    }

    fn load_suffix_attestation(
        &self,
        head: &DurableHead,
    ) -> Result<bitcoin_rs_storage::ScriptAttestation, StorageError> {
        self.inner.load_suffix_attestation(head)
    }

    fn attest(
        &self,
        _head: &DurableHead,
        _level: bitcoin_rs_storage::ScriptAttestation,
    ) -> Result<(), StorageError> {
        Err(StorageError::Backend(
            "simulated attestation failure".to_owned(),
        ))
    }
}

// RCV-02
#[test]
fn cold_replay_attestation_failure_fails_closed() -> TestResult {
    let (mut handles, child) = restored_chainstate()?;
    handles.applied_tip.store(None);
    handles.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let genesis = Network::Regtest.genesis_block();
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        0,
        Hash256::from(genesis.block_hash()),
        &consensus_bytes(&genesis),
    )?;
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    install_head(&mut handles, &child, bodies)?;
    let inner = Arc::clone(&handles.durable_head);
    handles.durable_head = Arc::new(AttestFailHeadStore { inner });

    let Err(error) = super::reconcile_at_boot(&handles) else {
        panic!("a failed Full attestation must fail the rebuild");
    };
    assert!(
        matches!(error, ApplyError::DurableHeadCommit(_)),
        "the attestation failure surfaces unchanged, got: {error:?}"
    );
    assert!(
        handles.shutdown_reader().is_triggered(),
        "a failed Full attestation must fail closed"
    );
    assert!(
        matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
        "admission must stay closed after a failed attestation"
    );
    Ok(())
}

struct CrashFault;

impl bitcoin_rs_storage::commit::CommitFault for CrashFault {
    fn before_commit(
        &self,
        _prefix: &bitcoin_rs_storage::AcceptedPrefix,
    ) -> Result<(), bitcoin_rs_storage::CommitError> {
        Err(bitcoin_rs_storage::CommitError::Storage(
            StorageError::Backend("simulated crash during head commit".to_owned()),
        ))
    }
}

// RCV-03
proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256),
        ..ProptestConfig::default()
    })]
    #[test]
    fn stateful_crash_window_leaves_state_exactly_before_or_after(
        fail_mode in 0_u8..=2,
        cold_boot in any::<bool>(),
    ) {
        let bodies: Arc<dyn BlockBodyStore> = Arc::new(MemoryBodies::default());
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        bodies
            .persist_block_body(0, genesis_hash, &consensus_bytes(&genesis))
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

        let genesis_head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: genesis_hash,
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        };

        let child1 = mined_child(BlockHash(genesis_hash), 1)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let child1_hash = Hash256::from(child1.block_hash());
        let child_coinbase_txid = child1.txs[0].txid();
        let child_coinbase_value = child1.txs[0].outputs[0].value.to_sat();
        bodies
            .persist_block_body(1, child1_hash, &consensus_bytes(&child1))
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

        let store = Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
        let mut chain = handles_with_store(
            Network::Regtest,
            Arc::new(UtxoSet::new()),
            Arc::clone(&store),
        );
        chain
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: None,
                next_head: genesis_head,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let genesis_tip = seed_genesis(&chain).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        chain.block_body_store = Some(Arc::clone(&bodies));

        if fail_mode == 0 {
            chain.commit_authority.set_fault(Arc::new(CrashFault));
        }

        let payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(child1);
        let apply_result = chain.apply_block(&payload);

        let prior_head = genesis_head;

        if fail_mode == 0 {
            prop_assert!(apply_result.is_err(), "write index failure must return error");
        } else {
            prop_assert!(apply_result.is_ok(), "clean write must succeed");
        }

        let committed_head = chain
            .durable_head
            .load()
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let mut reopened = handles_with_store(
            Network::Regtest,
            Arc::new(UtxoSet::new()),
            Arc::clone(&store),
        );
        let _ = seed_genesis(&reopened).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        reopened.block_body_store = Some(bodies);
        if cold_boot {
            reopened.applied_tip.store(None);
            reopened.coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        } else if fail_mode == 1 {
            reopened.applied_tip.store(Some(Arc::new(genesis_tip)));
        } else {
            reopened.applied_tip.store(chain.applied_tip.load_full());
        }
        super::reconcile_at_boot(&reopened).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;

        let recovered_tip = reopened
            .applied_tip_snapshot()
            .ok_or_else(|| TestCaseError::fail("recovered tip must exist"))?;
        let recovered_head = reopened
            .durable_head
            .load()
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?
            .ok_or_else(|| TestCaseError::fail("recovered head must exist"))?;

        prop_assert_eq!(recovered_tip.height, recovered_head.height);
        prop_assert_eq!(recovered_tip.hash, recovered_head.tip);
        prop_assert_eq!(
            Some(recovered_head),
            committed_head,
            "boot replay must leave the durable head exactly as it was committed"
        );

        let is_state_before = recovered_head == prior_head
            && recovered_tip.height == 0
            && recovered_tip.hash == genesis_hash;
        let is_state_after = recovered_head.height == 1
            && recovered_head.tip == child1_hash
            && recovered_tip.height == 1
            && recovered_tip.hash == child1_hash;

        let child_coinbase_key = CoinKey(child_coinbase_txid.0.to_le_bytes());
        let authoritative_coin = store
            .get(ColumnFamily::Coins, child_coinbase_key.as_bytes())
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        let reopened_coin = reopened
            .coins
            .get(&child_coinbase_key)
            .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
        prop_assert_eq!(
            reopened_coin.is_some(),
            is_state_after,
            "reopened coin view must expose the child coinbase exactly when the block is committed"
        );
        prop_assert_eq!(
            authoritative_coin.is_some(),
            is_state_after,
            "authoritative KV must hold the child coinbase row exactly when the block is committed"
        );
        if is_state_after {
            let committed_bytes = authoritative_coin.as_ref().ok_or_else(|| {
                TestCaseError::fail("committed coin row missing from authoritative store")
            })?;
            prop_assert_eq!(
                reopened_coin.as_deref(),
                authoritative_coin.as_deref(),
                "reopened coin store must read the committed authoritative row unchanged"
            );
            let record = UtxoRecord::from_encoded(committed_bytes.to_vec().into_boxed_slice())
                .map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            prop_assert_eq!(record.txid(), child_coinbase_txid.0);
            let coinbase_out = record
                .find_output(0)
                .ok_or_else(|| TestCaseError::fail("committed coinbase record lost output 0"))?;
            prop_assert_eq!(coinbase_out.height, 1_u32);
            prop_assert!(coinbase_out.coinbase, "committed coinbase row must be marked coinbase");
            prop_assert_eq!(coinbase_out.value, child_coinbase_value);
        }

        if fail_mode == 0 {
            prop_assert!(
                is_state_before,
                "fail mode 0 refuses the head commit, so reopen must land exactly before, got height {}",
                recovered_head.height
            );
        } else {
            prop_assert!(
                is_state_after,
                "fail modes 1 and 2 acknowledge the head commit, so reopen must land exactly after, got height {}",
                recovered_head.height
            );
        }
    }
}
