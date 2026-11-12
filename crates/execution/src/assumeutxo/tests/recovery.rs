//! RCV-02/04 and ARCH-07b: root-selected snapshot recovery with real storage.
use super::*;
use crate::assumeutxo::{DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL, HistoricalAdvance};
use crate::test_fixtures::{TestError, TestResult};
use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::BlockImage;
use bitcoin_rs_storage::assumeutxo::HistoricalCheckpointRef;
use bitcoin_rs_storage::block_body::IndexedBlockBodyStore;
use bitcoin_rs_storage::{
    DurableHeadStore, FlatFileBlockStore, KvDurableHeadStore, KvUndoStore, RocksDbStore,
};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU32;

fn open_persistent(dir: &Path, pinned: &AssumeUtxoData) -> TestResult<Arc<Chainstate>> {
    std::fs::create_dir_all(dir)?;
    crate::events::initialize_data_dir(dir)?;
    let store = Arc::new(RocksDbStore::open(dir.join("chainstate"))?);
    let head_store = Arc::new(KvDurableHeadStore::new(store.clone()));
    let head = head_store.load()?;
    let files = Arc::new(match head.and_then(|head| head.body_extent) {
        Some(extent) => FlatFileBlockStore::open_with_committed_extent(dir, extent)?,
        None => FlatFileBlockStore::open(dir)?,
    });
    let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
    let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
        Arc::clone(&dyn_store),
        64 * 1024 * 1024,
    ));
    let mut active = if head
        .is_some_and(|head| !matches!(head.assumeutxo, AssumeUtxoDiskStatus::Uninitialized))
    {
        if head.is_some_and(|head| matches!(head.assumeutxo, AssumeUtxoDiskStatus::Failed { .. })) {
            return Err(TestError::UnexpectedSuccess("persisted validation failure"));
        }
        let initial = crate::recovery::restore_snapshot(dir, Network::Regtest, pinned)?;
        let stats = Arc::new(CoinStatsListener::new(initial.coin_stats));
        let mut utxo = initial.utxo;
        utxo.track_coin_stats((*stats).clone());
        let header_tip = initial.tree.tip();
        Chainstate::new(
            Network::Regtest,
            Arc::new(ArcSwapOption::new(header_tip)),
            Arc::new(ArcSwapOption::new(initial.applied_tip.map(Arc::new))),
            Arc::new(RwLock::new(initial.tree)),
            Arc::new(utxo),
            stats,
            Arc::new(crate::events::ChainEventPublisher::detached(0)),
        )
    } else if let Some(head) = head.as_ref().filter(|h| h.height > 0) {
        let initial = crate::assumeutxo_snapshot::load_verified(dir, Network::Regtest, pinned)?;
        let tree = initial.tree;
        let node_id = tree
            .lookup(head.tip)
            .ok_or(TestError::Missing("head tip missing from tree"))?;
        let node = tree.node(node_id)?;
        let applied_tip = crate::chain::TipSnapshot {
            tip_id: node_id,
            height: head.height,
            hash: head.tip,
            chainwork: node.chainwork,
            chain_tx_count: crate::chain::ChainTxCount::established(head.chain_tx_count),
        };
        let engine_coins = engine_coin_set_from_store(dyn_store.as_ref())?;
        let mut stats = engine_coins.with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, head.height, true)
        })?;
        stats.tx_count = head.chain_tx_count;
        let listener = Arc::new(CoinStatsListener::new(stats));
        let header_tip = tree.tip();
        Chainstate::new(
            Network::Regtest,
            Arc::new(ArcSwapOption::new(header_tip)),
            Arc::new(ArcSwapOption::new(Some(Arc::new(applied_tip)))),
            Arc::new(RwLock::new(tree)),
            Arc::new(engine_coins),
            listener,
            Arc::new(crate::events::ChainEventPublisher::detached(0)),
        )
    } else {
        Arc::try_unwrap(chainstate()).map_err(|_| TestError::Missing("shared fixture"))?
    };
    coins.track_coin_stats((*active.coin_stats).clone());
    active.durable_head = head_store;
    active.undo_store = Arc::new(KvUndoStore::new(store.clone()));
    active.coins = Arc::clone(&coins);
    active.commit_authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(dyn_store, coins));
    active.block_body_store = Some(Arc::new(IndexedBlockBodyStore::new(store, files)));
    active.configure_checkpointing(dir, Arc::new(AtomicU32::new(0)))?;
    crate::recover_snapshot_activation(&active)?;
    crate::recover_disconnect_marker(&active)?;
    Ok(Arc::new(active))
}

fn activate(dir: &Path, fixture: &Fixture) -> TestResult<(Arc<Chainstate>, AssumeUtxoManager)> {
    let active = open_persistent(dir, &fixture.pinned)?;
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
    {
        let loaded = fixture.load()?;
        manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
    }?;
    Ok((active, manager))
}

#[test]
fn snapshot_lower_height_work_commit_survives_durable_record_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let committed = {
        let mut fixture = snapshot_work_fixture(1, 0x2000_ffff, 2, 0x207f_ffff)?;
        let prior = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("prior head missing"))?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let head = Arc::new(KvDurableHeadStore::new(Arc::clone(&store)));
        let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
        let rocks_coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            64 * 1024 * 1024,
        ));
        bitcoin_rs_storage::CommitAuthority::new(Arc::clone(&dyn_store), rocks_coins)
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: None,
                next_head: prior,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|error| {
                TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
            })?;
        let head_store: Arc<dyn DurableHeadStore> = head.clone();
        let authority_coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
            Arc::clone(&dyn_store),
            64 * 1024 * 1024,
        ));
        let authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
            dyn_store,
            Arc::clone(&authority_coins),
        ));
        let active =
            Arc::get_mut(&mut fixture.active).ok_or(TestError::Missing("shared fixture"))?;
        active.durable_head = head_store;
        active.coins = Arc::clone(&authority_coins);
        active.commit_authority = authority;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        fixture.activate(&manager)?;
        let next = head
            .load()?
            .ok_or(TestError::Missing("snapshot commit missing"))?;
        assert!(next.height < prior.height);
        assert_eq!(next.commit_id, prior.commit_id + 1);
        assert_eq!(next.tip, fixture.pinned.block_hash);
        assert_eq!(next.chain_tx_count, fixture.pinned.chain_tx_count);
        assert_eq!(
            fixture
                .active
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip missing"))?
                .hash,
            next.tip
        );
        assert!(
            matches!(next.assumeutxo, AssumeUtxoDiskStatus::Validating { base_height, base_hash, .. }
            if base_height == next.height && base_hash == next.tip)
        );
        next
    };
    let reopened = KvDurableHeadStore::new(Arc::new(RocksDbStore::open(dir.path())?));
    assert_eq!(reopened.load()?, Some(committed));
    Ok(())
}

#[derive(Default)]
struct SnapshotRestart {
    child: Option<bitcoin_rs_consensus::primitives::Block>,
    stats: CoinStats,
}

#[derive(Default)]
struct UnacceptedCheckpoint {
    coins: Option<bitcoin_rs_consensus::primitives::Hash256>,
    stats: CoinStats,
}

fn finalize_snapshot_after_foreground_restart(
    dir: &Path,
    fixture: &Fixture,
    out: &mut SnapshotRestart,
) -> TestResult {
    let (active, manager) = activate(dir, fixture)?;
    let child =
        crate::chain::regtest_fixture::mined_regtest_child_at(fixture.blocks[2].block_hash(), 3)?;
    active
        .begin_transition()?
        .connect(&BlockImage::from_local(child.clone()))?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone()))?;
    let expected_stats = active.coin_stats.snapshot();
    assert_eq!(expected_stats.utxo_count, 3);
    assert_eq!(expected_stats.total_amount, 15_000_000_000);
    let expected_tip = active
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("missing foreground tip"))?
        .hash;
    drop(manager);
    drop(active);

    let active = open_persistent(dir, &fixture.pinned)?;
    let manager = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
    assert_eq!(active.coin_stats.snapshot(), expected_stats);
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing recovered tip"))?
            .hash,
        expected_tip
    );
    assert!(active.role().is_assumed_active());
    assert!(
        manager
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical"))?
            .applied_tip_snapshot()
            .is_none()
    );
    let archived_head = active.durable_head.load()?;
    let archived_extent = active
        .block_body_store
        .as_ref()
        .and_then(|store| store.append_cursor());
    assert_eq!(
        manager.advance_historical()?,
        HistoricalAdvance::MissingBody {
            height: 2,
            hash: fixture.pinned.block_hash,
        }
    );
    assert_eq!(active.durable_head.load()?, archived_head);
    assert_eq!(
        active
            .block_body_store
            .as_ref()
            .and_then(|store| store.append_cursor()),
        archived_extent
    );
    let events = active.chain_events.snapshot();
    manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
    assert!(active.role().is_ordinary());
    assert_eq!(active.chain_events.snapshot(), events);
    assert_eq!(active.coin_stats.snapshot(), expected_stats);
    out.child = Some(child);
    out.stats = expected_stats;
    Ok(())
}

fn rewind_below_the_snapshot_base(
    dir: &Path,
    fixture: &Fixture,
    child: &bitcoin_rs_consensus::primitives::Block,
    expected_stats: &CoinStats,
    rewound: &mut CoinStats,
) -> TestResult {
    let active = open_persistent(dir, &fixture.pinned)?;
    let manager = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert_eq!(active.coin_stats.snapshot(), *expected_stats);
    active.begin_transition()?.disconnect(child)?;
    active.begin_transition()?.disconnect(&fixture.blocks[2])?;
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing rewound tip"))?
            .height,
        1
    );
    assert!(matches!(
        active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing head"))?
            .assumeutxo,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    assert!(matches!(
        manager.chainstates_summary()?.status,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    let engine_coins = engine_coin_set(&active)?;
    let mut stats = engine_coins
        .with_stable_view(|view| bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, 1, true))?;
    let tip = active
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("missing applied tip"))?;
    stats.tx_count = tip.chain_tx_count.to_wire();
    *rewound = stats;
    Ok(())
}

fn verify_restart_after_rewind(
    dir: &Path,
    fixture: &Fixture,
    rewound_stats: &CoinStats,
) -> TestResult {
    let active = open_persistent(dir, &fixture.pinned)?;
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
    assert!(manager.chainstates_summary()?.active_chainstate.validated);
    let recovered_stats = active.coin_stats.snapshot();
    assert_eq!(
        recovered_stats.muhash.finalize(),
        rewound_stats.muhash.finalize()
    );
    assert_eq!(
        (
            recovered_stats.height,
            recovered_stats.total_amount,
            recovered_stats.bogo_size,
            recovered_stats.tx_count,
            recovered_stats.utxo_count
        ),
        (
            rewound_stats.height,
            rewound_stats.total_amount,
            rewound_stats.bogo_size,
            rewound_stats.tx_count,
            rewound_stats.utxo_count
        ),
    );
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing restarted ordinary tip"))?
            .height,
        1
    );
    Ok(())
}

#[test]
fn durable_snapshot_restarts_foreground_and_background_then_allows_base_reorg() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut restart = SnapshotRestart::default();
    finalize_snapshot_after_foreground_restart(dir.path(), &fixture, &mut restart)?;
    let child = restart
        .child
        .as_ref()
        .ok_or(TestError::Missing("missing restart child"))?;
    let mut rewound = CoinStats::default();
    rewind_below_the_snapshot_base(dir.path(), &fixture, child, &restart.stats, &mut rewound)?;
    verify_restart_after_rewind(dir.path(), &fixture, &rewound)
}

fn engine_coin_set_from_store(store: &dyn bitcoin_rs_storage::KvStore) -> TestResult<UtxoSet> {
    let set = UtxoSet::new();
    for item in store.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
        let (_, value) = item?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|_| TestError::Missing("bad coin record"))?;
        set.insert_parsed_record(record);
    }
    Ok(set)
}

fn engine_coin_set(chain: &Chainstate) -> TestResult<UtxoSet> {
    engine_coin_set_from_store(chain.commit_authority.store().as_ref())
}

fn publish_unaccepted_historical_checkpoint(
    dir: &Path,
    fixture: &Fixture,
    out: &mut UnacceptedCheckpoint,
) -> TestResult {
    let active = open_persistent(dir, &fixture.pinned)?;
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active.clone(),
        dir.to_path_buf(),
        1,
    )?;
    {
        let loaded = fixture.load()?;
        manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
    }?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone()))?;
    let status = manager.status()?;
    let checkpoint = match &status {
        AssumeUtxoDiskStatus::Validating {
            checkpoint: Some(checkpoint),
            historical_height,
            historical_hash,
            ..
        } => {
            assert_eq!(*historical_height, 1);
            assert_eq!(*historical_hash, fixture.blocks[1].block_hash().0);
            *checkpoint
        }
        _ => {
            return Err(TestError::UnexpectedSuccess(
                "unexpected status after checkpoint",
            ));
        }
    };
    assert_eq!(checkpoint.height, 1);
    assert_eq!(checkpoint.hash, fixture.blocks[1].block_hash().0);
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("missing historical"))?;
    let accepted_coins = engine_coin_set(&historical)?
        .lock_stable_view()
        .hash_serialized_3()?;
    let accepted_stats = historical.coin_stats.snapshot();
    historical
        .lock_transition()?
        .into_transition()
        .connect(&BlockImage::from_local(fixture.blocks[2].clone()))?;
    let unaccepted_coins = engine_coin_set(&historical)?
        .lock_stable_view()
        .hash_serialized_3()?;
    assert_ne!(unaccepted_coins, accepted_coins);
    publish_two_historical_checkpoints(
        dir,
        &historical,
        checkpoint,
        unaccepted_coins,
        fixture.blocks[2].block_hash().0,
    )?;
    assert_eq!(
        manager.status()?,
        status,
        "publication cannot advance the durable head"
    );
    drop(historical);
    assert!(
        dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
            .join("CURRENT")
            .exists()
    );
    drop(manager);
    drop(active);
    out.coins = Some(accepted_coins);
    out.stats = accepted_stats;
    Ok(())
}

fn publish_two_historical_checkpoints(
    dir: &Path,
    historical: &Chainstate,
    checkpoint: HistoricalCheckpointRef,
    unaccepted_coins: bitcoin_rs_consensus::primitives::Hash256,
    expected_tip: bitcoin_rs_consensus::primitives::Hash256,
) -> TestResult {
    let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir)?;
    let config = crate::checkpoint::headers::HeaderCheckpointConfig {
        network: Network::Regtest,
        genesis: Network::Regtest.genesis_block_hash(),
    };
    for _ in 0..2 {
        let _ = crate::checkpoint::write_historical_checkpoint_with_store(
            &data,
            config,
            &historical.block_tree,
            &historical.coin_stats,
            historical.applied_tip_snapshot().as_deref(),
            crate::checkpoint::CheckpointStoreTarget {
                store: historical.commit_authority.store().as_ref(),
                host_data_dir: dir,
            },
        )?;
    }
    let crate::checkpoint::CheckpointLoad::Complete(current) =
        crate::checkpoint::load_checkpoint_from_dir_with_path(
            &data,
            Some(dir),
            config,
            bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
        )?
    else {
        return Err(TestError::UnexpectedSuccess(
            "unaccepted CURRENT generation was not published",
        ));
    };
    assert_ne!(current.generation, checkpoint.checkpoint.generation);
    assert_eq!(current.applied_tip.height, 2);
    assert_eq!(current.applied_tip.hash, expected_tip);
    assert_eq!(current.coin_stats.tx_count, 3);
    let engine = current
        .engine
        .as_ref()
        .ok_or(TestError::Missing("missing checkpoint engine"))?;
    let coins = UtxoSet::new();
    for item in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
        let (_, value) = item?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|_| TestError::Missing("bad coin record"))?;
        coins.insert_parsed_record(record);
    }
    assert_eq!(
        coins.lock_stable_view().hash_serialized_3()?,
        unaccepted_coins
    );
    Ok(())
}

fn restart_from_historical_checkpoint(
    dir: &Path,
    fixture: &Fixture,
    accepted_coins: bitcoin_rs_consensus::primitives::Hash256,
    accepted_stats: &CoinStats,
) -> TestResult {
    let active = open_persistent(dir, &fixture.pinned)?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active,
        dir.to_path_buf(),
        1,
    )?;
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("missing restored historical chainstate"))?;
    let restored_tip = historical
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("missing historical checkpoint tip"))?;
    assert_eq!(restored_tip.height, 1);
    assert_eq!(restored_tip.hash, fixture.blocks[1].block_hash().0);
    assert_eq!(restored_tip.chain_tx_count.to_wire(), 2);
    assert_eq!(historical.coin_stats.snapshot(), *accepted_stats);
    assert_eq!(
        engine_coin_set(&historical)?
            .lock_stable_view()
            .hash_serialized_3()?,
        accepted_coins
    );
    let generations =
        std::fs::read_dir(dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT))?
            .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        generations
            .iter()
            .filter(|entry| entry.path().is_dir())
            .count(),
        1,
        "startup must retire publication residue"
    );

    manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert_eq!(
        std::fs::read_dir(dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT))?
            .count(),
        0,
        "finalized commit must retire the last historical checkpoint"
    );
    Ok(())
}

#[test]
fn historical_checkpoint_bounds_restart_replay_to_the_checkpoint_suffix() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut unaccepted = UnacceptedCheckpoint::default();
    publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
    restart_from_historical_checkpoint(
        dir.path(),
        &fixture,
        unaccepted
            .coins
            .ok_or(TestError::Missing("missing accepted coins"))?,
        &unaccepted.stats,
    )
}

#[test]
fn restored_historical_stats_keep_following_commits_after_a_checkpoint_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut unaccepted = UnacceptedCheckpoint::default();
    publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active,
        dir.path().to_path_buf(),
        1,
    )?;
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("missing restored historical chainstate"))?;
    let restored_tip = historical
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("missing historical checkpoint tip"))?;
    assert_same_stats(
        &historical.coin_stats.snapshot(),
        &scanned_historical_stats(
            &historical,
            restored_tip.height,
            restored_tip.chain_tx_count.to_wire(),
        )?,
        restored_tip.height,
    );
    let outcome = manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
    assert!(outcome.height > restored_tip.height);
    assert_same_stats(
        &historical.coin_stats.snapshot(),
        &scanned_historical_stats(
            &historical,
            outcome.height,
            outcome.tip.chain_tx_count.to_wire(),
        )?,
        outcome.height,
    );
    Ok(())
}

fn accepted_historical_generation(dir: &Path, fixture: &Fixture) -> TestResult<u64> {
    let active = open_persistent(dir, &fixture.pinned)?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active,
        dir.to_path_buf(),
        1,
    )?;
    match manager.status()? {
        AssumeUtxoDiskStatus::Validating {
            checkpoint: Some(checkpoint),
            ..
        } => Ok(checkpoint.checkpoint.generation),
        _ => Err(TestError::Missing("missing accepted historical checkpoint")),
    }
}

fn remove_first_engine_coin(engine_dir: &Path) -> TestResult<(u64, u64)> {
    use bitcoin_rs_storage::KvStore as _;
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::open_checkpoint(engine_dir)?;
    let (key, value) = {
        let mut rows = store.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?;
        rows.next()
            .ok_or(TestError::Missing("engine image has no coins"))??
    };
    let record =
        bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
            .map_err(|_| TestError::Missing("bad coin record"))?;
    let outputs = u64::try_from(record.outputs().count())?;
    let amount: u64 = record.outputs().map(|out| out.value).sum();
    let mut batch = store.new_batch();
    batch.delete(bitcoin_rs_storage::ColumnFamily::Coins, &key);
    store.write_durable(batch)?;
    store.checkpoint(engine_dir)?;
    Ok((outputs, amount))
}

fn accepted_generation_dir(dir: &Path, generation: u64) -> PathBuf {
    dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
        .join(format!("gen-{generation:020}"))
}

#[test]
fn historical_checkpoint_coin_stats_come_from_the_engine_image() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut unaccepted = UnacceptedCheckpoint::default();
    publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
    let accepted_stats = unaccepted.stats.clone();
    let generation = accepted_historical_generation(dir.path(), &fixture)?;
    let (removed_outputs, removed_amount) = remove_first_engine_coin(
        &accepted_generation_dir(dir.path(), generation).join("chainstate"),
    )?;
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active,
        dir.path().to_path_buf(),
        1,
    )?;
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("missing restored historical chainstate"))?;
    let restored = historical.coin_stats.snapshot();
    assert_eq!(
        restored.utxo_count,
        accepted_stats.utxo_count - removed_outputs,
        "coin count must follow the engine image, not the coinstats artifact"
    );
    assert_eq!(
        restored.total_amount,
        accepted_stats.total_amount - removed_amount,
        "coin amount must follow the engine image"
    );
    assert_eq!(restored.tx_count, accepted_stats.tx_count);
    Ok(())
}

#[test]
fn historical_checkpoint_without_engine_image_refuses_to_restore() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut unaccepted = UnacceptedCheckpoint::default();
    publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
    let generation = accepted_historical_generation(dir.path(), &fixture)?;
    std::fs::remove_dir_all(accepted_generation_dir(dir.path(), generation).join("chainstate"))?;
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    match AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active,
        dir.path().to_path_buf(),
        1,
    ) {
        Err(crate::AssumeUtxoError::HistoricalCheckpointWithoutEngine) => Ok(()),
        Err(_) => Err(TestError::Missing(
            "a historical checkpoint without an engine image must refuse with its typed error",
        )),
        Ok(_) => Err(TestError::UnexpectedSuccess(
            "a historical checkpoint without an engine image restored",
        )),
    }
}
#[test]
fn finalized_checkpoint_cleanup_failure_is_retried_on_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let (active, manager) = activate(dir.path(), &fixture)?;
    drop(manager);
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active.clone(),
        dir.path().to_path_buf(),
        1,
    )?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    let root = dir
        .path()
        .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
    let generation = std::fs::read_dir(&root)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|entry| entry.path().is_dir())
        .ok_or(TestError::Missing("missing historical generation"))?
        .path();
    let blocker = generation.join("operator-backup");
    std::fs::create_dir(&blocker)?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert!(active.role().is_ordinary());
    assert!(manager.historical_chainstate().is_none());
    assert!(generation.is_dir());
    assert!(active.begin_transition().is_ok());
    let finalized_head = active.durable_head.load()?;
    drop(manager);
    drop(active);

    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())?;
    assert!(active.role().is_ordinary());
    assert!(manager.historical_chainstate().is_none());
    assert_eq!(active.durable_head.load()?, finalized_head);
    assert!(generation.is_dir());
    drop(manager);
    drop(active);
    std::fs::remove_dir(&blocker)?;
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())?;
    assert!(active.role().is_ordinary());
    assert!(manager.historical_chainstate().is_none());
    assert_eq!(active.durable_head.load()?, finalized_head);
    assert_eq!(std::fs::read_dir(root)?.count(), 0);
    Ok(())
}

#[test]
fn snapshot_activation_preserves_full_revalidation_requirement() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())?;
    let marker = dir
        .path()
        .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER);
    std::fs::write(&marker, b"required")?;
    let head = active.durable_head.load()?;
    let tip = active.applied_tip_snapshot();
    assert!(matches!(
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        },
        Err(AssumeUtxoError::FullRevalidationRequired)
    ));
    assert_eq!(active.durable_head.load()?, head);
    assert_eq!(active.applied_tip_snapshot(), tip);
    assert_eq!(std::fs::read(marker)?, b"required");
    assert!(active.role().is_ordinary());
    assert!(!dir.path().join("assumeutxo").exists());
    Ok(())
}

#[test]
fn snapshot_base_checkpoint_is_bound_to_the_pinned_commitment() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let (active, manager) = activate(dir.path(), &fixture)?;
    assert!(active.publish_checkpoint()?.is_some());
    drop(manager);
    drop(active);
    let mut wrong_pin = fixture.pinned;
    wrong_pin.hash_serialized = Hash256::default();
    assert!(crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &wrong_pin).is_err());
    let restored =
        crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned)?;
    let root = dir
        .path()
        .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
    let current: bitcoin_rs_storage::checkpoint::CurrentV1 = sonic_rs::from_slice(&std::fs::read(
        root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE),
    )?)?;
    let generation = root.join(&current.directory);
    let engine = bitcoin_rs_storage::open_checkpoint_store(&generation.join("chainstate"))?;
    let coins = UtxoSet::new();
    for item in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
        let (_, value) = item?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|_| TestError::Missing("bad coin record"))?;
        coins.insert_parsed_record(record);
    }
    assert_eq!(
        coins.lock_stable_view().hash_serialized_3()?,
        fixture.pinned.hash_serialized
    );
    assert_eq!(
        restored
            .applied_tip
            .as_ref()
            .map(|tip| tip.height)
            .ok_or(TestError::Missing("restored tip missing"))?,
        fixture.pinned.height
    );
    Ok(())
}

#[test]
fn snapshot_recovery_rejects_coin_height_alias() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let (active, manager) = activate(dir.path(), &fixture)?;
    drop(manager);
    drop(active);
    let path = dir
        .path()
        .join("assumeutxo")
        .join(fixture.pinned.block_hash.to_string())
        .join("coins.dat");
    let mut bytes = std::fs::read(&path)?;
    let offset = 52 + 45 + 12;
    let height = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?);
    assert!(height <= fixture.pinned.height);
    bytes[offset..offset + 4].copy_from_slice(&(height | 0x8000_0000).to_le_bytes());
    std::fs::write(&path, bytes)?;
    assert!(
        crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned).is_err(),
        "recovery must reject a commitment-preserving coin height mutation"
    );
    Ok(())
}

#[test]
fn committed_snapshot_corruption_fails_closed_but_orphan_import_is_ignored() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    crate::events::initialize_data_dir(dir.path())?;
    let _ =
        crate::assumeutxo_snapshot::write_coins(dir.path(), &fixture.load()?.set, &fixture.pinned)?;
    let cold = open_persistent(dir.path(), &fixture.pinned)?;
    assert!(cold.applied_tip_snapshot().is_none());
    drop(cold);
    let (active, manager) = activate(dir.path(), &fixture)?;
    drop(manager);
    drop(active);
    let coins = dir
        .path()
        .join("assumeutxo")
        .join(fixture.pinned.block_hash.to_string())
        .join("coins.dat");
    std::fs::write(&coins, b"truncated snapshot")?;
    assert!(open_persistent(dir.path(), &fixture.pinned).is_err());
    assert_eq!(std::fs::read(coins)?, b"truncated snapshot");
    Ok(())
}

struct KillCommit {
    phase: String,
    dir: std::path::PathBuf,
}

fn checkpoint_replaced(prefix: &bitcoin_rs_storage::AcceptedPrefix) -> bool {
    match &prefix.next_head.assumeutxo {
        AssumeUtxoDiskStatus::Validating {
            checkpoint: Some(checkpoint),
            ..
        } => {
            checkpoint.height == 1
                && prefix.expected_head.as_ref().is_some_and(|head| {
                    matches!(
                        &head.assumeutxo,
                        AssumeUtxoDiskStatus::Validating {
                            checkpoint: Some(previous),
                            ..
                        } if previous != checkpoint
                    )
                })
        }
        _ => false,
    }
}

fn activation_commit(prefix: &bitcoin_rs_storage::AcceptedPrefix) -> bool {
    prefix.expected_head.is_none()
        && matches!(
            prefix.next_head.assumeutxo,
            AssumeUtxoDiskStatus::Validating { .. }
        )
}

impl bitcoin_rs_storage::CommitFault for KillCommit {
    fn before_commit(
        &self,
        prefix: &bitcoin_rs_storage::AcceptedPrefix,
    ) -> Result<(), bitcoin_rs_storage::CommitError> {
        if self.phase == "checkpoint-published" && checkpoint_replaced(prefix) {
            await_kill(&self.dir);
        }
        if self.phase == "snapshot-ingest" && activation_commit(prefix) {
            await_kill(&self.dir);
        }
        Ok(())
    }

    fn after_commit(
        &self,
        prefix: &bitcoin_rs_storage::AcceptedPrefix,
        _receipt: &bitcoin_rs_storage::DurableReceipt,
    ) {
        if self.phase == "checkpoint-committed" && checkpoint_replaced(prefix) {
            await_kill(&self.dir);
        }
        let kill = match (self.phase.as_str(), &prefix.next_head.assumeutxo) {
            ("activation", AssumeUtxoDiskStatus::Validating { .. }) => {
                prefix.expected_head.is_none()
            }
            ("foreground", _) => false,
            (
                "historical",
                AssumeUtxoDiskStatus::Validating {
                    historical_height: 1,
                    ..
                },
            )
            | ("finalized", AssumeUtxoDiskStatus::Finalized { .. }) => true,
            (
                "checking",
                AssumeUtxoDiskStatus::Validating {
                    pending: Some(pending),
                    ..
                },
            ) => pending.height == 2,
            _ => false,
        };
        if kill {
            await_kill(&self.dir);
        }
    }
}

fn await_kill(dir: &Path) -> ! {
    std::fs::write(dir.join("kill-ready"), b"ready")
        .unwrap_or_else(|error| panic!("kill marker: {error}"));
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(1));
    }
}

#[test]
fn crash_writer() -> TestResult {
    let Some(dir) = std::env::var_os("BITCOIN_RS_SNAPSHOT_KILL_DIR") else {
        return Ok(());
    };
    let dir = std::path::PathBuf::from(dir);
    let phase = std::env::var("BITCOIN_RS_SNAPSHOT_KILL_PHASE")?;
    let fixture = Fixture::new()?;
    let mut active = open_persistent(&dir, &fixture.pinned)?;
    Arc::get_mut(&mut active)
        .ok_or(TestError::Missing("shared crash fixture"))?
        .commit_authority
        .set_fault(Arc::new(KillCommit {
            phase: phase.clone(),
            dir: dir.clone(),
        }));
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    if phase == "import" {
        let _ =
            crate::assumeutxo_snapshot::write_coins(&dir, &fixture.load()?.set, &fixture.pinned)?;
        await_kill(&dir);
    }
    let checkpoint_phase = phase.starts_with("checkpoint-");
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active.clone(),
        dir.clone(),
        if checkpoint_phase || phase == "finalized" {
            1
        } else {
            DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL
        },
    )?;
    {
        let loaded = fixture.load()?;
        manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
    }?;
    let child =
        crate::chain::regtest_fixture::mined_regtest_child_at(fixture.blocks[2].block_hash(), 3)?;
    active
        .begin_transition()?
        .connect(&BlockImage::from_local(child))?;
    if phase == "foreground" {
        await_kill(&dir);
    }
    for (height, block) in fixture.blocks.iter().enumerate() {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        if checkpoint_phase && height == 0 {
            publish_genesis_historical_checkpoint(&dir, &manager, block)?;
        }
    }
    Err(TestError::UnexpectedSuccess(
        "crash failpoint was not reached",
    ))
}

fn publish_genesis_historical_checkpoint(
    dir: &Path,
    manager: &AssumeUtxoManager,
    block: &bitcoin_rs_consensus::primitives::Block,
) -> TestResult {
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("missing history"))?;
    let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir)?;
    let write = crate::checkpoint::write_historical_checkpoint_with_store(
        &data,
        crate::checkpoint::headers::HeaderCheckpointConfig {
            network: Network::Regtest,
            genesis: Network::Regtest.genesis_block_hash(),
        },
        &historical.block_tree,
        &historical.coin_stats,
        historical.applied_tip_snapshot().as_deref(),
        crate::checkpoint::CheckpointStoreTarget {
            store: historical.commit_authority.store().as_ref(),
            host_data_dir: dir,
        },
    )?;
    let crate::checkpoint::CheckpointWrite::Published { reference } = write else {
        return Err(TestError::Missing("missing genesis checkpoint"));
    };
    let mut status = manager.status()?;
    let AssumeUtxoDiskStatus::Validating { checkpoint, .. } = &mut status else {
        return Err(TestError::Missing("missing validating status"));
    };
    *checkpoint = Some(HistoricalCheckpointRef {
        checkpoint: reference,
        height: 0,
        hash: block.block_hash().0,
    });
    manager.persist_status(status, None)?;
    Ok(())
}

fn run_crashing_writer(dir: &Path, phase: &str) -> TestResult {
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "assumeutxo::tests::recovery::crash_writer",
            "--nocapture",
        ])
        .env("BITCOIN_RS_SNAPSHOT_KILL_DIR", dir)
        .env("BITCOIN_RS_SNAPSHOT_KILL_PHASE", phase)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !dir.join("kill-ready").exists() && std::time::Instant::now() < deadline {
        if let Some(_status) = child.try_wait()? {
            return Err(TestError::WorkerPanicked("child exited before kill"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let ready = dir.join("kill-ready").exists();
    child.kill()?;
    child.wait()?;
    assert!(ready, "{phase} failed to reach its durable boundary");
    Ok(())
}

fn verify_recovered_snapshot_phase(fixture: &Fixture, dir: &Path, phase: &str) -> TestResult {
    let historical_root = dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
    if phase == "finalized" {
        assert!(historical_root.join("CURRENT").exists());
        assert!(std::fs::read_dir(&historical_root)?.count() > 1);
    }
    let active = open_persistent(dir, &fixture.pinned)?;
    if phase == "import" {
        assert!(active.applied_tip_snapshot().is_none());
        return Ok(());
    }
    if phase == "snapshot-ingest" {
        assert!(active.applied_tip_snapshot().is_none());
        assert!(
            active.durable_head.load()?.is_none(),
            "a crash before the activation head commit must leave the durable head unchanged"
        );
        assert!(
            active
                .commit_authority
                .store()
                .get(
                    bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                    bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY
                )?
                .is_none(),
            "the interrupted activation marker must be cleared with the coin wipe"
        );
        let coins = engine_coin_set_from_store(active.commit_authority.store().as_ref())?;
        assert!(
            coins.is_empty(),
            "snapshot coins survived a crash between coin ingest and the activation head commit"
        );
        active.admit_headers(
            &fixture
                .blocks
                .iter()
                .map(|block| block.header)
                .collect::<Vec<_>>(),
        )?;
        let manager = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
        let loaded = fixture.load()?;
        manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)?;
        let head = active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("re-activated head missing"))?;
        assert_eq!(head.tip, fixture.pinned.block_hash);
        assert_eq!(head.chain_tx_count, fixture.pinned.chain_tx_count);
        assert!(matches!(
            head.assumeutxo,
            AssumeUtxoDiskStatus::Validating { base_height, base_hash, .. }
                if base_height == fixture.pinned.height && base_hash == fixture.pinned.block_hash
        ));
        assert!(
            !engine_coin_set_from_store(active.commit_authority.store().as_ref())?.is_empty(),
            "re-activation must restage the snapshot coins"
        );
        return Ok(());
    }
    let manager = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing recovered tip"))?
            .height,
        if phase == "activation" { 2 } else { 3 }
    );
    if phase.starts_with("checkpoint-") {
        let historical_height = u32::from(phase != "checkpoint-published");
        assert_eq!(
            manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing history"))?
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing historical tip"))?
                .height,
            1
        );
        drop(manager);
        drop(active);
        let active = open_persistent(dir, &fixture.pinned)?;
        let manager = AssumeUtxoManager::open(Network::Regtest, active, dir.to_path_buf())?;
        assert_eq!(
            manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing history"))?
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing historical tip"))?
                .height,
            historical_height
        );
    } else if phase == "finalized" || phase == "checking" {
        assert!(active.role().is_ordinary());
        if phase == "finalized" {
            assert_eq!(std::fs::read_dir(&historical_root)?.count(), 0);
        }
    } else {
        assert!(active.role().is_assumed_active());
        assert!(
            manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing history"))?
                .applied_tip_snapshot()
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn process_death_recovers_each_snapshot_phase_from_the_committed_root() -> TestResult {
    let fixture = Fixture::new()?;
    for phase in [
        "import",
        "snapshot-ingest",
        "activation",
        "foreground",
        "historical",
        "checking",
        "finalized",
        "checkpoint-published",
        "checkpoint-committed",
    ] {
        let dir = tempfile::tempdir()?;
        run_crashing_writer(dir.path(), phase)?;
        verify_recovered_snapshot_phase(&fixture, dir.path(), phase)?;
    }
    Ok(())
}

struct RejectTerminalCommit;

impl bitcoin_rs_storage::CommitFault for RejectTerminalCommit {
    fn before_commit(
        &self,
        prefix: &bitcoin_rs_storage::AcceptedPrefix,
    ) -> Result<(), bitcoin_rs_storage::CommitError> {
        if matches!(
            prefix.next_head.assumeutxo,
            AssumeUtxoDiskStatus::Failed { .. } | AssumeUtxoDiskStatus::Finalized { .. }
        ) {
            return Err(bitcoin_rs_storage::CommitError::Storage(
                bitcoin_rs_storage::StorageError::InvalidOperation(
                    "injected terminal receipt failure",
                ),
            ));
        }
        Ok(())
    }
}

#[test]
fn finalized_checkpoint_recovers_without_replaying_pruned_foreground_history() -> TestResult {
    use bitcoin_rs_storage::KvStore;
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let (active, manager) = activate(dir.path(), &fixture)?;
    let child =
        crate::chain::regtest_fixture::mined_regtest_child_at(fixture.blocks[2].block_hash(), 3)?;
    active
        .begin_transition()?
        .connect(&BlockImage::from_local(child.clone()))?;
    for block in &fixture.blocks {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    assert!(active.publish_checkpoint()?.is_some());
    let stats = active.coin_stats.snapshot();
    drop(manager);
    drop(active);
    let store = RocksDbStore::open(dir.path().join("chainstate"))?;
    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        &bitcoin_rs_storage::pruning::block_body_key(3, child.block_hash().0),
    );
    store.write_durable(batch)?;
    drop(store);
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert_eq!(active.coin_stats.snapshot(), stats);
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing restored tip"))?
            .hash,
        child.block_hash().0
    );
    Ok(())
}

#[test]
fn failed_pre_base_validation_cannot_be_forgotten_when_failure_receipt_is_lost() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut active = open_persistent(dir.path(), &fixture.pinned)?;
    Arc::get_mut(&mut active)
        .ok_or(TestError::Missing("shared fixture"))?
        .commit_authority
        .set_fault(Arc::new(RejectTerminalCommit));
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())?;
    {
        let loaded = fixture.load()?;
        manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
    }?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
    let mut invalid = fixture.blocks[1].clone();
    invalid.txs[0].inputs[0].script_sig = bitcoin_rs_consensus::primitives::Script::new();
    invalid.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&invalid.txs)
        .ok_or(TestError::Missing("merkle root"))?;
    crate::chain::regtest_fixture::mine_block_to_declared_target(&mut invalid)?;
    assert!(
        manager
            .step_historical(&BlockImage::from_local(invalid.clone()))
            .is_err()
    );
    assert!(active.is_closed_for_recovery());
    assert!(
        matches!(manager.status()?, AssumeUtxoDiskStatus::Validating { pending: Some(pending), .. } if pending.height == 1)
    );
    drop(manager);
    drop(active);
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    assert!(
        AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())
            .is_err()
    );
    assert!(active.is_closed_for_recovery());
    assert!(matches!(
        active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing head"))?
            .assumeutxo,
        AssumeUtxoDiskStatus::Failed { .. }
    ));
    Ok(())
}

fn assert_reopen_refuses_mismatched_receipt(dir: &Path, fixture: &Fixture) -> TestResult {
    let active = open_persistent(dir, &fixture.pinned)?;
    let reopened = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf());
    assert!(reopened.is_err());
    assert!(active.is_closed_for_recovery());
    assert!(matches!(
        active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing head"))?
            .assumeutxo,
        AssumeUtxoDiskStatus::Failed { .. }
    ));
    Ok(())
}

fn assert_reopen_finalizes_after_rejected_write(dir: &Path, fixture: &Fixture) -> TestResult {
    let active = open_persistent(dir, &fixture.pinned)?;
    let reopened = AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
    assert!(matches!(
        reopened.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert!(active.role().is_ordinary());
    Ok(())
}

#[test]
fn failed_terminal_write_must_be_rechecked_before_restart_can_serve() -> TestResult {
    for mismatch in [false, true] {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let mut active = open_persistent(dir.path(), &fixture.pinned)?;
        Arc::get_mut(&mut active)
            .ok_or(TestError::Missing("shared fixture"))?
            .commit_authority
            .set_fault(Arc::new(RejectTerminalCommit));
        active.admit_headers(
            &fixture
                .blocks
                .iter()
                .map(|block| block.header)
                .collect::<Vec<_>>(),
        )?;
        let manager =
            AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())?;
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        }?;
        if mismatch {
            let prior = active
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing head"))?;
            let mut next = prior;
            if let AssumeUtxoDiskStatus::Validating { chain_tx_count, .. } = &mut next.assumeutxo {
                *chain_tx_count += 1;
            }
            next.commit_id += 1;
            active
                .commit_authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: Some(prior),
                    next_head: next,
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .map_err(|error| {
                    TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
                })?;
        }
        for block in &fixture.blocks[..2] {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        assert!(
            manager
                .step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))
                .is_err()
        );
        assert!(active.is_closed_for_recovery());
        let head = active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing head"))?;
        assert!(matches!(
            head.assumeutxo,
            AssumeUtxoDiskStatus::Validating {
                pending: Some(_),
                ..
            }
        ));
        assert!(
            active
                .block_body_store
                .as_ref()
                .ok_or(TestError::Missing("missing bodies"))?
                .load_block_body(2, fixture.pinned.block_hash)?
                .is_none()
        );
        drop(manager);
        drop(active);
        if mismatch {
            assert_reopen_refuses_mismatched_receipt(dir.path(), &fixture)?;
        } else {
            assert_reopen_finalizes_after_rejected_write(dir.path(), &fixture)?;
        }
    }
    Ok(())
}

#[test]
fn import_finalize_remove_archive_seed_completes() -> TestResult {
    let bad = Fixture::new()?;
    let bad_dir = tempfile::tempdir()?;
    let bad_manager = bad.manager(bad_dir.path())?;
    let wrong = Hash256::default();
    assert_ne!(wrong, bad.pinned.block_hash);
    let rejected = bad.load()?;
    assert!(matches!(
        bad_manager.activate_pinned_snapshot(rejected.set, wrong, &bad.pinned),
        Err(AssumeUtxoError::SnapshotBlockHashMismatch { .. })
    ));
    assert!(bad_manager.take_pending_activation_witness().is_none());

    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let archive = dir
        .path()
        .join("assumeutxo")
        .join(fixture.pinned.block_hash.to_string());
    assert!(archive.join("coins.dat").is_file());

    let initial =
        crate::assumeutxo_snapshot::load_verified(dir.path(), Network::Regtest, &fixture.pinned)?;
    assert!(matches!(
        initial.resume_source,
        crate::recovery::ResumeSource::Snapshot
    ));
    let mut seed = initial
        .script_live_seed
        .ok_or(TestError::Missing("restart recovery must mint a seed"))?;
    for block in &fixture.blocks {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    let _ = std::fs::remove_dir_all(&archive);
    assert!(!archive.exists(), "the seed must not need its path");

    let expected = u64::try_from(initial.utxo.len())?;
    assert!(expected > 0, "the fixture must hold live coins");
    let mut seen = 0_u64;
    seed.for_each_coin_raw(
        &mut |_, _| {
            seen += 1;
            Ok::<(), std::convert::Infallible>(())
        },
        &|| false,
    )?;
    assert_eq!(seen, expected);
    Ok(())
}
