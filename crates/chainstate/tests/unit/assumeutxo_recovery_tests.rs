//! RCV-02/04 and ARCH-07b: root-selected snapshot recovery with real storage.
use super::*;
use crate::assumeutxo::DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL;
use bitcoin_rs_storage::assumeutxo::HistoricalCheckpointRef;
use bitcoin_rs_storage::block_body::IndexedBlockBodyStore;
use bitcoin_rs_storage::{FjallStore, FlatFileBlockStore, KvDurableHeadStore, KvUndoStore};
use std::path::Path;
use std::sync::atomic::AtomicU32;

fn open_persistent(
    dir: &Path,
    pinned: &AssumeUtxoData,
) -> Result<Arc<Chainstate>, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    crate::events::initialize_data_dir(dir)?;
    let store = Arc::new(FjallStore::open(dir.join("chainstate"))?);
    let head_store = Arc::new(KvDurableHeadStore::new(store.clone()));
    let head = head_store.load()?;
    let files = Arc::new(match head.and_then(|head| head.body_extent) {
        Some(extent) => FlatFileBlockStore::open_with_committed_extent(dir, extent)?,
        None => FlatFileBlockStore::open(dir)?,
    });
    let mut active = if head
        .is_some_and(|head| !matches!(head.assumeutxo, AssumeUtxoDiskStatus::Uninitialized))
    {
        // Only the test trust anchor is substituted. Production chooses the
        // network pin before entering this same archive verifier.
        if head.is_some_and(|head| matches!(head.assumeutxo, AssumeUtxoDiskStatus::Failed { .. })) {
            return Err("persisted validation failure".into());
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
    } else {
        Arc::try_unwrap(chainstate()).map_err(|_| "shared fixture")?
    };
    active.durable_head = head_store;
    active.undo_store = Arc::new(KvUndoStore::new(store.clone()));
    active.block_body_store = Some(Arc::new(IndexedBlockBodyStore::new(store, files)));
    active.configure_checkpointing(dir, Arc::new(AtomicU32::new(0)))?;
    crate::recover_disconnect_marker(&active)?;
    Ok(Arc::new(active))
}

fn activate(
    dir: &Path,
    fixture: &Fixture,
) -> Result<(Arc<Chainstate>, AssumeUtxoManager), Box<dyn std::error::Error>> {
    let active = open_persistent(dir, &fixture.pinned)?;
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, active.clone(), Some(dir.to_path_buf()))?;
    manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned)?;
    Ok((active, manager))
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "One datadir must survive the complete activation, convergence, reorg and restart sequence"
)]
fn durable_snapshot_restarts_foreground_and_background_then_allows_base_reorg() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let (active, manager) = activate(dir.path(), &fixture)?;
    let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
        fixture.blocks[2].block_hash(),
        3,
    )?;
    active.begin_transition()?.connect(&child, None)?;
    manager.step_historical(&fixture.blocks[0], None)?;
    manager.step_historical(&fixture.blocks[1], None)?;
    let expected_stats = active.coin_stats.snapshot();
    let expected_tip = active
        .applied_tip_snapshot()
        .ok_or("missing foreground tip")?
        .hash;
    drop(manager);
    drop(active);

    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
    )?;
    assert_eq!(active.coin_stats.snapshot(), expected_stats);
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or("missing recovered tip")?
            .hash,
        expected_tip
    );
    assert!(active.role().is_assumed_active());
    assert!(
        manager
            .historical_chainstate()
            .ok_or("missing historical")?
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
    manager.step_historical(&fixture.blocks[2], None)?;
    assert!(active.role().is_ordinary());
    assert_eq!(active.chain_events.snapshot(), events);
    assert_eq!(active.coin_stats.snapshot(), expected_stats);
    drop(manager);
    drop(active);

    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
    )?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert_eq!(active.coin_stats.snapshot(), expected_stats);
    active.begin_transition()?.disconnect(&child)?;
    // Historical undo/body records entered the active archive atomically,
    // so finalization really permits ordinary reorgs below the snapshot base.
    active.begin_transition()?.disconnect(&fixture.blocks[2])?;
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or("missing rewound tip")?
            .height,
        1
    );
    assert!(matches!(
        active
            .durable_head
            .load()?
            .ok_or("missing head")?
            .assumeutxo,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    assert!(matches!(
        manager.chainstates_summary()?.status,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    let rewound_stats = active.coin_stats.snapshot();
    drop(manager);
    drop(active);
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
    )?;
    assert!(manager.chainstates_summary()?.active_chainstate.validated);
    let recovered_stats = active.coin_stats.snapshot();
    // Rollback and fresh replay can retain different MuHash fractions for
    // the same set. Compare the canonical digest, not internal numerator/denominator.
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
            .ok_or("missing restarted ordinary tip")?
            .height,
        1
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Exercise orphan publication, retirement and suffix replay in one datadir"
)]
fn historical_checkpoint_bounds_restart_replay_to_the_checkpoint_suffix() -> TestResult {
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
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
        1,
    )?;
    manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned)?;
    manager.step_historical(&fixture.blocks[0], None)?;
    manager.step_historical(&fixture.blocks[1], None)?;
    let status = manager.status()?;
    let checkpoint = match status {
        AssumeUtxoDiskStatus::Validating {
            checkpoint: Some(checkpoint),
            historical_height,
            historical_hash,
            ..
        } => {
            assert_eq!(historical_height, 1);
            assert_eq!(historical_hash, fixture.blocks[1].block_hash().0);
            checkpoint
        }
        other => return Err(format!("unexpected status after checkpoint: {other:?}").into()),
    };
    assert_eq!(checkpoint.height, 1);
    assert_eq!(checkpoint.hash, fixture.blocks[1].block_hash().0);
    // Simulate repeated crashes after publication but before the durable-head
    // reference commits. CURRENT leads, while the accepted coins stay intact.
    let historical = manager
        .historical_chainstate()
        .ok_or("missing historical")?;
    let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir.path())?;
    let config = crate::checkpoint::headers::HeaderCheckpointConfig {
        network: Network::Regtest,
        genesis: Network::Regtest.genesis_block_hash(),
    };
    for _ in 0..2 {
        crate::checkpoint::write_checkpoint_from_dir_at(
            &data,
            config,
            &historical.block_tree,
            &historical.utxo,
            &historical.coin_stats,
            historical.applied_tip_snapshot().as_deref(),
            bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
            bitcoin_rs_storage::checkpoint::CheckpointRetention::UntilReferenced,
        )?;
    }
    drop(historical);
    drop(data);
    assert!(
        dir.path()
            .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
            .join("CURRENT")
            .exists()
    );
    drop(manager);
    drop(active);

    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active,
        Some(dir.path().to_path_buf()),
        1,
    )?;
    let historical = manager
        .historical_chainstate()
        .ok_or("missing restored historical chainstate")?;
    let restored_tip = historical
        .applied_tip_snapshot()
        .ok_or("missing historical checkpoint tip")?;
    assert_eq!(restored_tip.height, 1);
    assert_eq!(restored_tip.hash, fixture.blocks[1].block_hash().0);
    assert_eq!(restored_tip.chain_tx_count.to_wire(), 2);
    assert_eq!(historical.coin_stats.snapshot().tx_count, 2);
    let generations = std::fs::read_dir(
        dir.path()
            .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT),
    )?
    .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        generations
            .iter()
            .filter(|entry| entry.path().is_dir())
            .count(),
        1,
        "startup must retire publication residue"
    );

    // The checkpoint restored blocks 0..1.  Only the remaining archived suffix
    // is replayed before the historical role reaches the pinned base.
    manager.step_historical(&fixture.blocks[2], None)?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
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
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
    )?;
    let journal = dir.path().join(crate::recovery::CHAINSTATE_JOURNAL_DIR);
    std::fs::create_dir_all(&journal)?;
    let marker = journal.join(bitcoin_rs_storage::chainstate_journal::FULL_REVALIDATION_MARKER);
    std::fs::write(&marker, b"required")?;
    let head = active.durable_head.load()?;
    let tip = active.applied_tip_snapshot();
    assert!(matches!(
        manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned),
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
    assert_eq!(
        restored.utxo.lock_stable_view().hash_serialized_3()?,
        fixture.pinned.hash_serialized
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
    // Import bytes without committing a root cannot activate a chainstate.
    crate::events::initialize_data_dir(dir.path())?;
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

struct KillPointHead {
    inner: Arc<dyn DurableHeadStore>,
    phase: String,
    dir: std::path::PathBuf,
}

fn await_kill(dir: &Path) -> ! {
    std::fs::write(dir.join("kill-ready"), b"ready")
        .unwrap_or_else(|error| panic!("kill marker: {error}"));
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(1));
    }
}

impl DurableHeadStore for KillPointHead {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.inner.load()
    }
    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        let checkpoint_replaced = match next.assumeutxo {
            AssumeUtxoDiskStatus::Validating {
                checkpoint: Some(checkpoint),
                ..
            } => {
                checkpoint.height == 1
                    && expected.is_some_and(|head| {
                        matches!(
                            head.assumeutxo,
                            AssumeUtxoDiskStatus::Validating { checkpoint: Some(previous), .. }
                                if previous != checkpoint
                        )
                    })
            }
            _ => false,
        };
        if self.phase == "checkpoint-published" && checkpoint_replaced {
            await_kill(&self.dir);
        }
        self.inner.commit(expected, next, records)?;
        if self.phase == "checkpoint-committed" && checkpoint_replaced {
            await_kill(&self.dir);
        }
        let kill = match (self.phase.as_str(), next.assumeutxo) {
            ("activation", AssumeUtxoDiskStatus::Validating { .. }) => expected.is_none(),
            ("foreground", _) => next.height == 3,
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
        Ok(())
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
    let inner = active.durable_head.clone();
    Arc::get_mut(&mut active)
        .ok_or("shared crash fixture")?
        .durable_head = Arc::new(KillPointHead {
        inner,
        phase: phase.clone(),
        dir: dir.clone(),
    });
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    if phase == "import" {
        crate::assumeutxo_snapshot::write_coins(&dir, &fixture.load()?.set, &fixture.pinned)?;
        await_kill(&dir);
    }
    let checkpoint_phase = phase.starts_with("checkpoint-");
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        active.clone(),
        Some(dir.clone()),
        if checkpoint_phase {
            1
        } else {
            DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL
        },
    )?;
    manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned)?;
    let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
        fixture.blocks[2].block_hash(),
        3,
    )?;
    active.begin_transition()?.connect(&child, None)?;
    for (height, block) in fixture.blocks.iter().enumerate() {
        manager.step_historical(block, None)?;
        if checkpoint_phase && height == 0 {
            // Seed an accepted genesis checkpoint so the next production step
            // replaces an existing head reference at the kill boundary.
            let historical = manager.historical_chainstate().ok_or("missing history")?;
            let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&dir)?;
            let crate::checkpoint::CheckpointWrite::Published { reference } =
                crate::checkpoint::write_checkpoint_from_dir_at(
                    &data,
                    crate::checkpoint::headers::HeaderCheckpointConfig {
                        network: Network::Regtest,
                        genesis: Network::Regtest.genesis_block_hash(),
                    },
                    &historical.block_tree,
                    &historical.utxo,
                    &historical.coin_stats,
                    historical.applied_tip_snapshot().as_deref(),
                    bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
                    bitcoin_rs_storage::checkpoint::CheckpointRetention::UntilReferenced,
                )?
            else {
                return Err("missing genesis checkpoint".into());
            };
            let mut status = manager.status()?;
            let AssumeUtxoDiskStatus::Validating { checkpoint, .. } = &mut status else {
                return Err("missing validating status".into());
            };
            *checkpoint = Some(HistoricalCheckpointRef {
                checkpoint: reference,
                height: 0,
                hash: block.block_hash().0,
            });
            manager.persist_status(status, None)?;
        }
    }
    Err("crash failpoint was not reached".into())
}

#[test]
fn process_death_recovers_each_snapshot_phase_from_the_committed_root() -> TestResult {
    let fixture = Fixture::new()?;
    for phase in [
        "import",
        "activation",
        "foreground",
        "historical",
        "checking",
        "finalized",
        "checkpoint-published",
        "checkpoint-committed",
    ] {
        let dir = tempfile::tempdir()?;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "assumeutxo::tests::recovery::crash_writer",
                "--nocapture",
            ])
            .env("BITCOIN_RS_SNAPSHOT_KILL_DIR", dir.path())
            .env("BITCOIN_RS_SNAPSHOT_KILL_PHASE", phase)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !dir.path().join("kill-ready").exists() && std::time::Instant::now() < deadline {
            if let Some(status) = child.try_wait()? {
                return Err(format!("{phase} child exited before kill: {status}").into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ready = dir.path().join("kill-ready").exists();
        child.kill()?;
        child.wait()?;
        assert!(ready, "{phase} failed to reach its durable boundary");
        let active = open_persistent(dir.path(), &fixture.pinned)?;
        if phase == "import" {
            assert!(active.applied_tip_snapshot().is_none());
            continue;
        }
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            active.clone(),
            Some(dir.path().to_path_buf()),
        )?;
        assert_eq!(
            active
                .applied_tip_snapshot()
                .ok_or("missing recovered tip")?
                .height,
            if phase == "activation" { 2 } else { 3 }
        );
        if phase.starts_with("checkpoint-") {
            let historical_height = u32::from(phase != "checkpoint-published");
            assert_eq!(
                manager
                    .historical_chainstate()
                    .ok_or("missing history")?
                    .applied_tip_snapshot()
                    .ok_or("missing historical tip")?
                    .height,
                1
            );
            // A second restart uses the same accepted reference regardless of
            // the publication pointer left ahead by the interrupted writer.
            drop(manager);
            drop(active);
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            let manager =
                AssumeUtxoManager::open(Network::Regtest, active, Some(dir.path().to_path_buf()))?;
            assert_eq!(
                manager
                    .historical_chainstate()
                    .ok_or("missing history")?
                    .applied_tip_snapshot()
                    .ok_or("missing historical tip")?
                    .height,
                historical_height
            );
        } else if phase == "finalized" || phase == "checking" {
            assert!(active.role().is_ordinary());
        } else {
            assert!(active.role().is_assumed_active());
            assert!(
                manager
                    .historical_chainstate()
                    .ok_or("missing history")?
                    .applied_tip_snapshot()
                    .is_none()
            );
        }
    }
    Ok(())
}

struct RejectTerminalHead {
    inner: Arc<dyn DurableHeadStore>,
}

#[test]
fn finalized_checkpoint_recovers_without_replaying_pruned_foreground_history() -> TestResult {
    use bitcoin_rs_storage::KvStore;
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let (active, manager) = activate(dir.path(), &fixture)?;
    let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
        fixture.blocks[2].block_hash(),
        3,
    )?;
    active.begin_transition()?.connect(&child, None)?;
    for block in &fixture.blocks {
        manager.step_historical(block, None)?;
    }
    assert!(active.publish_checkpoint()?.is_some());
    let stats = active.coin_stats.snapshot();
    drop(manager);
    drop(active);
    // Remove the old locator, as prefix pruning does. A checkpoint at the
    // durable tip must not need a genesis/base-to-tip replay of that body.
    let store = FjallStore::open(dir.path().join("chainstate"))?;
    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        &bitcoin_rs_storage::pruning::block_body_key(3, child.block_hash().0),
    );
    store.write_durable(batch)?;
    drop(store);
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
    )?;
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert_eq!(active.coin_stats.snapshot(), stats);
    assert_eq!(
        active
            .applied_tip_snapshot()
            .ok_or("missing restored tip")?
            .hash,
        child.block_hash().0
    );
    Ok(())
}

impl DurableHeadStore for RejectTerminalHead {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.inner.load()
    }
    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        if matches!(
            next.assumeutxo,
            AssumeUtxoDiskStatus::Failed { .. } | AssumeUtxoDiskStatus::Finalized { .. }
        ) {
            return Err(StorageError::InvalidOperation(
                "injected terminal receipt failure",
            ));
        }
        self.inner.commit(expected, next, records)
    }
}

#[test]
fn failed_pre_base_validation_cannot_be_forgotten_when_failure_receipt_is_lost() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let mut active = open_persistent(dir.path(), &fixture.pinned)?;
    let inner = active.durable_head.clone();
    Arc::get_mut(&mut active)
        .ok_or("shared fixture")?
        .durable_head = Arc::new(RejectTerminalHead { inner });
    active.admit_headers(
        &fixture
            .blocks
            .iter()
            .map(|block| block.header)
            .collect::<Vec<_>>(),
    )?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        active.clone(),
        Some(dir.path().to_path_buf()),
    )?;
    manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned)?;
    manager.step_historical(&fixture.blocks[0], None)?;
    let mut invalid = fixture.blocks[1].clone();
    invalid.txs.clear();
    assert!(manager.step_historical(&invalid, None).is_err());
    assert!(active.is_closed_for_recovery());
    assert!(
        matches!(manager.status()?, AssumeUtxoDiskStatus::Validating { pending: Some(pending), .. } if pending.height == 1)
    );
    drop(manager);
    drop(active);
    let active = open_persistent(dir.path(), &fixture.pinned)?;
    assert!(
        AssumeUtxoManager::open(
            Network::Regtest,
            active.clone(),
            Some(dir.path().to_path_buf())
        )
        .is_err()
    );
    assert!(active.is_closed_for_recovery());
    assert!(matches!(
        active
            .durable_head
            .load()?
            .ok_or("missing head")?
            .assumeutxo,
        AssumeUtxoDiskStatus::Failed { .. }
    ));
    Ok(())
}

#[test]
fn failed_terminal_write_must_be_rechecked_before_restart_can_serve() -> TestResult {
    for mismatch in [false, true] {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let mut active = open_persistent(dir.path(), &fixture.pinned)?;
        let inner = active.durable_head.clone();
        Arc::get_mut(&mut active)
            .ok_or("shared fixture")?
            .durable_head = Arc::new(RejectTerminalHead { inner });
        active.admit_headers(
            &fixture
                .blocks
                .iter()
                .map(|block| block.header)
                .collect::<Vec<_>>(),
        )?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            active.clone(),
            Some(dir.path().to_path_buf()),
        )?;
        manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned)?;
        if mismatch {
            let prior = active.durable_head.load()?.ok_or("missing head")?;
            let mut next = prior;
            if let AssumeUtxoDiskStatus::Validating { chain_tx_count, .. } = &mut next.assumeutxo {
                *chain_tx_count += 1;
            }
            next.commit_id += 1;
            active
                .durable_head
                .commit(Some(&prior), &next, &CommitRecords::default())?;
        }
        for block in &fixture.blocks[..2] {
            manager.step_historical(block, None)?;
        }
        assert!(manager.step_historical(&fixture.blocks[2], None).is_err());
        assert!(active.is_closed_for_recovery());
        let head = active.durable_head.load()?.ok_or("missing head")?;
        assert!(matches!(
            head.assumeutxo,
            AssumeUtxoDiskStatus::Validating {
                pending: Some(_),
                ..
            }
        ));
        // The candidate's locator is invisible to derived consumers until
        // successful validation publishes body, undo, and status together.
        assert!(
            active
                .block_body_store
                .as_ref()
                .ok_or("missing bodies")?
                .load_block_body(2, fixture.pinned.block_hash)?
                .is_none()
        );
        drop(manager);
        drop(active);
        let active = open_persistent(dir.path(), &fixture.pinned)?;
        let reopened = AssumeUtxoManager::open(
            Network::Regtest,
            active.clone(),
            Some(dir.path().to_path_buf()),
        );
        if mismatch {
            assert!(reopened.is_err());
            assert!(active.is_closed_for_recovery());
            assert!(matches!(
                active
                    .durable_head
                    .load()?
                    .ok_or("missing head")?
                    .assumeutxo,
                AssumeUtxoDiskStatus::Failed { .. }
            ));
        } else {
            let reopened = reopened?;
            assert!(matches!(
                reopened.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert!(active.role().is_ordinary());
        }
    }
    Ok(())
}
