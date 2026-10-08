//! ARCH-07b: verified installation, isolated replay, and fail-closed convergence.
use std::io::Cursor;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, ChainWork, NodeStatus};
use bitcoin_rs_primitives::{AssumeUtxoData, Block, Hash256, Network};
use bitcoin_rs_storage::{CommitRecords, DurableHead, DurableHeadStore, StorageError};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{SnapshotLoad, UtxoSet, read_snapshot_strict_v4, write_snapshot_observed};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, ChainstateRole};
use crate::{ApplyError, Chainstate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn chainstate() -> Arc<Chainstate> {
    let stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.track_coin_stats((*stats).clone());
    Arc::new(Chainstate::new(
        Network::Regtest,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        Arc::new(utxo),
        stats,
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    ))
}

#[derive(Default)]
struct FaultHead {
    inner: bitcoin_rs_storage::InMemoryDurableHeadStore,
    fail: AtomicBool,
    fail_terminal: AtomicBool,
}
impl DurableHeadStore for FaultHead {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.inner.load()
    }
    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        if self.fail.load(Ordering::Acquire)
            || (self.fail_terminal.load(Ordering::Acquire)
                && matches!(
                    next.assumeutxo,
                    AssumeUtxoDiskStatus::Failed { .. } | AssumeUtxoDiskStatus::Finalized { .. }
                ))
        {
            return Err(StorageError::InvalidOperation(
                "injected durable-head failure",
            ));
        }
        self.inner.commit(expected, next, records)
    }
}

struct Fixture {
    head: Arc<FaultHead>,
    active: Arc<Chainstate>,
    blocks: Vec<Block>,
    pinned: AssumeUtxoData,
    snapshot: Vec<u8>,
    stats: CoinStats,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let source = chainstate();
        let mut blocks = vec![Network::Regtest.genesis_block()];
        for height in 1..=2 {
            blocks.push(bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
                blocks.last().ok_or("missing predecessor")?.block_hash(),
                height,
            )?);
        }
        for block in &blocks {
            source
                .lock_transition()?
                .into_transition()
                .connect(block, None)?;
        }
        let tip = source.applied_tip_snapshot().ok_or("missing source tip")?;
        let pinned = AssumeUtxoData {
            height: tip.height,
            block_hash: tip.hash,
            hash_serialized: source.utxo.lock_stable_view().hash_serialized_3()?,
            chain_tx_count: tip.chain_tx_count.to_wire(),
        };
        let mut snapshot = Cursor::new(Vec::new());
        write_snapshot_observed(&source.utxo, &tip.hash, tip.height, &mut snapshot, ())?;
        let mut active = chainstate();
        let head = Arc::new(FaultHead::default());
        Arc::get_mut(&mut active)
            .ok_or("shared active fixture")?
            .durable_head = head.clone();
        for block in &blocks {
            active
                .block_tree
                .write()
                .insert_header(block.header, NodeStatus::HeaderValid)?;
        }
        Ok(Self {
            head,
            active,
            blocks,
            pinned,
            snapshot: snapshot.into_inner(),
            stats: source.coin_stats.snapshot(),
        })
    }

    fn load(&self) -> Result<SnapshotLoad, bitcoin_rs_utxo::UtxoError> {
        read_snapshot_strict_v4(&mut Cursor::new(&self.snapshot))
    }

    fn manager(&self, dir: &std::path::Path) -> Result<AssumeUtxoManager, AssumeUtxoError> {
        AssumeUtxoManager::open(
            Network::Regtest,
            Arc::clone(&self.active),
            Some(dir.to_path_buf()),
        )
    }

    fn activate(&self, manager: &AssumeUtxoManager) -> TestResult {
        manager.activate_pinned_snapshot(self.load()?, &self.pinned)?;
        Ok(())
    }
}

fn disk_status(active: &Chainstate) -> Result<AssumeUtxoDiskStatus, Box<dyn std::error::Error>> {
    Ok(active
        .durable_head
        .load()?
        .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo))
}

#[test]
fn untrusted_snapshot_cannot_assert_its_own_commitment() -> TestResult {
    let active = chainstate();
    let manager = AssumeUtxoManager::open(Network::Regtest, Arc::clone(&active), None)?;
    let pinned = Network::Regtest
        .assume_utxo_for_height(110)
        .ok_or("missing pin")?;
    for (height, hash) in [
        (1234, pinned.block_hash),
        (110, Hash256::default()),
        (110, pinned.block_hash),
    ] {
        let load = SnapshotLoad {
            set: UtxoSet::new(),
            height,
            tip_hash: hash,
            muhash_trailer: [0xff; 384],
        };
        let Err(error) = manager.activate_snapshot(load) else {
            return Err("untrusted snapshot accepted".into());
        };
        match height {
            1234 => assert!(matches!(
                error,
                AssumeUtxoError::UntrustedSnapshotHeight(1234)
            )),
            _ if hash == pinned.block_hash => assert!(matches!(
                error,
                AssumeUtxoError::SnapshotCommitmentMismatch { .. }
            )),
            _ => assert!(matches!(
                error,
                AssumeUtxoError::SnapshotBlockHashMismatch { .. }
            )),
        }
        assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
        assert!(active.applied_tip_snapshot().is_none());
        assert_eq!(active.role(), ChainstateRole::Ordinary);
    }
    Ok(())
}

#[test]
fn snapshot_rejects_coin_height_alias_with_identical_commitment() -> TestResult {
    let fixture = Fixture::new()?;
    let mut bytes = fixture.snapshot.clone();
    // Snapshot header (52), transaction record header (45), vout height offset (12).
    let offset = 52 + 45 + 12;
    let height = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?);
    assert!(height <= fixture.pinned.height);
    bytes[offset..offset + 4].copy_from_slice(&(height | 0x8000_0000).to_le_bytes());
    let forged = read_snapshot_strict_v4(&mut Cursor::new(&bytes))?;
    assert_eq!(
        forged.set.lock_stable_view().hash_serialized_3()?,
        fixture.pinned.hash_serialized,
        "the encoded commitment aliases the high height bit"
    );
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    assert!(matches!(
        manager.activate_pinned_snapshot(forged, &fixture.pinned),
        Err(AssumeUtxoError::Utxo(
            bitcoin_rs_utxo::UtxoError::SnapshotCoinHeightOutOfRange { .. }
        ))
    ));
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(fixture.active.applied_tip_snapshot().is_none());
    Ok(())
}

#[test]
fn snapshot_installs_coins_statistics_and_resolved_header_together() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let active = &fixture.active;
    let tip = active
        .applied_tip_snapshot()
        .ok_or("missing snapshot tip")?;
    let tree = active.block_tree.read();
    let node = tree.node(tip.tip_id)?;
    assert_eq!(
        (tip.hash, tip.height, tip.chainwork),
        (node.hash, node.height, node.chainwork)
    );
    assert_ne!(tip.chainwork, ChainWork::ZERO);
    assert_eq!(tip.chain_tx_count.to_wire(), fixture.pinned.chain_tx_count);
    assert_eq!(active.coin_stats.snapshot(), fixture.stats);
    assert_eq!(
        active.utxo.lock_stable_view().hash_serialized_3()?,
        fixture.pinned.hash_serialized
    );
    assert!(active.role().is_assumed_active());
    assert_eq!(manager.status()?, disk_status(&fixture.active)?);
    assert!(matches!(
        active.prune_authority().begin(),
        Err(ApplyError::PruneDuringHistoricalValidation { .. })
    ));
    assert!(matches!(
        manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned),
        Err(AssumeUtxoError::AlreadyActive)
    ));
    Ok(())
}

#[test]
fn snapshot_refuses_missing_or_wrong_height_header_before_persistence() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let active = chainstate();
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        Arc::clone(&active),
        Some(dir.path().to_path_buf()),
    )?;
    assert!(matches!(
        manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned),
        Err(AssumeUtxoError::SnapshotHeaderMissing(_))
    ));
    assert!(active.durable_head.load()?.is_none());
    let manager = fixture.manager(dir.path())?;
    let mut wrong_height = fixture.pinned;
    wrong_height.height += 1;
    assert!(matches!(
        manager.activate_pinned_snapshot(fixture.load()?, &wrong_height),
        Err(AssumeUtxoError::SnapshotHeaderHeightMismatch { .. })
    ));
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert!(active.durable_head.load()?.is_none());
    Ok(())
}

#[test]
fn activation_io_failure_does_not_publish_snapshot() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.head.fail.store(true, Ordering::Release);
    assert!(matches!(
        manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned),
        Err(AssumeUtxoError::Storage(_))
    ));
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert_eq!(fixture.active.coin_stats.snapshot(), CoinStats::default());
    assert!(fixture.active.role().is_ordinary());
    assert!(fixture.active.is_closed_for_recovery());
    Ok(())
}

#[test]
fn historical_replay_preserves_active_durable_head_and_notifications() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let active_head = fixture
        .active
        .durable_head
        .load()?
        .ok_or("missing active anchor")?;
    let events = fixture.active.chain_events.snapshot();
    let historical = manager
        .historical_chainstate()
        .ok_or("historical missing")?;
    assert!(!Arc::ptr_eq(
        &historical.undo_store,
        &fixture.active.undo_store
    ));
    assert!(!Arc::ptr_eq(
        &historical.durable_head,
        &fixture.active.durable_head
    ));
    assert!(historical.block_body_store.is_none());
    assert!(matches!(
        historical.prune_authority().begin(),
        Err(ApplyError::PruneDuringHistoricalValidation { .. })
    ));
    for block in &fixture.blocks {
        manager.step_historical(block, None)?;
        let head = fixture.active.durable_head.load()?.ok_or("missing head")?;
        assert_eq!(
            (head.tip, head.height, head.chain_tx_count),
            (
                active_head.tip,
                active_head.height,
                active_head.chain_tx_count
            )
        );
        assert!(head.commit_id > active_head.commit_id);
        assert_eq!(fixture.active.chain_events.snapshot(), events);
        assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
    }
    assert!(fixture.active.role().is_ordinary());
    assert!(fixture.active.prune_authority().begin().is_ok());
    assert!(manager.historical_chainstate().is_none());
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    assert_eq!(manager.status()?, disk_status(&fixture.active)?);
    Ok(())
}

#[cfg(feature = "fjall")]
#[path = "assumeutxo_recovery_tests.rs"]
mod recovery;

#[test]
fn snapshot_advances_partial_state_but_refuses_to_replace_an_equal_or_newer_tip() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    fixture
        .active
        .begin_transition()?
        .connect(&fixture.blocks[0], None)?;
    fixture
        .active
        .begin_transition()?
        .connect(&fixture.blocks[1], None)?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    for block in &fixture.blocks {
        fixture.active.begin_transition()?.connect(block, None)?;
    }
    let manager = fixture.manager(dir.path())?;
    let before = fixture.active.durable_head.load()?;
    // This is an ordinary user refusal, not an unresolved storage mutation.
    assert!(matches!(
        manager.activate_pinned_snapshot(fixture.load()?, &fixture.pinned),
        Err(AssumeUtxoError::ActivationBehindTip)
    ));
    assert_eq!(fixture.active.durable_head.load()?, before);
    assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
    assert!(!fixture.active.is_closed_for_recovery());
    Ok(())
}

#[test]
fn out_of_order_historical_input_does_not_persist_or_close_admission() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let before = fixture.active.durable_head.load()?;
    assert!(matches!(
        manager.step_historical(&fixture.blocks[1], None),
        Err(AssumeUtxoError::Apply(ApplyError::PrevHashMismatch { .. }))
    ));
    assert_eq!(fixture.active.durable_head.load()?, before);
    assert!(!fixture.active.is_closed_for_recovery());
    manager.step_historical(&fixture.blocks[0], None)?;
    Ok(())
}

#[test]
fn historical_restart_replays_coins_from_genesis_instead_of_fabricating_a_tip() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(block, None)?;
    }
    assert!(
        manager
            .historical_chainstate()
            .ok_or("missing historical")?
            .coin_stats
            .snapshot()
            .utxo_count
            > 0
    );
    drop(manager);
    let reopened = fixture.manager(dir.path())?;
    let historical = reopened
        .historical_chainstate()
        .ok_or("missing historical after restart")?;
    assert!(historical.applied_tip_snapshot().is_none());
    assert_eq!(historical.coin_stats.snapshot(), CoinStats::default());
    for block in &fixture.blocks {
        reopened.step_historical(block, None)?;
    }
    assert!(matches!(
        reopened.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    Ok(())
}

#[test]
fn reconstructed_commitment_or_transaction_count_mismatch_fails_closed() -> TestResult {
    for wrong_count in [false, true] {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        {
            let prior = fixture.active.durable_head.load()?.ok_or("missing head")?;
            let mut next = prior;
            if let AssumeUtxoDiskStatus::Validating {
                ref mut expected_hash_serialized,
                ref mut chain_tx_count,
                ..
            } = next.assumeutxo
            {
                if wrong_count {
                    *chain_tx_count += 1;
                } else {
                    *expected_hash_serialized = Hash256::default();
                }
            }
            next.commit_id += 1;
            fixture
                .active
                .durable_head
                .commit(Some(&prior), &next, &CommitRecords::default())?;
        }
        for block in &fixture.blocks[..2] {
            manager.step_historical(block, None)?;
        }
        let historical = manager
            .historical_chainstate()
            .ok_or("missing historical")?;
        let Err(error) = manager.step_historical(&fixture.blocks[2], None) else {
            return Err("divergence finalized".into());
        };
        if wrong_count {
            assert!(matches!(
                error,
                AssumeUtxoError::HistoricalTransactionCountMismatch { .. }
            ));
        } else {
            assert!(matches!(error, AssumeUtxoError::CommitmentMismatch { .. }));
        }
        assert!(fixture.active.is_closed_for_recovery());
        assert!(historical.is_closed_for_recovery());
        assert!(matches!(
            disk_status(&fixture.active)?,
            AssumeUtxoDiskStatus::Failed { .. }
        ));
        assert!(matches!(
            fixture.manager(dir.path()),
            Err(AssumeUtxoError::PreviouslyFailed { .. })
        ));
    }
    Ok(())
}

#[test]
fn target_hash_divergence_is_classified_and_persisted() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(block, None)?;
    }
    let mut wrong = fixture.blocks[2].clone();
    wrong.header.nonce = wrong.header.nonce.wrapping_add(1);
    assert!(matches!(
        manager.step_historical(&wrong, None),
        Err(AssumeUtxoError::HistoricalTargetHashMismatch { .. })
    ));
    assert!(fixture.active.is_closed_for_recovery());
    assert!(matches!(
        disk_status(&fixture.active)?,
        AssumeUtxoDiskStatus::Failed { .. }
    ));
    Ok(())
}

#[test]
fn mismatch_closes_admission_even_when_failure_record_cannot_be_written() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(block, None)?;
    }
    fixture.head.fail_terminal.store(true, Ordering::Release);
    let mut wrong = fixture.blocks[2].clone();
    wrong.header.nonce = wrong.header.nonce.wrapping_add(1);
    assert!(matches!(
        manager.step_historical(&wrong, None),
        Err(AssumeUtxoError::Storage(_))
    ));
    assert!(fixture.active.lock_transition().is_err());
    assert!(
        manager
            .historical_chainstate()
            .ok_or("missing historical")?
            .lock_transition()
            .is_err()
    );
    Ok(())
}

#[test]
fn finalization_io_failure_keeps_assumed_role_and_closes_both_admissions() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(block, None)?;
    }
    fixture.head.fail_terminal.store(true, Ordering::Release);
    assert!(matches!(
        manager.step_historical(&fixture.blocks[2], None),
        Err(AssumeUtxoError::Storage(_))
    ));
    assert!(fixture.active.role().is_assumed_active());
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Validating { .. }
    ));
    assert!(fixture.active.lock_transition().is_err());
    assert!(
        manager
            .historical_chainstate()
            .ok_or("missing historical")?
            .lock_transition()
            .is_err()
    );
    Ok(())
}

#[test]
fn assumed_reorg_and_historical_height_guards_remain_enforced() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    assert!(matches!(
        crate::disconnect::plan_disconnect(
            &fixture.active,
            &fixture.blocks[2],
            fixture.pinned.block_hash
        ),
        Err(ApplyError::DisconnectBelowSnapshotBase { .. })
    ));
    let historical = manager
        .historical_chainstate()
        .ok_or("missing historical")?;
    for block in &fixture.blocks {
        manager.step_historical(block, None)?;
    }
    let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
        fixture.blocks[2].block_hash(),
        3,
    )?;
    assert!(matches!(
        historical
            .lock_transition()?
            .into_transition()
            .connect(&child, None),
        Err(ApplyError::ConnectPastHistoricalTarget { .. })
    ));
    Ok(())
}
