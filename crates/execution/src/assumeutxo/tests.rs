use std::io::Cursor;
use std::sync::Arc;

use crate::chain::{ChainWork, NodeStatus};
use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::{AssumeUtxoData, Block, BlockImage, Hash256, Network};
use bitcoin_rs_storage::DurableHead;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_storage::utxo::{
    SnapshotLoad, UtxoSet, read_snapshot_strict_v4, write_snapshot_observed,
};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, ChainstateRole, known_progress,
};
use crate::test_fixtures::{TestError, TestResult, handles};
use crate::{ApplyError, Chainstate};

fn chainstate() -> Arc<Chainstate> {
    let stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.track_coin_stats((*stats).clone());
    let mut chainstate = handles(Network::Regtest, Arc::new(utxo));
    chainstate.coin_stats = stats;
    Arc::new(chainstate)
}

struct ActivationFault {
    fail: AtomicBool,
    fail_terminal: AtomicBool,
}

impl ActivationFault {
    fn new() -> Self {
        Self {
            fail: AtomicBool::new(false),
            fail_terminal: AtomicBool::new(false),
        }
    }
}

impl bitcoin_rs_storage::CommitFault for ActivationFault {
    fn before_commit(
        &self,
        prefix: &bitcoin_rs_storage::AcceptedPrefix,
    ) -> Result<(), bitcoin_rs_storage::CommitError> {
        if self.fail.load(Ordering::Acquire)
            || (self.fail_terminal.load(Ordering::Acquire)
                && matches!(
                    prefix.next_head.assumeutxo,
                    AssumeUtxoDiskStatus::Failed { .. } | AssumeUtxoDiskStatus::Finalized { .. }
                ))
        {
            return Err(bitcoin_rs_storage::CommitError::Storage(
                bitcoin_rs_storage::StorageError::InvalidOperation("injected durable-head failure"),
            ));
        }
        Ok(())
    }
}

struct Fixture {
    head: Arc<ActivationFault>,
    active: Arc<Chainstate>,
    blocks: Vec<Block>,
    pinned: AssumeUtxoData,
    snapshot: Vec<u8>,
    stats: CoinStats,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let source = chainstate();
        let mut blocks = vec![Network::Regtest.genesis_block()];
        for height in 1..=2 {
            blocks.push(crate::chain::regtest_fixture::mined_regtest_child_at(
                blocks
                    .last()
                    .ok_or(TestError::Missing("missing predecessor"))?
                    .block_hash(),
                height,
            )?);
        }
        for block in &blocks {
            source
                .lock_transition()?
                .into_transition()
                .connect(&BlockImage::from_local((*block).clone()))?;
        }
        let snapshot_set = UtxoSet::new();
        for item in source
            .commit_authority
            .store()
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        {
            let (_, value) = item?;
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                value.into_boxed_slice(),
            )
            .map_err(|_| TestError::Missing("bad coin record"))?;
            snapshot_set.insert_parsed_record(record);
        }
        let tip = source
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing source tip"))?;
        let pinned = AssumeUtxoData {
            height: tip.height,
            block_hash: tip.hash,
            hash_serialized: snapshot_set.lock_stable_view().hash_serialized_3()?,
            chain_tx_count: tip.chain_tx_count.to_wire(),
            index_commitments: [None; 4],
        };
        let mut stats = snapshot_set.with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, tip.height, true)
        })?;
        stats.tx_count = tip.chain_tx_count.to_wire();
        let mut snapshot = Cursor::new(Vec::new());
        write_snapshot_observed(&snapshot_set, &tip.hash, tip.height, &mut snapshot, ())?;
        let active = chainstate();
        let head = Arc::new(ActivationFault::new());
        let fault: Arc<dyn bitcoin_rs_storage::CommitFault> = head.clone();
        active.commit_authority.set_fault(fault);
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
            stats,
        })
    }

    fn load(&self) -> Result<SnapshotLoad, bitcoin_rs_storage::utxo::UtxoError> {
        read_snapshot_strict_v4(&mut Cursor::new(&self.snapshot))
    }

    fn manager(&self, dir: &std::path::Path) -> Result<AssumeUtxoManager, AssumeUtxoError> {
        AssumeUtxoManager::open(
            Network::Regtest,
            Arc::clone(&self.active),
            dir.to_path_buf(),
        )
    }

    fn activate(&self, manager: &AssumeUtxoManager) -> TestResult {
        {
            let loaded = self.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &self.pinned)
        }?;
        Ok(())
    }
}

fn disk_status(active: &Chainstate) -> TestResult<AssumeUtxoDiskStatus> {
    Ok(active
        .durable_head
        .load()?
        .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo))
}

fn engine_coin_set(chain: &Chainstate) -> TestResult<UtxoSet> {
    let set = UtxoSet::new();
    for item in chain
        .commit_authority
        .store()
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
    {
        let (_, value) = item?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|_| TestError::Missing("bad coin record"))?;
        set.insert_parsed_record(record);
    }
    Ok(set)
}

#[test]
fn untrusted_snapshot_cannot_assert_its_own_commitment() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    let untrusted =
        manager.activate_native_snapshot(&mut Cursor::new(&fixture.snapshot), |_, _| {}, || true);
    assert!(matches!(
        untrusted,
        Err(AssumeUtxoError::UntrustedSnapshotHeight(height)) if height == fixture.pinned.height
    ));
    let pin = |block_hash, hash_serialized| AssumeUtxoData {
        height: fixture.pinned.height,
        block_hash,
        hash_serialized,
        chain_tx_count: fixture.pinned.chain_tx_count,
        index_commitments: [None; 4],
    };
    let wrong_base = manager.activate_native_pinned(
        &mut Cursor::new(&fixture.snapshot),
        &pin(Hash256::default(), fixture.pinned.hash_serialized),
        |_, _| {},
        || true,
    );
    assert!(matches!(
        wrong_base,
        Err(AssumeUtxoError::SnapshotBlockHashMismatch { .. })
    ));
    let forged = manager.activate_native_pinned(
        &mut Cursor::new(&fixture.snapshot),
        &pin(fixture.pinned.block_hash, Hash256::default()),
        |_, _| {},
        || true,
    );
    assert!(matches!(
        forged,
        Err(AssumeUtxoError::SnapshotCommitmentMismatch { .. })
    ));
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
    Ok(())
}

#[test]
fn snapshot_rejects_coin_height_alias_with_identical_commitment() -> TestResult {
    let fixture = Fixture::new()?;
    let mut bytes = fixture.snapshot.clone();
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
        manager.activate_pinned_snapshot(forged.set, forged.tip_hash, &fixture.pinned),
        Err(AssumeUtxoError::Utxo(
            bitcoin_rs_storage::utxo::UtxoError::SnapshotCoinHeightOutOfRange { .. }
        ))
    ));
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(fixture.active.applied_tip_snapshot().is_none());
    Ok(())
}

#[test]
fn snapshot_rejects_invalid_base_and_descendant_before_persistence() -> TestResult {
    for invalid_height in [2, 1] {
        let fixture = Fixture::new()?;
        {
            let mut tree = fixture.active.block_tree.write();
            let invalid = tree
                .lookup(fixture.blocks[invalid_height].block_hash().0)
                .ok_or(TestError::Missing("invalidated header missing"))?;
            tree.invalidate_subtree(invalid)?;
            let base = tree
                .node_by_hash(fixture.pinned.block_hash)
                .ok_or(TestError::Missing("snapshot base missing"))?;
            assert_eq!(base.status, NodeStatus::Invalid);
        }
        let before_stats = fixture.active.coin_stats.snapshot();
        let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
        let loaded = fixture.load()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
        assert!(matches!(
            result,
            Err(AssumeUtxoError::Apply(ApplyError::Chain(
                crate::chain::ChainError::KnownInvalidHeader { hash }
            ))) if hash == fixture.pinned.block_hash
        ));
        assert!(!dir.path().join("assumeutxo").exists());
        assert!(fixture.active.durable_head.load()?.is_none());
        assert!(fixture.active.applied_tip_snapshot().is_none());
        assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
        assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
        assert_eq!(
            fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
            before_coins
        );
        assert!(!fixture.active.is_closed_for_recovery());
    }
    Ok(())
}

fn competing_snapshot_headers() -> TestResult<Vec<Block>> {
    let mut parent = Network::Regtest.genesis_block().block_hash();
    let mut fork = Vec::new();
    for height in 1..=3 {
        let block = crate::chain::regtest_fixture::mined_regtest_child_at_time(
            parent,
            crate::chain::regtest_fixture::genesis_time() + 100 + height,
            height,
        )?;
        parent = block.block_hash();
        fork.push(block);
    }
    Ok(fork)
}

#[test]
fn snapshot_rejects_competing_best_headers_and_allows_valid_retry() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        fixture.active.clone(),
        dir.path().to_path_buf(),
    )?;
    let loaded = fixture.load()?;
    assert_eq!(
        (loaded.tip_hash, loaded.height),
        (fixture.pinned.block_hash, fixture.pinned.height)
    );
    let commitment = loaded
        .set
        .with_stable_view(|view| view.hash_serialized_3_at_height(fixture.pinned.height))?;
    assert_eq!(commitment, fixture.pinned.hash_serialized);
    let fork = competing_snapshot_headers()?;
    let fork_root = {
        let mut tree = fixture.active.block_tree.write();
        let root = tree.insert_header(fork[0].header, NodeStatus::HeaderValid)?;
        for block in &fork[1..] {
            tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        }
        let tip = tree
            .tip()
            .ok_or(TestError::Missing("best header missing"))?;
        let base = tree
            .node_by_hash(fixture.pinned.block_hash)
            .ok_or(TestError::Missing("snapshot base missing"))?;
        assert!(tip.chainwork > base.chainwork);
        assert_eq!(tip.hash, fork[2].block_hash().0);
        root
    };
    let before_stats = fixture.active.coin_stats.snapshot();
    let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
    let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
    assert!(matches!(
        result,
        Err(AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain {
            base_hash,
            base_height,
            best_header: Some(best),
        }) if base_hash == fixture.pinned.block_hash
            && base_height == fixture.pinned.height
            && best == fork[2].block_hash().0
    ));
    assert!(!dir.path().join("assumeutxo").exists());
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(manager.historical_chainstate().is_none());
    assert!(fixture.active.durable_head.load()?.is_none());
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
    assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
    assert_eq!(
        fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
        before_coins
    );
    assert!(!fixture.active.is_closed_for_recovery());

    fixture
        .active
        .block_tree
        .write()
        .invalidate_subtree(fork_root)?;
    fixture.activate(&manager)?;
    assert_eq!(
        fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("snapshot tip missing"))?
            .hash,
        fixture.pinned.block_hash
    );
    assert!(fixture.active.role().is_assumed_active());
    Ok(())
}

#[test]
fn snapshot_rejects_base_above_shorter_best_work_header_chain() -> TestResult {
    let fixture = Fixture::new()?;
    let mut harder = competing_snapshot_headers()?.remove(0);
    harder.header.bits =
        bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x2000_ffff);
    harder.header.nonce = 0;
    crate::chain::regtest_fixture::mine_block_to_declared_target(&mut harder)?;
    {
        let mut tree = fixture.active.block_tree.write();
        tree.insert_header(harder.header, NodeStatus::HeaderValid)?;
        let tip = tree
            .tip()
            .ok_or(TestError::Missing("best header missing"))?;
        let base = tree
            .node_by_hash(fixture.pinned.block_hash)
            .ok_or(TestError::Missing("base missing"))?;
        assert!(tip.height < base.height);
        assert!(tip.chainwork > base.chainwork);
        assert_eq!(tip.hash, harder.block_hash().0);
    }
    let loaded = fixture.load()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
    assert!(matches!(
        result,
        Err(AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain {
            base_hash,
            base_height,
            best_header: Some(best),
        }) if base_hash == fixture.pinned.block_hash
            && base_height == fixture.pinned.height
            && best == harder.block_hash().0
    ));
    assert!(!dir.path().join("assumeutxo").exists());
    assert!(fixture.active.durable_head.load()?.is_none());
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
    assert!(!fixture.active.is_closed_for_recovery());
    Ok(())
}

#[test]
fn snapshot_accepts_base_below_best_header_tip_on_same_ancestry() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let child =
        crate::chain::regtest_fixture::mined_regtest_child_at(fixture.blocks[2].block_hash(), 3)?;
    fixture
        .active
        .block_tree
        .write()
        .insert_header(child.header, NodeStatus::HeaderValid)?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        fixture.active.clone(),
        dir.path().to_path_buf(),
    )?;
    fixture.activate(&manager)?;
    assert_eq!(
        fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("snapshot tip missing"))?
            .hash,
        fixture.pinned.block_hash
    );
    assert_eq!(
        fixture
            .active
            .block_tree
            .read()
            .tip()
            .ok_or(TestError::Missing("best header missing"))?
            .hash,
        child.block_hash().0
    );
    Ok(())
}

fn snapshot_work_branch(
    height: u32,
    bits: u32,
    time_offset: u32,
) -> TestResult<(Vec<Block>, SnapshotLoad, CoinStats)> {
    let source = chainstate();
    let mut blocks = vec![Network::Regtest.genesis_block()];
    for next_height in 1..=height {
        blocks.push(crate::chain::regtest_fixture::mined_regtest_child_at_time(
            blocks
                .last()
                .ok_or(TestError::Missing("branch parent missing"))?
                .block_hash(),
            crate::chain::regtest_fixture::genesis_time() + time_offset + next_height,
            next_height,
        )?);
    }
    for block in &blocks {
        source
            .begin_transition()?
            .connect(&BlockImage::from_local((*block).clone()))?;
    }
    for index in 1..blocks.len() {
        blocks[index].header.prev_blockhash = blocks[index - 1].block_hash();
        blocks[index].header.bits =
            bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(bits);
        blocks[index].header.nonce = 0;
        crate::chain::regtest_fixture::mine_block_to_declared_target(&mut blocks[index])?;
    }
    let snapshot_set = UtxoSet::new();
    for item in source
        .commit_authority
        .store()
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
    {
        let (_, value) = item?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|_| TestError::Missing("bad coin record"))?;
        snapshot_set.insert_parsed_record(record);
    }
    let tip = blocks
        .last()
        .ok_or(TestError::Missing("branch tip missing"))?
        .block_hash()
        .0;
    let mut stats = snapshot_set.with_stable_view(|view| {
        bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, height, true)
    })?;
    stats.tx_count = source.coin_stats.snapshot().tx_count;
    let mut encoded = Vec::new();
    write_snapshot_observed(&snapshot_set, &tip, height, &mut encoded, ())?;
    let loaded = read_snapshot_strict_v4(&mut Cursor::new(encoded))?;
    Ok((blocks, loaded, stats))
}

fn snapshot_work_fixture(
    snapshot_height: u32,
    snapshot_bits: u32,
    applied_height: u32,
    applied_bits: u32,
) -> TestResult<Fixture> {
    let (blocks, snapshot, stats) = snapshot_work_branch(snapshot_height, snapshot_bits, 0)?;
    let (applied_blocks, mut applied, applied_stats) =
        snapshot_work_branch(applied_height, applied_bits, 100)?;
    let mut tree = crate::chain::BlockTree::new();
    for block in blocks.iter().chain(applied_blocks.iter().skip(1)) {
        tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    }
    let applied_id = tree
        .lookup(applied.tip_hash)
        .ok_or(TestError::Missing("applied header missing"))?;
    tree.restore_chain_tx_count(
        applied_id,
        crate::chain::ChainTxCount::established(applied_stats.tx_count),
    )?;
    let applied_node = tree.node(applied_id)?;
    let applied_tip = crate::chain::TipSnapshot {
        tip_id: applied_id,
        height: applied_node.height,
        chainwork: applied_node.chainwork,
        hash: applied_node.hash,
        chain_tx_count: applied_node.chain_tx_count,
    };
    let coin_stats = Arc::new(CoinStatsListener::new(applied_stats));
    applied.set.track_coin_stats((*coin_stats).clone());
    let active = Chainstate::new(
        Network::Regtest,
        Arc::new(ArcSwapOption::new(tree.tip())),
        Arc::new(ArcSwapOption::new(Some(Arc::new(applied_tip.clone())))),
        Arc::new(RwLock::new(tree)),
        Arc::new(applied.set),
        coin_stats,
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    );
    active
        .commit_authority
        .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
            expected_head: None,
            next_head: DurableHead {
                assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 17,
                height: applied_tip.height,
                tip: applied_tip.hash,
                chain_tx_count: applied_tip.chain_tx_count.to_wire(),
                body_extent: None,
                undo_extent: None,
            },
            undo_rows: Vec::new(),
            body_rows: Vec::new(),
            attestation: None,
            coin_delta: bitcoin_rs_storage::WindowDelta::default(),
        })
        .map_err(|error| TestError::Storage(bitcoin_rs_storage::StorageError::backend(error)))?;
    let head = Arc::new(ActivationFault::new());
    let fault: Arc<dyn bitcoin_rs_storage::CommitFault> = head.clone();
    active.commit_authority.set_fault(fault);
    let pinned = AssumeUtxoData {
        height: snapshot.height,
        block_hash: snapshot.tip_hash,
        hash_serialized: snapshot.set.lock_stable_view().hash_serialized_3()?,
        chain_tx_count: stats.tx_count,
        index_commitments: [None; 4],
    };
    let mut encoded = Vec::new();
    write_snapshot_observed(
        &snapshot.set,
        &pinned.block_hash,
        pinned.height,
        &mut encoded,
        (),
    )?;
    Ok(Fixture {
        head,
        active: Arc::new(active),
        blocks,
        pinned,
        snapshot: encoded,
        stats,
    })
}

#[test]
fn snapshot_rejects_higher_base_with_less_work_than_applied_tip() -> TestResult {
    let fixture = snapshot_work_fixture(2, 0x207f_ffff, 1, 0x2000_ffff)?;
    let before = fixture
        .active
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip missing"))?;
    let before_head = fixture.active.durable_head.load()?;
    let before_stats = fixture.active.coin_stats.snapshot();
    let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
    let mut child =
        crate::chain::regtest_fixture::mined_regtest_child_at(fixture.blocks[2].block_hash(), 3)?;
    child.header.bits =
        bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1f7f_ffff);
    child.header.nonce = 0;
    crate::chain::regtest_fixture::mine_block_to_declared_target(&mut child)?;
    {
        let mut tree = fixture.active.block_tree.write();
        tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let best = tree
            .tip()
            .ok_or(TestError::Missing("best header missing"))?;
        let base_id = tree
            .lookup(fixture.pinned.block_hash)
            .ok_or(TestError::Missing("base missing"))?;
        let base = tree.node(base_id)?;
        assert!(base.height > before.height);
        assert!(base.chainwork < before.chainwork);
        assert!(best.chainwork > before.chainwork);
        assert_eq!(
            tree.node_at_height_from(best.tip_id, base.height),
            Some(base_id)
        );
    }
    let dir = tempfile::tempdir()?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        fixture.active.clone(),
        dir.path().to_path_buf(),
    )?;
    let loaded = fixture.load()?;
    let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
    assert!(matches!(result, Err(AssumeUtxoError::ActivationBehindTip)));
    assert_eq!(fixture.active.durable_head.load()?, before_head);
    assert_eq!(
        fixture.active.applied_tip_snapshot().as_deref(),
        Some(before.as_ref())
    );
    assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
    assert_eq!(
        fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
        before_coins
    );
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(!fixture.active.is_closed_for_recovery());
    Ok(())
}

#[test]
fn snapshot_accepts_lower_base_with_more_work_than_applied_tip() -> TestResult {
    let fixture = snapshot_work_fixture(1, 0x2000_ffff, 2, 0x207f_ffff)?;
    let dir = tempfile::tempdir()?;
    let before = fixture
        .active
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip missing"))?;
    let before_head = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head missing"))?;
    {
        let tree = fixture.active.block_tree.read();
        let base = tree
            .node_by_hash(fixture.pinned.block_hash)
            .ok_or(TestError::Missing("base missing"))?;
        assert!(base.height < before.height);
        assert!(base.chainwork > before.chainwork);
        assert_eq!(
            tree.tip()
                .ok_or(TestError::Missing("best header missing"))?
                .hash,
            base.hash
        );
    }
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        fixture.active.clone(),
        dir.path().to_path_buf(),
    )?;
    fixture.activate(&manager)?;
    let applied = fixture
        .active
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("snapshot tip missing"))?;
    let head = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("snapshot head missing"))?;
    assert_eq!(head.commit_id, before_head.commit_id + 1);
    assert_eq!(head.height, fixture.pinned.height);
    assert_eq!(head.tip, fixture.pinned.block_hash);
    assert_eq!(head.chain_tx_count, fixture.pinned.chain_tx_count);
    assert_eq!((applied.height, applied.hash), (head.height, head.tip));
    assert!(applied.chainwork > before.chainwork);
    assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
    assert_eq!(
        engine_coin_set(&fixture.active)?
            .lock_stable_view()
            .hash_serialized_3()?,
        fixture.pinned.hash_serialized
    );
    assert!(fixture.active.role().is_assumed_active());
    Ok(())
}

#[test]
fn snapshot_refuses_work_comparison_when_durable_and_applied_tips_differ() -> TestResult {
    for (change_hash, height_delta, count_delta) in [(true, 0, 0), (false, 1, 0), (false, 0, 1)] {
        let fixture = snapshot_work_fixture(2, 0x207f_ffff, 1, 0x207f_ffff)?;
        let applied = fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip missing"))?;
        let prior = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("durable head missing"))?;
        let unsettled = DurableHead {
            commit_id: prior.commit_id + 1,
            tip: if change_hash {
                fixture.blocks[1].block_hash().0
            } else {
                prior.tip
            },
            height: prior.height + height_delta,
            chain_tx_count: prior.chain_tx_count + count_delta,
            ..prior
        };
        fixture
            .active
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: Some(prior),
                next_head: unsettled,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|error| {
                TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
            })?;
        let dir = tempfile::tempdir()?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        let loaded = fixture.load()?;
        let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
        assert!(
            matches!(result, Err(AssumeUtxoError::SnapshotTipNotSettled {
            durable_tip: Some(durable), applied_tip: Some(current),
        }) if durable == (unsettled.tip, unsettled.height, unsettled.chain_tx_count)
            && current == (applied.hash, applied.height, applied.chain_tx_count.to_wire()))
        );
        assert!(fixture.active.is_closed_for_recovery());
        assert_eq!(fixture.active.durable_head.load()?, Some(unsettled));
        assert_eq!(
            fixture.active.applied_tip_snapshot().as_deref(),
            Some(applied.as_ref())
        );
        assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    }
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
        .ok_or(TestError::Missing("missing snapshot tip"))?;
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
        engine_coin_set(active)?
            .lock_stable_view()
            .hash_serialized_3()?,
        fixture.pinned.hash_serialized
    );
    assert!(active.role().is_assumed_active());
    assert_eq!(manager.status()?, disk_status(&fixture.active)?);
    assert!(matches!(
        active.prune_authority().begin(),
        Err(ApplyError::PruneDuringHistoricalValidation { .. })
    ));
    assert!(matches!(
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        },
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
        dir.path().to_path_buf(),
    )?;
    assert!(matches!(
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        },
        Err(AssumeUtxoError::SnapshotHeaderMissing(_))
    ));
    assert!(active.durable_head.load()?.is_none());
    let manager = fixture.manager(dir.path())?;
    let mut wrong_height = fixture.pinned;
    wrong_height.height += 1;
    assert!(matches!(
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &wrong_height)
        },
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
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        },
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
        .ok_or(TestError::Missing("missing active anchor"))?;
    let events = fixture.active.chain_events.snapshot();
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("historical missing"))?;
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
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        let head = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing head"))?;
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

mod recovery;

#[test]
fn snapshot_advances_partial_state_but_refuses_to_replace_an_equal_or_newer_tip() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    fixture
        .active
        .begin_transition()?
        .connect(&BlockImage::from_local(fixture.blocks[0].clone()))?;
    fixture
        .active
        .begin_transition()?
        .connect(&BlockImage::from_local(fixture.blocks[1].clone()))?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    for block in &fixture.blocks {
        fixture
            .active
            .begin_transition()?
            .connect(&BlockImage::from_local((*block).clone()))?;
    }
    let manager = fixture.manager(dir.path())?;
    let before = fixture.active.durable_head.load()?;
    let before_stats = fixture.active.coin_stats.snapshot();
    assert!(matches!(
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        },
        Err(AssumeUtxoError::ActivationBehindTip)
    ));
    assert_eq!(fixture.active.durable_head.load()?, before);
    assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
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
        manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone())),
        Err(AssumeUtxoError::Apply(ApplyError::PrevHashMismatch { .. }))
    ));
    assert_eq!(fixture.active.durable_head.load()?, before);
    assert!(!fixture.active.is_closed_for_recovery());
    manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
    Ok(())
}

#[test]
fn historical_restart_replays_coins_from_genesis_instead_of_fabricating_a_tip() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    assert!(
        manager
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical"))?
            .coin_stats
            .snapshot()
            .utxo_count
            > 0
    );
    drop(manager);
    let reopened = fixture.manager(dir.path())?;
    let historical = reopened
        .historical_chainstate()
        .ok_or(TestError::Missing("missing historical after restart"))?;
    assert!(historical.applied_tip_snapshot().is_none());
    assert_eq!(historical.coin_stats.snapshot(), CoinStats::default());
    for block in &fixture.blocks {
        reopened.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    assert!(matches!(
        reopened.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    Ok(())
}

// RCV-02
#[test]
fn finalized_replay_attests_full_so_a_full_start_skips_revalidation() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let activated = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing activated head"))?;
    assert_eq!(
        fixture.active.durable_head.load_attestation(&activated)?,
        bitcoin_rs_storage::ScriptAttestation::AssumeValid,
        "an activated snapshot has not executed the scripts below its base yet"
    );
    for block in &fixture.blocks {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Finalized { .. }
    ));
    let finalized = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing finalized head"))?;
    assert_eq!(
        fixture.active.durable_head.load_attestation(&finalized)?,
        bitcoin_rs_storage::ScriptAttestation::Full,
        "the historical replay executed every script below the base"
    );
    crate::recovery::require_full_script_attestation(
        dir.path(),
        crate::ValidationMode::Full,
        Some(&finalized),
        fixture.active.durable_head.as_ref(),
        false,
    )?;
    assert!(
        !crate::recovery::requires_full_revalidation(dir.path()),
        "a finalized assumeutxo datadir must not take the cold revalidation path"
    );
    Ok(())
}

// RCV-02
#[test]
fn finalized_replay_keeps_an_assume_valid_suffix_below_full() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let prior = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing activated head"))?;
    let next = DurableHead {
        commit_id: prior.commit_id + 1,
        height: prior.height + 1,
        tip: Hash256::from_le_bytes(&[0x33; 32]),
        chain_tx_count: prior.chain_tx_count + 1,
        ..prior
    };
    fixture
        .active
        .commit_authority
        .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
            expected_head: Some(prior),
            next_head: next,
            undo_rows: Vec::new(),
            body_rows: Vec::new(),
            attestation: Some(bitcoin_rs_storage::ScriptAttestation::AssumeValid),
            coin_delta: bitcoin_rs_storage::WindowDelta::default(),
        })
        .map_err(|error| TestError::Storage(bitcoin_rs_storage::StorageError::backend(error)))?;
    assert_eq!(
        fixture.active.durable_head.load_suffix_attestation(&next)?,
        bitcoin_rs_storage::ScriptAttestation::AssumeValid,
        "a block above the base that skipped scripts must lower the suffix level"
    );
    for block in &fixture.blocks {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    let finalized = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing finalized head"))?;
    assert_eq!(
        fixture.active.durable_head.load_attestation(&finalized)?,
        bitcoin_rs_storage::ScriptAttestation::AssumeValid,
        "the finalized head spans blocks above the base that never executed scripts"
    );
    crate::recovery::require_full_script_attestation(
        dir.path(),
        crate::ValidationMode::Full,
        Some(&finalized),
        fixture.active.durable_head.as_ref(),
        false,
    )?;
    assert!(
        crate::recovery::requires_full_revalidation(dir.path()),
        "a full start must revalidate a chain whose suffix skipped scripts"
    );
    Ok(())
}

// RCV-02
#[test]
fn finalized_replay_attests_full_after_an_executed_suffix() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let block = crate::chain::regtest_fixture::mined_regtest_child_at(
        fixture
            .blocks
            .last()
            .ok_or(TestError::Missing("missing base block"))?
            .block_hash(),
        3,
    )?;
    fixture
        .active
        .block_tree
        .write()
        .insert_header(block.header, NodeStatus::HeaderValid)?;
    fixture.active.apply_block(&BlockImage::from_local(block))?;
    let executed = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing executed head"))?;
    assert_eq!(executed.height, 3);
    assert_eq!(
        fixture
            .active
            .durable_head
            .load_suffix_attestation(&executed)?,
        bitcoin_rs_storage::ScriptAttestation::Full,
        "a block above the base that executed scripts keeps the suffix level Full"
    );
    for block in &fixture.blocks {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    let finalized = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing finalized head"))?;
    assert_eq!(
        fixture.active.durable_head.load_attestation(&finalized)?,
        bitcoin_rs_storage::ScriptAttestation::Full,
        "the historical replay and every suffix block executed scripts"
    );
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
            let prior = fixture
                .active
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing head"))?;
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
        let historical = manager
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical"))?;
        let Err(error) =
            manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))
        else {
            return Err(TestError::UnexpectedSuccess("divergence finalized"));
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
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    let mut wrong = fixture.blocks[2].clone();
    wrong.header.nonce = wrong.header.nonce.wrapping_add(1);
    assert!(matches!(
        manager.step_historical(&BlockImage::from_local(wrong)),
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
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    fixture.head.fail_terminal.store(true, Ordering::Release);
    let mut wrong = fixture.blocks[2].clone();
    wrong.header.nonce = wrong.header.nonce.wrapping_add(1);
    assert!(matches!(
        manager.step_historical(&BlockImage::from_local(wrong)),
        Err(AssumeUtxoError::Storage(_))
    ));
    assert!(fixture.active.lock_transition().is_err());
    assert!(
        manager
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical"))?
            .lock_transition()
            .is_err()
    );
    Ok(())
}

#[test]
fn finalization_io_failure_keeps_assumed_role_and_closes_both_admissions() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        fixture.active.clone(),
        dir.path().to_path_buf(),
        1,
    )?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    fixture.head.fail_terminal.store(true, Ordering::Release);
    let root = dir
        .path()
        .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
    let checkpoint_entries = std::fs::read_dir(&root)?.count();
    assert!(checkpoint_entries > 1);
    assert!(matches!(
        manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone())),
        Err(AssumeUtxoError::Storage(_))
    ));
    assert!(fixture.active.role().is_assumed_active());
    assert_eq!(std::fs::read_dir(root)?.count(), checkpoint_entries);
    assert!(matches!(
        manager.status()?,
        AssumeUtxoDiskStatus::Validating { .. }
    ));
    assert!(fixture.active.lock_transition().is_err());
    assert!(
        manager
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical"))?
            .lock_transition()
            .is_err()
    );
    Ok(())
}

// ARCH-07b
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
        .ok_or(TestError::Missing("missing historical"))?;
    for block in &fixture.blocks {
        manager.step_historical(&BlockImage::from_local((*block).clone()))?;
    }
    let child =
        crate::chain::regtest_fixture::mined_regtest_child_at(fixture.blocks[2].block_hash(), 3)?;
    assert!(matches!(
        historical
            .lock_transition()?
            .into_transition()
            .connect(&BlockImage::from_local(child)),
        Err(ApplyError::ConnectPastHistoricalTarget { .. })
    ));
    Ok(())
}

#[test]
fn snapshot_persistence_does_not_block_existing_progress_queries() -> TestResult {
    let fixture = Fixture::new()?;
    let genesis = Network::Regtest.genesis_block();
    fixture
        .active
        .lock_transition()?
        .into_transition()
        .connect(&BlockImage::from_local(genesis))?;
    let before = fixture
        .active
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("genesis missing"))?;
    let reader = fixture.active.chain_progress_reader();
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    let mut reader = Some(reader);
    let mut observed = None;
    let result = std::thread::scope(|scope| {
        manager.activate_native_pinned(
            &mut std::io::Cursor::new(&fixture.snapshot),
            &fixture.pinned,
            |_, _| {
                let Some(reader) = reader.take() else {
                    return;
                };
                let (sent, received) = std::sync::mpsc::sync_channel(1);
                scope.spawn(move || {
                    let progress = reader.progress(
                        Network::Regtest,
                        bitcoin_rs_consensus::primitives::unix_time_secs(),
                    );
                    let _ = sent.send(progress);
                });
                observed = received
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .ok();
            },
            || false,
        )
    });
    assert!(result.is_err());
    let progress = observed.ok_or(TestError::UnexpectedSuccess(
        "progress query blocked behind snapshot persistence",
    ))?;
    assert_eq!(progress.blocks, before.height);
    assert_eq!(progress.best_block_hash, before.hash);
    assert_eq!(
        fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::UnexpectedSuccess("prior tip lost"))?
            .hash,
        before.hash
    );
    Ok(())
}

#[test]
fn lifecycle_report_refuses_contention_without_waiting_for_the_transition() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager =
        AssumeUtxoManager::open(Network::Regtest, fixture.active, dir.path().to_path_buf())?;
    let observed = std::thread::scope(|scope| {
        let guard = manager.lifecycle.lock();
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let reader = &manager;
        scope.spawn(move || {
            let _ = sent.send(reader.try_chainstates_report());
        });
        let observed = received.recv_timeout(std::time::Duration::from_secs(5));
        drop(guard);
        observed
    });
    let report = observed??;
    assert!(
        report.is_none(),
        "busy lifecycle must not report fabricated roles"
    );
    let report = manager
        .try_chainstates_report()?
        .ok_or(TestError::UnexpectedSuccess(
            "lifecycle remained busy after release",
        ))?;
    assert_eq!(report.lifecycle, manager.chainstates_summary()?);
    Ok(())
}

#[test]
fn activation_stages_witness_only_after_durable_commit() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    assert!(manager.take_pending_activation_witness().is_none());
    fixture.activate(&manager)?;
    let staged = manager.take_pending_activation_witness();
    assert!(staged.is_some(), "activation must stage a witness");
    assert!(manager.take_pending_activation_witness().is_none());
    Ok(())
}

// RCV-02
#[test]
fn activation_attests_the_snapshot_base_as_assume_valid() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let head = fixture
        .active
        .durable_head
        .load()?
        .ok_or(TestError::Missing("missing activated durable head"))?;
    assert!(matches!(
        head.assumeutxo,
        AssumeUtxoDiskStatus::Validating { .. }
    ));
    assert_eq!(
        fixture.active.durable_head.load_attestation(&head)?,
        bitcoin_rs_storage::ScriptAttestation::AssumeValid,
        "the snapshot base was not script-checked locally"
    );
    Ok(())
}

#[test]
fn activation_failure_leaves_no_staged_witness() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    let loaded = fixture.load()?;
    let wrong_hash = Hash256::default();
    assert_ne!(wrong_hash, fixture.pinned.block_hash);
    let result = manager.activate_pinned_snapshot(loaded.set, wrong_hash, &fixture.pinned);
    assert!(matches!(
        result,
        Err(AssumeUtxoError::SnapshotBlockHashMismatch { .. })
    ));
    assert!(manager.take_pending_activation_witness().is_none());
    fixture.head.fail.store(true, Ordering::Release);
    let loaded = fixture.load()?;
    let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
    assert!(result.is_err());
    assert!(manager.take_pending_activation_witness().is_none());
    Ok(())
}

#[test]
fn lifecycle_progress_omits_missing_and_unauthenticated_counts() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        fixture.active.clone(),
        dir.path().to_path_buf(),
    )?;
    assert_eq!(
        manager
            .try_chainstates_report()?
            .ok_or(TestError::Missing("uncontended lifecycle is busy"))?
            .active_verification_progress,
        None
    );
    assert_eq!(known_progress(None, 0.5), None);
    let tip = fixture
        .active
        .block_tree
        .read()
        .tip()
        .ok_or(TestError::Missing("header tip missing"))?;
    let mut tip = (*tip).clone();
    tip.chain_tx_count = crate::chain::ChainTxCount::UNKNOWN;
    assert_eq!(known_progress(Some(&tip), 0.5), None);
    tip.chain_tx_count = crate::chain::ChainTxCount::established(3);
    assert_eq!(known_progress(Some(&tip), 0.5), Some(0.5));
    Ok(())
}

#[test]
fn activation_offer_only_on_full_success() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;

    let staged = manager.take_pending_activation_witness();
    assert!(staged.is_some(), "activation must stage a witness");
    let _ = staged;
    assert!(manager.take_pending_activation_witness().is_none());

    let retry = fixture.load()?;
    assert!(matches!(
        manager.activate_pinned_snapshot(retry.set, retry.tip_hash, &fixture.pinned),
        Err(AssumeUtxoError::AlreadyActive)
    ));
    let initial =
        crate::assumeutxo_snapshot::load_verified(dir.path(), Network::Regtest, &fixture.pinned)?;
    assert!(matches!(
        initial.resume_source,
        crate::recovery::ResumeSource::Snapshot
    ));
    assert!(manager.take_pending_activation_witness().is_none());

    drop(manager);
    let reopened = fixture.manager(dir.path())?;
    assert!(matches!(
        reopened.status()?,
        AssumeUtxoDiskStatus::Validating { .. }
    ));
    drop(reopened);
    let restored =
        crate::assumeutxo_snapshot::load_verified(dir.path(), Network::Regtest, &fixture.pinned)?;
    assert!(matches!(
        restored.resume_source,
        crate::recovery::ResumeSource::Snapshot
    ));
    Ok(())
}

// RCV-01, RCV-04
#[test]
fn rejects_assumeutxo_snapshot_with_truncated_headers() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    drop(manager);
    let path = dir
        .path()
        .join("assumeutxo")
        .join(fixture.pinned.block_hash.to_string());
    std::fs::write(path.join("headers.dat"), [0_u8; 10])?;
    let result =
        crate::assumeutxo_snapshot::load_verified(dir.path(), Network::Regtest, &fixture.pinned);
    assert!(matches!(
        result,
        Err(crate::assumeutxo_snapshot::SnapshotArchiveError::HeaderArchiveLength)
    ));
    Ok(())
}

fn engine_coin_records(
    chain: &Chainstate,
) -> TestResult<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut records = std::collections::BTreeMap::new();
    for item in chain
        .commit_authority
        .store()
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
    {
        let (key, value) = item?;
        records.insert(key.to_vec(), value.to_vec());
    }
    Ok(records)
}

fn assert_engine_matches_snapshot(chain: &Chainstate, fixture: &Fixture) -> TestResult {
    let file = read_snapshot_strict_v4(&mut Cursor::new(&fixture.snapshot))?;
    let file_records = file.set.all_records();
    let engine = engine_coin_records(chain)?;
    assert_eq!(
        engine.len(),
        file_records.len(),
        "one engine row per snapshot record"
    );
    for record in &file_records {
        let txid = record.txid().to_le_bytes();
        let stored = engine
            .get(txid.as_slice())
            .ok_or(TestError::Missing("snapshot coin absent from the engine"))?;
        assert_eq!(
            stored.as_slice(),
            record.bytes(),
            "engine row equals file record"
        );
    }
    let mut outputs = 0_u64;
    let mut amount = 0_u64;
    for stored in engine.values() {
        let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
            stored.clone().into_boxed_slice(),
        )
        .map_err(|_| TestError::Missing("bad coin record"))?;
        for output in record.outputs() {
            outputs += 1;
            amount += output.value;
        }
    }
    assert_eq!(
        outputs, fixture.stats.utxo_count,
        "coin count equals manifest"
    );
    assert_eq!(
        amount, fixture.stats.total_amount,
        "total amount equals manifest"
    );
    Ok(())
}

#[test]
fn activation_streams_every_snapshot_coin_into_the_engine() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    let activated = manager.activate_native_pinned(
        &mut Cursor::new(&fixture.snapshot),
        &fixture.pinned,
        |_, _| {},
        || true,
    )?;
    assert_eq!(activated.base_hash, fixture.pinned.block_hash);
    assert_engine_matches_snapshot(&fixture.active, &fixture)
}

// SNP-08
#[test]
fn historical_facts_hook_receives_facts_on_step_historical() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);
    manager.set_historical_facts_hook(Arc::new(move |_payload, outcome| {
        if outcome.height == 0 {
            called_clone.store(true, Ordering::Release);
        }
    }));
    let genesis = BlockImage::from_local(Network::Regtest.genesis_block());
    let outcome = manager.step_historical(&genesis)?;
    assert_eq!(outcome.height, 0);
    assert!(called.load(Ordering::Acquire));
    manager.clear_historical_facts_hook();
    Ok(())
}
