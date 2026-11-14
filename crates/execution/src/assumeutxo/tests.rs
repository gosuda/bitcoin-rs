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
use crate::test_fixtures::{TestError, TestResult, handles, seed_durable_head, seed_genesis};
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
        Self::from_blocks(blocks)
    }

    fn from_blocks(blocks: Vec<Block>) -> TestResult<Self> {
        let source = chainstate();
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
    let active = chainstate();
    let dir = tempfile::tempdir()?;
    let manager = AssumeUtxoManager::open(
        Network::Regtest,
        Arc::clone(&active),
        dir.path().to_path_buf(),
    )?;
    let pinned = Network::Regtest
        .assume_utxo_for_height(110)
        .ok_or(TestError::Missing("missing pin"))?;
    for (height, hash) in [
        (1234, pinned.block_hash),
        (110, Hash256::default()),
        (110, pinned.block_hash),
    ] {
        let Err(error) = manager.activate_snapshot_state(UtxoSet::new(), hash, height) else {
            return Err(TestError::UnexpectedSuccess("untrusted snapshot accepted"));
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
        let persisted = AtomicBool::new(false);
        let loaded = fixture.load()?;
        let result = fixture.active.install_snapshot(
            loaded.set,
            fixture.stats.clone(),
            &fixture.pinned,
            |_, _, _, _| {
                persisted.store(true, Ordering::Relaxed);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(AssumeUtxoError::Apply(ApplyError::Chain(
                crate::chain::ChainError::KnownInvalidHeader { hash }
            ))) if hash == fixture.pinned.block_hash
        ));
        assert!(!persisted.load(Ordering::Relaxed));
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
    let (commitment, verified_stats) = loaded.set.with_stable_view(|view| {
        Ok::<_, bitcoin_rs_storage::utxo::UtxoError>((
            view.hash_serialized_3_at_height(fixture.pinned.height)?,
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, fixture.pinned.height, true)?,
        ))
    })?;
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
    let persisted = AtomicBool::new(false);
    let result = fixture.active.install_snapshot(
        loaded.set,
        verified_stats,
        &fixture.pinned,
        |_, _, _, _| {
            persisted.store(true, Ordering::Relaxed);
            Ok(())
        },
    );
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
    assert!(!persisted.load(Ordering::Relaxed));
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
    let persisted = AtomicBool::new(false);
    let loaded = fixture.load()?;
    let result = fixture.active.install_snapshot(
        loaded.set,
        fixture.stats.clone(),
        &fixture.pinned,
        |_, _, _, _| {
            persisted.store(true, Ordering::Relaxed);
            Ok(())
        },
    );
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
    assert!(!persisted.load(Ordering::Relaxed));
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

/// Independent oracle for the historical chainstate's coin statistics: a full
/// scan of the engine `coins` keyspace at `height`, with the transaction count
/// taken from the connected tip instead of any listener.
fn scanned_historical_stats(
    historical: &Chainstate,
    height: u32,
    chain_tx_count: u64,
) -> TestResult<CoinStats> {
    let mut stats = engine_coin_set(historical)?.with_stable_view(|view| {
        bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, height, true)
    })?;
    stats.tx_count = chain_tx_count;
    Ok(stats)
}

/// Compares every field. A rolling `MuHash` and a scanned one are the same
/// value in different raw numerator and denominator form, so the digest is
/// compared after `finalize`.
fn assert_same_stats(actual: &CoinStats, expected: &CoinStats, height: u32) {
    assert_eq!(
        (
            actual.height,
            actual.tx_count,
            actual.utxo_count,
            actual.total_amount,
            actual.bogo_size,
        ),
        (
            expected.height,
            expected.tx_count,
            expected.utxo_count,
            expected.total_amount,
            expected.bogo_size,
        ),
        "historical coin statistics at height {height} must equal a full scan of the engine coins"
    );
    assert_eq!(
        actual.muhash.finalize(),
        expected.muhash.finalize(),
        "historical MuHash at height {height} must equal a full scan of the engine coins"
    );
}

/// Genesis plus 101 coinbase blocks. The last block also spends the height-1
/// coinbase output, which is mature at height 101, so the historical replay
/// removes a coin as well as adding them.
fn spending_chain() -> TestResult<(Vec<Block>, bitcoin_rs_consensus::primitives::OutPoint)> {
    use crate::chain::regtest_fixture::{
        coinbase, mined_block_with_prev_hash, mined_regtest_child_at,
    };
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;

    let mut blocks = vec![Network::Regtest.genesis_block()];
    for height in 1..=100 {
        let prev = blocks
            .last()
            .ok_or(TestError::Missing("missing predecessor"))?
            .block_hash();
        blocks.push(mined_regtest_child_at(prev, height)?);
    }
    let funding = OutPoint::new(blocks[1].txs[0].txid(), 0);
    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: vec![OP_PUSHNUM_1].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![OP_PUSHNUM_1].into(),
        }],
        lock_time: LockTime::ZERO,
    };
    let prev = blocks
        .last()
        .ok_or(TestError::Missing("missing predecessor"))?
        .block_hash();
    blocks.push(mined_block_with_prev_hash(
        prev,
        101,
        vec![coinbase(101), spend],
    )?);
    Ok((blocks, funding))
}

#[test]
fn historical_stats_equal_a_full_scan_after_every_step_including_a_spend() -> TestResult {
    let (blocks, funding) = spending_chain()?;
    let fixture = Fixture::from_blocks(blocks)?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("historical missing"))?;
    for block in &fixture.blocks {
        let outcome = manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        let expected = scanned_historical_stats(
            &historical,
            outcome.height,
            outcome.tip.chain_tx_count.to_wire(),
        )?;
        assert_same_stats(&historical.coin_stats.snapshot(), &expected, outcome.height);
    }
    assert!(
        engine_coin_set(&historical)?.get(&funding).is_none(),
        "the height-101 spend must have removed the funding coin"
    );
    Ok(())
}

#[test]
fn historical_step_advances_the_rolling_stats_without_rescanning_the_store() -> TestResult {
    const MARKER: u64 = 1_000_000;
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let manager = fixture.manager(dir.path())?;
    fixture.activate(&manager)?;
    let historical = manager
        .historical_chainstate()
        .ok_or(TestError::Missing("historical missing"))?;
    manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
    let mut marked = historical.coin_stats.snapshot();
    marked.tx_count += MARKER;
    historical.coin_stats.reset(marked);
    let outcome = manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone()))?;
    let mut expected = scanned_historical_stats(
        &historical,
        outcome.height,
        outcome.tip.chain_tx_count.to_wire(),
    )?;
    expected.tx_count += MARKER;
    assert_same_stats(&historical.coin_stats.snapshot(), &expected, outcome.height);
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
    let loaded = fixture.load()?;
    let mut observed = None;
    let result = std::thread::scope(|scope| {
        fixture.active.install_snapshot(
            loaded.set,
            fixture.stats.clone(),
            &fixture.pinned,
            |_, _, _, _| {
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
                Err(AssumeUtxoError::Storage(
                    bitcoin_rs_storage::StorageError::InvalidOperation(
                        "simulated persistence refusal",
                    ),
                ))
            },
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
    assert!(manager.take_pending_activation_witness().is_none());

    drop(manager);
    let reopened = fixture.manager(dir.path())?;
    assert!(matches!(
        reopened.status()?,
        AssumeUtxoDiskStatus::Validating { .. }
    ));
    let initial =
        crate::assumeutxo_snapshot::load_verified(dir.path(), Network::Regtest, &fixture.pinned)?;
    assert!(initial.script_live_seed.is_some());
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

#[test]
fn restored_coin_stats_scan_preserves_the_corrupt_row_utxo_error() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    seed_durable_head(
        &chain,
        DurableHead {
            assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: Hash256::from(Network::Regtest.genesis_block().block_hash()),
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        },
    )?;

    let txid = Hash256::from_le_bytes(&[0x5A; 32]);
    let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        txid,
        &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: 1_000,
            script_pubkey: vec![0x51],
            coinbase: false,
            height: 0,
        }],
    )?;
    let mut row = record.bytes().to_vec();
    row.truncate(20);
    chain.commit_authority.store().put(
        bitcoin_rs_storage::ColumnFamily::Coins,
        bitcoin_rs_storage::CoinKey(txid.to_le_bytes()).as_bytes(),
        &row,
    )?;

    let error = crate::recovery::settle_restored_coin_stats(&chain, None)
        .err()
        .ok_or(TestError::UnexpectedSuccess(
            "a malformed coin row must fail the restored coin statistics scan",
        ))?;
    let crate::recovery::RecoveryError::Utxo(source) = error else {
        return Err(TestError::Missing(
            "the scan failure must keep its UtxoError cause",
        ));
    };
    assert!(
        matches!(source, bitcoin_rs_storage::utxo::UtxoError::CorruptRecord),
        "the preserved cause must name the corrupt row, got {source:?}"
    );
    Ok(())
}
