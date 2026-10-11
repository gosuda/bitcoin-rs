//! ARCH-07b: verified installation, isolated replay, and fail-closed convergence.
use std::io::Cursor;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{ChainWork, NodeStatus};
use bitcoin_rs_primitives::{AssumeUtxoData, Block, Hash256, Network};
use bitcoin_rs_storage::{CommitRecords, DurableHead, DurableHeadStore, StorageError};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{SnapshotLoad, UtxoSet, read_snapshot_strict_v4, write_snapshot_observed};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, ChainstateRole, known_progress,
};
use crate::test_fixtures::handles;
use crate::{ApplyError, Chainstate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn chainstate() -> Arc<Chainstate> {
    let stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.track_coin_stats((*stats).clone());
    let mut chainstate = handles(Network::Regtest, Arc::new(utxo));
    chainstate.coin_stats = stats;
    Arc::new(chainstate)
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
        {
            let loaded = self.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &self.pinned)
        }?;
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
        manager.activate_pinned_snapshot(forged.set, forged.tip_hash, &fixture.pinned),
        Err(AssumeUtxoError::Utxo(
            bitcoin_rs_utxo::UtxoError::SnapshotCoinHeightOutOfRange { .. }
        ))
    ));
    assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
    assert!(fixture.active.applied_tip_snapshot().is_none());
    Ok(())
}

// Core 31.1 ActivateSnapshot rejects an invalid base and any base outside
// m_best_header's ancestry before making the snapshot chainstate active.
#[test]
fn snapshot_rejects_invalid_base_and_descendant_before_persistence() -> TestResult {
    for invalid_height in [2, 1] {
        let fixture = Fixture::new()?;
        {
            let mut tree = fixture.active.block_tree.write();
            let invalid = tree
                .lookup(fixture.blocks[invalid_height].block_hash().0)
                .ok_or("invalidated header missing")?;
            tree.invalidate_subtree(invalid)?;
            let base = tree
                .node_by_hash(fixture.pinned.block_hash)
                .ok_or("snapshot base missing")?;
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
            |_, _, _| {
                persisted.store(true, Ordering::Relaxed);
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(AssumeUtxoError::Apply(ApplyError::Chain(
                bitcoin_rs_chain::ChainError::KnownInvalidHeader { hash }
            ))) if hash == fixture.pinned.block_hash
        ));
        assert!(!persisted.load(Ordering::Relaxed));
        assert!(fixture.head.load()?.is_none());
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

fn competing_snapshot_headers() -> Result<Vec<Block>, Box<dyn std::error::Error>> {
    let mut parent = Network::Regtest.genesis_block().block_hash();
    let mut fork = Vec::new();
    for height in 1..=3 {
        let block = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at_time(
            parent,
            bitcoin_rs_chain::regtest_fixture::genesis_time() + 100 + height,
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
    let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active.clone(), None)?;
    // Authenticate the candidate before changing header selection. Invoke the
    // final installation owner directly so a manager-only precheck cannot
    // replace its guarded best-header admission rule.
    let loaded = fixture.load()?;
    assert_eq!(
        (loaded.tip_hash, loaded.height),
        (fixture.pinned.block_hash, fixture.pinned.height)
    );
    let (commitment, verified_stats) = loaded.set.with_stable_view(|view| {
        Ok::<_, bitcoin_rs_utxo::UtxoError>((
            view.hash_serialized_3_at_height(fixture.pinned.height)?,
            bitcoin_rs_utxo::stats::scan_coin_stats(view, fixture.pinned.height, true)?,
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
        let tip = tree.tip().ok_or("best header missing")?;
        let base = tree
            .node_by_hash(fixture.pinned.block_hash)
            .ok_or("snapshot base missing")?;
        assert!(tip.chainwork > base.chainwork);
        assert_eq!(tip.hash, fork[2].block_hash().0);
        root
    };
    let before_stats = fixture.active.coin_stats.snapshot();
    let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
    let persisted = AtomicBool::new(false);
    let result =
        fixture
            .active
            .install_snapshot(loaded.set, verified_stats, &fixture.pinned, |_, _, _| {
                persisted.store(true, Ordering::Relaxed);
                Ok(())
            });
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
    assert!(fixture.head.load()?.is_none());
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
    assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
    assert_eq!(
        fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
        before_coins
    );
    assert!(!fixture.active.is_closed_for_recovery());

    // Invalidating the competing branch restores the pinned ancestry; an
    // operational refusal must not poison the next legitimate activation.
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
            .ok_or("snapshot tip missing")?
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
    // Tree-level work-order fixture: this harder declared target makes a
    // shorter branch win. It does not claim regtest difficulty admission.
    harder.header.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x2000_ffff);
    harder.header.nonce = 0;
    bitcoin_rs_chain::regtest_fixture::mine_block_to_declared_target(&mut harder)?;
    {
        let mut tree = fixture.active.block_tree.write();
        tree.insert_header(harder.header, NodeStatus::HeaderValid)?;
        let tip = tree.tip().ok_or("best header missing")?;
        let base = tree
            .node_by_hash(fixture.pinned.block_hash)
            .ok_or("base missing")?;
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
        |_, _, _| {
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
    assert!(fixture.head.load()?.is_none());
    assert!(fixture.active.applied_tip_snapshot().is_none());
    assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
    assert!(!fixture.active.is_closed_for_recovery());
    Ok(())
}

#[test]
fn snapshot_accepts_base_below_best_header_tip_on_same_ancestry() -> TestResult {
    let fixture = Fixture::new()?;
    let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
        fixture.blocks[2].block_hash(),
        3,
    )?;
    fixture
        .active
        .block_tree
        .write()
        .insert_header(child.header, NodeStatus::HeaderValid)?;
    let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active.clone(), None)?;
    fixture.activate(&manager)?;
    assert_eq!(
        fixture
            .active
            .applied_tip_snapshot()
            .ok_or("snapshot tip missing")?
            .hash,
        fixture.pinned.block_hash
    );
    assert_eq!(
        fixture
            .active
            .block_tree
            .read()
            .tip()
            .ok_or("best header missing")?
            .hash,
        child.block_hash().0
    );
    Ok(())
}

// These fixtures exercise the shared installation owner with unequal-work
// forks. Coin contents come from ordinarily applied regtest blocks; changing
// only the declared header target does not change their coinbase transactions.
// Every replacement header meets its declared target, but this is not a claim
// that regtest's fixed contextual difficulty would admit those replacements.
fn snapshot_work_branch(
    height: u32,
    bits: u32,
    time_offset: u32,
) -> Result<(Vec<Block>, SnapshotLoad, CoinStats), Box<dyn std::error::Error>> {
    let source = chainstate();
    let mut blocks = vec![Network::Regtest.genesis_block()];
    for next_height in 1..=height {
        blocks.push(
            bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at_time(
                blocks.last().ok_or("branch parent missing")?.block_hash(),
                bitcoin_rs_chain::regtest_fixture::genesis_time() + time_offset + next_height,
                next_height,
            )?,
        );
    }
    for block in &blocks {
        source.begin_transition()?.connect(block, None)?;
    }
    for index in 1..blocks.len() {
        blocks[index].header.prev_blockhash = blocks[index - 1].block_hash();
        blocks[index].header.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(bits);
        blocks[index].header.nonce = 0;
        bitcoin_rs_chain::regtest_fixture::mine_block_to_declared_target(&mut blocks[index])?;
    }
    let tip = blocks.last().ok_or("branch tip missing")?.block_hash().0;
    let mut encoded = Vec::new();
    write_snapshot_observed(&source.utxo, &tip, height, &mut encoded, ())?;
    let loaded = read_snapshot_strict_v4(&mut Cursor::new(encoded))?;
    Ok((blocks, loaded, source.coin_stats.snapshot()))
}

fn snapshot_work_fixture(
    snapshot_height: u32,
    snapshot_bits: u32,
    applied_height: u32,
    applied_bits: u32,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (blocks, snapshot, stats) = snapshot_work_branch(snapshot_height, snapshot_bits, 0)?;
    let (applied_blocks, mut applied, applied_stats) =
        snapshot_work_branch(applied_height, applied_bits, 100)?;
    let mut tree = bitcoin_rs_chain::BlockTree::new();
    for block in blocks.iter().chain(applied_blocks.iter().skip(1)) {
        tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    }
    let applied_id = tree
        .lookup(applied.tip_hash)
        .ok_or("applied header missing")?;
    tree.restore_chain_tx_count(
        applied_id,
        bitcoin_rs_chain::ChainTxCount::established(applied_stats.tx_count),
    )?;
    let applied_node = tree.node(applied_id)?;
    let applied_tip = bitcoin_rs_chain::TipSnapshot {
        tip_id: applied_id,
        height: applied_node.height,
        chainwork: applied_node.chainwork,
        hash: applied_node.hash,
        chain_tx_count: applied_node.chain_tx_count,
    };
    let coin_stats = Arc::new(CoinStatsListener::new(applied_stats));
    applied.set.track_coin_stats((*coin_stats).clone());
    let mut active = Chainstate::new(
        Network::Regtest,
        Arc::new(ArcSwapOption::new(tree.tip())),
        Arc::new(ArcSwapOption::new(Some(Arc::new(applied_tip.clone())))),
        Arc::new(RwLock::new(tree)),
        Arc::new(applied.set),
        coin_stats,
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    );
    let head = Arc::new(FaultHead::default());
    head.commit(
        None,
        &DurableHead {
            assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 17,
            height: applied_tip.height,
            tip: applied_tip.hash,
            chain_tx_count: applied_tip.chain_tx_count.to_wire(),
            body_extent: None,
            undo_extent: None,
        },
        &CommitRecords::default(),
    )?;
    active.durable_head = head.clone();
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
        .ok_or("applied tip missing")?;
    let before_head = fixture.active.durable_head.load()?;
    let before_stats = fixture.active.coin_stats.snapshot();
    let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
    let mut child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
        fixture.blocks[2].block_hash(),
        3,
    )?;
    child.header.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x1f7f_ffff);
    child.header.nonce = 0;
    bitcoin_rs_chain::regtest_fixture::mine_block_to_declared_target(&mut child)?;
    {
        let mut tree = fixture.active.block_tree.write();
        tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let best = tree.tip().ok_or("best header missing")?;
        let base_id = tree
            .lookup(fixture.pinned.block_hash)
            .ok_or("base missing")?;
        let base = tree.node(base_id)?;
        assert!(base.height > before.height);
        assert!(base.chainwork < before.chainwork);
        assert!(best.chainwork > before.chainwork);
        assert_eq!(
            tree.node_at_height_from(best.tip_id, base.height),
            Some(base_id)
        );
    }
    let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active.clone(), None)?;
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
    let before = fixture
        .active
        .applied_tip_snapshot()
        .ok_or("applied tip missing")?;
    let before_head = fixture
        .active
        .durable_head
        .load()?
        .ok_or("durable head missing")?;
    {
        let tree = fixture.active.block_tree.read();
        let base = tree
            .node_by_hash(fixture.pinned.block_hash)
            .ok_or("base missing")?;
        assert!(base.height < before.height);
        assert!(base.chainwork > before.chainwork);
        assert_eq!(tree.tip().ok_or("best header missing")?.hash, base.hash);
    }
    let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active.clone(), None)?;
    fixture.activate(&manager)?;
    let applied = fixture
        .active
        .applied_tip_snapshot()
        .ok_or("snapshot tip missing")?;
    let head = fixture
        .active
        .durable_head
        .load()?
        .ok_or("snapshot head missing")?;
    assert_eq!(head.commit_id, before_head.commit_id + 1);
    assert_eq!(head.height, fixture.pinned.height);
    assert_eq!(head.tip, fixture.pinned.block_hash);
    assert_eq!(head.chain_tx_count, fixture.pinned.chain_tx_count);
    assert_eq!((applied.height, applied.hash), (head.height, head.tip));
    assert!(applied.chainwork > before.chainwork);
    assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
    assert_eq!(
        fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
        fixture.pinned.hash_serialized
    );
    assert!(fixture.active.role().is_assumed_active());
    Ok(())
}

#[test]
fn snapshot_refuses_work_comparison_when_durable_and_applied_tips_differ() -> TestResult {
    // Isolate identity, height and count mismatches, including equal hashes.
    for (change_hash, height_delta, count_delta) in [(true, 0, 0), (false, 1, 0), (false, 0, 1)] {
        let fixture = snapshot_work_fixture(2, 0x207f_ffff, 1, 0x207f_ffff)?;
        let applied = fixture
            .active
            .applied_tip_snapshot()
            .ok_or("applied tip missing")?;
        let prior = fixture
            .active
            .durable_head
            .load()?
            .ok_or("durable head missing")?;
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
            .head
            .commit(Some(&prior), &unsettled, &CommitRecords::default())?;
        let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active.clone(), None)?;
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
        Some(dir.path().to_path_buf()),
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
        {
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
        },
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
    let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
        Network::Regtest,
        fixture.active.clone(),
        Some(dir.path().to_path_buf()),
        1,
    )?;
    fixture.activate(&manager)?;
    for block in &fixture.blocks[..2] {
        manager.step_historical(block, None)?;
    }
    fixture.head.fail_terminal.store(true, Ordering::Release);
    let root = dir
        .path()
        .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
    let checkpoint_entries = std::fs::read_dir(&root)?.count();
    assert!(checkpoint_entries > 1);
    assert!(matches!(
        manager.step_historical(&fixture.blocks[2], None),
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

#[test]
fn snapshot_persistence_does_not_block_existing_progress_queries() -> TestResult {
    let fixture = Fixture::new()?;
    let genesis = Network::Regtest.genesis_block();
    fixture
        .active
        .lock_transition()?
        .into_transition()
        .connect(&genesis, None)?;
    let before = fixture
        .active
        .applied_tip_snapshot()
        .ok_or("genesis missing")?;
    let reader = fixture.active.chain_progress_reader();
    let loaded = fixture.load()?;
    let mut observed = None;
    let result = std::thread::scope(|scope| {
        fixture.active.install_snapshot(
            loaded.set,
            fixture.stats.clone(),
            &fixture.pinned,
            |_, _, _| {
                let (sent, received) = std::sync::mpsc::sync_channel(1);
                scope.spawn(move || {
                    let progress =
                        reader.progress(Network::Regtest, bitcoin_rs_primitives::unix_time_secs());
                    let _ = sent.send(progress);
                });
                // A storage callback may wait on slow I/O while public readers
                // continue to describe the previously committed chainstate.
                observed = received
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .ok();
                Err(AssumeUtxoError::Archive(anyhow::anyhow!(
                    "simulated persistence refusal"
                )))
            },
        )
    });
    assert!(result.is_err());
    let progress = observed.ok_or("progress query blocked behind snapshot persistence")?;
    assert_eq!(progress.blocks, before.height);
    assert_eq!(progress.best_block_hash, before.hash);
    assert_eq!(
        fixture
            .active
            .applied_tip_snapshot()
            .ok_or("prior tip lost")?
            .hash,
        before.hash
    );
    Ok(())
}

#[test]
fn lifecycle_report_refuses_contention_without_waiting_for_the_transition() -> TestResult {
    let fixture = Fixture::new()?;
    let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active, None)?;
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
    let report = observed.map_err(|_| "report waited for the lifecycle owner")??;
    assert!(
        report.is_none(),
        "busy lifecycle must not report fabricated roles"
    );
    let report = manager
        .try_chainstates_report()?
        .ok_or("lifecycle remained busy after release")?;
    assert_eq!(report.lifecycle, manager.chainstates_summary()?);
    Ok(())
}

#[test]
fn lifecycle_progress_omits_missing_and_unauthenticated_counts() -> TestResult {
    let fixture = Fixture::new()?;
    let manager = AssumeUtxoManager::open(Network::Regtest, fixture.active.clone(), None)?;
    assert_eq!(
        manager
            .try_chainstates_report()?
            .ok_or("uncontended lifecycle is busy")?
            .active_verification_progress,
        None
    );
    assert_eq!(known_progress(None, 0.5), None);
    let tip = fixture
        .active
        .block_tree
        .read()
        .tip()
        .ok_or("header tip missing")?;
    let mut tip = (*tip).clone();
    tip.chain_tx_count = bitcoin_rs_chain::ChainTxCount::UNKNOWN;
    assert_eq!(known_progress(Some(&tip), 0.5), None);
    tip.chain_tx_count = bitcoin_rs_chain::ChainTxCount::established(3);
    assert_eq!(known_progress(Some(&tip), 0.5), Some(0.5));
    Ok(())
}
