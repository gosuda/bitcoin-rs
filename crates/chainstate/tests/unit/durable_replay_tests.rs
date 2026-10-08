use std::sync::Arc;
use std::sync::atomic::Ordering;

use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at as mined_child;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Network, consensus_bytes};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::{
    CommitRecords, DurableHead, DurableHeadStore, InMemoryDurableHeadStore, StorageError,
};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};

use crate::test_fixtures::{MemoryBodies, handles, seed_genesis};
use crate::{ApplyError, Chainstate};

fn restored_chainstate() -> Result<(Chainstate, Block), Box<dyn std::error::Error>> {
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

#[test]
fn committed_gap_replays_to_head_without_recommitting_it() -> Result<(), Box<dyn std::error::Error>>
{
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
        .ok_or("replay did not publish an applied tip")?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    assert_eq!(
        landed.chain_tx_count,
        bitcoin_rs_chain::ChainTxCount::established(2)
    );
    assert_eq!(handles.durable_head.load()?, Some(head));
    assert_eq!(
        handles.durable_head.load()?.map(|head| head.commit_id),
        Some(7),
        "replay must consume the durable receipt rather than creating a new one"
    );
    Ok(())
}

/// Publication carries the count the durable receipt certified, never a
/// tree-side re-derivation: a replay whose derived count cannot match the
/// stored head still lands exactly on the head's facts.
#[test]
fn replay_publishes_the_receipt_certified_count() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, child) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(
        1,
        Hash256::from(child.block_hash()),
        &consensus_bytes(&child),
    )?;
    // The tree derives 1 (genesis) + 1 (the child's single transaction) = 2;
    // the stored head certified a different total before the crash.
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
        .ok_or("replay did not publish an applied tip")?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    assert_eq!(
        landed.chain_tx_count,
        bitcoin_rs_chain::ChainTxCount::established(5),
        "the published count is the receipt's, not the derivation's"
    );
    Ok(())
}

// A crash-recovery replay must not re-run the live future-drift recheck: the
// gap block passed the contextual gate at first connect and its durable head
// receipt certifies it, so an operator clock rollback beyond the future
// window after the commit must not turn the replay into a
// `TimestampTooFarAhead` refusal that strands the node on the older state at
// every boot.
#[test]
fn replay_gap_skips_the_live_future_drift_recheck() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, mut child) = restored_chainstate()?;
    // Simulate the rollback: the header time is pushed far beyond the real
    // clock plus the two-hour future window, so the real clock plays the part
    // of a clock that moved back after the block committed legally.
    child.header.time = current_unix_seconds().saturating_add(4 * 60 * 60);
    bitcoin_rs_chain::regtest_fixture::mine_header_to_declared_target(&mut child.header)?;
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
        .ok_or("replay did not publish an applied tip")?;
    assert_eq!((landed.height, landed.hash), (head.height, head.tip));
    Ok(())
}

#[test]
fn committed_gap_with_missing_body_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
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
        reason,
    } = error
    else {
        panic!("expected DurableHeadGapUnrecoverable, got {error:?}");
    };
    assert_eq!(head_tip, head.tip);
    assert_eq!(head_height, 1);
    assert_eq!(restored_tip, Some(Network::Regtest.genesis_block_hash()));
    assert_eq!(restored_height, Some(0));
    assert_eq!(reason, "a committed gap body is missing from storage");
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

#[test]
fn cold_chainstate_replays_head_chain_from_genesis() -> Result<(), Box<dyn std::error::Error>> {
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
        .ok_or("cold replay did not publish an applied tip")?;
    assert_eq!((landed.height, landed.hash), (1, head.tip));
    assert_eq!(
        landed.chain_tx_count,
        bitcoin_rs_chain::ChainTxCount::established(2)
    );
    assert_eq!(
        handles.durable_head.load()?,
        Some(head),
        "replay must consume the durable receipt rather than creating a new one"
    );
    Ok(())
}

#[test]
fn cold_chainstate_with_missing_genesis_body_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
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
            reason: "a committed gap body is missing from storage",
            ..
        }
    ));
    assert!(handles.applied_tip.load_full().is_none());
    assert_eq!(handles.durable_head.load()?, Some(head));
    Ok(())
}

#[test]
fn matching_durable_head_requires_no_replay() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, _) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or("restored tip missing")?;
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

#[test]
fn durable_head_at_or_below_restored_tip_is_not_a_replay_gap()
-> Result<(), Box<dyn std::error::Error>> {
    let (handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or("restored tip missing")?;
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
        ApplyError::DurableHeadGapUnrecoverable {
            reason: "the restored tip is not below the stored head; the state is not a publication lag",
            ..
        }
    ));
    Ok(())
}

/// A certified body chain wider than one commit group replays to the durable
/// head: recoverability is the body-identity and ancestry walk, not the gap
/// width. The replay lands on the stored head and preserves its `commit_id`
/// (`P3`).
#[test]
fn wide_authenticated_gap_replays_to_durable_head() -> Result<(), Box<dyn std::error::Error>> {
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
        .ok_or("wide replay did not publish an applied tip")?;
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
fn committed_gap_body_must_hash_to_the_head_identity() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or("restored tip missing")?;
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
        ApplyError::DurableHeadGapUnrecoverable {
            reason: "a stored body does not hash to its committed hash",
            ..
        }
    ));
    Ok(())
}

#[test]
fn committed_gap_must_descend_from_restored_tip() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or("restored tip missing")?;
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
        ApplyError::DurableHeadGapUnrecoverable {
            reason: "the head chain does not descend from the restored tip",
            ..
        }
    ));
    Ok(())
}

/// A replay failure inside the transition must close admission: the node
/// cannot serve a chain the durable head does not yet certify.
#[test]
fn committed_gap_replay_failure_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (mut handles, mut child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or("restored tip missing")?;
    // The body hashes to its own header and descends from the restored tip,
    // but its merkle root does not commit to its transactions, so the apply
    // inside the replay transition refuses.
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
        handles.shutdown_handle().load(Ordering::Acquire),
        "a failed replay must fail closed, got: {error}"
    );
    assert!(
        matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
        "admission must stay closed after a failed replay"
    );
    Ok(())
}

/// RCV-02 / JW-ORDER-1: retention relief must not turn append-gap poison into
/// a progress checkpoint or a retry. The original writer error stays intact.
#[cfg(feature = "fjall")]
#[test]
fn committed_gap_append_gap_does_not_enter_retention_relief()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_storage::chainstate_journal::{
        FULL_REVALIDATION_MARKER, JournalEmit, JournalWriter, JournalWriterError,
        shared_journal_writer,
    };

    let (mut handles, child) = restored_chainstate()?;
    let bodies = Arc::new(MemoryBodies::default());
    bodies.persist_block_body(1, child.block_hash().0, &consensus_bytes(&child))?;
    let head = install_head(&mut handles, &child, bodies)?;
    let temp = tempfile::tempdir()?;
    let store = Arc::new(bitcoin_rs_storage::FjallStore::open(
        temp.path().join("kv"),
    )?);
    let path = temp.path().join("journal");
    std::fs::create_dir(&path)?;
    let dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&path)?;
    let mut writer = JournalWriter::initialize(
        dir,
        store,
        0,
        (0, 0),
        0,
        Network::Regtest.genesis_block_hash().to_le_bytes(),
        [0; 32],
        1,
    )?;
    std::fs::write(
        path.join(FULL_REVALIDATION_MARKER),
        b"force full validation\n",
    )?;
    let marker_before = std::fs::read(path.join(FULL_REVALIDATION_MARKER))?;
    let journal_head_before = std::fs::read(path.join("head.json"))?;
    JournalEmit::mark_append_gap(&mut writer, 1);
    *handles.journal.write() = Some(shared_journal_writer(writer));

    let Err(ApplyError::JournalBackpressure(error)) = super::reconcile_at_boot(&handles) else {
        panic!("append gap must return the original journal refusal, not recovery publication");
    };
    assert!(matches!(
        *error,
        JournalWriterError::AppendGap { height: 1 }
    ));
    assert!(matches!(
        handles.begin_transition(),
        Err(ApplyError::Shutdown)
    ));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.height),
        Some(0)
    );
    assert_eq!(handles.durable_head.load()?, Some(head));
    assert_eq!(
        std::fs::read(path.join(FULL_REVALIDATION_MARKER))?,
        marker_before
    );
    assert_eq!(std::fs::read(path.join("head.json"))?, journal_head_before);
    Ok(())
}
