use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, compact_is_met_by, current_unix_seconds};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::{
    CommitRecords, DurableHead, DurableHeadStore, InMemoryDurableHeadStore, StorageError,
};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use parking_lot::RwLock;

use crate::test_fixtures::MemoryBodies;
use crate::{ApplyError, Chainstate};

fn restored_chainstate() -> Result<(Chainstate, Block), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let handles = Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        Arc::new(UtxoSet::new()),
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    );
    let genesis_tip = crate::connect::applied_header_tip(
        &handles,
        Hash256::from(genesis.block_hash()),
        &genesis,
        0,
    )?;
    handles
        .applied_tip
        .store(Some(Arc::new(genesis_tip.clone())));
    handles.chain_tx_count.store(1, Ordering::Release);

    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, 1, 0]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let mut leaves = vec![*tx.txid().as_bytes()];
    let merkle = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
        .ok_or("coinbase merkle root missing")?;
    let mut child = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(genesis_tip.hash),
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: genesis.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![tx],
    };
    while !compact_is_met_by(child.header.bits, child.header.compute_hash().0) {
        child.header.nonce = child
            .header
            .nonce
            .checked_add(1)
            .ok_or("test nonce exhausted")?;
    }
    Ok((handles, child))
}

fn install_head(
    handles: &mut Chainstate,
    child: &Block,
    bodies: Arc<MemoryBodies>,
) -> Result<DurableHead, StorageError> {
    let hash = Hash256::from(child.block_hash());
    let head = DurableHead {
        commit_id: 7,
        height: 1,
        tip: hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(handles, head, bodies)?;
    Ok(head)
}

fn install_arbitrary_head(
    handles: &mut Chainstate,
    head: DurableHead,
    bodies: Arc<MemoryBodies>,
) -> Result<(), StorageError> {
    let durable = Arc::new(InMemoryDurableHeadStore::new());
    durable.commit(None, &head, &CommitRecords::default())?;
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
    assert_eq!(handles.chain_tx_count.load(Ordering::Acquire), 2);
    assert_eq!(handles.durable_head.load()?, Some(head));
    assert_eq!(
        handles.durable_head.load()?.map(|head| head.commit_id),
        Some(7),
        "replay must consume the durable receipt rather than creating a new one"
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
    while !compact_is_met_by(child.header.bits, child.header.compute_hash().0) {
        child.header.nonce = child
            .header
            .nonce
            .checked_add(1)
            .ok_or("test nonce exhausted")?;
    }
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
    handles.chain_tx_count.store(0, Ordering::Release);
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
    assert_eq!(handles.chain_tx_count.load(Ordering::Acquire), 2);
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
    handles.chain_tx_count.store(0, Ordering::Release);
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
        commit_id: 3,
        height: restored.height,
        tip: restored.hash,
        chain_tx_count: 1,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(&mut handles, head, Arc::new(MemoryBodies::default()))?;

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
        commit_id: 4,
        height: restored.height,
        tip: Hash256::from(child.block_hash()),
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, head, Some(&restored)) else {
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

#[test]
fn durable_gap_wider_than_one_group_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (handles, child) = restored_chainstate()?;
    let restored = handles
        .applied_tip
        .load_full()
        .ok_or("restored tip missing")?;
    let head_height = u32::try_from(super::REPLAY_GAP_BLOCK_LIMIT)?.saturating_add(1);
    let head = DurableHead {
        commit_id: 5,
        height: head_height,
        tip: Hash256::from(child.block_hash()),
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, head, Some(&restored)) else {
        panic!("gap beyond the commit-group bound must fail");
    };
    assert!(matches!(
        error,
        ApplyError::DurableHeadGapUnrecoverable {
            reason: "the gap is wider than one commit group",
            ..
        }
    ));
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
        commit_id: 6,
        height: 1,
        tip: claimed,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, head, Some(&restored)) else {
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
        commit_id: 7,
        height: 1,
        tip: child_hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };

    let Err(error) = super::replay_committed_gap(&handles, head, Some(&wrong_restored)) else {
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
        commit_id: 9,
        height: 1,
        tip: child_hash,
        chain_tx_count: 2,
        body_extent: None,
        undo_extent: None,
    };
    install_arbitrary_head(&mut handles, head, bodies)?;

    let Err(error) = super::replay_committed_gap(&handles, head, Some(&restored)) else {
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
