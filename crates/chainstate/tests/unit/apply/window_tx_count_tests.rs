//! Grouped-window publication contract for the cumulative chain tx count.
//!
//! A staged block's outcome tip carries that block's own cumulative count —
//! never the group-final count unless the block is the final one — while one
//! durable batch certifies only the final count of the committed prefix
//! (`docs/contracts/recovery.md`, `RCV-02`; the `WindowGroup` docs in
//! `src/window.rs` state the same rule for the staged tips).
//!
//! PRE: a regtest genesis applied with count 1 and committed as the
//! durable head — the state a header-first sync that already applied
//! genesis leaves before a body window — plus three one-transaction
//! children whose headers are already in the tree.
//! POST: one `ChainTransition::connect_window` call drains one
//! outcome per block in order; outcome `n` carries `1 + n` transactions;
//! every prefix published (the event sequence advanced once per block);
//! the applied cell and the durable head name the final count.

use std::sync::Arc;

use bitcoin_rs_chain::ChainTxCount;
use bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at as mined_child;
use bitcoin_rs_primitives::{Hash256, Network, consensus_bytes};
use bitcoin_rs_storage::{CommitRecords, DurableHead};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::Mutex;

use crate::test_fixtures::{handles, seed_genesis};

#[test]
fn a_grouped_window_publishes_each_blocks_own_prefix_count()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    seed_genesis(&handles)?;
    // A real header-first sync that applied genesis also committed its
    // durable head; seed it so the window's lineage fence actually runs.
    handles.durable_head.commit(
        None,
        &DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: Hash256::from(genesis.block_hash()),
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        },
        &CommitRecords::default(),
    )?;

    let first = mined_child(genesis.block_hash(), 1)?;
    let second = mined_child(first.block_hash(), 2)?;
    let third = mined_child(second.block_hash(), 3)?;
    {
        let mut tree = handles.block_tree.write();
        bitcoin_rs_chain::accept_headers(
            &mut tree,
            &[first.header, second.header, third.header],
            Network::Regtest,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        )?;
    }
    let blocks = [&first, &second, &third];
    let serialized: Vec<bytes::Bytes> = blocks
        .iter()
        .map(|block| bytes::Bytes::from(consensus_bytes(*block)))
        .collect();

    let transition = handles.begin_transition()?;
    let outcomes = transition.connect_window(&blocks, &serialized)?;

    assert_eq!(outcomes.len(), 3, "one drained outcome per staged block");
    let prefix_counts = [
        ChainTxCount::established(2),
        ChainTxCount::established(3),
        ChainTxCount::established(4),
    ];
    for (outcome, expected) in outcomes.iter().zip(prefix_counts) {
        assert_eq!(
            outcome.tip.chain_tx_count, expected,
            "each staged tip carries its own cumulative count, not the group's final one"
        );
    }

    // Publication happened per block, in order, not once per group: the
    // event sequence advanced once per staged block. Publishing only the
    // final tip would leave the sequence at 1.
    let events = handles.chain_events.snapshot();
    assert_eq!(events.sequence, 3);
    assert_eq!(events.tip_height, 3);
    assert_eq!(events.tip_hash, outcomes[2].hash);

    let applied = handles.applied_tip.load_full();
    assert_eq!(
        applied.as_deref(),
        Some(&outcomes[2].tip),
        "the cell names the last published tip"
    );

    let head = handles
        .durable_head
        .load()?
        .ok_or("the group's one batch wrote the durable head")?;
    assert_eq!(head.height, 3);
    assert_eq!(head.tip, outcomes[2].hash);
    assert_eq!(
        head.chain_tx_count, 4,
        "the head certifies the final group count"
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.commit_id == head.commit_id),
        "one receipt certifies the whole committed prefix"
    );
    Ok(())
}

/// What the staged-tip hook observed: the staged tip it was handed, the
/// borrowed block's identity, and the published tip still in the cell.
/// Only hashes and heights cross the hook boundary — never a block clone.
struct StagedFire {
    staged_hash: Hash256,
    staged_height: u32,
    block_hash: Hash256,
    published: Option<(Hash256, u32)>,
}

fn staging_recorder(
    chain: &crate::Chainstate,
    fires: &Arc<Mutex<Vec<StagedFire>>>,
) -> crate::TipStagedHook {
    let fires = Arc::clone(fires);
    let chain = chain.clone();
    Arc::new(move |staged, block| {
        // `applied_tip_snapshot` is a lock-free read; the hook takes no
        // domain write lock and never reenters chainstate mutation.
        let published = chain
            .applied_tip_snapshot()
            .map(|tip| (tip.hash, tip.height));
        fires.lock().push(StagedFire {
            staged_hash: staged.hash,
            staged_height: staged.height,
            block_hash: Hash256::from(block.block_hash()),
            published,
        });
    })
}

/// A fully successful group hands exactly its newest block to the staged-tip
/// hook, before the group's durable sync: the published tip observed inside
/// the hook is still the pre-window tip, so no consumer could have seen the
/// staged tip early. A hook that fired per staged block, or after publish,
/// fails this test.
#[test]
fn a_grouped_window_stages_only_its_newest_block_before_the_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    seed_genesis(&handles)?;
    handles.durable_head.commit(
        None,
        &DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: genesis_hash,
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        },
        &CommitRecords::default(),
    )?;

    let first = mined_child(genesis.block_hash(), 1)?;
    let second = mined_child(first.block_hash(), 2)?;
    let third = mined_child(second.block_hash(), 3)?;
    let third_hash = Hash256::from(third.block_hash());
    {
        let mut tree = handles.block_tree.write();
        bitcoin_rs_chain::accept_headers(
            &mut tree,
            &[first.header, second.header, third.header],
            Network::Regtest,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        )?;
    }
    let blocks = [&first, &second, &third];
    let serialized: Vec<bytes::Bytes> = blocks
        .iter()
        .map(|block| bytes::Bytes::from(consensus_bytes(*block)))
        .collect();

    let fires: Arc<Mutex<Vec<StagedFire>>> = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_tip_staged(staging_recorder(&handles, &fires))
        .map_err(|_| "the staged-tip hook installs once")?;

    let outcomes = handles.apply_window(&blocks, &serialized)?;
    assert_eq!(outcomes.len(), 3, "one drained outcome per staged block");

    let fires = fires.lock();
    assert_eq!(fires.len(), 1, "one group commits, so one staging handoff");
    assert_eq!(
        fires[0].staged_hash, third_hash,
        "the handoff names the newest staged block, not an ancestor"
    );
    assert_eq!(fires[0].staged_height, 3);
    assert_eq!(
        fires[0].block_hash, third_hash,
        "the borrowed body is the caller's newest block"
    );
    assert_eq!(
        fires[0].published,
        Some((genesis_hash, 0)),
        "the applied tip is still the pre-window tip at fire time: \
         the staged tip publishes only with the group's durable receipt"
    );

    let applied = handles
        .applied_tip_snapshot()
        .ok_or("the group must publish an applied tip")?;
    assert_eq!(applied.hash, third_hash);
    Ok(())
}
