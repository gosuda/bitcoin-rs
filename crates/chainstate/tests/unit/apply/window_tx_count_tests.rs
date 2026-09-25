//! Grouped-window publication contract for the cumulative chain tx count.
//!
//! A staged block's outcome tip carries that block's own cumulative count —
//! never the group-final count unless the block is the final one — while one
//! durable batch certifies only the final count of the committed prefix
//! (`docs/contracts/recovery.md`, `RCV-02`; the `WindowGroup` docs in
//! `src/window.rs` state the same rule for the staged tips).
//!
//! PRE: a regtest genesis applied with count 1 and three one-transaction
//! children whose headers are already in the tree, exactly the state
//! header-first sync leaves before a body window.
//! POST: one `ChainTransition::connect_window` call drains one
//! outcome per block in order; outcome `n` carries `1 + n` transactions;
//! every prefix published (the event sequence advanced once per block);
//! the applied cell and the durable head name the final count.

use std::sync::Arc;

use bitcoin_rs_chain::ChainTxCount;
use bitcoin_rs_primitives::{Network, consensus_bytes};
use bitcoin_rs_utxo::UtxoSet;

use super::persistence_tests::{handles, mined_child, seed_genesis};

#[test]
fn a_grouped_window_publishes_each_blocks_own_prefix_count()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    seed_genesis(&handles)?;

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
