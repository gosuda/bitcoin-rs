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
use bitcoin_rs_primitives::{BlockPayload, Hash256, Network, Witness};
use bitcoin_rs_storage::{CommitRecords, DurableHead};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::Mutex;

use crate::test_fixtures::{StagedFire, handles, seed_genesis, staging_recorder};

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
    let first_payload = BlockPayload::from_local(first);
    let second_payload = BlockPayload::from_local(second);
    let third_payload = BlockPayload::from_local(third);
    let payloads = [&first_payload, &second_payload, &third_payload];

    let transition = handles.begin_transition()?;
    let outcomes = transition.connect_window(&payloads)?;

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
    let first_payload = BlockPayload::from_local(first);
    let second_payload = BlockPayload::from_local(second);
    let third_payload = BlockPayload::from_local(third);
    let payloads = [&first_payload, &second_payload, &third_payload];

    let fires: Arc<Mutex<Vec<StagedFire>>> = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_tip_staged(staging_recorder(&handles, &fires))
        .map_err(|_| "the staged-tip hook installs once")?;

    let outcomes = handles.apply_window(&payloads)?;
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

/// Corrupted delivered bytes fail payload construction before any window runs.
///
/// A stream that no longer decodes (truncated tail, trailing garbage) never reaches
/// counting: `from_raw` rejects it at construction, so nothing stages and the applied tip
/// stays put. The coinbase-only fixtures carry no witness section, so the corruption
/// targets the stream shape itself; a witness change that still decodes is a different
/// exact payload, rejected downstream and never passed on count alone.
#[test]
fn corrupted_window_bytes_fail_payload_construction() -> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    seed_genesis(&handles)?;
    let payload = BlockPayload::from_local(mined_child(genesis.block_hash(), 1)?);
    let raw = payload.bytes().to_vec();

    let mut truncated = raw.clone();
    truncated.pop();
    assert!(
        BlockPayload::from_raw(bytes::Bytes::from(truncated)).is_err(),
        "a truncated stream must fail construction, before any count is consulted"
    );

    let mut trailed = raw;
    trailed.push(0x00);
    assert!(
        BlockPayload::from_raw(bytes::Bytes::from(trailed)).is_err(),
        "trailing bytes must fail construction, before any count is consulted"
    );

    let applied = handles.applied_tip_snapshot().ok_or("seeded tip")?;
    assert_eq!(
        applied.hash,
        Hash256::from(genesis.block_hash()),
        "rejected construction stages nothing"
    );
    Ok(())
}

/// A witness-only mutation fails payload construction when it breaks the stream.
///
/// Setting a witness stack on the coinbase input leaves the txid unchanged (witness data
/// is outside the txid), so the only difference between the two encodings is witness
/// bytes. Raising the witness item-count byte then claims a second item the stream cannot
/// back: past the first item only the four lock-time bytes remain, while the decoder
/// still needs an item length, its data, and the lock time itself. The stream always
/// exhausts first, so `from_raw` rejects it at construction and no count is consulted.
/// (A witness change that still decodes is a different exact payload, rejected
/// downstream and covered in `connect/tests.rs`.)
#[test]
fn witness_only_mutation_fails_payload_construction() -> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    seed_genesis(&handles)?;
    let mut changed = mined_child(genesis.block_hash(), 1)?;
    let txid = changed.txs[0].txid();
    changed.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![0u8; 32]]);
    assert_eq!(
        changed.txs[0].txid(),
        txid,
        "witness data stays outside the txid"
    );

    let raw = BlockPayload::from_local(changed).bytes().to_vec();
    // Tail layout: item-count (1) + item length (1) + item (32) + lock time (4).
    let count_at = raw.len() - 38;
    assert_eq!(raw[count_at], 0x01, "witness item-count site");
    let mut broken = raw;
    broken[count_at] = 0x02;
    assert!(
        BlockPayload::from_raw(bytes::Bytes::from(broken)).is_err(),
        "a witness count the stream cannot back must fail construction"
    );

    let applied = handles.applied_tip_snapshot().ok_or("seeded tip")?;
    assert_eq!(
        applied.hash,
        Hash256::from(genesis.block_hash()),
        "rejected construction stages nothing"
    );
    Ok(())
}
