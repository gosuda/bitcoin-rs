//! Ancestor package policy limit coverage.
// A failed pool or fixture invariant is a test failure, and panicking reports
// it with the offending call site. `expect` is deliberate.
#![allow(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolError, MempoolLimits, PolicyError};

#[test]
fn chain_of_twenty_six_unconfirmed_transactions_rejects_twenty_sixth() -> Result<(), Box<dyn Error>>
{
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut previous = outpoint(1, 0);

    for height in 0_u32..25 {
        let label = u8::try_from(height + 2)?;
        let tx = chained_tx(label, previous);
        previous = OutPoint::new(tx.compute_txid(), 0);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx),
            4_000,
            4_000,
            u64::from(height),
            1,
        ))?;
    }

    let rejected = chained_tx(40, previous);
    let err = pool
        .insert_entry(MempoolEntry::new(Arc::new(rejected), 4_000, 4_000, 26, 1))
        .err();

    assert_eq!(
        err,
        Some(MempoolError::Policy(PolicyError::TooManyAncestors))
    );
    assert_eq!(pool.len(), 25);

    Ok(())
}

#[test]
fn rpc_graph_facts_are_transitive_and_aggregates_are_inclusive() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());

    let root = chained_tx(50, outpoint(49, 0));
    let root_txid = root.compute_txid();
    let root_id = pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 1_000, 1, 1))?;

    let child = chained_tx(51, OutPoint::new(root_txid, 0));
    let child_txid = child.compute_txid();
    let child_id = pool.insert_entry(MempoolEntry::new(Arc::new(child), 200, 3_000, 2, 1))?;

    let grandchild = chained_tx(52, OutPoint::new(child_txid, 0));
    let grandchild_txid = grandchild.compute_txid();
    let grandchild_id =
        pool.insert_entry(MempoolEntry::new(Arc::new(grandchild), 300, 6_000, 3, 1))?;

    assert_eq!(
        pool.ancestor_ids_for_entry(grandchild_id),
        vec![root_id, child_id]
    );
    assert_eq!(
        pool.descendant_ids_for_entry(root_id),
        vec![child_id, grandchild_id]
    );
    assert_eq!(pool.ancestor_count_inclusive(grandchild_id), 3);
    assert_eq!(pool.descendant_count_inclusive(root_id), 3);
    assert_eq!(pool.spender_txids(root_id), vec![child_txid]);
    assert_eq!(pool.spender_txids(child_id), vec![grandchild_txid]);

    let root_entry = pool.entry(root_id).ok_or("missing root entry")?;
    assert_eq!(
        (root_entry.descendant_size, root_entry.descendant_fee),
        (600, 10_000)
    );
    let grandchild_entry = pool
        .entry(grandchild_id)
        .ok_or("missing grandchild entry")?;
    assert_eq!(
        (
            grandchild_entry.ancestor_size,
            grandchild_entry.ancestor_fee
        ),
        (600, 10_000)
    );

    Ok(())
}

#[test]
fn descendant_count_limit_rejects_the_twenty_sixth_member() -> Result<(), Box<dyn Error>> {
    // Parent plus 24 children = 25 inclusive. The next child would make 26.
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent_tx = multi_output_tx(70, 25);
    let parent_txid = parent_tx.compute_txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent_tx), 100, 1_000, 1, 1))?;

    for vout in 0_u32..24 {
        let child = chained_tx(u8::try_from(vout + 71)?, OutPoint::new(parent_txid, vout));
        pool.insert_entry(MempoolEntry::new(
            Arc::new(child),
            100,
            1_000,
            u64::from(vout) + 2,
            1,
        ))?;
    }
    assert_eq!(pool.len(), 25);

    let rejected = chained_tx(100, OutPoint::new(parent_txid, 24));
    let err = pool
        .insert_entry(MempoolEntry::new(Arc::new(rejected), 100, 1_000, 30, 1))
        .err();
    assert_eq!(
        err,
        Some(MempoolError::Policy(PolicyError::TooManyDescendants))
    );
    Ok(())
}

#[test]
fn raw_pool_view_and_entry_metadata_facts() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let before = pool.sequence_number();
    let tx = chained_tx(80, outpoint(79, 0));
    let txid = tx.compute_txid();
    let entry = MempoolEntry::new(Arc::new(tx), 150, 3_000, 9, 42).with_sigop_cost(17);
    assert_eq!(entry.sigop_cost, 17);
    assert_eq!(entry.bip141_vsize, u32::try_from(entry.tx.vsize())?);
    assert_eq!(entry.weight, entry.tx.weight().to_wu());
    assert_eq!(entry.height, 42);
    assert_eq!(entry.time, 9);
    pool.insert_entry(entry)?;

    assert!(pool.sequence_number() > before);
    assert_eq!(pool.iter_txids(), vec![txid]);
    let stats = pool.stats();
    assert_eq!((stats.txs, stats.bytes, stats.total_fee), (1, 150, 3_000));
    let loaded = pool.entry_by_txid(&txid).ok_or("missing entry")?;
    assert_eq!(loaded.sigop_cost, 17);
    assert_eq!(loaded.fee, 3_000);
    Ok(())
}

#[test]
fn fee_estimate_access_reuses_pool_owned_estimator() -> Result<(), Box<dyn Error>> {
    let mut pool = Mempool::new(MempoolLimits::default());
    assert_eq!(pool.estimate_fee_rate(2), None);

    let first = chained_tx(81, outpoint(80, 0));
    let first_txid = first.compute_txid();
    let second = chained_tx(82, outpoint(81, 0));
    let second_txid = second.compute_txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(first.clone()),
        100,
        10_000,
        1,
        7,
    ))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(second.clone()),
        100,
        10_000,
        1,
        7,
    ))?;
    assert_eq!(pool.estimate_fee_rate(2), None);

    pool.remove_for_block(&[&first, &second], &[first_txid, second_txid], 8);
    assert!(pool.estimate_fee_rate(2).is_some());
    Ok(())
}

fn multi_output_tx(label: u8, outputs: u32) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label, 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: (0..outputs)
            .map(|vout| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x51,
                    label,
                    u8::try_from(vout).expect("fixture vout fits u8"),
                ]),
            })
            .collect(),
    }
}

fn chained_tx(label: u8, previous_output: OutPoint) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid::from_byte_array(bytes), vout)
}
