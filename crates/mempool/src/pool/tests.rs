use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut};

use super::*;

fn change_txids(result: &crate::mutation::MutationResult) -> Vec<Hash256> {
    result.changes.iter().map(|change| change.txid).collect()
}

#[test]
fn mutation_batch_crossing_sequence_rollover_keeps_base_and_lookups() {
    let mut pool = Mempool::new(MempoolLimits::default());
    pool.mempool_sequence = u64::MAX - 1;

    let mut changes = Vec::new();
    pool.push_change(&mut changes, txid_of([0xAA; 32]), MutationOutcome::Accepted);
    pool.push_change(&mut changes, txid_of([0xBB; 32]), MutationOutcome::Accepted);
    assert_eq!(pool.sequence_number(), 0, "assignment wraps modulo 2^64");

    let result = pool.finish_mutation(changes);
    assert_eq!(result.sequence_base, u64::MAX);
    assert_eq!(result.sequence_of(0), Some(u64::MAX));
    assert_eq!(result.sequence_of(1), Some(0));
    assert_eq!(result.sequence_of(2), None);
}

#[test]
fn pending_broadcast_index_tracks_flags_across_entry_lifecycle() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let first = Arc::new(tx(1, Vec::new()));
    let second = Arc::new(tx(2, Vec::new()));
    let assert_index = |pool: &Mempool| {
        let flags: std::collections::BTreeSet<_> = pool
            .iter_entries()
            .filter(|entry| entry.unbroadcast)
            .map(|entry| entry.wtxid)
            .collect();
        assert_eq!(pool.derived.unbroadcast, flags);
    };
    let mut entry = MempoolEntry::new(Arc::clone(&first), 100, 10_000, 1, 0, 0);
    entry.unbroadcast = true;
    pool.insert_entry(entry)?;
    pool.insert_entry(MempoolEntry::new(Arc::clone(&second), 100, 10_000, 1, 0, 0))?;
    assert_index(&pool);
    pool.set_unbroadcast(second.wtxid(), true);
    pool.set_unbroadcast(second.wtxid(), true);
    pool.set_unbroadcast(first.wtxid(), false);
    assert_index(&pool);
    pool.remove_for_block(&[second.as_ref()], &[second.txid()], 2, 1);
    assert_index(&pool);
    assert!(
        pool.derived.unbroadcast.is_empty(),
        "removal must retire the index key, not leave a tombstone"
    );
    pool.insert_entry(MempoolEntry::new(second, 100, 10_000, 1, 0, 0))?;
    assert_index(&pool);
    pool.set_unbroadcast(first.wtxid(), true);
    assert_index(&pool);
    pool.clear();
    assert_index(&pool);
    Ok(())
}

#[test]
fn default_min_relay_fee_is_1_sat_per_vbyte() {
    let pool = Mempool::new(MempoolLimits::default());
    assert_eq!(pool.min_relay_fee_sat_per_kvb(), 1_000);
}
#[test]
fn min_fee_floors_at_min_relay_while_the_rolling_rate_is_zero() {
    let pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 1_000,
        ..MempoolLimits::default()
    });
    assert_eq!(pool.min_fee_sat_per_kvb(0), 1_000);
    assert_eq!(pool.min_fee_sat_per_kvb(u64::MAX), 1_000);
}

#[test]
fn insert_entry_rejects_below_min_relay_fee() {
    let limits = MempoolLimits {
        min_relay_fee_sat_per_kvb: 5_000,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    let tx = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
    let entry = MempoolEntry::new(Arc::new(tx), 100, 100, 1, 7, 0);
    let result = pool.insert_entry(entry);

    assert!(
        matches!(
            result,
            Err(MempoolError::Policy(PolicyError::BelowMinRelayFee {
                tx_rate: 1_000,
                min_rate: 5_000
            }))
        ),
        "expected BelowMinRelayFee rejection, got {result:?}"
    );
}

#[test]
fn stats_reports_empty_and_inserted_entry_counters() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    assert_eq!(pool.stats(), MempoolStats::default());

    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    let entry = MempoolEntry::new(Arc::new(tx), 123, 4_567, 0, 0, 0);
    let expected_vsize = u64::from(entry.vsize);
    let expected_fee = entry.fee;

    pool.insert_entry(entry)?;

    let stats = pool.stats();
    assert_eq!(stats.txs, 1);
    assert_eq!(stats.bytes, expected_vsize);
    assert_eq!(stats.total_fee, expected_fee);
    Ok(())
}

#[test]
fn aggregate_fees_sums_entry_fees() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    assert_eq!(pool.aggregate_fees(), 0);

    let entry_a = MempoolEntry::new(Arc::new(tx(1, Vec::new())), 400, 500, 1, 7, 0);
    let entry_b = MempoolEntry::new(Arc::new(tx(2, Vec::new())), 900, 1_000, 2, 7, 0);
    pool.insert_entry(entry_a)?;
    pool.insert_entry(entry_b)?;

    assert_eq!(pool.aggregate_fees(), 1_500);
    Ok(())
}

#[test]
fn aggregate_fees_stays_saturated_after_decrements() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let prioritised = tx(2, Vec::new());
    let prioritised_txid = prioritised.txid();
    let removed = tx(3, Vec::new());
    let removed_txid = removed.txid();

    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(1, Vec::new())),
        100,
        u64::MAX - 1,
        1,
        7,
        0,
    ))?;
    pool.insert_entry(MempoolEntry::new(Arc::new(prioritised), 100, 100, 2, 7, 0))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(removed.clone()),
        100,
        50,
        3,
        7,
        0,
    ))?;

    assert_eq!(pool.aggregate_fees(), u64::MAX);
    assert!(
        !pool
            .remove_for_block(&[&removed], &[removed_txid], 8, 1)
            .is_empty()
    );
    assert_eq!(pool.aggregate_fees(), u64::MAX);
    pool.prioritise(prioritised_txid, -100)
        .expect("overlay delta applies");
    assert_eq!(pool.aggregate_fees(), u64::MAX);
    Ok(())
}

#[test]
fn iter_by_fee_rate_desc_orders_highest_first() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let low_tx = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
    let low_txid = low_tx.txid();
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(low_tx), 100, 1_000, 1, 7, 0));
    let high_tx = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
    let high_txid = high_tx.txid();
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(high_tx), 100, 10_000, 1, 7, 0));
    let ordered = pool.iter_by_fee_rate_desc();
    assert_eq!(ordered.len(), 2);
    let Some(&first_id) = ordered.first() else {
        panic!("expected at least one entry");
    };
    let Some(first_entry) = pool.entry(first_id) else {
        panic!("first entry missing");
    };
    assert_eq!(first_entry.tx.txid(), high_txid);
    let Some(&second_id) = ordered.get(1) else {
        panic!("expected two entries");
    };
    let Some(second_entry) = pool.entry(second_id) else {
        panic!("second entry missing");
    };
    assert_eq!(second_entry.tx.txid(), low_txid);
}

#[test]
fn fee_rate_aggregate_tracks_duplicate_rates_and_removals() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let first = Arc::new(tx(10, Vec::new()));
    let second = Arc::new(tx(11, Vec::new()));
    let other_rate = Arc::new(tx(12, Vec::new()));
    let first_txid = first.txid();
    let second_txid = second.txid();

    pool.insert_entry(MempoolEntry::new(Arc::clone(&first), 100, 1_000, 1, 7, 0))?;
    pool.insert_entry(MempoolEntry::new(Arc::clone(&second), 200, 2_000, 2, 7, 0))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::clone(&other_rate),
        100,
        3_000,
        3,
        7,
        0,
    ))?;

    let ten_k = pool
        .derived
        .fee_rate_aggregates
        .get(&10_000)
        .expect("duplicate rate aggregate");
    assert_eq!((ten_k.count, ten_k.vsize), (2, 300));
    assert_eq!(
        pool.fee_rate_histogram().collect::<Vec<_>>(),
        vec![(10_000, 300), (30_000, 100)]
    );

    assert_eq!(
        pool.remove_for_block(&[first.as_ref()], &[first_txid], 4, 1)
            .len(),
        1
    );
    let ten_k = pool
        .derived
        .fee_rate_aggregates
        .get(&10_000)
        .expect("remaining duplicate rate aggregate");
    assert_eq!((ten_k.count, ten_k.vsize), (1, 200));
    assert_eq!(
        pool.fee_rate_histogram().collect::<Vec<_>>(),
        vec![(10_000, 200), (30_000, 100)]
    );

    assert_eq!(
        pool.remove_for_block(&[second.as_ref()], &[second_txid], 5, 1)
            .len(),
        1
    );
    assert!(!pool.derived.fee_rate_aggregates.contains_key(&10_000));
    assert_eq!(
        pool.fee_rate_histogram().collect::<Vec<_>>(),
        vec![(30_000, 100)]
    );
    Ok(())
}

#[test]
fn iter_above_fee_rate_filters_to_high_fee_only() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let low_tx = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(low_tx), 100, 1_000, 1, 7, 0));
    let high_tx = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(high_tx), 100, 10_000, 1, 7, 0));
    let high_only = pool.iter_above_fee_rate(50_000);
    assert_eq!(high_only.len(), 1);
    let both = pool.iter_above_fee_rate(500);
    assert_eq!(both.len(), 2);
    let none = pool.iter_above_fee_rate(200_000);
    assert_eq!(none.len(), 0);
}

#[test]
fn iter_replaceable_txids_returns_only_rbf_signaled_txs() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let rbf_tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: txid_of([0xaa; 32]),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0x0000_0001),
            witness: Witness::new(),
        }],
        outputs: Vec::new(),
    };
    let rbf_txid = rbf_tx.txid();
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(rbf_tx), 100, 10_000, 1, 7, 0));
    let non_rbf_tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: txid_of([0xbb; 32]),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: Vec::new(),
    };
    let non_rbf_txid = non_rbf_tx.txid();
    let _ = pool.insert_entry(MempoolEntry::new(
        Arc::new(non_rbf_tx),
        100,
        10_000,
        1,
        7,
        0,
    ));
    let replaceable = pool.iter_replaceable_txids();
    assert!(replaceable.contains(&rbf_txid));
    assert!(!replaceable.contains(&non_rbf_txid));
    assert_eq!(replaceable.len(), 1);
}

#[test]
fn sequence_number_bumps_on_successful_insert() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let before = pool.sequence_number();
    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    let entry = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0);
    pool.insert_entry(entry)?;
    let after = pool.sequence_number();
    assert!(after > before, "expected sequence to bump");
    Ok(())
}

#[test]
fn clear_removes_all_entries_and_bumps_sequence() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x51].into());
    let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))?;
    let seq_before_clear = pool.sequence_number();

    pool.clear();

    assert_eq!(pool.len(), 0);
    assert!(pool.derived.by_txid.is_empty());
    assert!(pool.derived.funding.is_empty());
    assert!(pool.derived.spending.is_empty());
    assert!(pool.derived.chunks.is_empty());
    assert!(pool.fee_deltas.is_empty(), "clear is a wholesale reset");
    assert!(pool.sequence_number() > seq_before_clear);
    Ok(())
}

#[test]
fn outpoint_spender_returns_the_spending_entry_and_vin() {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let outpoint = OutPoint {
        txid: txid_of([0xaa; 32]),
        vout: 7,
    };
    let decoy = OutPoint {
        txid: txid_of([0xbb; 32]),
        vout: 3,
    };
    let spending = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![
            TxIn {
                previous_output: decoy,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: vec![0x51].into(),
        }],
    };
    let spending_txid = spending.txid();
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(spending), 100, 10_000, 1, 7, 0));
    let spender = pool
        .outpoint_spender(outpoint)
        .expect("the index and the entries agree")
        .expect("the pool holds a spender");
    assert_eq!(spender.entry.txid, spending_txid);
    assert_eq!(spender.vin, 1);
}

#[test]
fn outpoint_spender_returns_none_for_unspent_outpoint() {
    let pool = Mempool::new(MempoolLimits::default());
    let outpoint = OutPoint {
        txid: txid_of([0xff; 32]),
        vout: 0,
    };
    assert!(matches!(pool.outpoint_spender(outpoint), Ok(None)));
}

#[test]
fn entries_funding_script_selects_only_matching_funders() {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let matching = vec![0x51];
    let other = vec![0x52];
    let funder = |script: Vec<u8>, tag: u8| {
        single_output_tx(
            &[OutPoint {
                txid: txid_of([tag; 32]),
                vout: 0,
            }],
            Sequence::MAX,
            50_000,
            script.into(),
        )
    };
    let matching_tx = funder(matching.clone(), 0xaa);
    let matching_txid = matching_tx.txid();
    let matching_wtxid = matching_tx.wtxid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(matching_tx),
        100,
        10_000,
        1,
        7,
        0,
    ))
    .expect("matching insert");
    pool.insert_entry(MempoolEntry::new(
        Arc::new(funder(other, 0xbb)),
        100,
        10_000,
        1,
        7,
        0,
    ))
    .expect("other insert");

    let funded: Vec<_> = pool
        .entries_funding_script(ScriptHash::from_script(&matching))
        .map(|entry| entry.txid)
        .collect();
    assert_eq!(funded, vec![matching_txid]);
    assert!(pool.contains_wtxid(&matching_wtxid));
    assert_eq!(
        pool.entry_by_wtxid(&matching_wtxid).map(|entry| entry.txid),
        Some(matching_txid)
    );
    assert_eq!(pool.iter_entries().count(), 2);
}

#[test]
fn outpoint_spender_errors_when_the_index_names_a_missing_entry() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let outpoint = OutPoint {
        txid: txid_of([0xee; 32]),
        vout: 0,
    };
    pool.derived
        .spending
        .insert((SpendingKey::from(outpoint), 9_999));
    assert!(matches!(
        pool.outpoint_spender(outpoint),
        Err(MempoolError::InconsistentSpendingIndex)
    ));
}

#[test]
fn outpoint_spender_errors_when_the_entry_does_not_spend_the_outpoint() {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let unrelated = OutPoint {
        txid: txid_of([0xdd; 32]),
        vout: 0,
    };
    let indexed = OutPoint {
        txid: txid_of([0xcc; 32]),
        vout: 5,
    };
    let tx = single_output_tx(&[unrelated], Sequence::MAX, 99_000, vec![0x51].into());
    let entry_txid = tx.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
        .expect("insertion succeeds");
    let id = pool
        .entry_id_by_txid(&entry_txid)
        .expect("inserted entry id resolves");
    pool.derived
        .spending
        .insert((SpendingKey::from(indexed), id));
    assert!(matches!(
        pool.outpoint_spender(indexed),
        Err(MempoolError::InconsistentSpendingIndex)
    ));
}

#[test]
fn outpoint_spender_keeps_the_first_entry_when_two_spenders_are_indexed() {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let outpoint = OutPoint {
        txid: txid_of([0x11; 32]),
        vout: 0,
    };
    let spender_tx =
        |fee: u64| single_output_tx(&[outpoint], Sequence::MAX, fee, vec![0x51].into());
    let first = spender_tx(99_000);
    let first_txid = first.txid();
    let _ = pool.insert_entry(MempoolEntry::new(Arc::new(first), 100, 10_000, 1, 7, 0));
    let _ = pool.insert_entry(MempoolEntry::new(
        Arc::new(spender_tx(98_000)),
        100,
        10_000,
        1,
        7,
        0,
    ));
    let spender = pool
        .outpoint_spender(outpoint)
        .expect("both rows are internally consistent")
        .expect("the pool holds spenders");
    assert_eq!(spender.entry.txid, first_txid);
}

#[test]
fn is_outpoint_spent_returns_true_after_insert() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let prev_txid = txid_of([0xaa_u8; 32]);
    let outpoint = OutPoint {
        txid: prev_txid,
        vout: 1,
    };
    let spending = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![],
    };
    pool.insert_entry(MempoolEntry::new(Arc::new(spending), 100, 10_000, 1, 7, 0))?;
    assert!(pool.is_outpoint_spent(&outpoint));
    Ok(())
}

#[test]
fn is_outpoint_spent_returns_false_for_unspent_outpoint() {
    let pool = Mempool::new(MempoolLimits::default());
    let outpoint = OutPoint {
        txid: txid_of([0xff_u8; 32]),
        vout: 0,
    };
    assert!(!pool.is_outpoint_spent(&outpoint));
}

#[test]
fn block_inclusion_keeps_unmined_descendants() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx(13, Vec::new());
    let parent_txid = parent.txid();
    let child = tx(14, vec![OutPoint::new(parent_txid, 0)]);
    let child_txid = child.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(parent.clone()),
        100,
        1_000,
        1,
        7,
        0,
    ))?;
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 2, 7, 0))?;
    let child_id = pool
        .entry_id_by_txid(&child_txid)
        .expect("child id resolves");

    let removed = pool.remove_for_block(&[&parent], &[parent_txid], 8, 1);

    assert_eq!(
        removed.changes,
        vec![MutationChange {
            txid: Hash256::from(parent_txid),
            outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
        }]
    );
    assert!(pool.contains_txid(&child_txid));
    assert_eq!(pool.ancestor_ids_for_entry(child_id), Vec::<u32>::new());
    let incremental = totals(&pool);
    pool.recompute_all_metadata();
    assert_eq!(incremental, totals(&pool));
    Ok(())
}

#[test]
fn descendant_ids_for_entry_returns_descendants_excluding_origin() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx(1, Vec::new());
    let parent_txid = parent.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
    let parent_id = pool
        .entry_id_by_txid(&parent_txid)
        .expect("parent id resolves");
    let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
    let child_txid = child.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0, 0))?;
    let child_id = pool
        .entry_id_by_txid(&child_txid)
        .expect("child id resolves");

    let descendants = pool.descendant_ids_for_entry(parent_id);

    assert_eq!(descendants, vec![child_id]);
    Ok(())
}

#[test]
fn descendant_count_inclusive_returns_one_for_lone_tx() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let lone = tx(1, Vec::new());
    let lone_txid = lone.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(lone), 500, 1_000, 1, 7, 0))?;
    let Some(id) = pool.entry_id_by_txid(&lone_txid) else {
        panic!("insert failed");
    };
    assert_eq!(pool.descendant_count_inclusive(id), 1);
    assert_eq!(pool.ancestor_count_inclusive(id), 1);
    Ok(())
}

#[test]
fn prioritise_moves_modified_fee_without_touching_actual_fees() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = tx(1, Vec::new());
    let txid = tx.txid();
    let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;

    pool.prioritise(txid, 500).expect("overlay delta applies");

    let Some(entry) = pool.entry_by_txid(&txid) else {
        panic!("tx missing after prioritise");
    };
    assert_eq!(
        entry.fee, 1_000,
        "the actual fee is what the transaction pays"
    );
    assert_eq!(
        entry.fee_rate, 10_000,
        "the actual fee rate is policy input"
    );
    assert_eq!(entry.fee_delta, 500);
    assert_eq!(entry.modified_fee(), 1_500);
    assert_eq!(
        pool.aggregate_fees(),
        1_000,
        "aggregates read actual fees only"
    );
    Ok(())
}

#[test]
fn prioritise_keeps_the_actual_fee_when_modified_fee_goes_negative() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = tx(2, Vec::new());
    let txid = tx.txid();
    let _id = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;

    pool.prioritise(txid, -2_000)
        .expect("negative overlay applies");

    let Some(entry) = pool.entry_by_txid(&txid) else {
        panic!("tx missing after prioritise");
    };
    assert_eq!(entry.fee, 1_000);
    assert_eq!(entry.fee_rate, 10_000);
    assert_eq!(entry.modified_fee(), -1_000);
    assert_eq!(
        pool.derived.chunks.len(),
        1,
        "a negative overlay still indexes the entry"
    );
    Ok(())
}

#[test]
fn prioritise_accumulates_additively_and_rejects_overflow() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let entry_tx = tx(3, Vec::new());
    let txid = entry_tx.txid();
    let _id = pool.insert_entry(MempoolEntry::new(Arc::new(entry_tx), 100, 1_000, 1, 7, 0))?;

    pool.prioritise(txid, 2_000).expect("first delta applies");
    pool.prioritise(txid, 3_000)
        .expect("second delta accumulates");
    pool.prioritise(txid, -1_200)
        .expect("a negative delta subtracts");
    assert_eq!(
        pool.entry_by_txid(&txid).map(|entry| entry.fee_delta),
        Some(3_800),
        "deltas are additive, not replacements"
    );

    let other = tx(4, Vec::new());
    let other_txid = other.txid();
    let _other_id = pool.insert_entry(MempoolEntry::new(Arc::new(other), 100, 1_000, 1, 7, 0))?;
    pool.prioritise(other_txid, i64::MAX)
        .expect("the signed range edge itself is storable");
    assert_eq!(
        pool.prioritise(other_txid, 1),
        Err(PrioritiseError::FeeDeltaOverflow)
    );
    assert_eq!(
        pool.entry_by_txid(&other_txid).map(|entry| entry.fee_delta),
        Some(i64::MAX),
        "a rejected delta leaves the overlay exactly as it was"
    );
    pool.prioritise(other_txid, -1)
        .expect("recovery from the edge works");
    Ok(())
}

#[test]
fn prioritised_transactions_includes_absent_txids() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let pooled = tx(30, Vec::new());
    let pooled_txid = pooled.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(pooled), 100, 1_000, 1, 7, 0))?;
    pool.prioritise(pooled_txid, 500)
        .expect("pooled overlay applies");

    let absent_txid = tx(31, Vec::new()).txid();
    pool.prioritise(absent_txid, -25)
        .expect("absent overlay is stored");

    let overlay = pool.prioritised_transactions();
    assert_eq!(overlay.len(), 2);
    let pooled_row = overlay
        .iter()
        .find(|entry| entry.txid == pooled_txid)
        .expect("pooled overlay is listed");
    assert_eq!(pooled_row.fee_delta, 500);
    assert!(pooled_row.in_mempool);
    assert_eq!(pooled_row.modified_fee, Some(1_500));
    let absent_row = overlay
        .iter()
        .find(|entry| entry.txid == absent_txid)
        .expect("absent overlay is listed");
    assert_eq!(absent_row.fee_delta, -25);
    assert!(!absent_row.in_mempool);
    assert_eq!(absent_row.modified_fee, None);
    Ok(())
}

#[test]
fn prioritise_removes_a_zeroed_overlay() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let pooled = tx(32, Vec::new());
    let pooled_txid = pooled.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(pooled), 100, 1_000, 1, 7, 0))?;
    pool.prioritise(pooled_txid, 500)
        .expect("pooled overlay applies");
    pool.prioritise(pooled_txid, -500)
        .expect("reversing the overlay clears it");
    assert!(
        pool.prioritised_transactions().is_empty(),
        "a zero accumulated delta must leave the overlay map"
    );
    assert_eq!(
        pool.entry_by_txid(&pooled_txid)
            .map(|entry| entry.fee_delta),
        Some(0)
    );
    Ok(())
}

#[test]
fn prioritise_propagates_the_overlay_through_package_deltas() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx(5, Vec::new());
    let parent_txid = parent.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0, 0))?;
    let parent_id = pool
        .entry_id_by_txid(&parent_txid)
        .expect("parent id resolves");
    let child = tx(6, vec![OutPoint::new(parent_txid, 0)]);
    let child_txid = child.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 2_000, 0, 0, 0))?;
    let child_id = pool
        .entry_id_by_txid(&child_txid)
        .expect("child id resolves");
    let grandchild = tx(7, vec![OutPoint::new(child_txid, 0)]);
    let grandchild_txid = grandchild.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(grandchild), 100, 3_000, 0, 0, 0))?;
    let grandchild_id = pool
        .entry_id_by_txid(&grandchild_txid)
        .expect("grandchild id resolves");

    pool.prioritise(child_txid, 500)
        .expect("overlay delta applies");

    let Some(parent_after) = pool.entry(parent_id) else {
        panic!("missing parent");
    };
    assert_eq!(
        parent_after.descendant_fee, 6_000,
        "actual fees do not move"
    );
    assert_eq!(parent_after.descendant_fee_delta, 500);
    let Some(child_after) = pool.entry(child_id) else {
        panic!("missing child");
    };
    assert_eq!(child_after.ancestor_fee, 3_000, "actual fees do not move");
    assert_eq!(child_after.ancestor_fee_delta, 500);
    assert_eq!(
        i128::from(child_after.ancestor_fee) + child_after.ancestor_fee_delta,
        3_500,
        "the modified ancestor package fee carries the overlay"
    );
    let Some(grandchild_after) = pool.entry(grandchild_id) else {
        panic!("missing grandchild");
    };
    assert_eq!(
        grandchild_after.ancestor_fee, 6_000,
        "actual fees do not move"
    );
    assert_eq!(grandchild_after.ancestor_fee_delta, 500);
    Ok(())
}

#[test]
fn a_delta_may_predate_admission() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = tx(8, Vec::new());
    let txid = tx.txid();
    let before = pool.sequence_number();

    pool.prioritise(txid, 1_500)
        .expect("an absent txid stores its delta");
    assert!(!pool.contains_txid(&txid));
    assert_eq!(pool.sequence_number(), before);

    pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;

    let Some(entry) = pool.entry_by_txid(&txid) else {
        panic!("insert failed");
    };
    assert_eq!(entry.fee_delta, 1_500);
    assert_eq!(
        entry.fee, 1_000,
        "a pre-admission delta adjusts ordering only"
    );
    assert_eq!(entry.modified_fee(), 2_500);
    Ok(())
}

#[test]
fn ordinary_removal_keeps_the_overlay_for_readmission() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = tx(9, Vec::new());
    let txid = tx.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7, 0))?;
    pool.prioritise(txid, 700).expect("delta applies");

    assert!(!pool.evict_below_fee_rate(10_001).is_empty());

    pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))?;
    let Some(entry) = pool.entry_by_txid(&txid) else {
        panic!("readmission failed");
    };
    assert_eq!(entry.fee_delta, 700, "ordinary removal keeps the overlay");
    assert_eq!(entry.fee, 1_000);
    Ok(())
}

#[test]
fn mined_removal_clears_only_the_overlays_of_block_transactions() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx(10, Vec::new());
    let parent_txid = parent.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(parent.clone()),
        100,
        1_000,
        1,
        7,
        0,
    ))?;
    let child = tx(11, vec![OutPoint::new(parent_txid, 0)]);
    let child_txid = child.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 7, 0))?;
    let stranger = tx(12, Vec::new());
    let stranger_txid = stranger.txid();

    pool.prioritise(parent_txid, 100)
        .expect("parent delta applies");
    pool.prioritise(child_txid, 200)
        .expect("child delta applies");
    pool.prioritise(stranger_txid, 50)
        .expect("stranger delta applies");

    let removed = pool.remove_for_block(&[&parent, &stranger], &[parent_txid, stranger_txid], 8, 1);

    assert_eq!(removed.len(), 1, "only the mined parent leaves");
    assert_eq!(
        removed.changes,
        vec![MutationChange {
            txid: Hash256::from(parent_txid),
            outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
        }]
    );
    assert!(!pool.fee_deltas.contains_key(&parent_txid));
    assert!(!pool.fee_deltas.contains_key(&stranger_txid));
    assert_eq!(
        pool.fee_deltas.get(&child_txid).copied(),
        Some(200),
        "the unmined child keeps its overlay"
    );
    assert!(pool.contains_txid(&child_txid));

    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 7, 0))?;
    assert_eq!(
        pool.entry_by_txid(&parent_txid)
            .map(|entry| entry.fee_delta),
        Some(0),
        "a mined transaction's overlay is erased"
    );
    Ok(())
}

#[test]
fn prioritise_reorders_priority_index() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let lower_fee_tx = tx(13, Vec::new());
    let lower_fee_txid = lower_fee_tx.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(lower_fee_tx),
        100,
        1_000,
        1,
        7,
        0,
    ))?;
    let lower_fee_id = pool
        .entry_id_by_txid(&lower_fee_txid)
        .expect("lower id resolves");
    let higher_fee_tx = tx(14, Vec::new());
    let higher_fee_txid = higher_fee_tx.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(higher_fee_tx),
        100,
        2_000,
        2,
        7,
        0,
    ))?;
    let higher_fee_id = pool
        .entry_id_by_txid(&higher_fee_txid)
        .expect("higher id resolves");

    assert_eq!(
        pool.chunks_by_feerate()
            .flat_map(|chunk| chunk.members.iter().copied())
            .next(),
        Some(higher_fee_id)
    );
    pool.prioritise(lower_fee_txid, 2_000)
        .expect("delta applies");

    assert_eq!(
        pool.chunks_by_feerate()
            .flat_map(|chunk| chunk.members.iter().copied())
            .next(),
        Some(lower_fee_id)
    );
    Ok(())
}

#[test]
fn a_snapshot_outlives_pool_mutation() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let tx = tx(17, Vec::new());
    let txid = tx.txid();
    let shared = Arc::new(tx);
    pool.insert_entry(MempoolEntry::new(Arc::clone(&shared), 100, 1_000, 1, 7, 0))?;

    let snapshot = pool.mining_snapshot();
    pool.clear();
    pool.prioritise(txid, 5_000)
        .expect("delta applies after the clear");

    let Some(entry) = snapshot.entries.first() else {
        panic!("the snapshot holds what it captured");
    };
    assert_eq!(entry.txid, txid);
    assert_eq!(entry.fee, 1_000);
    assert_eq!(entry.fee_delta, 0);
    assert!(
        Arc::ptr_eq(&entry.tx, &shared),
        "payloads are shared, not copied"
    );
    Ok(())
}

#[test]
fn admissions_and_mined_confirmations_feed_the_pool_owned_estimator() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    assert_eq!(pool.estimate_fee_rate(2), None, "no history yet");

    let first = tx(18, Vec::new());
    let first_txid = first.txid();
    let second = tx(19, Vec::new());
    let second_txid = second.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(first.clone()),
        100,
        10_000,
        1,
        7,
        0,
    ))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(second.clone()),
        100,
        10_000,
        1,
        7,
        0,
    ))?;
    assert_eq!(
        pool.estimate_fee_rate(2),
        None,
        "arrivals alone are not confirmation evidence"
    );

    pool.remove_for_block(&[&first, &second], &[first_txid, second_txid], 8, 1);
    assert!(
        pool.estimate_fee_rate(2).is_some(),
        "the confirmations this pool observed itself answer the estimate"
    );
    assert!(!pool.contains_txid(&first_txid));
    assert!(
        !pool.contains_txid(&second_txid),
        "the mined transactions left the pool"
    );
    Ok(())
}

#[test]
fn evict_below_fee_rate_removes_low_fee_entries_only() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let low = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
    let low_txid = low.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(low), 100, 100, 1, 7, 0))?;

    let high = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
    let high_txid = high.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(high), 100, 10_000, 1, 7, 0))?;

    let evicted = pool.evict_below_fee_rate(5_000);

    assert_eq!(change_txids(&evicted), vec![Hash256::from(low_txid)]);
    assert!(!pool.contains_txid(&low_txid));
    assert!(pool.contains_txid(&high_txid));
    Ok(())
}

#[test]
fn enforce_size_limit_evicts_lowest_fee_until_below_target() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });

    let low = single_output_tx(&[], Sequence::MAX, 1_000, vec![0x51].into());
    let low_txid = low.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(low), 500, 100, 1, 7, 0))?;

    let high = single_output_tx(&[], Sequence::MAX, 99_000, vec![0x52].into());
    let high_txid = high.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(high), 500, 10_000, 1, 7, 0))?;

    let evicted = pool.enforce_size_limit(600)?;

    assert_eq!(evicted.len(), 1);
    assert!(!pool.contains_txid(&low_txid));
    assert!(pool.contains_txid(&high_txid));
    assert!(pool.total_vsize() <= 600);
    Ok(())
}

#[test]
fn insert_entry_triggers_size_limit_eviction_when_overflow() {
    let limits = MempoolLimits {
        max_total_bytes: 1_000,
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    for nonce in 0..2_u32 {
        let tx = single_output_tx(
            &[],
            Sequence::MAX,
            1_000 + u64::from(nonce),
            vec![0x51, u8::try_from(nonce).unwrap_or(0)].into(),
        );
        let fee = 100_u64.saturating_add(u64::from(nonce).saturating_mul(50));

        let _ = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 600, fee, 1, 7, 0));
    }

    assert!(
        pool.total_vsize() <= 1_000,
        "size limit must hold after inserts: {}",
        pool.total_vsize()
    );
}

#[test]
fn capacity_rejection_is_atomic_and_a_better_arrival_can_enter() {
    fn tx_paying(nonce: u8) -> Arc<Tx> {
        Arc::new(single_output_tx(
            &[],
            Sequence::MAX,
            1_000 + u64::from(nonce),
            vec![0x51, nonce].into(),
        ))
    }

    let limits = MempoolLimits {
        max_total_bytes: 1_000,
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    let seated = pool.insert_entry(MempoolEntry::new(tx_paying(1), 900, 90_000, 1, 7, 0));
    assert!(seated.is_ok(), "the first transaction fits: {seated:?}");

    let before = (pool.sequence_number(), pool.estimator_history());
    let refused = pool.insert_entry(MempoolEntry::new(tx_paying(2), 900, 10, 2, 7, 0));
    assert!(matches!(refused, Err(MempoolError::Full)));
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.sequence_number(), before.0);
    assert_eq!(pool.estimator_history(), before.1);

    let admitted = pool.insert_entry(MempoolEntry::new(tx_paying(3), 900, 900_000, 3, 7, 0));
    let Ok(_result) = admitted else {
        panic!("a better-paying transaction must be admitted: {admitted:?}");
    };
    assert_eq!(pool.len(), 1, "the accepted transaction is the only entry");
    assert!(
        pool.entries.iter().any(|(_, entry)| entry.vsize == 900),
        "an accepted entry must resolve"
    );
}

#[test]
fn a_replacement_that_would_be_shed_leaves_the_pool_unchanged() {
    let limits = MempoolLimits {
        max_total_bytes: 1_000,
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    let prev = OutPoint {
        txid: txid_of([0x11; 32]),
        vout: 0,
    };

    let original = single_output_tx(
        &[prev],
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        1_000,
        vec![0x51].into(),
    );
    let original_txid = original.txid();
    let seated = pool.insert_entry(MempoolEntry::new(Arc::new(original), 100, 10_000, 1, 7, 0));
    assert!(seated.is_ok(), "original must fit: {seated:?}");

    let bystander = tx(8, Vec::new());
    let seated_by = pool.insert_entry(MempoolEntry::new(
        Arc::new(bystander),
        850,
        8_500_000,
        1,
        7,
        0,
    ));
    assert!(seated_by.is_ok(), "bystander must fit: {seated_by:?}");
    assert_eq!(pool.len(), 2);

    let replacement = single_output_tx(
        &[prev],
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        100,
        vec![0x52].into(),
    );
    let replacement_txid = replacement.txid();
    let before = (
        pool.mining_snapshot().entries,
        pool.estimator_history(),
        pool.policy_stamp(),
    );
    let result = pool.replace_transaction(
        &crate::ReplacementCandidate::new(Arc::new(replacement), 900, 100_000, 1)
            .with_sigop_cost(4),
        2,
        7,
    );
    assert!(matches!(
        result,
        Err(crate::RbfError::Mempool(MempoolError::Full))
    ));
    assert!(pool.contains_txid(&original_txid));
    assert!(!pool.contains_txid(&replacement_txid));
    assert_eq!(pool.mining_snapshot().entries, before.0);
    assert_eq!(pool.estimator_history(), before.1);
    assert_ne!(pool.policy_stamp(), before.2);
    assert!(pool.min_fee_sat_per_kvb(9) > 0);
}

fn totals(pool: &Mempool) -> Vec<(usize, u64, u64, u64, u64)> {
    let mut all = pool
        .entries
        .iter()
        .map(|(index, entry)| {
            (
                index,
                entry.ancestor_size,
                entry.ancestor_fee,
                entry.descendant_size,
                entry.descendant_fee,
            )
        })
        .collect::<Vec<_>>();
    all.sort_unstable();
    all
}

fn graph_pool() -> Result<(Mempool, Vec<OutPoint>), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut outs = Vec::new();

    let add =
        |pool: &mut Mempool, label: u8, parents: Vec<OutPoint>| -> Result<OutPoint, MempoolError> {
            let transaction = tx(label, parents);
            let txid = transaction.txid();
            let vsize = 100 + u32::from(label);
            pool.insert_entry(MempoolEntry::new(
                Arc::new(transaction),
                vsize,
                u64::from(vsize) * 10,
                u64::from(label),
                1,
                0,
            ))?;
            Ok(OutPoint::new(txid, 0))
        };

    let root = add(&mut pool, 1, vec![OutPoint::default()])?;
    let mid = add(&mut pool, 2, vec![root])?;
    let leaf = add(&mut pool, 3, vec![mid])?;
    let sibling = add(&mut pool, 4, vec![root])?;
    let joined = add(&mut pool, 5, vec![leaf, sibling])?;
    let lonely = add(&mut pool, 6, vec![OutPoint::default()])?;

    outs.extend([root, mid, leaf, sibling, joined, lonely]);
    Ok((pool, outs))
}

#[test]
fn incremental_metadata_matches_the_full_recompute() -> Result<(), MempoolError> {
    let (mut pool, _outs) = graph_pool()?;

    let incremental = totals(&pool);
    pool.recompute_all_metadata();
    assert_eq!(
        incremental,
        totals(&pool),
        "incremental insert metadata diverged from the full recompute"
    );
    Ok(())
}

#[test]
fn incremental_metadata_matches_the_full_recompute_after_removals() -> Result<(), MempoolError> {
    for victim in 0..6_u32 {
        let (mut pool, _outs) = graph_pool()?;
        let Some(entry) = pool.entry(victim) else {
            panic!("entry {victim} must be present in the fixture");
        };
        let tx = entry.tx.clone();
        let txid = entry.txid;
        let removed = pool.remove_for_block(&[&tx], &[txid], 8, 1);
        assert!(
            !removed.is_empty(),
            "entry {victim} must be present in the fixture"
        );

        let incremental = totals(&pool);
        pool.recompute_all_metadata();
        assert_eq!(
            incremental,
            totals(&pool),
            "incremental removal metadata diverged from the full recompute \
                 after removing entry {victim}"
        );
    }
    Ok(())
}

#[test]
fn eviction_during_insertion_leaves_metadata_a_rebuild_agrees_with() -> Result<(), MempoolError> {
    let limits = MempoolLimits {
        max_total_bytes: 400,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    let root = tx(31, vec![OutPoint::default()]);
    let root_out = OutPoint::new(root.txid(), 0);
    pool.insert_entry(MempoolEntry::new(Arc::new(root), 100, 500, 0, 1, 0))?;
    let child = tx(32, vec![root_out]);
    let child_out = OutPoint::new(child.txid(), 0);
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 9_000, 1, 1, 0))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(33, vec![child_out])),
        100,
        100_000,
        2,
        1,
        0,
    ))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(34, vec![OutPoint::default()])),
        100,
        200,
        3,
        1,
        0,
    ))?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(35, vec![OutPoint::default()])),
        100,
        300,
        4,
        1,
        0,
    ))?;
    assert!(
        pool.len() < 5,
        "the fixture must actually cross the size limit"
    );

    let incremental = totals(&pool);
    let index = pool.chunk_order();
    pool.recompute_all_metadata();
    assert_eq!(
        incremental,
        totals(&pool),
        "eviction left package totals a full recompute disagrees with"
    );
    assert_eq!(
        index,
        pool.chunk_order(),
        "eviction left a stale chunk index behind"
    );
    Ok(())
}

#[test]
fn running_totals_track_inserts_removals_and_prioritise() -> Result<(), MempoolError> {
    fn folded(pool: &Mempool) -> (u64, u64) {
        pool.entries
            .iter()
            .fold((0_u64, 0_u64), |(size, fee), (_, entry)| {
                (
                    size.saturating_add(u64::from(entry.vsize)),
                    fee.saturating_add(entry.fee),
                )
            })
    }
    fn check(pool: &Mempool, stage: &str) {
        let (size, fee) = folded(pool);
        assert_eq!(pool.total_vsize(), size, "vsize total wrong after {stage}");
        assert_eq!(pool.aggregate_fees(), fee, "fee total wrong after {stage}");
        let stats = pool.stats();
        assert_eq!(stats.bytes, size, "stats.bytes wrong after {stage}");
        assert_eq!(stats.total_fee, fee, "stats.total_fee wrong after {stage}");
    }

    let (mut pool, outs) = graph_pool()?;
    check(&pool, "inserts");

    let Some(root) = outs.first().map(|out| out.txid) else {
        panic!("fixture must hold entries");
    };
    pool.prioritise(root, 250_000)
        .expect("prioritise up must apply");
    check(&pool, "a positive fee delta");

    pool.prioritise(root, -100_000)
        .expect("prioritise down must apply");
    check(&pool, "a negative fee delta");

    let Some(victim_txid) = outs.get(1).map(|out| out.txid) else {
        panic!("fixture must hold a second entry");
    };
    let Some(victim) = pool.entry_by_txid(&victim_txid) else {
        panic!("fixture must hold the victim entry");
    };
    let victim_tx = victim.tx.clone();
    let removed = pool.remove_for_block(&[&victim_tx], &[victim_txid], 8, 1);
    assert!(!removed.is_empty(), "the victim must actually be removed");
    assert!(
        outs.get(2).is_some_and(|out| pool.contains_txid(&out.txid)),
        "the chain below the victim remains in the pool"
    );
    check(&pool, "a removal");

    pool.clear();
    check(&pool, "clear");
    Ok(())
}

#[test]
fn prioritise_reindexes_the_descendants_it_lifts() -> Result<(), MempoolError> {
    let (mut pool, outs) = graph_pool()?;

    let Some(txid) = outs.first().map(|out| out.txid) else {
        panic!("fixture must hold entries");
    };
    pool.prioritise(txid, 5_000_000)
        .expect("prioritise must apply");

    let after_prioritise = pool.chunk_order();
    let totals_after = totals(&pool);
    pool.recompute_all_metadata();
    assert_eq!(
        totals_after,
        totals(&pool),
        "prioritise left package totals a full recompute disagrees with"
    );
    assert_eq!(
        after_prioritise,
        pool.chunk_order(),
        "prioritise left stale chunk keys behind"
    );
    Ok(())
}

#[test]
fn inserting_a_parent_after_its_child_refreshes_the_child() -> Result<(), MempoolError> {
    let mut pool = Mempool::new(MempoolLimits::default());

    let parent = tx(11, vec![OutPoint::default()]);
    let parent_out = OutPoint::new(parent.txid(), 0);
    let child = tx(12, vec![parent_out]);

    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 1, 0))?;
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 200, 4_000, 1, 1, 0))?;

    let incremental = totals(&pool);
    pool.recompute_all_metadata();
    assert_eq!(
        incremental,
        totals(&pool),
        "a child inserted before its parent kept stale ancestor totals"
    );
    Ok(())
}

#[test]
fn full_refusal_raises_the_floor_to_the_candidate_chunk_rate() {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 1_000,
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let seated = single_output_tx(&[], Sequence::MAX, 1_001, vec![0x51, 1].into());
    pool.insert_entry(MempoolEntry::new(Arc::new(seated), 900, 90_000, 1, 7, 0))
        .expect("first fits");
    assert_eq!(pool.min_fee_sat_per_kvb(2), 0);
    let candidate = single_output_tx(&[], Sequence::MAX, 1_002, vec![0x51, 2].into());
    let refused = pool.insert_entry(MempoolEntry::new(Arc::new(candidate), 900, 10, 2, 7, 0));
    assert!(matches!(refused, Err(MempoolError::Full)));
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.min_fee_sat_per_kvb(2), 1_011);
}

#[test]
fn remove_for_block_stamps_the_floor_for_decay_even_when_empty() {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 1_000,
        max_total_bytes: 400,
        ..MempoolLimits::default()
    });
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(1, Vec::new())),
        200,
        400,
        1,
        1,
        0,
    ))
    .expect("low");
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(2, Vec::new())),
        200,
        800,
        1,
        1,
        0,
    ))
    .expect("high");
    crate::eviction::evict_lowest_fee_packages(&mut pool, 200).expect("eviction");
    assert_eq!(pool.min_fee_sat_per_kvb(1_000), 3_000);
    pool.remove_for_block(&[], &[], 8, 1_000);
    assert_eq!(pool.min_fee_sat_per_kvb(1_000 + 12 * 60 * 60), 1_500);
}

#[test]
fn expire_removes_stale_root_with_descendants() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let parent = tx(41, Vec::new());
    let parent_txid = parent.txid();
    let child = tx(42, vec![OutPoint::new(parent_txid, 0)]);
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 1, 0))
        .expect("parent");
    pool.insert_entry(MempoolEntry::new(
        Arc::new(child),
        100,
        1_000,
        crate::policy::MEMPOOL_EXPIRY_SECS,
        1,
        0,
    ))
    .expect("child");
    let now = crate::policy::MEMPOOL_EXPIRY_SECS + 1;
    assert!(pool.has_expired_entries(now));
    let expired = pool.expire(now);
    assert_eq!(expired.len(), 2);
    assert!(
        expired.changes.iter().all(|change| matches!(
            change.outcome,
            crate::mutation::MutationOutcome::Removed(crate::RemovalReason::Expiry)
        )),
        "every expiry change is tagged Expiry: {expired:?}"
    );
    assert!(pool.is_empty());
    let sequence = pool.sequence_number();
    assert!(pool.expire(now).is_empty());
    assert_eq!(pool.sequence_number(), sequence);
}

#[test]
fn expire_keeps_entry_at_cutoff() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let now = crate::policy::MEMPOOL_EXPIRY_SECS + 1;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(43, Vec::new())),
        100,
        1_000,
        1,
        1,
        0,
    ))
    .expect("at cutoff");
    assert!(!pool.has_expired_entries(now));
    assert!(pool.expire(now).is_empty());
    assert_eq!(pool.len(), 1);
}

#[test]
fn expire_keeps_a_recycled_slot_with_a_fresh_timestamp() {
    let mut pool = Mempool::new(MempoolLimits::default());
    let old = Arc::new(tx(51, Vec::new()));
    let old_txid = old.txid();
    pool.insert_entry(MempoolEntry::new(Arc::clone(&old), 100, 1_000, 0, 1, 0))
        .expect("old");
    let recycled = pool.entry_id_by_txid(&old_txid).expect("old id resolves");
    pool.remove_for_block(&[old.as_ref()], &[old_txid], 1, 1);
    let now = crate::policy::MEMPOOL_EXPIRY_SECS + 1;
    let fresh = Arc::new(tx(52, Vec::new()));
    let fresh_txid = fresh.txid();
    pool.insert_entry(MempoolEntry::new(Arc::clone(&fresh), 100, 1_000, now, 1, 0))
        .expect("fresh");
    assert_eq!(
        pool.entry_id_by_txid(&fresh_txid),
        Some(recycled),
        "the vacated slot is reused"
    );
    assert!(!pool.has_expired_entries(now));
    assert!(pool.expire(now).is_empty());
    assert!(pool.contains_txid(&fresh_txid));
    assert_eq!(pool.len(), 1);
}

#[test]
fn has_expired_entries_false_when_empty_or_cleared() {
    let mut pool = Mempool::new(MempoolLimits::default());
    assert!(!pool.has_expired_entries(crate::policy::MEMPOOL_EXPIRY_SECS + 1));
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx(44, Vec::new())),
        100,
        1_000,
        0,
        1,
        0,
    ))
    .expect("stale");
    assert!(pool.has_expired_entries(crate::policy::MEMPOOL_EXPIRY_SECS + 1));
    pool.clear();
    assert!(!pool.has_expired_entries(crate::policy::MEMPOOL_EXPIRY_SECS + 1));
}

fn single_output_tx(
    previous_outputs: &[OutPoint],
    sequence: Sequence,
    value: u64,
    script_pubkey: Script,
) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: previous_outputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: Script::new(),
                sequence,
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }],
    }
}

fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: previous_outputs
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000 + u64::from(label)),
            script_pubkey: vec![label].into(),
        }],
    }
}
