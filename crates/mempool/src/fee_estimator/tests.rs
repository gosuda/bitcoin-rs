use super::{history_codec::HISTORY_MAGIC, *};
use bitcoin_rs_primitives::Hash256;

fn test_txid(n: u8) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    Txid(Hash256::from_le_bytes(&bytes))
}

fn wide_txid(n: u32) -> Txid {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    Txid(Hash256::from_le_bytes(&bytes))
}

fn assert_estimator_state_eq(left: &FeeEstimator, right: &FeeEstimator) {
    assert_eq!(left.last_decayed_height, right.last_decayed_height);
    assert_eq!(left.buckets.len(), right.buckets.len());
    for (left_bucket, right_bucket) in left.buckets.iter().zip(&right.buckets) {
        assert_eq!(
            left_bucket.fee_rate_sat_per_kvb,
            right_bucket.fee_rate_sat_per_kvb
        );
        assert_eq!(left_bucket.confirmed_within, right_bucket.confirmed_within);
        assert_eq!(left_bucket.resolved_within, right_bucket.resolved_within);
    }

    assert_eq!(left.pending.len(), right.pending.len());
    for (txid, left_entry) in &left.pending {
        let Some(right_entry) = right.pending.get(txid) else {
            panic!("pending transaction {txid} is missing from the comparison state");
        };
        assert_eq!(left_entry.bucket_index, right_entry.bucket_index);
        assert_eq!(left_entry.entry_height, right_entry.entry_height);
        assert_eq!(left_entry.resolved_through, right_entry.resolved_through);
    }
}

fn estimator_at_height_105_with_pending(pending_txid: Txid) -> FeeEstimator {
    let mut estimator = FeeEstimator::new();
    for n in 0..10_u8 {
        estimator.tx_entered(test_txid(n), 2_000, 100);
    }
    let confirmed: Vec<Txid> = (0..10_u8).map(test_txid).collect();
    estimator.block_connected(&confirmed, 101);
    estimator.block_connected(&[], 102);
    estimator.block_connected(&[], 103);
    estimator.tx_entered(pending_txid, 500_000, 103);
    estimator.block_connected(&[], 104);
    estimator.block_connected(&[], 105);
    estimator
}

#[test]
fn skipped_height_jump_matches_sequential_empty_notifications() {
    let mut sequential = FeeEstimator::new();
    let mut jumped = FeeEstimator::new();
    let final_txid = test_txid(200);
    let pending_txid = test_txid(201);

    for estimator in [&mut sequential, &mut jumped] {
        for n in 0..10_u8 {
            estimator.tx_entered(test_txid(n), 2_000, 100);
        }
        let confirmed: Vec<Txid> = (0..10_u8).map(test_txid).collect();
        estimator.block_connected(&confirmed, 101);
        estimator.tx_entered(final_txid, 500_000, 101);
        estimator.tx_entered(pending_txid, 100_000, 101);
    }

    sequential.block_connected(&[], 102);
    sequential.block_connected(&[], 103);
    sequential.block_connected(&[], 104);
    sequential.block_connected(&[final_txid], 105);
    jumped.block_connected(&[final_txid], 105);

    assert_estimator_state_eq(&jumped, &sequential);
    assert!(!jumped.pending.contains_key(&final_txid));
    let Some(pending) = jumped.pending.get(&pending_txid) else {
        panic!("the unconfirmed transaction must remain pending");
    };
    assert_eq!(pending.resolved_through, 4);

    let bucket_index = jumped.bucket_index_for_rate(500_000);
    assert_eq!(
        jumped.buckets[bucket_index].confirmed_within[3].to_bits(),
        DECAY_FACTOR.to_bits(),
        "the final-height sample must receive only the final block's decay"
    );
    assert_eq!(
        jumped.buckets[bucket_index].resolved_within[3].to_bits(),
        DECAY_FACTOR.to_bits(),
        "the final-height denominator must receive only the final block's decay"
    );
}

#[test]
fn a_burst_of_fresh_arrivals_does_not_erase_a_good_estimate() {
    let mut est = FeeEstimator::new();
    for n in 0..10_u8 {
        est.tx_entered(test_txid(n), 10_000, 100);
    }
    let confirmed: Vec<Txid> = (0..10_u8).map(test_txid).collect();
    est.block_connected(&confirmed, 101);
    let before = est.estimate(1);
    assert!(
        before.is_some(),
        "ten one-block confirmations must estimate"
    );

    for n in 100..200_u32 {
        est.tx_entered(wide_txid(n), 10_000, 101);
    }
    assert_eq!(
        est.estimate(1),
        before,
        "transactions that have not yet had a block cannot be failures"
    );
}

#[test]
fn a_repeated_admission_keeps_the_original_entry_height() {
    let mut est = FeeEstimator::new();
    let txid = test_txid(1);
    est.tx_entered(txid, 10_000, 100);
    est.tx_entered(txid, 10_000, 105);

    let Some(entry) = est.pending.get(&txid) else {
        panic!("the transaction must still be tracked");
    };
    assert_eq!(
        entry.entry_height, 100,
        "the second admission must not reset the clock"
    );
}

#[test]
fn a_departure_frees_capacity_for_new_transactions() {
    let mut est = FeeEstimator::new();
    for n in 0..u32::try_from(MAX_PENDING_ENTRIES).unwrap_or(u32::MAX) {
        est.tx_entered(wide_txid(n), 10_000, 100);
    }
    assert_eq!(
        est.pending.len(),
        MAX_PENDING_ENTRIES,
        "the map must be full"
    );

    let fresh = wide_txid(999_999);
    est.tx_entered(fresh, 10_000, 100);
    assert!(
        !est.pending.contains_key(&fresh),
        "a full map must refuse, or this test proves nothing"
    );

    est.tx_left(&wide_txid(0));
    est.tx_entered(fresh, 10_000, 100);
    assert!(
        est.pending.contains_key(&fresh),
        "a departure must free the slot it occupied"
    );
}

#[test]
fn a_confirmation_after_skipped_heights_records_the_targets_it_missed() {
    let mut est = FeeEstimator::new();
    let txid = test_txid(5);
    est.tx_entered(txid, 10_000, 100);
    est.block_connected(&[txid], 105);

    let bucket_index = est.bucket_index_for_rate(10_000);
    for target_idx in 0..4 {
        assert!(
            est.buckets[bucket_index].resolved_within[target_idx] > 0.5,
            "target {} was missed and must be sampled as resolved",
            target_idx + 1
        );
        assert!(
            est.buckets[bucket_index].confirmed_within[target_idx] < 1e-9,
            "target {} must not count as a success",
            target_idx + 1
        );
    }
    assert!(
        est.buckets[bucket_index].confirmed_within[4] > 0.5,
        "the five-block target is the first this confirmation satisfies"
    );
}

#[test]
fn a_repeated_height_notification_decays_the_history_once() {
    let mut once = FeeEstimator::new();
    let mut twice = FeeEstimator::new();
    for est in [&mut once, &mut twice] {
        for n in 0..10_u8 {
            est.tx_entered(test_txid(n), 10_000, 100);
        }
        let confirmed: Vec<Txid> = (0..10_u8).map(test_txid).collect();
        est.block_connected(&confirmed, 101);
    }
    for _ in 0..4 {
        twice.block_connected(&[], 101);
    }

    let bucket_index = once.bucket_index_for_rate(10_000);
    assert!(
        (twice.buckets[bucket_index].confirmed_within[0]
            - once.buckets[bucket_index].confirmed_within[0])
            .abs()
            < 1e-9,
        "repeating a height must not age the history: {} against {}",
        twice.buckets[bucket_index].confirmed_within[0],
        once.buckets[bucket_index].confirmed_within[0]
    );
}

#[test]
fn a_target_resolves_once_when_a_height_is_processed_twice() {
    let bucket_index = {
        let est = FeeEstimator::new();
        est.bucket_index_for_rate(10_000)
    };

    let mut once = FeeEstimator::new();
    let txid = test_txid(3);
    once.tx_entered(txid, 10_000, 100);
    once.block_connected(&[], 101);
    once.block_connected(&[txid], 102);

    let mut twice = FeeEstimator::new();
    twice.tx_entered(txid, 10_000, 100);
    twice.block_connected(&[], 101);
    twice.block_connected(&[], 102);
    twice.block_connected(&[txid], 102);

    let target_idx = 1;
    assert!(
        twice.buckets[bucket_index].resolved_within[target_idx]
            <= once.buckets[bucket_index].resolved_within[target_idx] + 1e-9,
        "one transaction must resolve the two-block target once, not twice: \
             {} against {}",
        twice.buckets[bucket_index].resolved_within[target_idx],
        once.buckets[bucket_index].resolved_within[target_idx]
    );
}

#[test]
fn no_data_yields_none() {
    let est = FeeEstimator::new();
    assert!(est.estimate(1).is_none());
    assert!(est.estimate(6).is_none());
    assert!(est.estimate(25).is_none());
}

#[test]
fn low_fee_confirms_quickly_yields_low_estimate() {
    let mut est = FeeEstimator::new();
    for i in 0..10 {
        est.tx_entered(test_txid(i), 2_000, 100);
    }
    for i in 10..20 {
        est.tx_entered(test_txid(i), 100_000, 100);
    }
    let confirmed: Vec<Txid> = (0..20).map(test_txid).collect();
    est.block_connected(&confirmed, 101);
    let result = est.estimate(1).expect("should have an estimate");
    assert!(
        result.as_sat_per_kvb() <= 3_000,
        "estimate should be low, got {} sat/kvB",
        result.as_sat_per_kvb()
    );
}

#[test]
fn never_confirms_yields_none() {
    let mut est = FeeEstimator::new();
    for i in 0..10 {
        est.tx_entered(test_txid(i), 5_000, 100);
    }
    assert!(est.estimate(1).is_none());
}

#[test]
fn decay_reduces_influence_of_old_data() {
    let mut est = FeeEstimator::new();
    for i in 0..10 {
        est.tx_entered(test_txid(i), 5_000, 100);
    }
    let confirmed: Vec<Txid> = (0..10).map(test_txid).collect();
    est.block_connected(&confirmed, 101);
    assert!(
        est.estimate(1).is_some(),
        "should have estimate before decay"
    );
    for height in 102..6_102 {
        est.block_connected(&[], height);
    }
    assert!(
        est.estimate(1).is_none(),
        "estimate should be None after heavy decay"
    );
}

fn total_confirmations(est: &FeeEstimator) -> f64 {
    est.buckets
        .iter()
        .flat_map(|bucket| bucket.confirmed_within.iter())
        .sum()
}

#[test]
#[allow(
    clippy::float_cmp,
    reason = "confirmation counts are small integers, exact in f64; exact accounting is the assertion"
)]
fn reconnect_of_the_same_block_does_not_double_count_a_confirmation() {
    let mut est = FeeEstimator::new();
    est.tx_entered(test_txid(1), 2_000, 100);
    est.block_connected(&[test_txid(1)], 105);
    let after_first_connect = total_confirmations(&est);
    assert!(after_first_connect > 0.0, "the confirmation must record");

    est.tx_entered(test_txid(1), 2_000, 104);
    est.block_connected(&[test_txid(1)], 105);

    assert_eq!(
        total_confirmations(&est),
        after_first_connect,
        "a re-connected block must untrack its txids without a second success"
    );
    assert!(
        !est.pending.contains_key(&test_txid(1)),
        "the re-confirmed transaction must still leave the pending set"
    );
}

#[test]
#[allow(
    clippy::float_cmp,
    reason = "confirmation counts are small integers, exact in f64; exact accounting is the assertion"
)]
fn confirmation_at_a_new_height_after_a_disconnect_records_exactly_once() {
    let mut est = FeeEstimator::new();
    est.tx_entered(test_txid(1), 2_000, 100);
    est.block_connected(&[test_txid(1)], 101);

    est.tx_entered(test_txid(1), 2_000, 100);
    est.block_connected(&[test_txid(1)], 103);

    let mut twin = FeeEstimator::new();
    twin.tx_entered(test_txid(1), 2_000, 100);
    twin.block_connected(&[test_txid(1)], 101);
    twin.tx_entered(test_txid(2), 2_000, 100);
    twin.block_connected(&[test_txid(2)], 103);
    assert_eq!(
        total_confirmations(&est),
        total_confirmations(&twin),
        "the reorged re-confirmation must weigh exactly one fresh observation"
    );
}

#[test]
fn non_advancing_height_confirmation_records_without_decay() {
    for (case, tag, height) in [
        ("duplicate height", 210, 105_u32),
        ("backward height", 211, 104),
    ] {
        let txid = test_txid(tag);
        let mut actual = estimator_at_height_105_with_pending(txid);
        let mut expected = estimator_at_height_105_with_pending(txid);

        let Some(entry) = expected.pending.remove(&txid) else {
            panic!("{case} confirmation must start pending");
        };
        expected.record_confirmation(&entry, height.saturating_sub(entry.entry_height).max(1));
        actual.block_connected(&[txid], height);

        assert_estimator_state_eq(&actual, &expected);
        assert_eq!(actual.last_decayed_height, Some(105), "{case}");
    }
}

#[test]
fn confirmation_records_expire_with_the_target_window() {
    let mut est = FeeEstimator::new();
    est.tx_entered(test_txid(1), 2_000, 100);
    est.block_connected(&[test_txid(1)], 105);
    assert!(!est.confirmed_at.is_empty());

    for height in 106..=105 + 26 {
        est.block_connected(&[], height);
    }
    assert!(
        est.confirmed_at.is_empty(),
        "stale confirmation records must prune as heights advance"
    );
}

#[test]
fn history_round_trip_preserves_state_and_estimates() {
    let mut est = estimator_at_height_105_with_pending(test_txid(200));
    est.tx_entered(test_txid(201), 700_000, 105);
    let confirmed: Vec<Txid> = (0..3).map(wide_txid).collect();
    est.block_connected(&confirmed, 110);

    let bytes = est.to_history_bytes();
    let restored =
        FeeEstimator::from_history_bytes(&bytes).expect("the encoder's own bytes must decode");
    assert_estimator_state_eq(&est, &restored);
    assert_eq!(est.confirmed_at, restored.confirmed_at);
    for target in 1..=u32::try_from(MAX_CONF_TARGET).unwrap_or(u32::MAX) {
        assert_eq!(est.estimate(target), restored.estimate(target));
    }
}

#[test]
fn history_encoding_is_deterministic() {
    let est = estimator_at_height_105_with_pending(test_txid(200));
    assert_eq!(est.to_history_bytes(), est.to_history_bytes());
}

#[test]
fn history_rejects_every_corrupt_payload_shape() {
    let base = FeeEstimator::new().to_history_bytes();
    let patch = |offset: usize, bytes: &[u8]| {
        let mut out = base.clone();
        out[offset..offset + bytes.len()].copy_from_slice(bytes);
        out
    };
    let first_bound = HISTORY_MAGIC.len() + 4 + 1 + 4;
    let bucket_bytes = 8 + 2 * MAX_CONF_TARGET * 8;
    let pending_offset = first_bound + bucket_bytes * build_buckets().len();
    let mut truncated = base.clone();
    truncated.pop();
    let mut trailing = base.clone();
    trailing.push(0);

    for (case, bytes, expected) in [
        ("bad magic", patch(0, b"X"), HistoryReject::BadMagic),
        (
            "unknown version",
            patch(HISTORY_MAGIC.len(), &[99]),
            HistoryReject::UnknownVersion(99),
        ),
        ("truncated", truncated, HistoryReject::Corrupt),
        ("trailing byte", trailing, HistoryReject::Corrupt),
        (
            "non-finite confirmed count",
            patch(first_bound + 8, &f64::NAN.to_le_bytes()),
            HistoryReject::Corrupt,
        ),
        (
            "drifted bucket bound",
            patch(first_bound, &7_u64.to_le_bytes()),
            HistoryReject::Corrupt,
        ),
        (
            "impossible pending count",
            patch(pending_offset, &u32::MAX.to_le_bytes()),
            HistoryReject::Corrupt,
        ),
    ] {
        assert_eq!(
            FeeEstimator::from_history_bytes(&bytes).err(),
            Some(expected),
            "{case}"
        );
    }
}
