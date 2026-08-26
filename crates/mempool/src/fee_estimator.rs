//! History-based fee-rate estimator modelled on Bitcoin Core's
//! `CBlockPolicyEstimator` but simplified.
//!
//! Maintains exponentially-spaced fee-rate buckets and records, per bucket,
//! how many blocks transactions waited before confirmation.
//! [`FeeEstimator::estimate`] returns the lowest fee rate whose historical
//! confirmation success rate clears a threshold, or [`None`] when there is
//! insufficient data.

use alloc::vec::Vec;

use bitcoin::Txid;
use hashbrown::HashMap;

/// Bucket fee-rate growth numerator: each bucket's lower bound is 5% above
/// the previous (`lower * 105 / 100`).
const BUCKET_GROWTH_NUM: u64 = 105;
/// Bucket fee-rate growth denominator.
const BUCKET_GROWTH_DEN: u64 = 100;
/// Minimum tracked fee rate: 1 sat/vB = 1 000 sat/kvB.
const MIN_FEE_RATE_SAT_PER_KVB: u64 = 1_000;
/// Maximum tracked fee rate: 1 000 sat/vB = 1 000 000 sat/kvB.
const MAX_FEE_RATE_SAT_PER_KVB: u64 = 1_000_000;
/// Maximum confirmation-target horizon in blocks.
const MAX_CONF_TARGET: usize = 25;
/// A bucket is suggested when >= 85% of historical transactions at or above
/// its fee rate confirmed within the target.
const SUCCESS_THRESHOLD: f64 = 0.85;
/// Per-block decay factor applied to all bucket counts.
const DECAY_FACTOR: f64 = 0.998;
/// Minimum decayed observation count required before producing an estimate.
const MIN_OBSERVATIONS: f64 = 1.0;
/// Maximum number of pending (unconfirmed) transaction entries tracked.
const MAX_PENDING_ENTRIES: usize = 10_000;

/// Fee rate in satoshis per kilo-virtual-byte (sat/kvB).
///
/// One sat/vB equals 1 000 sat/kvB. This unit matches
/// [`MempoolEntry`](crate::MempoolEntry).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeeRate(u64);

impl FeeRate {
    /// Returns the fee rate in sat/kvB.
    #[must_use]
    pub const fn as_sat_per_kvb(self) -> u64 {
        self.0
    }

    /// Returns the fee rate in sat/vB (truncated toward zero).
    #[must_use]
    pub const fn as_sat_per_vb(self) -> u64 {
        self.0 / 1_000
    }
}

/// Per-bucket confirmation statistics.
#[derive(Debug)]
struct Bucket {
    /// Lower-bound fee rate for this bucket (sat/kvB).
    fee_rate_sat_per_kvb: u64,
    /// Decayed count of transactions confirmed within N blocks
    /// (index 0 = 1 block, index 24 = 25 blocks).
    confirmed_within: [f64; MAX_CONF_TARGET],
    /// Decayed count of transactions RESOLVED for each target: confirmed
    /// within it, or still unconfirmed once it expired.
    ///
    /// One denominator per target rather than one for all of them. A single
    /// count incremented on entry made every pending transaction an immediate
    /// failure at every target, so two fresh arrivals could drop ten prior
    /// one-block successes to 10/12 and silence the estimator before either
    /// arrival had missed anything.
    ///
    /// Sampling at resolution also fixes the decay. The numerator and the
    /// denominator now enter together and decay from the same block, where
    /// before the denominator had been decaying since entry while the
    /// confirmation arrived fresh, reporting 81 successes out of 100 as
    /// roughly 85%.
    resolved_within: [f64; MAX_CONF_TARGET],
}

impl Bucket {
    /// Creates a zeroed bucket at the given fee-rate lower bound.
    const fn new(fee_rate_sat_per_kvb: u64) -> Self {
        Self {
            fee_rate_sat_per_kvb,
            confirmed_within: [0.0; MAX_CONF_TARGET],
            resolved_within: [0.0; MAX_CONF_TARGET],
        }
    }
}

/// Metadata for a pending (unconfirmed) transaction.
#[derive(Debug)]
struct PendingEntry {
    /// Index into `buckets`.
    bucket_index: usize,
    /// Block height at which the transaction entered the mempool.
    entry_height: u32,
    /// Highest target already sampled for this transaction, 0 for none.
    ///
    /// Carried per entry rather than derived from the height, so the sampling
    /// cannot double-count or skip. Deriving it would assume `block_connected`
    /// is called exactly once for every height, and a skipped or repeated call
    /// would then lose failures or record them twice.
    resolved_through: usize,
}

/// History-based fee estimator with exponential buckets and per-block decay.
///
/// Call [`FeeEstimator::tx_entered`] when a transaction enters the mempool
/// and [`FeeEstimator::block_connected`] for each connected block. Then use
/// [`FeeEstimator::estimate`] to obtain a fee-rate estimate for a given
/// confirmation target.
#[derive(Debug)]
pub struct FeeEstimator {
    buckets: Vec<Bucket>,
    /// Height whose decay has already been applied, so a repeated
    /// notification for it does not age the history a second time.
    last_decayed_height: Option<u32>,
    pending: HashMap<Txid, PendingEntry>,
}

impl FeeEstimator {
    /// Creates a new estimator with precomputed fee-rate buckets and no data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: build_buckets(),
            pending: HashMap::new(),
            last_decayed_height: None,
        }
    }

    /// Records that a transaction entered the mempool.
    ///
    /// Call this when a transaction is accepted into the mempool.
    /// `fee_rate_sat_per_kvb` is the effective fee rate
    /// (fee / vsize * 1 000). `height` is the current block height.
    pub fn tx_entered(&mut self, txid: Txid, fee_rate_sat_per_kvb: u64, height: u32) {
        // A second admission of the same txid must not reset its clock. It is
        // the same transaction waiting since the same height, and overwriting
        // the entry would make it look freshly arrived every time a caller
        // re-announced it.
        if self.pending.contains_key(&txid) {
            return;
        }
        if self.pending.len() >= MAX_PENDING_ENTRIES {
            return;
        }
        let bucket_index = self.bucket_index_for_rate(fee_rate_sat_per_kvb);
        // No denominator here. A transaction that just arrived has not missed
        // any target yet; it is sampled as each target resolves.
        self.pending.insert(
            txid,
            PendingEntry {
                bucket_index,
                entry_height: height,
                resolved_through: 0,
            },
        );
    }

    /// Records that a transaction left the mempool without confirming.
    ///
    /// Call this on eviction, replacement, or any other departure. Without it
    /// the pending map only ever shrinks on confirmation, so departures
    /// accumulate until the `MAX_PENDING_ENTRIES` guard silently drops every
    /// future transaction and the estimator is stuck forever.
    ///
    /// Untracks only. No failure is recorded, matching Core's
    /// `removeTx(hash, inBlock = false)`: an eviction or a replacement says
    /// something about the mempool, not about whether the transaction would
    /// have confirmed by any deadline. Real misses are sampled by
    /// `expire_targets` as each target passes.
    pub fn tx_left(&mut self, txid: &Txid) {
        self.pending.remove(txid);
    }

    /// Records confirmations from a connected block and applies decay.
    ///
    /// Call this for each connected block. `confirmed_txids` are the txids of
    /// transactions confirmed in that block. `block_height` is the height of
    /// the connected block. Transactions not tracked by the estimator are
    /// silently ignored.
    pub fn block_connected(&mut self, confirmed_txids: &[Txid], block_height: u32) {
        let advances_height = match self.last_decayed_height {
            Some(last_height) => block_height > last_height,
            None => true,
        };

        if let Some(last_height) = self.last_decayed_height
            && advances_height
        {
            for skipped_height in last_height.saturating_add(1)..block_height {
                self.advance_height(skipped_height);
            }
        }

        for txid in confirmed_txids {
            if let Some(entry) = self.pending.remove(txid) {
                let blocks_waited = block_height.saturating_sub(entry.entry_height).max(1);
                self.record_confirmation(&entry, blocks_waited);
            }
        }

        if advances_height {
            self.advance_height(block_height);
        }
    }

    /// Expires targets and decays observations for one newly reached height.
    fn advance_height(&mut self, block_height: u32) {
        self.expire_targets(block_height);
        self.last_decayed_height = Some(block_height);
        self.apply_decay();
    }

    /// Samples a failure for every target that expired on this block.
    ///
    /// Blocks arrive one at a time, so a transaction crosses exactly one target
    /// boundary per block: the one whose window equals how long it has now
    /// waited. Targets it has already outlived were sampled on earlier blocks.
    ///
    /// A transaction that outlives the longest target is dropped. It can no
    /// longer affect any estimate, and keeping it would fill the pending map.
    fn expire_targets(&mut self, block_height: u32) {
        let mut outlived = Vec::new();
        for (txid, entry) in &mut self.pending {
            let waited = usize::try_from(block_height.saturating_sub(entry.entry_height))
                .unwrap_or(usize::MAX)
                .min(MAX_CONF_TARGET);
            while entry.resolved_through < waited {
                self.buckets[entry.bucket_index].resolved_within[entry.resolved_through] += 1.0;
                entry.resolved_through += 1;
            }
            if entry.resolved_through == MAX_CONF_TARGET {
                outlived.push(*txid);
            }
        }
        for txid in outlived {
            self.pending.remove(&txid);
        }
    }

    /// Estimates the minimum fee rate for confirmation within
    /// `conf_target_blocks`.
    ///
    /// Returns the lowest fee-rate bucket whose historical success rate at
    /// the given confirmation target clears the threshold (0.85), or [`None`]
    /// when there is insufficient data. A [`None`] result is an honest
    /// refusal — a fabricated estimate is worse than no estimate.
    #[must_use]
    pub fn estimate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        let target = usize::try_from(conf_target_blocks)
            .unwrap_or(0)
            .min(MAX_CONF_TARGET);
        if target == 0 {
            return None;
        }
        let target_idx = target - 1;
        let mut cumulative_confirmed = 0.0_f64;
        let mut cumulative_total = 0.0_f64;
        let mut result = None;
        for bucket in self.buckets.iter().rev() {
            cumulative_confirmed += bucket.confirmed_within[target_idx];
            cumulative_total += bucket.resolved_within[target_idx];
            if cumulative_total >= MIN_OBSERVATIONS {
                let success_rate = cumulative_confirmed / cumulative_total;
                if success_rate >= SUCCESS_THRESHOLD {
                    result = Some(FeeRate(bucket.fee_rate_sat_per_kvb));
                }
            }
        }
        result
    }

    /// Returns the bucket index for a fee rate: the highest bucket whose
    /// lower bound is <= the given rate. Rates below the first bucket clamp
    /// to index 0.
    fn bucket_index_for_rate(&self, fee_rate_sat_per_kvb: u64) -> usize {
        let idx = self
            .buckets
            .partition_point(|b| b.fee_rate_sat_per_kvb <= fee_rate_sat_per_kvb);
        idx.saturating_sub(1)
    }

    /// Records a confirmation, incrementing all targets >= `blocks_waited`.
    fn record_confirmation(&mut self, entry: &PendingEntry, blocks_waited: u32) {
        let bucket_index = entry.bucket_index;
        let waited = usize::try_from(blocks_waited).unwrap_or(0);
        if waited == 0 {
            return;
        }
        let bucket = &mut self.buckets[bucket_index];
        if waited > MAX_CONF_TARGET {
            // Confirmed past the longest target, so it missed every one of
            // them. Reachable only when heights were skipped, because
            // `expire_targets` drops a transaction once it outlives the last
            // target. Dropping the evidence outright would let a slow
            // confirmation cost the estimator nothing.
            for target in entry.resolved_through..MAX_CONF_TARGET {
                bucket.resolved_within[target] += 1.0;
            }
            return;
        }
        // Targets shorter than `waited` were missed. `expire_targets` samples
        // those as they pass, but it never sees this transaction again once the
        // confirmation removes it, so any target that expired since the last
        // call — every one of them if heights were skipped — has to be sampled
        // here. Without this a transaction entering at 100 and confirming in a
        // call for 105 contributes successes to targets 5 and up and no
        // failures to 1 through 4, biasing the short targets upward.
        for target in entry.resolved_through.saturating_add(1)..waited {
            bucket.resolved_within[target - 1] += 1.0;
        }
        // Confirming at `waited` blocks satisfies every target from `waited`
        // up, and resolves each of them at the same moment, so numerator and
        // denominator decay together from here.
        //
        // Shorter targets are not touched: this transaction missed them, and
        // `expire_targets` already sampled those failures on the blocks where
        // they expired.
        for target in waited..=MAX_CONF_TARGET {
            bucket.confirmed_within[target - 1] += 1.0;
            // Only targets not already sampled as failures, so a late
            // confirmation cannot resolve a target twice.
            if target > entry.resolved_through {
                bucket.resolved_within[target - 1] += 1.0;
            }
        }
    }

    /// Applies the per-block decay factor to all bucket counts.
    fn apply_decay(&mut self) {
        for bucket in &mut self.buckets {
            for count in &mut bucket.confirmed_within {
                *count *= DECAY_FACTOR;
            }
            for count in &mut bucket.resolved_within {
                *count *= DECAY_FACTOR;
            }
        }
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the exponentially-spaced fee-rate buckets.
fn build_buckets() -> Vec<Bucket> {
    let mut buckets = Vec::new();
    let mut lower = MIN_FEE_RATE_SAT_PER_KVB;
    while lower <= MAX_FEE_RATE_SAT_PER_KVB {
        buckets.push(Bucket::new(lower));
        let next = lower.saturating_mul(BUCKET_GROWTH_NUM) / BUCKET_GROWTH_DEN;
        if next <= lower {
            break;
        }
        lower = next;
    }
    buckets
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn test_txid(n: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Txid::from_byte_array(bytes)
    }

    /// A txid spread over more than 256 values, for the capacity test.
    fn wide_txid(n: u32) -> Txid {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        Txid::from_byte_array(bytes)
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
    fn duplicate_height_confirmation_does_not_advance_or_decay() {
        let txid = test_txid(210);
        let mut actual = estimator_at_height_105_with_pending(txid);
        let mut expected = estimator_at_height_105_with_pending(txid);

        let Some(entry) = expected.pending.remove(&txid) else {
            panic!("the duplicate-height confirmation must start pending");
        };
        expected.record_confirmation(&entry, 105_u32.saturating_sub(entry.entry_height).max(1));
        actual.block_connected(&[txid], 105);

        assert_estimator_state_eq(&actual, &expected);
        assert_eq!(actual.last_decayed_height, Some(105));
    }

    #[test]
    fn backward_height_confirmation_does_not_lower_high_water_or_decay() {
        let txid = test_txid(211);
        let mut actual = estimator_at_height_105_with_pending(txid);
        let mut expected = estimator_at_height_105_with_pending(txid);

        let Some(entry) = expected.pending.remove(&txid) else {
            panic!("the backward-height confirmation must start pending");
        };
        expected.record_confirmation(&entry, 104_u32.saturating_sub(entry.entry_height).max(1));
        actual.block_connected(&[txid], 104);

        assert_estimator_state_eq(&actual, &expected);
        assert_eq!(actual.last_decayed_height, Some(105));
    }

    /// Fresh arrivals must not be counted as failures.
    ///
    /// The old denominator was incremented on entry and used for every target,
    /// so a burst of pending transactions erased a good estimate before any of
    /// them had missed anything.
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

        // A hundred transactions that arrived this instant and have missed
        // nothing at all.
        for n in 100..200_u32 {
            est.tx_entered(wide_txid(n), 10_000, 101);
        }
        assert_eq!(
            est.estimate(1),
            before,
            "transactions that have not yet had a block cannot be failures"
        );
    }

    /// Re-announcing a transaction must not restart its clock.
    #[test]
    fn a_repeated_admission_keeps_the_original_entry_height() {
        let mut est = FeeEstimator::new();
        let txid = test_txid(1);
        est.tx_entered(txid, 10_000, 100);
        // Same txid, five blocks later, as a duplicate announcement would.
        est.tx_entered(txid, 10_000, 105);

        let Some(entry) = est.pending.get(&txid) else {
            panic!("the transaction must still be tracked");
        };
        assert_eq!(
            entry.entry_height, 100,
            "the second admission must not reset the clock"
        );
    }

    /// Departures must free capacity, or the estimator wedges.
    ///
    /// The pending map only ever shrank on confirmation, so evicted and
    /// replaced transactions accumulated until the guard silently ignored
    /// every future transaction.
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

    /// A confirmation after skipped heights must still record its misses.
    ///
    /// `expire_targets` samples a miss as each target passes, but it never sees
    /// the transaction again once the confirmation removes it. If heights were
    /// skipped, every target that expired in the gap has to be sampled by the
    /// confirmation itself.
    #[test]
    fn a_confirmation_after_skipped_heights_records_the_targets_it_missed() {
        let mut est = FeeEstimator::new();
        let txid = test_txid(5);
        est.tx_entered(txid, 10_000, 100);
        // Five blocks elapse but only one notification arrives, carrying the
        // confirmation. Targets 1 through 4 were missed.
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

    /// Decay models elapsed blocks, so one height decays once.
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
        // The same height announced four more times.
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

    /// A target resolves once, even if the same height is processed twice.
    ///
    /// `block_connected` is public and takes the height from its caller, so
    /// nothing structurally prevents it being called twice for one height. When
    /// that happens the first call expires a target and the second confirms
    /// against the same one, and without the guard both would land in the
    /// denominator for a single transaction.
    #[test]
    fn a_target_resolves_once_when_a_height_is_processed_twice() {
        let bucket_index = {
            let est = FeeEstimator::new();
            est.bucket_index_for_rate(10_000)
        };

        // Reference run: the height is processed once, the normal case.
        let mut once = FeeEstimator::new();
        let txid = test_txid(3);
        once.tx_entered(txid, 10_000, 100);
        once.block_connected(&[], 101);
        once.block_connected(&[txid], 102);

        // Same sequence, but height 102 arrives twice: once with no
        // confirmation, then again carrying it.
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
}
