//! History-based fee-rate estimator modelled on Bitcoin Core's
//! `CBlockPolicyEstimator` but simplified.
//!
//! Maintains exponentially-spaced fee-rate buckets and records, per bucket,
//! how many blocks transactions waited before confirmation.
//! [`FeeEstimator::estimate`] returns the lowest fee rate whose historical
//! confirmation success rate clears a threshold, or [`None`] when there is
//! insufficient data.

use alloc::vec::Vec;

use bitcoin_rs_primitives::Txid;
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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeeRate(u64);

impl FeeRate {
    /// Returns the fee rate in sat/kvB.
    #[must_use]
    pub const fn as_sat_per_kvb(self) -> u64 {
        self.0
    }
}

/// Why a persisted estimator-history payload was not adopted.
/// CONTRACT: docs/policies/db-migration.md — every rejection degrades to
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryReject {
    /// Leading magic bytes are not the estimator's.
    BadMagic,
    /// The format version is not one this build reads.
    UnknownVersion(u32),
    /// Truncated, carries trailing bytes, or disagrees with the layout this
    /// build computes: drifted bucket bounds, non-finite or negative
    /// counts, out-of-range indexes, or impossible entry counts.
    Corrupt,
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
    resolved_through: usize,
}

/// History-based fee estimator with exponential buckets and per-block decay.
#[derive(Debug)]
pub struct FeeEstimator {
    buckets: Vec<Bucket>,
    /// Height whose decay has already been applied, so a repeated
    /// notification for it does not age the history a second time.
    last_decayed_height: Option<u32>,
    pending: HashMap<Txid, PendingEntry>,
    /// Heights at which tracked txids were recorded as confirmed.
    confirmed_at: HashMap<Txid, u32>,
}

impl FeeEstimator {
    /// Creates a new estimator with precomputed fee-rate buckets and no data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: build_buckets(),
            pending: HashMap::new(),
            last_decayed_height: None,
            confirmed_at: HashMap::new(),
        }
    }

    /// Records that a transaction entered the mempool.
    pub fn tx_entered(&mut self, txid: Txid, fee_rate_sat_per_kvb: u64, height: u32) {
        if self.pending.contains_key(&txid) {
            return;
        }
        if self.pending.len() >= MAX_PENDING_ENTRIES {
            return;
        }
        let bucket_index = self.bucket_index_for_rate(fee_rate_sat_per_kvb);
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
    pub fn tx_left(&mut self, txid: &Txid) {
        self.pending.remove(txid);
    }

    /// Records confirmations from a connected block and applies decay.
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
            if self.confirmed_at.get(txid) == Some(&block_height) {
                self.pending.remove(txid);
                continue;
            }
            if let Some(entry) = self.pending.remove(txid) {
                self.confirmed_at.insert(*txid, block_height);
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
        let prune_window = u32::try_from(MAX_CONF_TARGET).unwrap_or(u32::MAX);
        self.confirmed_at.retain(|_, confirmed_height| {
            block_height.saturating_sub(*confirmed_height) <= prune_window
        });
    }

    /// Samples a failure for every target that expired on this block.
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

    /// Returns the last height whose decay was applied, or `None` before the
    /// first `block_connected` call. A connected block ages the estimator even
    /// when it confirms nothing the pool tracked, so this is the observable
    /// proof that `block_connected` fired.
    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn last_decayed_height(&self) -> Option<u32> {
        self.last_decayed_height
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
            for target in entry.resolved_through..MAX_CONF_TARGET {
                bucket.resolved_within[target] += 1.0;
            }
            return;
        }
        for target in entry.resolved_through.saturating_add(1)..waited {
            bucket.resolved_within[target - 1] += 1.0;
        }
        for target in waited..=MAX_CONF_TARGET {
            bucket.confirmed_within[target - 1] += 1.0;
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

    /// Encodes the estimator's recoverable state for the owner-local
    /// history file. Deterministic: the same state produces the same bytes.
    #[must_use]
    pub fn to_history_bytes(&self) -> Vec<u8> {
        history_codec::encode(self)
    }

    /// Decodes a history payload written by [`Self::to_history_bytes`].
    pub(crate) fn from_history_bytes(bytes: &[u8]) -> Result<Self, HistoryReject> {
        history_codec::decode(bytes)
    }
}
impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Owner-local persistence of the estimator's recoverable state.
/// CONTRACT: docs/policies/db-migration.md — the format carries an
mod history_codec {
    use super::{
        Bucket, FeeEstimator, HistoryReject, MAX_CONF_TARGET, MAX_PENDING_ENTRIES, PendingEntry,
        build_buckets,
    };
    use alloc::vec::Vec;
    use bitcoin_rs_primitives::Txid;
    use hashbrown::HashMap;

    /// Magic prefix of every version-1 history payload.
    pub(super) const HISTORY_MAGIC: [u8; 8] = *b"BRSEFEES";
    /// Estimator-owned format version; bumped only for a format change.
    pub(super) const HISTORY_VERSION: u32 = 1;
    /// Decode-side bound on confirmation records. Runtime state is bounded
    /// by the prune window; this gate only stops a hostile payload from
    /// naming billions of entries before any work is believed.
    const MAX_CONFIRMED_RECORDS: usize = 1_000_000;

    /// Sequential little-endian reader over a trusted-length byte slice.
    struct Reader<'a> {
        bytes: &'a [u8],
    }

    impl<'a> Reader<'a> {
        fn take(&mut self, len: usize) -> Result<&'a [u8], HistoryReject> {
            if self.bytes.len() < len {
                return Err(HistoryReject::Corrupt);
            }
            let (head, tail) = self.bytes.split_at(len);
            self.bytes = tail;
            Ok(head)
        }

        fn u8(&mut self) -> Result<u8, HistoryReject> {
            Ok(self.take(1)?[0])
        }

        fn u32_le(&mut self) -> Result<u32, HistoryReject> {
            let raw: [u8; 4] = self
                .take(4)?
                .try_into()
                .map_err(|_| HistoryReject::Corrupt)?;
            Ok(u32::from_le_bytes(raw))
        }

        fn u64_le(&mut self) -> Result<u64, HistoryReject> {
            let raw: [u8; 8] = self
                .take(8)?
                .try_into()
                .map_err(|_| HistoryReject::Corrupt)?;
            Ok(u64::from_le_bytes(raw))
        }

        fn counts<const N: usize>(&mut self) -> Result<[f64; N], HistoryReject> {
            let raw = self.take(N * 8)?;
            let (chunks, remainder) = raw.as_chunks::<8>();
            if !remainder.is_empty() {
                return Err(HistoryReject::Corrupt);
            }
            let mut out = [0.0_f64; N];
            for (slot, chunk) in out.iter_mut().zip(chunks) {
                let value = f64::from_le_bytes(*chunk);
                if !value.is_finite() || value < 0.0 {
                    return Err(HistoryReject::Corrupt);
                }
                *slot = value;
            }
            Ok(out)
        }

        fn txid(&mut self) -> Result<Txid, HistoryReject> {
            let raw: [u8; 32] = self
                .take(32)?
                .try_into()
                .map_err(|_| HistoryReject::Corrupt)?;
            Ok(Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&raw)))
        }

        fn finish(&self) -> Result<(), HistoryReject> {
            if self.bytes.is_empty() {
                Ok(())
            } else {
                Err(HistoryReject::Corrupt)
            }
        }
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_counts<const N: usize>(out: &mut Vec<u8>, counts: &[f64; N]) {
        for count in counts {
            out.extend_from_slice(&count.to_le_bytes());
        }
    }

    /// Encodes the estimator state with txids in sorted order, so the same
    /// state always produces the same bytes.
    pub(super) fn encode(est: &FeeEstimator) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HISTORY_MAGIC);
        push_u32(&mut out, HISTORY_VERSION);
        match est.last_decayed_height {
            Some(height) => {
                out.push(1);
                out.extend_from_slice(&height.to_le_bytes());
            }
            None => out.push(0),
        }
        push_u32(
            &mut out,
            u32::try_from(est.buckets.len()).unwrap_or(u32::MAX),
        );
        for bucket in &est.buckets {
            out.extend_from_slice(&bucket.fee_rate_sat_per_kvb.to_le_bytes());
            push_counts(&mut out, &bucket.confirmed_within);
            push_counts(&mut out, &bucket.resolved_within);
        }
        let mut pending: Vec<_> = est.pending.iter().collect();
        pending.sort_unstable_by_key(|(txid, _)| **txid);
        push_u32(&mut out, u32::try_from(pending.len()).unwrap_or(u32::MAX));
        for (txid, entry) in pending {
            out.extend_from_slice(txid.as_bytes());
            push_u32(
                &mut out,
                u32::try_from(entry.bucket_index).unwrap_or(u32::MAX),
            );
            out.extend_from_slice(&entry.entry_height.to_le_bytes());
            push_u32(
                &mut out,
                u32::try_from(entry.resolved_through).unwrap_or(u32::MAX),
            );
        }
        let mut confirmed: Vec<_> = est.confirmed_at.iter().collect();
        confirmed.sort_unstable_by_key(|(txid, _)| **txid);
        push_u32(&mut out, u32::try_from(confirmed.len()).unwrap_or(u32::MAX));
        for (txid, height) in confirmed {
            out.extend_from_slice(txid.as_bytes());
            out.extend_from_slice(&height.to_le_bytes());
        }
        out
    }

    /// Decodes a version-1 payload, rejecting anything this build cannot
    /// interpret exactly.
    pub(super) fn decode(bytes: &[u8]) -> Result<FeeEstimator, HistoryReject> {
        let mut reader = Reader { bytes };
        if reader.take(HISTORY_MAGIC.len())? != HISTORY_MAGIC {
            return Err(HistoryReject::BadMagic);
        }
        let version = reader.u32_le()?;
        if version != HISTORY_VERSION {
            return Err(HistoryReject::UnknownVersion(version));
        }
        let last_decayed_height = match reader.u8()? {
            0 => None,
            1 => Some(reader.u32_le()?),
            _ => return Err(HistoryReject::Corrupt),
        };
        let bucket_count = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
        let mut buckets = Vec::new();
        for _ in 0..bucket_count {
            let fee_rate_sat_per_kvb = reader.u64_le()?;
            let confirmed_within = reader.counts::<MAX_CONF_TARGET>()?;
            let resolved_within = reader.counts::<MAX_CONF_TARGET>()?;
            buckets.push(Bucket {
                fee_rate_sat_per_kvb,
                confirmed_within,
                resolved_within,
            });
        }
        let expected = build_buckets();
        if buckets.len() != expected.len()
            || buckets
                .iter()
                .zip(expected.iter())
                .any(|(bucket, expected_bucket)| {
                    bucket.fee_rate_sat_per_kvb != expected_bucket.fee_rate_sat_per_kvb
                })
        {
            return Err(HistoryReject::Corrupt);
        }
        let pending_count = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
        if pending_count > MAX_PENDING_ENTRIES {
            return Err(HistoryReject::Corrupt);
        }
        let mut pending = HashMap::new();
        for _ in 0..pending_count {
            let txid = reader.txid()?;
            let bucket_index = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
            let entry_height = reader.u32_le()?;
            let resolved_through = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
            if bucket_index >= buckets.len() || resolved_through > MAX_CONF_TARGET {
                return Err(HistoryReject::Corrupt);
            }
            pending.insert(
                txid,
                PendingEntry {
                    bucket_index,
                    entry_height,
                    resolved_through,
                },
            );
        }
        let confirmed_count = reader.u32_le()?.try_into().unwrap_or(usize::MAX);
        if confirmed_count > MAX_CONFIRMED_RECORDS {
            return Err(HistoryReject::Corrupt);
        }
        let mut confirmed_at = HashMap::new();
        for _ in 0..confirmed_count {
            let txid = reader.txid()?;
            let height = reader.u32_le()?;
            confirmed_at.insert(txid, height);
        }
        reader.finish()?;
        Ok(FeeEstimator {
            buckets,
            last_decayed_height,
            pending,
            confirmed_at,
        })
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
#[expect(clippy::expect_used)]
mod tests {
    use super::{history_codec::HISTORY_MAGIC, *};
    use bitcoin_rs_primitives::Hash256;

    fn test_txid(n: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Txid(Hash256::from_le_bytes(&bytes))
    }

    /// A txid spread over more than 256 values, for the capacity test.
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

    /// Fresh arrivals must not be counted as failures.
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

    /// Re-announcing a transaction must not restart its clock.
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

    /// Departures must free capacity, or the estimator wedges.
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

    /// Sums every recorded success across all buckets and targets.
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

    /// A confirmation at or below the high-water height records the
    /// observation without advancing or re-decaying the estimator.
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

    /// Every payload shape the version-1 decoder must refuse. Offsets follow
    /// the layout magic(8) version(4) height-flag(1) bucket-count(4) buckets.
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
}
