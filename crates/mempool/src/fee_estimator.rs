use alloc::vec::Vec;

use bitcoin_rs_primitives::Txid;
use hashbrown::HashMap;

const BUCKET_GROWTH_NUM: u64 = 105;
const BUCKET_GROWTH_DEN: u64 = 100;
const MIN_FEE_RATE_SAT_PER_KVB: u64 = 1_000;
const MAX_FEE_RATE_SAT_PER_KVB: u64 = 1_000_000;
const MAX_CONF_TARGET: usize = 25;
const SUCCESS_THRESHOLD: f64 = 0.85;
const DECAY_FACTOR: f64 = 0.998;
const MIN_OBSERVATIONS: f64 = 1.0;
const MAX_PENDING_ENTRIES: usize = 10_000;

/// Fee rate in satoshis per kilo-virtual-byte (sat/kvB).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeeRate(u64);

impl FeeRate {
    #[must_use]
    pub const fn as_sat_per_kvb(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryReject {
    BadMagic,
    UnknownVersion(u32),
    Corrupt,
}

#[derive(Debug)]
struct Bucket {
    fee_rate_sat_per_kvb: u64,
    confirmed_within: [f64; MAX_CONF_TARGET],
    resolved_within: [f64; MAX_CONF_TARGET],
}

impl Bucket {
    const fn new(fee_rate_sat_per_kvb: u64) -> Self {
        Self {
            fee_rate_sat_per_kvb,
            confirmed_within: [0.0; MAX_CONF_TARGET],
            resolved_within: [0.0; MAX_CONF_TARGET],
        }
    }
}

#[derive(Debug)]
struct PendingEntry {
    bucket_index: usize,
    entry_height: u32,
    resolved_through: usize,
}

#[derive(Debug)]
pub struct FeeEstimator {
    buckets: Vec<Bucket>,
    last_decayed_height: Option<u32>,
    pending: HashMap<Txid, PendingEntry>,
    confirmed_at: HashMap<Txid, u32>,
}

impl FeeEstimator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: build_buckets(),
            pending: HashMap::new(),
            last_decayed_height: None,
            confirmed_at: HashMap::new(),
        }
    }

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

    pub fn tx_left(&mut self, txid: &Txid) {
        self.pending.remove(txid);
    }

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

    fn advance_height(&mut self, block_height: u32) {
        self.expire_targets(block_height);
        self.last_decayed_height = Some(block_height);
        self.apply_decay();
        let prune_window = u32::try_from(MAX_CONF_TARGET).unwrap_or(u32::MAX);
        self.confirmed_at.retain(|_, confirmed_height| {
            block_height.saturating_sub(*confirmed_height) <= prune_window
        });
    }

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

    #[must_use]
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn last_decayed_height(&self) -> Option<u32> {
        self.last_decayed_height
    }

    fn bucket_index_for_rate(&self, fee_rate_sat_per_kvb: u64) -> usize {
        let idx = self
            .buckets
            .partition_point(|b| b.fee_rate_sat_per_kvb <= fee_rate_sat_per_kvb);
        idx.saturating_sub(1)
    }

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

    #[must_use]
    pub fn to_history_bytes(&self) -> Vec<u8> {
        history_codec::encode(self)
    }

    pub(crate) fn from_history_bytes(bytes: &[u8]) -> Result<Self, HistoryReject> {
        history_codec::decode(bytes)
    }
}
impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

mod history_codec {
    use super::{
        Bucket, FeeEstimator, HistoryReject, MAX_CONF_TARGET, MAX_PENDING_ENTRIES, PendingEntry,
        build_buckets,
    };
    use alloc::vec::Vec;
    use bitcoin_rs_primitives::Txid;
    use hashbrown::HashMap;

    pub(super) const HISTORY_MAGIC: [u8; 8] = *b"BRSEFEES";
    pub(super) const HISTORY_VERSION: u32 = 1;
    const MAX_CONFIRMED_RECORDS: usize = 1_000_000;

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
mod tests;
