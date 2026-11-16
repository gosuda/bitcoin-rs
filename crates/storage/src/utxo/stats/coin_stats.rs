use alloc::sync::Arc;

use crate::utxo::snapshot::{SnapshotCoin, SnapshotCoinObserver};
use bitcoin_rs_consensus::primitives::{OutPoint, TxOut, varint};
use parking_lot::Mutex;
use rayon::prelude::*;
use zerocopy::IntoBytes;

use crate::utxo::stats::MuHash3072;

const OUTPOINT_BYTES: usize = 36;
const COIN_HEADER_BYTES: u64 = 4;
const AMOUNT_BYTES: u64 = 8;
const AMOUNT_ENCODED_BYTES: usize = 8;
const SCRIPT_LEN_BYTES: u64 = 2;
const FIXED_BOGO_SIZE: u64 = 36 + COIN_HEADER_BYTES + AMOUNT_BYTES + SCRIPT_LEN_BYTES;
pub(crate) const PARALLEL_COIN_BATCH_OP_THRESHOLD: usize = 1024;
const PARALLEL_MUHASH_MAX_COINS: usize = 262_144;
const PARALLEL_MUHASH_MAX_BYTES: usize = 16 * 1024 * 1024;
const PARALLEL_MUHASH_MAX_LANES: usize = 32;

/// Exact byte length of the stable `CoinStats` encoding.
pub const COIN_STATS_ENCODED_LEN: usize = 804;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CoinStatsRewindError {
    #[error("coinstats are at height {found}, not the disconnected height {expected}")]
    HeightMismatch { expected: u32, found: u32 },
    #[error("rewind of {tx_delta} transactions exceeds the recorded count {tx_count}")]
    TxCountUnderflow { tx_count: u64, tx_delta: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinStats {
    pub muhash: MuHash3072,
    pub height: u32,
    /// Sum of live output values in satoshis.
    pub total_amount: u64,
    pub bogo_size: u64,
    pub tx_count: u64,
    pub utxo_count: u64,
}

impl CoinStats {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            muhash: MuHash3072::new(),
            height: 0,
            total_amount: 0,
            bogo_size: 0,
            tx_count: 0,
            utxo_count: 0,
        }
    }

    pub fn insert_utxo(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        let encoded = coin_hash_bytes(op, txout, height, coinbase);
        self.muhash.insert(&encoded);
        self.account_insert(txout);
    }

    fn account_insert(&mut self, txout: &TxOut) {
        self.total_amount = self.total_amount.saturating_add(txout.value.to_sat());
        self.bogo_size = self.bogo_size.saturating_add(bogo_size(txout));
        self.utxo_count = self.utxo_count.saturating_add(1);
    }

    pub fn remove_utxo(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        let encoded = coin_hash_bytes(op, txout, height, coinbase);
        self.muhash.remove(&encoded);
        self.account_remove(txout);
    }

    fn account_remove(&mut self, txout: &TxOut) {
        self.total_amount = self.total_amount.saturating_sub(txout.value.to_sat());
        self.bogo_size = self.bogo_size.saturating_sub(bogo_size(txout));
        self.utxo_count = self.utxo_count.saturating_sub(1);
    }

    pub const fn finish_block(&mut self, height: u32, tx_delta: u64) {
        self.height = height;
        self.tx_count = self.tx_count.saturating_add(tx_delta);
    }

    pub(crate) fn rewind_block(
        &mut self,
        disconnected_height: u32,
        parent_height: u32,
        tx_delta: u64,
    ) -> Result<(), CoinStatsRewindError> {
        self.tx_count = self.check_rewind(disconnected_height, tx_delta)?;
        self.height = parent_height;
        Ok(())
    }

    pub(crate) fn check_rewind(
        &self,
        disconnected_height: u32,
        tx_delta: u64,
    ) -> Result<u64, CoinStatsRewindError> {
        if self.height != disconnected_height {
            return Err(CoinStatsRewindError::HeightMismatch {
                expected: disconnected_height,
                found: self.height,
            });
        }
        self.tx_count
            .checked_sub(tx_delta)
            .ok_or(CoinStatsRewindError::TxCountUnderflow {
                tx_count: self.tx_count,
                tx_delta,
            })
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COIN_STATS_ENCODED_LEN);
        out.extend_from_slice(&self.muhash.numerator_bytes());
        out.extend_from_slice(&self.muhash.denominator_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.total_amount.to_le_bytes());
        out.extend_from_slice(&self.bogo_size.to_le_bytes());
        out.extend_from_slice(&self.tx_count.to_le_bytes());
        out.extend_from_slice(&self.utxo_count.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoinStatsDecodeError> {
        let mut cursor = 0;
        let numerator = read_array::<384>(bytes, &mut cursor)?;
        let denominator = read_array::<384>(bytes, &mut cursor)?;
        let height = u32::from_le_bytes(read_array::<4>(bytes, &mut cursor)?);
        let total_amount = u64::from_le_bytes(read_array::<8>(bytes, &mut cursor)?);
        let bogo_size = u64::from_le_bytes(read_array::<8>(bytes, &mut cursor)?);
        let tx_count = u64::from_le_bytes(read_array::<8>(bytes, &mut cursor)?);
        let utxo_count = u64::from_le_bytes(read_array::<8>(bytes, &mut cursor)?);
        if cursor != bytes.len() {
            return Err(CoinStatsDecodeError::TrailingBytes);
        }
        Ok(Self {
            muhash: MuHash3072::from_parts(&numerator, &denominator),
            height,
            total_amount,
            bogo_size,
            tx_count,
            utxo_count,
        })
    }
}

impl Default for CoinStats {
    fn default() -> Self {
        Self::new()
    }
}

pub fn scan_coin_stats(
    view: &crate::utxo::UtxoSetView<'_>,
    height: u32,
    want_muhash: bool,
) -> Result<CoinStats, crate::utxo::UtxoError> {
    let mut accumulator = new_accumulator(height, want_muhash);
    view.for_each_coin(|coin| accumulator.observe_coin(coin))?;
    Ok(accumulator.into_stats())
}

pub fn scan_coin_stats_cancellable(
    view: &crate::utxo::UtxoSetView<'_>,
    height: u32,
    want_muhash: bool,
    cancelled: &dyn Fn() -> bool,
) -> Result<CoinStats, crate::utxo::UtxoError> {
    let mut accumulator = new_accumulator(height, want_muhash);
    view.for_each_coin_cancellable(|coin| accumulator.observe_coin(coin), cancelled)?;
    Ok(accumulator.into_stats())
}

fn new_accumulator(height: u32, want_muhash: bool) -> CoinStatsAccumulator {
    if want_muhash {
        CoinStatsAccumulator::with_muhash(height)
    } else {
        CoinStatsAccumulator::without_muhash(height)
    }
}

#[derive(Debug)]
pub struct CoinStatsAccumulator {
    stats: CoinStats,
    mode: MuHashMode,
}

#[derive(Debug)]
enum MuHashMode {
    Disabled,
    Serial(Vec<u8>),
    Parallel(EncodedPreimageArena),
}

#[derive(Debug)]
struct EncodedPreimageArena {
    bytes: Vec<u8>,
    ends: Vec<usize>,
}

impl EncodedPreimageArena {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(PARALLEL_MUHASH_MAX_BYTES),
            ends: Vec::with_capacity(PARALLEL_MUHASH_MAX_COINS),
        }
    }

    fn push(&mut self, coin: SnapshotCoin<'_>) {
        let op = OutPoint::new(coin.txid.into(), coin.vout);
        coin_hash_bytes_raw_append(
            &mut self.bytes,
            &op,
            coin.value,
            coin.script_pubkey,
            coin.height,
            coin.coinbase,
        );
        self.ends.push(self.bytes.len());
    }

    fn should_flush_before(&self, script_len: usize) -> bool {
        !self.ends.is_empty()
            && (self.ends.len() == PARALLEL_MUHASH_MAX_COINS
                || coin_hash_encoded_len(script_len)
                    > PARALLEL_MUHASH_MAX_BYTES.saturating_sub(self.bytes.len()))
    }

    fn flush_into(&mut self, muhash: &mut MuHash3072) {
        if self.ends.is_empty() {
            return;
        }
        if self.ends.len() < PARALLEL_COIN_BATCH_OP_THRESHOLD {
            for index in 0..self.ends.len() {
                let start = if index == 0 { 0 } else { self.ends[index - 1] };
                muhash.insert(&self.bytes[start..self.ends[index]]);
            }
        } else {
            let lane_count = self
                .ends
                .len()
                .min(PARALLEL_MUHASH_MAX_LANES)
                .min(rayon::current_num_threads());
            let lane_len = self.ends.len().div_ceil(lane_count);
            let partials: Vec<_> = (0..lane_count)
                .into_par_iter()
                .map(|lane| {
                    let first = lane * lane_len;
                    let last = (first + lane_len).min(self.ends.len());
                    let mut partial = MuHash3072::new();
                    for index in first..last {
                        let start = if index == 0 { 0 } else { self.ends[index - 1] };
                        partial.insert(&self.bytes[start..self.ends[index]]);
                    }
                    partial
                })
                .collect();
            for partial in partials {
                muhash.combine_numerator(&partial);
            }
        }
        self.bytes.clear();
        self.ends.clear();
    }
}

impl CoinStatsAccumulator {
    #[must_use]
    pub(crate) fn with_muhash(height: u32) -> Self {
        Self::new(height, MuHashMode::Serial(Vec::new()))
    }

    #[must_use]
    pub fn with_parallel_muhash(height: u32) -> Self {
        Self::new(height, MuHashMode::Parallel(EncodedPreimageArena::new()))
    }

    #[must_use]
    pub(crate) fn without_muhash(height: u32) -> Self {
        Self::new(height, MuHashMode::Disabled)
    }

    fn new(height: u32, mode: MuHashMode) -> Self {
        let mut stats = CoinStats::new();
        stats.height = height;
        Self { stats, mode }
    }

    fn flush_parallel_muhash(&mut self) {
        if let MuHashMode::Parallel(arena) = &mut self.mode {
            arena.flush_into(&mut self.stats.muhash);
        }
    }

    #[must_use]
    pub fn into_stats(mut self) -> CoinStats {
        self.flush_parallel_muhash();
        self.stats
    }
}

impl SnapshotCoinObserver for CoinStatsAccumulator {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        self.stats.total_amount = self.stats.total_amount.saturating_add(coin.value);
        let script_len = u64::try_from(coin.script_pubkey.len()).unwrap_or(u64::MAX);
        self.stats.bogo_size = self
            .stats
            .bogo_size
            .saturating_add(FIXED_BOGO_SIZE.saturating_add(script_len));
        self.stats.utxo_count = self.stats.utxo_count.saturating_add(1);
        match &mut self.mode {
            MuHashMode::Disabled => {}
            MuHashMode::Serial(scratch) => {
                let op = OutPoint::new(coin.txid.into(), coin.vout);
                coin_hash_bytes_raw_into(
                    scratch,
                    &op,
                    coin.value,
                    coin.script_pubkey,
                    coin.height,
                    coin.coinbase,
                );
                self.stats.muhash.insert(scratch);
            }
            MuHashMode::Parallel(arena) => {
                let encoded_len = coin_hash_encoded_len(coin.script_pubkey.len());
                if encoded_len > PARALLEL_MUHASH_MAX_BYTES {
                    arena.flush_into(&mut self.stats.muhash);
                    let mut preimage = Vec::with_capacity(encoded_len);
                    let op = OutPoint::new(coin.txid.into(), coin.vout);
                    coin_hash_bytes_raw_append(
                        &mut preimage,
                        &op,
                        coin.value,
                        coin.script_pubkey,
                        coin.height,
                        coin.coinbase,
                    );
                    self.stats.muhash.insert(&preimage);
                    return;
                }
                if arena.should_flush_before(coin.script_pubkey.len()) {
                    arena.flush_into(&mut self.stats.muhash);
                }
                arena.push(coin);
                if arena.ends.len() == PARALLEL_MUHASH_MAX_COINS
                    || arena.bytes.len() == PARALLEL_MUHASH_MAX_BYTES
                {
                    arena.flush_into(&mut self.stats.muhash);
                }
            }
        }
    }

    fn select_trailer(&mut self, fallback: [u8; 384]) -> [u8; 384] {
        self.flush_parallel_muhash();
        match &self.mode {
            MuHashMode::Disabled => fallback,
            MuHashMode::Serial(_) | MuHashMode::Parallel(_) => self.stats.muhash.finalize(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoinStatsDecodeError {
    #[error("coinstats row is truncated")]
    Truncated,
    #[error("coinstats row has trailing bytes")]
    TrailingBytes,
}

#[derive(Clone, Debug)]
pub struct CoinStatsListener {
    state: Arc<Mutex<CoinStatsListenerState>>,
}

#[derive(Debug)]
struct CoinStatsListenerState {
    stats: CoinStats,
}

impl CoinStatsListener {
    #[must_use]
    pub fn new(stats: CoinStats) -> Self {
        Self {
            state: Arc::new(Mutex::new(CoinStatsListenerState { stats })),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> CoinStats {
        self.state.lock().stats.clone()
    }

    pub fn reset(&self, stats: CoinStats) {
        let mut guard = self.state.lock();
        guard.stats = stats;
    }

    pub fn insert_utxo(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.state
            .lock()
            .stats
            .insert_utxo(op, txout, height, coinbase);
    }

    pub fn remove_utxo(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.state
            .lock()
            .stats
            .remove_utxo(op, txout, height, coinbase);
    }

    pub(crate) fn apply_utxos<'a>(
        &self,
        updates: impl IntoIterator<Item = (bool, &'a OutPoint, &'a TxOut, u32, bool)>,
    ) {
        let mut guard = self.state.lock();
        let stats = &mut guard.stats;
        let mut encoded = Vec::new();
        for (insert, op, txout, height, coinbase) in updates {
            coin_hash_bytes_into(&mut encoded, op, txout, height, coinbase);
            if insert {
                stats.muhash.insert(&encoded);
                stats.account_insert(txout);
            } else {
                stats.muhash.remove(&encoded);
                stats.account_remove(txout);
            }
        }
    }

    pub fn finish_block(&self, height: u32, tx_delta: u64) {
        self.state.lock().stats.finish_block(height, tx_delta);
    }

    pub fn rewind_block(
        &self,
        disconnected_height: u32,
        parent_height: u32,
        tx_delta: u64,
    ) -> Result<(), CoinStatsRewindError> {
        self.state
            .lock()
            .stats
            .rewind_block(disconnected_height, parent_height, tx_delta)
    }

    pub fn check_rewind(
        &self,
        disconnected_height: u32,
        tx_delta: u64,
    ) -> Result<(), CoinStatsRewindError> {
        self.state
            .lock()
            .stats
            .check_rewind(disconnected_height, tx_delta)
            .map(|_| ())
    }

    pub(crate) fn muhash3072(&self) -> [u8; 384] {
        self.state.lock().stats.muhash.finalize()
    }
}

fn coin_hash_bytes(op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(coin_hash_capacity(txout));
    coin_hash_bytes_into(&mut out, op, txout, height, coinbase);
    out
}

fn coin_hash_capacity(txout: &TxOut) -> usize {
    OUTPOINT_BYTES + 4 + txout.script_pubkey.len() + 16
}

#[inline]
fn coin_hash_bytes_into(
    out: &mut Vec<u8>,
    op: &OutPoint,
    txout: &TxOut,
    height: u32,
    coinbase: bool,
) {
    coin_hash_bytes_raw_into(
        out,
        op,
        txout.value.to_sat(),
        txout.script_pubkey.as_slice(),
        height,
        coinbase,
    );
}

fn coin_hash_bytes_raw_into(
    out: &mut Vec<u8>,
    op: &OutPoint,
    value: u64,
    script_pubkey: &[u8],
    height: u32,
    coinbase: bool,
) {
    out.clear();
    coin_hash_bytes_raw_append(out, op, value, script_pubkey, height, coinbase);
}

fn coin_hash_bytes_raw_append(
    out: &mut Vec<u8>,
    op: &OutPoint,
    value: u64,
    script_pubkey: &[u8],
    height: u32,
    coinbase: bool,
) {
    out.extend_from_slice(op.as_bytes());
    let coinbase_bit = u32::from(coinbase);
    out.extend_from_slice(&((height << 1) | coinbase_bit).to_le_bytes());
    encode_value_and_script_into(out, value, script_pubkey);
}

#[cfg(test)]
#[inline]
fn encode_txout_into(out: &mut Vec<u8>, txout: &TxOut) {
    encode_value_and_script_into(out, txout.value.to_sat(), txout.script_pubkey.as_slice());
}

#[inline]
fn encode_value_and_script_into(out: &mut Vec<u8>, value: u64, script_pubkey: &[u8]) {
    out.extend_from_slice(&value.to_le_bytes());
    let script_len = u64::try_from(script_pubkey.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(varint::encode(script_len).as_slice());
    out.extend_from_slice(script_pubkey);
}

#[inline]
fn bogo_size(txout: &TxOut) -> u64 {
    let script_len = u64::try_from(txout.script_pubkey.len()).unwrap_or(u64::MAX);
    FIXED_BOGO_SIZE.saturating_add(script_len)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], CoinStatsDecodeError> {
    let end = cursor
        .checked_add(N)
        .ok_or(CoinStatsDecodeError::Truncated)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(CoinStatsDecodeError::Truncated)?;
    let mut out = [0_u8; N];
    out.copy_from_slice(slice);
    *cursor = end;
    Ok(out)
}

#[inline]
fn coin_hash_encoded_len(script_len: usize) -> usize {
    OUTPOINT_BYTES
        .saturating_add(4)
        .saturating_add(AMOUNT_ENCODED_BYTES)
        .saturating_add(varint::encoded_len(
            u64::try_from(script_len).unwrap_or(u64::MAX),
        ))
        .saturating_add(script_len)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use crate::utxo::{SnapshotCoin, SnapshotCoinObserver};
    use bitcoin::{Amount, ScriptBuf};
    use proptest::prelude::*;

    use super::{CoinStats, CoinStatsRewindError, TxOut, encode_txout_into};

    #[test]
    fn manual_txout_encoding_matches_consensus_boundaries() {
        for len in [0_usize, 1, 252, 253, 65_535, 65_536] {
            let value = 50_000 + u64::try_from(len).unwrap_or(u64::MAX);
            let script = vec![0x51; len];
            let txout = TxOut {
                value: bitcoin_rs_consensus::primitives::Amount::from_sat(value),
                script_pubkey: script.clone().into(),
            };
            let mut manual = Vec::new();
            encode_txout_into(&mut manual, &txout);
            let bitcoin_txout = bitcoin::TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(script),
            };
            let consensus = bitcoin::consensus::encode::serialize(&bitcoin_txout);
            assert_eq!(manual, consensus, "script len {len}");
        }
    }

    #[test]
    fn scan_coin_stats_matches_rolling_listener() {
        use crate::utxo::UtxoSet;
        use bitcoin_rs_consensus::primitives::{Hash256, OutPoint};

        let utxo = UtxoSet::new();
        let mut stats = super::CoinStats::new();
        for (i, script_len) in [0_usize, 1, 252, 253, 65_535].into_iter().enumerate() {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes[0] = u8::try_from(i + 1).unwrap_or(u8::MAX);
            let txid = Hash256::from_le_bytes(&txid_bytes);
            let output = OutPoint::new(txid.into(), u32::MAX);
            let txout = TxOut {
                value: bitcoin_rs_consensus::primitives::Amount::from_sat(if i == 4 {
                    u64::MAX
                } else {
                    u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(100_000)
                }),
                script_pubkey: vec![0x51; script_len].into(),
            };
            let coinbase = i % 2 == 1;
            let height = if i == 4 {
                u32::MAX >> 1
            } else {
                u32::try_from(i).unwrap_or(u32::MAX)
            };
            stats.insert_utxo(&output, &txout, height, coinbase);
            let out = crate::utxo::record::OwnedUtxoOut {
                vout: output.vout,
                value: txout.value.to_sat(),
                script_pubkey: txout.script_pubkey.to_vec(),
                coinbase,
                height,
            };
            let record = crate::utxo::record::UtxoRecord::from_owned_outputs(txid, &[out])
                .unwrap_or_else(|err| panic!("record failed: {err}"));
            utxo.insert_parsed_record(record);
        }
        let listener = super::CoinStatsListener::new(stats);
        let rolling = listener.snapshot();
        let (scanned, accumulated, without_muhash) = utxo.with_stable_view(|view| {
            let scanned = super::scan_coin_stats(view, rolling.height, true)
                .unwrap_or_else(|err| panic!("scan_coin_stats failed: {err}"));
            let mut accumulated = super::CoinStatsAccumulator::with_muhash(rolling.height);
            let mut without_muhash = super::CoinStatsAccumulator::without_muhash(rolling.height);
            view.for_each_coin(|coin| {
                accumulated.observe_coin(coin);
                without_muhash.observe_coin(coin);
            })
            .unwrap_or_else(|err| panic!("coin traversal failed: {err}"));
            (
                scanned,
                accumulated.into_stats(),
                without_muhash.into_stats(),
            )
        });

        assert_eq!(accumulated, scanned, "snapshot accumulator");
        assert_eq!(scanned, rolling, "rolling listener");
        assert_eq!(without_muhash.height, scanned.height);
        assert_eq!(without_muhash.total_amount, scanned.total_amount);
        assert_eq!(without_muhash.bogo_size, scanned.bogo_size);
        assert_eq!(without_muhash.tx_count, scanned.tx_count);
        assert_eq!(without_muhash.utxo_count, scanned.utxo_count);
        assert_eq!(
            without_muhash.muhash.finalize(),
            super::MuHash3072::new().finalize(),
            "without_muhash must leave the identity accumulator"
        );
    }

    struct TestCoin {
        txid: bitcoin_rs_consensus::primitives::Hash256,
        vout: u32,
        value: u64,
        script_pubkey: Vec<u8>,
        height: u32,
        coinbase: bool,
    }

    fn generated_coins(count: usize, script_lens: &[usize]) -> Vec<TestCoin> {
        (0..count)
            .map(|index| {
                let mut txid = [0_u8; 32];
                txid[..8].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
                txid[8] = u8::try_from(index.rotate_left(7)).unwrap_or(u8::MAX);
                let script_len = script_lens[index % script_lens.len()];
                TestCoin {
                    txid: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&txid),
                    vout: u32::try_from(index).unwrap_or(u32::MAX),
                    value: 50_000_u64.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)),
                    script_pubkey: (0..script_len)
                        .map(|byte| u8::try_from(index.wrapping_add(byte)).unwrap_or(u8::MAX))
                        .collect(),
                    height: u32::try_from(index % 1_000).unwrap_or(u32::MAX),
                    coinbase: index % 2 == 1,
                }
            })
            .collect()
    }

    fn observe_all(accumulator: &mut super::CoinStatsAccumulator, coins: &[TestCoin]) {
        for coin in coins {
            accumulator.observe_coin(SnapshotCoin {
                txid: coin.txid,
                vout: coin.vout,
                value: coin.value,
                script_pubkey: &coin.script_pubkey,
                height: coin.height,
                coinbase: coin.coinbase,
            });
        }
    }

    fn assert_parallel_serialized_match(coins: &[TestCoin]) {
        let mut serial = super::CoinStatsAccumulator::with_muhash(77);
        let mut parallel = super::CoinStatsAccumulator::with_parallel_muhash(77);
        observe_all(&mut serial, coins);
        observe_all(&mut parallel, coins);

        let serial_trailer = serial.select_trailer([0_u8; 384]);
        let parallel_trailer = parallel.select_trailer([0_u8; 384]);
        let serial_stats = serial.into_stats();
        let parallel_stats = parallel.into_stats();

        assert_eq!(
            parallel_trailer, serial_trailer,
            "MuHash trailer must be byte-identical"
        );
        assert_eq!(
            parallel_stats.to_bytes(),
            serial_stats.to_bytes(),
            "CoinStats serialized form must be byte-identical despite noncanonical intermediate limbs"
        );
    }

    #[test]
    fn parallel_muhash_matches_serial_at_coin_flush_boundaries() {
        for count in [
            0,
            1,
            super::PARALLEL_COIN_BATCH_OP_THRESHOLD - 1,
            super::PARALLEL_COIN_BATCH_OP_THRESHOLD,
            super::PARALLEL_COIN_BATCH_OP_THRESHOLD + 1,
            super::PARALLEL_MUHASH_MAX_COINS - 1,
            super::PARALLEL_MUHASH_MAX_COINS,
            super::PARALLEL_MUHASH_MAX_COINS + 1,
        ] {
            assert_parallel_serialized_match(&generated_coins(count, &[0, 1, 252, 253]));
        }
    }

    #[test]
    fn parallel_muhash_matches_serial_at_byte_flush_boundaries() {
        let script_len = 2_048;
        let encoded_len = super::coin_hash_encoded_len(script_len);
        let exact_count = super::PARALLEL_MUHASH_MAX_BYTES / encoded_len;
        for count in [exact_count - 1, exact_count, exact_count + 1] {
            assert_parallel_serialized_match(&generated_coins(count, &[script_len]));
        }
    }

    #[test]
    fn parallel_muhash_flushes_oversized_preimage_and_reuses_arena() {
        let mut coins = generated_coins(1, &[3]);
        coins.extend(generated_coins(1, &[super::PARALLEL_MUHASH_MAX_BYTES + 1]));
        coins.extend(generated_coins(1, &[5]));
        coins[1].vout = 1;
        coins[2].vout = 2;
        coins[1].txid = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[1; 32]);
        coins[2].txid = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[2; 32]);
        assert_parallel_serialized_match(&coins);
    }

    #[test]
    fn parallel_muhash_matches_serial_generated_stream_and_into_stats_flush() {
        let coins = generated_coins(2_049, &[0, 1, 252, 253, 65_535]);
        assert_parallel_serialized_match(&coins);

        let mut parallel = super::CoinStatsAccumulator::with_parallel_muhash(77);
        observe_all(&mut parallel, &coins);
        let stats = parallel.into_stats();
        let mut serial = super::CoinStatsAccumulator::with_muhash(77);
        observe_all(&mut serial, &coins);
        assert_eq!(stats.to_bytes(), serial.into_stats().to_bytes());
    }

    #[test]
    fn parallel_muhash_matches_serial_at_configured_pool_widths() {
        let coins = generated_coins(2_049, &[0, 1, 252, 253, 65_535]);
        for width in [1, 4] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(width)
                .build()
                .expect("build test pool")
                .install(|| assert_parallel_serialized_match(&coins));
        }
    }

    fn proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|val| val.parse().ok())
            .unwrap_or(default_cases);
        ProptestConfig {
            cases,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(proptest_config(256))]

        #[test]
        fn parallel_muhash_differential_and_order_independence(
            count in 0_usize..=300_usize,
            script_lens in proptest::collection::vec(0_usize..=512_usize, 1..=8),
        ) {
            let coins = generated_coins(count, &script_lens);
            assert_parallel_serialized_match(&coins);

            let mut forward = super::CoinStatsAccumulator::with_muhash(77);
            observe_all(&mut forward, &coins);

            let mut reversed_coins = coins;
            reversed_coins.reverse();
            let mut reversed = super::CoinStatsAccumulator::with_muhash(77);
            observe_all(&mut reversed, &reversed_coins);

            let forward_stats = forward.into_stats();
            let reversed_stats = reversed.into_stats();
            prop_assert_eq!(
                forward_stats.muhash.finalize(),
                reversed_stats.muhash.finalize(),
                "MuHash must be order-independent"
            );
            prop_assert_eq!(forward_stats.total_amount, reversed_stats.total_amount);
            prop_assert_eq!(forward_stats.bogo_size, reversed_stats.bogo_size);
            prop_assert_eq!(forward_stats.utxo_count, reversed_stats.utxo_count);
        }

        #[test]
        fn coin_stats_rewind_algebraic_law_and_refusals(
            initial_height in 0_u32..10_000,
            initial_tx in 0_u64..1_000_000,
            tx_delta in 1_u64..10_000,
            bad_height_delta in 1_u32..100,
            excess_underflow in 1_u64..100,
        ) {
            let mut stats = CoinStats {
                height: initial_height,
                tx_count: initial_tx,
                ..Default::default()
            };
            let original = stats.clone();

            let next_height = initial_height.saturating_add(1);
            stats.finish_block(next_height, tx_delta);
            let connected = stats.clone();
            prop_assert_eq!(connected.height, next_height);
            prop_assert_eq!(connected.tx_count, initial_tx.saturating_add(tx_delta));

            let wrong_height = next_height.saturating_add(bad_height_delta);
            prop_assert_eq!(
                stats.rewind_block(wrong_height, initial_height, tx_delta),
                Err(CoinStatsRewindError::HeightMismatch {
                    expected: wrong_height,
                    found: next_height,
                })
            );
            prop_assert_eq!(&stats, &connected, "refused rewind must change nothing");

            let underflow_delta = connected.tx_count.saturating_add(excess_underflow);
            prop_assert_eq!(
                stats.rewind_block(next_height, initial_height, underflow_delta),
                Err(CoinStatsRewindError::TxCountUnderflow {
                    tx_count: connected.tx_count,
                    tx_delta: underflow_delta,
                })
            );
            prop_assert_eq!(&stats, &connected, "refused rewind must change nothing");

            prop_assert_eq!(stats.rewind_block(next_height, initial_height, tx_delta), Ok(()));
            prop_assert_eq!(&stats, &original, "rewind must invert finish_block byte-identically");
        }
    }
}
