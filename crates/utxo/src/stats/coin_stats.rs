use alloc::sync::Arc;
use core::convert::Infallible;

use crate::{
    SnapshotCoin, SnapshotCoinObserver, UtxoChangeEvents, UtxoChangeListener, UtxoCommittedEvent,
    UtxoInserted, UtxoRemoved,
};
use bitcoin_rs_primitives::{OutPoint, TxOut};
use parking_lot::Mutex;
use rayon::prelude::*;
use smallvec::SmallVec;
use zerocopy::IntoBytes;

use crate::stats::MuHash3072;

const OUTPOINT_BYTES: usize = 36;
const COIN_HEADER_BYTES: u64 = 4;
const AMOUNT_BYTES: u64 = 8;
const AMOUNT_ENCODED_BYTES: usize = 8;
const SCRIPT_LEN_BYTES: u64 = 2;
const FIXED_BOGO_SIZE: u64 = 36 + COIN_HEADER_BYTES + AMOUNT_BYTES + SCRIPT_LEN_BYTES;
const MAX_RETAINED_SCRATCH_CAPACITY: usize = 4096;
const PARALLEL_COIN_BATCH_OP_THRESHOLD: usize = 1024;
const COIN_BATCH_CHUNK_SIZE: usize = 512;
const PARALLEL_EVENT_CHUNK_OP_THRESHOLD: usize = 64;
const WIDE_EVENT_BATCH_SHARD_THRESHOLD: usize = 16;
const NARROW_EVENT_CHUNK_SIZE: usize = 16;
const WIDE_EVENT_CHUNK_SIZE: usize = 4;
const INLINE_EVENT_CHUNKS: usize = 64;

const PARALLEL_MUHASH_MAX_COINS: usize = 262_144;
const PARALLEL_MUHASH_MAX_BYTES: usize = 16 * 1024 * 1024;
const PARALLEL_MUHASH_MAX_LANES: usize = 32;

/// Exact byte length of the stable `CoinStats` encoding.
pub const COIN_STATS_ENCODED_LEN: usize = 804;

/// Why a [`CoinStats::rewind_block`] was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CoinStatsRewindError {
    /// The stats are not at the block being disconnected.
    #[error("coinstats are at height {found}, not the disconnected height {expected}")]
    HeightMismatch {
        /// Height the caller is disconnecting.
        expected: u32,
        /// Height the stats currently record.
        found: u32,
    },
    /// The rewind would take `tx_count` below zero.
    #[error("rewind of {tx_delta} transactions exceeds the recorded count {tx_count}")]
    TxCountUnderflow {
        /// Transactions currently recorded.
        tx_count: u64,
        /// Transactions the rewind would remove.
        tx_delta: u64,
    },
}

/// Incremental UTXO set statistics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinStats {
    /// `MuHash3072` accumulator over live coins.
    pub muhash: MuHash3072,
    /// Current chain height.
    pub height: u32,
    /// Sum of live output values in satoshis.
    pub total_amount: u64,
    /// Database-independent UTXO bogo-size.
    pub bogo_size: u64,
    /// Number of transactions represented by the current stats.
    pub tx_count: u64,
    /// Number of live UTXOs.
    pub utxo_count: u64,
}

impl CoinStats {
    /// Creates empty stats.
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

    /// Applies one created UTXO.
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

    /// Applies one spent UTXO.
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

    /// Applies per-block height and transaction-count deltas.
    pub const fn finish_block(&mut self, height: u32, tx_delta: u64) {
        self.height = height;
        self.tx_count = self.tx_count.saturating_add(tx_delta);
    }

    /// Reverses one [`Self::finish_block`], for a disconnected block.
    ///
    /// Only the block-level fields. The per-coin fields (`muhash`,
    /// `total_amount`, `bogo_size`, `utxo_count`) are maintained by the
    /// `UtxoChangeListener` callbacks, which a UTXO undo already drives in
    /// reverse; touching them here would double-count.
    ///
    /// Both invariants are checked before either field moves, so a rejected
    /// rewind leaves the stats exactly as they were. Saturating arithmetic was
    /// the first version and is wrong here: it turns a second rewind of the
    /// same block into a silent clamp, which is the failure this guards.
    ///
    /// # Errors
    ///
    /// Returns an error when the stats are not at `disconnected_height`, or
    /// when `tx_delta` exceeds the recorded `tx_count`.
    pub const fn rewind_block(
        &mut self,
        disconnected_height: u32,
        parent_height: u32,
        tx_delta: u64,
    ) -> Result<(), CoinStatsRewindError> {
        if self.height != disconnected_height {
            return Err(CoinStatsRewindError::HeightMismatch {
                expected: disconnected_height,
                found: self.height,
            });
        }
        let Some(tx_count) = self.tx_count.checked_sub(tx_delta) else {
            return Err(CoinStatsRewindError::TxCountUnderflow {
                tx_count: self.tx_count,
                tx_delta,
            });
        };
        self.height = parent_height;
        self.tx_count = tx_count;
        Ok(())
    }

    /// Serializes stats in a stable byte layout.
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

    /// Decodes one exact stable `CoinStats` encoding.
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

/// Computes `CoinStats` statistics by scanning a stable view.
///
/// Matches Bitcoin Core's on-demand model (no rolling listener required).
/// `want_muhash` controls the expensive per-coin `MuHash` pass; callers needing
/// only `total_amount`/`bogo_size`/`utxo_count` pass `false`.
pub fn scan_coin_stats(
    view: &crate::UtxoSetView<'_>,
    height: u32,
    want_muhash: bool,
) -> Result<CoinStats, crate::UtxoError> {
    let mut accumulator = if want_muhash {
        CoinStatsAccumulator::with_muhash(height)
    } else {
        CoinStatsAccumulator::without_muhash(height)
    };
    view.for_each_coin(|txid, vout, value, script_pubkey, coin_height, coinbase| {
        accumulator.observe_coin(SnapshotCoin {
            txid,
            vout,
            value,
            script_pubkey,
            height: coin_height,
            coinbase,
        });
    })?;
    Ok(accumulator.into_stats())
}

/// Owned `CoinStats` fold for a snapshot coin traversal.
///
/// The accumulator borrows each script only for its callback and reuses one
/// scratch buffer for optional `MuHash` preimages.
/// Transaction count remains zero because live coins do not encode it.
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
        let op = OutPoint::new(coin.txid, coin.vout);
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
            // Rayon collects scoped jobs before returning or propagating a panic,
            // so no lane can retain arena slices after this flush.
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
    /// Creates an accumulator that derives `CoinStats` and a `MuHash` trailer.
    #[must_use]
    pub fn with_muhash(height: u32) -> Self {
        Self::new(height, MuHashMode::Serial(Vec::new()))
    }

    /// Creates an accumulator that buffers exact preimages and combines ordered
    /// insert-only partial `MuHash` values for checkpoint traversals.
    #[must_use]
    pub fn with_parallel_muhash(height: u32) -> Self {
        Self::new(height, MuHashMode::Parallel(EncodedPreimageArena::new()))
    }

    /// Creates an accumulator that derives `CoinStats` without hashing coins.
    #[must_use]
    pub fn without_muhash(height: u32) -> Self {
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

    /// Finishes the fold and returns the derived statistics.
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
                let op = OutPoint::new(coin.txid, coin.vout);
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
                    let op = OutPoint::new(coin.txid, coin.vout);
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct CoinStatsDelta {
    muhash: MuHash3072,
    added_amount: u64,
    added_bogo_size: u64,
    added_utxos: u64,
    removed_amount: u64,
    removed_bogo_size: u64,
    removed_utxos: u64,
}

impl CoinStatsDelta {
    const fn new() -> Self {
        Self {
            muhash: MuHash3072::new(),
            added_amount: 0,
            added_bogo_size: 0,
            added_utxos: 0,
            removed_amount: 0,
            removed_bogo_size: 0,
            removed_utxos: 0,
        }
    }

    fn from_insertions(insertions: &[UtxoInserted<'_>]) -> Self {
        let mut delta = Self::new();
        let mut scratch = Vec::new();
        for insertion in insertions {
            delta.insert_utxo(
                &mut scratch,
                insertion.op,
                insertion.txout,
                insertion.height,
                insertion.coinbase,
            );
        }
        delta
    }

    fn from_removals(removals: &[UtxoRemoved]) -> Self {
        let mut delta = Self::new();
        let mut scratch = Vec::new();
        for removal in removals {
            delta.remove_utxo(
                &mut scratch,
                &removal.op,
                &removal.txout,
                removal.height,
                removal.coinbase,
            );
        }
        delta
    }

    fn from_events(events: &UtxoChangeEvents<'_>) -> Self {
        let mut delta = Self::new();
        let mut scratch = Vec::new();
        events.for_each(|event| match event {
            UtxoCommittedEvent::InsertBatch(insertions) => {
                delta.insert_batch(&mut scratch, insertions);
            }
            UtxoCommittedEvent::RemoveBatch(removals) => {
                delta.remove_batch(&mut scratch, removals);
            }
        });
        delta
    }

    fn from_event(event: UtxoCommittedEvent<'_, '_>) -> Self {
        let mut delta = Self::new();
        let mut scratch = Vec::new();
        match event {
            UtxoCommittedEvent::InsertBatch(insertions) => {
                delta.insert_batch(&mut scratch, insertions);
            }
            UtxoCommittedEvent::RemoveBatch(removals) => {
                delta.remove_batch(&mut scratch, removals);
            }
        }
        delta
    }

    fn combine(mut self, other: Self) -> Self {
        let Self {
            muhash,
            added_amount,
            added_bogo_size,
            added_utxos,
            removed_amount,
            removed_bogo_size,
            removed_utxos,
        } = other;
        if added_utxos != 0 {
            self.muhash.combine_numerator(&muhash);
        }
        if removed_utxos != 0 {
            self.muhash.combine_denominator(&muhash);
        }
        self.added_amount = self.added_amount.saturating_add(added_amount);
        self.added_bogo_size = self.added_bogo_size.saturating_add(added_bogo_size);
        self.added_utxos = self.added_utxos.saturating_add(added_utxos);
        self.removed_amount = self.removed_amount.saturating_add(removed_amount);
        self.removed_bogo_size = self.removed_bogo_size.saturating_add(removed_bogo_size);
        self.removed_utxos = self.removed_utxos.saturating_add(removed_utxos);
        self
    }

    #[inline]
    fn apply_to(self, stats: &mut CoinStats) {
        match (self.added_utxos != 0, self.removed_utxos != 0) {
            (true, true) => stats.muhash.combine(&self.muhash),
            (true, false) => stats.muhash.combine_numerator(&self.muhash),
            (false, true) => stats.muhash.combine_denominator(&self.muhash),
            (false, false) => {}
        }
        stats.total_amount = stats
            .total_amount
            .saturating_add(self.added_amount)
            .saturating_sub(self.removed_amount);
        stats.bogo_size = stats
            .bogo_size
            .saturating_add(self.added_bogo_size)
            .saturating_sub(self.removed_bogo_size);
        stats.utxo_count = stats
            .utxo_count
            .saturating_add(self.added_utxos)
            .saturating_sub(self.removed_utxos);
    }

    #[inline]
    fn insert_utxo(
        &mut self,
        scratch: &mut Vec<u8>,
        op: &OutPoint,
        txout: &TxOut,
        height: u32,
        coinbase: bool,
    ) {
        coin_hash_bytes_into(scratch, op, txout, height, coinbase);
        self.muhash.insert(scratch.as_slice());
        self.added_amount = self.added_amount.saturating_add(txout.value.to_sat());
        self.added_bogo_size = self.added_bogo_size.saturating_add(bogo_size(txout));
        self.added_utxos = self.added_utxos.saturating_add(1);
    }

    fn insert_batch(&mut self, scratch: &mut Vec<u8>, insertions: &[UtxoInserted<'_>]) {
        for insertion in insertions {
            self.insert_utxo(
                scratch,
                insertion.op,
                insertion.txout,
                insertion.height,
                insertion.coinbase,
            );
        }
    }

    #[inline]
    fn remove_utxo(
        &mut self,
        scratch: &mut Vec<u8>,
        op: &OutPoint,
        txout: &TxOut,
        height: u32,
        coinbase: bool,
    ) {
        coin_hash_bytes_into(scratch, op, txout, height, coinbase);
        self.muhash.remove(scratch.as_slice());
        self.removed_amount = self.removed_amount.saturating_add(txout.value.to_sat());
        self.removed_bogo_size = self.removed_bogo_size.saturating_add(bogo_size(txout));
        self.removed_utxos = self.removed_utxos.saturating_add(1);
    }

    fn remove_batch(&mut self, scratch: &mut Vec<u8>, removals: &[UtxoRemoved]) {
        for removal in removals {
            self.remove_utxo(
                scratch,
                &removal.op,
                &removal.txout,
                removal.height,
                removal.coinbase,
            );
        }
    }
}

/// Decode error for persisted coinstats rows.
#[derive(Debug, thiserror::Error)]
pub enum CoinStatsDecodeError {
    /// Encoded row ended before all fields were present.
    #[error("coinstats row is truncated")]
    Truncated,
    /// Encoded row had trailing bytes after known fields.
    #[error("coinstats row has trailing bytes")]
    TrailingBytes,
}

/// UTXO listener that maintains [`CoinStats`].
#[derive(Clone, Debug)]
pub struct CoinStatsListener {
    state: Arc<Mutex<CoinStatsListenerState>>,
}

#[derive(Debug)]
struct CoinStatsListenerState {
    stats: CoinStats,
    scratch: Vec<u8>,
}

impl CoinStatsListenerState {
    fn insert_utxo_hash(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        coin_hash_bytes_into(&mut self.scratch, op, txout, height, coinbase);
        self.stats.muhash.insert(self.scratch.as_slice());
    }

    fn insert_utxo(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.insert_utxo_hash(op, txout, height, coinbase);
        self.stats.account_insert(txout);
    }

    fn remove_utxo_hash(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        coin_hash_bytes_into(&mut self.scratch, op, txout, height, coinbase);
        self.stats.muhash.remove(self.scratch.as_slice());
    }

    fn remove_utxo(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.remove_utxo_hash(op, txout, height, coinbase);
        self.stats.account_remove(txout);
    }

    fn trim_scratch_capacity(&mut self) {
        if self.scratch.capacity() > MAX_RETAINED_SCRATCH_CAPACITY {
            self.scratch = Vec::new();
        }
    }
}

impl CoinStatsListener {
    /// Creates a listener around initial stats.
    #[must_use]
    pub fn new(stats: CoinStats) -> Self {
        Self {
            state: Arc::new(Mutex::new(CoinStatsListenerState {
                stats,
                scratch: Vec::new(),
            })),
        }
    }

    /// Returns a point-in-time copy of the current stats.
    #[must_use]
    pub fn snapshot(&self) -> CoinStats {
        self.state.lock().stats.clone()
    }

    /// Applies a per-block delta to the wrapped stats.
    pub fn finish_block(&self, height: u32, tx_delta: u64) {
        self.state.lock().stats.finish_block(height, tx_delta);
    }

    /// Reverses one [`Self::finish_block`], for a disconnected block.
    ///
    /// # Errors
    ///
    /// Propagates [`CoinStats::rewind_block`]'s invariant failures.
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
}

impl UtxoChangeListener for CoinStatsListener {
    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        if insertions.len() < PARALLEL_COIN_BATCH_OP_THRESHOLD {
            let mut state = self.state.lock();
            for insertion in insertions {
                state.insert_utxo(
                    insertion.op,
                    insertion.txout,
                    insertion.height,
                    insertion.coinbase,
                );
            }
            state.trim_scratch_capacity();
            return;
        }

        let delta = insertions
            .par_chunks(COIN_BATCH_CHUNK_SIZE)
            .map(CoinStatsDelta::from_insertions)
            .reduce(CoinStatsDelta::new, CoinStatsDelta::combine);
        let mut state = self.state.lock();
        delta.apply_to(&mut state.stats);
    }

    fn on_remove_coins(&self, removals: &[UtxoRemoved]) {
        if removals.len() < PARALLEL_COIN_BATCH_OP_THRESHOLD {
            let mut state = self.state.lock();
            for removal in removals {
                state.remove_utxo(
                    &removal.op,
                    &removal.txout,
                    removal.height,
                    removal.coinbase,
                );
            }
            state.trim_scratch_capacity();
            return;
        }

        let delta = removals
            .par_chunks(COIN_BATCH_CHUNK_SIZE)
            .map(CoinStatsDelta::from_removals)
            .reduce(CoinStatsDelta::new, CoinStatsDelta::combine);
        let mut state = self.state.lock();
        delta.apply_to(&mut state.stats);
    }

    fn on_committed_event_batches(&self, batches: &[UtxoChangeEvents<'_>]) {
        if batches.is_empty() {
            return;
        }

        let operation_count = batches
            .iter()
            .map(UtxoChangeEvents::operation_count)
            .sum::<usize>();
        let delta = if operation_count >= PARALLEL_EVENT_CHUNK_OP_THRESHOLD {
            let event_chunk_size = if batches.len() >= WIDE_EVENT_BATCH_SHARD_THRESHOLD {
                WIDE_EVENT_CHUNK_SIZE
            } else {
                NARROW_EVENT_CHUNK_SIZE
            };
            let mut chunks =
                SmallVec::<[UtxoCommittedEvent<'_, '_>; INLINE_EVENT_CHUNKS]>::with_capacity(
                    operation_count.div_ceil(event_chunk_size),
                );
            for batch in batches {
                batch.for_each_chunk(event_chunk_size, |event| chunks.push(event));
            }
            chunks
                .par_iter()
                .copied()
                .map(CoinStatsDelta::from_event)
                .reduce(CoinStatsDelta::new, CoinStatsDelta::combine)
        } else {
            batches
                .iter()
                .map(CoinStatsDelta::from_events)
                .fold(CoinStatsDelta::new(), CoinStatsDelta::combine)
        };
        let mut state = self.state.lock();
        delta.apply_to(&mut state.stats);
    }

    fn muhash3072(&self) -> Option<[u8; 384]> {
        Some(self.state.lock().stats.muhash.finalize())
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
        txout.script_pubkey.as_bytes(),
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
    encode_value_and_script_into(out, txout.value.to_sat(), txout.script_pubkey.as_bytes());
}

#[inline]
fn encode_value_and_script_into(out: &mut Vec<u8>, value: u64, script_pubkey: &[u8]) {
    out.extend_from_slice(&value.to_le_bytes());
    encode_compact_size_into(out, script_pubkey.len());
    out.extend_from_slice(script_pubkey);
}

#[inline]
fn encode_compact_size_into(out: &mut Vec<u8>, len: usize) {
    if len < 0xfd {
        out.push(u8::try_from(len).unwrap_or(0));
        return;
    }
    if let Ok(word_len) = u16::try_from(len) {
        out.push(0xfd);
        out.extend_from_slice(&word_len.to_le_bytes());
        return;
    }
    if let Ok(dword_len) = u32::try_from(len) {
        out.push(0xfe);
        out.extend_from_slice(&dword_len.to_le_bytes());
        return;
    }
    let qword_len = u64::try_from(len).unwrap_or(u64::MAX);
    out.push(0xff);
    out.extend_from_slice(&qword_len.to_le_bytes());
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

impl From<Infallible> for CoinStatsDecodeError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

#[inline]
fn coin_hash_encoded_len(script_len: usize) -> usize {
    OUTPOINT_BYTES
        .saturating_add(4)
        .saturating_add(AMOUNT_ENCODED_BYTES)
        .saturating_add(compact_size_len(script_len))
        .saturating_add(script_len)
}

#[inline]
const fn compact_size_len(len: usize) -> usize {
    if len < 0xfd {
        1
    } else if len <= 0xffff {
        3
    } else if len <= 0xffff_ffff {
        5
    } else {
        9
    }
}

#[cfg(test)]
// A test pool that will not build has failed the test; panicking names the
// reason. Matches the convention already used in `compress.rs`.
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use crate::{SnapshotCoin, SnapshotCoinObserver};
    use bitcoin::{Amount, ScriptBuf};
    use proptest::prelude::*;

    use super::{CoinStats, CoinStatsRewindError, TxOut, encode_txout_into};

    /// A rewind that would take the count below zero is a double rewind of the
    /// same block, or a delta from a different one. Saturating here would clamp
    /// it to zero and carry on with a count that describes no chain.
    #[test]
    fn rewind_refuses_to_take_the_transaction_count_below_zero() {
        let mut stats = CoinStats::default();
        stats.finish_block(7, 3);
        let before = stats.clone();

        let outcome = stats.rewind_block(7, 6, 4);

        assert_eq!(
            outcome,
            Err(CoinStatsRewindError::TxCountUnderflow {
                tx_count: 3,
                tx_delta: 4,
            })
        );
        assert_eq!(stats, before, "a refused rewind must change nothing");
    }

    /// Rewinding a block the stats are not on would silently move them to a
    /// height whose transaction count was never subtracted.
    #[test]
    fn rewind_refuses_a_height_the_stats_are_not_on() {
        let mut stats = CoinStats::default();
        stats.finish_block(7, 3);
        let before = stats.clone();

        let outcome = stats.rewind_block(9, 8, 1);

        assert_eq!(
            outcome,
            Err(CoinStatsRewindError::HeightMismatch {
                expected: 9,
                found: 7,
            })
        );
        assert_eq!(stats, before, "a refused rewind must change nothing");
    }

    /// The same block cannot be rewound twice: the second attempt no longer
    /// matches the height, which is what the guard is for.
    #[test]
    fn rewinding_the_same_block_twice_is_refused() {
        let mut stats = CoinStats::default();
        stats.finish_block(7, 3);

        assert_eq!(stats.rewind_block(7, 6, 3), Ok(()));
        let after_first = stats.clone();
        assert_eq!(stats.tx_count, 0, "the first rewind must subtract");

        let outcome = stats.rewind_block(7, 6, 3);

        assert!(
            matches!(outcome, Err(CoinStatsRewindError::HeightMismatch { .. })),
            "a second rewind must be refused, got {outcome:?}"
        );
        assert_eq!(stats, after_first, "a refused rewind must change nothing");
    }

    /// A rewind must invert exactly what `finish_block` recorded.
    #[test]
    fn rewind_inverts_finish_block() {
        let mut stats = CoinStats::default();
        let before = stats.clone();
        stats.finish_block(12, 5);
        assert_ne!(stats, before, "the setup must move the stats");

        assert_eq!(stats.rewind_block(12, before.height, 5), Ok(()));

        assert_eq!(stats, before, "the block-level fields must return exactly");
    }

    #[test]
    fn manual_txout_encoding_matches_consensus_boundaries() {
        for len in [0_usize, 1, 252, 253, 65_535, 65_536] {
            let txout = TxOut {
                value: Amount::from_sat(50_000 + u64::try_from(len).unwrap_or(u64::MAX)),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51; len]),
            };
            let mut manual = Vec::new();
            encode_txout_into(&mut manual, &txout);
            let consensus = bitcoin::consensus::encode::serialize(&txout);
            assert_eq!(manual, consensus, "script len {len}");
        }
    }

    #[test]
    fn scan_coin_stats_matches_rolling_listener() {
        use crate::{BlockChanges, SnapshotCoin, SnapshotCoinObserver, UtxoAdd, UtxoSet};
        use bitcoin_rs_primitives::{Hash256, OutPoint};

        let mut utxo = UtxoSet::new();
        let listener = super::CoinStatsListener::new(super::CoinStats::new());
        utxo.set_listener(Box::new(listener.clone()));
        let mut changes = BlockChanges::default();
        for (i, script_len) in [0_usize, 1, 252, 253, 65_535].into_iter().enumerate() {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes[0] = u8::try_from(i + 1).unwrap_or(u8::MAX);
            let output = OutPoint::new(Hash256::from_le_bytes(&txid_bytes), u32::MAX);
            let txout = TxOut {
                value: Amount::from_sat(if i == 4 {
                    u64::MAX
                } else {
                    u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(100_000)
                }),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51; script_len]),
            };
            changes.add(UtxoAdd::new(
                output,
                txout,
                i % 2 == 1,
                if i == 4 {
                    u32::MAX >> 1
                } else {
                    u32::try_from(i).unwrap_or(u32::MAX)
                },
            ));
        }
        utxo.commit_block(&changes, &Hash256::default())
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));

        let rolling = listener.snapshot();
        let (scanned, accumulated, without_muhash) = utxo.with_stable_view(|view| {
            let scanned = super::scan_coin_stats(view, rolling.height, true)
                .unwrap_or_else(|err| panic!("scan_coin_stats failed: {err}"));
            let mut accumulated = super::CoinStatsAccumulator::with_muhash(rolling.height);
            let mut without_muhash = super::CoinStatsAccumulator::without_muhash(rolling.height);
            view.for_each_coin(|txid, vout, value, script_pubkey, height, coinbase| {
                let coin = SnapshotCoin {
                    txid,
                    vout,
                    value,
                    script_pubkey,
                    height,
                    coinbase,
                };
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
        txid: bitcoin_rs_primitives::Hash256,
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
                    txid: bitcoin_rs_primitives::Hash256::from_le_bytes(&txid),
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
        coins[1].txid = bitcoin_rs_primitives::Hash256::from_le_bytes(&[1; 32]);
        coins[2].txid = bitcoin_rs_primitives::Hash256::from_le_bytes(&[2; 32]);
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn parallel_muhash_property_matches_serial_generated_streams(
            count in 0_usize..1_500,
            script_lens in proptest::collection::vec(0_usize..512, 1..8),
        ) {
            assert_parallel_serialized_match(&generated_coins(count, &script_lens));
        }
    }
}
