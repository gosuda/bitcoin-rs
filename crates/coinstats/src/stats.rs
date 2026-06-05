use alloc::sync::Arc;
use core::convert::Infallible;

use bitcoin_rs_primitives::{OutPoint, TxOut};
use bitcoin_rs_utxo::{
    UtxoChangeListener, UtxoInserted, UtxoRemoved,
    set::{UtxoChangeEvents, UtxoCommittedEvent},
};
use parking_lot::Mutex;
use rayon::prelude::*;
use smallvec::SmallVec;
use zerocopy::IntoBytes;

use crate::MuHash3072;

const OUTPOINT_BYTES: usize = 36;
const COIN_HEADER_BYTES: u64 = 4;
const AMOUNT_BYTES: u64 = 8;
const SCRIPT_LEN_BYTES: u64 = 2;
const MAX_RETAINED_SCRATCH_CAPACITY: usize = 4096;
const PARALLEL_COIN_BATCH_OP_THRESHOLD: usize = 1024;
const COIN_BATCH_CHUNK_SIZE: usize = 512;
const PARALLEL_EVENT_CHUNK_OP_THRESHOLD: usize = 64;
const EVENT_CHUNK_SIZE: usize = 32;
const INLINE_EVENT_CHUNKS: usize = 64;

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

    /// Serializes stats in a stable byte layout.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(824);
        out.extend_from_slice(&self.muhash.numerator_bytes());
        out.extend_from_slice(&self.muhash.denominator_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.total_amount.to_le_bytes());
        out.extend_from_slice(&self.bogo_size.to_le_bytes());
        out.extend_from_slice(&self.tx_count.to_le_bytes());
        out.extend_from_slice(&self.utxo_count.to_le_bytes());
        out
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CoinStatsDecodeError> {
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
            UtxoCommittedEvent::RemoveCoin(removal) => {
                delta.remove_batch(&mut scratch, core::slice::from_ref(removal));
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
            UtxoCommittedEvent::RemoveCoin(removal) => {
                delta.remove_batch(&mut scratch, core::slice::from_ref(removal));
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
        self.muhash.combine(&muhash);
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
        stats.muhash.combine(&self.muhash);
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
}

impl UtxoChangeListener for CoinStatsListener {
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        let mut state = self.state.lock();
        state.insert_utxo(op, txout, height, coinbase);
        state.trim_scratch_capacity();
    }

    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        let delta = if insertions.len() >= PARALLEL_COIN_BATCH_OP_THRESHOLD {
            insertions
                .par_chunks(COIN_BATCH_CHUNK_SIZE)
                .map(CoinStatsDelta::from_insertions)
                .reduce(CoinStatsDelta::new, CoinStatsDelta::combine)
        } else {
            CoinStatsDelta::from_insertions(insertions)
        };
        let mut state = self.state.lock();
        delta.apply_to(&mut state.stats);
    }

    fn on_remove(&self, op: &OutPoint, txout: &TxOut, height: u32) {
        let mut state = self.state.lock();
        state.remove_utxo(op, txout, height, false);
        state.trim_scratch_capacity();
    }

    fn on_remove_coin(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        let mut state = self.state.lock();
        state.remove_utxo(op, txout, height, coinbase);
        state.trim_scratch_capacity();
    }

    fn on_remove_coins(&self, removals: &[UtxoRemoved]) {
        let delta = if removals.len() >= PARALLEL_COIN_BATCH_OP_THRESHOLD {
            removals
                .par_chunks(COIN_BATCH_CHUNK_SIZE)
                .map(CoinStatsDelta::from_removals)
                .reduce(CoinStatsDelta::new, CoinStatsDelta::combine)
        } else {
            CoinStatsDelta::from_removals(removals)
        };
        let mut state = self.state.lock();
        delta.apply_to(&mut state.stats);
    }

    fn on_committed_event_batches(&self, batches: &[UtxoChangeEvents<'_>]) -> bool {
        if batches.is_empty() {
            return true;
        }

        let operation_count = batches
            .iter()
            .map(UtxoChangeEvents::operation_count)
            .sum::<usize>();
        let delta = if operation_count >= PARALLEL_EVENT_CHUNK_OP_THRESHOLD {
            let mut chunks =
                SmallVec::<[UtxoCommittedEvent<'_, '_>; INLINE_EVENT_CHUNKS]>::with_capacity(
                    operation_count.div_ceil(EVENT_CHUNK_SIZE),
                );
            for batch in batches {
                batch.for_each_chunk(EVENT_CHUNK_SIZE, |event| chunks.push(event));
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
        true
    }

    fn coalesces_committed_events(&self) -> bool {
        true
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
    out.clear();
    out.extend_from_slice(op.as_bytes());
    let coinbase_bit = u32::from(coinbase);
    out.extend_from_slice(&((height << 1) | coinbase_bit).to_le_bytes());
    encode_txout_into(out, txout);
}

#[inline]
fn encode_txout_into(out: &mut Vec<u8>, txout: &TxOut) {
    out.extend_from_slice(&txout.value.to_sat().to_le_bytes());
    let script = txout.script_pubkey.as_bytes();
    encode_compact_size_into(out, script.len());
    out.extend_from_slice(script);
}

#[inline]
fn encode_compact_size_into(out: &mut Vec<u8>, len: usize) {
    if let Ok(byte_len) = u8::try_from(len)
        && byte_len < 0xfd
    {
        out.push(byte_len);
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
    36_u64
        .saturating_add(COIN_HEADER_BYTES)
        .saturating_add(AMOUNT_BYTES)
        .saturating_add(SCRIPT_LEN_BYTES)
        .saturating_add(script_len)
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

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, ScriptBuf};

    use super::{TxOut, encode_txout_into};

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
}
