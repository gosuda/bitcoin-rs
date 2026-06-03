use alloc::sync::Arc;
use core::convert::Infallible;

use bitcoin_rs_primitives::{OutPoint, TxOut};
use bitcoin_rs_utxo::{UtxoChangeListener, UtxoInserted, UtxoRemoved};
use parking_lot::Mutex;
use zerocopy::IntoBytes;

use crate::MuHash3072;

const OUTPOINT_BYTES: usize = 36;
const COIN_HEADER_BYTES: u64 = 4;
const AMOUNT_BYTES: u64 = 8;
const SCRIPT_LEN_BYTES: u64 = 2;
const MAX_RETAINED_SCRATCH_CAPACITY: usize = 4096;

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
    fn insert_utxo(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        coin_hash_bytes_into(&mut self.scratch, op, txout, height, coinbase);
        self.stats.muhash.insert(self.scratch.as_slice());
        self.stats.account_insert(txout);
    }

    fn remove_utxo(&mut self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        coin_hash_bytes_into(&mut self.scratch, op, txout, height, coinbase);
        self.stats.muhash.remove(self.scratch.as_slice());
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

fn encode_txout_into(out: &mut Vec<u8>, txout: &TxOut) {
    out.extend_from_slice(&txout.value.to_sat().to_le_bytes());
    let script = txout.script_pubkey.as_bytes();
    encode_compact_size_into(out, script.len());
    out.extend_from_slice(script);
}

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
