//! Exact transaction and script resolution, including independent scan references.

use super::{error::IndexError, reader::Indexer};
use bitcoin_rs_primitives::{Block, OutPoint, Tx, Txid};
use bitcoin_rs_storage::KvStore;

/// One confirmed transaction discovered by the generic script-history resolver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScriptHistoryEntry {
    /// Transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
}

impl ScriptHistoryEntry {
    /// Creates a confirmed script-history entry.
    pub const fn confirmed(txid: Txid, height: u32) -> Self {
        Self { txid, height }
    }
}

impl<S: KvStore> Indexer<S> {
    /// Resolves confirmed script-history entries for `scripthash` via `source`.
    ///
    /// Walks `iter_funding_rows(scripthash)` to get every (prefix, height) pair,
    /// fetches each block via `source.block_at_height(height)`, and yields a
    /// `ScriptHistoryEntry::confirmed` for every transaction in that block that has
    /// at least one output matching `scripthash` exactly.
    ///
    /// Entries are returned sorted by numeric height (ascending). The underlying
    /// store iterates rows in lexicographic key-byte order, and because the
    /// 4-byte height suffix is little-endian, that order does **not** match
    /// numeric height order within one prefix (height 256 sorts before height
    /// 1). This method sorts the final entry list by numeric height so callers
    /// receive chronological order regardless of the on-disk key encoding.
    /// Heights not resolvable by `source` are skipped.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only transactions whose
    /// output scripthash matches the full 32-byte `scripthash` are emitted.
    pub fn resolve_script_history<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<crate::ScriptHistoryEntry>, IndexError> {
        let rows = self.iter_funding_rows_with_values(scripthash)?;
        let mut entries = Vec::new();
        for (row, value) in &rows {
            let height = row.height();
            match positioned_history(scripthash, height, value, source) {
                Some(found) => entries.extend(found),
                None => scan_height_history(scripthash, height, source, &mut entries),
            }
        }
        entries.sort_by_key(|entry| entry.height);
        Ok(entries)
    }

    /// Naive reference implementation of [`Self::resolve_script_history`].
    ///
    /// Loads and fully decodes the block once per funding row, then hashes every
    /// output script in it. Retained as the correctness oracle for the resolver
    /// equivalence tests, as the `before` arm of the `resolve_script_history`
    /// benchmark group, and as the live fallback for rows written before row
    /// values carried transaction positions.
    ///
    /// Like [`Self::resolve_script_history`], this sorts the final entry list by
    /// numeric height so the reference and the optimized resolver agree on order.
    pub fn resolve_script_history_scan<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<crate::ScriptHistoryEntry>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut entries = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                let mut matched = false;
                for output in &tx.outputs {
                    if crate::ScriptHash::from_script_bytes(&output.script_pubkey) == scripthash {
                        matched = true;
                        break;
                    }
                }
                if matched {
                    entries.push(crate::ScriptHistoryEntry::confirmed(tx.txid(), height));
                }
            }
        }
        entries.sort_by_key(|entry| entry.height);
        Ok(entries)
    }
    /// Resolves confirmed unspent-output candidates for `scripthash` via `source`.
    ///
    /// For every funding-row (prefix, height), fetches the block and emits a
    /// triple `(txid, vout, value_sats)` for every output whose scriptPubKey
    /// hashes to `scripthash`. Spending checks are NOT performed here — callers
    /// compose with `iter_spending_rows` to filter out spent outputs.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only outputs whose script
    /// hashes match the full 32-byte `scripthash` are emitted.
    pub fn resolve_unspent_outputs<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64)>, IndexError> {
        Ok(self
            .resolve_unspent_outputs_with_height(scripthash, source)?
            .into_iter()
            .map(|(txid, vout, value, _height)| (txid, vout, value))
            .collect())
    }

    /// Naive reference implementation of [`Self::resolve_unspent_outputs`].
    ///
    /// Retained as the correctness oracle for the resolver equivalence tests and
    /// as the `before` arm of the `resolve_unspent` benchmark group. Deliberately
    /// carries no optimization: an oracle that shares an optimization with the
    /// implementation it checks cannot catch a fault in that optimization.
    ///
    /// Not a fallback path — [`Self::resolve_unspent_outputs`] is always correct
    /// and always faster. Call that one.
    pub fn resolve_unspent_outputs_scan<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64)>, IndexError> {
        Ok(self
            .resolve_unspent_outputs_with_height_scan(scripthash, source)?
            .into_iter()
            .map(|(txid, vout, value, _height)| (txid, vout, value))
            .collect())
    }

    /// Same as `resolve_unspent_outputs` but each tuple carries the funding height.
    ///
    /// Returns `(txid, vout, value_sats, funding_height)` quadruples sorted by
    /// funding height (ascending). Use this when callers need the confirmation
    /// height (e.g. `ScriptIndex` `listunspent` emits the height for each
    /// unspent output). The sort mirrors [`Self::resolve_script_history`]:
    /// store iteration order is LE byte order, not numeric height order.
    pub fn resolve_unspent_outputs_with_height<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, IndexError> {
        let rows = self.iter_funding_rows_with_values(scripthash)?;
        let mut outputs = Vec::new();
        for (row, value) in &rows {
            let height = row.height();
            match positioned_unspent_outputs(scripthash, height, value, source) {
                Some(found) => outputs.extend(found),
                None => scan_height_unspent_outputs(scripthash, height, source, &mut outputs),
            }
        }
        outputs.sort_by_key(|&(_, _, _, height)| height);
        Ok(outputs)
    }

    /// Naive reference implementation of [`Self::resolve_unspent_outputs_with_height`].
    ///
    /// Computes every transaction's txid before testing any output script, which
    /// is the shape this resolver had before the lazy-txid change. Retained as
    /// the correctness oracle for the resolver equivalence tests and as the
    /// `before` arm of the `resolve_unspent` benchmark group.
    ///
    /// Not a fallback path — [`Self::resolve_unspent_outputs_with_height`] is
    /// always correct and always faster. Call that one. Like the fast path,
    /// this sorts by funding height so the reference and the optimized resolver
    /// agree on order.
    pub fn resolve_unspent_outputs_with_height_scan<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut outputs = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                let txid = tx.txid();
                for (vout_idx, output) in tx.outputs.iter().enumerate() {
                    if crate::ScriptHash::from_script_bytes(&output.script_pubkey) != scripthash {
                        continue;
                    }
                    let Ok(vout) = u32::try_from(vout_idx) else {
                        continue;
                    };
                    outputs.push((txid, vout, output.value.to_sat(), height));
                }
            }
        }
        outputs.sort_by_key(|&(_, _, _, height)| height);
        Ok(outputs)
    }

    /// Resolves a transaction by txid via `source`.
    ///
    /// Scans `iter_txid_rows(txid)` for candidate `(prefix, height)` entries.
    /// For each height, fetches the block and looks for the transaction whose
    /// full computed txid matches `txid` exactly. Returns the first match, or
    /// `None` if no candidates resolve to the requested txid.
    ///
    /// The 8-byte prefix is lossy; this method exact-resolves it by comparing
    /// the full 32-byte txid before returning.
    pub fn resolve_transaction<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<Tx>, IndexError> {
        let rows = self.iter_txid_rows_with_values(&txid)?;
        for (row, value) in &rows {
            let height = row.height();
            if let Some(positions) = crate::types::TxPositionValue::decode(value) {
                let found = positions
                    .iter()
                    .filter_map(|position| transaction_at(height, *position, source))
                    .find(|tx| tx.txid() == txid);
                if let Some(tx) = found {
                    return Ok(Some(tx));
                }
            }
            // The positions did not produce the transaction, which is either an
            // 8-byte txid-prefix collision or a stale row. Both are rare, and
            // both are answered correctly by scanning; "not found" is never
            // reported on the strength of positions alone.
            if let Some(block) = source.block_at_height(height) {
                for tx in &block.txs {
                    if tx.txid() == txid {
                        return Ok(Some(tx.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Naive reference implementation of [`Self::resolve_transaction`].
    ///
    /// Loads and fully decodes the block for each candidate row, then computes
    /// every transaction's txid until one matches. Retained as the correctness
    /// oracle and the `before` arm of the `resolve_transaction` benchmark group.
    pub fn resolve_transaction_scan<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<Tx>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                if tx.txid() == txid {
                    return Ok(Some(tx.clone()));
                }
            }
        }
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    pub fn resolve_outpoint_value<B: BlockSource + ?Sized>(
        &self,
        outpoint: OutPoint,
        source: &B,
    ) -> Result<Option<u64>, IndexError> {
        let Some(tx) = self.resolve_transaction(outpoint.txid, source)? else {
            return Ok(None);
        };
        let Ok(vout_idx) = usize::try_from(outpoint.vout) else {
            return Ok(None);
        };
        Ok(tx.outputs.get(vout_idx).map(|output| output.value.to_sat()))
    }

    /// Resolves a transaction by txid and returns it alongside the block
    /// height where it was confirmed.
    ///
    /// Same scanning strategy as [`Self::resolve_transaction`]: iterates the
    /// `iter_txid_rows(txid)` prefix candidates, fetches each candidate height's
    /// block via `source`, and compares full-32-byte txid for exact match.
    /// Returns the first match.
    ///
    /// Cost: O(R + B) where R = number of prefix rows for `txid` and B = block
    /// fetch cost per candidate height.
    pub fn resolve_tx_with_height<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<(Tx, u32)>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                if tx.txid() == txid {
                    return Ok(Some((tx.clone(), height)));
                }
            }
        }
        Ok(None)
    }
}

/// Reads and decodes the single transaction a position names.
///
/// Returns `None` when the source cannot serve the range, when the range is out
/// of bounds, or when the bytes are not exactly one transaction. `deserialize`
/// rejects trailing bytes, so a range covering more than one transaction fails
/// here rather than silently decoding the first.
fn transaction_at<B: BlockSource + ?Sized>(
    height: u32,
    position: crate::types::TxPosition,
    source: &B,
) -> Option<Tx> {
    let bytes = source.block_bytes_at_height(height, position.offset(), position.byte_len())?;
    Tx::consensus_decode(&bytes).ok()
}

/// Resolves one funding row's history entries from its positions.
///
/// Returns `None` — meaning "scan this height instead" — if **any** position
/// fails to resolve to a transaction funding `scripthash`. Skipping a failed
/// position and keeping the rest is what would turn a partial result into a
/// silently complete-looking one; see [`crate::types::TxPositionValue`].
fn positioned_history<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    value: &[u8],
    source: &B,
) -> Option<Vec<crate::ScriptHistoryEntry>> {
    let positions = crate::types::TxPositionValue::decode(value)?;
    let mut entries = Vec::with_capacity(positions.len());
    for position in positions {
        let tx = transaction_at(height, *position, source)?;
        if !funds_scripthash(&tx, scripthash) {
            return None;
        }
        entries.push(crate::ScriptHistoryEntry::confirmed(tx.txid(), height));
    }
    Some(entries)
}

/// Appends the history entries a full scan of `height` produces.
fn scan_height_history<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    source: &B,
    entries: &mut Vec<crate::ScriptHistoryEntry>,
) {
    let Some(block) = source.block_at_height(height) else {
        return;
    };
    for tx in &block.txs {
        if funds_scripthash(tx, scripthash) {
            entries.push(crate::ScriptHistoryEntry::confirmed(tx.txid(), height));
        }
    }
}

/// Resolves one funding row's unspent-output candidates from its positions.
///
/// Same all-or-scan rule as [`positioned_history`].
fn positioned_unspent_outputs<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    value: &[u8],
    source: &B,
) -> Option<Vec<(Txid, u32, u64, u32)>> {
    let positions = crate::types::TxPositionValue::decode(value)?;
    let mut outputs = Vec::new();
    for position in positions {
        let tx = transaction_at(height, *position, source)?;
        let before = outputs.len();
        append_matching_outputs(&tx, scripthash, height, &mut outputs);
        if outputs.len() == before {
            return None;
        }
    }
    Some(outputs)
}

/// Appends the unspent-output candidates a full scan of `height` produces.
fn scan_height_unspent_outputs<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    source: &B,
    outputs: &mut Vec<(Txid, u32, u64, u32)>,
) {
    let Some(block) = source.block_at_height(height) else {
        return;
    };
    for tx in &block.txs {
        append_matching_outputs(tx, scripthash, height, outputs);
    }
}

/// Appends `(txid, vout, value, height)` for every output of `tx` matching
/// `scripthash`, computing the txid only once a match is found.
fn append_matching_outputs(
    tx: &Tx,
    scripthash: crate::ScriptHash,
    height: u32,
    outputs: &mut Vec<(Txid, u32, u64, u32)>,
) {
    let mut computed_txid: Option<Txid> = None;
    for (vout_idx, output) in tx.outputs.iter().enumerate() {
        if crate::ScriptHash::from_script_bytes(&output.script_pubkey) != scripthash {
            continue;
        }
        let Ok(vout) = u32::try_from(vout_idx) else {
            continue;
        };
        let txid = *computed_txid.get_or_insert_with(|| tx.txid());
        outputs.push((txid, vout, output.value.to_sat(), height));
    }
}

fn funds_scripthash(tx: &Tx, scripthash: crate::ScriptHash) -> bool {
    tx.outputs
        .iter()
        .any(|output| crate::ScriptHash::from_script_bytes(&output.script_pubkey) == scripthash)
}

/// Provides block lookups for resolving lossy index prefixes to full identities.
///
/// The index column families store 8-byte prefixes of txids/scripthashes/outpoints.
/// To recover the full Bitcoin identities behind a `HashPrefixRow`, callers need
/// to fetch the block at the row's height and walk its transactions. `BlockSource`
/// is the trait that hides where blocks come from (in-memory store, raw-block KV
/// database, peer fetch).
pub trait BlockSource {
    /// Returns the Bitcoin block at `height` on the active chain, if known.
    fn block_at_height(&self, height: u32) -> Option<Block>;

    /// Returns `len` serialized bytes starting `offset` bytes into the active
    /// block at `height`, without materializing or decoding the whole body.
    ///
    /// This is what lets a resolver read only the transactions a row's
    /// [`crate::types::TxPosition`]s name instead of scanning the block.
    ///
    /// Defaults to `None`, meaning "this source cannot slice". A caller must
    /// then fall back to `block_at_height` — `None` never means the bytes are
    /// absent, and an out-of-range request yields `None` rather than a short
    /// read.
    fn block_bytes_at_height(&self, _height: u32, _offset: u32, _len: u32) -> Option<Vec<u8>> {
        None
    }
}
