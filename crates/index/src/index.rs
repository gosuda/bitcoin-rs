use std::ops::ControlFlow;

use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch as _};
use bitcoin_slices::{Visit as _, Visitor, bsl};
use thiserror::Error;
use tracing::debug;

use crate::types::{HeaderRow, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow};

/// Errors returned while indexing confirmed blocks.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Backend storage failed while applying index rows.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// `bitcoin_slices` rejected the serialized block.
    #[error("invalid serialized block: {0:?}")]
    BlockParse(bitcoin_slices::Error),
    /// A block header did not have the consensus 80-byte length.
    #[error("invalid block header length {len}")]
    InvalidHeaderLength {
        /// Actual header length observed by the visitor.
        len: usize,
    },
}

/// Counts of rows written by a confirmed block ingest.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexRowCounts {
    /// Transaction-id index rows written to [`ColumnFamily::TxConfirmed`].
    pub txids: usize,
    /// Script funding rows written to [`ColumnFamily::Funding`].
    pub funding: usize,
    /// Previous-outpoint spending rows written to [`ColumnFamily::Spending`].
    pub spending: usize,
    /// Header rows written to [`ColumnFamily::BlockHeaders`].
    pub headers: usize,
}

/// Electrs-shaped block indexer backed by a workspace [`KvStore`].
pub struct Indexer<S: KvStore> {
    store: std::sync::Arc<S>,
    last_counts: IndexRowCounts,
}

impl<S: KvStore> Indexer<S> {
    /// Creates an indexer over `store`.
    pub fn new(store: std::sync::Arc<S>) -> Self {
        Self {
            store,
            last_counts: IndexRowCounts::default(),
        }
    }

    /// Returns the underlying key-value store.
    pub const fn store(&self) -> &std::sync::Arc<S> {
        &self.store
    }

    /// Returns the row counts from the last successful ingest.
    pub const fn last_counts(&self) -> IndexRowCounts {
        self.last_counts
    }

    /// Iterates every persisted block header in the `BlockHeaders` column family.
    ///
    /// Returns the raw 80-byte header rows in storage order (lexicographic by key).
    /// Used by SPV-style range queries that need contiguous headers from genesis.
    pub fn iter_block_headers(&self) -> Result<Vec<[u8; crate::HEADER_ROW_SIZE]>, IndexError> {
        let iter = self.store.iter_prefix(ColumnFamily::BlockHeaders, &[])?;
        let mut rows = Vec::new();
        for entry in iter {
            let (key, _value) = entry?;
            if key.len() == crate::HEADER_ROW_SIZE {
                let mut header = [0_u8; crate::HEADER_ROW_SIZE];
                header.copy_from_slice(&key);
                rows.push(header);
            }
        }
        Ok(rows)
    }

    /// Returns the hash of every indexed block header in storage order.
    ///
    /// Cheaper than `iter_block_headers` when only the hash list matters:
    /// computes `BlockHash` from the 80-byte raw header bytes during iteration
    /// without retaining the payload.
    pub fn iter_block_header_hashes(
        &self,
    ) -> Result<Vec<bitcoin_rs_primitives::Hash256>, IndexError> {
        use bitcoin::hashes::Hash as _;

        let iter = self.store.iter_prefix(ColumnFamily::BlockHeaders, &[])?;
        let mut out = Vec::new();
        for entry in iter {
            let (key, _value) = entry?;
            if key.len() == crate::HEADER_ROW_SIZE {
                // BlockHeader hash is the double-SHA256 of the 80-byte serialized header.
                let block_hash = bitcoin::BlockHash::hash(&key);
                out.push(bitcoin_rs_primitives::Hash256::from_le_bytes(
                    &block_hash.to_byte_array(),
                ));
            }
        }
        Ok(out)
    }

    /// Returns the number of persisted block headers via `iter_block_headers`.
    ///
    /// Cost O(N) since the iterator pulls each row; cache if called frequently.
    pub fn header_count(&self) -> Result<usize, IndexError> {
        self.iter_block_headers().map(|rows| rows.len())
    }

    /// Returns the highest indexed header height, or `None` if no headers are
    /// indexed.
    ///
    /// Cost O(N) since `header_count` pulls every row. Cache if called
    /// frequently. Convenience for IBD progress reporting and status surfaces.
    pub fn tip_height_indexed(&self) -> Result<Option<u32>, IndexError> {
        let count = self.header_count()?;
        if count == 0 {
            return Ok(None);
        }
        Ok(u32::try_from(count.saturating_sub(1)).ok())
    }

    /// Iterates confirmed funding rows for `scripthash`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the scripthash's
    /// scan prefix, decoded from `ColumnFamily::Funding`. Rows are returned in
    /// the iteration order of the underlying store (typically lexicographic, so
    /// (prefix, height) ascending).
    ///
    /// The 8-byte prefix is lossy: callers MUST resolve heights back to full
    /// transactions via block storage to confirm scripthash identity.
    pub fn iter_funding_rows(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Resolves confirmed script-history entries for `scripthash` via `source`.
    ///
    /// Walks `iter_funding_rows(scripthash)` to get every (prefix, height) pair,
    /// fetches each block via `source.block_at_height(height)`, and yields a
    /// `HistoryEntry::confirmed` for every transaction in that block that has
    /// at least one output matching `scripthash` exactly.
    ///
    /// Entries are returned in iteration order (lexicographic by prefix||height).
    /// Heights not resolvable by `source` are skipped.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only transactions whose
    /// output scripthash matches the full 32-byte `scripthash` are emitted.
    pub fn resolve_script_history<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<crate::HistoryEntry>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut entries = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                let mut matched = false;
                for output in &tx.output {
                    if crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes())
                        == scripthash
                    {
                        matched = true;
                        break;
                    }
                }
                if matched {
                    entries.push(crate::HistoryEntry::confirmed(tx.compute_txid(), height));
                }
            }
        }
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
    ) -> Result<Vec<(bitcoin::Txid, u32, u64)>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut outputs = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for (vout_idx, output) in tx.output.iter().enumerate() {
                    if crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes())
                        != scripthash
                    {
                        continue;
                    }
                    let Ok(vout) = u32::try_from(vout_idx) else {
                        continue;
                    };
                    outputs.push((txid, vout, output.value.to_sat()));
                }
            }
        }
        Ok(outputs)
    }

    /// Same as `resolve_unspent_outputs` but each tuple carries the funding height.
    ///
    /// Returns `(txid, vout, value_sats, funding_height)` quadruples. Use this
    /// when callers need the confirmation height (e.g. Electrum `listunspent`
    /// emits the height for each unspent output).
    pub fn resolve_unspent_outputs_with_height<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(bitcoin::Txid, u32, u64, u32)>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut outputs = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for (vout_idx, output) in tx.output.iter().enumerate() {
                    if crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes())
                        != scripthash
                    {
                        continue;
                    }
                    let Ok(vout) = u32::try_from(vout_idx) else {
                        continue;
                    };
                    outputs.push((txid, vout, output.value.to_sat(), height));
                }
            }
        }
        Ok(outputs)
    }

    /// Iterates confirmed spending rows that spent `outpoint`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the outpoint's
    /// spending scan prefix, decoded from `ColumnFamily::Spending`. The 8-byte
    /// prefix is lossy as above.
    pub fn iter_spending_rows(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        let iter = self.store.iter_prefix(ColumnFamily::Spending, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Iterates confirmed transaction-id rows matching `txid`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the txid's scan
    /// prefix, decoded from `ColumnFamily::TxConfirmed`. The 8-byte prefix is
    /// lossy; multiple txids can share a prefix.
    pub fn iter_txid_rows(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows(iter)
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
        txid: bitcoin::Txid,
        source: &B,
    ) -> Result<Option<bitcoin::Transaction>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                if tx.compute_txid() == txid {
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
        outpoint: bitcoin::OutPoint,
        source: &B,
    ) -> Result<Option<u64>, IndexError> {
        let Some(tx) = self.resolve_transaction(outpoint.txid, source)? else {
            return Ok(None);
        };
        let Ok(vout_idx) = usize::try_from(outpoint.vout) else {
            return Ok(None);
        };
        Ok(tx.output.get(vout_idx).map(|output| output.value.to_sat()))
    }

    /// Resolves a transaction by txid and returns it alongside the block
    /// height where it was confirmed.
    ///
    /// Same scanning strategy as [`resolve_transaction`]: iterates the
    /// `iter_txid_rows(txid)` prefix candidates, fetches each candidate height's
    /// block via `source`, and compares full-32-byte txid for exact match.
    /// Returns the first match.
    ///
    /// Cost: O(R + B) where R = number of prefix rows for `txid` and B = block
    /// fetch cost per candidate height.
    pub fn resolve_tx_with_height<B: BlockSource + ?Sized>(
        &self,
        txid: bitcoin::Txid,
        source: &B,
    ) -> Result<Option<(bitcoin::Transaction, u32)>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                if tx.compute_txid() == txid {
                    return Ok(Some((tx.clone(), height)));
                }
            }
        }
        Ok(None)
    }

    /// Walks one serialized block once with `bitcoin_slices` and writes electrs-shaped rows.
    pub fn ingest_block(
        &mut self,
        block: &[u8],
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        let mut rows = PendingRows::default();
        {
            let mut visitor = IndexBlockVisitor {
                rows: &mut rows,
                height,
                invalid_header_len: None,
            };
            match bsl::Block::visit(block, &mut visitor) {
                Ok(_) => {}
                Err(bitcoin_slices::Error::VisitBreak) => {
                    if let Some(len) = visitor.invalid_header_len {
                        return Err(IndexError::InvalidHeaderLength { len });
                    }
                    return Err(IndexError::BlockParse(bitcoin_slices::Error::VisitBreak));
                }
                Err(error) => return Err(IndexError::BlockParse(error)),
            }
        }

        rows.sort();
        let counts = rows.counts();
        let mut batch = self.store.new_batch();
        for row in &rows.txid_rows {
            batch.put(ColumnFamily::TxConfirmed, row, &[]);
        }
        for row in &rows.funding_rows {
            batch.put(ColumnFamily::Funding, row, &[]);
        }
        for row in &rows.spending_rows {
            batch.put(ColumnFamily::Spending, row, &[]);
        }
        for row in &rows.header_rows {
            batch.put(ColumnFamily::BlockHeaders, row, &[]);
        }
        self.store.write(batch)?;
        self.last_counts = counts;
        debug!(
            height,
            txids = counts.txids,
            funding = counts.funding,
            spending = counts.spending,
            headers = counts.headers,
            "indexed block"
        );
        Ok(counts)
    }
}

#[derive(Default)]
struct PendingRows {
    txid_rows: Vec<[u8; crate::types::HASH_PREFIX_ROW_SIZE]>,
    funding_rows: Vec<[u8; crate::types::HASH_PREFIX_ROW_SIZE]>,
    spending_rows: Vec<[u8; crate::types::HASH_PREFIX_ROW_SIZE]>,
    header_rows: Vec<[u8; crate::types::HEADER_ROW_SIZE]>,
}

impl PendingRows {
    fn sort(&mut self) {
        self.txid_rows.sort_unstable();
        self.funding_rows.sort_unstable();
        self.spending_rows.sort_unstable();
        self.header_rows.sort_unstable();
        self.txid_rows.dedup();
        self.funding_rows.dedup();
        self.spending_rows.dedup();
        self.header_rows.dedup();
    }

    const fn counts(&self) -> IndexRowCounts {
        IndexRowCounts {
            txids: self.txid_rows.len(),
            funding: self.funding_rows.len(),
            spending: self.spending_rows.len(),
            headers: self.header_rows.len(),
        }
    }
}

struct IndexBlockVisitor<'a> {
    rows: &'a mut PendingRows,
    height: u32,
    invalid_header_len: Option<usize>,
}

impl Visitor for IndexBlockVisitor<'_> {
    fn visit_block_header(&mut self, header: &bsl::BlockHeader<'_>) -> ControlFlow<()> {
        let Some(row) = HeaderRow::from_header_bytes(header.as_ref()) else {
            self.invalid_header_len = Some(header.as_ref().len());
            return ControlFlow::Break(());
        };
        self.rows.header_rows.push(row.to_db_row());
        ControlFlow::Continue(())
    }

    fn visit_transaction(&mut self, tx: &bsl::Transaction<'_>) -> ControlFlow<()> {
        let txid = tx.txid_sha2();
        self.rows
            .txid_rows
            .push(TxidRow::row_bytes(txid.as_slice(), self.height).to_db_row());
        ControlFlow::Continue(())
    }

    fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn<'_>) -> ControlFlow<()> {
        let prevout = tx_in.prevout();
        if !is_null_prevout(prevout) {
            self.rows.spending_rows.push(
                SpendingPrefixRow::row_parts(prevout.txid(), prevout.vout(), self.height)
                    .to_db_row(),
            );
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_out(&mut self, _vout: usize, tx_out: &bsl::TxOut<'_>) -> ControlFlow<()> {
        let script = bitcoin::Script::from_bytes(tx_out.script_pubkey());
        if !script.is_op_return() {
            self.rows.funding_rows.push(
                ScriptHashRow::row(
                    ScriptHash::from_script_bytes(tx_out.script_pubkey()),
                    self.height,
                )
                .to_db_row(),
            );
        }
        ControlFlow::Continue(())
    }
}

fn is_null_prevout(prevout: &bsl::OutPoint<'_>) -> bool {
    prevout.vout() == u32::MAX && prevout.txid().iter().all(|byte| *byte == 0)
}

fn collect_prefix_rows(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, _value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            rows.push(
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
            );
        }
    }
    Ok(rows)
}

/// Storage-agnostic block-ingest interface.
///
/// Use this trait when consumers must hold the indexer behind a trait
/// object (e.g. when the storage backend is selected at runtime).
pub trait IndexerLike: Send + Sync {
    /// Walks `block` once and writes index rows. See `Indexer::ingest_block`.
    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError>;

    /// Resolves a confirmed transaction by txid via `source`.
    ///
    /// Default implementations may return `Ok(None)` when the concrete indexer
    /// does not support transaction lookup.
    fn resolve_transaction(
        &self,
        txid: bitcoin::Txid,
        source: &dyn BlockSource,
    ) -> Result<Option<bitcoin::Transaction>, IndexError> {
        let _ = (txid, source);
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    fn resolve_outpoint_value(
        &self,
        outpoint: bitcoin::OutPoint,
        source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError>;
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
    fn block_at_height(&self, height: u32) -> Option<bitcoin::Block>;
}

impl<S: KvStore + Send + Sync + 'static> IndexerLike for Indexer<S> {
    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block(self, block, height)
    }

    fn resolve_transaction(
        &self,
        txid: bitcoin::Txid,
        source: &dyn BlockSource,
    ) -> Result<Option<bitcoin::Transaction>, IndexError> {
        Self::resolve_transaction(self, txid, source)
    }

    fn resolve_outpoint_value(
        &self,
        outpoint: bitcoin::OutPoint,
        source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError> {
        Self::resolve_outpoint_value(self, outpoint, source)
    }
}

#[cfg(all(test, feature = "rocksdb"))]
mod tests {
    use std::sync::Arc;

    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
    };
    use bitcoin_rs_storage::RocksDbStore;

    use super::{BlockSource, Indexer};
    use crate::{HistoryEntry, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow};

    const HEIGHT: u32 = 42;

    #[test]
    fn iter_block_headers_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        indexer.ingest_block(&serialize(&genesis), 0)?;

        let rows = indexer.iter_block_headers()?;
        assert_eq!(rows.len(), 1);
        Ok(())
    }

    #[test]
    fn iter_block_header_hashes_empty_index_returns_empty() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, indexer) = indexer()?;
        assert!(indexer.iter_block_header_hashes()?.is_empty());
        Ok(())
    }

    #[test]
    fn iter_block_header_hashes_returns_genesis_after_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&block);
        indexer.ingest_block(&bytes, 0)?;
        let hashes = indexer.iter_block_header_hashes()?;
        assert_eq!(hashes.len(), 1);
        let expected = bitcoin_rs_primitives::Hash256::from_le_bytes(
            &block.header.block_hash().to_byte_array(),
        );
        assert_eq!(hashes[0], expected);
        Ok(())
    }

    #[test]
    fn header_count_returns_one_after_genesis_ingest() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        assert_eq!(indexer.header_count()?, 0);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        indexer.ingest_block(&serialize(&genesis), 0)?;

        assert_eq!(indexer.header_count()?, 1);
        Ok(())
    }

    #[test]
    fn tip_height_indexed_returns_none_for_empty_index() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        assert!(indexer.tip_height_indexed()?.is_none());
        Ok(())
    }

    #[test]
    fn tip_height_indexed_returns_zero_after_genesis_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        indexer.ingest_block(&serialize(&genesis), 0)?;

        assert_eq!(indexer.tip_height_indexed()?, Some(0));
        Ok(())
    }

    #[test]
    fn iter_funding_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let script = ScriptBuf::from_bytes(vec![0x51, 0x01]);
        let tx = tx(spent_outpoint(1, 0), script.clone());
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block(vec![tx])), HEIGHT)?;

        let scripthash = ScriptHash::from_script_bytes(script.as_bytes());
        assert_eq!(
            indexer.iter_funding_rows(scripthash)?,
            vec![ScriptHashRow::row(scripthash, HEIGHT)]
        );
        Ok(())
    }

    #[test]
    fn iter_spending_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let outpoint = spent_outpoint(2, 3);
        let tx = tx(outpoint, ScriptBuf::from_bytes(vec![0x51, 0x02]));
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block(vec![tx])), HEIGHT)?;

        assert_eq!(
            indexer.iter_spending_rows(&outpoint)?,
            vec![SpendingPrefixRow::row(&outpoint, HEIGHT)]
        );
        Ok(())
    }

    #[test]
    fn iter_txid_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let tx = tx(
            spent_outpoint(4, 5),
            ScriptBuf::from_bytes(vec![0x51, 0x03]),
        );
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block(vec![tx])), HEIGHT)?;

        let rows = indexer.iter_txid_rows(&txid)?;
        assert!(rows.contains(&TxidRow::row(&txid, HEIGHT)));
        Ok(())
    }

    #[test]
    fn resolve_script_history_returns_entries_for_funded_scripthash()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.output.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let entries = indexer.resolve_script_history(scripthash, &source)?;

        assert_eq!(entries, vec![HistoryEntry::confirmed(txid, 0)]);
        Ok(())
    }
    #[test]
    fn resolve_unspent_outputs_returns_txid_vout_value_for_funded_scripthash()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.output.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let txid = tx.compute_txid();
        let value = output.value.to_sat();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = indexer.resolve_unspent_outputs(scripthash, &source)?;

        assert_eq!(outputs, vec![(txid, 0, value)]);
        Ok(())
    }

    #[test]
    fn resolve_transaction_returns_coinbase_for_genesis_block_indexed_at_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let coinbase = tx.clone();
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = indexer.resolve_transaction(txid, &source)?;

        assert_eq!(resolved, Some(coinbase));
        Ok(())
    }

    #[test]
    fn resolve_transaction_returns_none_when_indexed_height_is_not_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 1,
        };
        let resolved = indexer.resolve_transaction(txid, &source)?;

        assert_eq!(resolved, None);
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_genesis_coinbase_at_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let coinbase = tx.clone();
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = indexer.resolve_tx_with_height(txid, &source)?;

        assert_eq!(resolved, Some((coinbase, 0)));
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        let txid = bitcoin::Txid::from_byte_array([0xff; 32]);
        let source = FakeSource {
            block: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest),
            target_height: 0,
        };

        assert_eq!(indexer.resolve_tx_with_height(txid, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_genesis_coinbase_subsidy()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = bitcoin::OutPoint { txid, vout: 0 };
        let value = indexer.resolve_outpoint_value(outpoint, &source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_via_indexerlike_dyn_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let dyn_indexer: &dyn super::IndexerLike = &indexer;
        let dyn_source: &dyn super::BlockSource = &source;
        let outpoint = bitcoin::OutPoint { txid, vout: 0 };
        let value = dyn_indexer.resolve_outpoint_value(outpoint, dyn_source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_vout_out_of_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = bitcoin::OutPoint { txid, vout: 99 };

        assert_eq!(indexer.resolve_outpoint_value(outpoint, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xff; 32]),
            vout: 0,
        };
        let source = FakeSource {
            block: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest),
            target_height: 0,
        };

        assert_eq!(indexer.resolve_outpoint_value(outpoint, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_unspent_outputs_with_height_returns_funding_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.output.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let txid = tx.compute_txid();
        let value = output.value.to_sat();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = indexer.resolve_unspent_outputs_with_height(scripthash, &source)?;

        assert_eq!(outputs, vec![(txid, 0, value, 0)]);
        Ok(())
    }

    struct FakeSource {
        block: Block,
        target_height: u32,
    }

    impl BlockSource for FakeSource {
        fn block_at_height(&self, height: u32) -> Option<Block> {
            if height == self.target_height {
                return Some(self.block.clone());
            }
            None
        }
    }

    fn indexer() -> Result<(tempfile::TempDir, Indexer<RocksDbStore>), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, Indexer::new(store)))
    }

    fn block(txdata: Vec<Transaction>) -> Block {
        Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        }
    }

    fn tx(previous_output: OutPoint, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey,
            }],
        }
    }

    fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([label; 32]),
            vout,
        }
    }
}
