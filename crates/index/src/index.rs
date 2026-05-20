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
}

impl<S: KvStore + Send + Sync + 'static> IndexerLike for Indexer<S> {
    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block(self, block, height)
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

    use super::Indexer;
    use crate::{ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow};

    const HEIGHT: u32 = 42;

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
