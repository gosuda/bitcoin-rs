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
