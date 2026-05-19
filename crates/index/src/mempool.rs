use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch as _};

use crate::{
    IndexError,
    types::{ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow},
};

const MEMPOOL_TXID_TAG: u8 = b'T';
const MEMPOOL_FUNDING_TAG: u8 = b'F';
const MEMPOOL_SPENDING_TAG: u8 = b'S';
const MEMPOOL_HEIGHT: u32 = 0;

/// Counts of unconfirmed rows written or removed for one transaction.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MempoolRowCounts {
    /// Transaction-id rows in [`ColumnFamily::TxMempool`].
    pub txids: usize,
    /// Script funding rows in [`ColumnFamily::TxMempool`].
    pub funding: usize,
    /// Previous-outpoint spending rows in [`ColumnFamily::TxMempool`].
    pub spending: usize,
}

/// Writer for electrs-shaped unconfirmed transaction rows.
pub struct MempoolRowWriter<S: KvStore> {
    store: std::sync::Arc<S>,
}

impl<S: KvStore> MempoolRowWriter<S> {
    /// Creates a mempool row writer over `store`.
    pub const fn new(store: std::sync::Arc<S>) -> Self {
        Self { store }
    }

    /// Returns the underlying key-value store.
    pub const fn store(&self) -> &std::sync::Arc<S> {
        &self.store
    }

    /// Writes unconfirmed rows for a transaction into [`ColumnFamily::TxMempool`].
    pub fn insert_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<MempoolRowCounts, IndexError> {
        let rows = MempoolRows::from_transaction(tx);
        let counts = rows.counts();
        let mut batch = self.store.new_batch();
        for row in &rows.txid_rows {
            batch.put(ColumnFamily::TxMempool, row, &[]);
        }
        for row in &rows.funding_rows {
            batch.put(ColumnFamily::TxMempool, row, &[]);
        }
        for row in &rows.spending_rows {
            batch.put(ColumnFamily::TxMempool, row, &[]);
        }
        self.store.write(batch)?;
        Ok(counts)
    }

    /// Removes unconfirmed rows for a transaction from [`ColumnFamily::TxMempool`].
    pub fn remove_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<MempoolRowCounts, IndexError> {
        let rows = MempoolRows::from_transaction(tx);
        let counts = rows.counts();
        let mut batch = self.store.new_batch();
        for row in &rows.txid_rows {
            batch.delete(ColumnFamily::TxMempool, row);
        }
        for row in &rows.funding_rows {
            batch.delete(ColumnFamily::TxMempool, row);
        }
        for row in &rows.spending_rows {
            batch.delete(ColumnFamily::TxMempool, row);
        }
        self.store.write(batch)?;
        Ok(counts)
    }
}

struct MempoolRows {
    txid_rows: Vec<[u8; crate::types::HASH_PREFIX_ROW_SIZE + 1]>,
    funding_rows: Vec<[u8; crate::types::HASH_PREFIX_ROW_SIZE + 1]>,
    spending_rows: Vec<[u8; crate::types::HASH_PREFIX_ROW_SIZE + 1]>,
}

impl MempoolRows {
    fn from_transaction(tx: &bitcoin::Transaction) -> Self {
        let txid = tx.compute_txid();
        let mut rows = Self {
            txid_rows: vec![tagged_row(
                MEMPOOL_TXID_TAG,
                TxidRow::row(&txid, MEMPOOL_HEIGHT).to_db_row(),
            )],
            funding_rows: Vec::with_capacity(tx.output.len()),
            spending_rows: Vec::with_capacity(tx.input.len()),
        };
        for output in &tx.output {
            rows.funding_rows.push(tagged_row(
                MEMPOOL_FUNDING_TAG,
                ScriptHashRow::row(ScriptHash::new(&output.script_pubkey), MEMPOOL_HEIGHT)
                    .to_db_row(),
            ));
        }
        for input in &tx.input {
            if !input.previous_output.is_null() {
                rows.spending_rows.push(tagged_row(
                    MEMPOOL_SPENDING_TAG,
                    SpendingPrefixRow::row(&input.previous_output, MEMPOOL_HEIGHT).to_db_row(),
                ));
            }
        }
        rows.txid_rows.sort_unstable();
        rows.funding_rows.sort_unstable();
        rows.spending_rows.sort_unstable();
        rows.txid_rows.dedup();
        rows.funding_rows.dedup();
        rows.spending_rows.dedup();
        rows
    }

    fn counts(&self) -> MempoolRowCounts {
        MempoolRowCounts {
            txids: self.txid_rows.len(),
            funding: self.funding_rows.len(),
            spending: self.spending_rows.len(),
        }
    }
}

fn tagged_row(
    tag: u8,
    row: [u8; crate::types::HASH_PREFIX_ROW_SIZE],
) -> [u8; crate::types::HASH_PREFIX_ROW_SIZE + 1] {
    let mut tagged = [0_u8; crate::types::HASH_PREFIX_ROW_SIZE + 1];
    tagged[0] = tag;
    tagged[1..].copy_from_slice(&row);
    tagged
}
