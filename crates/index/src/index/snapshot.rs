//! Point-in-time, bounded, typed index scans.

use super::{
    capability::IndexCapability, capability::IndexWatermark, error::IndexError, reader::Indexer,
    write::IndexWriter,
};
use crate::{
    types::HashPrefixRow, types::ScriptHash, types::ScriptHashRow, types::SpendingPrefixRow,
    types::TxidRow,
};
use bitcoin_rs_primitives::{OutPoint, Txid};
use bitcoin_rs_storage::{ColumnFamily, KvSnapshot, KvStore, PrefixScanLimit};

/// One typed row from a `TxIndex` prefix scan, including its raw value.
#[derive(Debug)]
pub struct TxIndexScanRow {
    /// Parsed fixed-width prefix row.
    pub row: HashPrefixRow,
    /// Raw storage value associated with the row.
    pub value: Vec<u8>,
}

/// Result of one bounded typed `TxIndex` prefix scan.
#[derive(Debug)]
pub struct TxIndexScan {
    /// Parsed fixed-width prefix rows.
    pub rows: Vec<TxIndexScanRow>,
    /// Encoded key and value bytes returned by storage.
    pub encoded_bytes: usize,
    /// Whether storage returned the complete matching prefix.
    pub complete: bool,
}

/// Result of one bounded `ScriptLive` prefix scan.
#[derive(Debug)]
pub struct ScriptLiveScan {
    /// Parsed live-output locator rows.
    pub rows: Vec<crate::ScriptLiveRow>,
    /// Encoded key and value bytes returned by storage.
    pub encoded_bytes: usize,
    /// Whether storage returned the complete matching prefix.
    pub complete: bool,
}

/// Point-in-time, typed view of durable `TxIndex` rows.
pub trait TxIndexSnapshot: Send + Sync {
    /// Loads the transaction lookup watermark from this snapshot.
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError>;
    /// Loads one capability's exact durable watermark from this snapshot.
    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let _ = capability;
        self.watermark()
    }
    /// Scans confirmed-transaction rows for `txid`.
    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    /// Scans funding rows for `scripthash`.
    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    /// Scans spending rows for `outpoint`.
    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    /// Scans compact live-output locator rows for `scripthash`.
    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError> {
        let _ = (scripthash, limit);
        Err(IndexError::UnsupportedRollback)
    }
}

struct StoreTxIndexSnapshot<'a> {
    snapshot: Box<dyn KvSnapshot + 'a>,
}

impl StoreTxIndexSnapshot<'_> {
    fn scan(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let scan = self.snapshot.scan_prefix_bounded(cf, prefix, limit)?;
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let row = zerocopy::FromBytes::read_from_bytes(&key)
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            rows.push(TxIndexScanRow { row, value });
        }
        Ok(TxIndexScan {
            rows,
            encoded_bytes,
            complete: scan.complete,
        })
    }
}

impl TxIndexSnapshot for StoreTxIndexSnapshot<'_> {
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.capability_watermark(IndexCapability::TxLookup)
    }

    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        IndexWatermark::read_from_snapshot(self.snapshot.as_ref(), capability)
    }

    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.scan(
            ColumnFamily::TxConfirmed,
            &TxidRow::scan_prefix(txid),
            limit,
        )
    }

    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.scan(
            ColumnFamily::Funding,
            &ScriptHashRow::scan_prefix(scripthash),
            limit,
        )
    }

    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.scan(
            ColumnFamily::Spending,
            &SpendingPrefixRow::scan_prefix(outpoint),
            limit,
        )
    }

    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError> {
        let scan = self.snapshot.scan_prefix_bounded(
            ColumnFamily::ScriptLive,
            &ScriptHashRow::scan_prefix(scripthash),
            limit,
        )?;
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if !value.is_empty() {
                return Err(IndexError::InvalidLiveRowValue { len: value.len() });
            }
            rows.push(
                crate::ScriptLiveRow::from_db_row(&key)
                    .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?,
            );
        }
        Ok(ScriptLiveScan {
            rows,
            encoded_bytes,
            complete: scan.complete,
        })
    }
}

/// Read-only `TxIndex` interface.
pub trait IndexReader: Send + Sync {
    /// Captures a point-in-time typed `TxIndex` snapshot.
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError>;
}

impl<S: KvStore> IndexReader for Indexer<S> {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(StoreTxIndexSnapshot {
            snapshot: self.store.snapshot()?,
        }))
    }
}

impl<S: KvStore> IndexReader for IndexWriter<S> {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(StoreTxIndexSnapshot {
            snapshot: self.indexer.store.snapshot()?,
        }))
    }
}
