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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TxIndexFamily {
    /// carrying packed `TxPosition` values.
    TxConfirmed,
}

impl TxIndexFamily {
    const fn column_family(self) -> ColumnFamily {
        match self {
            Self::TxConfirmed => ColumnFamily::TxConfirmed,
        }
    }
}

#[derive(Debug)]
pub struct TxIndexScanRow {
    /// Parsed fixed-width prefix row.
    pub row: HashPrefixRow,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct TxIndexScan {
    /// Parsed fixed-width prefix rows.
    pub rows: Vec<TxIndexScanRow>,
    pub encoded_bytes: usize,
    pub complete: bool,
}

/// One bounded page of a `TxIndex` family in ascending stored-key order.
#[derive(Debug)]
pub struct TxIndexPage {
    /// Parsed rows of this page in ascending stored-key order.
    pub rows: Vec<TxIndexScanRow>,
    pub complete: bool,
}

#[derive(Debug)]
pub struct ScriptLiveScan {
    pub rows: Vec<crate::ScriptLiveRow>,
    pub encoded_bytes: usize,
    pub complete: bool,
}

pub trait TxIndexSnapshot: Send + Sync {
    fn compact_filter(&self, _hash: &[u8; 32]) -> Result<Option<super::BasicFilter>, IndexError> {
        Ok(None)
    }
    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError>;
    /// Scans one bounded page of `family` in ascending stored-key order.
    /// begins at the first key strictly above `start_after`. Backends seek
    /// the snapshot to the cursor, so no family-sized copy is made on any
    fn scan_family_page(
        &self,
        family: TxIndexFamily,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexPage, IndexError>;
    /// Loads one capability's coverage floor: the first height its committed
    /// rows cover. `0` means complete coverage from genesis.
    fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
        let _ = capability;
        Ok(0)
    }
    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError>;
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
    fn compact_filter(&self, hash: &[u8; 32]) -> Result<Option<super::BasicFilter>, IndexError> {
        super::filters::read(self.snapshot.as_ref(), hash)
    }
    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        IndexWatermark::read_from_snapshot(self.snapshot.as_ref(), capability)
    }

    fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
        crate::index::capability::read_coverage_floor(self.snapshot.as_ref(), capability)
    }

    /// Resumes after `cursor` with `cursor || 0x00`: fixed-width keys make the suffixed key
    /// the least key strictly above `cursor`.
    fn scan_family_page(
        &self,
        family: TxIndexFamily,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexPage, IndexError> {
        let start: Vec<u8> = match start_after {
            Some(cursor) => {
                let mut start = Vec::with_capacity(cursor.len().saturating_add(1));
                start.extend_from_slice(cursor);
                start.push(0);
                start
            }
            None => Vec::new(),
        };
        let scan =
            self.snapshot
                .scan_prefix_from_bounded(family.column_family(), &[], &start, limit)?;
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let row = zerocopy::FromBytes::read_from_bytes(&key)
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            rows.push(TxIndexScanRow { row, value });
        }
        Ok(TxIndexPage {
            rows,
            complete: scan.complete,
        })
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

pub trait IndexReader: Send + Sync {
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
