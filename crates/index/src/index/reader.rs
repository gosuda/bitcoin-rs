//! Read-side store access and typed prefix-row decoding for confirmed index rows.

use super::{
    capability::IndexCapability, capability::IndexWatermark, capability::IndexWatermarks,
    capability::SCRIPT_LIVE_WATERMARK_KEY, error::IndexError,
};
use crate::{types::ScriptHashRow, types::SpendingPrefixRow};
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_storage::{ColumnFamily, KvStore};

pub struct Indexer<S: KvStore> {
    pub(super) store: std::sync::Arc<S>,
}

impl<S: KvStore> Indexer<S> {
    pub fn new(store: std::sync::Arc<S>) -> Self {
        Self { store }
    }

    pub(super) fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.capability_watermark(IndexCapability::TxLookup)
    }

    pub fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let key = capability.watermark_key();
        self.store
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(IndexWatermark::from_bytes)
            .transpose()
    }

    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        Ok(IndexWatermarks {
            tx_lookup: self.capability_watermark(IndexCapability::TxLookup)?,
            script_history: self.capability_watermark(IndexCapability::ScriptHistory)?,
            script_live: self.capability_watermark(IndexCapability::ScriptLive)?,
            compact_filters: self.capability_watermark(IndexCapability::CompactFilters)?,
        })
    }

    /// big-endian (format 5), so that order is chronological within a prefix.
    pub fn iter_funding_rows(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows(iter)
    }

    pub fn iter_live_outpoints(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<OutPoint>, IndexError> {
        let snapshot = self.store.snapshot()?;
        if snapshot
            .get(ColumnFamily::UtxoMeta, SCRIPT_LIVE_WATERMARK_KEY)?
            .is_none()
        {
            return Ok(Vec::new());
        }
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = snapshot.iter_prefix(ColumnFamily::ScriptLive, &prefix)?;
        let mut outpoints = Vec::new();
        for row in iter {
            let (key, value) = row?;
            if !value.is_empty() {
                return Err(IndexError::InvalidLiveRowValue { len: value.len() });
            }
            let row = crate::types::ScriptLiveRow::from_db_row(&key)
                .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?;
            outpoints.push(row.outpoint());
        }
        Ok(outpoints)
    }

    /// height suffix is big-endian (format 5), so prefix-range scans arrive
    pub fn iter_spending_rows(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        let iter = self.store.iter_prefix(ColumnFamily::Spending, &prefix)?;
        collect_prefix_rows(iter)
    }
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
