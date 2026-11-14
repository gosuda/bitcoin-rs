use super::{
    capability::IndexCapability, capability::IndexWatermark, capability::IndexWatermarks,
    capability::SCRIPT_LIVE_WATERMARK_KEY, error::IndexError,
};
use crate::types::ScriptHashRow;
use bitcoin_rs_consensus::primitives::OutPoint;
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
            let row = crate::types::ScriptLiveRow::from_db_row(&key)
                .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?;
            crate::types::ScriptLiveCoin::decode_value(&value)
                .map_err(|_| IndexError::InvalidLiveRowValue { len: value.len() })?;
            outpoints.push(row.outpoint());
        }
        Ok(outpoints)
    }
}
