//! Read-side store access and typed prefix-row decoding.

use super::{
    capability::IndexCapability, capability::IndexWatermark, capability::IndexWatermarks,
    capability::SCRIPT_LIVE_WATERMARK_KEY, capability::watermark_key, error::IndexError,
    rows::IndexRowCounts,
};
use crate::{types::ScriptHashRow, types::SpendingPrefixRow, types::TxidRow};
use bitcoin_rs_primitives::{OutPoint, Txid};
use bitcoin_rs_storage::{ColumnFamily, KvStore};

/// Electrs-shaped block indexer backed by a workspace [`KvStore`].
///
/// Reads and format/watermark queries live here. Durable row mutation is
/// owned exclusively by [`super::write::IndexWriter`].
pub struct Indexer<S: KvStore> {
    pub(super) store: std::sync::Arc<S>,
    pub(super) last_counts: IndexRowCounts,
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

    /// Returns the row counts from the last successful prepared commit.
    pub const fn last_counts(&self) -> IndexRowCounts {
        self.last_counts
    }

    /// Loads the exact durable `TxIndex` watermark, or `None` for an empty v2 index.
    pub fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.capability_watermark(IndexCapability::TxLookup)
    }

    /// Loads one capability's exact durable watermark.
    pub fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let key = watermark_key(capability);
        self.store
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(IndexWatermark::from_bytes)
            .transpose()
    }

    /// Loads all independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        Ok(IndexWatermarks {
            tx_lookup: self.capability_watermark(IndexCapability::TxLookup)?,
            script_history: self.capability_watermark(IndexCapability::ScriptHistory)?,
            script_live: self.capability_watermark(IndexCapability::ScriptLive)?,
        })
    }

    /// Iterates confirmed funding rows for `scripthash`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the scripthash's
    /// scan prefix, decoded from `ColumnFamily::Funding`. Rows are returned in
    /// the iteration order of the underlying store (lexicographic by key bytes).
    ///
    /// **Height ordering caveat:** the 4-byte height suffix is little-endian,
    /// so lexicographic byte order does **not** match numeric height order
    /// within one prefix. For example, height 256 (`00 01 00 00`) sorts before
    /// height 1 (`01 00 00 00`). Callers that need chronological order must
    /// sort the returned rows by numeric height after exact-resolving them.
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

    /// Iterates live-output rows for `scripthash`.
    ///
    /// Returns the outpoint locators currently filed under the scripthash's
    /// 8-byte scan prefix, decoded from [`ColumnFamily::ScriptLive`]. The
    /// prefix is lossy exactly like `Funding`'s: two scripts may share it, so
    /// callers MUST resolve each outpoint against authoritative UTXO state and
    /// exact-check the resolved coin's full `script_pubkey` before serving it
    /// (#225). This scan is read-only by contract -- live deletion is always a
    /// whole-key point delete, never a prefix-range operation.
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
                .ok_or(IndexError::InvalidWatermark)?;
            outpoints.push(row.outpoint());
        }
        Ok(outpoints)
    }

    /// Iterates confirmed funding rows for `scripthash` with their row values.
    ///
    /// The value carries the transaction byte positions that let a resolver read
    /// only the matching transactions; see [`crate::types::TxPositionValue`].
    pub(super) fn iter_funding_rows_with_values(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows_with_values(iter)
    }

    /// Iterates confirmed transaction-id rows for `txid` with their row values.
    pub(super) fn iter_txid_rows_with_values(
        &self,
        txid: &Txid,
    ) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows_with_values(iter)
    }

    /// Iterates confirmed spending rows that spent `outpoint`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the outpoint's
    /// spending scan prefix, decoded from `ColumnFamily::Spending`. The 8-byte
    /// prefix is lossy as above.
    ///
    /// **Height ordering caveat:** same as [`Self::iter_funding_rows`]: the
    /// 4-byte height suffix is little-endian, so lexicographic byte order does
    /// **not** match numeric height order within one prefix. Callers needing
    /// chronological order must sort by numeric height after exact-resolving
    /// rows.
    pub fn iter_spending_rows(
        &self,
        outpoint: &OutPoint,
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
    ///
    /// **Height ordering caveat:** same as [`Self::iter_funding_rows`]: the
    /// 4-byte height suffix is little-endian, so lexicographic byte order does
    /// **not** match numeric height order within one prefix. Callers needing
    /// chronological order must sort by numeric height after exact-resolving
    /// rows.
    pub fn iter_txid_rows(&self, txid: &Txid) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows(iter)
    }
}

fn collect_prefix_rows_with_values(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            rows.push((
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
                value,
            ));
        }
    }
    Ok(rows)
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
