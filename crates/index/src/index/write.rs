//! The sole concrete owner of durable index mutations.

use super::{
    block::NoSpentScripts, block::SpentCoinScripts, block::pending_rows_for_block_with_header,
    capability::IndexCapabilities, capability::IndexCapability, capability::IndexWatermark,
    capability::IndexWatermarks, capability::SCRIPT_LIVE_WATERMARK_KEY,
    capability::put_selected_watermarks, error::IndexError, prepared::PreparedBatch,
    prepared::PreparedBatchLimits, prepared::PreparedBlock, reader::Indexer, rows::IndexRowBytes,
    rows::PendingRows, rows::delete_rows, rows::put_rows, state::CONSUMER_CURSOR_KEY,
    state::ConsumerCursorUpdate, state::FORMAT_VERSION_KEY, state::FORMAT_VERSION_VALUE,
    state::IndexWriteFence, state::capture_write_fence, state::commit_ordinary,
    state::ensure_fence_live, state::resume_capability_reset,
};
use bitcoin_rs_primitives::{OutPoint, encode};
use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};

pub struct IndexWriter<S: KvStore> {
    pub(super) indexer: Indexer<S>,
    pub(super) generation: u64,
}

impl<S: KvStore> IndexWriter<S> {
    pub fn indexer(&self) -> &Indexer<S> {
        &self.indexer
    }

    /// Format 5 changed every row family (big-endian heights, 43-byte live
    /// the store for rebuild. No in-place upgrade path exists.
    pub fn open(store: std::sync::Arc<S>, generation: u64) -> Result<Self, IndexError> {
        let indexer = Indexer::new(store);
        match indexer
            .store
            .get(ColumnFamily::UtxoMeta, FORMAT_VERSION_KEY)?
        {
            Some(value) if value.as_slice() == FORMAT_VERSION_VALUE => {}
            Some(value) => {
                let version = value
                    .get(..4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map_or(0, u32::from_le_bytes);
                return Err(IndexError::UnsupportedTxIndexFormatVersion { version });
            }
            None => {
                if has_any_index_row(&*indexer.store)? {
                    return Err(IndexError::LegacyCursorlessIndex);
                }
            }
        }
        resume_capability_reset(indexer.store.as_ref(), generation, 0)?;
        Ok(Self {
            indexer,
            generation,
        })
    }

    pub fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.indexer.watermark()
    }

    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        self.indexer.watermarks()
    }

    pub fn fenced_watermarks(&mut self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        Ok((fence, fence.watermarks))
    }

    pub fn reset_index(store: &S, generation: u64) -> Result<(), IndexError> {
        resume_capability_reset(store, generation, IndexCapabilities::ALL.to_mask())
    }

    pub(crate) fn seed_script_live_stream<F>(
        &self,
        mut produce: F,
        seed_tip: IndexWatermark,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<usize, IndexError>
    where
        F: FnMut(
            &mut dyn FnMut(OutPoint, crate::ScriptHash) -> Result<(), IndexError>,
        ) -> Result<(), IndexError>,
    {
        const SEED_BATCH_ROWS: usize = 4_096;
        if cancelled() {
            return Err(IndexError::Cancelled);
        }
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if existing.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        self.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        let mut fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if fence.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        let mut written: usize = 0;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        let mut in_batch = 0;
        let mut add = |outpoint, scripthash| -> Result<(), IndexError> {
            let row = crate::types::ScriptLiveRow::new(scripthash, &outpoint);
            batch.put(ColumnFamily::ScriptLive, row.as_bytes(), &[]);
            written += 1;
            in_batch += 1;
            if in_batch >= SEED_BATCH_ROWS {
                let next = self.indexer.store.new_batch();
                let old = std::mem::replace(&mut batch, next);
                commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, old)?;
                fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
                if fence.watermarks.script_live.is_some() {
                    return Err(IndexError::LiveAlreadySeeded);
                }
                batch.put(
                    ColumnFamily::UtxoMeta,
                    FORMAT_VERSION_KEY,
                    &FORMAT_VERSION_VALUE,
                );
                in_batch = 0;
            }
            if written.is_multiple_of(SEED_BATCH_ROWS) && cancelled() {
                return Err(IndexError::Cancelled);
            }
            Ok(())
        };
        produce(&mut add)?;
        if cancelled() {
            return Err(IndexError::Cancelled);
        }
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        batch.put(
            ColumnFamily::UtxoMeta,
            SCRIPT_LIVE_WATERMARK_KEY,
            &seed_tip.to_bytes(),
        );
        commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)?;
        Ok(written)
    }

    pub(crate) fn reset_interrupted_script_live_seed(&self) -> Result<bool, IndexError> {
        if self.watermarks()?.script_live.is_some() {
            return Ok(false);
        }
        let probe = self.indexer.store.scan_prefix_bounded(
            ColumnFamily::ScriptLive,
            &[],
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: usize::MAX,
            },
        )?;
        if probe.rows.is_empty() {
            return Ok(false);
        }
        self.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        Ok(true)
    }

    pub fn seed_script_live<I>(
        &mut self,
        coins: I,
        seed_tip: IndexWatermark,
    ) -> Result<usize, IndexError>
    where
        I: IntoIterator<Item = (OutPoint, crate::ScriptHash)>,
    {
        let mut coins = coins.into_iter();
        self.seed_script_live_stream(
            |emit| {
                for (outpoint, scripthash) in coins.by_ref() {
                    emit(outpoint, scripthash)?;
                }
                Ok(())
            },
            seed_tip,
            &|| false,
        )
    }

    /// `TxLookup` watermark and coverage floor are written only in the final
    pub(crate) fn import_tx_lookup_stream<F>(
        &self,
        mut produce: F,
        base: IndexWatermark,
        floor: u32,
    ) -> Result<usize, IndexError>
    where
        F: FnMut(
            &mut dyn FnMut(PortableImportRow<'_>) -> Result<(), IndexError>,
        ) -> Result<(), IndexError>,
    {
        const IMPORT_BATCH_ROWS: usize = 65_536;
        const IMPORT_BATCH_BYTES: usize = 8 << 20;
        let refuse_populated = |fence: &IndexWriteFence| match fence.watermarks.tx_lookup {
            Some(actual) => Err(IndexError::WatermarkMismatch {
                expected: None,
                actual: Some(actual),
            }),
            None => Ok(()),
        };
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_populated(&existing)?;
        self.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
        let mut fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_populated(&fence)?;
        let mut written = 0_usize;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        let mut in_batch = 0_usize;
        let mut in_bytes = 0_usize;
        let mut add = |row: PortableImportRow<'_>| -> Result<(), IndexError> {
            match row {
                PortableImportRow::Header(header) => {
                    if self
                        .indexer
                        .store
                        .get(ColumnFamily::BlockHeaders, header)?
                        .is_some()
                    {
                        return Ok(());
                    }
                    batch.put(ColumnFamily::BlockHeaders, header, &[]);
                    in_bytes = in_bytes.saturating_add(header.len());
                }
                PortableImportRow::TxLookup { row, value } => {
                    batch.put(ColumnFamily::TxConfirmed, &row.to_db_row(), value);
                    in_bytes = in_bytes
                        .saturating_add(crate::HASH_PREFIX_ROW_SIZE)
                        .saturating_add(value.len());
                    written += 1;
                }
            }
            in_batch += 1;
            if in_batch >= IMPORT_BATCH_ROWS || in_bytes >= IMPORT_BATCH_BYTES {
                let next = self.indexer.store.new_batch();
                let old = std::mem::replace(&mut batch, next);
                commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, old)?;
                fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
                refuse_populated(&fence)?;
                batch.put(
                    ColumnFamily::UtxoMeta,
                    FORMAT_VERSION_KEY,
                    &FORMAT_VERSION_VALUE,
                );
                in_batch = 0;
                in_bytes = 0;
            }
            Ok(())
        };
        produce(&mut add)?;
        put_selected_watermarks(&mut batch, IndexCapabilities::TX_LOOKUP, Some(base));
        crate::index::capability::put_selected_floors(
            &mut batch,
            IndexCapabilities::TX_LOOKUP,
            floor,
        );
        commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)?;
        Ok(written)
    }

    pub fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::InvalidResetMarker);
        }
        resume_capability_reset(
            self.indexer.store.as_ref(),
            self.generation,
            capabilities.to_mask(),
        )
    }

    /// reseeds from an immutable artifact or retained history, so anchoring it would
    pub(crate) fn anchor_watermark(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        floor: u32,
    ) -> Result<(), IndexError> {
        if capabilities.is_empty()
            || capabilities.contains(IndexCapability::ScriptLive)
            || capabilities.contains(IndexCapability::CompactFilters)
        {
            return Err(IndexError::AnchorUnsupportedSelection);
        }
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut batch, capabilities, Some(watermark));
        crate::index::capability::put_selected_floors(&mut batch, capabilities, floor);
        commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)
    }

    pub fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.prepare_block_for(IndexCapabilities::HISTORICAL, height, hash, body)
    }

    pub fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.contains(IndexCapability::ScriptLive)
            || capabilities.contains(IndexCapability::CompactFilters)
        {
            return Err(IndexError::MissingSpentScripts);
        }
        self.prepare_block_with_spent_scripts(capabilities, height, hash, body, &NoSpentScripts)
    }

    pub fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        let (mut rows, header) =
            pending_rows_for_block_with_header(body, height, capabilities, spent_scripts)?;
        let actual_hash = encode::double_sha256(header.as_slice()).to_le_bytes();
        if actual_hash != hash {
            return Err(IndexError::BlockIdentityMismatch {
                height,
                expected: hash,
                actual: actual_hash,
            });
        }
        let mut parent_hash = [0_u8; 32];
        parent_hash.copy_from_slice(&header[4..36]);
        rows.sort();
        let row_count = rows.total();
        let family_bytes = rows.encoded_bytes_by_family()?;
        let encoded_bytes = family_bytes.total()?;
        Ok(PreparedBlock {
            height,
            hash,
            parent_hash,
            row_count,
            encoded_bytes,
            family_bytes,
            capabilities,
            rows,
        })
    }

    pub fn commit_block(&mut self, height: u32, body: &[u8]) -> Result<IndexWatermark, IndexError> {
        let header = body.get(..crate::types::HEADER_ROW_SIZE).ok_or_else(|| {
            IndexError::InvalidHeaderLength {
                len: body.len().min(crate::types::HEADER_ROW_SIZE),
            }
        })?;
        let hash = encode::double_sha256(header).to_le_bytes();
        let prepared = self.prepare_block(height, hash, body)?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if let Err(_block) = batch.try_push(prepared) {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        self.commit_forward(batch)
    }

    pub fn commit_forward(&mut self, batch: PreparedBatch) -> Result<IndexWatermark, IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_forward_with_cursor(fence, batch, ConsumerCursorUpdate::Keep)
    }

    pub fn commit_forward_with_cursor(
        &mut self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        if batch.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: fence.watermarks.tx_lookup,
            });
        }
        let capabilities = batch
            .capabilities()
            .ok_or(IndexError::NonContiguousPrepared {
                watermark: fence.watermarks.tx_lookup,
            })?;
        let current = fence.watermarks.selected(capabilities)?;
        let mut expected_height = match current {
            None => 0,
            Some(w) => w
                .height
                .checked_add(1)
                .ok_or(IndexError::NonContiguousPrepared { watermark: current })?,
        };
        let mut expected_parent = current.map(|w| w.hash);
        let mut previous_filter_header = if capabilities.contains(IndexCapability::CompactFilters) {
            ensure_fence_live(self.indexer.store.as_ref(), self.generation, &fence)?;
            match current {
                None => [0; 32],
                Some(w) => {
                    let parent =
                        super::filters::read(self.indexer.store.snapshot()?.as_ref(), &w.hash)?;
                    if parent.is_none() {
                        ensure_fence_live(self.indexer.store.as_ref(), self.generation, &fence)?;
                    }
                    parent.ok_or(IndexError::InvalidCompactFilter)?.header
                }
            }
        } else {
            [0; 32]
        };
        let batch_family_bytes = batch.family_bytes();
        let mut merged = PendingRows::default();
        let mut last = None;
        let block_count = batch.len();
        for (block_index, mut block) in batch.into_blocks().into_iter().enumerate() {
            if block.height != expected_height {
                return Err(IndexError::NonContiguousPrepared { watermark: current });
            }
            if let Some(parent) = expected_parent {
                if block.parent_hash != parent {
                    return Err(IndexError::NonContiguousPrepared { watermark: current });
                }
            }
            for (_, filter) in &mut block.rows.filter_rows {
                filter.chain(previous_filter_header);
                previous_filter_header = filter.header;
            }
            merged.append(block.rows);
            if block_index + 1 < block_count {
                expected_height = expected_height
                    .checked_add(1)
                    .ok_or(IndexError::NonContiguousPrepared { watermark: current })?;
            }
            expected_parent = Some(block.hash);
            last = Some(IndexWatermark {
                height: block.height,
                hash: block.hash,
            });
        }
        merged.sort();
        let final_watermark =
            last.ok_or(IndexError::NonContiguousPrepared { watermark: current })?;
        let mut store_batch = self.indexer.store.new_batch();
        put_rows(&mut store_batch, &merged);
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, Some(final_watermark));
        match cursor {
            ConsumerCursorUpdate::Keep => {}
            ConsumerCursorUpdate::Set(bytes) => {
                store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, bytes);
            }
            ConsumerCursorUpdate::Clear => {
                store_batch.delete(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY);
            }
        }
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )?;
        record_family_byte_histograms(&batch_family_bytes);
        Ok(final_watermark)
    }

    pub fn commit_rollback_one_for_with_cursor(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<(), IndexError> {
        if capabilities.contains(IndexCapability::ScriptLive)
            || capabilities.contains(IndexCapability::CompactFilters)
        {
            return Err(IndexError::MissingSpentScripts);
        }
        self.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            capabilities,
            prev,
            body,
            cursor,
            &NoSpentScripts,
        )
    }

    pub fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<(), IndexError> {
        let current = fence
            .watermarks
            .selected(capabilities)?
            .ok_or(IndexError::NonContiguousPrepared { watermark: None })?;
        let prepared = self.prepare_block_with_spent_scripts(
            capabilities,
            current.height,
            current.hash,
            body,
            spent_scripts,
        )?;
        if let Some(prev) = &prev {
            let expected_prev_height =
                current
                    .height
                    .checked_sub(1)
                    .ok_or(IndexError::NonContiguousPrepared {
                        watermark: Some(current),
                    })?;
            if prev.height != expected_prev_height || prev.hash != prepared.parent_hash {
                return Err(IndexError::WatermarkMismatch {
                    expected: Some(*prev),
                    actual: Some(current),
                });
            }
        } else if current.height != 0 {
            return Err(IndexError::NonContiguousPrepared {
                watermark: Some(current),
            });
        }
        let header =
            prepared
                .rows
                .header_rows
                .first()
                .ok_or(IndexError::MissingWatermarkIdentity {
                    height: current.height,
                    hash: current.hash,
                })?;
        let header_present = self
            .indexer
            .store
            .get(ColumnFamily::BlockHeaders, header)?
            .is_some();
        ensure_fence_live(self.indexer.store.as_ref(), self.generation, &fence)?;
        if !header_present {
            return Err(IndexError::MissingWatermarkIdentity {
                height: current.height,
                hash: current.hash,
            });
        }
        let mut store_batch = self.indexer.store.new_batch();
        let unselected_keeps_identity = IndexCapability::ALL.into_iter().any(|capability| {
            !capabilities.contains(capability)
                && fence
                    .watermarks
                    .get(capability)
                    .is_some_and(|watermark| watermark.height >= current.height)
        });
        delete_rows(&mut store_batch, &prepared.rows, !unselected_keeps_identity);
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, prev);
        match cursor {
            ConsumerCursorUpdate::Keep => {}
            ConsumerCursorUpdate::Set(bytes) => {
                store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, bytes);
            }
            ConsumerCursorUpdate::Clear => {
                store_batch.delete(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY);
            }
        }
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )?;
        Ok(())
    }

    pub fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        Ok(self
            .indexer
            .store
            .get(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY)?)
    }

    pub fn commit_consumer_cursor(
        &mut self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        let mut store_batch = self.indexer.store.new_batch();
        store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, cursor);
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )
    }
}

pub(crate) enum PortableImportRow<'a> {
    /// The 80-byte header identity of an active-chain block at or below the
    /// bundle base, so ordinary rollback can unseat the base later.
    Header(&'a [u8; crate::types::HEADER_ROW_SIZE]),
    /// One `TxConfirmed` row and its packed `TxPosition` value.
    TxLookup {
        /// Stored key: txid prefix and big-endian height.
        row: crate::types::HashPrefixRow,
        value: &'a [u8],
    },
}

pub(crate) const fn index_format_version() -> u32 {
    u32::from_le_bytes(FORMAT_VERSION_VALUE)
}

fn has_any_index_row<S: KvStore>(store: &S) -> Result<bool, IndexError> {
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
        ColumnFamily::ScriptLive,
    ] {
        let mut iter = store.iter_prefix(cf, &[])?;
        if let Some(entry) = iter.next() {
            let _ = entry?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) const FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM: &str = "index.family_planned_write_bytes";
pub(crate) const FAMILY_LABEL: &str = "family";

pub(crate) const FAMILY_TX_LOOKUP: &str = "tx_lookup";
pub(crate) const FAMILY_SCRIPT_HISTORY: &str = "script_history";
pub(crate) const FAMILY_SCRIPT_LIVE: &str = "script_live";
pub(crate) const FAMILY_HEADERS: &str = "headers";
pub(crate) const FAMILY_FILTERS: &str = "filters";

fn metric_f64_from_usize(val: usize) -> f64 {
    bitcoin_rs_primitives::u64_to_f64(u64::try_from(val).unwrap_or(u64::MAX))
}

pub(crate) fn record_family_byte_histograms(family_bytes: &IndexRowBytes) {
    if family_bytes.tx_lookup > 0 {
        metrics::histogram!(FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM, FAMILY_LABEL => FAMILY_TX_LOOKUP)
            .record(metric_f64_from_usize(family_bytes.tx_lookup));
    }
    if family_bytes.script_history > 0 {
        metrics::histogram!(FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM, FAMILY_LABEL => FAMILY_SCRIPT_HISTORY)
            .record(metric_f64_from_usize(family_bytes.script_history));
    }
    if family_bytes.script_live > 0 {
        metrics::histogram!(FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM, FAMILY_LABEL => FAMILY_SCRIPT_LIVE)
            .record(metric_f64_from_usize(family_bytes.script_live));
    }
    if family_bytes.headers > 0 {
        metrics::histogram!(FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM, FAMILY_LABEL => FAMILY_HEADERS)
            .record(metric_f64_from_usize(family_bytes.headers));
    }
    if family_bytes.filters > 0 {
        metrics::histogram!(FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM, FAMILY_LABEL => FAMILY_FILTERS)
            .record(metric_f64_from_usize(family_bytes.filters));
    }
}
