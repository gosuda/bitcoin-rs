use super::{
    block::NoSpentScripts, block::SpentCoins, block::pending_rows_for_block_with_header,
    block::pending_rows_for_facts, capability::IndexCapabilities, capability::IndexCapability,
    capability::IndexWatermark, capability::IndexWatermarks, capability::SCRIPT_LIVE_WATERMARK_KEY,
    capability::put_selected_watermarks, error::IndexError, prepared::PreparedBatch,
    prepared::PreparedBatchLimits, prepared::PreparedBlock, reader::Indexer, rows::IndexRowBytes,
    rows::PendingRows, rows::delete_rows, rows::delete_rows_with_headers, rows::put_rows,
    state::CONSUMER_CURSOR_KEY, state::ConsumerCursorUpdate, state::FORMAT_VERSION_KEY,
    state::FORMAT_VERSION_VALUE, state::IndexWriteFence, state::capture_write_fence,
    state::commit_ordinary, state::ensure_fence_live, state::resume_capability_reset,
};
use bitcoin_rs_consensus::primitives::{OutPoint, encode};
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, PrefixScanLimit};

pub struct IndexWriter<S: KvStore> {
    pub(super) indexer: Indexer<S>,
    pub(super) generation: u64,
}

impl<S: KvStore> IndexWriter<S> {
    pub fn indexer(&self) -> &Indexer<S> {
        &self.indexer
    }

    pub fn open(store: std::sync::Arc<S>, generation: u64) -> Result<Self, IndexError> {
        let indexer = Indexer::new(store);
        let format_opt = indexer
            .store
            .get(ColumnFamily::UtxoMeta, FORMAT_VERSION_KEY)?;
        match format_opt {
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
        crate::segment::recover_segments(indexer.store.as_ref())?;
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

    pub fn stage_script_live_rows(
        &self,
        rows: &mut dyn Iterator<Item = Vec<u8>>,
    ) -> Result<usize, IndexError> {
        const SEED_STAGE_BATCH_ROWS: usize = 4_096;
        let mut fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if fence.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        let mut written = 0usize;
        let mut in_batch = 0usize;
        let mut batch = self.indexer.store.new_batch();
        for row in rows {
            if in_batch == 0 {
                batch.put(
                    ColumnFamily::UtxoMeta,
                    FORMAT_VERSION_KEY,
                    &FORMAT_VERSION_VALUE,
                );
            }
            if row.len() < crate::types::SCRIPT_LIVE_ROW_SIZE {
                return Err(IndexError::InvalidLiveRowValue { len: row.len() });
            }
            let key = &row[..crate::types::SCRIPT_LIVE_ROW_SIZE];
            let value = &row[crate::types::SCRIPT_LIVE_ROW_SIZE..];
            crate::types::ScriptLiveCoin::decode_value(value)
                .map_err(|_| IndexError::InvalidLiveRowValue { len: row.len() })?;
            batch.put(ColumnFamily::ScriptLive, key, value);
            written += 1;
            in_batch += 1;
            if in_batch >= SEED_STAGE_BATCH_ROWS {
                let next = self.indexer.store.new_batch();
                let old = std::mem::replace(&mut batch, next);
                commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, old)?;
                fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
                if fence.watermarks.script_live.is_some() {
                    return Err(IndexError::LiveAlreadySeeded);
                }
                in_batch = 0;
            }
        }
        if in_batch > 0 {
            commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)?;
        }
        Ok(written)
    }

    pub fn publish_script_live_seed(&self, seed_tip: IndexWatermark) -> Result<(), IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if fence.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        let mut batch = self.indexer.store.new_batch();
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
        commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)
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
        I: IntoIterator<Item = (OutPoint, crate::types::ScriptLiveCoin)>,
    {
        let mut rows = Vec::new();
        for (outpoint, coin) in coins {
            let row = crate::types::ScriptLiveRow::new(coin.scripthash, &outpoint);
            let value = coin.encode_value()?;
            let mut bytes = Vec::with_capacity(crate::types::SCRIPT_LIVE_ROW_SIZE + value.len());
            bytes.extend_from_slice(row.as_bytes());
            bytes.extend_from_slice(&value);
            rows.push(bytes);
        }
        let written = self.stage_script_live_rows(&mut rows.into_iter())?;
        self.publish_script_live_seed(seed_tip)?;
        Ok(written)
    }

    pub fn attach_tx_lookup_rows(
        &self,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        attachment: &crate::writer::TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_tx_lookup_populated(&existing)?;
        self.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_tx_lookup_populated(&fence)?;
        let count = self.indexer.store.ingest_sorted(
            ColumnFamily::TxConfirmed,
            rows,
            attachment.scratch,
        )?;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        for header in attachment.headers {
            if self
                .indexer
                .store
                .get(ColumnFamily::BlockHeaders, *header)?
                .is_none()
            {
                batch.put(ColumnFamily::BlockHeaders, *header, &[]);
            }
        }
        put_selected_watermarks(
            &mut batch,
            IndexCapabilities::TX_LOOKUP,
            Some(attachment.base),
        );
        crate::index::capability::put_selected_floors(
            &mut batch,
            IndexCapabilities::TX_LOOKUP,
            attachment.floor,
        );
        commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)?;
        Ok(count)
    }

    pub fn attach_script_history_rows(
        &self,
        funding: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        spending: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        attachment: &crate::writer::ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_script_history_populated(self.indexer.store.as_ref(), &fence)?;
        match self.install_script_history(funding, spending, &fence, attachment) {
            Ok(rows) => Ok(rows),
            Err(IndexError::StaleIndexState) => Err(IndexError::StaleIndexState),
            Err(error) => Err(
                match self.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY) {
                    Ok(()) => error,
                    Err(cleanup) => cleanup,
                },
            ),
        }
    }

    fn install_script_history(
        &self,
        funding: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        spending: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        fence: &IndexWriteFence,
        attachment: &crate::writer::ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let funding_rows =
            self.indexer
                .store
                .ingest_sorted(ColumnFamily::Funding, funding, attachment.scratch)?;
        let spending_rows = self.indexer.store.ingest_sorted(
            ColumnFamily::Spending,
            spending,
            attachment.scratch,
        )?;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(
            &mut batch,
            IndexCapabilities::SCRIPT_HISTORY,
            Some(attachment.base),
        );
        crate::index::capability::put_selected_floors(
            &mut batch,
            IndexCapabilities::SCRIPT_HISTORY,
            attachment.floor,
        );
        commit_ordinary(self.indexer.store.as_ref(), self.generation, fence, batch)?;
        funding_rows
            .checked_add(spending_rows)
            .ok_or(IndexError::MutationSizeOverflow)
    }

    pub fn attach_compact_filter_rows(
        &self,
        by_height: &mut dyn Iterator<Item = crate::writer::CompactFilterRow>,
        by_block: &mut dyn Iterator<Item = crate::writer::CompactFilterRow>,
        attachment: &crate::writer::CompactFilterAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_compact_filters_populated(self.indexer.store.as_ref(), &fence)?;
        match self.install_compact_filters(by_height, by_block, &fence, attachment) {
            Ok(rows) => Ok(rows),
            Err(error) => Err(
                match remove_compact_filter_rows(self.indexer.store.as_ref()) {
                    Ok(()) => error,
                    Err(cleanup) => cleanup,
                },
            ),
        }
    }

    fn install_compact_filters(
        &self,
        by_height: &mut dyn Iterator<Item = crate::writer::CompactFilterRow>,
        by_block: &mut dyn Iterator<Item = crate::writer::CompactFilterRow>,
        fence: &IndexWriteFence,
        attachment: &crate::writer::CompactFilterAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let store = self.indexer.store.as_ref();
        let mut height_rows = by_height.map(|row| {
            let key = crate::segment::format::encode_filter_key(0, row.height);
            let value = crate::segment::format::encode_filter_value(
                &row.block_hash,
                &row.filter_hash,
                &row.header,
                &row.filter,
            );
            (key.to_vec(), value)
        });
        let height_count =
            store.ingest_sorted(ColumnFamily::Filters, &mut height_rows, attachment.scratch)?;
        let mut block_rows = by_block.map(|row| {
            let key = super::filters::key(&row.block_hash);
            let value = super::filters::BasicFilter {
                filter: row.filter,
                hash: row.filter_hash,
                header: row.header,
            }
            .encode();
            (key.to_vec(), value)
        });
        let block_count =
            store.ingest_sorted(ColumnFamily::UtxoMeta, &mut block_rows, attachment.scratch)?;
        for actual in [height_count, block_count] {
            if actual != attachment.records {
                return Err(IndexError::CompactFiltersIncomplete {
                    expected: attachment.records,
                    actual,
                });
            }
        }
        let mut batch = store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(
            &mut batch,
            IndexCapabilities::COMPACT_FILTERS,
            Some(attachment.base),
        );
        commit_ordinary(store, self.generation, fence, batch)?;
        Ok(attachment.records)
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
        spent_scripts: &dyn SpentCoins,
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

    pub fn prepare_block_from_facts(
        &self,
        capabilities: IndexCapabilities,
        block: &bitcoin_rs_storage::CommittedBlock,
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        let (mut rows, _header) = pending_rows_for_facts(block, capabilities)?;
        rows.sort();
        let row_count = rows.total();
        let family_bytes = rows.encoded_bytes_by_family()?;
        let encoded_bytes = family_bytes.total()?;
        Ok(PreparedBlock {
            height: block.height,
            hash: block.hash,
            parent_hash: block.parent_hash,
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
        let expected_height = match current {
            None => 0,
            Some(w) => w
                .height
                .checked_add(1)
                .ok_or(IndexError::NonContiguousPrepared { watermark: current })?,
        };
        let expected_parent = current.map(|w| w.hash);
        let previous_filter_header = self.initial_filter_header(&fence, capabilities, current)?;
        let batch_family_bytes = batch.family_bytes();
        let (merged, final_watermark) = chain_forward_blocks(
            batch,
            current,
            expected_height,
            expected_parent,
            previous_filter_header,
        )?;
        let mut store_batch = self.indexer.store.new_batch();
        put_rows(&mut store_batch, &merged)?;
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, Some(final_watermark));
        apply_cursor_update(&mut store_batch, cursor);
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
        spent_scripts: &dyn SpentCoins,
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
        validate_rollback_prev(current, prepared.parent_hash, prev.as_ref())?;
        let header =
            prepared
                .rows
                .header_rows
                .first()
                .ok_or(IndexError::MissingWatermarkIdentity {
                    height: current.height,
                    hash: current.hash,
                })?;
        verify_rollback_header_present(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            current,
            header,
        )?;
        let mut store_batch = self.indexer.store.new_batch();
        let unselected_keeps_identity = IndexCapability::ALL.into_iter().any(|capability| {
            !capabilities.contains(capability)
                && fence
                    .watermarks
                    .get(capability)
                    .is_some_and(|watermark| watermark.height >= current.height)
        });
        if unselected_keeps_identity {
            delete_rows(&mut store_batch, &prepared.rows)?;
        } else {
            delete_rows_with_headers(&mut store_batch, &prepared.rows)?;
        }
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, prev);
        apply_cursor_update(&mut store_batch, cursor);
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

pub const fn index_format_version() -> u32 {
    u32::from_le_bytes(FORMAT_VERSION_VALUE)
}

fn has_any_index_row<S: KvStore>(store: &S) -> Result<bool, IndexError> {
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
        ColumnFamily::ScriptLive,
        ColumnFamily::IdxMeta,
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
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

#[expect(clippy::expect_used, reason = "usize metric value fits in u64")]
fn metric_f64_from_usize(val: usize) -> f64 {
    bitcoin_rs_consensus::primitives::u64_to_f64(u64::try_from(val).expect("usize fits in u64"))
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
fn refuse_tx_lookup_populated(fence: &IndexWriteFence) -> Result<(), IndexError> {
    match fence.watermarks.tx_lookup {
        Some(actual) => Err(IndexError::WatermarkMismatch {
            expected: None,
            actual: Some(actual),
        }),
        None => Ok(()),
    }
}

fn refuse_script_history_populated<S: KvStore>(
    store: &S,
    fence: &IndexWriteFence,
) -> Result<(), IndexError> {
    if let Some(actual) = fence.watermarks.script_history {
        return Err(IndexError::WatermarkMismatch {
            expected: None,
            actual: Some(actual),
        });
    }
    for cf in [ColumnFamily::Funding, ColumnFamily::Spending] {
        if let Some(entry) = store.iter_prefix(cf, &[])?.next() {
            let _ = entry?;
            return Err(IndexError::ScriptHistoryPopulated);
        }
    }
    Ok(())
}

fn refuse_compact_filters_populated<S: KvStore>(
    store: &S,
    fence: &IndexWriteFence,
) -> Result<(), IndexError> {
    if let Some(actual) = fence.watermarks.compact_filters {
        return Err(IndexError::WatermarkMismatch {
            expected: None,
            actual: Some(actual),
        });
    }
    if let Some(entry) = store
        .iter_prefix(ColumnFamily::UtxoMeta, super::filters::PREFIX)?
        .next()
    {
        let _ = entry?;
        return Err(IndexError::CompactFiltersPopulated);
    }
    if let Some(entry) = store.iter_prefix(ColumnFamily::Filters, &[])?.next() {
        let _ = entry?;
        return Err(IndexError::CompactFiltersPopulated);
    }
    Ok(())
}

fn remove_compact_filter_rows<S: KvStore>(store: &S) -> Result<(), IndexError> {
    store.delete_range(ColumnFamily::UtxoMeta, super::filters::PREFIX, &[1, b'G'])?;
    store.delete_range(ColumnFamily::Filters, &[0; 8], &[0, 0, 0, 0, 0, 0, 0, 1])?;
    Ok(())
}
impl<S: KvStore> IndexWriter<S> {
    fn initial_filter_header(
        &self,
        fence: &IndexWriteFence,
        capabilities: IndexCapabilities,
        current: Option<IndexWatermark>,
    ) -> Result<[u8; 32], IndexError> {
        if !capabilities.contains(IndexCapability::CompactFilters) {
            return Ok([0; 32]);
        }
        ensure_fence_live(self.indexer.store.as_ref(), self.generation, fence)?;
        match current {
            None => Ok([0; 32]),
            Some(w) => {
                let parent =
                    super::filters::read(self.indexer.store.snapshot()?.as_ref(), &w.hash)?;
                if parent.is_none() {
                    ensure_fence_live(self.indexer.store.as_ref(), self.generation, fence)?;
                }
                parent
                    .ok_or(IndexError::InvalidCompactFilter)
                    .map(|f| f.header)
            }
        }
    }
}

fn chain_forward_blocks(
    batch: PreparedBatch,
    current: Option<IndexWatermark>,
    mut expected_height: u32,
    mut expected_parent: Option<[u8; 32]>,
    mut previous_filter_header: [u8; 32],
) -> Result<(PendingRows, IndexWatermark), IndexError> {
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
    let final_watermark = last.ok_or(IndexError::NonContiguousPrepared { watermark: current })?;
    Ok((merged, final_watermark))
}

fn apply_cursor_update(store_batch: &mut BufferedWriteBatch, cursor: ConsumerCursorUpdate<'_>) {
    match cursor {
        ConsumerCursorUpdate::Keep => {}
        ConsumerCursorUpdate::Set(bytes) => {
            store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, bytes);
        }
        ConsumerCursorUpdate::Clear => {
            store_batch.delete(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY);
        }
    }
}

fn validate_rollback_prev(
    current: IndexWatermark,
    parent_hash: [u8; 32],
    prev: Option<&IndexWatermark>,
) -> Result<(), IndexError> {
    if let Some(prev) = prev {
        let expected_prev_height =
            current
                .height
                .checked_sub(1)
                .ok_or(IndexError::NonContiguousPrepared {
                    watermark: Some(current),
                })?;
        if prev.height != expected_prev_height || prev.hash != parent_hash {
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
    Ok(())
}

fn verify_rollback_header_present<S: KvStore>(
    store: &S,
    generation: u64,
    fence: &IndexWriteFence,
    current: IndexWatermark,
    header: &[u8],
) -> Result<(), IndexError> {
    let header_present = store.get(ColumnFamily::BlockHeaders, header)?.is_some();
    ensure_fence_live(store, generation, fence)?;
    if !header_present {
        return Err(IndexError::MissingWatermarkIdentity {
            height: current.height,
            hash: current.hash,
        });
    }
    Ok(())
}
