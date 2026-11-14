use super::tail_writes::{RollbackStep, planned_tail_bytes};
use super::{
    block::BodyFacts, block::NoSpentScripts, block::SpentCoins, block::committed_block_from_image,
    block::parse_body, block::pending_rows_for_facts, block::pending_rows_for_image,
    capability::IndexCapabilities, capability::IndexCapability, capability::IndexWatermark,
    capability::IndexWatermarks, capability::SCRIPT_LIVE_WATERMARK_KEY,
    capability::put_selected_watermarks, error::IndexError, prepared::PreparedBatch,
    prepared::PreparedBatchLimits, prepared::PreparedBlock, reader::Indexer, rows::IndexRowBytes,
    rows::PendingRows, rows::delete_rows, rows::delete_rows_with_headers, rows::put_rows,
    state::CONSUMER_CURSOR_KEY, state::ConsumerCursorUpdate, state::FORMAT_VERSION_KEY,
    state::FORMAT_VERSION_VALUE, state::IndexWriteFence, state::ORDINARY_STATE_REVISION_KEY,
    state::capture_write_fence, state::commit_ordinary, state::ensure_fence_live,
    state::resume_capability_reset,
};
use crate::segment::tail::{PreparedTail, TailWriterState};
use bitcoin_rs_consensus::primitives::{OutPoint, encode};
use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily, KvStore, PrefixScanLimit};
use std::collections::VecDeque;
pub struct IndexWriter<S: KvStore> {
    pub(super) indexer: Indexer<S>,
    pub(super) generation: u64,
    pub(super) tail: Option<TailWriterState>,
    pub(super) seal_scratch: Option<std::path::PathBuf>,
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
        crate::segment::import::clear_unpublished_segment_rows(indexer.store.as_ref())?;
        resume_capability_reset(indexer.store.as_ref(), generation, 0)?;
        let tail = {
            let snapshot = indexer.store.snapshot()?;
            crate::segment::tail::load(snapshot.as_ref())?
        };
        Ok(Self {
            indexer,
            generation,
            tail: Some(tail),
            seal_scratch: None,
        })
    }

    pub fn with_seal_scratch(mut self, scratch: std::path::PathBuf) -> Self {
        self.seal_scratch = Some(scratch);
        self
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

    pub fn attach_tx_lookup_segment(
        &self,
        segment: &crate::segment::import::ImportedSegment,
        attachment: &crate::writer::TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_tx_lookup_populated(&existing)?;
        self.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_tx_lookup_populated(&fence)?;
        let store = self.indexer.store.as_ref();
        let gen_id = crate::segment::import::next_segment_id(store)?;
        crate::segment::import::clear_unpublished_segment_rows(store)?;
        crate::segment::import::stage_segment(store, gen_id, segment, attachment.scratch)?;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        for header in attachment.headers {
            if store.get(ColumnFamily::BlockHeaders, *header)?.is_none() {
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
        crate::segment::import::put_segment(
            &mut batch,
            gen_id,
            segment,
            IndexCapabilities::TX_LOOKUP,
        );
        commit_ordinary(store, self.generation, &fence, batch)?;
        Ok(segment.records)
    }

    pub fn clear_unpublished_segments(&self) -> Result<(), IndexError> {
        crate::segment::import::clear_unpublished_segment_rows(self.indexer.store.as_ref())
    }

    pub fn attach_script_history_segment(
        &self,
        segment: &crate::segment::import::ImportedSegment,
        attachment: &crate::writer::ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_script_history_populated(self.indexer.store.as_ref(), &existing)?;
        self.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_script_history_populated(self.indexer.store.as_ref(), &fence)?;
        let store = self.indexer.store.as_ref();
        let gen_id = crate::segment::import::next_segment_id(store)?;
        crate::segment::import::clear_unpublished_segment_rows(store)?;
        crate::segment::import::stage_segment(store, gen_id, segment, attachment.scratch)?;
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
        crate::segment::import::put_segment(
            &mut batch,
            gen_id,
            segment,
            IndexCapabilities::SCRIPT_HISTORY,
        );
        commit_ordinary(store, self.generation, &fence, batch)?;
        Ok(segment.records)
    }

    pub fn attach_compact_filter_segment(
        &self,
        by_height: &mut dyn Iterator<Item = crate::writer::CompactFilterRow>,
        attachment: &crate::writer::CompactFilterAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_compact_filters_populated(self.indexer.store.as_ref(), &fence)?;
        let store = self.indexer.store.as_ref();
        let gen_id = crate::segment::import::next_segment_id(store)?;
        crate::segment::import::clear_unpublished_segment_rows(store)?;
        let mut height_rows = by_height.map(|row| {
            let key = crate::segment::format::encode_filter_key(gen_id, row.height);
            let value = crate::segment::format::encode_filter_value(
                &row.block_hash,
                &row.filter_hash,
                &row.header,
                &row.filter,
            );
            (key.to_vec(), value)
        });
        let staged =
            store.ingest_sorted(ColumnFamily::Filters, &mut height_rows, attachment.scratch)?;
        if staged != attachment.records {
            return Err(IndexError::CompactFiltersIncomplete {
                expected: attachment.records,
                actual: staged,
            });
        }
        let segment = crate::segment::import::ImportedSegment {
            coverage: crate::segment::Coverage::new(
                0,
                attachment.base.height,
                attachment.base.hash,
            ),
            next_ordinal: 0,
            records: attachment.records,
            families: Vec::new(),
        };
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
        crate::segment::import::put_segment(
            &mut batch,
            gen_id,
            &segment,
            IndexCapabilities::COMPACT_FILTERS,
        );
        commit_ordinary(store, self.generation, &fence, batch)?;
        Ok(attachment.records)
    }

    pub fn attach_streamed_tx_lookup(
        &self,
        tx_dir: &crate::segment::import::StreamedFamily,
        seal: &crate::segment::import::StreamedSeal,
        attachment: &crate::writer::TxLookupAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_tx_lookup_populated(&existing)?;
        self.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_tx_lookup_populated(&fence)?;
        let store = self.indexer.store.as_ref();
        let gen_id = crate::segment::import::next_segment_id(store)?;
        crate::segment::import::clear_unpublished_segment_rows(store)?;
        crate::segment::import::stage_streamed(
            store,
            gen_id,
            ColumnFamily::TxDir,
            tx_dir,
            attachment.scratch,
        )?;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        for header in attachment.headers {
            if store.get(ColumnFamily::BlockHeaders, *header)?.is_none() {
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
        crate::segment::import::put_streamed_segment(
            &mut batch,
            gen_id,
            seal,
            IndexCapabilities::TX_LOOKUP,
        );
        commit_ordinary(store, self.generation, &fence, batch)?;
        Ok(seal.records)
    }

    pub fn attach_streamed_script_history(
        &self,
        families: &[(ColumnFamily, crate::segment::import::StreamedFamily)],
        seal: &crate::segment::import::StreamedSeal,
        attachment: &crate::writer::ScriptHistoryAttachment<'_>,
    ) -> Result<u64, IndexError> {
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_script_history_populated(self.indexer.store.as_ref(), &existing)?;
        self.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        refuse_script_history_populated(self.indexer.store.as_ref(), &fence)?;
        let store = self.indexer.store.as_ref();
        let gen_id = crate::segment::import::next_segment_id(store)?;
        crate::segment::import::clear_unpublished_segment_rows(store)?;
        for (cf, family) in families {
            crate::segment::import::stage_streamed(store, gen_id, *cf, family, attachment.scratch)?;
        }
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
        crate::segment::import::put_streamed_segment(
            &mut batch,
            gen_id,
            seal,
            IndexCapabilities::SCRIPT_HISTORY,
        );
        commit_ordinary(store, self.generation, &fence, batch)?;
        Ok(seal.records)
    }

    pub fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::InvalidResetMarker);
        }
        resume_capability_reset(
            self.indexer.store.as_ref(),
            self.generation,
            capabilities.to_mask(),
        )?;
        crate::segment::import::clear_unpublished_segment_rows(self.indexer.store.as_ref())
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
        let image = parse_body(body)?;
        let header = image.header_bytes();
        let mut rows = pending_rows_for_image(&image, height, capabilities, spent_scripts)?;
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
        let needs_scripts = capabilities.contains(IndexCapability::ScriptHistory)
            || capabilities.contains(IndexCapability::CompactFilters);
        let committed = Box::new(committed_block_from_image(
            &image,
            hash,
            parent_hash,
            &BodyFacts {
                height,
                needs_scripts,
                spent_coins: spent_scripts,
            },
        )?);

        let tail = PreparedTail::for_capabilities(&committed, capabilities);
        let family_bytes = rows
            .encoded_bytes_by_family()?
            .checked_add(&planned_tail_bytes(&committed, &tail)?)?;
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
            committed,
            tail,
        })
    }

    pub fn prepare_block_from_facts(
        &self,
        capabilities: IndexCapabilities,
        block: bitcoin_rs_storage::CommittedBlock,
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        let mut rows = pending_rows_for_facts(&block, capabilities)?;
        rows.sort();
        let row_count = rows.total();

        let tail = PreparedTail::for_capabilities(&block, capabilities);
        let family_bytes = rows
            .encoded_bytes_by_family()?
            .checked_add(&planned_tail_bytes(&block, &tail)?)?;
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
            committed: Box::new(block),
            tail,
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
        validate_cursor_update(cursor)?;
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
        let mut pending: VecDeque<PreparedBlock> = batch.into_blocks().into();
        let mut fence = fence;
        let mut last = None;
        while !pending.is_empty() {
            if let Some(watermark) =
                self.commit_next_step(&mut fence, capabilities, &mut pending, cursor)?
            {
                last = Some(watermark);
            }
        }
        last.ok_or(IndexError::NonContiguousPrepared {
            watermark: fence.watermarks.tx_lookup,
        })
    }

    fn commit_next_step(
        &mut self,
        fence: &mut IndexWriteFence,
        capabilities: IndexCapabilities,
        pending: &mut VecDeque<PreparedBlock>,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let current = fence.watermarks.selected(capabilities)?;
        let state = self.tail_for(current)?;
        let take = Self::admitted_prefix(&state, pending);
        if take > 0 {
            let run: Vec<PreparedBlock> = pending.drain(..take).collect();
            let run_cursor = if pending.is_empty() {
                cursor
            } else {
                ConsumerCursorUpdate::Keep
            };
            self.tail = Some(state);
            let watermark = self.forward_run(*fence, capabilities, run, run_cursor)?;
            *fence = self.fenced_watermarks()?.0;
            return Ok(Some(watermark));
        }
        let Some(head_bytes) = pending
            .front()
            .map(|head| crate::segment::tail::block_tail_bytes_bound(&head.committed))
        else {
            return Ok(None);
        };
        if head_bytes > Self::tail_byte_limit() {
            let Some(block) = pending.pop_front() else {
                return Ok(None);
            };
            if let Some(newest) = state.window.back().map(|block| block.height) {
                self.seal_through(&state, newest, capabilities)?;
            }
            let run_cursor = if pending.is_empty() {
                cursor
            } else {
                ConsumerCursorUpdate::Keep
            };
            let watermark = self.commit_oversized(*fence, capabilities, block, run_cursor)?;
            *fence = self.fenced_watermarks()?.0;
            return Ok(Some(watermark));
        }
        let cut = state
            .cut_before_append(head_bytes)
            .ok_or(IndexError::NonContiguousPrepared { watermark: current })?;
        self.seal_through(&state, cut, capabilities)?;
        Ok(None)
    }

    fn commit_oversized(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        block: PreparedBlock,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        let watermark = self.forward_run(fence, capabilities, vec![block], cursor)?;
        if let Some(alone) = self.tail.take() {
            self.seal_through(&alone, watermark.height, capabilities)?;
        }
        Ok(watermark)
    }

    fn admitted_prefix(state: &TailWriterState, pending: &VecDeque<PreparedBlock>) -> usize {
        let mut take = 0_usize;
        let mut bytes = 0_u64;
        for block in pending {
            let next = bytes.saturating_add(crate::segment::tail::block_tail_bytes_bound(
                &block.committed,
            ));
            if !state.admits(take + 1, next) {
                break;
            }
            take += 1;
            bytes = next;
        }
        take
    }

    fn tail_byte_limit() -> u64 {
        u64::try_from(crate::segment::format::TAIL_MAX_BYTES).unwrap_or(u64::MAX)
    }

    fn forward_run(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        run: Vec<PreparedBlock>,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        let current = fence.watermarks.selected(capabilities)?;
        let expected_height = match current {
            None => 0,
            Some(w) => w
                .height
                .checked_add(1)
                .ok_or(IndexError::NonContiguousPrepared { watermark: current })?,
        };
        let expected_parent = current.map(|w| w.hash);
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for block in run {
            batch
                .try_push(block)
                .map_err(|_| IndexError::NonContiguousPrepared { watermark: current })?;
        }
        let batch_family_bytes = batch.family_bytes();
        let (merged, final_watermark, blocks) =
            chain_forward_blocks(batch, current, expected_height, expected_parent)?;
        let mut tail = self.tail_for(current)?;
        let mut store_batch = self.indexer.store.new_batch();
        put_rows(&mut store_batch, &merged)?;
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, Some(final_watermark));
        self.append_forward_tail(&mut tail, &blocks, &mut store_batch)?;
        crate::segment::tail::put_generation_descriptors(
            &mut store_batch,
            capabilities.iter(),
            tail.bounds(),
        );
        apply_cursor_update(&mut store_batch, cursor);
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )?;
        record_family_byte_histograms(&batch_family_bytes);
        self.tail = Some(tail);
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
        validate_cursor_update(cursor)?;
        let capabilities = tail_rollback_group(fence.watermarks, capabilities);
        let current = fence
            .watermarks
            .selected(capabilities)?
            .ok_or(IndexError::NonContiguousPrepared { watermark: None })?;
        let prepared = self.prepare_block_with_spent_scripts(
            rollback_prepare_capabilities(capabilities),
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
        let mut tail = self.tail_for(Some(current))?;
        let snapshot = self.indexer.store.snapshot()?;
        let tail_plan = Self::plan_rollback_tail(snapshot.as_ref(), capabilities, current)?;
        drop(snapshot);
        let historical_prev = tail_plan.rewind(prev)?;
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
        put_selected_watermarks(
            &mut store_batch,
            capabilities.without(IndexCapability::ScriptLive),
            historical_prev,
        );
        if capabilities.contains(IndexCapability::ScriptLive) {
            put_selected_watermarks(&mut store_batch, IndexCapabilities::SCRIPT_LIVE, prev);
        }
        self.apply_rollback_tail(
            &mut tail,
            RollbackStep {
                plan: tail_plan,
                capabilities,
                current,
                prev: historical_prev,
                batch: &mut store_batch,
            },
        )?;
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
        validate_cursor_update(ConsumerCursorUpdate::Set(cursor))?;
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
pub(crate) const FAMILY_TAIL_LOG: &str = "tail_log";
pub(crate) const FAMILY_FILTERS: &str = "filters";

#[expect(clippy::expect_used, reason = "usize metric value fits in u64")]
fn metric_f64_from_usize(val: usize) -> f64 {
    bitcoin_rs_consensus::primitives::u64_to_f64(u64::try_from(val).expect("usize fits in u64"))
}

pub(crate) fn record_family_byte_histograms(family_bytes: &IndexRowBytes) {
    for (label, bytes) in [
        (FAMILY_TX_LOOKUP, family_bytes.tx_lookup),
        (FAMILY_SCRIPT_HISTORY, family_bytes.script_history),
        (FAMILY_SCRIPT_LIVE, family_bytes.script_live),
        (FAMILY_HEADERS, family_bytes.headers),
        (FAMILY_FILTERS, family_bytes.filters),
        (FAMILY_TAIL_LOG, family_bytes.tail_log),
    ] {
        if bytes > 0 {
            metrics::histogram!(FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM, FAMILY_LABEL => label)
                .record(metric_f64_from_usize(bytes));
        }
    }
}

/// Bytes a forward commit writes outside the planned families: the format
/// marker, the ordinary revision, the watermarks, the generation descriptors,
/// and the consumer cursor at its widest, a full cursor value. The figure
/// comes from the same writers the commit runs.
pub(crate) fn commit_overhead_bytes(capabilities: IndexCapabilities) -> usize {
    let mut batch = BufferedWriteBatch::default();
    batch.put(
        ColumnFamily::UtxoMeta,
        FORMAT_VERSION_KEY,
        &FORMAT_VERSION_VALUE,
    );
    batch.put(
        ColumnFamily::UtxoMeta,
        ORDINARY_STATE_REVISION_KEY,
        &0_u64.to_le_bytes(),
    );
    put_selected_watermarks(
        &mut batch,
        capabilities,
        Some(IndexWatermark {
            height: 0,
            hash: [0; 32],
        }),
    );
    crate::segment::tail::put_generation_descriptors(
        &mut batch,
        capabilities.iter(),
        crate::segment::tail::TailBounds::default(),
    );
    batch.put(
        ColumnFamily::UtxoMeta,
        CONSUMER_CURSOR_KEY,
        &[0_u8; crate::reconcile::CURSOR_BYTE_LEN],
    );
    batch
        .into_ops()
        .iter()
        .map(batch_op_bytes)
        .fold(0_usize, usize::saturating_add)
}

fn batch_op_bytes(op: &BatchOp) -> usize {
    match op {
        BatchOp::Put { key, value, .. } => key.len().saturating_add(value.len()),
        BatchOp::Delete { key, .. } => key.len(),
        BatchOp::DeleteRange { start, end, .. } => start.len().saturating_add(end.len()),
    }
}

/// TxLookup, ScriptHistory, and CompactFilters share one tail and one undo log,
/// so a rollback of any of them at height h is one group rollback. The group is
/// the tail-bound capabilities whose watermark sits at the requested height.
pub(crate) fn tail_rollback_group(
    watermarks: IndexWatermarks,
    requested: IndexCapabilities,
) -> IndexCapabilities {
    let tail_bound = |capability: &IndexCapability| *capability != IndexCapability::ScriptLive;
    let requested_height = IndexCapability::ALL
        .into_iter()
        .filter(tail_bound)
        .find(|capability| requested.contains(*capability))
        .and_then(|capability| watermarks.get(capability))
        .map(|watermark| watermark.height);

    let Some(height) = requested_height else {
        return requested;
    };
    IndexCapability::ALL
        .into_iter()
        .filter(tail_bound)
        .filter(|capability| watermarks.get(*capability).map(|w| w.height) == Some(height))
        .fold(requested, IndexCapabilities::insert)
}

/// A rollback needs the block's header and parent. Tail-bound rows come from the
/// tail's own undo log, so only ScriptLive needs spent scripts to prepare.
pub(crate) fn rollback_prepare_capabilities(capabilities: IndexCapabilities) -> IndexCapabilities {
    if capabilities.contains(IndexCapability::ScriptLive) {
        capabilities
    } else {
        IndexCapabilities::TX_LOOKUP
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
        .iter_prefix(
            ColumnFamily::UtxoMeta,
            super::state::LEGACY_FILTER_ROW_PREFIX,
        )?
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

/// The merged rows, final watermark, and per-block committed facts with their
/// prepared tail rows, in height order.
type ChainedForward = (
    PendingRows,
    IndexWatermark,
    Vec<(bitcoin_rs_storage::CommittedBlock, PreparedTail)>,
);

fn chain_forward_blocks(
    batch: PreparedBatch,
    current: Option<IndexWatermark>,
    mut expected_height: u32,
    mut expected_parent: Option<[u8; 32]>,
) -> Result<ChainedForward, IndexError> {
    let mut merged = PendingRows::default();
    let mut last = None;
    let block_count = batch.len();
    let mut blocks = Vec::with_capacity(block_count);
    for (block_index, block) in batch.into_blocks().into_iter().enumerate() {
        if block.height != expected_height {
            return Err(IndexError::NonContiguousPrepared { watermark: current });
        }
        if let Some(parent) = expected_parent {
            if block.parent_hash != parent {
                return Err(IndexError::NonContiguousPrepared { watermark: current });
            }
        }
        blocks.push((*block.committed, block.tail));
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
    Ok((merged, final_watermark, blocks))
}

fn validate_cursor_update(cursor: ConsumerCursorUpdate<'_>) -> Result<(), IndexError> {
    match cursor {
        ConsumerCursorUpdate::Set(bytes) if bytes.len() > crate::reconcile::CURSOR_BYTE_LEN => {
            Err(IndexError::CursorLength { len: bytes.len() })
        }
        _ => Ok(()),
    }
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

#[cfg(test)]
mod prepare_from_facts_tests {
    use super::*;

    // PRJ-01
    #[test]
    fn owned_facts_prepare_carries_the_input_identity() -> Result<(), crate::portable::TestError> {
        let block = bitcoin_rs_storage::CommittedBlock {
            height: 7,
            hash: [0x07; 32],
            parent_hash: [0x06; 32],
            header: [0x07; 80],
            txs: vec![bitcoin_rs_storage::committed_facts::TxFacts {
                txid: [0x07; 32],
                offset: 0,
                len: 100,
                inputs: vec![bitcoin_rs_storage::committed_facts::SpentPrevout {
                    txid: [0x06; 32],
                    vout: 0,
                    value: 5_000,
                    script: bitcoin_rs_storage::Bytes::from_static(&[0x51]),
                    height: 6,
                    coinbase: false,
                }],
                outputs: vec![bitcoin_rs_storage::committed_facts::CreatedOutput {
                    vout: 0,
                    value: 5_000,
                    script: bitcoin_rs_storage::Bytes::from_static(&[0x52]),
                }],
            }],
        };
        let store = std::sync::Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
        let writer = IndexWriter::open(store, 1)?;
        let prepared = writer.prepare_block_from_facts(IndexCapabilities::HISTORICAL, block)?;
        assert_eq!(
            prepared.watermark(),
            IndexWatermark {
                height: 7,
                hash: [0x07; 32]
            }
        );
        Ok(())
    }
}
