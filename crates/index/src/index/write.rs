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
use bitcoin_rs_storage::{ColumnFamily, KvStore};

/// Mutation-only handle for durable prepared `TxIndex` writes.
pub struct IndexWriter<S: KvStore> {
    pub(super) indexer: Indexer<S>,
    /// Process epoch recorded as reset-claim provenance. Any process may
    /// complete the exact claim; the durable reset bytes, not this epoch,
    /// fence ordinary mutations and reset completion.
    pub(super) generation: u64,
}

impl<S: KvStore> IndexWriter<S> {
    /// Read access to the owned indexer, for queries beside the write path.
    pub fn indexer(&self) -> &Indexer<S> {
        &self.indexer
    }

    /// Opens a writer over `store`, rejecting unversioned index tables.
    ///
    /// Format 5 changed every row family (big-endian heights, 43-byte live
    /// rows, 6-byte positions), so any older marker is
    /// [`IndexError::UnsupportedTxIndexFormatVersion`]; recovery full-resets
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
        // A plain open adopts any outstanding obligation (requested mask 0)
        // without publishing a claim of its own.
        resume_capability_reset(indexer.store.as_ref(), generation, 0)?;
        Ok(Self {
            indexer,
            generation,
        })
    }

    /// Loads the exact durable watermark.
    pub fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.indexer.watermark()
    }

    /// Loads independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        self.indexer.watermarks()
    }

    /// Captures one coherent fence with the exact reset state, ordinary revision,
    /// and all capability watermarks from a single snapshot. It returns the
    /// fence with the watermarks it carries. A reset that
    /// begins or completes in the read window therefore returns
    /// [`IndexError::ResetInProgress`]; callers must discard derived
    /// state and re-capture.
    pub fn fenced_watermarks(&mut self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        Ok((fence, fence.watermarks))
    }

    /// Resets every derived capability through the durable exact-claim fence.
    ///
    /// A pre-existing selective reset is merged into the all-capability
    /// obligation before any row is deleted.
    pub fn reset_index(store: &S, generation: u64) -> Result<(), IndexError> {
        resume_capability_reset(store, generation, IndexCapabilities::ALL.to_mask())
    }

    /// Seeds the live view from a producer of compact locators.
    ///
    /// `produce` emits every live `(outpoint, scripthash)` at `seed_tip`.
    /// Each bounded batch, and the watermark stamp, is an ordinary fenced
    /// write: reset state, ordinary revision, and every capability watermark
    /// must still match the capture. A lost fence is [`IndexError::StaleIndexState`]
    /// or [`IndexError::ResetInProgress`]; a storage failure is
    /// [`IndexError::Storage`]. The caller resets this capability before
    /// retrying. See `IDX-07` in `docs/contracts/indexing.md`.
    ///
    /// The live watermark is written only with the last batch, so an
    /// interrupted seed stays unqueryable. Refuses to run over an existing
    /// live watermark ([`IndexError::LiveAlreadySeeded`]).
    ///
    /// A missing live watermark with leftover rows is treated as an
    /// interrupted seed: `ScriptLive` is reset before any new row is
    /// written so a later watermark cannot advertise a stale view.
    pub(crate) fn seed_script_live_stream<F>(
        &self,
        mut produce: F,
        seed_tip: IndexWatermark,
    ) -> Result<usize, IndexError>
    where
        F: FnMut(
            &mut dyn FnMut(OutPoint, crate::ScriptHash) -> Result<(), IndexError>,
        ) -> Result<(), IndexError>,
    {
        const SEED_BATCH_ROWS: usize = 4_096;
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if existing.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        // An interrupted seed leaves rows without a ready watermark. Clear
        // them before writing so this publication cannot mix leftover
        // locators from a previous attempt. Recapture after the reset: the
        // claim advances the fence, so a pre-reset capture cannot commit.
        self.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        let mut fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if fence.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        let mut written = 0;
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
            Ok(())
        };
        produce(&mut add)?;
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

    /// Seeds `ScriptLive` from an iterator of compact locators.
    ///
    /// Delegates to `Self::seed_script_live_stream` so fenced write
    /// failures and watermark publication have one owner.
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
        )
    }

    /// Imports verified `TxLookup` rows and block identities for a portable
    /// bundle restore.
    ///
    /// `produce` emits every row of the bundle. Each bounded batch is an
    /// ordinary fenced write: reset state, ordinary revision, and every
    /// capability watermark must still match the capture, so a lost fence is
    /// [`IndexError::StaleIndexState`] or [`IndexError::ResetInProgress`]. The
    /// `TxLookup` watermark and coverage floor are written only in the final
    /// commit, after `produce` has returned, so an error, crash, or aborted
    /// source leaves the capability un-watermarked (and therefore
    /// `Unavailable`) with partial rows the caller resets.
    ///
    /// An existing `TxLookup` watermark is never reset or overwritten:
    /// the import refuses with [`IndexError::WatermarkMismatch`] naming it.
    /// Leftover rows without a watermark are an interrupted earlier attempt
    /// and are cleared through the capability reset before any row is written.
    ///
    /// Returns the number of `TxLookup` rows written.
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
        // Recapture after the reset: the claim advances the fence, so a
        // pre-reset capture cannot commit.
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

    /// Marks selected derived rows unavailable, deletes them in bounded batches,
    /// and leaves their durable cursors empty so the worker can rebuild from genesis.
    ///
    /// The claim and cursor deletion land atomically before row deletion, and
    /// completion CASes the exact claim to the next idle version.
    /// `open` resumes an interrupted reset before exposing the writer again.
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

    /// Stamps `watermark` on the selected capabilities without deriving rows.
    ///
    /// A rebuild from a pruned prefix needs the durable cursor to start at
    /// the first surviving height, not at genesis: the pruning authority has
    /// already deleted the bodies below it, so no commit can ever produce
    /// them. The anchor names the chain identity at that boundary — the
    /// block tree keeps headers for pruned heights, so the identity is
    /// always available — and the next prepared block must be its child.
    ///
    /// The write is fenced like every ordinary commit, so a reset in flight
    /// or a moved revision reports `ResetInProgress`/`StaleIndexState`.
    ///
    /// `floor` is the first covered height (`anchor.height + 1`): queries that
    /// cannot prove absence below it answer `Unavailable` rather than `None`.
    ///
    /// `capabilities` must name only history-derived indexes: `ScriptLive`
    /// reseeds from the authoritative UTXO view, so anchoring it would
    /// publish a live watermark with no rows behind it.
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

    /// Derives a `PreparedBlock` from a serialized body without allocating a decoded block.
    pub fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.prepare_block_for(IndexCapabilities::HISTORICAL, height, hash, body)
    }

    /// Derives capability-selected row mutations from one serialized block scan.
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

    /// [`Self::prepare_block_for`] with the spent-coin script source
    /// `ScriptLive` and `CompactFilters` preparation require.
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

    /// Commits one serialized block through the prepared-write owner.
    ///
    /// The successful return is the commit point: prepared rows and the
    /// watermark become durable together. Storage-write failures can leave the
    /// commit uncertain; the supervised worker owns retry from the last confirmed
    /// watermark, or reset and rebuild.
    ///
    /// Selects [`IndexCapabilities::HISTORICAL`]. Callers maintaining
    /// `ScriptLive` must use [`Self::prepare_block_with_spent_scripts`] with a
    /// spent-script source, then [`Self::commit_forward`]. See `IDX-06` /
    /// `IDX-07` in `docs/contracts/indexing.md`.
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

    /// Atomically connects a bounded batch and advances the durable watermark.
    ///
    /// Captures its own fence before any store-dependent derivation and keeps
    /// the consumer cursor untouched. See `IDX-06` / `IDX-07` in
    /// `docs/contracts/indexing.md`.
    pub fn commit_forward(&mut self, batch: PreparedBatch) -> Result<IndexWatermark, IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_forward_with_cursor(fence, batch, ConsumerCursorUpdate::Keep)
    }

    /// Atomically connects a bounded batch and applies one explicit consumer
    /// cursor disposition guarded by the captured reset-state fence.
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

    /// Atomically rolls back one block and applies one explicit consumer
    /// cursor disposition guarded by the captured reset-state fence.
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

    /// Atomically rolls back one block with the exact scripts of its spent
    /// coins. Required when `ScriptLive` or `CompactFilters` is selected.
    ///
    /// The commit point is the successful return from the durable conditional
    /// write, so recovery sees either the prior state or the complete rollback.
    /// Preparation and fence failures precede the rollback write. Storage-write
    /// errors can leave its commit uncertain; reacquire a fence and reconcile the
    /// stored watermark and cursor before retrying. Same fenced batch as
    /// [`Self::commit_forward`]; see `IDX-06` / `IDX-07` in `docs/contracts/indexing.md`.
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
        // A disabled capability may still point above this block on the same
        // disconnected prefix. Retain every ancestor identity it may need to
        // reconcile when it is enabled again.
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

    /// Loads the opaque consumer cursor bytes, or `None` when none is stored.
    ///
    /// The cursor is opaque to this crate: the owning consumer defines the
    /// encoding and writes it only after its rows reached the position it
    /// names, so a present cursor always describes committed rows.
    pub fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        Ok(self
            .indexer
            .store
            .get(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY)?)
    }

    /// Publishes the opaque consumer cursor under five exact conditions from the
    /// captured fence: reset state, ordinary revision, and all watermark rows.
    /// The commit atomically advances the ordinary revision.
    ///
    /// A lost race with an unchanged reset returns
    /// [`IndexError::StaleIndexState`]. A moved reset cooperatively completes
    /// the pending exact claim and returns [`IndexError::ResetInProgress`].
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

/// One verified row of a portable `TxLookup` import.
pub(crate) enum PortableImportRow<'a> {
    /// The 80-byte header identity of an active-chain block at or below the
    /// bundle base, so ordinary rollback can unseat the base later.
    Header(&'a [u8; crate::types::HEADER_ROW_SIZE]),
    /// One `TxConfirmed` row and its packed `TxPosition` value.
    TxLookup {
        /// Stored key: txid prefix and big-endian height.
        row: crate::types::HashPrefixRow,
        /// Sorted, packed positions of every transaction filed under the key.
        value: &'a [u8],
    },
}

/// The compiled on-disk index format number a portable bundle must carry.
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

/// Metric name for per-family planned write bytes histogram.
///
/// Records logical pre-coalescing planned bytes for row families present in a
/// prepared batch. Excludes engine-internal overhead, write-ahead logs, and
/// device-level physical storage writes.
pub(crate) const FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM: &str = "index.family_planned_write_bytes";
/// Label key distinguishing row families in [`FAMILY_PLANNED_WRITE_BYTES_HISTOGRAM`].
pub(crate) const FAMILY_LABEL: &str = "family";

pub(crate) const FAMILY_TX_LOOKUP: &str = "tx_lookup";
pub(crate) const FAMILY_SCRIPT_HISTORY: &str = "script_history";
pub(crate) const FAMILY_SCRIPT_LIVE: &str = "script_live";
pub(crate) const FAMILY_HEADERS: &str = "headers";
pub(crate) const FAMILY_FILTERS: &str = "filters";

fn metric_f64_from_usize(val: usize) -> f64 {
    bitcoin_rs_primitives::u64_to_f64(u64::try_from(val).unwrap_or(u64::MAX))
}

/// Emits one histogram observation per index family present with non-zero planned bytes in a committed batch.
///
/// Observations reflect the sum of prepared rows before multi-block coalescing (logical planned bytes),
/// and do not measure actual emitted batch writes or physical storage I/O.
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
