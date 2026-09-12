//! The sole concrete owner of durable index mutations.

use super::{
    block::NoSpentScripts, block::SpentCoinScripts, capability::IndexCapabilities,
    capability::IndexWatermark, capability::IndexWatermarks, capability::SCRIPT_LIVE_WATERMARK_KEY,
    capability::put_selected_watermarks, capability::selected_watermark, error::IndexError,
    prepared::PreparedBatch, prepared::PreparedBatchLimits, reader::Indexer, rows::IndexRowCounts,
    rows::PendingRows, rows::delete_rows, rows::put_rows, state::CONSUMER_CURSOR_KEY,
    state::ConsumerCursorUpdate, state::FORMAT_VERSION_KEY, state::FORMAT_VERSION_VALUE,
    state::IndexWriteFence, state::capture_write_fence, state::commit_ordinary,
    state::ensure_fence_live, state::resume_capability_reset,
};
use bitcoin_rs_primitives::{OutPoint, encode};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};

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

    /// Returns the row counts from the last successful prepared commit.
    pub const fn last_counts(&self) -> IndexRowCounts {
        self.indexer.last_counts()
    }

    /// Loads both independently durable capability watermarks.
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
    pub fn seed_script_live_stream<F>(
        &mut self,
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
    /// Delegates to [`Self::seed_script_live_stream`] so fenced write
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

    /// Commits one serialized block through the prepared-write owner.
    ///
    /// The successful return is the commit point: all prepared rows and the
    /// watermark become durable together under the store's atomic-write
    /// guarantee. A crash before that point leaves the previous watermark and
    /// rows; a crash after it leaves both the rows and watermark. A failed
    /// call is therefore ambiguous to the caller: do not retry blindly or
    /// write column families directly. The supervised index worker owns
    /// retry-from-the-last-confirmed-watermark, or reset and rebuild when
    /// the persisted state cannot be established; storage failures are
    /// non-retriable after the worker is marked failed.
    ///
    /// Production catch-up uses [`Self::prepare_block_with_spent_scripts`] plus
    /// [`super::prepared::PreparedBatch`] to bound multi-block writes. This is the same owner
    /// for a single block: tests and benches must not grow a second ingest path.
    /// Delegates to [`Self::commit_forward`]. See `IDX-06` / `IDX-07` in
    /// `docs/contracts/indexing.md`.
    ///
    /// This path selects [`IndexCapabilities::HISTORICAL`]: it advances
    /// `TxLookup` and `ScriptHistory` only. Callers that maintain `ScriptLive`
    /// must use [`Self::prepare_block_with_spent_scripts`] with `script_live`
    /// selected and a spent-script source, then [`Self::commit_forward`].
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
        let current = selected_watermark(fence.watermarks, capabilities)?;
        let mut expected_height = match current {
            None => 0,
            Some(w) => w
                .height
                .checked_add(1)
                .ok_or(IndexError::NonContiguousPrepared { watermark: current })?,
        };
        let mut expected_parent = current.map(|w| w.hash);
        let mut merged = PendingRows::default();
        let mut last = None;
        let block_count = batch.len();
        for (block_index, block) in batch.into_blocks().into_iter().enumerate() {
            if block.height != expected_height {
                return Err(IndexError::NonContiguousPrepared { watermark: current });
            }
            if let Some(parent) = expected_parent {
                if block.parent_hash != parent {
                    return Err(IndexError::NonContiguousPrepared { watermark: current });
                }
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
        self.indexer.last_counts = merged.counts();
        Ok(final_watermark)
    }

    /// Atomically rolls back one tip block and writes the parent watermark.
    ///
    /// Captures its own fence before any store-dependent derivation and
    /// clears the consumer cursor atomically: without a valid replacement
    /// block the cursor names rows that no longer exist.
    pub fn commit_rollback_one(
        &mut self,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor(
            fence,
            IndexCapabilities::HISTORICAL,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
        )
    }

    /// Atomically rolls back one block for the selected capabilities,
    /// capturing its own fence and clearing the consumer cursor.
    pub fn commit_rollback_one_for(
        &mut self,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        if capabilities.script_live {
            return Err(IndexError::MissingSpentScripts);
        }
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
        )
    }

    /// Rolls back a selected transition using authoritative spent-coin
    /// scripts. `ScriptLive` uses this anchor to restore rows for outputs that
    /// the disconnected block had spent.
    pub fn commit_rollback_one_with_spent_scripts(
        &mut self,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<(), IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
            spent_scripts,
        )
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
        if capabilities.script_live {
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
    /// coins. This is the anchored variant used when `ScriptLive` is selected.
    ///
    /// The commit point is the successful return from the durable conditional
    /// store write. Until then, no rollback rows, selected watermark, cursor,
    /// or ordinary revision is committed; after it, they are committed as one
    /// batch. Consequently, crash recovery sees either the prior state or the
    /// complete rollback state, never a partially applied rollback.
    ///
    /// Preparation and fence checks are deterministic failures and should be
    /// corrected rather than retried unchanged. Storage failures are returned
    /// without claiming whether the write reached the backend; the caller owns
    /// recovery, and must reacquire a fence and reconcile the stored watermark
    /// and cursor before retrying or compensating. A successful return is the
    /// durability guarantee; an error must not be treated as proof of rollback.
    ///
    /// Same fenced batch as [`Self::commit_forward`]. See `IDX-06` / `IDX-07`
    /// in `docs/contracts/indexing.md`.
    pub fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<(), IndexError> {
        let current = selected_watermark(fence.watermarks, capabilities)?
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
        let unselected_keeps_identity = (!capabilities.tx_lookup
            && fence
                .watermarks
                .tx_lookup
                .is_some_and(|watermark| watermark.height >= current.height))
            || (!capabilities.script_history
                && fence
                    .watermarks
                    .script_history
                    .is_some_and(|watermark| watermark.height >= current.height))
            || (!capabilities.script_live
                && fence
                    .watermarks
                    .script_live
                    .is_some_and(|watermark| watermark.height >= current.height));
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
        self.indexer.last_counts = prepared.rows.counts();
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

    /// Forces all completed writes to durable storage.
    pub fn flush(&self) -> Result<(), IndexError> {
        self.indexer.store.flush().map_err(IndexError::Storage)
    }
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
