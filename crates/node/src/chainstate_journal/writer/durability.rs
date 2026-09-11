//! Undo flush, segment sync, and atomic durable-head publication in dependency order.

use super::DurableCursor;
use super::HeadMarker;
use super::JournalWriter;
use super::JournalWriterError;
use super::segment_name;
use bitcoin_rs_storage::KvStore;
use std::io::Write;
use std::time::Instant;

impl<S: KvStore> JournalWriter<S> {
    /// §2.3 durability boundary, in one serialized step:
    /// 1. storage flush (deferred undo rows become durable),
    /// 2. log fsync,
    /// 3. atomic `head.json` publish.
    ///
    /// `target` is the record index (exclusive) in `pending_records` that the
    /// boundary covers.
    pub(super) fn advance_durability(&mut self) -> Result<(), JournalWriterError> {
        self.advance_durability_upto(self.pending_records.len())
    }

    /// Publishes `head.json` without advancing the cursor (used at
    /// initialization and by `freeze`).
    pub(super) fn publish_head_now(&self) -> Result<(), JournalWriterError> {
        let marker = self.head();
        self.write_head_atomic(&marker)
    }

    pub(super) fn write_head_atomic(&self, marker: &HeadMarker) -> Result<(), JournalWriterError> {
        self.fail_head_temp_write()?;
        {
            let mut options = cap_std::fs::OpenOptions::new();
            options.write(true).create(true);
            let mut tmp = self.dir.open_with("head.json.tmp", &options)?;
            tmp.set_len(0)?;
            tmp.write_all(&marker.serialize()?)?;
            self.fail_head_temp_sync()?;
            tmp.sync_all()?;
        }
        self.fail_head_rename()?;
        self.dir.rename("head.json.tmp", &self.dir, "head.json")?;
        self.fail_head_dir_sync()?;
        crate::checkpoint::fs::sync_dir(&self.dir)?;
        self.record_size_metric();
        Ok(())
    }

    /// Flushes buffered records up to and including `height` (plan §2.5's
    /// `flush_to`). No-op when the height is already durable; errors when the
    /// height is beyond the buffered frontier.
    pub(crate) fn flush_to(&mut self, height: u32) -> Result<(), JournalWriterError> {
        if height <= self.durable.height {
            return Ok(());
        }
        let Some(index) = self
            .pending_records
            .iter()
            .rposition(|record| record.height == height)
        else {
            return Err(JournalWriterError::CursorMismatch(format!(
                "height {height} is not buffered"
            )));
        };
        self.advance_durability_upto(index + 1)
    }

    /// Boundary over the first `target` buffered records.
    pub(super) fn advance_durability_upto(
        &mut self,
        target: usize,
    ) -> Result<(), JournalWriterError> {
        let result = self.try_advance_durability_upto(target);
        self.durability_retry_required = result.is_err();
        result
    }

    pub(super) fn try_advance_durability_upto(
        &mut self,
        target: usize,
    ) -> Result<(), JournalWriterError> {
        if self.pending_records.is_empty() || target == 0 {
            return Ok(());
        }
        let last = self.pending_records[target - 1];
        let target_offset = last.end_offset;
        let target_chain_tx_count = self.pending_records[..target].iter().try_fold(
            self.durable_chain_tx_count,
            |count, record| {
                count.checked_add(record.block_tx_count).ok_or_else(|| {
                    JournalWriterError::CursorMismatch(
                        "chain transaction count overflow".to_owned(),
                    )
                })
            },
        )?;

        self.fail_storage_flush()?;
        let flush_started = Instant::now();
        let flush_result = self
            .store
            .flush()
            .map_err(|error| JournalWriterError::StorageFlush(error.to_string()));
        metrics::histogram!("node.chainstate_journal.storage_flush_seconds")
            .record(flush_started.elapsed().as_secs_f64());
        flush_result?;

        self.fail_segment_sync()?;
        let name = segment_name(self.segment_gen);
        let file = self
            .dir
            .open_with(&name, cap_std::fs::OpenOptions::new().write(true))?;
        file.sync_all()?;

        let marker = HeadMarker {
            base_generation: self.base_generation,
            base_height: self.base_height,
            base_hash: self.base_hash,
            base_chain_tx_count: self.base_chain_tx_count,
            start_gen: self.start.0,
            start_offset: self.start.1,
            journal_gen: self.segment_gen,
            offset: target_offset,
            height: last.height,
            block_hash: last.block_hash,
            prev_hash: last.prev_hash,
            chain_tx_count: target_chain_tx_count,
            record_count: self.record_count
                + u64::try_from(target).map_err(|_| {
                    JournalWriterError::CursorMismatch("record count overflow".to_owned())
                })?,
        };
        self.write_head_atomic(&marker)?;

        self.durable = DurableCursor {
            generation: self.segment_gen,
            offset: target_offset,
            height: last.height,
        };
        self.durable_block_hash = last.block_hash;
        self.durable_prev_hash = last.prev_hash;
        self.durable_chain_tx_count = target_chain_tx_count;
        self.record_count += u64::try_from(target)
            .map_err(|_| JournalWriterError::CursorMismatch("record count overflow".to_owned()))?;
        self.pending_records.drain(..target);
        self.last_boundary = Instant::now();
        self.record_lag_metrics();
        Ok(())
    }
}
