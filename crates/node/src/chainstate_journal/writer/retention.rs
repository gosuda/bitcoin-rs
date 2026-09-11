//! Lag backpressure, journal retention, checkpoint compaction, and writer resumption.

use super::DurableCursor;
use super::HeadMarker;
use super::JournalWriter;
use super::JournalWriterError;
use super::WriterState;
use super::clear_full_revalidation_marker;
use super::parse_segment_name;
use bitcoin_rs_storage::KvStore;
use std::time::Duration;
use std::time::Instant;

impl<S: KvStore> JournalWriter<S> {
    /// Applies the resolved runtime batching and segment-rotation policy.
    pub(crate) fn configure(
        &mut self,
        batch_blocks: u32,
        batch_seconds: Duration,
        rotate_mib: u64,
        max_journal_mib: u64,
        max_lag_blocks: u32,
        max_lag_seconds: Duration,
    ) -> Result<(), JournalWriterError> {
        if batch_blocks == 0
            || batch_seconds.is_zero()
            || rotate_mib == 0
            || max_journal_mib == 0
            || max_lag_blocks == 0
            || max_lag_seconds.is_zero()
        {
            return Err(JournalWriterError::CursorMismatch(
                "journal runtime limits must be non-zero".to_owned(),
            ));
        }
        self.batch_blocks = batch_blocks;
        self.batch_seconds = batch_seconds;
        self.rotate_bytes = rotate_mib.checked_mul(1024 * 1024).ok_or_else(|| {
            JournalWriterError::CursorMismatch("journal rotation size overflow".to_owned())
        })?;
        self.max_journal_bytes = max_journal_mib.checked_mul(1024 * 1024).ok_or_else(|| {
            JournalWriterError::CursorMismatch("journal retention size overflow".to_owned())
        })?;
        self.max_lag_blocks = max_lag_blocks;
        self.max_lag_seconds = max_lag_seconds;
        Ok(())
    }

    /// Applies time/lag/retention maintenance before the next block mutates
    /// chainstate. A failed durability retry stops that apply before any write.
    pub(crate) fn prepare_for_apply(&mut self) -> Result<(), JournalWriterError> {
        self.ensure_appendable()?;
        if self.durability_retry_required {
            self.advance_durability()?;
        }
        self.flush_due()?;
        let lag = self
            .next_height
            .saturating_sub(1)
            .saturating_sub(self.durable.height);
        if lag >= self.max_lag_blocks
            || (!self.pending_records.is_empty()
                && self.last_boundary.elapsed() >= self.max_lag_seconds)
        {
            self.advance_durability()?;
        }
        let bytes = self.journal_size_bytes()?;
        if bytes >= self.max_journal_bytes {
            return Err(JournalWriterError::RetentionLimit {
                bytes,
                limit: self.max_journal_bytes,
            });
        }
        Ok(())
    }

    /// Flushes an idle pending batch once its configured time boundary elapses.
    pub(crate) fn flush_due(&mut self) -> Result<(), JournalWriterError> {
        if self.state == WriterState::Open
            && !self.pending_records.is_empty()
            && self.last_boundary.elapsed() >= self.batch_seconds
        {
            self.advance_durability()?;
        }
        Ok(())
    }

    /// Whether segment retention requires an immediate checkpoint compaction.
    pub(crate) fn requires_compaction(&self) -> Result<bool, JournalWriterError> {
        Ok(self.journal_size_bytes()? >= self.max_journal_bytes)
    }

    pub(super) fn record_lag_metrics(&self) {
        let latest_height = self
            .append_gap_height
            .unwrap_or_else(|| self.next_height.saturating_sub(1));
        let lag = latest_height.saturating_sub(self.durable.height);
        metrics::gauge!("node.chainstate_journal.lag_blocks").set(f64::from(lag));
        metrics::gauge!("node.chainstate_journal.head_height").set(f64::from(self.durable.height));
    }

    pub(super) fn record_size_metric(&self) {
        let Ok(bytes) = self.journal_size_bytes() else {
            return;
        };
        let kib = u32::try_from(bytes / 1024).unwrap_or(u32::MAX);
        metrics::gauge!("node.chainstate_journal.size_mib").set(f64::from(kib) / 1024.0);
    }

    pub(super) fn journal_size_bytes(&self) -> Result<u64, JournalWriterError> {
        self.dir.entries()?.try_fold(0_u64, |total, entry| {
            let entry = entry?;
            if parse_segment_name(entry.file_name().to_string_lossy().as_ref()).is_none() {
                return Ok(total);
            }
            total.checked_add(entry.metadata()?.len()).ok_or_else(|| {
                JournalWriterError::CursorMismatch("journal segment size overflow".to_owned())
            })
        })
    }

    /// §2.5 freeze: stop accepting appends; make the log durable up to the
    /// last buffered record; publish the final head. Called by the publication
    /// primitive with admission already closed.
    pub(crate) fn freeze(&mut self) -> Result<(), JournalWriterError> {
        self.ensure_appendable()?;
        self.state = WriterState::Frozen;
        match self.advance_durability() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.state = WriterState::Open;
                Err(error)
            }
        }
    }

    /// §2.5 compact: rebase the empty post-publication journal on the newly
    /// installed checkpoint and delete every superseded segment.
    pub(crate) fn compact_to_checkpoint(
        &mut self,
        checkpoint_generation: u64,
        tip_height: u32,
        tip_hash: [u8; 32],
        tip_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError> {
        if self.state != WriterState::Frozen {
            return Err(JournalWriterError::NotOpen {
                state: match self.state {
                    WriterState::Open => "not frozen",
                    WriterState::Compacted => "already compacted",
                    WriterState::Frozen => unreachable!("guarded above"),
                },
            });
        }
        if self.durable.height != tip_height
            || self.durable_block_hash != tip_hash
            || self.durable_chain_tx_count != chain_tx_count
        {
            return Err(JournalWriterError::CursorMismatch(format!(
                "checkpoint tip {tip_height} does not match frozen journal head {}",
                self.durable.height
            )));
        }
        let new_segment_gen = self.segment_gen.checked_add(1).ok_or_else(|| {
            JournalWriterError::CursorMismatch("segment generation overflow".to_owned())
        })?;
        let marker = HeadMarker {
            base_generation: checkpoint_generation,
            base_height: tip_height,
            base_hash: tip_hash,
            base_chain_tx_count: chain_tx_count,
            start_gen: new_segment_gen,
            start_offset: 0,
            journal_gen: new_segment_gen,
            offset: 0,
            height: tip_height,
            block_hash: tip_hash,
            prev_hash: tip_prev_hash,
            chain_tx_count,
            record_count: 0,
        };
        self.write_head_atomic(&marker)?;

        // The new head is now the logical commit point. Update in-memory state
        // before best-effort physical cleanup so `resume` cannot republish the
        // superseded base if cleanup reports an error.
        self.base_generation = checkpoint_generation;
        self.base_height = tip_height;
        self.base_hash = tip_hash;
        self.base_chain_tx_count = chain_tx_count;
        self.start = (new_segment_gen, 0);
        self.segment_gen = new_segment_gen;
        self.segment_offset = 0;
        self.durable = DurableCursor {
            generation: new_segment_gen,
            offset: 0,
            height: tip_height,
        };
        self.durable_block_hash = tip_hash;
        self.durable_prev_hash = tip_prev_hash;
        self.durable_chain_tx_count = chain_tx_count;
        self.chain_tx_count = chain_tx_count;
        self.record_count = 0;
        self.next_height = tip_height.checked_add(1).ok_or_else(|| {
            JournalWriterError::CursorMismatch("checkpoint height overflow".to_owned())
        })?;
        self.pending_records.clear();
        self.state = WriterState::Compacted;

        let entries: Vec<String> = self
            .dir
            .entries()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| parse_segment_name(name).is_some())
            .collect();
        for name in entries {
            self.dir.remove_file(name)?;
        }
        clear_full_revalidation_marker(&self.dir)?;
        crate::checkpoint::fs::sync_dir(&self.dir)?;
        Ok(())
    }

    /// §2.5 resume: reopen appends against the (possibly new) base.
    pub(crate) fn resume(&mut self) -> Result<(), JournalWriterError> {
        if self.state == WriterState::Open {
            return Err(JournalWriterError::NotOpen {
                state: "already open",
            });
        }
        // Publish the (possibly unchanged) head with the new base cursor. The
        // durable cursor was already committed by freeze/compaction, so a
        // redundant republish failure must not strand the runtime as Frozen.
        let publish_result = self.publish_head_now();
        self.state = WriterState::Open;
        self.last_boundary = Instant::now();
        publish_result
    }
}
