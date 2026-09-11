//! Ordered journal append, partial-write repair, and bounded segment rotation.

use super::super::record::JournalRecord;
use super::super::record::encode_record;
use super::DurableCursor;
use super::JournalWriter;
use super::JournalWriterError;
use super::JournalWriterFailpoint;
use super::PendingRecordMeta;
use super::segment_name;
use bitcoin_rs_storage::KvStore;
use std::io::Write;

impl<S: KvStore> JournalWriter<S> {
    /// Buffers one record. Idempotent per height: re-appending a record whose
    /// height equals the last appended height is rejected as a duplicate via
    /// the strict ordering rule (callers replay whole records after a crash).
    pub(crate) fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError> {
        self.ensure_appendable()?;
        if record.height != self.next_height {
            return self.fail_append(
                record.height,
                JournalWriterError::OutOfOrder {
                    got: record.height,
                    expected: self.next_height,
                },
            );
        }

        let next_frontier = self.next_append_frontier(record);
        let (next_height, next_chain_tx_count) = match next_frontier {
            Ok(frontier) => frontier,
            Err(error) => return self.fail_append(record.height, error),
        };
        let bytes = match encode_record(record) {
            Ok(bytes) => bytes,
            Err(error) => return self.fail_append(record.height, error.into()),
        };
        let next_offset = self.append_record_bytes(record.height, &bytes)?;

        self.segment_offset = next_offset;
        self.pending_records.push(PendingRecordMeta {
            end_offset: next_offset,
            height: record.height,
            block_hash: record.block_hash,
            prev_hash: record.prev_hash,
            block_tx_count: record.block_tx_count,
        });
        self.next_height = next_height;
        self.chain_tx_count = next_chain_tx_count;

        if self.pending_records.len()
            >= usize::try_from(self.batch_blocks).map_err(|_| {
                JournalWriterError::CursorMismatch("batch blocks overflow".to_owned())
            })?
            || self.last_boundary.elapsed() >= self.batch_seconds
        {
            self.advance_durability()?;
        }
        self.record_lag_metrics();
        Ok(())
    }

    pub(super) fn next_append_frontier(
        &self,
        record: &JournalRecord,
    ) -> Result<(u32, u64), JournalWriterError> {
        let next_height = self
            .next_height
            .checked_add(1)
            .ok_or_else(|| JournalWriterError::CursorMismatch("height overflow".to_owned()))?;
        let next_chain_tx_count = self
            .chain_tx_count
            .checked_add(record.block_tx_count)
            .ok_or_else(|| {
                JournalWriterError::CursorMismatch("chain_tx_count overflow".to_owned())
            })?;
        Ok((next_height, next_chain_tx_count))
    }

    pub(super) fn append_record_bytes(
        &mut self,
        height: u32,
        bytes: &[u8],
    ) -> Result<u64, JournalWriterError> {
        if let Err(error) = self.maybe_rotate() {
            return self.fail_append(height, error);
        }
        if let Err(error) = self.fail_segment_append() {
            return self.fail_append(height, error);
        }

        let bytes_len = match u64::try_from(bytes.len()) {
            Ok(len) => len,
            Err(_) => {
                return self.fail_append(
                    height,
                    JournalWriterError::CursorMismatch("record byte length overflow".to_owned()),
                );
            }
        };
        let known_good_offset = self.segment_offset;
        let Some(next_offset) = known_good_offset.checked_add(bytes_len) else {
            return self.fail_append(
                height,
                JournalWriterError::CursorMismatch("segment offset overflow".to_owned()),
            );
        };
        let name = segment_name(self.segment_gen);
        let mut options = cap_std::fs::OpenOptions::new();
        options.append(true).create(true);
        let mut file = match self.dir.open_with(&name, &options) {
            Ok(file) => file,
            Err(error) => return self.fail_append(height, error.into()),
        };
        let write_result = if self.failpoint == Some(JournalWriterFailpoint::SegmentAppendPartial) {
            let prefix_len = (bytes.len() / 2).max(1);
            file.write_all(&bytes[..prefix_len]).and_then(|()| {
                Err(std::io::Error::other(
                    "injected chainstate journal partial append failure",
                ))
            })
        } else {
            file.write_all(bytes)
        };
        if let Err(append_error) = write_result {
            let rollback_result = file
                .set_len(known_good_offset)
                .and_then(|()| file.sync_all());
            if let Err(rollback_error) = rollback_result {
                return self.fail_append(
                    height,
                    JournalWriterError::CursorMismatch(format!(
                        "append at height {height} failed ({append_error}); partial-tail rollback failed: {rollback_error}"
                    )),
                );
            }
            return self.fail_append(height, append_error.into());
        }
        Ok(next_offset)
    }

    pub(super) fn fail_append<T>(
        &mut self,
        height: u32,
        error: JournalWriterError,
    ) -> Result<T, JournalWriterError> {
        self.mark_append_gap(height);
        Err(error)
    }

    /// Rotates the active segment when it crosses the size threshold.
    pub(super) fn maybe_rotate(&mut self) -> Result<(), JournalWriterError> {
        if self.segment_offset < self.rotate_bytes {
            return Ok(());
        }
        // Close the current segment durably: the boundary covers buffered
        // records, then the next append starts a new generation.
        self.advance_durability()?;
        let previous_gen = self.segment_gen;
        let previous_offset = self.segment_offset;
        let previous_durable = self.durable;
        let next_gen = previous_gen
            .checked_add(1)
            .ok_or_else(|| JournalWriterError::CursorMismatch("generation overflow".to_owned()))?;
        // A head may name a zero-offset generation only after the directory
        // entry itself is durable. Reuse after a pre-head crash truncates the
        // uncommitted generation before publishing it again.
        let name = segment_name(next_gen);
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let file = self.dir.open_with(&name, &options)?;
        file.sync_all()?;
        crate::checkpoint::fs::sync_dir(&self.dir)?;

        self.segment_gen = next_gen;
        self.segment_offset = 0;
        self.durable = DurableCursor {
            generation: next_gen,
            offset: 0,
            height: previous_durable.height,
        };
        if let Err(error) = self.publish_head_now() {
            self.segment_gen = previous_gen;
            self.segment_offset = previous_offset;
            self.durable = previous_durable;
            return Err(error);
        }
        Ok(())
    }
}
