//! Authenticated journal fork cursors and fail-closed truncation/rewrite.

use super::super::record::FRAME_HEADER_LEN;
use super::super::record::decode_record;
use super::DurableCursor;
use super::FULL_REVALIDATION_MARKER;
use super::ForkCursor;
use super::HeadMarker;
use super::JournalWriter;
use super::JournalWriterError;
use super::WriterState;
use super::parse_segment_name;
use super::segment_name;
use bitcoin_rs_storage::KvStore;
use std::io::Read;
use std::time::Instant;

impl<S: KvStore> JournalWriter<S> {
    /// Durably moves the journal frontier to a canonical fork point and
    /// invalidates every old-branch record above it.
    pub(crate) fn rewind_to(
        &mut self,
        fork_height: u32,
        fork_hash: [u8; 32],
        fork_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError> {
        self.ensure_appendable()?;
        if fork_height < self.base_height {
            self.invalidate_generation()?;
            return Err(JournalWriterError::ForkBelowBase {
                fork_height,
                base_height: self.base_height,
            });
        }
        if fork_height > self.durable.height {
            let target = self
                .pending_records
                .iter()
                .position(|record| record.height == fork_height)
                .ok_or_else(|| {
                    JournalWriterError::CursorMismatch(format!(
                        "fork height {fork_height} is outside the journal frontier"
                    ))
                })?;
            self.advance_durability_upto(target + 1)?;
        }
        let cursor = if fork_height == self.durable.height {
            ForkCursor {
                generation: self.durable.generation,
                offset: self.durable.offset,
                record_count: self.record_count,
                chain_tx_count: self.durable_chain_tx_count,
                block_hash: self.durable_block_hash,
            }
        } else {
            self.committed_cursor_at(fork_height)?
        };
        if cursor.block_hash != fork_hash || cursor.chain_tx_count != chain_tx_count {
            return Err(JournalWriterError::CursorMismatch(format!(
                "fork identity mismatch at height {fork_height}"
            )));
        }

        let marker = HeadMarker {
            base_generation: self.base_generation,
            base_height: self.base_height,
            base_hash: self.base_hash,
            base_chain_tx_count: self.base_chain_tx_count,
            start_gen: self.start.0,
            start_offset: self.start.1,
            journal_gen: cursor.generation,
            offset: cursor.offset,
            height: fork_height,
            block_hash: fork_hash,
            prev_hash: fork_prev_hash,
            chain_tx_count,
            record_count: cursor.record_count,
        };
        // The atomic head rewrite is the logical invalidation point. Physical
        // truncation follows; a crash between them leaves only an ignored tail.
        self.write_head_atomic(&marker)?;
        if let Err(error) = self.truncate_after(cursor) {
            self.mark_append_gap(fork_height.saturating_add(1));
            return Err(error);
        }

        self.segment_gen = cursor.generation;
        self.segment_offset = cursor.offset;
        self.durable = DurableCursor {
            generation: cursor.generation,
            offset: cursor.offset,
            height: fork_height,
        };
        self.durable_block_hash = fork_hash;
        self.durable_prev_hash = fork_prev_hash;
        self.durable_chain_tx_count = chain_tx_count;
        self.chain_tx_count = chain_tx_count;
        self.record_count = cursor.record_count;
        self.next_height = fork_height
            .checked_add(1)
            .ok_or_else(|| JournalWriterError::CursorMismatch("fork height overflow".to_owned()))?;
        self.pending_records.clear();
        self.last_boundary = Instant::now();
        Ok(())
    }

    pub(super) fn committed_cursor_at(
        &self,
        target_height: u32,
    ) -> Result<ForkCursor, JournalWriterError> {
        if target_height == self.base_height {
            return Ok(ForkCursor {
                generation: self.start.0,
                offset: self.start.1,
                record_count: 0,
                chain_tx_count: self.base_chain_tx_count,
                block_hash: self.base_hash,
            });
        }
        let mut record_count = 0_u64;
        let mut chain_tx_count = self.base_chain_tx_count;
        for generation in self.start.0..=self.durable.generation {
            let name = segment_name(generation);
            let mut file = self.dir.open(&name)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let start = if generation == self.start.0 {
                self.start.1
            } else {
                0
            };
            let end = if generation == self.durable.generation {
                self.durable.offset
            } else {
                u64::try_from(bytes.len()).map_err(|_| {
                    JournalWriterError::CursorMismatch("segment size overflow".to_owned())
                })?
            };
            if let Some(cursor) = scan_fork_cursor(
                &bytes,
                generation,
                start,
                end,
                target_height,
                &mut record_count,
                &mut chain_tx_count,
            )? {
                return Ok(cursor);
            }
        }
        Err(JournalWriterError::CursorMismatch(format!(
            "fork height {target_height} is absent from the committed journal"
        )))
    }

    pub(super) fn truncate_after(&self, cursor: ForkCursor) -> Result<(), JournalWriterError> {
        self.fail_rewind_truncate()?;
        let name = segment_name(cursor.generation);
        match self
            .dir
            .open_with(&name, cap_std::fs::OpenOptions::new().write(true))
        {
            Ok(file) => {
                file.set_len(cursor.offset)?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && cursor.offset == 0 => {}
            Err(error) => return Err(error.into()),
        }
        let names: Vec<String> = self
            .dir
            .entries()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                parse_segment_name(name).is_some_and(|generation| generation > cursor.generation)
            })
            .collect();
        for name in names {
            self.dir.remove_file(name)?;
        }
        crate::checkpoint::fs::sync_dir(&self.dir)?;
        Ok(())
    }

    pub(super) fn invalidate_generation(&mut self) -> Result<(), JournalWriterError> {
        let names: Vec<String> = self
            .dir
            .entries()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name == "head.json" || name == "head.json.tmp" || parse_segment_name(name).is_some()
            })
            .collect();
        for name in names {
            self.dir.remove_file(name)?;
        }
        self.dir.write(
            FULL_REVALIDATION_MARKER,
            b"journal fork crossed below checkpoint base\n",
        )?;
        crate::checkpoint::fs::sync_dir(&self.dir)?;
        self.state = WriterState::Frozen;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_fork_cursor(
    bytes: &[u8],
    generation: u64,
    start: u64,
    end: u64,
    target_height: u32,
    record_count: &mut u64,
    chain_tx_count: &mut u64,
) -> Result<Option<ForkCursor>, JournalWriterError> {
    const FRAME_HEADER_U64: u64 = 4 + 1 + 4;
    if end > u64::try_from(bytes.len()).unwrap_or(u64::MAX) || start > end {
        return Err(JournalWriterError::CursorMismatch(format!(
            "segment {generation} committed window is outside the file"
        )));
    }
    let mut offset = start;
    while offset < end {
        if offset + FRAME_HEADER_U64 > end {
            return Err(JournalWriterError::CursorMismatch(format!(
                "segment {generation} has a truncated frame header"
            )));
        }
        let index = usize::try_from(offset)
            .map_err(|_| JournalWriterError::CursorMismatch("frame offset overflow".to_owned()))?;
        let payload_len = u32::from_le_bytes(
            bytes[index + 5..index + FRAME_HEADER_LEN]
                .try_into()
                .map_err(|_| {
                    JournalWriterError::CursorMismatch("frame length is malformed".to_owned())
                })?,
        );
        let frame_len = FRAME_HEADER_U64 + u64::from(payload_len) + 4;
        let next = offset
            .checked_add(frame_len)
            .ok_or_else(|| JournalWriterError::CursorMismatch("frame end overflow".to_owned()))?;
        if next > end {
            return Err(JournalWriterError::CursorMismatch(format!(
                "segment {generation} has a truncated committed frame"
            )));
        }
        let next_index = usize::try_from(next)
            .map_err(|_| JournalWriterError::CursorMismatch("frame end overflow".to_owned()))?;
        let record = decode_record(&bytes[index..next_index]).map_err(|error| {
            JournalWriterError::CursorMismatch(format!(
                "segment {generation} contains an invalid record: {error}"
            ))
        })?;
        *record_count = record_count.checked_add(1).ok_or_else(|| {
            JournalWriterError::CursorMismatch("record count overflow".to_owned())
        })?;
        *chain_tx_count = chain_tx_count
            .checked_add(record.block_tx_count)
            .ok_or_else(|| {
                JournalWriterError::CursorMismatch("chain transaction count overflow".to_owned())
            })?;
        if record.height == target_height {
            return Ok(Some(ForkCursor {
                generation,
                offset: next,
                record_count: *record_count,
                chain_tx_count: *chain_tx_count,
                block_hash: record.block_hash,
            }));
        }
        if record.height > target_height {
            break;
        }
        offset = next;
    }
    Ok(None)
}
