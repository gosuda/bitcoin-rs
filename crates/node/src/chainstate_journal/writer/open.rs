//! Journal initialization and recovery of its exact durable append frontier.

use super::DurableCursor;
use super::HeadMarker;
use super::JournalWriter;
use super::JournalWriterError;
use super::WriterState;
use super::read_head_bytes;
use super::segment_name;
use bitcoin_rs_storage::KvStore;
use std::time::Duration;
use std::time::Instant;

impl<S: KvStore> JournalWriter<S> {
    /// Opens (or creates) the journal directory and restores the durable
    /// cursor from `head.json`.
    ///
    /// Recovery rules (plan §2.3): a torn tail beyond the head is ignored
    /// (the active segment is truncated back to the head cursor); a missing
    /// `head.json` with no segments is a fresh journal.
    pub(crate) fn open(
        dir: cap_std::fs::Dir,
        store: std::sync::Arc<S>,
    ) -> Result<Self, JournalWriterError> {
        let head_bytes = read_head_bytes(&dir)?;
        let head = match head_bytes {
            Some(bytes) => HeadMarker::deserialize(&bytes)?,
            None => {
                return Err(JournalWriterError::HeadUnreadable(
                    "fresh journal requires an explicit initialize call".to_owned(),
                ));
            }
        };
        Self::restore(dir, store, head)
    }

    /// Creates a fresh journal at the given base cursor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initialize(
        dir: cap_std::fs::Dir,
        store: std::sync::Arc<S>,
        base_generation: u64,
        start: (u64, u64),
        height: u32,
        block_hash: [u8; 32],
        prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<Self, JournalWriterError> {
        let head = HeadMarker {
            base_generation,
            base_height: height,
            base_hash: block_hash,
            base_chain_tx_count: chain_tx_count,
            start_gen: start.0,
            start_offset: start.1,
            journal_gen: start.0,
            offset: start.1,
            height,
            block_hash,
            prev_hash,
            chain_tx_count,
            record_count: 0,
        };
        let writer = Self::restore(dir, store, head)?;
        writer.publish_head_now()?;
        Ok(writer)
    }

    pub(super) fn restore(
        dir: cap_std::fs::Dir,
        store: std::sync::Arc<S>,
        head: HeadMarker,
    ) -> Result<Self, JournalWriterError> {
        let defaults = crate::config::ChainstateJournalConfig::default();
        let mut writer = Self {
            dir,
            store,
            base_generation: head.base_generation,
            base_height: head.base_height,
            base_hash: head.base_hash,
            base_chain_tx_count: head.base_chain_tx_count,
            pending_records: Vec::new(),
            segment_offset: head.offset,
            segment_gen: head.journal_gen,
            start: (head.start_gen, head.start_offset),
            durable: DurableCursor {
                generation: head.journal_gen,
                offset: head.offset,
                height: head.height,
            },
            durable_chain_tx_count: head.chain_tx_count,
            next_height: head.height.checked_add(1).ok_or_else(|| {
                JournalWriterError::HeadUnreadable("head height overflow".to_owned())
            })?,
            chain_tx_count: head.chain_tx_count,
            record_count: head.record_count,
            durable_block_hash: head.block_hash,
            durable_prev_hash: head.prev_hash,
            rotate_bytes: defaults.rotate_mib * 1024 * 1024,
            batch_blocks: defaults.blocks,
            batch_seconds: Duration::from_secs(defaults.seconds),
            max_journal_bytes: defaults.max_journal_mib * 1024 * 1024,
            max_lag_blocks: defaults.max_lag_blocks,
            max_lag_seconds: Duration::from_secs(defaults.max_lag_seconds),
            last_boundary: Instant::now(),
            append_gap_height: None,
            durability_retry_required: false,
            state: WriterState::Open,
            failpoint: None,
        };
        writer.recover_active_segment()?;
        metrics::gauge!("node.chainstate_journal.append_gap").set(0.0);
        Ok(writer)
    }

    /// Truncates the active segment to the durable cursor (torn tail ignored).
    pub(super) fn recover_active_segment(&mut self) -> Result<(), JournalWriterError> {
        let name = segment_name(self.segment_gen);
        let file = match self.dir.open_with(
            &name,
            cap_std::fs::OpenOptions::new().write(true).read(true),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // No active segment: the head is the last boundary; a fresh
                // segment is created lazily on the first append.
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let length = file.metadata()?.len();
        if length > self.durable.offset {
            // Torn tail beyond the durable head: truncate to the cursor.
            file.set_len(self.durable.offset)?;
            file.sync_all()?;
        }
        self.segment_offset = self.durable.offset;
        Ok(())
    }
}
