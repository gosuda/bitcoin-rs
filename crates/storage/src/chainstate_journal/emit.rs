use std::sync::Arc;

use parking_lot::Mutex;

use crate::KvStore;

use super::record::JournalRecord;
use super::writer::{JournalWriter, JournalWriterError};

pub trait JournalEmit: Send + Sync {
    fn prepare_for_apply(&mut self) -> Result<(), JournalWriterError>;

    /// The current apply records an append error, but the writer then enters a
    /// fail-closed append-gap state.
    ///
    /// `prepare_for_apply` refuses the next block before mutation, so a transient I/O
    /// failure cannot grow an untracked hole between live chainstate and the journal
    /// frontier.
    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError>;

    fn mark_append_gap(&mut self, height: u32);

    fn flush_through(&mut self, height: u32) -> Result<(), JournalWriterError>;

    fn flush_due(&mut self) -> Result<(), JournalWriterError>;

    fn requires_compaction(&self) -> Result<bool, JournalWriterError>;

    fn rewind_to(
        &mut self,
        fork_height: u32,
        fork_hash: [u8; 32],
        fork_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError>;

    fn freeze(&mut self) -> Result<(), JournalWriterError>;

    fn compact_to_checkpoint(
        &mut self,
        checkpoint_generation: u64,
        tip_height: u32,
        tip_hash: [u8; 32],
        tip_prev_hash: [u8; 32],
        chain_tx_count: u64,
        retire_full_revalidation_marker: bool,
    ) -> Result<(), JournalWriterError>;

    fn resume(&mut self) -> Result<(), JournalWriterError>;
}

#[expect(clippy::use_self)] // inherent vs trait method disambiguation requires the type path
impl<S: KvStore> JournalEmit for JournalWriter<S> {
    fn prepare_for_apply(&mut self) -> Result<(), JournalWriterError> {
        JournalWriter::prepare_for_apply(self)
    }

    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError> {
        JournalWriter::append(self, record)
    }

    fn mark_append_gap(&mut self, height: u32) {
        JournalWriter::mark_append_gap(self, height);
    }

    fn flush_through(&mut self, height: u32) -> Result<(), JournalWriterError> {
        JournalWriter::flush_to(self, height)
    }

    fn flush_due(&mut self) -> Result<(), JournalWriterError> {
        JournalWriter::flush_due(self)
    }

    fn requires_compaction(&self) -> Result<bool, JournalWriterError> {
        JournalWriter::requires_compaction(self)
    }

    fn rewind_to(
        &mut self,
        fork_height: u32,
        fork_hash: [u8; 32],
        fork_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError> {
        JournalWriter::rewind_to(self, fork_height, fork_hash, fork_prev_hash, chain_tx_count)
    }

    fn freeze(&mut self) -> Result<(), JournalWriterError> {
        JournalWriter::freeze(self)
    }

    fn compact_to_checkpoint(
        &mut self,
        checkpoint_generation: u64,
        tip_height: u32,
        tip_hash: [u8; 32],
        tip_prev_hash: [u8; 32],
        chain_tx_count: u64,
        retire_full_revalidation_marker: bool,
    ) -> Result<(), JournalWriterError> {
        JournalWriter::compact_to_checkpoint(
            self,
            checkpoint_generation,
            tip_height,
            tip_hash,
            tip_prev_hash,
            chain_tx_count,
            retire_full_revalidation_marker,
        )
    }

    fn resume(&mut self) -> Result<(), JournalWriterError> {
        JournalWriter::resume(self)
    }
}

pub type SharedJournalWriter = Arc<Mutex<dyn JournalEmit>>;

pub fn shared_journal_writer<S: KvStore + 'static>(
    writer: JournalWriter<S>,
) -> SharedJournalWriter {
    Arc::new(Mutex::new(writer))
}
