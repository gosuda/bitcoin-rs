//! Type-erased journal-writer handle for the apply path.
//!
//! [`JournalWriter`] is generic over the storage backend, but
//! `Chainstate` is not (it is a concrete struct shared by every backend).
//! This module is the single owner of that erasure: the apply path holds an
//! [`SharedJournalWriter`] and never names `S`. The trait mirrors exactly the
//! operations the apply path may perform: append, batched flush, fork rewinds,
//! and the retention and checkpoint-publication transitions (`freeze`,
//! `compact_to_checkpoint`, `resume`).

use std::sync::Arc;

use parking_lot::Mutex;

use crate::KvStore;

use super::record::JournalRecord;
use super::writer::{JournalWriter, JournalWriterError};

/// Type-erased operations used by the live apply path to maintain the journal.
pub trait JournalEmit: Send + Sync {
    /// Checks that the writer can append the next block.
    fn prepare_for_apply(&mut self) -> Result<(), JournalWriterError>;

    /// The current apply records an append error, but the writer then enters a
    /// fail-closed append-gap state. `prepare_for_apply` refuses the next block
    /// before mutation, so a transient I/O failure cannot grow an untracked
    /// hole between live chainstate and the journal frontier.
    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError>;

    /// Records that the live apply could not be represented as a journal
    /// record. The next pre-apply gate then fails closed at this height.
    fn mark_append_gap(&mut self, height: u32);

    /// Enforces the §2.3 boundary for everything buffered: storage flush,
    /// segment fsync, atomic `head.json` publish — in that order.
    fn flush_through(&mut self, height: u32) -> Result<(), JournalWriterError>;

    /// Flushes buffered records when the configured batch deadline expires.
    fn flush_due(&mut self) -> Result<(), JournalWriterError>;

    /// Reports whether journal retention requires checkpoint compaction.
    fn requires_compaction(&self) -> Result<bool, JournalWriterError>;

    /// Durably rewrites the canonical journal frontier to a reorg fork.
    fn rewind_to(
        &mut self,
        fork_height: u32,
        fork_hash: [u8; 32],
        fork_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError>;

    /// Freezes appends while a checkpoint publication consumes the journal.
    fn freeze(&mut self) -> Result<(), JournalWriterError>;

    /// Replaces the journal base with a committed checkpoint tip. Recovery
    /// progress passes `false` for marker retirement until replay reaches the
    /// durable head; completed and ordinary publications pass `true`.
    fn compact_to_checkpoint(
        &mut self,
        checkpoint_generation: u64,
        tip_height: u32,
        tip_hash: [u8; 32],
        tip_prev_hash: [u8; 32],
        chain_tx_count: u64,
        retire_full_revalidation_marker: bool,
    ) -> Result<(), JournalWriterError>;

    /// Resumes appends after checkpoint publication completes.
    fn resume(&mut self) -> Result<(), JournalWriterError>;
}

#[allow(clippy::use_self)] // inherent vs trait method disambiguation requires the type path
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

/// Thread-safe erased journal writer shared by the apply and publication paths.
pub type SharedJournalWriter = Arc<Mutex<dyn JournalEmit>>;

/// Wraps a concrete writer for sharing through the apply-path trait object.
pub fn shared_journal_writer<S: KvStore + 'static>(
    writer: JournalWriter<S>,
) -> SharedJournalWriter {
    Arc::new(Mutex::new(writer))
}
