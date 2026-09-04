//! Type-erased journal-writer handle for the apply path.
//!
//! [`JournalWriter`] is generic over the storage backend, but
//! `ApplyHandles` is not (it is a concrete struct shared by every backend).
//! This module is the single owner of that erasure: the apply path holds an
//! [`SharedJournalWriter`] and never names `S`. The trait mirrors exactly the
//! operations the apply path may perform (append + batched flush); state
//! transitions (`freeze`/`compact`/`resume`) belong to the publication path
//! and stay off this trait.

use std::sync::Arc;

use parking_lot::Mutex;

use bitcoin_rs_storage::KvStore;

use super::record::JournalRecord;
use super::writer::{JournalWriter, JournalWriterError};

/// The apply-path surface of the journal writer, storage-backend-agnostic.
pub(crate) trait JournalEmit: Send + Sync {
    /// Retries lagged durability and enforces retention before block mutation.
    fn prepare_for_apply(&mut self) -> Result<(), JournalWriterError>;

    /// Buffers one record; batched durability applies (`blocks`/`seconds`).
    ///
    /// Errors are transient journal-I/O classifications (plan Task 4): the
    /// apply path logs + counts them and keeps applying; the §2.3 degraded
    /// mode owns persistent failure.
    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError>;

    /// Enforces the §2.3 boundary for everything buffered: storage flush,
    /// segment fsync, atomic `head.json` publish — in that order.
    fn flush_through(&mut self, height: u32) -> Result<(), JournalWriterError>;

    /// Flushes a pending batch whose wall-clock deadline has elapsed.
    fn flush_due(&mut self) -> Result<(), JournalWriterError>;

    /// Whether the retained segment budget requires checkpoint compaction.
    fn requires_compaction(&self) -> Result<bool, JournalWriterError>;

    /// Durably rewrites the canonical journal frontier to a reorg fork.
    fn rewind_to(
        &mut self,
        fork_height: u32,
        fork_hash: [u8; 32],
        fork_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError>;

    /// Stops appends and publishes every buffered record durably.
    fn freeze(&mut self) -> Result<(), JournalWriterError>;

    /// Re-bases the frozen writer on a successfully installed checkpoint.
    fn compact_to_checkpoint(
        &mut self,
        checkpoint_generation: u64,
        tip_height: u32,
        tip_hash: [u8; 32],
        tip_prev_hash: [u8; 32],
        chain_tx_count: u64,
    ) -> Result<(), JournalWriterError>;

    /// Reopens appends after publication success or failure.
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
    ) -> Result<(), JournalWriterError> {
        JournalWriter::compact_to_checkpoint(
            self,
            checkpoint_generation,
            tip_height,
            tip_hash,
            tip_prev_hash,
            chain_tx_count,
        )
    }

    fn resume(&mut self) -> Result<(), JournalWriterError> {
        JournalWriter::resume(self)
    }
}

/// Shared, exclusively-accessed handle for the apply path.
pub(crate) type SharedJournalWriter = Arc<Mutex<dyn JournalEmit>>;

/// Wraps a concrete writer into the shared, erased handle.
pub(crate) fn shared_journal_writer<S: KvStore + 'static>(
    writer: JournalWriter<S>,
) -> SharedJournalWriter {
    Arc::new(Mutex::new(writer))
}
