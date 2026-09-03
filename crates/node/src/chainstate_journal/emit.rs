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
    /// Buffers one record; batched durability applies (`blocks`/`seconds`).
    ///
    /// Errors are transient journal-I/O classifications (plan Task 4): the
    /// apply path logs + counts them and keeps applying; the §2.3 degraded
    /// mode owns persistent failure.
    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError>;

    /// Enforces the §2.3 boundary for everything buffered: storage flush,
    /// segment fsync, atomic `head.json` publish — in that order.
    fn flush_through(&mut self, height: u32) -> Result<(), JournalWriterError>;
}

#[allow(clippy::use_self)] // inherent vs trait method disambiguation requires the type path
impl<S: KvStore> JournalEmit for JournalWriter<S> {
    fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError> {
        JournalWriter::append(self, record)
    }

    fn flush_through(&mut self, height: u32) -> Result<(), JournalWriterError> {
        JournalWriter::flush_to(self, height)
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
