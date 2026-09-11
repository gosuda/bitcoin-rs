//! Typed injection points at the writer's persistence boundaries.

use super::JournalWriter;
use super::JournalWriterError;
use super::JournalWriterFailpoint;
use bitcoin_rs_storage::KvStore;

impl<S: KvStore> JournalWriter<S> {
    // --- failpoint plumbing (mirrors checkpoint.rs) ---

    pub(super) fn fail_segment_append(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::SegmentAppend)
    }

    pub(super) fn fail_segment_sync(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::SegmentSync)
    }

    pub(super) fn fail_storage_flush(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::StorageFlush)
    }

    pub(super) fn fail_rewind_truncate(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::RewindTruncate)
    }

    pub(super) fn fail_head_temp_write(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadTempWrite)
    }

    pub(super) fn fail_head_temp_sync(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadTempSync)
    }

    pub(super) fn fail_head_rename(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadRename)
    }

    pub(super) fn fail_head_dir_sync(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadDirSync)
    }

    pub(super) fn failpoint(
        &self,
        boundary: JournalWriterFailpoint,
    ) -> Result<(), JournalWriterError> {
        if self.failpoint == Some(boundary) {
            return Err(std::io::Error::from_raw_os_error(28).into());
        }
        Ok(())
    }

    /// Arms the next failpoint (test-only; mirrors checkpoint.rs's injector).
    #[cfg(test)]
    pub(crate) fn inject_failpoint(&mut self, failpoint: JournalWriterFailpoint) {
        self.failpoint = Some(failpoint);
    }
}
