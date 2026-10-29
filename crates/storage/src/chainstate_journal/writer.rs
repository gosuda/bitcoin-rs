mod append;
mod durability;
mod open;
mod retention;
mod rewind;

#[cfg(test)]
use super::record::JournalRecord;
use super::record::crc32c;
#[cfg(test)]
use super::record::encode_record;
use crate::KvStore;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalPolicy {
    pub batch_blocks: u32,
    pub batch_seconds: Duration,
    pub rotate_mib: u64,
    pub max_journal_mib: u64,
    pub max_lag_blocks: u32,
    pub max_lag_seconds: Duration,
}

impl Default for JournalPolicy {
    fn default() -> Self {
        Self {
            batch_blocks: 500,
            batch_seconds: Duration::from_secs(5),
            rotate_mib: 256,
            max_journal_mib: 2048,
            max_lag_blocks: 500,
            max_lag_seconds: Duration::from_secs(30),
        }
    }
}

const HEAD_MAGIC: [u8; 4] = *b"JRNH";
const HEAD_VERSION: u8 = 1;
const MAX_HEAD_BYTES: u64 = 4 * 1024;
const SEGMENT_NAME_MAX: usize = 32;
pub const FULL_REVALIDATION_MARKER: &str = "full-revalidation";
pub const JOURNAL_DIR_NAME: &str = "chainstate-journal";

pub fn clear_full_revalidation_marker_at(data_dir: &Path) -> Result<(), JournalWriterError> {
    let path = data_dir.join(JOURNAL_DIR_NAME);
    let dir = match crate::checkpoint::fs::open_data_dir(&path) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    clear_full_revalidation_marker(&dir)
}

fn clear_full_revalidation_marker(dir: &cap_std::fs::Dir) -> Result<(), JournalWriterError> {
    clear_full_revalidation_marker_with_sync(dir, crate::checkpoint::fs::sync_dir)
}

fn clear_full_revalidation_marker_with_sync(
    dir: &cap_std::fs::Dir,
    sync_dir: impl FnOnce(&cap_std::fs::Dir) -> std::io::Result<()>,
) -> Result<(), JournalWriterError> {
    match dir.remove_file(FULL_REVALIDATION_MARKER) {
        Ok(()) => sync_dir(dir).map_err(JournalWriterError::from),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            sync_dir(dir).map_err(JournalWriterError::from)
        }
        Err(error) => Err(error.into()),
    }
}

const SEGMENT_GEN_WIDTH: usize = 10;

pub(crate) fn segment_name(generation: u64) -> String {
    format!("segment-{generation:0SEGMENT_GEN_WIDTH$}.log")
}

pub(crate) fn parse_segment_name(name: &str) -> Option<u64> {
    let raw = name.strip_prefix("segment-")?.strip_suffix(".log")?;
    if raw.is_empty() || raw.len() > SEGMENT_NAME_MAX || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

#[cfg(any(test, feature = "test-seam"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalWriterFailpoint {
    SegmentAppend,
    SegmentAppendPartial,
    SegmentSync,
    HeadTempWrite,
    HeadTempSync,
    HeadRename,
    HeadDirSync,
    StorageFlush,
    RewindTruncate,
}

#[derive(Debug, Error)]
pub enum JournalWriterError {
    #[error("chainstate journal writer io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("chainstate journal storage flush failed: {0}")]
    StorageFlush(String),
    #[error("chainstate journal writer is not open for appends: {state}")]
    NotOpen { state: &'static str },
    #[error("chainstate journal append out of order: got {got}, expected {expected}")]
    OutOfOrder { got: u32, expected: u32 },
    /// A live block advanced after its journal append failed. Further applies
    /// must stop until restart recovery discards the partial tail.
    #[error("chainstate journal has an untracked append gap at height {height}")]
    AppendGap { height: u32 },
    #[error("chainstate journal head marker is unreadable: {0}")]
    HeadUnreadable(String),
    #[error("chainstate journal cursor mismatch: {0}")]
    CursorMismatch(String),
    #[error("chainstate journal size {bytes} bytes reached configured limit {limit} bytes")]
    RetentionLimit { bytes: u64, limit: u64 },
    #[error("journal fork height {fork_height} is below checkpoint base {base_height}")]
    ForkBelowBase { fork_height: u32, base_height: u32 },
}

/// Serialized as: `HEAD_MAGIC | version u8 | crc32c(payload) | payload`,
/// where payload is a JSON object. The checksum covers the payload so a torn
/// rename or a bit flip fails closed at load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HeadMarker {
    pub base_generation: u64,
    pub base_height: u32,
    pub base_hash: [u8; 32],
    pub base_chain_tx_count: u64,
    pub start_gen: u64,
    pub start_offset: u64,
    pub journal_gen: u64,
    pub offset: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub chain_tx_count: u64,
    pub record_count: u64,
}

impl HeadMarker {
    fn serialize(&self) -> Result<Vec<u8>, JournalWriterError> {
        let payload = sonic_rs::to_vec(self).map_err(|error| {
            JournalWriterError::HeadUnreadable(format!("marker serialization failed: {error}"))
        })?;
        let checksum = crc32c(&payload);
        let mut bytes = Vec::with_capacity(payload.len() + 9);
        bytes.extend_from_slice(&HEAD_MAGIC);
        bytes.push(HEAD_VERSION);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, JournalWriterError> {
        if bytes.len() < 9 {
            return Err(JournalWriterError::HeadUnreadable(
                "marker shorter than its frame header".to_owned(),
            ));
        }
        if bytes[..4] != HEAD_MAGIC {
            return Err(JournalWriterError::HeadUnreadable(
                "marker magic mismatch".to_owned(),
            ));
        }
        if bytes[4] != HEAD_VERSION {
            return Err(JournalWriterError::HeadUnreadable(format!(
                "marker version {} not supported",
                bytes[4]
            )));
        }
        let expected = u32::from_le_bytes(bytes[5..9].try_into().map_err(|_| {
            JournalWriterError::HeadUnreadable("marker frame header is short".to_owned())
        })?);
        let payload = &bytes[9..];
        let found = crc32c(payload);
        if found != expected {
            return Err(JournalWriterError::HeadUnreadable(format!(
                "marker checksum mismatch: expected {expected:#010x}, found {found:#010x}"
            )));
        }
        sonic_rs::from_slice(payload)
            .map_err(|error| JournalWriterError::HeadUnreadable(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DurableCursor {
    generation: u64,
    offset: u64,
    height: u32,
}

#[derive(Clone, Copy)]
struct ForkCursor {
    generation: u64,
    offset: u64,
    record_count: u64,
    chain_tx_count: u64,
    block_hash: [u8; 32],
}

#[derive(Clone, Copy)]
struct PendingRecordMeta {
    end_offset: u64,
    height: u32,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
    block_tx_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriterState {
    Open,
    Frozen,
    Compacted,
}

fn advance_chain_tx_count(
    base_height: u32,
    count: u64,
    delta: u64,
) -> Result<u64, JournalWriterError> {
    if count == 0 && base_height != 0 {
        return Ok(0);
    }
    count
        .checked_add(delta)
        .ok_or_else(|| JournalWriterError::CursorMismatch("chain_tx_count overflow".to_owned()))
}

pub struct JournalWriter<S: KvStore> {
    dir: cap_std::fs::Dir,
    store: std::sync::Arc<S>,
    base_generation: u64,
    base_height: u32,
    base_hash: [u8; 32],
    base_chain_tx_count: u64,
    pending_records: Vec<PendingRecordMeta>,
    segment_offset: u64,
    segment_gen: u64,
    start: (u64, u64),
    durable: DurableCursor,
    durable_chain_tx_count: u64,
    next_height: u32,
    chain_tx_count: u64,
    record_count: u64,
    rotate_bytes: u64,
    batch_blocks: u32,
    batch_seconds: Duration,
    max_journal_bytes: u64,
    max_lag_blocks: u32,
    max_lag_seconds: Duration,
    last_boundary: Instant,
    durable_block_hash: [u8; 32],
    durable_prev_hash: [u8; 32],
    append_gap_height: Option<u32>,
    durability_retry_required: bool,
    generation_invalidated: bool,
    state: WriterState,
    #[cfg(any(test, feature = "test-seam"))]
    failpoint: Option<JournalWriterFailpoint>,
}

impl<S: KvStore> JournalWriter<S> {
    #[cfg(any(test, feature = "test-seam"))]
    pub(super) fn failpoint(
        &self,
        boundary: JournalWriterFailpoint,
    ) -> Result<(), JournalWriterError> {
        if self.failpoint == Some(boundary) {
            return Err(std::io::Error::from_raw_os_error(28).into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn inject_failpoint(&mut self, failpoint: JournalWriterFailpoint) {
        self.failpoint = Some(failpoint);
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> WriterState {
        self.state
    }

    fn ensure_open(&self) -> Result<(), JournalWriterError> {
        match self.state {
            WriterState::Open => Ok(()),
            WriterState::Frozen => Err(JournalWriterError::NotOpen { state: "frozen" }),
            WriterState::Compacted => Err(JournalWriterError::NotOpen { state: "compacted" }),
        }
    }

    fn ensure_appendable(&self) -> Result<(), JournalWriterError> {
        self.ensure_open()?;
        if let Some(height) = self.append_gap_height {
            return Err(JournalWriterError::AppendGap { height });
        }
        Ok(())
    }

    pub(crate) fn mark_append_gap(&mut self, height: u32) {
        self.append_gap_height.get_or_insert(height);
        metrics::gauge!("node.chainstate_journal.append_gap").set(1.0);
        self.record_lag_metrics();
    }

    pub(crate) fn head(&self) -> HeadMarker {
        HeadMarker {
            base_generation: self.base_generation,
            base_height: self.base_height,
            base_hash: self.base_hash,
            base_chain_tx_count: self.base_chain_tx_count,
            start_gen: self.start.0,
            start_offset: self.start.1,
            journal_gen: self.durable.generation,
            offset: self.durable.offset,
            height: self.durable.height,
            block_hash: self.durable_block_hash,
            prev_hash: self.durable_prev_hash,
            chain_tx_count: self.durable_chain_tx_count,
            record_count: self.record_count,
        }
    }
}

pub(crate) fn read_head_bytes(
    dir: &cap_std::fs::Dir,
) -> Result<Option<Vec<u8>>, JournalWriterError> {
    match dir.open("head.json") {
        Ok(mut file) => {
            let length = file.metadata()?.len();
            if length > MAX_HEAD_BYTES {
                return Err(JournalWriterError::HeadUnreadable(format!(
                    "head marker {length} bytes exceeds {MAX_HEAD_BYTES}"
                )));
            }
            let capacity = usize::try_from(length).map_err(|_| {
                JournalWriterError::HeadUnreadable("head marker is too large".to_owned())
            })?;
            let mut bytes = Vec::with_capacity(capacity);
            std::io::Read::read_to_end(&mut file, &mut bytes)?;
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
