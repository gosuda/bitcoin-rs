//! Journal writer: the single owner of journal segment files, the durable
//! cursor, and `head.json`.
//!
//! Ownership and commit point: the codec (`record.rs`) turns records into
//! bytes; this writer is the *only* component that appends those bytes to
//! segments and advances the durable head marker. `head.json` is the journal's
//! commit point — nothing below it (a torn tail) is acknowledged at boot, and
//! nothing above it is claimed without the full §2.3 dependency order.
//!
//! Durability: appends are buffered in memory and in the page cache; the
//! durability boundary advances in one serialized step — (1) storage flush
//! (`KvStore::flush()`, which makes the deferred undo rows durable), (2) log
//! fsync, (3) atomic `head.json` publish (tmp + rename + directory fsync).
//! The order matters: undo is the sole inverse transition for reorg, so its
//! durability must precede the head that claims the height.
//!
//! Recovery: a crash before the boundary leaves "record present, head older"
//! (a torn tail, ignored); a crash after the boundary leaves a valid head.
//! A partial append is truncated back to the last known-good cursor and the
//! writer fails closed before the next block mutation. Restart recovery then
//! permits the missed height to be applied and journaled again.
//!
//! Failure classification: append/boundary failures are never consensus-fatal
//! (the journal only accelerates recovery); callers see [`JournalWriterError`]
//! and apply §2.3's degraded-mode policy. Loading a corrupt journal at boot
//! fails closed (handled by replay, later task).

mod append;
mod durability;
mod failpoints;
mod open;
mod retention;
mod rewind;

#[cfg(test)]
use super::record::JournalRecord;
#[cfg(test)]
use super::record::encode_record;
use bitcoin_rs_storage::KvStore;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use thiserror::Error;

/// Magic prefix of `head.json` payload bytes (versioned container, crc32c).
const HEAD_MAGIC: [u8; 4] = *b"JRNH";
/// Current `head.json` format version.
const HEAD_VERSION: u8 = 1;
/// Maximum serialized `head.json` size accepted on load.
const MAX_HEAD_BYTES: u64 = 4 * 1024;
/// Maximum serialized segment name length sanity bound.
const SEGMENT_NAME_MAX: usize = 32;
pub(crate) const FULL_REVALIDATION_MARKER: &str = "full-revalidation";
/// Directory name under the node data dir that owns journal files and the
/// sticky full-revalidation marker.
pub(crate) const JOURNAL_DIR_NAME: &str = "chainstate-journal";

/// Removes the sticky full-revalidation marker after a replacement checkpoint
/// has reached its `CURRENT` commit point.
///
/// Ownership: the journal directory owns this file. Startup treats presence as
/// authoritative independently of `chainstate_journal.enabled`. This helper is
/// the only remover; journal compaction uses the same unlink-and-directory-sync
/// sequence against an already-open journal directory.
///
/// Commit point: `unlink(full-revalidation)` followed by `fsync` of the journal
/// directory. The replacement checkpoint's `CURRENT` rename and root sync is a
/// prior, independent commit point. This helper does not publish checkpoints
/// and does not roll `CURRENT` back if removal fails.
///
/// Durability / crash:
/// - crash before unlink: the marker remains; every restart stays on cold
///   validation and refuses the stale pre-reorg checkpoint
/// - crash after unlink, before directory sync: a power loss may make the
///   marker visible again; boot stays on cold validation until a later
///   successful clear
/// - crash after directory sync: the marker is gone; boot may restore the
///   published replacement checkpoint
///
/// Failure classification: a missing journal directory is success (nothing to
/// retire). A missing marker still syncs an existing journal directory so a
/// retry after an earlier sync failure can durably commit the prior unlink.
/// Open, unlink, and directory-sync errors are I/O
/// ([`JournalWriterError::Io`]). They are not consensus-fatal. The already
/// published checkpoint remains durable; only marker retirement is unfinished.
///
/// Retry owner: the checkpoint worker. Callers must propagate the error so the
/// worker's next tick retries publication (and therefore this clear). Do not
/// treat a published checkpoint as finished while this returns `Err`.
pub(crate) fn clear_full_revalidation_marker_at(data_dir: &Path) -> Result<(), JournalWriterError> {
    let path = data_dir.join(JOURNAL_DIR_NAME);
    let dir = match crate::checkpoint_fs::open_data_dir(&path) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    clear_full_revalidation_marker(&dir)
}

fn clear_full_revalidation_marker(dir: &cap_std::fs::Dir) -> Result<(), JournalWriterError> {
    clear_full_revalidation_marker_with_sync(dir, crate::checkpoint_fs::sync_dir)
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

/// Zero-padded 10-digit generation: lexicographic order equals numeric order.
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

/// §2.6 crash-injection boundaries (reuse of the `CheckpointFailpoint` style).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalWriterFailpoint {
    /// Injected just before the buffered record bytes hit the segment file.
    SegmentAppend,
    /// Injected after a prefix of a record reaches the segment file.
    SegmentAppendPartial,
    /// Injected just before the segment file is fsynced at the boundary.
    SegmentSync,
    /// Injected just before `head.json.tmp` is written.
    HeadTempWrite,
    /// Injected just before `head.json.tmp` is fsynced.
    HeadTempSync,
    /// Injected just before `head.json.tmp` is renamed onto `head.json`.
    HeadRename,
    /// Injected just before the journal directory is fsynced after the rename.
    HeadDirSync,
    /// Injected just before the storage-dependency flush at the boundary.
    StorageFlush,
    /// Injected after a rewind head publishes but before tail truncation.
    RewindTruncate,
}

#[derive(Debug, Error)]
pub(crate) enum JournalWriterError {
    /// Underlying filesystem error (segment append, sync, rename, ...).
    #[error("chainstate journal writer io error: {0}")]
    Io(#[from] std::io::Error),
    /// The storage flush dependency failed at a durability boundary.
    #[error("chainstate journal storage flush failed: {0}")]
    StorageFlush(String),
    /// Appends are not accepted in the writer's current state.
    #[error("chainstate journal writer is not open for appends: {state}")]
    NotOpen { state: &'static str },
    /// A record was appended whose height does not continue the journal.
    #[error("chainstate journal append out of order: got {got}, expected {expected}")]
    OutOfOrder { got: u32, expected: u32 },
    /// A live block advanced after its journal append failed. Further applies
    /// must stop until restart recovery discards the partial tail.
    #[error("chainstate journal has an untracked append gap at height {height}")]
    AppendGap { height: u32 },
    /// `head.json` is missing, unreadable, or fails its checksum.
    #[error("chainstate journal head marker is unreadable: {0}")]
    HeadUnreadable(String),
    /// The active segment does not match the durable cursor it claims.
    #[error("chainstate journal cursor mismatch: {0}")]
    CursorMismatch(String),
    /// Retained segment bytes reached the configured compaction budget.
    #[error("chainstate journal size {bytes} bytes reached configured limit {limit} bytes")]
    RetentionLimit { bytes: u64, limit: u64 },
    /// A reorg crossed below the checkpoint base this journal presupposes.
    #[error("journal fork height {fork_height} is below checkpoint base {base_height}")]
    ForkBelowBase { fork_height: u32, base_height: u32 },
}

/// Durable head marker payload (`head.json`, plan §2.1).
///
/// Serialized as: `HEAD_MAGIC | version u8 | crc32c(payload) | payload`,
/// where payload is a JSON object. The checksum covers the payload so a torn
/// rename or a bit flip fails closed at load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct HeadMarker {
    /// Checkpoint generation this journal extends.
    pub(crate) base_generation: u64,
    /// Applied-tip height of the checkpoint base.
    pub(crate) base_height: u32,
    /// Applied-tip hash of the checkpoint base.
    pub(crate) base_hash: [u8; 32],
    /// Cumulative transaction count through the checkpoint base.
    pub(crate) base_chain_tx_count: u64,
    /// Oldest RETAINED segment generation (the base cursor).
    pub(crate) start_gen: u64,
    /// Byte offset within the oldest retained segment's active record window.
    pub(crate) start_offset: u64,
    /// Generation of the segment holding the durable frontier.
    pub(crate) journal_gen: u64,
    /// Byte offset of the durable frontier inside `journal_gen`'s segment.
    pub(crate) offset: u64,
    /// Height of the last durably journaled block.
    pub(crate) height: u32,
    /// Hash of the last durably journaled block (32 raw bytes).
    pub(crate) block_hash: [u8; 32],
    /// Hash of its predecessor (32 raw bytes).
    pub(crate) prev_hash: [u8; 32],
    /// Cumulative transaction count through the head tip.
    pub(crate) chain_tx_count: u64,
    /// Number of records retained from `(start_gen, start_offset)` through head.
    pub(crate) record_count: u64,
}

impl HeadMarker {
    fn crc32c(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            }
        }
        !crc
    }

    fn serialize(&self) -> Result<Vec<u8>, JournalWriterError> {
        let payload = serde_json::to_vec(self).map_err(|error| {
            JournalWriterError::HeadUnreadable(format!("marker serialization failed: {error}"))
        })?;
        let checksum = Self::crc32c(&payload);
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
        let found = Self::crc32c(payload);
        if found != expected {
            return Err(JournalWriterError::HeadUnreadable(format!(
                "marker checksum mismatch: expected {expected:#010x}, found {found:#010x}"
            )));
        }
        serde_json::from_slice(payload)
            .map_err(|error| JournalWriterError::HeadUnreadable(error.to_string()))
    }
}

/// Cursor of the durable frontier: which segment and byte offset are covered
/// by the published `head.json`.
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

/// Lightweight metadata for a record already written to the active segment.
/// The encoded payload has a single in-memory owner during `append`; batching
/// retains only the cursor fields needed to publish a later durability head.
#[derive(Clone, Copy)]
struct PendingRecordMeta {
    end_offset: u64,
    height: u32,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
    block_tx_count: u64,
}

/// Lifecycle of the single-owner writer (plan §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriterState {
    /// Accepting appends.
    Open,
    /// Publication in progress: appends rejected; log frozen at a durable head.
    Frozen,
    /// Compaction ran; appends still blocked until `resume`.
    Compacted,
}

/// The journal writer. One owner per node: the apply path appends; the
/// publication primitive freezes/compacts/resumes.
pub(crate) struct JournalWriter<S: KvStore> {
    dir: cap_std::fs::Dir,
    store: std::sync::Arc<S>,
    /// Checkpoint generation this writer extends.
    base_generation: u64,
    /// Applied-tip height of the checkpoint base.
    base_height: u32,
    /// Applied-tip hash of the checkpoint base.
    base_hash: [u8; 32],
    /// Cumulative transaction count through the checkpoint base.
    base_chain_tx_count: u64,
    /// Lightweight cursors for records written since the last boundary.
    pending_records: Vec<PendingRecordMeta>,
    /// Byte offset of the end of the active segment file.
    segment_offset: u64,
    /// Generation of the active segment.
    segment_gen: u64,
    /// Oldest retained (generation, offset) — the base cursor.
    start: (u64, u64),
    /// Durable frontier published via `head.json`.
    durable: DurableCursor,
    /// Cumulative transaction count covered by `durable`.
    durable_chain_tx_count: u64,
    /// Height expected by the next `append`.
    next_height: u32,
    /// Cumulative `chain_tx_count` through the next append.
    chain_tx_count: u64,
    /// Total retained records (from the base cursor through the durable head).
    record_count: u64,
    /// Buffered byte threshold that forces a boundary (approximate; bytes).
    rotate_bytes: u64,
    /// Blocks-per-boundary default.
    batch_blocks: u32,
    /// Seconds-per-boundary default.
    batch_seconds: Duration,
    /// Total retained segment-byte budget.
    max_journal_bytes: u64,
    /// Maximum pending block count before pre-apply backpressure.
    max_lag_blocks: u32,
    /// Maximum pending age before pre-apply backpressure.
    max_lag_seconds: Duration,
    /// Last boundary instant, for the time-based trigger.
    last_boundary: Instant,
    /// Hash of the durable head block (from the last boundary record).
    durable_block_hash: [u8; 32],
    /// Hash of its predecessor.
    durable_prev_hash: [u8; 32],
    /// First live height whose append did not complete. Once set, the writer
    /// fails closed before any later block mutation; restart recovery truncates
    /// the active segment to the durable cursor and creates a fresh writer.
    append_gap_height: Option<u32>,
    /// A durability boundary failed after all record bytes were tracked. The
    /// next pre-apply check must retry that boundary regardless of configured
    /// lag thresholds before permitting another chainstate mutation.
    durability_retry_required: bool,
    state: WriterState,
    failpoint: Option<JournalWriterFailpoint>,
}

impl<S: KvStore> JournalWriter<S> {
    /// Current lifecycle state.
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

    /// Durable head marker, for the boot path and metrics.
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

/// Journal-directory helpers shared by writer and boot replay (later task).
///
/// `head.json` is bounded by [`MAX_HEAD_BYTES`].
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
