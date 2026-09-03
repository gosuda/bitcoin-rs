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
//! whole record is retried — appends are idempotent per height.
//!
//! Failure classification: append/boundary failures are never consensus-fatal
//! (the journal only accelerates recovery); callers see [`JournalWriterError`]
//! and apply §2.3's degraded-mode policy. Loading a corrupt journal at boot
//! fails closed (handled by replay, later task).

use std::io::Write;
use std::time::{Duration, Instant};

use bitcoin_rs_storage::KvStore;
use thiserror::Error;

use super::record::{JournalRecord, encode_record};

/// Magic prefix of `head.json` payload bytes (versioned container, crc32c).
const HEAD_MAGIC: [u8; 4] = *b"JRNH";
/// Current `head.json` format version.
const HEAD_VERSION: u8 = 1;
/// Maximum serialized `head.json` size accepted on load.
const MAX_HEAD_BYTES: u64 = 4 * 1024;
/// Maximum serialized segment name length sanity bound.
const SEGMENT_NAME_MAX: usize = 32;

/// Durability batch size, in blocks (plan §2.3 default; config lands in Task 3).
const DEFAULT_BATCH_BLOCKS: u32 = 500;
/// Durability batch period, in seconds (plan §2.3 default; config lands in Task 3).
const DEFAULT_BATCH_SECONDS: u64 = 5;
/// Segment rotation threshold, in MiB (plan §2.1; config lands in Task 3).
const DEFAULT_ROTATE_MIB: u64 = 256;
/// Retention bound on total journal size, in MiB (plan §2.1; config lands in Task 3).
const DEFAULT_MAX_JOURNAL_MIB: u64 = 2048;

/// Zero-padded 10-digit generation: lexicographic order equals numeric order.
const SEGMENT_GEN_WIDTH: usize = 10;

/// Public-to-crate wrapper for the boot replay's segment window reader.
pub(crate) fn segment_name_pub(generation: u64) -> String {
    segment_name(generation)
}

fn segment_name(generation: u64) -> String {
    format!("segment-{generation:0SEGMENT_GEN_WIDTH$}.log")
}

/// Public-to-crate wrapper for the boot replay's segment window reader.
pub(crate) fn parse_segment_name_pub(name: &str) -> Option<u64> {
    parse_segment_name(name)
}

fn parse_segment_name(name: &str) -> Option<u64> {
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
    /// `head.json` is missing, unreadable, or fails its checksum.
    #[error("chainstate journal head marker is unreadable: {0}")]
    HeadUnreadable(String),
    /// The active segment does not match the durable cursor it claims.
    #[error("chainstate journal cursor mismatch: {0}")]
    CursorMismatch(String),
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
    /// Buffered record bytes not yet covered by a durability boundary.
    pending: Vec<u8>,
    /// Records buffered since the last boundary (for `flush_to` accounting).
    pending_records: Vec<JournalRecord>,
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
    /// Last boundary instant, for the time-based trigger.
    last_boundary: Instant,
    /// Hash of the durable head block (from the last boundary record).
    durable_block_hash: [u8; 32],
    /// Hash of its predecessor.
    durable_prev_hash: [u8; 32],
    state: WriterState,
    failpoint: Option<JournalWriterFailpoint>,
}

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

    fn restore(
        dir: cap_std::fs::Dir,
        store: std::sync::Arc<S>,
        head: HeadMarker,
    ) -> Result<Self, JournalWriterError> {
        let mut writer = Self {
            dir,
            store,
            base_generation: head.base_generation,
            base_height: head.base_height,
            base_hash: head.base_hash,
            base_chain_tx_count: head.base_chain_tx_count,
            pending: Vec::new(),
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
            rotate_bytes: DEFAULT_ROTATE_MIB * 1024 * 1024,
            batch_blocks: DEFAULT_BATCH_BLOCKS,
            batch_seconds: Duration::from_secs(DEFAULT_BATCH_SECONDS),
            last_boundary: Instant::now(),
            state: WriterState::Open,
            failpoint: None,
        };
        writer.recover_active_segment()?;
        Ok(writer)
    }

    /// Truncates the active segment to the durable cursor (torn tail ignored).
    fn recover_active_segment(&mut self) -> Result<(), JournalWriterError> {
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

    /// Current lifecycle state.
    pub(crate) fn state(&self) -> WriterState {
        self.state
    }

    /// Applies the resolved runtime batching and segment-rotation policy.
    pub(crate) fn configure(
        &mut self,
        batch_blocks: u32,
        batch_seconds: Duration,
        rotate_mib: u64,
    ) -> Result<(), JournalWriterError> {
        if batch_blocks == 0 || batch_seconds.is_zero() || rotate_mib == 0 {
            return Err(JournalWriterError::CursorMismatch(
                "journal runtime limits must be non-zero".to_owned(),
            ));
        }
        self.batch_blocks = batch_blocks;
        self.batch_seconds = batch_seconds;
        self.rotate_bytes = rotate_mib.checked_mul(1024 * 1024).ok_or_else(|| {
            JournalWriterError::CursorMismatch("journal rotation size overflow".to_owned())
        })?;
        Ok(())
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

    /// Buffers one record. Idempotent per height: re-appending a record whose
    /// height equals the last appended height is rejected as a duplicate via
    /// the strict ordering rule (callers replay whole records after a crash).
    pub(crate) fn append(&mut self, record: &JournalRecord) -> Result<(), JournalWriterError> {
        if self.state != WriterState::Open {
            return Err(JournalWriterError::NotOpen {
                state: match self.state {
                    WriterState::Frozen => "frozen",
                    WriterState::Compacted => "compacted",
                    WriterState::Open => unreachable!("guarded above"),
                },
            });
        }
        if record.height != self.next_height {
            return Err(JournalWriterError::OutOfOrder {
                got: record.height,
                expected: self.next_height,
            });
        }
        self.maybe_rotate()?;
        self.fail_segment_append()?;

        let name = segment_name(self.segment_gen);
        let mut options = cap_std::fs::OpenOptions::new();
        options.append(true).create(true);
        let mut file = self.dir.open_with(&name, &options)?;
        let bytes = encode_record(record);
        file.write_all(&bytes)?;
        file.sync_data()?;
        self.segment_offset = self
            .segment_offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                JournalWriterError::CursorMismatch("record byte length overflow".to_owned())
            })?)
            .ok_or_else(|| {
                JournalWriterError::CursorMismatch("segment offset overflow".to_owned())
            })?;

        self.pending.extend_from_slice(&bytes);
        self.pending_records.push(record.clone());
        self.next_height = self
            .next_height
            .checked_add(1)
            .ok_or_else(|| JournalWriterError::CursorMismatch("height overflow".to_owned()))?;
        self.chain_tx_count = self
            .chain_tx_count
            .checked_add(record.block_tx_count)
            .ok_or_else(|| {
                JournalWriterError::CursorMismatch("chain_tx_count overflow".to_owned())
            })?;

        if self.pending_records.len()
            >= usize::try_from(self.batch_blocks).map_err(|_| {
                JournalWriterError::CursorMismatch("batch blocks overflow".to_owned())
            })?
            || self.last_boundary.elapsed() >= self.batch_seconds
        {
            self.advance_durability()?;
        }
        Ok(())
    }

    /// §2.3 durability boundary, in one serialized step:
    /// 1. storage flush (deferred undo rows become durable),
    /// 2. log fsync,
    /// 3. atomic `head.json` publish.
    ///
    /// `target` is the record index (exclusive) in `pending_records` that the
    /// boundary covers.
    fn advance_durability(&mut self) -> Result<(), JournalWriterError> {
        if self.pending_records.is_empty() {
            return Ok(());
        }
        let target = self.pending_records.len();
        let last = &self.pending_records[target - 1];

        // (1) storage dependency — deferred undo rows must be durable before
        // the head claims the covered heights.
        self.fail_storage_flush()?;
        self.store
            .flush()
            .map_err(|error| JournalWriterError::StorageFlush(error.to_string()))?;

        // (2) log fsync — the segment bytes covering the range become durable.
        self.fail_segment_sync()?;
        let name = segment_name(self.segment_gen);
        let file = self
            .dir
            .open_with(&name, cap_std::fs::OpenOptions::new().write(true))?;
        file.sync_all()?;

        // (3) atomic head publish.
        let marker = HeadMarker {
            base_generation: self.base_generation,
            base_height: self.base_height,
            base_hash: self.base_hash,
            base_chain_tx_count: self.base_chain_tx_count,
            start_gen: self.start.0,
            start_offset: self.start.1,
            journal_gen: self.segment_gen,
            offset: self.segment_offset,
            height: last.height,
            block_hash: last.block_hash,
            prev_hash: last.prev_hash,
            chain_tx_count: self.chain_tx_count,
            record_count: self.record_count
                + u64::try_from(target).map_err(|_| {
                    JournalWriterError::CursorMismatch("record count overflow".to_owned())
                })?,
        };
        self.write_head_atomic(&marker)?;

        self.durable = DurableCursor {
            generation: self.segment_gen,
            offset: self.segment_offset,
            height: last.height,
        };
        self.durable_block_hash = last.block_hash;
        self.durable_prev_hash = last.prev_hash;
        self.durable_chain_tx_count = self.chain_tx_count;
        self.record_count += u64::try_from(target)
            .map_err(|_| JournalWriterError::CursorMismatch("record count overflow".to_owned()))?;
        self.pending.clear();
        self.pending_records.clear();
        self.last_boundary = Instant::now();
        Ok(())
    }

    /// Publishes `head.json` without advancing the cursor (used at
    /// initialization and by `freeze`).
    fn publish_head_now(&self) -> Result<(), JournalWriterError> {
        let marker = self.head();
        self.write_head_atomic(&marker)
    }

    fn write_head_atomic(&self, marker: &HeadMarker) -> Result<(), JournalWriterError> {
        self.fail_head_temp_write()?;
        {
            let mut options = cap_std::fs::OpenOptions::new();
            options.write(true).create(true);
            let mut tmp = self.dir.open_with("head.json.tmp", &options)?;
            tmp.set_len(0)?;
            tmp.write_all(&marker.serialize()?)?;
            self.fail_head_temp_sync()?;
            tmp.sync_all()?;
        }
        self.fail_head_rename()?;
        self.dir.rename("head.json.tmp", &self.dir, "head.json")?;
        self.fail_head_dir_sync()?;
        crate::checkpoint_fs::sync_dir(&self.dir)?;
        Ok(())
    }

    /// Flushes buffered records up to and including `height` (plan §2.5's
    /// `flush_to`). No-op when the height is already durable; errors when the
    /// height is beyond the buffered frontier.
    pub(crate) fn flush_to(&mut self, height: u32) -> Result<(), JournalWriterError> {
        if height <= self.durable.height {
            return Ok(());
        }
        let Some(index) = self
            .pending_records
            .iter()
            .rposition(|record| record.height == height)
        else {
            return Err(JournalWriterError::CursorMismatch(format!(
                "height {height} is not buffered"
            )));
        };
        self.advance_durability_upto(index + 1)
    }

    /// Boundary over the first `target` buffered records.
    fn advance_durability_upto(&mut self, target: usize) -> Result<(), JournalWriterError> {
        if self.pending_records.is_empty() || target == 0 {
            return Ok(());
        }
        let last = &self.pending_records[target - 1];
        let prefix_len = u64::try_from(self.pending_len_for(target))
            .map_err(|_| JournalWriterError::CursorMismatch("record bytes overflow".to_owned()))?;
        let target_offset = self.durable.offset.checked_add(prefix_len).ok_or_else(|| {
            JournalWriterError::CursorMismatch("segment offset overflow".to_owned())
        })?;
        let target_chain_tx_count = self.pending_records[..target].iter().try_fold(
            self.durable_chain_tx_count,
            |count, record| {
                count.checked_add(record.block_tx_count).ok_or_else(|| {
                    JournalWriterError::CursorMismatch(
                        "chain transaction count overflow".to_owned(),
                    )
                })
            },
        )?;

        self.fail_storage_flush()?;
        self.store
            .flush()
            .map_err(|error| JournalWriterError::StorageFlush(error.to_string()))?;

        self.fail_segment_sync()?;
        let name = segment_name(self.segment_gen);
        let file = self
            .dir
            .open_with(&name, cap_std::fs::OpenOptions::new().write(true))?;
        file.sync_all()?;

        let marker = HeadMarker {
            base_generation: self.base_generation,
            base_height: self.base_height,
            base_hash: self.base_hash,
            base_chain_tx_count: self.base_chain_tx_count,
            start_gen: self.start.0,
            start_offset: self.start.1,
            journal_gen: self.segment_gen,
            offset: target_offset,
            height: last.height,
            block_hash: last.block_hash,
            prev_hash: last.prev_hash,
            chain_tx_count: target_chain_tx_count,
            record_count: self.record_count
                + u64::try_from(target).map_err(|_| {
                    JournalWriterError::CursorMismatch("record count overflow".to_owned())
                })?,
        };
        self.write_head_atomic(&marker)?;

        self.durable = DurableCursor {
            generation: self.segment_gen,
            offset: target_offset,
            height: last.height,
        };
        self.durable_block_hash = last.block_hash;
        self.durable_prev_hash = last.prev_hash;
        self.durable_chain_tx_count = target_chain_tx_count;
        self.record_count += u64::try_from(target)
            .map_err(|_| JournalWriterError::CursorMismatch("record count overflow".to_owned()))?;
        self.pending.drain(
            ..usize::try_from(prefix_len).map_err(|_| {
                JournalWriterError::CursorMismatch("record bytes overflow".to_owned())
            })?,
        );
        self.pending_records.drain(..target);
        self.last_boundary = Instant::now();
        Ok(())
    }

    /// Byte length of the first `target` buffered records.
    fn pending_len_for(&self, target: usize) -> usize {
        self.pending_records
            .iter()
            .take(target)
            .map(|record| {
                let encoded = encode_record(record);
                encoded.len()
            })
            .sum()
    }

    /// §2.5 freeze: stop accepting appends; make the log durable up to the
    /// last buffered record; publish the final head. Called by the publication
    /// primitive with admission already closed.
    pub(crate) fn freeze(&mut self) -> Result<(), JournalWriterError> {
        if self.state != WriterState::Open {
            return Err(JournalWriterError::NotOpen {
                state: match self.state {
                    WriterState::Frozen | WriterState::Compacted => "already frozen",
                    WriterState::Open => unreachable!("guarded above"),
                },
            });
        }
        self.state = WriterState::Frozen;
        self.advance_durability()?;
        Ok(())
    }

    /// §2.5 compact: drop segments fully below the published checkpoint base
    /// and reset the base cursor. Called by the publication primitive AFTER a
    /// successful checkpoint install.
    pub(crate) fn compact(&mut self, new_base: (u64, u64)) -> Result<(), JournalWriterError> {
        if self.state != WriterState::Frozen {
            return Err(JournalWriterError::NotOpen {
                state: match self.state {
                    WriterState::Open => "not frozen",
                    WriterState::Compacted => "already compacted",
                    WriterState::Frozen => unreachable!("guarded above"),
                },
            });
        }
        if new_base.0 > self.segment_gen
            || (new_base.0 == self.segment_gen && new_base.1 > self.segment_offset)
        {
            return Err(JournalWriterError::CursorMismatch(format!(
                "compaction base {new_base:?} is ahead of the durable frontier"
            )));
        }
        // Delete fully-retained segments strictly below the new base gen.
        let entries: Vec<String> = self
            .dir
            .entries()?
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
            })
            .filter(|name| {
                parse_segment_name(name).is_some_and(|generation| generation < new_base.0)
            })
            .collect();
        for name in entries {
            self.dir.remove_file(&name)?;
        }
        self.start = new_base;
        self.state = WriterState::Compacted;
        Ok(())
    }

    /// §2.5 resume: reopen appends against the (possibly new) base.
    pub(crate) fn resume(&mut self) -> Result<(), JournalWriterError> {
        if self.state == WriterState::Open {
            return Err(JournalWriterError::NotOpen {
                state: "already open",
            });
        }
        // Publish the (possibly unchanged) head with the new base cursor.
        self.publish_head_now()?;
        self.state = WriterState::Open;
        self.last_boundary = Instant::now();
        Ok(())
    }

    /// Rotates the active segment when it crosses the size threshold.
    fn maybe_rotate(&mut self) -> Result<(), JournalWriterError> {
        if self.segment_offset < self.rotate_bytes {
            return Ok(());
        }
        // Close the current segment durably: the boundary covers buffered
        // records, then the next append starts a new generation.
        self.advance_durability()?;
        self.segment_gen = self
            .segment_gen
            .checked_add(1)
            .ok_or_else(|| JournalWriterError::CursorMismatch("generation overflow".to_owned()))?;
        self.segment_offset = 0;
        self.durable = DurableCursor {
            generation: self.segment_gen,
            offset: 0,
            height: self.durable.height,
        };
        self.publish_head_now()?;
        Ok(())
    }

    // --- failpoint plumbing (mirrors checkpoint.rs) ---

    fn fail_segment_append(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::SegmentAppend)
    }

    fn fail_segment_sync(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::SegmentSync)
    }

    fn fail_storage_flush(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::StorageFlush)
    }

    fn fail_head_temp_write(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadTempWrite)
    }

    fn fail_head_temp_sync(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadTempSync)
    }

    fn fail_head_rename(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadRename)
    }

    fn fail_head_dir_sync(&self) -> Result<(), JournalWriterError> {
        self.failpoint(JournalWriterFailpoint::HeadDirSync)
    }

    fn failpoint(&self, boundary: JournalWriterFailpoint) -> Result<(), JournalWriterError> {
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
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use bitcoin_rs_storage::{
        ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
    };
    use cap_std::ambient_authority;

    use super::*;
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};

    use crate::chainstate_journal::record::{Coin, Mutation};

    /// Counts `flush()` calls and can fail them, proving the §2.3 order:
    /// the head marker must never advance without a counted flush.
    struct CountingStore {
        flushes: AtomicU64,
        fail_flush: Mutex<bool>,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                flushes: AtomicU64::new(0),
                fail_flush: Mutex::new(false),
            }
        }

        fn flush_count(&self) -> u64 {
            self.flushes.load(Ordering::SeqCst)
        }

        fn set_fail_flush(&self, fail: bool) {
            *self.fail_flush.lock().expect("uncontended") = fail;
        }
    }

    impl KvStore for CountingStore {
        type WriteBatch = NoopBatch;

        fn get(&self, _cf: ColumnFamily, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }

        fn iter_prefix<'a>(
            &'a self,
            _cf: ColumnFamily,
            _prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            Ok(Box::new(std::iter::empty()))
        }

        fn new_batch(&self) -> Self::WriteBatch {
            NoopBatch
        }

        fn write(&self, _batch: Self::WriteBatch) -> Result<(), StorageError> {
            Ok(())
        }

        fn write_durable_if(
            &self,
            _conditions: &[WriteCondition<'_>],
            _batch: Self::WriteBatch,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            if *self.fail_flush.lock().expect("uncontended") {
                return Err(StorageError::InvalidOperation(
                    "injected flush failure".into(),
                ));
            }
            Ok(())
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            unreachable!("unused in writer tests")
        }
    }

    struct NoopBatch;

    impl WriteBatch for NoopBatch {
        fn put(&mut self, _cf: ColumnFamily, _key: &[u8], _value: &[u8]) {}
        fn delete(&mut self, _cf: ColumnFamily, _key: &[u8]) {}
        fn delete_range(&mut self, _cf: ColumnFamily, _start: &[u8], _end: &[u8]) {}
    }

    fn temp_dir(tag: &str) -> cap_std::fs::Dir {
        let path =
            std::env::temp_dir().join(format!("journal-writer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir creation");
        cap_std::fs::Dir::open_ambient_dir(&path, ambient_authority()).expect("ambient open")
    }

    fn sample_record(height: u32) -> JournalRecord {
        JournalRecord {
            height,
            block_hash: [u8::try_from(height).unwrap_or(9); 32],
            prev_hash: [u8::try_from(height.wrapping_sub(1)).unwrap_or(8); 32],
            block_tx_count: 3,
            coin_stats_height_delta: 1,
            raw_header: [0; 80],
            mutations: vec![
                Mutation::Create {
                    coin: Coin {
                        outpoint: OutPoint::new(
                            Txid(Hash256::from_le_bytes(
                                &[u8::try_from(height).unwrap_or(9); 32],
                            )),
                            u32::from(height),
                        ),
                        txout: TxOut {
                            value: u64::from(height),
                            script_pubkey: vec![0x51],
                        },
                        height,
                        coinbase: true,
                    },
                },
                Mutation::Spend {
                    coin: Coin {
                        outpoint: OutPoint::new(
                            Txid(Hash256::from_le_bytes(
                                &[u8::try_from(height.wrapping_sub(1)).unwrap_or(8); 32],
                            )),
                            u32::from(height.wrapping_sub(1)),
                        ),
                        txout: TxOut {
                            value: u64::from(height),
                            script_pubkey: vec![0x51],
                        },
                        height: height.wrapping_sub(1),
                        coinbase: false,
                    },
                },
            ],
        }
    }

    fn open_fresh(tag: &str, store: Arc<CountingStore>) -> JournalWriter<CountingStore> {
        let dir = temp_dir(tag);
        JournalWriter::initialize(dir, store, 0, (0, 0), 0, [1; 32], [0; 32], 0)
            .expect("initialize journal")
    }

    #[test]
    fn head_never_advances_without_counted_storage_flush() {
        let store = Arc::new(CountingStore::new());
        let mut writer = open_fresh("flush-order", Arc::clone(&store));
        let flushes_at_open = store.flush_count();

        // Fail the storage dependency: append still succeeds (buffered), but
        // the automatic boundary must not publish a head.
        store.set_fail_flush(true);
        writer
            .append(&sample_record(1))
            .expect("buffered append is infallible");
        store.set_fail_flush(false);

        // Force the boundary now: flush counted, head publishable.
        writer.flush_to(1).expect("boundary after flush recovery");
        assert_eq!(store.flush_count(), flushes_at_open + 1);
        assert_eq!(writer.head().height, 1);
    }

    #[test]
    fn torn_tail_beyond_head_is_ignored_on_reopen() {
        let store = Arc::new(CountingStore::new());
        let dir;
        {
            let mut writer = open_fresh("torn-tail", Arc::clone(&store));
            writer.append(&sample_record(1)).expect("append 1");
            writer.flush_to(1).expect("durable head at 1");
            dir = writer.dir.try_clone().expect("dir clone");
            // Simulate a torn append after the head: raw bytes past the cursor.
            let mut options = cap_std::fs::OpenOptions::new();
            options.append(true).create(true);
            let mut file = dir
                .open_with(&segment_name(writer.segment_gen), &options)
                .expect("open segment");
            file.write_all(&[0xde, 0xad, 0xbe, 0xef])
                .expect("torn bytes");
            file.sync_all().expect("torn sync");
        }
        // Reopen: the torn tail must be truncated away without error.
        let writer = JournalWriter::open(dir, store).expect("reopen after torn tail");
        assert_eq!(writer.head().height, 1);
    }

    #[test]
    fn partial_append_truncates_and_retries_idempotently() {
        let store = Arc::new(CountingStore::new());
        let dir;
        let record = sample_record(1);
        {
            let mut writer = open_fresh("idempotent", Arc::clone(&store));
            // Buffer record 1 but crash before any boundary (drop = crash).
            writer.append(&record).expect("append");
            dir = writer.dir.try_clone().expect("dir clone");
        }
        // After the crash, record 1 was fsynced per append but never covered
        // by a head. Reopening truncates to the head cursor; the caller
        // replays record 1 and gets the same bytes in the same place.
        let mut writer = JournalWriter::open(dir, Arc::clone(&store)).expect("reopen");
        writer.append(&record).expect("replay append");
        writer.flush_to(1).expect("durable");
        assert_eq!(writer.head().height, 1);
        assert_eq!(writer.head().record_count, 1);
    }

    #[test]
    fn rotation_keeps_cursor_invariants() {
        let store = Arc::new(CountingStore::new());
        let mut writer = open_fresh("rotation", Arc::clone(&store));
        // Force a tiny rotation threshold so the first append rotates.
        writer.rotate_bytes = 0;
        writer.append(&sample_record(1)).expect("append 1");
        writer.append(&sample_record(2)).expect("append 2");
        assert_eq!(writer.segment_gen, 1, "rotation bumped the generation");
        // head must stay valid across the rotation.
        writer.flush_to(2).expect("durable across rotation");
        assert_eq!(writer.head().height, 2);
        assert_eq!(writer.head().journal_gen, 1);
        // Zero-padded naming: lexicographic == numeric.
        let names: Vec<String> = (0..3).map(segment_name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "zero-padded segments sort numerically");
    }

    #[test]
    fn failpoints_fire_documented_errors() {
        for boundary in [
            JournalWriterFailpoint::StorageFlush,
            JournalWriterFailpoint::SegmentSync,
            JournalWriterFailpoint::HeadTempWrite,
            JournalWriterFailpoint::HeadTempSync,
            JournalWriterFailpoint::HeadRename,
            JournalWriterFailpoint::HeadDirSync,
        ] {
            let store = Arc::new(CountingStore::new());
            let mut writer = open_fresh("failpoints", Arc::clone(&store));
            writer.inject_failpoint(boundary);
            // The boundary path must fail at the armed boundary...
            let result = writer.append(&sample_record(1));
            assert!(result.is_err(), "{boundary:?} did not fire");
            // ...and head.json must still reflect height 0 (no advancement).
            assert_eq!(writer.head().height, 0, "{boundary:?} advanced the head");
        }
    }

    #[test]
    fn freeze_rejects_appends_and_compaction_flow_completes() {
        let store = Arc::new(CountingStore::new());
        let mut writer = open_fresh("freeze", Arc::clone(&store));
        writer.append(&sample_record(1)).expect("append 1");
        writer.freeze().expect("freeze");
        assert_eq!(writer.state(), WriterState::Frozen);
        let error = writer
            .append(&sample_record(2))
            .expect_err("frozen writer rejects appends");
        assert!(matches!(error, JournalWriterError::NotOpen { .. }));
        writer.compact((0, 0)).expect("compact");
        writer.resume().expect("resume");
        assert_eq!(writer.state(), WriterState::Open);
        writer
            .append(&sample_record(2))
            .expect("append 2 after resume");
    }
}
