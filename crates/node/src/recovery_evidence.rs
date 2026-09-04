//! Durable rollback evidence: witness and marker file protocol.
//!
//! Private to the node crate. Implements A2 of REC-A12.
//!
//! ## Design
//!
//! Two root-level sidecar file families live beside `process-epoch`:
//!
//! - `applied-tip-witness.json` (+ `.prev`, `.tmp`): the applied tip at the
//!   last durable checkpoint publication.
//! - `chain-rollback-event.json` (+ `.prev`, `.tmp`): the last detected
//!   rollback event (checkpoint fallback or index watermark ahead).
//!
//! Both use a bounded current/previous protocol: write to temp, fsync temp,
//! rotate valid current to `.prev`, rename temp to current, fsync the
//! directory. Reading falls back to `.prev` only when current is missing or
//! invalid. Never selects by greatest height.
//!
//! One `ArcSwap` warning snapshot holds both checkpoint-fallback and
//! index-ahead warnings together. `getblockchaininfo` loads one immutable
//! snapshot per request.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum file size for any evidence file (4 KiB).
const MAX_FILE_BYTES: usize = 4096;

const WITNESS_FILE: &str = "applied-tip-witness.json";
const WITNESS_PREV: &str = "applied-tip-witness.json.prev";
const WITNESS_TMP: &str = "applied-tip-witness.json.tmp";

const MARKER_FILE: &str = "chain-rollback-event.json";
const MARKER_PREV: &str = "chain-rollback-event.json.prev";
const MARKER_TMP: &str = "chain-rollback-event.json.tmp";

const WITNESS_FORMAT: &str = "1";
const MARKER_FORMAT: &str = "1";

// ---------------------------------------------------------------------------
// Witness codec
// ---------------------------------------------------------------------------

/// Durable record of the applied tip at the last clean checkpoint publication.
///
/// Written only by `NodeState::write_clean_checkpoint` after
/// `CheckpointWrite::Published` and root fsync.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedTipWitness {
    pub(crate) format: String,
    /// Genesis block hash in hex.
    pub(crate) genesis_hash: String,
    /// Process epoch that wrote this witness.
    pub(crate) writer_epoch: u64,
    pub(crate) height: u32,
    /// Block hash in hex.
    pub(crate) block_hash: String,
    /// Unix time in seconds.
    pub(crate) time: u64,
}

impl AppliedTipWitness {
    pub(crate) fn new(
        genesis_hash: impl Into<String>,
        writer_epoch: u64,
        height: u32,
        block_hash: impl Into<String>,
        time: u64,
    ) -> Self {
        Self {
            format: WITNESS_FORMAT.to_owned(),
            genesis_hash: genesis_hash.into(),
            writer_epoch,
            height,
            block_hash: block_hash.into(),
            time,
        }
    }

    /// Serializes to a JSON string (no trailing newline).
    #[expect(clippy::expect_used, reason = "serialization of infallible types")]
    fn to_json(&self) -> String {
        serde_json::to_string(self).expect("witness serialization is infallible")
    }

    /// Deserializes from JSON bytes (with or without trailing newline).
    fn from_json(data: &[u8]) -> Option<Self> {
        let trimmed = data.strip_suffix(b"\n").unwrap_or(data);
        serde_json::from_slice(trimmed).ok()
    }

    /// Returns true if the format matches and the genesis hash matches.
    fn is_valid_for(&self, expected_format: &str, genesis_hash: &str) -> bool {
        self.format == expected_format && self.genesis_hash == genesis_hash
    }
}

// ---------------------------------------------------------------------------
// Event marker codec
// ---------------------------------------------------------------------------

/// Exactly one rollback event kind.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum RollbackEventKind {
    CheckpointFallback {
        restored_height: u32,
        restored_hash: String,
        source: String,
        old_height: u32,
        old_hash: String,
    },
    IndexWatermarkAhead {
        capability: String,
        restored_height: u32,
        restored_hash: String,
        old_height: u32,
        old_hash: String,
        gap: u32,
    },
}

/// Durable record of the last detected rollback event.
///
/// Last-event-wins. The prior valid event is preserved as `.prev`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainRollbackEvent {
    pub(crate) format: String,
    /// Genesis block hash in hex.
    pub(crate) genesis_hash: String,
    /// Process epoch that detected this event.
    pub(crate) detecting_epoch: u64,
    /// Unix time in seconds.
    pub(crate) time: u64,
    pub(crate) event: RollbackEventKind,
}

impl ChainRollbackEvent {
    pub(crate) fn new(
        genesis_hash: impl Into<String>,
        detecting_epoch: u64,
        time: u64,
        event: RollbackEventKind,
    ) -> Self {
        Self {
            format: MARKER_FORMAT.to_owned(),
            genesis_hash: genesis_hash.into(),
            detecting_epoch,
            time,
            event,
        }
    }

    #[expect(clippy::expect_used, reason = "serialization of infallible types")]
    fn to_json(&self) -> String {
        serde_json::to_string(self).expect("event serialization is infallible")
    }

    fn from_json(data: &[u8]) -> Option<Self> {
        let trimmed = data.strip_suffix(b"\n").unwrap_or(data);
        serde_json::from_slice(trimmed).ok()
    }

    fn is_valid_for(&self, expected_format: &str, genesis_hash: &str) -> bool {
        self.format == expected_format && self.genesis_hash == genesis_hash
    }
}

// ---------------------------------------------------------------------------
// Bounded current/previous file protocol
// ---------------------------------------------------------------------------

/// Error from the bounded file protocol.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EvidenceError {
    #[error("evidence I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("evidence serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Writes a bounded current/previous file pair atomically.
///
/// Protocol:
/// 1. Remove stale temp (`NotFound` is success).
/// 2. Open temp with `create_new` (no-symlink semantics).
/// 3. Write bounded payload + newline.
/// 4. `sync_all` the temp file.
/// 5. Validate current; rotate valid current to `.prev`.
///    Never overwrite a known-valid `.prev` with an invalid current.
/// 6. Rename temp to current.
/// 7. `sync_all` the data-dir root.
/// 8. On error, remove temp best-effort.
///
/// `validate` checks whether the current file's bytes are a valid payload.
/// Only a valid current is rotated to `.prev`; an invalid current is removed
/// without overwriting an existing valid `.prev`.
pub(crate) fn write_bounded(
    dir: &Path,
    payload: &str,
    current_name: &str,
    prev_name: &str,
    tmp_name: &str,
    validate: impl Fn(&[u8]) -> bool,
) -> Result<(), EvidenceError> {
    let tmp_path = dir.join(tmp_name);
    let current_path = dir.join(current_name);
    let prev_path = dir.join(prev_name);

    // 1. Remove stale temp.
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(EvidenceError::Io(e)),
    }

    // 2-4. Create temp, write, fsync.
    let result = (|| -> Result<(), EvidenceError> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(payload.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        Ok(())
    })();

    if let Err(e) = result {
        // 8. Best-effort temp cleanup on error.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // 5. Validate current; rotate valid current to `.prev`.
    // Never overwrite a known-valid `.prev` with an invalid current.
    if current_path.exists() {
        match std::fs::read(&current_path) {
            Ok(data) if data.len() <= MAX_FILE_BYTES && validate(&data) => {
                // Current is valid; rotate to .prev.
                let _ = std::fs::remove_file(&prev_path);
                std::fs::rename(&current_path, &prev_path)?;
            }
            _ => {
                // Current is invalid or oversized; remove it.
                // Keep existing .prev (never overwrite valid .prev with invalid current).
                let _ = std::fs::remove_file(&current_path);
            }
        }
    }

    // 6. Rename temp to current.
    std::fs::rename(&tmp_path, &current_path)?;

    // 7. Fsync the data-dir root.
    sync_dir(dir)?;

    Ok(())
}
/// missing or invalid (oversized or unreadable). Never selects by greater
/// height or newer time.
pub(crate) fn read_bounded(dir: &Path, current_name: &str, prev_name: &str) -> Option<Vec<u8>> {
    let current_path = dir.join(current_name);
    if let Some(data) = read_and_validate(&current_path) {
        Some(data)
    } else {
        let prev_path = dir.join(prev_name);
        read_and_validate(&prev_path)
    }
}

/// Reads, validates size, and returns the file contents. Returns `None` for
/// missing, oversized, or unreadable files.
fn read_and_validate(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) if data.len() <= MAX_FILE_BYTES => Some(data),
        Ok(_) => {
            tracing::debug!(path = %path.display(), "evidence file oversized, ignoring");
            None
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "evidence file read error");
            None
        }
    }
}

/// Syncs a directory's metadata to durable storage.
fn sync_dir(dir: &Path) -> Result<(), EvidenceError> {
    let f = std::fs::File::open(dir)?;
    f.sync_all()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Witness-specific helpers
// ---------------------------------------------------------------------------

/// Writes the applied-tip witness using the bounded current/prev protocol.
///
/// The rotation check is semantic: a parseable but foreign-genesis or
/// wrong-format current is INVALID and is removed without displacing a
/// valid `.prev`, mirroring `read_witness`'s acceptance criteria.
pub(crate) fn write_witness(dir: &Path, witness: &AppliedTipWitness) -> Result<(), EvidenceError> {
    write_bounded(
        dir,
        &witness.to_json(),
        WITNESS_FILE,
        WITNESS_PREV,
        WITNESS_TMP,
        |data| {
            AppliedTipWitness::from_json(data)
                .is_some_and(|w| w.is_valid_for(WITNESS_FORMAT, &witness.genesis_hash))
        },
    )
}

/// Reads the applied-tip witness, falling back to `.prev` when current is
/// missing or invalid. Returns `None` if neither is available.
///
/// Ignores malformed, oversized, wrong-format, and foreign-genesis evidence
/// at DEBUG level.
pub(crate) fn read_witness(dir: &Path, genesis_hash: &str) -> Option<AppliedTipWitness> {
    let data = read_bounded(dir, WITNESS_FILE, WITNESS_PREV)?;
    let witness = AppliedTipWitness::from_json(&data)?;
    if !witness.is_valid_for(WITNESS_FORMAT, genesis_hash) {
        tracing::debug!("witness has wrong format or foreign genesis, ignoring");
        return None;
    }
    Some(witness)
}

// ---------------------------------------------------------------------------
// Marker-specific helpers
// ---------------------------------------------------------------------------

/// Writes the chain-rollback event marker using the bounded current/prev
/// protocol. Last-event-wins; prior valid event preserved as `.prev`.
///
/// The rotation check is semantic: a parseable but foreign-genesis or
/// wrong-format current is INVALID and is removed without displacing a
/// valid `.prev`, mirroring `read_marker`'s acceptance criteria.
pub(crate) fn write_marker(dir: &Path, event: &ChainRollbackEvent) -> Result<(), EvidenceError> {
    write_bounded(
        dir,
        &event.to_json(),
        MARKER_FILE,
        MARKER_PREV,
        MARKER_TMP,
        |data| {
            ChainRollbackEvent::from_json(data)
                .is_some_and(|e| e.is_valid_for(MARKER_FORMAT, &event.genesis_hash))
        },
    )
}

/// Reads the most recent valid chain-rollback event marker, falling back to
/// `.prev` when current is missing or invalid.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn read_marker(dir: &Path, genesis_hash: &str) -> Option<ChainRollbackEvent> {
    let data = read_bounded(dir, MARKER_FILE, MARKER_PREV)?;
    let event = ChainRollbackEvent::from_json(&data)?;
    if !event.is_valid_for(MARKER_FORMAT, genesis_hash) {
        tracing::debug!("marker has wrong format or foreign genesis, ignoring");
        return None;
    }
    Some(event)
}

// ---------------------------------------------------------------------------
// Warning snapshot
// ---------------------------------------------------------------------------

/// One immutable warning snapshot holding both checkpoint-fallback and
/// index-ahead warnings together.
#[derive(Clone, Debug, Default)]
pub(crate) struct WarningSnapshot {
    /// At most one checkpoint-fallback warning for the process.
    checkpoint: Option<String>,
    /// One warning per distinct index capability/evidence tuple, sorted by
    /// capability id and stable evidence fields.
    index: Vec<String>,
}

impl WarningSnapshot {
    /// Renders all warnings in deterministic order: checkpoint fallback
    /// first, then index warnings sorted by capability id.
    pub(crate) fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(msg) = &self.checkpoint {
            out.push(msg.clone());
        }
        out.extend(self.index.iter().cloned());
        out
    }

    /// Returns a new snapshot with the checkpoint warning set. Does not
    /// overwrite an existing checkpoint warning (deduplicate exact repeats).
    fn with_checkpoint(mut self, msg: &str) -> Self {
        if self.checkpoint.as_deref() != Some(msg) {
            self.checkpoint = Some(msg.to_owned());
        }
        self
    }

    /// Returns a new snapshot with an index warning added if it is not an
    /// exact duplicate of an existing one. Preserves the checkpoint warning.
    #[cfg_attr(not(test), allow(dead_code))]
    fn with_index(mut self, msg: &str) -> Self {
        if !self.index.iter().any(|w| w == msg) {
            self.index.push(msg.to_owned());
            self.index.sort();
        }
        self
    }
}

/// Process-wide warning snapshot store. One `ArcSwap` holds the complete
/// immutable snapshot. Updates are atomic RCU transactions.
pub(crate) struct WarningStore {
    snapshot: ArcSwap<WarningSnapshot>,
}

impl WarningStore {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(WarningSnapshot::default()),
        }
    }

    /// Loads one immutable snapshot. Each caller gets a consistent view.
    pub(crate) fn load(&self) -> Arc<WarningSnapshot> {
        self.snapshot.load_full()
    }

    /// Atomically sets the checkpoint-fallback warning. Deduplicates exact
    /// repeats.
    pub(crate) fn set_checkpoint(&self, msg: &str) {
        self.snapshot
            .rcu(|current| Arc::new((**current).clone().with_checkpoint(msg)));
    }

    /// Atomically adds an index-ahead warning. Deduplicates exact repeats.
    /// Preserves the checkpoint warning.
    pub(crate) fn add_index(&self, msg: &str) {
        self.snapshot
            .rcu(|current| Arc::new((**current).clone().with_index(msg)));
    }

    /// Renders all warnings in deterministic order from one immutable load.
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.load().warnings()
    }
}

impl Default for WarningStore {
    fn default() -> Self {
        Self::new()
    }
}

impl bitcoin_rs_rpc::context::RollbackWarningSource for WarningStore {
    fn rollback_warnings(&self) -> Vec<String> {
        self.warnings()
    }
}

// ---------------------------------------------------------------------------
// Warning message rendering
// ---------------------------------------------------------------------------

/// Renders a checkpoint-fallback warning message.
///
/// Says the durable applied-tip witness is ahead of the restored
/// checkpoint/cold/headers-only tip. Does not say recoverable live
/// chainstate was rejected.
pub(crate) fn checkpoint_fallback_warning(witness_height: u32, restored_height: u32) -> String {
    format!(
        "Durable applied-tip witness at height {witness_height} is ahead of \
         the restored tip at height {restored_height}. \
         Chainstate was restored from a clean checkpoint, not rejected."
    )
}

/// Renders an index-watermark-ahead warning message.
pub(crate) fn index_ahead_warning(
    capability: &str,
    watermark_height: u32,
    restored_height: u32,
    gap: u32,
) -> String {
    format!(
        "Index capability '{capability}' watermark at height \
         {watermark_height} is {gap} block(s) ahead of the restored tip \
         at height {restored_height}."
    )
}

// ---------------------------------------------------------------------------
// Detection logic
// ---------------------------------------------------------------------------

/// Checks whether a witness constitutes checkpoint-fallback evidence.
///
/// Returns `Some((witness_height, restored_height))` when all conditions hold:
/// - format and bounds are valid;
/// - genesis matches;
/// - witness epoch is older than the current process epoch;
/// - witness height is strictly greater than the restored applied-tip height
///   (where no applied tip means height zero).
///
/// Does not require hash inequality. Does not warn for equal or lower heights.
pub(crate) fn detect_checkpoint_fallback(
    witness: &AppliedTipWitness,
    current_epoch: u64,
    genesis_hash: &str,
    restored_height: u32,
) -> Option<(u32, u32)> {
    if !witness.is_valid_for(WITNESS_FORMAT, genesis_hash) {
        return None;
    }
    if witness.writer_epoch >= current_epoch {
        // Current or future epoch — not eligible.
        return None;
    }
    if witness.height <= restored_height {
        // Equal or lower height — not a warning.
        return None;
    }
    Some((witness.height, restored_height))
}

// ---------------------------------------------------------------------------
// Reporter
// ---------------------------------------------------------------------------

/// Concrete private reporter created once in `NodeState::open` and shared
/// with the txindex worker. Routes checkpoint-fallback and index-ahead facts
/// through one `WarningStore` and one event marker.
///
/// For each event: emit structured WARN, atomically update the in-memory
/// warning snapshot, then durably publish the event marker.
pub(crate) struct RecoveryReporter {
    warning_store: Arc<WarningStore>,
    data_dir: PathBuf,
    genesis_hash: String,
    detecting_epoch: u64,
}

impl RecoveryReporter {
    pub(crate) fn new(
        warning_store: Arc<WarningStore>,
        data_dir: PathBuf,
        genesis_hash: String,
        detecting_epoch: u64,
    ) -> Self {
        Self {
            warning_store,
            data_dir,
            genesis_hash,
            detecting_epoch,
        }
    }

    /// Reports a checkpoint-fallback event. Marker failure aborts
    /// `NodeState::open`.
    pub(crate) fn report_checkpoint_fallback(
        &self,
        witness_height: u32,
        restored_height: u32,
        restored_hash: &str,
        source: &str,
        old_hash: &str,
        time: u64,
    ) -> Result<(), EvidenceError> {
        let msg = checkpoint_fallback_warning(witness_height, restored_height);
        tracing::warn!(%msg, witness_height, restored_height, "checkpoint fallback detected");

        // Update in-memory snapshot.
        self.warning_store.set_checkpoint(&msg);

        // Durably publish the event marker.
        let event = ChainRollbackEvent::new(
            &self.genesis_hash,
            self.detecting_epoch,
            time,
            RollbackEventKind::CheckpointFallback {
                restored_height,
                restored_hash: restored_hash.to_owned(),
                source: source.to_owned(),
                old_height: witness_height,
                old_hash: old_hash.to_owned(),
            },
        );
        write_marker(&self.data_dir, &event)
    }

    /// Reports an index-watermark-ahead event. The warning snapshot is
    /// updated before the marker write, so a marker failure (returned to the
    /// caller) still leaves the fact RPC-visible for this process.
    pub(crate) fn report_index_ahead(
        &self,
        capability: &str,
        watermark_height: u32,
        restored_height: u32,
        restored_hash: &str,
        old_hash: &str,
        gap: u32,
        time: u64,
    ) -> Result<(), EvidenceError> {
        let msg = index_ahead_warning(capability, watermark_height, restored_height, gap);
        tracing::warn!(
            %msg, capability, watermark_height, restored_height, gap,
            "index watermark ahead of restored tip"
        );

        // Update in-memory snapshot (preserves checkpoint warning).
        self.warning_store.add_index(&msg);

        // Durably publish the event marker.
        let event = ChainRollbackEvent::new(
            &self.genesis_hash,
            self.detecting_epoch,
            time,
            RollbackEventKind::IndexWatermarkAhead {
                capability: capability.to_owned(),
                restored_height,
                restored_hash: restored_hash.to_owned(),
                old_height: watermark_height,
                old_hash: old_hash.to_owned(),
                gap,
            },
        );
        write_marker(&self.data_dir, &event)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // A2.1: Witness and marker file codec tests
    // -----------------------------------------------------------------------

    #[test]
    fn witness_round_trips_and_falls_back_to_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "000000000019d6689c085ae165831e93";
        let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
        let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);

        // Write w1 as current.
        write_witness(dir.path(), &w1).expect("write w1");
        let read = read_witness(dir.path(), genesis);
        assert_eq!(read, Some(w1.clone()), "current witness loads");

        // Write w2: rotates w1 to .prev, w2 becomes current.
        write_witness(dir.path(), &w2).expect("write w2");
        let read = read_witness(dir.path(), genesis);
        assert_eq!(read, Some(w2), "new current loads");

        // Remove current — .prev (w1) should load.
        std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
        let read = read_witness(dir.path(), genesis);
        assert_eq!(
            read,
            Some(w1),
            "falls back to .prev when current is missing"
        );
    }

    #[test]
    fn foreign_genesis_or_future_epoch_witness_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";
        let foreign = "bbbb";

        // Foreign genesis — written directly, not through read_witness validation.
        let w = AppliedTipWitness::new(foreign, 1, 100, "aaa", 1000);
        write_witness(dir.path(), &w).expect("write");
        // read_witness with our genesis should return None (foreign genesis).
        assert_eq!(
            read_witness(dir.path(), genesis),
            None,
            "foreign genesis witness is ignored"
        );

        // Same genesis, future epoch — should be readable but not eligible
        // for detection.
        let dir2 = tempfile::tempdir().expect("tempdir");
        let w2 = AppliedTipWitness::new(genesis, 10, 100, "aaa", 1000);
        write_witness(dir2.path(), &w2).expect("write");
        // read_witness returns the witness (it's valid format + genesis),
        // but detect_checkpoint_fallback rejects it (future epoch).
        let read = read_witness(dir2.path(), genesis);
        assert_eq!(read, Some(w2.clone()), "same-genesis witness loads");
        assert_eq!(
            detect_checkpoint_fallback(&w2, 5, genesis, 50),
            None,
            "future-epoch witness is not eligible for detection"
        );
    }

    // -----------------------------------------------------------------------
    // A2.1: Bounded file protocol tests
    // -----------------------------------------------------------------------

    #[test]
    fn witness_stage_failure_preserves_bounded_current_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";
        let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);

        // Write a valid current.
        write_witness(dir.path(), &w1).expect("write w1");
        assert_eq!(
            read_witness(dir.path(), genesis),
            Some(w1.clone()),
            "current loads"
        );

        // Simulate a write failure: leave a stale temp file.
        std::fs::write(dir.path().join(WITNESS_TMP), b"garbage").expect("stale temp");

        // A subsequent write should clean up the stale temp and succeed.
        let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);
        write_witness(dir.path(), &w2).expect("write w2 after stale temp");
        assert_eq!(read_witness(dir.path(), genesis), Some(w2.clone()));
        // .prev should be w1.
        std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), genesis),
            Some(w1.clone()),
            ".prev preserved after successful write"
        );

        // Restore w2 as current so .prev is w1 and current is w2.
        write_witness(dir.path(), &w2).expect("restore w2");
        assert_eq!(read_witness(dir.path(), genesis), Some(w2));
        // .prev is now w1 again (w2 was current, rotated w1 to .prev).

        // Corrupt the current file (w2) so it is invalid. A new write must
        // NOT rotate the invalid current over the valid .prev (w1).
        std::fs::write(dir.path().join(WITNESS_FILE), b"corrupt-garbage").expect("corrupt current");
        let w3 = AppliedTipWitness::new(genesis, 3, 300, "ccc", 3000);
        write_witness(dir.path(), &w3).expect("write w3 over corrupt current");
        // Current is now w3.
        assert_eq!(read_witness(dir.path(), genesis), Some(w3));
        // .prev must be w1 (the valid .prev), not the corrupt garbage.
        std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), genesis),
            Some(w1),
            ".prev preserves last valid .prev, not corrupt garbage"
        );
    }

    // -----------------------------------------------------------------------
    // A2.3: Detection logic tests
    // -----------------------------------------------------------------------

    #[test]
    fn same_genesis_older_epoch_higher_witness_warns() {
        let genesis = "aaaa";
        // Witness at height 200, epoch 1 (older).
        let witness = AppliedTipWitness::new(genesis, 1, 200, "bbb", 1000);
        // Current epoch is 5, restored height is 100.
        let result = detect_checkpoint_fallback(&witness, 5, genesis, 100);
        assert_eq!(
            result,
            Some((200, 100)),
            "same-genesis, older-epoch, higher witness must warn"
        );
    }

    #[test]
    fn equal_or_lower_witness_does_not_warn() {
        let genesis = "aaaa";

        // Equal height, different hash — no warning.
        let witness_equal = AppliedTipWitness::new(genesis, 1, 100, "ccc", 1000);
        assert_eq!(
            detect_checkpoint_fallback(&witness_equal, 5, genesis, 100),
            None,
            "equal height does not warn even with different hash"
        );

        // Lower height — no warning.
        let witness_lower = AppliedTipWitness::new(genesis, 1, 50, "ddd", 1000);
        assert_eq!(
            detect_checkpoint_fallback(&witness_lower, 5, genesis, 100),
            None,
            "lower height does not warn"
        );
    }

    // -----------------------------------------------------------------------
    // A2.3: Warning snapshot tests
    // -----------------------------------------------------------------------

    #[test]
    fn checkpoint_and_index_warnings_coexist() {
        let store = WarningStore::new();

        // Set checkpoint warning.
        store.set_checkpoint("checkpoint fallback at 200");
        // Add index warning.
        store.add_index("index 'txindex' watermark at 250 is 150 block(s) ahead");

        let warnings = store.warnings();
        assert_eq!(warnings.len(), 2, "both warning classes coexist");
        assert_eq!(
            warnings[0], "checkpoint fallback at 200",
            "checkpoint warning is first"
        );
        assert!(warnings[1].contains("txindex"), "index warning is second");
    }

    #[test]
    fn repeated_index_ahead_report_is_deduplicated() {
        let store = WarningStore::new();
        let msg = "index 'txindex' watermark at 250 is 150 block(s) ahead";

        store.add_index(msg);
        store.add_index(msg); // exact duplicate

        let warnings = store.warnings();
        assert_eq!(
            warnings.len(),
            1,
            "exact duplicate index warning is deduplicated"
        );
        assert_eq!(warnings[0], msg);
    }

    #[test]
    fn index_update_preserves_checkpoint_warning() {
        let store = WarningStore::new();

        store.set_checkpoint("checkpoint fallback at 200");
        store.add_index("index 'txindex' watermark at 250 is 150 block(s) ahead");

        // Another index report should preserve the checkpoint warning.
        store.add_index("index 'scriptindex' watermark at 300 is 200 block(s) ahead");

        let warnings = store.warnings();
        assert_eq!(warnings.len(), 3, "checkpoint + two index warnings");
        assert_eq!(
            warnings[0], "checkpoint fallback at 200",
            "checkpoint warning preserved after index update"
        );
    }

    // -----------------------------------------------------------------------
    // A2.3: Marker file tests
    // -----------------------------------------------------------------------

    #[test]
    fn marker_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";

        let event = ChainRollbackEvent::new(
            genesis,
            5,
            1000,
            RollbackEventKind::CheckpointFallback {
                restored_height: 100,
                restored_hash: "aaa".to_owned(),
                source: "checkpoint".to_owned(),
                old_height: 200,
                old_hash: "bbb".to_owned(),
            },
        );
        write_marker(dir.path(), &event).expect("write marker");
        let read = read_marker(dir.path(), genesis);
        assert_eq!(read, Some(event), "marker round-trips");
    }

    #[test]
    fn marker_last_event_wins_preserves_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";

        let e1 = ChainRollbackEvent::new(
            genesis,
            5,
            1000,
            RollbackEventKind::CheckpointFallback {
                restored_height: 100,
                restored_hash: "aaa".to_owned(),
                source: "checkpoint".to_owned(),
                old_height: 200,
                old_hash: "bbb".to_owned(),
            },
        );
        let e2 = ChainRollbackEvent::new(
            genesis,
            5,
            2000,
            RollbackEventKind::IndexWatermarkAhead {
                capability: "txindex".to_owned(),
                restored_height: 100,
                restored_hash: "aaa".to_owned(),
                old_height: 250,
                old_hash: "ccc".to_owned(),
                gap: 150,
            },
        );

        write_marker(dir.path(), &e1).expect("write e1");
        write_marker(dir.path(), &e2).expect("write e2");

        // Current is e2 (last-event-wins).
        assert_eq!(read_marker(dir.path(), genesis), Some(e2));

        // .prev is e1.
        std::fs::remove_file(dir.path().join(MARKER_FILE)).expect("remove current");
        assert_eq!(
            read_marker(dir.path(), genesis),
            Some(e1),
            ".prev preserves prior event"
        );
    }

    // -----------------------------------------------------------------------
    // A2.3: Reporter tests
    // -----------------------------------------------------------------------

    #[test]
    fn reporter_report_checkpoint_fallback_writes_marker_and_warns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(WarningStore::new());
        let reporter = RecoveryReporter::new(
            Arc::clone(&store),
            dir.path().to_path_buf(),
            "aaaa".to_owned(),
            5,
        );

        reporter
            .report_checkpoint_fallback(200, 100, "aaa", "checkpoint", "bbb", 1000)
            .expect("report");

        // Warning snapshot has checkpoint warning.
        let warnings = store.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("height 200"));

        // Marker is on disk.
        let marker = read_marker(dir.path(), "aaaa");
        assert!(marker.is_some(), "marker written");
    }

    #[test]
    fn reporter_report_index_ahead_writes_marker_and_warns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(WarningStore::new());
        let reporter = RecoveryReporter::new(
            Arc::clone(&store),
            dir.path().to_path_buf(),
            "aaaa".to_owned(),
            5,
        );

        reporter
            .report_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000)
            .expect("report");

        // Warning snapshot has index warning.
        let warnings = store.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("txindex"));

        // Marker is on disk.
        let marker = read_marker(dir.path(), "aaaa");
        assert!(marker.is_some(), "marker written");
    }

    // -----------------------------------------------------------------------
    // A2.4: Oversized file is ignored
    // -----------------------------------------------------------------------

    #[test]
    fn oversized_evidence_file_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";

        // Write a valid witness.
        let w = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
        write_witness(dir.path(), &w).expect("write");

        // Overwrite current with oversized garbage.
        let big = "x".repeat(MAX_FILE_BYTES + 1);
        std::fs::write(dir.path().join(WITNESS_FILE), &big).expect("overwrite");

        // No .prev exists, so read_witness returns None.
        assert_eq!(
            read_witness(dir.path(), genesis),
            None,
            "oversized file is ignored"
        );
    }

    // -----------------------------------------------------------------------
    // A2.4: getblockchaininfo warnings from one immutable load
    // -----------------------------------------------------------------------

    #[test]
    fn getblockchaininfo_reports_atomic_rollback_warnings() {
        let store = WarningStore::new();

        store.set_checkpoint("checkpoint fallback at 200");
        store.add_index("index 'txindex' watermark at 250 is 150 block(s) ahead");
        store.add_index("index 'scriptindex' watermark at 300 is 200 block(s) ahead");

        // One immutable load produces all warnings in deterministic order.
        let snapshot = store.load();
        let warnings = snapshot.warnings();

        assert_eq!(warnings.len(), 3);
        assert_eq!(warnings[0], "checkpoint fallback at 200");
        // Index warnings sorted alphabetically.
        assert!(
            warnings[1].contains("scriptindex"),
            "sorted: scriptindex before txindex"
        );
        assert!(warnings[2].contains("txindex"));
    }

    // -----------------------------------------------------------------------
    // A2 cycle 9: checkpoint fallback with index far ahead converges and warns
    // -----------------------------------------------------------------------

    #[test]
    fn checkpoint_fallback_with_index_far_ahead_converges_and_warns() {
        // Simulates the boot scenario: checkpoint restored at height K,
        // older-epoch witness at N>K, and txindex watermark above K.
        // Both warning classes must coexist in one snapshot after reopen.
        let store = Arc::new(WarningStore::new());
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";

        // Write an older-epoch witness at height 200.
        let witness = AppliedTipWitness::new(genesis, 1, 200, "bbb", 1000);
        write_witness(dir.path(), &witness).expect("write witness");

        // Boot: read witness, detect checkpoint fallback (restored at 100).
        let read = read_witness(dir.path(), genesis).expect("witness loads");
        let fallback = detect_checkpoint_fallback(&read, 5, genesis, 100);
        assert_eq!(fallback, Some((200, 100)), "checkpoint fallback detected");

        // Report checkpoint fallback.
        let reporter = RecoveryReporter::new(
            Arc::clone(&store),
            dir.path().to_path_buf(),
            genesis.to_owned(),
            5,
        );
        reporter
            .report_checkpoint_fallback(200, 100, "aaa", "checkpoint", "bbb", 2000)
            .expect("report checkpoint fallback");

        // Index watermark ahead: txindex at 250, restored at 100, gap 150.
        reporter
            .report_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 3000)
            .expect("report index ahead");

        // Both warning classes coexist in one snapshot.
        let warnings = store.warnings();
        assert_eq!(
            warnings.len(),
            2,
            "both checkpoint and index warnings present"
        );
        assert!(
            warnings[0].contains("height 200"),
            "checkpoint fallback is first"
        );
        assert!(warnings[1].contains("txindex"), "index warning is second");

        // Marker is on disk.
        let marker = read_marker(dir.path(), genesis);
        assert!(marker.is_some(), "event marker written");
    }

    // -----------------------------------------------------------------------
    // A2 cycle 10: marker write failure fails only the reporting index
    // -----------------------------------------------------------------------

    #[test]
    fn marker_write_failure_fails_only_the_reporting_index() {
        // When the marker write fails from the index path, the warning is
        // still set in memory (operator can see it), but the error is
        // returned so the caller can fail only that index capability.
        // The checkpoint warning (if any) must survive.
        let store = Arc::new(WarningStore::new());
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";

        // Set a checkpoint warning first.
        store.set_checkpoint("checkpoint fallback at 200");

        let _reporter = RecoveryReporter::new(
            Arc::clone(&store),
            dir.path().to_path_buf(),
            genesis.to_owned(),
            5,
        );

        // Make the data dir read-only so marker write fails.
        // We simulate this by pointing the reporter at a non-existent
        // parent directory.
        let bad_dir = dir.path().join("nonexistent");
        let bad_reporter =
            RecoveryReporter::new(Arc::clone(&store), bad_dir, genesis.to_owned(), 5);

        // Index report fails (marker write to nonexistent dir).
        let result = bad_reporter.report_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000);
        assert!(result.is_err(), "marker write failure must return an error");

        // The warning was still set in memory before the marker write.
        let warnings = store.warnings();
        assert_eq!(
            warnings.len(),
            2,
            "checkpoint warning survives index marker failure; index warning was set"
        );
        assert_eq!(
            warnings[0], "checkpoint fallback at 200",
            "checkpoint warning preserved"
        );
        assert!(
            warnings[1].contains("txindex"),
            "index warning was set before marker failure"
        );

        // The node (chain RPC) stays live: the store is still usable.
        let snapshot = store.load();
        assert_eq!(
            snapshot.warnings().len(),
            2,
            "warning store is still readable after marker failure"
        );
    }

    // -----------------------------------------------------------------------
    // A2 repair (RecA12c4): semantic rotation — a parseable but foreign-genesis
    // or wrong-format current cannot displace a valid .prev
    // -----------------------------------------------------------------------

    #[test]
    fn foreign_genesis_current_cannot_displace_valid_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";
        let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
        let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);

        // Establish a valid current (w2) and a valid .prev (w1).
        write_witness(dir.path(), &w1).expect("write w1");
        write_witness(dir.path(), &w2).expect("write w2 -> w1 rotates to .prev");
        assert_eq!(read_witness(dir.path(), genesis), Some(w2.clone()));

        // Plant a parseable but FOREIGN-GENESIS current directly. This is the
        // bug class: parseable JSON that the old parse-only validator accepted.
        let foreign = AppliedTipWitness::new("bbbb", 3, 300, "ccc", 3000);
        let foreign_bytes = format!("{}\n", foreign.to_json());
        std::fs::write(dir.path().join(WITNESS_FILE), foreign_bytes.as_bytes())
            .expect("plant foreign current");
        assert!(
            AppliedTipWitness::from_json(&std::fs::read(dir.path().join(WITNESS_FILE)).unwrap())
                .is_some(),
            "foreign current is parseable JSON"
        );

        // A subsequent valid write must classify the foreign current INVALID:
        // remove it, keep the valid .prev (w1), then publish the new current.
        let w3 = AppliedTipWitness::new(genesis, 4, 400, "ddd", 4000);
        write_witness(dir.path(), &w3).expect("write w3 over foreign current");
        assert_eq!(read_witness(dir.path(), genesis), Some(w3.clone()));

        // Removal path: delete the current; the valid .prev (w1) must survive
        // and read_bounded must never surface the foreign record.
        std::fs::remove_file(dir.path().join(WITNESS_FILE)).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), genesis),
            Some(w1.clone()),
            "valid .prev survives; foreign current never displaced it"
        );
        let raw = read_bounded(dir.path(), WITNESS_FILE, WITNESS_PREV)
            .expect("bounded read returns .prev bytes");
        assert!(
            AppliedTipWitness::from_json(&raw).is_some_and(|w| w.genesis_hash == genesis),
            "read_bounded returns the valid .prev, never the foreign record"
        );

        // Same contract for a WRONG-FORMAT current (parseable, our genesis, bad format).
        let dir2 = tempfile::tempdir().expect("tempdir");
        write_witness(dir2.path(), &w1).expect("write w1");
        write_witness(dir2.path(), &w2).expect("write w2 -> w1 to .prev");
        let mut wrong_format = w2;
        wrong_format.format = "999".to_owned();
        std::fs::write(
            dir2.path().join(WITNESS_FILE),
            format!("{}\n", wrong_format.to_json()).as_bytes(),
        )
        .expect("plant wrong-format current");
        write_witness(dir2.path(), &w3).expect("write w3 over wrong-format current");
        std::fs::remove_file(dir2.path().join(WITNESS_FILE)).expect("remove current");
        assert_eq!(
            read_witness(dir2.path(), genesis),
            Some(w1),
            "valid .prev survives a wrong-format current"
        );
    }

    #[test]
    fn foreign_genesis_marker_current_cannot_displace_valid_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "aaaa";
        let mk = |epoch: u64, time: u64| {
            ChainRollbackEvent::new(
                genesis,
                epoch,
                time,
                RollbackEventKind::CheckpointFallback {
                    restored_height: 100,
                    restored_hash: "aaa".to_owned(),
                    source: "checkpoint".to_owned(),
                    old_height: 200,
                    old_hash: "bbb".to_owned(),
                },
            )
        };
        let e1 = mk(1, 1000);
        let e2 = mk(2, 2000);

        write_marker(dir.path(), &e1).expect("write e1");
        write_marker(dir.path(), &e2).expect("write e2 -> e1 to .prev");

        // Plant a parseable foreign-genesis marker current.
        let foreign = ChainRollbackEvent::new(
            "bbbb",
            3,
            3000,
            RollbackEventKind::CheckpointFallback {
                restored_height: 100,
                restored_hash: "aaa".to_owned(),
                source: "checkpoint".to_owned(),
                old_height: 200,
                old_hash: "bbb".to_owned(),
            },
        );
        std::fs::write(
            dir.path().join(MARKER_FILE),
            format!("{}\n", foreign.to_json()).as_bytes(),
        )
        .expect("plant foreign marker current");

        let e3 = mk(4, 4000);
        write_marker(dir.path(), &e3).expect("write e3 over foreign current");
        assert_eq!(read_marker(dir.path(), genesis), Some(e3));

        std::fs::remove_file(dir.path().join(MARKER_FILE)).expect("remove current");
        assert_eq!(
            read_marker(dir.path(), genesis),
            Some(e1),
            "valid marker .prev survives; foreign current never displaced it"
        );
    }
}
