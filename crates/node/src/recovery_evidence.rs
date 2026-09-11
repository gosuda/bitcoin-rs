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

mod io;
mod reporter;

use arc_swap::ArcSwap;
use io::read_bounded;
use io::write_bounded;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum file size for any evidence file (4 KiB).
pub(crate) const MAX_FILE_BYTES: usize = 4096;

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

/// Decodes an applied-tip witness from already-read sidecar bytes.
pub(crate) fn decode_applied_tip_witness(
    data: &[u8],
    genesis_hash: &str,
) -> Option<AppliedTipWitness> {
    let witness = AppliedTipWitness::from_json(data)?;
    witness
        .is_valid_for(WITNESS_FORMAT, genesis_hash)
        .then_some(witness)
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
