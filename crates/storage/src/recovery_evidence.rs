//! Durable rollback evidence.
//!
//! Bounded, genesis-scoped JSON sidecars with a `.prev` rotation, plus the
//! process-visible warning snapshot (RCV-12).
//!
//! `applied-tip-witness.json` records the applied tip at the last durable
//! checkpoint publication; `chain-rollback-event.json` records the last
//! detected rollback event. Publishing stages `.tmp` (`create_new`, fsync),
//! rotates a *valid* current to `.prev`, renames, and fsyncs the directory.
//! Reads try current then `.prev`; a missing or invalid current falls
//! through. Never selects by greatest height.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Maximum file size for any evidence file (4 KiB).
pub const MAX_FILE_BYTES: usize = 4096;

const FORMAT: &str = "1";
const WITNESS_FILE: &str = "applied-tip-witness.json";
const MARKER_FILE: &str = "chain-rollback-event.json";

/// Error from the bounded file protocol.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Filesystem I/O failure.
    #[error("evidence I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization failure.
    #[error("evidence serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Durable record of the applied tip at the last clean checkpoint publication.
///
/// Written by the node checkpoint publisher only after
/// `CheckpointWrite::Published` and root fsync.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppliedTipWitness {
    /// Format identifier.
    pub format: String,
    /// Genesis block hash in hex.
    pub genesis_hash: String,
    /// Process epoch that wrote this witness.
    pub writer_epoch: u64,
    /// Applied-tip height.
    pub height: u32,
    /// Block hash in hex.
    pub block_hash: String,
    /// Unix time in seconds.
    pub time: u64,
}

impl AppliedTipWitness {
    /// Creates a witness for `height`/`block_hash` at `time`.
    pub fn new(
        genesis_hash: impl Into<String>,
        writer_epoch: u64,
        height: u32,
        block_hash: impl Into<String>,
        time: u64,
    ) -> Self {
        Self {
            format: FORMAT.to_owned(),
            genesis_hash: genesis_hash.into(),
            writer_epoch,
            height,
            block_hash: block_hash.into(),
            time,
        }
    }

    /// Decodes bounded bytes; rejects wrong format or foreign genesis.
    fn decode(data: &[u8], genesis_hash: &str) -> Option<Self> {
        if data.len() > MAX_FILE_BYTES {
            return None;
        }
        let w: Self = serde_json::from_slice(data.strip_suffix(b"\n").unwrap_or(data)).ok()?;
        (w.format == FORMAT && w.genesis_hash == genesis_hash).then_some(w)
    }
}

/// Exactly one rollback event kind.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RollbackEventKind {
    /// The durable applied-tip witness is ahead of the restored tip.
    CheckpointFallback {
        /// Restored applied-tip height.
        restored_height: u32,
        /// Restored applied-tip hash in hex.
        restored_hash: String,
        /// Resume source (`cold`, `checkpoint`, `journal`).
        source: String,
        /// Witness height (the higher, pre-restore tip).
        old_height: u32,
        /// Witness block hash in hex.
        old_hash: String,
    },
    /// An index capability watermark is ahead of the restored tip.
    IndexWatermarkAhead {
        /// Index capability id.
        capability: String,
        /// Restored applied-tip height.
        restored_height: u32,
        /// Restored applied-tip hash in hex.
        restored_hash: String,
        /// Watermark height (the higher, pre-restore tip).
        old_height: u32,
        /// Watermark block hash in hex.
        old_hash: String,
        /// `old_height - restored_height`.
        gap: u32,
    },
}

/// Durable record of the last detected rollback event.
///
/// Last-event-wins. The prior valid event is preserved as `.prev`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ChainRollbackEvent {
    /// Format identifier.
    pub format: String,
    /// Genesis block hash in hex.
    pub genesis_hash: String,
    /// Process epoch that detected this event.
    pub detecting_epoch: u64,
    /// Unix time in seconds.
    pub time: u64,
    /// The rollback event.
    pub event: RollbackEventKind,
}

impl ChainRollbackEvent {
    /// Creates an event detected by `detecting_epoch` at `time`.
    pub fn new(
        genesis_hash: impl Into<String>,
        detecting_epoch: u64,
        time: u64,
        event: RollbackEventKind,
    ) -> Self {
        Self {
            format: FORMAT.to_owned(),
            genesis_hash: genesis_hash.into(),
            detecting_epoch,
            time,
            event,
        }
    }

    /// Decodes bounded bytes; rejects wrong format or foreign genesis.
    fn decode(data: &[u8], genesis_hash: &str) -> Option<Self> {
        if data.len() > MAX_FILE_BYTES {
            return None;
        }
        let e: Self = serde_json::from_slice(data.strip_suffix(b"\n").unwrap_or(data)).ok()?;
        (e.format == FORMAT && e.genesis_hash == genesis_hash).then_some(e)
    }
}

/// Reads `name`, then `name.prev`; each candidate must decode.
fn read_sidecar<T>(dir: &Path, name: &str, decode: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
    [name.to_owned(), format!("{name}.prev")]
        .iter()
        .find_map(|n| decode(&std::fs::read(dir.join(n)).ok()?))
}

/// Atomic publish: stage `.tmp` (`create_new`, fsync), rotate a *valid*
/// current to `.prev` (an invalid current is removed, never displacing a
/// valid `.prev`), rename, fsync dir.
fn write_sidecar(
    dir: &Path,
    name: &str,
    payload: &str,
    valid: impl Fn(&[u8]) -> bool,
) -> Result<(), EvidenceError> {
    use std::io::Write;
    let current = dir.join(name);
    let prev = dir.join(format!("{name}.prev"));
    let tmp = dir.join(format!("{name}.tmp"));
    // A stale tmp is left by a crashed earlier write; create_new below fails
    // if it still exists.
    let _ = std::fs::remove_file(&tmp);
    let result = (|| -> Result<(), EvidenceError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(payload.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        if let Ok(data) = std::fs::read(&current) {
            if valid(&data) {
                let _ = std::fs::remove_file(&prev);
                // Only a valid current may displace `.prev`.
                std::fs::rename(&current, &prev)?;
            } else {
                // Invalid or oversized current: remove it, keep `.prev`.
                let _ = std::fs::remove_file(&current);
            }
        }
        std::fs::rename(&tmp, &current)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // A returned failure must not leave the staged tmp behind (RCV-03).
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Reads the applied-tip witness (current, then `.prev`).
pub fn read_witness(dir: &Path, genesis_hash: &str) -> Option<AppliedTipWitness> {
    read_sidecar(dir, WITNESS_FILE, |data| {
        AppliedTipWitness::decode(data, genesis_hash)
    })
}

/// Publishes the applied-tip witness atomically.
pub fn write_witness(dir: &Path, witness: &AppliedTipWitness) -> Result<(), EvidenceError> {
    write_sidecar(
        dir,
        WITNESS_FILE,
        &serde_json::to_string(witness)?,
        |data| AppliedTipWitness::decode(data, &witness.genesis_hash).is_some(),
    )
}

/// Reads the most recent valid rollback marker (current, then `.prev`).
pub fn read_marker(dir: &Path, genesis_hash: &str) -> Option<ChainRollbackEvent> {
    read_sidecar(dir, MARKER_FILE, |data| {
        ChainRollbackEvent::decode(data, genesis_hash)
    })
}

/// Publishes a rollback marker atomically. Last-event-wins.
pub fn write_marker(dir: &Path, event: &ChainRollbackEvent) -> Result<(), EvidenceError> {
    write_sidecar(dir, MARKER_FILE, &serde_json::to_string(event)?, |data| {
        ChainRollbackEvent::decode(data, &event.genesis_hash).is_some()
    })
}

/// True when the witness was written by an older epoch and sits strictly
/// above the restored applied-tip height (no tip means zero).
pub fn checkpoint_fallback(
    witness: &AppliedTipWitness,
    current_epoch: u64,
    restored_height: u32,
) -> bool {
    witness.writer_epoch < current_epoch && witness.height > restored_height
}

/// Reads the applied-tip witness through an opened data-dir anchor (current,
/// then `.prev`); `(0, genesis)` when absent/invalid.
pub fn read_witness_from_anchor(
    anchor: &crate::footprint::DataDirAnchor,
    genesis: &str,
) -> Result<(u32, String), crate::footprint::FootprintError> {
    for name in [WITNESS_FILE, &format!("{WITNESS_FILE}.prev")] {
        if let Some(bytes) = anchor.read_child_file(name, MAX_FILE_BYTES)?
            && let Some(witness) = AppliedTipWitness::decode(&bytes, genesis)
        {
            return Ok((witness.height, witness.block_hash));
        }
    }
    Ok((0, genesis.to_owned()))
}

#[derive(Clone, Default)]
struct Warnings {
    checkpoint: Option<String>,
    index: Vec<String>,
}

/// Publishes recovery facts: WARN log, process-visible warning snapshot, then
/// durable marker (RCV-12 ordering).
pub struct RecoveryEvidencePublisher {
    warnings: ArcSwap<Warnings>,
    data_dir: PathBuf,
    genesis_hash: String,
    detecting_epoch: u64,
}

impl RecoveryEvidencePublisher {
    /// Creates a publisher with an empty warning snapshot.
    pub fn new(data_dir: PathBuf, genesis_hash: String, detecting_epoch: u64) -> Self {
        Self {
            warnings: ArcSwap::from_pointee(Warnings::default()),
            data_dir,
            genesis_hash,
            detecting_epoch,
        }
    }

    /// Checkpoint warning first, then index warnings sorted; one immutable load.
    pub fn warnings(&self) -> Vec<String> {
        let w = self.warnings.load();
        w.checkpoint.iter().chain(&w.index).cloned().collect()
    }

    /// Publishes a checkpoint-fallback event. Marker failure aborts
    /// `NodeState::open`.
    pub fn publish_checkpoint_fallback(
        &self,
        witness_height: u32,
        restored_height: u32,
        restored_hash: &str,
        source: &str,
        old_hash: &str,
        time: u64,
    ) -> Result<(), EvidenceError> {
        let msg = format!(
            "Durable applied-tip witness at height {witness_height} is ahead of \
             the restored tip at height {restored_height}. \
             Chainstate was restored from a clean checkpoint, not rejected."
        );
        tracing::warn!(%msg, witness_height, restored_height, "checkpoint fallback detected");
        self.update(move |w| w.checkpoint = Some(msg.clone()));
        self.marker(
            time,
            RollbackEventKind::CheckpointFallback {
                restored_height,
                restored_hash: restored_hash.to_owned(),
                source: source.to_owned(),
                old_height: witness_height,
                old_hash: old_hash.to_owned(),
            },
        )
    }

    /// Publishes an index-watermark-ahead event. The warning snapshot is
    /// updated before the marker write, so a marker failure (returned to the
    /// caller) still leaves the fact RPC-visible for this process.
    pub fn publish_index_ahead(
        &self,
        capability: &str,
        watermark_height: u32,
        restored_height: u32,
        restored_hash: &str,
        old_hash: &str,
        gap: u32,
        time: u64,
    ) -> Result<(), EvidenceError> {
        let msg = format!(
            "Index capability '{capability}' watermark at height \
             {watermark_height} is {gap} block(s) ahead of the restored tip \
             at height {restored_height}."
        );
        tracing::warn!(
            %msg, capability, watermark_height, restored_height, gap,
            "index watermark ahead of restored tip"
        );
        self.update(move |w| {
            if !w.index.contains(&msg) {
                w.index.push(msg.clone());
                w.index.sort();
            }
        });
        self.marker(
            time,
            RollbackEventKind::IndexWatermarkAhead {
                capability: capability.to_owned(),
                restored_height,
                restored_hash: restored_hash.to_owned(),
                old_height: watermark_height,
                old_hash: old_hash.to_owned(),
                gap,
            },
        )
    }

    fn update(&self, f: impl Fn(&mut Warnings)) {
        self.warnings.rcu(|w| {
            let mut next = (**w).clone();
            f(&mut next);
            Arc::new(next)
        });
    }

    fn marker(&self, time: u64, event: RollbackEventKind) -> Result<(), EvidenceError> {
        write_marker(
            &self.data_dir,
            &ChainRollbackEvent::new(&self.genesis_hash, self.detecting_epoch, time, event),
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
