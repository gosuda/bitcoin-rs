use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

pub const MAX_FILE_BYTES: usize = 4096;

const FORMAT: &str = "1";
const WITNESS_FILE: &str = "applied-tip-witness.json";
const MARKER_FILE: &str = "chain-rollback-event.json";

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("evidence serialization error: {0}")]
    Json(#[from] sonic_rs::Error),
    #[error("evidence payload is {found} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// Staged byte count including the trailing newline.
        found: usize,
        limit: usize,
    },
    #[error("evidence payload fails its own read validation")]
    InvalidRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppliedTipWitness {
    pub format: String,
    pub genesis_hash: String,
    pub writer_epoch: u64,
    pub height: u32,
    pub block_hash: String,
    pub time: u64,
}

impl AppliedTipWitness {
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

    fn decode(data: &[u8], genesis_hash: &str) -> Option<Self> {
        if data.len() > MAX_FILE_BYTES {
            return None;
        }
        let w: Self = sonic_rs::from_slice(data.strip_suffix(b"\n").unwrap_or(data)).ok()?;
        (w.format == FORMAT && w.genesis_hash == genesis_hash).then_some(w)
    }
}

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainRollbackEvent {
    pub format: String,
    pub genesis_hash: String,
    pub detecting_epoch: u64,
    pub time: u64,
    pub event: RollbackEventKind,
}

impl ChainRollbackEvent {
    pub(crate) fn new(
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

    fn decode(data: &[u8], genesis_hash: &str) -> Option<Self> {
        if data.len() > MAX_FILE_BYTES {
            return None;
        }
        let e: Self = sonic_rs::from_slice(data.strip_suffix(b"\n").unwrap_or(data)).ok()?;
        (e.format == FORMAT && e.genesis_hash == genesis_hash).then_some(e)
    }
}

fn read_sidecar<T>(dir: &Path, name: &str, decode: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
    [name.to_owned(), format!("{name}.prev")]
        .iter()
        .find_map(|n| decode(&std::fs::read(dir.join(n)).ok()?))
}

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
    let result = (|| -> Result<(), EvidenceError> {
        let staged = payload.len() + 1;
        if staged > MAX_FILE_BYTES {
            return Err(EvidenceError::TooLarge {
                found: staged,
                limit: MAX_FILE_BYTES,
            });
        }
        if !valid(payload.as_bytes()) {
            return Err(EvidenceError::InvalidRecord);
        }
        let _ = std::fs::remove_file(&tmp);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(payload.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        match std::fs::read(&current) {
            Ok(data) if valid(&data) => {
                let _ = std::fs::remove_file(&prev);
                std::fs::rename(&current, &prev)?;
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&current);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::rename(&tmp, &current)?;
        let capability = cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority())?;
        crate::checkpoint::fs::sync_dir(&capability)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }

    result
}

pub fn read_witness(dir: &Path, genesis_hash: &str) -> Option<AppliedTipWitness> {
    read_sidecar(dir, WITNESS_FILE, |data| {
        AppliedTipWitness::decode(data, genesis_hash)
    })
}

pub fn write_witness(dir: &Path, witness: &AppliedTipWitness) -> Result<(), EvidenceError> {
    write_sidecar(dir, WITNESS_FILE, &sonic_rs::to_string(witness)?, |data| {
        AppliedTipWitness::decode(data, &witness.genesis_hash).is_some()
    })
}

pub(crate) fn write_marker(dir: &Path, event: &ChainRollbackEvent) -> Result<(), EvidenceError> {
    write_sidecar(dir, MARKER_FILE, &sonic_rs::to_string(event)?, |data| {
        ChainRollbackEvent::decode(data, &event.genesis_hash).is_some()
    })
}

pub fn checkpoint_fallback(
    witness: &AppliedTipWitness,
    current_epoch: u64,
    restored_height: u32,
) -> bool {
    witness.writer_epoch < current_epoch && witness.height > restored_height
}

#[derive(Clone, Default)]
struct Warnings {
    checkpoint: Option<String>,
    index: Vec<String>,
}

pub struct RecoveryEvidencePublisher {
    warnings: ArcSwap<Warnings>,
    data_dir: PathBuf,
    genesis_hash: String,
    detecting_epoch: u64,
}

impl RecoveryEvidencePublisher {
    pub fn new(data_dir: PathBuf, genesis_hash: String, detecting_epoch: u64) -> Self {
        Self {
            warnings: ArcSwap::from_pointee(Warnings::default()),
            data_dir,
            genesis_hash,
            detecting_epoch,
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let w = self.warnings.load();
        w.checkpoint.iter().chain(&w.index).cloned().collect()
    }

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
#[expect(clippy::expect_used, clippy::unwrap_used)]
mod tests;
