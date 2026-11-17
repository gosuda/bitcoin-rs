use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};

pub const MAX_FILE_BYTES: usize = 4096;

const FORMAT: &str = "1";
const WITNESS_FILE: &str = "applied-tip-witness.json";
const MARKER_FILE: &str = "chain-rollback-event.json";
pub const FULL_REVALIDATION_MARKER: &str = "full-revalidation";

pub fn mark_full_revalidation_at(data_dir: &Path) -> Result<(), EvidenceError> {
    let dir = crate::checkpoint::fs::open_data_dir(data_dir)?;
    mark_full_revalidation_with_sync(&dir, crate::checkpoint::fs::sync_dir)
}

fn mark_full_revalidation_with_sync(
    dir: &Dir,
    sync_dir: impl FnOnce(&Dir) -> std::io::Result<()>,
) -> Result<(), EvidenceError> {
    use std::io::Write as _;

    match crate::checkpoint::fs::create_file(dir, FULL_REVALIDATION_MARKER) {
        Ok(mut file) => {
            file.write_all(b"required\n")?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            crate::checkpoint::fs::open_file(dir, FULL_REVALIDATION_MARKER)?;
        }
        Err(error) => return Err(error.into()),
    }
    sync_dir(dir)?;
    Ok(())
}

pub fn clear_full_revalidation_marker_at(data_dir: &Path) -> Result<(), EvidenceError> {
    let dir = match crate::checkpoint::fs::open_data_dir(data_dir) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    clear_full_revalidation_marker_with_sync(&dir, crate::checkpoint::fs::sync_dir)
}

fn clear_full_revalidation_marker_with_sync(
    dir: &Dir,
    sync_dir: impl FnOnce(&Dir) -> std::io::Result<()>,
) -> Result<(), EvidenceError> {
    match dir.remove_file(FULL_REVALIDATION_MARKER) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    sync_dir(dir)?;
    Ok(())
}

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
mod tests {
    use super::*;

    const G: &str = "aaaa";

    fn witness_file(dir: &Path) -> PathBuf {
        dir.join(WITNESS_FILE)
    }
    fn witness_prev(dir: &Path) -> PathBuf {
        dir.join(format!("{WITNESS_FILE}.prev"))
    }
    fn witness_tmp(dir: &Path) -> PathBuf {
        dir.join(format!("{WITNESS_FILE}.tmp"))
    }
    fn marker_file(dir: &Path) -> PathBuf {
        dir.join(MARKER_FILE)
    }

    fn read_marker(dir: &Path, genesis_hash: &str) -> Option<ChainRollbackEvent> {
        read_sidecar(dir, MARKER_FILE, |data| {
            ChainRollbackEvent::decode(data, genesis_hash)
        })
    }

    fn fallback_event(genesis: &str, epoch: u64, time: u64) -> ChainRollbackEvent {
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
    }

    #[test]
    fn witness_round_trips_and_falls_back_to_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = "000000000019d6689c085ae165831e93";
        let w1 = AppliedTipWitness::new(genesis, 1, 100, "aaa", 1000);
        let w2 = AppliedTipWitness::new(genesis, 2, 200, "bbb", 2000);

        write_witness(dir.path(), &w1).expect("write w1");
        assert_eq!(read_witness(dir.path(), genesis), Some(w1.clone()));

        write_witness(dir.path(), &w2).expect("write w2");
        assert_eq!(read_witness(dir.path(), genesis), Some(w2));

        std::fs::remove_file(witness_file(dir.path())).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), genesis),
            Some(w1),
            "falls back to .prev when current is missing"
        );
    }

    #[test]
    fn malformed_current_falls_back_to_valid_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
        let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
        write_witness(dir.path(), &w1).expect("write w1");
        write_witness(dir.path(), &w2).expect("write w2 -> w1 to .prev");
        std::fs::write(witness_file(dir.path()), b"corrupt-garbage").expect("corrupt current");
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1),
            "malformed current falls back to valid .prev"
        );

        let e1 = fallback_event(G, 1, 1000);
        let e2 = fallback_event(G, 2, 2000);
        write_marker(dir.path(), &e1).expect("write e1");
        write_marker(dir.path(), &e2).expect("write e2 -> e1 to .prev");
        std::fs::write(marker_file(dir.path()), b"corrupt-garbage").expect("corrupt current");
        assert_eq!(
            read_marker(dir.path(), G),
            Some(e1),
            "malformed marker current falls back to valid .prev"
        );
    }

    #[test]
    fn foreign_genesis_or_future_epoch_witness_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");

        let w = AppliedTipWitness::new("bbbb", 1, 100, "aaa", 1000);
        write_witness(dir.path(), &w).expect("write");
        assert_eq!(
            read_witness(dir.path(), G),
            None,
            "foreign genesis witness is ignored"
        );

        let dir2 = tempfile::tempdir().expect("tempdir");
        let w2 = AppliedTipWitness::new(G, 10, 100, "aaa", 1000);
        write_witness(dir2.path(), &w2).expect("write");
        assert_eq!(read_witness(dir2.path(), G), Some(w2.clone()));
        assert!(
            !checkpoint_fallback(&w2, 5, 50),
            "future-epoch witness is not eligible for detection"
        );
    }

    #[test]
    fn witness_rotation_failure_removes_staged_temp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
        write_witness(dir.path(), &w1).expect("write current");

        std::fs::create_dir(witness_prev(dir.path())).expect("block prev rotation");
        let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
        assert!(
            write_witness(dir.path(), &w2).is_err(),
            "rotation failure must propagate"
        );
        assert!(
            !witness_tmp(dir.path()).exists(),
            "returned failure must remove staged temp"
        );
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1),
            "failed rotation keeps the current witness readable"
        );
    }

    #[test]
    fn witness_stage_failure_preserves_bounded_current_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);

        write_witness(dir.path(), &w1).expect("write w1");
        std::fs::write(witness_tmp(dir.path()), b"garbage").expect("stale temp");

        let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
        write_witness(dir.path(), &w2).expect("write w2 after stale temp");
        std::fs::remove_file(witness_file(dir.path())).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1.clone()),
            ".prev preserved after successful write"
        );

        write_witness(dir.path(), &w2).expect("restore w2");

        std::fs::write(witness_file(dir.path()), b"corrupt-garbage").expect("corrupt current");
        let w3 = AppliedTipWitness::new(G, 3, 300, "ccc", 3000);
        write_witness(dir.path(), &w3).expect("write w3 over corrupt current");
        assert_eq!(read_witness(dir.path(), G), Some(w3));
        std::fs::remove_file(witness_file(dir.path())).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1),
            ".prev preserves last valid .prev, not corrupt garbage"
        );
    }

    #[test]
    fn same_genesis_older_epoch_higher_witness_warns() {
        let witness = AppliedTipWitness::new(G, 1, 200, "bbb", 1000);
        assert!(
            checkpoint_fallback(&witness, 5, 100),
            "same-genesis, older-epoch, higher witness must warn"
        );
    }

    #[test]
    fn equal_or_lower_witness_does_not_warn() {
        let witness_equal = AppliedTipWitness::new(G, 1, 100, "ccc", 1000);
        assert!(!checkpoint_fallback(&witness_equal, 5, 100));

        let witness_lower = AppliedTipWitness::new(G, 1, 50, "ddd", 1000);
        assert!(!checkpoint_fallback(&witness_lower, 5, 100));
    }

    #[test]
    fn index_update_preserves_checkpoint_warning() {
        let publisher = RecoveryEvidencePublisher::new(PathBuf::new(), G.to_owned(), 5);
        publisher.update(|w| w.checkpoint = Some("checkpoint fallback at 200".to_owned()));
        publisher.update(|w| {
            w.index
                .push("index 'txindex' watermark at 250 is 150 block(s) ahead".to_owned());
            w.index
                .push("index 'scriptindex' watermark at 300 is 200 block(s) ahead".to_owned());
        });

        let warnings = publisher.warnings();
        assert_eq!(warnings.len(), 3, "checkpoint + two index warnings");
        assert_eq!(warnings[0], "checkpoint fallback at 200");
    }

    #[test]
    fn repeated_index_ahead_report_is_deduplicated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let publisher = RecoveryEvidencePublisher::new(dir.path().to_path_buf(), G.to_owned(), 5);

        publisher
            .publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000)
            .expect("publish");
        publisher
            .publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000)
            .expect("publish");

        let warnings = publisher.warnings();
        assert_eq!(
            warnings.len(),
            1,
            "exact duplicate index warning is deduplicated"
        );
    }

    #[test]
    fn getblockchaininfo_reports_atomic_rollback_warnings() {
        let publisher = RecoveryEvidencePublisher::new(PathBuf::new(), G.to_owned(), 5);
        publisher.update(|w| {
            w.checkpoint = Some("checkpoint fallback at 200".to_owned());
            w.index
                .push("index 'txindex' watermark at 250 is 150 block(s) ahead".to_owned());
            w.index
                .push("index 'scriptindex' watermark at 300 is 200 block(s) ahead".to_owned());
            w.index.sort();
        });

        let warnings = publisher.warnings();
        assert_eq!(warnings.len(), 3);
        assert_eq!(warnings[0], "checkpoint fallback at 200");
        assert!(warnings[1].contains("scriptindex"), "sorted");
        assert!(warnings[2].contains("txindex"));
    }

    #[test]
    fn marker_last_event_wins_preserves_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let e1 = fallback_event(G, 5, 1000);
        let e2 = ChainRollbackEvent::new(
            G,
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
        assert_eq!(read_marker(dir.path(), G), Some(e2));

        std::fs::remove_file(marker_file(dir.path())).expect("remove current");
        assert_eq!(
            read_marker(dir.path(), G),
            Some(e1),
            ".prev preserves prior event"
        );
    }

    // RCV-12
    #[test]
    fn checkpoint_fallback_with_index_far_ahead_converges_and_warns() {
        let dir = tempfile::tempdir().expect("tempdir");

        let witness = AppliedTipWitness::new(G, 1, 200, "bbb", 1000);
        write_witness(dir.path(), &witness).expect("write witness");
        let read_back = read_witness(dir.path(), G).expect("witness loads");
        assert!(checkpoint_fallback(&read_back, 5, 100));

        let publisher = RecoveryEvidencePublisher::new(dir.path().to_path_buf(), G.to_owned(), 5);
        publisher
            .publish_checkpoint_fallback(200, 100, "aaa", "checkpoint", "bbb", 2000)
            .expect("publish checkpoint fallback");
        publisher
            .publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 3000)
            .expect("publish index ahead");

        let warnings = publisher.warnings();
        assert_eq!(warnings.len(), 2, "both warning classes present");
        assert!(warnings[0].contains("height 200"));
        assert!(warnings[1].contains("txindex"));
        assert!(read_marker(dir.path(), G).is_some());
    }

    // RCV-12
    #[test]
    fn index_marker_failure_preserves_checkpoint_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let publisher =
            RecoveryEvidencePublisher::new(dir.path().join("nonexistent"), G.to_owned(), 5);
        publisher.update(|w| w.checkpoint = Some("checkpoint fallback at height 200".to_owned()));

        let result = publisher.publish_index_ahead("txindex", 250, 100, "aaa", "ccc", 150, 1000);
        assert!(result.is_err(), "marker write failure must return an error");

        let warnings = publisher.warnings();
        assert_eq!(
            warnings.len(),
            2,
            "checkpoint warning survives index marker failure"
        );
        assert!(warnings[0].contains("height 200"));
        assert!(warnings[1].contains("txindex"));
    }

    // RCV-12
    #[test]
    fn oversized_evidence_file_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_witness(dir.path(), &AppliedTipWitness::new(G, 1, 100, "aaa", 1000)).expect("write");

        std::fs::write(witness_file(dir.path()), "x".repeat(MAX_FILE_BYTES + 1))
            .expect("overwrite");
        assert_eq!(
            read_witness(dir.path(), G),
            None,
            "oversized file is ignored"
        );
    }

    #[test]
    fn oversized_witness_write_is_rejected_without_rotating() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
        write_witness(dir.path(), &w1).expect("write w1");

        let big = AppliedTipWitness::new(G, 2, 200, "a".repeat(MAX_FILE_BYTES), 2000);
        let error = write_witness(dir.path(), &big).unwrap_err();
        assert!(
            matches!(error, EvidenceError::TooLarge { .. }),
            "oversized write is rejected, got {error:?}"
        );
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1),
            "rejected write leaves current untouched"
        );
        assert!(
            !witness_tmp(dir.path()).exists(),
            "rejected write stages no tmp tail"
        );

        let event = fallback_event(G, 3, 3000);
        write_marker(dir.path(), &event).expect("write marker");
        let big_event = ChainRollbackEvent::new(
            G,
            4,
            4000,
            RollbackEventKind::CheckpointFallback {
                restored_height: 100,
                restored_hash: "a".repeat(MAX_FILE_BYTES),
                source: "checkpoint".to_owned(),
                old_height: 200,
                old_hash: "bbb".to_owned(),
            },
        );
        assert!(
            matches!(
                write_marker(dir.path(), &big_event).unwrap_err(),
                EvidenceError::TooLarge { .. }
            ),
            "oversized marker is rejected"
        );
        assert_eq!(
            read_marker(dir.path(), G),
            Some(event),
            "rejected marker leaves current untouched"
        );
    }

    #[test]
    fn foreign_format_write_is_rejected_without_rotating() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
        write_witness(dir.path(), &w1).expect("write w1");

        let mut bad = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
        bad.format = "9".to_owned();
        let error = write_witness(dir.path(), &bad).unwrap_err();
        assert!(
            matches!(error, EvidenceError::InvalidRecord),
            "unwritable record is rejected, got {error:?}"
        );
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1),
            "rejected write leaves current untouched"
        );
        assert!(
            !witness_tmp(dir.path()).exists(),
            "rejected write stages no tmp tail"
        );
    }

    #[test]
    fn foreign_genesis_current_cannot_displace_valid_prev() {
        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
        let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);

        write_witness(dir.path(), &w1).expect("write w1");
        write_witness(dir.path(), &w2).expect("write w2 -> w1 to .prev");
        assert_eq!(read_witness(dir.path(), G), Some(w2.clone()));

        let foreign = AppliedTipWitness::new("bbbb", 3, 300, "ccc", 3000);
        let foreign_bytes = format!("{}\n", sonic_rs::to_string(&foreign).unwrap());
        std::fs::write(witness_file(dir.path()), foreign_bytes.as_bytes())
            .expect("plant foreign current");
        assert!(
            sonic_rs::from_slice::<AppliedTipWitness>(
                &std::fs::read(witness_file(dir.path())).unwrap()
            )
            .is_ok(),
            "foreign current is parseable JSON"
        );

        let w3 = AppliedTipWitness::new(G, 4, 400, "ddd", 4000);
        write_witness(dir.path(), &w3).expect("write w3 over foreign current");
        assert_eq!(read_witness(dir.path(), G), Some(w3.clone()));

        std::fs::remove_file(witness_file(dir.path())).expect("remove current");
        assert_eq!(
            read_witness(dir.path(), G),
            Some(w1.clone()),
            "valid .prev survives; foreign current never displaced it"
        );
        let raw = std::fs::read(witness_prev(dir.path())).expect(".prev bytes");
        assert_eq!(
            AppliedTipWitness::decode(&raw, G).map(|w| w.genesis_hash),
            Some(G.to_owned()),
            ".prev is the valid record, never the foreign one"
        );

        let dir2 = tempfile::tempdir().expect("tempdir");
        write_witness(dir2.path(), &w1).expect("write w1");
        write_witness(dir2.path(), &w2).expect("write w2 -> w1 to .prev");
        let mut wrong_format = w2;
        wrong_format.format = "999".to_owned();
        std::fs::write(
            witness_file(dir2.path()),
            format!("{}\n", sonic_rs::to_string(&wrong_format).unwrap()).as_bytes(),
        )
        .expect("plant wrong-format current");
        write_witness(dir2.path(), &w3).expect("write w3 over wrong-format current");
        std::fs::remove_file(witness_file(dir2.path())).expect("remove current");
        assert_eq!(
            read_witness(dir2.path(), G),
            Some(w1),
            "valid .prev survives a wrong-format current"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_current_is_never_replaced_by_a_new_publication() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let w1 = AppliedTipWitness::new(G, 1, 100, "aaa", 1000);
        let w2 = AppliedTipWitness::new(G, 2, 200, "bbb", 2000);
        write_witness(dir.path(), &w1).expect("write w1");
        let current = witness_file(dir.path());
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o000))
            .expect("make current unreadable");

        let refusal = write_witness(dir.path(), &w2);
        assert!(
            matches!(refusal, Err(EvidenceError::Io(_))),
            "a read error on the current record must refuse publication instead of \
         discarding it, got {refusal:?}"
        );
        assert!(
            !witness_tmp(dir.path()).exists(),
            "a refused publication removes its staged tmp"
        );

        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o644))
            .expect("restore permissions");
        let kept = std::fs::read(&current).expect("current record still readable");
        assert_eq!(
            AppliedTipWitness::decode(&kept, G),
            Some(w1),
            "the refused publication leaves the last valid record in place"
        );
    }

    fn marker_dir(path: &Path) -> Dir {
        Dir::open_ambient_dir(path, cap_std::ambient_authority()).expect("open data dir")
    }

    fn full_revalidation_path(dir: &Path) -> PathBuf {
        dir.join(FULL_REVALIDATION_MARKER)
    }

    fn injected_sync_failure(_: &Dir) -> std::io::Result<()> {
        Err(std::io::Error::other("injected directory sync failure"))
    }

    // RCV-04, RCV-12
    #[test]
    fn marker_creation_syncs_the_directory_once_after_the_marker_holds_its_content() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = marker_dir(tmp.path());
        let seen_at_sync = std::cell::RefCell::new(Vec::new());

        mark_full_revalidation_with_sync(&dir, |synced| {
            seen_at_sync
                .borrow_mut()
                .push(synced.read(FULL_REVALIDATION_MARKER).ok());
            Ok(())
        })
        .expect("create marker");

        assert_eq!(
            seen_at_sync.into_inner(),
            vec![Some(b"required\n".to_vec())],
            "one directory sync, taken after the marker file exists with its content"
        );
    }

    // RCV-04, RCV-12
    #[test]
    fn marker_creation_fails_closed_on_sync_failure_and_a_retry_syncs_again() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = marker_dir(tmp.path());

        let first = mark_full_revalidation_with_sync(&dir, injected_sync_failure);
        assert!(
            matches!(first, Err(EvidenceError::Io(_))),
            "a directory sync failure must reach the caller, got {first:?}"
        );
        assert!(
            full_revalidation_path(tmp.path()).is_file(),
            "the unsynced marker stays in place, so a surviving process keeps the gate"
        );

        let syncs = std::cell::Cell::new(0_u32);
        mark_full_revalidation_with_sync(&dir, |_| {
            syncs.set(syncs.get() + 1);
            Ok(())
        })
        .expect("retry after the failed sync");
        assert_eq!(
            syncs.get(),
            1,
            "an already-present marker still needs its directory entry made durable"
        );
    }

    // RCV-04, RCV-12
    #[test]
    fn marker_creation_reports_success_only_when_a_regular_marker_file_stands() {
        type Seed = fn(&Path);
        #[allow(unused_mut)]
        let mut cases: Vec<(&str, Seed, bool)> = vec![
            ("absent", |_| {}, true),
            (
                "empty regular file",
                |path| std::fs::write(path, b"").expect("seed"),
                true,
            ),
            (
                "foreign regular file",
                |path| {
                    std::fs::write(path, b"journal fork crossed below checkpoint base\n")
                        .expect("seed");
                },
                true,
            ),
            (
                "directory",
                |path| std::fs::create_dir(path).expect("seed"),
                false,
            ),
        ];
        #[cfg(unix)]
        cases.push((
            "dangling symlink",
            |path| std::os::unix::fs::symlink("does-not-exist", path).expect("seed"),
            false,
        ));

        for (label, seed, expect_success) in cases {
            let tmp = tempfile::tempdir().expect("tempdir");
            let marker = full_revalidation_path(tmp.path());
            seed(&marker);
            let before = std::fs::read(&marker).ok();
            let dir = marker_dir(tmp.path());
            let syncs = std::cell::Cell::new(0_u32);

            let outcome = mark_full_revalidation_with_sync(&dir, |_| {
                syncs.set(syncs.get() + 1);
                Ok(())
            });

            assert_eq!(outcome.is_ok(), expect_success, "{label}: {outcome:?}");
            if outcome.is_ok() {
                assert!(
                    marker.is_file(),
                    "{label}: success must leave the file the consumer looks for"
                );
                assert_eq!(
                    syncs.get(),
                    1,
                    "{label}: success implies one directory sync"
                );
                if before.is_some() {
                    assert_eq!(
                        std::fs::read(&marker).ok(),
                        before,
                        "{label}: existing marker content is never rewritten"
                    );
                }
            } else {
                assert_eq!(
                    syncs.get(),
                    0,
                    "{label}: a refused marker is never synced as if written"
                );
            }
        }
    }

    // RCV-04, RCV-12
    #[test]
    fn marker_retirement_syncs_the_directory_once_after_the_unlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(full_revalidation_path(tmp.path()), b"required\n").expect("seed marker");
        let dir = marker_dir(tmp.path());
        let present_at_sync = std::cell::RefCell::new(Vec::new());

        clear_full_revalidation_marker_with_sync(&dir, |synced| {
            present_at_sync
                .borrow_mut()
                .push(synced.exists(FULL_REVALIDATION_MARKER));
            Ok(())
        })
        .expect("retire marker");

        assert_eq!(
            present_at_sync.into_inner(),
            vec![false],
            "one directory sync, taken after the marker is unlinked"
        );
    }

    // RCV-04, RCV-12
    #[test]
    fn marker_retirement_fails_closed_on_sync_failure_and_a_retry_syncs_the_absent_marker() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(full_revalidation_path(tmp.path()), b"required\n").expect("seed marker");
        let dir = marker_dir(tmp.path());

        let first = clear_full_revalidation_marker_with_sync(&dir, injected_sync_failure);
        assert!(
            matches!(first, Err(EvidenceError::Io(_))),
            "a directory sync failure must reach the caller, got {first:?}"
        );
        assert!(
            !full_revalidation_path(tmp.path()).exists(),
            "the unlink already took effect in the live directory"
        );

        let syncs = std::cell::Cell::new(0_u32);
        clear_full_revalidation_marker_with_sync(&dir, |_| {
            syncs.set(syncs.get() + 1);
            Ok(())
        })
        .expect("retry after the failed sync");
        assert_eq!(
            syncs.get(),
            1,
            "an already-absent marker still needs its removal made durable"
        );
    }

    // RCV-04, RCV-12
    #[test]
    fn marker_retirement_refused_by_the_filesystem_is_not_synced_as_success() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(full_revalidation_path(tmp.path())).expect("directory at marker path");
        let dir = marker_dir(tmp.path());
        let syncs = std::cell::Cell::new(0_u32);

        let outcome = clear_full_revalidation_marker_with_sync(&dir, |_| {
            syncs.set(syncs.get() + 1);
            Ok(())
        });

        assert!(
            matches!(outcome, Err(EvidenceError::Io(_))),
            "removing a non-file must fail, got {outcome:?}"
        );
        assert_eq!(syncs.get(), 0, "a failed unlink is never reported durable");
    }

    // RCV-12
    #[test]
    fn marker_round_trip_through_the_public_seam_uses_the_real_directory_sync() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let marker = full_revalidation_path(tmp.path());

        mark_full_revalidation_at(tmp.path()).expect("create marker");
        assert_eq!(std::fs::read(&marker).expect("marker bytes"), b"required\n");
        mark_full_revalidation_at(tmp.path()).expect("creating twice is idempotent");

        clear_full_revalidation_marker_at(tmp.path()).expect("retire marker");
        assert!(!marker.exists());
        clear_full_revalidation_marker_at(tmp.path()).expect("retiring twice is idempotent");

        let missing = tmp.path().join("no-such-data-dir");
        clear_full_revalidation_marker_at(&missing).expect("no data dir means no marker");
        assert!(
            matches!(
                mark_full_revalidation_at(&missing),
                Err(EvidenceError::Io(_))
            ),
            "creating a marker in a missing data dir must fail, not be skipped"
        );
    }
}
