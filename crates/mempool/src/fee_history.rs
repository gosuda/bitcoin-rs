//! Owner-local persistence for the fee estimator's confirmation history.
//!
//! CONTRACT: docs/policies/db-migration.md.

use std::io::{self, Read};
use std::path::Path;

use parking_lot::RwLock;

use crate::{FeeEstimator, Mempool};

const HISTORY_FILE: &str = "fee-estimator-history.dat";
const HISTORY_TEMP: &str = "fee-estimator-history.dat.tmp";
/// Version-1 payloads larger than this bound are treated as corrupt.
const MAX_HISTORY_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Reads only bounded, ordinary files. Only a genuinely missing path permits
/// creating a new history; all other failures must preserve the live entry.
fn read_history(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::other("history is not a regular file"));
    }
    if metadata.len() > MAX_HISTORY_FILE_BYTES {
        return Err(io::Error::other("exceeds the version-1 size bound"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_HISTORY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_HISTORY_FILE_BYTES {
        return Err(io::Error::other("exceeds the version-1 size bound"));
    }
    Ok(Some(bytes))
}

/// Adopts persisted estimator history at node open, if any.
pub fn load(data_dir: &Path, mempool: &RwLock<Mempool>) {
    let path = data_dir.join(HISTORY_FILE);
    let bytes = match read_history(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            tracing::debug!(
                path = %path.display(),
                "no fee-estimator history: starting with insufficient data"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "fee-estimator history is unreadable; degrading to insufficient data and leaving the file in place"
            );
            return;
        }
    };
    match FeeEstimator::from_history_bytes(&bytes) {
        Ok(history) => {
            mempool.write().adopt_estimator_history(history);
            tracing::info!(
                path = %path.display(),
                bytes = bytes.len(),
                "restored fee-estimator history"
            );
        }
        Err(reject) => tracing::warn!(
            path = %path.display(),
            ?reject,
            "fee-estimator history rejected; degrading to insufficient data and leaving the file in place"
        ),
    }
}

/// Persists the estimator history at shutdown while preserving rejected files.
///
/// Publish: stage with `create_new`, `sync_all`, rename over the live file,
/// best-effort dir sync; any failure is a
/// warning, never a failed shutdown. A live file this build cannot adopt is
/// preserved until an explicitly authorized rebuild, including after shutdown.
/// Stale staging files are removed even when the live history is rejected.
pub fn save(data_dir: &Path, mempool: &RwLock<Mempool>) {
    let temp_path = data_dir.join(HISTORY_TEMP);
    let live_path = data_dir.join(HISTORY_FILE);
    let result = (|| -> std::io::Result<Option<usize>> {
        match std::fs::remove_file(&temp_path) {
            Ok(()) => {}
            // No stale temp staged: nothing to remove.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            // A real IO failure on the temp path aborts the publish.
            Err(error) => return Err(error),
        }
        // Recheck the live file, not a remembered startup result: it may have
        // changed since load. Disk I/O and decoding occur outside the pool lock
        // and before staging a replacement. Publication retains the existing
        // assumption that no external writer changes this datadir.
        match read_history(&live_path) {
            Ok(Some(bytes)) => {
                if let Err(reject) = FeeEstimator::from_history_bytes(&bytes) {
                    tracing::warn!(
                        path = %live_path.display(),
                        ?reject,
                        "fee-estimator history rejected; leaving the file in place without saving"
                    );
                    return Ok(None);
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    path = %live_path.display(),
                    %error,
                    "fee-estimator history is unreadable; leaving the file in place without saving"
                );
                return Ok(None);
            }
        }
        let bytes = mempool.read().estimator_history();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, &live_path)?;
        if let Ok(dir) = std::fs::File::open(data_dir) {
            let _ = dir.sync_all();
        }
        Ok(Some(bytes.len()))
    })();
    match result {
        Ok(Some(bytes)) => tracing::info!(
            path = %live_path.display(),
            bytes,
            "saved fee-estimator history"
        ),
        Ok(None) => {}
        Err(error) => tracing::warn!(
            path = %live_path.display(),
            %error,
            "failed to save fee-estimator history; the node still shuts down cleanly"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{MempoolEntry, MempoolLimits};
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use std::sync::Arc;

    fn open_pool() -> Arc<RwLock<Mempool>> {
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())))
    }

    fn seeded_pool() -> Arc<RwLock<Mempool>> {
        let mempool = open_pool();
        let mut guard = mempool.write();
        let mut txs: Vec<Arc<Tx>> = Vec::new();
        for index in 0_u8..2 {
            let mut prevout = [0_u8; 32];
            prevout[0] = 9;
            prevout[1] = index;
            txs.push(Arc::new(Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&prevout)), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: vec![0x51].into(),
                }],
            }));
        }
        for tx in &txs {
            guard
                .insert_entry(MempoolEntry::new(Arc::clone(tx), 100, 10_000, 1, 100))
                .expect("the seeded entries must be admissible");
        }
        // Two confirmations: a single one decays to 0.998 within its own
        // block, under the estimator's one-decayed-observation minimum.
        let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
        let refs: Vec<&Tx> = txs.iter().map(AsRef::as_ref).collect();
        let _ = guard.remove_for_block(&refs, &txids, 101);
        drop(guard);
        mempool
    }

    #[test]
    fn load_after_save_restores_the_estimated_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seeded = seeded_pool();
        save(dir.path(), &seeded);

        let fresh = open_pool();
        assert_eq!(fresh.read().estimate_fee_rate(1), None);
        load(dir.path(), &fresh);
        let seeded_rate = seeded.read().estimate_fee_rate(1);
        assert!(seeded_rate.is_some());
        assert_eq!(
            fresh.read().estimate_fee_rate(1),
            seeded_rate,
            "the saved history must survive the datadir round trip"
        );
        assert!(!dir.path().join(HISTORY_TEMP).exists());
    }

    #[test]
    fn save_updates_supported_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fresh = open_pool();
        save(dir.path(), &fresh);
        let empty_history = std::fs::read(dir.path().join(HISTORY_FILE)).expect("empty history");
        std::fs::write(dir.path().join(HISTORY_TEMP), b"interrupted save")
            .expect("stale staging fixture");

        let seeded = seeded_pool();
        save(dir.path(), &seeded);
        assert_ne!(
            std::fs::read(dir.path().join(HISTORY_FILE)).expect("updated history"),
            empty_history,
            "a supported file must remain writable as new history is learned"
        );
        load(dir.path(), &fresh);
        assert_eq!(
            fresh.read().estimate_fee_rate(1),
            seeded.read().estimate_fee_rate(1)
        );
        assert!(!dir.path().join(HISTORY_TEMP).exists());
    }

    #[test]
    fn load_without_a_file_starts_insufficient_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pool = open_pool();
        load(dir.path(), &pool);
        assert_eq!(pool.read().estimate_fee_rate(1), None);
    }

    #[test]
    fn rejected_history_survives_load_save_and_reopen() {
        // RCV-09 preserves rejected live bytes. The disposable staging file
        // never acquires that status, including for an unknown owner version.
        let valid = seeded_pool().read().estimator_history();
        let mut bad_magic = valid.clone();
        bad_magic[3] ^= 0xff;
        let mut unknown_version = valid.clone();
        unknown_version[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut trailing_bytes = valid.clone();
        trailing_bytes.push(0xff);

        for bytes in [
            bad_magic,
            valid[..valid.len() - 1].to_vec(),
            unknown_version,
            trailing_bytes,
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join(HISTORY_FILE);
            std::fs::write(&path, &bytes).expect("rejected fixture");
            let temp_path = dir.path().join(HISTORY_TEMP);
            std::fs::write(&temp_path, b"interrupted save").expect("stale staging fixture");

            let fresh = open_pool();
            load(dir.path(), &fresh);
            assert_eq!(fresh.read().estimate_fee_rate(1), None);
            save(dir.path(), &fresh);
            assert!(!temp_path.exists());
            // Even learned observations do not authorize replacing a file
            // the owner could not adopt.
            std::fs::write(&temp_path, b"another interrupted save").expect("stale staging fixture");
            save(dir.path(), &seeded_pool());
            let reopened = open_pool();
            load(dir.path(), &reopened);
            assert_eq!(reopened.read().estimate_fee_rate(1), None);
            assert_eq!(
                std::fs::read(&path).expect("file must survive"),
                bytes,
                "a rejected file survives shutdown and reopen byte for byte"
            );
            assert!(!dir.path().join(HISTORY_TEMP).exists());
        }
    }

    #[test]
    fn oversized_history_survives_load_save_and_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(HISTORY_FILE);
        let marker = [0xff; 128];
        std::fs::write(&path, marker).expect("oversize marker");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("history file")
            .set_len(MAX_HISTORY_FILE_BYTES + 1)
            .expect("sparse oversized history");

        let fresh = open_pool();
        load(dir.path(), &fresh);
        assert_eq!(fresh.read().estimate_fee_rate(1), None);
        save(dir.path(), &fresh);
        let reopened = open_pool();
        load(dir.path(), &reopened);
        assert_eq!(reopened.read().estimate_fee_rate(1), None);
        assert_eq!(
            std::fs::metadata(&path).expect("history metadata").len(),
            MAX_HISTORY_FILE_BYTES + 1
        );
        let mut file = std::fs::File::open(&path).expect("preserved oversized file");
        let mut actual_marker = [0; 128];
        file.read_exact(&mut actual_marker)
            .expect("preserved marker");
        assert_eq!(actual_marker, marker);
        let mut chunk = [0; 8192];
        loop {
            let count = file.read(&mut chunk).expect("preserved sparse tail");
            if count == 0 {
                break;
            }
            assert!(chunk[..count].iter().all(|byte| *byte == 0));
        }
        assert!(!dir.path().join(HISTORY_TEMP).exists());
    }

    #[test]
    fn save_rechecks_a_history_replaced_after_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seeded = seeded_pool();
        save(dir.path(), &seeded);
        let path = dir.path().join(HISTORY_FILE);
        let fresh = open_pool();
        load(dir.path(), &fresh);
        assert!(fresh.read().estimate_fee_rate(1).is_some());

        let replacement = [0xff; 128];
        std::fs::write(&path, replacement).expect("replacement after successful load");
        save(dir.path(), &fresh);
        assert_eq!(
            std::fs::read(&path).expect("file must survive"),
            replacement
        );
        assert!(!dir.path().join(HISTORY_TEMP).exists());
    }

    #[test]
    fn unreadable_history_is_preserved_while_stale_staging_is_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(HISTORY_FILE);
        std::fs::create_dir(&path).expect("unreadable history directory");
        let marker_path = path.join("operator-data");
        std::fs::write(&marker_path, b"preserve me").expect("operator marker");
        std::fs::write(dir.path().join(HISTORY_TEMP), b"interrupted save")
            .expect("stale staging fixture");

        let fresh = open_pool();
        load(dir.path(), &fresh);
        assert_eq!(fresh.read().estimate_fee_rate(1), None);
        save(dir.path(), &fresh);
        assert_eq!(
            std::fs::read(marker_path).expect("marker survives"),
            b"preserve me"
        );
        assert!(!dir.path().join(HISTORY_TEMP).exists());
    }

    #[cfg(unix)]
    #[test]
    fn metadata_failure_is_not_treated_as_missing_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(HISTORY_FILE);
        // Following this self-referential symlink fails regardless of the
        // test process's permissions, unlike a mode-000 permission fixture.
        std::os::unix::fs::symlink(HISTORY_FILE, &path).expect("unreadable history link");
        std::fs::write(dir.path().join(HISTORY_TEMP), b"interrupted save")
            .expect("stale staging fixture");
        let fresh = open_pool();
        load(dir.path(), &fresh);
        save(dir.path(), &fresh);
        assert_eq!(
            std::fs::read_link(&path).expect("link survives"),
            Path::new(HISTORY_FILE)
        );
        assert!(!dir.path().join(HISTORY_TEMP).exists());
    }

    #[test]
    fn staging_cleanup_failure_preserves_rejected_history_and_operator_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(HISTORY_FILE);
        let rejected = b"corrupt history";
        std::fs::write(&path, rejected).expect("rejected fixture");
        let temp_path = dir.path().join(HISTORY_TEMP);
        std::fs::create_dir(&temp_path).expect("blocked staging path");
        let marker_path = temp_path.join("operator-data");
        std::fs::write(&marker_path, b"preserve me").expect("operator marker");

        // Cleanup is best effort at shutdown; it must neither recursively
        // delete a directory nor replace the RCV-09 rejected live file.
        save(dir.path(), &seeded_pool());
        assert_eq!(std::fs::read(&path).expect("history survives"), rejected);
        assert_eq!(
            std::fs::read(marker_path).expect("marker survives"),
            b"preserve me"
        );
        assert!(temp_path.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn rejected_history_cleanup_unlinks_only_the_staging_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(HISTORY_FILE);
        let rejected = b"corrupt history";
        std::fs::write(&path, rejected).expect("rejected fixture");
        let temp_path = dir.path().join(HISTORY_TEMP);
        let marker_path = dir.path().join("operator-data");
        std::fs::write(&marker_path, b"preserve me").expect("operator marker");
        std::os::unix::fs::symlink(&marker_path, &temp_path).expect("staging symlink");

        save(dir.path(), &seeded_pool());
        assert_eq!(std::fs::read(&path).expect("history survives"), rejected);
        assert_eq!(
            std::fs::read(marker_path).expect("marker survives"),
            b"preserve me"
        );
        assert_eq!(
            std::fs::symlink_metadata(&temp_path)
                .expect_err("staging symlink is removed")
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn staging_failure_keeps_supported_live_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        save(dir.path(), &open_pool());
        let path = dir.path().join(HISTORY_FILE);
        let before = std::fs::read(&path).expect("supported history");
        let temp_path = dir.path().join(HISTORY_TEMP);
        std::fs::create_dir(&temp_path).expect("blocked staging path");

        save(dir.path(), &seeded_pool());
        assert_eq!(std::fs::read(&path).expect("history survives"), before);
        assert!(temp_path.is_dir());
    }
}
