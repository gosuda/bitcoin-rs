//! Owner-local persistence for the fee estimator's confirmation history.
//!
//! CONTRACT: docs/policies/db-migration.md — the history file carries an
//! estimator-owned version outside `CURRENT_SCHEMA`. A corrupt, missing, or
//! unknown-version payload degrades to insufficient-data status and the node
//! starts; startup never fails on this file, no rate is ever fabricated, and
//! a rejected file is left in place (the next owner save atomically replaces
//! it with the state the node actually holds). There is no translation layer
//! and no backup or rotation.

use std::path::Path;
use std::sync::Arc;

use bitcoin_rs_mempool::HistoryReject;
use parking_lot::RwLock;

use bitcoin_rs_mempool::Mempool;

/// Name of the estimator's history file inside the datadir.
const HISTORY_FILE: &str = "fee-estimator-history.dat";
/// Staging name for the atomic publish; same filesystem, renamed into place.
const HISTORY_TEMP: &str = "fee-estimator-history.dat.tmp";
/// Read-side bound: a history payload larger than this cannot be a genuine
/// version-1 file (the encoder's worst case is a few megabytes), so treat it
/// as corrupt without buffering it.
const MAX_HISTORY_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Adopts the persisted estimator history at node open, if any.
///
/// A missing file is a normal cold start. A rejected payload logs a typed
/// warning naming the reject reason and leaves the pool's fresh,
/// insufficient-data estimator in place.
pub(crate) fn load(data_dir: &Path, mempool: &Arc<RwLock<Mempool>>) {
    let path = data_dir.join(HISTORY_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::debug!(
            path = %path.display(),
            "no fee-estimator history: starting with insufficient data"
        );
        return;
    };
    if metadata.len() > MAX_HISTORY_FILE_BYTES {
        tracing::warn!(
            path = %path.display(),
            size = metadata.len(),
            "fee-estimator history exceeds the version-1 size bound; \
             degrading to insufficient data and leaving the file in place"
        );
        return;
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "fee-estimator history is unreadable; \
                 degrading to insufficient data and leaving the file in place"
            );
            return;
        }
    };
    let value = mempool.write().restore_estimator_history(&bytes);
    match value {
        Ok(()) => tracing::info!(
            path = %path.display(),
            bytes = bytes.len(),
            "restored fee-estimator history"
        ),
        Err(reject) => warn_rejected(&path, reject),
    }
}

/// Persists the estimator history at shutdown, after the event loop drained
/// and no further mempool mutations run.
///
/// Publish protocol (mirrors the recovery-evidence writer): remove a stale
/// temp, stage the payload with `create_new`, `sync_all` the temp, rename it
/// over the live file, then best-effort sync the containing directory. A
/// failure at any stage is a warning: owner-local persistence must never
/// block a clean shutdown.
pub(crate) fn save(data_dir: &Path, mempool: &Arc<RwLock<Mempool>>) {
    let bytes = mempool.read().estimator_history();
    let temp_path = data_dir.join(HISTORY_TEMP);
    let live_path = data_dir.join(HISTORY_FILE);
    let result = (|| -> std::io::Result<()> {
        match std::fs::remove_file(&temp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
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
        Ok(())
    })();
    match result {
        Ok(()) => tracing::info!(
            path = %live_path.display(),
            bytes = bytes.len(),
            "saved fee-estimator history"
        ),
        Err(error) => tracing::warn!(
            path = %live_path.display(),
            %error,
            "failed to save fee-estimator history; the node still shuts down cleanly"
        ),
    }
}

/// Typed warning for a rejected history payload; the file stays in place.
fn warn_rejected(path: &Path, reject: HistoryReject) {
    match reject {
        HistoryReject::BadMagic => tracing::warn!(
            path = %path.display(),
            "fee-estimator history has a foreign magic prefix; \
             degrading to insufficient data and leaving the file in place"
        ),
        HistoryReject::UnknownVersion(version) => tracing::warn!(
            path = %path.display(),
            version,
            "fee-estimator history was written by an unknown format version; \
             degrading to insufficient data and leaving the file in place"
        ),
        HistoryReject::Corrupt => tracing::warn!(
            path = %path.display(),
            "fee-estimator history is corrupt; \
             degrading to insufficient data and leaving the file in place"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
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
        let refs: Vec<&Tx> = txs.iter().map(|tx| tx.as_ref()).collect();
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
        assert_eq!(
            fresh.read().estimate_fee_rate(1),
            seeded.read().estimate_fee_rate(1),
            "the saved history must survive the datadir round trip"
        );
        assert!(fresh.read().estimate_fee_rate(1).is_some());
    }

    #[test]
    fn load_without_a_file_starts_insufficient_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pool = open_pool();
        load(dir.path(), &pool);
        assert_eq!(pool.read().estimate_fee_rate(1), None);
    }

    #[test]
    fn load_of_a_corrupt_file_degrades_and_keeps_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let seeded = seeded_pool();
        save(dir.path(), &seeded);
        let path = dir.path().join(HISTORY_FILE);
        let mut bytes = std::fs::read(&path).expect("the saved file");
        bytes[3] ^= 0xff;
        std::fs::write(&path, &bytes).expect("rewrite");

        let fresh = open_pool();
        load(dir.path(), &fresh);
        assert_eq!(
            fresh.read().estimate_fee_rate(1),
            None,
            "a corrupt payload degrades to insufficient data"
        );
        assert_eq!(
            std::fs::read(&path).expect("file must survive"),
            bytes,
            "a rejected file stays in place, byte for byte"
        );
    }
}
