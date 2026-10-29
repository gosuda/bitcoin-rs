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
            .insert_entry(MempoolEntry::new(Arc::clone(tx), 100, 10_000, 1, 100, 0))
            .expect("the seeded entries must be admissible");
    }
    let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
    let refs: Vec<&Tx> = txs.iter().map(AsRef::as_ref).collect();
    let _ = guard.remove_for_block(&refs, &txids, 101, 1);
    drop(guard);
    mempool
}

fn save_pool(data_dir: &Path, mempool: &RwLock<Mempool>) {
    save(data_dir, &mempool.read().estimator_history());
}

#[test]
fn load_after_save_restores_the_estimated_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seeded = seeded_pool();
    save_pool(dir.path(), &seeded);

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
    save_pool(dir.path(), &fresh);
    let empty_history = std::fs::read(dir.path().join(HISTORY_FILE)).expect("empty history");
    std::fs::write(dir.path().join(HISTORY_TEMP), b"interrupted save")
        .expect("stale staging fixture");

    let seeded = seeded_pool();
    save_pool(dir.path(), &seeded);
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
        save_pool(dir.path(), &fresh);
        assert!(!temp_path.exists());
        std::fs::write(&temp_path, b"another interrupted save").expect("stale staging fixture");
        save_pool(dir.path(), &seeded_pool());
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
    save_pool(dir.path(), &fresh);
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
    save_pool(dir.path(), &seeded);
    let path = dir.path().join(HISTORY_FILE);
    let fresh = open_pool();
    load(dir.path(), &fresh);
    assert!(fresh.read().estimate_fee_rate(1).is_some());

    let replacement = [0xff; 128];
    std::fs::write(&path, replacement).expect("replacement after successful load");
    save_pool(dir.path(), &fresh);
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
    save_pool(dir.path(), &fresh);
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
    std::os::unix::fs::symlink(HISTORY_FILE, &path).expect("unreadable history link");
    std::fs::write(dir.path().join(HISTORY_TEMP), b"interrupted save")
        .expect("stale staging fixture");
    let fresh = open_pool();
    load(dir.path(), &fresh);
    save_pool(dir.path(), &fresh);
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

    save_pool(dir.path(), &seeded_pool());
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

    save_pool(dir.path(), &seeded_pool());
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
    save_pool(dir.path(), &open_pool());
    let path = dir.path().join(HISTORY_FILE);
    let before = std::fs::read(&path).expect("supported history");
    let temp_path = dir.path().join(HISTORY_TEMP);
    std::fs::create_dir(&temp_path).expect("blocked staging path");

    save_pool(dir.path(), &seeded_pool());
    assert_eq!(std::fs::read(&path).expect("history survives"), before);
    assert!(temp_path.is_dir());
}
