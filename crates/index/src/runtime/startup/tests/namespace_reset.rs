use super::*;

// IDX-05
#[test]
#[cfg(feature = "fjall")]
fn pending_namespace_reset_completes_before_backend_open() -> Result<(), DerivedIndexWorkerError> {
    for phase in 0..3 {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("txindex");
        let obsolete = path.join("partly-deleted-engine");
        if phase != 0 {
            std::fs::create_dir(&path)?;
        }
        if phase == 2 {
            std::fs::write(&obsolete, b"unreadable old engine")?;
        }
        let marker = dir.path().join(".txindex.reset");
        std::fs::write(&marker, b"bitcoin-rs-derived-index-reset-v1\n")?;
        let mut spec = recovery_open_spec(dir.path());
        if phase == 2 {
            spec.open_store = Arc::new(|path| {
                assert!(!path.join("partly-deleted-engine").exists());
                Err(DerivedIndexWorkerError::Storage(
                    bitcoin_rs_storage::StorageError::InvalidOperation("fresh engine open fault"),
                ))
            });
            let failed = open_derived_index_with_timeout(
                &spec,
                &path,
                Duration::from_secs(5),
                &LatchWriter::new().reader(),
                || false,
            );
            assert!(matches!(failed, Err(DerivedIndexWorkerError::Storage(_))));
            assert!(
                marker.exists(),
                "failed recreation must retain the reset intent"
            );
        }
        spec.open_store = Arc::new(move |path| {
            assert!(!path.join("partly-deleted-engine").exists());
            let store = Arc::new(bitcoin_rs_storage::FjallStore::open(path)?);
            open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
        });
        let result = open_derived_index_with_timeout(
            &spec,
            &path,
            Duration::from_secs(5),
            &LatchWriter::new().reader(),
            || false,
        );
        assert!(
            result.is_ok(),
            "reset intent must resume without opening the old engine"
        );
        assert!(!marker.exists(), "completed reset must retire its intent");
    }
    Ok(())
}

// IDX-05
#[test]
fn unknown_namespace_reset_intent_preserves_files_and_refuses_open() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("txindex");
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("keep"), b"old index")?;
    let marker = dir.path().join(".txindex.reset");
    std::fs::write(&marker, b"operator file")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Err(DerivedIndexWorkerError::Stopped)
    });
    let result = open_derived_index_with_timeout(
        &spec,
        &path,
        Duration::from_secs(5),
        &LatchWriter::new().reader(),
        || false,
    );
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(&marker)?, b"operator file");
    assert_eq!(std::fs::read(path.join("keep"))?, b"old index");
    Ok(())
}

// IDX-05
#[test]
fn namespace_reset_refuses_paths_outside_the_named_child() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut spec = recovery_open_spec(root.path());
    spec.open_store = Arc::new(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 }.into())
    });
    for path in [
        other.path().join("txindex"),
        root.path().to_path_buf(),
        root.path().join("other"),
    ] {
        let result = open_derived_index_with_timeout(
            &spec,
            &path,
            Duration::from_secs(5),
            &LatchWriter::new().reader(),
            || false,
        );
        assert!(result.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

// IDX-05
#[test]
#[cfg(unix)]
fn namespace_reset_refuses_a_link_to_another_directory() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let authoritative = tempfile::tempdir()?;
    let path = root.path().join("txindex");
    std::fs::write(authoritative.path().join("keep"), b"authoritative bytes")?;
    std::os::unix::fs::symlink(authoritative.path(), &path)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut spec = recovery_open_spec(root.path());
    spec.open_store = Arc::new(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 }.into())
    });
    let result = open_derived_index_with_timeout(
        &spec,
        &path,
        Duration::from_secs(5),
        &LatchWriter::new().reader(),
        || false,
    );
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(authoritative.path().join("keep"))?,
        b"authoritative bytes"
    );
    assert!(std::fs::symlink_metadata(&path)?.file_type().is_symlink());
    Ok(())
}

// IDX-05, IDX-07
#[test]
fn backend_failure_does_not_authorize_namespace_reset() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("txindex");
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("keep"), b"operator data")?;
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(|_| {
        Err(DerivedIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::InvalidOperation("unrelated backend failure"),
        ))
    });
    let result = open_derived_index_with_timeout(
        &spec,
        &path,
        Duration::from_secs(5),
        &LatchWriter::new().reader(),
        || false,
    );
    assert!(matches!(
        result,
        Err(DerivedIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::InvalidOperation("unrelated backend failure")
        ))
    ));
    assert_eq!(std::fs::read(path.join("keep"))?, b"operator data");
    assert!(!dir.path().join(".txindex.reset").exists());
    Ok(())
}

// IDX-05, IDX-07
#[test]
fn abandoned_open_cannot_start_a_late_namespace_reset() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("txindex");
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("keep"), b"obsolete but still owned")?;
    let (release_tx, release_rx) = crossbeam_channel::bounded(1);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |_| {
        let _ = release_rx.recv();
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 }.into())
    });
    let open_thread = Arc::downgrade(&spec.open_store);
    let result = open_derived_index_with_timeout(
        &spec,
        &path,
        Duration::ZERO,
        &LatchWriter::new().reader(),
        || false,
    );
    assert!(matches!(
        result,
        Err(DerivedIndexWorkerError::OpenTimeout { .. })
    ));
    drop(spec);
    let _ = release_tx.send(());
    let deadline = Instant::now() + Duration::from_secs(5);
    while open_thread.upgrade().is_some() {
        assert!(
            Instant::now() < deadline,
            "abandoned opener must finish after release"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        std::fs::read(path.join("keep"))?,
        b"obsolete but still owned"
    );
    assert!(!dir.path().join(".txindex.reset").exists());
    Ok(())
}

// IDX-05
#[test]
#[cfg(feature = "redb")]
fn redb_namespace_reset_closes_the_rejected_store_before_reopening()
-> Result<(), DerivedIndexWorkerError> {
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PersistFault};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("txindex");
    {
        let store = bitcoin_rs_storage::open_redb_tx_index_store(&path)?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::UtxoMeta, &[0, b'V'], &5_u32.to_le_bytes());
        for index in 0..8_000_u32 {
            let mut key = [0_u8; 12];
            key[8..].copy_from_slice(&index.to_be_bytes());
            batch.put(ColumnFamily::Funding, &key, &[1; 16]);
        }
        store.write_durable(batch)?;
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |path| {
        let store = Arc::new(bitcoin_rs_storage::open_redb_tx_index_store(path)?);
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            store.arm_persist_fault(PersistFault::FailApply);
        } else {
            assert!(
                store
                    .iter_prefix(ColumnFamily::Funding, &[])?
                    .next()
                    .is_none()
            );
        }
        open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
    });
    let result = open_derived_index_with_timeout(
        &spec,
        &path,
        Duration::from_secs(5),
        &LatchWriter::new().reader(),
        || false,
    );
    assert!(result.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!dir.path().join(".txindex.reset").exists());
    Ok(())
}
