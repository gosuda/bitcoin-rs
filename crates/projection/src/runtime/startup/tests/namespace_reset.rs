use super::*;

// IDX-05
#[test]
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
            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                path,
                8 * 1024 * 1024,
            )?);
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
    assert!(matches!(
        result,
        Err(DerivedIndexWorkerError::NamespaceOpen(ref error))
            if error.kind() == std::io::ErrorKind::InvalidData
    ));
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
        assert!(matches!(
            result,
            Err(DerivedIndexWorkerError::NamespaceOpen(ref error))
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for namespace in ["", ".", "..", "foo/", "foo/.", "foo/bar"] {
        spec.namespace = namespace;
        let result = open_derived_index_with_timeout(
            &spec,
            &root.path().join(namespace),
            Duration::from_secs(5),
            &LatchWriter::new().reader(),
            || false,
        );
        assert!(matches!(
            result,
            Err(DerivedIndexWorkerError::NamespaceOpen(ref error))
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));
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
    assert!(matches!(
        result,
        Err(DerivedIndexWorkerError::NamespaceOpen(ref error))
            if error.kind() == std::io::ErrorKind::InvalidInput
    ));
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

// IDX-05
#[test]
fn malformed_reset_claim_does_not_authorize_namespace_reset() -> Result<(), DerivedIndexWorkerError>
{
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    for marker in [5_u32, 9_u32] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("txindex");
        {
            let store = bitcoin_rs_storage::RocksDbStore::open_with_cache(&path, 8 * 1024 * 1024)?;
            let mut batch = store.new_batch();
            batch.put(ColumnFamily::UtxoMeta, &[0, b'V'], &marker.to_le_bytes());
            batch.put(ColumnFamily::UtxoMeta, &[0, b'R'], &[0b1111]);
            store.write_durable(batch)?;
        }
        std::fs::write(path.join("keep"), b"unrecognized reset")?;
        let mut spec = recovery_open_spec(dir.path());
        spec.open_store = Arc::new(|path| {
            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                path,
                8 * 1024 * 1024,
            )?);
            open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
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
            Err(DerivedIndexWorkerError::Index(
                IndexError::InvalidResetMarker
            ))
        ));
        assert_eq!(std::fs::read(path.join("keep"))?, b"unrecognized reset");
        assert!(!dir.path().join(".txindex.reset").exists());
    }
    Ok(())
}

// IDX-05, IDX-07
#[test]
fn cancelled_fresh_open_releases_store_and_retains_reset_intent()
-> Result<(), DerivedIndexWorkerError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("txindex");
    std::fs::create_dir(&path)?;
    let marker = dir.path().join(".txindex.reset");
    std::fs::write(&marker, b"bitcoin-rs-derived-index-reset-v1\n")?;
    let stop = LatchWriter::new();
    let stop_reader = stop.reader();
    let result = rebuild::open(
        dir.path(),
        "txindex",
        &path,
        || stop_reader.is_triggered(),
        |path| {
            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                path,
                8 * 1024 * 1024,
            )?);
            let open =
                open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)?;
            stop.trigger();
            Ok(open)
        },
    );
    assert!(matches!(result, Err(DerivedIndexWorkerError::Stopped)));
    assert!(marker.exists());
    let store = bitcoin_rs_storage::RocksDbStore::open_with_cache(&path, 8 * 1024 * 1024)?;
    drop(store);
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
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |_| {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 }.into())
    });
    let open_thread = Arc::downgrade(&spec.open_store);
    let opener = thread::spawn(move || {
        let result = open_derived_index_with_timeout(
            &spec,
            &spec.data_dir.join("txindex"),
            Duration::from_secs(1),
            &LatchWriter::new().reader(),
            || false,
        );
        (result, spec)
    });
    assert!(started_rx.recv_timeout(Duration::from_secs(5)).is_ok());
    let (result, spec) = opener
        .join()
        .map_err(|_| std::io::Error::other("open waiter panicked"))?;
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
