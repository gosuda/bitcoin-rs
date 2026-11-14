use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
#[test]
fn abandoned_open_outcomes_poison_the_namespace_before_release() -> std::io::Result<()> {
    for error in [
        DerivedIndexWorkerError::OpenStopped,
        DerivedIndexWorkerError::OpenTimeout { secs: 1 },
    ] {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join("txindex");
        let generation = Generation::new(1);
        let runtime = DerivedIndexRuntime::new(crossbeam_channel::bounded(1).0);
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
        assert!(NAMESPACE_REGISTRY.claim(key.clone(), generation.id()));
        let open_abandoned = LatchWriter::new();
        finish_worker(
            &runtime,
            &lifecycle,
            &generation,
            &key,
            Err(error),
            &open_abandoned,
        );
        assert!(runtime.should_stop());
        assert!(matches!(
            **lifecycle.load(),
            DerivedIndexLifecycle::Failed(_)
        ));
        assert!(open_abandoned.reader().is_triggered());
        assert!(NAMESPACE_REGISTRY.is_poisoned(&key));
        assert!(!NAMESPACE_REGISTRY.claim(key, 2));
    }
    Ok(())
}

#[test]
fn completed_worker_outcomes_release_without_poisoning() -> std::io::Result<()> {
    for result in [
        Ok(()),
        Err(DerivedIndexWorkerError::Stopped),
        Err(DerivedIndexWorkerError::NoBodyStore),
    ] {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join("txindex");
        let generation = Generation::new(1);
        let runtime = DerivedIndexRuntime::new(crossbeam_channel::bounded(1).0);
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
        assert!(NAMESPACE_REGISTRY.claim(key.clone(), generation.id()));
        let open_abandoned = LatchWriter::new();
        finish_worker(
            &runtime,
            &lifecycle,
            &generation,
            &key,
            result,
            &open_abandoned,
        );
        assert!(!open_abandoned.reader().is_triggered());
        assert!(!NAMESPACE_REGISTRY.is_poisoned(&key));
        assert!(NAMESPACE_REGISTRY.claim(key.clone(), 2));
        NAMESPACE_REGISTRY.release(&key, 2);
    }
    Ok(())
}
#[test]
fn pending_open_cancels_before_the_open_deadline() {
    let (_open_tx, open_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    let shutdown_reader = shutdown.reader();
    let worker = std::thread::spawn(move || {
        let result =
            wait_for_open_result(&open_rx, Duration::from_secs(30), &shutdown_reader, || {
                false
            });
        let _receiver_gone = done_tx.send(result);
    });
    std::thread::sleep(Duration::from_millis(20));
    shutdown.trigger();
    let Ok(result) = done_rx.recv_timeout(Duration::from_secs(5)) else {
        panic!("must exit within 5 s deadline");
    };
    assert!(worker.join().is_ok());
    assert!(matches!(result, Err(DerivedIndexWorkerError::OpenStopped)));
}

#[test]
fn shutdown_wins_over_an_expired_open_deadline() {
    let (_tx, rx) = crossbeam_channel::bounded(1);
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    shutdown.trigger();
    assert!(matches!(
        wait_for_open_result(&rx, Duration::ZERO, &shutdown.reader(), || false),
        Err(DerivedIndexWorkerError::OpenStopped)
    ));
}

#[test]
fn expired_open_deadline_is_typed() {
    let (_tx, rx) = crossbeam_channel::bounded(1);
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    assert!(matches!(
        wait_for_open_result(&rx, Duration::ZERO, &shutdown.reader(), || false),
        Err(DerivedIndexWorkerError::OpenTimeout { secs: 0 })
    ));
}

#[test]
fn disconnected_open_thread_is_a_storage_failure() {
    let (tx, rx) = crossbeam_channel::bounded(1);
    drop(tx);
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    assert!(matches!(
        wait_for_open_result(&rx, Duration::from_secs(1), &shutdown.reader(), || false),
        Err(DerivedIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::Backend(_)
        ))
    ));
}

#[test]
fn backend_error_is_preserved_without_becoming_abandonment() {
    let (tx, rx) = crossbeam_channel::bounded(1);
    assert!(
        tx.send(Err(DerivedIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::InvalidOperation("backend sentinel")
        )))
        .is_ok()
    );
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    assert!(matches!(
        wait_for_open_result(&rx, Duration::from_secs(1), &shutdown.reader(), || false),
        Err(DerivedIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::InvalidOperation("backend sentinel")
        ))
    ));
}

#[test]
fn shutdown_before_thread_creation_never_touches_the_store() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("must-not-be-created");
    let spec = DerivedIndexOpenSpec {
        scripthash_limit: crate::runtime::DEFAULT_SCRIPTHASH_LIMIT,
        data_dir: dir.path().to_path_buf(),
        namespace: "txindex",
        storage_backend: bitcoin_rs_storage::StorageBackend::RocksDb,
        epoch: 1,
        enabled: crate::IndexCapabilities::default(),
        rollback_rebuild_cutover: 0,
        canonical_data_root: dir.path().to_path_buf(),
        open_store: std::sync::Arc::new(|_| Err(DerivedIndexWorkerError::Stopped)),
        bundle: crate::portable::IndexBundleDirective::None,
        facts_rx: None,
        facts_charge: None,
        query_charge: None,
        facts_gap: None,
        cpu: None,
    };
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    shutdown.trigger();
    let result = open_derived_index_with_timeout(
        &spec,
        &path,
        Duration::from_secs(30),
        &shutdown.reader(),
        || false,
    );
    assert!(matches!(result, Err(DerivedIndexWorkerError::Stopped)));
    assert!(!path.exists());
    Ok(())
}

#[test]
fn heartbeat_cancellation_wakes_and_joins_promptly() {
    let heartbeat = Heartbeat::start(
        "txindex",
        "test".to_owned(),
        "rocksdb".to_owned(),
        HEARTBEAT_INTERVAL,
    );
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let join_thread = std::thread::spawn(move || {
        drop(heartbeat);
        let _ = done_tx.send(());
    });
    let result = done_rx.recv_timeout(Duration::from_secs(5));
    assert!(result.is_ok(), "heartbeat must exit within 5 s deadline");
    assert!(join_thread.join().is_ok());
}

const TEST_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone)]
struct RecoveryHeartbeatCounter {
    count: Arc<AtomicUsize>,
    line2_tx: crossbeam_channel::Sender<()>,
    line2_rx: crossbeam_channel::Receiver<()>,
}

impl RecoveryHeartbeatCounter {
    fn new() -> Self {
        let (line2_tx, line2_rx) = crossbeam_channel::bounded(1);
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            line2_tx,
            line2_rx,
        }
    }

    fn lines(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn wait_for_line2(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while self.lines() < 2 {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return self.lines() >= 2;
            }
            let remaining = timeout.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            match self.line2_rx.recv_timeout(remaining) {
                Ok(()) => {
                    if self.lines() >= 2 {
                        return true;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    return self.lines() >= 2;
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    return self.lines() >= 2;
                }
            }
        }
        true
    }

    fn on_line(&self) {
        let previous = self.count.fetch_add(1, Ordering::SeqCst);
        if previous + 1 >= 2 {
            let _ = self.line2_tx.try_send(());
        }
    }
}

impl Default for RecoveryHeartbeatCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl tracing::Subscriber for RecoveryHeartbeatCounter {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _id: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _id: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let names: Vec<&str> = event.fields().map(|field| field.name()).collect();
        if names.contains(&"capability") && names.contains(&"elapsed_secs") {
            self.on_line();
        }
    }

    fn enter(&self, _id: &tracing::span::Id) {}

    fn exit(&self, _id: &tracing::span::Id) {}
}

fn recovery_open_spec(dir: &Path) -> DerivedIndexOpenSpec {
    DerivedIndexOpenSpec {
        scripthash_limit: crate::runtime::DEFAULT_SCRIPTHASH_LIMIT,
        data_dir: dir.to_path_buf(),
        namespace: "txindex",
        storage_backend: bitcoin_rs_storage::StorageBackend::RocksDb,
        epoch: 1,
        enabled: crate::IndexCapabilities::default(),
        rollback_rebuild_cutover: 0,
        canonical_data_root: dir.to_path_buf(),
        open_store: Arc::new(|_| Err(DerivedIndexWorkerError::Stopped)),
        bundle: crate::portable::IndexBundleDirective::None,
        facts_rx: None,
        facts_charge: None,
        query_charge: None,
        facts_gap: None,
        cpu: None,
    }
}

fn assert_no_heartbeat_lines_after_the_open_phase(
    counter: &RecoveryHeartbeatCounter,
    phase_label: &str,
) {
    let lines_while_pending = counter.lines();
    assert!(
        lines_while_pending >= 2,
        "{phase_label}: heartbeat must emit at least two lines while the open phase is pending, got {lines_while_pending}"
    );
    thread::sleep(TEST_HEARTBEAT_INTERVAL * 4);
    assert_eq!(
        counter.lines(),
        lines_while_pending,
        "{phase_label}: heartbeat must stop emitting once the open phase has ended"
    );
}

#[test]
fn recovery_heartbeat_stops_when_the_open_phase_fails() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |_| {
        assert!(
            started_tx.send(()).is_ok(),
            "open phase must report that it started"
        );
        let _ = release_rx.recv();
        Err(DerivedIndexWorkerError::Stopped)
    });
    let counter = RecoveryHeartbeatCounter::new();
    let dispatch = tracing::Dispatch::new(counter.clone());
    let releaser_counter = counter.clone();
    let releaser = thread::spawn(move || {
        let started = started_rx.recv_timeout(Duration::from_secs(5));
        assert!(started.is_ok(), "open phase must start within 5 s deadline");
        assert!(
            releaser_counter.wait_for_line2(Duration::from_secs(5)),
            "heartbeat must emit at least two lines within 5 s deadline"
        );
        let _ = release_tx.send(());
    });
    let cancel = LatchWriter::new();
    let txindex_dir = dir.path().join("txindex");
    let result = tracing::dispatcher::with_default(&dispatch, || {
        open_with_recovery_heartbeat(
            &spec,
            &txindex_dir,
            TEST_HEARTBEAT_INTERVAL,
            &cancel.reader(),
            || false,
        )
    });
    assert!(
        matches!(result, Err(DerivedIndexWorkerError::Stopped)),
        "blocked open must surface the open error"
    );
    assert_no_heartbeat_lines_after_the_open_phase(&counter, "failed open");
    assert!(releaser.join().is_ok());
    Ok(())
}

#[test]
fn recovery_heartbeat_stops_after_a_successful_open() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let (started_tx, _started_rx) = crossbeam_channel::bounded(1);
    let mut spec = recovery_open_spec(dir.path());
    let store_dir = dir.path().join("store");
    let counter = RecoveryHeartbeatCounter::new();
    let open_counter = counter.clone();
    spec.open_store = Arc::new(move |_| {
        assert!(
            started_tx.send(()).is_ok(),
            "open phase must report that it started"
        );
        assert!(
            open_counter.wait_for_line2(Duration::from_secs(5)),
            "heartbeat must emit at least two lines within 5 s deadline"
        );
        let store = Arc::new(
            bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir, 8 * 1024 * 1024)
                .map_err(DerivedIndexWorkerError::Storage)?,
        );
        open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
    });
    let dispatch = tracing::Dispatch::new(counter.clone());
    let cancel = LatchWriter::new();
    let txindex_dir = dir.path().join("txindex");
    let open = tracing::dispatcher::with_default(&dispatch, || {
        open_with_recovery_heartbeat(
            &spec,
            &txindex_dir,
            TEST_HEARTBEAT_INTERVAL,
            &cancel.reader(),
            || false,
        )
    });
    assert!(open.is_ok(), "successful open must return the opened index");
    assert_no_heartbeat_lines_after_the_open_phase(&counter, "successful open");
    Ok(())
}

#[test]
fn cancellation_after_spawn_joins_helper_and_returns_stopped() -> std::io::Result<()> {
    struct DropProbe(crossbeam_channel::Sender<()>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let dir = tempfile::tempdir()?;
    let store_dir = dir.path().join("txindex");
    let (opened_tx, opened_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
    let mut spec = recovery_open_spec(dir.path());
    let store_dir_clone = store_dir.clone();
    spec.open_store = Arc::new(move |_| {
        let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DropProbe(dropped_tx.clone()));
        let store = Arc::new(
            bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir_clone, 8 * 1024 * 1024)
                .map(|s| s.guarded_by(guard))
                .map_err(DerivedIndexWorkerError::Storage)?,
        );
        let _ = opened_tx.send(());
        let _ = release_rx.recv();
        open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
    });
    let shutdown = LatchWriter::new();
    let shutdown_reader = shutdown.reader();
    let store_dir_for_thread = store_dir.clone();
    let open_thread = thread::spawn(move || {
        open_derived_index_with_timeout(
            &spec,
            &store_dir_for_thread,
            Duration::from_secs(30),
            &shutdown_reader,
            || false,
        )
    });

    assert!(
        opened_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "helper must open store and signal opened"
    );

    shutdown.trigger();
    assert!(release_tx.send(()).is_ok());

    let Ok(result) = open_thread.join() else {
        panic!("open thread must join promptly");
    };

    assert!(
        dropped_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "store must drop after open cancellation"
    );

    assert!(
        matches!(result, Err(DerivedIndexWorkerError::Stopped)),
        "cancellation after spawn must return clean Stopped, got {:?}",
        result.as_ref().err()
    );

    let second_open =
        bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir, 8 * 1024 * 1024);
    assert!(
        second_open.is_ok(),
        "second RocksDbStore open must succeed, proving helper joined and lock released: {:?}",
        second_open.as_ref().err()
    );

    Ok(())
}

#[test]
fn cancellation_after_spawn_preserves_backend_error_when_helper_fails() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let store_dir = dir.path().join("txindex");
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let (helper_done_tx, helper_done_rx) = crossbeam_channel::bounded::<()>(1);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |_| {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
        let _ = helper_done_tx.send(());
        Err(DerivedIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::InvalidOperation("native corruption sentinel"),
        ))
    });
    let shutdown = LatchWriter::new();
    let shutdown_reader = shutdown.reader();
    let open_thread = thread::spawn(move || {
        open_derived_index_with_timeout(
            &spec,
            &store_dir,
            Duration::from_secs(30),
            &shutdown_reader,
            || false,
        )
    });

    assert!(
        started_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "helper must signal started"
    );
    shutdown.trigger();
    assert!(release_tx.send(()).is_ok());

    let Ok(result) = open_thread.join() else {
        panic!("open thread must join promptly");
    };

    let _ = helper_done_rx.recv_timeout(Duration::from_secs(5));

    assert!(
        matches!(
            result,
            Err(DerivedIndexWorkerError::Storage(
                bitcoin_rs_storage::StorageError::InvalidOperation("native corruption sentinel")
            ))
        ),
        "cancellation after spawn must preserve original typed backend error, got {:?}",
        result.as_ref().err()
    );

    Ok(())
}

#[test]
fn cancellation_after_spawn_resumes_panic_when_helper_panics() -> std::io::Result<()> {
    struct PanicSentinel(crossbeam_channel::Sender<()>);
    impl Drop for PanicSentinel {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let dir = tempfile::tempdir()?;
    let store_dir = dir.path().join("txindex");
    let (started_tx, started_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let (unwound_tx, unwound_rx) = crossbeam_channel::bounded::<()>(1);
    let mut spec = recovery_open_spec(dir.path());
    spec.open_store = Arc::new(move |_| {
        let _sentinel = PanicSentinel(unwound_tx.clone());
        let _ = started_tx.send(());
        let _ = release_rx.recv();
        panic!("helper panic sentinel");
    });
    let shutdown = LatchWriter::new();
    let shutdown_reader = shutdown.reader();
    let open_thread = thread::spawn(move || {
        open_derived_index_with_timeout(
            &spec,
            &store_dir,
            Duration::from_secs(30),
            &shutdown_reader,
            || false,
        )
    });

    assert!(
        started_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "helper must signal started"
    );
    shutdown.trigger();
    assert!(release_tx.send(()).is_ok());

    let join_result = open_thread.join();
    assert!(
        unwound_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "helper must unwind its sentinel on cancellation"
    );
    let Err(payload) = join_result else {
        panic!("open thread must resume the helper panic on cancellation");
    };
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("helper panic sentinel"),
        "open thread must resume the helper panic, not another panic"
    );

    Ok(())
}
