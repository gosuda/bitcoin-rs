#![expect(
    clippy::expect_used,
    reason = "test: supervisor tests use expect for clarity"
)]

use super::namespace::NAMESPACE_REGISTRY;
use super::*;
use arc_swap::ArcSwap;
use bitcoin_rs_execution::chain::BlockTree;
use std::sync::Arc;

fn test_open_spec(dir: &std::path::Path, epoch: u64) -> DerivedIndexOpenSpec {
    DerivedIndexOpenSpec {
        scripthash_limit: crate::runtime::DEFAULT_SCRIPTHASH_LIMIT,
        data_dir: dir.to_path_buf(),
        namespace: "txindex",
        storage_backend: bitcoin_rs_storage::StorageBackend::RocksDb,
        epoch,
        enabled: IndexCapabilities::default(),
        rollback_rebuild_cutover: 0,
        canonical_data_root: dir.to_path_buf(),
        bundle: crate::portable::IndexBundleDirective::None,
        facts_rx: None,
        facts_charge: None,
        query_charge: None,
        facts_gap: None,
        cpu: None,
        open_store: Arc::new(move |dir| {
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(dir, 8 * 1024 * 1024)
                    .map_err(DerivedIndexWorkerError::Storage)?,
            );
            open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, epoch)
        }),
    }
}

struct WorkerInputs {
    runtime: Arc<DerivedIndexRuntime>,
    spec: DerivedIndexOpenSpec,
    lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: Generation,
    applied_tip: Arc<arc_swap::ArcSwapOption<bitcoin_rs_execution::chain::TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    shutdown: bitcoin_rs_consensus::latch::LatchWriter,
    wake_rx: Receiver<()>,
    chain_events: Arc<dyn crate::reconcile::ChainCursorSource>,
}

fn build_worker_inputs(dir: &std::path::Path, epoch: u64) -> WorkerInputs {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let spec = test_open_spec(dir, epoch);
    let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
    let generation = Generation::new(epoch);
    let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    let chain_events = Arc::new(TestChainCursor);

    WorkerInputs {
        runtime,
        spec,
        lifecycle,
        generation,
        applied_tip,
        block_tree,
        shutdown,
        wake_rx,
        chain_events,
    }
}

#[test]
fn blocked_open_abandonment_detaches_and_poisons() {
    struct DropProbe(crossbeam_channel::Sender<()>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("txindex");

    let (open_tx, open_rx) = crossbeam_channel::bounded::<()>(0);
    let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
    let mut inputs = build_worker_inputs(dir.path(), 42);
    let store_dir_clone = store_dir.clone();
    inputs.spec.open_store = Arc::new(move |_| {
        let _ = open_rx.recv();
        let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DropProbe(dropped_tx.clone()));
        let store = Arc::new(
            bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir_clone, 8 * 1024 * 1024)
                .map(|s| s.guarded_by(guard))
                .map_err(DerivedIndexWorkerError::Storage)?,
        );
        open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 42)
    });
    let mut worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        None,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
        None,
        bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
            bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
        ),
        None,
        Arc::clone(&inputs.chain_events),
        RecordedIndexAhead::new(),
        inputs.shutdown.reader(),
        inputs.wake_rx,
    )
    .expect("spawn");

    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        !worker.is_finished(),
        "worker should still be blocked on open"
    );

    let deadline = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();
    while std::time::Instant::now() < start + deadline {
        if worker.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        !worker.is_finished(),
        "worker must still be blocked past deadline"
    );

    worker.generation.revoke();
    inputs
        .lifecycle
        .store(Arc::new(DerivedIndexLifecycle::ShutdownAbandoned));
    worker.poison_namespace();
    worker.detach();

    assert!(
        start.elapsed() < deadline + std::time::Duration::from_secs(5),
        "abandonment must be bounded"
    );
    assert!(worker.generation.is_revoked());
    assert!(matches!(
        **inputs.lifecycle.load(),
        DerivedIndexLifecycle::ShutdownAbandoned
    ));

    let namespace_key = dir.path().join("txindex");
    assert!(NAMESPACE_REGISTRY.is_poisoned(&namespace_key));
    assert!(!NAMESPACE_REGISTRY.claim(namespace_key, 999));
    drop(worker);

    inputs.runtime.request_shutdown();
    inputs.shutdown.trigger();
    drop(open_tx);

    dropped_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("detached helper store must drop before tempdir cleanup");
}

#[test]
fn shutdown_during_open_joins_helper_releases_lock_and_leaves_namespace_reusable() {
    struct DropProbe(crossbeam_channel::Sender<()>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("txindex");

    let (opened_tx, opened_rx) = crossbeam_channel::bounded::<()>(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
    let mut inputs = build_worker_inputs(dir.path(), 43);
    let store_dir_clone = store_dir.clone();
    inputs.spec.open_store = Arc::new(move |_| {
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

    let worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        None,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
        None,
        bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
            bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
        ),
        None,
        Arc::clone(&inputs.chain_events),
        RecordedIndexAhead::new(),
        inputs.shutdown.reader(),
        inputs.wake_rx,
    )
    .expect("spawn");

    opened_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("open thread opened store and held native lock");
    assert!(
        !worker.is_finished(),
        "worker should still be blocked on open"
    );

    inputs.shutdown.trigger();
    release_tx.send(()).expect("release helper");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "shutdown during open must exit the supervisor promptly"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let open_abandoned = worker.open_was_abandoned();
    worker.join();

    dropped_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("store must drop before assertions");

    assert!(
        !open_abandoned,
        "open must not be reported as abandoned when helper completes"
    );
    let namespace_key = dir.path().join("txindex");
    assert!(
        !NAMESPACE_REGISTRY.is_poisoned(&namespace_key),
        "namespace must not be poisoned when helper completes cleanly"
    );
    assert!(
        NAMESPACE_REGISTRY.claim(namespace_key.clone(), 999),
        "namespace must be claimable after clean shutdown"
    );
    NAMESPACE_REGISTRY.release(&namespace_key, 999);

    let second_open =
        bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir, 8 * 1024 * 1024);
    assert!(
        second_open.is_ok(),
        "second RocksDbStore open must succeed, proving native lock released: {:?}",
        second_open.as_ref().err()
    );
}

#[test]
fn stalled_open_at_shutdown_deadline_yields_poison_and_safely_cleans_up() {
    struct DropProbe(crossbeam_channel::Sender<()>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("txindex");

    let (opened_tx, opened_rx) = crossbeam_channel::bounded::<()>(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
    let mut inputs = build_worker_inputs(dir.path(), 44);
    let store_dir_clone = store_dir.clone();
    inputs.spec.open_store = Arc::new(move |_| {
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

    let mut worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        None,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
        None,
        bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
            bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
        ),
        None,
        Arc::clone(&inputs.chain_events),
        RecordedIndexAhead::new(),
        inputs.shutdown.reader(),
        inputs.wake_rx,
    )
    .expect("spawn");

    opened_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("open thread opened store and held native lock");
    assert!(
        !worker.is_finished(),
        "worker should still be blocked on open"
    );

    inputs.runtime.request_shutdown();
    inputs.shutdown.trigger();

    let deadline = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();
    while std::time::Instant::now() < start + deadline {
        if worker.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        !worker.is_finished(),
        "worker must still be blocked past deadline while helper is stalled"
    );

    worker.generation.revoke();
    inputs
        .lifecycle
        .store(Arc::new(DerivedIndexLifecycle::ShutdownAbandoned));
    worker.poison_namespace();
    worker.detach();

    let namespace_key = dir.path().join("txindex");
    assert!(
        NAMESPACE_REGISTRY.is_poisoned(&namespace_key),
        "namespace must be poisoned on deadline abandonment"
    );

    let second_open =
        bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir, 8 * 1024 * 1024);
    assert!(
        second_open.is_err(),
        "second open must fail while stalled helper still holds native lock"
    );

    release_tx.send(()).expect("release stalled helper");
    dropped_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("helper store must drop before tempdir cleanup");
}

#[test]
fn open_timeout_publishes_error_not_infinite_spin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
    let mut spec = test_open_spec(dir.path(), 1);
    spec.open_store = Arc::new(move |_dir| {
        std::thread::sleep(Duration::from_secs(10));
        Err(DerivedIndexWorkerError::Stopped)
    });
    let result = open_derived_index_with_timeout(
        &spec,
        &dir.path().join("txindex"),
        Duration::from_secs(1),
        &shutdown.reader(),
        || false,
    );

    let Err(DerivedIndexWorkerError::OpenTimeout { secs }) = result else {
        panic!("expected OpenTimeout, got a different error variant");
    };
    assert_eq!(secs, 1);
}

#[test]
fn caught_up_idle_worker_wakes_on_shutdown_latch_and_joins_promptly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inputs = build_worker_inputs(dir.path(), 45);
    let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
    let mut worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        None,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
        None,
        bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
            bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
        ),
        None,
        Arc::clone(&inputs.chain_events),
        RecordedIndexAhead::new(),
        shutdown_writer.reader(),
        inputs.wake_rx,
    )
    .expect("spawn");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !matches!(**inputs.lifecycle.load(), DerivedIndexLifecycle::Serving(_)) {
        assert!(
            std::time::Instant::now() < deadline,
            "worker must enter serving state"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    shutdown_writer.trigger();

    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let join_thread = std::thread::spawn(move || {
        let handle = worker.join_handle.take().expect("handle");
        let _ = handle.join();
        let _ = done_tx.send(());
    });

    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok(),
        "worker thread must join within deadline on latch trigger"
    );
    assert!(join_thread.join().is_ok());
}

#[test]
fn revision_quiet_cancellation_wakes_and_joins_promptly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inputs = build_worker_inputs(dir.path(), 46);
    let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
    let store = Arc::new(
        bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), 8 * 1024 * 1024)
            .expect("store"),
    );
    let open = open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 46).expect("open");
    let writer = open.writer;
    let worker = Worker {
        runtime: Arc::clone(&inputs.runtime),
        writer,
        applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
            &inputs.block_tree,
        )),
        body_store: None,
        history: bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
            bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
        ),
        batch_limits: DEFAULT_BATCH_LIMITS,
        enabled: IndexCapabilities::default(),
        chain_events: Arc::new(TestChainCursor),
        reporter: RecordedIndexAhead::new(),
        shutdown: shutdown_writer.reader(),
        wake_rx: inputs.wake_rx,
        quiet_period: Duration::from_secs(30),
        batch_delay: Duration::ZERO,
        rollback_rebuild_cutover: 0,
        seed_history_lease: parking_lot::Mutex::new(None),
        facts_rx: None,
        facts_charge: None,
        facts_gap: None,
        cpu: None,
        buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
    };

    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let join_thread = std::thread::spawn(move || {
        let result = worker.wait_for_revision_quiet(0);
        let _ = done_tx.send(result);
    });

    std::thread::sleep(Duration::from_millis(20));
    shutdown_writer.trigger();

    let result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("must exit within 5 s deadline");
    assert_eq!(result, None);
    assert!(join_thread.join().is_ok());
}

#[test]
fn batch_deadline_cancellation_wakes_and_joins_promptly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inputs = build_worker_inputs(dir.path(), 47);
    let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
    let store = Arc::new(
        bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), 8 * 1024 * 1024)
            .expect("store"),
    );
    let open = open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 47).expect("open");
    let writer = open.writer;
    let worker = Worker {
        runtime: Arc::clone(&inputs.runtime),
        writer,
        applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
            &inputs.block_tree,
        )),
        body_store: None,
        history: bitcoin_rs_storage::pruning::HistoryAccess::new(
            Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
            bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
        ),
        batch_limits: DEFAULT_BATCH_LIMITS,
        enabled: IndexCapabilities::default(),
        chain_events: Arc::new(TestChainCursor),
        reporter: RecordedIndexAhead::new(),
        shutdown: shutdown_writer.reader(),
        wake_rx: inputs.wake_rx,
        quiet_period: Duration::from_secs(30),
        batch_delay: Duration::ZERO,
        rollback_rebuild_cutover: 0,
        seed_history_lease: parking_lot::Mutex::new(None),
        facts_rx: None,
        facts_charge: None,
        facts_gap: None,
        cpu: None,
        buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
    };

    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let join_thread = std::thread::spawn(move || {
        let result =
            worker.wait_for_batch_deadline(std::time::Instant::now() + Duration::from_secs(30));
        let _ = done_tx.send(result);
    });

    std::thread::sleep(Duration::from_millis(20));
    shutdown_writer.trigger();

    let result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("must exit within 5 s deadline");
    assert_eq!(result, super::catch_up::BatchWait::Stopped);
    assert!(join_thread.join().is_ok());
}
