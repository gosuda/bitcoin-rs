#![expect(
    clippy::expect_used,
    reason = "test: integration tests use expect for clarity"
)]

use super::namespace::NAMESPACE_REGISTRY;
use super::*;
use crate::block_log::BlockLog;
use arc_swap::ArcSwap;
use bitcoin_rs_chain::BlockTree;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn test_open_spec(dir: &std::path::Path, epoch: u64) -> DerivedIndexOpenSpec {
    DerivedIndexOpenSpec {
        data_dir: dir.to_path_buf(),
        namespace: "txindex",
        storage_backend: bitcoin_rs_storage::StorageBackend::Fjall,
        epoch,
        enabled: IndexCapabilities::default(),
        rollback_rebuild_cutover: 0,
        canonical_data_root: dir.to_path_buf(),
        utxo: None,
        chain_transition: None,
        open_store: Arc::new(move |dir| {
            let store = Arc::new(
                bitcoin_rs_storage::FjallStore::open_with_cache(dir, 8 * 1024 * 1024)
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
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    shutdown: Arc<AtomicBool>,
    wake_rx: Receiver<()>,
    block_source: IndexBlockSource,
    chain_events: Arc<dyn crate::reconcile::ChainCursorSource>,
}

fn build_worker_inputs(dir: &std::path::Path, epoch: u64) -> WorkerInputs {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let spec = test_open_spec(dir, epoch);
    let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
    let generation = Generation::new(epoch);
    let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let blocks = Arc::new(RwLock::new(BlockLog::new()));
    let block_source = IndexBlockSource::new(blocks);
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
        block_source,
        chain_events,
    }
}

#[test]
fn blocked_open_abandonment_detaches_and_poisons() {
    let dir = tempfile::tempdir().expect("tempdir");

    let (open_tx, open_rx) = crossbeam_channel::bounded::<()>(0);
    let mut inputs = build_worker_inputs(dir.path(), 42);
    let open_store = Arc::clone(&inputs.spec.open_store);
    inputs.spec.open_store = Arc::new(move |dir| {
        let _ = open_rx.recv();
        open_store(dir)
    });

    let mut worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        Arc::clone(&inputs.applied_tip),
        Arc::clone(&inputs.block_tree),
        None,
        inputs.block_source,
        None,
        Arc::clone(&inputs.chain_events),
        RecordedIndexAhead::new(),
        Arc::clone(&inputs.shutdown),
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

    if let Some(token) = &worker.generation {
        token.revoke();
    }
    inputs
        .lifecycle
        .store(Arc::new(DerivedIndexLifecycle::ShutdownAbandoned));
    worker.poison_namespace();
    worker.detach();

    assert!(
        start.elapsed() < deadline + std::time::Duration::from_secs(5),
        "abandonment must be bounded"
    );
    assert!(
        worker
            .generation
            .as_ref()
            .is_some_and(Generation::is_revoked)
    );
    assert!(matches!(
        **inputs.lifecycle.load(),
        DerivedIndexLifecycle::ShutdownAbandoned
    ));

    let namespace_key = dir.path().join("txindex");
    assert!(NAMESPACE_REGISTRY.is_poisoned(&namespace_key));
    assert!(!NAMESPACE_REGISTRY.claim(namespace_key, 999));
    drop(worker);

    inputs.runtime.request_shutdown();
    inputs.shutdown.store(true, Ordering::Release);
    drop(open_tx);
}

/// An interrupted open detaches the backend open thread: the supervisor
/// still exits, so `open_was_abandoned` is the caller's only signal that a
/// detached thread may still touch the store.
#[test]
fn shutdown_during_open_reports_abandonment_after_supervisor_exit() {
    let dir = tempfile::tempdir().expect("tempdir");

    let (open_tx, open_rx) = crossbeam_channel::bounded::<()>(0);
    let (entered_tx, entered_rx) = crossbeam_channel::bounded::<()>(0);
    let (opened_tx, opened_rx) = crossbeam_channel::bounded::<()>(0);
    let mut inputs = build_worker_inputs(dir.path(), 43);
    let open_store = Arc::clone(&inputs.spec.open_store);
    inputs.spec.open_store = Arc::new(move |dir| {
        let _ = entered_tx.send(());
        let _ = open_rx.recv();
        let result = open_store(dir);
        let _ = opened_tx.send(());
        result
    });

    let worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        Arc::clone(&inputs.applied_tip),
        Arc::clone(&inputs.block_tree),
        None,
        inputs.block_source,
        None,
        Arc::clone(&inputs.chain_events),
        RecordedIndexAhead::new(),
        Arc::clone(&inputs.shutdown),
        inputs.wake_rx,
    )
    .expect("spawn");

    // Entry is signaled from inside `open_store`, so the shutdown below lands
    // on the abandoned-open path rather than the pre-spawn stop check.
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("open thread entered open_store");
    assert!(
        !worker.is_finished(),
        "worker should still be blocked on open"
    );

    inputs.shutdown.store(true, Ordering::Release);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "shutdown during open must exit the supervisor promptly"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // The open thread is still parked on `open_rx` here; the worker-local
    // flag records the abandonment durably.
    assert!(worker.open_was_abandoned());
    assert!(NAMESPACE_REGISTRY.is_poisoned(&dir.path().join("txindex")));
    worker.join();

    // Release the parked opener and wait for the detached thread to leave
    // the tempdir before test scope removes it.
    drop(open_tx);
    opened_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("detached open thread finished with the store");
}

#[test]
fn open_timeout_publishes_error_not_infinite_spin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut spec = test_open_spec(dir.path(), 1);
    spec.open_store = Arc::new(move |_dir| {
        std::thread::sleep(Duration::from_secs(10));
        Err(DerivedIndexWorkerError::Stopped)
    });
    let result = open_derived_index_with_timeout(
        &spec,
        &dir.path().join("txindex"),
        Duration::from_secs(1),
        || shutdown.load(Ordering::Acquire),
    );

    let Err(DerivedIndexWorkerError::OpenTimeout { secs }) = result else {
        panic!("expected OpenTimeout, got a different error variant");
    };
    assert_eq!(secs, 1);
}
