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
