#![expect(
    clippy::expect_used,
    reason = "test: supervisor tests use expect for clarity"
)]

use super::namespace::NAMESPACE_REGISTRY;
use super::*;
use arc_swap::ArcSwap;
use bitcoin_rs_chain::BlockTree;
use std::sync::Arc;

fn test_open_spec(dir: &std::path::Path, epoch: u64) -> DerivedIndexOpenSpec {
    DerivedIndexOpenSpec {
        scripthash_limit: crate::runtime::DEFAULT_SCRIPTHASH_LIMIT,
        data_dir: dir.to_path_buf(),
        namespace: "txindex",
        storage_backend: bitcoin_rs_storage::StorageBackend::Fjall,
        epoch,
        enabled: IndexCapabilities::default(),
        rollback_rebuild_cutover: 0,
        canonical_data_root: dir.to_path_buf(),
        utxo: None,
        chain_transition: None,
        bundle: crate::portable::IndexBundleDirective::None,
        seed_slot: None,
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
    shutdown: bitcoin_rs_chain::LatchWriter,
    wake_rx: Receiver<()>,
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
    let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
        bitcoin_rs_chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
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
}

#[test]
fn shutdown_during_open_reports_abandonment_after_supervisor_exit() {
    let dir = tempfile::tempdir().expect("tempdir");

    let (open_tx, open_rx) = crossbeam_channel::bounded::<()>(0);
    let (entered_tx, entered_rx) = crossbeam_channel::bounded::<()>(0);
    let mut inputs = build_worker_inputs(dir.path(), 43);
    let open_store = Arc::clone(&inputs.spec.open_store);
    inputs.spec.open_store = Arc::new(move |dir| {
        let _ = entered_tx.send(());
        let _ = open_rx.recv();
        open_store(dir)
    });

    let worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        bitcoin_rs_chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
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

    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("open thread entered open_store");
    assert!(
        !worker.is_finished(),
        "worker should still be blocked on open"
    );

    inputs.shutdown.trigger();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "shutdown during open must exit the supervisor promptly"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(worker.open_was_abandoned());
    assert!(NAMESPACE_REGISTRY.is_poisoned(&dir.path().join("txindex")));
    worker.join();

    std::mem::forget(open_tx);
}

#[test]
fn open_timeout_publishes_error_not_infinite_spin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
    let shutdown_writer = bitcoin_rs_chain::LatchWriter::new();
    let mut worker = DerivedIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        inputs.spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        bitcoin_rs_chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
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

// IDX-05, SYNC-03, SYNC-05
#[test]
fn incompatible_populated_index_reopens_without_writing_obsolete_rows()
-> Result<(), DerivedIndexWorkerError> {
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PersistFault};
    use std::sync::atomic::{AtomicUsize, Ordering};

    for marker in [Some(5_u32), None, Some(6_u32)] {
        let dir = tempfile::tempdir()?;
        let index_dir = dir.path().join("txindex");
        let sibling = dir.path().join("chainstate-evidence");
        std::fs::write(&sibling, b"authoritative bytes")?;
        {
            let store = bitcoin_rs_storage::FjallStore::open(&index_dir)?;
            let mut batch = store.new_batch();
            for family in [
                ColumnFamily::TxConfirmed,
                ColumnFamily::Funding,
                ColumnFamily::Spending,
                ColumnFamily::ScriptLive,
            ] {
                for index in 0..32_000_u32 {
                    batch.put(family, &index.to_be_bytes(), &[0xa5; 16]);
                }
            }
            if let Some(marker) = marker {
                batch.put(ColumnFamily::UtxoMeta, &[0, b'V'], &marker.to_le_bytes());
                if marker == 6 {
                    let mut claim = vec![0b1111];
                    claim.extend_from_slice(&1_u64.to_le_bytes());
                    claim.extend_from_slice(&0_u64.to_le_bytes());
                    batch.put(ColumnFamily::UtxoMeta, &[0, b'R'], &claim);
                }
            }
            store.write_durable(batch)?;
        }
        let obsolete_file = index_dir.join("obsolete-layout");
        std::fs::write(&obsolete_file, b"obsolete")?;
        let mut inputs = build_worker_inputs(dir.path(), 1780);
        let opens = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&opens);
        inputs.spec.open_store = Arc::new(move |path| {
            let attempt = observed.fetch_add(1, Ordering::SeqCst);
            let store = Arc::new(bitcoin_rs_storage::FjallStore::open(path)?);
            if attempt == 0 {
                store.arm_persist_fault(PersistFault::FailApply);
            } else {
                for family in [
                    ColumnFamily::TxConfirmed,
                    ColumnFamily::Funding,
                    ColumnFamily::Spending,
                    ColumnFamily::ScriptLive,
                ] {
                    assert!(store.iter_prefix(family, &[])?.next().is_none());
                }
            }
            open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 1780)
        });
        let worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&inputs.runtime),
            inputs.spec,
            Arc::clone(&inputs.lifecycle),
            inputs.generation.clone(),
            bitcoin_rs_chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
            bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
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
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while matches!(**inputs.lifecycle.load(), DerivedIndexLifecycle::Opening)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let serving = matches!(**inputs.lifecycle.load(), DerivedIndexLifecycle::Serving(_));
        inputs.shutdown.trigger();
        worker.join();
        assert!(
            serving,
            "obsolete rows must not be deleted through durable writes"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 2);
        assert!(!obsolete_file.exists());
        assert_eq!(std::fs::read(&sibling)?, b"authoritative bytes");
        assert!(!NAMESPACE_REGISTRY.is_poisoned(&index_dir));
    }
    Ok(())
}

#[test]
fn revision_quiet_cancellation_wakes_and_joins_promptly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inputs = build_worker_inputs(dir.path(), 46);
    let shutdown_writer = bitcoin_rs_chain::LatchWriter::new();
    let store = Arc::new(
        bitcoin_rs_storage::FjallStore::open_with_cache(dir.path(), 8 * 1024 * 1024)
            .expect("store"),
    );
    let open = open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 46).expect("open");
    let writer = open.writer;
    let worker = Worker {
        runtime: Arc::clone(&inputs.runtime),
        writer,
        applied_tip: bitcoin_rs_chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        block_tree: bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
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
        seed_slot: None,
        seed_bundle: parking_lot::Mutex::new(None),
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
    let shutdown_writer = bitcoin_rs_chain::LatchWriter::new();
    let store = Arc::new(
        bitcoin_rs_storage::FjallStore::open_with_cache(dir.path(), 8 * 1024 * 1024)
            .expect("store"),
    );
    let open = open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 47).expect("open");
    let writer = open.writer;
    let worker = Worker {
        runtime: Arc::clone(&inputs.runtime),
        writer,
        applied_tip: bitcoin_rs_chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
        block_tree: bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
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
        seed_slot: None,
        seed_bundle: parking_lot::Mutex::new(None),
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
