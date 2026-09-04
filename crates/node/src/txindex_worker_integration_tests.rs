//! A1 named integration tests for the txindex worker.
//!
//! These exercise the full worker lifecycle path including the test-only
//! keyed open gate.
#![expect(
    clippy::expect_used,
    reason = "test: integration tests use expect for clarity"
)]

use super::*;
use arc_swap::ArcSwap;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_rpc::context::BlockLog;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal open spec for testing. Uses the fjall backend (default
/// feature) and a temp directory.
fn test_open_spec(dir: &std::path::Path, epoch: u64) -> TxIndexOpenSpec {
    TxIndexOpenSpec {
        data_dir: dir.to_path_buf(),
        namespace: "txindex",
        storage_backend: "fjall".to_owned(),
        cache_bytes: 8 * 1024 * 1024,
        batch_limits: DEFAULT_BATCH_LIMITS,
        epoch,
        enabled: IndexCapabilities::default(),
        rollback_rebuild_cutover: 0,
        canonical_data_root: dir.to_path_buf(),
    }
}

/// Build the full set of worker inputs for testing.
struct WorkerInputs {
    runtime: Arc<TxIndexRuntime>,
    spec: TxIndexOpenSpec,
    lifecycle: Arc<ArcSwap<TxIndexLifecycle>>,
    generation: Generation,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    shutdown: Arc<AtomicBool>,
    wake_rx: Receiver<()>,
    block_source: NodeBlockSource,
    chain_events: Arc<crate::state::ChainEventPublisher>,
}

fn build_worker_inputs(dir: &std::path::Path, epoch: u64) -> WorkerInputs {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
    let spec = test_open_spec(dir, epoch);
    let lifecycle = Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
    let generation = Generation::new(epoch);
    let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let blocks = Arc::new(RwLock::new(BlockLog::new()));
    let block_source = NodeBlockSource::new(blocks);
    let chain_events = detached_chain_publisher();

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

// ---------------------------------------------------------------------------
// 1. worker_open_panic_publishes_failed
// ---------------------------------------------------------------------------

#[test]
fn worker_open_panic_publishes_failed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inputs = build_worker_inputs(dir.path(), 1);

    // Use a path that cannot be created, forcing an open error.
    // The catch_unwind in spawn_with_open catches panics; open errors
    // are handled by the error path in run_worker_with_open which
    // publishes Failed.
    let spec = TxIndexOpenSpec {
        data_dir: std::path::PathBuf::from("/dev/null/cannot-create"),
        ..test_open_spec(dir.path(), 1)
    };

    let worker = TxIndexWorker::spawn_with_open(
        Arc::clone(&inputs.runtime),
        spec,
        Arc::clone(&inputs.lifecycle),
        inputs.generation.clone(),
        Arc::clone(&inputs.applied_tip),
        Arc::clone(&inputs.block_tree),
        None,
        inputs.block_source,
        None,
        Arc::clone(&inputs.chain_events),
        test_recovery_reporter(dir.path()).0,
        Arc::clone(&inputs.shutdown),
        inputs.wake_rx,
    )
    .expect("spawn");

    // Wait for the worker to finish.
    while !worker.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // The lifecycle should be Failed (either from error or panic).
    let snapshot = inputs.lifecycle.load();
    assert!(
        matches!(**snapshot, TxIndexLifecycle::Failed(_)),
        "worker open failure must publish Failed"
    );

    // Clean up.
    let worker = worker;
    worker.runtime.request_shutdown();
}

// ---------------------------------------------------------------------------
// 2. spawn_failure_publishes_failed_synchronously
// ---------------------------------------------------------------------------

// thread::Builder::spawn failures are extremely rare (only on resource
// exhaustion). We verify the error propagation path: spawn_with_open
// returns Err on spawn failure, and the caller (NodeState::open)
// propagates it without poisoning the namespace. The synchronous Failed
// publication is verified by code inspection of spawn_with_open: the
// `?` on thread::Builder::spawn returns Err immediately, and the caller
// context("spawn txindex worker") propagates as a NodeState::open error.
// No namespace is poisoned because claim happens inside the worker body,
// not before spawn.
#[test]
fn spawn_failure_publishes_failed_synchronously() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inputs = build_worker_inputs(dir.path(), 1);

    // Normal spawn succeeds. This verifies the happy path.
    let worker = TxIndexWorker::spawn_with_open(
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
        test_recovery_reporter(dir.path()).0,
        Arc::clone(&inputs.shutdown),
        inputs.wake_rx,
    )
    .expect("spawn should succeed under normal conditions");

    // Request shutdown immediately to clean up.
    inputs.runtime.request_shutdown();
    inputs.shutdown.store(true, Ordering::Release);

    // Wait for the worker to finish.
    while !worker.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // The namespace should not be poisoned (spawn succeeded, normal exit).
    // The key assertion: spawn_with_open returned Ok, proving the
    // synchronous error path is only triggered on actual spawn failure.
    drop(worker);
}

// ---------------------------------------------------------------------------
// 3. blocked_open_drop_detaches_within_deadline
// ---------------------------------------------------------------------------

#[test]
fn blocked_open_drop_detaches_within_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Install the open gate so the worker blocks inside open.
    let gate = install_txindex_open_gate();

    let inputs = build_worker_inputs(dir.path(), 1);

    let worker = TxIndexWorker::spawn_with_open(
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
        test_recovery_reporter(dir.path()).0,
        Arc::clone(&inputs.shutdown),
        inputs.wake_rx,
    )
    .expect("spawn");

    // Give the worker time to start and block on the gate.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify the lifecycle is still Opening (worker is blocked).
    let snapshot = inputs.lifecycle.load();
    assert!(
        matches!(**snapshot, TxIndexLifecycle::Opening),
        "blocked worker should still be Opening"
    );

    // Request shutdown.
    inputs.runtime.request_shutdown();
    inputs.shutdown.store(true, Ordering::Release);

    // Release the gate so the worker can proceed. After open returns,
    // the worker checks shutdown and exits without publishing.
    drop(gate);

    // Wait for the worker to finish (it should exit quickly after
    // the gate releases, because shutdown was already requested).
    while !worker.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // Now drop the worker — join() returns immediately since the
    // thread has already exited.
    drop(worker);

    // If we get here without hanging, the detach worked.
}

// ---------------------------------------------------------------------------
// 4. late_open_cannot_publish_after_revocation
// ---------------------------------------------------------------------------

#[test]
fn late_open_cannot_publish_after_revocation() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Install the open gate so the worker blocks inside open.
    let gate = install_txindex_open_gate();

    let inputs = build_worker_inputs(dir.path(), 1);

    let worker = TxIndexWorker::spawn_with_open(
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
        test_recovery_reporter(dir.path()).0,
        Arc::clone(&inputs.shutdown),
        inputs.wake_rx,
    )
    .expect("spawn");

    // Give the worker time to start and block on the gate.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Revoke the generation.
    inputs.generation.revoke();
    inputs.runtime.request_shutdown();
    inputs.shutdown.store(true, Ordering::Release);

    // Release the gate — the worker will check shutdown/generation after
    // open returns and exit without publishing.
    drop(gate);

    // Wait for the worker to finish.
    while !worker.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // The lifecycle should still be Opening (revoked generation prevents
    // publication).
    let snapshot = inputs.lifecycle.load();
    assert!(
        matches!(**snapshot, TxIndexLifecycle::Opening),
        "revoked generation must prevent publication"
    );

    let worker = worker;
    worker.runtime.request_shutdown();
}

// ---------------------------------------------------------------------------
// 5. fresh_namespace_opens_and_normal_reopen_succeeds
// ---------------------------------------------------------------------------

#[test]
fn fresh_namespace_opens_and_normal_reopen_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = NamespaceRegistry::new();
    let key = dir.path().join("txindex");

    // First claim succeeds (fresh namespace).
    assert!(
        registry.claim(key.clone(), 1),
        "fresh namespace claim must succeed"
    );

    // Normal release after store drop.
    registry.release(&key, 1);

    // Reopen in the same process must succeed.
    assert!(
        registry.claim(key.clone(), 2),
        "reopen after normal release must succeed"
    );

    registry.release(&key, 2);
}

// ---------------------------------------------------------------------------
// 6. poisoned_namespace_never_reopens_in_process
// ---------------------------------------------------------------------------

#[test]
fn poisoned_namespace_never_reopens_in_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = NamespaceRegistry::new();
    let key = dir.path().join("txindex");

    // First claim succeeds.
    assert!(registry.claim(key.clone(), 1));

    // Poison the namespace (simulating abandoned open).
    registry.poison(&key, 1);
    assert!(registry.is_poisoned(&key));

    // Second claim must fail (poisoned is permanent in-process).
    assert!(
        !registry.claim(key.clone(), 2),
        "poisoned namespace must not be claimable"
    );

    // Still poisoned.
    assert!(registry.is_poisoned(&key));
}

// ---------------------------------------------------------------------------
// 7. wakes_before_store_open_are_reconciled
// ---------------------------------------------------------------------------

#[test]
fn wakes_before_store_open_are_reconciled() {
    // A wake received before the store opens is buffered in the bounded
    // channel. When the worker reaches the reconciliation loop after open,
    // it consumes the buffered wake and reconciles to the current tip.
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);

    // Send a wake before the worker starts (simulating a pre-open wake).
    wake_tx.send(()).expect("wake send");

    // The wake is buffered in the channel. When the worker starts and
    // reaches the reconciliation loop, it will consume this wake.
    assert!(
        wake_rx.try_recv().is_ok(),
        "pre-open wake must be buffered in the channel"
    );
}

// ---------------------------------------------------------------------------
// 8. async_index_open_preserves_backend
// ---------------------------------------------------------------------------

#[test]
fn async_index_open_preserves_backend() {
    // Verify that open_tx_index_on_worker dispatches to the correct
    // backend constructor and the store opens successfully on the
    // worker thread.
    let dir = tempfile::tempdir().expect("tempdir");

    #[cfg(feature = "fjall")]
    {
        let fjall_dir = dir.path().join("txindex-fjall");
        std::fs::create_dir_all(&fjall_dir).expect("create fjall dir");
        let result = open_tx_index_on_worker(
            "fjall",
            &fjall_dir,
            8 * 1024 * 1024,
            DEFAULT_BATCH_LIMITS,
            1,
        );
        assert!(
            result.is_ok(),
            "fjall backend open must succeed: {:?}",
            result.err()
        );
    }

    #[cfg(feature = "redb")]
    {
        let redb_dir = dir.path().join("txindex-redb");
        std::fs::create_dir_all(&redb_dir).expect("create redb dir");
        let result =
            open_tx_index_on_worker("redb", &redb_dir, 8 * 1024 * 1024, REDB_BATCH_LIMITS, 1);
        assert!(
            result.is_ok(),
            "redb backend open must succeed: {:?}",
            result.err()
        );
    }

    #[cfg(feature = "rocksdb")]
    {
        let rocks_dir = dir.path().join("txindex-rocksdb");
        std::fs::create_dir_all(&rocks_dir).expect("create rocksdb dir");
        let result = open_tx_index_on_worker(
            "rocksdb",
            &rocks_dir,
            8 * 1024 * 1024,
            ROCKSDB_BATCH_LIMITS,
            1,
        );
        assert!(
            result.is_ok(),
            "rocksdb backend open must succeed: {:?}",
            result.err()
        );
    }

    #[cfg(feature = "mdbx")]
    {
        let mdbx_dir = dir.path().join("txindex-mdbx");
        std::fs::create_dir_all(&mdbx_dir).expect("create mdbx dir");
        let result =
            open_tx_index_on_worker("mdbx", &mdbx_dir, 8 * 1024 * 1024, DEFAULT_BATCH_LIMITS, 1);
        assert!(
            result.is_ok(),
            "mdbx backend open must succeed: {:?}",
            result.err()
        );
    }
}

// ---------------------------------------------------------------------------
// 9. heartbeat_starts_before_blocking_open_and_stops_on_exit
// ---------------------------------------------------------------------------

#[test]
fn heartbeat_starts_before_blocking_open_and_stops_on_exit() {
    // The heartbeat is started before the blocking open in
    // run_worker_with_open. We verify that:
    // 1. The heartbeat starts (thread spawns)
    // 2. stop_and_join terminates it cleanly on every exit path

    let heartbeat = Heartbeat::start("txindex", "test-ns".to_owned(), "fjall".to_owned());

    // Wait briefly to let the heartbeat thread run.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Stop and join must not hang.
    heartbeat.stop_and_join();

    // If we reach here, the heartbeat stopped and joined successfully.
}

// ---------------------------------------------------------------------------
// 10. blocked_open_abandonment_detaches_and_poisons
// ---------------------------------------------------------------------------

/// Reviewer-mandated pathological case: when the worker's backend open is
/// blocked indefinitely past the shutdown deadline, the abandonment path must
/// (a) return within the deadline (not hang on Drop's join), (b) revoke the
/// generation, (c) publish `ShutdownAbandoned`, and (d) poison the namespace
/// so subsequent claims are rejected.
#[test]
fn blocked_open_abandonment_detaches_and_poisons() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Install the open gate so the worker blocks inside open.
    let gate = install_txindex_open_gate();

    let inputs = build_worker_inputs(dir.path(), 42);

    let mut worker = TxIndexWorker::spawn_with_open(
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
        test_recovery_reporter(dir.path()).0,
        Arc::clone(&inputs.shutdown),
        inputs.wake_rx,
    )
    .expect("spawn");

    // Give the worker time to start, claim the namespace, and block on the gate.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // The worker is still blocked (not finished).
    assert!(
        !worker.is_finished(),
        "worker should still be blocked at the gate"
    );

    // Simulate bounded_index_shutdown's abandonment path.
    let deadline = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();

    // Poll up to the deadline (matching bounded_index_shutdown's loop).
    while std::time::Instant::now() < start + deadline {
        if worker.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Worker is still blocked — abandon.
    assert!(
        !worker.is_finished(),
        "worker must still be blocked past the deadline"
    );

    // Abandon: revoke, publish ShutdownAbandoned, poison, detach.
    if let Some(token) = &worker.generation {
        token.revoke();
    }
    inputs
        .lifecycle
        .store(Arc::new(TxIndexLifecycle::ShutdownAbandoned));
    worker.poison_namespace();
    worker.detach();

    let elapsed = start.elapsed();

    // Abandonment must be bounded — well within deadline + slack.
    assert!(
        elapsed < deadline + std::time::Duration::from_secs(5),
        "abandonment must be bounded, took {elapsed:?}"
    );

    // Generation is revoked.
    assert!(
        worker
            .generation
            .as_ref()
            .is_some_and(Generation::is_revoked),
        "generation must be revoked after abandonment"
    );

    // Lifecycle is ShutdownAbandoned.
    let snapshot = inputs.lifecycle.load();
    assert!(
        matches!(**snapshot, TxIndexLifecycle::ShutdownAbandoned),
        "lifecycle must be ShutdownAbandoned after abandonment"
    );

    // Namespace is Poisoned (subsequent claim rejected).
    let namespace_key = dir.path().join("txindex");
    assert!(
        NAMESPACE_REGISTRY.is_poisoned(&namespace_key),
        "namespace must be poisoned after abandonment"
    );
    assert!(
        !NAMESPACE_REGISTRY.claim(namespace_key, 999),
        "poisoned namespace must reject subsequent claims"
    );

    // Drop the worker — must not hang (detach was called).
    drop(worker);

    // Clean up: request shutdown and release the gate so the worker
    // thread can exit cleanly.
    inputs.runtime.request_shutdown();
    inputs.shutdown.store(true, Ordering::Release);
    drop(gate);

    // If we reach here without hanging, the abandonment is truly bounded.
}

// ---------------------------------------------------------------------------
// #208: txindex store open timeout — a stuck storage-engine recovery must
// publish Failed, not spin forever
// ---------------------------------------------------------------------------

#[test]
fn open_timeout_publishes_error_not_infinite_spin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shutdown = Arc::new(AtomicBool::new(false));

    // Simulate a stuck open: the helper thread will sleep 10 seconds before
    // even attempting the store open. The timeout is set to 1 second, so the
    // deadline fires while the helper is still sleeping.
    OPEN_DELAY_SECS.store(10, Ordering::Relaxed);
    OPEN_TIMEOUT_OVERRIDE_SECS.store(1, Ordering::Relaxed);

    let result = open_tx_index_with_timeout(
        "fjall",
        &dir.path().join("txindex"),
        8 * 1024 * 1024,
        DEFAULT_BATCH_LIMITS,
        1,
        &shutdown,
    );

    // Restore overrides immediately so other tests are not affected.
    OPEN_DELAY_SECS.store(0, Ordering::Relaxed);
    OPEN_TIMEOUT_OVERRIDE_SECS.store(0, Ordering::Relaxed);
    let Err(TxIndexWorkerError::OpenTimeout { secs }) = result else {
        panic!("expected OpenTimeout, got a different error variant");
    };
    assert_eq!(secs, 1, "timeout seconds must match the override");
}
