//! Supervised index backend opening, failure publication, and worker handoff.

use super::DerivedIndexComposer;
use super::DerivedIndexLifecycle;
use super::DerivedIndexOpenSpec;
use super::DerivedIndexQueryEngine;
use super::DerivedIndexRuntime;
use super::DerivedIndexWorkerError;
use super::FORWARD_BATCH_DELAY;
use super::Generation;
use super::IndexBlockSource;
use super::OpenDerivedIndex;
use super::QueryEngineLive;
use super::REVISION_QUIET_PERIOD;
use super::TXINDEX_OPEN_TIMEOUT;
use super::Worker;
use super::heartbeat::Heartbeat;
use super::namespace::NAMESPACE_REGISTRY;
use super::namespace::NamespaceRegistry;
use super::wait_txindex_open_gate;
use arc_swap::ArcSwap;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::PreparedBatchLimits;
use bitcoin_rs_index::recovery::open_writer;
use bitcoin_rs_index::writer::TxIndexWriter;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use crossbeam_channel::Receiver;
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

/// Worker-owned open: opens the store, constructs writer/reader/engine,
/// publishes lifecycle, and runs reconciliation — all behind one
/// `catch_unwind` boundary that starts before directory creation and includes
/// schema inspection, writer construction, complete query-engine construction,
/// publication, and the initial reconciliation handoff.
///
/// On an ordinary error or panic, publishes `Failed` with a bounded
/// diagnostic and no query, if the generation is still current. If the token
/// was revoked, publishes nothing. Converts panic payloads to bounded text.
#[allow(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::needless_borrow
)]
pub(super) fn run_worker_with_open(
    runtime: &Arc<DerivedIndexRuntime>,
    spec: DerivedIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    block_source: IndexBlockSource,
    body_source: Option<Arc<dyn BlockBodySource>>,
    chain_events: &Arc<crate::state::ChainEventPublisher>,
    reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
    shutdown: &Arc<AtomicBool>,
    wake_rx: &Receiver<()>,
) {
    let namespace_key =
        match NamespaceRegistry::validate_child(&spec.canonical_data_root, spec.namespace) {
            Ok(key) => key,
            Err(reason) => {
                fail_worker(runtime, lifecycle, generation, &reason);
                return;
            }
        };
    let registry = &*NAMESPACE_REGISTRY;
    if !registry.claim(namespace_key.clone(), generation.id()) {
        let reason = if registry.is_poisoned(&namespace_key) {
            "txindex namespace is poisoned from a previous abandoned open"
        } else {
            "txindex namespace is already active in this process"
        };
        fail_worker(runtime, lifecycle, generation, reason);
        return;
    }

    let heartbeat = Heartbeat::start(
        "txindex",
        spec.namespace.to_owned(),
        spec.storage_backend.to_string(),
    );

    let worker_result = open_and_run(
        runtime,
        &spec,
        lifecycle,
        generation,
        &applied_tip,
        &block_tree,
        &body_store,
        &block_source,
        &body_source,
        chain_events,
        reporter,
        shutdown,
        wake_rx,
    );

    heartbeat.stop_and_join();

    finish_worker(
        runtime,
        lifecycle,
        generation,
        &namespace_key,
        worker_result,
    );
}

/// Report the terminal outcome before releasing its namespace claim.
/// An abandoned backend may still touch the store, so its claim must stay
/// poisoned for the process lifetime (`IDX-07`).
fn finish_worker(
    runtime: &DerivedIndexRuntime,
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    namespace_key: &Path,
    result: Result<(), DerivedIndexWorkerError>,
) {
    let registry = &*NAMESPACE_REGISTRY;
    if let Err(error) = result {
        if error.abandoned_open() {
            registry.poison(namespace_key, generation.id());
        }
        tracing::error!(%error, "txindex worker open or run failed");
        fail_worker(runtime, lifecycle, generation, &error.to_string());
    }
    // Release is generation-checked and never removes a poisoned claim.
    registry.release(namespace_key, generation.id());
}

/// Fails the worker as one unit: the runtime stops the loop and gates the
/// query engine, and the lifecycle withdraws the query payload so the
/// adapter answers typed `Unavailable`. The lifecycle write is skipped for a
/// revoked generation; the runtime write is unconditional because the
/// runtime belongs to this worker alone.
pub(super) fn fail_worker(
    runtime: &DerivedIndexRuntime,
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    reason: &str,
) {
    runtime.publish_failed(reason);
    publish_lifecycle(
        lifecycle,
        generation,
        DerivedIndexLifecycle::Failed(reason.into()),
    );
}

/// Publishes a lifecycle transition with generation-checked `rcu`.
/// A stale token returns the current `Arc` unchanged.
pub(super) fn publish_lifecycle(
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    new: DerivedIndexLifecycle,
) {
    if generation.is_revoked() {
        return;
    }
    let new = Arc::new(new);
    lifecycle.rcu(|current| {
        if generation.is_revoked() {
            Arc::clone(current)
        } else {
            Arc::clone(&new)
        }
    });
}

/// Opens the store, constructs the engine, publishes lifecycle, and runs.
#[allow(clippy::too_many_arguments, clippy::ref_option)]
pub(super) fn open_and_run(
    runtime: &Arc<DerivedIndexRuntime>,
    spec: &DerivedIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    applied_tip: &Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: &Arc<RwLock<BlockTree>>,
    body_store: &Option<Arc<dyn BlockBodyStore>>,
    block_source: &IndexBlockSource,
    body_source: &Option<Arc<dyn BlockBodySource>>,
    chain_events: &Arc<crate::state::ChainEventPublisher>,
    reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
    shutdown: &Arc<AtomicBool>,
    wake_rx: &Receiver<()>,
) -> Result<(), DerivedIndexWorkerError> {
    // Wait for the test-only open gate before touching the store.
    wait_txindex_open_gate();

    let txindex_dir = spec.data_dir.join(spec.namespace);
    std::fs::create_dir_all(&txindex_dir)
        .map_err(|e| DerivedIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let open: OpenDerivedIndex = open_derived_index_with_timeout(
        spec.storage_backend,
        &txindex_dir,
        spec.cache_bytes,
        spec.epoch,
        Duration::ZERO,
        TXINDEX_OPEN_TIMEOUT,
        || shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop(),
    )?;

    // Check shutdown and generation immediately after backend open returns.
    if shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop() {
        // Drop all store values (open.writer, open.reader) and exit without
        // publication or reconciliation.
        return Ok(());
    }

    let query_engine = Arc::new(DerivedIndexQueryEngine::new(
        Arc::clone(runtime),
        open.reader,
        block_source.clone(),
        Arc::clone(block_tree),
        Arc::clone(applied_tip),
        body_source.clone(),
        QueryEngineLive {
            utxo: spec.utxo.clone(),
            chain_transition: spec.chain_transition.clone(),
            enabled: spec.enabled,
        },
    ));

    // Publish the complete engine atomically; readiness is proven per query.
    publish_lifecycle(
        lifecycle,
        generation,
        DerivedIndexLifecycle::Serving(query_engine),
    );

    // Check shutdown immediately after publication.
    if shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop() {
        return Ok(());
    }

    let worker = Worker {
        runtime: Arc::clone(runtime),
        writer: open.writer,
        applied_tip: Arc::clone(applied_tip),
        block_tree: Arc::clone(block_tree),
        body_store: body_store.clone(),
        batch_limits: open.batch_limits,
        enabled: spec.enabled,
        rollback_rebuild_cutover: spec.rollback_rebuild_cutover,
        wake_rx: wake_rx.clone(),
        quiet_period: REVISION_QUIET_PERIOD,
        chain_events: Arc::clone(chain_events),
        reporter,
        batch_delay: FORWARD_BATCH_DELAY,
        utxo: spec.utxo.clone(),
        chain_transition: spec.chain_transition.clone(),
    };

    worker.run()
}

/// Opens the txindex store with a bounded deadline.
///
/// The storage engine open (fjall/lsm-tree recovery, rocksdb column-family
/// open) can wedge on a large or partially-corrupted store, spinning one
/// thread at 100% CPU indefinitely. This wrapper runs the open on a helper
/// thread and waits with [`TXINDEX_OPEN_TIMEOUT`]. If the deadline fires, the
/// helper thread is detached (it may eventually finish or hang — we cannot
/// kill a thread) and `OpenTimeout` is returned so the worker publishes
/// `Failed` and the node stays operable without the index.
pub(super) fn open_derived_index_with_timeout(
    storage_backend: bitcoin_rs_storage::StorageBackend,
    txindex_dir: &Path,
    cache_bytes: u64,
    epoch: u64,
    open_delay: Duration,
    open_timeout: Duration,
    should_stop: impl Fn() -> bool,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    // No helper exists yet: cancellation here can release the namespace.
    if should_stop() {
        return Err(DerivedIndexWorkerError::Stopped);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let backend = storage_backend;
    let dir = txindex_dir.to_path_buf();
    let _join = thread::Builder::new()
        .name("bitcoin-rs-txindex-open".to_owned())
        .spawn(move || {
            let result =
                open_derived_index_on_worker(backend, &dir, cache_bytes, epoch, open_delay);
            let _ = tx.send(result);
        })
        .map_err(|e| DerivedIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let result = open_wait::wait_for_open_result(&rx, open_timeout, should_stop);
    if matches!(&result, Err(DerivedIndexWorkerError::OpenTimeout { .. })) {
        tracing::error!(
            timeout_secs = open_timeout.as_secs(),
            backend = %storage_backend,
            dir = %txindex_dir.display(),
            "txindex store open timed out; detaching the open helper and poisoning its namespace"
        );
    }
    result
}

/// Opens the txindex store on the worker thread through the namespace's single
/// runtime composition owner.
pub(super) fn open_derived_index_on_worker(
    storage_backend: bitcoin_rs_storage::StorageBackend,
    txindex_dir: &Path,
    cache_bytes: u64,
    epoch: u64,
    open_delay: Duration,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    if !open_delay.is_zero() {
        std::thread::sleep(open_delay);
    }
    crate::storage_backend::open_txindex(
        storage_backend,
        txindex_dir,
        Some(cache_bytes),
        DerivedIndexComposer {
            backend: storage_backend,
            epoch,
        },
    )
}

/// Constructs the writer and reader from the opened store.
pub(super) fn open_derived_index_store_on_worker<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    let writer = open_writer(&store, epoch)?;
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(writer));
    let reader: Arc<dyn bitcoin_rs_index::IndexReader> =
        Arc::new(bitcoin_rs_index::Indexer::new(store));
    Ok(OpenDerivedIndex {
        writer,
        reader,
        batch_limits,
    })
}

mod open_wait;

#[cfg(test)]
mod tests;
