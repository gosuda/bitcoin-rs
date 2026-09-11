//! Supervised index open, namespace ownership, and bounded worker shutdown.

use super::{
    heartbeat::Heartbeat, namespace::NAMESPACE_REGISTRY, namespace::NamespaceRegistry,
    query::QueryEngineLive, query::TxIndexQueryEngine, runtime::TxIndexRuntime,
    source::IndexBlockSource, worker::DEFAULT_BATCH_LIMITS, worker::FORWARD_BATCH_DELAY,
    worker::REDB_BATCH_LIMITS, worker::REVISION_QUIET_PERIOD, worker::ROCKSDB_BATCH_LIMITS,
    worker::TxIndexWorkerError, worker::Worker,
};
use arc_swap::ArcSwap;
use bitcoin_rs_chain::{BlockBodySource, BlockTree, TipSnapshot};
use bitcoin_rs_index::{
    IndexCapabilities, PreparedBatchLimits, recovery::open_writer, writer::TxIndexWriter,
};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use compact_str::CompactString;
use crossbeam_channel::Receiver;
use parking_lot::{Mutex, RwLock};
use std::{
    path::Path, path::PathBuf, sync::Arc, sync::atomic::AtomicBool, sync::atomic::Ordering, thread,
    thread::JoinHandle, time::Duration, time::Instant,
};

/// Monotonic publication token. Each worker holds one; a revoked token makes
/// `rcu` publication a no-op so a late worker cannot publish after abandonment.
#[derive(Clone, Debug)]
pub(crate) struct Generation {
    id: u64,
    revoked: Arc<AtomicBool>,
}

impl Generation {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

/// One immutable lifecycle snapshot published atomically behind `ArcSwap`.
///
/// Only `Serving` carries a query payload — the complete existing
/// `TxIndexQueryEngine`, never a raw reader. Readiness is not a lifecycle
/// state: the engine proves it per query from the durable watermarks
/// (`IDX-03`), and the worker reports its reconciliation leg through
/// `TxIndexRuntime::phase`. `Opening`, `Failed`, and `ShutdownAbandoned`
/// carry no payload; the adapter returns typed `Unavailable` for them.
#[derive(Clone)]
pub(crate) enum TxIndexLifecycle {
    Opening,
    Serving(Arc<TxIndexQueryEngine>),
    Failed(CompactString),
    ShutdownAbandoned,
}

impl TxIndexLifecycle {
    pub(super) fn query_payload(&self) -> Option<&Arc<TxIndexQueryEngine>> {
        match self {
            Self::Serving(engine) => Some(engine),
            _ => None,
        }
    }

    pub(super) fn unavailable_reason(&self) -> &'static str {
        match self {
            Self::Opening => "txindex is opening",
            Self::Failed(_) => "txindex is unavailable",
            Self::ShutdownAbandoned => "txindex was abandoned at shutdown",
            Self::Serving(_) => unreachable!("query_payload is Some for Serving"),
        }
    }
}

/// Immutable specification for worker-owned store open. Constructed
/// synchronously in `NodeState::open`; consumed on the worker thread.
pub(crate) struct TxIndexOpenSpec {
    pub(crate) data_dir: PathBuf,
    pub(crate) namespace: &'static str,
    pub(crate) storage_backend: bitcoin_rs_storage::StorageBackend,
    pub(crate) cache_bytes: u64,
    pub(crate) epoch: u64,
    pub(crate) enabled: IndexCapabilities,
    pub(crate) rollback_rebuild_cutover: u32,
    pub(crate) canonical_data_root: PathBuf,
    /// Authoritative UTXO set used to seed and resolve the compact live view.
    /// Test-only open specs may leave this unset; live queries then fail closed.
    pub(crate) utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    /// Serializes a live-view query or seed against a chain transition.
    pub(crate) chain_transition: Option<Arc<Mutex<()>>>,
}

/// Test-only keyed open gate. Holds the worker inside the open phase until
/// released, proving RPC binds and queries see `Opening` while the store is
/// not yet open. `#[cfg(test)]` only — not a production trait or `NodeConfig` field.
#[cfg(test)]
pub(crate) static TXINDEX_OPEN_GATE: std::sync::LazyLock<
    parking_lot::Mutex<Option<crossbeam_channel::Receiver<()>>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

#[cfg(test)]
pub(crate) fn install_txindex_open_gate() -> crossbeam_channel::Sender<()> {
    let (tx, rx) = crossbeam_channel::bounded(1);
    *TXINDEX_OPEN_GATE.lock() = Some(rx);
    tx
}

#[cfg(test)]
fn wait_txindex_open_gate() {
    if let Some(rx) = TXINDEX_OPEN_GATE.lock().as_ref() {
        let _ = rx.recv();
    }
}

/// Handle used to spawn and join the supervised reconciliation worker.
pub(crate) struct TxIndexWorker {
    runtime: Arc<TxIndexRuntime>,
    join_handle: Option<JoinHandle<()>>,
    pub(crate) generation: Option<Generation>,
    /// Canonical namespace key for poisoning on abandonment.
    namespace_key: Option<PathBuf>,
}

impl TxIndexWorker {
    /// Spawns a worker over an already-open `writer`. Test seam for writer
    /// fakes; production workers open their own store via `spawn_with_open`.
    ///
    /// `wake_rx` must be the receiver paired with the `Sender` used to construct
    /// `runtime`. `chain_events` is the publisher whose snapshot the worker
    /// mirrors into the persisted consumer cursor; its `record` fires at the
    /// same commit point as the wake, so the worker treats the wake channel as
    /// its coalesced hint stream and recovers from dropped wakes by
    /// reconciling fresh snapshots.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        runtime: Arc<TxIndexRuntime>,
        writer: Arc<dyn TxIndexWriter>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        body_store: Option<Arc<dyn BlockBodyStore>>,
        batch_limits: PreparedBatchLimits,
        enabled: IndexCapabilities,
        chain_events: Arc<crate::state::ChainEventPublisher>,
        reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
        rollback_rebuild_cutover: u32,
        wake_rx: Receiver<()>,
    ) -> std::io::Result<Self> {
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            writer,
            applied_tip,
            block_tree,
            body_store,
            batch_limits,
            enabled,
            rollback_rebuild_cutover,
            wake_rx,
            quiet_period: REVISION_QUIET_PERIOD,
            chain_events,
            reporter,
            batch_delay: FORWARD_BATCH_DELAY,
            utxo: None,
            chain_transition: None,
        };
        let runtime_for_error = Arc::clone(&runtime);
        let join_handle = thread::Builder::new()
            .name("bitcoin-rs-txindex".to_owned())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.run()));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(%error, "txindex worker failed");
                        runtime_for_error.publish_failed(error.to_string());
                    }
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("txindex worker panicked");
                        tracing::error!(%message, "txindex worker panicked");
                        runtime_for_error.publish_failed(message);
                    }
                }
            })?;
        Ok(Self {
            runtime,
            join_handle: Some(join_handle),
            generation: None,
            namespace_key: None,
        })
    }

    /// Spawns a worker that opens the store on its own thread, constructs the
    /// complete query engine, publishes lifecycle snapshots, and runs
    /// reconciliation — all behind one `catch_unwind`.
    ///
    /// The `lifecycle` `ArcSwap` is the publication surface: the caller
    /// constructs a stable `TxIndexQueryAdapter` over it before this call.
    /// The `generation` token makes late publication a no-op after
    /// abandonment. The `shutdown` signal is checked immediately after
    /// backend open returns. `reporter` receives the index-ahead rollback
    /// evidence the worker detects against the restored tip.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_with_open(
        runtime: Arc<TxIndexRuntime>,
        spec: TxIndexOpenSpec,
        lifecycle: Arc<ArcSwap<TxIndexLifecycle>>,
        generation: Generation,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        body_store: Option<Arc<dyn BlockBodyStore>>,
        block_source: IndexBlockSource,
        body_source: Option<Arc<dyn BlockBodySource>>,
        chain_events: Arc<crate::state::ChainEventPublisher>,
        reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
        shutdown: Arc<AtomicBool>,
        wake_rx: Receiver<()>,
    ) -> std::io::Result<Self> {
        // Compute the namespace key before moving `spec` into the thread.
        let namespace_key =
            NamespaceRegistry::validate_child(&spec.canonical_data_root, spec.namespace).ok();
        let runtime_for_thread = Arc::clone(&runtime);
        let generation_for_thread = generation.clone();
        let join_handle = thread::Builder::new()
            .name("bitcoin-rs-txindex".to_owned())
            .spawn(move || {
                #[allow(clippy::needless_borrow)]
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker_with_open(
                        &runtime_for_thread,
                        spec,
                        &lifecycle,
                        &generation_for_thread,
                        applied_tip,
                        block_tree,
                        body_store,
                        block_source,
                        body_source,
                        &chain_events,
                        reporter,
                        &shutdown,
                        &wake_rx,
                    );
                }));
                match result {
                    Ok(()) => {}
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("txindex worker panicked during open");
                        tracing::error!(%message, "txindex worker panicked");
                        fail_worker(
                            &runtime_for_thread,
                            &lifecycle,
                            &generation_for_thread,
                            message,
                        );
                    }
                }
            })?;
        Ok(Self {
            runtime,
            join_handle: Some(join_handle),
            generation: Some(generation),
            namespace_key,
        })
    }

    /// Returns true if the worker thread has exited.
    pub(crate) fn is_finished(&self) -> bool {
        self.join_handle
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
    }

    /// Requests shutdown and joins the worker thread.
    pub(crate) fn join(mut self) {
        self.runtime.request_shutdown();
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }

    /// Detaches the worker thread so `Drop` will not join it. Used by the
    /// abandonment path in `bounded_index_shutdown` when the worker is still
    /// blocked past the deadline. The thread continues running; dropping the
    /// `JoinHandle` detaches it.
    pub(crate) fn detach(&mut self) {
        self.join_handle = None;
    }

    /// Poisons the namespace associated with this worker. Used by the
    /// abandonment path so the namespace is permanently `Poisoned` and
    /// subsequent claims are rejected.
    pub(crate) fn poison_namespace(&self) {
        if let (Some(key), Some(token)) = (&self.namespace_key, &self.generation) {
            NAMESPACE_REGISTRY.poison(key, token.id());
        }
    }
}

impl Drop for TxIndexWorker {
    fn drop(&mut self) {
        self.runtime.request_shutdown();
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Result of opening the txindex store: writer, reader, and batch limits.
pub(crate) struct OpenTxIndex {
    pub(crate) writer: Arc<dyn TxIndexWriter>,
    pub(crate) reader: Arc<dyn bitcoin_rs_index::IndexReader>,
    #[allow(dead_code)]
    pub(crate) batch_limits: PreparedBatchLimits,
}

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
fn run_worker_with_open(
    runtime: &Arc<TxIndexRuntime>,
    spec: TxIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
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

    match worker_result {
        Ok(()) => {
            registry.release(&namespace_key, generation.id());
        }
        Err(error) => {
            tracing::error!(%error, "txindex worker open or run failed");
            fail_worker(runtime, lifecycle, generation, &error.to_string());
            registry.release(&namespace_key, generation.id());
        }
    }
}

/// Fails the worker as one unit: the runtime stops the loop and gates the
/// query engine, and the lifecycle withdraws the query payload so the
/// adapter answers typed `Unavailable`. The lifecycle write is skipped for a
/// revoked generation; the runtime write is unconditional because the
/// runtime belongs to this worker alone.
pub(super) fn fail_worker(
    runtime: &TxIndexRuntime,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    reason: &str,
) {
    runtime.publish_failed(reason);
    if generation.is_revoked() {
        return;
    }
    let reason = CompactString::from(reason);
    lifecycle.rcu(|current| {
        if generation.is_revoked() {
            return Arc::clone(current);
        }
        Arc::new(TxIndexLifecycle::Failed(reason.clone()))
    });
}

/// Publishes a lifecycle transition with generation-checked `rcu`.
/// A stale token returns the current `Arc` unchanged.
fn publish_lifecycle(
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    new: TxIndexLifecycle,
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
fn open_and_run(
    runtime: &Arc<TxIndexRuntime>,
    spec: &TxIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
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
) -> Result<(), TxIndexWorkerError> {
    // Wait for the test-only open gate before touching the store.
    #[cfg(test)]
    wait_txindex_open_gate();

    let txindex_dir = spec.data_dir.join(spec.namespace);
    std::fs::create_dir_all(&txindex_dir)
        .map_err(|e| TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let open: OpenTxIndex = open_tx_index_with_timeout(
        spec.storage_backend,
        &txindex_dir,
        spec.cache_bytes,
        spec.epoch,
        Duration::ZERO,
        TXINDEX_OPEN_TIMEOUT,
        shutdown,
    )?;

    // Check shutdown and generation immediately after backend open returns.
    if shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop() {
        // Drop all store values (open.writer, open.reader) and exit without
        // publication or reconciliation.
        return Ok(());
    }

    let query_engine = Arc::new(TxIndexQueryEngine::new(
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
        TxIndexLifecycle::Serving(query_engine),
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
pub(super) fn open_tx_index_with_timeout(
    storage_backend: bitcoin_rs_storage::StorageBackend,
    txindex_dir: &Path,
    cache_bytes: u64,
    epoch: u64,
    open_delay: Duration,
    open_timeout: Duration,
    shutdown: &Arc<AtomicBool>,
) -> Result<OpenTxIndex, TxIndexWorkerError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let backend = storage_backend;
    let dir = txindex_dir.to_path_buf();
    let _join = thread::Builder::new()
        .name("bitcoin-rs-txindex-open".to_owned())
        .spawn(move || {
            let result = open_tx_index_on_worker(backend, &dir, cache_bytes, epoch, open_delay);
            let _ = tx.send(result);
        })
        .map_err(|e| TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    // Poll in short slices so a shutdown during the open deadline
    // exits promptly instead of waiting the full timeout.
    let timeout = open_timeout;
    let deadline = Instant::now() + timeout;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(TxIndexWorkerError::Stopped);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tracing::error!(
                timeout_secs = timeout.as_secs(),
                backend = %storage_backend,
                dir = %txindex_dir.display(),
                "txindex store open timed out — the storage engine recovery \
                 appears stuck; detaching the open thread and publishing Failed"
            );
            return Err(TxIndexWorkerError::OpenTimeout {
                secs: timeout.as_secs(),
            });
        }
        match rx.recv_timeout(remaining) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(TxIndexWorkerError::Storage(
                    bitcoin_rs_storage::StorageError::Backend(
                        "txindex open helper thread exited without result".to_owned(),
                    ),
                ));
            }
        }
    }
}

/// Opens the txindex store on the worker thread through the namespace's single
/// runtime composition owner.
pub(super) fn open_tx_index_on_worker(
    storage_backend: bitcoin_rs_storage::StorageBackend,
    txindex_dir: &Path,
    cache_bytes: u64,
    epoch: u64,
    open_delay: Duration,
) -> Result<OpenTxIndex, TxIndexWorkerError> {
    if !open_delay.is_zero() {
        std::thread::sleep(open_delay);
    }
    crate::storage_backend::open_txindex(
        storage_backend,
        txindex_dir,
        Some(cache_bytes),
        TxIndexComposer {
            backend: storage_backend,
            epoch,
        },
    )
}

struct TxIndexComposer {
    backend: bitcoin_rs_storage::StorageBackend,
    epoch: u64,
}

impl crate::storage_backend::StoreConsumer for TxIndexComposer {
    type Output = OpenTxIndex;
    type Error = TxIndexWorkerError;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output, Self::Error>
    where
        S: bitcoin_rs_storage::KvStore,
    {
        let batch_limits = match self.backend {
            bitcoin_rs_storage::StorageBackend::RocksDb => ROCKSDB_BATCH_LIMITS,
            bitcoin_rs_storage::StorageBackend::Fjall => DEFAULT_BATCH_LIMITS,
            bitcoin_rs_storage::StorageBackend::Redb => REDB_BATCH_LIMITS,
        };
        open_tx_index_store_on_worker(store, batch_limits, self.epoch)
    }
}

/// Constructs the writer and reader from the opened store.
fn open_tx_index_store_on_worker<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
) -> Result<OpenTxIndex, TxIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    let writer = open_writer(&store, epoch)?;
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(writer));
    let reader: Arc<dyn bitcoin_rs_index::IndexReader> =
        Arc::new(bitcoin_rs_index::Indexer::new(store));
    Ok(OpenTxIndex {
        writer,
        reader,
        batch_limits,
    })
}

/// Maximum time the txindex worker waits for the storage engine to open and
/// recover the index store. A store open that exceeds this deadline is
/// treated as a wedge — the worker publishes `Failed` so the node stays
/// operable without the index rather than spinning one thread at 100% CPU
/// indefinitely. The deadline is a backstop, not a tight bound: the issue's
/// own data shows fjall/lsm-tree manifest recovery of a 139 GiB store logs
/// progress within seconds and then, when wedged, freezes block I/O for
/// hours. Thirty minutes is far below the observed wedge and far above any
/// legitimate recovery, so it cannot falsely kill a slow-but-progressing
/// open while still surfacing a stuck one. The 30-second heartbeat already
/// makes a slow open observable to an operator watching logs.
const TXINDEX_OPEN_TIMEOUT: Duration = Duration::from_mins(30);
