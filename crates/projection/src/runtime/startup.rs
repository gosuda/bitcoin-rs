#[cfg(kani)]
pub(crate) mod open_model;

use super::DerivedIndexLifecycle;
use super::DerivedIndexOpenSpec;
use super::DerivedIndexQueryEngine;
use super::DerivedIndexRuntime;
use super::DerivedIndexWorkerError;
use super::FORWARD_BATCH_DELAY;
use super::Generation;
use super::HEARTBEAT_INTERVAL;
use super::OpenDerivedIndex;
use super::QueryEngineLive;
use super::REVISION_QUIET_PERIOD;
use super::TXINDEX_OPEN_TIMEOUT;
use super::Worker;
use super::namespace::NAMESPACE_REGISTRY;
use super::namespace::NamespaceRegistry;
use crate::PreparedBatchLimits;
use crate::portable::{BundleHost, BundleOutcome, IndexBundleError, Withheld};
use crate::writer::TxIndexWriter;
use crate::{IndexError, IndexWriter};
use arc_swap::ArcSwap;
use bitcoin_rs_consensus::latch::{LatchReader, LatchWriter};
use bitcoin_rs_execution::chain::{BlockTreeReader, TipReader};
use bitcoin_rs_storage::block_body::BlockBodySource;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::pruning::HistoryAccess;
use crossbeam_channel::Receiver;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod rebuild;

pub(super) fn run_worker_with_open(
    runtime: &Arc<DerivedIndexRuntime>,
    spec: DerivedIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    applied_tip: TipReader,
    historical_verified: Option<super::HistoricalVerifiedReader>,
    block_tree: BlockTreeReader,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    history: HistoryAccess,
    body_source: Option<Arc<dyn BlockBodySource>>,
    chain_events: &Arc<dyn crate::reconcile::ChainCursorSource>,
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    wake_rx: &Receiver<()>,
    open_abandoned: &bitcoin_rs_consensus::latch::LatchWriter,
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

    let cancel_hook = shutdown.on_cancel({
        let runtime = Arc::clone(runtime);
        move || runtime.request_shutdown()
    });
    let setup = WorkerSetup {
        runtime,
        spec: &spec,
        lifecycle,
        generation,
        applied_tip: &applied_tip,
        historical_verified: &historical_verified,
        block_tree: &block_tree,
        body_source,
        shutdown,
        cancel: runtime.cancel_reader(),
    };
    let worker_result = open_and_run(&setup, body_store, history, chain_events, reporter, wake_rx);
    drop(cancel_hook);

    finish_worker(
        runtime,
        lifecycle,
        generation,
        &namespace_key,
        worker_result,
        open_abandoned,
    );
}

fn finish_worker(
    runtime: &DerivedIndexRuntime,
    lifecycle: &Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &Generation,
    namespace_key: &Path,
    result: Result<(), DerivedIndexWorkerError>,
    open_abandoned: &bitcoin_rs_consensus::latch::LatchWriter,
) {
    let registry = &*NAMESPACE_REGISTRY;
    if let Err(error) = result {
        if error.abandoned_open() {
            open_abandoned.trigger();
            registry.poison(namespace_key, generation.id());
        }
        tracing::error!(%error, "txindex worker open or run failed");
        fail_worker(runtime, lifecycle, generation, &error.to_string());
    }
    registry.release(namespace_key, generation.id());
}

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

pub(super) struct WorkerSetup<'a> {
    runtime: &'a Arc<DerivedIndexRuntime>,
    spec: &'a DerivedIndexOpenSpec,
    lifecycle: &'a Arc<ArcSwap<DerivedIndexLifecycle>>,
    generation: &'a Generation,
    applied_tip: &'a TipReader,
    historical_verified: &'a Option<super::HistoricalVerifiedReader>,
    block_tree: &'a BlockTreeReader,
    body_source: Option<Arc<dyn BlockBodySource>>,
    shutdown: &'a LatchReader,
    cancel: LatchReader,
}

impl WorkerSetup<'_> {
    fn is_interrupted(&self) -> bool {
        self.shutdown.is_triggered() || self.generation.is_revoked() || self.runtime.should_stop()
    }
}
pub(super) fn open_and_run(
    setup: &WorkerSetup<'_>,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    history: HistoryAccess,
    chain_events: &Arc<dyn crate::reconcile::ChainCursorSource>,
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
    wake_rx: &Receiver<()>,
) -> Result<(), DerivedIndexWorkerError> {
    let txindex_dir = setup.spec.data_dir.join(setup.spec.namespace);
    std::fs::create_dir_all(&txindex_dir)
        .map_err(|e| DerivedIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let shutdown = setup.shutdown.clone();
    let generation = setup.generation.clone();
    let runtime = Arc::clone(setup.runtime);
    let open: OpenDerivedIndex = open_with_recovery_heartbeat(
        setup.spec,
        &txindex_dir,
        HEARTBEAT_INTERVAL,
        &setup.cancel,
        move || shutdown.is_triggered() || generation.is_revoked() || runtime.should_stop(),
    )?;

    if setup.is_interrupted() {
        return Ok(());
    }

    publish_serving_query_engine(&open, setup);

    if setup.is_interrupted() {
        return Ok(());
    }

    execute_portable_bundle(&open, setup)?;

    if setup.is_interrupted() {
        return Ok(());
    }

    let worker = build_worker(
        open,
        setup,
        body_store,
        history,
        chain_events,
        reporter,
        wake_rx,
    );
    worker.run()
}

fn publish_serving_query_engine(open: &OpenDerivedIndex, setup: &WorkerSetup<'_>) {
    let query_engine = Arc::new(
        DerivedIndexQueryEngine::new(
            Arc::clone(setup.runtime),
            Arc::clone(&open.reader),
            setup.block_tree.clone(),
            setup.applied_tip.clone(),
            setup.body_source.clone(),
            QueryEngineLive {
                enabled: setup.spec.enabled,
                generation: std::sync::Arc::new(setup.generation.clone()),
                historical_verified: setup.historical_verified.clone(),
                #[cfg(any(test, feature = "test-seam"))]
                chain_transition: None,
            },
        )
        .with_scripthash_limit(setup.spec.scripthash_limit)
        .with_query_charge(setup.spec.query_charge.clone()),
    );
    publish_lifecycle(
        setup.lifecycle,
        setup.generation,
        DerivedIndexLifecycle::Serving(query_engine),
    );
}

fn execute_portable_bundle(
    open: &OpenDerivedIndex,
    setup: &WorkerSetup<'_>,
) -> Result<(), DerivedIndexWorkerError> {
    if setup
        .spec
        .enabled
        .contains(crate::IndexCapability::TxLookup)
    {
        crate::portable::reset_interrupted_import(open.writer.as_ref())
            .map_err(DerivedIndexWorkerError::Index)?;
    }
    let cancelled = || setup.is_interrupted();
    let host = BundleHost {
        writer: open.writer.as_ref(),
        reader: open.reader.as_ref(),
        block_tree: setup.block_tree,
        applied_tip: setup.applied_tip,
        body_source: setup.body_source.as_deref(),
        enabled: setup.spec.enabled,
        cancelled: &cancelled,
    };
    finish_portable_bundle(crate::portable::run(&host, &setup.spec.bundle))
}

fn finish_portable_bundle(
    result: Result<Option<BundleOutcome>, IndexBundleError>,
) -> Result<(), DerivedIndexWorkerError> {
    match result {
        Ok(None) => Ok(()),
        Ok(Some(outcome)) => {
            log_bundle_outcome(&outcome);
            Ok(())
        }
        Err(IndexBundleError::Cancelled) => Err(DerivedIndexWorkerError::Stopped),
        Err(IndexBundleError::Index(
            error @ IndexError::WatermarkMismatch {
                expected: None,
                actual: Some(_),
            },
        )) => {
            log::error!(
                "portable index attach refused a populated capability; ordinary reconciliation proceeds: {error}"
            );
            Ok(())
        }
        Err(IndexBundleError::Index(error)) => Err(DerivedIndexWorkerError::Index(error)),
        Err(IndexBundleError::Incomplete {
            height,
            expected,
            actual,
        }) => {
            tracing::error!(
                height,
                expected,
                actual,
                "portable txindex bundle is incomplete; ordinary reconciliation proceeds"
            );
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                %error,
                "portable txindex bundle request refused; ordinary reconciliation proceeds"
            );
            Ok(())
        }
    }
}

fn build_worker(
    open: OpenDerivedIndex,
    setup: &WorkerSetup<'_>,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    history: HistoryAccess,
    chain_events: &Arc<dyn crate::reconcile::ChainCursorSource>,
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
    wake_rx: &Receiver<()>,
) -> Worker {
    Worker {
        runtime: Arc::clone(setup.runtime),
        writer: open.writer,
        applied_tip: setup.applied_tip.clone(),
        block_tree: setup.block_tree.clone(),
        body_store,
        history,
        batch_limits: open.batch_limits,
        enabled: setup.spec.enabled,
        rollback_rebuild_cutover: setup.spec.rollback_rebuild_cutover,
        shutdown: setup.cancel.clone(),
        wake_rx: wake_rx.clone(),
        quiet_period: REVISION_QUIET_PERIOD,
        chain_events: Arc::clone(chain_events),
        reporter,
        batch_delay: FORWARD_BATCH_DELAY,
        seed_history_lease: parking_lot::Mutex::new(None),
        facts_rx: setup.spec.facts_rx.clone(),
        facts_charge: setup.spec.facts_charge.clone(),
        facts_gap: setup.spec.facts_gap.clone(),
        cpu: setup.spec.cpu.clone(),
        buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
    }
}

fn log_bundle_outcome(outcome: &BundleOutcome) {
    match outcome {
        BundleOutcome::Exported(report) => tracing::info!(
            height = report.base.height,
            records = report.records,
            bytes = report.bytes,
            "exported portable txindex bundle"
        ),
        BundleOutcome::Restored(report) => tracing::info!(
            height = report.base.height,
            records = report.records,
            rows = report.rows,
            "restored portable txindex bundle; ordinary reconciliation continues from its base"
        ),
        BundleOutcome::RestoreWithheld(Withheld::NoBodySource) => tracing::warn!(
            "portable txindex bundle not activated: no block body source to verify locators; ordinary backfill proceeds"
        ),
        BundleOutcome::RestoreWithheld(Withheld::BodyUnavailable { height }) => tracing::warn!(
            height,
            "portable txindex bundle not activated: a block body its locators need is unavailable; ordinary backfill proceeds"
        ),
    }
}

fn open_with_recovery_heartbeat(
    spec: &DerivedIndexOpenSpec,
    txindex_dir: &Path,
    heartbeat_interval: Duration,
    shutdown: &LatchReader,
    should_stop: impl Fn() -> bool + Send + Sync + 'static,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    let heartbeat = Heartbeat::start(
        "txindex",
        spec.namespace.to_owned(),
        spec.storage_backend.to_string(),
        heartbeat_interval,
    );
    let open = open_derived_index_with_timeout(
        spec,
        txindex_dir,
        TXINDEX_OPEN_TIMEOUT,
        shutdown,
        should_stop,
    );
    drop(heartbeat);
    open
}

pub(super) fn open_derived_index_with_timeout(
    spec: &DerivedIndexOpenSpec,
    txindex_dir: &Path,
    open_timeout: Duration,
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    should_stop: impl Fn() -> bool + Send + Sync + 'static,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    if shutdown.is_triggered() || should_stop() {
        return Err(DerivedIndexWorkerError::Stopped);
    }
    let (tx, rx) = crossbeam_channel::bounded(1);
    let open_store = Arc::clone(&spec.open_store);
    let dir = txindex_dir.to_path_buf();
    let root = spec.canonical_data_root.clone();
    let namespace = spec.namespace;
    let stop_open = LatchWriter::new();
    let stop_reader = stop_open.reader();
    let shutdown_reader = shutdown.clone();
    let should_stop = Arc::new(should_stop);
    let open_should_stop = Arc::clone(&should_stop);
    let open_thread = thread::Builder::new()
        .name("bitcoin-rs-txindex-open".to_owned())
        .spawn(move || {
            let result = rebuild::open(
                &root,
                namespace,
                &dir,
                || {
                    stop_reader.is_triggered()
                        || shutdown_reader.is_triggered()
                        || open_should_stop()
                },
                |path| open_store(path),
            );
            let _receiver_gone = tx.send(result);
        })
        .map_err(|e| DerivedIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let result = wait_for_open_result(&rx, open_timeout, shutdown, || should_stop());
    if result.is_err() {
        stop_open.trigger();
    }
    match result {
        Err(DerivedIndexWorkerError::OpenTimeout { secs }) => {
            tracing::error!(
                timeout_secs = open_timeout.as_secs(),
                backend = %spec.storage_backend,
                dir = %txindex_dir.display(),
                "txindex store open timed out; detaching the open thread and poisoning its namespace"
            );
            Err(DerivedIndexWorkerError::OpenTimeout { secs })
        }
        Err(DerivedIndexWorkerError::OpenStopped) => {
            if let Err(payload) = open_thread.join() {
                std::panic::resume_unwind(payload);
            }
            match rx.try_recv() {
                Ok(Ok(_open)) => Err(DerivedIndexWorkerError::Stopped),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(DerivedIndexWorkerError::Storage(
                    bitcoin_rs_storage::StorageError::Backend(
                        "txindex open thread exited without result".to_owned(),
                    ),
                )),
            }
        }
        Ok(open) => {
            if let Err(payload) = open_thread.join() {
                std::panic::resume_unwind(payload);
            }
            if shutdown.is_triggered() || should_stop() {
                drop(open);
                Err(DerivedIndexWorkerError::Stopped)
            } else {
                Ok(open)
            }
        }
        Err(err) => {
            if let Err(payload) = open_thread.join() {
                std::panic::resume_unwind(payload);
            }
            Err(err)
        }
    }
}

pub fn open_derived_index_store_on_worker<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    open_derived_index_store_in(store, batch_limits, epoch, None)
}

pub fn open_derived_index_store_with_scratch<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
    seal_scratch: std::path::PathBuf,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    open_derived_index_store_in(store, batch_limits, epoch, Some(seal_scratch))
}

fn open_derived_index_store_in<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
    seal_scratch: Option<std::path::PathBuf>,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    IndexWriter::check_startup_reset(store.as_ref())?;
    let mut writer = IndexWriter::open(Arc::clone(&store), epoch)?;
    if let Some(scratch) = seal_scratch {
        writer = writer.with_seal_scratch(scratch);
    }
    writer
        .restore_tail_bounds()
        .map_err(DerivedIndexWorkerError::Index)?;
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(writer));
    let reader: Arc<dyn crate::IndexReader> = Arc::new(crate::Indexer::new(store));
    Ok(OpenDerivedIndex {
        writer,
        reader,
        batch_limits,
    })
}

pub(super) struct Heartbeat {
    stop: LatchWriter,
    handle: Option<JoinHandle<()>>,
}

impl Heartbeat {
    pub(super) fn start(
        capability: &'static str,
        namespace: String,
        backend: String,
        interval: Duration,
    ) -> Self {
        let stop = LatchWriter::new();
        let reader = stop.reader();
        let start = Instant::now();
        let dispatch = tracing::dispatcher::get_default(|current| current.clone());
        let handle = match thread::Builder::new()
            .name(format!("bitcoin-rs-{capability}-heartbeat"))
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    while !reader.is_triggered() {
                        let elapsed = start.elapsed();
                        tracing::info!(
                            capability,
                            namespace = %namespace,
                            backend = %backend,
                            elapsed_secs = elapsed.as_secs(),
                            "index store recovery in progress"
                        );
                        crossbeam_channel::select! {
                            recv(reader.closed()) -> _ => return,
                            recv(crossbeam_channel::after(interval)) -> _ => {}
                        }
                    }
                });
            }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                tracing::warn!(%error, "failed to spawn heartbeat thread; continuing without telemetry");
                None
            }
        };
        Self { stop, handle }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.stop.trigger();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(super) fn wait_for_open_result(
    receiver: &crossbeam_channel::Receiver<Result<OpenDerivedIndex, DerivedIndexWorkerError>>,
    timeout: Duration,
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
    should_stop: impl Fn() -> bool,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    if shutdown.is_triggered() || should_stop() {
        if let Ok(result) = receiver.try_recv() {
            return result;
        }
        return Err(DerivedIndexWorkerError::OpenStopped);
    }
    if timeout.is_zero() {
        return Err(DerivedIndexWorkerError::OpenTimeout { secs: 0 });
    }
    crossbeam_channel::select! {
        recv(shutdown.closed()) -> _ => match receiver.try_recv() {
            Ok(result) => result,
            Err(_) => Err(DerivedIndexWorkerError::OpenStopped),
        },
        recv(receiver) -> result => match result {
            Ok(result) => result,
            Err(_) => Err(DerivedIndexWorkerError::Storage(
                bitcoin_rs_storage::StorageError::Backend(
                    "txindex open thread exited without result".to_owned(),
                ),
            )),
        },
        recv(crossbeam_channel::after(timeout)) -> _ => {
            if shutdown.is_triggered() || should_stop() {
                Err(DerivedIndexWorkerError::OpenStopped)
            } else {
                Err(DerivedIndexWorkerError::OpenTimeout {
                    secs: timeout.as_secs(),
                })
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    mod namespace_reset {
        use super::*;

        // IDX-05
        #[test]
        fn missing_reset_intent_after_fresh_open_is_refused() -> Result<(), DerivedIndexWorkerError>
        {
            let root = tempfile::tempdir()?;
            let path = root.path().join("txindex");
            let marker = root.path().join(".txindex.reset");
            std::fs::write(&marker, b"bitcoin-rs-derived-index-reset-v1\n")?;
            let result = rebuild::open(
                root.path(),
                "txindex",
                &path,
                || false,
                |path| {
                    let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                        path,
                        8 * 1024 * 1024,
                    )?);
                    let opened = open_derived_index_store_on_worker(
                        store,
                        crate::runtime::DEFAULT_BATCH_LIMITS,
                        1,
                    )?;
                    std::fs::remove_file(&marker)?;
                    Ok(opened)
                },
            );
            assert!(
                matches!(result, Err(DerivedIndexWorkerError::NamespaceOpen(ref error)) if error.kind() == std::io::ErrorKind::NotFound)
            );
            assert!(path.is_dir());
            Ok(())
        }

        // IDX-05, SYNC-03
        #[test]
        fn revoked_generation_cannot_authorize_namespace_reset() -> std::io::Result<()> {
            let root = tempfile::tempdir()?;
            let path = root.path().join("txindex");
            std::fs::create_dir(&path)?;
            std::fs::write(path.join("keep"), b"index owned by revoked generation")?;
            let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = Arc::clone(&revoked);
            let mut spec = recovery_open_spec(root.path());
            spec.open_store = Arc::new(move |_| {
                observed.store(true, Ordering::Release);
                Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 }.into())
            });
            let result = open_derived_index_with_timeout(
                &spec,
                &path,
                Duration::from_secs(5),
                &LatchWriter::new().reader(),
                move || revoked.load(Ordering::Acquire),
            );
            assert!(matches!(result, Err(DerivedIndexWorkerError::Stopped)));
            assert_eq!(
                std::fs::read(path.join("keep"))?,
                b"index owned by revoked generation"
            );
            assert!(!root.path().join(".txindex.reset").exists());
            Ok(())
        }

        // IDX-05
        #[test]
        #[cfg(unix)]
        fn compatible_linked_namespace_opens_without_recreation()
        -> Result<(), DerivedIndexWorkerError> {
            let root = tempfile::tempdir()?;
            let target = tempfile::tempdir()?;
            let path = root.path().join("txindex");
            std::os::unix::fs::symlink(target.path(), &path)?;
            std::fs::write(target.path().join("keep"), b"compatible linked index")?;
            let mut spec = recovery_open_spec(root.path());
            spec.open_store = Arc::new(|path| {
                let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                    path,
                    8 * 1024 * 1024,
                )?);
                open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
            });
            let opened = open_derived_index_with_timeout(
                &spec,
                &path,
                Duration::from_secs(5),
                &LatchWriter::new().reader(),
                || false,
            )?;
            drop(opened);
            assert!(std::fs::symlink_metadata(&path)?.file_type().is_symlink());
            assert_eq!(
                std::fs::read(target.path().join("keep"))?,
                b"compatible linked index"
            );
            assert!(!root.path().join(".txindex.reset").exists());
            Ok(())
        }

        // IDX-05
        #[test]
        fn pending_namespace_reset_completes_before_backend_open()
        -> Result<(), DerivedIndexWorkerError> {
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
                            bitcoin_rs_storage::StorageError::InvalidOperation(
                                "fresh engine open fault",
                            ),
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
                    open_derived_index_store_on_worker(
                        store,
                        crate::runtime::DEFAULT_BATCH_LIMITS,
                        1,
                    )
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
        fn unknown_namespace_reset_intent_preserves_files_and_refuses_open() -> std::io::Result<()>
        {
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
        fn namespace_reset_refuses_a_link_to_another_directory()
        -> Result<(), DerivedIndexWorkerError> {
            assert_linked_namespace_preserved(bitcoin_rs_storage::StorageBackend::RocksDb, |path| {
                bitcoin_rs_storage::RocksDbStore::open_with_cache(path, 8 * 1024 * 1024)
            })
        }

        // IDX-05
        #[test]
        #[cfg(all(unix, feature = "surrealkv"))]
        fn surrealkv_namespace_reset_refuses_a_link_to_another_directory()
        -> Result<(), DerivedIndexWorkerError> {
            assert_linked_namespace_preserved(
                bitcoin_rs_storage::StorageBackend::SurrealKv,
                |path| bitcoin_rs_storage::SurrealKvStore::open_with_cache(path, 8 * 1024 * 1024),
            )
        }

        // IDX-05
        #[test]
        #[cfg(all(unix, feature = "mdbx"))]
        fn mdbx_namespace_reset_refuses_a_link_to_another_directory()
        -> Result<(), DerivedIndexWorkerError> {
            assert_linked_namespace_preserved(bitcoin_rs_storage::StorageBackend::Mdbx, |path| {
                bitcoin_rs_storage::MdbxStore::open_with_cache(path, 8 * 1024 * 1024)
            })
        }

        #[cfg(unix)]
        fn assert_linked_namespace_preserved<S: bitcoin_rs_storage::KvStore>(
            backend: bitcoin_rs_storage::StorageBackend,
            open_store: fn(&Path) -> Result<S, bitcoin_rs_storage::StorageError>,
        ) -> Result<(), DerivedIndexWorkerError> {
            use bitcoin_rs_storage::{ColumnFamily, PersistFault};

            for marker in [Some(5_u32), None, Some(9_u32)] {
                let root = tempfile::tempdir()?;
                let target = tempfile::tempdir()?;
                let path = root.path().join("txindex");
                let reset = (marker == Some(9)).then(|| {
                    let mut claim = vec![0b1111];
                    claim.extend_from_slice(&1_u64.to_le_bytes());
                    claim.extend_from_slice(&0_u64.to_le_bytes());
                    claim
                });
                {
                    let store = open_store(target.path())?;
                    let mut batch = store.new_batch();
                    for &family in ColumnFamily::ALL {
                        batch.put(family, b"retained", b"durable bytes");
                    }
                    if let Some(marker) = marker {
                        batch.put(ColumnFamily::UtxoMeta, &[0, b'V'], &marker.to_le_bytes());
                    }
                    if let Some(reset) = &reset {
                        batch.put(ColumnFamily::UtxoMeta, &[0, b'R'], reset);
                    }
                    store.write_durable(batch)?;
                }
                std::fs::write(target.path().join("keep"), b"operator bytes")?;
                std::os::unix::fs::symlink(target.path(), &path)?;
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let mut spec = recovery_open_spec(root.path());
                spec.storage_backend = backend;
                spec.open_store = Arc::new(move |path| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let store = Arc::new(open_store(path)?);
                    store.arm_persist_fault(PersistFault::FailApply);
                    open_derived_index_store_on_worker(
                        store,
                        crate::runtime::DEFAULT_BATCH_LIMITS,
                        1,
                    )
                });
                let result = open_derived_index_with_timeout(
                    &spec,
                    &path,
                    Duration::from_secs(30),
                    &LatchWriter::new().reader(),
                    || false,
                );
                assert!(matches!(
                    result,
                    Err(DerivedIndexWorkerError::NamespaceOpen(ref error))
                        if error.kind() == std::io::ErrorKind::InvalidInput
                ));
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert!(!root.path().join(".txindex.reset").exists());
                assert!(std::fs::symlink_metadata(&path)?.file_type().is_symlink());
                assert_eq!(
                    std::fs::read(target.path().join("keep"))?,
                    b"operator bytes"
                );
                let store = open_store(target.path())?;
                for &family in ColumnFamily::ALL {
                    assert_eq!(
                        store.get(family, b"retained")?.as_deref(),
                        Some(b"durable bytes".as_slice())
                    );
                }
                assert_eq!(
                    store.get(ColumnFamily::UtxoMeta, &[0, b'V'])?,
                    marker.map(|value| value.to_le_bytes().to_vec())
                );
                assert_eq!(store.get(ColumnFamily::UtxoMeta, &[0, b'R'])?, reset);
            }
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
        fn malformed_reset_claim_does_not_authorize_namespace_reset()
        -> Result<(), DerivedIndexWorkerError> {
            use bitcoin_rs_storage::{ColumnFamily, KvStore};

            for marker in [5_u32, 9_u32] {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("txindex");
                {
                    let store =
                        bitcoin_rs_storage::RocksDbStore::open_with_cache(&path, 8 * 1024 * 1024)?;
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
                    open_derived_index_store_on_worker(
                        store,
                        crate::runtime::DEFAULT_BATCH_LIMITS,
                        1,
                    )
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
                    let open = open_derived_index_store_on_worker(
                        store,
                        crate::runtime::DEFAULT_BATCH_LIMITS,
                        1,
                    )?;
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
    }

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
                bitcoin_rs_storage::RocksDbStore::open_with_cache(
                    &store_dir_clone,
                    8 * 1024 * 1024,
                )
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
                    bitcoin_rs_storage::StorageError::InvalidOperation(
                        "native corruption sentinel"
                    )
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

    #[derive(Debug, thiserror::Error)]
    enum AttachTestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        Index(#[from] IndexError),
        #[error(transparent)]
        Bundle(#[from] IndexBundleError),
        #[error(transparent)]
        Chain(#[from] bitcoin_rs_execution::chain::ChainError),
        #[error(transparent)]
        Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error(transparent)]
        Integer(#[from] std::num::TryFromIntError),
        #[error("missing fixture tip after inserting two headers")]
        MissingFixtureTip,
    }

    // SNP-10
    #[test]
    fn populated_attach_refusal_preserves_sibling_coverage() -> Result<(), AttachTestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
            dir.path(),
            8 * 1024 * 1024,
        )?);
        let writer = IndexWriter::open(store, 1)?;
        let existing = crate::IndexWatermark {
            height: 1,
            hash: [1; 32],
        };
        let base = crate::IndexWatermark {
            height: 2,
            hash: [2; 32],
        };
        writer.anchor_watermark(crate::IndexCapabilities::TX_LOOKUP, existing, 0)?;
        writer.publish_script_live_seed(existing)?;
        let family = crate::segment::import::StreamedFamily {
            runs: Vec::new(),
            rows: 0,
        };
        let seal = crate::segment::import::tx_lookup_seal(0, base.height, base.hash, 0, 0)?;
        let attachment = crate::writer::TxLookupAttachment {
            headers: &[],
            base,
            floor: 0,
            scratch: dir.path(),
        };
        let refusal = writer
            .attach_streamed_tx_lookup(&family, &seal, &attachment)
            .map_err(IndexBundleError::Index);
        assert!(matches!(
            &refusal,
            Err(IndexBundleError::Index(IndexError::WatermarkMismatch {
                expected: None,
                actual: Some(actual),
            })) if *actual == existing
        ));
        assert!(finish_portable_bundle(refusal.map(|_| None)).is_ok());
        let watermarks = writer.watermarks()?;
        assert_eq!(watermarks.tx_lookup, Some(existing));
        assert_eq!(watermarks.script_live, Some(existing));
        Ok(())
    }

    // SNP-10
    #[test]
    fn portable_attach_storage_and_corruption_remain_worker_failures() {
        for error in [
            IndexError::Storage(bitcoin_rs_storage::StorageError::Io(std::io::Error::other(
                "attach storage unavailable",
            ))),
            IndexError::InvalidWatermark,
            IndexError::WatermarkMismatch {
                expected: Some(crate::IndexWatermark {
                    height: 2,
                    hash: [2; 32],
                }),
                actual: None,
            },
        ] {
            assert!(matches!(
                finish_portable_bundle(Err(IndexBundleError::Index(error))),
                Err(DerivedIndexWorkerError::Index(_))
            ));
        }
        assert!(finish_portable_bundle(Ok(None)).is_ok());
    }
    // SNP-10
    #[test]
    fn populated_manifest_capability_does_not_skip_fresh_siblings() -> Result<(), AttachTestError> {
        use crate::portable::{IndexBundleDirective, IndexBundleRequest, ManifestArtifactTarget};
        use bitcoin::hashes::Hash as _;
        use bitcoin_rs_consensus::primitives::{BlockHash, Hash256, Network};
        use bitcoin_rs_execution::chain::{BlockTree, NodeStatus, TipSnapshot};
        use sha2::{Digest as _, Sha256};

        struct Bodies(Vec<([u8; 32], Vec<u8>)>);
        impl bitcoin_rs_storage::block_body::BlockBodySource for Bodies {
            fn block_body(
                &self,
                height: u32,
                hash: BlockHash,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError>
            {
                Ok(usize::try_from(height)
                    .ok()
                    .and_then(|height| self.0.get(height))
                    .filter(|(expected, _)| *expected == Hash256::from(hash).to_le_bytes())
                    .map(|(_, bytes)| bytes.clone()))
            }

            fn block_body_range(
                &self,
                height: u32,
                hash: BlockHash,
                offset: u32,
                length: u32,
            ) -> Option<Vec<u8>> {
                let height = usize::try_from(height).ok()?;
                let offset = usize::try_from(offset).ok()?;
                let length = usize::try_from(length).ok()?;
                let (_, bytes) = self
                    .0
                    .get(height)
                    .filter(|(expected, _)| *expected == Hash256::from(hash).to_le_bytes())?;
                bytes
                    .get(offset..offset.checked_add(length)?)
                    .map(<[u8]>::to_vec)
            }
        }

        struct CoinbaseOnly;
        impl crate::SpentCoins for CoinbaseOnly {
            fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<crate::SpentCoin<'_>> {
                None
            }
        }
        let dir = tempfile::tempdir()?;
        let source_store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
            dir.path().join("source"),
            8 * 1024 * 1024,
        )?);
        let mut source = IndexWriter::open(Arc::clone(&source_store), 1)?;
        let mut tree = BlockTree::new();
        let mut bodies = Bodies(Vec::new());
        let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut tip_id = None;
        let enabled = crate::IndexCapabilities::HISTORICAL.with_compact_filters(true);
        for height in 0..=1 {
            if height != 0 {
                block.header.prev_blockhash = block.block_hash();
                block.header.time += 1;
            }
            let hash = block.block_hash().to_byte_array();
            let bytes = bitcoin::consensus::serialize(&block);
            let header = bitcoin_rs_consensus::primitives::deserialize(
                &bitcoin::consensus::serialize(&block.header),
            )?;
            let id = tree.insert_header(header, NodeStatus::HeaderValid)?;
            tree.record_applied_tx_count(id, 1)?;
            tip_id = Some(id);
            let prepared = source.prepare_block_with_spent_scripts(
                enabled,
                height,
                hash,
                &bytes,
                &CoinbaseOnly,
            )?;
            let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            assert!(batch.try_push(prepared).is_ok());
            source.commit_forward(batch)?;
            bodies.0.push((hash, bytes));
        }
        let tip_id = tip_id.ok_or(AttachTestError::MissingFixtureTip)?;
        let node = tree.node(tip_id)?;
        let base = crate::IndexWatermark {
            height: 1,
            hash: node.hash.to_le_bytes(),
        };
        let tip = Arc::new(TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        });
        let tree = bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(
            parking_lot::RwLock::new(tree),
        ));
        let applied_tip = bitcoin_rs_execution::chain::TipReader::new(Arc::new(
            arc_swap::ArcSwapOption::from(Some(tip)),
        ));
        let source = parking_lot::RwLock::new(source);
        let source_reader = crate::Indexer::new(source_store);
        let bundle_dir = dir.path().join("bundle");
        let source_host = BundleHost {
            writer: &source,
            reader: &source_reader,
            block_tree: &tree,
            applied_tip: &applied_tip,
            body_source: Some(&bodies),
            enabled,
            cancelled: &|| false,
        };
        crate::portable::run(
            &source_host,
            &IndexBundleDirective::Export(IndexBundleRequest {
                dir: bundle_dir.clone(),
                network: Network::Regtest,
            }),
        )?;
        let script_path = bundle_dir.join("script.artifact");
        crate::portable::write_script_history_artifact(
            &source.read(),
            Network::Regtest,
            &script_path,
        )?;
        let filter_path = bundle_dir.join("filters.artifact");
        crate::portable::write_compact_filter_artifact(
            &*source.read(),
            Network::Regtest,
            &bodies.0.iter().map(|(hash, _)| *hash).collect::<Vec<_>>(),
            &filter_path,
        )?;
        let target =
            |path: std::path::PathBuf| -> Result<Box<ManifestArtifactTarget>, AttachTestError> {
                let bytes = std::fs::read(&path)?;
                Ok(Box::new(ManifestArtifactTarget {
                    artifact_path: path,
                    base_height: base.height,
                    base_hash: base.hash,
                    floor: 0,
                    network: Network::Regtest,
                    index_format: crate::index_format_version(),
                    sha256: Sha256::digest(&bytes).into(),
                    size_bytes: u64::try_from(bytes.len())?,
                    chain_tx_count: 2,
                }))
            };
        let tx = IndexBundleDirective::AttachManifestArtifact(target(
            bundle_dir.join("txlookup-v1.dat"),
        )?);
        let script = IndexBundleDirective::AttachManifestScriptHistory(target(script_path)?);
        let filters = IndexBundleDirective::AttachManifestCompactFilters(target(filter_path)?);

        let control_store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
            dir.path().join("fresh-control"),
            8 * 1024 * 1024,
        )?);
        let control = parking_lot::RwLock::new(IndexWriter::open(Arc::clone(&control_store), 1)?);
        let control_reader = crate::Indexer::new(control_store);
        let control_host = BundleHost {
            writer: &control,
            reader: &control_reader,
            block_tree: &tree,
            applied_tip: &applied_tip,
            body_source: Some(&bodies),
            enabled,
            cancelled: &|| false,
        };
        for directive in [&tx, &script, &filters] {
            crate::portable::run(&control_host, directive)?;
        }
        let control_marks = control.read().watermarks()?;
        assert_eq!(control_marks.tx_lookup, Some(base));
        assert_eq!(control_marks.script_history, Some(base));
        assert_eq!(control_marks.compact_filters, Some(base));

        for (name, populated, directives) in [
            (
                "tx-first",
                crate::IndexCapabilities::TX_LOOKUP,
                vec![tx.clone(), script.clone(), filters.clone()],
            ),
            (
                "script-first",
                crate::IndexCapabilities::SCRIPT_HISTORY,
                vec![script, tx, filters],
            ),
        ] {
            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open_with_cache(
                dir.path().join(name),
                8 * 1024 * 1024,
            )?);
            let receiver = IndexWriter::open(Arc::clone(&store), 1)?;
            let existing = crate::IndexWatermark {
                height: 0,
                hash: bodies.0[0].0,
            };
            receiver.anchor_watermark(populated, existing, 0)?;
            let receiver = parking_lot::RwLock::new(receiver);
            let reader = crate::Indexer::new(store);
            let host = BundleHost {
                writer: &receiver,
                reader: &reader,
                block_tree: &tree,
                applied_tip: &applied_tip,
                body_source: Some(&bodies),
                enabled,
                cancelled: &|| false,
            };
            let outcome = crate::portable::run(&host, &IndexBundleDirective::Manifest(directives))?;
            assert!(finish_portable_bundle(Ok(outcome)).is_ok());
            let marks = receiver.read().watermarks()?;
            assert_eq!(
                marks.compact_filters,
                Some(base),
                "{name}: fresh filters were skipped"
            );
            if populated == crate::IndexCapabilities::TX_LOOKUP {
                assert_eq!(marks.tx_lookup, Some(existing));
                assert_eq!(marks.script_history, Some(base));
            } else {
                assert_eq!(marks.script_history, Some(existing));
                assert_eq!(marks.tx_lookup, Some(base));
            }
        }
        Ok(())
    }
}
