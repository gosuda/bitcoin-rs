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

fn open_writer<S>(store: &Arc<S>, generation: u64) -> Result<IndexWriter<S>, IndexError>
where
    S: bitcoin_rs_storage::KvStore,
{
    match IndexWriter::open(Arc::clone(store), generation) {
        Ok(writer) => Ok(writer),
        Err(
            error @ (IndexError::LegacyCursorlessIndex
            | IndexError::UnsupportedTxIndexFormatVersion { .. }),
        ) => {
            tracing::warn!(
                %error,
                "resetting incompatible derived transaction index for rebuild"
            );
            IndexWriter::reset_index(store.as_ref(), generation)?;
            IndexWriter::open(Arc::clone(store), generation)
        }
        Err(error) => Err(error),
    }
}

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

    let open: OpenDerivedIndex = open_with_recovery_heartbeat(
        setup.spec,
        &txindex_dir,
        HEARTBEAT_INTERVAL,
        &setup.cancel,
        || setup.is_interrupted(),
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
    match crate::portable::run(&host, &setup.spec.bundle) {
        Ok(None) => Ok(()),
        Ok(Some(outcome)) => {
            log_bundle_outcome(&outcome);
            Ok(())
        }
        Err(IndexBundleError::Cancelled) => Err(DerivedIndexWorkerError::Stopped),
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
    should_stop: impl Fn() -> bool,
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
    should_stop: impl Fn() -> bool,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    if shutdown.is_triggered() || should_stop() {
        return Err(DerivedIndexWorkerError::Stopped);
    }
    let (tx, rx) = crossbeam_channel::bounded(1);
    let open_store = Arc::clone(&spec.open_store);
    let dir = txindex_dir.to_path_buf();
    let open_thread = thread::Builder::new()
        .name("bitcoin-rs-txindex-open".to_owned())
        .spawn(move || {
            let _receiver_gone = tx.send(open_store(&dir));
        })
        .map_err(|e| DerivedIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let result = wait_for_open_result(&rx, open_timeout, shutdown, &should_stop);
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
    let mut writer = open_writer(&store, epoch)?;
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
mod tests;
