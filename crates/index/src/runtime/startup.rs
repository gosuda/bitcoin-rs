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
use crate::{IndexCapability, IndexError, IndexWriter};
use arc_swap::ArcSwap;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::{BlockTreeReader, LatchReader, LatchWriter, TipReader};
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
    block_tree: BlockTreeReader,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    history: HistoryAccess,
    body_source: Option<Arc<dyn BlockBodySource>>,
    chain_events: &Arc<dyn crate::reconcile::ChainCursorSource>,
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
    shutdown: &bitcoin_rs_chain::LatchReader,
    wake_rx: &Receiver<()>,
    open_abandoned: &bitcoin_rs_chain::LatchWriter,
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
    open_abandoned: &bitcoin_rs_chain::LatchWriter,
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
                utxo: setup.spec.utxo.clone(),
                chain_transition: setup.spec.chain_transition.clone(),
                enabled: setup.spec.enabled,
            },
        )
        .with_scripthash_limit(setup.spec.scripthash_limit),
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
    if setup.spec.enabled.contains(IndexCapability::TxLookup)
        && crate::portable::reset_interrupted_import(open.writer.as_ref(), open.reader.as_ref())
            .map_err(DerivedIndexWorkerError::Index)?
    {
        tracing::warn!("cleared rows left by an interrupted portable index import");
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
        seed_slot: setup.spec.seed_slot.clone(),
        seed_bundle: parking_lot::Mutex::new(None),
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
    shutdown: &bitcoin_rs_chain::LatchReader,
    should_stop: impl Fn() -> bool,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    if shutdown.is_triggered() || should_stop() {
        return Err(DerivedIndexWorkerError::Stopped);
    }
    let (tx, rx) = crossbeam_channel::bounded(1);
    let open_store = Arc::clone(&spec.open_store);
    let dir = txindex_dir.to_path_buf();
    let _join = thread::Builder::new()
        .name("bitcoin-rs-txindex-open".to_owned())
        .spawn(move || {
            let _receiver_gone = tx.send(open_store(&dir));
        })
        .map_err(|e| DerivedIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let result = wait_for_open_result(&rx, open_timeout, shutdown, should_stop);
    if matches!(&result, Err(DerivedIndexWorkerError::OpenTimeout { .. })) {
        tracing::error!(
            timeout_secs = open_timeout.as_secs(),
            backend = %spec.storage_backend,
            dir = %txindex_dir.display(),
            "txindex store open timed out; detaching the open thread and poisoning its namespace"
        );
    }
    result
}

pub fn open_derived_index_store_on_worker<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    let writer = open_writer(&store, epoch)?;
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
    shutdown: &bitcoin_rs_chain::LatchReader,
    should_stop: impl Fn() -> bool,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    if shutdown.is_triggered() || should_stop() {
        return Err(DerivedIndexWorkerError::OpenStopped);
    }
    if timeout.is_zero() {
        return Err(DerivedIndexWorkerError::OpenTimeout { secs: 0 });
    }
    crossbeam_channel::select! {
        recv(shutdown.closed()) -> _ => Err(DerivedIndexWorkerError::OpenStopped),
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
        let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
        let shutdown = bitcoin_rs_chain::LatchWriter::new();
        shutdown.trigger();
        assert!(matches!(
            wait_for_open_result(&rx, Duration::ZERO, &shutdown.reader(), || false),
            Err(DerivedIndexWorkerError::OpenStopped)
        ));
    }

    #[test]
    fn expired_open_deadline_is_typed() {
        let (_tx, rx) = crossbeam_channel::bounded(1);
        let shutdown = bitcoin_rs_chain::LatchWriter::new();
        assert!(matches!(
            wait_for_open_result(&rx, Duration::ZERO, &shutdown.reader(), || false),
            Err(DerivedIndexWorkerError::OpenTimeout { secs: 0 })
        ));
    }

    #[test]
    fn disconnected_open_thread_is_a_storage_failure() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        drop(tx);
        let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
        let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
            storage_backend: bitcoin_rs_storage::StorageBackend::Fjall,
            epoch: 1,
            enabled: crate::IndexCapabilities::default(),
            rollback_rebuild_cutover: 0,
            canonical_data_root: dir.path().to_path_buf(),
            open_store: std::sync::Arc::new(|_| Err(DerivedIndexWorkerError::Stopped)),
            utxo: None,
            chain_transition: None,
            bundle: crate::portable::IndexBundleDirective::None,
            seed_slot: None,
        };
        let shutdown = bitcoin_rs_chain::LatchWriter::new();
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
            "fjall".to_owned(),
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
    }

    impl RecoveryHeartbeatCounter {
        fn lines(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl tracing::field::Visit for RecoveryHeartbeatCounter {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" && value == "index store recovery in progress" {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message"
                && format!("{value:?}").contains("index store recovery in progress")
            {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
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
            event.record(&mut RecoveryHeartbeatCounter {
                count: Arc::clone(&self.count),
            });
        }

        fn enter(&self, _id: &tracing::span::Id) {}

        fn exit(&self, _id: &tracing::span::Id) {}
    }

    fn recovery_open_spec(dir: &Path) -> DerivedIndexOpenSpec {
        DerivedIndexOpenSpec {
            scripthash_limit: crate::runtime::DEFAULT_SCRIPTHASH_LIMIT,
            data_dir: dir.to_path_buf(),
            namespace: "txindex",
            storage_backend: bitcoin_rs_storage::StorageBackend::Fjall,
            epoch: 1,
            enabled: crate::IndexCapabilities::default(),
            rollback_rebuild_cutover: 0,
            canonical_data_root: dir.to_path_buf(),
            open_store: Arc::new(|_| Err(DerivedIndexWorkerError::Stopped)),
            utxo: None,
            chain_transition: None,
            bundle: crate::portable::IndexBundleDirective::None,
            seed_slot: None,
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
        let counter = RecoveryHeartbeatCounter {
            count: Arc::new(AtomicUsize::new(0)),
        };
        let dispatch = tracing::Dispatch::new(counter.clone());
        let releaser = thread::spawn(move || {
            let started = started_rx.recv_timeout(Duration::from_secs(5));
            assert!(started.is_ok(), "open phase must start within 5 s deadline");
            thread::sleep(TEST_HEARTBEAT_INTERVAL * 6);
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
    #[cfg(feature = "fjall")]
    fn recovery_heartbeat_stops_after_a_successful_open() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let (started_tx, _started_rx) = crossbeam_channel::bounded(1);
        let mut spec = recovery_open_spec(dir.path());
        let store_dir = dir.path().join("store");
        spec.open_store = Arc::new(move |_| {
            assert!(
                started_tx.send(()).is_ok(),
                "open phase must report that it started"
            );
            thread::sleep(TEST_HEARTBEAT_INTERVAL * 6);
            let store = Arc::new(
                bitcoin_rs_storage::FjallStore::open_with_cache(&store_dir, 8 * 1024 * 1024)
                    .map_err(DerivedIndexWorkerError::Storage)?,
            );
            open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
        });
        let counter = RecoveryHeartbeatCounter {
            count: Arc::new(AtomicUsize::new(0)),
        };
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
}
