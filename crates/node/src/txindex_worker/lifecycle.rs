//! Process-owned worker spawning, joining, and explicit abandonment.

#[cfg(test)]
use super::FORWARD_BATCH_DELAY;
use super::Generation;
use super::IndexBlockSource;
#[cfg(test)]
use super::REVISION_QUIET_PERIOD;
use super::TxIndexLifecycle;
use super::TxIndexOpenSpec;
use super::TxIndexRuntime;
use super::TxIndexWorker;
#[cfg(test)]
use super::Worker;
use super::namespace::NAMESPACE_REGISTRY;
use super::namespace::NamespaceRegistry;
use super::startup::fail_worker;
use super::startup::run_worker_with_open;
use arc_swap::ArcSwap;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::TipSnapshot;
#[cfg(test)]
use bitcoin_rs_index::IndexCapabilities;
#[cfg(test)]
use bitcoin_rs_index::PreparedBatchLimits;
#[cfg(test)]
use bitcoin_rs_index::writer::TxIndexWriter;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use crossbeam_channel::Receiver;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;

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
