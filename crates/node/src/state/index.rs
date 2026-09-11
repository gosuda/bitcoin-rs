//! Index capability selection, startup, query handles, and bounded shutdown.

use super::NodeState;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_chain::BlockBodySource;
use crossbeam_channel::Receiver;
use std::sync::Arc;
use std::time::Duration;

pub(super) fn tx_index_capabilities(config: &NodeConfig) -> bitcoin_rs_index::IndexCapabilities {
    bitcoin_rs_index::IndexCapabilities {
        // Full ScriptIndex-backed Esplora responses need exact historical
        // transactions to render prevouts and calculate fees. `utxo` owns
        // only the compact live-output view and must not pay for TxLookup.
        // `tx_index_query` still exposes TxLookup to Core RPCs only for an
        // explicit --txindex configuration.
        tx_lookup: config.indexes.txindex || config.indexes.script_index.keeps_history(),
        script_history: config.indexes.script_index.keeps_history(),
        script_live: config.indexes.script_index.is_enabled(),
    }
}

pub(super) fn build_tx_index_open_spec(
    config: &NodeConfig,
    txindex_cache_bytes: u64,
    epoch: u64,
) -> Result<Option<crate::txindex::TxIndexOpenSpec>> {
    let enabled = tx_index_capabilities(config);
    if enabled.is_empty() {
        return Ok(None);
    }
    if config.storage.prune_target_mb > 0 {
        bail!("transaction and script indexing are not compatible with -prune");
    }
    let canonical_data_root = config
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| config.data_dir.clone());
    Ok(Some(crate::txindex::TxIndexOpenSpec {
        data_dir: config.data_dir.clone(),
        namespace: "txindex",
        storage_backend: config.storage.backend,
        cache_bytes: txindex_cache_bytes,
        epoch,
        enabled,
        rollback_rebuild_cutover: crate::txindex::DEFAULT_ROLLBACK_REBUILD_CUTOVER,
        canonical_data_root,
        utxo: None,
        chain_transition: None,
    }))
}

pub(super) struct TxIndexSpawn {
    pub(super) spec: crate::txindex::TxIndexOpenSpec,
    pub(super) generation: crate::txindex::Generation,
    pub(super) block_source: crate::txindex::IndexBlockSource,
    pub(super) body_source: Arc<dyn BlockBodySource>,
    pub(super) wake_rx: Receiver<()>,
    pub(super) recovery_reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
}

impl NodeState {
    /// Returns the node-owned complete transaction-index query adapter.
    #[must_use]
    pub fn tx_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery>> {
        if !self.config.indexes.txindex {
            return None;
        }
        self.tx_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns transaction lookup for internal Esplora projections.
    ///
    /// `--scriptindex` builds this dependency as well, but that does not
    /// enable or advertise the Core `--txindex` contract.
    #[must_use]
    pub fn esplora_tx_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery>> {
        self.tx_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns the node-owned complete generic script-index query adapter.
    #[must_use]
    pub fn script_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery>> {
        if !self.config.indexes.script_index.is_enabled() {
            return None;
        }
        self.tx_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery> = adapter.clone();
            q
        })
    }

    /// Starts the derived-index workers. Call only once the applied tip is
    /// authoritative — after crash recovery — so the index reconciles against
    /// the real chainstate and never mistakes a recovered gap for a stale branch.
    pub fn start_index_workers(&mut self) -> anyhow::Result<()> {
        let Some(spawn) = self.tx_index_spawn.take() else {
            return Ok(());
        };
        let runtime = self
            .tx_index_runtime
            .as_ref()
            .context("txindex runtime missing for a pending worker spawn")?;
        let lifecycle = self
            .tx_index_lifecycle
            .as_ref()
            .context("txindex lifecycle missing for a pending worker spawn")?;
        let worker = crate::txindex::TxIndexWorker::spawn_with_open(
            Arc::clone(runtime),
            spawn.spec,
            Arc::clone(lifecycle),
            spawn.generation,
            Arc::clone(&self.applied_tip),
            Arc::clone(&self.block_tree),
            Some(Arc::clone(&self.block_body_store)),
            spawn.block_source,
            Some(spawn.body_source),
            Arc::clone(&self.chain_events),
            spawn.recovery_reporter,
            Arc::clone(&self.apply_handles.shutdown),
            spawn.wake_rx,
        )
        .context("spawn txindex worker")?;
        self.tx_index_worker = Some(worker);
        Ok(())
    }

    /// Returns the live txindex status source for `getcapabilities`.
    #[must_use]
    pub fn txindex_status(&self) -> Arc<dyn bitcoin_rs_rpc::capabilities::TxIndexCapabilitySource> {
        self.txindex_status.clone()
    }

    /// Bounded txindex-worker shutdown: requests the worker shutdown, waits up
    /// to `deadline` for a clean join, and detaches on
    /// expiry. On detach, revokes the generation token and publishes
    /// `ShutdownAbandoned` so queries return typed `Unavailable` instead of
    /// hitting a torn reader.
    pub(crate) fn bounded_index_shutdown(&mut self, deadline: Duration) {
        let start = std::time::Instant::now();
        if let Some(runtime) = &self.tx_index_runtime {
            runtime.request_shutdown();
        }
        // Take the worker out of self so we can join it without holding self
        // mutably across the wait.
        let tx_index_worker = self.tx_index_worker.take();
        let tx_deadline = start + deadline;
        if let Some(mut worker) = tx_index_worker {
            while std::time::Instant::now() < tx_deadline {
                if worker.is_finished() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                worker.join();
            } else {
                tracing::warn!("txindex worker still blocked; abandoning join");
                // Revoke the generation token so late publication is a no-op.
                if let Some(generation_token) = &worker.generation {
                    generation_token.revoke();
                }
                if let Some(lifecycle) = &self.tx_index_lifecycle {
                    lifecycle.store(Arc::new(
                        crate::txindex::TxIndexLifecycle::ShutdownAbandoned,
                    ));
                }
                // Poison the namespace so it cannot be reclaimed in this process.
                worker.poison_namespace();
                // Detach the join handle so Drop does not block on join.
                // The worker thread continues running but will exit after
                // shutdown is observed; Drop is a no-op for the handle.
                worker.detach();
            }
        }
    }
}
