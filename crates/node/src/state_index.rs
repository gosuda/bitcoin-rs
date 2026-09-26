//! Derived-index (txindex/scriptindex) lifecycle: open, start, shutdown.
//!
//! One host owns the whole capability: the always-present status source, the
//! configured parts (runtime, spawn, lifecycle, adapter), and the one
//! state-machine slot for the worker. `NodeState` holds this host and
//! delegates its index surface to it.

use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;

use super::TxIndexSpawn;

/// Owns the derived-index parts and the one worker slot for a node.
///
/// A disabled config keeps `enabled: None`; the status source still answers
/// a concrete `Disabled` row in every phase.
pub(crate) struct DerivedIndexHost {
    status: Arc<bitcoin_rs_index::runtime::DerivedIndexCapability>,
    enabled: Option<EnabledDerivedIndex>,
    /// Workers this host has spawned; the idempotence contract needs a
    /// measure that distinguishes one worker from two.
    #[cfg(test)]
    spawned_workers: usize,
    /// Set once the owned worker's join returns. An abandoned join never
    /// sets it, so the lifecycle tests prove join-before-checkpoint rather
    /// than only shutdown-requested-before-checkpoint.
    #[cfg(test)]
    worker_joined: Arc<AtomicBool>,
}

/// The configured index parts. They live as long as the node so status and
/// adapter queries keep answering after the worker stops.
struct EnabledDerivedIndex {
    runtime: Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>,
    lifecycle: Arc<ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>>,
    adapter: Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>,
    phase: DerivedIndexPhase,
}

/// The one state-machine slot that replaces the old spawn/worker pair.
enum DerivedIndexPhase {
    /// `open()` produced a spawn; `start()` has not run yet.
    Ready(TxIndexSpawn),
    /// `start()` spawned the worker; live until `shutdown()`/`Drop`.
    Running(bitcoin_rs_index::runtime::DerivedIndexWorker),
    /// `shutdown()`/`Drop` took and joined (or abandoned) the worker.
    Stopped,
}

/// The parts a configured derived index needs from node open: its runtime,
/// the pending spawn, the lifecycle slot, and the query adapter.
type DerivedIndexParts = (
    Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>,
    TxIndexSpawn,
    Arc<ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>>,
    Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>,
);

impl DerivedIndexHost {
    /// PRE: `NodeState::open` has completed construction; `enabled` is `Some`
    /// only if an index capability is configured.
    /// POST: the host is in phase `Ready`, or disabled.
    pub(crate) fn from_parts(
        enabled: Option<DerivedIndexParts>,
        status: Arc<bitcoin_rs_index::runtime::DerivedIndexCapability>,
    ) -> Self {
        let enabled = enabled.map(|(runtime, spawn, lifecycle, adapter)| EnabledDerivedIndex {
            runtime,
            lifecycle,
            adapter,
            phase: DerivedIndexPhase::Ready(spawn),
        });
        Self {
            status,
            enabled,
            #[cfg(test)]
            spawned_workers: 0,
            #[cfg(test)]
            worker_joined: Arc::new(AtomicBool::new(false)),
        }
    }

    /// PRE: the applied tip is authoritative (after crash recovery).
    /// POST: a `Ready` host becomes `Running`; a disabled, `Running`, or
    /// `Stopped` host does not change.
    /// INVARIANT: `start` is idempotent; a second call does not spawn a
    /// second worker.
    pub(crate) fn start(&mut self, chainstate: &bitcoin_rs_chainstate::Chainstate) -> Result<()> {
        let Some(enabled) = self.enabled.as_mut() else {
            return Ok(());
        };
        let DerivedIndexPhase::Ready(_) = &enabled.phase else {
            return Ok(());
        };
        // Take the spawn out first: a failed spawn leaves `Stopped`, which
        // permanently consumes the pending spawn exactly as the old
        // `Option`-field code did.
        let DerivedIndexPhase::Ready(spawn) =
            core::mem::replace(&mut enabled.phase, DerivedIndexPhase::Stopped)
        else {
            return Ok(());
        };
        let worker = bitcoin_rs_index::runtime::DerivedIndexWorker::spawn_with_open(
            Arc::clone(&enabled.runtime),
            spawn.spec,
            Arc::clone(&enabled.lifecycle),
            spawn.generation,
            chainstate.applied_tip_handle(),
            chainstate.block_tree_handle(),
            chainstate.block_body_store_handle(),
            spawn.block_source,
            Some(spawn.body_source),
            Arc::new(super::IndexChainCursorSource(
                chainstate.chain_events_handle(),
            )),
            spawn.recovery_reporter,
            chainstate.shutdown_handle(),
            spawn.wake_rx,
        )
        .context("spawn txindex worker")?;
        enabled.phase = DerivedIndexPhase::Running(worker);
        #[cfg(test)]
        {
            self.spawned_workers += 1;
        }
        Ok(())
    }

    /// PRE: teardown or drop started.
    /// POST: a `Running` host becomes `Stopped`; a clean join happened before
    /// `deadline`, or the join is abandoned, the generation token revoked,
    /// `ShutdownAbandoned` published, the namespace poisoned, and an error
    /// returned so the caller's teardown records the abandonment and
    /// suppresses the clean checkpoint. A joined worker whose backend open
    /// detached a thread (shutdown or open deadline mid-open) is also an
    /// error: the supervisor exits while the open thread may still write.
    /// INVARIANT: `shutdown` is idempotent; `request_shutdown` runs on every
    /// call.
    pub(crate) fn shutdown(&mut self, deadline: Duration) -> Result<()> {
        let start = Instant::now();
        let Some(enabled) = self.enabled.as_mut() else {
            return Ok(());
        };
        enabled.runtime.request_shutdown();
        let DerivedIndexPhase::Running(mut worker) =
            core::mem::replace(&mut enabled.phase, DerivedIndexPhase::Stopped)
        else {
            return Ok(());
        };
        let tx_deadline = start + deadline;
        while Instant::now() < tx_deadline {
            if worker.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if worker.is_finished() {
            // A supervisor that exits mid-open leaves its detached backend
            // open thread possibly writing to the store; joining it is not a
            // clean stop, so the checkpoint must stay suppressed.
            let open_abandoned = worker.open_was_abandoned();
            worker.join();
            #[cfg(test)]
            self.worker_joined.store(true, Ordering::Release);
            if open_abandoned {
                return Err(anyhow::anyhow!(
                    "derived-index worker exited with a detached backend open still in flight"
                ));
            }
            return Ok(());
        }
        tracing::warn!("txindex worker still blocked; abandoning join");
        // Revoke the generation token so late publication is a no-op.
        if let Some(generation_token) = &worker.generation {
            generation_token.revoke();
        }
        enabled.lifecycle.store(Arc::new(
            bitcoin_rs_index::runtime::DerivedIndexLifecycle::ShutdownAbandoned,
        ));
        // Poison the namespace so it cannot be reclaimed in this process.
        worker.poison_namespace();
        // Detach the join handle so Drop does not block on join. The
        // worker thread continues running but will exit after shutdown is
        // observed; Drop is a no-op for the handle.
        worker.detach();
        Err(anyhow::anyhow!(
            "derived-index worker did not exit within the join deadline; join abandoned"
        ))
    }

    /// POST: returns a concrete answer in every phase, including disabled.
    /// INVARIANT: callers never see no status for a live node.
    pub(crate) fn status(
        &self,
    ) -> Arc<dyn bitcoin_rs_rpc::capabilities::DerivedIndexCapabilitySource> {
        self.status.clone()
    }

    pub(crate) fn adapter(
        &self,
    ) -> Option<&Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>> {
        self.enabled.as_ref().map(|enabled| &enabled.adapter)
    }

    /// Observation accessor for the unit tests.
    #[cfg(test)]
    pub(crate) fn is_running(&self) -> bool {
        self.enabled
            .as_ref()
            .is_some_and(|enabled| matches!(enabled.phase, DerivedIndexPhase::Running(_)))
    }

    /// Workers this host has spawned; a correct `start` never exceeds one.
    #[cfg(test)]
    pub(crate) fn spawn_count(&self) -> usize {
        self.spawned_workers
    }

    /// `true` once the owned worker's join returned; stays `false` when the
    /// bounded join was abandoned.
    #[cfg(test)]
    pub(crate) fn worker_joined(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.worker_joined)
    }

    /// Observation accessor for the unit tests.
    #[cfg(test)]
    pub(crate) fn lifecycle_is_opening(&self) -> bool {
        self.enabled.as_ref().is_some_and(|enabled| {
            matches!(
                &**enabled.lifecycle.load(),
                bitcoin_rs_index::runtime::DerivedIndexLifecycle::Opening
            )
        })
    }

    /// Observation accessor for the unit tests: the worker published a
    /// durable terminal failure or its join was abandoned. A transient
    /// progress-read race surfaces as `CapabilityState::Failed` without
    /// touching the lifecycle slot, so this distinguishes real open
    /// failures from raced status reads.
    #[cfg(test)]
    pub(crate) fn lifecycle_is_failed(&self) -> bool {
        self.enabled.as_ref().is_some_and(|enabled| {
            matches!(
                &**enabled.lifecycle.load(),
                bitcoin_rs_index::runtime::DerivedIndexLifecycle::Failed(_)
                    | bitcoin_rs_index::runtime::DerivedIndexLifecycle::ShutdownAbandoned
            )
        })
    }
}

impl Drop for DerivedIndexHost {
    /// POST: if `shutdown` was not called, the worker stop is requested and
    /// any `Running` worker is joined. Order-safe relative to
    /// `Chainstate::close()`: admission stays closed through the permanent
    /// `closed` flag, and the worker only reads chain handles, so firing
    /// this drop before or after the admission guard's release is
    /// behavior-identical.
    fn drop(&mut self) {
        let Some(enabled) = self.enabled.as_mut() else {
            return;
        };
        if let DerivedIndexPhase::Running(worker) =
            core::mem::replace(&mut enabled.phase, DerivedIndexPhase::Stopped)
        {
            worker.join();
            #[cfg(test)]
            self.worker_joined.store(true, Ordering::Release);
        }
    }
}
