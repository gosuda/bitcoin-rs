use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;

use super::TxIndexSpawn;

pub(super) struct DerivedIndexHost {
    status: Arc<bitcoin_rs_index::runtime::DerivedIndexCapability>,
    enabled: Option<EnabledDerivedIndex>,
    #[cfg(test)]
    spawned_workers: usize,
    #[cfg(test)]
    worker_joined: Arc<AtomicBool>,
}

struct EnabledDerivedIndex {
    runtime: Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>,
    lifecycle: Arc<ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>>,
    adapter: Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>,
    phase: DerivedIndexPhase,
}

enum DerivedIndexPhase {
    Ready(TxIndexSpawn),
    Running(bitcoin_rs_index::runtime::DerivedIndexWorker),
    Stopped,
}

type DerivedIndexParts = (
    Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>,
    TxIndexSpawn,
    Arc<ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>>,
    Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>,
);

impl DerivedIndexHost {
    pub(super) fn from_parts(
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

    pub(super) fn start(
        &mut self,
        chainstate: &bitcoin_rs_chainstate::Chainstate,
        history: bitcoin_rs_storage::pruning::HistoryAccess,
    ) -> Result<()> {
        let Some(enabled) = self.enabled.as_mut() else {
            return Ok(());
        };
        let DerivedIndexPhase::Ready(_) = &enabled.phase else {
            return Ok(());
        };
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
            chainstate.applied_tip_reader(),
            chainstate.block_tree_reader(),
            chainstate.block_body_store_handle(),
            history,
            Some(spawn.body_source),
            Arc::new(super::IndexChainCursorSource(
                chainstate.chain_events_handle(),
            )),
            spawn.recovery_reporter,
            chainstate.shutdown_reader(),
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

    pub(super) fn shutdown(&mut self, deadline: Duration) -> Result<()> {
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
        worker.generation.revoke();
        enabled.lifecycle.store(Arc::new(
            bitcoin_rs_index::runtime::DerivedIndexLifecycle::ShutdownAbandoned,
        ));
        worker.poison_namespace();
        worker.detach();
        Err(anyhow::anyhow!(
            "derived-index worker did not exit within the join deadline; join abandoned"
        ))
    }

    pub(super) fn status(&self) -> Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource> {
        self.status.clone()
    }

    pub(super) fn adapter(
        &self,
    ) -> Option<&Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>> {
        self.enabled.as_ref().map(|enabled| &enabled.adapter)
    }

    #[cfg(test)]
    pub(super) fn is_running(&self) -> bool {
        self.enabled
            .as_ref()
            .is_some_and(|enabled| matches!(enabled.phase, DerivedIndexPhase::Running(_)))
    }

    #[cfg(test)]
    pub(super) fn spawn_count(&self) -> usize {
        self.spawned_workers
    }

    #[cfg(test)]
    pub(super) fn worker_joined(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.worker_joined)
    }

    #[cfg(test)]
    pub(super) fn lifecycle_is_opening(&self) -> bool {
        self.enabled.as_ref().is_some_and(|enabled| {
            matches!(
                &**enabled.lifecycle.load(),
                bitcoin_rs_index::runtime::DerivedIndexLifecycle::Opening
            )
        })
    }

    #[cfg(test)]
    pub(super) fn lifecycle_is_failed(&self) -> bool {
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
