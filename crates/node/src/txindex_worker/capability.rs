//! Txindex lifecycle/progress projection for RPC capability reporting.

use super::{
    Arc, ArcSwap, CapabilityState, CapabilityStatus, IndexCapabilities, IndexProgress,
    TxIndexCapabilitySource, TxIndexLifecycle, TxIndexQueryEngine, TxIndexRuntime, TxQueryError,
    txindex_status,
};

/// Progress reads that raced a tip or revision move before the status
/// report gives up on a coherent answer for this snapshot.
const PROGRESS_READ_ATTEMPTS: usize = 4;

/// Worker-owned txindex facts for the RPC capability projection.
pub(crate) struct TxIndexCapability {
    lifecycle: Option<Arc<ArcSwap<TxIndexLifecycle>>>,
    runtime: Option<Arc<TxIndexRuntime>>,
    enabled: IndexCapabilities,
}

impl TxIndexCapability {
    pub(crate) fn new(
        lifecycle: Option<Arc<ArcSwap<TxIndexLifecycle>>>,
        runtime: Option<Arc<TxIndexRuntime>>,
        enabled: IndexCapabilities,
    ) -> Self {
        Self {
            lifecycle,
            runtime,
            enabled,
        }
    }

    fn report(
        lifecycle: &TxIndexLifecycle,
        runtime: &TxIndexRuntime,
        enabled: IndexCapabilities,
    ) -> CapabilityState {
        if let Some(message) = runtime.failure_message() {
            return CapabilityState::Failed {
                reason: message.to_string(),
            };
        }
        let engine = match lifecycle {
            TxIndexLifecycle::Opening => return CapabilityState::Opening,
            TxIndexLifecycle::ShutdownAbandoned => return CapabilityState::ShutdownAbandoned,
            TxIndexLifecycle::Failed(reason) => {
                return CapabilityState::Failed {
                    reason: reason.to_string(),
                };
            }
            TxIndexLifecycle::Serving(engine) => engine,
        };
        let phase = runtime.phase();
        if let Some((from_height, to_height)) = phase.rolling_back() {
            return CapabilityState::RollingBack {
                from_height,
                to_height,
            };
        }
        let rebuilding = phase.rebuilding();
        if rebuilding != IndexCapabilities::NONE {
            return match Self::progress(engine, rebuilding) {
                Ok(progress) => CapabilityState::Rebuilding {
                    processed_height: progress.processed_height,
                    target_height: progress.target_height,
                },
                Err(error) => CapabilityState::Failed {
                    reason: error.to_string(),
                },
            };
        }
        match Self::progress(engine, enabled) {
            Ok(progress) if progress.synced => CapabilityState::Ready,
            Ok(progress) => CapabilityState::CatchingUp {
                processed_height: progress.processed_height,
                target_height: progress.target_height,
            },
            Err(error) => CapabilityState::Failed {
                reason: error.to_string(),
            },
        }
    }

    fn progress(
        engine: &TxIndexQueryEngine,
        required: IndexCapabilities,
    ) -> Result<IndexProgress, TxQueryError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match engine.index_progress_for(required) {
                Err(TxQueryError::Retry) if attempts < PROGRESS_READ_ATTEMPTS => {}
                result => return result,
            }
        }
    }
}

impl TxIndexCapabilitySource for TxIndexCapability {
    fn capability(&self) -> CapabilityStatus {
        let enabled = !self.enabled.is_empty();
        let state = match (&self.lifecycle, &self.runtime) {
            (Some(lifecycle), Some(runtime)) if enabled => {
                Self::report(&lifecycle.load(), runtime, self.enabled)
            }
            _ => CapabilityState::Disabled,
        };
        txindex_status(enabled, state)
    }
}
