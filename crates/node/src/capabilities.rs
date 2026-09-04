//! RPC status for the concrete node-owned transaction index.
//!
//! This module is intentionally specific to the transaction index. It does
//! not define a generic extension registry, lifecycle interface, namespace
//! schema, or capability framework.

use std::sync::Arc;

use arc_swap::ArcSwap;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_rpc::context::{
    CapabilityProvider, CapabilitySnapshot, CapabilityState, CapabilityStatus, TxQueryError,
};
use parking_lot::Mutex;

use crate::NodeConfig;
use crate::txindex_worker::{IndexProgress, TxIndexLifecycle, TxIndexQueryEngine, TxIndexRuntime};

/// Progress reads that raced a tip or revision move before the status
/// report gives up on a coherent answer for this snapshot.
const PROGRESS_READ_ATTEMPTS: usize = 4;

/// Stable identifier used by the RPC capability report.
pub(crate) const TXINDEX_CAPABILITY: &str = "txindex";

/// Live inputs consumed by the transaction-index status provider.
pub(crate) struct CapabilityInputs {
    /// Worker-published lifecycle snapshot, present when the worker runs.
    pub tx_lifecycle: Option<Arc<ArcSwap<TxIndexLifecycle>>>,
    /// Transaction-index runtime handle, present when the worker runs.
    pub tx_runtime: Option<Arc<TxIndexRuntime>>,
    /// Whether the Core `--txindex` surface or its script-index dependency is enabled.
    pub txindex_enabled: bool,
}

/// Node-owned provider for the concrete RPC capability report.
pub(crate) struct NodeCapabilities {
    inputs: Mutex<CapabilityInputs>,
}

impl NodeCapabilities {
    pub(crate) fn new(inputs: CapabilityInputs) -> Self {
        Self {
            inputs: Mutex::new(inputs),
        }
    }

    /// Maps the worker-owned lifecycle and reconciliation phase onto the RPC
    /// state. Health comes from the worker's own publications; the query
    /// engine is consulted only for the watermark position once the worker
    /// is serving and moving forward.
    fn txindex_status(inputs: &CapabilityInputs) -> CapabilityStatus {
        let state = match (&inputs.tx_lifecycle, &inputs.tx_runtime) {
            (Some(lifecycle), Some(runtime)) if inputs.txindex_enabled => {
                Self::worker_state(&lifecycle.load(), runtime)
            }
            _ => CapabilityState::Disabled,
        };
        CapabilityStatus {
            id: TXINDEX_CAPABILITY.to_owned(),
            compiled: true,
            enabled: inputs.txindex_enabled,
            state,
        }
    }

    fn worker_state(lifecycle: &TxIndexLifecycle, runtime: &TxIndexRuntime) -> CapabilityState {
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
        match Self::progress(engine, IndexCapabilities::TX_LOOKUP) {
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

    /// One coherent progress read: the processed and target heights come
    /// from the same applied tip, re-read a bounded number of times when
    /// the tip or index revision moves underneath.
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

impl CapabilityProvider for NodeCapabilities {
    fn snapshot(&self) -> CapabilitySnapshot {
        let inputs = self.inputs.lock();
        CapabilitySnapshot {
            capabilities: vec![Self::txindex_status(&inputs)],
        }
    }
}

/// Returns whether the transaction-index capability is enabled by config.
#[must_use]
pub(crate) fn txindex_enabled(config: &NodeConfig) -> bool {
    config.indexes.txindex || config.indexes.script_index.is_enabled()
}
