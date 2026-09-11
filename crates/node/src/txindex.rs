//! Asynchronous, durable, node-owned transaction index runtime.
//!
//! The node creates and owns exactly one `TxIndexRuntime` when Core txindex or
//! `ScriptIndex` enables an index capability.
//!
//! The runtime holds a process-local revision counter and a bounded
//! nonblocking wake channel; [`crate::chain_effects::ChainFollowers`] wakes the
//! worker after each committed chain transition. The worker is a process-local
//! reconciliation loop; storage-level CAS conditions on exact reset state,
//! optional revision, and all capability watermarks linearize every ordinary mutation
//! across coexisting current-process and cross-process writers. A lost CAS
//! with an unchanged reset is transient (`StaleIndexState`): the worker
//! discards pending derived work and re-derives from durable state. Exact
//! query gating refuses that temporary lag and the next worker pass repairs
//! it. Independent durable capability watermarks let aligned row families
//! share one parse and commit while divergent families backfill separately.
//! A snapshot-gated query engine serves `bitcoin_rs_rpc::context::TxIndexQuery`
//! and the generic [`bitcoin_rs_rpc::context::ScriptIndexQuery`] without raw index mutex paths.

mod capability;
mod forward;
mod lifecycle;
mod query;
mod runtime;
mod source;
mod worker;
#[cfg(test)]
use bitcoin_rs_chain::{BlockBodySource, BlockTree, TipSnapshot};
#[cfg(test)]
use bitcoin_rs_index::{
    BlockSource, IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark,
    ScriptHash, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
#[cfg(all(test, feature = "fjall"))]
use bitcoin_rs_index::{
    IndexWatermarks,
    reconcile::{ReconcileLeg, ReconcilePhase},
    writer::TxIndexWriter,
};
#[cfg(test)]
use bitcoin_rs_primitives::{BlockHash, Hash256, Txid};
#[cfg(test)]
use bitcoin_rs_rpc::{
    context::BlockLog, context::ScriptIndexQuery, context::TxIndexQuery, context::TxQueryError,
};
pub(crate) use capability::TxIndexCapability;
#[cfg(test)]
use compact_str::CompactString;
#[cfg(test)]
use crossbeam_channel::Receiver;
#[cfg(test)]
use heartbeat::Heartbeat;
#[cfg(test)]
pub(crate) use lifecycle::install_txindex_open_gate;
pub(crate) use lifecycle::{Generation, TxIndexLifecycle, TxIndexOpenSpec, TxIndexWorker};
#[cfg(test)]
use lifecycle::{fail_worker, open_tx_index_on_worker, open_tx_index_with_timeout};
#[cfg(test)]
use namespace::{NAMESPACE_REGISTRY, NamespaceRegistry};
#[cfg(test)]
use parking_lot::RwLock;
#[cfg(test)]
use query::QUERY_SCAN_COUNT_LIMIT;
pub(crate) use query::TxIndexQueryAdapter;
#[cfg(test)]
pub(crate) use query::{QueryEngineLive, TxIndexQueryEngine};
pub use runtime::TxIndexRuntime;
pub(crate) use source::IndexBlockSource;
#[cfg(test)]
use std::{path::Path, sync::Arc, sync::atomic::Ordering, time::Duration};
#[cfg(test)]
pub(crate) use worker::DEFAULT_BATCH_LIMITS;
pub(crate) use worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER;
#[cfg(test)]
use worker::TxIndexWorkerError;
#[cfg(all(test, feature = "fjall"))]
use worker::{PendingForward, ReconcileAction, Worker};

mod heartbeat;

mod namespace;

mod scheduling;

/// Detached publisher for test worker construction; records still sequence.
#[cfg(test)]
pub(crate) fn detached_chain_publisher() -> Arc<crate::state::ChainEventPublisher> {
    Arc::new(crate::state::ChainEventPublisher::detached(0).0)
}

/// Reporter for test worker construction that writes rollback evidence
/// under `data_dir` and exposes its warnings through the returned store.
#[cfg(test)]
pub(crate) fn test_recovery_reporter(
    data_dir: &Path,
) -> (
    Arc<crate::recovery_evidence::RecoveryReporter>,
    Arc<crate::recovery_evidence::WarningStore>,
) {
    let warning_store = Arc::new(crate::recovery_evidence::WarningStore::new());
    let reporter = Arc::new(crate::recovery_evidence::RecoveryReporter::new(
        Arc::clone(&warning_store),
        data_dir.to_path_buf(),
        bitcoin_rs_chain::Network::Regtest
            .genesis_block_hash()
            .to_string_be(),
        1,
    ));
    (reporter, warning_store)
}

#[cfg(all(test, feature = "fjall"))]
mod body_reader_tests;

#[cfg(test)]
mod block_source_tests;

#[cfg(test)]
mod query_tests;

#[cfg(test)]
mod lifecycle_tests;

#[cfg(test)]
mod integration_tests;

#[cfg(all(test, feature = "fjall"))]
#[allow(clippy::expect_used, clippy::panic)]
mod recovery_tests;
