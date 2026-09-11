//! Asynchronous, durable, node-owned transaction index runtime.
//!
//! The node creates and owns exactly one `TxIndexRuntime` when Core txindex or
//! `ScriptIndex` enables an index capability.
//!
//! The runtime holds a process-local revision counter and a bounded
//! nonblocking wake channel; `Chainstate` clones it and wakes the worker
//! after every committed `applied_tip.store`. The worker is a process-local
//! reconciliation loop; storage-level CAS conditions on exact reset state,
//! optional revision, and all capability watermarks linearize every ordinary mutation
//! across coexisting current-process and cross-process writers. A lost CAS
//! with an unchanged reset is transient (`StaleIndexState`): the worker
//! discards pending derived work and re-derives from durable state. Exact
//! query gating refuses that temporary lag and the next worker pass repairs
//! it. Independent durable capability watermarks let aligned row families
//! share one parse and commit while divergent families backfill separately.
//! A snapshot-gated query engine serves `bitcoin_rs_rpc::context::TxIndexQuery`
//! and the generic [`ScriptIndexQuery`] without raw index mutex paths.

use arc_swap::ArcSwap;

use bitcoin_rs_chain::{BlockBodySource, BlockTree, TipSnapshot};

use bitcoin_rs_index::{
    BlockSource, IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark,
    IndexWatermarks, IndexWriteFence, PreparedBatch, PreparedBatchLimits, ScriptHash,
    ScriptLiveScan, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
    reconcile::{ReconcileLeg, ReconcilePhase},
    types::{TxPosition, TxPositionValue},
    writer::TxIndexWriter,
};

use bitcoin_rs_primitives::{Block, BlockHash, Hash256, OutPoint, Tx, Txid, deserialize};

use bitcoin_rs_rpc::{
    capabilities::{CapabilityState, CapabilityStatus, TxIndexCapabilitySource, txindex_status},
    context::{
        BlockLog, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot,
        SpendingRecord, TxIndexInfo, TxIndexQuery, TxQueryError, record_at_height,
    },
};

use bitcoin_rs_storage::{PrefixScanLimit, block_body::BlockBodyStore};

use compact_str::CompactString;

use crossbeam_channel::{Receiver, Sender};

#[cfg(test)]
use heartbeat::Heartbeat;

#[cfg(test)]
use namespace::{NAMESPACE_REGISTRY, NamespaceRegistry};

use parking_lot::{Mutex, RwLock};

#[cfg(test)]
use startup::{fail_worker, open_tx_index_on_worker, open_tx_index_with_timeout};
use startup::open_tx_index_store_on_worker;

#[cfg(test)]
use std::path::Path;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

mod capability;
mod catch_up;
mod cursor;
mod heartbeat;
mod lifecycle;
mod namespace;
mod query;
mod query_adapter;
mod reconciliation;
mod rollback;
mod scheduling;
mod startup;

pub(crate) use capability::TxIndexCapability;
use query::IndexProgress;
pub(crate) use query::{IndexBlockSource, QueryEngineLive, TxIndexQueryEngine};

/// Bounded scan limits used by the query engine.
///
/// These are query-side safety limits, not the writer batch limits.
const QUERY_SCAN_ROW_LIMIT: usize = 1_000_000;
const QUERY_SCAN_BYTE_LIMIT: usize = 64 << 20;
const QUERY_SCAN_COUNT_LIMIT: usize = 4_096;
const QUERY_BODY_READ_LIMIT: usize = 4_096;
const MAX_SERIALIZED_BLOCK_BYTES: usize = 4_000_000;

/// Writer-side batch limits.
///
/// Capped by actual retained row count and encoded bytes to keep each forward
/// commit bounded.
const BATCH_BYTE_LIMIT: usize = 256 << 20;

pub(crate) const ROCKSDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

pub(crate) const DEFAULT_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

pub(crate) const REDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 16_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

/// Default fork depth at which a stale txindex watermark routes to a
/// selective reset + rebuild instead of a per-block rewind.
///
/// Grounded in three measured runs of per-block forward-ingest versus rollback
/// cost (see `docs/benchmarks/index-rollback-rebuild-cutover.md`): the default
/// routes the 834k-block stale-branch incident shape to a rebuild while organic
/// reorgs (tens of blocks) keep rewinding block by block.
pub(crate) const DEFAULT_ROLLBACK_REBUILD_CUTOVER: u32 = 100_000;

const IDENTITY_CHUNK_BLOCKS: u32 = 65_536;
const POSITION_PREFETCH_BLOCKS: usize = 65_536;
/// In-memory parallel-prepare cap owned by this worker. 256 matches the IBD
/// download window so a filled staging set can prepare in one pass when bodies
/// are small; catch-up also prepares already-stored bodies, so this is not
/// `RECEIVED_BLOCK_BUDGET`. The byte budget below is independent of P2P staging.
const PREPARE_CHUNK_BLOCKS: usize = 256;
/// Serialized-body budget for one parallel prepare step. Later bodies are not
/// retained once this bound would be exceeded. Stops a 1 MiB-class window from
/// holding 256 bodies in RAM while still packing early-chain blocks up to the
/// count cap.
const PREPARE_CHUNK_BYTES: usize = 32 << 20;
const REVISION_QUIET_PERIOD: Duration = Duration::from_millis(100);
const FORWARD_BATCH_DELAY: Duration = Duration::from_millis(100);

/// Maximum time the txindex worker waits for the storage engine to open and
/// recover the index store. A store open that exceeds this deadline is
/// treated as a wedge — the worker publishes `Failed` so the node stays
/// operable without the index rather than spinning one thread at 100% CPU
/// indefinitely. The deadline is a backstop, not a tight bound: the issue's
/// own data shows fjall/lsm-tree manifest recovery of a 139 GiB store logs
/// progress within seconds and then, when wedged, freezes block I/O for
/// hours. Thirty minutes is far below the observed wedge and far above any
/// legitimate recovery, so it cannot falsely kill a slow-but-progressing
/// open while still surfacing a stuck one. The 30-second heartbeat already
/// makes a slow open observable to an operator watching logs.
const TXINDEX_OPEN_TIMEOUT: Duration = Duration::from_mins(30);

/// Shared wake/revision/health state owned by `NodeState` and referenced by
/// `Chainstate`, the worker thread, and the query engine.
#[derive(Debug)]
pub struct TxIndexRuntime {
    revision: AtomicU64,
    shutdown: AtomicBool,
    failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<CompactString>>,
    phase: arc_swap::ArcSwap<ReconcilePhase>,
}
impl TxIndexRuntime {
    /// Creates a runtime attached to `wake_tx`.
    #[must_use]
    pub fn new(wake_tx: Sender<()>) -> Self {
        Self {
            revision: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wake_tx,
            failure_message: RwLock::new(None),
            phase: arc_swap::ArcSwap::from_pointee(ReconcilePhase::FORWARD),
        }
    }

    /// Publishes the reconciliation phase. Only the worker thread writes it.
    pub fn publish_phase(&self, phase: ReconcilePhase) {
        if **self.phase.load() != phase {
            self.phase.store(Arc::new(phase));
        }
    }

    /// Publishes `leg` for `capabilities`, leaving the other legs as they are.
    pub fn publish_leg(&self, capabilities: IndexCapabilities, leg: ReconcileLeg) {
        self.publish_phase(self.phase().with_leg(capabilities, leg));
    }

    /// Returns the reconciliation phase the worker last published.
    #[must_use]
    pub fn phase(&self) -> ReconcilePhase {
        **self.phase.load()
    }

    /// Called immediately after a committed `applied_tip.store`.
    ///
    /// Increments the revision with `Release` ordering and `try_send`s one
    /// wake.  Coalesced or lost wakes are harmless: the worker reconciles
    /// against current authoritative state each loop.
    pub fn wake(&self) {
        self.revision.fetch_add(1, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Marks the worker as failed with an explanatory message.
    pub fn publish_failed(&self, message: impl Into<CompactString>) {
        *self.failure_message.write() = Some(message.into());
        self.failed.store(true, Ordering::Release);
    }

    /// Returns the current revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Returns true once a failure or shutdown has been published.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    /// Initiates graceful shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Returns the published failure message, if any.
    #[must_use]
    pub fn failure_message(&self) -> Option<CompactString> {
        self.failure_message.read().clone()
    }
}

/// Monotonic publication token. Each worker holds one; a revoked token makes
/// `rcu` publication a no-op so a late worker cannot publish after abandonment.
#[derive(Clone, Debug)]
pub(crate) struct Generation {
    id: u64,
    revoked: Arc<AtomicBool>,
}

impl Generation {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

/// One immutable lifecycle snapshot published atomically behind `ArcSwap`.
///
/// Only `Serving` carries a query payload — the complete existing
/// `TxIndexQueryEngine`, never a raw reader. Readiness is not a lifecycle
/// state: the engine proves it per query from the durable watermarks
/// (`IDX-03`), and the worker reports its reconciliation leg through
/// `TxIndexRuntime::phase`. `Opening`, `Failed`, and `ShutdownAbandoned`
/// carry no payload; the adapter returns typed `Unavailable` for them.
#[derive(Clone)]
pub(crate) enum TxIndexLifecycle {
    Opening,
    Serving(Arc<TxIndexQueryEngine>),
    Failed(CompactString),
    ShutdownAbandoned,
}

impl TxIndexLifecycle {
    fn query_payload(&self) -> Option<&Arc<TxIndexQueryEngine>> {
        match self {
            Self::Serving(engine) => Some(engine),
            _ => None,
        }
    }

    fn unavailable_reason(&self) -> &'static str {
        match self {
            Self::Opening => "txindex is opening",
            Self::Failed(_) => "txindex is unavailable",
            Self::ShutdownAbandoned => "txindex was abandoned at shutdown",
            Self::Serving(_) => unreachable!("query_payload is Some for Serving"),
        }
    }
}

/// Stable outer query adapter constructed before backend open and before RPC
/// context construction. Each method loads exactly one `ArcSwap` snapshot,
/// holds that `Arc` for the complete request, and delegates to the captured
/// query engine if a payload exists. It never reads lifecycle state and query
/// payload from separate loads.
#[derive(Clone)]
pub(crate) struct TxIndexQueryAdapter {
    lifecycle: Arc<ArcSwap<TxIndexLifecycle>>,
}

impl TxIndexQueryAdapter {
    pub(crate) fn new(lifecycle: Arc<ArcSwap<TxIndexLifecycle>>) -> Self {
        Self { lifecycle }
    }

    fn load_engine(&self) -> Result<Arc<TxIndexQueryEngine>, TxQueryError> {
        let snapshot = self.lifecycle.load_full();
        match snapshot.query_payload() {
            Some(engine) => Ok(Arc::clone(engine)),
            None => Err(TxQueryError::Unavailable(
                snapshot.unavailable_reason().into(),
            )),
        }
    }
}

/// Immutable specification for worker-owned store open. Constructed
/// synchronously in `NodeState::open`; consumed on the worker thread.
pub(crate) struct TxIndexOpenSpec {
    pub(crate) data_dir: PathBuf,
    pub(crate) namespace: &'static str,
    pub(crate) storage_backend: bitcoin_rs_storage::StorageBackend,
    pub(crate) cache_bytes: u64,
    pub(crate) epoch: u64,
    pub(crate) enabled: IndexCapabilities,
    pub(crate) rollback_rebuild_cutover: u32,
    pub(crate) canonical_data_root: PathBuf,
    /// Authoritative UTXO set used to seed and resolve the compact live view.
    /// Test-only open specs may leave this unset; live queries then fail closed.
    pub(crate) utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    /// Serializes a live-view query or seed against a chain transition.
    pub(crate) chain_transition: Option<Arc<Mutex<()>>>,
}

/// Test-only keyed open gate. Holds the worker inside the open phase until
/// released, proving RPC binds and queries see `Opening` while the store is
/// not yet open. `#[cfg(test)]` only — not a production trait or `NodeConfig` field.
#[cfg(test)]
pub(crate) static TXINDEX_OPEN_GATE: std::sync::LazyLock<
    parking_lot::Mutex<Option<crossbeam_channel::Receiver<()>>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

#[cfg(test)]
pub(crate) fn install_txindex_open_gate() -> crossbeam_channel::Sender<()> {
    let (tx, rx) = crossbeam_channel::bounded(1);
    *TXINDEX_OPEN_GATE.lock() = Some(rx);
    tx
}

#[cfg(test)]
pub(crate) fn wait_txindex_open_gate() {
    if let Some(rx) = TXINDEX_OPEN_GATE.lock().as_ref() {
        let _ = rx.recv();
    }
}

#[cfg(not(test))]
pub(crate) fn wait_txindex_open_gate() {}

/// Handle used to spawn and join the supervised reconciliation worker.
pub(crate) struct TxIndexWorker {
    runtime: Arc<TxIndexRuntime>,
    join_handle: Option<JoinHandle<()>>,
    pub(crate) generation: Option<Generation>,
    /// Canonical namespace key for poisoning on abandonment.
    namespace_key: Option<PathBuf>,
}

/// Result of opening the txindex store: writer, reader, and batch limits.
pub(crate) struct OpenTxIndex {
    pub(crate) writer: Arc<dyn TxIndexWriter>,
    pub(crate) reader: Arc<dyn bitcoin_rs_index::IndexReader>,
    #[allow(dead_code)]
    pub(crate) batch_limits: PreparedBatchLimits,
}

struct TxIndexComposer {
    backend: bitcoin_rs_storage::StorageBackend,
    epoch: u64,
}

impl crate::storage_backend::StoreConsumer for TxIndexComposer {
    type Output = OpenTxIndex;
    type Error = TxIndexWorkerError;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output, Self::Error>
    where
        S: bitcoin_rs_storage::KvStore,
    {
        let batch_limits = match self.backend {
            bitcoin_rs_storage::StorageBackend::RocksDb => ROCKSDB_BATCH_LIMITS,
            bitcoin_rs_storage::StorageBackend::Fjall => DEFAULT_BATCH_LIMITS,
            bitcoin_rs_storage::StorageBackend::Redb => REDB_BATCH_LIMITS,
        };
        open_tx_index_store_on_worker(store, batch_limits, self.epoch)
    }
}

/// Exact spent-coin script anchor decoded from one block's undo record.
///
/// The undo restores are precisely the external coins spent by the block and
/// carry their full `script_pubkey`. Intra-block spends are absent because
/// those outputs never entered the committed UTXO set.
pub(crate) struct UndoScripts {
    scripts: hashbrown::HashMap<([u8; 32], u32), Vec<u8>>,
}

impl UndoScripts {
    pub(crate) fn from_undo_bytes(
        bytes: &[u8],
        hash: Hash256,
    ) -> Result<Self, bitcoin_rs_utxo::undo_codec::UndoCodecError> {
        let batch = bitcoin_rs_utxo::undo_codec::decode(bytes, hash)?;
        let mut scripts = hashbrown::HashMap::with_capacity(batch.restores().len());
        for add in batch.restores() {
            scripts.insert(
                (add.outpoint.txid.0.to_le_bytes(), add.outpoint.vout),
                add.txout.script_pubkey.as_bytes().to_vec(),
            );
        }
        Ok(Self { scripts })
    }
}

impl bitcoin_rs_index::SpentCoinScripts for UndoScripts {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
        self.scripts.get(&(*txid, vout)).map(Vec::as_slice)
    }
}

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

struct Worker {
    runtime: Arc<TxIndexRuntime>,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    batch_limits: PreparedBatchLimits,
    enabled: IndexCapabilities,
    chain_events: Arc<crate::state::ChainEventPublisher>,
    /// Sink for the index-ahead rollback evidence (`chain-rollback-event`
    /// marker plus `getblockchaininfo` warning).
    reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
    wake_rx: Receiver<()>,
    quiet_period: Duration,
    batch_delay: Duration,
    /// Fork depth at which a stale watermark routes to a selective reset
    /// and rebuild instead of a per-block rewind. `u32::MAX` means rewind
    /// at any depth (pre-cutover behavior).
    rollback_rebuild_cutover: u32,
    /// Authoritative UTXO source for live-view seeding.
    utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    /// Chain transition authority shared with apply and RPC reads.
    chain_transition: Option<Arc<Mutex<()>>>,
}

/// Uncommitted contiguous rows based on one unchanged durable watermark.
struct PendingForward {
    fence: IndexWriteFence,
    watermarks: IndexWatermarks,
    capabilities: IndexCapabilities,
    durable: Option<IndexWatermark>,
    batch: PreparedBatch,
    deadline: Instant,
}

impl PendingForward {
    fn endpoint(&self) -> IndexWatermark {
        let Some(watermark) = self.batch.watermark() else {
            unreachable!("pending forward batch is nonempty");
        };
        watermark
    }
}

/// Identity of one block on the active chain, captured under a short tree lock.
#[derive(Clone, Copy, Debug)]
struct BlockIdentity {
    height: u32,
    hash: [u8; 32],
    parent_hash: [u8; 32],
}

/// Outcome of one sub-chunk prepare-and-admit step.
enum ChunkAction {
    Continue,
    Stalled,
    Progressed,
}

enum CursorCommit {
    Settled,
    ResetRejected,
    NotAligned,
}

#[derive(Debug)]
enum ReconcileAction {
    Progressed,
    Buffered,
    CaughtUp,
    Stalled,
}

#[derive(Debug, thiserror::Error)]
enum TxIndexWorkerError {
    #[error("txindex worker stopped")]
    Stopped,
    #[error("txindex durable watermark changed while a forward batch was pending")]
    PendingDurableChanged,
    #[error("txindex storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(
        "txindex store open timed out after {secs}s — the storage engine recovery may be stuck"
    )]
    OpenTimeout { secs: u64 },
    #[error("txindex index error: {0}")]
    Index(#[from] IndexError),
    #[error("txindex worker: missing body at height {height}, hash {hash}")]
    MissingBody { height: u32, hash: Hash256 },
    #[error("txindex worker: body store missing")]
    NoBodyStore,
    #[error("txindex worker: authoritative UTXO view missing for ScriptLive")]
    MissingUtxo,
    #[error("txindex worker: chain transition authority missing for ScriptLive")]
    MissingChainTransition,
    #[error("txindex worker: undo record missing or unreadable at height {height}, hash {hash}")]
    UndoUnavailable { height: u32, hash: Hash256 },
    #[error("txindex worker: target chain node missing at height {height}")]
    MissingTargetChain { height: u32 },
    #[error("txindex worker: rollback evidence marker not written: {0}")]
    RollbackEvidence(#[source] crate::recovery_evidence::EvidenceError),
}

impl TxIndexWorkerError {
    fn requires_capability_rebuild(&self) -> bool {
        matches!(
            self,
            Self::MissingBody { .. } | Self::Index(IndexError::MissingWatermarkIdentity { .. })
        )
    }
}

#[cfg(all(test, feature = "fjall"))]
mod body_reader_tests;

#[cfg(test)]
#[path = "txindex_worker_block_source_tests.rs"]
mod block_source_tests;

#[cfg(test)]
#[path = "txindex_worker_query_tests.rs"]
mod query_tests;

#[cfg(test)]
#[path = "txindex_worker_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "txindex_worker_integration_tests.rs"]
mod integration_tests;

#[cfg(all(test, feature = "fjall"))]
#[allow(clippy::expect_used, clippy::panic)]
#[path = "txindex_worker_recovery_tests.rs"]
mod recovery_tests;
