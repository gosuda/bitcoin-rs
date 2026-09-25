//! Asynchronous, durable, node-owned transaction index runtime.
//!
//! The node creates and owns exactly one `DerivedIndexRuntime` when Core txindex or
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
//! A snapshot-gated query engine serves `crate::query_api::DerivedIndexQuery`
//! and the generic [`ScriptIndexQuery`] without raw index mutex paths.

use arc_swap::ArcSwap;

use bitcoin_rs_chain::{BlockBodySource, BlockTree, BlockTreeReader, TipReader, TipSnapshot};

use crate::{
    BlockSource, IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark,
    IndexWatermarks, IndexWriteFence, PreparedBatch, PreparedBatchLimits, ScriptHash,
    ScriptLiveScan, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
    reconcile::{ReconcileLeg, ReconcilePhase},
    types::{TxPosition, TxPositionValue},
    writer::TxIndexWriter,
};

use bitcoin_rs_primitives::{Block, BlockHash, Hash256, OutPoint, Tx, Txid, deserialize};

use crate::block_log::{BlockLog, record_at_height};
use crate::capabilities::{
    CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource, derived_index_status,
};
use crate::query_api::{
    DerivedIndexInfo, DerivedIndexQuery, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,
    ScriptIndexSnapshot, SpendingRecord, TxQueryError,
};

use bitcoin_rs_storage::{
    PrefixScanLimit,
    block_body::BlockBodyStore,
    pruning::{HistoryAccess, HistoryUnavailable},
};

use compact_str::CompactString;
use std::sync::atomic::AtomicU64;

use crossbeam_channel::{Receiver, Sender};

#[cfg(all(test, feature = "fjall"))]
use parking_lot::Mutex;
use parking_lot::RwLock;

#[cfg(all(test, feature = "fjall"))]
use startup::open_derived_index_with_timeout;

use std::path::Path;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

mod capability;

mod catch_up;

mod cursor;

mod lifecycle;

mod namespace;

mod query;

mod reconciliation;

mod rollback;

mod startup;
pub use startup::open_derived_index_store_on_worker;

pub use capability::DerivedIndexCapability;
use query::IndexProgress;
pub use query::{DerivedIndexQueryEngine, IndexBlockSource, QueryEngineLive};

/// Shared wake/revision/health state owned by `NodeState` and referenced by
/// `Chainstate`, the worker thread, and the query engine.
#[derive(Debug)]
pub struct DerivedIndexRuntime {
    revision: AtomicU64,
    pub(super) shutdown: AtomicBool,
    pub(super) failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<CompactString>>,
    phase: arc_swap::ArcSwap<ReconcilePhase>,
}

impl DerivedIndexRuntime {
    /// Creates shared runtime state.
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

    /// Reads the published reconciliation phase.
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

    /// Reads the wake revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Reports whether shutdown or failure was published.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    /// Initiates graceful shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Reads the published failure message.
    #[must_use]
    pub fn failure_message(&self) -> Option<CompactString> {
        self.failure_message.read().clone()
    }
}

impl DerivedIndexQuery for DerivedIndexQueryAdapter {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction(txid)
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.outpoint_value(outpoint)
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction_height(txid)
    }

    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        let engine = self.load_engine()?;
        engine.index_info()
    }
}

impl ScriptIndexQuery for DerivedIndexQueryAdapter {
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let engine = self.load_engine()?;
        engine.history_snapshot(scripthash)
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.unspent_outputs(scripthash)
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.spender(outpoint)
    }
}

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

/// Writer-side batch limits for the default (fjall) backend.
pub const DEFAULT_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

/// Writer-side batch limits for the redb backend.
pub const REDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
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
pub const DEFAULT_ROLLBACK_REBUILD_CUTOVER: u32 = 100_000;

const IDENTITY_CHUNK_BLOCKS: u32 = 65_536;

const POSITION_PREFETCH_BLOCKS: usize = 65_536;

/// In-memory parallel-prepare cap owned by this worker. 256 matches the IBD
/// download window so a filled staging set can prepare in one pass when bodies
/// are small; catch-up also prepares already-stored bodies, so this is not
/// `RECEIVED_BLOCK_BUDGET`. The byte budget below is independent of P2P staging.
const PREPARE_CHUNK_BLOCKS: usize = 256;

/// Serialized-body budget for one parallel prepare step. Loading stops once
/// the total reaches this bound; the body that reaches it is kept, so a step
/// holds at most this budget plus one body. Stops a 1 MiB-class window from
/// holding 256 bodies in RAM while still packing early-chain blocks up to the
/// count cap.
const PREPARE_CHUNK_BYTES: usize = 32 << 20;

const REVISION_QUIET_PERIOD: Duration = Duration::from_millis(100);

const FORWARD_BATCH_DELAY: Duration = Duration::from_millis(100);

/// Upper bound on waiting for backend recovery. Timeout isolates the index
/// failure from the node; it does not prove recovery stopped making progress.
/// The backend open thread cannot be cancelled, so abandonment poisons its namespace.
const TXINDEX_OPEN_TIMEOUT: Duration = Duration::from_mins(30);

/// Monotonic publication token. Each worker holds one; a revoked token makes
/// `rcu` publication a no-op so a late worker cannot publish after abandonment.
#[derive(Clone, Debug)]
pub struct Generation {
    id: u64,
    revoked: Arc<AtomicBool>,
}

impl Generation {
    /// Creates a publication token for one worker generation.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Reads the generation identifier.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Revokes the token; late publication becomes a no-op.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    /// Reports whether this generation was revoked.
    #[must_use]
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

/// One immutable lifecycle snapshot published atomically behind `ArcSwap`.
///
/// Only `Serving` carries a query payload — the complete existing
/// `DerivedIndexQueryEngine`, never a raw reader. Readiness is not a lifecycle
/// state: the engine proves it per query from the durable watermarks
/// (`IDX-03`), and the worker reports its reconciliation leg through
/// `DerivedIndexRuntime::phase`. `Opening`, `Failed`, and `ShutdownAbandoned`
/// carry no payload; the adapter returns typed `Unavailable` for them.
#[derive(Clone)]
pub enum DerivedIndexLifecycle {
    /// The worker is still opening its store.
    Opening,
    /// The complete query engine is published.
    Serving(Arc<DerivedIndexQueryEngine>),
    /// The worker failed; the string is a bounded diagnostic.
    Failed(CompactString),
    /// The worker was abandoned at shutdown before its store opened.
    ShutdownAbandoned,
}

/// Stable outer query adapter constructed before backend open and before RPC
/// context construction.
///
/// Each method loads exactly one `ArcSwap` snapshot,
/// holds that `Arc` for the complete request, and delegates to the captured
/// query engine if a payload exists. It never reads lifecycle state and query
/// payload from separate loads.
#[derive(Clone)]
pub struct DerivedIndexQueryAdapter {
    lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>,
}

impl DerivedIndexQueryAdapter {
    /// Constructs the stable adapter over the lifecycle publication cell.
    #[must_use]
    pub fn new(lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>) -> Self {
        Self { lifecycle }
    }

    fn load_engine(&self) -> Result<Arc<DerivedIndexQueryEngine>, TxQueryError> {
        let snapshot = self.lifecycle.load_full();
        match &*snapshot {
            DerivedIndexLifecycle::Serving(engine) => Ok(Arc::clone(engine)),
            // Opening has not published a query engine yet.
            DerivedIndexLifecycle::Opening => {
                Err(TxQueryError::Unavailable("txindex is opening".into()))
            }
            // Failed startup leaves the index unavailable.
            DerivedIndexLifecycle::Failed(_) => {
                Err(TxQueryError::Unavailable("txindex is unavailable".into()))
            }
            // Shutdown abandoned the backend before it opened.
            DerivedIndexLifecycle::ShutdownAbandoned => Err(TxQueryError::Unavailable(
                "txindex was abandoned at shutdown".into(),
            )),
        }
    }
}

/// Immutable specification for worker-owned store open. Constructed
/// synchronously in `NodeState::open`; consumed on the worker thread.
pub struct DerivedIndexOpenSpec {
    /// Data directory the `txindex` namespace lives under.
    pub data_dir: PathBuf,
    /// Namespace subdirectory name.
    pub namespace: &'static str,
    /// Backend label retained for open-time logging; the concrete backend is
    /// constructed by `open_store`, which node owns.
    pub storage_backend: bitcoin_rs_storage::StorageBackend,
    /// Process epoch stamped into new writer state.
    pub epoch: u64,
    /// Capability set the worker maintains.
    pub enabled: IndexCapabilities,
    /// Fork depth routing stale watermarks to reset+rebuild.
    pub rollback_rebuild_cutover: u32,
    /// Canonicalized data root used for namespace exclusion.
    pub canonical_data_root: PathBuf,
    /// Opens the durable store inside `dir`. Concrete backend construction
    /// stays with the node's storage composition; the runtime only calls the
    /// closure on its worker thread.
    #[allow(clippy::type_complexity)]
    pub open_store:
        Arc<dyn Fn(&Path) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> + Send + Sync>,
    /// Authoritative UTXO set used to seed and resolve the compact live view.
    /// Test-only open specs may leave this unset; live queries then fail closed.
    pub utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    /// Serializes a live-view query or seed against a chain transition.
    pub chain_transition: Option<Arc<parking_lot::Mutex<()>>>,
}

/// Handle used to spawn and join the supervised reconciliation worker.
pub struct DerivedIndexWorker {
    runtime: Arc<DerivedIndexRuntime>,
    join_handle: Option<JoinHandle<()>>,
    /// Publication token; revoked on abandonment.
    pub generation: Option<Generation>,
    /// Canonical namespace key for poisoning on abandonment.
    namespace_key: Option<PathBuf>,
}

/// Result of opening the txindex store: writer, reader, and batch limits.
pub struct OpenDerivedIndex {
    /// Fenced durable writer.
    pub writer: Arc<dyn TxIndexWriter>,
    /// Snapshot-capable reader for the query engine.
    pub reader: Arc<dyn crate::IndexReader>,
    /// Batch limits selected by the composing backend.
    pub batch_limits: PreparedBatchLimits,
}

/// Sink for index-ahead rollback evidence.
///
/// When a durable watermark sits above the restored applied tip, the worker
/// reports it through this seam; node owns the concrete evidence (the
/// `chain-rollback-event` marker plus the `getblockchaininfo` warning).
pub trait IndexAheadSink: Send + Sync {
    /// Records that `capability`'s durable index sits ahead of the restored tip.
    fn report_index_ahead(
        &self,
        capability: &str,
        index_height: u32,
        tip_height: u32,
        tip_hash_be: &str,
        index_hash_be: &str,
        depth: u32,
        unix_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
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
    ) -> Result<Self, bitcoin_rs_utxo::contract::UndoCodecError> {
        let batch = bitcoin_rs_utxo::contract::decode_undo_record(bytes, hash)?;
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

impl crate::SpentCoinScripts for UndoScripts {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
        self.scripts.get(&(*txid, vout)).map(Vec::as_slice)
    }
}

/// Test cursor source anchored at an empty tip for worker construction.
#[cfg(all(test, feature = "fjall"))]
pub(crate) struct TestChainCursor;

#[cfg(all(test, feature = "fjall"))]
impl crate::reconcile::ChainCursorSource for TestChainCursor {
    fn cursor(&self) -> crate::reconcile::ConsumerCursor {
        crate::reconcile::ConsumerCursor {
            epoch: 0,
            sequence: 0,
            height: 0,
            hash: Hash256::from_le_bytes(&[0; 32]),
        }
    }
}

/// Test double standing in for node's `RecoveryReporter`; construction returns
/// the sink handle plus the recording the test asserts against.
#[cfg(all(test, feature = "fjall"))]
pub(crate) struct RecordedIndexAhead {
    /// One entry per call: `(capability, index_height, tip_height,
    /// tip_hash_be, index_hash_be, depth, unix_secs)`.
    #[allow(clippy::type_complexity)]
    pub(crate) calls: Mutex<Vec<(String, u32, u32, String, String, u32, u64)>>,
}

#[cfg(all(test, feature = "fjall"))]
impl RecordedIndexAhead {
    /// An empty recording sink.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
        })
    }
}

#[cfg(all(test, feature = "fjall"))]
impl IndexAheadSink for RecordedIndexAhead {
    fn report_index_ahead(
        &self,
        capability: &str,
        index_height: u32,
        tip_height: u32,
        tip_hash_be: &str,
        index_hash_be: &str,
        depth: u32,
        unix_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.calls.lock().push((
            capability.to_owned(),
            index_height,
            tip_height,
            tip_hash_be.to_owned(),
            index_hash_be.to_owned(),
            depth,
            unix_secs,
        ));
        Ok(())
    }
}

struct Worker {
    runtime: Arc<DerivedIndexRuntime>,
    writer: Arc<dyn TxIndexWriter>,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    body_store: Option<Arc<dyn BlockBodyStore>>,
    /// The pruning authority's narrow history capability, paired with the
    /// budget the operator configured for this consumer. The worker asks it
    /// whether history is available and reacts to the typed answer; it never
    /// derives permanence from a prune height or from a bare `None`.
    history: HistoryAccess,
    batch_limits: PreparedBatchLimits,
    enabled: IndexCapabilities,
    chain_events: Arc<dyn crate::reconcile::ChainCursorSource>,
    /// Sink for the index-ahead rollback evidence (`chain-rollback-event`
    /// marker plus `getblockchaininfo` warning).
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
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
    chain_transition: Option<Arc<parking_lot::Mutex<()>>>,
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

    /// Transfers retained rows without changing their fence or flush deadline.
    fn take(&mut self, limits: PreparedBatchLimits) -> Self {
        let replacement = Self {
            fence: self.fence,
            watermarks: self.watermarks,
            capabilities: self.capabilities,
            durable: self.durable,
            batch: PreparedBatch::new(limits),
            deadline: self.deadline,
        };
        std::mem::replace(self, replacement)
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

/// Errors the derived-index worker can surface.
#[derive(Debug, thiserror::Error)]
pub enum DerivedIndexWorkerError {
    /// The worker was stopped before it could finish the requested step.
    #[error("txindex worker stopped")]
    Stopped,
    /// A shutdown request abandoned a store open still in flight.
    #[error("txindex store open abandoned on shutdown")]
    OpenStopped,
    /// The durable watermark changed while a forward batch was pending.
    #[error("txindex durable watermark changed while a forward batch was pending")]
    PendingDurableChanged,
    /// A durable store operation failed.
    #[error("txindex storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    /// The store did not open within the bounded wait.
    #[error(
        "txindex store open timed out after {secs}s — the storage engine recovery may be stuck"
    )]
    OpenTimeout {
        /// Seconds waited before abandoning the open.
        secs: u64,
    },
    /// The index writer or reader reported a failure.
    #[error("txindex index error: {0}")]
    Index(#[from] IndexError),
    /// A block body the pruning authority confirmed as retained was absent.
    /// The owner decided the history is not gone, so the defined reaction is
    /// to wait and retry, never to rebuild.
    #[error("txindex worker: retained history unavailable: {0}")]
    HistoryUnavailable(#[from] HistoryUnavailable),
    /// A block body needed for indexing or rollback is permanently gone: the
    /// pruning authority reported the height outside retained history. The
    /// defined recovery is a rebuild from what remains.
    #[error("txindex worker: missing body at height {height}, hash {hash}")]
    MissingBody {
        /// Block height whose body is missing.
        height: u32,
        /// Active-chain hash of the missing body.
        hash: Hash256,
    },
    /// A capability requiring bodies was enabled without a body store.
    #[error("txindex worker: body store missing")]
    NoBodyStore,
    /// `ScriptLive` was enabled without the authoritative UTXO view.
    #[error("txindex worker: authoritative UTXO view missing for ScriptLive")]
    MissingUtxo,
    /// `ScriptLive` was enabled without the chain transition authority.
    #[error("txindex worker: chain transition authority missing for ScriptLive")]
    MissingChainTransition,
    /// A rewind needed an undo record that is missing or unreadable.
    #[error("txindex worker: undo record missing or unreadable at height {height}, hash {hash}")]
    UndoUnavailable {
        /// Block height whose undo record is unavailable.
        height: u32,
        /// Block hash whose undo record is unavailable.
        hash: Hash256,
    },
    /// The rollback plan referenced a chain node not present in the tree.
    #[error("txindex worker: target chain node missing at height {height}")]
    MissingTargetChain {
        /// Height whose chain node is missing.
        height: u32,
    },
    /// The rollback evidence sink failed to publish the index-ahead event.
    #[error("txindex worker: rollback evidence marker not written: {0}")]
    RollbackEvidence(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl DerivedIndexWorkerError {
    /// The backend open thread may still hold or acquire the store after this error.
    fn abandoned_open(&self) -> bool {
        matches!(self, Self::OpenStopped | Self::OpenTimeout { .. })
    }

    fn requires_capability_rebuild(&self) -> bool {
        matches!(
            self,
            Self::MissingBody { .. } | Self::Index(IndexError::MissingWatermarkIdentity { .. })
        )
    }
}

#[cfg(test)]
mod query_tests;

#[cfg(all(test, feature = "fjall"))]
mod integration_tests;

#[cfg(all(test, feature = "fjall"))]
#[allow(clippy::expect_used, clippy::panic)]
mod recovery_tests;
