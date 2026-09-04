//! Asynchronous, durable, node-owned transaction index runtime.
//!
//! The node creates and owns exactly one `TxIndexRuntime` when Core txindex or
//! `ScriptIndex` enables an index capability.
//!
//! The runtime holds a process-local revision counter and a bounded
//! nonblocking wake channel; `ApplyHandles` clones it and wakes the worker
//! after every committed `applied_tip.store`. The worker is a process-local
//! reconciliation loop; storage-level CAS conditions on exact reset state,
//! optional revision, and both watermarks linearize every ordinary mutation
//! across coexisting current-process and cross-process writers. A lost CAS
//! with an unchanged reset is transient (`StaleIndexState`): the worker
//! discards pending derived work and re-derives from durable state. Exact
//! query gating refuses that temporary lag and the next worker pass repairs
//! it. Independent durable capability watermarks let aligned row families
//! share one parse and commit while divergent families backfill separately.
//! A snapshot-gated query engine serves `bitcoin_rs_rpc::context::TxIndexQuery`
//! and the generic [`ScriptIndexQuery`] without raw index mutex paths.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_index::{
    ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexReader,
    IndexWatermark, IndexWatermarks, IndexWriteFence, IndexWriter, PreparedBatch,
    PreparedBatchLimits, PreparedBlock, ScriptHash, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
    types::{TxPosition, TxPositionValue},
};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::{Block, BlockHash, OutPoint, Tx, Txid, deserialize};
use bitcoin_rs_rpc::context::{
    BlockBodySource, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot,
    SpendingRecord, TxIndexInfo, TxIndexQuery, TxQueryError,
};
use bitcoin_rs_storage::PrefixScanLimit;
use compact_str::CompactString;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;

use crate::apply::{PruneBodyReader, PruneBodyStore};
use crate::block_source::NodeBlockSource;

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

#[cfg(feature = "rocksdb")]
pub(crate) const ROCKSDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

#[cfg(any(feature = "fjall", feature = "mdbx", test))]
pub(crate) const DEFAULT_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

#[cfg(feature = "redb")]
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
/// Maximum number of blocks whose bodies are held in memory and whose
/// `prepare_block_for` row-build work is fanned out across the rayon pool
/// in one parallel prepare step. Bounds memory while keeping the CPU-bound
/// decode/row-build off the single writer thread.
const PREPARE_CHUNK_BLOCKS: usize = 128;
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

/// Test-only override for the open timeout, in seconds. When non-zero it
/// replaces [`TXINDEX_OPEN_TIMEOUT`] so tests can exercise the timeout path
/// without waiting the production backstop.
#[cfg(test)]
static OPEN_TIMEOUT_OVERRIDE_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Returns the effective open timeout, honoring the test-only override.
fn effective_open_timeout() -> Duration {
    #[cfg(test)]
    {
        let override_secs = OPEN_TIMEOUT_OVERRIDE_SECS.load(Ordering::Relaxed);
        if override_secs > 0 {
            return Duration::from_secs(override_secs);
        }
    }
    TXINDEX_OPEN_TIMEOUT
}

/// Reconciliation leg one capability's rows are executing against the
/// applied tip. Forward is the resting leg: a watermark that names the
/// applied tip is ready; one below it is catching up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReconcileLeg {
    /// Rows extend the active chain from the durable watermark.
    #[default]
    Forward,
    /// Rows on an abandoned or ahead-of-tip branch are deleted block by
    /// block from `from_height` down to the common ancestor `to_height`.
    RollingBack {
        /// Height of the watermark being rewound.
        from_height: u32,
        /// Height of the last block shared with the active chain.
        to_height: u32,
    },
    /// The rows were reset and rebuild from genesis.
    Rebuilding,
}

/// Reconciliation legs of every capability the worker owns.
///
/// Capabilities carry independent watermarks, so a selective reset can leave
/// one capability rebuilding while its sibling still rewinds. The worker
/// publishes each leg change so operators can tell a rewind or rebuild apart
/// from ordinary forward catch-up, whose progress is the durable watermark
/// itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcilePhase {
    /// Transaction-lookup leg.
    pub tx_lookup: ReconcileLeg,
    /// Script-history leg.
    pub script_history: ReconcileLeg,
}

impl ReconcilePhase {
    /// Every capability moving forward.
    pub const FORWARD: Self = Self {
        tx_lookup: ReconcileLeg::Forward,
        script_history: ReconcileLeg::Forward,
    };

    /// Returns the phase with `leg` assigned to every capability in
    /// `capabilities`.
    #[must_use]
    pub const fn with_leg(mut self, capabilities: IndexCapabilities, leg: ReconcileLeg) -> Self {
        if capabilities.tx_lookup {
            self.tx_lookup = leg;
        }
        if capabilities.script_history {
            self.script_history = leg;
        }
        self
    }

    /// Capabilities whose rows are rebuilding from genesis.
    #[must_use]
    pub const fn rebuilding(self) -> IndexCapabilities {
        IndexCapabilities {
            tx_lookup: matches!(self.tx_lookup, ReconcileLeg::Rebuilding),
            script_history: matches!(self.script_history, ReconcileLeg::Rebuilding),
        }
    }

    /// Widest rollback in flight: the highest watermark being rewound and
    /// the lowest common ancestor any capability rewinds to.
    #[must_use]
    pub fn rolling_back(self) -> Option<(u32, u32)> {
        [self.tx_lookup, self.script_history]
            .into_iter()
            .filter_map(|leg| match leg {
                ReconcileLeg::RollingBack {
                    from_height,
                    to_height,
                } => Some((from_height, to_height)),
                ReconcileLeg::Forward | ReconcileLeg::Rebuilding => None,
            })
            .reduce(|(from_a, to_a), (from_b, to_b)| (from_a.max(from_b), to_a.min(to_b)))
    }

    /// Ends every rollback leg; rebuild legs persist until their rows reach
    /// the applied tip.
    #[must_use]
    fn rollbacks_finished(self) -> Self {
        let finish = |leg| match leg {
            ReconcileLeg::RollingBack { .. } => ReconcileLeg::Forward,
            other => other,
        };
        Self {
            tx_lookup: finish(self.tx_lookup),
            script_history: finish(self.script_history),
        }
    }
}

/// Shared wake/revision/health state owned by `NodeState` and referenced by
/// `ApplyHandles`, the worker thread, and the query engine.
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

// ---------------------------------------------------------------------------
// A1: lifecycle snapshot, stable query adapter, namespace registry, heartbeat
// ---------------------------------------------------------------------------

use hashbrown::HashMap;
use std::path::{Path, PathBuf};

use arc_swap::ArcSwap;

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

impl TxIndexQuery for TxIndexQueryAdapter {
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

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        let engine = self.load_engine()?;
        engine.index_info()
    }
}

impl ScriptIndexQuery for TxIndexQueryAdapter {
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

/// Process-global namespace ownership state.
#[derive(Debug)]
enum NamespaceEntry {
    /// An active open owns this namespace.
    Active(u64),
    /// An abandoned open poisoned this namespace permanently.
    Poisoned,
}

/// Process-global, process-lifetime namespace map. The key is the canonical
/// data root joined with one validated fixed child component.
pub(crate) struct NamespaceRegistry {
    entries: parking_lot::Mutex<HashMap<PathBuf, NamespaceEntry>>,
}

impl NamespaceRegistry {
    pub(crate) fn new() -> Self {
        Self {
            entries: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Validates the child component: exactly the fixed name, no separator, not
    /// `.` or `..`, not absolute. Does not canonicalize the child.
    fn validate_child(root: &Path, child: &str) -> Result<PathBuf, String> {
        if child.is_empty() {
            return Err("namespace child is empty".to_owned());
        }
        if child.contains(std::path::MAIN_SEPARATOR) {
            return Err(format!("namespace child {child} contains a path separator"));
        }
        if child == "." || child == ".." {
            return Err(format!("namespace child {child} is a path traversal"));
        }
        if Path::new(child).is_absolute() {
            return Err(format!("namespace child {child} is absolute"));
        }
        Ok(root.join(child))
    }

    /// Atomically claims `Active(owner)` for the key. Rejects an existing
    /// `Active` or `Poisoned` entry without touching the store.
    fn claim(&self, key: PathBuf, owner: u64) -> bool {
        let mut entries = self.entries.lock();
        match entries.get(&key) {
            None => {
                entries.insert(key, NamespaceEntry::Active(owner));
                true
            }
            Some(NamespaceEntry::Active(_) | NamespaceEntry::Poisoned) => false,
        }
    }

    /// Releases `Active(owner)` only if the map still contains the same owner.
    /// Does nothing if the entry was already changed (e.g. poisoned).
    fn release(&self, key: &Path, owner: u64) {
        let mut entries = self.entries.lock();
        if let Some(NamespaceEntry::Active(current)) = entries.get(key) {
            if *current == owner {
                entries.remove(key);
            }
        }
    }

    /// Poisons the namespace only if the entry is `Active(owner)`. Used for
    /// abandoned opens only.
    fn poison(&self, key: &Path, owner: u64) {
        let mut entries = self.entries.lock();
        if let Some(NamespaceEntry::Active(current)) = entries.get(key) {
            if *current == owner {
                entries.insert(key.to_path_buf(), NamespaceEntry::Poisoned);
            }
        }
    }

    /// Returns true if the namespace is poisoned.
    fn is_poisoned(&self, key: &Path) -> bool {
        matches!(self.entries.lock().get(key), Some(NamespaceEntry::Poisoned))
    }
}

/// One shared process-global namespace registry for all index workers.
pub(crate) static NAMESPACE_REGISTRY: std::sync::LazyLock<NamespaceRegistry> =
    std::sync::LazyLock::new(NamespaceRegistry::new);

/// Heartbeat helper: emits a log line every 30 seconds while the worker's
/// backend open is blocked. Observability only — not a timeout.
struct Heartbeat {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Heartbeat {
    fn start(capability: &'static str, namespace: String, backend: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let start = Instant::now();
        let handle = thread::Builder::new()
            .name(format!("bitcoin-rs-{capability}-heartbeat"))
            .spawn(move || {
                while !stop_clone.load(Ordering::Acquire) {
                    let elapsed = start.elapsed();
                    tracing::info!(
                        capability,
                        namespace = %namespace,
                        backend = %backend,
                        elapsed_secs = elapsed.as_secs(),
                        "index store recovery in progress"
                    );
                    for _ in 0..300 {
                        if stop_clone.load(Ordering::Acquire) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .ok();
        Self { stop, handle }
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Immutable specification for worker-owned store open. Constructed
/// synchronously in `NodeState::open`; consumed on the worker thread.
pub(crate) struct TxIndexOpenSpec {
    pub(crate) data_dir: PathBuf,
    pub(crate) namespace: &'static str,
    pub(crate) storage_backend: String,
    pub(crate) cache_bytes: u64,
    #[allow(dead_code)]
    pub(crate) batch_limits: PreparedBatchLimits,
    pub(crate) epoch: u64,
    pub(crate) enabled: IndexCapabilities,
    pub(crate) rollback_rebuild_cutover: u32,
    pub(crate) canonical_data_root: PathBuf,
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
        body_store: Option<Arc<dyn PruneBodyStore>>,
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
        body_store: Option<Arc<dyn PruneBodyStore>>,
        block_source: NodeBlockSource,
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

/// Result of opening the txindex store: writer, reader, and batch limits.
pub(crate) struct OpenTxIndex {
    pub(crate) writer: Arc<dyn TxIndexWriter>,
    pub(crate) reader: Arc<dyn bitcoin_rs_index::IndexReader>,
    #[allow(dead_code)]
    pub(crate) batch_limits: PreparedBatchLimits,
}

/// Opens an `IndexWriter` with legacy/unsupported-format recovery.
///
/// Format 3 is upgraded inside [`bitcoin_rs_index::IndexWriter::open`] by
/// resetting `ScriptHistory` only. This path still full-resets foreign
/// versions and cursorless legacy tables so they can rebuild.
pub(crate) fn open_writer<S>(
    store: &Arc<S>,
    generation: u64,
) -> Result<bitcoin_rs_index::IndexWriter<S>, IndexError>
where
    S: bitcoin_rs_storage::KvStore,
{
    match bitcoin_rs_index::IndexWriter::open(Arc::clone(store), generation) {
        Ok(writer) => Ok(writer),
        Err(
            error @ (IndexError::LegacyCursorlessIndex
            | IndexError::UnsupportedTxIndexFormatVersion { .. }),
        ) => {
            tracing::warn!(
                %error,
                "resetting incompatible derived transaction index for rebuild"
            );
            bitcoin_rs_index::IndexWriter::reset_index(store.as_ref(), generation)?;
            bitcoin_rs_index::IndexWriter::open(Arc::clone(store), generation)
        }
        Err(error) => Err(error),
    }
}

/// Worker-owned open: opens the store, constructs writer/reader/engine,
/// publishes lifecycle, and runs reconciliation — all behind one
/// `catch_unwind` boundary that starts before directory creation and includes
/// schema inspection, writer construction, complete query-engine construction,
/// publication, and the initial reconciliation handoff.
///
/// On an ordinary error or panic, publishes `Failed` with a bounded
/// diagnostic and no query, if the generation is still current. If the token
/// was revoked, publishes nothing. Converts panic payloads to bounded text.
#[allow(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::needless_borrow
)]
fn run_worker_with_open(
    runtime: &Arc<TxIndexRuntime>,
    spec: TxIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    body_store: Option<Arc<dyn PruneBodyStore>>,
    block_source: NodeBlockSource,
    body_source: Option<Arc<dyn BlockBodySource>>,
    chain_events: &Arc<crate::state::ChainEventPublisher>,
    reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
    shutdown: &Arc<AtomicBool>,
    wake_rx: &Receiver<()>,
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

    let heartbeat = Heartbeat::start(
        "txindex",
        spec.namespace.to_owned(),
        spec.storage_backend.clone(),
    );

    let worker_result = open_and_run(
        runtime,
        &spec,
        lifecycle,
        generation,
        &applied_tip,
        &block_tree,
        &body_store,
        &block_source,
        &body_source,
        chain_events,
        reporter,
        shutdown,
        wake_rx,
    );

    heartbeat.stop_and_join();

    match worker_result {
        Ok(()) => {
            registry.release(&namespace_key, generation.id());
        }
        Err(error) => {
            tracing::error!(%error, "txindex worker open or run failed");
            fail_worker(runtime, lifecycle, generation, &error.to_string());
            registry.release(&namespace_key, generation.id());
        }
    }
}

/// Fails the worker as one unit: the runtime stops the loop and gates the
/// query engine, and the lifecycle withdraws the query payload so the
/// adapter answers typed `Unavailable`. The lifecycle write is skipped for a
/// revoked generation; the runtime write is unconditional because the
/// runtime belongs to this worker alone.
fn fail_worker(
    runtime: &TxIndexRuntime,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    reason: &str,
) {
    runtime.publish_failed(reason);
    if generation.is_revoked() {
        return;
    }
    let reason = CompactString::from(reason);
    lifecycle.rcu(|current| {
        if generation.is_revoked() {
            return Arc::clone(current);
        }
        Arc::new(TxIndexLifecycle::Failed(reason.clone()))
    });
}

/// Publishes a lifecycle transition with generation-checked `rcu`.
/// A stale token returns the current `Arc` unchanged.
fn publish_lifecycle(
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    new: TxIndexLifecycle,
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

/// Opens the store, constructs the engine, publishes lifecycle, and runs.
#[allow(clippy::too_many_arguments, clippy::ref_option)]
fn open_and_run(
    runtime: &Arc<TxIndexRuntime>,
    spec: &TxIndexOpenSpec,
    lifecycle: &Arc<ArcSwap<TxIndexLifecycle>>,
    generation: &Generation,
    applied_tip: &Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: &Arc<RwLock<BlockTree>>,
    body_store: &Option<Arc<dyn PruneBodyStore>>,
    block_source: &NodeBlockSource,
    body_source: &Option<Arc<dyn BlockBodySource>>,
    chain_events: &Arc<crate::state::ChainEventPublisher>,
    reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
    shutdown: &Arc<AtomicBool>,
    wake_rx: &Receiver<()>,
) -> Result<(), TxIndexWorkerError> {
    // Wait for the test-only open gate before touching the store.
    wait_txindex_open_gate();

    let txindex_dir = spec.data_dir.join(spec.namespace);
    std::fs::create_dir_all(&txindex_dir)
        .map_err(|e| TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    let open: OpenTxIndex = open_tx_index_with_timeout(
        &spec.storage_backend,
        &txindex_dir,
        spec.cache_bytes,
        spec.batch_limits,
        spec.epoch,
        shutdown,
    )?;

    // Check shutdown and generation immediately after backend open returns.
    if shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop() {
        // Drop all store values (open.writer, open.reader) and exit without
        // publication or reconciliation.
        return Ok(());
    }

    let query_engine = Arc::new(TxIndexQueryEngine::new(
        Arc::clone(runtime),
        open.reader,
        block_source.clone(),
        Arc::clone(block_tree),
        Arc::clone(applied_tip),
        body_source.clone(),
    ));

    // Publish the complete engine atomically; readiness is proven per query.
    publish_lifecycle(
        lifecycle,
        generation,
        TxIndexLifecycle::Serving(query_engine),
    );

    // Check shutdown immediately after publication.
    if shutdown.load(Ordering::Acquire) || generation.is_revoked() || runtime.should_stop() {
        return Ok(());
    }

    let worker = Worker {
        runtime: Arc::clone(runtime),
        writer: open.writer,
        applied_tip: Arc::clone(applied_tip),
        block_tree: Arc::clone(block_tree),
        body_store: body_store.clone(),
        batch_limits: spec.batch_limits,
        enabled: spec.enabled,
        rollback_rebuild_cutover: spec.rollback_rebuild_cutover,
        wake_rx: wake_rx.clone(),
        quiet_period: REVISION_QUIET_PERIOD,
        chain_events: Arc::clone(chain_events),
        reporter,
        batch_delay: FORWARD_BATCH_DELAY,
    };

    worker.run()
}

/// Opens the txindex store with a bounded deadline.
///
/// The storage engine open (fjall/lsm-tree recovery, rocksdb column-family
/// open) can wedge on a large or partially-corrupted store, spinning one
/// thread at 100% CPU indefinitely. This wrapper runs the open on a helper
/// thread and waits with [`TXINDEX_OPEN_TIMEOUT`]. If the deadline fires, the
/// helper thread is detached (it may eventually finish or hang — we cannot
/// kill a thread) and `OpenTimeout` is returned so the worker publishes
/// `Failed` and the node stays operable without the index.
fn open_tx_index_with_timeout(
    storage_backend: &str,
    txindex_dir: &Path,
    cache_bytes: u64,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
    shutdown: &Arc<AtomicBool>,
) -> Result<OpenTxIndex, TxIndexWorkerError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let backend = storage_backend.to_owned();
    let dir = txindex_dir.to_path_buf();
    let _join = thread::Builder::new()
        .name("bitcoin-rs-txindex-open".to_owned())
        .spawn(move || {
            let result = open_tx_index_on_worker(&backend, &dir, cache_bytes, batch_limits, epoch);
            let _ = tx.send(result);
        })
        .map_err(|e| TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Io(e)))?;

    // Poll in short slices so a shutdown during the open deadline
    // exits promptly instead of waiting the full timeout.
    let timeout = effective_open_timeout();
    let deadline = Instant::now() + timeout;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(TxIndexWorkerError::Stopped);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tracing::error!(
                timeout_secs = timeout.as_secs(),
                backend = storage_backend,
                dir = %txindex_dir.display(),
                "txindex store open timed out — the storage engine recovery \
                 appears stuck; detaching the open thread and publishing Failed"
            );
            return Err(TxIndexWorkerError::OpenTimeout {
                secs: timeout.as_secs(),
            });
        }
        match rx.recv_timeout(remaining) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(TxIndexWorkerError::Storage(
                    bitcoin_rs_storage::StorageError::Backend(
                        "txindex open helper thread exited without result".to_owned(),
                    ),
                ));
            }
        }
    }
}

/// Test-only: when non-zero, `open_tx_index_on_worker` sleeps this many
/// seconds before proceeding, simulating a stuck storage-engine recovery.
#[cfg(test)]
static OPEN_DELAY_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Opens the txindex store on the worker thread, preserving all backend
/// constructors, cache paths, and batch limits.
fn open_tx_index_on_worker(
    storage_backend: &str,
    txindex_dir: &Path,
    cache_bytes: u64,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
) -> Result<OpenTxIndex, TxIndexWorkerError> {
    #[cfg(test)]
    {
        let delay = OPEN_DELAY_SECS.load(Ordering::Relaxed);
        if delay > 0 {
            std::thread::sleep(Duration::from_secs(delay));
        }
    }
    match storage_backend {
        #[cfg(feature = "rocksdb")]
        "rocksdb" => {
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(txindex_dir, cache_bytes)
                    .map_err(|e| {
                        TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::backend(e))
                    })?,
            );
            open_tx_index_store_on_worker(store, batch_limits, epoch)
        }
        #[cfg(feature = "fjall")]
        "fjall" => {
            let store = Arc::new(
                bitcoin_rs_storage::FjallStore::open_with_cache(txindex_dir, cache_bytes).map_err(
                    |e| TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::backend(e)),
                )?,
            );
            open_tx_index_store_on_worker(store, batch_limits, epoch)
        }
        #[cfg(feature = "redb")]
        "redb" => {
            let store = Arc::new(
                bitcoin_rs_storage::open_redb_tx_index_store_with_cache(txindex_dir, cache_bytes)
                    .map_err(|e| {
                    TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::backend(e))
                })?,
            );
            open_tx_index_store_on_worker(store, batch_limits, epoch)
        }
        #[cfg(feature = "mdbx")]
        "mdbx" => {
            let store = Arc::new(
                bitcoin_rs_storage::MdbxStore::open_with_cache(txindex_dir, cache_bytes).map_err(
                    |e| TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::backend(e)),
                )?,
            );
            open_tx_index_store_on_worker(store, batch_limits, epoch)
        }
        other => Err(TxIndexWorkerError::Storage(
            bitcoin_rs_storage::StorageError::Backend(format!(
                "unsupported storage backend for txindex: {other}"
            )),
        )),
    }
}

/// Constructs the writer and reader from the opened store.
fn open_tx_index_store_on_worker<S>(
    store: Arc<S>,
    batch_limits: PreparedBatchLimits,
    epoch: u64,
) -> Result<OpenTxIndex, TxIndexWorkerError>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    let writer = open_writer(&store, epoch)?;
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(writer));
    let reader: Arc<dyn bitcoin_rs_index::IndexReader> =
        Arc::new(bitcoin_rs_index::Indexer::new(store));
    Ok(OpenTxIndex {
        writer,
        reader,
        batch_limits,
    })
}

/// Erased prepared-index writer used by the worker and stored in `NodeState`.
pub(crate) trait TxIndexWriter: Send + Sync {
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError>;
    fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError>;
    fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        let _ = capabilities;
        self.prepare_block(height, hash, body)
    }
    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError>;
    fn commit_rollback_one_for_with_cursor(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<(), IndexError>;
    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        let _ = capabilities;
        Err(IndexError::UnsupportedRollback)
    }
    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError>;
    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError>;
}

impl<S> TxIndexWriter for Mutex<IndexWriter<S>>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        self.lock().fenced_watermarks()
    }

    fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.lock().prepare_block(height, hash, body)
    }

    fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.lock()
            .prepare_block_for(capabilities, height, hash, body)
    }

    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        self.lock().commit_forward_with_cursor(fence, batch, cursor)
    }

    fn commit_rollback_one_for_with_cursor(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<(), IndexError> {
        self.lock()
            .commit_rollback_one_for_with_cursor(fence, capabilities, prev, body, cursor)
    }

    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        self.lock().reset_capabilities(capabilities)
    }

    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        self.lock().consumer_cursor()
    }

    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        self.lock().commit_consumer_cursor(fence, cursor)
    }
}

/// `RwLock`-backed writer: `prepare_block_for` and `consumer_cursor` take a
/// shared read lock so the CPU-bound decode/row-build can run concurrently
/// across the rayon pool, while `commit_*`, `fenced_watermarks`, and
/// `reset_capabilities` take an exclusive write lock to preserve the
/// single-writer atomic commit and watermark semantics.
impl<S> TxIndexWriter for RwLock<IndexWriter<S>>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    fn fenced_watermarks(&self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        self.write().fenced_watermarks()
    }

    fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.read().prepare_block(height, hash, body)
    }

    fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.read()
            .prepare_block_for(capabilities, height, hash, body)
    }

    fn commit_forward_with_cursor(
        &self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        self.write()
            .commit_forward_with_cursor(fence, batch, cursor)
    }

    fn commit_rollback_one_for_with_cursor(
        &self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<(), IndexError> {
        self.write()
            .commit_rollback_one_for_with_cursor(fence, capabilities, prev, body, cursor)
    }

    fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        self.write().reset_capabilities(capabilities)
    }

    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        self.read().consumer_cursor()
    }

    fn commit_consumer_cursor(
        &self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        self.write().commit_consumer_cursor(fence, cursor)
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
    body_store: Option<Arc<dyn PruneBodyStore>>,
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SelectedWatermark {
    Valid(Option<IndexWatermark>),
    Invalid,
}

fn selected_watermark(
    watermarks: IndexWatermarks,
    capabilities: IndexCapabilities,
) -> SelectedWatermark {
    match (capabilities.tx_lookup, capabilities.script_history) {
        (true, false) => SelectedWatermark::Valid(watermarks.tx_lookup),
        (false, true) => SelectedWatermark::Valid(watermarks.script_history),
        (true, true) if watermarks.tx_lookup == watermarks.script_history => {
            SelectedWatermark::Valid(watermarks.tx_lookup)
        }
        (true, true) | (false, false) => SelectedWatermark::Invalid,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchWait {
    Woken,
    Deadline,
    Stopped,
}

fn wait_for_revision_quiet(
    runtime: &TxIndexRuntime,
    wake_rx: &Receiver<()>,
    quiet_period: Duration,
    mut seen_revision: u64,
) -> Option<u64> {
    loop {
        if runtime.should_stop() {
            return None;
        }
        match wake_rx.recv_timeout(quiet_period) {
            Ok(()) => seen_revision = runtime.revision(),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                let current = runtime.revision();
                if current == seen_revision {
                    return Some(current);
                }
                seen_revision = current;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return None,
        }
    }
}
/// Waits for a wake hint or the pending batch's original deadline.
fn wait_for_batch_deadline(
    runtime: &TxIndexRuntime,
    wake_rx: &Receiver<()>,
    deadline: Instant,
) -> BatchWait {
    if runtime.should_stop() {
        return BatchWait::Stopped;
    }
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return BatchWait::Deadline;
    };
    if remaining.is_zero() {
        return BatchWait::Deadline;
    }
    match wake_rx.recv_timeout(remaining) {
        Ok(()) if runtime.should_stop() => BatchWait::Stopped,
        Ok(()) => BatchWait::Woken,
        Err(crossbeam_channel::RecvTimeoutError::Timeout) if runtime.should_stop() => {
            BatchWait::Stopped
        }
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => BatchWait::Deadline,
        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => BatchWait::Stopped,
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

impl Worker {
    fn run(self) -> Result<(), TxIndexWorkerError> {
        let mut quiet_armed = false;
        let mut pending = None;
        loop {
            if self.runtime.should_stop() {
                break;
            }
            if quiet_armed {
                quiet_armed = false;
                if wait_for_revision_quiet(
                    &self.runtime,
                    &self.wake_rx,
                    self.quiet_period,
                    self.runtime.revision(),
                )
                .is_none()
                {
                    break;
                }
            }

            let revision_before = self.runtime.revision();
            let action = match self.reconcile_once(&mut pending) {
                Ok(action) => action,
                Err(TxIndexWorkerError::Stopped) => break,
                Err(TxIndexWorkerError::Index(
                    IndexError::ResetInProgress | IndexError::StaleIndexState,
                )) => {
                    pending = None;
                    ReconcileAction::Stalled
                }
                Err(error) => return Err(error),
            };
            if self.runtime.should_stop() {
                break;
            }

            match action {
                ReconcileAction::Progressed => continue,
                ReconcileAction::CaughtUp => {
                    // A wake can be coalesced or consumed while this pass runs.
                    // The revision is authoritative: never sleep after it moved.
                    if self.runtime.revision() != revision_before {
                        continue;
                    }
                    match self.persist_chain_cursor()? {
                        CursorCommit::Settled => {}
                        CursorCommit::ResetRejected | CursorCommit::NotAligned => {
                            quiet_armed = true;
                            continue;
                        }
                    }
                    match self.wake_rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
                ReconcileAction::Buffered => {
                    let Some(deadline) = pending.as_ref().map(|state| state.deadline) else {
                        unreachable!("buffered action has a pending batch");
                    };
                    match wait_for_batch_deadline(&self.runtime, &self.wake_rx, deadline) {
                        BatchWait::Woken => continue,
                        BatchWait::Deadline => {
                            if !self.commit_pending(&mut pending)? {
                                // `commit_pending` already took the pending
                                // forward; `Ok(false)` means a retryable
                                // reset rejection, not a permanent failure.
                                // Exit only on shutdown; otherwise let the
                                // quiet wait throttle the retry.
                                if self.runtime.should_stop() {
                                    break;
                                }
                                quiet_armed = true;
                                continue;
                            }
                        }
                        BatchWait::Stopped => break,
                    }
                }
                ReconcileAction::Stalled => {
                    // Missing bodies and stopped writes retry only after one
                    // revision lull; forward progress never waits.
                    quiet_armed = true;
                }
            }
        }
        Ok(())
    }

    /// Reconciles the durable watermark to the current applied tip in one pass.
    ///
    /// All `BlockTree` data needed for the pass is copied under a short read
    /// lock before any body I/O or index commit.  Body loads, prepares, and
    /// commits happen with the lock released.
    fn reconcile_once(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let action = self.reconcile_pass(pending)?;
        if !matches!(action, ReconcileAction::CaughtUp) {
            return Ok(action);
        }
        // A forward leg commits one capability set at a time, so its
        // completion is only `CaughtUp` when no enabled capability needs
        // another transition against the current tip; otherwise the pass
        // merely progressed and the remaining legs (and their published
        // phase) carry over.
        let (target, _, watermarks) = self.capture_target_watermarks()?;
        if self
            .rollback_selection(watermarks, target.as_deref())
            .is_some()
            || target
                .as_deref()
                .is_some_and(|target| self.forward_selection(watermarks, target).is_some())
        {
            return Ok(ReconcileAction::Progressed);
        }
        self.runtime.publish_phase(ReconcilePhase::FORWARD);
        Ok(ReconcileAction::CaughtUp)
    }

    fn reconcile_pass(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let (target, fence, watermarks) = self.capture_target_watermarks()?;

        if pending.is_some() {
            return self.reconcile_pending(pending, fence, watermarks, target.as_deref());
        }

        let mut fence = fence;
        let mut watermarks = watermarks;
        let mut reported_ahead = false;
        while let Some((capabilities, watermark)) =
            self.rollback_selection(watermarks, target.as_deref())
        {
            // Report once per pass: an 834k-block stale branch would otherwise
            // report once per rolled-back block.
            if let Some(target) = target.as_deref()
                && !reported_ahead
                && watermark.height > target.height
            {
                reported_ahead = true;
                self.report_index_ahead(capabilities, watermark, target)?;
            }
            let depth = self.rollback_depth_for(watermark, target.as_deref());
            if depth.is_some_and(|depth| depth > self.rollback_rebuild_cutover) {
                tracing::warn!(
                    depth,
                    cutover = self.rollback_rebuild_cutover,
                    tx_lookup = capabilities.tx_lookup,
                    script_history = capabilities.script_history,
                    "stale index watermark exceeds the rollback cutover; rebuilding selected capabilities"
                );
                (fence, watermarks) = self.reset_for_rebuild(capabilities)?;
                continue;
            }
            self.runtime.publish_leg(
                capabilities,
                ReconcileLeg::RollingBack {
                    from_height: watermark.height,
                    to_height: depth.map_or(0, |depth| watermark.height.saturating_sub(depth)),
                },
            );
            match self.rollback_one(fence, watermarks, capabilities, watermark) {
                Ok(_) => {
                    let (next_fence, next_watermarks) = self
                        .writer
                        .fenced_watermarks()
                        .map_err(TxIndexWorkerError::Index)?;
                    fence = next_fence;
                    watermarks = next_watermarks;
                }
                Err(error) if error.requires_capability_rebuild() => {
                    tracing::warn!(
                        error = %error,
                        tx_lookup = capabilities.tx_lookup,
                        script_history = capabilities.script_history,
                        "index cursor cannot be rolled back; rebuilding selected capabilities"
                    );
                    (fence, watermarks) = self.reset_for_rebuild(capabilities)?;
                    continue;
                }
                Err(TxIndexWorkerError::Index(
                    IndexError::ResetInProgress | IndexError::StaleIndexState,
                )) => {
                    return Ok(ReconcileAction::Stalled);
                }
                Err(error) => return Err(error),
            }
        }
        // A rewind ends with the rollback loop; a rebuild ends only when the
        // reset capabilities reach the tip again.
        self.runtime
            .publish_phase(self.runtime.phase().rollbacks_finished());

        let Some(target) = target else {
            return Ok(ReconcileAction::CaughtUp);
        };
        let Some((capabilities, watermark)) = self.forward_selection(watermarks, &target) else {
            return Ok(ReconcileAction::CaughtUp);
        };
        self.catch_up_to(&target, fence, watermarks, watermark, capabilities, pending)
    }

    /// Resets `capabilities` for a rebuild from genesis and publishes the
    /// rebuild phase, returning the post-reset fence and watermarks.
    fn reset_for_rebuild(
        &self,
        capabilities: IndexCapabilities,
    ) -> Result<(IndexWriteFence, IndexWatermarks), TxIndexWorkerError> {
        self.writer
            .reset_capabilities(capabilities)
            .map_err(TxIndexWorkerError::Index)?;
        self.runtime
            .publish_leg(capabilities, ReconcileLeg::Rebuilding);
        self.writer
            .fenced_watermarks()
            .map_err(TxIndexWorkerError::Index)
    }

    /// Publishes the index-ahead rollback evidence for a watermark above the
    /// applied tip. The marker is part of the rollback transition: a data dir
    /// that cannot hold it fails this optional index, never the chain.
    fn report_index_ahead(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> Result<(), TxIndexWorkerError> {
        let capability = match (capabilities.tx_lookup, capabilities.script_history) {
            (true, true) => "tx_lookup,script_history",
            (true, false) => "tx_lookup",
            (false, true) => "script_history",
            (false, false) => return Ok(()),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.reporter
            .report_index_ahead(
                capability,
                watermark.height,
                target.height,
                &target.hash.to_string_be(),
                &Hash256::from_le_bytes(&watermark.hash).to_string_be(),
                watermark.height.saturating_sub(target.height),
                now,
            )
            .map_err(TxIndexWorkerError::RollbackEvidence)
    }

    fn reconcile_pending(
        &self,
        pending: &mut Option<PendingForward>,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        target: Option<&TipSnapshot>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        let Some(state) = pending.as_ref() else {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        };
        // Any fence change invalidates the retained rows. Discard them and
        // re-derive from the new reset, revision, and watermark state.
        if fence != state.fence {
            *pending = None;
            return Ok(ReconcileAction::Stalled);
        }
        // A different watermark under the same fence is an incoherent writer
        // response, not a concurrent commit. Treat it as corruption.
        if selected_watermark(watermarks, state.capabilities)
            != SelectedWatermark::Valid(state.durable)
        {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        }
        let endpoint = state.endpoint();
        let Some(target) = target else {
            return if self.commit_pending(pending)? {
                Ok(ReconcileAction::Progressed)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        };

        if endpoint.height == target.height && endpoint.hash == target.hash.to_le_bytes() {
            if Instant::now() < state.deadline {
                return Ok(ReconcileAction::Buffered);
            }
            return if self.commit_pending(pending)? {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }
        if endpoint.height < target.height && self.watermark_is_on_target_chain(endpoint, target) {
            if Instant::now() >= state.deadline {
                return if self.commit_pending(pending)? {
                    Ok(ReconcileAction::Progressed)
                } else {
                    Ok(ReconcileAction::Stalled)
                };
            }
            return self.catch_up_to(
                target,
                state.fence,
                state.watermarks,
                state.durable,
                state.capabilities,
                pending,
            );
        }

        if self.commit_pending(pending)? {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
    }

    fn capture_target_watermarks(
        &self,
    ) -> Result<(Option<Arc<TipSnapshot>>, IndexWriteFence, IndexWatermarks), TxIndexWorkerError>
    {
        let (fence, watermarks) = self
            .writer
            .fenced_watermarks()
            .map_err(TxIndexWorkerError::Index)?;
        let target = self.applied_tip.load_full();
        Ok((target, fence, watermarks))
    }

    fn rollback_selection(
        &self,
        watermarks: IndexWatermarks,
        target: Option<&TipSnapshot>,
    ) -> Option<(IndexCapabilities, IndexWatermark)> {
        let tx = self
            .enabled
            .tx_lookup
            .then_some(watermarks.tx_lookup)
            .flatten();
        let script_index = self
            .enabled
            .script_history
            .then_some(watermarks.script_history)
            .flatten();
        let needs_rollback = |watermark: IndexWatermark| {
            target.is_none_or(|target| !self.watermark_is_on_target_chain(watermark, target))
        };
        let selected = [tx, script_index]
            .into_iter()
            .flatten()
            .filter(|watermark| needs_rollback(*watermark))
            .max_by_key(|watermark| watermark.height)?;
        Some((
            IndexCapabilities {
                tx_lookup: tx == Some(selected) && needs_rollback(selected),
                script_history: script_index == Some(selected) && needs_rollback(selected),
            },
            selected,
        ))
    }

    fn forward_selection(
        &self,
        watermarks: IndexWatermarks,
        target: &TipSnapshot,
    ) -> Option<(IndexCapabilities, Option<IndexWatermark>)> {
        let tx = self.enabled.tx_lookup.then_some(watermarks.tx_lookup);
        let script_index = self
            .enabled
            .script_history
            .then_some(watermarks.script_history);
        let needs_forward = |watermark: Option<IndexWatermark>| {
            watermark.is_none_or(|watermark| watermark.height < target.height)
        };
        let start_height = |watermark: Option<IndexWatermark>| {
            watermark.map_or(0, |watermark| watermark.height.saturating_add(1))
        };
        let selected_start = [tx, script_index]
            .into_iter()
            .flatten()
            .filter(|watermark| needs_forward(*watermark))
            .map(start_height)
            .min()?;
        let selected_watermark = if selected_start == 0 {
            None
        } else {
            let height = selected_start - 1;
            [tx, script_index]
                .into_iter()
                .flatten()
                .flatten()
                .find(|watermark| watermark.height == height)
        };
        Some((
            IndexCapabilities {
                tx_lookup: tx.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
                script_history: script_index.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
            },
            selected_watermark,
        ))
    }

    fn watermark_is_on_target_chain(
        &self,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> bool {
        let tree = self.block_tree.read();
        crate::reconcile::position_on_active_chain(
            &tree,
            Hash256::from_le_bytes(&watermark.hash),
            watermark.height,
            target.tip_id,
        )
    }
    /// Canonical rollback-versus-rebuild depth for one watermark, captured
    /// under a short tree lock. `None` leaves the per-block rollback route:
    /// an unresolvable watermark hash or an absent target fails inside
    /// `rollback_one` into the error-driven reset arm.
    fn rollback_depth_for(
        &self,
        watermark: IndexWatermark,
        target: Option<&TipSnapshot>,
    ) -> Option<u32> {
        let target = target?;
        let tree = self.block_tree.read();
        crate::reconcile::rollback_depth(
            &tree,
            Hash256::from_le_bytes(&watermark.hash),
            watermark.height,
            target.tip_id,
        )
    }

    /// Persists the consumer cursor once the rows provably mirror the live
    /// snapshot.
    ///
    /// The cursor is advisory: it lets a restarted or hint-starved consumer
    /// trust its position and lets a new epoch invalidate it. It is written
    /// only when the publisher snapshot names exactly the tip the rows
    /// reached, so it can never describe rows the store does not hold. The
    /// publisher briefly lags `applied_tip` inside one commit, so a disagreeing
    /// snapshot simply skips the write; the next caught-up pass retries.
    fn persist_chain_cursor(&self) -> Result<CursorCommit, TxIndexWorkerError> {
        let (fence, watermarks) = match self.writer.fenced_watermarks() {
            Ok(snapshot) => snapshot,
            Err(IndexError::ResetInProgress) => return Ok(CursorCommit::ResetRejected),
            Err(error) => return Err(TxIndexWorkerError::Index(error)),
        };
        let loaded_tip = self.applied_tip.load_full();
        let Some(target) = loaded_tip.as_deref() else {
            return Ok(CursorCommit::Settled);
        };
        let snapshot = self.chain_events.snapshot();
        if snapshot.tip_hash != target.hash || snapshot.tip_height != target.height {
            return Ok(CursorCommit::Settled);
        }
        let expected = IndexWatermark {
            height: snapshot.tip_height,
            hash: snapshot.tip_hash.to_le_bytes(),
        };
        if (self.enabled.tx_lookup && watermarks.tx_lookup != Some(expected))
            || (self.enabled.script_history && watermarks.script_history != Some(expected))
        {
            return Ok(CursorCommit::NotAligned);
        }
        let bytes = crate::reconcile::ConsumerCursor::from_snapshot(&snapshot).to_bytes();
        if self
            .writer
            .consumer_cursor()
            .map_err(TxIndexWorkerError::Index)?
            .is_some_and(|stored| stored == bytes)
        {
            return Ok(CursorCommit::Settled);
        }
        match self.writer.commit_consumer_cursor(fence, &bytes) {
            Ok(()) => Ok(CursorCommit::Settled),
            Err(IndexError::ResetInProgress) => Ok(CursorCommit::ResetRejected),
            Err(IndexError::StaleIndexState) => Ok(CursorCommit::NotAligned),
            Err(error) => Err(TxIndexWorkerError::Index(error)),
        }
    }
    /// Copies one bounded chunk of active-chain identities under one short
    /// read lock.
    fn collect_target_chain(
        &self,
        target: &TipSnapshot,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<BlockIdentity>, TxIndexWorkerError> {
        let tree = self.block_tree.read();
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(usize::MAX);
        let mut identities = Vec::with_capacity(capacity);
        for height in start_height..=end_height {
            let node_id = tree
                .node_at_height_from(target.tip_id, height)
                .ok_or(TxIndexWorkerError::MissingTargetChain { height })?;
            let node = tree
                .node(node_id)
                .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?;
            let parent_hash = if height == 0 {
                [0_u8; 32]
            } else {
                let parent_id = tree
                    .parent_id(node_id)
                    .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?
                    .ok_or(TxIndexWorkerError::MissingTargetChain { height })?;
                let parent = tree
                    .node(parent_id)
                    .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?;
                *parent.hash.as_byte_array()
            };
            identities.push(BlockIdentity {
                height,
                hash: *node.hash.as_byte_array(),
                parent_hash,
            });
        }
        Ok(identities)
    }

    fn catch_up_to(
        &self,
        target: &TipSnapshot,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        watermark: Option<IndexWatermark>,
        capabilities: IndexCapabilities,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
        }

        let mut state = pending.take().unwrap_or_else(|| PendingForward {
            fence,
            watermarks,
            capabilities,
            durable: watermark,
            batch: PreparedBatch::new(self.batch_limits),
            deadline: Instant::now() + self.batch_delay,
        });
        if state.durable != watermark || state.capabilities != capabilities {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        }
        let start_height = state.batch.watermark().map_or_else(
            || watermark.map_or(0, |w| w.height.saturating_add(1)),
            |endpoint| endpoint.height.saturating_add(1),
        );
        if start_height > target.height {
            return if self.sync_and_commit(state)?.is_some() {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }

        let chunk_end = start_height
            .saturating_add(IDENTITY_CHUNK_BLOCKS - 1)
            .min(target.height);
        let identities = self.collect_target_chain(target, start_height, chunk_end)?;
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
        }
        let Some(body_store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        let mut body_reader = body_store.reader().map_err(TxIndexWorkerError::Storage)?;
        let mut requests = Vec::with_capacity(POSITION_PREFETCH_BLOCKS);
        for identities in identities.chunks(POSITION_PREFETCH_BLOCKS) {
            if self.runtime.should_stop() {
                return Ok(ReconcileAction::Stalled);
            }
            requests.clear();
            requests.extend(
                identities
                    .iter()
                    .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash))),
            );
            body_reader
                .prefetch_positions(&requests)
                .map_err(TxIndexWorkerError::Storage)?;

            // Sub-chunk: load bodies serially (preserving the reader's
            // prefetch state), prepare blocks in parallel across the rayon
            // pool, then push prepared blocks into the batch in height order.
            // The single-writer commit and watermark publish remain the only
            // ordering points (#209 invariants).
            for sub_chunk in identities.chunks(PREPARE_CHUNK_BLOCKS) {
                match self.prepare_and_admit_chunk(
                    sub_chunk,
                    &mut body_reader,
                    capabilities,
                    &mut state,
                    pending,
                )? {
                    ChunkAction::Continue => {}
                    ChunkAction::Stalled => return Ok(ReconcileAction::Stalled),
                    ChunkAction::Progressed => return Ok(ReconcileAction::Progressed),
                }
            }
        }

        self.finish_catch_up(state, chunk_end, target, pending)
    }

    /// Loads bodies serially, prepares blocks in parallel across the rayon pool,
    /// then admits them into the batch in height order on the single writer
    /// thread. Returns `Stalled` if a body is missing or shutdown was requested,
    /// `Progressed` if the batch filled and was committed, or `Continue` to keep
    /// processing.
    #[allow(clippy::too_many_lines)]
    fn prepare_and_admit_chunk(
        &self,
        sub_chunk: &[BlockIdentity],
        body_reader: &mut Box<dyn PruneBodyReader + '_>,
        capabilities: IndexCapabilities,
        state: &mut PendingForward,
        pending: &mut Option<PendingForward>,
    ) -> Result<ChunkAction, TxIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }

        // Load bodies serially through the single reader.
        let mut bodies = Vec::with_capacity(sub_chunk.len());
        for identity in sub_chunk {
            if self.runtime.should_stop() {
                return Ok(ChunkAction::Stalled);
            }
            let hash = Hash256::from_le_bytes(&identity.hash);
            match body_reader.load_block_body(identity.height, hash) {
                Ok(Some(body)) => bodies.push(body),
                Ok(None) => {
                    if !state.batch.is_empty() {
                        let replacement = PendingForward {
                            fence: state.fence,
                            watermarks: state.watermarks,
                            capabilities: state.capabilities,
                            durable: state.durable,
                            batch: PreparedBatch::new(self.batch_limits),
                            deadline: state.deadline,
                        };
                        *pending = Some(std::mem::replace(state, replacement));
                    }
                    return Ok(ChunkAction::Stalled);
                }
                Err(e) => return Err(TxIndexWorkerError::Storage(e)),
            }
        }

        // Prepare blocks in parallel. Each call takes a shared read lock on the
        // RwLock-backed writer, so the CPU-bound decode/row-build runs
        // concurrently across pool threads.
        let prepared: Vec<Result<PreparedBlock, IndexError>> = sub_chunk
            .par_iter()
            .zip(bodies.par_iter())
            .map(|(identity, body)| {
                self.writer.prepare_block_for(
                    capabilities,
                    identity.height,
                    identity.hash,
                    body.as_slice(),
                )
            })
            .collect();
        drop(bodies);

        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }

        // Push prepared blocks into the batch in height order on the single
        // writer thread.
        for (result, identity) in prepared.into_iter().zip(sub_chunk.iter()) {
            let prepared = result.map_err(TxIndexWorkerError::Index)?;
            if identity.height > 0 && prepared.parent_hash != identity.parent_hash {
                return Err(TxIndexWorkerError::MissingTargetChain {
                    height: identity.height,
                });
            }
            if state.batch.try_push(prepared).is_err() {
                let replacement = PendingForward {
                    fence: state.fence,
                    watermarks: state.watermarks,
                    capabilities: state.capabilities,
                    durable: state.durable,
                    batch: PreparedBatch::new(self.batch_limits),
                    deadline: state.deadline,
                };
                return if self
                    .sync_and_commit(std::mem::replace(state, replacement))?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
            if state.batch.is_full() {
                let replacement = PendingForward {
                    fence: state.fence,
                    watermarks: state.watermarks,
                    capabilities: state.capabilities,
                    durable: state.durable,
                    batch: PreparedBatch::new(self.batch_limits),
                    deadline: state.deadline,
                };
                return if self
                    .sync_and_commit(std::mem::replace(state, replacement))?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
        }
        Ok(ChunkAction::Continue)
    }
    fn finish_catch_up(
        &self,
        state: PendingForward,
        chunk_end: u32,
        target: &TipSnapshot,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        if chunk_end < target.height {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        let endpoint = state.endpoint();
        let latest = self.applied_tip.load_full();
        if latest.as_deref().is_some_and(|tip| {
            endpoint.height < tip.height && self.watermark_is_on_target_chain(endpoint, tip)
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        if latest.as_deref().is_some_and(|tip| {
            endpoint.height == tip.height && endpoint.hash == tip.hash.to_le_bytes()
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Buffered);
        }

        if self.sync_and_commit(state)?.is_some() {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
    }
    /// Rolls back one complete block for every selected capability.
    fn rollback_one(
        &self,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        let watermark_hash = Hash256::from_le_bytes(&watermark.hash);
        let body = self.load_body(watermark.height, watermark_hash)?;

        let prev = if watermark.height == 0 {
            None
        } else {
            let prepared = self
                .writer
                .prepare_block_for(capabilities, watermark.height, watermark.hash, &body)
                .map_err(TxIndexWorkerError::Index)?;
            Some(IndexWatermark {
                height: watermark.height.saturating_sub(1),
                hash: prepared.parent_hash,
            })
        };

        if self.runtime.should_stop() {
            return Err(TxIndexWorkerError::Stopped);
        }
        let cursor = self.cursor_for_result(capabilities, prev, watermarks);
        self.writer
            .commit_rollback_one_for_with_cursor(
                fence,
                capabilities,
                prev,
                &body,
                cursor
                    .as_ref()
                    .map_or(ConsumerCursorUpdate::Clear, |bytes| {
                        ConsumerCursorUpdate::Set(bytes.as_slice())
                    }),
            )
            .map_err(TxIndexWorkerError::Index)?;
        Ok(prev)
    }

    fn load_body(&self, height: u32, hash: Hash256) -> Result<Vec<u8>, TxIndexWorkerError> {
        let Some(store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        store
            .load_block_body(height, hash)
            .map_err(TxIndexWorkerError::Storage)?
            .ok_or(TxIndexWorkerError::MissingBody { height, hash })
    }

    fn sync_and_commit(
        &self,
        state: PendingForward,
    ) -> Result<Option<IndexWatermark>, TxIndexWorkerError> {
        let PendingForward {
            fence,
            watermarks,
            batch,
            ..
        } = state;
        if batch.is_empty() {
            return Ok(None);
        }
        if let Some(store) = self.body_store.as_ref() {
            store.sync().map_err(TxIndexWorkerError::Storage)?;
        }
        if self.runtime.should_stop() {
            return Ok(None);
        }

        let endpoint = batch
            .watermark()
            .ok_or(TxIndexWorkerError::PendingDurableChanged)?;
        let capabilities = batch
            .capabilities()
            .ok_or(TxIndexWorkerError::PendingDurableChanged)?;
        let cursor = self.cursor_for_result(capabilities, Some(endpoint), watermarks);
        let watermark = match self.writer.commit_forward_with_cursor(
            fence,
            batch,
            cursor.as_ref().map_or(ConsumerCursorUpdate::Keep, |bytes| {
                ConsumerCursorUpdate::Set(bytes.as_slice())
            }),
        ) {
            Ok(watermark) => watermark,
            Err(IndexError::ResetInProgress) => {
                tracing::debug!("index reset rejected a stale forward batch");
                return Ok(None);
            }
            Err(IndexError::StaleIndexState) => {
                tracing::debug!("index CAS lost with unchanged reset; re-deriving");
                return Ok(None);
            }
            Err(error) => return Err(TxIndexWorkerError::Index(error)),
        };
        Ok(Some(watermark))
    }

    fn cursor_for_result(
        &self,
        capabilities: IndexCapabilities,
        result: Option<IndexWatermark>,
        mut watermarks: IndexWatermarks,
    ) -> Option<[u8; crate::reconcile::CURSOR_BYTE_LEN]> {
        let snapshot = self.chain_events.snapshot();
        let result = result?;
        if result.height != snapshot.tip_height || result.hash != snapshot.tip_hash.to_le_bytes() {
            return None;
        }
        if capabilities.tx_lookup {
            watermarks.tx_lookup = Some(result);
        }
        if capabilities.script_history {
            watermarks.script_history = Some(result);
        }
        let aligned = (!self.enabled.tx_lookup || watermarks.tx_lookup == Some(result))
            && (!self.enabled.script_history || watermarks.script_history == Some(result));
        aligned.then(|| crate::reconcile::ConsumerCursor::from_snapshot(&snapshot).to_bytes())
    }

    fn commit_pending(
        &self,
        pending: &mut Option<PendingForward>,
    ) -> Result<bool, TxIndexWorkerError> {
        let Some(state) = pending.take() else {
            unreachable!("commit_pending has a pending batch");
        };
        Ok(self.sync_and_commit(state)?.is_some())
    }
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
    Storage(#[source] bitcoin_rs_storage::StorageError),
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

/// Aggregate work budget shared by every operation in one public query.
struct QueryBudget {
    remaining_rows: usize,
    remaining_bytes: usize,
    remaining_scans: usize,
    remaining_body_reads: usize,
}

impl QueryBudget {
    const fn new() -> Self {
        Self {
            remaining_rows: QUERY_SCAN_ROW_LIMIT,
            remaining_bytes: QUERY_SCAN_BYTE_LIMIT,
            remaining_scans: QUERY_SCAN_COUNT_LIMIT,
            remaining_body_reads: QUERY_BODY_READ_LIMIT,
        }
    }

    fn next_scan_limit(&mut self) -> Result<PrefixScanLimit, TxQueryError> {
        if self.remaining_scans == 0 || self.remaining_rows == 0 || self.remaining_bytes == 0 {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exhausted".into(),
            ));
        }
        self.remaining_scans -= 1;
        Ok(PrefixScanLimit {
            max_rows: self.remaining_rows,
            max_bytes: self.remaining_bytes,
        })
    }

    fn accept_scan(&mut self, scan: TxIndexScan) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex prefix scan truncated".into(),
            ));
        }
        if scan.rows.len() > self.remaining_rows || scan.encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        self.remaining_rows -= scan.rows.len();
        self.remaining_bytes -= scan.encoded_bytes;
        Ok(scan.rows)
    }

    fn reserve_body_read(&mut self, max_bytes: usize) -> Result<(), TxQueryError> {
        if self.remaining_body_reads == 0 || max_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exhausted".into(),
            ));
        }
        self.remaining_body_reads -= 1;
        Ok(())
    }

    fn charge_body_bytes(&mut self, bytes: usize) -> Result<(), TxQueryError> {
        if bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exceeded".into(),
            ));
        }
        self.remaining_bytes -= bytes;
        Ok(())
    }
}

/// Node-owned, snapshot-gated transaction-index query engine.
///
/// Implements `bitcoin_rs_rpc::context::TxIndexQuery` and [`ScriptIndexQuery`] as the
/// only public read paths for the transaction index. Every query runs against
/// one typed point-in-time snapshot, captures
/// health/shutdown/revision/tip before and after work, and returns typed
/// `Retry`/`Unavailable` when the answer cannot be proven.
#[derive(Clone)]
pub(crate) struct TxIndexQueryEngine {
    runtime: Arc<TxIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_source: NodeBlockSource,
    block_tree: Arc<RwLock<BlockTree>>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    body_source: Option<Arc<dyn BlockBodySource>>,
}

impl core::fmt::Debug for TxIndexQueryEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxIndexQueryEngine").finish_non_exhaustive()
    }
}

impl TxIndexQueryEngine {
    /// Builds a query engine over the shared reader and authoritative block source.
    #[must_use]
    pub(crate) fn new(
        runtime: Arc<TxIndexRuntime>,
        reader: Arc<dyn IndexReader>,
        block_source: NodeBlockSource,
        block_tree: Arc<RwLock<BlockTree>>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        body_source: Option<Arc<dyn BlockBodySource>>,
    ) -> Self {
        Self {
            runtime,
            reader,
            block_source,
            block_tree,
            applied_tip,
            body_source,
        }
    }

    fn query_health(&self) -> Result<(), TxQueryError> {
        if self.runtime.failed.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable(
                self.runtime
                    .failure_message()
                    .unwrap_or_else(|| "txindex worker failed".into()),
            ));
        }
        if self.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable("txindex worker stopped".into()));
        }
        Ok(())
    }

    fn with_snapshot<F, T>(&self, required: IndexCapabilities, f: F) -> Result<T, TxQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &TipSnapshot,
            &mut QueryBudget,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health()?;

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        // Ensure the index watermark is exactly at the applied tip we are
        // answering for, otherwise the snapshot is stale.
        for capability in [IndexCapability::TxLookup, IndexCapability::ScriptHistory] {
            if !required.contains(capability) {
                continue;
            }
            let watermark = snapshot
                .capability_watermark(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            let Some(watermark) = watermark else {
                return Err(TxQueryError::Retry);
            };
            if watermark.height != tip_before.height
                || watermark.hash != *tip_before.hash.as_byte_array()
            {
                return Err(TxQueryError::Retry);
            }
        }

        let mut budget = QueryBudget::new();
        let result = f(snapshot.as_ref(), &tip_before, &mut budget);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();
        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        result
    }

    fn resolve_hash_at_height(
        &self,
        height: u32,
        tip: &TipSnapshot,
    ) -> Result<Hash256, TxQueryError> {
        let tree = self.block_tree.read();
        Self::hash_at_height(&tree, tip.tip_id, height).ok_or(TxQueryError::Retry)
    }

    fn hash_at_height(
        tree: &BlockTree,
        tip_id: bitcoin_rs_chain::NodeId,
        height: u32,
    ) -> Option<Hash256> {
        let node_id = tree.node_at_height_from(tip_id, height)?;
        tree.node(node_id).ok().map(|n| n.hash)
    }

    fn resolve_block(
        &self,
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
    ) -> Result<Block, TxQueryError> {
        budget.reserve_body_read(MAX_SERIALIZED_BLOCK_BYTES)?;
        let bytes = self.resolve_block_body_bytes(height, BlockHash::from(hash))?;
        budget.charge_body_bytes(bytes.len())?;
        Self::verify_block(&bytes, height, hash)
    }

    fn resolve_block_body_bytes(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Vec<u8>, TxQueryError> {
        if let Some(body_source) = self.body_source.as_ref() {
            if let Some(bytes) = body_source.block_body(height, hash) {
                return Ok(bytes);
            }
        }
        self.block_source
            .block_body_bytes_for(height, hash)
            .ok_or_else(|| {
                TxQueryError::Unavailable(
                    format!("block body missing for txindex query at height {height}").into(),
                )
            })
    }

    fn verify_block(bytes: &[u8], height: u32, hash: Hash256) -> Result<Block, TxQueryError> {
        let block = deserialize::<Block>(bytes).map_err(|_| {
            TxQueryError::Storage(format!("corrupt serialized block at height {height}").into())
        })?;
        let decoded = block.block_hash().0;
        if decoded != hash {
            return Err(TxQueryError::Storage(
                format!("block identity mismatch at height {height}").into(),
            ));
        }
        Ok(block)
    }

    fn validated_positions(value: &[u8]) -> Option<&[TxPosition]> {
        let positions = TxPositionValue::decode(value)?;
        let mut previous: Option<TxPosition> = None;
        for &position in positions {
            let end = position.end()?;
            if position.byte_len() == 0
                || usize::try_from(end).ok()? > MAX_SERIALIZED_BLOCK_BYTES
                || previous.is_some_and(|prior| {
                    position.offset() <= prior.offset()
                        || position.offset() < prior.end().unwrap_or(u32::MAX)
                })
            {
                return None;
            }
            previous = Some(position);
        }
        Some(positions)
    }

    fn resolve_positioned_transaction(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        position: TxPosition,
    ) -> Result<Option<Tx>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let Some(body_source) = self.body_source.as_ref() else {
            return Ok(None);
        };
        let byte_len = usize::try_from(position.byte_len())
            .map_err(|_| TxQueryError::Storage("transaction position length overflow".into()))?;
        budget.reserve_body_read(byte_len)?;
        let Some(bytes) = body_source.block_body_range(
            height,
            BlockHash::from(hash),
            position.offset(),
            position.byte_len(),
        ) else {
            return Ok(None);
        };
        budget.charge_body_bytes(bytes.len())?;
        if bytes.len() != byte_len {
            return Ok(None);
        }
        Ok(deserialize::<Tx>(&bytes).ok())
    }

    fn transaction_from_full_block(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let block = self.resolve_block(budget, height, hash)?;
        Ok(block
            .txs
            .into_iter()
            .find(|transaction| transaction.txid() == *txid))
    }

    fn transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        Ok(self
            .locate_transaction_for(snapshot, tip, budget, txid)?
            .map(|(_, transaction)| transaction))
    }

    /// Resolves both the confirming height and the transaction itself.
    ///
    /// `transaction_for` and `transaction_height_for` are the same walk, so they
    /// share it rather than keeping two copies of the row/position/full-block
    /// fallback ladder. The height caller pays for the deserialization it does
    /// not use, which is the price of not answering with an unverified row: a
    /// row surviving from a reorged block would otherwise name a height whose
    /// block never held the transaction.
    fn locate_transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<(u32, Tx)>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let rows = budget.accept_scan(scan)?;
        if rows.is_empty() {
            return Ok(None);
        }

        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                if let Some(transaction) =
                    self.transaction_from_full_block(tip, budget, height, txid)?
                {
                    return Ok(Some((height, transaction)));
                }
                continue;
            };
            let position = positions[0];
            match self.resolve_positioned_transaction(tip, budget, height, position)? {
                Some(transaction) if transaction.txid() == *txid => {
                    return Ok(Some((height, transaction)));
                }
                _ => {
                    if let Some(transaction) =
                        self.transaction_from_full_block(tip, budget, height, txid)?
                    {
                        return Ok(Some((height, transaction)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn outpoint_value_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<u64>, TxQueryError> {
        let tx = self.transaction_for(snapshot, tip, budget, &outpoint.txid)?;
        let Some(tx) = tx else {
            return Ok(None);
        };
        let vout = usize::try_from(outpoint.vout)
            .map_err(|_| TxQueryError::Storage("outpoint vout overflow".into()))?;
        Ok(tx.outputs.get(vout).map(|o| o.value))
    }

    fn scan_funding_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .funding_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_scan(scan)
    }

    fn scan_spending_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .spending_rows(outpoint, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_scan(scan)
    }

    fn collect_funding_outputs(
        transaction: &Tx,
        height: u32,
        scripthash: ScriptHash,
        outputs: &mut Vec<(Txid, u32, u64, u32)>,
    ) -> Result<bool, TxQueryError> {
        let txid = transaction.txid();
        let before = outputs.len();
        for (vout_idx, output) in transaction.outputs.iter().enumerate() {
            if ScriptHash::new(&output.script_pubkey) != scripthash {
                continue;
            }
            let vout = u32::try_from(vout_idx)
                .map_err(|_| TxQueryError::Storage("vout overflow".into()))?;
            outputs.push((txid, vout, output.value, height));
        }
        Ok(outputs.len() != before)
    }

    fn funding_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, TxQueryError> {
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                let hash = self.resolve_hash_at_height(height, tip)?;
                let block = self.resolve_block(budget, height, hash)?;
                for transaction in &block.txs {
                    Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
                }
                continue;
            };

            let row_start = outputs.len();
            let mut complete = true;
            for &position in positions {
                let Some(transaction) =
                    self.resolve_positioned_transaction(tip, budget, height, position)?
                else {
                    complete = false;
                    break;
                };
                if !Self::collect_funding_outputs(&transaction, height, scripthash, &mut outputs)? {
                    complete = false;
                    break;
                }
            }
            if complete {
                continue;
            }

            outputs.truncate(row_start);
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
            }
        }
        Ok(outputs)
    }

    fn spender_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let rows = Self::scan_spending_rows(snapshot, budget, outpoint)?;
        let mut last_height = None;
        for row in rows {
            let height = row.row.height();
            if last_height == Some(height) {
                continue;
            }
            last_height = Some(height);
            if let Some(positions) = Self::validated_positions(&row.value) {
                for &position in positions {
                    let Some(transaction) =
                        self.resolve_positioned_transaction(tip, budget, height, position)?
                    else {
                        break;
                    };
                    if let Some(record) = Self::spending_input(&transaction, height, outpoint)? {
                        return Ok(Some(record));
                    }
                }
            }
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                if let Some(record) = Self::spending_input(transaction, height, outpoint)? {
                    return Ok(Some(record));
                }
            }
        }
        Ok(None)
    }

    fn spending_input(
        transaction: &Tx,
        height: u32,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let Some(vin) = transaction
            .inputs
            .iter()
            .position(|input| input.previous_output == *outpoint)
        else {
            return Ok(None);
        };
        Ok(Some(SpendingRecord {
            txid: transaction.txid(),
            height,
            vin: u32::try_from(vin).map_err(|_| TxQueryError::Storage("vin overflow".into()))?,
        }))
    }

    fn history_snapshot_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let funding_outputs = self.funding_outputs_for(snapshot, tip, budget, scripthash)?;

        let mut history = Vec::with_capacity(funding_outputs.len());
        let mut funding = Vec::with_capacity(funding_outputs.len());
        for (txid, vout, value, height) in funding_outputs {
            history.push(ScriptHistoryRecord { txid, height });
            funding.push(ScriptIndexRecord {
                txid,
                height,
                value,
                vout,
            });
            let outpoint = OutPoint { txid, vout };
            if let Some(spender) = self.spender_for(snapshot, tip, budget, &outpoint)? {
                history.push(ScriptHistoryRecord {
                    txid: spender.txid,
                    height: spender.height,
                });
            }
        }

        history.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        funding.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        funding.dedup();

        Ok(ScriptIndexSnapshot { history, funding })
    }

    fn unspent_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let funding_outputs = self.funding_outputs_for(snapshot, tip, budget, scripthash)?;
        let mut records = Vec::new();
        for (txid, vout, value, height) in funding_outputs {
            let outpoint = OutPoint { txid, vout };
            if self
                .spender_for(snapshot, tip, budget, &outpoint)?
                .is_none()
            {
                records.push(ScriptIndexRecord {
                    txid,
                    height,
                    value,
                    vout,
                });
            }
        }

        records.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        records.dedup_by(|a, b| a.txid == b.txid && a.height == b.height && a.vout == b.vout);
        Ok(records)
    }

    /// Watermark progress of `required` capabilities against one applied
    /// tip: `synced` when every one names that tip, `processed_height` the
    /// lowest of their heights, `target_height` the tip they were measured
    /// against. `Retry` when the tip or revision moved during the read.
    pub(crate) fn index_progress_for(
        &self,
        required: IndexCapabilities,
    ) -> Result<IndexProgress, TxQueryError> {
        self.query_health()?;

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        let tx = required
            .tx_lookup
            .then(|| snapshot.capability_watermark(IndexCapability::TxLookup))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let script_index = required
            .script_history
            .then(|| snapshot.capability_watermark(IndexCapability::ScriptHistory))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let at_tip = |watermark: Option<IndexWatermark>| {
            watermark.is_some_and(|watermark| {
                watermark.height == tip_before.height
                    && watermark.hash == *tip_before.hash.as_byte_array()
            })
        };
        let synced = (!required.tx_lookup || at_tip(tx))
            && (!required.script_history || at_tip(script_index));
        let best_block_height = match (required.tx_lookup, required.script_history) {
            (true, true) => tx
                .map_or(0, |watermark| watermark.height)
                .min(script_index.map_or(0, |watermark| watermark.height)),
            (true, false) => tx.map_or(0, |watermark| watermark.height),
            (false, true) => script_index.map_or(0, |watermark| watermark.height),
            (false, false) => 0,
        };

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();

        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        Ok(IndexProgress {
            synced,
            processed_height: best_block_height,
            target_height: tip_before.height,
        })
    }
}

/// One coherent read of index progress against a single applied tip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexProgress {
    pub synced: bool,
    pub processed_height: u32,
    pub target_height: u32,
}

impl TxIndexQuery for TxIndexQueryEngine {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            self.transaction_for(snapshot, tip, budget, txid)
        })
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            self.outpoint_value_for(snapshot, tip, budget, outpoint)
        })
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            Ok(self
                .locate_transaction_for(snapshot, tip, budget, txid)?
                .map(|(height, _)| height))
        })
    }

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        let progress = self.index_progress_for(IndexCapabilities::TX_LOOKUP)?;
        Ok(TxIndexInfo {
            synced: progress.synced,
            best_block_height: progress.processed_height,
        })
    }
}

impl ScriptIndexQuery for TxIndexQueryEngine {
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.history_snapshot_for(snapshot, tip, budget, scripthash),
        )
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.unspent_outputs_for(snapshot, tip, budget, scripthash),
        )
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.spender_for(snapshot, tip, budget, &outpoint),
        )
    }
}

#[cfg(all(test, feature = "fjall"))]
mod body_reader_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::{Network, consensus_bytes};
    use bitcoin_rs_storage::StorageError;

    use super::*;
    use crate::apply::{PruneBodyReader, PruneBodyStore};

    struct SessionBodyStore {
        height: u32,
        hash: Hash256,
        body: Vec<u8>,
        readers: AtomicUsize,
        prefetches: AtomicUsize,
        session_loads: AtomicUsize,
        direct_loads: AtomicUsize,
    }

    struct SessionBodyReader<'a> {
        store: &'a SessionBodyStore,
        pending: Option<(u32, Hash256)>,
    }

    impl PruneBodyReader for SessionBodyReader<'_> {
        fn prefetch_positions(&mut self, requests: &[(u32, Hash256)]) -> Result<(), StorageError> {
            let [request] = requests else {
                return Err(StorageError::InvalidOperation(
                    "session test expects one prefetched position",
                ));
            };
            if self.pending.replace(*request).is_some() {
                return Err(StorageError::InvalidOperation(
                    "session test position was not consumed",
                ));
            }
            self.store.prefetches.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn load_block_body(
            &mut self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            if self.pending.take() != Some((height, hash)) {
                return Err(StorageError::InvalidOperation(
                    "session body loaded without matching prefetch",
                ));
            }
            self.store.session_loads.fetch_add(1, Ordering::AcqRel);
            Ok((height == self.store.height && hash == self.store.hash)
                .then(|| self.store.body.clone()))
        }
    }

    impl PruneBodyStore for SessionBodyStore {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
            _body: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            self.direct_loads.fetch_add(1, Ordering::AcqRel);
            Err(StorageError::InvalidOperation(
                "direct body load must not be used",
            ))
        }

        fn reader(&self) -> Result<Box<dyn PruneBodyReader + '_>, StorageError> {
            self.readers.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(SessionBodyReader {
                store: self,
                pending: None,
            }))
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[test]
    fn catch_up_uses_one_body_reader_session() -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let hash = block.block_hash().0;
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let node = tree.node(tip_id)?;
        let tip = TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        };

        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(tip.clone())));
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
        let data_dir = tempfile::tempdir()?;
        let index_store = Arc::new(bitcoin_rs_storage::FjallStore::open(data_dir.path())?);
        let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
            bitcoin_rs_index::IndexWriter::open(index_store, 1)?,
        ));
        let body_store = Arc::new(SessionBodyStore {
            height: tip.height,
            hash,
            body: consensus_bytes(&block),
            readers: AtomicUsize::new(0),
            prefetches: AtomicUsize::new(0),
            session_loads: AtomicUsize::new(0),
            direct_loads: AtomicUsize::new(0),
        });
        let (fence, watermarks) = writer.fenced_watermarks()?;
        let worker = Worker {
            runtime,
            writer,
            applied_tip,
            block_tree: tree,
            body_store: Some(body_store.clone()),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled: IndexCapabilities::ALL,
            wake_rx,
            chain_events: detached_chain_publisher(),
            reporter: test_recovery_reporter(data_dir.path()).0,
            quiet_period: Duration::ZERO,
            batch_delay: Duration::ZERO,
            // The body-reader session test never exercises reset routing;
            // `u32::MAX` keeps every stale watermark on the per-block rewind.
            rollback_rebuild_cutover: u32::MAX,
        };
        let mut pending = None;

        assert!(matches!(
            worker.catch_up_to(
                &tip,
                fence,
                watermarks,
                None,
                IndexCapabilities::ALL,
                &mut pending
            )?,
            ReconcileAction::Buffered
        ));
        assert_eq!(body_store.readers.load(Ordering::Acquire), 1);
        assert_eq!(body_store.prefetches.load(Ordering::Acquire), 1);
        assert_eq!(body_store.session_loads.load(Ordering::Acquire), 1);
        assert_eq!(body_store.direct_loads.load(Ordering::Acquire), 0);
        Ok(())
    }
}

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
