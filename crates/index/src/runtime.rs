//! Asynchronous, durable, node-owned transaction index runtime.

use arc_swap::ArcSwap;

use bitcoin_rs_chain::{BlockBodySource, BlockTree, BlockTreeReader, TipReader, TipSnapshot};

use crate::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWatermarks,
    IndexWriteFence, PreparedBatch, PreparedBatchLimits, ScriptHash, ScriptLiveScan, TxIndexScan,
    TxIndexScanRow, TxIndexSnapshot,
    reconcile::{ReconcileLeg, ReconcilePhase},
    types::{TxPosition, TxPositionValue},
    writer::TxIndexWriter,
};

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, Txid, deserialize};

use crate::capabilities::{
    CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource, derived_index_status,
};
use crate::query_api::{
    AtPrefix, DerivedIndexInfo, DerivedIndexQuery, HistoricalQueryError, ScriptHistoryRecord,
    ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, SpendingRecord, TxQueryError,
    TxUnavailableCause,
};

use bitcoin_rs_storage::{
    PrefixScanLimit,
    block_body::BlockBodyStore,
    pruning::{HistoryAccess, HistoryLease, HistoryUnavailable},
};
use bitcoin_rs_utxo::snapshot::{SeedOfferCell, VerifiedSnapshotArtifact};

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
pub use query::DerivedIndexQueryEngine;
pub(crate) use query::QueryEngineLive;
use query::{IndexProgress, map_historical_error};

#[derive(Debug)]
pub struct DerivedIndexRuntime {
    revision: AtomicU64,
    pub(super) shutdown: AtomicBool,
    pub(super) failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<CompactString>>,
    compact_filter_failure: RwLock<Option<CompactString>>,
    script_live_failure: RwLock<Option<CompactString>>,
    phase: arc_swap::ArcSwap<ReconcilePhase>,
}

impl DerivedIndexRuntime {
    #[must_use]
    pub fn new(wake_tx: Sender<()>) -> Self {
        Self {
            revision: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wake_tx,
            failure_message: RwLock::new(None),
            compact_filter_failure: RwLock::new(None),
            script_live_failure: RwLock::new(None),
            phase: arc_swap::ArcSwap::from_pointee(ReconcilePhase::FORWARD),
        }
    }

    pub(crate) fn publish_phase(&self, phase: ReconcilePhase) {
        if **self.phase.load() != phase {
            self.phase.store(Arc::new(phase));
        }
    }

    pub(crate) fn publish_leg(&self, capabilities: IndexCapabilities, leg: ReconcileLeg) {
        self.publish_phase(self.phase().with_leg(capabilities, leg));
    }

    #[must_use]
    pub(crate) fn phase(&self) -> ReconcilePhase {
        **self.phase.load()
    }

    pub fn wake(&self) {
        self.revision.fetch_add(1, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    pub(crate) fn publish_failed(&self, message: impl Into<CompactString>) {
        *self.failure_message.write() = Some(message.into());
        self.failed.store(true, Ordering::Release);
    }

    pub(crate) fn fail_compact_filters(&self, error: &DerivedIndexWorkerError) {
        tracing::error!(%error, "compact filter index unavailable; other indexes continue");
        *self.compact_filter_failure.write() = Some(error.to_string().into());
        self.publish_leg(IndexCapabilities::COMPACT_FILTERS, ReconcileLeg::Forward);
        self.wake();
    }

    pub(crate) fn fail_script_live(&self, error: &DerivedIndexWorkerError) {
        tracing::error!(%error, "ScriptLive index unavailable; other indexes continue");
        *self.script_live_failure.write() = Some(error.to_string().into());
        self.publish_leg(IndexCapabilities::SCRIPT_LIVE, ReconcileLeg::Forward);
        self.wake();
    }

    pub(crate) fn clear_script_live(&self) {
        self.script_live_failure.write().take();
    }

    #[cfg(all(test, feature = "fjall"))]
    #[must_use]
    pub(crate) fn script_live_failure(&self) -> Option<CompactString> {
        self.script_live_failure.read().clone()
    }

    #[must_use]
    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    #[must_use]
    pub(crate) fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    #[must_use]
    pub(crate) fn failure_message(&self) -> Option<CompactString> {
        self.failure_message.read().clone()
    }
}

impl crate::CompactFilterQuery for DerivedIndexQueryAdapter {
    fn block_filter(&self, hash: Hash256) -> Result<Option<crate::BasicFilter>, TxQueryError> {
        crate::CompactFilterQuery::block_filter(self.load_engine()?.as_ref(), hash)
    }
    fn for_each_filter(
        &self,
        start: u32,
        stop: Hash256,
        step: u32,
        emit: &mut dyn FnMut(Hash256, crate::BasicFilter) -> bool,
    ) -> Result<Option<[u8; 32]>, TxQueryError> {
        crate::CompactFilterQuery::for_each_filter(
            self.load_engine()?.as_ref(),
            start,
            stop,
            step,
            emit,
        )
    }
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        crate::CompactFilterQuery::filter_index_info(self.load_engine()?.as_ref())
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

    fn confirmed_history(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.confirmed_history(scripthash)
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

/// These are query-side safety limits, not the writer batch limits.
const QUERY_SCAN_ROW_LIMIT: usize = 1_000_000;

const QUERY_SCAN_BYTE_LIMIT: usize = 64 << 20;

const QUERY_SCAN_COUNT_LIMIT: usize = 4_096;

const QUERY_BODY_READ_LIMIT: usize = 4_096;

pub(crate) const MAX_SERIALIZED_BLOCK_BYTES: usize = crate::types::MAX_POSITION_END_BYTES;

const BATCH_BYTE_LIMIT: usize = 256 << 20;

pub const DEFAULT_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 1_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

pub const REDB_BATCH_LIMITS: PreparedBatchLimits = PreparedBatchLimits {
    max_rows: 16_000_000,
    max_bytes: BATCH_BYTE_LIMIT,
};

/// selective reset + rebuild instead of a per-block rewind.
/// Grounded in three measured runs of per-block forward-ingest versus rollback
pub const DEFAULT_ROLLBACK_REBUILD_CUTOVER: u32 = 100_000;

const IDENTITY_CHUNK_BLOCKS: u32 = 65_536;

const POSITION_PREFETCH_BLOCKS: usize = 65_536;

const PREPARE_CHUNK_BLOCKS: usize = 256;

const PREPARE_CHUNK_BYTES: usize = 32 << 20;

const REVISION_QUIET_PERIOD: Duration = Duration::from_millis(100);

const FORWARD_BATCH_DELAY: Duration = Duration::from_millis(100);

const TXINDEX_OPEN_TIMEOUT: Duration = Duration::from_mins(30);

#[derive(Clone, Debug)]
pub struct Generation {
    id: u64,
    revoked: Arc<AtomicBool>,
}

impl Generation {
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    #[must_use]
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub enum DerivedIndexLifecycle {
    Opening,
    Serving(Arc<DerivedIndexQueryEngine>),
    Failed(CompactString),
    ShutdownAbandoned,
}

#[derive(Clone)]
pub struct DerivedIndexQueryAdapter {
    lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>,
}

impl DerivedIndexQueryAdapter {
    #[must_use]
    pub fn new(lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>) -> Self {
        Self { lifecycle }
    }

    pub fn transaction_at_prefix(
        &self,
        txid: &Txid,
    ) -> Result<AtPrefix<Option<(u32, Tx)>>, HistoricalQueryError> {
        let engine = self.load_engine().map_err(map_historical_error)?;
        engine.transaction_at_prefix(txid)
    }

    pub fn script_history_at_prefix(
        &self,
        script: ScriptHash,
    ) -> Result<AtPrefix<ScriptIndexSnapshot>, HistoricalQueryError> {
        let engine = self.load_engine().map_err(map_historical_error)?;
        engine.script_history_at_prefix(script)
    }

    pub fn spender_at_prefix(
        &self,
        outpoint: OutPoint,
    ) -> Result<AtPrefix<Option<SpendingRecord>>, HistoricalQueryError> {
        let engine = self.load_engine().map_err(map_historical_error)?;
        engine.spender_at_prefix(outpoint)
    }

    fn load_engine(&self) -> Result<Arc<DerivedIndexQueryEngine>, TxQueryError> {
        let snapshot = self.lifecycle.load_full();
        match &*snapshot {
            DerivedIndexLifecycle::Serving(engine) => Ok(Arc::clone(engine)),
            DerivedIndexLifecycle::Opening => Err(TxQueryError::Unavailable(
                TxUnavailableCause::Other("txindex is opening".into()),
            )),
            DerivedIndexLifecycle::Failed(_) => Err(TxQueryError::Unavailable(
                TxUnavailableCause::WorkerFailed("txindex is unavailable".into()),
            )),
            DerivedIndexLifecycle::ShutdownAbandoned => Err(TxQueryError::Unavailable(
                TxUnavailableCause::Other("txindex was abandoned at shutdown".into()),
            )),
        }
    }
}

pub struct DerivedIndexOpenSpec {
    pub data_dir: PathBuf,
    pub namespace: &'static str,
    pub storage_backend: bitcoin_rs_storage::StorageBackend,
    pub epoch: u64,
    pub enabled: IndexCapabilities,
    pub rollback_rebuild_cutover: u32,
    pub canonical_data_root: PathBuf,
    #[expect(clippy::type_complexity)]
    pub open_store:
        Arc<dyn Fn(&Path) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> + Send + Sync>,
    pub seed_slot: Option<SeedOfferCell>,
    /// Test-only open specs may leave this unset; live queries then fail closed.
    pub utxo: Option<bitcoin_rs_utxo::UtxoReader>,
    pub chain_transition: Option<bitcoin_rs_chain::StableRead>,
    pub bundle: crate::portable::IndexBundleDirective,
}

pub struct DerivedIndexWorker {
    runtime: Arc<DerivedIndexRuntime>,
    join_handle: Option<JoinHandle<()>>,
    pub generation: Generation,
    namespace_key: Option<PathBuf>,
    open_abandoned: Arc<AtomicBool>,
}

pub struct OpenDerivedIndex {
    pub(crate) writer: Arc<dyn TxIndexWriter>,
    pub(crate) reader: Arc<dyn crate::IndexReader>,
    pub(crate) batch_limits: PreparedBatchLimits,
}

/// Sink for index-ahead rollback evidence.
pub trait IndexAheadSink: Send + Sync {
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

#[cfg(all(test, feature = "fjall"))]
pub(crate) struct RecordedIndexAhead {
    #[expect(clippy::type_complexity)]
    pub(crate) calls: Mutex<Vec<(String, u32, u32, String, String, u32, u64)>>,
}

#[cfg(all(test, feature = "fjall"))]
impl RecordedIndexAhead {
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
    history: HistoryAccess,
    batch_limits: PreparedBatchLimits,
    enabled: IndexCapabilities,
    chain_events: Arc<dyn crate::reconcile::ChainCursorSource>,
    /// Sink for the index-ahead rollback evidence (`chain-rollback-event`
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
    wake_rx: Receiver<()>,
    quiet_period: Duration,
    batch_delay: Duration,
    /// and rebuild instead of a per-block rewind. `u32::MAX` means rewind
    rollback_rebuild_cutover: u32,
    seed_slot: Option<SeedOfferCell>,
    seed_bundle: parking_lot::Mutex<Option<SeedBundle>>,
}

pub(crate) struct SeedBundle {
    pub(crate) artifact: Option<VerifiedSnapshotArtifact>,
    pub(crate) lease: Option<HistoryLease>,
}

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

#[derive(Clone, Copy, Debug)]
struct BlockIdentity {
    height: u32,
    hash: [u8; 32],
    parent_hash: [u8; 32],
}

enum ChunkAction {
    Continue,
    Stalled,
    Progressed,
    MissingBody,
}

enum ForwardLeg {
    Settled(ReconcileAction),
    BodyAbsent,
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
pub enum DerivedIndexWorkerError {
    #[error("txindex worker stopped")]
    Stopped,
    #[error("txindex store open abandoned on shutdown")]
    OpenStopped,
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
    #[error("txindex worker: retained history unavailable: {0}")]
    HistoryUnavailable(#[from] HistoryUnavailable),
    #[error("txindex worker: missing body at height {height}, hash {hash}")]
    MissingBody { height: u32, hash: Hash256 },
    #[error("txindex worker: body store missing")]
    NoBodyStore,
    #[error("txindex worker: ScriptLive history pruned; seed or replay unavailable")]
    ScriptLiveHistoryPruned,
    #[error("txindex worker: undo record missing or unreadable at height {height}, hash {hash}")]
    UndoUnavailable { height: u32, hash: Hash256 },
    #[error("txindex worker: target chain node missing at height {height}")]
    MissingTargetChain { height: u32 },
    /// The rollback evidence sink failed to publish the index-ahead event.
    #[error("txindex worker: rollback evidence marker not written: {0}")]
    RollbackEvidence(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl DerivedIndexWorkerError {
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
mod supervisor_tests;

#[cfg(all(test, feature = "fjall"))]
#[expect(clippy::expect_used, clippy::panic)]
mod recovery_tests;

#[cfg(all(test, feature = "fjall"))]
mod tests;
