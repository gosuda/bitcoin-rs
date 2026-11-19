use arc_swap::ArcSwap;

use bitcoin_rs_consensus::latch::{LatchReader, LatchWriter};
use bitcoin_rs_execution::chain::{BlockTree, BlockTreeReader, TipReader};
use bitcoin_rs_storage::block_body::BlockBodySource;

use crate::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWatermarks,
    IndexWriteFence, PreparedBatch, PreparedBatchLimits, ScriptHash, ScriptLiveScan, TxIndexScan,
    TxIndexScanRow, TxIndexSnapshot,
    reconcile::{ReconcileLeg, ReconcilePhase},
    types::{TxPosition, TxPositionValue},
    writer::TxIndexWriter,
};

use bitcoin_rs_consensus::primitives::{Block, Hash256, OutPoint, Tx, Txid, deserialize};

use crate::capabilities::{
    CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource, derived_index_status,
};
use crate::query_api::{
    Answer, DerivedIndexInfo, DerivedIndexQuery, ScriptHistoryRecord, ScriptIndexQuery,
    ScriptIndexRecord, ScriptIndexSnapshot, SpendingRecord, TransactionBlock, TxQueryError,
    TxUnavailableCause,
};

use bitcoin_rs_storage::{
    PrefixScanLimit,
    block_body::BlockBodyStore,
    pruning::{HistoryAccess, HistoryLease, HistoryUnavailable},
};

use compact_str::CompactString;
use std::sync::atomic::AtomicU64;

use crossbeam_channel::{Receiver, Sender};

#[cfg(test)]
use parking_lot::Mutex;
use parking_lot::RwLock;

#[cfg(test)]
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
pub use startup::{open_derived_index_store_on_worker, open_derived_index_store_with_scratch};

pub use capability::DerivedIndexCapability;
use query::IndexProgress;
pub(crate) use query::QueryEngineLive;
pub use query::{DEFAULT_SCRIPTHASH_LIMIT, DerivedIndexQueryEngine, HistoricalVerifiedReader};

const NO_HISTORICAL_BASE: u64 = u64::MAX;

/// Why ScriptLive is down. `HistoryPruned` is terminal: pruned undo history
/// does not return, so the group stays down until the artifact is replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScriptLiveOutage {
    HistoryPruned,
    Failed(CompactString),
}

impl ScriptLiveOutage {
    pub(crate) fn reason(&self) -> CompactString {
        match self {
            Self::HistoryPruned => DerivedIndexWorkerError::ScriptLiveHistoryPruned
                .to_string()
                .into(),
            Self::Failed(reason) => reason.clone(),
        }
    }
}

pub struct DerivedIndexRuntime {
    revision: AtomicU64,
    pub(super) shutdown: AtomicBool,
    cancel: LatchWriter,
    pub(super) failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<CompactString>>,
    compact_filter_failure: RwLock<Option<CompactString>>,
    script_live_failure: RwLock<Option<ScriptLiveOutage>>,
    tx_lookup_failure: RwLock<Option<CompactString>>,
    undo_gap: RwLock<Option<(u32, Hash256)>>,
    script_history_failure: RwLock<Option<CompactString>>,
    phase: arc_swap::ArcSwap<ReconcilePhase>,
    script_live_seed: Arc<crate::snapshot_seed::ScriptLiveSeedState>,
    historical_base: AtomicU64,
    historical_next: AtomicU64,
}

impl DerivedIndexRuntime {
    #[must_use]
    pub fn new(wake_tx: Sender<()>) -> Arc<Self> {
        let script_live_seed = Arc::new(crate::snapshot_seed::ScriptLiveSeedState::new());
        let runtime = Arc::new(Self {
            revision: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            cancel: LatchWriter::new(),
            failed: AtomicBool::new(false),
            wake_tx,
            failure_message: RwLock::new(None),
            compact_filter_failure: RwLock::new(None),
            tx_lookup_failure: RwLock::new(None),
            script_live_failure: RwLock::new(None),
            undo_gap: RwLock::new(None),
            script_history_failure: RwLock::new(None),
            phase: arc_swap::ArcSwap::from_pointee(ReconcilePhase::FORWARD),
            script_live_seed,
            historical_base: AtomicU64::new(NO_HISTORICAL_BASE),
            historical_next: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&runtime);
        runtime.script_live_seed.set_wake(Arc::new(move || {
            if let Some(runtime) = weak.upgrade() {
                runtime.wake();
            }
        }));
        runtime
    }

    #[must_use]
    pub fn script_live_seed(&self) -> &Arc<crate::snapshot_seed::ScriptLiveSeedState> {
        &self.script_live_seed
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
        let _receiver_gone = self.wake_tx.try_send(());
    }

    /// SNP-08: the snapshot base and the first height whose historical facts
    /// are not yet produced. Heights from `next` through `base` take their
    /// facts from historical validation instead of block bodies.
    pub fn set_historical_window(&self, base: u32, next: u32) {
        self.historical_next
            .store(u64::from(next), Ordering::SeqCst);
        self.historical_base
            .store(u64::from(base), Ordering::SeqCst);
        self.wake();
    }

    /// SNP-08: records that historical facts through `height` were offered to
    /// the facts queue. Called after the offer, so a height below `next` always
    /// has its facts queued or repaired from its body.
    pub fn note_historical_facts(&self, height: u32) {
        self.historical_next
            .fetch_max(u64::from(height) + 1, Ordering::SeqCst);
        self.wake();
    }

    pub(crate) fn awaits_historical_facts(&self, height: u32) -> bool {
        let base = self.historical_base.load(Ordering::SeqCst);
        let height = u64::from(height);
        base != NO_HISTORICAL_BASE
            && height <= base
            && height >= self.historical_next.load(Ordering::SeqCst)
    }

    pub fn publish_failed(&self, message: impl Into<CompactString>) {
        *self.failure_message.write() = Some(message.into());
        self.failed.store(true, Ordering::Release);
    }

    fn fail_capability<T>(
        &self,
        capability: IndexCapabilities,
        failure: &RwLock<Option<T>>,
        value: T,
        error: &DerivedIndexWorkerError,
        message: &str,
    ) {
        tracing::error!(%error, message);
        *failure.write() = Some(value);
        self.publish_leg(capability, ReconcileLeg::Forward);
        self.wake();
    }

    pub fn fail_compact_filters(&self, error: &DerivedIndexWorkerError) {
        self.fail_capability(
            IndexCapabilities::COMPACT_FILTERS,
            &self.compact_filter_failure,
            error.to_string().into(),
            error,
            "compact filter index unavailable; other indexes continue",
        );
    }

    pub fn fail_script_live(&self, error: &DerivedIndexWorkerError) {
        let outage = match error {
            DerivedIndexWorkerError::ScriptLiveHistoryPruned => ScriptLiveOutage::HistoryPruned,
            other => ScriptLiveOutage::Failed(other.to_string().into()),
        };
        self.fail_capability(
            IndexCapabilities::SCRIPT_LIVE,
            &self.script_live_failure,
            outage,
            error,
            "ScriptLive index unavailable; other indexes continue",
        );
    }

    pub fn fail_script_history(&self, error: &DerivedIndexWorkerError) {
        self.fail_capability(
            IndexCapabilities::SCRIPT_HISTORY,
            &self.script_history_failure,
            error.to_string().into(),
            error,
            "ScriptHistory index unavailable; other indexes continue",
        );
    }

    pub(crate) fn clear_script_live(&self) {
        self.script_live_failure.write().take();
    }

    /// SNP-10: TxLookup fails as one capability, never as the whole runtime.
    pub fn fail_tx_lookup(&self, error: &DerivedIndexWorkerError) {
        self.fail_capability(
            IndexCapabilities::TX_LOOKUP,
            &self.tx_lookup_failure,
            error.to_string().into(),
            error,
            "TxLookup paused; other indexes continue",
        );
    }

    pub(crate) fn stop_undo_group(
        &self,
        capabilities: IndexCapabilities,
        error: &DerivedIndexWorkerError,
    ) {
        let filters = capabilities.contains(IndexCapability::CompactFilters);
        let history = capabilities.contains(IndexCapability::ScriptHistory);
        let script_live = capabilities.contains(IndexCapability::ScriptLive);
        if let DerivedIndexWorkerError::UndoUnavailable { height, hash } = error
            && (filters || history || script_live)
        {
            *self.undo_gap.write() = Some((*height, *hash));
        }
        if filters {
            self.fail_compact_filters(error);
        }
        if history {
            self.fail_script_history(error);
        }
        if filters || history {
            self.fail_tx_lookup(error);
        }
        if script_live {
            self.fail_script_live(error);
        }
    }

    pub(crate) fn undo_gap(&self) -> Option<(u32, Hash256)> {
        *self.undo_gap.read()
    }

    pub(crate) fn clear_undo_group(&self) {
        self.undo_gap.write().take();
        self.tx_lookup_failure.write().take();
        self.script_history_failure.write().take();
        self.compact_filter_failure.write().take();
        self.script_live_failure.write().take();
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn script_live_failure(&self) -> Option<ScriptLiveOutage> {
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
        self.cancel();
    }

    pub(crate) fn cancel(&self) {
        self.cancel.trigger();
        let _receiver_gone = self.wake_tx.try_send(());
    }

    #[must_use]
    pub(crate) fn cancel_reader(&self) -> LatchReader {
        self.cancel.reader()
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

    fn transaction_block(
        &self,
        txid: &Txid,
    ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction_block(txid)
    }

    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        let engine = self.load_engine()?;
        engine.index_info()
    }
}

impl ScriptIndexQuery for DerivedIndexQueryAdapter {
    fn history_page(
        &self,
        script: ScriptHash,
        last: Option<Txid>,
        limit: usize,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        self.load_engine()?.history_page(script, last, limit)
    }
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

    fn confirmed_history_page(
        &self,
        scripthash: ScriptHash,
        cursor: Option<Txid>,
        limit: usize,
    ) -> Result<crate::ScriptHistoryPage, TxQueryError> {
        let engine = self.load_engine()?;
        engine.confirmed_history_page(scripthash, cursor, limit)
    }
}

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

pub const DEFAULT_ROLLBACK_REBUILD_CUTOVER: u32 = 100_000;

const IDENTITY_CHUNK_BLOCKS: u32 = 65_536;

const POSITION_PREFETCH_BLOCKS: usize = 65_536;

const PREPARE_CHUNK_BLOCKS: usize = 256;

const PREPARE_CHUNK_BYTES: usize = 32 << 20;

const REVISION_QUIET_PERIOD: Duration = Duration::from_millis(100);

const FORWARD_BATCH_DELAY: Duration = Duration::from_millis(100);

const TXINDEX_OPEN_TIMEOUT: Duration = Duration::from_mins(30);

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

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
    ) -> Result<Answer<Option<(u32, Tx)>>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction_at_answer(txid)
    }

    pub fn script_history_at_prefix(
        &self,
        script: ScriptHash,
    ) -> Result<Answer<ScriptIndexSnapshot>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.script_history_at_answer(script)
    }

    pub fn spender_at_prefix(
        &self,
        outpoint: OutPoint,
    ) -> Result<Answer<Option<SpendingRecord>>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.spender_at_answer(outpoint)
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
    pub scripthash_limit: usize,
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
    pub bundle: crate::portable::IndexBundleDirective,
    pub facts_rx:
        Option<crossbeam_channel::Receiver<std::sync::Arc<bitcoin_rs_storage::CommittedFacts>>>,
    pub facts_charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    pub query_charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    pub facts_gap: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub cpu: Option<Arc<bitcoin_rs_storage::budget::CpuShares>>,
}

pub struct DerivedIndexWorker {
    runtime: Arc<DerivedIndexRuntime>,
    pub(crate) join_handle: Option<JoinHandle<()>>,
    pub generation: Generation,
    namespace_key: Option<PathBuf>,
    open_abandoned: LatchReader,
}

pub struct OpenDerivedIndex {
    pub(crate) writer: Arc<dyn TxIndexWriter>,
    pub(crate) reader: Arc<dyn crate::IndexReader>,
    pub(crate) batch_limits: PreparedBatchLimits,
}

impl OpenDerivedIndex {
    pub fn writer(&self) -> &dyn TxIndexWriter {
        self.writer.as_ref()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IndexAheadError {
    #[error(transparent)]
    Evidence(#[from] bitcoin_rs_storage::recovery_evidence::EvidenceError),
}

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
    ) -> Result<(), IndexAheadError>;
}

pub(crate) struct UndoScripts {
    coins: hashbrown::HashMap<([u8; 32], u32), UndoCoin>,
}

#[derive(Clone)]
pub(crate) struct UndoCoin {
    script: Vec<u8>,
    value: u64,
    height: u32,
    coinbase: bool,
}

impl UndoScripts {
    pub(crate) fn from_undo_bytes(
        bytes: &[u8],
        hash: Hash256,
    ) -> Result<Self, bitcoin_rs_storage::utxo::contract::UndoCodecError> {
        let batch = bitcoin_rs_storage::utxo::contract::decode_undo_record(bytes, hash)?;
        let mut coins = hashbrown::HashMap::with_capacity(batch.restores().len());
        for add in batch.restores() {
            coins.insert(
                (add.outpoint.txid.0.to_le_bytes(), add.outpoint.vout),
                UndoCoin {
                    script: add.txout.script_pubkey.as_bytes().to_vec(),
                    value: add.txout.value.to_sat(),
                    height: add.height,
                    coinbase: add.coinbase,
                },
            );
        }
        Ok(Self { coins })
    }
}

impl crate::SpentCoins for UndoScripts {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<crate::SpentCoin<'_>> {
        self.coins.get(&(*txid, vout)).map(|coin| crate::SpentCoin {
            script: &coin.script[..],
            value: coin.value,
            height: coin.height,
            coinbase: coin.coinbase,
        })
    }
}

#[cfg(test)]
pub(crate) struct TestChainCursor;

#[cfg(test)]
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

#[cfg(test)]
pub(crate) struct RecordedIndexAhead {
    #[expect(clippy::type_complexity)]
    pub(crate) calls: Mutex<Vec<(String, u32, u32, String, String, u32, u64)>>,
}

#[cfg(test)]
impl RecordedIndexAhead {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
        })
    }
}

#[cfg(test)]
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
    ) -> Result<(), IndexAheadError> {
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
    reporter: Arc<dyn crate::runtime::IndexAheadSink>,
    shutdown: LatchReader,
    wake_rx: Receiver<()>,
    quiet_period: Duration,
    batch_delay: Duration,
    rollback_rebuild_cutover: u32,
    seed_history_lease: parking_lot::Mutex<Option<HistoryLease>>,
    facts_rx: Option<Receiver<std::sync::Arc<bitcoin_rs_storage::CommittedFacts>>>,
    facts_charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    facts_gap: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    cpu: Option<Arc<bitcoin_rs_storage::budget::CpuShares>>,
    buffered_facts:
        parking_lot::Mutex<hashbrown::HashMap<([u8; 32], u32), bitcoin_rs_storage::CommittedBlock>>,
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
    AwaitingFacts,
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
    #[error("txindex namespace open or recreation failed: {0}")]
    NamespaceOpen(#[from] std::io::Error),
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
    #[error("txindex worker: tx lookup artifact unavailable: {0}")]
    ArtifactUnavailable(String),
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
    #[error("txindex worker: rollback evidence marker not written: {0}")]
    RollbackEvidence(#[from] IndexAheadError),
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
mod query_tests {
    use crate::TxIndexSnapshot;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::types::{TxPosition, TxPositionValue, TxidRow};
    use crate::{
        HashPrefixRow, IndexCapabilities, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow,
    };
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
        Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_execution::chain::{NodeStatus, regtest_fixture};
    use bitcoin_rs_storage::{ColumnFamily, PrefixScan, PrefixScanLimit};

    use super::*;
    use crate::{IndexCapability, IndexWatermark, RetryReason};
    use bitcoin_rs_execution::chain::TipSnapshot;
    use bitcoin_rs_execution::chain::{BlockTree, NodeId};
    use parking_lot::Mutex as ParkMutex;

    #[derive(Clone)]
    struct ScanResponse {
        cf: ColumnFamily,
        prefix: Vec<u8>,
        scan: PrefixScan,
    }

    fn fake_family_page(
        scans: &[ScanResponse],
        cf: ColumnFamily,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<crate::TxIndexPage, IndexError> {
        let mut rows: Vec<_> = scans
            .iter()
            .filter(|response| response.cf == cf)
            .flat_map(|response| response.scan.rows.iter().cloned())
            .collect();
        rows.sort();
        rows.dedup_by(|left, right| left.0 == right.0);
        let mut page = Vec::new();
        let mut bytes = 0_usize;
        for (key, value) in rows {
            if start_after.is_some_and(|cursor| key.as_slice() <= cursor) {
                continue;
            }
            let row_bytes = key.len() + value.len();
            if page.len() >= limit.max_rows
                || (!page.is_empty() && bytes.saturating_add(row_bytes) > limit.max_bytes)
            {
                return Ok(crate::TxIndexPage {
                    rows: page,
                    complete: false,
                });
            }
            bytes = bytes.saturating_add(row_bytes);
            if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let row = zerocopy::FromBytes::read_from_bytes(&key)
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            page.push(TxIndexScanRow { row, value });
        }
        Ok(crate::TxIndexPage {
            rows: page,
            complete: true,
        })
    }

    #[derive(Clone)]
    struct QuerySnapshot {
        watermark: IndexWatermark,
        scans: Vec<ScanResponse>,
    }

    impl QuerySnapshot {
        fn scan_for(&self, cf: ColumnFamily, prefix: &[u8]) -> PrefixScan {
            self.scans
                .iter()
                .find(|response| response.cf == cf && response.prefix == prefix)
                .map_or(
                    PrefixScan {
                        rows: Vec::new(),
                        complete: true,
                    },
                    |response| response.scan.clone(),
                )
        }

        fn typed_scan(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<TxIndexScan, IndexError> {
            let scan = self.scan_for(cf, prefix);
            let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
                total.saturating_add(key.len()).saturating_add(value.len())
            });
            let mut rows = Vec::with_capacity(scan.rows.len());
            for (key, value) in scan.rows {
                if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                    return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
                }
                let prefix = key[..crate::types::HASH_PREFIX_LEN]
                    .try_into()
                    .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
                let height = key[crate::types::HASH_PREFIX_LEN..crate::HASH_PREFIX_ROW_SIZE]
                    .try_into()
                    .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
                rows.push(TxIndexScanRow {
                    row: HashPrefixRow { prefix, height },
                    value,
                });
            }
            Ok(TxIndexScan {
                rows,
                encoded_bytes,
                complete: scan.complete,
            })
        }

        fn history_scan(&self, scripthash: ScriptHash) -> Result<TxIndexScan, IndexError> {
            let mut scan = self.typed_scan(
                ColumnFamily::Funding,
                &ScriptHashRow::scan_prefix(scripthash),
            )?;
            for row in &mut scan.rows {
                row.row.height = crate::types::encode_height(!u32::from_be_bytes(row.row.height));
            }
            Ok(scan)
        }
    }

    impl TxIndexSnapshot for QuerySnapshot {
        fn compact_filter(
            &self,
            height: u32,
            hash: &[u8; 32],
        ) -> Result<Option<crate::BasicFilter>, IndexError> {
            let key = crate::segment::format::encode_filter_key(0, height);
            let scan = self.scan_for(ColumnFamily::Filters, &key);
            Ok(scan.rows.iter().find_map(|(_, value)| {
                let (block_hash, filter_hash, header, filter) =
                    crate::segment::format::decode_filter_value(value)?;
                (block_hash == *hash).then(|| crate::BasicFilter {
                    filter: filter.to_vec(),
                    hash: filter_hash,
                    header,
                })
            }))
        }

        fn capability_watermark(
            &self,
            _capability: IndexCapability,
        ) -> Result<Option<IndexWatermark>, IndexError> {
            Ok(Some(self.watermark))
        }

        fn tx_lookup_page(
            &self,
            start_after: Option<&[u8]>,
            limit: PrefixScanLimit,
        ) -> Result<crate::TxIndexPage, IndexError> {
            fake_family_page(&self.scans, ColumnFamily::TxConfirmed, start_after, limit)
        }

        fn transaction_rows(
            &self,
            txid: &Txid,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            self.typed_scan(ColumnFamily::TxConfirmed, &TxidRow::scan_prefix(txid))
        }

        fn funding_transaction_rows(
            &self,
            _txid: &Txid,
            _limit: PrefixScanLimit,
        ) -> Result<crate::FundingTransactionScan, IndexError> {
            Ok(crate::FundingTransactionScan {
                rows: Vec::new(),
                examined_rows: 0,
                encoded_bytes: 0,
                complete: true,
            })
        }

        fn funding_rows(
            &self,
            scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            self.history_scan(scripthash)
        }

        fn funding_rows_from(
            &self,
            scripthash: ScriptHash,
            start_height: u32,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            let mut scan = self.history_scan(scripthash)?;
            scan.rows.retain(|row| row.row.height() <= start_height);
            scan.rows.truncate(limit.max_rows);
            Ok(scan)
        }

        fn spending_rows(
            &self,
            outpoint: &OutPoint,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            self.typed_scan(
                ColumnFamily::Spending,
                &SpendingPrefixRow::scan_prefix(outpoint),
            )
        }

        fn live_rows(
            &self,
            scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<crate::ScriptLiveScan, IndexError> {
            let scan = self.scan_for(
                ColumnFamily::ScriptLive,
                &ScriptHashRow::scan_prefix(scripthash),
            );
            let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
                total.saturating_add(key.len()).saturating_add(value.len())
            });
            let mut rows = Vec::with_capacity(scan.rows.len());
            let mut coins = Vec::with_capacity(scan.rows.len());
            for (key, value) in scan.rows {
                rows.push(
                    ScriptLiveRow::from_db_row(&key)
                        .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?,
                );
                coins.push(
                    crate::types::ScriptLiveCoin::decode_value(&value)
                        .map_err(|_| IndexError::InvalidLiveRowValue { len: value.len() })?,
                );
            }
            Ok(crate::ScriptLiveScan {
                rows,
                coins,
                encoded_bytes,
                complete: scan.complete,
            })
        }
    }

    struct QueryReader {
        snapshot: QuerySnapshot,
    }

    impl IndexReader for QueryReader {
        fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
            Ok(Box::new(self.snapshot.clone()))
        }
    }

    struct FixtureConfig {
        block: Block,
        retain_body: bool,
        scans: Vec<ScanResponse>,
        watermark: Option<IndexWatermark>,
        extra_blocks: Vec<Block>,
    }

    struct QueryFixture {
        engine: DerivedIndexQueryEngine,
        runtime: Arc<DerivedIndexRuntime>,
        body: Option<Arc<SingleBlockBody>>,
        multi_body: Option<Arc<MultiBlockBody>>,
    }

    pub(super) struct SingleBlockBody {
        pub(super) height: u32,
        pub(super) hash: BlockHash,
        pub(super) body: Vec<u8>,
        pub(super) full_reads: AtomicUsize,
        range_reads: AtomicUsize,
    }

    impl BlockBodySource for SingleBlockBody {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            if height == self.height && hash == self.hash {
                self.full_reads.fetch_add(1, Ordering::Relaxed);
            }
            Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: BlockHash,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            if height != self.height || hash != self.hash {
                return None;
            }
            self.range_reads.fetch_add(1, Ordering::Relaxed);
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            self.body.get(start..end).map(<[u8]>::to_vec)
        }
    }

    impl QueryFixture {
        fn new(config: FixtureConfig) -> Result<Self, crate::portable::TestError> {
            Self::new_with_transition(config, None)
        }

        fn new_with_transition(
            config: FixtureConfig,
            chain_transition: Option<bitcoin_rs_execution::chain::StableRead>,
        ) -> Result<Self, crate::portable::TestError> {
            let mut tree = BlockTree::new();
            let mut tip_id = tree.insert_header(config.block.header, NodeStatus::HeaderValid)?;
            let mut heights = vec![tree.node(tip_id)?.height];
            let mut blocks = vec![config.block];
            for block in config.extra_blocks {
                tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
                heights.push(tree.node(tip_id)?.height);
                blocks.push(block);
            }
            let node = tree.node(tip_id)?;
            let tip = TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            };
            let tree = Arc::new(RwLock::new(tree));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let home = Arc::new(tip.clone());
            applied_tip.store(Some(Arc::clone(&home)));

            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
            let runtime = DerivedIndexRuntime::new(wake_tx);
            let watermark = config.watermark.unwrap_or(IndexWatermark {
                height: tip.height,
                hash: *tip.hash.as_byte_array(),
            });
            let reader = Arc::new(QueryReader {
                snapshot: QuerySnapshot {
                    watermark,
                    scans: config.scans,
                },
            });
            let body = if config.retain_body && blocks.len() == 1 {
                Some(Arc::new(SingleBlockBody {
                    range_reads: AtomicUsize::new(0),
                    height: heights[0],
                    hash: blocks[0].block_hash(),
                    body: consensus_bytes(&blocks[0]),
                    full_reads: AtomicUsize::new(0),
                }))
            } else {
                None
            };
            let multi_body = if config.retain_body && blocks.len() > 1 {
                Some(Arc::new(MultiBlockBody {
                    range_reads: AtomicUsize::new(0),
                    bodies: heights
                        .iter()
                        .zip(blocks.iter())
                        .map(|(height, block)| {
                            (*height, block.block_hash(), consensus_bytes(block))
                        })
                        .collect(),
                    full_reads: AtomicUsize::new(0),
                }))
            } else {
                None
            };
            let body_source: Option<Arc<dyn BlockBodySource>> = body
                .as_ref()
                .map(|source| {
                    let source: Arc<dyn BlockBodySource> = source.clone();
                    source
                })
                .or_else(|| {
                    multi_body.as_ref().map(|source| {
                        let source: Arc<dyn BlockBodySource> = source.clone();
                        source
                    })
                });
            let engine = DerivedIndexQueryEngine::new(
                Arc::clone(&runtime),
                reader,
                bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
                bitcoin_rs_execution::chain::TipReader::new(applied_tip),
                body_source,
                QueryEngineLive {
                    enabled: IndexCapabilities::ALL,
                    generation: Arc::new(Generation::new(1)),
                    historical_verified: None,
                    chain_transition,
                },
            );
            Ok(Self {
                engine,
                runtime,
                body,
                multi_body,
            })
        }

        fn full_reads(&self) -> Result<usize, std::io::Error> {
            if self.body.is_none() && self.multi_body.is_none() {
                return Err(std::io::Error::other("body source"));
            }
            let single = self
                .body
                .as_ref()
                .map_or(0, |body| body.full_reads.load(Ordering::Relaxed));
            let multi = self
                .multi_body
                .as_ref()
                .map_or(0, |body| body.full_reads.load(Ordering::Relaxed));
            Ok(single + multi)
        }
    }

    // SYNC-03, IDX-03
    #[test]
    fn unusable_worker_makes_queries_unavailable() -> Result<(), crate::portable::TestError> {
        for publish in [true, false] {
            let block = Network::Regtest.genesis_block();
            let txid = block.txs[0].txid();
            let fixture = QueryFixture::new(FixtureConfig {
                block,
                retain_body: true,
                scans: Vec::new(),
                watermark: None,
                extra_blocks: Vec::new(),
            })?;
            if publish {
                fixture.runtime.publish_failed("injected worker failure");
            } else {
                fixture.runtime.request_shutdown();
            }

            let result = fixture.engine.transaction(&txid);
            if publish {
                assert!(
                    matches!(
                        &result,
                        Err(TxQueryError::Unavailable(
                            TxUnavailableCause::WorkerFailed(reason)
                        )) if reason.as_str() == "injected worker failure"
                    ),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(
                        &result,
                        Err(TxQueryError::Unavailable(TxUnavailableCause::WorkerStopped))
                    ),
                    "{result:?}"
                );
            }
        }
        Ok(())
    }

    // SYNC-03
    #[test]
    fn filter_failure_refuses_filters_but_preserves_durable_progress_and_tx_queries()
    -> Result<(), crate::portable::TestError> {
        use crate::CompactFilterQuery;
        let block = Network::Regtest.genesis_block();
        let hash = Hash256::from(block.block_hash());
        let transaction = block.txs[0].clone();
        let txid = transaction.txid();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;
        fixture
            .runtime
            .fail_compact_filters(&DerivedIndexWorkerError::UndoUnavailable { height: 1, hash });
        assert!(matches!(
            fixture.engine.block_filter(hash),
            Err(TxQueryError::Unavailable(_))
        ));
        assert!(!fixture.engine.filter_index_info()?.synced);
        assert!(fixture.engine.index_info()?.synced);
        assert_eq!(fixture.engine.transaction(&txid)?, Some(transaction));
        assert!(!fixture.runtime.should_stop());
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Serving(
            Arc::new(fixture.engine.clone()),
        )));
        let status = DerivedIndexCapability::new(
            Some(lifecycle.clone()),
            Some(fixture.runtime.clone()),
            IndexCapabilities::ALL,
        );
        for leg in [
            ReconcileLeg::Forward,
            ReconcileLeg::Rebuilding,
            ReconcileLeg::RollingBack {
                from_height: 1,
                to_height: 0,
            },
        ] {
            fixture
                .runtime
                .publish_leg(IndexCapabilities::COMPACT_FILTERS, leg);
            assert_eq!(status.capability().state, CapabilityState::Ready);
        }
        let filters_only = DerivedIndexCapability::new(
            Some(lifecycle),
            Some(fixture.runtime),
            IndexCapabilities::COMPACT_FILTERS,
        )
        .capability();
        assert!(filters_only.enabled);
        assert_ne!(filters_only.state, CapabilityState::Disabled);
        Ok(())
    }

    fn scan_response(
        cf: ColumnFamily,
        prefix: impl Into<Vec<u8>>,
        rows: Vec<(Vec<u8>, Vec<u8>)>,
        complete: bool,
    ) -> ScanResponse {
        ScanResponse {
            cf,
            prefix: prefix.into(),
            scan: PrefixScan { rows, complete },
        }
    }

    fn position_of_transaction(block: &Block, index: usize) -> Result<TxPosition, std::io::Error> {
        let body = consensus_bytes(block);
        let transaction = consensus_bytes(&block.txs[index]);
        let offset = body
            .windows(transaction.len())
            .position(|window| window == transaction)
            .ok_or_else(|| std::io::Error::other("transaction must be present"))?;
        let offset =
            u32::try_from(offset).map_err(|_| std::io::Error::other("transaction offset fits"))?;
        let length = u32::try_from(transaction.len())
            .map_err(|_| std::io::Error::other("transaction length fits"))?;
        Ok(TxPosition::new(offset, length))
    }

    fn history_row_raw(
        scripthash: ScriptHash,
        height: u32,
        occurrences: &[crate::types::ScriptHistoryOccurrence],
    ) -> (Vec<u8>, Vec<u8>) {
        let row = HashPrefixRow {
            prefix: ScriptHashRow::scan_prefix(scripthash),
            height: (!height).to_be_bytes(),
        };
        (
            row.to_db_row().to_vec(),
            crate::types::ScriptHistoryOccurrence::encode_all(occurrences),
        )
    }

    fn history_row(
        scripthash: ScriptHash,
        height: u32,
        occurrences: &[(Txid, TxPosition, u8)],
    ) -> (Vec<u8>, Vec<u8>) {
        let encoded: Vec<_> = occurrences
            .iter()
            .map(
                |(txid, position, flags)| crate::types::ScriptHistoryOccurrence {
                    scripthash,
                    txid: *txid.as_bytes(),
                    position: *position,
                    flags: *flags,
                },
            )
            .collect();
        history_row_raw(scripthash, height, &encoded)
    }

    fn block_with_spending_transaction()
    -> Result<(Block, OutPoint, ScriptHash, Txid), std::io::Error> {
        let mut block = Network::Regtest.genesis_block();
        let funding_txid = block.txs[0].txid();
        let script = block.txs[0].outputs[0].script_pubkey.clone();
        let value = block.txs[0].outputs[0].value;
        let outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        block.txs.push(Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: Script::new(),
            }],
        });
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| std::io::Error::other("block has transactions"))?;
        let spend_txid = block.txs[1].txid();
        Ok((block, outpoint, ScriptHash::new(&script), spend_txid))
    }

    // IDX-03
    #[test]
    fn transaction_rejects_watermark_from_rival_tip() -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let prefix = TxidRow::scan_prefix(&txid);
        let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                prefix,
                vec![(indexed_row, vec![0])],
                true,
            )],
            watermark: Some(IndexWatermark {
                height: 0,
                hash: [0x5a; 32],
            }),
            extra_blocks: Vec::new(),
        })?;

        assert!(matches!(
            fixture.engine.transaction(&txid),
            Err(TxQueryError::Retry(RetryReason::PendingCapabilityCoverage(
                IndexCapability::TxLookup
            )))
        ));
        Ok(())
    }

    #[test]
    fn transaction_rejects_incomplete_prefix_scan() -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let prefix = TxidRow::scan_prefix(&txid);
        let tempting_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                prefix,
                vec![(tempting_row, vec![0])],
                false,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        assert!(matches!(
            fixture.engine.transaction(&txid),
            Err(TxQueryError::Unavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn transaction_reports_unavailable_when_indexed_body_is_missing()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let prefix = TxidRow::scan_prefix(&txid);
        let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: false,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                prefix,
                vec![(indexed_row, vec![0])],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        assert!(matches!(
            fixture.engine.transaction(&txid),
            Err(TxQueryError::Unavailable(_))
        ));
        Ok(())
    }

    struct FailingBody {
        error: bitcoin_rs_storage::block_body::BlockBodyReadError,
    }

    impl BlockBodySource for FailingBody {
        fn block_body(
            &self,
            _height: u32,
            _hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            Err(self.error.clone())
        }
    }

    struct MissingBody;

    impl BlockBodySource for MissingBody {
        fn block_body(
            &self,
            _height: u32,
            _hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            Ok(None)
        }
    }

    fn engine_with_body_source(
        block: &Block,
        scans: Vec<ScanResponse>,
        body_source: Option<Arc<dyn BlockBodySource>>,
    ) -> Result<DerivedIndexQueryEngine, crate::portable::TestError> {
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let node = tree.node(tip_id)?;
        let tip = TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        };
        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(tip.clone())));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reader = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark: IndexWatermark {
                    height: tip.height,
                    hash: *tip.hash.as_byte_array(),
                },
                scans,
            },
        });
        Ok(DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
            bitcoin_rs_execution::chain::TipReader::new(applied_tip),
            body_source,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        ))
    }

    fn engine_with_body_error(
        block: &Block,
        scans: Vec<ScanResponse>,
        error: bitcoin_rs_storage::block_body::BlockBodyReadError,
    ) -> Result<DerivedIndexQueryEngine, crate::portable::TestError> {
        engine_with_body_source(block, scans, Some(Arc::new(FailingBody { error })))
    }

    #[derive(Default)]
    struct RecordingQueryCharge {
        balance: ParkMutex<u64>,
    }

    impl bitcoin_rs_storage::budget::BudgetCharge for RecordingQueryCharge {
        fn reserve_bytes(
            &self,
            _owner: bitcoin_rs_storage::budget::BudgetOwner,
            _bytes: u64,
        ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
            Ok(())
        }

        fn allocate_bytes(
            &self,
            _owner: bitcoin_rs_storage::budget::BudgetOwner,
            bytes: u64,
        ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
            *self.balance.lock() += bytes;
            Ok(())
        }

        fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, bytes: u64) {
            let mut balance = self.balance.lock();
            *balance = balance.saturating_sub(bytes);
        }

        fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
            u64::MAX
        }
    }

    // BUD-06
    #[test]
    fn query_view_capture_charges_query_views_and_drop_returns_it()
    -> Result<(), crate::portable::TestError> {
        let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
        let engine = engine_with_body_source(&genesis, Vec::new(), None)?;
        let charge = Arc::new(RecordingQueryCharge::default());
        let engine = engine.with_query_charge(Some(bitcoin_rs_storage::budget::ChargeHandle::new(
            charge.clone(),
            bitcoin_rs_storage::budget::BudgetOwner::QueryViews,
        )));
        let (view, snapshot) = engine
            .capture_view(IndexCapabilities::TX_LOOKUP)
            .map_err(|_| std::io::Error::other("query view capture refused"))?;
        let held = *charge.balance.lock();
        assert!(held > 0, "capturing a view charges the query views owner");
        drop(snapshot);
        drop(view);
        let current = *charge.balance.lock();
        assert_eq!(current, 0, "dropping the view returns its charge");
        Ok(())
    }

    #[test]
    fn transaction_reports_unavailable_when_body_source_returns_none()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let prefix = TxidRow::scan_prefix(&txid);
        let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
        let engine = engine_with_body_source(
            &block,
            vec![scan_response(
                ColumnFamily::TxConfirmed,
                prefix,
                vec![(indexed_row, vec![0])],
                true,
            )],
            Some(Arc::new(MissingBody)),
        )?;

        assert!(matches!(
            engine.transaction(&txid),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::BlockBodyMissing { height: 0 }
            ))
        ));
        Ok(())
    }

    #[test]
    fn history_snapshot_reports_unavailable_when_a_funding_body_is_missing()
    -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let block = Network::Regtest.genesis_block();
        let tx = &block.txs[0];
        let scripthash = ScriptHash::new(&tx.outputs[0].script_pubkey);
        let body = consensus_bytes(&block);
        let transaction = consensus_bytes(tx);
        let offset = body
            .windows(transaction.len())
            .position(|window| window == transaction)
            .ok_or("the coinbase is present")?;
        let offset = u32::try_from(offset).map_err(|_| "offset fits")?;
        let length = u32::try_from(transaction.len()).map_err(|_| "length fits")?;
        let occurrence = ScriptHistoryOccurrence {
            scripthash,
            txid: *tx.txid().as_bytes(),
            position: TxPosition::new(offset, length),
            flags: ScriptHistoryOccurrence::FUNDING,
        };
        let engine = engine_with_body_source(
            &block,
            vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![history_row_raw(scripthash, 0, &[occurrence])],
                true,
            )],
            Some(Arc::new(MissingBody)),
        )?;

        assert!(matches!(
            engine.history_snapshot(scripthash),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::BlockBodyMissing { height: 0 }
            ))
        ));
        Ok(())
    }

    // IDX-03
    #[test]
    fn transaction_reports_storage_when_body_read_fails() -> Result<(), crate::portable::TestError>
    {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let prefix = TxidRow::scan_prefix(&txid);
        let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
        let engine = engine_with_body_error(
            &block,
            vec![scan_response(
                ColumnFamily::TxConfirmed,
                prefix,
                vec![(indexed_row, vec![0])],
                true,
            )],
            bitcoin_rs_storage::block_body::BlockBodyReadError::Read(
                "injected read failure".into(),
            ),
        )?;

        assert!(matches!(
            engine.transaction(&txid),
            Err(TxQueryError::Storage(_))
        ));
        Ok(())
    }

    #[test]
    fn transaction_reports_storage_when_body_is_corrupt() -> Result<(), crate::portable::TestError>
    {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let prefix = TxidRow::scan_prefix(&txid);
        let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
        let engine = engine_with_body_error(
            &block,
            vec![scan_response(
                ColumnFamily::TxConfirmed,
                prefix,
                vec![(indexed_row, vec![0])],
                true,
            )],
            bitcoin_rs_storage::block_body::BlockBodyReadError::Corrupt(
                "injected corruption".into(),
            ),
        )?;

        assert!(matches!(
            engine.transaction(&txid),
            Err(TxQueryError::Storage(_))
        ));
        Ok(())
    }

    #[test]
    fn empty_position_rows_are_refused_before_body_reads() -> Result<(), crate::portable::TestError>
    {
        let (block, outpoint, scripthash, _) = block_with_spending_transaction()?;
        let txid = block.txs[0].txid();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![
                scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), Vec::new())],
                    true,
                ),
                scan_response(
                    ColumnFamily::Funding,
                    ScriptHashRow::scan_prefix(scripthash),
                    vec![history_row(scripthash, 0, &[])],
                    true,
                ),
                scan_response(
                    ColumnFamily::Spending,
                    SpendingPrefixRow::scan_prefix(&outpoint),
                    vec![(
                        SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec(),
                        Vec::new(),
                    )],
                    true,
                ),
            ],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;
        assert!(matches!(
            fixture.engine.transaction(&txid),
            Err(TxQueryError::Storage(_))
        ));
        assert!(matches!(
            fixture.engine.confirmed_history(scripthash),
            Err(TxQueryError::Storage(_))
        ));
        assert!(matches!(
            fixture.engine.spender(outpoint),
            Err(TxQueryError::Storage(_))
        ));
        assert_eq!(fixture.full_reads()?, 0);
        Ok(())
    }

    #[test]
    fn spending_position_mismatch_falls_back_to_full_block()
    -> Result<(), crate::portable::TestError> {
        let (block, outpoint, _, spend_txid) = block_with_spending_transaction()?;
        let spending_row = SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec();
        let fixture = QueryFixture::new(FixtureConfig {
            block: block.clone(),
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::Spending,
                SpendingPrefixRow::scan_prefix(&outpoint),
                vec![(
                    spending_row,
                    TxPositionValue::encode(&[position_of_transaction(&block, 0)?]),
                )],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        assert_eq!(
            fixture
                .engine
                .spender(outpoint)?
                .map(|spender| spender.txid),
            Some(spend_txid)
        );
        assert_eq!(fixture.full_reads()?, 1);
        Ok(())
    }

    #[test]
    fn confirmed_history_serves_stored_occurrences_without_block_bodies()
    -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let (block, outpoint, scripthash, spend_txid) = block_with_spending_transaction()?;
        let funding_txid = block.txs[0].txid();
        let coinbase_at = position_of_transaction(&block, 0)?;
        let spend_at = position_of_transaction(&block, 1)?;
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![
                scan_response(
                    ColumnFamily::Funding,
                    ScriptHashRow::scan_prefix(scripthash),
                    vec![history_row(
                        scripthash,
                        0,
                        &[
                            (funding_txid, coinbase_at, ScriptHistoryOccurrence::FUNDING),
                            (spend_txid, spend_at, ScriptHistoryOccurrence::SPENDING),
                        ],
                    )],
                    true,
                ),
                scan_response(
                    ColumnFamily::Spending,
                    SpendingPrefixRow::scan_prefix(&outpoint),
                    vec![(
                        SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec(),
                        vec![0],
                    )],
                    true,
                ),
            ],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        let history = fixture.engine.confirmed_history(scripthash)?;
        assert_eq!(history.len(), 2);
        assert!(
            history
                .iter()
                .any(|record| record.txid == funding_txid && record.height == 0)
        );
        assert!(
            history
                .iter()
                .any(|record| record.txid == spend_txid && record.height == 0)
        );
        assert_eq!(
            fixture.full_reads()?,
            0,
            "a stored occurrence names its transaction, so no body is read"
        );
        Ok(())
    }

    struct MultiBlockBody {
        range_reads: AtomicUsize,
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        full_reads: AtomicUsize,
    }

    impl BlockBodySource for MultiBlockBody {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            let hit = self.bodies.iter().find(|(block_height, block_hash, _)| {
                *block_height == height && *block_hash == hash
            });
            if hit.is_some() {
                self.full_reads.fetch_add(1, Ordering::Relaxed);
            }
            Ok(hit.map(|(_, _, body)| body.clone()))
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: BlockHash,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            let (_, _, body) = self.bodies.iter().find(|(block_height, block_hash, _)| {
                *block_height == height && *block_hash == hash
            })?;
            self.range_reads.fetch_add(1, Ordering::Relaxed);
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            body.get(start..end).map(<[u8]>::to_vec)
        }
    }

    fn child_block(parent: &Block, txs: Vec<Tx>) -> Result<Block, std::io::Error> {
        let mut block = parent.clone();
        block.header.prev_blockhash = parent.block_hash();
        block.txs = txs;
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| std::io::Error::other("chain test block carries transactions"))?;
        Ok(block)
    }

    fn paying_chain() -> Result<(Block, Vec<Block>, ScriptHash), std::io::Error> {
        let genesis = Network::Regtest.genesis_block();
        let script = genesis.txs[0].outputs[0].script_pubkey.clone();
        let value = genesis.txs[0].outputs[0].value;
        let pay = |filler: &[u8]| Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: {
                let mut outputs = vec![TxOut {
                    value,
                    script_pubkey: script.clone(),
                }];
                if !filler.is_empty() {
                    outputs.push(TxOut {
                        value,
                        script_pubkey: Script::from_bytes(filler.to_vec()),
                    });
                }
                outputs
            },
        };
        let mut middle_txs = vec![pay(&[0x6a, 0x01]), pay(&[0x6a, 0x02])];
        middle_txs.sort_by_key(|tx| std::cmp::Reverse(tx.txid()));
        let middle = child_block(&genesis, middle_txs)?;
        let tip = child_block(&middle, vec![pay(&[])])?;
        let scripthash = ScriptHash::new(&script);
        Ok((genesis, vec![middle, tip], scripthash))
    }

    #[test]
    fn outpoint_value_returns_confirmed_output_value() -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let expected = block.txs[0].outputs[0].value.to_sat();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        assert_eq!(
            fixture.engine.outpoint_value(&OutPoint { txid, vout: 0 })?,
            Some(expected)
        );
        Ok(())
    }

    #[test]
    fn outpoint_value_returns_none_for_out_of_range_vout() -> Result<(), crate::portable::TestError>
    {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let vout = u32::try_from(block.txs[0].outputs.len())
            .map_err(|_| std::io::Error::other("vout fits"))?;
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        assert_eq!(
            fixture.engine.outpoint_value(&OutPoint { txid, vout })?,
            None
        );
        Ok(())
    }

    #[test]
    fn outpoint_value_returns_none_for_unknown_txid() -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let known = block.txs[0].txid();
        let unknown = Txid(Hash256::from_le_bytes(&[0xa5; 32]));
        assert_ne!(known.as_bytes(), &[0xa5; 32]);
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&unknown),
                Vec::new(),
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        assert_eq!(
            fixture.engine.outpoint_value(&OutPoint {
                txid: unknown,
                vout: 0,
            })?,
            None
        );
        Ok(())
    }

    #[test]
    fn funding_prefix_scan_ignores_occurrences_of_other_scripts()
    -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let (block, _, scripthash, _) = block_with_spending_transaction()?;
        let funding_txid = block.txs[0].txid();
        let expected_value = block.txs[0].outputs[0].value.to_sat();
        let coinbase_at = position_of_transaction(&block, 0)?;
        let foreign_at = position_of_transaction(&block, 1)?;
        let mut foreign_bytes = scripthash.to_byte_array();
        foreign_bytes[31] ^= 0xEE;
        let foreign = ScriptHash::from_byte_array(foreign_bytes);
        let mut occurrences = vec![ScriptHistoryOccurrence {
            scripthash,
            txid: *funding_txid.as_bytes(),
            position: coinbase_at,
            flags: ScriptHistoryOccurrence::FUNDING,
        }];
        occurrences.push(ScriptHistoryOccurrence {
            scripthash: foreign,
            txid: *block.txs[1].txid().as_bytes(),
            position: foreign_at,
            flags: ScriptHistoryOccurrence::SPENDING,
        });
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![history_row_raw(scripthash, 0, &occurrences)],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        let history = fixture.engine.confirmed_history(scripthash)?;
        assert_eq!(
            history.len(),
            1,
            "only the exact script occurrence is served"
        );
        assert_eq!(history[0].txid, funding_txid);
        let snapshot = fixture.engine.history_snapshot(scripthash)?;
        assert_eq!(snapshot.funding.len(), 1);
        assert_eq!(snapshot.funding[0].value, expected_value);
        Ok(())
    }

    // IDX-02
    #[test]
    fn history_snapshot_reports_each_confirmed_transaction_once()
    -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let mut block = Network::Regtest.genesis_block();
        let script = block.txs[0].outputs[0].script_pubkey.clone();
        let scripthash = ScriptHash::new(&script);
        let value = block.txs[0].outputs[0].value;
        let coinbase_txid = block.txs[0].txid();
        let duplicate_outputs = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value,
                    script_pubkey: script.clone(),
                },
                TxOut {
                    value,
                    script_pubkey: script.clone(),
                },
            ],
        };
        let self_spend = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: script.clone(),
            }],
        };
        block.txs.push(duplicate_outputs);
        block.txs.push(self_spend);
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| std::io::Error::other("block has transactions"))?;
        let duplicate_txid = block.txs[1].txid();
        let self_spend_txid = block.txs[2].txid();
        let duplicate_at = position_of_transaction(&block, 1)?;
        let self_spend_at = position_of_transaction(&block, 2)?;
        let occurrences = [
            (
                duplicate_txid,
                duplicate_at,
                ScriptHistoryOccurrence::FUNDING,
            ),
            (
                duplicate_txid,
                duplicate_at,
                ScriptHistoryOccurrence::FUNDING,
            ),
            (
                self_spend_txid,
                self_spend_at,
                ScriptHistoryOccurrence::SPENDING,
            ),
            (
                self_spend_txid,
                self_spend_at,
                ScriptHistoryOccurrence::FUNDING,
            ),
        ];
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![history_row(scripthash, 0, &occurrences)],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        let snapshot = fixture.engine.history_snapshot(scripthash)?;
        let mut history_txids: Vec<_> = snapshot.history.iter().map(|record| record.txid).collect();
        history_txids.sort();
        let mut expected_txids = vec![duplicate_txid, self_spend_txid];
        expected_txids.sort();
        assert_eq!(history_txids, expected_txids);
        assert_eq!(
            snapshot.funding.len(),
            3,
            "funding keeps every distinct output"
        );
        let duplicate_vouts: Vec<u32> = snapshot
            .funding
            .iter()
            .filter(|record| record.txid == duplicate_txid)
            .map(|record| record.vout)
            .collect();
        assert_eq!(duplicate_vouts, [0, 1]);
        assert_eq!(
            snapshot
                .funding
                .iter()
                .filter(|record| record.txid == self_spend_txid)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn history_summary_never_consults_spender_rows() -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let (block, outpoint, scripthash, _) = block_with_spending_transaction()?;
        let funding_txid = block.txs[0].txid();
        let coinbase_at = position_of_transaction(&block, 0)?;
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![
                scan_response(
                    ColumnFamily::Funding,
                    ScriptHashRow::scan_prefix(scripthash),
                    vec![history_row(
                        scripthash,
                        0,
                        &[(funding_txid, coinbase_at, ScriptHistoryOccurrence::FUNDING)],
                    )],
                    true,
                ),
                scan_response(
                    ColumnFamily::Spending,
                    SpendingPrefixRow::scan_prefix(&outpoint),
                    Vec::new(),
                    false,
                ),
            ],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        let snapshot = fixture.engine.history_snapshot(scripthash)?;
        assert_eq!(
            snapshot.history.len(),
            1,
            "the occurrence family owns history"
        );
        assert_eq!(snapshot.funding.len(), 1);
        assert_eq!(snapshot.funding[0].txid, funding_txid);
        assert!(
            matches!(
                fixture.engine.spender(outpoint),
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::PrefixScanTruncated
                ))
            ),
            "the spender family is broken, so the summary cannot have consulted it"
        );
        Ok(())
    }

    #[test]
    fn live_prefix_scan_ignores_coins_paying_other_scripts()
    -> Result<(), crate::portable::TestError> {
        let (block, _, scripthash, _) = block_with_spending_transaction()?;
        let real = OutPoint {
            txid: block.txs[0].txid(),
            vout: 0,
        };
        let foreign = OutPoint {
            txid: block.txs[1].txid(),
            vout: 0,
        };
        let real_txout = block.txs[0].outputs[0].clone();
        let foreign_txout = block.txs[1].outputs[0].clone();
        let foreign_scripthash = ScriptHash::new(&foreign_txout.script_pubkey);
        let real_txid = real.txid;
        let expected_value = real_txout.value.to_sat();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::ScriptLive,
                ScriptHashRow::scan_prefix(scripthash),
                vec![
                    (
                        ScriptLiveRow::new(scripthash, &foreign).as_bytes().to_vec(),
                        crate::types::ScriptLiveCoin::new(foreign_scripthash, 9, 0, false)
                            .encode_value()?,
                    ),
                    (
                        ScriptLiveRow::new(scripthash, &real).as_bytes().to_vec(),
                        crate::types::ScriptLiveCoin::new(scripthash, expected_value, 0, true)
                            .encode_value()?,
                    ),
                ],
                true,
            )],
            watermark: None,
            extra_blocks: Vec::new(),
        })?;

        let unspent = fixture.engine.unspent_outputs(scripthash)?;
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].txid, real_txid);
        assert_eq!(unspent[0].vout, 0);
        assert_eq!(unspent[0].height, 0);
        assert_eq!(unspent[0].value, expected_value);
        Ok(())
    }

    #[test]
    fn confirmed_history_orders_funding_rows_by_height_then_txid()
    -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let (genesis, chain, scripthash) = paying_chain()?;
        let mut funded: Vec<(u32, Txid)> = vec![(0, genesis.txs[0].txid())];
        for tx in &chain[1].txs {
            funded.push((2, tx.txid()));
        }
        for tx in &chain[0].txs {
            funded.push((1, tx.txid()));
        }
        funded.sort();
        let mut rows = Vec::new();
        for (height, txid) in &funded {
            let block = match height {
                0 => &genesis,
                1 => &chain[0],
                _ => &chain[1],
            };
            let index = block
                .txs
                .iter()
                .position(|candidate| candidate.txid() == *txid)
                .ok_or("funded transaction belongs to its block")?;
            rows.push(history_row(
                scripthash,
                *height,
                &[(
                    *txid,
                    position_of_transaction(block, index)?,
                    ScriptHistoryOccurrence::FUNDING,
                )],
            ));
        }
        let fixture = QueryFixture::new(FixtureConfig {
            block: genesis,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                rows,
                true,
            )],
            watermark: None,
            extra_blocks: chain,
        })?;

        let history = fixture.engine.confirmed_history(scripthash)?;
        assert_eq!(history.len(), funded.len());
        for (record, (height, txid)) in history.iter().zip(funded.iter()) {
            assert_eq!(record.height, *height);
            assert_eq!(record.txid, *txid);
        }
        let snapshot = fixture.engine.history_snapshot(scripthash)?;
        assert_eq!(snapshot.funding.len(), funded.len());
        for (record, (height, txid)) in snapshot.funding.iter().zip(funded.iter()) {
            assert_eq!(record.height, *height);
            assert_eq!(record.txid, *txid);
            assert_eq!(record.vout, 0);
        }
        Ok(())
    }

    #[test]
    fn unspent_outputs_orders_live_rows_by_height_then_txid()
    -> Result<(), crate::portable::TestError> {
        let (genesis, chain, scripthash) = paying_chain()?;
        let coin_value = genesis.txs[0].outputs[0].value.to_sat();
        let mut coins: Vec<(u32, OutPoint, TxOut)> = Vec::new();
        for tx in &chain[1].txs {
            coins.push((2, OutPoint::new(tx.txid(), 0), tx.outputs[0].clone()));
        }
        coins.push((
            0,
            OutPoint::new(genesis.txs[0].txid(), 0),
            genesis.txs[0].outputs[0].clone(),
        ));
        for tx in &chain[0].txs {
            coins.push((1, OutPoint::new(tx.txid(), 0), tx.outputs[0].clone()));
        }
        let rows = coins
        .iter()
        .map(|(height, outpoint, txout)| -> Result<(Vec<u8>, Vec<u8>), crate::types::ScriptLiveValueError> {
            Ok((
                ScriptLiveRow::new(scripthash, outpoint).as_bytes().to_vec(),
                crate::types::ScriptLiveCoin::new(
                    scripthash,
                    txout.value.to_sat(),
                    *height,
                    false,
                )
                .encode_value()?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
        let mut expected: Vec<(u32, Txid, u32)> = coins
            .iter()
            .map(|(height, outpoint, _)| (*height, outpoint.txid, outpoint.vout))
            .collect();
        expected.sort();
        let fixture = QueryFixture::new(FixtureConfig {
            block: genesis,
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::ScriptLive,
                ScriptHashRow::scan_prefix(scripthash),
                rows,
                true,
            )],
            watermark: None,
            extra_blocks: chain,
        })?;

        let unspent = fixture.engine.unspent_outputs(scripthash)?;
        assert_eq!(
            fixture
                .engine
                .with_scripthash_limit(0)
                .unspent_outputs(scripthash),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::ScriptHashLimitExceeded { limit: 0 }
            ))
        );
        assert_eq!(unspent.len(), expected.len());
        for (record, (height, txid, vout)) in unspent.iter().zip(expected.iter()) {
            assert_eq!(record.height, *height);
            assert_eq!(record.txid, *txid);
            assert_eq!(record.vout, *vout);
            assert_eq!(record.value, coin_value);
        }
        Ok(())
    }

    #[test]
    fn confirmed_history_filters_a_shared_prefix_by_exact_script()
    -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let (genesis, chain, scripthash) = paying_chain()?;
        let mut other_bytes = scripthash.to_byte_array();
        other_bytes[31] ^= 0xAA;
        let other = ScriptHash::from_byte_array(other_bytes);
        assert_eq!(
            scripthash.prefix(),
            other.prefix(),
            "the fixture must share the scan prefix"
        );
        let rows = (0..=2_u32)
            .map(|height| {
                history_row(
                    scripthash,
                    height,
                    &[(
                        genesis.txs[0].txid(),
                        TxPosition::new(1 + height, 10),
                        ScriptHistoryOccurrence::FUNDING,
                    )],
                )
            })
            .collect::<Vec<_>>();
        let fixture = QueryFixture::new(FixtureConfig {
            block: genesis,
            retain_body: false,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                rows,
                true,
            )],
            watermark: None,
            extra_blocks: chain,
        })?;

        let history = fixture.engine.confirmed_history(other)?;
        assert_eq!(
            history.len(),
            0,
            "another script that shares the prefix is never served"
        );
        Ok(())
    }

    // IDX-03
    #[test]
    fn history_limit_counts_occurrences_not_heights() -> Result<(), crate::portable::TestError> {
        use crate::types::ScriptHistoryOccurrence;
        let (genesis, chain, scripthash) = paying_chain()?;
        let txid = genesis.txs[0].txid();
        let occurrences = (0..3_u32)
            .map(|index| {
                (
                    txid,
                    TxPosition::new(index, 10),
                    ScriptHistoryOccurrence::SPENDING,
                )
            })
            .collect::<Vec<_>>();
        let rows = vec![history_row(scripthash, 0, &occurrences)];
        let fixture = QueryFixture::new(FixtureConfig {
            block: genesis,
            retain_body: false,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                rows,
                true,
            )],
            watermark: None,
            extra_blocks: chain,
        })?;

        assert_eq!(
            fixture
                .engine
                .clone()
                .with_scripthash_limit(2)
                .confirmed_history(scripthash),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::ScriptHashLimitExceeded { limit: 2 }
            )),
            "three occurrences in one height exceed a two-candidate allowance"
        );
        assert_eq!(
            fixture.engine.confirmed_history(scripthash)?.len(),
            1,
            "the same row deduplicates to one transaction record"
        );
        Ok(())
    }

    #[derive(Clone)]
    struct HistoricalSnapshot {
        tx_watermark: Option<IndexWatermark>,
        sh_watermark: Option<IndexWatermark>,
        tx_floor: u32,
        sh_floor: u32,
        scans: Vec<ScanResponse>,
    }

    impl HistoricalSnapshot {
        fn scan_for(&self, cf: ColumnFamily, prefix: &[u8]) -> PrefixScan {
            self.scans
                .iter()
                .find(|response| response.cf == cf && response.prefix == prefix)
                .map_or(
                    PrefixScan {
                        rows: Vec::new(),
                        complete: true,
                    },
                    |response| response.scan.clone(),
                )
        }

        fn typed_scan(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<TxIndexScan, IndexError> {
            let scan = self.scan_for(cf, prefix);
            let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
                total.saturating_add(key.len()).saturating_add(value.len())
            });
            let mut rows = Vec::with_capacity(scan.rows.len());
            for (key, value) in scan.rows {
                if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                    return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
                }
                let prefix_bytes: [u8; 8] = key[..crate::types::HASH_PREFIX_LEN]
                    .try_into()
                    .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
                let height_bytes: [u8; 4] = key
                    [crate::types::HASH_PREFIX_LEN..crate::HASH_PREFIX_ROW_SIZE]
                    .try_into()
                    .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
                rows.push(TxIndexScanRow {
                    row: HashPrefixRow {
                        prefix: prefix_bytes,
                        height: height_bytes,
                    },
                    value,
                });
            }
            Ok(TxIndexScan {
                rows,
                encoded_bytes,
                complete: scan.complete,
            })
        }
    }

    impl TxIndexSnapshot for HistoricalSnapshot {
        fn capability_watermark(
            &self,
            capability: IndexCapability,
        ) -> Result<Option<IndexWatermark>, IndexError> {
            match capability {
                IndexCapability::TxLookup => Ok(self.tx_watermark),
                IndexCapability::ScriptHistory => Ok(self.sh_watermark),
                _ => Ok(None),
            }
        }

        fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
            match capability {
                IndexCapability::TxLookup => Ok(self.tx_floor),
                IndexCapability::ScriptHistory => Ok(self.sh_floor),
                _ => Ok(0),
            }
        }

        fn tx_lookup_page(
            &self,
            start_after: Option<&[u8]>,
            limit: PrefixScanLimit,
        ) -> Result<crate::TxIndexPage, IndexError> {
            fake_family_page(&self.scans, ColumnFamily::TxConfirmed, start_after, limit)
        }

        fn transaction_rows(
            &self,
            txid: &Txid,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            self.typed_scan(ColumnFamily::TxConfirmed, &TxidRow::scan_prefix(txid))
        }

        fn funding_transaction_rows(
            &self,
            _txid: &Txid,
            _limit: PrefixScanLimit,
        ) -> Result<crate::FundingTransactionScan, IndexError> {
            Ok(crate::FundingTransactionScan {
                rows: Vec::new(),
                examined_rows: 0,
                encoded_bytes: 0,
                complete: true,
            })
        }

        fn funding_rows(
            &self,
            scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            let mut scan = self.typed_scan(
                ColumnFamily::Funding,
                &ScriptHashRow::scan_prefix(scripthash),
            )?;
            for row in &mut scan.rows {
                row.row.height = crate::types::encode_height(!u32::from_be_bytes(row.row.height));
            }
            Ok(scan)
        }

        fn funding_rows_from(
            &self,
            scripthash: ScriptHash,
            start_height: u32,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            let mut scan = self.funding_rows(scripthash, limit)?;
            scan.rows.retain(|row| row.row.height() <= start_height);
            Ok(scan)
        }

        fn spending_rows(
            &self,
            outpoint: &OutPoint,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            self.typed_scan(
                ColumnFamily::Spending,
                &SpendingPrefixRow::scan_prefix(outpoint),
            )
        }

        fn live_rows(
            &self,
            _scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<crate::ScriptLiveScan, IndexError> {
            Ok(crate::ScriptLiveScan {
                rows: Vec::new(),
                coins: Vec::new(),
                encoded_bytes: 0,
                complete: true,
            })
        }
    }

    struct HistoricalReader {
        snapshot: HistoricalSnapshot,
    }

    impl IndexReader for HistoricalReader {
        fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
            Ok(Box::new(self.snapshot.clone()))
        }
    }

    struct SnapshotCountingReader {
        initial: HistoricalSnapshot,
        rewritten: HistoricalSnapshot,
        calls: AtomicUsize,
    }

    impl IndexReader for SnapshotCountingReader {
        fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Box::new(self.initial.clone()))
            } else {
                Ok(Box::new(self.rewritten.clone()))
            }
        }
    }

    struct ResetReader {
        state: Arc<ParkMutex<HistoricalSnapshot>>,
    }

    impl IndexReader for ResetReader {
        fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
            Ok(Box::new(self.state.lock().clone()))
        }
    }

    struct MovingBody {
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        full_reads: AtomicUsize,
        on_first_read: ParkMutex<Option<Box<dyn Fn() + Send>>>,
    }

    impl MovingBody {
        fn new(
            bodies: Vec<(u32, BlockHash, Vec<u8>)>,
            on_first_read: Option<Box<dyn Fn() + Send>>,
        ) -> Self {
            Self {
                bodies,
                full_reads: AtomicUsize::new(0),
                on_first_read: ParkMutex::new(on_first_read),
            }
        }

        fn fire_once(&self) {
            let taken = self.on_first_read.lock().take();
            if let Some(callback) = taken {
                callback();
            }
        }

        fn lookup(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            self.bodies
                .iter()
                .find(|(h, hh, _)| *h == height && *hh == hash)
                .map(|(_, _, body)| body.clone())
        }
    }

    impl BlockBodySource for MovingBody {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
            self.fire_once();
            let hit = self.lookup(height, hash);
            if hit.is_some() {
                self.full_reads.fetch_add(1, Ordering::Relaxed);
            }
            Ok(hit)
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: BlockHash,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            self.fire_once();
            let (_, _, body) = self
                .bodies
                .iter()
                .find(|(h, hh, _)| *h == height && *hh == hash)?;
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            body.get(start..end).map(<[u8]>::to_vec)
        }
    }

    struct HistoricalFixture {
        engine: DerivedIndexQueryEngine,
        runtime: Arc<DerivedIndexRuntime>,
    }

    fn tip_snapshot_for(
        tree: &BlockTree,
        tip_id: NodeId,
    ) -> Result<TipSnapshot, crate::portable::TestError> {
        let node = tree.node(tip_id)?;
        Ok(TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        })
    }

    fn watermark_for(
        tree: &BlockTree,
        node_id: NodeId,
    ) -> Result<IndexWatermark, crate::portable::TestError> {
        let node = tree.node(node_id)?;
        Ok(IndexWatermark {
            height: node.height,
            hash: *node.hash.as_byte_array(),
        })
    }

    struct HistoricalConfig {
        tx_watermark: Option<IndexWatermark>,
        sh_watermark: Option<IndexWatermark>,
        tx_floor: u32,
        sh_floor: u32,
        scans: Vec<ScanResponse>,
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        on_first_read: Option<Box<dyn Fn() + Send>>,
        enabled: IndexCapabilities,
    }

    impl HistoricalFixture {
        fn build(
            tree: BlockTree,
            tip_id: NodeId,
            config: HistoricalConfig,
        ) -> Result<(Self, Arc<MovingBody>), crate::portable::TestError> {
            let HistoricalConfig {
                tx_watermark,
                sh_watermark,
                tx_floor,
                sh_floor,
                scans,
                bodies,
                on_first_read,
                enabled,
            } = config;
            let tip = tip_snapshot_for(&tree, tip_id)?;
            let tree = Arc::new(RwLock::new(tree));
            let tip_cell = Arc::new(ArcSwapOption::empty());
            tip_cell.store(Some(Arc::new(tip)));
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
            let runtime = DerivedIndexRuntime::new(wake_tx);
            let reader = Arc::new(HistoricalReader {
                snapshot: HistoricalSnapshot {
                    tx_watermark,
                    sh_watermark,
                    tx_floor,
                    sh_floor,
                    scans,
                },
            });
            let body = Arc::new(MovingBody::new(bodies, on_first_read));
            let body_source: Option<Arc<dyn BlockBodySource>> = Some(body.clone());
            let engine = DerivedIndexQueryEngine::new(
                Arc::clone(&runtime),
                reader,
                bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&tree)),
                bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&tip_cell)),
                body_source,
                QueryEngineLive {
                    enabled,
                    generation: Arc::new(Generation::new(1)),
                    historical_verified: None,
                    chain_transition: None,
                },
            );
            let fixture = Self { engine, runtime };
            Ok((fixture, body))
        }
    }

    #[test]
    fn historical_extension_during_read_keeps_same_anchor() -> Result<(), crate::portable::TestError>
    {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let tip_block = child_block(&block, vec![block.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let tip_id = tree.insert_header(tip_block.header, NodeStatus::HeaderValid)?;
        let genesis_watermark = watermark_for(&tree, genesis_id)?;
        let tip_snapshot = tip_snapshot_for(&tree, tip_id)?;
        let extension_block = child_block(&tip_block, vec![tip_block.txs[0].clone()])?;
        let extension_id = tree.insert_header(extension_block.header, NodeStatus::HeaderValid)?;
        let extension_tip = tip_snapshot_for(&tree, extension_id)?;
        let bodies = vec![(0, block.block_hash(), consensus_bytes(&block))];
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip_snapshot)));
        let tip_cell_clone = Arc::clone(&tip_cell);
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let runtime_clone = Arc::clone(&runtime);
        let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
            tip_cell_clone.store(Some(Arc::new(extension_tip.clone())));
            runtime_clone.wake();
        }));
        let body = Arc::new(MovingBody::new(bodies, on_read));
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(genesis_watermark),
                sh_watermark: Some(genesis_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            Arc::clone(&runtime),
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let at = engine.transaction_at_answer(&txid)?;
        assert_eq!(at.coverage.height, 0);
        assert_eq!(at.coverage.floor, 0);
        assert!(at.value.is_some());
        Ok(())
    }

    #[test]
    fn historical_wake_without_tip_move_stays_valid_for_strict_reads()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let genesis_watermark = watermark_for(&tree, genesis_id)?;
        let tip_snapshot = tip_snapshot_for(&tree, genesis_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip_snapshot)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let runtime_clone = Arc::clone(&runtime);
        let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || runtime_clone.wake()));
        let body = Arc::new(MovingBody::new(
            vec![(0, block.block_hash(), consensus_bytes(&block))],
            on_read,
        ));
        let reader: Arc<dyn IndexReader> = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(genesis_watermark),
                sh_watermark: Some(genesis_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let strict_reader: Arc<dyn IndexReader> = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark: genesis_watermark,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let tree_handle = Arc::new(RwLock::new(tree));
        let historical = DerivedIndexQueryEngine::new(
            Arc::clone(&runtime),
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&tree_handle)),
            bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&tip_cell)),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let at = historical.transaction_at_answer(&txid)?;
        assert_eq!(at.coverage.height, 0);
        assert!(at.value.is_some());
        let runtime_clone = Arc::clone(&runtime);
        let strict_body = Arc::new(MovingBody::new(
            vec![(0, block.block_hash(), consensus_bytes(&block))],
            Some(Box::new(move || runtime_clone.wake())),
        ));
        let strict = DerivedIndexQueryEngine::new(
            runtime,
            strict_reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(tree_handle),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(strict_body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let at = strict.transaction(&txid)?;
        assert!(at.is_some());
        Ok(())
    }

    #[test]
    fn historical_reorg_above_anchor_stays_valid() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let txid = genesis.txs[0].txid();
        let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let side_child = {
            let mut tx = genesis.txs[0].clone();
            tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
            child_block(&genesis, vec![tx])?
        };
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
        let side_id = tree.insert_header(side_child.header, NodeStatus::HeaderValid)?;
        let genesis_watermark = watermark_for(&tree, genesis_id)?;
        let main_tip = tip_snapshot_for(&tree, main_id)?;
        let side_tip = tip_snapshot_for(&tree, side_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(main_tip)));
        let tip_cell_clone = Arc::clone(&tip_cell);
        let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
            tip_cell_clone.store(Some(Arc::new(side_tip.clone())));
        }));
        let body = Arc::new(MovingBody::new(
            vec![(0, genesis.block_hash(), consensus_bytes(&genesis))],
            on_read,
        ));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(genesis_watermark),
                sh_watermark: Some(genesis_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let at = engine.transaction_at_answer(&txid)?;
        assert_eq!(at.coverage.height, 0);
        assert!(at.value.is_some());
        Ok(())
    }

    #[test]
    fn historical_reset_completing_after_snapshot_stays_valid()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let watermark = watermark_for(&tree, tip_id)?;
        let tip_snapshot = tip_snapshot_for(&tree, tip_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip_snapshot)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let shared_state = Arc::new(ParkMutex::new(HistoricalSnapshot {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
        }));
        let reset_state = Arc::clone(&shared_state);
        let runtime_clone = Arc::clone(&runtime);
        let body = Arc::new(MovingBody::new(
            vec![(0, block.block_hash(), consensus_bytes(&block))],
            Some(Box::new(move || {
                reset_state.lock().tx_watermark = None;
                reset_state.lock().sh_watermark = None;
                reset_state.lock().tx_watermark = Some(watermark);
                reset_state.lock().sh_watermark = Some(watermark);
                runtime_clone.wake();
            })),
        ));
        let reader: Arc<dyn IndexReader> = Arc::new(ResetReader {
            state: shared_state,
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let at = engine.transaction_at_answer(&txid)?;
        assert_eq!(at.coverage.height, 0);
        assert_eq!(at.coverage.floor, 0);
        assert!(at.value.is_some());
        Ok(())
    }

    #[test]
    fn historical_reorg_below_anchor_stays_valid() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let txid = genesis.txs[0].txid();
        let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let main_grandchild = child_block(&main_child, vec![main_child.txs[0].clone()])?;
        let side_child = {
            let mut tx = genesis.txs[0].clone();
            tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
            child_block(&genesis, vec![tx])?
        };
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
        let main_tip_id = tree.insert_header(main_grandchild.header, NodeStatus::HeaderValid)?;
        let side_id = tree.insert_header(side_child.header, NodeStatus::HeaderValid)?;
        let main_watermark = watermark_for(&tree, main_tip_id)?;
        let main_tip = tip_snapshot_for(&tree, main_tip_id)?;
        let side_tip = tip_snapshot_for(&tree, side_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(main_tip)));
        let tip_cell_clone = Arc::clone(&tip_cell);
        let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
            tip_cell_clone.store(Some(Arc::new(side_tip.clone())));
        }));
        let body = Arc::new(MovingBody::new(
            vec![
                (1, main_child.block_hash(), consensus_bytes(&main_child)),
                (
                    2,
                    main_grandchild.block_hash(),
                    consensus_bytes(&main_grandchild),
                ),
            ],
            on_read,
        ));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(main_watermark),
                sh_watermark: Some(main_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![
                        (TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0]),
                        (TxidRow::row(&txid, 2).to_db_row().to_vec(), vec![0]),
                    ],
                    true,
                )],
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let at = engine.transaction_at_answer(&txid)?;
        assert!(at.value.is_some());
        assert_eq!(at.coverage.height, 2);
        Ok(())
    }

    // QRY-01, QRY-02, QRY-03, PRJ-06
    #[test]
    fn transaction_block_retains_membership_across_reorg_and_aba()
    -> Result<(), crate::portable::TestError> {
        for restore in [false, true] {
            let genesis = Network::Regtest.genesis_block();
            let original = child_block(&genesis, vec![genesis.txs[0].clone()])?;
            let mut other_tx = genesis.txs[0].clone();
            other_tx.outputs[0].value = Amount::from_sat(123);
            let replacement = child_block(&genesis, vec![other_tx])?;
            let txid = original.txs[0].txid();
            assert!(original.txs.iter().any(|tx| tx.txid() == txid));
            assert!(replacement.txs.iter().all(|tx| tx.txid() != txid));
            let mut tree = BlockTree::new();
            tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
            let original_id = tree.insert_header(original.header, NodeStatus::HeaderValid)?;
            let replacement_id = tree.insert_header(replacement.header, NodeStatus::HeaderValid)?;
            let original_tip = tip_snapshot_for(&tree, original_id)?;
            let replacement_tip = tip_snapshot_for(&tree, replacement_id)?;
            let watermark = watermark_for(&tree, original_id)?;
            let tip_cell = Arc::new(ArcSwapOption::empty());
            tip_cell.store(Some(Arc::new(original_tip.clone())));
            let moved = Arc::new(AtomicUsize::new(0));
            let on_read: Option<Box<dyn Fn() + Send>> = {
                let tips = Arc::clone(&tip_cell);
                let moved = Arc::clone(&moved);
                Some(Box::new(move || {
                    tips.store(Some(Arc::new(replacement_tip.clone())));
                    moved.fetch_add(1, Ordering::SeqCst);
                    if restore {
                        tips.store(Some(Arc::new(original_tip.clone())));
                        moved.fetch_add(1, Ordering::SeqCst);
                    }
                }))
            };
            let body = Arc::new(MovingBody::new(
                vec![(1, original.block_hash(), consensus_bytes(&original))],
                on_read,
            ));
            let reader = Arc::new(QueryReader {
                snapshot: QuerySnapshot {
                    watermark,
                    scans: vec![scan_response(
                        ColumnFamily::TxConfirmed,
                        TxidRow::scan_prefix(&txid),
                        vec![(TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0])],
                        true,
                    )],
                },
            });
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
            let engine = DerivedIndexQueryEngine::new(
                DerivedIndexRuntime::new(wake_tx),
                reader,
                bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
                bitcoin_rs_execution::chain::TipReader::new(tip_cell),
                Some(body),
                QueryEngineLive {
                    enabled: IndexCapabilities::ALL,
                    generation: Arc::new(Generation::new(1)),
                    historical_verified: None,
                    chain_transition: None,
                },
            );
            let (transaction, identity) = engine
                .transaction_block(&txid)?
                .ok_or_else(|| std::io::Error::other("captured occurrence missing"))?;
            assert_eq!(moved.load(Ordering::SeqCst), if restore { 2 } else { 1 });
            assert_eq!(identity.height, 1);
            assert_eq!(identity.hash, Hash256::from(original.block_hash()));
            assert_eq!(transaction, original.txs[0]);
            assert_ne!(identity.hash, Hash256::from(replacement.block_hash()));
        }
        Ok(())
    }

    #[test]
    fn historical_unknown_watermark_hash_refuses_prefix() -> Result<(), crate::portable::TestError>
    {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let tip = tip_snapshot_for(&tree, tip_id)?;
        let unknown = IndexWatermark {
            height: 0,
            hash: [0x77; 32],
        };
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(unknown),
                sh_watermark: Some(unknown),
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            None,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        assert!(matches!(
            engine.transaction_at_answer(&txid),
            Err(TxQueryError::Retry(RetryReason::PendingCapabilityCoverage(
                IndexCapability::TxLookup
            )))
        ));
        Ok(())
    }

    #[test]
    fn historical_stale_watermark_refuses_prefix() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let stale_child = {
            let mut tx = genesis.txs[0].clone();
            tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(5));
            child_block(&genesis, vec![tx])?
        };
        let stale_txid = stale_child.txs[0].txid();
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
        let stale_id = tree.insert_header(stale_child.header, NodeStatus::HeaderValid)?;
        let stale_watermark = watermark_for(&tree, stale_id)?;
        let main_tip = tip_snapshot_for(&tree, main_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(main_tip)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let stale_prefix = TxidRow::scan_prefix(&stale_txid);
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(stale_watermark),
                sh_watermark: Some(stale_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    stale_prefix,
                    vec![(TxidRow::row(&stale_txid, 1).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(Arc::new(MovingBody::new(
                vec![(1, main_child.block_hash(), consensus_bytes(&main_child))],
                None,
            ))),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        assert!(matches!(
            engine.transaction_at_answer(&stale_txid),
            Err(TxQueryError::Retry(RetryReason::PendingCapabilityCoverage(
                IndexCapability::TxLookup
            )))
        ));
        Ok(())
    }

    // SYNC-05
    #[test]
    fn historical_off_chain_watermark_refuses_prefix_reads()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let stale_child = {
            let mut tx = genesis.txs[0].clone();
            tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(5));
            child_block(&genesis, vec![tx])?
        };
        let stale_txid = stale_child.txs[0].txid();
        let script = ScriptHash::from_script_bytes(&[0x51]);
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
        let stale_id = tree.insert_header(stale_child.header, NodeStatus::HeaderValid)?;
        let stale_watermark = watermark_for(&tree, stale_id)?;
        let main_tip = tip_snapshot_for(&tree, main_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(main_tip)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let stale_prefix = TxidRow::scan_prefix(&stale_txid);
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(stale_watermark),
                sh_watermark: Some(stale_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    stale_prefix,
                    vec![(TxidRow::row(&stale_txid, 1).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(Arc::new(MovingBody::new(
                vec![
                    (1, main_child.block_hash(), consensus_bytes(&main_child)),
                    (1, stale_child.block_hash(), consensus_bytes(&stale_child)),
                ],
                None,
            ))),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        assert!(matches!(
            engine.transaction_at_answer(&stale_txid),
            Err(TxQueryError::Retry(RetryReason::PendingCapabilityCoverage(
                IndexCapability::TxLookup
            )))
        ));
        assert!(matches!(
            engine.script_history_at_answer(script),
            Err(TxQueryError::Retry(RetryReason::PendingCapabilityCoverage(
                IndexCapability::ScriptHistory
            )))
        ));
        Ok(())
    }

    // SYNC-01
    #[test]
    fn assumed_history_view_reports_verified_frontier() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let txid = child.txs[0].txid();
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let tip = tip_snapshot_for(&tree, child_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let frontier = Arc::new(RwLock::new(None));
        let reader_frontier = Arc::clone(&frontier);
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let watermark = watermark_for(&tree, child_id)?;
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(watermark),
                sh_watermark: Some(watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(Arc::new(MovingBody::new(
                vec![(1, child.block_hash(), consensus_bytes(&child))],
                None,
            ))),
            QueryEngineLive {
                enabled: IndexCapabilities::TX_LOOKUP,
                generation: Arc::new(Generation::new(1)),
                historical_verified: Some(Arc::new(move || Ok(*reader_frontier.read()))),
                chain_transition: None,
            },
        );
        let verified_hash: Hash256 = genesis.block_hash().into();
        *frontier.write() = Some((0, verified_hash));
        let assumed = engine.transaction_at_answer(&txid)?;
        assert_eq!(
            assumed.verification_state,
            crate::query_api::VerificationState::AssumedHistory {
                verified_height: 0,
                verified_hash,
            }
        );
        *frontier.write() = Some((1, child.block_hash().into()));
        let caught_up = engine.transaction_at_answer(&txid)?;
        assert_eq!(
            caught_up.verification_state,
            crate::query_api::VerificationState::ChainVerified
        );
        *frontier.write() = None;
        let verified = engine.transaction_at_answer(&txid)?;
        assert_eq!(
            verified.verification_state,
            crate::query_api::VerificationState::ChainVerified
        );
        Ok(())
    }

    // IDX-12
    #[test]
    fn historical_tx_positive_floor_scopes_absence_and_rejects_anchor_below_floor()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let txid = genesis.txs[0].txid();
        let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let tip_watermark = watermark_for(&tree, tip_id)?;
        let (fixture, _) = HistoricalFixture::build(
            tree,
            tip_id,
            HistoricalConfig {
                tx_watermark: Some(tip_watermark),
                sh_watermark: Some(tip_watermark),
                tx_floor: 1,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: vec![
                    (0, genesis.block_hash(), consensus_bytes(&genesis)),
                    (1, child.block_hash(), consensus_bytes(&child)),
                ],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        let at = fixture.engine.transaction_at_answer(&txid)?;
        assert_eq!(at.coverage.floor, 1);
        assert_eq!(at.coverage.height, 1);
        assert_eq!(at.value, None);
        let mut deep_tree = BlockTree::new();
        let deep_genesis_id = deep_tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let floor_watermark = IndexWatermark {
            height: 0,
            hash: *deep_tree.node(deep_genesis_id)?.hash.as_byte_array(),
        };
        let (floor_fixture, _) = HistoricalFixture::build(
            deep_tree,
            deep_genesis_id,
            HistoricalConfig {
                tx_watermark: Some(floor_watermark),
                sh_watermark: Some(floor_watermark),
                tx_floor: 5,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        assert!(matches!(
            floor_fixture.engine.transaction_at_answer(&txid),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: 5
                }
            ))
        ));
        Ok(())
    }

    #[test]
    fn historical_full_history_positive_floor_is_unproven() -> Result<(), crate::portable::TestError>
    {
        let (block, _, scripthash, _) = block_with_spending_transaction()?;
        let child = child_block(&block, vec![block.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let watermark = watermark_for(&tree, tip_id)?;
        let (fixture, _) = HistoricalFixture::build(
            tree,
            tip_id,
            HistoricalConfig {
                tx_watermark: Some(watermark),
                sh_watermark: Some(watermark),
                tx_floor: 0,
                sh_floor: 1,
                scans: vec![scan_response(
                    ColumnFamily::Funding,
                    ScriptHashRow::scan_prefix(scripthash),
                    vec![(
                        ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                        vec![0],
                    )],
                    true,
                )],
                bodies: vec![
                    (0, block.block_hash(), consensus_bytes(&block)),
                    (1, child.block_hash(), consensus_bytes(&child)),
                ],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        assert!(matches!(
            fixture.engine.script_history_at_answer(scripthash),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven { floor: 1 }
            ))
        ));
        Ok(())
    }

    #[test]
    fn historical_standalone_spender_scoped_none_above_floor()
    -> Result<(), crate::portable::TestError> {
        let (block, outpoint, _, _) = block_with_spending_transaction()?;
        let child = child_block(&block, vec![block.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let watermark = watermark_for(&tree, tip_id)?;
        let (fixture, _) = HistoricalFixture::build(
            tree,
            tip_id,
            HistoricalConfig {
                tx_watermark: Some(watermark),
                sh_watermark: Some(watermark),
                tx_floor: 0,
                sh_floor: 1,
                scans: vec![scan_response(
                    ColumnFamily::Spending,
                    SpendingPrefixRow::scan_prefix(&outpoint),
                    vec![(
                        SpendingPrefixRow::row(&outpoint, 1).to_db_row().to_vec(),
                        vec![0],
                    )],
                    true,
                )],
                bodies: vec![
                    (0, block.block_hash(), consensus_bytes(&block)),
                    (1, child.block_hash(), consensus_bytes(&child)),
                ],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        let at = fixture.engine.spender_at_answer(outpoint)?;
        assert_eq!(at.coverage.floor, 1);
        assert_eq!(at.coverage.height, 1);
        assert_eq!(at.value, None);
        Ok(())
    }

    // IDX-12
    #[test]
    fn spender_at_prefix_preserves_spend_of_unindexed_below_floor_creation()
    -> Result<(), crate::portable::TestError> {
        struct FundingCoin {
            outpoint: OutPoint,
            output: TxOut,
        }

        impl crate::SpentCoins for FundingCoin {
            fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<crate::SpentCoin<'_>> {
                (*txid == *self.outpoint.txid.as_bytes() && vout == self.outpoint.vout).then_some(
                    crate::SpentCoin {
                        script: self.output.script_pubkey.as_bytes(),
                        value: self.output.value.to_sat(),
                        height: 0,
                        coinbase: true,
                    },
                )
            }
        }

        let genesis = Network::Regtest.genesis_block();
        let (spending_fixture, outpoint, scripthash, _) = block_with_spending_transaction()?;
        let spending_tx = spending_fixture.txs[1].clone();
        assert_eq!(spending_tx.inputs[0].previous_output, outpoint);
        let mined = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        let child = child_block(&genesis, vec![mined.txs[0].clone(), spending_tx.clone()])?;
        let body_bytes = consensus_bytes(&child);
        let funding = FundingCoin {
            outpoint,
            output: genesis.txs[0].outputs[0].clone(),
        };
        let dir = tempfile::TempDir::new()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);
        let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1)?;
        writer.anchor_watermark(
            IndexCapabilities::HISTORICAL,
            IndexWatermark {
                height: 0,
                hash: *genesis.block_hash().as_bytes(),
            },
            1,
        )?;
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            1,
            *child.block_hash().as_bytes(),
            &body_bytes,
            &funding,
        )?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err("one covered block is admitted per batch".into());
        }
        writer.commit_forward(batch)?;

        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let tip = tip_snapshot_for(&tree, tip_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let body = Arc::new(MovingBody::new(
            vec![(1, child.block_hash(), body_bytes)],
            None,
        ));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let engine = Arc::new(DerivedIndexQueryEngine::new(
            DerivedIndexRuntime::new(wake_tx),
            Arc::new(crate::Indexer::new(Arc::clone(&store))),
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::HISTORICAL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        ));
        let adapter = DerivedIndexQueryAdapter::new(Arc::new(arc_swap::ArcSwap::from_pointee(
            DerivedIndexLifecycle::Serving(engine),
        )));
        let answer = adapter.spender_at_prefix(outpoint)?;
        assert_eq!(answer.coverage.floor, 1);
        assert_eq!(answer.coverage.height, 1);
        assert_eq!(
            answer
                .value
                .as_ref()
                .map(|record| (record.txid, record.height)),
            Some((spending_tx.txid(), 1)),
            "the covered canonical input must remain discoverable without its funding transaction"
        );
        let unrelated = adapter.spender_at_prefix(OutPoint::new(outpoint.txid, 1))?;
        assert_eq!(unrelated.coverage.floor, 1);
        assert_eq!(unrelated.value, None);
        assert_eq!(adapter.transaction_at_prefix(&outpoint.txid)?.value, None);
        assert!(matches!(
            adapter.script_history_at_prefix(scripthash),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven { floor: 1 }
            ))
        ));
        Ok(())
    }

    // IDX-12
    #[test]
    fn spender_at_prefix_distinguishes_recreated_outpoints_at_each_canonical_prefix()
    -> Result<(), crate::portable::TestError> {
        assert_recreated_outpoint_spenders_at_canonical_prefixes(
            IndexCapabilities::HISTORICAL,
            false,
        )
    }

    // IDX-12
    #[test]
    fn spender_at_prefix_distinguishes_recreated_outpoints_with_script_history_only()
    -> Result<(), crate::portable::TestError> {
        assert_recreated_outpoint_spenders_at_canonical_prefixes(
            IndexCapabilities::SCRIPT_HISTORY,
            false,
        )
    }

    // IDX-02, IDX-12
    #[test]
    fn spender_at_prefix_distinguishes_recreated_outpoints_with_pruned_creation_bodies()
    -> Result<(), crate::portable::TestError> {
        assert_recreated_outpoint_spenders_at_canonical_prefixes(
            IndexCapabilities::SCRIPT_HISTORY,
            true,
        )
    }

    fn assert_recreated_outpoint_spenders_at_canonical_prefixes(
        capabilities: IndexCapabilities,
        prune_creations: bool,
    ) -> Result<(), crate::portable::TestError> {
        struct FundingOccurrence<'a> {
            transaction: &'a Tx,
            height: u32,
        }

        impl crate::SpentCoins for FundingOccurrence<'_> {
            fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<crate::SpentCoin<'_>> {
                if txid != self.transaction.txid().as_bytes() {
                    return None;
                }
                let output = self.transaction.outputs.get(usize::try_from(vout).ok()?)?;
                Some(crate::SpentCoin {
                    script: output.script_pubkey.as_bytes(),
                    value: output.value.to_sat(),
                    height: self.height,
                    coinbase: true,
                })
            }
        }

        let genesis = Network::Regtest.genesis_block();
        let mut creation = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        let mut funding_tx = creation.txs[0].clone();
        funding_tx.outputs[0].value = Amount::from_sat(2_500_000_000);
        funding_tx.outputs.push(funding_tx.outputs[0].clone());
        creation = child_block(&genesis, vec![funding_tx.clone()])?;
        let outpoints = [
            OutPoint::new(funding_tx.txid(), 0),
            OutPoint::new(funding_tx.txid(), 1),
        ];
        let spend = |height: u32, vout: u8| Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoints[usize::from(vout)],
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000 + u64::from(height) + u64::from(vout)),
                script_pubkey: Script::new(),
            }],
        };
        let first_spends = [spend(3, 0), spend(3, 1)];
        let second_spends = [spend(5, 0), spend(5, 1)];
        let mut blocks = Vec::new();
        let mut parent = creation.clone();
        for height in 2..=5 {
            let mined = regtest_fixture::mined_regtest_child_at(parent.block_hash(), height)
                .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
            let transactions = match height {
                3 => vec![
                    mined.txs[0].clone(),
                    first_spends[0].clone(),
                    first_spends[1].clone(),
                ],
                4 => vec![funding_tx.clone()],
                5 => vec![
                    mined.txs[0].clone(),
                    second_spends[0].clone(),
                    second_spends[1].clone(),
                ],
                _ => vec![mined.txs[0].clone()],
            };
            let block = child_block(&parent, transactions)?;
            parent = block.clone();
            blocks.push((height, block));
        }
        let dir = tempfile::TempDir::new()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);
        let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1)?;
        writer.anchor_watermark(
            capabilities,
            IndexWatermark {
                height: 1,
                hash: *creation.block_hash().as_bytes(),
            },
            2,
        )?;
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        tree.insert_header(creation.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));
        let mut bodies = Vec::new();
        let mut answers = Vec::new();
        for (height, block) in blocks {
            let body_bytes = consensus_bytes(&block);
            let prepared = writer.prepare_block_with_spent_scripts(
                capabilities,
                height,
                *block.block_hash().as_bytes(),
                &body_bytes,
                &FundingOccurrence {
                    transaction: &funding_tx,
                    height: if height == 5 { 4 } else { 1 },
                },
            )?;
            let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            if batch.try_push(prepared).is_err() {
                return Err("one canonical block is admitted per batch".into());
            }
            writer.commit_forward(batch)?;
            if !prune_creations || height != 4 {
                bodies.push((height, block.block_hash(), body_bytes));
            }
            let tip_id = tree
                .write()
                .insert_header(block.header, NodeStatus::HeaderValid)?;
            if height < 3 {
                continue;
            }
            let tip = tip_snapshot_for(&tree.read(), tip_id)?;
            let tip_cell = Arc::new(ArcSwapOption::empty());
            tip_cell.store(Some(Arc::new(tip)));
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
            let engine = Arc::new(DerivedIndexQueryEngine::new(
                DerivedIndexRuntime::new(wake_tx),
                Arc::new(crate::Indexer::new(Arc::clone(&store))),
                bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&tree)),
                bitcoin_rs_execution::chain::TipReader::new(tip_cell),
                Some(Arc::new(MovingBody::new(bodies.clone(), None))),
                QueryEngineLive {
                    enabled: capabilities,
                    generation: Arc::new(Generation::new(1)),
                    historical_verified: None,
                    chain_transition: None,
                },
            ));
            let adapter = DerivedIndexQueryAdapter::new(Arc::new(arc_swap::ArcSwap::from_pointee(
                DerivedIndexLifecycle::Serving(engine),
            )));
            for (vout, outpoint) in outpoints.iter().enumerate() {
                let answer = adapter.spender_at_prefix(*outpoint)?;
                assert_eq!(answer.height, height);
                assert_eq!(answer.coverage.floor, 2);
                assert_eq!(answer.coverage.height, height);
                answers.push((
                    height,
                    vout,
                    answer.value.map(|record| (record.txid, record.height)),
                ));
            }
        }
        for (height, vout, actual) in answers {
            let expected = match height {
                3 => Some((first_spends[vout].txid(), 3)),
                4 => None,
                5 => Some((second_spends[vout].txid(), 5)),
                _ => return Err("only prefixes 3, 4, and 5 are queried".into()),
            };
            assert_eq!(actual, expected, "canonical prefix {height}, vout {vout}");
        }
        Ok(())
    }

    // IDX-12
    #[test]
    fn spender_at_prefix_finds_later_same_block_spend_with_script_history_only()
    -> Result<(), crate::portable::TestError> {
        struct AvailableInputs<'a> {
            genesis: &'a Tx,
            funding: &'a Tx,
        }

        impl crate::SpentCoins for AvailableInputs<'_> {
            fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<crate::SpentCoin<'_>> {
                let (transaction, height, coinbase) = if txid == self.genesis.txid().as_bytes() {
                    (self.genesis, 0, true)
                } else if txid == self.funding.txid().as_bytes() {
                    (self.funding, 1, false)
                } else {
                    return None;
                };
                let output = transaction.outputs.get(usize::try_from(vout).ok()?)?;
                Some(crate::SpentCoin {
                    script: output.script_pubkey.as_bytes(),
                    value: output.value.to_sat(),
                    height,
                    coinbase,
                })
            }
        }

        let genesis = Network::Regtest.genesis_block();
        let funding = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::new(),
                },
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: Script::new(),
                },
            ],
        };
        let outpoints = [
            OutPoint::new(funding.txid(), 0),
            OutPoint::new(funding.txid(), 1),
        ];
        let spending = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: outpoints
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(1_500),
                script_pubkey: Script::new(),
            }],
        };
        let mined = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        let child = child_block(
            &genesis,
            vec![mined.txs[0].clone(), funding.clone(), spending.clone()],
        )?;
        let body_bytes = consensus_bytes(&child);
        let dir = tempfile::TempDir::new()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);
        let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1)?;
        writer.anchor_watermark(
            IndexCapabilities::SCRIPT_HISTORY,
            IndexWatermark {
                height: 0,
                hash: *genesis.block_hash().as_bytes(),
            },
            1,
        )?;
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::SCRIPT_HISTORY,
            1,
            *child.block_hash().as_bytes(),
            &body_bytes,
            &AvailableInputs {
                genesis: &genesis.txs[0],
                funding: &funding,
            },
        )?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err("the same-block funding and spending body is admitted together".into());
        }
        writer.commit_forward(batch)?;
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let tip = tip_snapshot_for(&tree, tip_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let engine = Arc::new(DerivedIndexQueryEngine::new(
            DerivedIndexRuntime::new(wake_tx),
            Arc::new(crate::Indexer::new(Arc::clone(&store))),
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(Arc::new(MovingBody::new(
                vec![(1, child.block_hash(), body_bytes)],
                None,
            ))),
            QueryEngineLive {
                enabled: IndexCapabilities::SCRIPT_HISTORY,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        ));
        let adapter = DerivedIndexQueryAdapter::new(Arc::new(arc_swap::ArcSwap::from_pointee(
            DerivedIndexLifecycle::Serving(engine),
        )));
        for (vin, outpoint) in outpoints.iter().enumerate() {
            let answer = adapter.spender_at_prefix(*outpoint)?;
            assert_eq!(answer.height, 1);
            assert_eq!(answer.coverage.floor, 1);
            assert_eq!(answer.coverage.height, 1);
            assert_eq!(
                answer
                    .value
                    .map(|record| (record.txid, record.height, record.vin)),
                Some((spending.txid(), 1, u32::try_from(vin)?)),
            );
        }
        Ok(())
    }

    #[test]
    fn historical_mixed_cap_script_anchors_at_sh_watermark()
    -> Result<(), crate::portable::TestError> {
        let (genesis, chain, scripthash) = paying_chain()?;
        let mut script_tree = BlockTree::new();
        let mut script_tip_id =
            script_tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        for block in &chain {
            script_tip_id = script_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        }
        assert_eq!(script_tree.node(script_tip_id)?.height, 2);
        let script_middle_id = script_tree
            .node_at_height_from(script_tip_id, 1)
            .ok_or_else(|| std::io::Error::other("middle present"))?;
        let mut bodies = Vec::new();
        bodies.push((0, genesis.block_hash(), consensus_bytes(&genesis)));
        for (height, block) in [1u32, 2u32].iter().zip(chain.iter()) {
            bodies.push((*height, block.block_hash(), consensus_bytes(block)));
        }
        let funding_rows = {
            use crate::types::ScriptHistoryOccurrence;
            let mut rows = Vec::new();
            for (height, block) in std::iter::once((0_u32, &genesis))
                .chain([1_u32, 2_u32].into_iter().zip(chain.iter()))
            {
                for (index, tx) in block.txs.iter().enumerate() {
                    if ScriptHash::new(&tx.outputs[0].script_pubkey) != scripthash {
                        continue;
                    }
                    rows.push(history_row(
                        scripthash,
                        height,
                        &[(
                            tx.txid(),
                            position_of_transaction(block, index)?,
                            ScriptHistoryOccurrence::FUNDING,
                        )],
                    ));
                }
            }
            rows
        };
        let funding_scans = vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            funding_rows,
            true,
        )];
        let script_tx_watermark = watermark_for(&script_tree, script_tip_id)?;
        let script_sh_watermark = watermark_for(&script_tree, script_middle_id)?;
        let (script_fixture, _) = HistoricalFixture::build(
            script_tree,
            script_tip_id,
            HistoricalConfig {
                tx_watermark: Some(script_tx_watermark),
                sh_watermark: Some(script_sh_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: funding_scans,
                bodies,
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        let script_at = script_fixture.engine.script_history_at_answer(scripthash)?;
        assert_eq!(script_at.coverage.height, 1);
        assert_eq!(script_at.coverage.floor, 0);
        for record in &script_at.value.history {
            assert!(record.height <= 1);
        }
        Ok(())
    }

    #[test]
    fn historical_mixed_cap_tx_anchors_at_tx_watermark() -> Result<(), crate::portable::TestError> {
        let (genesis, chain, _scripthash) = paying_chain()?;
        let mut tx_tree = BlockTree::new();
        let mut tx_tip_id = tx_tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        for block in &chain {
            tx_tip_id = tx_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        }
        assert_eq!(tx_tree.node(tx_tip_id)?.height, 2);
        let tx_middle_id = tx_tree
            .node_at_height_from(tx_tip_id, 1)
            .ok_or_else(|| std::io::Error::other("middle present"))?;
        let mut bodies = Vec::new();
        bodies.push((0, genesis.block_hash(), consensus_bytes(&genesis)));
        for (height, block) in [1u32, 2u32].iter().zip(chain.iter()) {
            bodies.push((*height, block.block_hash(), consensus_bytes(block)));
        }
        let funding_txid_height_two = chain[1].txs[0].txid();
        let tx_scans = vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&funding_txid_height_two),
            vec![(
                TxidRow::row(&funding_txid_height_two, 2)
                    .to_db_row()
                    .to_vec(),
                vec![0],
            )],
            true,
        )];
        let tx_tx_watermark = watermark_for(&tx_tree, tx_tip_id)?;
        let tx_sh_watermark = watermark_for(&tx_tree, tx_middle_id)?;
        let (tx_fixture, _) = HistoricalFixture::build(
            tx_tree,
            tx_tip_id,
            HistoricalConfig {
                tx_watermark: Some(tx_tx_watermark),
                sh_watermark: Some(tx_sh_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: tx_scans,
                bodies,
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        let tx_at = tx_fixture
            .engine
            .transaction_at_answer(&funding_txid_height_two)?;
        assert_eq!(tx_at.coverage.height, 2);
        assert!(tx_at.value.is_some());
        assert_eq!(tx_at.value.as_ref().map(|(h, _)| *h), Some(2));
        Ok(())
    }

    #[test]
    fn historical_duplicate_txid_returns_earliest_verified_and_skips_stale()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let mut target = genesis.txs[0].clone();
        target.outputs[0].value = target.outputs[0].value.saturating_add(Amount::from_sat(7));
        let target_txid = target.txid();
        let main_plain = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let main_mid = child_block(&main_plain, vec![target.clone()])?;
        let main_tip = child_block(&main_mid, vec![target.clone()])?;
        let stale_child = child_block(&genesis, vec![target.clone(), genesis.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let _plain_id = tree.insert_header(main_plain.header, NodeStatus::HeaderValid)?;
        let _mid_id = tree.insert_header(main_mid.header, NodeStatus::HeaderValid)?;
        let main_tip_id = tree.insert_header(main_tip.header, NodeStatus::HeaderValid)?;
        let _stale_id = tree.insert_header(stale_child.header, NodeStatus::HeaderValid)?;
        let watermark = watermark_for(&tree, main_tip_id)?;
        let (fixture, _) = HistoricalFixture::build(
            tree,
            main_tip_id,
            HistoricalConfig {
                tx_watermark: Some(watermark),
                sh_watermark: Some(watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&target_txid),
                    vec![
                        (TxidRow::row(&target_txid, 1).to_db_row().to_vec(), vec![0]),
                        (TxidRow::row(&target_txid, 2).to_db_row().to_vec(), vec![0]),
                        (TxidRow::row(&target_txid, 3).to_db_row().to_vec(), vec![0]),
                    ],
                    true,
                )],
                bodies: vec![
                    (1, main_plain.block_hash(), consensus_bytes(&main_plain)),
                    (2, main_mid.block_hash(), consensus_bytes(&main_mid)),
                    (3, main_tip.block_hash(), consensus_bytes(&main_tip)),
                ],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        let at = fixture.engine.transaction_at_answer(&target_txid)?;
        assert_eq!(at.coverage.height, 3);
        let Some((height, _)) = at.value else {
            return Err(std::io::Error::other("duplicate must verify").into());
        };
        assert_eq!(height, 2);
        Ok(())
    }

    #[test]
    fn historical_no_covered_prefix_for_reset_claim() -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let (fixture, _) = HistoricalFixture::build(
            tree,
            tip_id,
            HistoricalConfig {
                tx_watermark: None,
                sh_watermark: None,
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        assert!(matches!(
            fixture.engine.transaction_at_answer(&txid),
            Err(TxQueryError::Retry(_))
        ));
        assert!(matches!(
            fixture
                .engine
                .script_history_at_answer(ScriptHash::new(&[])),
            Err(TxQueryError::Retry(_))
        ));
        Ok(())
    }

    #[test]
    fn historical_budgets_truncation_and_missing_map_to_shared()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let mut truncated_tree = BlockTree::new();
        let truncated_tip_id =
            truncated_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let truncated_watermark = watermark_for(&truncated_tree, truncated_tip_id)?;
        let truncated = HistoricalFixture::build(
            truncated_tree,
            truncated_tip_id,
            HistoricalConfig {
                tx_watermark: Some(truncated_watermark),
                sh_watermark: Some(truncated_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                    false,
                )],
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?
        .0;
        assert!(matches!(
            truncated.engine.transaction_at_answer(&txid),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrefixScanTruncated
            ))
        ));
        let mut missing_tree = BlockTree::new();
        let missing_tip_id = missing_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let missing_watermark = watermark_for(&missing_tree, missing_tip_id)?;
        let missing = HistoricalFixture::build(
            missing_tree,
            missing_tip_id,
            HistoricalConfig {
                tx_watermark: Some(missing_watermark),
                sh_watermark: Some(missing_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                    true,
                )],
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?
        .0;
        assert!(matches!(
            missing.engine.transaction_at_answer(&txid),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::BlockBodyMissing { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn historical_budgets_health_and_capability_map_to_shared()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let mut failed_tree = BlockTree::new();
        let failed_tip_id = failed_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let failed_watermark = watermark_for(&failed_tree, failed_tip_id)?;
        let (failed_fixture, _) = HistoricalFixture::build(
            failed_tree,
            failed_tip_id,
            HistoricalConfig {
                tx_watermark: Some(failed_watermark),
                sh_watermark: Some(failed_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        failed_fixture
            .runtime
            .publish_failed("injected worker failure");
        assert!(matches!(
            failed_fixture.engine.transaction_at_answer(&txid),
            Err(TxQueryError::Unavailable(TxUnavailableCause::WorkerFailed(
                _
            )))
        ));
        let mut disabled_tree = BlockTree::new();
        let disabled_tip_id = disabled_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        let disabled_watermark = watermark_for(&disabled_tree, disabled_tip_id)?;
        let (disabled_fixture, _) = HistoricalFixture::build(
            disabled_tree,
            disabled_tip_id,
            HistoricalConfig {
                tx_watermark: Some(disabled_watermark),
                sh_watermark: Some(disabled_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::TX_LOOKUP,
            },
        )?;
        assert!(matches!(
            disabled_fixture
                .engine
                .script_history_at_answer(ScriptHash::new(&[])),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::CapabilityDisabled(_)
            ))
        ));
        let tx_only = disabled_fixture.engine.transaction_at_answer(&txid)?;
        assert_eq!(tx_only.coverage.height, 0);
        Ok(())
    }

    #[test]
    fn historical_deep_stale_branch_refuses_prefix() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let mut main_tip_id = genesis_id;
        let mut main_tip_block = genesis.clone();
        for _ in 0..320 {
            let child = child_block(&main_tip_block, vec![main_tip_block.txs[0].clone()])?;
            main_tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
            main_tip_block = child;
        }
        let mut stale_tip_id = genesis_id;
        let mut stale_tip_block = genesis.clone();
        for _ in 0..320 {
            let mut tx = stale_tip_block.txs[0].clone();
            tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
            let child = child_block(&stale_tip_block, vec![tx])?;
            stale_tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
            stale_tip_block = child;
        }
        let stale_watermark = watermark_for(&tree, stale_tip_id)?;
        let txid = genesis.txs[0].txid();
        let (fixture, _) = HistoricalFixture::build(
            tree,
            main_tip_id,
            HistoricalConfig {
                tx_watermark: Some(stale_watermark),
                sh_watermark: Some(stale_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;
        assert!(matches!(
            fixture.engine.transaction_at_answer(&txid),
            Err(TxQueryError::Retry(RetryReason::PendingCapabilityCoverage(
                IndexCapability::TxLookup
            )))
        ));
        Ok(())
    }

    // IDX-02, IDX-04
    #[test]
    fn cursor_page_requires_txlookup_floor_that_covers_the_page()
    -> Result<(), crate::portable::TestError> {
        let (genesis, chain, scripthash) = paying_chain()?;
        let mut tree = BlockTree::new();
        let mut tip_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        for block in &chain {
            tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        }
        let watermark = watermark_for(&tree, tip_id)?;
        let mut funding_rows = Vec::new();
        for (height, block) in
            std::iter::once((0_u32, &genesis)).chain([1_u32, 2_u32].into_iter().zip(chain.iter()))
        {
            for (index, tx) in block.txs.iter().enumerate() {
                funding_rows.push(history_row(
                    scripthash,
                    height,
                    &[(
                        tx.txid(),
                        position_of_transaction(block, index)?,
                        crate::types::ScriptHistoryOccurrence::FUNDING,
                    )],
                ));
            }
        }
        funding_rows.reverse();
        let tip_txid = chain[1].txs[0].txid();
        let middle_txids = [chain[0].txs[0].txid(), chain[0].txs[1].txid()];
        let tx_scan = |txid: &Txid, height: u32| {
            scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(txid),
                vec![(TxidRow::row(txid, height).to_db_row().to_vec(), vec![0_u8])],
                true,
            )
        };
        let scans = vec![
            scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                funding_rows,
                true,
            ),
            tx_scan(&tip_txid, 2),
            tx_scan(&middle_txids[0], 1),
            tx_scan(&middle_txids[1], 1),
        ];
        let (fixture, _) = HistoricalFixture::build(
            tree,
            tip_id,
            HistoricalConfig {
                tx_watermark: Some(watermark),
                sh_watermark: Some(watermark),
                tx_floor: 1,
                sh_floor: 0,
                scans,
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;

        let first = fixture.engine.confirmed_history_page(scripthash, None, 3)?;
        assert_eq!(
            first.records.len(),
            3,
            "a first page lists the three newest records without tx lookups"
        );

        let paged = fixture
            .engine
            .confirmed_history_page(scripthash, Some(tip_txid), 3);
        assert!(
            matches!(
                &paged,
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::PrunedPrefixUnproven {
                        family: "transaction index",
                        floor: 1,
                    }
                ))
            ),
            "a cursor page must refuse when the tx floor cannot cover it: {paged:?}"
        );

        let genesis_txid = genesis.txs[0].txid();
        let paged = fixture
            .engine
            .confirmed_history_page(scripthash, Some(genesis_txid), 3);
        assert!(
            matches!(
                &paged,
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::PrunedPrefixUnproven { .. }
                ))
            ),
            "a cursor below the tx floor must refuse instead of restarting: {paged:?}"
        );
        Ok(())
    }

    // QRY-03
    #[test]
    fn history_query_survives_chain_extension() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let txid = genesis.txs[0].txid();
        let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let side_child = {
            let mut tx = genesis.txs[0].clone();
            tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
            child_block(&genesis, vec![tx])?
        };
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
        let side_id = tree.insert_header(side_child.header, NodeStatus::HeaderValid)?;
        let main_watermark = watermark_for(&tree, main_id)?;
        let main_tip = tip_snapshot_for(&tree, main_id)?;
        let side_tip = tip_snapshot_for(&tree, side_id)?;

        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(main_tip)));

        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let tip_cell_clone = Arc::clone(&tip_cell);
        let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
            tip_cell_clone.store(Some(Arc::new(side_tip.clone())));
        }));

        let body = Arc::new(MovingBody::new(
            vec![(1, main_child.block_hash(), consensus_bytes(&main_child))],
            on_read,
        ));

        let reader: Arc<dyn IndexReader> = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: Some(main_watermark),
                sh_watermark: Some(main_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });

        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );

        let at = engine.transaction_at_answer(&txid)?;
        assert_eq!(at.height, 1);
        assert_eq!(at.coverage.height, 1);
        assert!(at.value.is_some());
        Ok(())
    }

    // QRY-01
    #[test]
    fn answer_reads_the_captured_snapshot_when_tail_rows_are_rewritten()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let mut tx_a = genesis.txs[0].clone();
        tx_a.outputs.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: genesis.txs[0].outputs[0].script_pubkey.clone(),
        });
        let child = child_block(&genesis, vec![tx_a.clone()])?;
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let tip_watermark = watermark_for(&tree, child_id)?;
        let tip = tip_snapshot_for(&tree, child_id)?;
        let txid_a = tx_a.txid();

        let initial = HistoricalSnapshot {
            tx_watermark: Some(tip_watermark),
            sh_watermark: Some(tip_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid_a),
                vec![(TxidRow::row(&txid_a, 1).to_db_row().to_vec(), vec![0_u8])],
                true,
            )],
        };
        let rewritten = HistoricalSnapshot {
            tx_watermark: Some(tip_watermark),
            sh_watermark: Some(tip_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
        };

        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let body = Arc::new(MovingBody::new(
            vec![(1, child.block_hash(), consensus_bytes(&child))],
            None,
        ));

        let engine = DerivedIndexQueryEngine::new(
            runtime,
            Arc::new(SnapshotCountingReader {
                initial,
                rewritten,
                calls: AtomicUsize::new(0),
            }),
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );

        let at = engine.transaction_at_answer(&txid_a)?;
        assert!(
            at.value.is_some(),
            "the answer must come from the capture-time snapshot even though the read rewrote the tail rows, got value {:?}",
            at.value
        );
        assert_eq!(at.height, 1);
        assert_eq!(at.coverage.height, 1);
        Ok(())
    }

    // QRY-05
    #[test]
    fn below_floor_point_lookups_refuse_with_outside_coverage()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let tip_watermark = watermark_for(&tree, child_id)?;
        let genesis_txid = genesis.txs[0].txid();
        let outpoint = OutPoint::new(genesis_txid, 0);

        let (fixture, _) = HistoricalFixture::build(
            tree,
            child_id,
            HistoricalConfig {
                tx_watermark: Some(tip_watermark),
                sh_watermark: Some(tip_watermark),
                tx_floor: 1,
                sh_floor: 1,
                scans: vec![
                    scan_response(
                        ColumnFamily::TxConfirmed,
                        TxidRow::scan_prefix(&genesis_txid),
                        vec![(
                            TxidRow::row(&genesis_txid, 0).to_db_row().to_vec(),
                            vec![0_u8],
                        )],
                        true,
                    ),
                    scan_response(
                        ColumnFamily::Spending,
                        SpendingPrefixRow::scan_prefix(&outpoint),
                        vec![(
                            SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec(),
                            Vec::new(),
                        )],
                        true,
                    ),
                ],
                bodies: Vec::new(),
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;

        let located = fixture.engine.transaction_at_answer(&genesis_txid);
        assert!(
            matches!(
                &located,
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::OutsideCoverage {
                        declared_floor_or_tip: 1,
                    }
                ))
            ),
            "a below-floor txid must refuse instead of returning scoped absence: {located:?}"
        );

        let spent = fixture.engine.spender_at_answer(outpoint);
        assert!(
            matches!(
                &spent,
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::OutsideCoverage {
                        declared_floor_or_tip: 1,
                    }
                ))
            ),
            "a below-floor spender must refuse instead of returning scoped absence: {spent:?}"
        );
        Ok(())
    }

    // QRY-05
    #[test]
    fn outside_coverage_is_unavailable() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let genesis_watermark = watermark_for(&tree, genesis_id)?;

        let (fixture, _) = HistoricalFixture::build(
            tree,
            child_id,
            HistoricalConfig {
                tx_watermark: Some(genesis_watermark),
                sh_watermark: Some(genesis_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
                bodies: vec![
                    (0, genesis.block_hash(), consensus_bytes(&genesis)),
                    (1, child.block_hash(), consensus_bytes(&child)),
                ],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;

        let unknown_txid = Txid(Hash256::from_le_bytes(&[0xEE; 32]));
        let result = fixture.engine.transaction_at_answer(&unknown_txid);
        assert!(
            matches!(
                result,
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::OutsideCoverage {
                        declared_floor_or_tip: 0
                    }
                ))
            ),
            "query outside declared coverage must return OutsideCoverage error, got {result:?}"
        );
        Ok(())
    }

    // QRY-03
    #[test]
    fn tip_promising_script_pages_refuse_while_watermark_lags_the_tip()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let genesis_watermark = watermark_for(&tree, genesis_id)?;
        let scripthash = ScriptHash::new(&genesis.txs[0].outputs[0].script_pubkey);
        let funding = history_row(
            scripthash,
            0,
            &[(
                genesis.txs[0].txid(),
                position_of_transaction(&genesis, 0)?,
                crate::types::ScriptHistoryOccurrence::FUNDING,
            )],
        );

        let (fixture, _) = HistoricalFixture::build(
            tree,
            child_id,
            HistoricalConfig {
                tx_watermark: Some(genesis_watermark),
                sh_watermark: Some(genesis_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::Funding,
                    ScriptHashRow::scan_prefix(scripthash),
                    vec![funding],
                    true,
                )],
                bodies: vec![(0, genesis.block_hash(), consensus_bytes(&genesis))],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;

        let page = fixture.engine.confirmed_history_page(scripthash, None, 10);
        assert!(
            matches!(&page, Err(TxQueryError::Retry(_))),
            "a tip-promising history page must refuse while the watermark lags the tip: {page:?}"
        );

        let live = fixture.engine.unspent_outputs(scripthash);
        assert!(
            matches!(&live, Err(TxQueryError::Retry(_))),
            "a tip-promising utxo listing must refuse while the watermark lags the tip: {live:?}"
        );

        let embed = fixture.engine.script_history_at_answer(scripthash)?;
        assert_eq!(embed.coverage.height, 0);
        assert_eq!(embed.value.history.len(), 1);
        Ok(())
    }

    // QRY-03
    #[test]
    fn tx_lookups_refuse_with_retry_while_watermark_lags_the_tip()
    -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        let genesis_watermark = watermark_for(&tree, genesis_id)?;
        let genesis_txid = genesis.txs[0].txid();
        let outpoint = OutPoint::new(genesis_txid, 0);

        let (fixture, _) = HistoricalFixture::build(
            tree,
            child_id,
            HistoricalConfig {
                tx_watermark: Some(genesis_watermark),
                sh_watermark: Some(genesis_watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&genesis_txid),
                    vec![(
                        TxidRow::row(&genesis_txid, 0).to_db_row().to_vec(),
                        vec![0_u8],
                    )],
                    true,
                )],
                bodies: vec![(0, genesis.block_hash(), consensus_bytes(&genesis))],
                on_first_read: None,
                enabled: IndexCapabilities::ALL,
            },
        )?;

        let found = fixture.engine.transaction(&genesis_txid);
        assert!(
            matches!(&found, Err(TxQueryError::Retry(_))),
            "a current-tip tx lookup must refuse with Retry while the watermark lags: {found:?}"
        );
        let height = fixture.engine.transaction_block(&genesis_txid);
        assert!(
            matches!(&height, Err(TxQueryError::Retry(_))),
            "a current-tip height lookup must refuse with Retry while the watermark lags: {height:?}"
        );
        let value = fixture.engine.outpoint_value(&outpoint);
        assert!(
            matches!(&value, Err(TxQueryError::Retry(_))),
            "a current-tip outpoint lookup must refuse with Retry while the watermark lags: {value:?}"
        );
        Ok(())
    }

    // QRY-07
    #[test]
    fn expired_revoked_and_replaced_views_fail_closed() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tip = tip_snapshot_for(&tree, genesis_id)?;
        let watermark = watermark_for(&tree, genesis_id)?;
        let generation = Arc::new(Generation::new(1));

        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reader: Arc<dyn IndexReader> = Arc::new(ResetReader {
            state: Arc::new(ParkMutex::new(HistoricalSnapshot {
                tx_watermark: Some(watermark),
                sh_watermark: Some(watermark),
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
            })),
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            None,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::clone(&generation),
                historical_verified: None,
                chain_transition: None,
            },
        );

        let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
        let expired_view = view;
        expired_view.expire_for_test();
        let expired = engine.with_view(
            IndexCapabilities::TX_LOOKUP,
            &expired_view,
            snapshot.as_ref(),
            |_, _, _| Ok::<(), TxQueryError>(()),
        );
        assert!(
            matches!(expired, Err(TxQueryError::ExpiredView)),
            "a view past its deadline must fail closed: {expired:?}"
        );

        let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
        let expired_during_read = engine.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |_, view, _| {
                view.expire_for_test();
                Ok::<(), TxQueryError>(())
            },
        );
        assert!(
            matches!(expired_during_read, Err(TxQueryError::ExpiredView)),
            "a view that expires during a read must not return success: {expired_during_read:?}"
        );

        let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
        let mut moved = engine.clone();
        moved.set_generation_for_test(Arc::new(Generation::new(2)));
        let replaced = moved.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |_, _, _| Ok::<(), TxQueryError>(()),
        );
        assert!(
            matches!(replaced, Err(TxQueryError::ExpiredView)),
            "a view from a replaced generation must fail closed: {replaced:?}"
        );

        let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
        generation.revoke();
        let revoked = engine.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |_, _, _| Ok::<(), TxQueryError>(()),
        );
        assert!(
            matches!(revoked, Err(TxQueryError::ExpiredView)),
            "a view whose generation was revoked must fail closed: {revoked:?}"
        );

        let refused = engine.transaction(&genesis.txs[0].txid());
        assert!(
            matches!(refused, Err(TxQueryError::ExpiredView)),
            "a fresh capture on a revoked generation must refuse: {refused:?}"
        );
        Ok(())
    }

    // QRY-07
    #[test]
    fn filter_stream_stops_after_callback_revokes_view() -> Result<(), crate::portable::TestError> {
        use crate::CompactFilterQuery;

        let genesis = Network::Regtest.genesis_block();
        let child = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        let stop = Hash256::from(child.block_hash());
        let scans = [(0_u32, &genesis), (1_u32, &child)]
            .into_iter()
            .map(|(height, block)| {
                let key = crate::segment::format::encode_filter_key(0, height);
                scan_response(
                    ColumnFamily::Filters,
                    key,
                    vec![(
                        key.to_vec(),
                        crate::segment::format::encode_filter_value(
                            block.block_hash().as_bytes(),
                            &[0; 32],
                            &[0; 32],
                            &[0],
                        ),
                    )],
                    true,
                )
            })
            .collect();
        let mut fixture = QueryFixture::new(FixtureConfig {
            block: genesis,
            retain_body: false,
            scans,
            watermark: None,
            extra_blocks: vec![child],
        })?;
        let generation = Arc::new(Generation::new(1));
        fixture
            .engine
            .set_generation_for_test(Arc::clone(&generation));
        let mut emitted = 0;
        let result = fixture.engine.for_each_filter(0, stop, 1, &mut |_, _| {
            emitted += 1;
            generation.revoke();
            true
        });
        assert_eq!(
            emitted, 1,
            "the next filter must not be emitted after expiry"
        );
        assert!(matches!(result, Err(TxQueryError::ExpiredView)));
        Ok(())
    }

    // PRJ-11
    #[test]
    fn script_live_takes_no_transition_lock() -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let script = ScriptHash::from_byte_array([1; 32]);
        let outpoint = OutPoint::new(block.txs[0].txid(), 0);
        let row = ScriptLiveRow::new(script, &outpoint);
        let coin = crate::types::ScriptLiveCoin::new(script, 50_000, 0, true);

        let transition = bitcoin_rs_execution::chain::TransitionDomain::new();
        let stable_read = transition.stable_read();

        let fixture = QueryFixture::new_with_transition(
            FixtureConfig {
                block: block.clone(),
                retain_body: true,
                scans: vec![scan_response(
                    ColumnFamily::ScriptLive,
                    ScriptHashRow::scan_prefix(script),
                    vec![(row.as_bytes().to_vec(), coin.encode_value()?)],
                    true,
                )],
                watermark: Some(IndexWatermark {
                    height: 0,
                    hash: *block.block_hash().as_bytes(),
                }),
                extra_blocks: Vec::new(),
            },
            Some(stable_read.clone()),
        )?;
        let authority = transition.authority();
        let _guard = authority.lock();

        for _ in 0..100 {
            let live = fixture.engine.unspent_outputs(script)?;
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].value, 50_000);
        }

        assert_eq!(
            stable_read.lock_acquisitions(),
            0,
            "ScriptLive must take zero transition locks"
        );
        Ok(())
    }

    // QRY-02
    #[test]
    fn traversal_of_a_captured_view_ignores_commits_and_seal_during_it()
    -> Result<(), crate::portable::TestError> {
        struct NoSpends;

        impl crate::SpentCoins for NoSpends {
            fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<crate::SpentCoin<'_>> {
                None
            }
        }

        fn commit_one(
            writer: &mut crate::IndexWriter<bitcoin_rs_storage::RocksDbStore>,
            height: u32,
            hash: [u8; 32],
            body: &[u8],
        ) -> Result<(), crate::portable::TestError> {
            let prepared = writer.prepare_block_with_spent_scripts(
                IndexCapabilities::TX_LOOKUP,
                height,
                hash,
                body,
                &NoSpends,
            )?;
            let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            if batch.try_push(prepared).is_err() {
                return Err("one block is admitted per batch".into());
            }
            writer.commit_forward(batch)?;
            Ok(())
        }

        fn sealed_generation_count(
            store: &bitcoin_rs_storage::RocksDbStore,
        ) -> Result<usize, crate::portable::TestError> {
            use bitcoin_rs_storage::KvStore as _;
            let snapshot = store.snapshot()?;
            Ok(
                crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?
                    .len(),
            )
        }

        let genesis = Network::Regtest.genesis_block();
        let txid_a = genesis
            .txs
            .first()
            .ok_or("genesis carries a coinbase")?
            .txid();
        let dir = tempfile::TempDir::new()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);
        let scratch = tempfile::TempDir::new()?;
        let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1)?
            .with_seal_scratch(scratch.path().to_path_buf());
        commit_one(
            &mut writer,
            0,
            *genesis.block_hash().as_bytes(),
            &consensus_bytes(&genesis),
        )?;
        assert_eq!(
            sealed_generation_count(&store)?,
            0,
            "no sealed generation exists before the tail reaches its bound"
        );

        let last_height = crate::segment::format::TAIL_MAX_BLOCKS + 1;
        let mut chain = Vec::new();
        let mut parent = genesis.block_hash();
        for height in 1..=last_height {
            let block = regtest_fixture::mined_regtest_child_at(parent, height)
                .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
            parent = block.block_hash();
            chain.push((
                height,
                *block.block_hash().as_bytes(),
                consensus_bytes(&block),
                block
                    .txs
                    .first()
                    .ok_or("each mined block carries a coinbase")?
                    .txid(),
            ));
        }
        let txid_b = chain.first().ok_or("the chain is non-empty")?.3;
        let txid_last = chain.last().ok_or("the chain is non-empty")?.3;
        assert_ne!(
            txid_a, txid_b,
            "each block contributes its own coinbase row"
        );

        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tip = tip_snapshot_for(&tree, tip_id)?;
        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(tip)));
        let reader: Arc<dyn IndexReader> = Arc::new(crate::Indexer::new(Arc::clone(&store)));
        let fresh_reader = Arc::clone(&reader);
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let engine = DerivedIndexQueryEngine::new(
            DerivedIndexRuntime::new(wake_tx),
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
            bitcoin_rs_execution::chain::TipReader::new(applied_tip),
            None,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let limit = PrefixScanLimit {
            max_rows: 16,
            max_bytes: 4096,
        };
        let values = |scan: &TxIndexScan| {
            scan.rows
                .iter()
                .map(|row| row.value.clone())
                .collect::<Vec<_>>()
        };

        let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
        let read = |txid: &Txid| {
            engine.with_view(
                IndexCapabilities::TX_LOOKUP,
                &view,
                snapshot.as_ref(),
                |snap: &dyn TxIndexSnapshot, _view, _budget| {
                    snap.transaction_rows(txid, limit)
                        .map_err(|error| TxQueryError::Storage(error.to_string().into()))
                },
            )
        };
        let before = values(&read(&txid_a)?);
        assert_eq!(
            before.len(),
            1,
            "the captured view holds the genesis coinbase row"
        );

        let (first_committed_tx, first_committed_rx) = std::sync::mpsc::channel::<()>();
        let (traversed_tx, traversed_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || -> Result<(), crate::portable::TestError> {
            let mut blocks = chain.into_iter();
            let (height, hash, body, _) = blocks.next().ok_or("the chain is non-empty")?;
            commit_one(&mut writer, height, hash, &body)?;
            first_committed_tx
                .send(())
                .map_err(|_| "the reader stopped")?;
            traversed_rx
                .recv_timeout(std::time::Duration::from_secs(120))
                .map_err(|_| "the reader did not traverse the first commit")?;
            for (height, hash, body, _) in blocks {
                commit_one(&mut writer, height, hash, &body)?;
            }
            Ok(())
        });

        first_committed_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "the commit worker did not commit the first block")?;
        assert_eq!(
            values(&read(&txid_a)?),
            before,
            "a traversal that overlaps the first commit must return the capture-time answer"
        );
        assert!(
            read(&txid_b)?.rows.is_empty(),
            "a block committed after capture must not appear in the captured view"
        );
        traversed_tx
            .send(())
            .map_err(|_| "the commit worker stopped")?;

        while !worker.is_finished() {
            assert_eq!(
                values(&read(&txid_a)?),
                before,
                "a traversal overlapping commits must return the capture-time answer"
            );
            assert!(
                read(&txid_b)?.rows.is_empty(),
                "rows committed after capture must not appear in the captured view"
            );
        }
        worker.join().map_err(|_| "commit worker panicked")??;

        assert_eq!(
            sealed_generation_count(&store)?,
            1,
            "committing past the tail bound must seal exactly one generation"
        );
        assert_eq!(
            values(&read(&txid_a)?),
            before,
            "the captured view keeps its answer after the tail seals"
        );
        let fresh = fresh_reader.snapshot()?;
        assert_eq!(
            fresh
                .capability_watermark(IndexCapability::TxLookup)?
                .map(|watermark| watermark.height),
            Some(last_height),
            "the writer committed every block"
        );
        assert_eq!(
            fresh.transaction_rows(&txid_last, limit)?.rows.len(),
            1,
            "a view captured after the commits sees the last block"
        );
        Ok(())
    }
    // BUD-02
    #[test]
    fn view_charge_refusal_reports_node_budget() -> Result<(), crate::portable::TestError> {
        let genesis = Network::Regtest.genesis_block();
        let engine = engine_with_body_source(&genesis, Vec::new(), None)?;
        struct Refusing;
        impl bitcoin_rs_storage::budget::BudgetCharge for Refusing {
            fn reserve_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                _bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted)
            }
            fn allocate_bytes(
                &self,
                _owner: bitcoin_rs_storage::budget::BudgetOwner,
                _bytes: u64,
            ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
                Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted)
            }
            fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, _bytes: u64) {}
            fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
                0
            }
        }
        let engine = engine.with_query_charge(Some(bitcoin_rs_storage::budget::ChargeHandle::new(
            std::sync::Arc::new(Refusing),
            bitcoin_rs_storage::budget::BudgetOwner::QueryViews,
        )));
        assert!(matches!(
            engine.capture_view(IndexCapabilities::TX_LOOKUP),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::NodeBudgetExhausted
            ))
        ));
        Ok(())
    }

    #[test]
    fn uninitialized_applied_tip_returns_missing_applied_tip_retry()
    -> Result<(), crate::portable::TestError> {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let tree = Arc::new(RwLock::new(BlockTree::new()));
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark: None,
                sh_watermark: None,
                tx_floor: 0,
                sh_floor: 0,
                scans: Vec::new(),
            },
        });
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
            bitcoin_rs_execution::chain::TipReader::new(Arc::new(ArcSwapOption::empty())),
            None,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        assert!(matches!(
            engine.transaction(&txid),
            Err(TxQueryError::Retry(RetryReason::MissingAppliedTip))
        ));
        assert!(matches!(
            engine.index_progress_for(IndexCapabilities::ALL),
            Err(TxQueryError::Retry(RetryReason::MissingAppliedTip))
        ));
        Ok(())
    }
}

#[cfg(test)]
mod supervisor_tests {
    #![expect(
        clippy::expect_used,
        reason = "test: supervisor tests use expect for clarity"
    )]

    use super::namespace::NAMESPACE_REGISTRY;
    use super::*;
    use arc_swap::ArcSwap;
    use bitcoin_rs_execution::chain::BlockTree;
    use std::sync::Arc;

    fn test_open_spec(dir: &std::path::Path, epoch: u64) -> DerivedIndexOpenSpec {
        DerivedIndexOpenSpec {
            scripthash_limit: crate::runtime::DEFAULT_SCRIPTHASH_LIMIT,
            data_dir: dir.to_path_buf(),
            namespace: "txindex",
            storage_backend: bitcoin_rs_storage::StorageBackend::RocksDb,
            epoch,
            enabled: IndexCapabilities::default(),
            rollback_rebuild_cutover: 0,
            canonical_data_root: dir.to_path_buf(),
            bundle: crate::portable::IndexBundleDirective::None,
            facts_rx: None,
            facts_charge: None,
            query_charge: None,
            facts_gap: None,
            cpu: None,
            open_store: Arc::new(move |dir| {
                let store = Arc::new(
                    bitcoin_rs_storage::RocksDbStore::open_with_cache(dir, 8 * 1024 * 1024)
                        .map_err(DerivedIndexWorkerError::Storage)?,
                );
                open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, epoch)
            }),
        }
    }

    struct WorkerInputs {
        runtime: Arc<DerivedIndexRuntime>,
        spec: DerivedIndexOpenSpec,
        lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>,
        generation: Generation,
        applied_tip: Arc<arc_swap::ArcSwapOption<bitcoin_rs_execution::chain::TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        shutdown: bitcoin_rs_consensus::latch::LatchWriter,
        wake_rx: Receiver<()>,
        chain_events: Arc<dyn crate::reconcile::ChainCursorSource>,
    }

    fn build_worker_inputs(dir: &std::path::Path, epoch: u64) -> WorkerInputs {
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let spec = test_open_spec(dir, epoch);
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
        let generation = Generation::new(epoch);
        let applied_tip = Arc::new(arc_swap::ArcSwapOption::empty());
        let block_tree = Arc::new(RwLock::new(BlockTree::new()));
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let chain_events = Arc::new(TestChainCursor);

        WorkerInputs {
            runtime,
            spec,
            lifecycle,
            generation,
            applied_tip,
            block_tree,
            shutdown,
            wake_rx,
            chain_events,
        }
    }

    #[test]
    fn blocked_open_abandonment_detaches_and_poisons() {
        struct DropProbe(crossbeam_channel::Sender<()>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store_dir = dir.path().join("txindex");

        let (open_tx, open_rx) = crossbeam_channel::bounded::<()>(0);
        let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
        let mut inputs = build_worker_inputs(dir.path(), 42);
        let store_dir_clone = store_dir.clone();
        inputs.spec.open_store = Arc::new(move |_| {
            let _ = open_rx.recv();
            let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DropProbe(dropped_tx.clone()));
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(
                    &store_dir_clone,
                    8 * 1024 * 1024,
                )
                .map(|s| s.guarded_by(guard))
                .map_err(DerivedIndexWorkerError::Storage)?,
            );
            open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 42)
        });
        let mut worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&inputs.runtime),
            inputs.spec,
            Arc::clone(&inputs.lifecycle),
            inputs.generation.clone(),
            bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
            None,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
            None,
            bitcoin_rs_storage::pruning::HistoryAccess::new(
                Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
            ),
            None,
            Arc::clone(&inputs.chain_events),
            RecordedIndexAhead::new(),
            inputs.shutdown.reader(),
            inputs.wake_rx,
        )
        .expect("spawn");

        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !worker.is_finished(),
            "worker should still be blocked on open"
        );

        let deadline = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();
        while std::time::Instant::now() < start + deadline {
            if worker.is_finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !worker.is_finished(),
            "worker must still be blocked past deadline"
        );

        worker.generation.revoke();
        inputs
            .lifecycle
            .store(Arc::new(DerivedIndexLifecycle::ShutdownAbandoned));
        worker.poison_namespace();
        worker.detach();

        assert!(
            start.elapsed() < deadline + std::time::Duration::from_secs(5),
            "abandonment must be bounded"
        );
        assert!(worker.generation.is_revoked());
        assert!(matches!(
            **inputs.lifecycle.load(),
            DerivedIndexLifecycle::ShutdownAbandoned
        ));

        let namespace_key = dir.path().join("txindex");
        assert!(NAMESPACE_REGISTRY.is_poisoned(&namespace_key));
        assert!(!NAMESPACE_REGISTRY.claim(namespace_key, 999));
        drop(worker);

        inputs.runtime.request_shutdown();
        inputs.shutdown.trigger();
        drop(open_tx);

        dropped_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("detached helper store must drop before tempdir cleanup");
    }

    #[test]
    fn shutdown_during_open_joins_helper_releases_lock_and_leaves_namespace_reusable() {
        struct DropProbe(crossbeam_channel::Sender<()>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store_dir = dir.path().join("txindex");

        let (opened_tx, opened_rx) = crossbeam_channel::bounded::<()>(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
        let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
        let mut inputs = build_worker_inputs(dir.path(), 43);
        let store_dir_clone = store_dir.clone();
        inputs.spec.open_store = Arc::new(move |_| {
            let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DropProbe(dropped_tx.clone()));
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(
                    &store_dir_clone,
                    8 * 1024 * 1024,
                )
                .map(|s| s.guarded_by(guard))
                .map_err(DerivedIndexWorkerError::Storage)?,
            );
            let _ = opened_tx.send(());
            let _ = release_rx.recv();
            open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
        });

        let worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&inputs.runtime),
            inputs.spec,
            Arc::clone(&inputs.lifecycle),
            inputs.generation.clone(),
            bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
            None,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
            None,
            bitcoin_rs_storage::pruning::HistoryAccess::new(
                Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
            ),
            None,
            Arc::clone(&inputs.chain_events),
            RecordedIndexAhead::new(),
            inputs.shutdown.reader(),
            inputs.wake_rx,
        )
        .expect("spawn");

        opened_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("open thread opened store and held native lock");
        assert!(
            !worker.is_finished(),
            "worker should still be blocked on open"
        );

        inputs.shutdown.trigger();
        release_tx.send(()).expect("release helper");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !worker.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown during open must exit the supervisor promptly"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let open_abandoned = worker.open_was_abandoned();
        worker.join();

        dropped_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("store must drop before assertions");

        assert!(
            !open_abandoned,
            "open must not be reported as abandoned when helper completes"
        );
        let namespace_key = dir.path().join("txindex");
        assert!(
            !NAMESPACE_REGISTRY.is_poisoned(&namespace_key),
            "namespace must not be poisoned when helper completes cleanly"
        );
        assert!(
            NAMESPACE_REGISTRY.claim(namespace_key.clone(), 999),
            "namespace must be claimable after clean shutdown"
        );
        NAMESPACE_REGISTRY.release(&namespace_key, 999);

        let second_open =
            bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir, 8 * 1024 * 1024);
        assert!(
            second_open.is_ok(),
            "second RocksDbStore open must succeed, proving native lock released: {:?}",
            second_open.as_ref().err()
        );
    }

    #[test]
    fn stalled_open_at_shutdown_deadline_yields_poison_and_safely_cleans_up() {
        struct DropProbe(crossbeam_channel::Sender<()>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store_dir = dir.path().join("txindex");

        let (opened_tx, opened_rx) = crossbeam_channel::bounded::<()>(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
        let (dropped_tx, dropped_rx) = crossbeam_channel::bounded::<()>(1);
        let mut inputs = build_worker_inputs(dir.path(), 44);
        let store_dir_clone = store_dir.clone();
        inputs.spec.open_store = Arc::new(move |_| {
            let guard: bitcoin_rs_storage::StoreGuard = Arc::new(DropProbe(dropped_tx.clone()));
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(
                    &store_dir_clone,
                    8 * 1024 * 1024,
                )
                .map(|s| s.guarded_by(guard))
                .map_err(DerivedIndexWorkerError::Storage)?,
            );
            let _ = opened_tx.send(());
            let _ = release_rx.recv();
            open_derived_index_store_on_worker(store, crate::runtime::DEFAULT_BATCH_LIMITS, 1)
        });

        let mut worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&inputs.runtime),
            inputs.spec,
            Arc::clone(&inputs.lifecycle),
            inputs.generation.clone(),
            bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
            None,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
            None,
            bitcoin_rs_storage::pruning::HistoryAccess::new(
                Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
            ),
            None,
            Arc::clone(&inputs.chain_events),
            RecordedIndexAhead::new(),
            inputs.shutdown.reader(),
            inputs.wake_rx,
        )
        .expect("spawn");

        opened_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("open thread opened store and held native lock");
        assert!(
            !worker.is_finished(),
            "worker should still be blocked on open"
        );

        inputs.runtime.request_shutdown();
        inputs.shutdown.trigger();

        let deadline = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();
        while std::time::Instant::now() < start + deadline {
            if worker.is_finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !worker.is_finished(),
            "worker must still be blocked past deadline while helper is stalled"
        );

        worker.generation.revoke();
        inputs
            .lifecycle
            .store(Arc::new(DerivedIndexLifecycle::ShutdownAbandoned));
        worker.poison_namespace();
        worker.detach();

        let namespace_key = dir.path().join("txindex");
        assert!(
            NAMESPACE_REGISTRY.is_poisoned(&namespace_key),
            "namespace must be poisoned on deadline abandonment"
        );

        let second_open =
            bitcoin_rs_storage::RocksDbStore::open_with_cache(&store_dir, 8 * 1024 * 1024);
        assert!(
            second_open.is_err(),
            "second open must fail while stalled helper still holds native lock"
        );

        release_tx.send(()).expect("release stalled helper");
        dropped_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("helper store must drop before tempdir cleanup");
    }

    #[test]
    fn open_timeout_publishes_error_not_infinite_spin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut spec = test_open_spec(dir.path(), 1);
        spec.open_store = Arc::new(move |_dir| {
            std::thread::sleep(Duration::from_secs(10));
            Err(DerivedIndexWorkerError::Stopped)
        });
        let result = open_derived_index_with_timeout(
            &spec,
            &dir.path().join("txindex"),
            Duration::from_secs(1),
            &shutdown.reader(),
            || false,
        );

        let Err(DerivedIndexWorkerError::OpenTimeout { secs }) = result else {
            panic!("expected OpenTimeout, got a different error variant");
        };
        assert_eq!(secs, 1);
    }

    #[test]
    fn caught_up_idle_worker_wakes_on_shutdown_latch_and_joins_promptly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inputs = build_worker_inputs(dir.path(), 45);
        let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&inputs.runtime),
            inputs.spec,
            Arc::clone(&inputs.lifecycle),
            inputs.generation.clone(),
            bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
            None,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
            None,
            bitcoin_rs_storage::pruning::HistoryAccess::new(
                Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
            ),
            None,
            Arc::clone(&inputs.chain_events),
            RecordedIndexAhead::new(),
            shutdown_writer.reader(),
            inputs.wake_rx,
        )
        .expect("spawn");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !matches!(**inputs.lifecycle.load(), DerivedIndexLifecycle::Serving(_)) {
            assert!(
                std::time::Instant::now() < deadline,
                "worker must enter serving state"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        shutdown_writer.trigger();

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let join_thread = std::thread::spawn(move || {
            let handle = worker.join_handle.take().expect("handle");
            let _ = handle.join();
            let _ = done_tx.send(());
        });

        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "worker thread must join within deadline on latch trigger"
        );
        assert!(join_thread.join().is_ok());
    }

    #[test]
    fn revision_quiet_cancellation_wakes_and_joins_promptly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inputs = build_worker_inputs(dir.path(), 46);
        let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        let store = Arc::new(
            bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), 8 * 1024 * 1024)
                .expect("store"),
        );
        let open =
            open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 46).expect("open");
        let writer = open.writer;
        let worker = Worker {
            runtime: Arc::clone(&inputs.runtime),
            writer,
            applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(
                &inputs.applied_tip,
            )),
            block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
                &inputs.block_tree,
            )),
            body_store: None,
            history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
            ),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled: IndexCapabilities::default(),
            chain_events: Arc::new(TestChainCursor),
            reporter: RecordedIndexAhead::new(),
            shutdown: shutdown_writer.reader(),
            wake_rx: inputs.wake_rx,
            quiet_period: Duration::from_secs(30),
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover: 0,
            seed_history_lease: parking_lot::Mutex::new(None),
            facts_rx: None,
            facts_charge: None,
            facts_gap: None,
            cpu: None,
            buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
        };

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let join_thread = std::thread::spawn(move || {
            let result = worker.wait_for_revision_quiet(0);
            let _ = done_tx.send(result);
        });

        std::thread::sleep(Duration::from_millis(20));
        shutdown_writer.trigger();

        let result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("must exit within 5 s deadline");
        assert_eq!(result, None);
        assert!(join_thread.join().is_ok());
    }

    #[test]
    fn batch_deadline_cancellation_wakes_and_joins_promptly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inputs = build_worker_inputs(dir.path(), 47);
        let shutdown_writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        let store = Arc::new(
            bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), 8 * 1024 * 1024)
                .expect("store"),
        );
        let open =
            open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 47).expect("open");
        let writer = open.writer;
        let worker = Worker {
            runtime: Arc::clone(&inputs.runtime),
            writer,
            applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(
                &inputs.applied_tip,
            )),
            block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
                &inputs.block_tree,
            )),
            body_store: None,
            history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
            ),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled: IndexCapabilities::default(),
            chain_events: Arc::new(TestChainCursor),
            reporter: RecordedIndexAhead::new(),
            shutdown: shutdown_writer.reader(),
            wake_rx: inputs.wake_rx,
            quiet_period: Duration::from_secs(30),
            batch_delay: Duration::ZERO,
            rollback_rebuild_cutover: 0,
            seed_history_lease: parking_lot::Mutex::new(None),
            facts_rx: None,
            facts_charge: None,
            facts_gap: None,
            cpu: None,
            buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
        };

        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let join_thread = std::thread::spawn(move || {
            let result =
                worker.wait_for_batch_deadline(std::time::Instant::now() + Duration::from_secs(30));
            let _ = done_tx.send(result);
        });

        std::thread::sleep(Duration::from_millis(20));
        shutdown_writer.trigger();

        let result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("must exit within 5 s deadline");
        assert_eq!(result, super::catch_up::BatchWait::Stopped);
        assert!(join_thread.join().is_ok());
    }
    // IDX-05
    #[test]
    fn incompatible_populated_index_reopens_without_writing_obsolete_rows()
    -> Result<(), crate::portable::TestError> {
        assert_namespace_rebuild(bitcoin_rs_storage::StorageBackend::RocksDb, |path| {
            bitcoin_rs_storage::RocksDbStore::open_with_cache(path, 8 * 1024 * 1024)
        })
    }

    // IDX-05
    #[test]
    #[cfg(feature = "surrealkv")]
    fn surrealkv_incompatible_populated_index_reopens_without_writing_obsolete_rows()
    -> Result<(), crate::portable::TestError> {
        assert_namespace_rebuild(bitcoin_rs_storage::StorageBackend::SurrealKv, |path| {
            bitcoin_rs_storage::SurrealKvStore::open_with_cache(path, 8 * 1024 * 1024)
        })
    }

    // IDX-05
    #[test]
    #[cfg(feature = "mdbx")]
    fn mdbx_incompatible_populated_index_reopens_without_writing_obsolete_rows()
    -> Result<(), crate::portable::TestError> {
        assert_namespace_rebuild(bitcoin_rs_storage::StorageBackend::Mdbx, |path| {
            bitcoin_rs_storage::MdbxStore::open_with_cache(path, 8 * 1024 * 1024)
        })
    }

    fn assert_namespace_rebuild<S: bitcoin_rs_storage::KvStore>(
        backend: bitcoin_rs_storage::StorageBackend,
        open_store: fn(&std::path::Path) -> Result<S, bitcoin_rs_storage::StorageError>,
    ) -> Result<(), crate::portable::TestError> {
        use bitcoin_rs_storage::{ColumnFamily, PersistFault};
        use std::sync::atomic::{AtomicUsize, Ordering};

        for marker in [Some(5_u32), None, Some(9_u32)] {
            let dir = tempfile::tempdir()?;
            let index_dir = dir.path().join("txindex");
            let sibling = dir.path().join("chainstate-evidence");
            std::fs::write(&sibling, b"authoritative bytes")?;
            {
                let store = open_store(&index_dir)?;
                let mut batch = store.new_batch();
                for family in [
                    ColumnFamily::TxConfirmed,
                    ColumnFamily::Funding,
                    ColumnFamily::Spending,
                    ColumnFamily::ScriptLive,
                ] {
                    for index in 0..32_000_u32 {
                        batch.put(family, &index.to_be_bytes(), &[0xa5; 16]);
                    }
                }
                if let Some(marker) = marker {
                    batch.put(ColumnFamily::UtxoMeta, &[0, b'V'], &marker.to_le_bytes());
                    if marker == 9 {
                        let mut claim = vec![0b1111];
                        claim.extend_from_slice(&1_u64.to_le_bytes());
                        claim.extend_from_slice(&0_u64.to_le_bytes());
                        batch.put(ColumnFamily::UtxoMeta, &[0, b'R'], &claim);
                    }
                }
                store.write_durable(batch)?;
            }
            let obsolete_file = index_dir.join("obsolete-layout");
            std::fs::write(&obsolete_file, b"obsolete")?;
            let mut inputs = build_worker_inputs(dir.path(), 1780);
            inputs.spec.storage_backend = backend;
            let opens = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&opens);
            inputs.spec.open_store = Arc::new(move |path| {
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                let store = Arc::new(open_store(path)?);
                if attempt == 0 {
                    store.arm_persist_fault(PersistFault::FailApply);
                } else {
                    for family in [
                        ColumnFamily::TxConfirmed,
                        ColumnFamily::Funding,
                        ColumnFamily::Spending,
                        ColumnFamily::ScriptLive,
                    ] {
                        assert!(store.iter_prefix(family, &[])?.next().is_none());
                    }
                }
                open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, 1780)
            });
            let worker = DerivedIndexWorker::spawn_with_open(
                Arc::clone(&inputs.runtime),
                inputs.spec,
                Arc::clone(&inputs.lifecycle),
                inputs.generation.clone(),
                bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&inputs.applied_tip)),
                None,
                bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&inputs.block_tree)),
                None,
                bitcoin_rs_storage::pruning::HistoryAccess::new(
                    Arc::new(bitcoin_rs_storage::pruning::RetentionRegistry::new()),
                    bitcoin_rs_storage::pruning::RetentionBudget::Unlimited,
                ),
                None,
                Arc::clone(&inputs.chain_events),
                RecordedIndexAhead::new(),
                inputs.shutdown.reader(),
                inputs.wake_rx,
            )
            .expect("spawn");
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while matches!(**inputs.lifecycle.load(), DerivedIndexLifecycle::Opening)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            inputs.shutdown.trigger();
            worker.join();
            let final_lifecycle = inputs.lifecycle.load_full();
            let serving = matches!(**inputs.lifecycle.load(), DerivedIndexLifecycle::Serving(_));
            let failure = match final_lifecycle.as_ref() {
                DerivedIndexLifecycle::Failed(reason) => reason.as_str(),
                DerivedIndexLifecycle::Opening => "still opening",
                DerivedIndexLifecycle::ShutdownAbandoned => "shutdown abandoned",
                DerivedIndexLifecycle::Serving(_) => "serving",
            };
            assert!(
                serving,
                "obsolete rows must not be deleted through durable writes: {failure}"
            );
            assert_eq!(opens.load(Ordering::SeqCst), 2);
            assert!(!obsolete_file.exists());
            assert_eq!(std::fs::read(&sibling)?, b"authoritative bytes");
            assert!(!NAMESPACE_REGISTRY.is_poisoned(&index_dir));
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic)]
mod recovery_tests {
    use crate::reconcile::{ReconcileLeg, ReconcilePhase};
    use arc_swap::ArcSwapOption;

    use bitcoin::{
        Amount, Block, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
        Witness,
        block::{Header as BlockHeader, Version},
        consensus::encode::serialize,
        hashes::Hash as _,
        pow::CompactTarget,
        script::Builder,
    };

    use bitcoin_rs_execution::chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};

    use crate::IndexCapabilities;

    use bitcoin_rs_consensus::primitives::Hash256;

    use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
    use bitcoin_rs_storage::utxo::SnapshotCoinObserver as _;
    use bitcoin_rs_storage::{
        InMemoryUndoStore, RocksDbStore, StorageError, block_body::BlockBodyStore,
    };

    use hashbrown::{HashMap, HashSet};

    use parking_lot::{Mutex, RwLock};

    use std::{sync::Arc, time::Duration};

    use super::*;

    type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

    #[derive(Debug, thiserror::Error)]
    enum RecoveryTestError {
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        Index(#[from] crate::IndexError),
        #[error(transparent)]
        LiveValue(#[from] crate::types::ScriptLiveValueError),
        #[error("live row key fails to decode")]
        BadLiveRow,
    }

    struct MapBodyStore {
        bodies: Mutex<BodyMap>,
        undo: Mutex<BodyMap>,
        undo_read_failures: Mutex<HashSet<(u32, [u8; 32])>>,
        stop_on_absent_body: Mutex<Option<Arc<DerivedIndexRuntime>>>,
    }

    impl BlockBodyStore for MapBodyStore {
        fn persist_block_body(
            &self,
            height: u32,
            hash: Hash256,
            body: &[u8],
        ) -> Result<(), StorageError> {
            self.bodies
                .lock()
                .insert((height, hash.to_le_bytes()), body.to_vec());
            Ok(())
        }

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            let body = self
                .bodies
                .lock()
                .get(&(height, hash.to_le_bytes()))
                .cloned();
            if body.is_none()
                && let Some(runtime) = self.stop_on_absent_body.lock().as_ref()
            {
                runtime.request_shutdown();
            }
            Ok(body)
        }

        fn undo_record(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
            let key = (height, hash.to_le_bytes());
            if self.undo_read_failures.lock().contains(&key) {
                return Err(StorageError::backend("injected undo read failure"));
            }
            Ok(self.undo.lock().get(&key).cloned())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct BranchCoins(Vec<bitcoin_rs_storage::utxo::UtxoCoin>);

    impl bitcoin_rs_storage::utxo::contract::SpentOutputLookup for BranchCoins {
        fn entry(
            &self,
            outpoint: &bitcoin_rs_consensus::primitives::OutPoint,
        ) -> Option<&bitcoin_rs_storage::utxo::UtxoCoin> {
            self.0.iter().find(|coin| coin.outpoint == *outpoint)
        }
    }

    impl BranchCoins {
        fn connect(
            &mut self,
            height: u32,
            block: &bitcoin_rs_consensus::primitives::Block,
            txids: &[bitcoin_rs_consensus::primitives::Txid],
        ) {
            for (tx, txid) in block.txs.iter().zip(txids) {
                for (vout, txout) in tx.outputs.iter().enumerate() {
                    self.0.push(bitcoin_rs_storage::utxo::UtxoCoin {
                        outpoint: bitcoin_rs_consensus::primitives::OutPoint::new(
                            *txid,
                            u32::try_from(vout).expect("vout"),
                        ),
                        txout: txout.clone(),
                        coinbase: tx.is_coinbase(),
                        height,
                    });
                }
            }
        }
    }

    fn coinbase_tx(height: u32, extra: i64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: Builder::new()
                    .push_int(i64::from(height))
                    .push_int(extra)
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn tree_header(block: &Block) -> bitcoin_rs_consensus::primitives::Header {
        bitcoin_rs_consensus::primitives::deserialize::<bitcoin_rs_consensus::primitives::Header>(
            &serialize(&block.header),
        )
        .expect("80-byte header")
    }

    fn mine_block(
        prev_hash: Hash256,
        height: u32,
        extra: i64,
        prev_extra: i64,
    ) -> (Block, Hash256) {
        let prev_blockhash = BlockHash::from_byte_array(prev_hash.to_le_bytes());
        let mut block = Block {
            header: BlockHeader {
                version: Version::ONE,
                prev_blockhash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx(height, extra)],
        };
        if height > 0 {
            let mut spend = coinbase_tx(height, extra);
            spend.input[0].previous_output = bitcoin::OutPoint {
                txid: coinbase_tx(height - 1, prev_extra).compute_txid(),
                vout: 0,
            };
            block.txdata.push(spend);
        }
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(TxMerkleNode::all_zeros);
        let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        (block, hash)
    }

    pub(super) struct ForkFixture {
        tree: Arc<RwLock<BlockTree>>,
        bodies: Arc<MapBodyStore>,
        genesis: Hash256,
        pub(super) a: Vec<(NodeId, Hash256)>,
        b: Vec<(NodeId, Hash256)>,
    }

    impl ForkFixture {
        pub(super) fn new(len: u32) -> Self {
            let mut tree = BlockTree::new();
            let mut bodies = BodyMap::new();
            let (genesis, genesis_hash) = mine_block(Hash256::from_le_bytes(&[0_u8; 32]), 0, 0, 0);
            tree.insert_header(tree_header(&genesis), NodeStatus::HeaderValid)
                .expect("genesis");
            bodies.insert((0, genesis_hash.to_le_bytes()), serialize(&genesis));
            let mut branch = |extra: i64| {
                let mut prev = genesis_hash;
                let mut ids = Vec::new();
                for height in 1..=len {
                    let prev_extra = if height == 1 { 0 } else { extra };
                    let (block, hash) = mine_block(prev, height, extra, prev_extra);
                    let id = tree
                        .insert_header(tree_header(&block), NodeStatus::HeaderValid)
                        .expect("branch header");
                    bodies.insert((height, hash.to_le_bytes()), serialize(&block));
                    ids.push((id, hash));
                    prev = hash;
                }
                ids
            };
            let a = branch(0);
            let b = branch(1);
            Self {
                tree: Arc::new(RwLock::new(tree)),
                bodies: Arc::new(MapBodyStore {
                    bodies: Mutex::new(bodies),
                    undo: Mutex::default(),
                    undo_read_failures: Mutex::default(),
                    stop_on_absent_body: Mutex::default(),
                }),
                genesis: genesis_hash,
                a,
                b,
            }
        }

        fn a_key(&self, height: u32) -> (u32, [u8; 32]) {
            if height == 0 {
                return (0, self.genesis.to_le_bytes());
            }
            let index = usize::try_from(height - 1).expect("height index");
            (height, self.a[index].1.to_le_bytes())
        }

        fn take_bodies(&self, through: u32) -> BodyMap {
            let mut bodies = self.bodies.bodies.lock();
            (0..=through)
                .filter_map(|height| {
                    let key = self.a_key(height);
                    bodies.remove(&key).map(|body| (key, body))
                })
                .collect()
        }

        fn restore_bodies(&self, lost: BodyMap) {
            self.bodies.bodies.lock().extend(lost);
        }

        fn branch_key(&self, branch: &[(NodeId, Hash256)], height: u32) -> (u32, [u8; 32]) {
            if height == 0 {
                return (0, self.genesis.to_le_bytes());
            }
            let index = usize::try_from(height - 1).expect("height index");
            (height, branch[index].1.to_le_bytes())
        }

        fn persist_branch_undo(&self, branch: &[(NodeId, Hash256)]) {
            let store = InMemoryUndoStore::default();
            let mut coins = BranchCoins::default();
            let tip_height = u32::try_from(branch.len()).expect("branch length");
            for height in 0..=tip_height {
                let key = self.branch_key(branch, height);
                let block = {
                    let bodies = self.bodies.bodies.lock();
                    bitcoin_rs_consensus::primitives::deserialize::<
                        bitcoin_rs_consensus::primitives::Block,
                    >(&bodies[&key])
                    .expect("fixture block")
                };
                let txids = block.txids();
                let image = bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone());
                if height > 0 {
                    let (_, undo, _) = bitcoin_rs_storage::utxo::contract::build_block_changes(
                        &bitcoin_rs_storage::utxo::contract::BlockChangeInputs {
                            block: &image,
                            height,
                            txids: &txids,
                            same_block_spent: None,
                            add_capacity: 0,
                            remove_capacity: 0,
                            max_script_size: crate::MAX_LIVE_SCRIPT_SIZE,
                        },
                        &coins,
                    )
                    .expect("undo batch");
                    let record = bitcoin_rs_storage::utxo::contract::persist_block_undo(
                        &store,
                        height,
                        Hash256::from_le_bytes(&key.1),
                        &undo,
                    )
                    .expect("undo record");
                    self.bodies
                        .undo
                        .lock()
                        .insert(key, record.as_bytes().to_vec());
                }
                coins.connect(height, &block, &txids);
            }
        }
        pub(super) fn persist_undo(&self) {
            self.persist_branch_undo(&self.a.clone());
            self.persist_branch_undo(&self.b.clone());
        }

        fn fork_from_a(&self, fork_height: u32, len: u32) -> Vec<(NodeId, Hash256)> {
            let shared = usize::try_from(fork_height).expect("fork height");
            let mut branch: Vec<(NodeId, Hash256)> = self.a[..shared].to_vec();
            let mut prev = branch.last().map_or(self.genesis, |(_, hash)| *hash);
            for height in fork_height + 1..=len {
                let prev_extra = if height == fork_height + 1 { 0 } else { 2 };
                let (block, hash) = mine_block(prev, height, 2, prev_extra);
                let id = self
                    .tree
                    .write()
                    .insert_header(tree_header(&block), NodeStatus::HeaderValid)
                    .expect("fork header");
                self.bodies
                    .bodies
                    .lock()
                    .insert((height, hash.to_le_bytes()), serialize(&block));
                branch.push((id, hash));
                prev = hash;
            }
            branch
        }

        pub(super) fn tip(&self, (node_id, _): (NodeId, Hash256)) -> Arc<TipSnapshot> {
            let tree = self.tree.read();
            let node = tree.node(node_id).expect("node");
            Arc::new(TipSnapshot {
                tip_id: node_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            })
        }
    }

    struct Harness {
        _index_dir: tempfile::TempDir,
        store: Arc<RocksDbStore>,
        writer: Arc<dyn TxIndexWriter>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        runtime: Arc<DerivedIndexRuntime>,
        evidence: Arc<RecordedIndexAhead>,
        retention: Arc<RetentionRegistry>,
        worker: Worker,
    }

    // IDX-07
    #[test]
    fn missing_undo_pauses_the_tail_group_and_resumes_to_bulk() {
        const TIP: u32 = 20;
        const MISSING: u32 = 10;
        let f = ForkFixture::new(TIP);
        f.persist_undo();
        let key = f.a_key(MISSING);
        let record = f
            .bodies
            .undo
            .lock()
            .remove(&key)
            .expect("undo record for the missing height");
        let h = Harness::with_enabled(
            &f,
            u32::MAX,
            IndexCapabilities::HISTORICAL.with_compact_filters(true),
        );
        let tip = f.tip(f.a[usize::try_from(TIP - 1).expect("index")]);
        h.set_tip(&tip);
        h.settle(&mut None);

        let paused = h.watermarks();
        assert_eq!(
            paused.tx_lookup, paused.script_history,
            "the tail group moves together"
        );
        assert_eq!(
            paused.tx_lookup, paused.compact_filters,
            "the tail group moves together"
        );
        assert!(
            paused
                .tx_lookup
                .is_none_or(|watermark| watermark.height < MISSING),
            "the tail group stops before the missing height: {paused:?}"
        );
        assert!(h.runtime.compact_filter_failure.read().is_some());
        assert!(h.runtime.script_history_failure.read().is_some());
        assert!(h.runtime.tx_lookup_failure.read().is_some());
        assert!(!h.runtime.should_stop(), "the worker keeps running");

        f.bodies.undo.lock().insert(key, record);
        h.settle(&mut None);
        h.assert_at(&tip);
        assert!(
            h.runtime.undo_gap().is_none(),
            "the gap clears once the undo row returns"
        );
        assert_chain_matches_bulk(&h.store, &f, TIP);
    }

    fn assert_chain_matches_bulk(live: &RocksDbStore, f: &ForkFixture, tip: u32) {
        let blocks = committed_chain(f, &f.a, 0, tip);
        let oracle = bulk_oracle(&blocks);
        let bulk_view =
            crate::segment::SegmentSnapshot::open(oracle.store.snapshot().expect("bulk snapshot"))
                .expect("bulk view");
        let live_view =
            crate::segment::SegmentSnapshot::open(live.snapshot().expect("live snapshot"))
                .expect("live view");
        assert_eq!(
            winner_answers(&live_view, &blocks),
            winner_answers(&bulk_view, &blocks),
            "resumed index answers equal the bulk build of the chain"
        );
    }

    impl Harness {
        fn new(fixture: &ForkFixture, rollback_rebuild_cutover: u32) -> Self {
            Self::with_enabled(
                fixture,
                rollback_rebuild_cutover,
                IndexCapabilities::HISTORICAL,
            )
        }

        fn with_enabled(
            fixture: &ForkFixture,
            rollback_rebuild_cutover: u32,
            enabled: IndexCapabilities,
        ) -> Self {
            let index_dir = tempfile::tempdir().expect("index dir");
            let store = Arc::new(RocksDbStore::open(index_dir.path()).expect("rocksdb open"));
            Self::on_store(fixture, rollback_rebuild_cutover, enabled, index_dir, store)
        }

        fn on_store(
            fixture: &ForkFixture,
            rollback_rebuild_cutover: u32,
            enabled: IndexCapabilities,
            index_dir: tempfile::TempDir,
            store: Arc<RocksDbStore>,
        ) -> Self {
            let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
                crate::IndexWriter::open(Arc::clone(&store), 1)
                    .expect("index writer open")
                    .with_seal_scratch(index_dir.path().join("seal-scratch")),
            ));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
            let runtime = DerivedIndexRuntime::new(wake_tx);
            let evidence = RecordedIndexAhead::new();
            let reporter: Arc<dyn IndexAheadSink> = evidence.clone();
            let body_store: Arc<dyn BlockBodyStore> = fixture.bodies.clone();
            let retention = Arc::new(RetentionRegistry::new());
            let worker = Worker {
                runtime: Arc::clone(&runtime),
                writer: Arc::clone(&writer),
                applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&applied_tip)),
                block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
                    &fixture.tree,
                )),
                body_store: Some(body_store),
                history: HistoryAccess::new(Arc::clone(&retention), RetentionBudget::Unlimited),
                batch_limits: DEFAULT_BATCH_LIMITS,
                enabled,
                chain_events: Arc::new(TestChainCursor),
                reporter,
                shutdown: bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
                wake_rx,
                quiet_period: Duration::ZERO,
                batch_delay: Duration::ZERO,
                rollback_rebuild_cutover,
                seed_history_lease: parking_lot::Mutex::new(None),
                facts_rx: None,
                facts_charge: None,
                facts_gap: None,
                cpu: None,
                buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
            };
            Self {
                _index_dir: index_dir,
                store,
                writer,
                applied_tip,
                runtime,
                evidence,
                retention,
                worker,
            }
        }

        fn set_tip(&self, tip: &Arc<TipSnapshot>) {
            self.applied_tip.store(Some(Arc::clone(tip)));
        }

        fn settle(&self, pending: &mut Option<PendingForward>) {
            for _ in 0..64 {
                match self.worker.reconcile_once(pending).expect("reconcile pass") {
                    ReconcileAction::CaughtUp => return,
                    ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                    ReconcileAction::Stalled => panic!("worker stalled"),
                }
            }
            panic!("worker did not converge");
        }

        fn watermarks(&self) -> IndexWatermarks {
            self.writer.fenced_watermarks().expect("watermarks").1
        }

        fn assert_at(&self, tip: &TipSnapshot) {
            let expected = Some(IndexWatermark {
                height: tip.height,
                hash: tip.hash.to_le_bytes(),
            });
            let watermarks = self.watermarks();
            assert_eq!(watermarks.tx_lookup, expected, "tx_lookup watermark");
            if self.worker.enabled.contains(IndexCapability::ScriptHistory)
                && self.runtime.script_history_failure.read().is_none()
            {
                assert_eq!(
                    watermarks.script_history, expected,
                    "script_history watermark"
                );
            }
            assert_eq!(self.runtime.phase(), ReconcilePhase::FORWARD);
        }

        fn index_ahead_call(&self) -> Option<(String, u32, u32, String, String, u32)> {
            self.evidence
                .calls
                .lock()
                .first()
                .map(|(cap, ih, th, thb, ihb, d, _)| {
                    (cap.clone(), *ih, *th, thb.clone(), ihb.clone(), *d)
                })
        }
    }

    // IDX-07
    #[test]
    fn missing_undo_pauses_the_tail_group_at_the_fork_point() {
        struct SpentScript;
        impl crate::SpentCoins for SpentScript {
            fn spent_coin(&self, _: &[u8; 32], _: u32) -> Option<crate::SpentCoin<'_>> {
                Some(crate::SpentCoin {
                    script: &[0x51],
                    value: 0,
                    height: 0,
                    coinbase: false,
                })
            }
        }
        let f = ForkFixture::new(2);
        let h = Harness::with_enabled(
            &f,
            u32::MAX,
            IndexCapabilities::HISTORICAL.with_compact_filters(true),
        );
        let a2 = f.tip(f.a[1]);
        let identities = h.worker.collect_target_chain(&a2, 0, 2).expect("chain");
        let mut batch = PreparedBatch::new(DEFAULT_BATCH_LIMITS);
        for identity in identities {
            let body = f.bodies.bodies.lock()[&(identity.height, identity.hash)].clone();
            let prepared = h
                .writer
                .prepare_block_with_spent_scripts(
                    h.worker.enabled,
                    identity.height,
                    identity.hash,
                    &body,
                    &SpentScript,
                )
                .expect("prepare");
            assert!(batch.try_push(prepared).is_ok());
        }
        let fence = h.writer.fenced_watermarks().expect("fence").0;
        h.writer
            .commit_forward_with_cursor(fence, batch, crate::ConsumerCursorUpdate::Keep)
            .expect("initial filter publication");
        h.set_tip(&f.tip(f.b[1]));
        h.settle(&mut None);
        let watermarks = h.watermarks();
        for (name, mark) in [
            ("tx_lookup", watermarks.tx_lookup),
            ("script_history", watermarks.script_history),
            ("compact_filters", watermarks.compact_filters),
        ] {
            assert_eq!(
                mark.map(|watermark| watermark.height),
                Some(0),
                "{name} pauses at the fork point: the forward block has no undo record"
            );
        }
        assert!(
            h.runtime.compact_filter_failure.read().is_some(),
            "compact_filter_failure records the pause of the forward block"
        );
        assert!(
            h.runtime.script_history_failure.read().is_some(),
            "script_history_failure records the pause of the forward block"
        );
        assert!(
            h.runtime.tx_lookup_failure.read().is_some(),
            "tx_lookup_failure records the pause of the forward block"
        );
        assert_eq!(
            h.runtime.undo_gap(),
            Some((1, f.b[0].1)),
            "the gap names the forward block height and hash"
        );
        assert_eq!(h.runtime.phase(), ReconcilePhase::FORWARD);
        assert!(!h.runtime.should_stop());
    }

    // EVT-04, IDX-07
    #[test]
    fn unavailable_filter_history_preserves_sibling_indexes_and_filter_watermark() {
        let fixture = ForkFixture::new(2);
        fixture.persist_undo();
        for pruned in [false, true] {
            let harness = Harness::with_enabled(
                &fixture,
                u32::MAX,
                IndexCapabilities::HISTORICAL.with_compact_filters(true),
            );
            if pruned {
                harness.retention.reserve(1).commit(1);
            }
            harness.set_tip(&fixture.tip(fixture.a[1]));
            harness.settle(&mut None);
            harness.assert_at(&fixture.tip(fixture.a[1]));
            if pruned {
                assert!(harness.runtime.compact_filter_failure.read().is_some());
            } else {
                assert!(harness.runtime.compact_filter_failure.read().is_none());
                assert_eq!(
                    harness.watermarks().compact_filters,
                    Some(at(&fixture.tip(fixture.a[1]))),
                    "filters advance when history is retained"
                );
            }
            assert!(!harness.runtime.should_stop());
            harness.set_tip(&fixture.tip(fixture.b[1]));
            harness.settle(&mut None);
            harness.assert_at(&fixture.tip(fixture.b[1]));
            if pruned {
                assert!(harness.watermarks().compact_filters.is_none());
            } else {
                assert_eq!(
                    harness.watermarks().compact_filters,
                    Some(at(&fixture.tip(fixture.b[1]))),
                    "filters follow the reorg when history is retained"
                );
            }
        }
    }

    // IDX-06, IDX-07
    #[test]
    fn rollback_without_undo_preserves_script_history_and_rewinds_siblings() {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::HISTORICAL);
        let a3 = f.tip(f.a[2]);
        h.set_tip(&a3);
        h.settle(&mut None);
        h.assert_at(&a3);

        for height in 1..=3 {
            f.bodies.undo.lock().remove(&f.a_key(height));
        }
        let a1 = f.tip(f.a[0]);
        h.set_tip(&a1);
        h.settle(&mut None);

        assert_eq!(
            h.watermarks().tx_lookup,
            Some(at(&a1)),
            "TxLookup rolls back without the undo anchor"
        );
        assert_eq!(
            h.watermarks().script_history,
            Some(at(&a1)),
            "the tail group rewinds together: ScriptHistory moves with TxLookup"
        );
        assert!(h.runtime.script_history_failure.read().is_none());
        assert!(!h.runtime.should_stop());
    }

    #[test]
    fn index_ahead_of_restored_tip_is_reported_once_and_rewound() {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;

        let a3 = f.tip(f.a[2]);
        h.set_tip(&a3);
        h.settle(&mut pending);
        h.assert_at(&a3);

        let a1 = f.tip(f.a[0]);
        h.set_tip(&a1);
        h.settle(&mut pending);
        h.assert_at(&a1);

        assert_eq!(
            h.evidence.calls.lock().len(),
            1,
            "one warning per rollback pass"
        );
        match h.index_ahead_call() {
            Some((_capability, index_height, tip_height, tip_hash_be, index_hash_be, depth)) => {
                assert_eq!((tip_height, index_height, depth), (1, 3, 2));
                assert_eq!(tip_hash_be, a1.hash.to_string_be());
                assert_eq!(index_hash_be, a3.hash.to_string_be());
            }
            other => panic!("expected IndexWatermarkAhead report, got {other:?}"),
        }
    }

    // RCV-05
    #[test]
    fn deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up() {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = Harness::new(&f, 1);
        let mut pending = None;

        let a3 = f.tip(f.a[2]);
        h.set_tip(&a3);
        h.settle(&mut pending);
        h.assert_at(&a3);

        let b3 = f.tip(f.b[2]);
        h.set_tip(&b3);
        let first = h.worker.reconcile_once(&mut pending).expect("reset pass");
        assert!(!matches!(first, ReconcileAction::CaughtUp));
        assert_eq!(
            h.runtime.phase(),
            ReconcilePhase::FORWARD
                .with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Rebuilding)
        );
        for _ in 0..64 {
            let action = h.worker.reconcile_once(&mut pending).expect("rebuild pass");
            if matches!(action, ReconcileAction::CaughtUp) {
                break;
            }
            assert!(!matches!(action, ReconcileAction::Stalled));
            assert_eq!(
                h.runtime.phase(),
                ReconcilePhase::FORWARD
                    .with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Rebuilding)
            );
        }
        h.assert_at(&b3);
        let blocks = committed_chain(&f, &f.b, 0, b3.height);
        let oracle = bulk_oracle(&blocks);
        let bulk_view =
            crate::segment::SegmentSnapshot::open(oracle.store.snapshot().expect("bulk snapshot"))
                .expect("bulk view");
        let live_view =
            crate::segment::SegmentSnapshot::open(h.store.snapshot().expect("live snapshot"))
                .expect("live view");
        assert_eq!(
            winner_answers(&live_view, &blocks),
            winner_answers(&bulk_view, &blocks),
            "rebuilt transaction positions and script history equal an independent bulk build"
        );
        let abandoned = committed_chain(&f, &f.a, 1, a3.height);
        assert_eq!(
            winner_answers(&live_view, &abandoned),
            winner_answers(&bulk_view, &abandoned),
            "abandoned branch answers equal the winning-chain bulk build"
        );
        assert!(h.index_ahead_call().is_none(), "equal height is not ahead");
    }

    // RCV-07
    #[test]
    fn pruned_history_rebuilds_from_the_frontier_and_absent_history_waits() {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let a3 = f.tip(f.a[2]);
        h.set_tip(&a3);
        h.settle(&mut pending);
        h.assert_at(&a3);

        h.retention.reserve(2).commit(2);

        let b3 = f.tip(f.b[2]);
        h.set_tip(&b3);
        let action = h.worker.reconcile_once(&mut pending).expect("rebuild pass");
        assert!(!matches!(action, ReconcileAction::CaughtUp));
        assert_eq!(
            h.runtime.phase(),
            ReconcilePhase::FORWARD
                .with_leg(IndexCapabilities::HISTORICAL, ReconcileLeg::Rebuilding),
            "the frontier answer must publish a rebuild, not a stall or a plain rollback"
        );
        let anchored = Some(IndexWatermark {
            height: 1,
            hash: f.b[0].1.to_le_bytes(),
        });
        let watermarks = h.watermarks();
        assert_eq!(
            watermarks.tx_lookup, anchored,
            "the durable watermark is anchored at the first surviving height"
        );
        assert_eq!(watermarks.script_history, anchored);

        h.settle(&mut pending);
        h.assert_at(&b3);
        assert!(h.index_ahead_call().is_none(), "equal height is not ahead");

        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let a3 = f.tip(f.a[2]);
        h.set_tip(&a3);
        h.settle(&mut pending);
        f.bodies.bodies.lock().remove(&(3, f.a[2].1.to_le_bytes()));
        let a1 = f.tip(f.a[0]);
        h.set_tip(&a1);
        let action = h.worker.reconcile_once(&mut pending).expect("wait pass");
        assert!(
            matches!(action, ReconcileAction::Stalled),
            "transient absence under a grant must not rebuild, got {action:?}"
        );
        assert_eq!(
            h.watermarks().tx_lookup,
            Some(IndexWatermark {
                height: 3,
                hash: a3.hash.to_le_bytes(),
            }),
            "the consumer keeps its derived rows while it waits"
        );
    }

    pub(super) fn at(tip: &TipSnapshot) -> IndexWatermark {
        IndexWatermark {
            height: tip.height,
            hash: tip.hash.to_le_bytes(),
        }
    }

    fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !ready() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    struct StopOnDrop(Arc<DerivedIndexRuntime>);

    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.request_shutdown();
        }
    }

    fn held_prefix() -> (ForkFixture, SeedCellHarness, BodyMap) {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let lost = f.take_bodies(2);
        let tip = f.tip(f.a[1]);
        h.stage_seed_rows(&tip, 32);
        h.set_tip(&tip);
        h.settle_stalled(&mut None);
        assert_eq!(h.watermarks().script_live, Some(at(&tip)));
        h.set_tip(&f.tip(f.a[3]));
        (f, h, lost)
    }

    #[test]
    fn absent_prefix_body_holds_back_only_its_own_group() {
        let (f, h, lost) = held_prefix();
        let a4 = f.tip(f.a[3]);
        let mut pending = None;

        h.settle_stalled(&mut pending);
        let held = h.watermarks();
        assert_eq!(
            held.script_live,
            Some(at(&a4)),
            "the ready group follows the tip past the absent prefix"
        );
        assert_eq!(held.tx_lookup, None);
        assert_eq!(held.script_history, None);

        for _ in 0..3 {
            assert!(matches!(
                h.worker.reconcile_once(&mut pending),
                Ok(ReconcileAction::Stalled)
            ));
        }

        f.restore_bodies(lost);
        h.settle(&mut pending);
        h.assert_at(&a4);
        assert_eq!(h.watermarks().script_live, Some(at(&a4)));
    }

    #[test]
    fn shutdown_after_an_absent_body_does_not_run_a_higher_group() {
        let (f, h, _lost) = held_prefix();
        *f.bodies.stop_on_absent_body.lock() = Some(Arc::clone(&h.runtime));

        assert!(matches!(
            h.worker.reconcile_once(&mut None),
            Ok(ReconcileAction::Stalled)
        ));
        assert!(h.runtime.should_stop());
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&f.tip(f.a[1]))),
            "the stopped pass left the ready group where it was"
        );
    }

    #[test]
    fn deferred_history_grant_does_not_run_a_higher_group() {
        let (f, h, _lost) = held_prefix();
        let mut pending = None;

        let reservation = h.retention.reserve(1);
        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Stalled)
        ));
        assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[1]))));

        drop(reservation);
        h.settle_stalled(&mut pending);
        assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[3]))));
    }

    struct AbsentBody {
        key: (u32, [u8; 32]),
        body: Vec<u8>,
    }

    fn retained_prefix() -> (ForkFixture, SeedCellHarness, AbsentBody) {
        let f = ForkFixture::new(300);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let tip = f.tip(f.a[289]);
        h.stage_seed_rows(&tip, 32);
        h.set_tip(&tip);
        assert!(matches!(
            h.worker.reconcile_once(&mut None),
            Ok(ReconcileAction::Progressed)
        ));
        let key = f.a_key(280);
        let body = f
            .bodies
            .bodies
            .lock()
            .remove(&key)
            .expect("body at height 280");
        h.set_tip(&f.tip(f.a[299]));
        (f, h, AbsentBody { key, body })
    }

    #[test]
    fn retained_prefix_commits_before_any_group_switch_and_never_outlives_a_fence_change() {
        let (f, h, _absent) = retained_prefix();
        let a279 = Some(at(&f.tip(f.a[278])));
        let a290 = Some(at(&f.tip(f.a[289])));
        let mut pending = None;

        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Buffered)
        ));
        assert!(pending.is_some());
        let retained = h.watermarks();
        assert_eq!(retained.tx_lookup, None);
        assert_eq!(retained.script_live, a290);

        let (fence, _) = h.writer.fenced_watermarks().expect("fence");
        h.writer
            .commit_consumer_cursor(fence, &h.worker.chain_events.cursor().to_bytes())
            .expect("foreign commit");
        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Stalled)
        ));
        assert!(pending.is_none());
        let discarded = h.watermarks();
        assert_eq!(discarded.tx_lookup, None);
        assert_eq!(discarded.script_live, a290);

        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Buffered)
        ));
        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Progressed)
        ));
        let flushed = h.watermarks();
        assert_eq!(flushed.tx_lookup, a279);
        assert_eq!(flushed.script_history, a279);
        assert_eq!(flushed.script_live, a290);

        h.settle_stalled(&mut pending);
        let end = h.watermarks();
        assert_eq!(end.script_live, Some(at(&f.tip(f.a[299]))));
        assert_eq!(end.tx_lookup, a279);
    }

    #[test]
    fn run_loop_commits_a_retained_prefix_and_retries_an_absent_body_without_a_wake() {
        let (f, mut h, absent) = retained_prefix();
        h.worker.batch_delay = Duration::from_millis(50);
        h.worker.quiet_period = Duration::from_millis(20);
        let writer = Arc::clone(&h.writer);
        let runtime = Arc::clone(&h.runtime);
        let watermarks = move || writer.fenced_watermarks().expect("watermarks").1;
        let a279 = Some(at(&f.tip(f.a[278])));
        let a300 = Some(at(&f.tip(f.a[299])));

        let worker = h.worker;
        let run = std::thread::spawn(move || worker.run());
        let _cancel = StopOnDrop(Arc::clone(&runtime));

        wait_until("the prefix commit and the ready group", || {
            let marks = watermarks();
            marks.tx_lookup == a279 && marks.script_live == a300
        });
        f.bodies.bodies.lock().insert(absent.key, absent.body);
        wait_until("the history families to catch up", || {
            let marks = watermarks();
            marks.tx_lookup == a300 && marks.script_history == a300 && marks.script_live == a300
        });

        runtime.request_shutdown();
        run.join().expect("worker thread").expect("worker run");
    }

    type LiveCoin = (ScriptHash, [u8; 32], u32, u64, u32, bool);

    struct UnspentCoin {
        script: Vec<u8>,
        value: u64,
        height: u32,
        coinbase: bool,
    }
    type UnspentMap = hashbrown::HashMap<([u8; 32], u32), UnspentCoin>;

    fn unspent_live_coins(blocks: &[bitcoin_rs_storage::CommittedBlock]) -> Vec<LiveCoin> {
        let mut unspent: UnspentMap = hashbrown::HashMap::new();
        for block in blocks {
            if block.height == 0 {
                continue;
            }
            apply_live_block(&mut unspent, block);
        }
        let mut coins: Vec<LiveCoin> = unspent
            .into_iter()
            .map(|((txid, vout), coin)| {
                (
                    ScriptHash::from_script_bytes(&coin.script),
                    txid,
                    vout,
                    coin.value,
                    coin.height,
                    coin.coinbase,
                )
            })
            .collect();
        coins.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        coins
    }

    fn apply_live_block(unspent: &mut UnspentMap, block: &bitcoin_rs_storage::CommittedBlock) {
        for tx in &block.txs {
            let coinbase = tx.inputs.len() == 1
                && tx.inputs[0].txid == [0u8; 32]
                && tx.inputs[0].vout == u32::MAX;
            spend_live_inputs(unspent, tx);
            create_live_outputs(unspent, tx, block.height, coinbase);
        }
    }

    fn spend_live_inputs(unspent: &mut UnspentMap, tx: &bitcoin_rs_storage::TxFacts) {
        for input in &tx.inputs {
            if input.txid == [0u8; 32] && input.vout == u32::MAX {
                continue;
            }
            unspent.remove(&(input.txid, input.vout));
        }
    }

    fn create_live_outputs(
        unspent: &mut UnspentMap,
        tx: &bitcoin_rs_storage::TxFacts,
        height: u32,
        coinbase: bool,
    ) {
        for output in &tx.outputs {
            let admitted = !matches!(output.script.first(), Some(0x6a))
                && output.script.len() <= crate::MAX_LIVE_SCRIPT_SIZE;
            if !admitted {
                continue;
            }
            unspent.insert(
                (tx.txid, output.vout),
                UnspentCoin {
                    script: output.script.to_vec(),
                    value: output.value,
                    height,
                    coinbase,
                },
            );
        }
    }

    // IDX-06, IDX-07
    #[test]
    fn script_live_undo_gap_pauses_the_group_and_resumes_to_bulk() -> Result<(), RecoveryTestError>
    {
        #[derive(Clone, Copy)]
        enum Undo {
            Present,
            Missing,
            Corrupt,
        }
        const MISSING: u32 = 4;
        for undo in [Undo::Present, Undo::Missing, Undo::Corrupt] {
            let f = ForkFixture::new(5);
            f.persist_undo();
            let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
            let (a2, a5) = (f.tip(f.a[1]), f.tip(f.a[4]));
            let seed_blocks = committed_chain(&f, &f.a, 0, 2);
            let staged: Vec<Vec<u8>> = unspent_live_coins(&seed_blocks)
                .iter()
                .map(|(scripthash, txid, vout, value, height, coinbase)| {
                    let outpoint = bitcoin_rs_consensus::primitives::OutPoint::new(
                        bitcoin_rs_consensus::primitives::Txid(Hash256::from_le_bytes(txid)),
                        *vout,
                    );
                    let coin =
                        crate::types::ScriptLiveCoin::new(*scripthash, *value, *height, *coinbase);
                    let row = crate::types::ScriptLiveRow::new(*scripthash, &outpoint);
                    let mut bytes = row.as_bytes().to_vec();
                    let Ok(encoded) = coin.encode_value() else {
                        panic!("the seed coin must encode");
                    };
                    bytes.extend_from_slice(&encoded);
                    bytes
                })
                .collect();
            h.writer.stage_script_live_rows(&mut staged.into_iter())?;
            h.writer
                .publish_script_live_seed(at(&a2))
                .expect("publish seed at h-1");
            h.set_tip(&a2);
            h.settle(&mut None);

            let key = f.a_key(MISSING);
            let original = f.bodies.undo.lock().get(&key).cloned();
            match undo {
                Undo::Present => {}
                Undo::Missing => {
                    f.bodies.undo.lock().remove(&key);
                }
                Undo::Corrupt => {
                    let mut undo = f.bodies.undo.lock();
                    let Some(record) = undo.get_mut(&key) else {
                        panic!("the undo record must exist to corrupt it");
                    };
                    record[0] ^= 0xff;
                }
            }
            assert_eq!(
                h.watermarks().script_live,
                Some(at(&a2)),
                "ScriptLive is seeded at h-1 before the gap"
            );
            h.set_tip(&a5);
            let mut pending = None;
            if matches!(undo, Undo::Present) {
                h.settle(&mut pending);
            } else {
                for _ in 0..64 {
                    match h
                        .worker
                        .reconcile_once(&mut pending)
                        .expect("the pass returns instead of halting")
                    {
                        ReconcileAction::CaughtUp | ReconcileAction::Stalled => break,
                        ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                    }
                }
                let paused = h.watermarks();
                assert_eq!(
                    paused.script_live,
                    Some(at(&a2)),
                    "ScriptLive pauses at h-1 without a reset"
                );
                assert_eq!(
                    paused.tx_lookup, paused.script_history,
                    "the tail group moves together"
                );
                assert!(
                    paused
                        .tx_lookup
                        .is_some_and(|watermark| watermark.height < MISSING),
                    "the tail group stops before the missing height: {paused:?}"
                );
                assert!(h.runtime.script_history_failure.read().is_some());
                assert_eq!(
                    h.runtime.undo_gap().map(|(height, _)| height),
                    Some(MISSING),
                    "the gap names the missing height"
                );
                if let Some(record) = original {
                    f.bodies.undo.lock().insert(key, record);
                }
            }
            h.settle(&mut pending);
            assert_eq!(h.watermarks().tx_lookup, Some(at(&a5)));
            assert_eq!(h.watermarks().script_history, Some(at(&a5)));
            assert_eq!(h.watermarks().script_live, Some(at(&a5)));
            assert!(
                h.runtime.undo_gap().is_none(),
                "the gap clears once the undo row returns"
            );
            assert_chain_matches_bulk(&h.store, &f, 5);
            let snapshot = h.store.snapshot()?;
            let mut live: Vec<LiveCoin> = Vec::new();
            for item in snapshot.iter_prefix(ColumnFamily::ScriptLive, &[])? {
                let (key, value) = item?;
                if key.len() != crate::types::SCRIPT_LIVE_ROW_SIZE {
                    continue;
                }
                let Some(row) = crate::types::ScriptLiveRow::from_db_row(&key) else {
                    return Err(RecoveryTestError::BadLiveRow);
                };
                let outpoint = row.outpoint();
                let coin = crate::types::ScriptLiveCoin::decode_value(&value)?;
                live.push((
                    coin.scripthash,
                    *outpoint.txid.as_bytes(),
                    outpoint.vout,
                    coin.value,
                    coin.height,
                    coin.coinbase,
                ));
            }
            live.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
            assert_eq!(
                live,
                unspent_live_coins(&committed_chain(&f, &f.a, 0, 5)),
                "ScriptLive contents equal the unspent set at the tip"
            );
        }
        Ok(())
    }

    // IDX-06
    #[test]
    fn anchor_failure_outranks_an_earlier_preparation_failure() {
        let f = ForkFixture::new(6);
        f.persist_undo();
        let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
        h.set_tip(&f.tip(f.a[1]));
        h.settle(&mut None);

        f.bodies.bodies.lock().insert(f.a_key(3), vec![0; 10]);
        f.bodies.undo.lock().remove(&f.a_key(5));
        h.set_tip(&f.tip(f.a[5]));

        assert!(matches!(
            h.worker.reconcile_once(&mut None),
            Ok(ReconcileAction::Progressed)
        ));
        assert_eq!(
            h.runtime.undo_gap().map(|(height, _)| height),
            Some(5),
            "the anchor failure at height 5 is the recorded gap"
        );
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&f.tip(f.a[1]))),
            "block 3 cannot be prepared, so ScriptLive stops at height 2"
        );
    }

    #[test]
    fn preparation_failure_keeps_its_height_after_committed_successes() {
        let f = ForkFixture::new(6);
        f.persist_undo();
        let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
        h.set_tip(&f.tip(f.a[1]));
        h.settle(&mut None);

        f.bodies.bodies.lock().insert(f.a_key(4), vec![0; 10]);
        h.worker.batch_limits = PreparedBatchLimits {
            max_rows: 1,
            max_bytes: BATCH_BYTE_LIMIT,
        };
        h.set_tip(&f.tip(f.a[5]));
        let mut pending = None;

        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Ok(ReconcileAction::Progressed)
        ));
        let committed = Some(at(&f.tip(f.a[2])));
        assert_eq!(h.watermarks().script_live, committed);
        assert!(matches!(
            h.worker.reconcile_once(&mut pending),
            Err(DerivedIndexWorkerError::Index(IndexError::BlockParse(_)))
        ));
        assert_eq!(h.watermarks().script_live, committed);
    }

    // IDX-07
    #[test]
    fn undo_read_failure_is_not_a_missing_undo() {
        let f = ForkFixture::new(5);
        f.persist_undo();
        let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::SCRIPT_LIVE);
        h.set_tip(&f.tip(f.a[1]));
        h.settle(&mut None);

        f.bodies.undo_read_failures.lock().insert(f.a_key(4));
        f.bodies.undo.lock().remove(&f.a_key(5));
        h.set_tip(&f.tip(f.a[4]));

        assert!(matches!(
            h.worker.reconcile_once(&mut None),
            Err(DerivedIndexWorkerError::Storage(_))
        ));
        assert_eq!(h.watermarks().script_live, Some(at(&f.tip(f.a[1]))));
    }

    // IDX-07
    #[test]
    fn script_live_pruned_terminal_keeps_worker_alive() {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        h.set_tip(&f.tip(f.a[0]));
        let mut pending = None;
        h.settle(&mut pending);
        h.assert_at(&f.tip(f.a[0]));

        h.retention.reserve(3).commit(3);
        h.set_tip(&f.tip(f.a[2]));
        let mut flagged = false;
        for _ in 0..16 {
            match h.worker.reconcile_once(&mut pending).expect("prune pass") {
                ReconcileAction::CaughtUp
                | ReconcileAction::Progressed
                | ReconcileAction::Buffered
                | ReconcileAction::Stalled => {}
            }
            assert!(!h.runtime.should_stop(), "worker stays alive");
            assert!(
                h.runtime.failure_message().is_none(),
                "no global worker failure"
            );
            if let Some(outage) = h.runtime.script_live_failure() {
                assert_eq!(
                    outage,
                    ScriptLiveOutage::HistoryPruned,
                    "pruned history is the terminal ScriptLive reason"
                );
                flagged = true;
            }
        }
        assert!(flagged, "pruned frontier raises terminal unavailable");
        let t = f.tip(f.a[2]);
        assert_eq!(
            h.watermarks().tx_lookup,
            Some(at(&t)),
            "other groups progress"
        );
        assert_eq!(h.watermarks().script_history, Some(at(&t)));
        assert_eq!(
            h.watermarks().script_live,
            None,
            "live waits for a replacement artifact after the old view is reset"
        );
        let mut converged_once = false;
        for _ in 0..16 {
            match h.worker.reconcile_once(&mut pending).expect("replay pass") {
                ReconcileAction::CaughtUp
                | ReconcileAction::Progressed
                | ReconcileAction::Buffered
                | ReconcileAction::Stalled => {}
            }
            assert!(!h.runtime.should_stop(), "worker stays alive");
            assert!(
                h.runtime.failure_message().is_none(),
                "no global worker failure"
            );
            if h.watermarks().tx_lookup == Some(at(&t))
                && h.watermarks().script_history == Some(at(&t))
            {
                converged_once = true;
            }
        }
        assert!(converged_once, "other groups converge");

        h.stage_seed_rows(&t, 32);
        h.settle(&mut pending);
        assert!(
            h.runtime.script_live_failure().is_none(),
            "take clears the flag"
        );
        assert_eq!(h.watermarks().script_live, Some(at(&t)));
        h.assert_at(&t);
    }

    // IDX-06
    #[test]
    fn seed_first_leg_runs_under_the_held_history_pin() {
        let registry = Arc::new(RetentionRegistry::new());
        let access = HistoryAccess::new(Arc::clone(&registry), RetentionBudget::Depth(288));
        let lease = access.request_history(2).expect("grant at 2");
        assert_eq!(lease.floor(), Some(2));
        assert_eq!(registry.active_leases(), 1);
        lease.advance(4);
        assert_eq!(lease.floor(), Some(4), "progress moves the pin");
        drop(lease);
        assert_eq!(registry.retention_floor(), None);
        assert_eq!(registry.active_leases(), 0);

        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let h_tip = f.tip(f.a[1]);
        h.stage_seed_rows(&h_tip, 32);
        h.set_tip(&f.tip(f.a[3]));
        let absent = f.a_key(3);
        let withheld = f
            .bodies
            .bodies
            .lock()
            .remove(&absent)
            .expect("withheld body");
        let mut pending = None;
        let first = h.worker.reconcile_once(&mut pending).expect("take");
        assert!(
            !matches!(first, ReconcileAction::CaughtUp),
            "take plus seed never completes the pass"
        );
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&h_tip)),
            "seed commits H before the first leg"
        );
        for _ in 0..16 {
            match h.worker.reconcile_once(&mut pending).expect("stalled leg") {
                ReconcileAction::CaughtUp
                | ReconcileAction::Progressed
                | ReconcileAction::Buffered
                | ReconcileAction::Stalled => {}
            }
            assert!(
                h.retention.active_leases() <= 1,
                "a stalled leg holds at most the single pin"
            );
            assert!(h.runtime.failure_message().is_none());
        }
        f.bodies.bodies.lock().insert(absent, withheld);
        h.settle(&mut pending);
        let t = f.tip(f.a[3]);
        assert_eq!(h.watermarks().script_live, Some(at(&t)));
        h.assert_at(&t);
        assert_eq!(h.retention.active_leases(), 0, "progress past H releases");
        assert_eq!(h.retention.retention_floor(), None);
    }

    pub(super) struct SeedCellHarness {
        _index_dir: tempfile::TempDir,
        store: Arc<RocksDbStore>,
        writer: Arc<dyn TxIndexWriter>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        pub(super) runtime: Arc<DerivedIndexRuntime>,
        retention: Arc<RetentionRegistry>,
        worker: Worker,
    }

    impl SeedCellHarness {
        pub(super) fn new(fixture: &ForkFixture, enabled: IndexCapabilities) -> Self {
            let index_dir = tempfile::tempdir().expect("index dir");
            let store = Arc::new(RocksDbStore::open(index_dir.path()).expect("rocksdb open"));
            let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
                crate::IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
            ));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
            let runtime = DerivedIndexRuntime::new(wake_tx);
            let reporter: Arc<dyn IndexAheadSink> = RecordedIndexAhead::new();
            let body_store: Arc<dyn BlockBodyStore> = fixture.bodies.clone();
            let retention = Arc::new(RetentionRegistry::new());
            let worker = Worker {
                runtime: Arc::clone(&runtime),
                writer: Arc::clone(&writer),
                applied_tip: bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&applied_tip)),
                block_tree: bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(
                    &fixture.tree,
                )),
                body_store: Some(body_store),
                history: HistoryAccess::new(Arc::clone(&retention), RetentionBudget::Depth(288)),
                batch_limits: DEFAULT_BATCH_LIMITS,
                enabled,
                chain_events: Arc::new(TestChainCursor),
                reporter,
                shutdown: bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
                wake_rx,
                quiet_period: Duration::ZERO,
                batch_delay: Duration::ZERO,
                rollback_rebuild_cutover: u32::MAX,
                seed_history_lease: parking_lot::Mutex::new(None),
                facts_rx: None,
                facts_charge: None,
                facts_gap: None,
                cpu: None,
                buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
            };
            Self {
                _index_dir: index_dir,
                store,
                writer,
                applied_tip,
                runtime,
                retention,
                worker,
            }
        }

        pub(super) fn stage_seed_rows(&self, tip: &TipSnapshot, count: u64) {
            let session = self
                .runtime
                .script_live_seed()
                .begin_session()
                .expect("seed session open");
            {
                let mut observer = session.observer();
                for i in 0..count {
                    let mut txid = [0_u8; 32];
                    txid[..8].copy_from_slice(&i.to_le_bytes());
                    observer.observe_coin(bitcoin_rs_storage::utxo::SnapshotCoin {
                        txid: Hash256::from_le_bytes(&txid),
                        vout: 0,
                        value: 1_000 + i,
                        script_pubkey: &[0x51],
                        height: tip.height,
                        coinbase: false,
                    });
                }
            }
            assert!(session.take_error().is_none(), "staging must not fail");
            session.publish(IndexWatermark {
                height: tip.height,
                hash: tip.hash.to_le_bytes(),
            });
        }

        pub(super) fn set_tip(&self, tip: &Arc<TipSnapshot>) {
            self.applied_tip.store(Some(Arc::clone(tip)));
        }

        fn settle_stalled(&self, pending: &mut Option<PendingForward>) {
            for _ in 0..16 {
                match self.worker.reconcile_once(pending).expect("reconcile pass") {
                    ReconcileAction::Stalled => return,
                    ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                    ReconcileAction::CaughtUp => {
                        panic!("a capability still owed rows is caught up")
                    }
                }
            }
            panic!("worker kept progressing instead of waiting");
        }

        pub(super) fn watermarks(&self) -> IndexWatermarks {
            self.writer.fenced_watermarks().expect("watermarks").1
        }

        pub(super) fn live_row_count(&self) -> usize {
            self.store
                .iter_prefix(ColumnFamily::ScriptLive, &[])
                .expect("live scan")
                .filter_map(std::result::Result::ok)
                .count()
        }

        pub(super) fn stalled_pass(&self, pending: &mut Option<PendingForward>) -> bool {
            matches!(
                self.worker.reconcile_once(pending).expect("reconcile pass"),
                ReconcileAction::Stalled
            )
        }

        pub(super) fn assert_at(&self, tip: &TipSnapshot) {
            let expected = Some(IndexWatermark {
                height: tip.height,
                hash: tip.hash.to_le_bytes(),
            });
            let watermarks = self.watermarks();
            assert_eq!(watermarks.tx_lookup, expected, "tx_lookup watermark");
            assert_eq!(
                watermarks.script_history, expected,
                "script_history watermark"
            );
        }

        pub(super) fn settle(&self, pending: &mut Option<PendingForward>) {
            for _ in 0..64 {
                assert!(
                    self.retention.active_leases() <= 1,
                    "single live history pin at every instant"
                );
                match self.worker.reconcile_once(pending).expect("reconcile pass") {
                    ReconcileAction::CaughtUp => return,
                    ReconcileAction::Progressed | ReconcileAction::Buffered => {}
                    ReconcileAction::Stalled => panic!("worker stalled"),
                }
            }
            panic!("worker did not converge");
        }
    }

    // EVT-03
    #[test]
    fn malformed_stored_consumer_cursor_never_causes_panic_and_overwrites_cleanly()
    -> Result<(), RecoveryTestError> {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
        let mut tip = (*f.tip(f.a[0])).clone();
        tip.height = 0;
        tip.hash = Hash256::from_le_bytes(&[0; 32]);
        h.applied_tip.store(Some(Arc::new(tip)));
        let expected = IndexWatermark {
            height: 0,
            hash: [0; 32],
        };
        h.writer
            .anchor_watermark(IndexCapabilities::TX_LOOKUP, expected, 0)
            .expect("anchor");

        let mut fixed = [0u8; crate::reconcile::CURSOR_BYTE_LEN];
        fixed[..8].copy_from_slice(&0u64.to_le_bytes());
        fixed[8..16].copy_from_slice(&0u64.to_le_bytes());
        fixed[16..20].copy_from_slice(&0u32.to_le_bytes());
        fixed[20..].copy_from_slice(&[0u8; 32]);
        for malformed in [
            &b""[..],
            &b"\xff"[..],
            &b"corrupt-cursor-bytes"[..],
            &[0xaa; 51][..],
            &[0xbb; crate::reconcile::CURSOR_BYTE_LEN][..],
        ] {
            let (fence, _) = h.writer.fenced_watermarks().expect("fence");
            h.writer
                .commit_consumer_cursor(fence, malformed)
                .expect("commit malformed cursor");

            let commit = h
                .worker
                .persist_chain_cursor()
                .expect("persist must not panic on malformed cursor");
            assert!(matches!(commit, CursorCommit::Settled));

            let stored = h
                .writer
                .consumer_cursor()
                .expect("read cursor")
                .expect("cursor exists");
            assert_eq!(
                stored.len(),
                52,
                "the durable cursor is exactly the EVT-03 layout"
            );
            assert_eq!(stored, fixed, "the overwrite pins the EVT-03 field order");
        }
        let (fence, _) = h.writer.fenced_watermarks().expect("fence");
        for oversized in [
            &[0xbb; crate::reconcile::CURSOR_BYTE_LEN + 1][..],
            &[0xcc; 1024][..],
        ] {
            assert!(
                matches!(
                    h.writer.commit_consumer_cursor(fence, oversized),
                    Err(crate::IndexError::CursorLength { .. })
                ),
                "a cursor wider than the reserved width is refused before any write"
            );
        }
        assert_eq!(
            h.writer.consumer_cursor()?,
            Some(fixed.to_vec()),
            "an oversized cursor is refused before any write"
        );
        Ok(())
    }

    // PRJ-04
    #[test]
    fn buffered_facts_below_index_progress_are_evicted() {
        use bitcoin_rs_storage::CommittedBlock;

        let f = ForkFixture::new(2);
        let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
        let (_facts_tx, facts_rx) = crossbeam_channel::bounded(8);
        h.worker.facts_rx = Some(facts_rx);

        let a2 = f.tip(f.a[1]);
        let identities = h
            .worker
            .collect_target_chain(&a2, 1, 2)
            .expect("target chain from height one");
        let stale = CommittedBlock {
            height: 0,
            hash: [0x77; 32],
            parent_hash: [0_u8; 32],
            header: [0_u8; 80],
            txs: Vec::new(),
        };
        let window = CommittedBlock {
            height: identities[0].height,
            hash: identities[0].hash,
            parent_hash: identities[0].parent_hash,
            header: [0_u8; 80],
            txs: Vec::new(),
        };
        let stale_key = (stale.hash, stale.height);
        let window_key = (window.hash, window.height);
        {
            let mut guard = h.worker.buffered_facts.lock();
            guard.insert(stale_key, stale);
            guard.insert(window_key, window);
        }

        let prepared = h
            .worker
            .try_prepare_from_facts(&identities, IndexCapabilities::TX_LOOKUP)
            .expect("facts preparation");
        assert_eq!(
            prepared.map(|blocks| blocks.len()),
            Some(1),
            "the fact inside the requested window must serve the fast path"
        );
        let guard = h.worker.buffered_facts.lock();
        assert!(
            !guard.contains_key(&stale_key),
            "facts below the requested height must be evicted instead of accumulating"
        );
        assert!(
            guard.contains_key(&window_key),
            "a fact stays buffered until admission consumes it"
        );
        drop(guard);
    }

    // BUD-06, BUD-07
    #[test]
    fn buffered_facts_hold_their_charge_while_the_queue_refills() {
        use bitcoin_rs_storage::CommittedBlock;
        use bitcoin_rs_storage::CommittedFacts;
        use bitcoin_rs_storage::budget::BudgetCharge;
        use bitcoin_rs_storage::budget::BudgetError;
        use bitcoin_rs_storage::budget::BudgetOwner;
        use bitcoin_rs_storage::budget::ChargeHandle;
        use std::sync::Mutex as StdMutex;

        struct Ledger {
            outstanding: StdMutex<u64>,
            capacity: u64,
        }
        impl BudgetCharge for Ledger {
            fn reserve_bytes(&self, _: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
                let mut outstanding = self.outstanding.lock().expect("ledger lock");
                let next = outstanding.saturating_add(bytes);
                if next > self.capacity {
                    return Err(BudgetError::BudgetExhausted);
                }
                *outstanding = next;
                Ok(())
            }
            fn allocate_bytes(&self, _: BudgetOwner, _: u64) -> Result<(), BudgetError> {
                Ok(())
            }
            fn release_bytes(&self, _: BudgetOwner, bytes: u64) {
                let mut outstanding = self.outstanding.lock().expect("ledger lock");
                *outstanding = outstanding.saturating_sub(bytes);
            }
            fn available_bytes(&self, _: BudgetOwner) -> u64 {
                self.capacity - *self.outstanding.lock().expect("ledger lock")
            }
        }

        fn probe_block(height: u32, hash: u8) -> CommittedBlock {
            CommittedBlock {
                height,
                hash: [hash; 32],
                parent_hash: [hash.wrapping_sub(1); 32],
                header: [0_u8; 80],
                txs: Vec::new(),
            }
        }

        let f = ForkFixture::new(2);
        let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
        let facts = Arc::new(CommittedFacts {
            commit_id: 1,
            blocks: vec![probe_block(1, 1)],
        });
        let facts_size = facts.size_bytes();
        let capacity = facts_size * 4;
        let ledger: Arc<dyn BudgetCharge> = Arc::new(Ledger {
            outstanding: StdMutex::new(0),
            capacity,
        });
        let charge = ChargeHandle::new(Arc::clone(&ledger), BudgetOwner::FactsQueue);
        let (facts_tx, facts_rx) = crossbeam_channel::bounded(8);
        h.worker.facts_rx = Some(facts_rx);
        h.worker.facts_charge = Some(charge.clone());

        let mut refused = false;
        for index in 0..16_u8 {
            if charge.charge(facts_size).is_err() {
                refused = true;
                break;
            }
            if facts_tx
                .send(Arc::new(CommittedFacts {
                    commit_id: u64::from(index) + 2,
                    blocks: vec![probe_block(1, index + 2)],
                }))
                .is_err()
            {
                break;
            }
            let prepared = h
                .worker
                .try_prepare_from_facts(&[], IndexCapabilities::TX_LOOKUP)
                .expect("facts drain");
            assert!(prepared.is_none(), "no identities requested");
        }
        assert!(
            refused,
            "the sender budget must refuse while buffered facts are retained without a charge"
        );

        let buffered: u64 = h
            .worker
            .buffered_facts
            .lock()
            .values()
            .map(|block| block.size_bytes())
            .sum();
        assert_eq!(
            ledger.available_bytes(BudgetOwner::FactsQueue),
            capacity - buffered,
            "every retained buffered block must hold a ledger charge"
        );
    }

    // IDX-06
    #[test]
    fn facts_batch_overflow_keeps_the_unadmitted_suffix() {
        let f = ForkFixture::new(4);
        let mut h = Harness::with_enabled(&f, u32::MAX, IndexCapabilities::TX_LOOKUP);
        let blocks = committed_chain(&f, &f.a, 0, 2);
        f.bodies.bodies.lock().clear();
        let tip = f.tip(f.a[1]);
        h.set_tip(&tip);
        let (facts_tx, facts_rx) = crossbeam_channel::bounded(8);
        h.worker.facts_rx = Some(facts_rx);
        h.worker.batch_limits = PreparedBatchLimits {
            max_rows: 1,
            max_bytes: usize::MAX,
        };
        for (index, block) in blocks.iter().enumerate() {
            facts_tx
                .send(Arc::new(bitcoin_rs_storage::CommittedFacts {
                    commit_id: u64::try_from(index).expect("index fits") + 1,
                    blocks: vec![block.clone()],
                }))
                .expect("facts send");
        }
        let mut pending = None;
        for _ in 0..8 {
            if matches!(
                h.worker.reconcile_once(&mut pending).expect("reconcile"),
                ReconcileAction::CaughtUp
            ) {
                break;
            }
        }
        assert_eq!(
            h.watermarks().tx_lookup,
            Some(IndexWatermark {
                height: 2,
                hash: blocks[2].hash,
            }),
            "every facts block must reach the watermark despite the one-row batch limit"
        );
    }

    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    const SEGMENT_FAMILIES: [ColumnFamily; 6] = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];

    fn sealed_at(store: &RocksDbStore) -> Vec<crate::segment::SealedGen> {
        let snapshot = store.snapshot().expect("snapshot");
        crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)
            .expect("sealed generations")
    }

    fn generation_rows(
        store: &RocksDbStore,
        sealed_id: u64,
    ) -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
        let snapshot = store.snapshot().expect("snapshot");
        let prefix = sealed_id.to_be_bytes();
        let mut rows = Vec::new();
        for cf in SEGMENT_FAMILIES {
            for item in snapshot.iter_prefix(cf, &prefix).expect("scan") {
                let (key, value) = item.expect("row");
                rows.push((cf, key, value));
            }
        }
        rows
    }

    type CreatedCoin = (Vec<u8>, u64, u32, bool);

    #[derive(Default)]
    struct CreatedCoinMap(HashMap<([u8; 32], u32), CreatedCoin>);

    impl CreatedCoinMap {
        fn insert_block(&mut self, block: &bitcoin_rs_storage::CommittedBlock) {
            for tx in &block.txs {
                let coinbase = tx.inputs.is_empty();
                for output in &tx.outputs {
                    self.0.insert(
                        (tx.txid, output.vout),
                        (output.script.to_vec(), output.value, block.height, coinbase),
                    );
                }
            }
        }
    }

    impl crate::index::SpentCoins for CreatedCoinMap {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<crate::index::SpentCoin<'_>> {
            self.0
                .get(&(*txid, vout))
                .map(
                    |(script, value, height, coinbase)| crate::index::SpentCoin {
                        script,
                        value: *value,
                        height: *height,
                        coinbase: *coinbase,
                    },
                )
        }
    }

    fn committed_chain(
        f: &ForkFixture,
        branch: &[(NodeId, Hash256)],
        first_height: u32,
        last_height: u32,
    ) -> Vec<bitcoin_rs_storage::CommittedBlock> {
        let bodies = f.bodies.bodies.lock();
        let mut created = CreatedCoinMap::default();
        let mut out = Vec::new();
        for height in 0..=last_height {
            let index = usize::try_from(height).expect("height fits usize");
            let hash = if height == 0 {
                f.genesis
            } else {
                branch[index - 1].1
            };
            let parent = match height {
                0 => Hash256::from_le_bytes(&[0_u8; 32]),
                1 => f.genesis,
                _ => branch[index - 2].1,
            };
            let body = bodies
                .get(&(height, hash.to_le_bytes()))
                .expect("fixture body");
            let image = crate::index::parse_body(body).expect("fixture body parses");
            let block = {
                let facts = crate::index::BodyFacts {
                    height,
                    needs_scripts: true,
                    spent_coins: &created,
                };
                crate::index::committed_block_from_image(
                    &image,
                    hash.to_le_bytes(),
                    parent.to_le_bytes(),
                    &facts,
                )
                .expect("committed block")
            };
            let parsed: bitcoin::Block = match bitcoin::consensus::encode::deserialize(body) {
                Ok(block) => block,
                Err(_) => panic!("the fixture body must deserialize as a consensus block"),
            };
            assert_eq!(
                block.txs.len(),
                parsed.txdata.len(),
                "the image parse and the consensus decode agree on the tx count"
            );
            for (tx, parsed_tx) in block.txs.iter().zip(&parsed.txdata) {
                assert_eq!(
                    tx.txid,
                    parsed_tx.compute_txid().to_byte_array(),
                    "the txid matches the consensus crate"
                );
            }
            created.insert_block(&block);
            if height >= first_height {
                out.push(block);
            }
        }
        out
    }

    fn assert_sealed_matches_bulk(
        store: &RocksDbStore,
        f: &ForkFixture,
        branch: &[(NodeId, Hash256)],
    ) {
        let sealed = sealed_at(store);
        assert_eq!(
            sealed.len(),
            1,
            "one tail-bound seal publishes one generation"
        );
        let segment = sealed[0];
        let blocks = committed_chain(
            f,
            branch,
            segment.coverage.first_height,
            segment.coverage.last_height,
        );
        let bulk_dir = tempfile::tempdir().expect("bulk dir");
        let scratch = tempfile::tempdir().expect("bulk scratch");
        let bulk_store = RocksDbStore::open(bulk_dir.path()).expect("bulk store");
        let builder = crate::segment::bulk_builder::BulkSegmentBuilder::new(
            Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .without_filter();
        let bulk_builder_coverage = builder
            .build_and_ingest(&bulk_store, segment.gen_id, &blocks)
            .expect("bulk build");
        assert_eq!(
            bulk_builder_coverage, segment.coverage,
            "bulk coverage matches the sealed segment"
        );
        let sealed_rows = generation_rows(store, segment.gen_id);
        let bulk_rows = generation_rows(&bulk_store, segment.gen_id);
        let per_family = |rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)]| {
            SEGMENT_FAMILIES
                .iter()
                .map(|cf| rows.iter().filter(|row| row.0 == *cf).count())
                .collect::<Vec<_>>()
        };
        let posting_items = |rows: &[(ColumnFamily, Vec<u8>, Vec<u8>)]| {
            rows.iter()
                .filter(|row| row.0 == ColumnFamily::ScriptPost)
                .map(|row| {
                    crate::segment::format::decode_posting_items(&row.2)
                        .map_or(0, |items| items.len())
                })
                .sum::<usize>()
        };
        assert_eq!(
            posting_items(&sealed_rows),
            posting_items(&bulk_rows),
            "posting items"
        );
        assert_eq!(
            per_family(&sealed_rows),
            per_family(&bulk_rows),
            "per-family row counts"
        );
        if let Some(index) = sealed_rows
            .iter()
            .zip(bulk_rows.iter())
            .position(|(a, b)| a != b)
        {
            let (sealed_cf, sealed_key, sealed_value) = &sealed_rows[index];
            let (bulk_cf, bulk_key, bulk_value) = &bulk_rows[index];
            panic!(
                "first differing sealed row {index}: sealed {sealed_cf:?} {sealed_key:?} ({} bytes) != bulk {bulk_cf:?} {bulk_key:?} ({} bytes)",
                sealed_value.len(),
                bulk_value.len()
            );
        }
    }

    // PRJ-05
    #[test]
    fn sync_past_the_tail_bound_seals_one_generation_equal_to_bulk() {
        let f = ForkFixture::new(2100);
        f.persist_undo();
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let tip = f.tip(f.a[2099]);
        h.set_tip(&tip);
        h.settle(&mut pending);
        h.assert_at(&tip);
        assert_sealed_matches_bulk(&h.store, &f, &f.a);
    }

    // REO-04
    #[test]
    fn deep_reorg_through_the_runtime_retires_exactly_the_affected_generation() {
        let f = ForkFixture::new(2100);
        f.persist_undo();
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let a = f.tip(f.a[2099]);
        h.set_tip(&a);
        h.settle(&mut pending);
        h.assert_at(&a);
        let affected = sealed_at(&h.store);
        assert_eq!(affected.len(), 1, "the sync seals one generation");
        let affected_id = affected[0].gen_id;
        assert!(!generation_rows(&h.store, affected_id).is_empty());

        let b = f.tip(f.b[2099]);
        h.set_tip(&b);
        h.settle(&mut pending);
        h.assert_at(&b);
        assert!(
            sealed_at(&h.store)
                .iter()
                .all(|segment| segment.gen_id != affected_id),
            "the affected generation leaves the published set"
        );
        let left: Vec<ColumnFamily> = generation_rows(&h.store, affected_id)
            .iter()
            .map(|(cf, _, _)| *cf)
            .collect();
        assert!(left.is_empty(), "affected rows left in {left:?}");
        assert_answers_match_bulk(&h.store, &f, &f.b, 1, 2100);
    }

    // RCV-04
    #[test]
    fn crash_between_seal_steps_recovers_on_reopen() -> Result<(), RecoveryTestError> {
        use crate::segment::{SealFault, arm_seal_fault};
        let f = ForkFixture::new(2100);
        f.persist_undo();
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let tip = f.tip(f.a[2099]);
        h.set_tip(&tip);
        arm_seal_fault(Some(SealFault::AfterCommitted));
        let mut failed = false;
        for _ in 0..64 {
            match h.worker.reconcile_once(&mut pending) {
                Ok(ReconcileAction::CaughtUp) => break,
                Ok(_) => {}
                Err(DerivedIndexWorkerError::Index(crate::IndexError::InjectedFault {
                    stage: "seal",
                })) => {
                    failed = true;
                    break;
                }
                Err(other) => {
                    panic!("the seal fault must surface as the injected seal fault, got {other:?}")
                }
            }
        }
        arm_seal_fault(None);
        assert!(failed, "the injected seal fault must surface");
        let Harness {
            _index_dir: index_dir,
            store,
            writer,
            worker,
            ..
        } = h;
        drop(worker);
        drop(writer);
        drop(store);
        let store = Arc::new(RocksDbStore::open(index_dir.path())?);
        let h = Harness::on_store(
            &f,
            u32::MAX,
            IndexCapabilities::HISTORICAL,
            index_dir,
            store,
        );
        h.set_tip(&tip);
        let mut pending = None;
        h.settle(&mut pending);
        h.assert_at(&tip);
        assert_eq!(
            sealed_at(&h.store).len(),
            1,
            "recovery publishes one generation"
        );
        assert_sealed_matches_bulk(&h.store, &f, &f.a);
        Ok(())
    }

    type TxAnswer = (Vec<(u32, TxPosition)>, Vec<Vec<(Vec<u8>, Vec<u8>)>>);

    struct BulkOracle {
        _dirs: (tempfile::TempDir, tempfile::TempDir),
        store: RocksDbStore,
    }

    fn bulk_oracle(blocks: &[bitcoin_rs_storage::CommittedBlock]) -> BulkOracle {
        let bulk_dir = tempfile::tempdir().expect("bulk dir");
        let scratch = tempfile::tempdir().expect("bulk scratch");
        let store = RocksDbStore::open(bulk_dir.path()).expect("bulk store");
        let builder = crate::segment::bulk_builder::BulkSegmentBuilder::new(
            Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        );
        let coverage = builder
            .build_and_ingest(&store, 1, blocks)
            .expect("bulk build");
        let next_ordinal: usize = blocks.iter().map(|block| block.txs.len()).sum();
        crate::segment::publish_sealed(
            &store,
            1,
            coverage,
            u32::try_from(next_ordinal).expect("ordinal count"),
            IndexCapabilities::HISTORICAL,
        )
        .expect("publish bulk generation");
        BulkOracle {
            _dirs: (bulk_dir, scratch),
            store,
        }
    }

    fn winner_answers(
        view: &crate::segment::SegmentSnapshot<'_>,
        blocks: &[bitcoin_rs_storage::CommittedBlock],
    ) -> Vec<TxAnswer> {
        let mut answers = Vec::new();
        let mut histories = std::collections::HashMap::new();
        for block in blocks {
            for tx in &block.txs {
                let txid = bitcoin_rs_consensus::primitives::Txid(Hash256::from_le_bytes(&tx.txid));
                let positions = view.tx_answer_for_test(&txid).expect("tx answer");
                let outputs = tx
                    .outputs
                    .iter()
                    .map(|output| {
                        let hash = ScriptHash::from_script_bytes(&output.script);
                        histories
                            .entry(hash.to_byte_array())
                            .or_insert_with(|| {
                                view.history_answer_for_test(hash).expect("history answer")
                            })
                            .clone()
                    })
                    .collect();
                answers.push((positions, outputs));
            }
        }
        answers
    }

    fn audited_height(height: u32, cut: u32, rewound_from: u32) -> bool {
        height.is_multiple_of(500)
            || height.abs_diff(cut) <= 1
            || height.saturating_add(2) >= rewound_from
    }

    fn assert_answers_match_bulk(
        live: &RocksDbStore,
        f: &ForkFixture,
        winner: &[(NodeId, Hash256)],
        rewound_from: u32,
        tip: u32,
    ) {
        let cut = tip - crate::segment::format::REORG_WINDOW_BLOCKS;
        let blocks = committed_chain(f, winner, 0, tip);
        let oracle = bulk_oracle(&blocks);
        let audited: Vec<bitcoin_rs_storage::CommittedBlock> = blocks
            .iter()
            .filter(|block| audited_height(block.height, cut, rewound_from))
            .cloned()
            .collect();
        let bulk_view =
            crate::segment::SegmentSnapshot::open(oracle.store.snapshot().expect("bulk snapshot"))
                .expect("bulk view");
        let live_view =
            crate::segment::SegmentSnapshot::open(live.snapshot().expect("live snapshot"))
                .expect("live view");
        let live_answers = winner_answers(&live_view, &audited);
        let bulk_answers = winner_answers(&bulk_view, &audited);
        assert_eq!(
            live_answers, bulk_answers,
            "winning chain answers equal the bulk build over the same blocks"
        );
        let rewound = committed_chain(f, &f.a, rewound_from, tip);
        let rewound_live = winner_answers(&live_view, &rewound);
        assert_eq!(
            rewound_live,
            winner_answers(&bulk_view, &rewound),
            "rewound blocks answer as the bulk build does"
        );
        assert!(
            rewound_live
                .iter()
                .all(|(positions, _)| positions.is_empty()),
            "rewound transactions leave no tx lookup answer"
        );
    }

    // PRJ-05, REO-04
    #[test]
    fn shallow_reorg_after_seal_keeps_the_segment_and_rewinds_the_tail() {
        const TIP: u32 = 2100;
        const FORK: u32 = 2098;
        let f = ForkFixture::new(TIP);
        f.persist_undo();
        let winner = f.fork_from_a(FORK, TIP);
        f.persist_branch_undo(&winner);
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let first = f.tip(f.a[usize::try_from(TIP - 1).expect("index")]);
        h.set_tip(&first);
        h.settle(&mut pending);
        h.assert_at(&first);
        let sealed = sealed_at(&h.store);
        assert_eq!(sealed.len(), 1, "the sync seals one stable prefix");
        let segment = sealed[0];
        assert_eq!(segment.coverage.first_height, 0);
        assert!(
            segment.coverage.last_height < FORK,
            "the fork lies above the sealed coverage"
        );
        let sealed_rows = generation_rows(&h.store, segment.gen_id);

        let reorged = f.tip(winner[usize::try_from(TIP - 1).expect("index")]);
        h.set_tip(&reorged);
        h.settle(&mut pending);
        h.assert_at(&reorged);
        assert_eq!(
            sealed_at(&h.store),
            sealed,
            "the sealed segment stays published"
        );
        assert_eq!(
            generation_rows(&h.store, segment.gen_id),
            sealed_rows,
            "sealed rows are untouched by the shallow reorg"
        );
        assert_answers_match_bulk(&h.store, &f, &winner, FORK + 1, TIP);
    }

    // PRJ-05, REO-04
    #[test]
    fn reorg_past_the_retained_tail_retires_the_newest_segment_and_matches_bulk() {
        const TIP: u32 = crate::segment::format::TAIL_MAX_BLOCKS;
        const FORK: u32 = crate::segment::format::TAIL_MAX_BLOCKS
            - crate::segment::format::REORG_WINDOW_BLOCKS
            - 2;
        let f = ForkFixture::new(TIP);
        f.persist_undo();
        let winner = f.fork_from_a(FORK, TIP);
        f.persist_branch_undo(&winner);
        let h = Harness::new(&f, u32::MAX);
        let mut pending = None;
        let first = f.tip(f.a[usize::try_from(TIP - 1).expect("index")]);
        h.set_tip(&first);
        h.settle(&mut pending);
        h.assert_at(&first);
        let sealed = sealed_at(&h.store);
        assert_eq!(sealed.len(), 1, "the sync seals one stable prefix");
        let retired = sealed[0].gen_id;
        assert!(
            sealed[0].coverage.last_height > FORK,
            "the fork lands inside the newest sealed segment"
        );

        let reorged = f.tip(winner[usize::try_from(TIP - 1).expect("index")]);
        h.set_tip(&reorged);
        h.settle(&mut pending);
        h.assert_at(&reorged);
        assert!(
            sealed_at(&h.store)
                .iter()
                .all(|segment| segment.gen_id != retired),
            "the newest segment leaves the published set"
        );
        assert!(
            generation_rows(&h.store, retired).is_empty(),
            "retired rows are gone"
        );
        assert_answers_match_bulk(&h.store, &f, &winner, FORK + 1, TIP);
    }
}

#[cfg(test)]
mod seed_session_tests {
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::utxo::{SnapshotCoin, SnapshotCoinObserver as _};

    use super::recovery_tests::{ForkFixture, SeedCellHarness, at};
    use crate::snapshot_seed::ScriptLiveSeedPhase;
    use crate::{IndexCapabilities, IndexError};

    #[derive(Debug, thiserror::Error)]
    enum SeedSessionTestError {
        #[error(transparent)]
        Index(#[from] crate::IndexError),
        #[error(transparent)]
        Int(#[from] std::num::TryFromIntError),
    }

    fn coin(index: u64, height: u32) -> SnapshotCoin<'static> {
        let mut txid = [0_u8; 32];
        txid[..8].copy_from_slice(&index.to_le_bytes());
        SnapshotCoin {
            txid: Hash256::from_le_bytes(&txid),
            vout: 0,
            value: 1_000 + index,
            script_pubkey: &[0x51],
            height,
            coinbase: false,
        }
    }

    // SYNC-03
    #[test]
    fn blocks_apply_while_a_paused_seed_is_stopped() -> Result<(), SeedSessionTestError> {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let seed = h.runtime.script_live_seed();
        let session = seed.begin_session()?;
        {
            let mut observer = session.observer();
            for index in 0..4 {
                observer.observe_coin(coin(index, 2));
            }
        }
        assert!(session.take_error().is_none(), "staging must not fail");
        assert_eq!(session.staged_rows(), 4);
        drop(session);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
        let tip = f.tip(f.a[3]);
        h.set_tip(&tip);
        let mut pending = None;
        h.settle(&mut pending);
        h.assert_at(&tip);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(seed.take_backlog(usize::MAX)?.is_empty());
        Ok(())
    }

    // SNP-07
    #[test]
    fn staged_seed_rows_stay_unpublished_until_the_worker_publishes()
    -> Result<(), SeedSessionTestError> {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let base = f.tip(f.a[1]);
        h.stage_seed_rows(&base, 4);
        assert_eq!(
            h.watermarks().script_live,
            None,
            "rows exist without a watermark while decoding"
        );
        let tip = f.tip(f.a[3]);
        h.set_tip(&tip);
        let mut pending = None;
        h.settle(&mut pending);
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&tip)),
            "the worker publishes the staged base"
        );
        h.assert_at(&tip);
        Ok(())
    }

    // SNP-07
    #[test]
    fn an_aborted_session_discards_the_staged_base() -> Result<(), SeedSessionTestError> {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let seed = h.runtime.script_live_seed();
        let session = seed.begin_session()?;
        {
            let mut observer = session.observer();
            for index in 0..4 {
                observer.observe_coin(coin(index, 2));
            }
        }
        session.abort();
        drop(session);
        assert_eq!(h.watermarks().script_live, None);
        let tip = f.tip(f.a[3]);
        h.set_tip(&tip);
        let mut pending = None;
        h.settle(&mut pending);
        h.assert_at(&tip);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(seed.take_backlog(usize::MAX)?.is_empty());
        seed.begin_session()?;
        Ok(())
    }

    // SNP-07
    #[test]
    fn stopping_a_paused_seed_discards_its_internal_data() -> Result<(), SeedSessionTestError> {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let seed = h.runtime.script_live_seed();
        let first = seed.begin_session()?;
        assert!(matches!(
            seed.begin_session(),
            Err(IndexError::SeedAlreadyActive)
        ));
        {
            let mut observer = first.observer();
            for index in 0..4 {
                observer.observe_coin(coin(index, 2));
            }
        }
        assert_eq!(first.staged_rows(), 4);
        drop(first);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
        let tip = f.tip(f.a[3]);
        h.set_tip(&tip);
        let mut pending = None;
        h.settle(&mut pending);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0, "a stopped seed keeps no rows");
        assert!(seed.take_backlog(usize::MAX)?.is_empty());
        let second = seed.begin_session()?;
        assert!(
            seed.claim_row_reset(),
            "a fresh session starts from an empty queue"
        );
        {
            let mut observer = second.observer();
            for index in 0..2 {
                observer.observe_coin(coin(100 + index, 3));
            }
        }
        assert!(second.take_error().is_none());
        let rows = seed.take_backlog(usize::MAX)?;
        assert_eq!(
            rows.len(),
            2,
            "the backlog holds only the second session's rows"
        );
        Ok(())
    }

    #[test]
    fn staging_needs_no_draining_worker() -> Result<(), SeedSessionTestError> {
        let f = ForkFixture::new(1);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let seed = h.runtime.script_live_seed();
        let session = seed.begin_session()?;
        const ROWS: u64 = 8_192;
        {
            let mut observer = session.observer();
            for index in 0..ROWS {
                observer.observe_coin(coin(index, 1));
            }
        }
        assert!(
            session.take_error().is_none(),
            "decode stalls when no worker drains the seed"
        );
        assert_eq!(session.staged_rows(), ROWS);
        let drained = seed.take_backlog(usize::MAX)?;
        assert_eq!(
            drained.len(),
            usize::try_from(ROWS)?,
            "every staged row survives staging"
        );
        Ok(())
    }

    // SNP-07
    #[test]
    fn a_seed_replaces_the_published_live_base() -> Result<(), SeedSessionTestError> {
        let f = ForkFixture::new(4);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let first = f.tip(f.a[1]);
        h.stage_seed_rows(&first, 4);
        h.set_tip(&first);
        let mut pending = None;
        h.settle(&mut pending);
        assert_eq!(h.watermarks().script_live, Some(at(&first)));
        assert_eq!(h.live_row_count(), 4, "the first seed owns the live base");

        let second = f.tip(f.a[3]);
        h.stage_seed_rows(&second, 2);
        h.set_tip(&second);
        h.settle(&mut pending);
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&second)),
            "the higher seed must publish over the replaced base"
        );
        assert_eq!(
            h.live_row_count(),
            2,
            "the replaced base holds only the new seed's rows"
        );
        h.assert_at(&second);
        assert_eq!(
            h.runtime.script_live_seed().phase(),
            ScriptLiveSeedPhase::Idle
        );
        Ok(())
    }

    // SNP-07
    #[test]
    fn an_abort_before_decode_preserves_the_published_live_base() -> Result<(), SeedSessionTestError>
    {
        let f = ForkFixture::new(2);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let base = f.tip(f.a[1]);
        h.stage_seed_rows(&base, 4);
        h.set_tip(&base);
        let mut pending = None;
        h.settle(&mut pending);
        assert_eq!(h.watermarks().script_live, Some(at(&base)));
        assert_eq!(h.live_row_count(), 4);

        let seed = h.runtime.script_live_seed();
        let session = seed.begin_session()?;
        session.abort();
        drop(session);
        h.settle(&mut pending);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(seed.take_backlog(usize::MAX)?.is_empty());
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&base)),
            "a seed rejected before decoding must preserve the published base"
        );
        assert_eq!(
            h.live_row_count(),
            4,
            "the published rows must survive the abort"
        );
        Ok(())
    }

    // SNP-07
    #[test]
    fn an_abort_after_staging_preserves_the_published_live_base() -> Result<(), SeedSessionTestError>
    {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let first = f.tip(f.a[1]);
        h.stage_seed_rows(&first, 4);
        h.set_tip(&first);
        let mut pending = None;
        h.settle(&mut pending);
        assert_eq!(h.watermarks().script_live, Some(at(&first)));

        let second = f.tip(f.a[2]);
        let seed = h.runtime.script_live_seed();
        let session = seed.begin_session()?;
        {
            let mut observer = session.observer();
            for index in 0..3 {
                observer.observe_coin(coin(index, 3));
            }
        }
        assert!(session.take_error().is_none());
        h.set_tip(&second);
        assert!(
            h.stalled_pass(&mut pending),
            "an open seed pass must stall while the published base is present"
        );
        session.abort();
        drop(session);
        h.settle(&mut pending);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(seed.take_backlog(usize::MAX)?.is_empty());
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&second)),
            "the preserved base must carry forward to the applied tip"
        );
        Ok(())
    }

    // SNP-07
    #[test]
    fn a_seed_at_or_below_the_published_base_is_already_covered() -> Result<(), SeedSessionTestError>
    {
        let f = ForkFixture::new(3);
        f.persist_undo();
        let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
        let tip = f.tip(f.a[2]);
        h.stage_seed_rows(&tip, 4);
        h.set_tip(&tip);
        let mut pending = None;
        h.settle(&mut pending);
        assert_eq!(h.watermarks().script_live, Some(at(&tip)));
        let rows_before = h.live_row_count();
        assert!(rows_before > 0, "the published base must hold rows");

        let seed = h.runtime.script_live_seed();
        let lower = f.tip(f.a[1]);
        let session = seed.begin_session()?;
        {
            let mut observer = session.observer();
            for index in 0..2 {
                observer.observe_coin(coin(index, lower.height));
            }
        }
        session.publish(at(&lower));
        assert!(h.stalled_pass(&mut pending));
        assert_eq!(
            seed.phase(),
            ScriptLiveSeedPhase::PublishPending { tip: at(&lower) }
        );
        drop(session);
        h.settle(&mut pending);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(seed.take_backlog(usize::MAX)?.is_empty());
        assert_eq!(
            h.watermarks().script_live,
            Some(at(&tip)),
            "a seed at or below the published base must not move the watermark"
        );
        assert_eq!(
            h.live_row_count(),
            rows_before,
            "a covered seed must leave the published rows untouched"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod historical_window {
        use crate::runtime::DerivedIndexRuntime;

        // SNP-08
        #[test]
        fn only_heights_without_historical_facts_await_them() -> Result<(), TestError> {
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
            let runtime = DerivedIndexRuntime::new(wake_tx);
            assert!(!runtime.awaits_historical_facts(0));

            runtime.set_historical_window(200, 50);
            assert!(!runtime.awaits_historical_facts(49));
            assert!(runtime.awaits_historical_facts(50));
            assert!(runtime.awaits_historical_facts(200));
            assert!(!runtime.awaits_historical_facts(201));

            runtime.note_historical_facts(60);
            assert!(!runtime.awaits_historical_facts(60));
            assert!(runtime.awaits_historical_facts(61));

            runtime.note_historical_facts(10);
            assert!(runtime.awaits_historical_facts(61));
            Ok(())
        }

        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        use arc_swap::ArcSwapOption;
        use bitcoin::{
            Amount, Block, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
            absolute::LockTime,
            block::{Header as BlockHeader, Version},
            consensus::encode::serialize,
            hashes::Hash as _,
            pow::CompactTarget,
            script::Builder,
            transaction::Version as TxVersion,
        };
        use bitcoin_rs_consensus::latch::LatchReader;
        use bitcoin_rs_consensus::primitives::Hash256;
        use bitcoin_rs_consensus::primitives::layout::{
            parse_exact_call_count, reset_parse_exact_call_count,
        };
        use bitcoin_rs_execution::chain::{
            BlockTree, BlockTreeReader, NodeStatus, TipReader, TipSnapshot,
        };
        use bitcoin_rs_storage::block_body::BlockBodyStore;
        use bitcoin_rs_storage::budget::CpuShares;
        use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
        use bitcoin_rs_storage::{
            CommittedBlock, CommittedFacts, RocksDbStore, StorageError, TxFacts,
        };
        use parking_lot::{Mutex, RwLock};

        use crate::IndexCapabilities;
        use crate::portable::TestError;
        use crate::reconcile::{ChainCursorSource, ConsumerCursor};
        use crate::runtime::{DEFAULT_BATCH_LIMITS, IndexAheadError, IndexAheadSink, Worker};

        type BodyMap = hashbrown::HashMap<(u32, [u8; 32]), Vec<u8>>;

        struct CountingBodies {
            bodies: Mutex<BodyMap>,
            loads: AtomicU64,
        }

        impl BlockBodyStore for CountingBodies {
            fn persist_block_body(
                &self,
                height: u32,
                hash: Hash256,
                body: &[u8],
            ) -> Result<(), StorageError> {
                self.bodies
                    .lock()
                    .insert((height, hash.to_le_bytes()), body.to_vec());
                Ok(())
            }

            fn load_block_body(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                self.loads.fetch_add(1, Ordering::SeqCst);
                Ok(self
                    .bodies
                    .lock()
                    .get(&(height, hash.to_le_bytes()))
                    .cloned())
            }

            fn undo_record(
                &self,
                _height: u32,
                _hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                Ok(None)
            }

            fn sync(&self) -> Result<(), StorageError> {
                Ok(())
            }
        }

        struct StillCursor;

        impl ChainCursorSource for StillCursor {
            fn cursor(&self) -> ConsumerCursor {
                ConsumerCursor {
                    epoch: 0,
                    sequence: 0,
                    height: 0,
                    hash: Hash256::from_le_bytes(&[0; 32]),
                }
            }
        }

        struct DropEvidence;

        impl IndexAheadSink for DropEvidence {
            fn report_index_ahead(
                &self,
                _capability: &str,
                _index_height: u32,
                _tip_height: u32,
                _tip_hash_be: &str,
                _index_hash_be: &str,
                _depth: u32,
                _unix_secs: u64,
            ) -> Result<(), IndexAheadError> {
                Ok(())
            }
        }

        fn snp08_block(prev: Hash256, height: u32) -> Block {
            let coinbase = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: Builder::new().push_int(i64::from(height)).into_script(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_000_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            let mut block = Block {
                header: BlockHeader {
                    version: Version::ONE,
                    prev_blockhash: bitcoin::BlockHash::from_byte_array(prev.to_le_bytes()),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: height,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce: 0,
                },
                txdata: vec![coinbase],
            };
            block.header.merkle_root = block
                .compute_merkle_root()
                .unwrap_or(TxMerkleNode::all_zeros());
            block
        }

        fn snp08_facts(
            block: &Block,
            height: u32,
            parent: [u8; 32],
        ) -> Result<CommittedBlock, TestError> {
            let header: [u8; 80] = serialize(&block.header)[..80]
                .try_into()
                .map_err(|_| TestError::Missing("80-byte header"))?;
            Ok(CommittedBlock {
                height,
                hash: block.block_hash().to_byte_array(),
                parent_hash: parent,
                header,
                txs: block
                    .txdata
                    .iter()
                    .map(|tx| TxFacts {
                        txid: tx.compute_txid().to_byte_array(),
                        offset: 81,
                        len: 60,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                    })
                    .collect(),
            })
        }

        // SNP-08
        #[test]
        fn heights_above_the_base_come_only_from_committed_facts() -> Result<(), TestError> {
            use bitcoin_rs_consensus::primitives::deserialize;

            let bodies = Arc::new(CountingBodies {
                bodies: Mutex::new(hashbrown::HashMap::new()),
                loads: AtomicU64::new(0),
            });
            let mut tree = BlockTree::new();
            let mut facts: Vec<CommittedBlock> = Vec::new();
            let mut prev = Hash256::from_le_bytes(&[0; 32]);
            let mut tip_id = None;
            for height in 0..=3 {
                let block = snp08_block(prev, height);
                let bytes = serialize(&block);
                let hash = Hash256::from_le_bytes(&block.block_hash().to_byte_array());
                let header = deserialize::<bitcoin_rs_consensus::primitives::Header>(&serialize(
                    &block.header,
                ))?;
                let node_id = tree.insert_header(header, NodeStatus::HeaderValid)?;
                bodies
                    .bodies
                    .lock()
                    .insert((height, hash.to_le_bytes()), bytes);
                facts.push(snp08_facts(&block, height, prev.to_le_bytes())?);
                prev = hash;
                if height == 3 {
                    tip_id = Some(node_id);
                }
            }
            let tip_id = tip_id.ok_or("height three inserted")?;
            let node = tree.node(tip_id)?;
            let tip = Arc::new(TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            });
            let index_dir = tempfile::tempdir()?;
            let store = Arc::new(RocksDbStore::open(index_dir.path())?);
            let writer: Arc<dyn crate::TxIndexWriter> = Arc::new(parking_lot::RwLock::new(
                crate::IndexWriter::open(Arc::clone(&store), 1)?
                    .with_seal_scratch(index_dir.path().join("seal-scratch")),
            ));
            let applied_tip = Arc::new(ArcSwapOption::empty());
            applied_tip.store(Some(Arc::clone(&tip)));
            let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
            let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
            runtime.set_historical_window(1, 0);
            let (facts_tx, facts_rx) = crossbeam_channel::bounded(8);
            let shared_bodies = Arc::clone(&bodies);
            let body_store: Arc<dyn BlockBodyStore> = shared_bodies;
            let mut worker = Worker {
                runtime: Arc::clone(&runtime),
                writer: Arc::clone(&writer),
                applied_tip: TipReader::new(Arc::clone(&applied_tip)),
                block_tree: BlockTreeReader::new(Arc::new(RwLock::new(tree))),
                body_store: Some(body_store),
                history: HistoryAccess::new(
                    Arc::new(RetentionRegistry::new()),
                    RetentionBudget::Unlimited,
                ),
                batch_limits: DEFAULT_BATCH_LIMITS,
                enabled: IndexCapabilities::TX_LOOKUP,
                chain_events: Arc::new(StillCursor),
                reporter: Arc::new(DropEvidence),
                shutdown: LatchReader::fixture_never(),
                wake_rx,
                quiet_period: Duration::ZERO,
                batch_delay: Duration::ZERO,
                rollback_rebuild_cutover: u32::MAX,
                seed_history_lease: parking_lot::Mutex::new(None),
                facts_rx: None,
                facts_charge: None,
                facts_gap: None,
                cpu: Some(Arc::new(CpuShares::new(1, 1))),
                buffered_facts: parking_lot::Mutex::new(hashbrown::HashMap::new()),
            };
            worker.facts_rx = Some(facts_rx);
            reset_parse_exact_call_count();
            let mut pending = None;
            let mut stalled = false;
            for _ in 0..8 {
                match worker
                    .reconcile_once(&mut pending)
                    .map_err(|_| TestError::Missing("reconcile_once"))?
                {
                    crate::runtime::ReconcileAction::Stalled => {
                        stalled = true;
                        break;
                    }
                    crate::runtime::ReconcileAction::Progressed
                    | crate::runtime::ReconcileAction::Buffered
                    | crate::runtime::ReconcileAction::CaughtUp => continue,
                }
            }
            assert!(
                stalled,
                "the worker must stall while heights await historical facts"
            );
            assert_eq!(
                bodies.loads.load(Ordering::SeqCst),
                0,
                "heights awaiting historical facts must not read block bodies"
            );
            for (index, block) in facts.iter().enumerate() {
                facts_tx
                    .send(Arc::new(CommittedFacts {
                        commit_id: u64::try_from(index)? + 1,
                        blocks: vec![block.clone()],
                    }))
                    .map_err(|_| TestError::Missing("facts send"))?;
                if block.height <= 1 {
                    runtime.note_historical_facts(block.height);
                }
                runtime.wake();
            }
            for _ in 0..64 {
                match worker
                    .reconcile_once(&mut pending)
                    .map_err(|_| TestError::Missing("reconcile_once"))?
                {
                    crate::runtime::ReconcileAction::CaughtUp => break,
                    crate::runtime::ReconcileAction::Progressed
                    | crate::runtime::ReconcileAction::Buffered
                    | crate::runtime::ReconcileAction::Stalled => continue,
                }
            }
            let watermarks = writer.fenced_watermarks()?.1;
            assert_eq!(
                watermarks.tx_lookup,
                Some(crate::IndexWatermark {
                    height: 3,
                    hash: facts[3].hash,
                }),
                "catch-up must reach the tip"
            );
            assert_eq!(
                bodies.loads.load(Ordering::SeqCst),
                0,
                "heights above the base fed by facts must make zero block-body reads"
            );
            assert_eq!(
                parse_exact_call_count(),
                0,
                "the facts-only catch-up must not parse a block body"
            );
            Ok(())
        }
    }
    #[expect(clippy::expect_used)]
    mod seed_paused {
        use std::sync::Arc;

        use bitcoin_rs_storage::ColumnFamily;
        use bitcoin_rs_storage::KvStore as _;
        use bitcoin_rs_storage::utxo::SnapshotCoinObserver as _;

        use crate::IndexCapabilities;
        use crate::IndexError;
        use crate::IndexWatermark;
        use crate::snapshot_seed::{ScriptLiveSeedPhase, ScriptLiveSeedState};
        use crate::{IndexWriter, ScriptHash};
        use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
        use bitcoin_rs_storage::RocksDbStore;
        use bitcoin_rs_storage::utxo::SnapshotCoin;

        type Harness = (
            tempfile::TempDir,
            Arc<RocksDbStore>,
            Arc<parking_lot::RwLock<IndexWriter<RocksDbStore>>>,
            Arc<ScriptLiveSeedState>,
        );

        fn harness() -> Harness {
            let dir = tempfile::tempdir().expect("index dir");
            let store = Arc::new(RocksDbStore::open(dir.path()).expect("rocksdb open"));
            let writer = Arc::new(parking_lot::RwLock::new(
                IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
            ));
            let seed = Arc::new(ScriptLiveSeedState::new());
            (dir, store, writer, seed)
        }

        fn coin(index: u64, height: u32) -> SnapshotCoin<'static> {
            let mut txid = [0_u8; 32];
            txid[..8].copy_from_slice(&index.to_le_bytes());
            SnapshotCoin {
                txid: Hash256::from_le_bytes(&txid),
                vout: 0,
                value: 1_000 + index,
                script_pubkey: &[0x51],
                height,
                coinbase: false,
            }
        }

        fn watermark(height: u32) -> IndexWatermark {
            let byte = u8::try_from(height).unwrap_or(0);
            IndexWatermark {
                height,
                hash: Hash256::from_le_bytes(&[byte; 32]).to_le_bytes(),
            }
        }

        #[test]
        fn a_second_session_is_refused_while_one_is_active() {
            let (_dir, _store, _writer, seed) = harness();
            let session = seed.begin_session().expect("first session");
            assert_eq!(seed.phase(), ScriptLiveSeedPhase::Seeding);
            assert!(matches!(
                seed.begin_session(),
                Err(IndexError::SeedAlreadyActive)
            ));
            drop(session);
            assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
            seed.complete_abort();
            assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
            seed.begin_session().expect("session after abort");
        }

        #[test]
        fn staged_rows_stay_unpublished_until_the_worker_publishes() {
            let (_dir, _store, writer, seed) = harness();
            let session = seed.begin_session().expect("session");
            {
                let mut observer = session.observer();
                for i in 0..4 {
                    observer.observe_coin(coin(i, 10));
                }
            }
            assert!(session.take_error().is_none());
            assert_eq!(session.staged_rows(), 4);
            assert_eq!(
                writer.read().watermarks().expect("watermarks").script_live,
                None,
                "SNP-07: rows exist without a watermark while decoding"
            );

            session.publish(watermark(10));
            assert_eq!(
                seed.phase(),
                ScriptLiveSeedPhase::PublishPending { tip: watermark(10) }
            );
            writer
                .write()
                .publish_script_live_seed(watermark(10))
                .expect("publish staged rows");
            seed.complete_publish();
            assert_eq!(
                writer.read().watermarks().expect("watermarks").script_live,
                Some(watermark(10))
            );
            assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        }

        #[test]
        fn an_aborted_session_discards_the_staged_base() {
            let (_dir, store, writer, seed) = harness();
            let session = seed.begin_session().expect("session");
            {
                let mut observer = session.observer();
                for i in 0..4 {
                    observer.observe_coin(coin(i, 10));
                }
            }
            session.abort();
            writer
                .write()
                .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                .expect("reset staged rows");
            seed.complete_abort();
            let probe = writer
                .write()
                .fenced_watermarks()
                .expect("watermarks")
                .1
                .script_live;
            assert_eq!(probe, None);
            assert_eq!(
                count_live_rows(&store),
                0,
                "SNP-07: discarded staging must leave no rows"
            );
        }

        #[test]
        fn a_closed_session_is_a_sticky_stage_error() {
            let (_dir, _store, _writer, seed) = harness();
            let session = seed.begin_session().expect("session");
            seed.close_session();
            {
                let mut observer = session.observer();
                observer.observe_coin(coin(1, 1));
            }
            assert!(matches!(
                session.take_error(),
                Some(IndexError::SeedChannelClosed)
            ));
        }

        // SNP-07
        #[test]
        fn a_new_session_publishes_only_its_own_rows() {
            let (_dir, store, writer, seed) = harness();
            let first = seed.begin_session().expect("first session");
            {
                let mut observer = first.observer();
                for index in 0..4 {
                    observer.observe_coin(coin(index, 10));
                }
            }
            assert!(first.take_error().is_none());
            drop(first);
            let stale = seed.take_backlog(usize::MAX).expect("stale rows");
            writer
                .read()
                .stage_script_live_rows(&mut stale.into_iter())
                .expect("stage stale rows");
            assert_eq!(count_live_rows(&store), 4);
            seed.complete_abort();

            let second = seed.begin_session().expect("second session");
            assert!(
                seed.claim_row_reset(),
                "a fresh session must claim exactly one reset"
            );
            let cleared = writer
                .read()
                .reset_interrupted_script_live_seed()
                .expect("interrupted probe");
            assert!(cleared, "rows without a watermark are stale staging");
            {
                let mut observer = second.observer();
                observer.observe_coin(coin(99, 20));
            }
            assert!(second.take_error().is_none());
            drop(second);
            let rows = seed.take_backlog(usize::MAX).expect("second rows");
            writer
                .read()
                .stage_script_live_rows(&mut rows.into_iter())
                .expect("stage second rows");
            writer
                .write()
                .publish_script_live_seed(watermark(20))
                .expect("publish one row");
            seed.complete_publish();
            assert_eq!(
                count_live_rows(&store),
                1,
                "the published base must hold exactly the second session's row"
            );
        }

        #[test]
        fn rows_without_a_watermark_are_recovered_as_an_interrupted_seed() {
            let (_dir, store, writer, _seed) = harness();
            let rows = (0..3_u64)
                .map(|i| -> Result<Vec<u8>, IndexError> {
                    let scripthash = ScriptHash::from_script_bytes(&[0x51]);
                    let outpoint = OutPoint::new(
                        Txid(Hash256::from_le_bytes(&{
                            let mut bytes = [0_u8; 32];
                            bytes[..8].copy_from_slice(&i.to_le_bytes());
                            bytes
                        })),
                        0,
                    );
                    let row = crate::types::ScriptLiveRow::new(scripthash, &outpoint);
                    let coin = crate::types::ScriptLiveCoin::new(scripthash, 1_000 + i, 1, false);
                    let mut bytes = row.as_bytes().to_vec();
                    bytes.extend_from_slice(&coin.encode_value()?);
                    Ok(bytes)
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("encode rows");
            let staged = writer
                .read()
                .stage_script_live_rows(&mut rows.into_iter())
                .expect("stage rows");
            assert_eq!(staged, 3);
            let cleared = writer
                .read()
                .reset_interrupted_script_live_seed()
                .expect("interrupted probe");
            assert!(cleared, "unwatermarked rows must be cleared before replay");
            assert_eq!(count_live_rows(&store), 0);
        }

        fn count_live_rows(store: &RocksDbStore) -> usize {
            let mut count = 0;
            let iter = store
                .iter_prefix(ColumnFamily::ScriptLive, &[])
                .expect("live scan");
            for entry in iter {
                let _ = entry.expect("live row");
                count += 1;
            }
            count
        }
    }
}
