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
            "TxLookup paused at a missing undo record; other indexes continue",
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
mod query_tests;

#[cfg(test)]
mod supervisor_tests;

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic)]
mod recovery_tests;

#[cfg(test)]
mod seed_session_tests;

#[cfg(test)]
mod tests;
