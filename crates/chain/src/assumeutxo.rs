#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::assumeutxo_snapshot::{
    SnapshotAnchorError, StagedCoins, StreamedCoins, finish_stage, stage_record,
};
use crate::chain::TipSnapshot;
use crate::error::{ApplyError, DisconnectError};
use crate::{Chainstate, ConnectOutcome};
use bitcoin_rs_consensus::primitives::{AssumeUtxoData, BlockImage, Hash256, Network};
#[cfg(test)]
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::core_snapshot::{CoreSnapshotStream, StateVerifyError};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use parking_lot::{Mutex, MutexGuard, RwLock};

mod serde_hash256 {
    use bitcoin_rs_consensus::primitives::Hash256;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(hash: &Hash256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hash.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Hash256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Hash256>().map_err(serde::de::Error::custom)
    }
}

mod serde_opt_hash256 {
    use bitcoin_rs_consensus::primitives::Hash256;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(hash: &Option<Hash256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hash.as_ref().map(ToString::to_string).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Hash256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| s.parse::<Hash256>())
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChainstateRole {
    Ordinary,
    AssumedActive {
        base_height: u32,
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
    },
    Historical {
        base_height: u32,
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
    },
}

impl ChainstateRole {
    #[must_use]
    pub const fn is_assumed_active(&self) -> bool {
        matches!(self, Self::AssumedActive { .. })
    }

    #[must_use]
    pub const fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary)
    }

    #[must_use]
    pub const fn base_height(&self) -> Option<u32> {
        match self {
            Self::AssumedActive { base_height, .. } | Self::Historical { base_height, .. } => {
                Some(*base_height)
            }
            Self::Ordinary => None,
        }
    }
}

pub use bitcoin_rs_storage::assumeutxo::{AssumeUtxoDiskStatus, HistoricalCheckpointRef};

/// Digest and length of a snapshot file, as the manifest attests them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileAttestation {
    pub sha256: [u8; 32],
    pub size: u64,
}

#[derive(Default)]
struct IngestDigest {
    hasher: Sha256,
    bytes: u64,
}

impl IngestDigest {
    fn finish(self) -> FileAttestation {
        FileAttestation {
            sha256: self.hasher.finalize().into(),
            size: self.bytes,
        }
    }
}

/// Hashes exactly the bytes its inner reader hands to the ingest pass.
struct DigestingReader<'a, R> {
    inner: &'a mut R,
    digest: Rc<RefCell<IngestDigest>>,
}

impl<R: Read> Read for DigestingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buf)?;
        let mut digest = self.digest.borrow_mut();
        digest.hasher.update(&buf[..count]);
        digest.bytes += u64::try_from(count).unwrap_or(u64::MAX);
        Ok(count)
    }
}

fn storage_io(error: std::io::Error) -> AssumeUtxoError {
    AssumeUtxoError::Storage(bitcoin_rs_storage::StorageError::Io(error))
}

fn rewind_to<R: Seek>(reader: &mut R, position: u64) -> Result<(), AssumeUtxoError> {
    reader
        .seek(SeekFrom::Start(position))
        .map(|_| ())
        .map_err(storage_io)
}

pub(crate) fn commit_error(error: bitcoin_rs_storage::CommitError) -> AssumeUtxoError {
    match error {
        bitcoin_rs_storage::CommitError::Storage(storage) => AssumeUtxoError::Storage(storage),
        other => {
            AssumeUtxoError::Storage(bitcoin_rs_storage::StorageError::backend(other.to_string()))
        }
    }
}

pub(crate) fn engine_coin_stats(
    engine: &dyn bitcoin_rs_storage::KvStore,
    tip: &crate::chain::TipSnapshot,
) -> Result<bitcoin_rs_storage::utxo::stats::CoinStats, AssumeUtxoError> {
    use bitcoin_rs_storage::utxo::SnapshotCoinObserver;
    let mut accumulator =
        bitcoin_rs_storage::utxo::stats::CoinStatsAccumulator::with_parallel_muhash(tip.height);
    for item in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
        let (key, value) = item?;
        let key: [u8; 32] = key.as_slice().try_into().map_err(|_| {
            AssumeUtxoError::Storage(bitcoin_rs_storage::StorageError::InvalidOperation(
                "coin key is not a 32-byte txid",
            ))
        })?;
        let txid = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&key);
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())?;
        for out in record.outputs() {
            accumulator.observe_coin(bitcoin_rs_storage::utxo::SnapshotCoin {
                txid,
                vout: out.vout,
                value: out.value,
                script_pubkey: out.script_pubkey,
                height: out.height,
                coinbase: out.coinbase,
            });
        }
    }
    let mut stats = accumulator.into_stats();
    stats.tx_count = tip.chain_tx_count.to_wire();
    Ok(stats)
}

/// Reconciles an interrupted snapshot activation before anything reads coins.
///
/// A durable activation marker without its activation head means the staged
/// snapshot coin ingest never completed its head commit. The marker's staged
/// coins are wiped from the engine and the marker cleared, leaving the exact
/// pre-activation state; the activation must be run again from the snapshot
/// file (CMT-01, CMT-03).
///
/// The snapshot-base checkpoint is published before the head commit, so a
/// crash in between leaves a checkpoint generation no durable head names.
/// The rollback below removes that orphan generation and resets the
/// in-memory applied state to cold, so the same restart re-runs the
/// activation; a crash after the head commit finds the checkpoint on
/// restart. The orphan removal is linearizable with the marker clear by
/// ordering: the coins are wiped and the marker handed back here, the
/// orphan generation is removed next, the checkpoint root is synced so the
/// removal is durable, and the marker is only cleared once that sync
/// succeeded. A failed removal or sync propagates the error before the
/// marker is cleared, so no restart can observe a cleared marker next to a
/// loadable orphan checkpoint and adopt it as ordinary state; the next boot
/// re-runs this rollback.
/// Callers must run this before installing a checkpoint engine image and
/// before boot replay, so the wipe cannot erase rows the replay cannot
/// rebuild.
pub fn recover_snapshot_activation(
    active: &Chainstate,
    data_dir: &Path,
) -> Result<(), AssumeUtxoError> {
    let Some(marker) = active
        .commit_authority
        .recover_snapshot_activation()
        .map_err(commit_error)?
    else {
        return Ok(());
    };
    remove_orphan_base_checkpoint(data_dir, &marker.base_hash).map_err(storage_io)?;
    active
        .commit_authority
        .clear_snapshot_activation_marker()
        .map_err(commit_error)?;
    reset_rolled_back_chainstate(active)?;
    tracing::warn!(
        base_hash = %marker.base_hash.to_string_be(),
        coin_count = marker.coin_count,
        "interrupted snapshot activation rolled back; staged coins wiped and the pre-activation head kept; re-run the activation"
    );
    Ok(())
}

/// Removes the checkpoint generation the given snapshot base orphaned.
///
/// Fail-closed: any read, parse, deletion, or directory-sync failure other
/// than an absent target is returned, so the caller keeps the activation
/// marker durable and the next restart retries the removal. Every path that
/// deleted entries, and the path that finds CURRENT already absent because
/// a prior boot may have deleted them but failed the root sync, syncs the
/// checkpoint root before reporting success; a missing root has nothing to
/// sync and succeeds. An absent CURRENT names no generation, and a
/// generation with no manifest cannot be loaded, so those still remove what
/// they can and report success.
fn remove_orphan_base_checkpoint(data_dir: &Path, base: &Hash256) -> Result<(), std::io::Error> {
    let root = data_dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
    let current_path = root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE);
    let current_bytes = match std::fs::read(&current_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return sync_checkpoint_root(&root);
        }
        Err(error) => {
            tracing::warn!(%error, "interrupted activation checkpoint CURRENT was not inspected");
            return Err(error);
        }
    };
    let current: bitcoin_rs_storage::checkpoint::CurrentV1 = match sonic_rs::from_slice(
        &current_bytes,
    ) {
        Ok(current) => current,
        Err(error) => {
            tracing::warn!(%error, "interrupted activation left an unreadable checkpoint CURRENT");
            return Err(std::io::Error::other(error));
        }
    };
    let manifest_path = root
        .join(&current.directory)
        .join(bitcoin_rs_storage::checkpoint::MANIFEST_FILE);
    let names_the_orphan = match std::fs::read(&manifest_path) {
        Ok(bytes) => {
            let manifest: bitcoin_rs_storage::checkpoint::CheckpointManifestV1 =
                match sonic_rs::from_slice(&bytes) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "interrupted activation left an unreadable checkpoint manifest"
                        );
                        return Err(std::io::Error::other(error));
                    }
                };
            manifest.applied_tip.hash == base.to_string_be()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            tracing::warn!(%error, "interrupted activation checkpoint manifest was not inspected");
            return Err(error);
        }
    };
    if !names_the_orphan {
        return Ok(());
    }
    match std::fs::remove_dir_all(root.join(&current.directory)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, "interrupted activation orphan checkpoint was not removed");
            return Err(error);
        }
    }
    match std::fs::remove_file(&current_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, "interrupted activation orphan checkpoint CURRENT was not removed");
            return Err(error);
        }
    }
    sync_checkpoint_root(&root)
}

fn sync_checkpoint_root(root: &Path) -> Result<(), std::io::Error> {
    #[cfg(test)]
    {
        if let Some(message) = ORPHAN_ROOT_SYNC_FAILPOINT.with(Cell::take) {
            return Err(std::io::Error::other(message));
        }
    }
    let dir = match bitcoin_rs_storage::checkpoint::fs::open_data_dir(root) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            tracing::warn!(
                %error,
                "interrupted activation checkpoint root was not opened for sync"
            );
            return Err(error);
        }
    };
    match bitcoin_rs_storage::checkpoint::fs::sync_dir(&dir) {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(%error, "interrupted activation checkpoint root was not synced");
            Err(error)
        }
    }
}

#[cfg(test)]
thread_local! {
    static ORPHAN_ROOT_SYNC_FAILPOINT: Cell<Option<&'static str>> = const { Cell::new(None) };
}

#[cfg(test)]
fn inject_orphan_root_sync_failure(message: &'static str) {
    ORPHAN_ROOT_SYNC_FAILPOINT.with(|slot| slot.set(Some(message)));
}

fn reset_rolled_back_chainstate(active: &Chainstate) -> Result<(), AssumeUtxoError> {
    use crate::chain::NodeStatus;
    active.applied_tip.store(None);
    active.chain_tip.store(None);
    {
        let mut tree = active.block_tree.write();
        *tree = crate::chain::BlockTree::new();
        if tree.is_empty() {
            tree.insert_header(
                active.network.genesis_block().header,
                NodeStatus::HeaderValid,
            )
            .map_err(crate::error::ApplyError::from)?;
        }
    }
    active
        .coin_stats
        .reset(bitcoin_rs_storage::utxo::stats::CoinStats::default());
    active.set_role(ChainstateRole::Ordinary);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivatedSnapshot {
    pub base_hash: Hash256,
    pub height: u32,
    pub declared_coins: u64,
}

const DEFAULT_INGEST_CHUNK_BYTES: usize = 8 << 20;
const DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL: u32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalAdvance {
    Complete,
    ReplayPending,
    MissingBody { height: u32, hash: Hash256 },
}

#[derive(Debug, thiserror::Error)]
pub enum AssumeUtxoError {
    #[error("snapshot base does not have more accumulated work than the applied tip")]
    ActivationBehindTip,
    #[error(
        "snapshot activation requires matching tip (hash, height, transaction count; transaction count 0 means unknown): durable {}, applied {}",
        durable_tip.map_or_else(|| "<none>".to_owned(), |(hash, height, count)| format!("({hash}, {height}, {count})")),
        applied_tip.map_or_else(|| "<none>".to_owned(), |(hash, height, count)| format!("({hash}, {height}, {count})"))
    )]
    SnapshotTipNotSettled {
        durable_tip: Option<(Hash256, u32, u64)>,
        applied_tip: Option<(Hash256, u32, u64)>,
    },
    #[error("missing durable snapshot anchor")]
    MissingDurableAnchor,
    #[error("historical validation produced no undo record")]
    MissingHistoricalUndo,
    #[error("snapshot storage: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error("snapshot codec: {0}")]
    Codec(#[from] bitcoin_rs_storage::utxo::core_snapshot::SnapshotError),
    #[error("snapshot observer refused the activation; the staged coins were discarded")]
    ObserverRefused,
    #[error("snapshot file does not match its manifest attestation (digest or length)")]
    ArtifactDigestMismatch {
        expected_sha256: [u8; 32],
        found_sha256: [u8; 32],
        expected_size: u64,
        found_size: u64,
    },
    #[error(
        "snapshot activation failed ({ingest}) and its staged coins could not be discarded ({discard}); the datadir refuses to open until the activation marker is recovered"
    )]
    PartialIngestNotDiscarded {
        ingest: Box<AssumeUtxoError>,
        discard: String,
    },
    #[error("snapshot anchor: {0}")]
    Anchor(#[from] SnapshotAnchorError),
    #[error("snapshot block decode: {0}")]
    BlockDecode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
    #[error("snapshot checkpoint publish: {error}")]
    ActivationCheckpointPublish {
        error: crate::checkpoint::CheckpointError,
    },
    #[error("snapshot-base checkpoint coin statistics do not match the pinned trust anchor")]
    ActivationCommitmentMismatch,
    #[error("open historical checkpoint data directory: {error}")]
    HistoricalCheckpointDir { error: std::io::Error },
    #[error("historical checkpoint load failed: {error}")]
    HistoricalCheckpointLoad {
        error: bitcoin_rs_storage::checkpoint::CheckpointLoadError,
    },
    #[error("publish historical checkpoint: {error}")]
    HistoricalCheckpointPublish {
        error: crate::checkpoint::CheckpointError,
    },
    #[error("historical checkpoint is ahead of certified validation progress")]
    HistoricalCheckpointAheadOfProgress,
    #[error("durable head names a historical checkpoint that is not published")]
    HistoricalCheckpointNotPublished,
    #[error("historical checkpoint does not match its durable-head reference")]
    HistoricalCheckpointReferenceMismatch,
    #[error("historical checkpoint has no certified transaction count")]
    HistoricalCheckpointWithoutTransactionCount,
    #[error("historical checkpoint has no engine image, so its coins cannot be restored")]
    HistoricalCheckpointWithoutEngine,
    #[error("historical checkpoint is not on the pinned ancestry")]
    HistoricalCheckpointNotOnAncestry,
    #[error("historical checkpoint hash is not on the pinned ancestry")]
    HistoricalCheckpointHashNotOnAncestry,
    #[error("certified historical progress is not on the pinned ancestry")]
    HistoricalProgressNotOnAncestry,
    #[error("durable historical progress is not on the pinned ancestry")]
    DurableHistoricalProgressNotOnAncestry,
    #[error("historical archive body identity mismatch")]
    HistoricalBodyIdentityMismatch,
    #[error("historical validation intent exceeds snapshot base")]
    ValidationIntentExceedsBase,
    #[error("historical checkpoint is ahead of pending validation intent")]
    HistoricalCheckpointAheadOfIntent,
    #[error("missing historical body store")]
    MissingHistoricalBodyStore,
    #[error("missing historical validation dependency")]
    MissingHistoricalDependencyBody,
    #[error("historical validation dependency identity mismatch")]
    HistoricalDependencyIdentityMismatch,
    #[error("missing pending validation body store")]
    MissingPendingBodyStore,
    #[error("missing pending validation body")]
    MissingPendingBody,
    #[error("pending validation body identity mismatch")]
    PendingBodyIdentityMismatch,
    #[error("historical checkpoint is due without a historical chainstate")]
    CheckpointDueWithoutChainstate,
    #[error("historical checkpoint tip does not match certified progress")]
    CheckpointTipMismatch,
    #[error("snapshot base header {0} is not present")]
    SnapshotHeaderMissing(Hash256),
    #[error("snapshot base header height {found} does not match pinned height {expected}")]
    SnapshotHeaderHeightMismatch { expected: u32, found: u32 },
    #[error(
        "snapshot base {base_hash} at height {base_height} is not on the best-work header chain ending at {best_header:?}"
    )]
    SnapshotBaseNotOnBestHeaderChain {
        base_hash: Hash256,
        base_height: u32,
        best_header: Option<Hash256>,
    },
    #[error("historical transaction count {found} does not match pinned count {expected}")]
    HistoricalTransactionCountMismatch { expected: u64, found: u64 },
    #[error("snapshot block hash {found} does not match pinned hash {expected}")]
    SnapshotBlockHashMismatch { expected: Hash256, found: Hash256 },
    #[error("snapshot commitment {found} does not match pinned hash {expected}")]
    SnapshotCommitmentMismatch { expected: Hash256, found: Hash256 },
    #[error(
        "node previously failed assumeutxo validation at base height {base_height}: expected {expected_hash_serialized}, found {actual_hash_serialized}; failing closed"
    )]
    PreviouslyFailed {
        base_height: u32,
        expected_hash_serialized: Hash256,
        actual_hash_serialized: Hash256,
    },
    #[error("cannot activate assumeutxo snapshot: assumeutxo validation is already in progress")]
    AlreadyActive,
    #[error("snapshot activation requires completion of full revalidation")]
    FullRevalidationRequired,
    #[error(
        "assumeutxo commitment mismatch at base height {base_height}: expected {expected}, actual {actual}"
    )]
    CommitmentMismatch {
        base_height: u32,
        expected: Hash256,
        actual: Hash256,
    },
    #[error("no historical chainstate present")]
    NoHistoricalChainstate,
    #[error(
        "historical validation reached unexpected block hash {found} at target height {base_height}, expected {expected}"
    )]
    HistoricalTargetHashMismatch {
        base_height: u32,
        expected: Hash256,
        found: Hash256,
    },
    #[error("apply error: {0}")]
    Apply(#[from] ApplyError),
    #[error("disconnect error: {0}")]
    Disconnect(#[from] DisconnectError),
    #[error("utxo error: {0}")]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
}

impl From<StateVerifyError> for AssumeUtxoError {
    fn from(error: StateVerifyError) -> Self {
        match error {
            StateVerifyError::Utxo(error) => Self::Utxo(error),
            StateVerifyError::CommitmentMismatch { expected, actual } => {
                Self::SnapshotCommitmentMismatch {
                    expected,
                    found: actual,
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainstatesSummary {
    pub active_chainstate: ActiveChainstateSummary,
    pub historical_chainstate: Option<HistoricalChainstateSummary>,
    pub status: AssumeUtxoDiskStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainstatesReport {
    pub lifecycle: ChainstatesSummary,
    pub headers: u32,
    pub active_verification_progress: Option<f64>,
    pub historical_verification_progress: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveChainstateSummary {
    pub role: ChainstateRole,
    pub height: Option<u32>,
    #[serde(with = "serde_opt_hash256")]
    pub hash: Option<Hash256>,
    pub validated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalChainstateSummary {
    pub base_height: u32,
    #[serde(with = "serde_hash256")]
    pub base_hash: Hash256,
    pub current_height: u32,
    #[serde(with = "serde_hash256")]
    pub current_hash: Hash256,
    #[serde(with = "serde_hash256")]
    pub expected_hash_serialized: Hash256,
    pub validated_utxo_count: u64,
}

pub type HistoricalFactsHook = Arc<dyn Fn(&Arc<bitcoin_rs_storage::CommittedFacts>) + Send + Sync>;

pub struct AssumeUtxoManager {
    lifecycle: Mutex<()>,
    network: Network,
    active_chainstate: Arc<Chainstate>,
    historical_chainstate: RwLock<Option<Arc<Chainstate>>>,
    data_dir: PathBuf,
    historical_checkpoint_interval: u32,
    ingest_chunk_bytes: usize,
    historical_facts_hook: RwLock<Option<HistoricalFactsHook>>,
}

impl std::fmt::Debug for AssumeUtxoManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeUtxoManager")
            .field("network", &self.network)
            .field("status", &self.status())
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

struct HistoricalRecovery {
    network: Network,
    data_dir: PathBuf,
    base_height: u32,
    base_hash: Hash256,
    historical_height: u32,
    historical_hash: Hash256,
    checkpoint: Option<HistoricalCheckpointRef>,
}

#[derive(Clone, Copy)]
struct ValidatingBase {
    base_height: u32,
    base_hash: Hash256,
    expected_hash_serialized: Hash256,
    chain_tx_count: u64,
}

impl AssumeUtxoManager {
    pub fn open(
        network: Network,
        active_chainstate: Arc<Chainstate>,
        data_dir: PathBuf,
    ) -> Result<Self, AssumeUtxoError> {
        Self::open_with_historical_checkpoint_interval(
            network,
            active_chainstate,
            data_dir,
            DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL,
        )
    }

    fn open_with_historical_checkpoint_interval(
        network: Network,
        active_chainstate: Arc<Chainstate>,
        data_dir: PathBuf,
        historical_checkpoint_interval: u32,
    ) -> Result<Self, AssumeUtxoError> {
        crate::recover_snapshot_activation(&active_chainstate, &data_dir)?;
        let loaded_status = active_chainstate
            .durable_head
            .load()?
            .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo);
        let historical =
            Self::restore_historical(&active_chainstate, network, &data_dir, &loaded_status)?;

        let manager = Self {
            lifecycle: Mutex::new(()),
            network,
            active_chainstate,
            historical_chainstate: RwLock::new(historical),
            data_dir,
            historical_checkpoint_interval: historical_checkpoint_interval.max(1),
            ingest_chunk_bytes: DEFAULT_INGEST_CHUNK_BYTES,
            historical_facts_hook: RwLock::new(None),
        };
        manager.finish_open()?;
        Ok(manager)
    }

    #[cfg(test)]
    pub(crate) fn with_ingest_chunk_bytes(mut self, bytes: usize) -> Self {
        self.ingest_chunk_bytes = bytes.max(1);
        self
    }

    fn restore_historical(
        active_chainstate: &Arc<Chainstate>,
        network: Network,
        data_dir: &Path,
        loaded_status: &AssumeUtxoDiskStatus,
    ) -> Result<Option<Arc<Chainstate>>, AssumeUtxoError> {
        match *loaded_status {
            AssumeUtxoDiskStatus::Failed {
                base_height,
                expected_hash_serialized,
                actual_hash_serialized,
                ..
            } => {
                active_chainstate.fail_closed_for_recovery();
                Err(AssumeUtxoError::PreviouslyFailed {
                    base_height,
                    expected_hash_serialized,
                    actual_hash_serialized,
                })
            }
            AssumeUtxoDiskStatus::Validating {
                base_height,
                base_hash,
                historical_height,
                historical_hash,
                checkpoint,
                ..
            } => {
                active_chainstate.set_role(ChainstateRole::AssumedActive {
                    base_height,
                    base_hash,
                });
                Self::open_historical_chainstate(
                    active_chainstate,
                    HistoricalRecovery {
                        network,
                        data_dir: data_dir.to_path_buf(),
                        base_height,
                        base_hash,
                        historical_height,
                        historical_hash,
                        checkpoint,
                    },
                )
                .map(Some)
            }
            AssumeUtxoDiskStatus::Finalized { .. } | AssumeUtxoDiskStatus::Uninitialized => {
                active_chainstate.set_role(ChainstateRole::Ordinary);
                Ok(None)
            }
        }
    }

    fn finish_open(&self) -> Result<(), AssumeUtxoError> {
        self.recover_pending().inspect_err(|_| {
            self.active_chainstate.fail_closed_for_recovery();
        })?;
        match self.status()? {
            AssumeUtxoDiskStatus::Validating {
                checkpoint: Some(checkpoint),
                ..
            } => self.cleanup_historical_checkpoints(Some(checkpoint.checkpoint)),
            AssumeUtxoDiskStatus::Finalized { .. } => self.cleanup_historical_checkpoints(None),
            _ => {}
        }
        Ok(())
    }

    fn open_historical_chainstate(
        active: &Arc<Chainstate>,
        recovery: HistoricalRecovery,
    ) -> Result<Arc<Chainstate>, AssumeUtxoError> {
        let Some(checkpoint) = recovery.checkpoint else {
            return active.create_historical_counterpart(
                recovery.base_height,
                recovery.base_hash,
                None,
                None,
            );
        };
        if checkpoint.height > recovery.historical_height
            || checkpoint.height > recovery.base_height
        {
            return Err(AssumeUtxoError::HistoricalCheckpointAheadOfProgress);
        }
        let restored = Self::load_historical_checkpoint(&recovery, &checkpoint)?;
        Self::install_historical_checkpoint(active, recovery, &checkpoint, restored)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn historical_checkpoint_engine(
        network: Network,
        data_dir: PathBuf,
        checkpoint: &HistoricalCheckpointRef,
    ) -> Result<Option<Arc<dyn bitcoin_rs_storage::KvStore>>, AssumeUtxoError> {
        let recovery = HistoricalRecovery {
            network,
            data_dir,
            base_height: checkpoint.height,
            base_hash: checkpoint.hash,
            historical_height: checkpoint.height,
            historical_hash: checkpoint.hash,
            checkpoint: Some(*checkpoint),
        };
        Ok(Self::load_historical_checkpoint(&recovery, checkpoint)?.engine)
    }

    fn load_historical_checkpoint(
        recovery: &HistoricalRecovery,
        checkpoint: &HistoricalCheckpointRef,
    ) -> Result<crate::checkpoint::RestoredChainstate, AssumeUtxoError> {
        let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&recovery.data_dir)
            .map_err(|error| AssumeUtxoError::HistoricalCheckpointDir { error })?;
        let config = crate::checkpoint::headers::HeaderCheckpointConfig {
            network: recovery.network,
            genesis: recovery.network.genesis_block_hash(),
        };
        let loaded = crate::checkpoint::load_checkpoint_generation_from_dir_with_path(
            &data,
            Some(&recovery.data_dir),
            config,
            bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
            checkpoint.checkpoint,
        )
        .map_err(|error| AssumeUtxoError::HistoricalCheckpointLoad { error })?;
        let crate::checkpoint::CheckpointLoad::Complete(restored) = loaded else {
            return Err(AssumeUtxoError::HistoricalCheckpointNotPublished);
        };
        if restored.generation != checkpoint.checkpoint.generation
            || restored.applied_tip.height != checkpoint.height
            || restored.applied_tip.hash != checkpoint.hash
        {
            return Err(AssumeUtxoError::HistoricalCheckpointReferenceMismatch);
        }
        if restored.applied_tip.chain_tx_count.get().is_none() {
            return Err(AssumeUtxoError::HistoricalCheckpointWithoutTransactionCount);
        }
        if restored.engine.is_none() {
            return Err(AssumeUtxoError::HistoricalCheckpointWithoutEngine);
        }
        Ok(*restored)
    }

    fn install_historical_checkpoint(
        active: &Arc<Chainstate>,
        recovery: HistoricalRecovery,
        checkpoint: &HistoricalCheckpointRef,
        restored: crate::checkpoint::RestoredChainstate,
    ) -> Result<Arc<Chainstate>, AssumeUtxoError> {
        let HistoricalRecovery {
            base_height,
            base_hash,
            ..
        } = recovery;
        let mut tree = active.block_tree.write();
        let base_id = tree
            .lookup(base_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(base_hash))?;
        let checkpoint_id = tree
            .node_at_height_from(base_id, checkpoint.height)
            .ok_or(AssumeUtxoError::HistoricalCheckpointNotOnAncestry)?;
        let checkpoint_node = tree.node(checkpoint_id).map_err(ApplyError::from)?;
        if checkpoint_node.hash != checkpoint.hash || checkpoint_node.height != checkpoint.height {
            return Err(AssumeUtxoError::HistoricalCheckpointHashNotOnAncestry);
        }
        let checkpoint_height = checkpoint_node.height;
        let checkpoint_hash = checkpoint_node.hash;
        let checkpoint_chainwork = checkpoint_node.chainwork;
        let progress_id = tree
            .node_at_height_from(base_id, recovery.historical_height)
            .ok_or(AssumeUtxoError::HistoricalProgressNotOnAncestry)?;
        let progress_node = tree.node(progress_id).map_err(ApplyError::from)?;
        if progress_node.hash != recovery.historical_hash {
            return Err(AssumeUtxoError::DurableHistoricalProgressNotOnAncestry);
        }
        tree.restore_chain_tx_count(checkpoint_id, restored.applied_tip.chain_tx_count)
            .map_err(ApplyError::from)?;
        let applied_tip = TipSnapshot {
            tip_id: checkpoint_id,
            height: checkpoint_height,
            chainwork: checkpoint_chainwork,
            hash: checkpoint_hash,
            chain_tx_count: restored.applied_tip.chain_tx_count,
        };
        drop(tree);
        active.create_historical_counterpart(
            base_height,
            base_hash,
            restored.engine,
            Some(applied_tip),
        )
    }

    #[cfg(test)]
    pub(crate) fn activate_pinned_snapshot(
        &self,
        set: UtxoSet,
        base_hash: Hash256,
        pinned: &AssumeUtxoData,
    ) -> Result<(), AssumeUtxoError> {
        self.activate_pinned_snapshot_with(set, base_hash, pinned, |_, _| {}, || true)
            .map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn activate_pinned_snapshot_with(
        &self,
        set: UtxoSet,
        base_hash: Hash256,
        pinned: &AssumeUtxoData,
        mut observe: impl FnMut(Hash256, &UtxoRecord),
        admit: impl FnOnce() -> bool,
    ) -> Result<ActivatedSnapshot, AssumeUtxoError> {
        if base_hash != pinned.block_hash {
            return Err(AssumeUtxoError::SnapshotBlockHashMismatch {
                expected: pinned.block_hash,
                found: base_hash,
            });
        }
        let commitment = set.lock_stable_view().hash_serialized_3()?;
        if commitment != pinned.hash_serialized {
            return Err(AssumeUtxoError::SnapshotCommitmentMismatch {
                expected: pinned.hash_serialized,
                found: commitment,
            });
        }
        let stats = set.with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, pinned.height, true)
        })?;
        let record_count = u64::try_from(set.record_count()).map_err(|_| {
            AssumeUtxoError::Storage(bitcoin_rs_storage::StorageError::InvalidOperation(
                "snapshot record count does not fit u64",
            ))
        })?;
        let records = set.all_records();
        let limit = self.ingest_chunk_bytes;
        self.activate_streamed(pinned, record_count, move |coins| {
            let mut staged = StagedCoins::new(limit);
            for record in &records {
                observe(record.txid(), record);
                stage_record(&mut staged, coins, record.txid(), record)?;
            }
            finish_stage(&mut staged, coins)?;
            if !admit() {
                return Err(AssumeUtxoError::ObserverRefused);
            }
            Ok(StreamedCoins { coin_stats: stats })
        })
    }

    pub fn activate_core_snapshot<R: Read + Seek>(
        &self,
        reader: &mut R,
        attestation: Option<FileAttestation>,
        observe: impl FnMut(Hash256, &UtxoRecord),
        admit: impl FnOnce() -> bool,
    ) -> Result<ActivatedSnapshot, AssumeUtxoError> {
        let body_start = reader.stream_position().map_err(storage_io)?;
        if self.active_chainstate.has_durable_head()? {
            CoreSnapshotStream::open(reader, self.network)?
                .stream(|_, _| Ok::<(), AssumeUtxoError>(()))?;
            rewind_to(reader, body_start)?;
        }
        let ingested = Rc::new(RefCell::new(IngestDigest::default()));
        let mut hashed = DigestingReader {
            inner: reader,
            digest: Rc::clone(&ingested),
        };
        let snapshot = CoreSnapshotStream::open(&mut hashed, self.network)?;
        let pinned = snapshot.anchor();
        let declared_coins = snapshot.metadata().coins_count;
        let limit = self.ingest_chunk_bytes;
        self.activate_streamed(pinned, declared_coins, move |coins| {
            let mut observe = observe;
            let mut staged = StagedCoins::new(limit);
            let streamed = snapshot.stream(|txid, record| {
                observe(txid, record);
                stage_record(&mut staged, coins, txid, record).map_err(AssumeUtxoError::Storage)
            })?;
            finish_stage(&mut staged, coins)?;
            if let Some(expected) = attestation {
                let found = std::mem::take(&mut *ingested.borrow_mut()).finish();
                if found.sha256 != expected.sha256 || found.size != expected.size {
                    return Err(AssumeUtxoError::ArtifactDigestMismatch {
                        expected_sha256: expected.sha256,
                        found_sha256: found.sha256,
                        expected_size: expected.size,
                        found_size: found.size,
                    });
                }
            }
            if !admit() {
                return Err(AssumeUtxoError::ObserverRefused);
            }
            Ok(StreamedCoins {
                coin_stats: streamed.coin_stats,
            })
        })
    }

    fn require_unactivated(&self) -> Result<(), AssumeUtxoError> {
        if !matches!(self.status()?, AssumeUtxoDiskStatus::Uninitialized) {
            return Err(AssumeUtxoError::AlreadyActive);
        }
        if crate::recovery::requires_full_revalidation(&self.data_dir) {
            return Err(AssumeUtxoError::FullRevalidationRequired);
        }
        Ok(())
    }

    fn activate_streamed<S>(
        &self,
        pinned: &AssumeUtxoData,
        declared_coins: u64,
        stream: S,
    ) -> Result<ActivatedSnapshot, AssumeUtxoError>
    where
        S: FnOnce(&bitcoin_rs_storage::CoinStore) -> Result<StreamedCoins, AssumeUtxoError>,
    {
        let _lifecycle = self.lifecycle.lock();
        self.require_unactivated()?;
        let genesis_hash = self.network.genesis_block_hash();
        let new_status = AssumeUtxoDiskStatus::Validating {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
            expected_hash_serialized: pinned.hash_serialized,
            chain_tx_count: pinned.chain_tx_count,
            historical_height: 0,
            historical_hash: genesis_hash,
            pending: None,
            checkpoint: None,
        };
        let activation_authority = Arc::clone(&self.active_chainstate.commit_authority);
        self.active_chainstate.install_snapshot(
            pinned,
            declared_coins,
            stream,
            |coins, block_tree, tip, prior, marker, _streamed| {
                if crate::recovery::requires_full_revalidation(&self.data_dir) {
                    return Err(AssumeUtxoError::FullRevalidationRequired);
                }
                let commitment = coins
                    .commitment(pinned.height, None)
                    .map_err(AssumeUtxoError::Utxo)?;
                if commitment.hash_serialized != pinned.hash_serialized {
                    return Err(AssumeUtxoError::ActivationCommitmentMismatch);
                }
                let mut stats = commitment.stats;
                stats.tx_count = pinned.chain_tx_count;
                let listener =
                    bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(stats);
                let data_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&self.data_dir)
                    .map_err(|error| {
                        AssumeUtxoError::Storage(bitcoin_rs_storage::StorageError::Io(error))
                    })?;
                let config = crate::checkpoint::headers::HeaderCheckpointConfig {
                    network: self.network,
                    genesis: self.network.genesis_block_hash(),
                };
                let written = crate::checkpoint::write_checkpoint_with_store(
                    &data_dir,
                    config,
                    block_tree,
                    &listener,
                    Some(tip),
                    crate::checkpoint::CheckpointStoreTarget {
                        store: coins.store().as_ref(),
                        host_data_dir: &self.data_dir,
                    },
                )
                .map_err(|error| AssumeUtxoError::ActivationCheckpointPublish { error })?;
                if !matches!(
                    written,
                    crate::checkpoint::CheckpointWrite::Published { .. }
                ) {
                    return Err(AssumeUtxoError::ActivationCheckpointPublish {
                        error: crate::checkpoint::CheckpointError::Store(
                            bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                                "snapshot-base checkpoint publish skipped".to_owned(),
                            ),
                        ),
                    });
                }
                let witness = bitcoin_rs_storage::recovery_evidence::AppliedTipWitness::new(
                    self.network.genesis_block_hash().to_string_be(),
                    self.active_chainstate.chain_events.epoch(),
                    tip.height,
                    tip.hash.to_string_be(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                );
                bitcoin_rs_storage::recovery_evidence::write_witness(&self.data_dir, &witness)
                    .map_err(|error| {
                        AssumeUtxoError::Storage(bitcoin_rs_storage::StorageError::backend(
                            error.to_string(),
                        ))
                    })?;
                let next = bitcoin_rs_storage::DurableHead {
                    assumeutxo: new_status,
                    commit_id: prior.map_or(1, |head| head.commit_id + 1),
                    height: pinned.height,
                    tip: pinned.block_hash,
                    chain_tx_count: pinned.chain_tx_count,
                    body_extent: prior.and_then(|head| head.body_extent),
                    undo_extent: prior.and_then(|head| head.undo_extent),
                };
                if let Err(error) = activation_authority.commit_snapshot_activation(
                    bitcoin_rs_storage::AcceptedPrefix {
                        expected_head: prior.cloned(),
                        next_head: next,
                        undo_rows: Vec::new(),
                        body_rows: Vec::new(),
                        attestation: Some(bitcoin_rs_storage::ScriptAttestation::AssumeValid),
                        coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                    },
                    marker,
                ) {
                    let landed = match self.active_chainstate.durable_head.load() {
                        Ok(head) => head.is_some_and(|head| head.tip == pinned.block_hash),
                        Err(error) => {
                            tracing::warn!(
                                %error,
                                "snapshot activation commit failed and the head is unreadable; keeping the published checkpoint"
                            );
                            true
                        }
                    };
                    if !landed {
                        if let Err(error) = remove_orphan_base_checkpoint(
                            &self.data_dir,
                            &pinned.block_hash,
                        ) {
                            tracing::warn!(
                                %error,
                                "failed activation orphan checkpoint was not removed; the durable activation marker retries the rollback on the next boot"
                            );
                        }
                    }
                    return Err(commit_error(error));
                }
                Ok(())
            },
        )?;
        let historical = self.active_chainstate.create_historical_counterpart(
            pinned.height,
            pinned.block_hash,
            None,
            None,
        )?;
        *self.historical_chainstate.write() = Some(historical);
        Ok(ActivatedSnapshot {
            base_hash: pinned.block_hash,
            height: pinned.height,
            declared_coins,
        })
    }
    pub fn set_historical_facts_hook(&self, hook: HistoricalFactsHook) {
        let _lifecycle = self.lifecycle.lock();
        *self.historical_facts_hook.write() = Some(hook);
    }

    pub fn clear_historical_facts_hook(&self) {
        let _lifecycle = self.lifecycle.lock();
        self.historical_facts_hook.write().take();
    }

    pub fn step_historical(&self, payload: &BlockImage) -> Result<ConnectOutcome, AssumeUtxoError> {
        let _lifecycle = self.lifecycle.lock();
        let historical = self
            .historical_chainstate
            .read()
            .clone()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
        let (outcome, archived) = self.connect_historical_block(&historical, payload)?;
        if !archived {
            self.record_historical_progress(&historical, payload, &outcome)?;
        }
        historical
            .undo_store
            .remove_archived(outcome.height, outcome.hash)?;
        if let (Some(hook), Some(facts)) = (
            self.historical_facts_hook.read().as_ref(),
            outcome.committed_facts.as_ref(),
        ) {
            hook(facts);
        }
        Ok(outcome)
    }
    fn connect_historical_block(
        &self,
        historical: &Arc<Chainstate>,
        payload: &BlockImage,
    ) -> Result<(ConnectOutcome, bool), AssumeUtxoError> {
        let expected_prev = historical
            .applied_tip_snapshot()
            .map_or_else(Hash256::default, |tip| tip.hash);
        let header = payload.header();
        if header.prev_blockhash.0 != expected_prev {
            return Err(ApplyError::PrevHashMismatch {
                tip: expected_prev,
                prev: header.prev_blockhash.0,
            }
            .into());
        }
        let archived = self
            .begin_historical(payload, historical)
            .inspect_err(|_| {
                self.active_chainstate.fail_closed_for_recovery();
                historical.fail_closed_for_recovery();
            })?;
        historical.set_committed_facts_consumer(self.historical_facts_hook.read().is_some());
        let result = {
            let transition = historical.lock_transition()?.into_transition();
            transition.connect(payload)
        };
        match result {
            Err(ApplyError::HistoricalTargetHashMismatch {
                base_height,
                expected,
                found,
            }) => {
                self.fail_historical(historical)?;
                Err(AssumeUtxoError::HistoricalTargetHashMismatch {
                    base_height,
                    expected,
                    found,
                })
            }
            Err(error) => {
                if matches!(
                    crate::classify_apply_error(&error),
                    crate::WindowApplyDisposition::Permanent | crate::WindowApplyDisposition::Fatal
                ) {
                    self.fail_historical(historical)?;
                }
                Err(error.into())
            }
            Ok(outcome) => Ok((outcome, archived)),
        }
    }

    fn record_historical_progress(
        &self,
        historical: &Arc<Chainstate>,
        payload: &BlockImage,
        outcome: &ConnectOutcome,
    ) -> Result<(), AssumeUtxoError> {
        let current_status = self.status().inspect_err(|_| {
            self.active_chainstate.fail_closed_for_recovery();
            historical.fail_closed_for_recovery();
        })?;
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            chain_tx_count,
            checkpoint,
            ..
        } = current_status
        else {
            return Ok(());
        };
        let base = ValidatingBase {
            base_height,
            base_hash,
            expected_hash_serialized,
            chain_tx_count,
        };
        if outcome.height < base_height {
            let updated = AssumeUtxoDiskStatus::Validating {
                base_height,
                base_hash,
                expected_hash_serialized,
                chain_tx_count,
                historical_height: outcome.height,
                historical_hash: outcome.hash,
                pending: None,
                checkpoint,
            };
            return self
                .persist_status(updated, Some((payload, historical.as_ref())))
                .inspect_err(|_| {
                    self.active_chainstate.fail_closed_for_recovery();
                    historical.fail_closed_for_recovery();
                });
        }
        if outcome.height != base_height {
            return Ok(());
        }
        self.finalize_historical_progress(historical, payload, base, outcome.hash)
    }

    fn finalize_historical_progress(
        &self,
        historical: &Arc<Chainstate>,
        payload: &BlockImage,
        base: ValidatingBase,
        outcome_hash: Hash256,
    ) -> Result<(), AssumeUtxoError> {
        if outcome_hash != base.base_hash {
            self.fail_historical(historical)?;
            return Err(AssumeUtxoError::HistoricalTargetHashMismatch {
                base_height: base.base_height,
                expected: base.base_hash,
                found: outcome_hash,
            });
        }
        let actual_hash_serialized = historical
            .coins
            .commitment(base.base_height, None)
            .inspect_err(|_| {
                self.active_chainstate.fail_closed_for_recovery();
                historical.fail_closed_for_recovery();
            })?
            .hash_serialized;
        let actual_count = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.chain_tx_count.to_wire());
        if actual_count != base.chain_tx_count {
            self.fail_historical(historical)?;
            return Err(AssumeUtxoError::HistoricalTransactionCountMismatch {
                expected: base.chain_tx_count,
                found: actual_count,
            });
        }
        if actual_hash_serialized != base.expected_hash_serialized {
            self.fail_historical(historical)?;
            return Err(AssumeUtxoError::CommitmentMismatch {
                base_height: base.base_height,
                expected: base.expected_hash_serialized,
                actual: actual_hash_serialized,
            });
        }
        let finalized = AssumeUtxoDiskStatus::Finalized {
            base_height: base.base_height,
            base_hash: base.base_hash,
            validated_hash_serialized: actual_hash_serialized,
        };
        self.persist_status(finalized, Some((payload, historical.as_ref())))
            .inspect_err(|_| {
                self.active_chainstate.fail_closed_for_recovery();
                historical.fail_closed_for_recovery();
            })?;
        self.active_chainstate.set_role(ChainstateRole::Ordinary);
        *self.historical_chainstate.write() = None;
        Ok(())
    }

    pub fn next_historical_block(&self) -> Result<Option<(u32, Hash256)>, AssumeUtxoError> {
        let historical = self.historical_chainstate.read().clone();
        let Some(historical) = historical else {
            return Ok(None);
        };
        if self.active_chainstate.is_closed_for_recovery() || historical.is_closed_for_recovery() {
            return Err(ApplyError::Shutdown.into());
        }
        let ChainstateRole::Historical {
            base_height,
            base_hash,
        } = historical.role()
        else {
            return Err(AssumeUtxoError::NoHistoricalChainstate);
        };
        let height = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height + 1);
        if height > base_height {
            return Ok(None);
        }
        let tree = self.active_chainstate.block_tree.read();
        let base = tree
            .lookup(base_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(base_hash))?;
        let id = tree
            .node_at_height_from(base, height)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(base_hash))?;
        Ok(Some((
            height,
            tree.node(id).map_err(ApplyError::from)?.hash,
        )))
    }

    pub fn advance_historical(&self) -> Result<HistoricalAdvance, AssumeUtxoError> {
        for _ in 0..8 {
            let Some((height, hash)) = self.next_historical_block()? else {
                return Ok(HistoricalAdvance::Complete);
            };
            if height == 0 {
                let genesis_payload = BlockImage::from_local(self.network.genesis_block());
                self.step_historical(&genesis_payload)?;
                continue;
            }
            let bytes = match &self.active_chainstate.block_body_store {
                Some(store) => store.load_block_body(height, hash)?,
                None => None,
            };
            let Some(bytes) = bytes else {
                return Ok(HistoricalAdvance::MissingBody { height, hash });
            };
            let payload = BlockImage::from_raw(bytes::Bytes::from(bytes))?;
            if payload.block_hash().0 != hash {
                return Err(AssumeUtxoError::HistoricalBodyIdentityMismatch);
            }
            self.step_historical(&payload)?;
        }
        if self.next_historical_block()?.is_some() {
            Ok(HistoricalAdvance::ReplayPending)
        } else {
            Ok(HistoricalAdvance::Complete)
        }
    }

    pub fn chainstates_summary(&self) -> Result<ChainstatesSummary, AssumeUtxoError> {
        let lifecycle = self.lifecycle.lock();
        self.capture_chainstates_report(&lifecycle)
            .map(|report| report.lifecycle)
    }

    pub fn try_chainstates_report(&self) -> Result<Option<ChainstatesReport>, AssumeUtxoError> {
        let Some(lifecycle) = self.lifecycle.try_lock() else {
            return Ok(None);
        };
        self.capture_chainstates_report(&lifecycle).map(Some)
    }

    fn capture_chainstates_report(
        &self,
        _lifecycle: &MutexGuard<'_, ()>,
    ) -> Result<ChainstatesReport, AssumeUtxoError> {
        let _transition = self.active_chainstate.chain_transition.lock();
        let active_role = self.active_chainstate.role();
        let active_applied = self.active_chainstate.applied_tip_snapshot();
        let now = bitcoin_rs_consensus::primitives::unix_time_secs();
        let reader = self.active_chainstate.chain_progress_reader();
        let active_progress = reader.progress_at(active_applied.as_deref(), self.network, now);
        let active_summary = ActiveChainstateSummary {
            role: active_role,
            height: active_applied.as_ref().map(|tip| tip.height),
            hash: active_applied.as_ref().map(|tip| tip.hash),
            validated: active_role.is_ordinary(),
        };
        let status = self.status()?;
        let (historical_summary, historical_verification_progress) =
            match (status, self.historical_chainstate.read().as_ref()) {
                (
                    AssumeUtxoDiskStatus::Validating {
                        base_height,
                        base_hash,
                        expected_hash_serialized,
                        ..
                    },
                    Some(historical),
                ) => {
                    let applied = historical.applied_tip_snapshot();
                    let progress = reader.progress_at(applied.as_deref(), self.network, now);
                    (
                        Some(HistoricalChainstateSummary {
                            base_height,
                            base_hash,
                            current_height: applied.as_ref().map_or(0, |tip| tip.height),
                            current_hash: applied
                                .as_ref()
                                .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash),
                            expected_hash_serialized,
                            validated_utxo_count: historical.coin_stats.snapshot().utxo_count,
                        }),
                        known_progress(applied.as_deref(), progress.verification_progress),
                    )
                }
                _ => (None, None),
            };
        Ok(ChainstatesReport {
            headers: active_progress.headers,
            active_verification_progress: known_progress(
                active_applied.as_deref(),
                active_progress.verification_progress,
            ),
            historical_verification_progress,
            lifecycle: ChainstatesSummary {
                active_chainstate: active_summary,
                historical_chainstate: historical_summary,
                status,
            },
        })
    }

    #[must_use]
    pub fn active_chainstate(&self) -> Arc<Chainstate> {
        Arc::clone(&self.active_chainstate)
    }

    #[must_use]
    #[cfg(test)]
    fn historical_chainstate(&self) -> Option<Arc<Chainstate>> {
        self.historical_chainstate.read().clone()
    }

    pub fn status(&self) -> Result<AssumeUtxoDiskStatus, AssumeUtxoError> {
        Ok(self
            .active_chainstate
            .durable_head
            .load()?
            .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo))
    }

    fn fail_historical(&self, historical: &Chainstate) -> Result<(), AssumeUtxoError> {
        self.active_chainstate.fail_closed_for_recovery();
        historical.fail_closed_for_recovery();
        if let AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            ..
        } = self.status()?
        {
            let actual_hash_serialized = historical
                .coins
                .commitment(base_height, None)?
                .hash_serialized;
            let failed = AssumeUtxoDiskStatus::Failed {
                base_height,
                base_hash,
                expected_hash_serialized,
                actual_hash_serialized,
            };
            self.persist_status(failed, None)?;
        }
        Ok(())
    }

    fn begin_historical(
        &self,
        image: &BlockImage,
        historical: &Chainstate,
    ) -> Result<bool, AssumeUtxoError> {
        let active = &self.active_chainstate;
        let _transition = active.lock_transition()?;
        let mut status = self.status()?;
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            historical_height,
            pending,
            ..
        } = &mut status
        else {
            return Err(AssumeUtxoError::NoHistoricalChainstate);
        };
        let height = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height + 1);
        let hash = image.block_hash().0;
        if height < *base_height
            && height <= *historical_height
            && self.next_historical_block()? == Some((height, hash))
            && active.undo_store.load_undo(height, hash)?.is_some()
        {
            return Ok(true);
        }
        if pending.is_some_and(|record| record.height == height && record.hash == hash) {
            return Ok(false);
        }
        let prior = active
            .durable_head
            .load()?
            .ok_or(AssumeUtxoError::MissingDurableAnchor)?;
        let position = match &active.block_body_store {
            Some(store) => {
                let position = store.stage_block_body(height, hash, image.bytes().as_ref())?;
                store.sync()?;
                position
            }
            None => None,
        };
        *pending = Some(bitcoin_rs_storage::assumeutxo::PendingHistoricalBlock {
            height,
            hash,
            position,
        });
        let next = bitcoin_rs_storage::DurableHead {
            commit_id: prior.commit_id + 1,
            assumeutxo: status,
            body_extent: active
                .block_body_store
                .as_ref()
                .and_then(|store| store.append_cursor())
                .or(prior.body_extent),
            ..prior
        };
        active
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: Some(prior),
                next_head: next,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(commit_error)?;
        Ok(false)
    }

    fn recover_pending(&self) -> Result<(), AssumeUtxoError> {
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            pending: Some(pending),
            ..
        } = self.status()?
        else {
            return Ok(());
        };
        if pending.height > base_height {
            return Err(AssumeUtxoError::ValidationIntentExceedsBase);
        }
        let historical = self
            .historical_chainstate
            .read()
            .clone()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
        let replay_start = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height.saturating_add(1));
        if replay_start > pending.height {
            return Err(AssumeUtxoError::HistoricalCheckpointAheadOfIntent);
        }
        for height in replay_start..pending.height {
            let (_, hash) = self
                .next_historical_block()?
                .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
            let payload = if height == 0 {
                BlockImage::from_local(self.network.genesis_block())
            } else {
                let bytes = self
                    .active_chainstate
                    .block_body_store
                    .as_ref()
                    .ok_or(AssumeUtxoError::MissingHistoricalBodyStore)?
                    .load_block_body(height, hash)?
                    .ok_or(AssumeUtxoError::MissingHistoricalDependencyBody)?;
                BlockImage::from_raw(bytes::Bytes::from(bytes))?
            };
            if payload.block_hash().0 != hash {
                return Err(AssumeUtxoError::HistoricalDependencyIdentityMismatch);
            }
            historical
                .lock_transition()?
                .into_transition()
                .connect(&payload)?;
            historical.undo_store.remove_archived(height, hash)?;
        }
        let payload = if pending.height == 0 && pending.hash == self.network.genesis_block_hash() {
            BlockImage::from_local(self.network.genesis_block())
        } else {
            let bytes = self
                .active_chainstate
                .block_body_store
                .as_ref()
                .ok_or(AssumeUtxoError::MissingPendingBodyStore)?
                .load_staged_body(pending.height, pending.hash, pending.position)?
                .ok_or(AssumeUtxoError::MissingPendingBody)?;
            BlockImage::from_raw(bytes::Bytes::from(bytes))?
        };
        if payload.block_hash().0 != pending.hash {
            return Err(AssumeUtxoError::PendingBodyIdentityMismatch);
        }
        self.step_historical(&payload)?;
        Ok(())
    }

    fn persist_status(
        &self,
        mut status: AssumeUtxoDiskStatus,
        historical_block: Option<(&BlockImage, &Chainstate)>,
    ) -> Result<(), AssumeUtxoError> {
        let active = &self.active_chainstate;
        let _transition = active.chain_transition.lock();
        let prior = active
            .durable_head
            .load()?
            .ok_or(AssumeUtxoError::MissingDurableAnchor)?;
        self.maybe_publish_historical_checkpoint(&mut status, historical_block.map(|(_, cs)| cs))?;
        let mut body_rows: Vec<(u32, Hash256, bitcoin_rs_storage::BlockFilePosition)> = Vec::new();
        let mut undo_rows: Vec<(u32, Hash256, bytes::Bytes)> = Vec::new();
        if let Some((block, historical)) = historical_block {
            let tip = historical
                .applied_tip_snapshot()
                .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
            let undo = historical
                .undo_store
                .load_undo(tip.height, tip.hash)?
                .ok_or(AssumeUtxoError::MissingHistoricalUndo)?;
            undo_rows.push((tip.height, tip.hash, bytes::Bytes::copy_from_slice(&undo)));
            if let Some(store) = &active.block_body_store {
                let staged = match prior.assumeutxo {
                    AssumeUtxoDiskStatus::Validating {
                        pending: Some(pending),
                        ..
                    } if pending.height == tip.height && pending.hash == tip.hash => {
                        pending.position
                    }
                    _ => None,
                };
                let position = match staged {
                    Some(position) => Some(position),
                    None => store.stage_block_body(tip.height, tip.hash, block.bytes())?,
                };
                store.sync()?;
                if let Some(position) = position {
                    body_rows.push((tip.height, tip.hash, position));
                }
            }
        }
        let next = bitcoin_rs_storage::DurableHead {
            commit_id: prior.commit_id + 1,
            assumeutxo: status,
            undo_extent: undo_rows
                .last()
                .map(|(height, hash, _)| (*height, *hash))
                .filter(|(height, _)| prior.undo_extent.is_none_or(|(old, _)| *height > old))
                .or(prior.undo_extent),
            body_extent: active
                .block_body_store
                .as_ref()
                .and_then(|store| store.append_cursor())
                .or(prior.body_extent),
            ..prior
        };
        let finalized_full = match status {
            AssumeUtxoDiskStatus::Finalized {
                base_height,
                base_hash,
                ..
            } => {
                (next.height == base_height && next.tip == base_hash)
                    || active.durable_head.load_suffix_attestation(&prior)?
                        >= bitcoin_rs_storage::ScriptAttestation::Full
            }
            _ => false,
        };
        active
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: Some(prior),
                next_head: next,
                undo_rows,
                body_rows,
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(commit_error)?;
        if finalized_full {
            active
                .durable_head
                .attest(&next, bitcoin_rs_storage::ScriptAttestation::Full)?;
        }
        if let AssumeUtxoDiskStatus::Validating {
            checkpoint: Some(checkpoint),
            ..
        } = status
        {
            let previous = match prior.assumeutxo {
                AssumeUtxoDiskStatus::Validating { checkpoint, .. } => checkpoint,
                _ => None,
            };
            if previous != Some(checkpoint) {
                self.cleanup_historical_checkpoints(Some(checkpoint.checkpoint));
            }
        } else if matches!(status, AssumeUtxoDiskStatus::Finalized { .. }) {
            self.cleanup_historical_checkpoints(None);
        }
        Ok(())
    }

    fn cleanup_historical_checkpoints(
        &self,
        retained: Option<bitcoin_rs_storage::checkpoint::CheckpointReference>,
    ) {
        let cleanup = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&self.data_dir)
            .map_err(bitcoin_rs_storage::checkpoint::CheckpointError::from)
            .and_then(|data| match retained {
                Some(reference) => {
                    bitcoin_rs_storage::checkpoint::retire_checkpoint_generations_at(
                        &data,
                        bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
                        reference.generation,
                    )
                }
                None => bitcoin_rs_storage::checkpoint::clear_checkpoint_generations_at(
                    &data,
                    bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
                ),
            });
        if let Err(error) = cleanup {
            tracing::warn!(%error, "historical checkpoint cleanup deferred");
        }
    }

    fn maybe_publish_historical_checkpoint(
        &self,
        status: &mut AssumeUtxoDiskStatus,
        historical: Option<&Chainstate>,
    ) -> Result<(), AssumeUtxoError> {
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            historical_height,
            checkpoint,
            ..
        } = status
        else {
            return Ok(());
        };
        let interval = self.historical_checkpoint_interval.max(1);
        let due = *historical_height
            >= (*checkpoint).map_or(interval, |ref_| ref_.height.saturating_add(interval));
        if !due {
            return Ok(());
        }
        let Some(historical) = historical else {
            return Err(AssumeUtxoError::CheckpointDueWithoutChainstate);
        };
        let tip = historical
            .applied_tip_snapshot()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
        if tip.height != *historical_height || tip.height > *base_height {
            return Err(AssumeUtxoError::CheckpointTipMismatch);
        }
        let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&self.data_dir)
            .map_err(|error| AssumeUtxoError::HistoricalCheckpointDir { error })?;
        let config = crate::checkpoint::headers::HeaderCheckpointConfig {
            network: self.network,
            genesis: self.network.genesis_block_hash(),
        };
        let write = crate::checkpoint::write_historical_checkpoint_with_store(
            &data,
            config,
            &historical.block_tree,
            &historical.coin_stats,
            Some(&tip),
            crate::checkpoint::CheckpointStoreTarget {
                store: historical.commit_authority.store().as_ref(),
                host_data_dir: &self.data_dir,
            },
        )
        .map_err(|error| AssumeUtxoError::HistoricalCheckpointPublish { error })?;
        let reference = match write {
            crate::checkpoint::CheckpointWrite::Published { reference } => reference,
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                return Err(AssumeUtxoError::NoHistoricalChainstate);
            }
        };
        *checkpoint = Some(HistoricalCheckpointRef {
            checkpoint: reference,
            height: tip.height,
            hash: tip.hash,
        });
        Ok(())
    }
}

#[cfg(any(test, verification, kani))]
pub(crate) mod proofs;
#[cfg(test)]
mod tests;

fn known_progress(tip: Option<&TipSnapshot>, progress: f64) -> Option<f64> {
    match tip {
        None => None,
        Some(tip) => tip.chain_tx_count.get().map(|_| progress),
    }
}
