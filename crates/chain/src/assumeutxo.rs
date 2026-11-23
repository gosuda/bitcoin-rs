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
        let mut restored = crate::chain::BlockTree::new();
        restored
            .insert_header(
                active.network.genesis_block().header,
                NodeStatus::HeaderValid,
            )
            .map_err(crate::error::ApplyError::from)?;
        active
            .header_retention
            .restore_operator_verdicts(&mut restored)
            .map_err(crate::error::ApplyError::from)?;
        *tree = restored;
        active.reevaluate_assume_valid_with(&tree);
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

fn known_progress(tip: Option<&TipSnapshot>, progress: f64) -> Option<f64> {
    match tip {
        None => None,
        Some(tip) => tip.chain_tx_count.get().map(|_| progress),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use crate::chain::NodeStatus;
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::{AssumeUtxoData, Block, BlockImage, Hash256, Network};
    use bitcoin_rs_storage::DurableHead;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
    use bitcoin_rs_storage::utxo::{
        SnapshotLoad, UtxoSet, read_snapshot_strict_v4, write_snapshot_observed,
    };
    use parking_lot::RwLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{
        AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, ChainstateRole, known_progress,
    };
    use crate::test_fixtures::{TestError, TestResult, handles, seed_durable_head, seed_genesis};
    use crate::{ApplyError, Chainstate};

    fn chainstate() -> Arc<Chainstate> {
        let stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
        let mut utxo = UtxoSet::new();
        utxo.track_coin_stats((*stats).clone());
        let mut chainstate = handles(Network::Regtest, Arc::new(utxo));
        chainstate.coin_stats = stats;
        Arc::new(chainstate)
    }

    struct ActivationFault {
        fail: AtomicBool,
        fail_terminal: AtomicBool,
    }

    impl ActivationFault {
        fn new() -> Self {
            Self {
                fail: AtomicBool::new(false),
                fail_terminal: AtomicBool::new(false),
            }
        }
    }

    impl bitcoin_rs_storage::CommitFault for ActivationFault {
        fn before_commit(
            &self,
            prefix: &bitcoin_rs_storage::AcceptedPrefix,
        ) -> Result<(), bitcoin_rs_storage::CommitError> {
            if self.fail.load(Ordering::Acquire)
                || (self.fail_terminal.load(Ordering::Acquire)
                    && matches!(
                        prefix.next_head.assumeutxo,
                        AssumeUtxoDiskStatus::Failed { .. }
                            | AssumeUtxoDiskStatus::Finalized { .. }
                    ))
            {
                return Err(bitcoin_rs_storage::CommitError::Storage(
                    bitcoin_rs_storage::StorageError::InvalidOperation(
                        "injected durable-head failure",
                    ),
                ));
            }
            Ok(())
        }
    }

    struct Fixture {
        head: Arc<ActivationFault>,
        active: Arc<Chainstate>,
        blocks: Vec<Block>,
        pinned: AssumeUtxoData,
        snapshot: Vec<u8>,
        stats: CoinStats,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            let mut blocks = vec![Network::Regtest.genesis_block()];
            for height in 1..=2 {
                blocks.push(crate::chain::regtest_fixture::mined_regtest_child_at(
                    blocks
                        .last()
                        .ok_or(TestError::Missing("missing predecessor"))?
                        .block_hash(),
                    height,
                )?);
            }
            Self::from_blocks(blocks)
        }

        fn from_blocks(blocks: Vec<Block>) -> TestResult<Self> {
            let source = chainstate();
            for block in &blocks {
                source
                    .lock_transition()?
                    .into_transition()
                    .connect(&BlockImage::from_local((*block).clone()))?;
            }
            let snapshot_set = UtxoSet::new();
            for item in source
                .commit_authority
                .store()
                .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
            {
                let (_, value) = item?;
                let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                    value.into_boxed_slice(),
                )
                .map_err(|_| TestError::Missing("bad coin record"))?;
                snapshot_set.insert_parsed_record(record);
            }
            let tip = source
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing source tip"))?;
            let pinned = AssumeUtxoData {
                height: tip.height,
                block_hash: tip.hash,
                hash_serialized: snapshot_set.lock_stable_view().hash_serialized_3()?,
                chain_tx_count: tip.chain_tx_count.to_wire(),
                index_commitments: [None; 4],
            };
            let mut stats = snapshot_set.with_stable_view(|view| {
                bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, tip.height, true)
            })?;
            stats.tx_count = tip.chain_tx_count.to_wire();
            let mut snapshot = Cursor::new(Vec::new());
            write_snapshot_observed(&snapshot_set, &tip.hash, tip.height, &mut snapshot, ())?;
            let active = chainstate();
            let head = Arc::new(ActivationFault::new());
            let fault: Arc<dyn bitcoin_rs_storage::CommitFault> = head.clone();
            active.commit_authority.set_fault(fault);
            for block in &blocks {
                active
                    .block_tree
                    .write()
                    .insert_header(block.header, NodeStatus::HeaderValid)?;
            }
            Ok(Self {
                head,
                active,
                blocks,
                pinned,
                snapshot: snapshot.into_inner(),
                stats,
            })
        }

        fn load(&self) -> Result<SnapshotLoad, bitcoin_rs_storage::utxo::UtxoError> {
            read_snapshot_strict_v4(&mut Cursor::new(&self.snapshot))
        }

        fn manager(&self, dir: &std::path::Path) -> Result<AssumeUtxoManager, AssumeUtxoError> {
            AssumeUtxoManager::open(
                Network::Regtest,
                Arc::clone(&self.active),
                dir.to_path_buf(),
            )
        }

        fn activate(&self, manager: &AssumeUtxoManager) -> TestResult {
            {
                let loaded = self.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &self.pinned)
            }?;
            Ok(())
        }
    }

    fn disk_status(active: &Chainstate) -> TestResult<AssumeUtxoDiskStatus> {
        Ok(active
            .durable_head
            .load()?
            .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo))
    }

    fn engine_coin_set(chain: &Chainstate) -> TestResult<UtxoSet> {
        let set = UtxoSet::new();
        for item in chain
            .commit_authority
            .store()
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        {
            let (_, value) = item?;
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                value.into_boxed_slice(),
            )
            .map_err(|_| TestError::Missing("bad coin record"))?;
            set.insert_parsed_record(record);
        }
        Ok(set)
    }

    // P2P-10, RCV-03, SYNC-03
    #[test]
    fn activation_rollback_cancels_header_candidates_without_replacing_their_budget() -> TestResult
    {
        let fixture = Fixture::new()?;
        let root = Network::Regtest.genesis_block_hash();
        let invalid = fixture.blocks[1].block_hash().0;
        fixture
            .active
            .header_retention
            .remember_operator_invalidation(invalid);
        let mut candidates = (0..4)
            .map(|_| fixture.active.begin_header_candidate(root, ChainWork::ZERO))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(candidates.iter().all(|candidate| !candidate.is_cancelled()));
        super::reset_rolled_back_chainstate(&fixture.active)?;
        assert!(
            candidates
                .iter()
                .all(crate::chain::HeaderCandidate::is_cancelled)
        );
        assert!(matches!(
            fixture.active.begin_header_candidate(root, ChainWork::ZERO),
            Err(crate::HeaderAdmissionError::Candidate(
                crate::chain::HeaderCandidateError::Busy
            ))
        ));
        assert!(matches!(
            fixture.active.admit_headers(&[fixture.blocks[1].header]),
            Err(crate::HeaderAdmissionError::Rejected(crate::chain::ChainError::KnownInvalidHeader { hash })) if hash == invalid
        ));
        candidates.pop();
        let replacement = fixture
            .active
            .begin_header_candidate(root, ChainWork::ZERO)?;
        assert!(!replacement.is_cancelled());
        Ok(())
    }

    #[test]
    fn untrusted_snapshot_height_and_tx_count_fail_the_trust_anchor() -> TestResult {
        let pinned = Network::Regtest
            .assume_utxo_for_height(110)
            .ok_or(TestError::Missing("missing pin"))?;
        assert!(Network::Regtest.assume_utxo_for_height(1234).is_none());
        let unpinned_height = AssumeUtxoDiskStatus::Validating {
            base_height: 1234,
            base_hash: pinned.block_hash,
            expected_hash_serialized: pinned.hash_serialized,
            chain_tx_count: pinned.chain_tx_count,
            historical_height: 0,
            historical_hash: Network::Regtest.genesis_block_hash(),
            pending: None,
            checkpoint: None,
        };
        assert!(matches!(
            crate::assumeutxo_snapshot::trusted_anchor(Network::Regtest, &unpinned_height),
            Err(crate::SnapshotAnchorError::UnrecognizedBase)
        ));
        let miscounted = AssumeUtxoDiskStatus::Validating {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
            expected_hash_serialized: pinned.hash_serialized,
            chain_tx_count: pinned.chain_tx_count + 1,
            historical_height: 0,
            historical_hash: Network::Regtest.genesis_block_hash(),
            pending: None,
            checkpoint: None,
        };
        assert!(matches!(
            crate::assumeutxo_snapshot::trusted_anchor(Network::Regtest, &miscounted),
            Err(crate::SnapshotAnchorError::TrustAnchorTxCount)
        ));
        Ok(())
    }

    #[test]
    fn snapshot_rejects_invalid_base_and_descendant_before_persistence() -> TestResult {
        for invalid_height in [2, 1] {
            let fixture = Fixture::new()?;
            {
                let mut tree = fixture.active.block_tree.write();
                let invalid = tree
                    .lookup(fixture.blocks[invalid_height].block_hash().0)
                    .ok_or(TestError::Missing("invalidated header missing"))?;
                tree.invalidate_subtree(invalid)?;
                let base = tree
                    .node_by_hash(fixture.pinned.block_hash)
                    .ok_or(TestError::Missing("snapshot base missing"))?;
                assert_eq!(base.status, NodeStatus::Invalid);
            }
            let before_stats = fixture.active.coin_stats.snapshot();
            let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
            let loaded = fixture.load()?;
            let dir = tempfile::tempdir()?;
            let manager = fixture.manager(dir.path())?;
            let result =
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
            assert!(matches!(
                result,
                Err(AssumeUtxoError::Apply(ApplyError::Chain(
                    crate::chain::ChainError::KnownInvalidHeader { hash }
                ))) if hash == fixture.pinned.block_hash
            ));
            assert!(!dir.path().join("assumeutxo").exists());
            assert!(fixture.active.durable_head.load()?.is_none());
            assert!(fixture.active.applied_tip_snapshot().is_none());
            assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
            assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
            assert_eq!(
                fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
                before_coins
            );
            assert!(!fixture.active.is_closed_for_recovery());
        }
        Ok(())
    }

    fn competing_snapshot_headers() -> TestResult<Vec<Block>> {
        let mut parent = Network::Regtest.genesis_block().block_hash();
        let mut fork = Vec::new();
        for height in 1..=3 {
            let block = crate::chain::regtest_fixture::mined_regtest_child_at_time(
                parent,
                crate::chain::regtest_fixture::genesis_time() + 100 + height,
                height,
            )?;
            parent = block.block_hash();
            fork.push(block);
        }
        Ok(fork)
    }

    #[test]
    fn snapshot_rejects_competing_best_headers_and_allows_valid_retry() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        let loaded = fixture.load()?;
        assert_eq!(
            (loaded.tip_hash, loaded.height),
            (fixture.pinned.block_hash, fixture.pinned.height)
        );
        let commitment = loaded
            .set
            .with_stable_view(|view| view.hash_serialized_3_at_height(fixture.pinned.height))?;
        assert_eq!(commitment, fixture.pinned.hash_serialized);
        let fork = competing_snapshot_headers()?;
        let fork_root = {
            let mut tree = fixture.active.block_tree.write();
            let root = tree.insert_header(fork[0].header, NodeStatus::HeaderValid)?;
            for block in &fork[1..] {
                tree.insert_header(block.header, NodeStatus::HeaderValid)?;
            }
            let tip = tree
                .tip()
                .ok_or(TestError::Missing("best header missing"))?;
            let base = tree
                .node_by_hash(fixture.pinned.block_hash)
                .ok_or(TestError::Missing("snapshot base missing"))?;
            assert!(tip.chainwork > base.chainwork);
            assert_eq!(tip.hash, fork[2].block_hash().0);
            root
        };
        let before_stats = fixture.active.coin_stats.snapshot();
        let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
        let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
        assert!(matches!(
            result,
            Err(AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain {
                base_hash,
                base_height,
                best_header: Some(best),
            }) if base_hash == fixture.pinned.block_hash
                && base_height == fixture.pinned.height
                && best == fork[2].block_hash().0
        ));
        assert!(!dir.path().join("assumeutxo").exists());
        assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
        assert!(manager.historical_chainstate().is_none());
        assert!(fixture.active.durable_head.load()?.is_none());
        assert!(fixture.active.applied_tip_snapshot().is_none());
        assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
        assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
        assert_eq!(
            fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
            before_coins
        );
        assert!(!fixture.active.is_closed_for_recovery());

        fixture
            .active
            .block_tree
            .write()
            .invalidate_subtree(fork_root)?;
        fixture.activate(&manager)?;
        assert_eq!(
            fixture
                .active
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("snapshot tip missing"))?
                .hash,
            fixture.pinned.block_hash
        );
        assert!(fixture.active.role().is_assumed_active());
        Ok(())
    }

    #[test]
    fn snapshot_rejects_base_above_shorter_best_work_header_chain() -> TestResult {
        let fixture = Fixture::new()?;
        let mut harder = competing_snapshot_headers()?.remove(0);
        harder.header.bits =
            bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x2000_ffff);
        harder.header.nonce = 0;
        crate::chain::regtest_fixture::mine_block_to_declared_target(&mut harder)?;
        {
            let mut tree = fixture.active.block_tree.write();
            tree.insert_header(harder.header, NodeStatus::HeaderValid)?;
            let tip = tree
                .tip()
                .ok_or(TestError::Missing("best header missing"))?;
            let base = tree
                .node_by_hash(fixture.pinned.block_hash)
                .ok_or(TestError::Missing("base missing"))?;
            assert!(tip.height < base.height);
            assert!(tip.chainwork > base.chainwork);
            assert_eq!(tip.hash, harder.block_hash().0);
        }
        let loaded = fixture.load()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
        assert!(matches!(
            result,
            Err(AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain {
                base_hash,
                base_height,
                best_header: Some(best),
            }) if base_hash == fixture.pinned.block_hash
                && base_height == fixture.pinned.height
                && best == harder.block_hash().0
        ));
        assert!(!dir.path().join("assumeutxo").exists());
        assert!(fixture.active.durable_head.load()?.is_none());
        assert!(fixture.active.applied_tip_snapshot().is_none());
        assert_eq!(fixture.active.role(), ChainstateRole::Ordinary);
        assert!(!fixture.active.is_closed_for_recovery());
        Ok(())
    }

    #[test]
    fn snapshot_accepts_base_below_best_header_tip_on_same_ancestry() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let child = crate::chain::regtest_fixture::mined_regtest_child_at(
            fixture.blocks[2].block_hash(),
            3,
        )?;
        fixture
            .active
            .block_tree
            .write()
            .insert_header(child.header, NodeStatus::HeaderValid)?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        fixture.activate(&manager)?;
        assert_eq!(
            fixture
                .active
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("snapshot tip missing"))?
                .hash,
            fixture.pinned.block_hash
        );
        assert_eq!(
            fixture
                .active
                .block_tree
                .read()
                .tip()
                .ok_or(TestError::Missing("best header missing"))?
                .hash,
            child.block_hash().0
        );
        Ok(())
    }

    fn snapshot_work_branch(
        height: u32,
        bits: u32,
        time_offset: u32,
    ) -> TestResult<(Vec<Block>, SnapshotLoad, CoinStats)> {
        let source = chainstate();
        let mut blocks = vec![Network::Regtest.genesis_block()];
        for next_height in 1..=height {
            blocks.push(crate::chain::regtest_fixture::mined_regtest_child_at_time(
                blocks
                    .last()
                    .ok_or(TestError::Missing("branch parent missing"))?
                    .block_hash(),
                crate::chain::regtest_fixture::genesis_time() + time_offset + next_height,
                next_height,
            )?);
        }
        for block in &blocks {
            source
                .begin_transition()?
                .connect(&BlockImage::from_local((*block).clone()))?;
        }
        for index in 1..blocks.len() {
            blocks[index].header.prev_blockhash = blocks[index - 1].block_hash();
            blocks[index].header.bits =
                bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(bits);
            blocks[index].header.nonce = 0;
            crate::chain::regtest_fixture::mine_block_to_declared_target(&mut blocks[index])?;
        }
        let snapshot_set = UtxoSet::new();
        for item in source
            .commit_authority
            .store()
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        {
            let (_, value) = item?;
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                value.into_boxed_slice(),
            )
            .map_err(|_| TestError::Missing("bad coin record"))?;
            snapshot_set.insert_parsed_record(record);
        }
        let tip = blocks
            .last()
            .ok_or(TestError::Missing("branch tip missing"))?
            .block_hash()
            .0;
        let mut stats = snapshot_set.with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, height, true)
        })?;
        stats.tx_count = source.coin_stats.snapshot().tx_count;
        let mut encoded = Vec::new();
        write_snapshot_observed(&snapshot_set, &tip, height, &mut encoded, ())?;
        let loaded = read_snapshot_strict_v4(&mut Cursor::new(encoded))?;
        Ok((blocks, loaded, stats))
    }

    fn snapshot_work_fixture(
        snapshot_height: u32,
        snapshot_bits: u32,
        applied_height: u32,
        applied_bits: u32,
    ) -> TestResult<Fixture> {
        let (blocks, snapshot, stats) = snapshot_work_branch(snapshot_height, snapshot_bits, 0)?;
        let (applied_blocks, mut applied, applied_stats) =
            snapshot_work_branch(applied_height, applied_bits, 100)?;
        let mut tree = crate::chain::BlockTree::new();
        for block in blocks.iter().chain(applied_blocks.iter().skip(1)) {
            tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        }
        let applied_id = tree
            .lookup(applied.tip_hash)
            .ok_or(TestError::Missing("applied header missing"))?;
        tree.restore_chain_tx_count(
            applied_id,
            crate::chain::ChainTxCount::established(applied_stats.tx_count),
        )?;
        let applied_node = tree.node(applied_id)?;
        let applied_tip = crate::chain::TipSnapshot {
            tip_id: applied_id,
            height: applied_node.height,
            chainwork: applied_node.chainwork,
            hash: applied_node.hash,
            chain_tx_count: applied_node.chain_tx_count,
        };
        let coin_stats = Arc::new(CoinStatsListener::new(applied_stats));
        applied.set.track_coin_stats((*coin_stats).clone());
        let active = Chainstate::new(
            Network::Regtest,
            Arc::new(ArcSwapOption::new(tree.tip())),
            Arc::new(ArcSwapOption::new(Some(Arc::new(applied_tip.clone())))),
            Arc::new(RwLock::new(tree)),
            Arc::new(applied.set),
            coin_stats,
            Arc::new(crate::events::ChainEventPublisher::detached(0)),
        );
        active
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: None,
                next_head: DurableHead {
                    assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
                    commit_id: 17,
                    height: applied_tip.height,
                    tip: applied_tip.hash,
                    chain_tx_count: applied_tip.chain_tx_count.to_wire(),
                    body_extent: None,
                    undo_extent: None,
                },
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|error| {
                TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
            })?;
        let head = Arc::new(ActivationFault::new());
        let fault: Arc<dyn bitcoin_rs_storage::CommitFault> = head.clone();
        active.commit_authority.set_fault(fault);
        let pinned = AssumeUtxoData {
            height: snapshot.height,
            block_hash: snapshot.tip_hash,
            hash_serialized: snapshot.set.lock_stable_view().hash_serialized_3()?,
            chain_tx_count: stats.tx_count,
            index_commitments: [None; 4],
        };
        let mut encoded = Vec::new();
        write_snapshot_observed(
            &snapshot.set,
            &pinned.block_hash,
            pinned.height,
            &mut encoded,
            (),
        )?;
        Ok(Fixture {
            head,
            active: Arc::new(active),
            blocks,
            pinned,
            snapshot: encoded,
            stats,
        })
    }

    #[test]
    fn snapshot_rejects_higher_base_with_less_work_than_applied_tip() -> TestResult {
        let fixture = snapshot_work_fixture(2, 0x207f_ffff, 1, 0x2000_ffff)?;
        let before = fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip missing"))?;
        let before_head = fixture.active.durable_head.load()?;
        let before_stats = fixture.active.coin_stats.snapshot();
        let before_coins = fixture.active.utxo.lock_stable_view().hash_serialized_3()?;
        let mut child = crate::chain::regtest_fixture::mined_regtest_child_at(
            fixture.blocks[2].block_hash(),
            3,
        )?;
        child.header.bits =
            bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1f7f_ffff);
        child.header.nonce = 0;
        crate::chain::regtest_fixture::mine_block_to_declared_target(&mut child)?;
        {
            let mut tree = fixture.active.block_tree.write();
            tree.insert_header(child.header, NodeStatus::HeaderValid)?;
            let best = tree
                .tip()
                .ok_or(TestError::Missing("best header missing"))?;
            let base_id = tree
                .lookup(fixture.pinned.block_hash)
                .ok_or(TestError::Missing("base missing"))?;
            let base = tree.node(base_id)?;
            assert!(base.height > before.height);
            assert!(base.chainwork < before.chainwork);
            assert!(best.chainwork > before.chainwork);
            assert_eq!(
                tree.node_at_height_from(best.tip_id, base.height),
                Some(base_id)
            );
        }
        let dir = tempfile::tempdir()?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        let loaded = fixture.load()?;
        let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
        assert!(matches!(result, Err(AssumeUtxoError::ActivationBehindTip)));
        assert_eq!(fixture.active.durable_head.load()?, before_head);
        assert_eq!(
            fixture.active.applied_tip_snapshot().as_deref(),
            Some(before.as_ref())
        );
        assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
        assert_eq!(
            fixture.active.utxo.lock_stable_view().hash_serialized_3()?,
            before_coins
        );
        assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
        assert!(!fixture.active.is_closed_for_recovery());
        Ok(())
    }

    #[test]
    fn snapshot_accepts_lower_base_with_more_work_than_applied_tip() -> TestResult {
        let fixture = snapshot_work_fixture(1, 0x2000_ffff, 2, 0x207f_ffff)?;
        let dir = tempfile::tempdir()?;
        let before = fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip missing"))?;
        let before_head = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("durable head missing"))?;
        {
            let tree = fixture.active.block_tree.read();
            let base = tree
                .node_by_hash(fixture.pinned.block_hash)
                .ok_or(TestError::Missing("base missing"))?;
            assert!(base.height < before.height);
            assert!(base.chainwork > before.chainwork);
            assert_eq!(
                tree.tip()
                    .ok_or(TestError::Missing("best header missing"))?
                    .hash,
                base.hash
            );
        }
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        fixture.activate(&manager)?;
        let applied = fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("snapshot tip missing"))?;
        let head = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("snapshot head missing"))?;
        assert_eq!(head.commit_id, before_head.commit_id + 1);
        assert_eq!(head.height, fixture.pinned.height);
        assert_eq!(head.tip, fixture.pinned.block_hash);
        assert_eq!(head.chain_tx_count, fixture.pinned.chain_tx_count);
        assert_eq!((applied.height, applied.hash), (head.height, head.tip));
        assert!(applied.chainwork > before.chainwork);
        assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
        assert_eq!(
            engine_coin_set(&fixture.active)?
                .lock_stable_view()
                .hash_serialized_3()?,
            fixture.pinned.hash_serialized
        );
        assert!(fixture.active.role().is_assumed_active());
        Ok(())
    }

    #[test]
    fn snapshot_refuses_work_comparison_when_durable_and_applied_tips_differ() -> TestResult {
        for (change_hash, height_delta, count_delta) in [(true, 0, 0), (false, 1, 0), (false, 0, 1)]
        {
            let fixture = snapshot_work_fixture(2, 0x207f_ffff, 1, 0x207f_ffff)?;
            let applied = fixture
                .active
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip missing"))?;
            let prior = fixture
                .active
                .durable_head
                .load()?
                .ok_or(TestError::Missing("durable head missing"))?;
            let unsettled = DurableHead {
                commit_id: prior.commit_id + 1,
                tip: if change_hash {
                    fixture.blocks[1].block_hash().0
                } else {
                    prior.tip
                },
                height: prior.height + height_delta,
                chain_tx_count: prior.chain_tx_count + count_delta,
                ..prior
            };
            fixture
                .active
                .commit_authority
                .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: Some(prior),
                    next_head: unsettled,
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .map_err(|error| {
                    TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
                })?;
            let dir = tempfile::tempdir()?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                fixture.active.clone(),
                dir.path().to_path_buf(),
            )?;
            let loaded = fixture.load()?;
            let result =
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
            assert!(
                matches!(result, Err(AssumeUtxoError::SnapshotTipNotSettled {
            durable_tip: Some(durable), applied_tip: Some(current),
        }) if durable == (unsettled.tip, unsettled.height, unsettled.chain_tx_count)
            && current == (applied.hash, applied.height, applied.chain_tx_count.to_wire()))
            );
            assert!(fixture.active.is_closed_for_recovery());
            assert_eq!(fixture.active.durable_head.load()?, Some(unsettled));
            assert_eq!(
                fixture.active.applied_tip_snapshot().as_deref(),
                Some(applied.as_ref())
            );
            assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
        }
        Ok(())
    }

    #[test]
    fn snapshot_installs_coins_statistics_and_resolved_header_together() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let active = &fixture.active;
        let tip = active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("missing snapshot tip"))?;
        let tree = active.block_tree.read();
        let node = tree.node(tip.tip_id)?;
        assert_eq!(
            (tip.hash, tip.height, tip.chainwork),
            (node.hash, node.height, node.chainwork)
        );
        assert_ne!(tip.chainwork, ChainWork::ZERO);
        assert_eq!(tip.chain_tx_count.to_wire(), fixture.pinned.chain_tx_count);
        assert_eq!(active.coin_stats.snapshot(), fixture.stats);
        assert_eq!(
            engine_coin_set(active)?
                .lock_stable_view()
                .hash_serialized_3()?,
            fixture.pinned.hash_serialized
        );
        assert!(active.role().is_assumed_active());
        assert_eq!(manager.status()?, disk_status(&fixture.active)?);
        assert!(matches!(
            active.prune_authority().begin(),
            Err(ApplyError::PruneDuringHistoricalValidation { .. })
        ));
        assert!(matches!(
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            },
            Err(AssumeUtxoError::AlreadyActive)
        ));
        Ok(())
    }

    #[test]
    fn snapshot_refuses_missing_or_wrong_height_header_before_persistence() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let active = chainstate();
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            Arc::clone(&active),
            dir.path().to_path_buf(),
        )?;
        assert!(matches!(
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            },
            Err(AssumeUtxoError::SnapshotHeaderMissing(_))
        ));
        assert!(active.durable_head.load()?.is_none());
        let manager = fixture.manager(dir.path())?;
        let mut wrong_height = fixture.pinned;
        wrong_height.height += 1;
        assert!(matches!(
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &wrong_height)
            },
            Err(AssumeUtxoError::SnapshotHeaderHeightMismatch { .. })
        ));
        assert!(fixture.active.applied_tip_snapshot().is_none());
        assert!(active.durable_head.load()?.is_none());
        Ok(())
    }

    #[test]
    fn activation_io_failure_does_not_publish_snapshot() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.head.fail.store(true, Ordering::Release);
        assert!(matches!(
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            },
            Err(AssumeUtxoError::Storage(_))
        ));
        assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
        assert!(fixture.active.applied_tip_snapshot().is_none());
        assert_eq!(fixture.active.coin_stats.snapshot(), CoinStats::default());
        assert!(fixture.active.role().is_ordinary());
        assert!(fixture.active.is_closed_for_recovery());
        Ok(())
    }

    #[test]
    fn historical_replay_preserves_active_durable_head_and_notifications() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let active_head = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing active anchor"))?;
        let events = fixture.active.chain_events.snapshot();
        let historical = manager
            .historical_chainstate()
            .ok_or(TestError::Missing("historical missing"))?;
        assert!(!Arc::ptr_eq(
            &historical.undo_store,
            &fixture.active.undo_store
        ));
        assert!(!Arc::ptr_eq(
            &historical.durable_head,
            &fixture.active.durable_head
        ));
        assert!(historical.block_body_store.is_none());
        assert!(matches!(
            historical.prune_authority().begin(),
            Err(ApplyError::PruneDuringHistoricalValidation { .. })
        ));
        for block in &fixture.blocks {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
            let head = fixture
                .active
                .durable_head
                .load()?
                .ok_or(TestError::Missing("missing head"))?;
            assert_eq!(
                (head.tip, head.height, head.chain_tx_count),
                (
                    active_head.tip,
                    active_head.height,
                    active_head.chain_tx_count
                )
            );
            assert!(head.commit_id > active_head.commit_id);
            assert_eq!(fixture.active.chain_events.snapshot(), events);
            assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
        }
        assert!(fixture.active.role().is_ordinary());
        assert!(fixture.active.prune_authority().begin().is_ok());
        assert!(manager.historical_chainstate().is_none());
        assert!(matches!(
            manager.status()?,
            AssumeUtxoDiskStatus::Finalized { .. }
        ));
        assert_eq!(manager.status()?, disk_status(&fixture.active)?);
        Ok(())
    }

    fn scanned_historical_stats(
        historical: &Chainstate,
        height: u32,
        chain_tx_count: u64,
    ) -> TestResult<CoinStats> {
        let mut stats = engine_coin_set(historical)?.with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, height, true)
        })?;
        stats.tx_count = chain_tx_count;
        Ok(stats)
    }

    fn assert_same_stats(actual: &CoinStats, expected: &CoinStats, height: u32) {
        assert_eq!(
            (
                actual.height,
                actual.tx_count,
                actual.utxo_count,
                actual.total_amount,
                actual.bogo_size,
            ),
            (
                expected.height,
                expected.tx_count,
                expected.utxo_count,
                expected.total_amount,
                expected.bogo_size,
            ),
            "historical coin statistics at height {height} must equal a full scan of the engine coins"
        );
        assert_eq!(
            actual.muhash.finalize(),
            expected.muhash.finalize(),
            "historical MuHash at height {height} must equal a full scan of the engine coins"
        );
    }

    fn spending_chain() -> TestResult<(Vec<Block>, bitcoin_rs_consensus::primitives::OutPoint)> {
        use crate::chain::regtest_fixture::{
            coinbase, mined_block_with_prev_hash, mined_regtest_child_at,
        };
        use bitcoin_rs_consensus::primitives::{
            Amount, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
        };
        use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;

        let mut blocks = vec![Network::Regtest.genesis_block()];
        for height in 1..=100 {
            let prev = blocks
                .last()
                .ok_or(TestError::Missing("missing predecessor"))?
                .block_hash();
            blocks.push(mined_regtest_child_at(prev, height)?);
        }
        let funding = OutPoint::new(blocks[1].txs[0].txid(), 0);
        let spend = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: funding,
                script_sig: vec![OP_PUSHNUM_1].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![OP_PUSHNUM_1].into(),
            }],
            lock_time: LockTime::ZERO,
        };
        let prev = blocks
            .last()
            .ok_or(TestError::Missing("missing predecessor"))?
            .block_hash();
        blocks.push(mined_block_with_prev_hash(
            prev,
            101,
            vec![coinbase(101), spend],
        )?);
        Ok((blocks, funding))
    }

    #[test]
    fn historical_stats_equal_a_full_scan_after_every_step_including_a_spend() -> TestResult {
        let (blocks, funding) = spending_chain()?;
        let fixture = Fixture::from_blocks(blocks)?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let historical = manager
            .historical_chainstate()
            .ok_or(TestError::Missing("historical missing"))?;
        for block in &fixture.blocks {
            let outcome = manager.step_historical(&BlockImage::from_local((*block).clone()))?;
            let expected = scanned_historical_stats(
                &historical,
                outcome.height,
                outcome.tip.chain_tx_count.to_wire(),
            )?;
            assert_same_stats(&historical.coin_stats.snapshot(), &expected, outcome.height);
        }
        assert!(
            engine_coin_set(&historical)?.get(&funding).is_none(),
            "the height-101 spend must have removed the funding coin"
        );
        Ok(())
    }

    #[test]
    fn historical_step_advances_the_rolling_stats_without_rescanning_the_store() -> TestResult {
        const MARKER: u64 = 1_000_000;
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let historical = manager
            .historical_chainstate()
            .ok_or(TestError::Missing("historical missing"))?;
        manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
        let mut marked = historical.coin_stats.snapshot();
        marked.tx_count += MARKER;
        historical.coin_stats.reset(marked);
        let outcome =
            manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone()))?;
        let mut expected = scanned_historical_stats(
            &historical,
            outcome.height,
            outcome.tip.chain_tx_count.to_wire(),
        )?;
        expected.tx_count += MARKER;
        assert_same_stats(&historical.coin_stats.snapshot(), &expected, outcome.height);
        Ok(())
    }

    mod recovery {
        //! RCV-02/04 and ARCH-07b: root-selected snapshot recovery with real storage.
        use super::*;
        use crate::assumeutxo::{DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL, HistoricalAdvance};
        use crate::test_fixtures::{TestError, TestResult};
        use arc_swap::ArcSwapOption;
        use bitcoin_rs_consensus::primitives::BlockImage;
        use bitcoin_rs_storage::assumeutxo::HistoricalCheckpointRef;
        use bitcoin_rs_storage::block_body::IndexedBlockBodyStore;
        use bitcoin_rs_storage::write_fault::WriteFaultStore;
        use bitcoin_rs_storage::{
            DurableHeadStore, FlatFileBlockStore, KvDurableHeadStore, KvUndoStore, RocksDbStore,
        };
        use parking_lot::RwLock;
        use sha2::Digest as _;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::AtomicU32;

        fn chainstate_store(dir: &Path) -> TestResult<Arc<WriteFaultStore>> {
            std::fs::create_dir_all(dir)?;
            crate::events::initialize_data_dir(dir)?;
            Ok(Arc::new(WriteFaultStore::new(Arc::new(
                RocksDbStore::open(dir.join("chainstate"))?,
            ))))
        }

        fn open_persistent(dir: &Path, pinned: &AssumeUtxoData) -> TestResult<Arc<Chainstate>> {
            open_persistent_over(dir, pinned, chainstate_store(dir)?)
        }

        fn open_persistent_over(
            dir: &Path,
            pinned: &AssumeUtxoData,
            store: Arc<WriteFaultStore>,
        ) -> TestResult<Arc<Chainstate>> {
            let head_store = Arc::new(KvDurableHeadStore::new(store.clone()));
            let head = head_store.load()?;
            let files = Arc::new(match head.and_then(|head| head.body_extent) {
                Some(extent) => FlatFileBlockStore::open_with_committed_extent(dir, extent)?,
                None => FlatFileBlockStore::open(dir)?,
            });
            let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
            let coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
                Arc::clone(&dyn_store),
                64 * 1024 * 1024,
            ));
            let mut active = if head
                .is_some_and(|head| !matches!(head.assumeutxo, AssumeUtxoDiskStatus::Uninitialized))
            {
                if head.is_some_and(|head| {
                    matches!(head.assumeutxo, AssumeUtxoDiskStatus::Failed { .. })
                }) {
                    return Err(TestError::UnexpectedSuccess("persisted validation failure"));
                }
                let initial = crate::recovery::restore_snapshot(dir, Network::Regtest, pinned)?;
                let stats = Arc::new(CoinStatsListener::new(initial.coin_stats));
                let mut utxo = initial.utxo;
                utxo.track_coin_stats((*stats).clone());
                let header_tip = initial.tree.tip();
                Chainstate::new(
                    Network::Regtest,
                    Arc::new(ArcSwapOption::new(header_tip)),
                    Arc::new(ArcSwapOption::new(initial.applied_tip.map(Arc::new))),
                    Arc::new(RwLock::new(initial.tree)),
                    Arc::new(utxo),
                    stats,
                    Arc::new(crate::events::ChainEventPublisher::detached(0)),
                )
            } else if let Some(head) = head.as_ref().filter(|h| h.height > 0) {
                let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir)?;
                let config = crate::checkpoint::headers::HeaderCheckpointConfig {
                    network: Network::Regtest,
                    genesis: Network::Regtest.genesis_block_hash(),
                };
                let loaded = crate::checkpoint::load_checkpoint_from_dir_with_path(
                    &data,
                    Some(dir),
                    config,
                    bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
                )?;
                let crate::checkpoint::CheckpointLoad::Complete(restored) = loaded else {
                    return Err(TestError::Missing(
                        "ordinary restart needs its checkpoint header tree",
                    ));
                };
                let tree = restored.tree;
                let node_id = tree
                    .lookup(head.tip)
                    .ok_or(TestError::Missing("head tip missing from tree"))?;
                let node = tree.node(node_id)?;
                let applied_tip = crate::chain::TipSnapshot {
                    tip_id: node_id,
                    height: head.height,
                    hash: head.tip,
                    chainwork: node.chainwork,
                    chain_tx_count: crate::chain::ChainTxCount::established(head.chain_tx_count),
                };
                let engine_coins = engine_coin_set_from_store(dyn_store.as_ref())?;
                let mut stats = engine_coins.with_stable_view(|view| {
                    bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, head.height, true)
                })?;
                stats.tx_count = head.chain_tx_count;
                let listener = Arc::new(CoinStatsListener::new(stats));
                let header_tip = tree.tip();
                Chainstate::new(
                    Network::Regtest,
                    Arc::new(ArcSwapOption::new(header_tip)),
                    Arc::new(ArcSwapOption::new(Some(Arc::new(applied_tip)))),
                    Arc::new(RwLock::new(tree)),
                    Arc::new(engine_coins),
                    listener,
                    Arc::new(crate::events::ChainEventPublisher::detached(0)),
                )
            } else {
                Arc::try_unwrap(chainstate()).map_err(|_| TestError::Missing("shared fixture"))?
            };
            coins.track_coin_stats((*active.coin_stats).clone());
            active.durable_head = head_store;
            active.undo_store = Arc::new(KvUndoStore::new(store.clone()));
            active.coins = Arc::clone(&coins);
            active.commit_authority =
                Arc::new(bitcoin_rs_storage::CommitAuthority::new(dyn_store, coins));
            active.block_body_store = Some(Arc::new(IndexedBlockBodyStore::new(store, files)));
            active.configure_checkpointing(dir, Arc::new(AtomicU32::new(0)))?;
            crate::recover_snapshot_activation(&active, dir)?;
            crate::recover_disconnect_marker(&active)?;
            Ok(Arc::new(active))
        }

        fn activate(
            dir: &Path,
            fixture: &Fixture,
        ) -> TestResult<(Arc<Chainstate>, AssumeUtxoManager)> {
            let active = open_persistent(dir, &fixture.pinned)?;
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let manager =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            }?;
            Ok((active, manager))
        }

        #[test]
        fn snapshot_lower_height_work_commit_survives_durable_record_reopen() -> TestResult {
            let dir = tempfile::tempdir()?;
            let committed = {
                let mut fixture = snapshot_work_fixture(1, 0x2000_ffff, 2, 0x207f_ffff)?;
                let prior = fixture
                    .active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("prior head missing"))?;
                let store = Arc::new(RocksDbStore::open(dir.path())?);
                let head = Arc::new(KvDurableHeadStore::new(Arc::clone(&store)));
                let dyn_store: Arc<dyn bitcoin_rs_storage::KvStore> = store.clone();
                let rocks_coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
                    Arc::clone(&dyn_store),
                    64 * 1024 * 1024,
                ));
                bitcoin_rs_storage::CommitAuthority::new(Arc::clone(&dyn_store), rocks_coins)
                    .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                        expected_head: None,
                        next_head: prior,
                        undo_rows: Vec::new(),
                        body_rows: Vec::new(),
                        attestation: None,
                        coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                    })
                    .map_err(|error| {
                        TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
                    })?;
                let head_store: Arc<dyn DurableHeadStore> = head.clone();
                let authority_coins = Arc::new(bitcoin_rs_storage::CoinStore::open(
                    Arc::clone(&dyn_store),
                    64 * 1024 * 1024,
                ));
                let authority = Arc::new(bitcoin_rs_storage::CommitAuthority::new(
                    dyn_store,
                    Arc::clone(&authority_coins),
                ));
                let active = Arc::get_mut(&mut fixture.active)
                    .ok_or(TestError::Missing("shared fixture"))?;
                active.durable_head = head_store;
                active.coins = Arc::clone(&authority_coins);
                active.commit_authority = authority;
                let manager = AssumeUtxoManager::open(
                    Network::Regtest,
                    fixture.active.clone(),
                    dir.path().to_path_buf(),
                )?;
                fixture.activate(&manager)?;
                let next = head
                    .load()?
                    .ok_or(TestError::Missing("snapshot commit missing"))?;
                assert!(next.height < prior.height);
                assert_eq!(next.commit_id, prior.commit_id + 1);
                assert_eq!(next.tip, fixture.pinned.block_hash);
                assert_eq!(next.chain_tx_count, fixture.pinned.chain_tx_count);
                assert_eq!(
                    fixture
                        .active
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("applied tip missing"))?
                        .hash,
                    next.tip
                );
                assert!(
                    matches!(next.assumeutxo, AssumeUtxoDiskStatus::Validating { base_height, base_hash, .. }
            if base_height == next.height && base_hash == next.tip)
                );
                next
            };
            let reopened = KvDurableHeadStore::new(Arc::new(RocksDbStore::open(dir.path())?));
            assert_eq!(reopened.load()?, Some(committed));
            Ok(())
        }

        #[derive(Default)]
        struct SnapshotRestart {
            child: Option<bitcoin_rs_consensus::primitives::Block>,
            stats: CoinStats,
        }

        #[derive(Default)]
        struct UnacceptedCheckpoint {
            coins: Option<bitcoin_rs_consensus::primitives::Hash256>,
            stats: CoinStats,
        }

        fn finalize_snapshot_after_foreground_restart(
            dir: &Path,
            fixture: &Fixture,
            out: &mut SnapshotRestart,
        ) -> TestResult {
            let (active, manager) = activate(dir, fixture)?;
            let child = crate::chain::regtest_fixture::mined_regtest_child_at(
                fixture.blocks[2].block_hash(),
                3,
            )?;
            active
                .begin_transition()?
                .connect(&BlockImage::from_local(child.clone()))?;
            manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
            manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone()))?;
            let expected_stats = active.coin_stats.snapshot();
            assert_eq!(expected_stats.utxo_count, 3);
            assert_eq!(expected_stats.total_amount, 15_000_000_000);
            let expected_tip = active
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing foreground tip"))?
                .hash;
            drop(manager);
            drop(active);

            let active = open_persistent(dir, &fixture.pinned)?;
            let manager =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
            assert_eq!(active.coin_stats.snapshot(), expected_stats);
            assert_eq!(
                active
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing recovered tip"))?
                    .hash,
                expected_tip
            );
            assert!(active.role().is_assumed_active());
            assert!(
                manager
                    .historical_chainstate()
                    .ok_or(TestError::Missing("missing historical"))?
                    .applied_tip_snapshot()
                    .is_none()
            );
            let archived_head = active.durable_head.load()?;
            let archived_extent = active
                .block_body_store
                .as_ref()
                .and_then(|store| store.append_cursor());
            assert_eq!(
                manager.advance_historical()?,
                HistoricalAdvance::MissingBody {
                    height: 2,
                    hash: fixture.pinned.block_hash,
                }
            );
            assert_eq!(active.durable_head.load()?, archived_head);
            assert_eq!(
                active
                    .block_body_store
                    .as_ref()
                    .and_then(|store| store.append_cursor()),
                archived_extent
            );
            let events = active.chain_events.snapshot();
            manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
            assert!(active.role().is_ordinary());
            assert_eq!(active.chain_events.snapshot(), events);
            assert_eq!(active.coin_stats.snapshot(), expected_stats);
            out.child = Some(child);
            out.stats = expected_stats;
            Ok(())
        }

        fn rewind_below_the_snapshot_base(
            dir: &Path,
            fixture: &Fixture,
            child: &bitcoin_rs_consensus::primitives::Block,
            expected_stats: &CoinStats,
            rewound: &mut CoinStats,
        ) -> TestResult {
            let active = open_persistent(dir, &fixture.pinned)?;
            let manager =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
            assert!(matches!(
                manager.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert_eq!(active.coin_stats.snapshot(), *expected_stats);
            active.begin_transition()?.disconnect(child)?;
            active.begin_transition()?.disconnect(&fixture.blocks[2])?;
            assert_eq!(
                active
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing rewound tip"))?
                    .height,
                1
            );
            assert!(matches!(
                active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("missing head"))?
                    .assumeutxo,
                AssumeUtxoDiskStatus::Uninitialized
            ));
            assert!(matches!(
                manager.chainstates_summary()?.status,
                AssumeUtxoDiskStatus::Uninitialized
            ));
            let engine_coins = engine_coin_set(&active)?;
            let mut stats = engine_coins.with_stable_view(|view| {
                bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, 1, true)
            })?;
            let tip = active
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing applied tip"))?;
            stats.tx_count = tip.chain_tx_count.to_wire();
            *rewound = stats;
            Ok(())
        }

        fn verify_restart_after_rewind(
            dir: &Path,
            fixture: &Fixture,
            rewound_stats: &CoinStats,
        ) -> TestResult {
            let active = open_persistent(dir, &fixture.pinned)?;
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let manager =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
            assert!(manager.chainstates_summary()?.active_chainstate.validated);
            let recovered_stats = active.coin_stats.snapshot();
            assert_eq!(
                recovered_stats.muhash.finalize(),
                rewound_stats.muhash.finalize()
            );
            assert_eq!(
                (
                    recovered_stats.height,
                    recovered_stats.total_amount,
                    recovered_stats.bogo_size,
                    recovered_stats.tx_count,
                    recovered_stats.utxo_count
                ),
                (
                    rewound_stats.height,
                    rewound_stats.total_amount,
                    rewound_stats.bogo_size,
                    rewound_stats.tx_count,
                    rewound_stats.utxo_count
                ),
            );
            assert_eq!(
                active
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing restarted ordinary tip"))?
                    .height,
                1
            );
            Ok(())
        }

        #[test]
        fn durable_snapshot_restarts_foreground_and_background_then_allows_base_reorg() -> TestResult
        {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let mut restart = SnapshotRestart::default();
            finalize_snapshot_after_foreground_restart(dir.path(), &fixture, &mut restart)?;
            let child = restart
                .child
                .as_ref()
                .ok_or(TestError::Missing("missing restart child"))?;
            let mut rewound = CoinStats::default();
            rewind_below_the_snapshot_base(
                dir.path(),
                &fixture,
                child,
                &restart.stats,
                &mut rewound,
            )?;
            verify_restart_after_rewind(dir.path(), &fixture, &rewound)
        }

        fn engine_coin_set_from_store(
            store: &dyn bitcoin_rs_storage::KvStore,
        ) -> TestResult<UtxoSet> {
            let set = UtxoSet::new();
            for item in store.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
                let (_, value) = item?;
                let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                    value.into_boxed_slice(),
                )
                .map_err(|_| TestError::Missing("bad coin record"))?;
                set.insert_parsed_record(record);
            }
            Ok(set)
        }

        fn engine_coin_set(chain: &Chainstate) -> TestResult<UtxoSet> {
            engine_coin_set_from_store(chain.commit_authority.store().as_ref())
        }

        fn publish_unaccepted_historical_checkpoint(
            dir: &Path,
            fixture: &Fixture,
            out: &mut UnacceptedCheckpoint,
        ) -> TestResult {
            let active = open_persistent(dir, &fixture.pinned)?;
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active.clone(),
                dir.to_path_buf(),
                1,
            )?;
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            }?;
            manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
            manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone()))?;
            let status = manager.status()?;
            let checkpoint = match &status {
                AssumeUtxoDiskStatus::Validating {
                    checkpoint: Some(checkpoint),
                    historical_height,
                    historical_hash,
                    ..
                } => {
                    assert_eq!(*historical_height, 1);
                    assert_eq!(*historical_hash, fixture.blocks[1].block_hash().0);
                    *checkpoint
                }
                _ => {
                    return Err(TestError::UnexpectedSuccess(
                        "unexpected status after checkpoint",
                    ));
                }
            };
            assert_eq!(checkpoint.height, 1);
            assert_eq!(checkpoint.hash, fixture.blocks[1].block_hash().0);
            let historical = manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing historical"))?;
            let accepted_coins = engine_coin_set(&historical)?
                .lock_stable_view()
                .hash_serialized_3()?;
            let accepted_stats = historical.coin_stats.snapshot();
            historical
                .lock_transition()?
                .into_transition()
                .connect(&BlockImage::from_local(fixture.blocks[2].clone()))?;
            let unaccepted_coins = engine_coin_set(&historical)?
                .lock_stable_view()
                .hash_serialized_3()?;
            assert_ne!(unaccepted_coins, accepted_coins);
            publish_two_historical_checkpoints(
                dir,
                &historical,
                checkpoint,
                unaccepted_coins,
                fixture.blocks[2].block_hash().0,
            )?;
            assert_eq!(
                manager.status()?,
                status,
                "publication cannot advance the durable head"
            );
            drop(historical);
            assert!(
                dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
                    .join("CURRENT")
                    .exists()
            );
            drop(manager);
            drop(active);
            out.coins = Some(accepted_coins);
            out.stats = accepted_stats;
            Ok(())
        }

        fn publish_two_historical_checkpoints(
            dir: &Path,
            historical: &Chainstate,
            checkpoint: HistoricalCheckpointRef,
            unaccepted_coins: bitcoin_rs_consensus::primitives::Hash256,
            expected_tip: bitcoin_rs_consensus::primitives::Hash256,
        ) -> TestResult {
            let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir)?;
            let config = crate::checkpoint::headers::HeaderCheckpointConfig {
                network: Network::Regtest,
                genesis: Network::Regtest.genesis_block_hash(),
            };
            for _ in 0..2 {
                let _ = crate::checkpoint::write_historical_checkpoint_with_store(
                    &data,
                    config,
                    &historical.block_tree,
                    &historical.coin_stats,
                    historical.applied_tip_snapshot().as_deref(),
                    crate::checkpoint::CheckpointStoreTarget {
                        store: historical.commit_authority.store().as_ref(),
                        host_data_dir: dir,
                    },
                )?;
            }
            let crate::checkpoint::CheckpointLoad::Complete(current) =
                crate::checkpoint::load_checkpoint_from_dir_with_path(
                    &data,
                    Some(dir),
                    config,
                    bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
                )?
            else {
                return Err(TestError::UnexpectedSuccess(
                    "unaccepted CURRENT generation was not published",
                ));
            };
            assert_ne!(current.generation, checkpoint.checkpoint.generation);
            assert_eq!(current.applied_tip.height, 2);
            assert_eq!(current.applied_tip.hash, expected_tip);
            assert_eq!(current.coin_stats.tx_count, 3);
            let engine = current
                .engine
                .as_ref()
                .ok_or(TestError::Missing("missing checkpoint engine"))?;
            let coins = UtxoSet::new();
            for item in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
                let (_, value) = item?;
                let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                    value.into_boxed_slice(),
                )
                .map_err(|_| TestError::Missing("bad coin record"))?;
                coins.insert_parsed_record(record);
            }
            assert_eq!(
                coins.lock_stable_view().hash_serialized_3()?,
                unaccepted_coins
            );
            Ok(())
        }

        fn restart_from_historical_checkpoint(
            dir: &Path,
            fixture: &Fixture,
            accepted_coins: bitcoin_rs_consensus::primitives::Hash256,
            accepted_stats: &CoinStats,
        ) -> TestResult {
            let active = open_persistent(dir, &fixture.pinned)?;
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active,
                dir.to_path_buf(),
                1,
            )?;
            let historical = manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing restored historical chainstate"))?;
            let restored_tip = historical
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing historical checkpoint tip"))?;
            assert_eq!(restored_tip.height, 1);
            assert_eq!(restored_tip.hash, fixture.blocks[1].block_hash().0);
            assert_eq!(restored_tip.chain_tx_count.to_wire(), 2);
            assert_eq!(historical.coin_stats.snapshot(), *accepted_stats);
            assert_eq!(
                engine_coin_set(&historical)?
                    .lock_stable_view()
                    .hash_serialized_3()?,
                accepted_coins
            );
            let generations = std::fs::read_dir(
                dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT),
            )?
            .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                generations
                    .iter()
                    .filter(|entry| entry.path().is_dir())
                    .count(),
                1,
                "startup must retire publication residue"
            );

            manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
            assert!(matches!(
                manager.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert_eq!(
                std::fs::read_dir(
                    dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
                )?
                .count(),
                0,
                "finalized commit must retire the last historical checkpoint"
            );
            Ok(())
        }

        #[test]
        fn historical_checkpoint_bounds_restart_replay_to_the_checkpoint_suffix() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let mut unaccepted = UnacceptedCheckpoint::default();
            publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
            restart_from_historical_checkpoint(
                dir.path(),
                &fixture,
                unaccepted
                    .coins
                    .ok_or(TestError::Missing("missing accepted coins"))?,
                &unaccepted.stats,
            )
        }

        #[test]
        fn restored_historical_stats_keep_following_commits_after_a_checkpoint_restart()
        -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let mut unaccepted = UnacceptedCheckpoint::default();
            publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active,
                dir.path().to_path_buf(),
                1,
            )?;
            let historical = manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing restored historical chainstate"))?;
            let restored_tip = historical
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing historical checkpoint tip"))?;
            assert_same_stats(
                &historical.coin_stats.snapshot(),
                &scanned_historical_stats(
                    &historical,
                    restored_tip.height,
                    restored_tip.chain_tx_count.to_wire(),
                )?,
                restored_tip.height,
            );
            let outcome =
                manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
            assert!(outcome.height > restored_tip.height);
            assert_same_stats(
                &historical.coin_stats.snapshot(),
                &scanned_historical_stats(
                    &historical,
                    outcome.height,
                    outcome.tip.chain_tx_count.to_wire(),
                )?,
                outcome.height,
            );
            Ok(())
        }

        fn accepted_historical_generation(dir: &Path, fixture: &Fixture) -> TestResult<u64> {
            let active = open_persistent(dir, &fixture.pinned)?;
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active,
                dir.to_path_buf(),
                1,
            )?;
            match manager.status()? {
                AssumeUtxoDiskStatus::Validating {
                    checkpoint: Some(checkpoint),
                    ..
                } => Ok(checkpoint.checkpoint.generation),
                _ => Err(TestError::Missing("missing accepted historical checkpoint")),
            }
        }

        fn remove_first_engine_coin(engine_dir: &Path) -> TestResult<()> {
            use bitcoin_rs_storage::KvStore as _;
            let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::open_checkpoint(engine_dir)?;
            let key = {
                let mut rows = store.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?;
                rows.next()
                    .ok_or(TestError::Missing("engine image has no coins"))??
                    .0
            };
            let mut batch = store.new_batch();
            batch.delete(bitcoin_rs_storage::ColumnFamily::Coins, &key);
            store.write_durable(batch)?;
            store.checkpoint(engine_dir)?;
            Ok(())
        }
        fn resign_engine_image(generation_dir: &Path) -> TestResult<[u8; 32]> {
            let chainstate = cap_std::fs::Dir::open_ambient_dir(
                generation_dir.join("chainstate"),
                cap_std::ambient_authority(),
            )?;
            let engine = bitcoin_rs_storage::checkpoint::digest_engine_dir(&chainstate)
                .map_err(crate::CheckpointError::Store)?;
            let manifest_path = generation_dir.join(bitcoin_rs_storage::checkpoint::MANIFEST_FILE);
            let mut manifest: bitcoin_rs_storage::checkpoint::CheckpointManifestV1 =
                sonic_rs::from_slice(&std::fs::read(&manifest_path)?)?;
            manifest.engine = Some(engine);
            let manifest_bytes = sonic_rs::to_vec(&manifest)?;
            std::fs::write(&manifest_path, &manifest_bytes)?;
            let root = generation_dir.parent().ok_or(TestError::Missing(
                "historical generation has no checkpoint root",
            ))?;
            let current_path = root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE);
            let mut current: bitcoin_rs_storage::checkpoint::CurrentV1 =
                sonic_rs::from_slice(&std::fs::read(&current_path)?)?;
            let manifest_sha256: [u8; 32] = sha2::Sha256::digest(&manifest_bytes).into();
            current.manifest_sha256 =
                bitcoin_rs_consensus::primitives::hex::hex_encode(&manifest_sha256);
            std::fs::write(&current_path, sonic_rs::to_vec(&current)?)?;
            Ok(manifest_sha256)
        }

        fn accepted_generation_dir(dir: &Path, generation: u64) -> PathBuf {
            dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
                .join(format!("gen-{generation:020}"))
        }

        #[test]
        fn historical_checkpoint_coin_stats_come_from_the_engine_image() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let mut unaccepted = UnacceptedCheckpoint::default();
            publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
            let accepted_stats = unaccepted.stats.clone();
            let generation = accepted_historical_generation(dir.path(), &fixture)?;
            let generation_dir = accepted_generation_dir(dir.path(), generation);
            remove_first_engine_coin(&generation_dir.join("chainstate"))?;
            let manifest_sha256 = resign_engine_image(&generation_dir)?;
            {
                use bitcoin_rs_storage::KvStore as _;
                let live = bitcoin_rs_storage::RocksDbStore::open(dir.path().join("chainstate"))?;
                let raw = live
                    .get(
                        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                        bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
                    )?
                    .ok_or(TestError::Missing("live chainstate has no durable head"))?;
                let mut head = bitcoin_rs_storage::DurableHead::decode(&raw)
                    .ok_or(TestError::Missing("live durable head is undecodable"))?;
                match &mut head.assumeutxo {
                    AssumeUtxoDiskStatus::Validating {
                        checkpoint: Some(checkpoint),
                        ..
                    } => {
                        checkpoint.checkpoint.manifest_sha256 = manifest_sha256;
                    }
                    _ => {
                        return Err(TestError::Missing(
                            "accepted historical checkpoint is not recorded as validating",
                        ));
                    }
                }
                live.put(
                    bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                    bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
                    &head.encode(),
                )?;
            }
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active,
                dir.path().to_path_buf(),
                1,
            )?;
            let historical = manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing restored historical chainstate"))?;
            let restored = historical.coin_stats.snapshot();
            assert_eq!(
                restored.utxo_count,
                accepted_stats.utxo_count - 1,
                "coin count must follow the engine image, not the coinstats artifact"
            );
            assert_eq!(
                restored.total_amount,
                accepted_stats.total_amount - 50 * 100_000_000,
                "coin amount must follow the engine image"
            );
            assert_eq!(restored.tx_count, accepted_stats.tx_count);
            Ok(())
        }

        #[test]
        fn historical_checkpoint_without_engine_image_refuses_to_restore() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let mut unaccepted = UnacceptedCheckpoint::default();
            publish_unaccepted_historical_checkpoint(dir.path(), &fixture, &mut unaccepted)?;
            let generation = accepted_historical_generation(dir.path(), &fixture)?;
            std::fs::remove_dir_all(
                accepted_generation_dir(dir.path(), generation).join("chainstate"),
            )?;
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            match AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active,
                dir.path().to_path_buf(),
                1,
            ) {
                Err(crate::AssumeUtxoError::HistoricalCheckpointWithoutEngine) => Ok(()),
                Err(_) => Err(TestError::Missing(
                    "a historical checkpoint without an engine image must refuse with its typed error",
                )),
                Ok(_) => Err(TestError::UnexpectedSuccess(
                    "a historical checkpoint without an engine image restored",
                )),
            }
        }
        #[test]
        fn finalized_checkpoint_cleanup_failure_is_retried_on_restart() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let (active, manager) = activate(dir.path(), &fixture)?;
            drop(manager);
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active.clone(),
                dir.path().to_path_buf(),
                1,
            )?;
            for block in &fixture.blocks[..2] {
                manager.step_historical(&BlockImage::from_local((*block).clone()))?;
            }
            let root = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
            let generation = std::fs::read_dir(&root)?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .find(|entry| entry.path().is_dir())
                .ok_or(TestError::Missing("missing historical generation"))?
                .path();
            let blocker = generation.join("operator-backup");
            std::fs::create_dir(&blocker)?;
            manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))?;
            assert!(matches!(
                manager.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert!(active.role().is_ordinary());
            assert!(manager.historical_chainstate().is_none());
            assert!(generation.is_dir());
            assert!(active.begin_transition().is_ok());
            let finalized_head = active.durable_head.load()?;
            drop(manager);
            drop(active);

            let active = open_persistent(dir.path(), &fixture.pinned)?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                active.clone(),
                dir.path().to_path_buf(),
            )?;
            assert!(active.role().is_ordinary());
            assert!(manager.historical_chainstate().is_none());
            assert_eq!(active.durable_head.load()?, finalized_head);
            assert!(generation.is_dir());
            drop(manager);
            drop(active);
            std::fs::remove_dir(&blocker)?;
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                active.clone(),
                dir.path().to_path_buf(),
            )?;
            assert!(active.role().is_ordinary());
            assert!(manager.historical_chainstate().is_none());
            assert_eq!(active.durable_head.load()?, finalized_head);
            assert_eq!(std::fs::read_dir(root)?.count(), 0);
            Ok(())
        }

        #[test]
        fn snapshot_activation_preserves_full_revalidation_requirement() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                active.clone(),
                dir.path().to_path_buf(),
            )?;
            let marker = dir
                .path()
                .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER);
            std::fs::write(&marker, b"required")?;
            let head = active.durable_head.load()?;
            let tip = active.applied_tip_snapshot();
            assert!(matches!(
                {
                    let loaded = fixture.load()?;
                    manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
                },
                Err(AssumeUtxoError::FullRevalidationRequired)
            ));
            assert_eq!(active.durable_head.load()?, head);
            assert_eq!(active.applied_tip_snapshot(), tip);
            assert_eq!(std::fs::read(marker)?, b"required");
            assert!(active.role().is_ordinary());
            assert!(!dir.path().join("assumeutxo").exists());
            Ok(())
        }

        // ARCH-07b
        #[test]
        fn snapshot_base_checkpoint_is_bound_to_the_pinned_commitment() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let (active, manager) = activate(dir.path(), &fixture)?;
            assert!(active.publish_checkpoint()?.is_some());
            drop(manager);
            drop(active);
            let mut wrong_pin = fixture.pinned;
            wrong_pin.hash_serialized = Hash256::default();
            assert!(
                crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &wrong_pin)
                    .is_err()
            );
            let restored =
                crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned)?;
            let root = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
            let current: bitcoin_rs_storage::checkpoint::CurrentV1 = sonic_rs::from_slice(
                &std::fs::read(root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE))?,
            )?;
            let generation = root.join(&current.directory);
            let engine = bitcoin_rs_storage::open_checkpoint_store(&generation.join("chainstate"))?;
            let coins = UtxoSet::new();
            for item in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
                let (_, value) = item?;
                let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                    value.into_boxed_slice(),
                )
                .map_err(|_| TestError::Missing("bad coin record"))?;
                coins.insert_parsed_record(record);
            }
            assert_eq!(
                coins.lock_stable_view().hash_serialized_3()?,
                fixture.pinned.hash_serialized
            );
            assert_eq!(
                restored
                    .applied_tip
                    .as_ref()
                    .map(|tip| tip.height)
                    .ok_or(TestError::Missing("restored tip missing"))?,
                fixture.pinned.height
            );
            Ok(())
        }

        #[test]
        fn snapshot_recovery_rejects_checkpoint_coin_mutation() -> TestResult {
            use bitcoin_rs_storage::KvStore as _;
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let (active, manager) = activate(dir.path(), &fixture)?;
            drop(manager);
            drop(active);
            let root = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
            let current: bitcoin_rs_storage::checkpoint::CurrentV1 = sonic_rs::from_slice(
                &std::fs::read(root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE))?,
            )?;
            let engine_dir = root.join(&current.directory).join("chainstate");
            let store = bitcoin_rs_storage::RocksDbStore::open(&engine_dir)?;
            let (key, value) = {
                let mut rows = store.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?;
                rows.next()
                    .ok_or(TestError::Missing("checkpoint engine has no coins"))??
            };
            let mut mutated = value.to_vec();
            let last = mutated
                .len()
                .checked_sub(1)
                .ok_or(TestError::Missing("empty coin"))?;
            mutated[last] ^= 0x01;
            let mut batch = store.new_batch();
            batch.put(bitcoin_rs_storage::ColumnFamily::Coins, &key, &mutated);
            store.write_durable(batch)?;
            drop(store);
            assert!(
                crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned)
                    .is_err(),
                "recovery must reject a mutated checkpoint coin image"
            );
            Ok(())
        }

        #[test]
        fn committed_snapshot_corruption_fails_closed_but_orphan_dir_is_ignored() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            crate::events::initialize_data_dir(dir.path())?;
            let orphan = dir
                .path()
                .join("assumeutxo")
                .join(fixture.pinned.block_hash.to_string());
            std::fs::create_dir_all(&orphan)?;
            std::fs::write(orphan.join("coins.dat"), b"truncated snapshot")?;
            let (active, manager) = activate(dir.path(), &fixture)?;
            drop(manager);
            drop(active);
            assert_eq!(
                std::fs::read(orphan.join("coins.dat"))?,
                b"truncated snapshot",
                "activation must not touch an operator-planted archive"
            );
            let restored =
                crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned)?;
            assert_eq!(
                restored
                    .applied_tip
                    .as_ref()
                    .map(|tip| tip.height)
                    .ok_or(TestError::Missing("restored tip missing"))?,
                fixture.pinned.height,
                "an orphan archive must not move the snapshot base"
            );
            let root = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
            std::fs::write(
                root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE),
                b"corrupt",
            )?;
            assert!(open_persistent(dir.path(), &fixture.pinned).is_err());
            Ok(())
        }

        struct KillCommit {
            phase: String,
            dir: std::path::PathBuf,
        }

        fn checkpoint_replaced(prefix: &bitcoin_rs_storage::AcceptedPrefix) -> bool {
            match &prefix.next_head.assumeutxo {
                AssumeUtxoDiskStatus::Validating {
                    checkpoint: Some(checkpoint),
                    ..
                } => {
                    checkpoint.height == 1
                        && prefix.expected_head.as_ref().is_some_and(|head| {
                            matches!(
                                &head.assumeutxo,
                                AssumeUtxoDiskStatus::Validating {
                                    checkpoint: Some(previous),
                                    ..
                                } if previous != checkpoint
                            )
                        })
                }
                _ => false,
            }
        }

        fn activation_commit(prefix: &bitcoin_rs_storage::AcceptedPrefix) -> bool {
            prefix.expected_head.is_none()
                && matches!(
                    prefix.next_head.assumeutxo,
                    AssumeUtxoDiskStatus::Validating { .. }
                )
        }

        impl bitcoin_rs_storage::CommitFault for KillCommit {
            fn before_commit(
                &self,
                prefix: &bitcoin_rs_storage::AcceptedPrefix,
            ) -> Result<(), bitcoin_rs_storage::CommitError> {
                if self.phase == "checkpoint-published" && checkpoint_replaced(prefix) {
                    await_kill(&self.dir);
                }
                if self.phase == "snapshot-ingest" && activation_commit(prefix) {
                    await_kill(&self.dir);
                }
                Ok(())
            }

            fn after_commit(
                &self,
                prefix: &bitcoin_rs_storage::AcceptedPrefix,
                _receipt: &bitcoin_rs_storage::DurableReceipt,
            ) {
                if self.phase == "checkpoint-committed" && checkpoint_replaced(prefix) {
                    await_kill(&self.dir);
                }
                let kill = match (self.phase.as_str(), &prefix.next_head.assumeutxo) {
                    ("activation", AssumeUtxoDiskStatus::Validating { .. }) => {
                        prefix.expected_head.is_none()
                    }
                    ("foreground", _) => false,
                    (
                        "historical",
                        AssumeUtxoDiskStatus::Validating {
                            historical_height: 1,
                            ..
                        },
                    )
                    | ("finalized", AssumeUtxoDiskStatus::Finalized { .. }) => true,
                    (
                        "checking",
                        AssumeUtxoDiskStatus::Validating {
                            pending: Some(pending),
                            ..
                        },
                    ) => pending.height == 2,
                    _ => false,
                };
                if kill {
                    await_kill(&self.dir);
                }
            }
        }

        fn await_kill(dir: &Path) -> ! {
            std::fs::write(dir.join("kill-ready"), b"ready")
                .unwrap_or_else(|error| panic!("kill marker: {error}"));
            loop {
                std::thread::park_timeout(std::time::Duration::from_secs(1));
            }
        }
        #[test]
        fn crash_writer() -> TestResult {
            let Some(dir) = std::env::var_os("BITCOIN_RS_SNAPSHOT_KILL_DIR") else {
                return Ok(());
            };
            let dir = std::path::PathBuf::from(dir);
            let phase = std::env::var("BITCOIN_RS_SNAPSHOT_KILL_PHASE")?;
            let fixture = Fixture::new()?;
            let mut active = open_persistent(&dir, &fixture.pinned)?;
            Arc::get_mut(&mut active)
                .ok_or(TestError::Missing("shared crash fixture"))?
                .commit_authority
                .set_fault(Arc::new(KillCommit {
                    phase: phase.clone(),
                    dir: dir.clone(),
                }));
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let checkpoint_phase = phase.starts_with("checkpoint-");
            let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
                Network::Regtest,
                active.clone(),
                dir.clone(),
                if checkpoint_phase || phase == "finalized" {
                    1
                } else {
                    DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL
                },
            )?;
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            }?;
            let child = crate::chain::regtest_fixture::mined_regtest_child_at(
                fixture.blocks[2].block_hash(),
                3,
            )?;
            active
                .begin_transition()?
                .connect(&BlockImage::from_local(child))?;
            if phase == "foreground" {
                await_kill(&dir);
            }
            for (height, block) in fixture.blocks.iter().enumerate() {
                manager.step_historical(&BlockImage::from_local((*block).clone()))?;
                if checkpoint_phase && height == 0 {
                    publish_genesis_historical_checkpoint(&dir, &manager, block)?;
                }
            }
            Err(TestError::UnexpectedSuccess(
                "crash failpoint was not reached",
            ))
        }

        fn publish_genesis_historical_checkpoint(
            dir: &Path,
            manager: &AssumeUtxoManager,
            block: &bitcoin_rs_consensus::primitives::Block,
        ) -> TestResult {
            let historical = manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing history"))?;
            let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir)?;
            let write = crate::checkpoint::write_historical_checkpoint_with_store(
                &data,
                crate::checkpoint::headers::HeaderCheckpointConfig {
                    network: Network::Regtest,
                    genesis: Network::Regtest.genesis_block_hash(),
                },
                &historical.block_tree,
                &historical.coin_stats,
                historical.applied_tip_snapshot().as_deref(),
                crate::checkpoint::CheckpointStoreTarget {
                    store: historical.commit_authority.store().as_ref(),
                    host_data_dir: dir,
                },
            )?;
            let crate::checkpoint::CheckpointWrite::Published { reference } = write else {
                return Err(TestError::Missing("missing genesis checkpoint"));
            };
            let mut status = manager.status()?;
            let AssumeUtxoDiskStatus::Validating { checkpoint, .. } = &mut status else {
                return Err(TestError::Missing("missing validating status"));
            };
            *checkpoint = Some(HistoricalCheckpointRef {
                checkpoint: reference,
                height: 0,
                hash: block.block_hash().0,
            });
            manager.persist_status(status, None)?;
            Ok(())
        }

        fn run_crashing_writer(dir: &Path, phase: &str) -> TestResult {
            let mut child = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "assumeutxo::tests::recovery::crash_writer",
                    "--nocapture",
                ])
                .env("BITCOIN_RS_SNAPSHOT_KILL_DIR", dir)
                .env("BITCOIN_RS_SNAPSHOT_KILL_PHASE", phase)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .spawn()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while !dir.join("kill-ready").exists() && std::time::Instant::now() < deadline {
                if let Some(_status) = child.try_wait()? {
                    return Err(TestError::WorkerPanicked("child exited before kill"));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let ready = dir.join("kill-ready").exists();
            child.kill()?;
            child.wait()?;
            assert!(ready, "{phase} failed to reach its durable boundary");
            Ok(())
        }

        fn verify_recovered_snapshot_phase(
            fixture: &Fixture,
            dir: &Path,
            phase: &str,
        ) -> TestResult {
            let historical_root =
                dir.join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
            if phase == "finalized" {
                assert!(historical_root.join("CURRENT").exists());
                assert!(std::fs::read_dir(&historical_root)?.count() > 1);
            }
            if phase == "snapshot-ingest" {
                assert!(
                    dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT)
                        .join("CURRENT")
                        .is_file(),
                    "the snapshot-base checkpoint is published before the head commit"
                );
            }
            let active = open_persistent(dir, &fixture.pinned)?;
            if phase == "snapshot-ingest" {
                assert!(
                    !dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT)
                        .join("CURRENT")
                        .exists(),
                    "the rollback removes the checkpoint no head names"
                );
                assert!(active.applied_tip_snapshot().is_none());
                assert!(
                    active.durable_head.load()?.is_none(),
                    "a crash before the activation head commit must leave the durable head unchanged"
                );
                assert!(
                    active
                        .commit_authority
                        .store()
                        .get(
                            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                            bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY
                        )?
                        .is_none(),
                    "the interrupted activation marker must be cleared with the coin wipe"
                );
                let coins = engine_coin_set_from_store(active.commit_authority.store().as_ref())?;
                assert!(
                    coins.is_empty(),
                    "snapshot coins survived a crash between coin ingest and the activation head commit"
                );
                active.admit_headers(
                    &fixture
                        .blocks
                        .iter()
                        .map(|block| block.header)
                        .collect::<Vec<_>>(),
                )?;
                let manager =
                    AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)?;
                let head = active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("re-activated head missing"))?;
                assert_eq!(head.tip, fixture.pinned.block_hash);
                assert_eq!(head.chain_tx_count, fixture.pinned.chain_tx_count);
                assert!(matches!(
                    head.assumeutxo,
                    AssumeUtxoDiskStatus::Validating { base_height, base_hash, .. }
                        if base_height == fixture.pinned.height && base_hash == fixture.pinned.block_hash
                ));
                assert!(
                    !engine_coin_set_from_store(active.commit_authority.store().as_ref())?
                        .is_empty(),
                    "re-activation must restage the snapshot coins"
                );
                return Ok(());
            }
            let manager =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
            assert_eq!(
                active
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing recovered tip"))?
                    .height,
                if phase == "activation" { 2 } else { 3 }
            );
            if phase.starts_with("checkpoint-") {
                let historical_height = u32::from(phase != "checkpoint-published");
                assert_eq!(
                    manager
                        .historical_chainstate()
                        .ok_or(TestError::Missing("missing history"))?
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("missing historical tip"))?
                        .height,
                    1
                );
                drop(manager);
                drop(active);
                let active = open_persistent(dir, &fixture.pinned)?;
                let manager = AssumeUtxoManager::open(Network::Regtest, active, dir.to_path_buf())?;
                assert_eq!(
                    manager
                        .historical_chainstate()
                        .ok_or(TestError::Missing("missing history"))?
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("missing historical tip"))?
                        .height,
                    historical_height
                );
            } else if phase == "finalized" || phase == "checking" {
                assert!(active.role().is_ordinary());
                if phase == "finalized" {
                    assert_eq!(std::fs::read_dir(&historical_root)?.count(), 0);
                }
            } else {
                assert!(active.role().is_assumed_active());
                assert!(
                    manager
                        .historical_chainstate()
                        .ok_or(TestError::Missing("missing history"))?
                        .applied_tip_snapshot()
                        .is_none()
                );
            }
            Ok(())
        }

        #[test]
        fn process_death_recovers_each_snapshot_phase_from_the_committed_root() -> TestResult {
            let fixture = Fixture::new()?;
            for phase in [
                "snapshot-ingest",
                "activation",
                "foreground",
                "historical",
                "checking",
                "finalized",
                "checkpoint-published",
                "checkpoint-committed",
            ] {
                let dir = tempfile::tempdir()?;
                run_crashing_writer(dir.path(), phase)?;
                verify_recovered_snapshot_phase(&fixture, dir.path(), phase)?;
            }
            Ok(())
        }

        struct RejectTerminalCommit;

        impl bitcoin_rs_storage::CommitFault for RejectTerminalCommit {
            fn before_commit(
                &self,
                prefix: &bitcoin_rs_storage::AcceptedPrefix,
            ) -> Result<(), bitcoin_rs_storage::CommitError> {
                if matches!(
                    prefix.next_head.assumeutxo,
                    AssumeUtxoDiskStatus::Failed { .. } | AssumeUtxoDiskStatus::Finalized { .. }
                ) {
                    return Err(bitcoin_rs_storage::CommitError::Storage(
                        bitcoin_rs_storage::StorageError::InvalidOperation(
                            "injected terminal receipt failure",
                        ),
                    ));
                }
                Ok(())
            }
        }

        #[test]
        fn finalized_checkpoint_recovers_without_replaying_pruned_foreground_history() -> TestResult
        {
            use bitcoin_rs_storage::KvStore;
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let (active, manager) = activate(dir.path(), &fixture)?;
            let child = crate::chain::regtest_fixture::mined_regtest_child_at(
                fixture.blocks[2].block_hash(),
                3,
            )?;
            active
                .begin_transition()?
                .connect(&BlockImage::from_local(child.clone()))?;
            for block in &fixture.blocks {
                manager.step_historical(&BlockImage::from_local((*block).clone()))?;
            }
            assert!(active.publish_checkpoint()?.is_some());
            let stats = active.coin_stats.snapshot();
            drop(manager);
            drop(active);
            let store = RocksDbStore::open(dir.path().join("chainstate"))?;
            let mut batch = store.new_batch();
            batch.delete(
                bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::pruning::block_body_key(3, child.block_hash().0),
            );
            store.write_durable(batch)?;
            drop(store);
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                active.clone(),
                dir.path().to_path_buf(),
            )?;
            assert!(matches!(
                manager.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert_eq!(active.coin_stats.snapshot(), stats);
            assert_eq!(
                active
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing restored tip"))?
                    .hash,
                child.block_hash().0
            );
            Ok(())
        }

        #[test]
        fn failed_pre_base_validation_cannot_be_forgotten_when_failure_receipt_is_lost()
        -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let mut active = open_persistent(dir.path(), &fixture.pinned)?;
            Arc::get_mut(&mut active)
                .ok_or(TestError::Missing("shared fixture"))?
                .commit_authority
                .set_fault(Arc::new(RejectTerminalCommit));
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                active.clone(),
                dir.path().to_path_buf(),
            )?;
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            }?;
            manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
            let mut invalid = fixture.blocks[1].clone();
            invalid.txs[0].inputs[0].script_sig = bitcoin_rs_consensus::primitives::Script::new();
            invalid.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&invalid.txs)
                .ok_or(TestError::Missing("merkle root"))?;
            crate::chain::regtest_fixture::mine_block_to_declared_target(&mut invalid)?;
            assert!(
                manager
                    .step_historical(&BlockImage::from_local(invalid.clone()))
                    .is_err()
            );
            assert!(active.is_closed_for_recovery());
            assert!(
                matches!(manager.status()?, AssumeUtxoDiskStatus::Validating { pending: Some(pending), .. } if pending.height == 1)
            );
            drop(manager);
            drop(active);
            let active = open_persistent(dir.path(), &fixture.pinned)?;
            assert!(
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.path().to_path_buf())
                    .is_err()
            );
            assert!(active.is_closed_for_recovery());
            assert!(matches!(
                active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("missing head"))?
                    .assumeutxo,
                AssumeUtxoDiskStatus::Failed { .. }
            ));
            Ok(())
        }

        fn assert_reopen_refuses_mismatched_receipt(dir: &Path, fixture: &Fixture) -> TestResult {
            let active = open_persistent(dir, &fixture.pinned)?;
            let reopened =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf());
            assert!(reopened.is_err());
            assert!(active.is_closed_for_recovery());
            assert!(matches!(
                active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("missing head"))?
                    .assumeutxo,
                AssumeUtxoDiskStatus::Failed { .. }
            ));
            Ok(())
        }

        fn assert_reopen_finalizes_after_rejected_write(
            dir: &Path,
            fixture: &Fixture,
        ) -> TestResult {
            let active = open_persistent(dir, &fixture.pinned)?;
            let reopened =
                AssumeUtxoManager::open(Network::Regtest, active.clone(), dir.to_path_buf())?;
            assert!(matches!(
                reopened.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert!(active.role().is_ordinary());
            Ok(())
        }

        #[test]
        fn failed_terminal_write_must_be_rechecked_before_restart_can_serve() -> TestResult {
            for mismatch in [false, true] {
                let fixture = Fixture::new()?;
                let dir = tempfile::tempdir()?;
                let mut active = open_persistent(dir.path(), &fixture.pinned)?;
                Arc::get_mut(&mut active)
                    .ok_or(TestError::Missing("shared fixture"))?
                    .commit_authority
                    .set_fault(Arc::new(RejectTerminalCommit));
                active.admit_headers(
                    &fixture
                        .blocks
                        .iter()
                        .map(|block| block.header)
                        .collect::<Vec<_>>(),
                )?;
                let manager = AssumeUtxoManager::open(
                    Network::Regtest,
                    active.clone(),
                    dir.path().to_path_buf(),
                )?;
                {
                    let loaded = fixture.load()?;
                    manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
                }?;
                if mismatch {
                    let prior = active
                        .durable_head
                        .load()?
                        .ok_or(TestError::Missing("missing head"))?;
                    let mut next = prior;
                    if let AssumeUtxoDiskStatus::Validating { chain_tx_count, .. } =
                        &mut next.assumeutxo
                    {
                        *chain_tx_count += 1;
                    }
                    next.commit_id += 1;
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
                        .map_err(|error| {
                            TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
                        })?;
                }
                for block in &fixture.blocks[..2] {
                    manager.step_historical(&BlockImage::from_local((*block).clone()))?;
                }
                assert!(
                    manager
                        .step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))
                        .is_err()
                );
                assert!(active.is_closed_for_recovery());
                let head = active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("missing head"))?;
                assert!(matches!(
                    head.assumeutxo,
                    AssumeUtxoDiskStatus::Validating {
                        pending: Some(_),
                        ..
                    }
                ));
                assert!(
                    active
                        .block_body_store
                        .as_ref()
                        .ok_or(TestError::Missing("missing bodies"))?
                        .load_block_body(2, fixture.pinned.block_hash)?
                        .is_none()
                );
                drop(manager);
                drop(active);
                if mismatch {
                    assert_reopen_refuses_mismatched_receipt(dir.path(), &fixture)?;
                } else {
                    assert_reopen_finalizes_after_rejected_write(dir.path(), &fixture)?;
                }
            }
            Ok(())
        }

        #[test]
        fn import_finalize_from_checkpoint_seed_completes() -> TestResult {
            let bad = Fixture::new()?;
            let bad_dir = tempfile::tempdir()?;
            let bad_manager = bad.manager(bad_dir.path())?;
            let wrong = Hash256::default();
            assert_ne!(wrong, bad.pinned.block_hash);
            let rejected = bad.load()?;
            assert!(matches!(
                bad_manager.activate_pinned_snapshot(rejected.set, wrong, &bad.pinned),
                Err(AssumeUtxoError::SnapshotBlockHashMismatch { .. })
            ));
            assert_no_checkpoint_published(bad_dir.path());

            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let manager = fixture.manager(dir.path())?;
            fixture.activate(&manager)?;
            let current = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT)
                .join("CURRENT");
            assert!(
                current.is_file(),
                "activation publishes the snapshot-base checkpoint"
            );

            std::fs::write(
                dir.path()
                    .join(bitcoin_rs_storage::checkpoint::fs::CURRENT_SCHEMA_FILE),
                bitcoin_rs_storage::checkpoint::fs::current_schema_bytes(),
            )?;
            let restored =
                crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned)?;
            assert!(matches!(
                restored.resume_source,
                crate::recovery::ResumeSource::Checkpoint
            ));
            for block in &fixture.blocks {
                manager.step_historical(&BlockImage::from_local((*block).clone()))?;
            }
            assert!(matches!(
                manager.status()?,
                AssumeUtxoDiskStatus::Finalized { .. }
            ));
            assert_engine_matches_snapshot(&fixture.active, &fixture)?;

            Ok(())
        }

        fn assert_no_checkpoint_published(dir: &std::path::Path) {
            assert!(
                !dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT)
                    .join("CURRENT")
                    .is_file(),
                "a rejected activation must not publish a checkpoint"
            );
        }

        #[test]
        fn crash_mid_ingest_is_rolled_back_by_the_marker_and_the_retry_matches_the_snapshot()
        -> TestResult {
            let mut fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let set = read_snapshot_strict_v4(&mut Cursor::new(&fixture.snapshot))?.set;
            for seed in 0x40_u8..0x44 {
                let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
                    Hash256::from_le_bytes(&[seed; 32]),
                    &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut::new(
                        0,
                        1_000,
                        vec![0x51],
                        false,
                        1,
                    )],
                )
                .map_err(|_| TestError::Missing("synthetic coin record"))?;
                set.insert_parsed_record(record);
            }
            let records = set.all_records();
            assert!(
                records.len() >= 3,
                "the fixture must span at least three batches"
            );
            fixture.pinned.hash_serialized = set.lock_stable_view().hash_serialized_3()?;
            let mut bytes = Cursor::new(Vec::new());
            write_snapshot_observed(
                &set,
                &fixture.pinned.block_hash,
                fixture.pinned.height,
                &mut bytes,
                (),
            )?;
            fixture.snapshot = bytes.into_inner();
            let mut stats = set.with_stable_view(|view| {
                bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, fixture.pinned.height, true)
            })?;
            stats.tx_count = fixture.pinned.chain_tx_count;
            fixture.stats = stats;
            let record_bytes: usize = records
                .iter()
                .map(|record| bitcoin_rs_storage::COIN_KEY_LEN + record.bytes().len())
                .sum();
            let chunk = (record_bytes / 6).max(1);
            let headers = fixture
                .blocks
                .iter()
                .map(|block| block.header)
                .collect::<Vec<_>>();
            {
                let store = chainstate_store(dir.path())?;
                let active = open_persistent_over(dir.path(), &fixture.pinned, Arc::clone(&store))?;
                active.admit_headers(&headers)?;
                let manager = AssumeUtxoManager::open(
                    Network::Regtest,
                    active.clone(),
                    dir.path().to_path_buf(),
                )?
                .with_ingest_chunk_bytes(chunk);
                let before = store.durable_batches();
                store.fail_durable_batch(2);
                let loaded = fixture.load()?;
                let outcome = manager.activate_pinned_snapshot_with(
                    loaded.set,
                    loaded.tip_hash,
                    &fixture.pinned,
                    |_, _| {},
                    || true,
                );
                assert!(
                    matches!(
                        outcome,
                        Err(AssumeUtxoError::PartialIngestNotDiscarded { .. })
                    ),
                    "the crashed store cannot discard its staged coins: {outcome:?}"
                );
                assert!(store.is_dead());
                assert!(active.is_closed_for_recovery());
                assert_eq!(store.durable_batches() - before, 2);
                assert!(!engine_coin_records(&active)?.is_empty());
                assert!(
                    active
                        .commit_authority
                        .store()
                        .get(
                            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                            bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY,
                        )?
                        .is_some()
                );
            }
            let store = chainstate_store(dir.path())?;
            let reopened = open_persistent_over(dir.path(), &fixture.pinned, Arc::clone(&store))?;
            assert!(engine_coin_records(&reopened)?.is_empty());
            assert!(
                reopened
                    .commit_authority
                    .store()
                    .get(
                        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                        bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY,
                    )?
                    .is_none()
            );
            reopened.admit_headers(&headers)?;
            let manager = AssumeUtxoManager::open(
                Network::Regtest,
                reopened.clone(),
                dir.path().to_path_buf(),
            )?
            .with_ingest_chunk_bytes(chunk);
            let loaded = fixture.load()?;
            manager.activate_pinned_snapshot_with(
                loaded.set,
                loaded.tip_hash,
                &fixture.pinned,
                |_, _| {},
                || true,
            )?;
            assert!(
                store.durable_batches() >= 3,
                "the retry ingests in at least three batches: {} batches for {} records of {record_bytes} bytes at chunk {chunk}",
                store.durable_batches(),
                records.len(),
            );
            assert_engine_matches_snapshot(&reopened, &fixture)
        }

        #[test]
        fn failed_orphan_cleanup_keeps_the_marker_and_the_next_boot_retries_the_rollback()
        -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let store = chainstate_store(dir.path())?;
            let active = open_persistent_over(dir.path(), &fixture.pinned, Arc::clone(&store))?;
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let marker = bitcoin_rs_storage::SnapshotActivationMarker {
                base_hash: fixture.pinned.block_hash,
                coin_count: 0,
                coin_digest: Hash256::from_le_bytes(&[0_u8; 32]),
            };
            active
                .commit_authority
                .begin_snapshot_activation(None, &marker)
                .map_err(crate::assumeutxo::commit_error)?;

            let root = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
            std::fs::create_dir_all(&root)?;
            let generation_name = "generation-000001";
            let current = bitcoin_rs_storage::checkpoint::CurrentV1 {
                format: bitcoin_rs_storage::checkpoint::CURRENT_FORMAT.to_owned(),
                version: 1,
                generation: 1,
                directory: generation_name.to_owned(),
                manifest_sha256: String::new(),
            };
            std::fs::write(
                root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE),
                sonic_rs::to_vec(&current)?,
            )?;
            let generation = root.join(generation_name);
            std::fs::write(
                &generation,
                b"obstruction where the orphan generation belongs",
            )?;

            let marker_bytes = || -> TestResult<Option<Vec<u8>>> {
                Ok(active
                    .commit_authority
                    .store()
                    .get(
                        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                        bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY,
                    )?
                    .map(|bytes| bytes.to_vec()))
            };

            let outcome = crate::recover_snapshot_activation(&active, dir.path());
            assert!(
                matches!(
                    &outcome,
                    Err(AssumeUtxoError::Storage(
                        bitcoin_rs_storage::StorageError::Io(error)
                    )) if error.kind() == std::io::ErrorKind::NotADirectory
                ),
                "a failed orphan cleanup must fail the recovery before the marker is cleared: {outcome:?}"
            );
            assert!(
                marker_bytes()?.is_some(),
                "a failed orphan cleanup must keep the activation marker durable"
            );
            assert!(
                root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE)
                    .is_file(),
                "a failed orphan cleanup must keep the orphan checkpoint root selected"
            );

            std::fs::remove_file(&generation)?;
            crate::recover_snapshot_activation(&active, dir.path())?;
            assert!(
                marker_bytes()?.is_none(),
                "a successful orphan cleanup must clear the activation marker"
            );
            assert!(
                !root
                    .join(bitcoin_rs_storage::checkpoint::CURRENT_FILE)
                    .exists(),
                "a successful orphan cleanup must remove the orphan CURRENT"
            );
            Ok(())
        }

        // RCV-03
        #[test]
        fn orphan_rollback_syncs_checkpoint_root_before_clearing_the_marker() -> TestResult {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let store = chainstate_store(dir.path())?;
            let active = open_persistent_over(dir.path(), &fixture.pinned, Arc::clone(&store))?;
            active.admit_headers(
                &fixture
                    .blocks
                    .iter()
                    .map(|block| block.header)
                    .collect::<Vec<_>>(),
            )?;
            let marker = bitcoin_rs_storage::SnapshotActivationMarker {
                base_hash: fixture.pinned.block_hash,
                coin_count: 0,
                coin_digest: Hash256::from_le_bytes(&[0_u8; 32]),
            };
            let arm_marker = || -> TestResult<()> {
                active
                    .commit_authority
                    .begin_snapshot_activation(None, &marker)
                    .map_err(crate::assumeutxo::commit_error)?;
                Ok(())
            };
            let marker_bytes = || -> TestResult<Option<Vec<u8>>> {
                Ok(active
                    .commit_authority
                    .store()
                    .get(
                        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                        bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY,
                    )?
                    .map(|bytes| bytes.to_vec()))
            };
            let root = dir
                .path()
                .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
            std::fs::create_dir_all(&root)?;
            let current = bitcoin_rs_storage::checkpoint::CurrentV1 {
                format: bitcoin_rs_storage::checkpoint::CURRENT_FORMAT.to_owned(),
                version: 1,
                generation: 1,
                directory: "generation-000001".to_owned(),
                manifest_sha256: String::new(),
            };
            std::fs::write(
                root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE),
                sonic_rs::to_vec(&current)?,
            )?;
            arm_marker()?;

            crate::assumeutxo::inject_orphan_root_sync_failure(
                "injected checkpoint root sync failure",
            );
            let outcome = crate::recover_snapshot_activation(&active, dir.path());
            assert!(
                matches!(
                    &outcome,
                    Err(AssumeUtxoError::Storage(
                        bitcoin_rs_storage::StorageError::Io(_)
                    ))
                ),
                "a failed checkpoint root sync must keep the recovery fail-closed: {outcome:?}"
            );
            assert!(
                marker_bytes()?.is_some(),
                "a failed checkpoint root sync must keep the activation marker durable"
            );
            assert!(
                !root
                    .join(bitcoin_rs_storage::checkpoint::CURRENT_FILE)
                    .exists(),
                "the orphan deletion lands before the root sync decides the marker clear"
            );

            crate::assumeutxo::inject_orphan_root_sync_failure(
                "injected checkpoint root sync failure",
            );
            let outcome = crate::recover_snapshot_activation(&active, dir.path());
            assert!(
                matches!(
                    &outcome,
                    Err(AssumeUtxoError::Storage(
                        bitcoin_rs_storage::StorageError::Io(_)
                    ))
                ),
                "a failed retry root sync must keep the recovery fail-closed: {outcome:?}"
            );
            assert!(
                marker_bytes()?.is_some(),
                "a failed retry root sync must keep the activation marker durable"
            );

            crate::recover_snapshot_activation(&active, dir.path())?;
            assert!(
                marker_bytes()?.is_none(),
                "a retry without CURRENT must sync the existing checkpoint root and clear the marker"
            );

            arm_marker()?;
            std::fs::remove_dir_all(&root)?;
            crate::recover_snapshot_activation(&active, dir.path())?;
            assert!(
                marker_bytes()?.is_none(),
                "a missing checkpoint root has nothing to sync and must clear the marker"
            );
            Ok(())
        }
    }

    #[test]
    fn snapshot_advances_partial_state_but_refuses_to_replace_an_equal_or_newer_tip() -> TestResult
    {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        fixture
            .active
            .begin_transition()?
            .connect(&BlockImage::from_local(fixture.blocks[0].clone()))?;
        fixture
            .active
            .begin_transition()?
            .connect(&BlockImage::from_local(fixture.blocks[1].clone()))?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        assert_eq!(fixture.active.coin_stats.snapshot(), fixture.stats);
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        for block in &fixture.blocks {
            fixture
                .active
                .begin_transition()?
                .connect(&BlockImage::from_local((*block).clone()))?;
        }
        let manager = fixture.manager(dir.path())?;
        let before = fixture.active.durable_head.load()?;
        let before_stats = fixture.active.coin_stats.snapshot();
        assert!(matches!(
            {
                let loaded = fixture.load()?;
                manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned)
            },
            Err(AssumeUtxoError::ActivationBehindTip)
        ));
        assert_eq!(fixture.active.durable_head.load()?, before);
        assert_eq!(fixture.active.coin_stats.snapshot(), before_stats);
        assert!(!fixture.active.is_closed_for_recovery());
        Ok(())
    }

    #[test]
    fn out_of_order_historical_input_does_not_persist_or_close_admission() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let before = fixture.active.durable_head.load()?;
        assert!(matches!(
            manager.step_historical(&BlockImage::from_local(fixture.blocks[1].clone())),
            Err(AssumeUtxoError::Apply(ApplyError::PrevHashMismatch { .. }))
        ));
        assert_eq!(fixture.active.durable_head.load()?, before);
        assert!(!fixture.active.is_closed_for_recovery());
        manager.step_historical(&BlockImage::from_local(fixture.blocks[0].clone()))?;
        Ok(())
    }

    #[test]
    fn historical_restart_replays_coins_from_genesis_instead_of_fabricating_a_tip() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        for block in &fixture.blocks[..2] {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        assert!(
            manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing historical"))?
                .coin_stats
                .snapshot()
                .utxo_count
                > 0
        );
        drop(manager);
        let reopened = fixture.manager(dir.path())?;
        let historical = reopened
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical after restart"))?;
        assert!(historical.applied_tip_snapshot().is_none());
        assert_eq!(historical.coin_stats.snapshot(), CoinStats::default());
        for block in &fixture.blocks {
            reopened.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        assert!(matches!(
            reopened.status()?,
            AssumeUtxoDiskStatus::Finalized { .. }
        ));
        Ok(())
    }

    // RCV-02
    #[test]
    fn finalized_replay_attests_full_so_a_full_start_skips_revalidation() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let activated = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing activated head"))?;
        assert_eq!(
            fixture.active.durable_head.load_attestation(&activated)?,
            bitcoin_rs_storage::ScriptAttestation::AssumeValid,
            "an activated snapshot has not executed the scripts below its base yet"
        );
        for block in &fixture.blocks {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        assert!(matches!(
            manager.status()?,
            AssumeUtxoDiskStatus::Finalized { .. }
        ));
        let finalized = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing finalized head"))?;
        assert_eq!(
            fixture.active.durable_head.load_attestation(&finalized)?,
            bitcoin_rs_storage::ScriptAttestation::Full,
            "the historical replay executed every script below the base"
        );
        crate::recovery::require_full_script_attestation(
            dir.path(),
            crate::ValidationMode::Full,
            Some(&finalized),
            fixture.active.durable_head.as_ref(),
            false,
        )?;
        assert!(
            !crate::recovery::requires_full_revalidation(dir.path()),
            "a finalized assumeutxo datadir must not take the cold revalidation path"
        );
        Ok(())
    }

    // RCV-02
    #[test]
    fn finalized_replay_keeps_an_assume_valid_suffix_below_full() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let prior = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing activated head"))?;
        let next = DurableHead {
            commit_id: prior.commit_id + 1,
            height: prior.height + 1,
            tip: Hash256::from_le_bytes(&[0x33; 32]),
            chain_tx_count: prior.chain_tx_count + 1,
            ..prior
        };
        fixture
            .active
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: Some(prior),
                next_head: next,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: Some(bitcoin_rs_storage::ScriptAttestation::AssumeValid),
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(|error| {
                TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
            })?;
        assert_eq!(
            fixture.active.durable_head.load_suffix_attestation(&next)?,
            bitcoin_rs_storage::ScriptAttestation::AssumeValid,
            "a block above the base that skipped scripts must lower the suffix level"
        );
        for block in &fixture.blocks {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        let finalized = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing finalized head"))?;
        assert_eq!(
            fixture.active.durable_head.load_attestation(&finalized)?,
            bitcoin_rs_storage::ScriptAttestation::AssumeValid,
            "the finalized head spans blocks above the base that never executed scripts"
        );
        crate::recovery::require_full_script_attestation(
            dir.path(),
            crate::ValidationMode::Full,
            Some(&finalized),
            fixture.active.durable_head.as_ref(),
            false,
        )?;
        assert!(
            crate::recovery::requires_full_revalidation(dir.path()),
            "a full start must revalidate a chain whose suffix skipped scripts"
        );
        Ok(())
    }

    // RCV-02
    #[test]
    fn finalized_replay_attests_full_after_an_executed_suffix() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let block = crate::chain::regtest_fixture::mined_regtest_child_at(
            fixture
                .blocks
                .last()
                .ok_or(TestError::Missing("missing base block"))?
                .block_hash(),
            3,
        )?;
        fixture
            .active
            .block_tree
            .write()
            .insert_header(block.header, NodeStatus::HeaderValid)?;
        fixture.active.apply_block(&BlockImage::from_local(block))?;
        let executed = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing executed head"))?;
        assert_eq!(executed.height, 3);
        assert_eq!(
            fixture
                .active
                .durable_head
                .load_suffix_attestation(&executed)?,
            bitcoin_rs_storage::ScriptAttestation::Full,
            "a block above the base that executed scripts keeps the suffix level Full"
        );
        for block in &fixture.blocks {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        let finalized = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing finalized head"))?;
        assert_eq!(
            fixture.active.durable_head.load_attestation(&finalized)?,
            bitcoin_rs_storage::ScriptAttestation::Full,
            "the historical replay and every suffix block executed scripts"
        );
        Ok(())
    }

    #[test]
    fn reconstructed_commitment_or_transaction_count_mismatch_fails_closed() -> TestResult {
        for wrong_count in [false, true] {
            let fixture = Fixture::new()?;
            let dir = tempfile::tempdir()?;
            let manager = fixture.manager(dir.path())?;
            fixture.activate(&manager)?;
            {
                let prior = fixture
                    .active
                    .durable_head
                    .load()?
                    .ok_or(TestError::Missing("missing head"))?;
                let mut next = prior;
                if let AssumeUtxoDiskStatus::Validating {
                    ref mut expected_hash_serialized,
                    ref mut chain_tx_count,
                    ..
                } = next.assumeutxo
                {
                    if wrong_count {
                        *chain_tx_count += 1;
                    } else {
                        *expected_hash_serialized = Hash256::default();
                    }
                }
                next.commit_id += 1;
                fixture
                    .active
                    .commit_authority
                    .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                        expected_head: Some(prior),
                        next_head: next,
                        undo_rows: Vec::new(),
                        body_rows: Vec::new(),
                        attestation: None,
                        coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                    })
                    .map_err(|error| {
                        TestError::Storage(bitcoin_rs_storage::StorageError::backend(error))
                    })?;
            }
            for block in &fixture.blocks[..2] {
                manager.step_historical(&BlockImage::from_local((*block).clone()))?;
            }
            let historical = manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing historical"))?;
            let Err(error) =
                manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone()))
            else {
                return Err(TestError::UnexpectedSuccess("divergence finalized"));
            };
            if wrong_count {
                assert!(matches!(
                    error,
                    AssumeUtxoError::HistoricalTransactionCountMismatch { .. }
                ));
            } else {
                assert!(matches!(error, AssumeUtxoError::CommitmentMismatch { .. }));
            }
            assert!(fixture.active.is_closed_for_recovery());
            assert!(historical.is_closed_for_recovery());
            assert!(matches!(
                disk_status(&fixture.active)?,
                AssumeUtxoDiskStatus::Failed { .. }
            ));
            assert!(matches!(
                fixture.manager(dir.path()),
                Err(AssumeUtxoError::PreviouslyFailed { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn target_hash_divergence_is_classified_and_persisted() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        for block in &fixture.blocks[..2] {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        let mut wrong = fixture.blocks[2].clone();
        wrong.header.nonce = wrong.header.nonce.wrapping_add(1);
        assert!(matches!(
            manager.step_historical(&BlockImage::from_local(wrong)),
            Err(AssumeUtxoError::HistoricalTargetHashMismatch { .. })
        ));
        assert!(fixture.active.is_closed_for_recovery());
        assert!(matches!(
            disk_status(&fixture.active)?,
            AssumeUtxoDiskStatus::Failed { .. }
        ));
        Ok(())
    }

    #[test]
    fn mismatch_closes_admission_even_when_failure_record_cannot_be_written() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        for block in &fixture.blocks[..2] {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        fixture.head.fail_terminal.store(true, Ordering::Release);
        let mut wrong = fixture.blocks[2].clone();
        wrong.header.nonce = wrong.header.nonce.wrapping_add(1);
        assert!(matches!(
            manager.step_historical(&BlockImage::from_local(wrong)),
            Err(AssumeUtxoError::Storage(_))
        ));
        assert!(fixture.active.lock_transition().is_err());
        assert!(
            manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing historical"))?
                .lock_transition()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn finalization_io_failure_keeps_assumed_role_and_closes_both_admissions() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = AssumeUtxoManager::open_with_historical_checkpoint_interval(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
            1,
        )?;
        fixture.activate(&manager)?;
        for block in &fixture.blocks[..2] {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        fixture.head.fail_terminal.store(true, Ordering::Release);
        let root = dir
            .path()
            .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT);
        let checkpoint_entries = std::fs::read_dir(&root)?.count();
        assert!(checkpoint_entries > 1);
        assert!(matches!(
            manager.step_historical(&BlockImage::from_local(fixture.blocks[2].clone())),
            Err(AssumeUtxoError::Storage(_))
        ));
        assert!(fixture.active.role().is_assumed_active());
        assert_eq!(std::fs::read_dir(root)?.count(), checkpoint_entries);
        assert!(matches!(
            manager.status()?,
            AssumeUtxoDiskStatus::Validating { .. }
        ));
        assert!(fixture.active.lock_transition().is_err());
        assert!(
            manager
                .historical_chainstate()
                .ok_or(TestError::Missing("missing historical"))?
                .lock_transition()
                .is_err()
        );
        Ok(())
    }

    // ARCH-07b
    #[test]
    fn assumed_reorg_and_historical_height_guards_remain_enforced() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        assert!(matches!(
            crate::disconnect::plan_disconnect(
                &fixture.active,
                &fixture.blocks[2],
                fixture.pinned.block_hash
            ),
            Err(ApplyError::DisconnectBelowSnapshotBase { .. })
        ));
        let historical = manager
            .historical_chainstate()
            .ok_or(TestError::Missing("missing historical"))?;
        for block in &fixture.blocks {
            manager.step_historical(&BlockImage::from_local((*block).clone()))?;
        }
        let child = crate::chain::regtest_fixture::mined_regtest_child_at(
            fixture.blocks[2].block_hash(),
            3,
        )?;
        assert!(matches!(
            historical
                .lock_transition()?
                .into_transition()
                .connect(&BlockImage::from_local(child)),
            Err(ApplyError::ConnectPastHistoricalTarget { .. })
        ));
        Ok(())
    }

    #[test]
    fn snapshot_persistence_does_not_block_existing_progress_queries() -> TestResult {
        let fixture = Fixture::new()?;
        let genesis = Network::Regtest.genesis_block();
        fixture
            .active
            .lock_transition()?
            .into_transition()
            .connect(&BlockImage::from_local(genesis))?;
        let before = fixture
            .active
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("genesis missing"))?;
        let reader = fixture.active.chain_progress_reader();
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        let mut reader = Some(reader);
        let mut observed = None;
        let loaded = fixture.load()?;
        let result = std::thread::scope(|scope| {
            manager.activate_pinned_snapshot_with(
                loaded.set,
                loaded.tip_hash,
                &fixture.pinned,
                |_, _| {
                    let Some(reader) = reader.take() else {
                        return;
                    };
                    let (sent, received) = std::sync::mpsc::sync_channel(1);
                    scope.spawn(move || {
                        let progress = reader.progress(
                            Network::Regtest,
                            bitcoin_rs_consensus::primitives::unix_time_secs(),
                        );
                        let _ = sent.send(progress);
                    });
                    observed = received
                        .recv_timeout(std::time::Duration::from_secs(1))
                        .ok();
                },
                || false,
            )
        });
        assert!(result.is_err());
        let progress = observed.ok_or(TestError::UnexpectedSuccess(
            "progress query blocked behind snapshot persistence",
        ))?;
        assert_eq!(progress.blocks, before.height);
        assert_eq!(progress.best_block_hash, before.hash);
        assert_eq!(
            fixture
                .active
                .applied_tip_snapshot()
                .ok_or(TestError::UnexpectedSuccess("prior tip lost"))?
                .hash,
            before.hash
        );
        Ok(())
    }

    #[test]
    fn lifecycle_report_refuses_contention_without_waiting_for_the_transition() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager =
            AssumeUtxoManager::open(Network::Regtest, fixture.active, dir.path().to_path_buf())?;
        let observed = std::thread::scope(|scope| {
            let guard = manager.lifecycle.lock();
            let (sent, received) = std::sync::mpsc::sync_channel(1);
            let reader = &manager;
            scope.spawn(move || {
                let _ = sent.send(reader.try_chainstates_report());
            });
            let observed = received.recv_timeout(std::time::Duration::from_secs(5));
            drop(guard);
            observed
        });
        let report = observed??;
        assert!(
            report.is_none(),
            "busy lifecycle must not report fabricated roles"
        );
        let report = manager
            .try_chainstates_report()?
            .ok_or(TestError::UnexpectedSuccess(
                "lifecycle remained busy after release",
            ))?;
        assert_eq!(report.lifecycle, manager.chainstates_summary()?);
        Ok(())
    }

    // RCV-02
    #[test]
    fn activation_attests_the_snapshot_base_as_assume_valid() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let head = fixture
            .active
            .durable_head
            .load()?
            .ok_or(TestError::Missing("missing activated durable head"))?;
        assert!(matches!(
            head.assumeutxo,
            AssumeUtxoDiskStatus::Validating { .. }
        ));
        assert_eq!(
            fixture.active.durable_head.load_attestation(&head)?,
            bitcoin_rs_storage::ScriptAttestation::AssumeValid,
            "the snapshot base was not script-checked locally"
        );
        Ok(())
    }

    #[test]
    fn activation_failure_publishes_no_checkpoint() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        let loaded = fixture.load()?;
        let wrong_hash = Hash256::default();
        assert_ne!(wrong_hash, fixture.pinned.block_hash);
        let result = manager.activate_pinned_snapshot(loaded.set, wrong_hash, &fixture.pinned);
        assert!(matches!(
            result,
            Err(AssumeUtxoError::SnapshotBlockHashMismatch { .. })
        ));
        assert_no_checkpoint(dir.path());
        fixture.head.fail.store(true, Ordering::Release);
        let loaded = fixture.load()?;
        let result = manager.activate_pinned_snapshot(loaded.set, loaded.tip_hash, &fixture.pinned);
        assert!(result.is_err());
        assert_no_checkpoint(dir.path());
        Ok(())
    }

    fn assert_no_checkpoint(dir: &std::path::Path) {
        let current = dir.join("chainstate-checkpoints").join("CURRENT");
        assert!(
            !current.is_file(),
            "a failed activation must not publish a checkpoint"
        );
    }

    #[test]
    fn lifecycle_progress_omits_missing_and_unauthenticated_counts() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            fixture.active.clone(),
            dir.path().to_path_buf(),
        )?;
        assert_eq!(
            manager
                .try_chainstates_report()?
                .ok_or(TestError::Missing("uncontended lifecycle is busy"))?
                .active_verification_progress,
            None
        );
        assert_eq!(known_progress(None, 0.5), None);
        let tip = fixture
            .active
            .block_tree
            .read()
            .tip()
            .ok_or(TestError::Missing("header tip missing"))?;
        let mut tip = (*tip).clone();
        tip.chain_tx_count = crate::chain::ChainTxCount::UNKNOWN;
        assert_eq!(known_progress(Some(&tip), 0.5), None);
        tip.chain_tx_count = crate::chain::ChainTxCount::established(3);
        assert_eq!(known_progress(Some(&tip), 0.5), Some(0.5));
        Ok(())
    }

    #[test]
    fn activation_offer_only_on_full_success() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let retry = fixture.load()?;
        assert!(matches!(
            manager.activate_pinned_snapshot(retry.set, retry.tip_hash, &fixture.pinned),
            Err(AssumeUtxoError::AlreadyActive)
        ));
        assert_restores_at_snapshot_base(dir.path(), &fixture.pinned)?;
        drop(manager);
        let reopened = fixture.manager(dir.path())?;
        assert!(matches!(
            reopened.status()?,
            AssumeUtxoDiskStatus::Validating { .. }
        ));
        drop(reopened);
        assert_restores_at_snapshot_base(dir.path(), &fixture.pinned)?;
        Ok(())
    }
    fn assert_restores_at_snapshot_base(
        dir: &std::path::Path,
        pinned: &AssumeUtxoData,
    ) -> TestResult {
        std::fs::write(
            dir.join(bitcoin_rs_storage::checkpoint::fs::CURRENT_SCHEMA_FILE),
            bitcoin_rs_storage::checkpoint::fs::current_schema_bytes(),
        )
        .map_err(TestError::Io)?;
        let restored = crate::recovery::restore_snapshot(dir, Network::Regtest, pinned)?;
        assert!(
            matches!(
                restored.resume_source,
                crate::recovery::ResumeSource::Checkpoint
            ),
            "restart must resume from the published checkpoint"
        );
        assert_eq!(
            restored.coin_stats.tx_count, pinned.chain_tx_count,
            "restored coin statistics must equal the pinned transaction count"
        );
        let root = dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT);
        let current: bitcoin_rs_storage::checkpoint::CurrentV1 = sonic_rs::from_slice(
            &std::fs::read(root.join(bitcoin_rs_storage::checkpoint::CURRENT_FILE))?,
        )
        .map_err(TestError::Sonic)?;
        let engine = bitcoin_rs_storage::open_checkpoint_store(
            &root.join(&current.directory).join("chainstate"),
        )?;
        let coins = UtxoSet::new();
        for row in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
            let (_key, value) = row?;
            coins.insert_parsed_record(bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                value.into_boxed_slice(),
            )?);
        }
        assert_eq!(
            coins
                .lock_stable_view()
                .hash_serialized_3_at_height(pinned.height)?,
            pinned.hash_serialized,
            "restored coin statistics must equal the pinned hash"
        );
        Ok(())
    }

    // ARCH-07b
    #[test]
    fn restart_without_checkpoint_at_snapshot_base_refuses() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        drop(manager);
        std::fs::remove_dir_all(dir.path().join("chainstate-checkpoints"))?;
        std::fs::write(
            dir.path()
                .join(bitcoin_rs_storage::checkpoint::fs::CURRENT_SCHEMA_FILE),
            bitcoin_rs_storage::checkpoint::fs::current_schema_bytes(),
        )?;
        let result =
            crate::recovery::restore_snapshot(dir.path(), Network::Regtest, &fixture.pinned);
        assert!(
            matches!(
                result,
                Err(crate::recovery::RecoveryError::SnapshotBaseCheckpointMissing)
            ),
            "a snapshot base without its checkpoint must fail closed"
        );
        Ok(())
    }

    fn engine_coin_records(
        chain: &Chainstate,
    ) -> TestResult<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut records = std::collections::BTreeMap::new();
        for item in chain
            .commit_authority
            .store()
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        {
            let (key, value) = item?;
            records.insert(key.to_vec(), value.to_vec());
        }
        Ok(records)
    }

    fn assert_engine_matches_snapshot(chain: &Chainstate, fixture: &Fixture) -> TestResult {
        let file = read_snapshot_strict_v4(&mut Cursor::new(&fixture.snapshot))?;
        let file_records = file.set.all_records();
        let engine = engine_coin_records(chain)?;
        assert_eq!(
            engine.len(),
            file_records.len(),
            "one engine row per snapshot record"
        );
        for record in &file_records {
            let txid = record.txid().to_le_bytes();
            let stored = engine
                .get(txid.as_slice())
                .ok_or(TestError::Missing("snapshot coin absent from the engine"))?;
            assert_eq!(
                stored.as_slice(),
                record.bytes(),
                "engine row equals file record"
            );
        }
        let mut outputs = 0_u64;
        let mut amount = 0_u64;
        for stored in engine.values() {
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                stored.clone().into_boxed_slice(),
            )
            .map_err(|_| TestError::Missing("bad coin record"))?;
            for output in record.outputs() {
                outputs += 1;
                amount += output.value;
            }
        }
        assert_eq!(
            outputs, fixture.stats.utxo_count,
            "coin count equals manifest"
        );
        assert_eq!(
            amount, fixture.stats.total_amount,
            "total amount equals manifest"
        );
        Ok(())
    }

    #[test]
    fn activation_streams_every_snapshot_coin_into_the_engine() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        let loaded = fixture.load()?;
        let activated = manager.activate_pinned_snapshot_with(
            loaded.set,
            loaded.tip_hash,
            &fixture.pinned,
            |_, _| {},
            || true,
        )?;
        assert_eq!(activated.base_hash, fixture.pinned.block_hash);
        assert_engine_matches_snapshot(&fixture.active, &fixture)
    }

    // SNP-08
    #[test]
    fn historical_facts_hook_receives_facts_on_step_historical() -> TestResult {
        let fixture = Fixture::new()?;
        let dir = tempfile::tempdir()?;
        let manager = fixture.manager(dir.path())?;
        fixture.activate(&manager)?;
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        manager.set_historical_facts_hook(Arc::new(move |facts| {
            if facts.blocks.iter().any(|block| block.height == 0) {
                called_clone.store(true, Ordering::SeqCst);
            }
        }));
        let genesis = BlockImage::from_local(Network::Regtest.genesis_block());
        let outcome = manager.step_historical(&genesis)?;
        assert_eq!(outcome.height, 0);
        assert!(called.load(Ordering::SeqCst));
        manager.clear_historical_facts_hook();
        Ok(())
    }

    fn core_varint(mut value: u64) -> TestResult<Vec<u8>> {
        let mut digits = vec![u8::try_from(value & 0x7f)?];
        value >>= 7;
        while value > 0 {
            value -= 1;
            digits.push(0x80 | u8::try_from(value & 0x7f)?);
            value >>= 7;
        }
        digits.reverse();
        Ok(digits)
    }

    fn core_snapshot_with_coin_code(pinned: &AssumeUtxoData, code: u64) -> TestResult<Vec<u8>> {
        let mut bytes = b"utxo\xff".to_vec();
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&Network::Regtest.magic());
        bytes.extend_from_slice(&pinned.block_hash.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.push(0x01);
        bytes.push(0x00);
        bytes.extend(core_varint(code)?);
        bytes.push(0x00);
        bytes.push(0x07);
        bytes.push(0x51);
        Ok(bytes)
    }

    // SNP-07
    #[test]
    fn core_snapshot_rejects_coin_height_beyond_base_before_activation() -> TestResult {
        let pinned = Network::Regtest
            .assume_utxo_for_height(110)
            .ok_or(TestError::Missing("missing pin"))?;
        let active = chainstate();
        let mut blocks = vec![Network::Regtest.genesis_block()];
        for height in 1..=2 {
            blocks.push(crate::chain::regtest_fixture::mined_regtest_child_at(
                blocks
                    .last()
                    .ok_or(TestError::Missing("missing predecessor"))?
                    .block_hash(),
                height,
            )?);
        }
        for block in &blocks {
            active
                .lock_transition()?
                .into_transition()
                .connect(&BlockImage::from_local((*block).clone()))?;
        }
        assert!(active.has_durable_head()?);
        let coins_before = engine_coin_set(&active)?
            .lock_stable_view()
            .hash_serialized_3()?;
        let dir = tempfile::tempdir()?;
        let manager = AssumeUtxoManager::open(
            Network::Regtest,
            Arc::clone(&active),
            dir.path().to_path_buf(),
        )?;
        let alias_of_base =
            core_snapshot_with_coin_code(pinned, u64::from(0x8000_0000_u32 | 110) << 1)?;
        let Err(error) = manager.activate_core_snapshot(
            &mut Cursor::new(alias_of_base),
            None,
            |_, _| {},
            || true,
        ) else {
            return Err(TestError::UnexpectedSuccess(
                "a coin height at or above 2^31 was activated",
            ));
        };
        assert!(matches!(
            error,
            AssumeUtxoError::Codec(
                bitcoin_rs_storage::utxo::core_snapshot::SnapshotError::VarIntOverflow
            )
        ));
        let past_base = core_snapshot_with_coin_code(pinned, 111 << 1)?;
        let Err(error) =
            manager.activate_core_snapshot(&mut Cursor::new(past_base), None, |_, _| {}, || true)
        else {
            return Err(TestError::UnexpectedSuccess(
                "a coin height above the base was activated",
            ));
        };
        assert!(matches!(
            error,
            AssumeUtxoError::Codec(
                bitcoin_rs_storage::utxo::core_snapshot::SnapshotError::InvalidHeight {
                    height: 111,
                    base_height: 110,
                }
            )
        ));
        assert_eq!(manager.status()?, AssumeUtxoDiskStatus::Uninitialized);
        assert_no_checkpoint(dir.path());
        assert_eq!(
            engine_coin_set(&active)?
                .lock_stable_view()
                .hash_serialized_3()?,
            coins_before
        );
        Ok(())
    }

    #[test]
    fn restored_coin_stats_scan_preserves_the_corrupt_row_utxo_error() -> TestResult {
        let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        seed_genesis(&chain)?;
        seed_durable_head(
            &chain,
            DurableHead {
                assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 0,
                tip: Hash256::from(Network::Regtest.genesis_block().block_hash()),
                chain_tx_count: 1,
                body_extent: None,
                undo_extent: None,
            },
        )?;

        let txid = Hash256::from_le_bytes(&[0x5A; 32]);
        let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            txid,
            &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                vout: 0,
                value: 1_000,
                script_pubkey: vec![0x51],
                coinbase: false,
                height: 0,
            }],
        )?;
        let mut row = record.bytes().to_vec();
        row.truncate(20);
        chain.commit_authority.store().put(
            bitcoin_rs_storage::ColumnFamily::Coins,
            bitcoin_rs_storage::CoinKey(txid.to_le_bytes()).as_bytes(),
            &row,
        )?;

        let error = crate::recovery::settle_restored_coin_stats(&chain, None)
            .err()
            .ok_or(TestError::UnexpectedSuccess(
                "a malformed coin row must fail the restored coin statistics scan",
            ))?;
        let crate::recovery::RecoveryError::Utxo(source) = error else {
            return Err(TestError::Missing(
                "the scan failure must keep its UtxoError cause",
            ));
        };
        assert!(
            matches!(source, bitcoin_rs_storage::utxo::UtxoError::CorruptRecord),
            "the preserved cause must name the corrupt row, got {source:?}"
        );
        Ok(())
    }
}
