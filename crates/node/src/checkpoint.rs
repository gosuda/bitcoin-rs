pub(crate) mod headers;

use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::{Hash256, Network};
use bitcoin_rs_utxo::stats::{
    CoinStats, CoinStatsAccumulator, CoinStatsListener, coin_stats::COIN_STATS_ENCODED_LEN,
};
use bitcoin_rs_utxo::{UtxoSet, read_snapshot_strict_v4_observed, write_snapshot_observed};
use cap_std::fs::{Dir, File};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(test)]
use crate::checkpoint_fs::open_data_dir;
use crate::checkpoint_fs::{
    CheckpointRoot, create_file, open_file, read_file, remove_known_dir, sync_dir,
};

const CHECKPOINT_ROOT: &str = "chainstate-checkpoints";
const CURRENT_FILE: &str = "CURRENT";
const MANIFEST_FILE: &str = "manifest-v1.json";
const HEADERS_FILE: &str = "headers-v1.dat";
const UTXO_FILE: &str = "utxo-v4.dat";
const COINSTATS_FILE: &str = "coinstats-v1.dat";
const CURRENT_FORMAT: &str = "bitcoin-rs-chainstate-current";
const MANIFEST_FORMAT: &str = "bitcoin-rs-chainstate-checkpoint";
const HEADER_CODEC: &str = "bitcoin-rs-canonical-headers";
const UTXO_CODEC: &str = "bitcoin-rs-utxo-spendable-v1";
// This identifier is written into `manifest-v1.json` and matched on load. It
// is an on-disk value; changing it requires a schema epoch bump and resync.
const COINSTATS_CODEC: &str = "bitcoin-rs-coinstats-v1";
const CURRENT_VERSION: u32 = 1;
const MANIFEST_VERSION: u32 = 1;
const UTXO_VERSION: u32 = 4;
const COINSTATS_VERSION: u32 = 1;
const COINSTATS_MAGIC: [u8; 8] = *b"BRSSTAT\0";
const COINSTATS_PAYLOAD_LEN: u32 = 804;
const COINSTATS_ARTIFACT_LEN: u64 = 820;
const MAX_CHECKPOINT_PAYLOAD_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
const MAX_CHECKPOINT_METADATA_BYTES: u64 = 1024 * 1024;

const CHECKPOINT_WRITE_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentV1 {
    format: String,
    version: u32,
    generation: u64,
    directory: String,
    manifest_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointTipV1 {
    height: u32,
    hash: String,
    chainwork: String,
    /// Cumulative transaction count of the chain through this tip.
    ///
    /// Only meaningful for the applied tip; the best-header tip records `0`,
    /// since headers carry no transactions.
    chain_tx_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadersArtifactV1 {
    file: String,
    codec: String,
    version: u32,
    bytes: u64,
    sha256: String,
    header_count: u64,
    best_chain_sha256: String,
    applied_chain_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UtxoArtifactV1 {
    file: String,
    codec: String,
    version: u32,
    bytes: u64,
    sha256: String,
    record_count: u64,
    output_count: u64,
    muhash_trailer_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoinStatsArtifactV1 {
    file: String,
    codec: String,
    version: u32,
    bytes: u64,
    sha256: String,
    height: u32,
    total_amount: u64,
    bogo_size: u64,
    tx_count: u64,
    utxo_count: u64,
    muhash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointManifestV1 {
    format: String,
    version: u32,
    generation: u64,
    network: String,
    network_magic: String,
    genesis_hash: String,
    applied_tip: CheckpointTipV1,
    best_header_tip: CheckpointTipV1,
    headers: HeadersArtifactV1,
    utxo: UtxoArtifactV1,
    coinstats: CoinStatsArtifactV1,
}

pub(crate) enum CheckpointLoad {
    Cold,
    Complete(Box<RestoredChainstate>),
}

pub(crate) struct RestoredChainstate {
    /// Authenticated immutable checkpoint generation from `CURRENT`/manifest.
    pub(crate) generation: u64,
    pub(crate) tree: BlockTree,
    pub(crate) utxo: UtxoSet,
    pub(crate) coin_stats: CoinStats,
    pub(crate) applied_tip: TipSnapshot,
    /// Cumulative transaction count through `applied_tip`, or `0` when the
    /// manifest predates the field.
    pub(crate) chain_tx_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointWrite {
    SkippedNoAppliedTip,
    Published { generation: u64 },
}

#[derive(Debug, Error)]
pub(crate) enum CheckpointCorruption {
    #[error(
        "corrupt current-schema checkpoint: {reason}; remove or replace the datadir and restart to perform a full resync"
    )]
    Invalid { reason: String },
}

#[derive(Debug, Error)]
pub(crate) enum CheckpointLoadError {
    #[error(transparent)]
    Corrupt(#[from] CheckpointCorruption),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub(crate) enum CheckpointError {
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("header checkpoint failed: {0}")]
    Header(#[from] headers::HeaderCheckpointError),
    #[error("checkpoint chain state failed: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error("UTXO checkpoint failed: {0}")]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error("CoinStats checkpoint decode failed: {0}")]
    CoinStats(#[from] bitcoin_rs_utxo::stats::CoinStatsDecodeError),
    #[error("checkpoint JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checkpoint invariant failed: {0}")]
    Invalid(String),
    #[error("checkpoint block-body durability failed: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error("checkpoint refused while disconnect of block {hash} at height {height} is in flight")]
    DisconnectInFlight { hash: Hash256, height: u32 },
    /// The replacement checkpoint's `CURRENT` is already durable; retiring the
    /// sticky full-revalidation marker failed. Retryable I/O owned by the
    /// checkpoint worker, not checkpoint corruption.
    #[error("failed to retire full-revalidation marker: {0}")]
    FullRevalidationMarker(std::io::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointFailpoint {
    HeadersWrite,
    HeadersSync,
    UtxoWrite,
    UtxoSync,
    CoinStatsWrite,
    CoinStatsSync,
    ManifestWrite,
    ManifestSync,
    StageSync,
    GenerationRename,
    GenerationRootSync,
    CurrentTempWrite,
    CurrentTempSync,
    CurrentRename,
    CurrentRootSync,
}

struct GenerationPaths {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    staging: String,
    final_dir: String,
    current_temp: String,
    directory: String,
}

struct HashingWriter<'a> {
    file: BufWriter<&'a mut File>,
    hasher: Sha256,
    bytes: u64,
    fail: bool,
}

impl<'a> HashingWriter<'a> {
    fn new(
        file: &'a mut File,
        configured: Option<CheckpointFailpoint>,
        boundary: CheckpointFailpoint,
    ) -> Self {
        Self {
            file: BufWriter::with_capacity(CHECKPOINT_WRITE_BUFFER_SIZE, file),
            hasher: Sha256::new(),
            bytes: 0,
            fail: configured == Some(boundary),
        }
    }

    fn finish(mut self) -> std::io::Result<(u64, [u8; 32])> {
        self.file.flush()?;
        Ok((self.bytes, self.hasher.finalize().into()))
    }
}

impl Write for HashingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail {
            return Err(std::io::Error::from_raw_os_error(28));
        }
        let written = self.file.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(written).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("checkpoint byte count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

pub(crate) fn load_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let root = match CheckpointRoot::open_existing(data_dir, CHECKPOINT_ROOT) {
        Ok(Some(root)) => root,
        Ok(None) => return Ok(CheckpointLoad::Cold),
        Err(error) => return Err(classify_open_error("open checkpoint root", error)),
    };

    let current = match read_current(&root) {
        Ok(Some(current)) => current,
        // CURRENT is the publication commit point. A root without it can be
        // leftover from a first publication that crashed before the pointer
        // became visible; none of that generation is committed state.
        Ok(None) => return Ok(CheckpointLoad::Cold),
        Err(error) => return Err(classify_checkpoint_error(error)),
    };
    let generation_dir = root.open_dir(&current.directory).map_err(|error| {
        classify_open_error(
            &format!("open checkpoint generation {}", current.directory),
            error,
        )
    })?;
    let manifest = match read_manifest(&generation_dir, &current, config) {
        Ok(manifest) => manifest,
        Err(error) => return Err(classify_checkpoint_error(error)),
    };
    if manifest.headers.version != headers::HEADER_VERSION {
        return Err(corrupt_checkpoint(format!(
            "headers checkpoint version {} is not current",
            manifest.headers.version
        )));
    }
    if manifest.headers.codec != HEADER_CODEC {
        return Err(corrupt_checkpoint(format!(
            "unexpected headers checkpoint codec {}",
            manifest.headers.codec
        )));
    }

    let restored_headers = match load_headers(&generation_dir, config, &manifest) {
        Ok(headers) => headers,
        Err(CheckpointError::Header(headers::HeaderCheckpointError::UnsupportedVersion {
            actual,
        })) => {
            return Err(corrupt_checkpoint(format!(
                "headers checkpoint version {actual} is not current"
            )));
        }
        Err(error) => return Err(classify_checkpoint_error(error)),
    };
    if manifest.utxo.version != UTXO_VERSION {
        return Err(corrupt_checkpoint(format!(
            "UTXO checkpoint version {} is not current",
            manifest.utxo.version
        )));
    }
    if manifest.coinstats.version != COINSTATS_VERSION {
        return Err(corrupt_checkpoint(format!(
            "CoinStats checkpoint version {} is not current",
            manifest.coinstats.version
        )));
    }
    if manifest.utxo.codec != UTXO_CODEC || manifest.coinstats.codec != COINSTATS_CODEC {
        return Err(corrupt_checkpoint(format!(
            "unexpected payload codecs UTXO={} CoinStats={}",
            manifest.utxo.codec, manifest.coinstats.codec
        )));
    }
    match load_payloads(&generation_dir, &manifest, restored_headers) {
        Ok(restored) => Ok(CheckpointLoad::Complete(Box::new(restored))),
        Err(error) => Err(classify_checkpoint_error(error)),
    }
}

fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
    match error {
        CheckpointError::Io(error)
        | CheckpointError::FullRevalidationMarker(error)
        | CheckpointError::Utxo(bitcoin_rs_utxo::UtxoError::Io(error))
        | CheckpointError::Storage(bitcoin_rs_storage::StorageError::Io(error)) => {
            classify_checkpoint_io(error)
        }
        error => corrupt_checkpoint(error.to_string()),
    }
}

fn classify_open_error(operation: &str, error: std::io::Error) -> CheckpointLoadError {
    if is_checkpoint_corruption(&error) {
        return corrupt_checkpoint(format!("{operation} failed: {error}"));
    }
    CheckpointLoadError::Io(error)
}

fn checkpoint_file_error(name: &str, error: std::io::Error) -> CheckpointError {
    if is_checkpoint_corruption(&error) {
        return CheckpointError::Invalid(format!("checkpoint file {name:?} failed: {error}"));
    }
    CheckpointError::Io(error)
}

fn classify_checkpoint_io(error: std::io::Error) -> CheckpointLoadError {
    if is_checkpoint_corruption(&error) {
        return corrupt_checkpoint(error.to_string());
    }
    CheckpointLoadError::Io(error)
}

fn corrupt_checkpoint(reason: impl Into<String>) -> CheckpointLoadError {
    CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid {
        reason: reason.into(),
    })
}

fn is_checkpoint_corruption(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::InvalidData
            | std::io::ErrorKind::NotADirectory
            | std::io::ErrorKind::IsADirectory
            | std::io::ErrorKind::UnexpectedEof
    )
}
#[cfg(test)]
fn load_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let data_dir = match open_data_dir(data_dir) {
        Ok(data_dir) => data_dir,
        Err(_) => return Ok(CheckpointLoad::Cold),
    };
    load_checkpoint_from_dir(&data_dir, config)
}

pub(crate) fn write_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    chain_tx_count: u64,
) -> Result<CheckpointWrite, CheckpointError> {
    write_checkpoint_inner(
        data_dir,
        config,
        block_tree,
        utxo,
        coin_stats,
        applied_tip,
        chain_tx_count,
        test_failpoint(),
    )
}
#[cfg(test)]
fn write_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
) -> Result<CheckpointWrite, CheckpointError> {
    let data_dir = open_data_dir(data_dir)?;
    write_checkpoint_from_dir(
        &data_dir,
        config,
        block_tree,
        utxo,
        coin_stats,
        applied_tip,
        0,
    )
}

fn checkpoint_best_tip_id(
    tree: &BlockTree,
    applied_tip: &TipSnapshot,
) -> Result<NodeId, CheckpointError> {
    let applied_id = tree.lookup(applied_tip.hash).ok_or_else(|| {
        CheckpointError::Invalid("applied tip disappeared during checkpoint".to_owned())
    })?;
    let best_tip_id = tree.tip_id().ok_or_else(|| {
        CheckpointError::Invalid("applied tip exists without a best header tip".to_owned())
    })?;
    if tree.node_at_height_from(best_tip_id, applied_tip.height) == Some(applied_id) {
        return Ok(best_tip_id);
    }
    Ok(applied_id)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_checkpoint_inner(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    chain_tx_count: u64,
    #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<CheckpointFailpoint>,
) -> Result<CheckpointWrite, CheckpointError> {
    let Some(applied_tip) = applied_tip else {
        return Ok(CheckpointWrite::SkippedNoAppliedTip);
    };
    let root = CheckpointRoot::open_or_create(data_dir, CHECKPOINT_ROOT)?;
    let current_generation = match read_current(&root) {
        Ok(Some(current)) => current.generation,
        Ok(None) => 0,
        Err(error) => return Err(error),
    };
    let (generation, paths, staging) = allocate_generation(&root, current_generation)?;

    let (headers_write, headers_bytes, headers_sha256) = {
        let tree = block_tree.read();
        let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
        let mut file = create_file(&staging, HEADERS_FILE)?;
        let mut writer =
            HashingWriter::new(&mut file, failpoint, CheckpointFailpoint::HeadersWrite);
        let applied_point = headers::HeaderCheckpointPoint {
            height: applied_tip.height,
            hash: applied_tip.hash,
        };
        let metadata = if tree.tip_id() == Some(best_tip_id) {
            headers::write_headers(&mut writer, &tree, config, best_tip_id, applied_point)?
        } else {
            headers::write_selected_headers(&mut writer, &tree, config, best_tip_id, applied_point)?
        };
        let (bytes, digest) = writer.finish()?;
        sync_file(&file, failpoint, CheckpointFailpoint::HeadersSync)?;
        (metadata, bytes, digest)
    };

    let mut utxo_file = create_file(&staging, UTXO_FILE)?;
    let mut utxo_writer =
        HashingWriter::new(&mut utxo_file, failpoint, CheckpointFailpoint::UtxoWrite);
    let (trailer, accumulator) = write_snapshot_observed(
        utxo,
        &applied_tip.hash,
        applied_tip.height,
        &mut utxo_writer,
        CoinStatsAccumulator::with_parallel_muhash(applied_tip.height),
    )?;
    let (utxo_bytes, utxo_sha256) = utxo_writer.finish()?;
    sync_file(&utxo_file, failpoint, CheckpointFailpoint::UtxoSync)?;

    let listener_stats = coin_stats.snapshot();
    if listener_stats.height != applied_tip.height {
        return Err(CheckpointError::Invalid(format!(
            "CoinStats height {} does not match applied height {}",
            listener_stats.height, applied_tip.height
        )));
    }
    let mut fused_stats = accumulator.into_stats();
    fused_stats.tx_count = listener_stats.tx_count;
    let record_count = utxo.record_count();
    if trailer == [0_u8; 384] {
        return Err(CheckpointError::Invalid(
            "scanned UTXO snapshot has a zero MuHash trailer".to_owned(),
        ));
    }
    let persisted_stats = fused_stats;

    let mut coinstats_file = create_file(&staging, COINSTATS_FILE)?;
    let mut coinstats_writer = HashingWriter::new(
        &mut coinstats_file,
        failpoint,
        CheckpointFailpoint::CoinStatsWrite,
    );
    coinstats_writer.write_all(&COINSTATS_MAGIC)?;
    coinstats_writer.write_all(&COINSTATS_VERSION.to_le_bytes())?;
    coinstats_writer.write_all(&COINSTATS_PAYLOAD_LEN.to_le_bytes())?;
    coinstats_writer.write_all(&persisted_stats.to_bytes())?;
    let (coinstats_bytes, coinstats_sha256) = coinstats_writer.finish()?;
    sync_file(
        &coinstats_file,
        failpoint,
        CheckpointFailpoint::CoinStatsSync,
    )?;

    let tree = block_tree.read();
    let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
    let best = tree.node(best_tip_id)?;
    if best.hash != headers_write.metadata.best.hash
        || best.height != headers_write.metadata.best.height
        || best.chainwork != headers_write.metadata.best.chainwork
    {
        return Err(CheckpointError::Invalid(
            "best header tip changed during checkpoint".to_owned(),
        ));
    }
    drop(tree);

    let record_count = u64::try_from(record_count)
        .map_err(|_| CheckpointError::Invalid("UTXO record count does not fit u64".to_owned()))?;
    let manifest = CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        version: MANIFEST_VERSION,
        generation,
        network: network_name(config.network).to_owned(),
        network_magic: hex_encode(&config.network.magic()),
        genesis_hash: config.genesis.to_string_be(),
        applied_tip: manifest_tip(headers_write.metadata.applied, chain_tx_count),
        best_header_tip: manifest_tip(headers_write.metadata.best, 0),
        headers: HeadersArtifactV1 {
            file: HEADERS_FILE.to_owned(),
            codec: HEADER_CODEC.to_owned(),
            version: headers::HEADER_VERSION,
            bytes: headers_bytes,
            sha256: hex_encode(&headers_sha256),
            header_count: headers_write.metadata.header_count,
            best_chain_sha256: hex_encode(&headers_write.metadata.best_chain_commitment),
            applied_chain_sha256: hex_encode(&headers_write.metadata.applied_prefix_commitment),
        },
        utxo: UtxoArtifactV1 {
            file: UTXO_FILE.to_owned(),
            codec: UTXO_CODEC.to_owned(),
            version: UTXO_VERSION,
            bytes: utxo_bytes,
            sha256: hex_encode(&utxo_sha256),
            record_count,
            output_count: persisted_stats.utxo_count,
            muhash_trailer_sha256: hex_encode(&Sha256::digest(trailer)),
        },
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_owned(),
            codec: COINSTATS_CODEC.to_owned(),
            version: COINSTATS_VERSION,
            bytes: coinstats_bytes,
            sha256: hex_encode(&coinstats_sha256),
            height: persisted_stats.height,
            total_amount: persisted_stats.total_amount,
            bogo_size: persisted_stats.bogo_size,
            tx_count: persisted_stats.tx_count,
            utxo_count: persisted_stats.utxo_count,
            muhash: hex_encode(&persisted_stats.muhash.finalize()),
        },
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let mut manifest_file = create_file(&staging, MANIFEST_FILE)?;
    write_file(
        &mut manifest_file,
        &manifest_bytes,
        failpoint,
        CheckpointFailpoint::ManifestWrite,
    )?;
    manifest_file.flush()?;
    sync_file(&manifest_file, failpoint, CheckpointFailpoint::ManifestSync)?;

    sync_checkpoint_dir(&staging, failpoint, CheckpointFailpoint::StageSync)?;
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    rename_generation(
        &root,
        &paths.staging,
        &paths.final_dir,
        failpoint,
        CheckpointFailpoint::GenerationRename,
    )?;
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    )))]
    injected_io(failpoint, CheckpointFailpoint::GenerationRename)?;
    // On portable targets `allocate_generation` atomically reserved and this
    // function wrote the final generation directory directly. CURRENT is the
    // sole visibility commit point.
    sync_root(&root, failpoint, CheckpointFailpoint::GenerationRootSync)?;

    let current = CurrentV1 {
        format: CURRENT_FORMAT.to_owned(),
        version: CURRENT_VERSION,
        generation,
        directory: paths.directory.clone(),
        manifest_sha256: hex_encode(&Sha256::digest(&manifest_bytes)),
    };
    let current_bytes = serde_json::to_vec(&current)?;
    let mut current_file = root.create_file(&paths.current_temp)?;
    write_file(
        &mut current_file,
        &current_bytes,
        failpoint,
        CheckpointFailpoint::CurrentTempWrite,
    )?;
    current_file.flush()?;
    sync_file(
        &current_file,
        failpoint,
        CheckpointFailpoint::CurrentTempSync,
    )?;
    rename_current(
        &root,
        &paths.current_temp,
        failpoint,
        CheckpointFailpoint::CurrentRename,
    )?;
    sync_root(&root, failpoint, CheckpointFailpoint::CurrentRootSync)?;

    cleanup_after_publication(&root, &paths.directory);
    Ok(CheckpointWrite::Published { generation })
}

#[cfg(test)]
pub(crate) fn write_checkpoint_with_failpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    failpoint: CheckpointFailpoint,
) -> Result<CheckpointWrite, CheckpointError> {
    let data_dir = open_data_dir(data_dir)?;
    write_checkpoint_inner(
        &data_dir,
        config,
        block_tree,
        utxo,
        coin_stats,
        applied_tip,
        0,
        Some(failpoint),
    )
}

#[cfg(test)]
std::thread_local! {
    static NEXT_CHECKPOINT_FAILPOINT: std::cell::Cell<Option<CheckpointFailpoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn inject_next_checkpoint_failpoint(failpoint: CheckpointFailpoint) {
    NEXT_CHECKPOINT_FAILPOINT.with(|slot| slot.set(Some(failpoint)));
}

#[cfg(test)]
fn test_failpoint() -> Option<CheckpointFailpoint> {
    NEXT_CHECKPOINT_FAILPOINT.with(std::cell::Cell::take)
}

#[cfg(not(test))]
const fn test_failpoint() -> Option<CheckpointFailpoint> {
    None
}

fn injected_io(
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> std::io::Result<()> {
    if configured == Some(boundary) {
        return Err(std::io::Error::from_raw_os_error(28));
    }
    Ok(())
}

fn write_file(
    file: &mut File,
    bytes: &[u8],
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    file.write_all(bytes)?;
    Ok(())
}

fn sync_file(
    file: &File,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    file.sync_all()?;
    Ok(())
}

fn sync_checkpoint_dir(
    dir: &Dir,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    sync_dir(dir)?;
    Ok(())
}

fn sync_root(
    root: &CheckpointRoot,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    root.sync()?;
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn rename_generation(
    root: &CheckpointRoot,
    from: &str,
    to: &str,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    root.rename_noreplace(from, to)?;
    Ok(())
}

fn rename_current(
    root: &CheckpointRoot,
    from: &str,
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> Result<(), CheckpointError> {
    injected_io(configured, boundary)?;
    root.rename(from, CURRENT_FILE)?;
    Ok(())
}

fn read_current(root: &CheckpointRoot) -> Result<Option<CurrentV1>, CheckpointError> {
    let bytes = match read_file(root.dir(), CURRENT_FILE, MAX_CHECKPOINT_METADATA_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(checkpoint_file_error(CURRENT_FILE, error)),
    };
    let current: CurrentV1 = serde_json::from_slice(&bytes).map_err(CheckpointError::Json)?;
    if current.version != CURRENT_VERSION {
        return Err(CheckpointError::Invalid(format!(
            "CURRENT checkpoint version {} is not current",
            current.version
        )));
    }
    if current.format != CURRENT_FORMAT {
        return Err(CheckpointError::Invalid(format!(
            "unexpected CURRENT format {}",
            current.format
        )));
    }
    let expected_directory = generation_name(current.generation);
    if current.directory != expected_directory || !valid_generation_name(&current.directory) {
        return Err(CheckpointError::Invalid(
            "CURRENT generation directory does not match its generation".to_owned(),
        ));
    }
    decode_hex::<32>(&current.manifest_sha256)?;
    Ok(Some(current))
}

fn read_manifest(
    generation_dir: &Dir,
    current: &CurrentV1,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointManifestV1, CheckpointError> {
    let bytes = read_file(generation_dir, MANIFEST_FILE, MAX_CHECKPOINT_METADATA_BYTES)
        .map_err(|error| checkpoint_file_error(MANIFEST_FILE, error))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != decode_hex::<32>(&current.manifest_sha256)? {
        return Err(CheckpointError::Invalid(
            "manifest SHA256 does not match CURRENT".to_owned(),
        ));
    }
    let manifest: CheckpointManifestV1 =
        serde_json::from_slice(&bytes).map_err(CheckpointError::Json)?;
    if manifest.version != MANIFEST_VERSION {
        return Err(CheckpointError::Invalid(format!(
            "manifest version {} is not current",
            manifest.version
        )));
    }
    if manifest.format != MANIFEST_FORMAT {
        return Err(CheckpointError::Invalid(format!(
            "unexpected manifest format {}",
            manifest.format
        )));
    }
    if manifest.generation != current.generation {
        return Err(CheckpointError::Invalid(
            "manifest generation does not match CURRENT".to_owned(),
        ));
    }
    let expected_network = network_name(config.network);
    if manifest.network != expected_network
        || manifest.network_magic != hex_encode(&config.network.magic())
        || manifest.genesis_hash != config.genesis.to_string_be()
    {
        return Err(CheckpointError::Invalid(
            "checkpoint network, magic, or genesis does not match configuration".to_owned(),
        ));
    }
    Ok(manifest)
}

fn load_headers(
    generation_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    manifest: &CheckpointManifestV1,
) -> Result<headers::RestoredHeaders, CheckpointError> {
    require_filename(&manifest.headers.file, HEADERS_FILE)?;
    let mut file = verify_artifact(
        generation_dir,
        HEADERS_FILE,
        manifest.headers.bytes,
        &manifest.headers.sha256,
    )?;
    let expected = headers::HeaderCheckpointMetadata {
        header_count: manifest.headers.header_count,
        best: parse_tip(&manifest.best_header_tip)?,
        applied: parse_tip(&manifest.applied_tip)?,
        best_chain_commitment: decode_hex::<32>(&manifest.headers.best_chain_sha256)?,
        applied_prefix_commitment: decode_hex::<32>(&manifest.headers.applied_chain_sha256)?,
    };
    headers::read_headers(&mut file, config, expected).map_err(CheckpointError::Header)
}

fn load_payloads(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    mut headers: headers::RestoredHeaders,
) -> Result<RestoredChainstate, CheckpointError> {
    let chain_tx_count = manifest.applied_tip.chain_tx_count;
    let (utxo, coin_stats) = load_payloads_inner(generation_dir, manifest, &headers)?;
    headers
        .tree
        .restore_chain_tx_count(headers.applied_tip_id, chain_tx_count)?;
    let applied_node = headers
        .tree
        .node(headers.applied_tip_id)
        .map_err(|error| CheckpointError::Header(error.into()))?;
    let applied_tip = TipSnapshot {
        tip_id: headers.applied_tip_id,
        height: applied_node.height,
        chainwork: applied_node.chainwork,
        hash: applied_node.hash,
    };
    Ok(RestoredChainstate {
        generation: manifest.generation,
        tree: headers.tree,
        utxo,
        coin_stats,
        applied_tip,
        chain_tx_count,
    })
}

fn load_payloads_inner(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    headers: &headers::RestoredHeaders,
) -> Result<(UtxoSet, CoinStats), CheckpointError> {
    require_filename(&manifest.utxo.file, UTXO_FILE)?;
    require_filename(&manifest.coinstats.file, COINSTATS_FILE)?;
    if manifest.coinstats.bytes != COINSTATS_ARTIFACT_LEN {
        return Err(CheckpointError::Invalid(
            "CoinStats artifact is not exactly 820 bytes".to_owned(),
        ));
    }
    let utxo_file = verify_artifact(
        generation_dir,
        UTXO_FILE,
        manifest.utxo.bytes,
        &manifest.utxo.sha256,
    )?;
    let mut coinstats_file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )?;
    let expected_applied = parse_tip(&manifest.applied_tip)?;

    let (snapshot, mut derived) =
        read_checkpoint_snapshot(utxo_file, manifest.utxo.bytes, expected_applied.height)?;
    let snapshot_tip = (snapshot.height, snapshot.tip_hash);
    let expected_tip = (expected_applied.height, expected_applied.hash);
    if snapshot_tip != expected_tip {
        return Err(CheckpointError::Invalid(
            "UTXO tip does not match manifest applied tip".to_owned(),
        ));
    }
    let record_count = u64::try_from(snapshot.set.record_count()).map_err(|_| {
        CheckpointError::Invalid("loaded UTXO record count does not fit u64".to_owned())
    })?;
    if record_count != manifest.utxo.record_count {
        return Err(CheckpointError::Invalid(
            "UTXO record count does not match manifest".to_owned(),
        ));
    }
    let trailer_digest: [u8; 32] = Sha256::digest(snapshot.muhash_trailer).into();
    if trailer_digest != decode_hex::<32>(&manifest.utxo.muhash_trailer_sha256)? {
        return Err(CheckpointError::Invalid(
            "UTXO MuHash trailer digest does not match manifest".to_owned(),
        ));
    }

    let mut coinstats_bytes = Vec::with_capacity(COIN_STATS_ENCODED_LEN + 16);
    coinstats_file
        .read_to_end(&mut coinstats_bytes)
        .map_err(|error| checkpoint_file_error(COINSTATS_FILE, error))?;
    let coin_stats = decode_coinstats_artifact(&coinstats_bytes)?;
    validate_coinstats_manifest(&coin_stats, &manifest.coinstats)?;
    // Transaction count is chain metadata and cannot be derived from live coins.
    derived.tx_count = coin_stats.tx_count;
    if derived != coin_stats {
        return Err(CheckpointError::Invalid(
            "CoinStats does not match loaded UTXO traversal".to_owned(),
        ));
    }
    if coin_stats.utxo_count != manifest.utxo.output_count {
        return Err(CheckpointError::Invalid(
            "UTXO output count does not match manifest".to_owned(),
        ));
    }
    if snapshot.muhash_trailer != coin_stats.muhash.finalize() {
        return Err(CheckpointError::Invalid(
            "UTXO trailer does not match restored CoinStats".to_owned(),
        ));
    }
    let applied = headers.tree.node(headers.applied_tip_id)?;
    let applied_tip = (applied.height, applied.hash);
    if applied_tip != snapshot_tip {
        return Err(CheckpointError::Invalid(
            "restored header and UTXO applied tips differ".to_owned(),
        ));
    }
    Ok((snapshot.set, coin_stats))
}

fn read_checkpoint_snapshot(
    utxo_file: File,
    encoded_len: u64,
    height: u32,
) -> Result<(bitcoin_rs_utxo::SnapshotLoad, CoinStats), CheckpointError> {
    let mut limited = BufReader::new(utxo_file).take(
        encoded_len
            .checked_add(1)
            .ok_or_else(|| CheckpointError::Invalid("UTXO byte length overflow".to_owned()))?,
    );
    let (snapshot, accumulator) = read_snapshot_strict_v4_observed(
        &mut limited,
        CoinStatsAccumulator::with_parallel_muhash(height),
    )?;
    Ok((snapshot, accumulator.into_stats()))
}

fn validate_coinstats_manifest(
    stats: &CoinStats,
    expected: &CoinStatsArtifactV1,
) -> Result<(), CheckpointError> {
    if stats.height != expected.height
        || stats.total_amount != expected.total_amount
        || stats.bogo_size != expected.bogo_size
        || stats.tx_count != expected.tx_count
        || stats.utxo_count != expected.utxo_count
        || hex_encode(&stats.muhash.finalize()) != expected.muhash
    {
        return Err(CheckpointError::Invalid(
            "CoinStats fields do not match manifest".to_owned(),
        ));
    }
    Ok(())
}

fn allocate_generation(
    root: &CheckpointRoot,
    current_generation: u64,
) -> Result<(u64, GenerationPaths, Dir), CheckpointError> {
    let mut generation = current_generation.checked_add(1).ok_or_else(|| {
        CheckpointError::Invalid("checkpoint generation exhausted u64".to_owned())
    })?;
    loop {
        let paths = generation_paths(generation);
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        if root.entry_exists(&paths.final_dir)? || root.entry_exists(&paths.current_temp)? {
            generation = generation.checked_add(1).ok_or_else(|| {
                CheckpointError::Invalid("checkpoint generation exhausted u64".to_owned())
            })?;
            continue;
        }
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        let name = &paths.staging;
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        )))]
        let name = &paths.final_dir;
        match root.create_dir(name) {
            Ok(dir) => return Ok((generation, paths, dir)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                generation = generation.checked_add(1).ok_or_else(|| {
                    CheckpointError::Invalid("checkpoint generation exhausted u64".to_owned())
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn generation_paths(generation: u64) -> GenerationPaths {
    let directory = generation_name(generation);
    GenerationPaths {
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        staging: format!(".{directory}.tmp"),
        final_dir: directory.clone(),
        current_temp: format!(".CURRENT-{generation:020}.tmp"),
        directory,
    }
}

fn generation_name(generation: u64) -> String {
    format!("gen-{generation:020}")
}

fn valid_generation_name(name: &str) -> bool {
    name.len() == 24
        && name.starts_with("gen-")
        && name[4..].bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_staging_name(name: &str) -> bool {
    name.strip_prefix(".gen-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|digits| {
            digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn valid_current_temp_name(name: &str) -> bool {
    name.strip_prefix(".CURRENT-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|digits| {
            digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn open_regular_file(dir: &Dir, name: &str, expected_len: u64) -> Result<File, CheckpointError> {
    let file = open_file(dir, name).map_err(|error| checkpoint_file_error(name, error))?;
    let actual_len = file
        .metadata()
        .map_err(|error| checkpoint_file_error(name, error))?
        .len();
    if actual_len != expected_len {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact {name:?} has {actual_len} bytes, expected {expected_len}"
        )));
    }
    Ok(file)
}

fn verify_artifact(
    dir: &Dir,
    name: &str,
    expected_len: u64,
    expected_sha256: &str,
) -> Result<File, CheckpointError> {
    if expected_len > MAX_CHECKPOINT_PAYLOAD_BYTES {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact {name:?} exceeds the payload bound"
        )));
    }
    let mut file = open_regular_file(dir, name, expected_len)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| checkpoint_file_error(name, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| CheckpointError::Invalid("artifact byte count overflow".to_owned()))?;
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if bytes != expected_len || actual != decode_hex::<32>(expected_sha256)? {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact {name:?} length or SHA256 mismatch"
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| checkpoint_file_error(name, error))?;
    Ok(file)
}

fn decode_coinstats_artifact(bytes: &[u8]) -> Result<CoinStats, CheckpointError> {
    if u64::try_from(bytes.len()).ok() != Some(COINSTATS_ARTIFACT_LEN) {
        return Err(CheckpointError::Invalid(
            "CoinStats artifact is not exactly 820 bytes".to_owned(),
        ));
    }
    if bytes[..8] != COINSTATS_MAGIC {
        return Err(CheckpointError::Invalid(
            "bad CoinStats artifact magic".to_owned(),
        ));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| {
        CheckpointError::Invalid("truncated CoinStats artifact version".to_owned())
    })?);
    if version != COINSTATS_VERSION {
        return Err(CheckpointError::Invalid(format!(
            "unsupported CoinStats artifact version {version}"
        )));
    }
    let payload_len =
        u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| {
            CheckpointError::Invalid("truncated CoinStats artifact length".to_owned())
        })?);
    if usize::try_from(payload_len).ok() != Some(COIN_STATS_ENCODED_LEN) {
        return Err(CheckpointError::Invalid(format!(
            "CoinStats artifact declares payload length {payload_len}"
        )));
    }
    Ok(CoinStats::from_bytes(&bytes[16..])?)
}

fn cleanup_after_publication(root: &CheckpointRoot, current: &str) {
    let entries = match root.entries() {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, "failed to enumerate checkpoint cleanup entries");
            return;
        }
    };
    let mut attempted = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "failed to inspect checkpoint cleanup entry");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                tracing::warn!(%error, entry = name, "failed to classify checkpoint cleanup entry");
                continue;
            }
        };
        let result = if file_type.is_dir()
            && name != current
            && (valid_generation_name(name) || valid_staging_name(name))
        {
            attempted = true;
            remove_known_dir(root, name)
        } else if file_type.is_file() && valid_current_temp_name(name) {
            attempted = true;
            root.remove_file(name)
        } else {
            continue;
        };
        if let Err(error) = result {
            tracing::warn!(%error, entry = name, "failed to remove checkpoint cleanup entry");
        }
    }
    if attempted {
        if let Err(error) = root.sync() {
            tracing::warn!(%error, "failed to sync checkpoint directory after cleanup");
        }
    }
}

fn require_filename(actual: &str, expected: &str) -> Result<(), CheckpointError> {
    if actual != expected || Path::new(actual).components().count() != 1 {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact filename {actual:?} is not {expected:?}"
        )));
    }
    Ok(())
}

fn manifest_tip(tip: headers::HeaderCheckpointTip, chain_tx_count: u64) -> CheckpointTipV1 {
    let chainwork: [u8; 32] = tip.chainwork.to_be_bytes();
    CheckpointTipV1 {
        height: tip.height,
        hash: tip.hash.to_string_be(),
        chainwork: hex_encode(&chainwork),
        chain_tx_count,
    }
}

fn parse_tip(tip: &CheckpointTipV1) -> Result<headers::HeaderCheckpointTip, CheckpointError> {
    Ok(headers::HeaderCheckpointTip {
        height: tip.height,
        hash: Hash256::from_str_be(&tip.hash)
            .map_err(|error| CheckpointError::Invalid(error.to_string()))?,
        chainwork: ChainWork::from_be_bytes(decode_hex::<32>(&tip.chainwork)?),
    })
}

/// Checkpoint-file network spelling. Core's `testnet` alias names
/// [`Network::Testnet3`]. Evidence identity uses [`Network::identity_name`].
fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet3 => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], CheckpointError> {
    if encoded.len() != N.saturating_mul(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CheckpointError::Invalid(format!(
            "expected {} lowercase hexadecimal characters",
            N.saturating_mul(2)
        )));
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
    }
    Ok(decoded)
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests;
