//! Checkpoint formats, loading, publication, and periodic scheduling.

mod format;
pub(crate) mod fs;
mod io;
mod load;
mod publish;
pub(crate) mod worker;

use crate::checkpoint::fs::CheckpointRoot;
#[cfg(test)]
use crate::checkpoint::fs::open_data_dir;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::CoinStats;
use bitcoin_rs_utxo::stats::CoinStatsListener;
use cap_std::fs::Dir;
use cap_std::fs::File;
#[cfg(test)]
use format::hex_encode;
use load::classify_checkpoint_error;
use load::classify_open_error;
use load::corrupt_checkpoint;
use load::load_headers;
use load::load_payloads;
use load::read_current;
use load::read_manifest;
use parking_lot::RwLock;
use publish::write_checkpoint_inner;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::io::BufWriter;
use std::io::Write;
#[cfg(test)]
use std::path::Path;
use thiserror::Error;

pub(crate) mod headers;

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

#[cfg(test)]
mod tests;
