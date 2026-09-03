use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot, accept_headers};
use bitcoin_rs_primitives::{ConsensusEncode, Header, deserialize};
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

const HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\0";
const HEADER_VERSION: u32 = 1;
const HEADER_PREFIX_LEN: usize = 56;
const HEADER_LEN: usize = 80;
const BEST_CHAIN_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/best\0";
const APPLIED_PREFIX_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/applied\0";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointConfig {
    pub(crate) network: Network,
    pub(crate) genesis: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointPoint {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointTip {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
    pub(crate) chainwork: ChainWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointMetadata {
    pub(crate) header_count: u64,
    pub(crate) best: HeaderCheckpointTip,
    pub(crate) applied: HeaderCheckpointTip,
    pub(crate) best_chain_commitment: [u8; 32],
    pub(crate) applied_prefix_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointWrite {
    pub(crate) metadata: HeaderCheckpointMetadata,
    pub(crate) bytes_written: u64,
}

pub(crate) struct RestoredHeaders {
    pub(crate) tree: BlockTree,
    pub(crate) applied_tip_id: NodeId,
}

#[derive(Debug, Error)]
pub(crate) enum HeaderCheckpointError {
    #[error("configured genesis {configured} does not match {network:?} genesis {expected}")]
    ConfiguredGenesisMismatch {
        configured: Hash256,
        expected: Hash256,
        network: Network,
    },
    #[error("header checkpoint contains zero headers")]
    ZeroHeaderCount,
    #[error("header checkpoint count {count} does not fit usize")]
    CountDoesNotFitUsize { count: u64 },
    #[error("header checkpoint count {count} exceeds the u32 block-height domain")]
    CountExceedsHeightDomain { count: u64 },
    #[error("header checkpoint byte length overflow for {count} headers")]
    SizeOverflow { count: u64 },
    #[error("header checkpoint has {actual} bytes, expected {expected}")]
    InvalidFileLength { actual: u64, expected: u64 },
    #[error("header checkpoint magic is invalid")]
    BadMagic,
    #[error("header checkpoint version {actual} is unsupported")]
    UnsupportedVersion { actual: u32 },
    #[error("header checkpoint network magic does not match configured network")]
    NetworkMismatch,
    #[error("header checkpoint genesis does not match configured genesis")]
    GenesisMismatch,
    #[error("header checkpoint count {actual} does not match manifest count {expected}")]
    CountMismatch { actual: u64, expected: u64 },
    #[error("header checkpoint best tip is not the tree's published best tip")]
    BestTipNotActive,
    #[error("header checkpoint active ancestry is malformed at height {height}")]
    MalformedAncestry { height: u32 },
    #[error("header checkpoint root is not the configured genesis")]
    RootIsNotGenesis,
    #[error("header checkpoint applied tip is not a prefix of the active best chain")]
    AppliedTipNotBestPrefix,
    #[error("header checkpoint metadata does not match reconstructed chain")]
    MetadataMismatch,
    #[error("header checkpoint commitment does not match reconstructed chain")]
    CommitmentMismatch,
    #[error("header checkpoint consensus codec failed: {0}")]
    Codec(String),
    #[error("header checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("header checkpoint consensus validation failed: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
}

pub(crate) fn write_headers<W: Write>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    validate_config(config)?;
    if tree.tip_id() != Some(best_tip_id) {
        return Err(HeaderCheckpointError::BestTipNotActive);
    }
    write_headers_inner(writer, tree, config, best_tip_id, applied)
}

fn write_selected_headers<W: Write>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    validate_config(config)?;
    write_headers_inner(writer, tree, config, best_tip_id, applied)
}

fn write_headers_inner<W: Write>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    let mut ancestry = tree.ancestor_chain(best_tip_id)?;
    ancestry.reverse();
    let count = u64::try_from(ancestry.len())
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count: u64::MAX })?;
    let bytes_written = checkpoint_size(count)?;

    let root = tree.node(
        *ancestry
            .first()
            .ok_or(HeaderCheckpointError::ZeroHeaderCount)?,
    )?;
    if root.height != 0 || root.hash != config.genesis {
        return Err(HeaderCheckpointError::RootIsNotGenesis);
    }

    let best = tip_from_node(tree, best_tip_id)?;
    if u64::from(best.height).checked_add(1) != Some(count) {
        return Err(HeaderCheckpointError::MalformedAncestry {
            height: best.height,
        });
    }
    let applied_id = tree
        .lookup(applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_node = tree.node(applied_id)?;
    if applied_node.height != applied.height
        || tree.node_at_height_from(best_tip_id, applied.height) != Some(applied_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    let applied = tip_from_node(tree, applied_id)?;

    writer.write_all(&prefix(config, count))?;
    let mut best_hasher = Sha256::new();
    best_hasher.update(BEST_CHAIN_DOMAIN);
    let mut applied_hasher = Sha256::new();
    applied_hasher.update(APPLIED_PREFIX_DOMAIN);

    for (index, node_id) in ancestry.into_iter().enumerate() {
        let height = u32::try_from(index)
            .map_err(|_| HeaderCheckpointError::CountExceedsHeightDomain { count })?;
        let node = tree.node(node_id)?;
        if node.height != height {
            return Err(HeaderCheckpointError::MalformedAncestry { height });
        }
        let encoded = encode_header(&node.header)?;
        writer.write_all(&encoded)?;
        best_hasher.update(encoded);
        if node.height <= applied.height {
            applied_hasher.update(encoded);
        }
    }

    Ok(HeaderCheckpointWrite {
        metadata: HeaderCheckpointMetadata {
            header_count: count,
            best,
            applied,
            best_chain_commitment: best_hasher.finalize().into(),
            applied_prefix_commitment: applied_hasher.finalize().into(),
        },
        bytes_written,
    })
}

pub(crate) fn read_headers<R: Read + Seek>(
    reader: &mut R,
    config: HeaderCheckpointConfig,
    expected: HeaderCheckpointMetadata,
) -> Result<RestoredHeaders, HeaderCheckpointError> {
    validate_config(config)?;
    let expected_size = checkpoint_size(expected.header_count)?;
    reader.seek(SeekFrom::Start(0))?;
    let actual_size = reader.seek(SeekFrom::End(0))?;
    if actual_size != expected_size {
        return Err(HeaderCheckpointError::InvalidFileLength {
            actual: actual_size,
            expected: expected_size,
        });
    }
    reader.seek(SeekFrom::Start(0))?;

    let mut encoded_prefix = [0_u8; HEADER_PREFIX_LEN];
    reader.read_exact(&mut encoded_prefix)?;
    let count = parse_prefix(encoded_prefix, config)?;
    if count != expected.header_count {
        return Err(HeaderCheckpointError::CountMismatch {
            actual: count,
            expected: expected.header_count,
        });
    }

    let mut tree = BlockTree::new();
    let mut best_hasher = Sha256::new();
    best_hasher.update(BEST_CHAIN_DOMAIN);
    let mut applied_hasher = Sha256::new();
    applied_hasher.update(APPLIED_PREFIX_DOMAIN);
    let mut last_id = None;

    for index in 0..usize::try_from(count)
        .map_err(|_| HeaderCheckpointError::CountDoesNotFitUsize { count })?
    {
        let height = u32::try_from(index)
            .map_err(|_| HeaderCheckpointError::CountExceedsHeightDomain { count })?;
        let mut encoded = [0_u8; HEADER_LEN];
        reader.read_exact(&mut encoded)?;
        let header: Header = deserialize(&encoded)
            .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
        let ids = accept_headers(
            &mut tree,
            core::slice::from_ref(&header),
            config.network,
            bitcoin_rs_chain::current_unix_seconds(),
        )?;
        let id = ids[0];
        let node = tree.node(id)?;
        if node.height != height || tree.len() != index + 1 {
            return Err(HeaderCheckpointError::MalformedAncestry { height });
        }
        best_hasher.update(encoded);
        if height <= expected.applied.height {
            applied_hasher.update(encoded);
        }
        last_id = Some(id);
    }

    let best_tip_id = last_id.ok_or(HeaderCheckpointError::ZeroHeaderCount)?;
    let best = tip_from_node(&tree, best_tip_id)?;
    if tree.tip_id() != Some(best_tip_id) || best != expected.best {
        return Err(HeaderCheckpointError::MetadataMismatch);
    }
    let applied_tip_id = tree
        .lookup(expected.applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_tip = tip_from_node(&tree, applied_tip_id)?;
    if applied_tip != expected.applied
        || tree.node_at_height_from(best_tip_id, expected.applied.height) != Some(applied_tip_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    let best_chain_commitment: [u8; 32] = best_hasher.finalize().into();
    let applied_prefix_commitment: [u8; 32] = applied_hasher.finalize().into();
    if best_chain_commitment != expected.best_chain_commitment
        || applied_prefix_commitment != expected.applied_prefix_commitment
    {
        return Err(HeaderCheckpointError::CommitmentMismatch);
    }

    Ok(RestoredHeaders {
        tree,
        applied_tip_id,
    })
}

fn validate_config(config: HeaderCheckpointConfig) -> Result<(), HeaderCheckpointError> {
    let expected = config.network.genesis_block_hash();
    if config.genesis != expected {
        return Err(HeaderCheckpointError::ConfiguredGenesisMismatch {
            configured: config.genesis,
            expected,
            network: config.network,
        });
    }
    Ok(())
}

fn checkpoint_size(count: u64) -> Result<u64, HeaderCheckpointError> {
    if count == 0 {
        return Err(HeaderCheckpointError::ZeroHeaderCount);
    }
    if usize::try_from(count).is_err() {
        return Err(HeaderCheckpointError::CountDoesNotFitUsize { count });
    }
    if count > u64::from(u32::MAX) + 1 {
        return Err(HeaderCheckpointError::CountExceedsHeightDomain { count });
    }
    let prefix_len = u64::try_from(HEADER_PREFIX_LEN)
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count })?;
    let header_len =
        u64::try_from(HEADER_LEN).map_err(|_| HeaderCheckpointError::SizeOverflow { count })?;
    prefix_len
        .checked_add(
            count
                .checked_mul(header_len)
                .ok_or(HeaderCheckpointError::SizeOverflow { count })?,
        )
        .ok_or(HeaderCheckpointError::SizeOverflow { count })
}

fn prefix(config: HeaderCheckpointConfig, count: u64) -> [u8; HEADER_PREFIX_LEN] {
    let mut out = [0_u8; HEADER_PREFIX_LEN];
    out[..8].copy_from_slice(&HEADER_MAGIC);
    out[8..12].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&config.network.magic());
    out[16..48].copy_from_slice(&config.genesis.to_le_bytes());
    out[48..].copy_from_slice(&count.to_le_bytes());
    out
}

fn parse_prefix(
    encoded: [u8; HEADER_PREFIX_LEN],
    config: HeaderCheckpointConfig,
) -> Result<u64, HeaderCheckpointError> {
    if encoded[..8] != HEADER_MAGIC {
        return Err(HeaderCheckpointError::BadMagic);
    }
    let version = u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
    if version != HEADER_VERSION {
        return Err(HeaderCheckpointError::UnsupportedVersion { actual: version });
    }
    if encoded[12..16] != config.network.magic() {
        return Err(HeaderCheckpointError::NetworkMismatch);
    }
    if encoded[16..48] != config.genesis.to_le_bytes() {
        return Err(HeaderCheckpointError::GenesisMismatch);
    }
    let count = u64::from_le_bytes([
        encoded[48],
        encoded[49],
        encoded[50],
        encoded[51],
        encoded[52],
        encoded[53],
        encoded[54],
        encoded[55],
    ]);
    checkpoint_size(count)?;
    Ok(count)
}

fn tip_from_node(
    tree: &BlockTree,
    id: NodeId,
) -> Result<HeaderCheckpointTip, HeaderCheckpointError> {
    let node = tree.node(id)?;
    Ok(HeaderCheckpointTip {
        height: node.height,
        hash: node.hash,
        chainwork: node.chainwork,
    })
}

fn encode_header(header: &Header) -> Result<[u8; HEADER_LEN], HeaderCheckpointError> {
    let mut encoded = [0_u8; HEADER_LEN];
    let mut cursor = &mut encoded[..];
    header
        .consensus_encode(&mut cursor)
        .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
    if !cursor.is_empty() {
        return Err(HeaderCheckpointError::Codec(
            "Bitcoin header did not encode to 80 bytes".to_owned(),
        ));
    }
    Ok(encoded)
}

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
    Header(#[from] HeaderCheckpointError),
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
    config: HeaderCheckpointConfig,
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
    if manifest.headers.version != HEADER_VERSION {
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
        Err(CheckpointError::Header(HeaderCheckpointError::UnsupportedVersion { actual })) => {
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
    config: HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let data_dir = match open_data_dir(data_dir) {
        Ok(data_dir) => data_dir,
        Err(_) => return Ok(CheckpointLoad::Cold),
    };
    load_checkpoint_from_dir(&data_dir, config)
}

pub(crate) fn write_checkpoint_from_dir(
    data_dir: &Dir,
    config: HeaderCheckpointConfig,
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
    config: HeaderCheckpointConfig,
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
    config: HeaderCheckpointConfig,
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
        let applied_point = HeaderCheckpointPoint {
            height: applied_tip.height,
            hash: applied_tip.hash,
        };
        let metadata = if tree.tip_id() == Some(best_tip_id) {
            write_headers(&mut writer, &tree, config, best_tip_id, applied_point)?
        } else {
            write_selected_headers(&mut writer, &tree, config, best_tip_id, applied_point)?
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
            version: HEADER_VERSION,
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
    config: HeaderCheckpointConfig,
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
    config: HeaderCheckpointConfig,
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
    config: HeaderCheckpointConfig,
    manifest: &CheckpointManifestV1,
) -> Result<RestoredHeaders, CheckpointError> {
    require_filename(&manifest.headers.file, HEADERS_FILE)?;
    let mut file = verify_artifact(
        generation_dir,
        HEADERS_FILE,
        manifest.headers.bytes,
        &manifest.headers.sha256,
    )?;
    let expected = HeaderCheckpointMetadata {
        header_count: manifest.headers.header_count,
        best: parse_tip(&manifest.best_header_tip)?,
        applied: parse_tip(&manifest.applied_tip)?,
        best_chain_commitment: decode_hex::<32>(&manifest.headers.best_chain_sha256)?,
        applied_prefix_commitment: decode_hex::<32>(&manifest.headers.applied_chain_sha256)?,
    };
    read_headers(&mut file, config, expected).map_err(CheckpointError::Header)
}

fn load_payloads(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    headers: RestoredHeaders,
) -> Result<RestoredChainstate, CheckpointError> {
    let chain_tx_count = manifest.applied_tip.chain_tx_count;
    let (utxo, coin_stats) = load_payloads_inner(generation_dir, manifest, &headers)?;
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
    headers: &RestoredHeaders,
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

fn manifest_tip(tip: HeaderCheckpointTip, chain_tx_count: u64) -> CheckpointTipV1 {
    let chainwork: [u8; 32] = tip.chainwork.to_be_bytes();
    CheckpointTipV1 {
        height: tip.height,
        hash: tip.hash.to_string_be(),
        chainwork: hex_encode(&chainwork),
        chain_tx_count,
    }
}

fn parse_tip(tip: &CheckpointTipV1) -> Result<HeaderCheckpointTip, CheckpointError> {
    Ok(HeaderCheckpointTip {
        height: tip.height,
        hash: Hash256::from_str_be(&tip.hash)
            .map_err(|error| CheckpointError::Invalid(error.to_string()))?,
        chainwork: ChainWork::from_be_bytes(decode_hex::<32>(&tip.chainwork)?),
    })
}

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
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
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
mod tests {

    /// The checkpoint manifest's codec identifiers are on-disk values.
    ///
    /// Pinned as literals rather than through the constants, because comparing a
    /// constant to itself proves nothing: the writer and the reader use the same
    /// three names, so renaming one keeps a single binary perfectly
    /// self-consistent while every checkpoint already on disk stops loading and
    /// requires an explicit full resync (`docs/policies/db-migration.md`). That
    /// failure is invisible to a round-trip test and expensive in production.
    ///
    /// These identifiers are the current schema's on-disk codec names. Changing
    /// one requires a schema epoch bump and an explicit resync.
    #[test]
    fn manifest_codec_identifiers_are_current_and_frozen() {
        assert_eq!(super::HEADER_CODEC, "bitcoin-rs-canonical-headers");
        assert_eq!(super::UTXO_CODEC, "bitcoin-rs-utxo-spendable-v1");
        assert_eq!(super::COINSTATS_CODEC, "bitcoin-rs-coinstats-v1");
        assert_eq!(super::CURRENT_FORMAT, "bitcoin-rs-chainstate-current");
        assert_eq!(super::MANIFEST_FORMAT, "bitcoin-rs-chainstate-checkpoint");
    }

    use std::fs;
    use std::io::Cursor;
    use std::path::Path;

    use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot, accept_headers};
    use bitcoin_rs_primitives::{
        BlockHash, Hash256, Header, Network, OutPoint, TxOut, Txid, deserialize,
    };
    use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener, scan_coin_stats};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};

    use super::{
        CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CheckpointCorruption, CheckpointFailpoint,
        CheckpointLoad, CheckpointLoadError, CheckpointManifestV1, CheckpointWrite, CurrentV1,
        HEADER_PREFIX_LEN, HEADERS_FILE, HeaderCheckpointConfig, HeaderCheckpointError,
        HeaderCheckpointPoint, HeaderCheckpointTip, HeaderCheckpointWrite, MANIFEST_FILE,
        UTXO_FILE, encode_header, load_checkpoint, read_headers, write_checkpoint_with_failpoint,
        write_headers,
    };

    const NETWORK: Network = Network::Regtest;

    #[test]
    fn transient_checkpoint_io_is_not_classified_as_incompatible() {
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "checkpoint locked");
        let classified = super::classify_checkpoint_error(super::CheckpointError::Io(error));
        let CheckpointLoadError::Io(error) = classified else {
            panic!("transient checkpoint I/O was classified as datadir incompatibility");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "checkpoint locked");

        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "root locked");
        let classified = super::classify_open_error("open checkpoint root", error);
        let CheckpointLoadError::Io(error) = classified else {
            panic!("transient checkpoint-open I/O was classified as datadir incompatibility");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "root locked");
    }

    #[test]
    fn round_trip_replays_consensus_validated_active_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let (tree, best_tip_id, applied) = chain_with_applied_height(3, 1)?;
        let written = write_checkpoint(&tree, best_tip_id, applied)?;
        let mut reader = Cursor::new(written.0);

        let restored = read_headers(&mut reader, config(), written.1.metadata)?;

        assert_eq!(restored.tree.len(), 4);
        assert_eq!(
            restored.tree.tip().map(|tip| tip.hash),
            Some(tree.node(best_tip_id)?.hash),
            "the restored best tip identifies the same chain across distinct trees"
        );
        assert_eq!(
            restored.tree.node(restored.applied_tip_id)?.hash,
            applied.hash,
            "the applied checkpoint tip is reconstructed from the accepted prefix"
        );
        Ok(())
    }

    #[test]
    fn reader_rejects_wrong_network_and_genesis() -> Result<(), Box<dyn std::error::Error>> {
        let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
        let written = write_checkpoint(&tree, best_tip_id, applied)?;

        let wrong_network = HeaderCheckpointConfig {
            network: Network::Testnet3,
            genesis: Network::Testnet3.genesis_block_hash(),
        };
        assert!(
            read_headers(
                &mut Cursor::new(&written.0),
                wrong_network,
                written.1.metadata
            )
            .is_err()
        );
        let configured_genesis_mismatch = HeaderCheckpointConfig {
            network: NETWORK,
            genesis: Hash256::from_le_bytes(&[0x22; 32]),
        };
        assert!(matches!(
            read_headers(
                &mut Cursor::new(&written.0),
                configured_genesis_mismatch,
                written.1.metadata
            ),
            Err(HeaderCheckpointError::ConfiguredGenesisMismatch { .. })
        ));
        let mut wrong_genesis = written.0;
        wrong_genesis[16] ^= 1;
        assert!(
            read_headers(
                &mut Cursor::new(wrong_genesis),
                config(),
                written.1.metadata
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn reader_rejects_bad_prefix_count_and_trailing_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
        let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_magic), config(), written.metadata).is_err());
        let mut bad_version = bytes.clone();
        bad_version[8] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_version), config(), written.metadata).is_err());
        let mut bad_count = bytes.clone();
        bad_count[48] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_count), config(), written.metadata).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(read_headers(&mut Cursor::new(trailing), config(), written.metadata).is_err());
        Ok(())
    }

    #[test]
    fn reader_rejects_mutated_linkage_and_invalid_pow_or_nbits()
    -> Result<(), Box<dyn std::error::Error>> {
        let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
        let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

        let mut bad_prev = bytes.clone();
        bad_prev[HEADER_PREFIX_LEN + 80 + 4] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_prev), config(), written.metadata).is_err());

        let mut bad_pow = bytes.clone();
        let header_offset = HEADER_PREFIX_LEN + 80;
        let mut invalid = header_from_row(&bad_pow[header_offset..header_offset + 80])?;
        while pow_meets_target(invalid.bits, invalid.compute_hash().0) {
            invalid.nonce = invalid.nonce.checked_add(1).ok_or("nonce exhausted")?;
        }
        bad_pow[header_offset..header_offset + 80].copy_from_slice(&encode_header(&invalid)?);
        assert!(read_headers(&mut Cursor::new(bad_pow), config(), written.metadata).is_err());

        let mut bad_nbits = bytes;
        let previous = header_from_row(&bad_nbits[header_offset..header_offset + 80])?;
        let mut nbits_mismatch = Header {
            bits: 0x207f_fffe,
            ..previous
        };
        mine_header_to_declared_target(&mut nbits_mismatch)?;
        bad_nbits[header_offset..header_offset + 80]
            .copy_from_slice(&encode_header(&nbits_mismatch)?);
        assert!(read_headers(&mut Cursor::new(bad_nbits), config(), written.metadata).is_err());
        Ok(())
    }

    #[test]
    fn reader_rejects_metadata_and_commitment_mutations() -> Result<(), Box<dyn std::error::Error>>
    {
        let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
        let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

        let mut wrong_best = written.metadata;
        wrong_best.best.hash = Hash256::from_le_bytes(&[0x11; 32]);
        assert!(read_headers(&mut Cursor::new(&bytes), config(), wrong_best).is_err());

        let mut wrong_applied = written.metadata;
        wrong_applied.applied = HeaderCheckpointTip {
            hash: written.metadata.best.hash,
            ..written.metadata.applied
        };
        assert!(read_headers(&mut Cursor::new(&bytes), config(), wrong_applied).is_err());

        let mut wrong_applied_prefix_commitment = written.metadata;
        wrong_applied_prefix_commitment.applied_prefix_commitment[0] ^= 1;
        assert!(
            read_headers(
                &mut Cursor::new(bytes.clone()),
                config(),
                wrong_applied_prefix_commitment
            )
            .is_err()
        );

        let mut wrong_commitment = written.metadata;
        wrong_commitment.best_chain_commitment[0] ^= 1;
        assert!(read_headers(&mut Cursor::new(bytes), config(), wrong_commitment).is_err());
        Ok(())
    }

    #[test]
    fn writer_refuses_a_best_tip_that_is_not_active() -> Result<(), Box<dyn std::error::Error>> {
        let (tree, _, applied) = chain_with_applied_height(3, 1)?;

        assert!(matches!(
            write_headers(&mut Vec::new(), &tree, config(), NodeId::new(0), applied),
            Err(HeaderCheckpointError::BestTipNotActive)
        ));
        Ok(())
    }

    #[test]
    fn writer_refuses_an_applied_tip_off_the_active_best_ancestry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut tree, best_tip_id, _) = chain_with_applied_height(3, 1)?;
        let genesis_hash = tree.node(NodeId::new(0))?.hash;
        let mut fork = next_header(
            BlockHash(genesis_hash),
            u32::from(NETWORK.genesis_block_hash().to_le_bytes()[0]) + 1,
        );
        mine_header_to_declared_target(&mut fork)?;
        let fork_id = accept_headers(
            &mut tree,
            core::slice::from_ref(&fork),
            NETWORK,
            bitcoin_rs_chain::current_unix_seconds(),
        )?[0];
        let fork = tree.node(fork_id)?;
        let applied = HeaderCheckpointPoint {
            height: fork.height,
            hash: fork.hash,
        };

        assert!(matches!(
            write_headers(&mut Vec::new(), &tree, config(), best_tip_id, applied),
            Err(HeaderCheckpointError::AppliedTipNotBestPrefix)
        ));
        Ok(())
    }

    #[test]
    fn immutable_generation_resumes_best_ahead_of_applied() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(3, 1)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let mut stats = CoinStats::new();
        stats.height = applied.height;
        let listener = CoinStatsListener::new(stats);

        assert!(matches!(
            super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
            )?,
            CheckpointWrite::Published { .. }
        ));
        let loaded = load_checkpoint(dir.path(), config())?;
        let CheckpointLoad::Complete(restored) = loaded else {
            return Err("checkpoint did not restore complete chainstate".into());
        };
        assert_eq!(restored.tree.tip().map(|tip| tip.height), Some(3));
        assert_eq!(restored.applied_tip.height, 1);
        assert_eq!(restored.applied_tip.hash, applied.hash);
        assert_eq!(restored.utxo.record_count(), 0);
        assert_eq!(restored.coin_stats.height, 1);
        Ok(())
    }

    #[test]
    fn publication_selects_applied_ancestry_and_forgets_competing_fork()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (mut tree, main_best_id, applied_point) = chain_with_applied_height(3, 1)?;
        let main_best_hash = tree.node(main_best_id)?.hash;

        let genesis_hash = tree.node(NodeId::new(0))?.hash;
        let mut prev = BlockHash(genesis_hash);
        let mut fork_best_id = NodeId::new(0);
        for height in 1..=4 {
            let mut header = next_header(prev, height);
            header.time = header.time.saturating_add(100);
            mine_header_to_declared_target(&mut header)?;
            fork_best_id = accept_headers(
                &mut tree,
                core::slice::from_ref(&header),
                NETWORK,
                bitcoin_rs_chain::current_unix_seconds(),
            )?[0];
            prev = BlockHash(tree.node(fork_best_id)?.hash);
        }
        let fork_best_hash = tree.node(fork_best_id)?.hash;
        assert_eq!(tree.tip().map(|tip| tip.tip_id), Some(fork_best_id));
        assert_ne!(
            tree.node_at_height_from(fork_best_id, applied_point.height),
            tree.lookup(applied_point.hash),
            "fixture must place the applied tip outside the live best ancestry"
        );

        let applied_tip = tip_snapshot(&tree, applied_point)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let mut stats = CoinStats::new();
        stats.height = applied_point.height;
        let listener = CoinStatsListener::new(stats);

        assert!(matches!(
            super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
            )?,
            CheckpointWrite::Published { .. }
        ));

        let loaded = load_checkpoint(dir.path(), config())?;
        let CheckpointLoad::Complete(restored) = loaded else {
            return Err("checkpoint did not restore complete chainstate".into());
        };

        assert_eq!(
            restored.tree.tip().map(|tip| (tip.height, tip.hash)),
            Some((applied_point.height, applied_point.hash)),
            "checkpoint must publish the coherent applied ancestry"
        );
        assert!(
            restored.tree.lookup(fork_best_hash).is_none(),
            "the competing best-work fork must be rediscovered after restart"
        );
        assert!(
            restored.tree.lookup(main_best_hash).is_none(),
            "headers above the applied tip must be rediscovered after restart"
        );
        assert_eq!(restored.applied_tip.height, applied_point.height);
        assert_eq!(restored.applied_tip.hash, applied_point.hash);
        Ok(())
    }

    #[test]
    fn every_publication_failpoint_leaves_old_or_fully_valid_current()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let listener = CoinStatsListener::new(CoinStats::new());
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?;

        for failpoint in [
            CheckpointFailpoint::HeadersWrite,
            CheckpointFailpoint::HeadersSync,
            CheckpointFailpoint::UtxoWrite,
            CheckpointFailpoint::UtxoSync,
            CheckpointFailpoint::CoinStatsWrite,
            CheckpointFailpoint::CoinStatsSync,
            CheckpointFailpoint::ManifestWrite,
            CheckpointFailpoint::ManifestSync,
            CheckpointFailpoint::StageSync,
            CheckpointFailpoint::GenerationRename,
            CheckpointFailpoint::GenerationRootSync,
            CheckpointFailpoint::CurrentTempWrite,
            CheckpointFailpoint::CurrentTempSync,
            CheckpointFailpoint::CurrentRename,
        ] {
            let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
            let previous_current = fs::read(&current_path)?;
            assert!(
                write_checkpoint_with_failpoint(
                    dir.path(),
                    config(),
                    &tree,
                    &utxo,
                    &listener,
                    Some(&applied_tip),
                    failpoint,
                )
                .is_err(),
                "{failpoint:?}"
            );
            assert_eq!(
                fs::read(&current_path)?,
                previous_current,
                "pre-CURRENT failure changed the authoritative pointer at {failpoint:?}"
            );
            assert!(matches!(
                load_checkpoint(dir.path(), config())?,
                CheckpointLoad::Complete(_)
            ));
        }
        assert!(
            write_checkpoint_with_failpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
                CheckpointFailpoint::CurrentRootSync,
            )
            .is_err()
        );
        assert!(matches!(
            load_checkpoint(dir.path(), config())?,
            CheckpointLoad::Complete(_)
        ));
        Ok(())
    }

    #[test]
    fn first_publication_failures_leave_no_committed_checkpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        for failpoint in [
            CheckpointFailpoint::HeadersWrite,
            CheckpointFailpoint::HeadersSync,
            CheckpointFailpoint::UtxoWrite,
            CheckpointFailpoint::UtxoSync,
            CheckpointFailpoint::CoinStatsWrite,
            CheckpointFailpoint::CoinStatsSync,
            CheckpointFailpoint::ManifestWrite,
            CheckpointFailpoint::ManifestSync,
            CheckpointFailpoint::StageSync,
            CheckpointFailpoint::GenerationRename,
            CheckpointFailpoint::GenerationRootSync,
            CheckpointFailpoint::CurrentTempWrite,
            CheckpointFailpoint::CurrentTempSync,
            CheckpointFailpoint::CurrentRename,
        ] {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            let utxo = UtxoSet::new();
            let listener = CoinStatsListener::new(CoinStats::new());

            assert!(
                write_checkpoint_with_failpoint(
                    dir.path(),
                    config(),
                    &tree,
                    &utxo,
                    &listener,
                    Some(&applied_tip),
                    failpoint,
                )
                .is_err(),
                "{failpoint:?}"
            );
            assert!(
                !dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists(),
                "pre-publication failure exposed CURRENT at {failpoint:?}"
            );
            assert!(matches!(
                load_checkpoint(dir.path(), config()),
                Ok(CheckpointLoad::Cold)
            ));
        }
        Ok(())
    }

    #[test]
    fn no_applied_tip_skips_without_changing_current() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let listener = CoinStatsListener::new(CoinStats::new());
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?;
        let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
        let before = fs::read(&current_path)?;
        assert_eq!(
            super::write_checkpoint(dir.path(), config(), &tree, &utxo, &listener, None)?,
            CheckpointWrite::SkippedNoAppliedTip
        );
        assert_eq!(fs::read(current_path)?, before);
        Ok(())
    }

    #[test]
    fn checkpoint_without_current_is_cold() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        super::write_checkpoint(
            dir.path(),
            config(),
            &RwLock::new(tree),
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        fs::remove_file(dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE))?;

        assert!(matches!(
            load_checkpoint(dir.path(), config()),
            Ok(CheckpointLoad::Cold)
        ));
        Ok(())
    }

    #[test]
    fn unsupported_utxo_codec_requires_explicit_resync() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        super::write_checkpoint(
            dir.path(),
            config(),
            &RwLock::new(tree),
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_manifest(dir.path(), |manifest| {
            manifest.utxo.codec = "bitcoin-rs-utxo".to_owned();
        })?;

        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("unsupported UTXO codec unexpectedly loaded".into());
        };
        let message = error.to_string();
        assert!(message.contains("unexpected payload codecs"));
        assert!(message.contains("full resync"));
        Ok(())
    }

    #[test]
    fn unsupported_utxo_snapshot_version_requires_explicit_resync()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(1, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        super::write_checkpoint(
            dir.path(),
            config(),
            &RwLock::new(tree),
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_manifest(dir.path(), |manifest| {
            manifest.utxo.version = 3;
        })?;

        let Err(CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid { reason })) =
            load_checkpoint(dir.path(), config())
        else {
            return Err("unsupported UTXO snapshot unexpectedly loaded".into());
        };
        assert!(reason.contains("UTXO checkpoint version 3 is not current"));
        Ok(())
    }

    #[test]
    fn unsupported_current_version_is_current_checkpoint_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
        let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
        current.version = current.version.saturating_add(1);
        fs::write(current_path, serde_json::to_vec(&current)?)?;
        let Err(CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid { reason })) =
            load_checkpoint(dir.path(), config())
        else {
            return Err("unsupported CURRENT version was not reported as corruption".into());
        };
        assert!(reason.contains("CURRENT checkpoint version"));
        assert!(!reason.contains("incompatible bitcoin-rs datadir"));
        Ok(())
    }

    #[test]
    fn semantic_utxo_trailing_byte_with_rebound_hashes_requires_resync()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(1, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let listener = CoinStatsListener::new(CoinStats::new());
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?;

        let root = dir.path().join(CHECKPOINT_ROOT);
        let current_path = root.join(CURRENT_FILE);
        let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
        let generation = root.join(&current.directory);
        let manifest_path = generation.join(MANIFEST_FILE);
        let mut manifest: CheckpointManifestV1 =
            serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let utxo_path = generation.join(UTXO_FILE);
        let mut utxo_bytes = fs::read(&utxo_path)?;
        utxo_bytes.push(0x5a);
        fs::write(&utxo_path, &utxo_bytes)?;
        manifest.utxo.bytes = u64::try_from(utxo_bytes.len())?;
        manifest.utxo.sha256 = super::hex_encode(&Sha256::digest(&utxo_bytes));
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        fs::write(&manifest_path, &manifest_bytes)?;
        current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
        fs::write(&current_path, serde_json::to_vec(&current)?)?;

        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("semantic UTXO corruption unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
        Ok(())
    }

    #[test]
    fn configured_network_mismatch_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        let wrong = HeaderCheckpointConfig {
            network: Network::Testnet3,
            genesis: Network::Testnet3.genesis_block_hash(),
        };
        assert!(load_checkpoint(dir.path(), wrong).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_inner_header_version_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
            bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
        })?;

        assert!(matches!(
            load_checkpoint(dir.path(), config()),
            Err(super::CheckpointLoadError::Corrupt(
                super::CheckpointCorruption::Invalid { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn authenticated_header_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(2, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
            bytes[HEADER_PREFIX_LEN + 80 + 4] ^= 1;
        })?;

        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("corrupt header checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
        Ok(())
    }
    #[test]
    fn authenticated_header_tip_and_commitment_mutations_require_resync()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in 0..4 {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(2, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            )?;
            mutate_authenticated_manifest(dir.path(), |manifest| match case {
                0 => manifest.best_header_tip.hash = "00".repeat(32),
                1 => manifest.applied_tip.hash = "00".repeat(32),
                2 => manifest.headers.best_chain_sha256 = "00".repeat(32),
                _ => manifest.headers.applied_chain_sha256 = "00".repeat(32),
            })?;
            let Err(error) = load_checkpoint(dir.path(), config()) else {
                return Err("corrupt checkpoint unexpectedly loaded".into());
            };
            assert!(error.to_string().contains("full resync"));
        }
        Ok(())
    }

    #[test]
    fn authenticated_coinstats_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>>
    {
        for offset in [16, 16 + 768, 16 + 772, 16 + 780, 16 + 788, 16 + 796] {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            )?;
            mutate_authenticated_artifact(dir.path(), COINSTATS_FILE, |bytes| {
                bytes[offset] ^= 1;
            })?;

            let Err(error) = load_checkpoint(dir.path(), config()) else {
                return Err("corrupt CoinStats checkpoint unexpectedly loaded".into());
            };
            assert!(error.to_string().contains("full resync"));
        }
        Ok(())
    }

    #[test]
    fn checkpoint_roundtrip_preserves_record_with_440_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        const OUTPUT_COUNT: u32 = 440;
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let record_txid = Txid(Hash256::from_le_bytes(&[0x44; 32]));
        let mut changes = BlockChanges::default();
        for vout in 0..OUTPUT_COUNT {
            changes.add(UtxoAdd::new(
                OutPoint::new(record_txid, vout),
                TxOut {
                    value: u64::from(vout) + 1,
                    script_pubkey: vec![0x51],
                },
                false,
                0,
            ));
        }
        let utxo = UtxoSet::new();
        utxo.commit_block(&changes, &Hash256::default())?;

        super::write_checkpoint(
            dir.path(),
            config(),
            &RwLock::new(tree),
            &utxo,
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
            return Err("multi-output checkpoint did not restore".into());
        };

        assert_eq!(restored.utxo.len(), usize::try_from(OUTPUT_COUNT)?);
        assert!(
            restored
                .utxo
                .get(&OutPoint::new(record_txid, OUTPUT_COUNT - 1))
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn scanned_trailer_restores_independently_scanned_stats()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = populated_utxo()?;
        let expected = utxo.with_stable_view(|view| scan_coin_stats(view, 0, true))?;
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;

        let root = dir.path().join(CHECKPOINT_ROOT);
        let current: CurrentV1 = serde_json::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
        let generation = root.join(current.directory);
        let mut reader = std::io::BufReader::new(std::fs::File::open(generation.join(UTXO_FILE))?);
        let snapshot = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut reader)?;
        assert_ne!(snapshot.muhash_trailer, [0_u8; 384]);
        assert_eq!(snapshot.muhash_trailer, expected.muhash.finalize());

        let CheckpointLoad::Complete(mut restored) = load_checkpoint(dir.path(), config())? else {
            return Err(std::io::Error::other("scanned generation did not restore").into());
        };
        assert_eq!(restored.coin_stats, expected);

        let listener = CoinStatsListener::new(restored.coin_stats.clone());
        restored.utxo.set_listener(Box::new(listener.clone()));
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 42),
            TxOut {
                value: 123_456,
                script_pubkey: vec![0x51, 0xac],
            },
            false,
            restored.applied_tip.height,
        ));
        restored
            .utxo
            .commit_block(&changes, &Hash256::from_le_bytes(&[0xa5; 32]))?;
        let continued = restored
            .utxo
            .with_stable_view(|view| scan_coin_stats(view, restored.applied_tip.height, true))?;
        assert_eq!(listener.snapshot().to_bytes(), continued.to_bytes());
        Ok(())
    }

    #[test]
    fn authenticated_utxo_value_mutation_requires_resync() -> Result<(), Box<dyn std::error::Error>>
    {
        const FIRST_VALUE_OFFSET: usize = 52 + 45 + 4;

        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        super::write_checkpoint(
            dir.path(),
            config(),
            &RwLock::new(tree),
            &populated_utxo()?,
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;

        mutate_authenticated_artifact(dir.path(), UTXO_FILE, |bytes| {
            bytes[FIRST_VALUE_OFFSET] ^= 1;
        })?;
        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("corrupt UTXO checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unknown_entries_and_symlinks_are_never_deleted() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let listener = CoinStatsListener::new(CoinStats::new());
        super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?;
        let root = dir.path().join(CHECKPOINT_ROOT);
        let unknown = root.join("operator-note");
        fs::write(&unknown, b"keep")?;
        let linked = root.join("gen-18446744073709551615");
        symlink(dir.path().join("outside"), &linked)?;
        let stale_generation = root.join("gen-00000000000000000088");
        let stale_staging = root.join(".gen-18446744073709551615.tmp");
        let stale_current = root.join(".CURRENT-00000000000000000066.tmp");
        fs::create_dir(&stale_generation)?;
        fs::create_dir(&stale_staging)?;
        fs::write(&stale_current, b"stale")?;

        assert_eq!(
            super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
            )?,
            CheckpointWrite::Published { generation: 2 }
        );
        assert!(unknown.exists());
        assert!(fs::symlink_metadata(linked)?.file_type().is_symlink());
        assert!(!stale_generation.exists());
        assert!(!stale_staging.exists());
        assert!(!stale_current.exists());
        let current: CurrentV1 = serde_json::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
        assert!(root.join(&current.directory).is_dir());
        Ok(())
    }

    fn mutate_authenticated_artifact(
        data_dir: &Path,
        artifact: &str,
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = data_dir.join(CHECKPOINT_ROOT);
        let current_path = root.join(CURRENT_FILE);
        let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;

        let generation = root.join(&current.directory);
        let manifest_path = generation.join(MANIFEST_FILE);
        let mut manifest: CheckpointManifestV1 =
            serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let artifact_path = generation.join(artifact);
        let mut bytes = fs::read(&artifact_path)?;
        mutate(&mut bytes);
        fs::write(&artifact_path, &bytes)?;
        let digest = super::hex_encode(&Sha256::digest(&bytes));
        let length = u64::try_from(bytes.len())?;
        match artifact {
            HEADERS_FILE => {
                manifest.headers.bytes = length;
                manifest.headers.sha256 = digest;
            }
            UTXO_FILE => {
                manifest.utxo.bytes = length;
                manifest.utxo.sha256 = digest;
            }
            COINSTATS_FILE => {
                manifest.coinstats.bytes = length;
                manifest.coinstats.sha256 = digest;
            }
            _ => return Err("unknown checkpoint artifact".into()),
        }
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        fs::write(&manifest_path, &manifest_bytes)?;
        current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
        fs::write(current_path, serde_json::to_vec(&current)?)?;
        Ok(())
    }
    fn mutate_authenticated_manifest(
        data_dir: &Path,
        mutate: impl FnOnce(&mut CheckpointManifestV1),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = data_dir.join(CHECKPOINT_ROOT);
        let current_path = root.join(CURRENT_FILE);
        let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
        let manifest_path = root.join(&current.directory).join(MANIFEST_FILE);
        let mut manifest: CheckpointManifestV1 =
            serde_json::from_slice(&fs::read(&manifest_path)?)?;
        mutate(&mut manifest);
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        fs::write(&manifest_path, &manifest_bytes)?;
        current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
        fs::write(current_path, serde_json::to_vec(&current)?)?;
        Ok(())
    }

    fn tip_snapshot(
        tree: &BlockTree,
        point: HeaderCheckpointPoint,
    ) -> Result<TipSnapshot, HeaderCheckpointError> {
        let id = tree
            .lookup(point.hash)
            .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
        let node = tree.node(id)?;
        Ok(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })
    }

    fn config() -> HeaderCheckpointConfig {
        HeaderCheckpointConfig {
            network: NETWORK,
            genesis: NETWORK.genesis_block_hash(),
        }
    }

    fn write_checkpoint(
        tree: &BlockTree,
        best_tip_id: NodeId,
        applied: HeaderCheckpointPoint,
    ) -> Result<(Vec<u8>, HeaderCheckpointWrite), HeaderCheckpointError> {
        let mut bytes = Vec::new();
        let written = write_headers(&mut bytes, tree, config(), best_tip_id, applied)?;
        assert_eq!(u64::try_from(bytes.len()).ok(), Some(written.bytes_written));
        Ok((bytes, written))
    }

    fn chain_with_applied_height(
        best_height: u32,
        applied_height: u32,
    ) -> Result<(BlockTree, NodeId, HeaderCheckpointPoint), HeaderCheckpointError> {
        let genesis = NETWORK.genesis_block().header;
        let mut tree = BlockTree::new();
        let mut current = accept_headers(
            &mut tree,
            core::slice::from_ref(&genesis),
            NETWORK,
            bitcoin_rs_chain::current_unix_seconds(),
        )?[0];
        for height in 1..=best_height {
            let prev = BlockHash(tree.node(current)?.hash);
            let mut header = next_header(prev, height);
            mine_header_to_declared_target(&mut header)?;
            current = accept_headers(
                &mut tree,
                core::slice::from_ref(&header),
                NETWORK,
                bitcoin_rs_chain::current_unix_seconds(),
            )?[0];
        }
        let applied_id = tree
            .node_at_height_from(current, applied_height)
            .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
        let applied = tree.node(applied_id)?;
        let height = applied.height;
        let hash = applied.hash;
        Ok((tree, current, HeaderCheckpointPoint { height, hash }))
    }

    fn next_header(prev_blockhash: BlockHash, height: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: 0x207f_ffff,
            nonce: 0,
        }
    }

    fn mine_header_to_declared_target(header: &mut Header) -> Result<(), HeaderCheckpointError> {
        while !pow_meets_target(header.bits, header.compute_hash().0) {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or_else(|| HeaderCheckpointError::Codec("exhausted test nonce".to_owned()))?;
        }
        Ok(())
    }

    /// Decodes a compact target and checks whether `hash` meets it, mirroring
    /// the chain crate's private `compact_is_met_by`.
    fn pow_meets_target(bits: u32, hash: Hash256) -> bool {
        let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
        let mantissa = u64::from(bits & 0x007f_ffff);
        let negative = mantissa != 0 && bits & 0x0080_0000 != 0;
        let overflow = mantissa != 0
            && (exponent > 34
                || (mantissa > 0xff && exponent > 33)
                || (mantissa > 0xffff && exponent > 32));
        if negative || overflow {
            return false;
        }
        let target = if exponent <= 3 {
            ChainWork::from(mantissa >> (8 * (3 - exponent)))
        } else {
            let shift = 8 * (exponent - 3);
            if shift < 256 {
                ChainWork::from(mantissa) << shift
            } else {
                return false;
            }
        };
        if target == ChainWork::ZERO {
            return false;
        }
        ChainWork::from_le_bytes(hash.to_le_bytes()) <= target
    }

    fn header_from_row(row: &[u8]) -> Result<Header, HeaderCheckpointError> {
        deserialize(row).map_err(|error| HeaderCheckpointError::Codec(error.to_string()))
    }

    fn populated_utxo() -> Result<UtxoSet, bitcoin_rs_utxo::UtxoError> {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[7_u8; 32])), 3),
            TxOut {
                value: 50_000,
                script_pubkey: vec![0x51, 0x21],
            },
            true,
            0,
        ));
        let utxo = UtxoSet::new();
        utxo.commit_block(&changes, &Hash256::default())?;
        Ok(utxo)
    }
}
