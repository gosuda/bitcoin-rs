//! Filesystem, format, and atomic publication primitives for chainstate checkpoints.

mod format;
pub mod fs;
mod io;
mod load;
mod publish;

#[cfg(test)]
mod tests;

pub use format::{decode_hex, hex_encode, network_name};
pub use fs::{
    CURRENT_SCHEMA_FILE, create_file, current_schema_bytes, ensure_current_schema, open_data_dir,
    read_file, sync_dir,
};
pub use load::open_checkpoint_generation_at;
pub use load::open_current_checkpoint_at;
pub use publish::begin_publication_at;
#[cfg(any(test, feature = "test-seam"))]
pub use publish::begin_publication_at_with_failpoint;
pub use publish::clear_checkpoint_generations_at;
pub use publish::retire_checkpoint_generations_at;

use cap_std::fs::File;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Write};
use thiserror::Error;

/// Root directory containing checkpoint generations.
pub const CHECKPOINT_ROOT: &str = "chainstate-checkpoints";
/// Root containing checkpoints for the background `AssumeUTXO` chainstate.
pub const HISTORICAL_CHECKPOINT_ROOT: &str = "assumeutxo-historical-checkpoints";
/// Immutable checkpoint identity and publication-time manifest digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointReference {
    /// Published generation.
    pub generation: u64,
    /// SHA-256 of the manifest bytes synchronized by publication.
    pub manifest_sha256: [u8; 32],
}

/// When publication may retire older generations.
#[derive(Clone, Copy)]
pub enum CheckpointRetention {
    /// CURRENT is the owner; retire older generations after publishing it.
    Replace,
    /// A separate durable reference owns recovery; retirement follows its commit.
    UntilReferenced,
}
/// Published pointer file for the active checkpoint generation.
pub const CURRENT_FILE: &str = "CURRENT";
/// Manifest filename inside each checkpoint generation.
pub const MANIFEST_FILE: &str = "manifest-v1.json";
/// Canonical header artifact filename.
pub const HEADERS_FILE: &str = "headers-v1.dat";
/// UTXO artifact filename.
pub const UTXO_FILE: &str = "utxo-v4.dat";
/// Coin statistics artifact filename.
pub const COINSTATS_FILE: &str = "coinstats-v1.dat";
/// Expected format identifier for the CURRENT pointer.
pub(crate) const CURRENT_FORMAT: &str = "bitcoin-rs-chainstate-current";
/// Expected format identifier for checkpoint manifests.
pub const MANIFEST_FORMAT: &str = "bitcoin-rs-chainstate-checkpoint";
/// Codec identifier for canonical header artifacts.
pub const HEADER_CODEC: &str = "bitcoin-rs-canonical-headers";
/// Codec identifier for spendable UTXO artifacts.
pub const UTXO_CODEC: &str = "bitcoin-rs-utxo-spendable-v1";
/// Codec identifier for `CoinStats` artifacts.
pub const COINSTATS_CODEC: &str = "bitcoin-rs-coinstats-v1";
/// CURRENT pointer schema version.
pub(crate) const CURRENT_VERSION: u32 = 1;
/// Checkpoint manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;
/// UTXO artifact schema version.
pub const UTXO_VERSION: u32 = 4;
/// `CoinStats` artifact schema version.
pub const COINSTATS_VERSION: u32 = 1;
/// Magic bytes at the start of a `CoinStats` artifact.
pub const COINSTATS_MAGIC: [u8; 8] = *b"BRSSTAT\0";
/// `CoinStats` payload length in bytes, excluding its 16-byte header.
pub const COINSTATS_PAYLOAD_LEN: u32 = 804;
/// Complete `CoinStats` artifact length in bytes.
pub const COINSTATS_ARTIFACT_LEN: u64 = 820;
/// Maximum accepted checkpoint artifact payload size in bytes.
pub(crate) const MAX_CHECKPOINT_PAYLOAD_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
/// Maximum accepted checkpoint metadata size in bytes.
pub(crate) const MAX_CHECKPOINT_METADATA_BYTES: u64 = 1024 * 1024;
const CHECKPOINT_WRITE_BUFFER_SIZE: usize = 64 * 1024;

/// Authenticated pointer to the currently published checkpoint generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentV1 {
    /// Serialized CURRENT format identifier.
    pub format: String,
    /// CURRENT pointer schema version.
    pub version: u32,
    /// Published checkpoint generation number.
    pub generation: u64,
    /// Generation directory named by `generation`.
    pub directory: String,
    /// SHA-256 digest of the generation manifest, in lowercase hex.
    pub manifest_sha256: String,
}
/// Chain tip identity and cumulative transaction count recorded in a manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTipV1 {
    /// Block height represented by this tip.
    pub height: u32,
    /// Big-endian block hash encoded as lowercase hex.
    pub hash: String,
    /// Chainwork encoded as lowercase hex.
    pub chainwork: String,
    /// Cumulative transaction count of the chain through this tip.
    pub chain_tx_count: u64,
}
/// Header artifact metadata authenticated by the checkpoint manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersArtifactV1 {
    /// Artifact filename relative to its generation directory.
    pub file: String,
    /// Header codec identifier.
    pub codec: String,
    /// Header artifact schema version.
    pub version: u32,
    /// Artifact length in bytes.
    pub bytes: u64,
    /// SHA-256 digest of the artifact, in lowercase hex.
    pub sha256: String,
    /// Number of encoded headers.
    pub header_count: u64,
    /// Digest of the best-header chain.
    pub best_chain_sha256: String,
    /// Digest of the applied-tip chain.
    pub applied_chain_sha256: String,
}
/// UTXO artifact metadata authenticated by the checkpoint manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoArtifactV1 {
    /// Artifact filename relative to its generation directory.
    pub file: String,
    /// UTXO codec identifier.
    pub codec: String,
    /// UTXO artifact schema version.
    pub version: u32,
    /// Artifact length in bytes.
    pub bytes: u64,
    /// SHA-256 digest of the artifact, in lowercase hex.
    pub sha256: String,
    /// Number of transaction-level UTXO records.
    pub record_count: u64,
    /// Number of unspent outputs represented.
    pub output_count: u64,
    /// SHA-256 digest of the `MuHash` trailer.
    pub muhash_trailer_sha256: String,
}
/// `CoinStats` artifact metadata authenticated by the checkpoint manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoinStatsArtifactV1 {
    /// Artifact filename relative to its generation directory.
    pub file: String,
    /// `CoinStats` codec identifier.
    pub codec: String,
    /// `CoinStats` artifact schema version.
    pub version: u32,
    /// Artifact length in bytes.
    pub bytes: u64,
    /// SHA-256 digest of the artifact, in lowercase hex.
    pub sha256: String,
    /// Block height used for the statistics snapshot.
    pub height: u32,
    /// Total value of unspent outputs in satoshis.
    pub total_amount: u64,
    /// `CoinStats` bogo-size aggregate.
    pub bogo_size: u64,
    /// Cumulative transaction count at `height`.
    pub tx_count: u64,
    /// Number of unspent transaction outputs.
    pub utxo_count: u64,
    /// `MuHash` value encoded as lowercase hex.
    pub muhash: String,
}
/// Authenticated metadata for one complete checkpoint generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifestV1 {
    /// Manifest format identifier.
    pub format: String,
    /// Manifest schema version.
    pub version: u32,
    /// Generation number named by this manifest.
    pub generation: u64,
    /// Network name used to create the checkpoint.
    pub network: String,
    /// Network magic encoded as lowercase hex.
    pub network_magic: String,
    /// Genesis block hash encoded as lowercase hex.
    pub genesis_hash: String,
    /// Applied chain tip and transaction count.
    pub applied_tip: CheckpointTipV1,
    /// Best known header tip.
    pub best_header_tip: CheckpointTipV1,
    /// Authenticated header artifact metadata.
    pub headers: HeadersArtifactV1,
    /// Authenticated UTXO artifact metadata.
    pub utxo: UtxoArtifactV1,
    /// Authenticated `CoinStats` artifact metadata.
    pub coinstats: CoinStatsArtifactV1,
}

/// Errors raised while reading or publishing checkpoint files.
#[derive(Debug, Error)]
pub enum CheckpointError {
    /// Filesystem operation failed.
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encoding or decoding failed.
    #[error("checkpoint JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// A checkpoint invariant or authenticated value is invalid.
    #[error("checkpoint invariant failed: {0}")]
    Invalid(String),
}
/// Errors returned while opening the current checkpoint.
#[derive(Debug, Error)]
pub enum CheckpointLoadError {
    /// The checkpoint failed a current-schema integrity or format check and
    /// cannot be trusted; a full resync is required.
    #[error(
        "corrupt current-schema checkpoint: {0}; remove or replace the datadir and restart to perform a full resync"
    )]
    Corrupt(String),
    /// Opening or reading the checkpoint failed with I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
/// Failpoint boundaries used to test checkpoint publication recovery.
#[cfg(any(test, feature = "test-seam"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointFailpoint {
    /// Before headers bytes are written.
    HeadersWrite,
    /// Before headers are synchronized.
    HeadersSync,
    /// Before UTXO bytes are written.
    UtxoWrite,
    /// Before UTXO bytes are synchronized.
    UtxoSync,
    /// Before `CoinStats` bytes are written.
    CoinStatsWrite,
    /// Before `CoinStats` bytes are synchronized.
    CoinStatsSync,
    /// Before the manifest is written.
    ManifestWrite,
    /// Before the manifest is synchronized.
    ManifestSync,
    /// Before staging directory synchronization.
    StageSync,
    /// Before generation publication rename.
    GenerationRename,
    /// Before generation-root synchronization.
    GenerationRootSync,
    /// Before temporary CURRENT bytes are written.
    CurrentTempWrite,
    /// Before temporary CURRENT is synchronized.
    CurrentTempSync,
    /// Before CURRENT publication rename.
    CurrentRename,
    /// Before final checkpoint-root synchronization.
    CurrentRootSync,
}
pub(crate) struct GenerationPaths {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    pub staging: String,
    pub final_dir: String,
    pub current_temp: String,
    pub directory: String,
}
pub(crate) struct HashingWriter<'a> {
    file: BufWriter<&'a mut File>,
    hasher: Sha256,
    bytes: u64,
    #[cfg(any(test, feature = "test-seam"))]
    fail: bool,
}
impl<'a> HashingWriter<'a> {
    /// The `configured`/`boundary` parameters exist only under
    /// `test`/`test-seam` and arm the write-failure injection.
    pub(crate) fn new(
        file: &'a mut File,
        #[cfg(any(test, feature = "test-seam"))] configured: Option<CheckpointFailpoint>,
        #[cfg(any(test, feature = "test-seam"))] boundary: Option<CheckpointFailpoint>,
    ) -> Self {
        Self {
            file: BufWriter::with_capacity(CHECKPOINT_WRITE_BUFFER_SIZE, file),
            hasher: Sha256::new(),
            bytes: 0,
            #[cfg(any(test, feature = "test-seam"))]
            fail: configured.is_some() && configured == boundary,
        }
    }

    pub(crate) fn finish(mut self) -> std::io::Result<(u64, [u8; 32])> {
        self.file.flush()?;
        Ok((self.bytes, self.hasher.finalize().into()))
    }
}
impl Write for HashingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(any(test, feature = "test-seam"))]
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

/// Network and genesis identity required to authenticate a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointIdentity {
    /// Network whose magic and spelling must match the manifest.
    pub network: bitcoin_rs_primitives::Network,
    /// Genesis hash that must match the manifest.
    pub genesis: bitcoin_rs_primitives::Hash256,
}

pub use load::{
    CheckpointOpen, classify_checkpoint_error, classify_checkpoint_io, coinstats_artifact_payload,
    corrupt_checkpoint, open_current_checkpoint, read_manifest, require_filename, verify_artifact,
};
#[cfg(any(test, feature = "test-seam"))]
pub use publish::begin_publication_with_failpoint;
pub use publish::{ArtifactDigest, CheckpointStage, begin_publication, commit_publication};
