mod format;
pub mod fs;
mod load;
mod publish;

#[cfg(test)]
mod tests;

pub use format::{decode_hex, network_name};
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

pub const CHECKPOINT_ROOT: &str = "chainstate-checkpoints";
pub const HISTORICAL_CHECKPOINT_ROOT: &str = "assumeutxo-historical-checkpoints";
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointReference {
    pub generation: u64,
    pub manifest_sha256: [u8; 32],
}

#[derive(Clone, Copy)]
pub enum CheckpointRetention {
    Replace,
    UntilReferenced,
}
pub const CURRENT_FILE: &str = "CURRENT";
pub const MANIFEST_FILE: &str = "manifest-v1.json";
pub const HEADERS_FILE: &str = "headers-v1.dat";
pub const UTXO_FILE: &str = "utxo-v4.dat";
pub const COINSTATS_FILE: &str = "coinstats-v1.dat";
pub(crate) const CURRENT_FORMAT: &str = "bitcoin-rs-chainstate-current";
pub const MANIFEST_FORMAT: &str = "bitcoin-rs-chainstate-checkpoint";
pub const HEADER_CODEC: &str = "bitcoin-rs-canonical-headers";
pub const UTXO_CODEC: &str = "bitcoin-rs-utxo-spendable-v1";
pub const COINSTATS_CODEC: &str = "bitcoin-rs-coinstats-v1";
pub(crate) const CURRENT_VERSION: u32 = 1;
pub const MANIFEST_VERSION: u32 = 1;
pub const UTXO_VERSION: u32 = 4;
pub const COINSTATS_VERSION: u32 = 1;
pub const COINSTATS_MAGIC: [u8; 8] = *b"BRSSTAT\0";
/// `CoinStats` payload length in bytes, excluding its 16-byte header.
pub const COINSTATS_PAYLOAD_LEN: u32 = 804;
pub const COINSTATS_ARTIFACT_LEN: u64 = 820;
pub(crate) const MAX_CHECKPOINT_PAYLOAD_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
pub(crate) const MAX_CHECKPOINT_METADATA_BYTES: u64 = 1024 * 1024;
const CHECKPOINT_WRITE_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentV1 {
    pub format: String,
    pub version: u32,
    pub generation: u64,
    pub directory: String,
    pub manifest_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTipV1 {
    pub height: u32,
    /// Big-endian block hash encoded as lowercase hex.
    pub hash: String,
    /// Chainwork encoded as lowercase hex.
    pub chainwork: String,
    pub chain_tx_count: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersArtifactV1 {
    pub file: String,
    pub codec: String,
    pub version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub header_count: u64,
    pub best_chain_sha256: String,
    pub applied_chain_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoArtifactV1 {
    pub file: String,
    pub codec: String,
    pub version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub record_count: u64,
    pub output_count: u64,
    pub muhash_trailer_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoinStatsArtifactV1 {
    pub file: String,
    pub codec: String,
    pub version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub height: u32,
    /// Total value of unspent outputs in satoshis.
    pub total_amount: u64,
    pub bogo_size: u64,
    pub tx_count: u64,
    pub utxo_count: u64,
    /// `MuHash` value encoded as lowercase hex.
    pub muhash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifestV1 {
    pub format: String,
    pub version: u32,
    pub generation: u64,
    pub network: String,
    /// Network magic encoded as lowercase hex.
    pub network_magic: String,
    /// Genesis block hash encoded as lowercase hex.
    pub genesis_hash: String,
    pub applied_tip: CheckpointTipV1,
    pub best_header_tip: CheckpointTipV1,
    pub headers: HeadersArtifactV1,
    pub utxo: UtxoArtifactV1,
    pub coinstats: CoinStatsArtifactV1,
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint JSON failed: {0}")]
    Json(#[from] sonic_rs::Error),
    #[error("checkpoint invariant failed: {0}")]
    Invalid(String),
}
#[derive(Debug, Error)]
pub enum CheckpointLoadError {
    #[error(
        "corrupt current-schema checkpoint: {0}; remove or replace the datadir and restart to perform a full resync"
    )]
    Corrupt(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
#[cfg(any(test, feature = "test-seam"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointFailpoint {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointIdentity {
    pub network: bitcoin_rs_primitives::Network,
    pub genesis: bitcoin_rs_primitives::Hash256,
}

pub use load::{
    CheckpointOpen, classify_checkpoint_error, classify_checkpoint_io, coinstats_artifact_payload,
    corrupt_checkpoint, open_current_checkpoint, read_manifest, require_filename, verify_artifact,
};
#[cfg(any(test, feature = "test-seam"))]
pub use publish::begin_publication_with_failpoint;
pub use publish::{ArtifactDigest, CheckpointStage, begin_publication, commit_publication};
