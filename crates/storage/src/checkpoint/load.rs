use super::format::{decode_hex, generation_name, hex_encode, network_name, valid_generation_name};
use super::fs::{CheckpointRoot, open_file, read_file};
use super::{
    COINSTATS_ARTIFACT_LEN, COINSTATS_MAGIC, COINSTATS_VERSION, CURRENT_FILE, CURRENT_FORMAT,
    CURRENT_VERSION, CheckpointError, CheckpointIdentity, CheckpointLoadError,
    CheckpointManifestV1, CurrentV1, MANIFEST_FILE, MANIFEST_FORMAT, MANIFEST_VERSION,
    MAX_CHECKPOINT_METADATA_BYTES, MAX_CHECKPOINT_PAYLOAD_BYTES,
};
use cap_std::fs::{Dir, File};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Maps checkpoint errors into corruption or ordinary I/O load failures.
pub fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
    match error {
        CheckpointError::Io(error) => classify_checkpoint_io(error),
        other => corrupt_checkpoint(other.to_string()),
    }
}
pub(crate) fn classify_open_error(operation: &str, error: std::io::Error) -> CheckpointLoadError {
    if is_checkpoint_corruption(&error) {
        corrupt_checkpoint(format!("{operation} failed: {error}"))
    } else {
        CheckpointLoadError::Io(error)
    }
}
pub(crate) fn checkpoint_file_error(name: &str, error: std::io::Error) -> CheckpointError {
    if is_checkpoint_corruption(&error) {
        CheckpointError::Invalid(format!("checkpoint file {name:?} failed: {error}"))
    } else {
        CheckpointError::Io(error)
    }
}
/// Classifies checkpoint filesystem errors as corruption or ordinary I/O.
pub fn classify_checkpoint_io(error: std::io::Error) -> CheckpointLoadError {
    if is_checkpoint_corruption(&error) {
        corrupt_checkpoint(error.to_string())
    } else {
        CheckpointLoadError::Io(error)
    }
}
/// Wraps a validation reason as a fail-closed checkpoint corruption error.
pub fn corrupt_checkpoint(reason: impl Into<String>) -> CheckpointLoadError {
    CheckpointLoadError::Corrupt(reason.into())
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

pub(crate) fn read_current(root: &CheckpointRoot) -> Result<Option<CurrentV1>, CheckpointError> {
    let bytes = match read_file(root.dir(), CURRENT_FILE, MAX_CHECKPOINT_METADATA_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(checkpoint_file_error(CURRENT_FILE, e)),
    };
    let current: CurrentV1 = serde_json::from_slice(&bytes)?;
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
    let expected = generation_name(current.generation);
    if current.directory != expected || !valid_generation_name(&current.directory) {
        return Err(CheckpointError::Invalid(
            "CURRENT generation directory does not match its generation".to_owned(),
        ));
    }
    decode_hex::<32>(&current.manifest_sha256)?;
    Ok(Some(current))
}

impl CurrentV1 {
    /// Returns the immutable reference carried by this validated pointer.
    pub fn reference(&self) -> Result<super::CheckpointReference, CheckpointError> {
        Ok(super::CheckpointReference {
            generation: self.generation,
            manifest_sha256: decode_hex(&self.manifest_sha256)?,
        })
    }
}

/// Reads and authenticates the manifest against its owner's reference and identity.
pub fn read_manifest(
    generation_dir: &Dir,
    reference: &super::CheckpointReference,
    identity: CheckpointIdentity,
) -> Result<CheckpointManifestV1, CheckpointError> {
    let bytes = read_file(generation_dir, MANIFEST_FILE, MAX_CHECKPOINT_METADATA_BYTES)
        .map_err(|e| checkpoint_file_error(MANIFEST_FILE, e))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != reference.manifest_sha256 {
        return Err(CheckpointError::Invalid(
            "manifest SHA256 does not match checkpoint reference".to_owned(),
        ));
    }
    let manifest: CheckpointManifestV1 = serde_json::from_slice(&bytes)?;
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
    if manifest.generation != reference.generation {
        return Err(CheckpointError::Invalid(
            "manifest generation does not match checkpoint reference".to_owned(),
        ));
    }
    if manifest.network != network_name(identity.network)
        || manifest.network_magic != hex_encode(&identity.network.magic())
        || manifest.genesis_hash != identity.genesis.to_string_be()
    {
        return Err(CheckpointError::Invalid(
            "checkpoint network, magic, or genesis does not match configuration".to_owned(),
        ));
    }
    Ok(manifest)
}

pub(crate) fn open_regular_file(
    dir: &Dir,
    name: &str,
    expected_len: u64,
) -> Result<File, CheckpointError> {
    let file = open_file(dir, name).map_err(|e| checkpoint_file_error(name, e))?;
    let actual = file
        .metadata()
        .map_err(|e| checkpoint_file_error(name, e))?
        .len();
    if actual != expected_len {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact {name:?} has {actual} bytes, expected {expected_len}"
        )));
    }
    Ok(file)
}
/// Verifies an artifact's exact length and SHA-256 digest before rewinding it.
pub fn verify_artifact(
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
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| checkpoint_file_error(name, e))?;
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
        .map_err(|e| checkpoint_file_error(name, e))?;
    Ok(file)
}
/// Rejects path components and names that differ from the expected artifact.
pub fn require_filename(actual: &str, expected: &str) -> Result<(), CheckpointError> {
    if actual != expected || Path::new(actual).components().count() != 1 {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact filename {actual:?} is not {expected:?}"
        )));
    }
    Ok(())
}
/// Validates the fixed 820-byte `CoinStats` envelope and returns its payload.
pub fn coinstats_artifact_payload(bytes: &[u8]) -> Result<&[u8], CheckpointError> {
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
    if payload_len != super::COINSTATS_PAYLOAD_LEN {
        return Err(CheckpointError::Invalid(format!(
            "CoinStats artifact declares payload length {payload_len}"
        )));
    }
    Ok(&bytes[16..])
}

/// Result of probing the data directory for a committed checkpoint.
pub enum CheckpointOpen {
    /// No checkpoint has committed; the node must start cold.
    Cold,
    /// The owner identifies a generation directory and its expected manifest digest.
    Selected {
        /// Open generation directory capability.
        generation_dir: Dir,
        /// Immutable reference supplied by CURRENT or the durable head.
        reference: super::CheckpointReference,
    },
}
/// Opens a generation selected by an authoritative durable-head reference.
/// CURRENT may be ahead or absent after an interrupted publication.
pub fn open_checkpoint_generation_at(
    data_dir: &Dir,
    root_name: &str,
    reference: super::CheckpointReference,
) -> Result<CheckpointOpen, CheckpointLoadError> {
    let root = CheckpointRoot::open_existing(data_dir, root_name)
        .map_err(|error| classify_open_error("open checkpoint root", error))?
        .ok_or_else(|| corrupt_checkpoint("referenced checkpoint root is missing"))?;
    let directory = generation_name(reference.generation);
    let generation_dir = root
        .open_dir(&directory)
        .map_err(|error| classify_open_error("open referenced checkpoint generation", error))?;
    Ok(CheckpointOpen::Selected {
        generation_dir,
        reference,
    })
}

/// Opens and validates the checkpoint named by the data directory's CURRENT.
pub fn open_current_checkpoint(data_dir: &Dir) -> Result<CheckpointOpen, CheckpointLoadError> {
    open_current_checkpoint_at(data_dir, super::CHECKPOINT_ROOT)
}

/// Opens the published checkpoint in an explicit namespace.
pub fn open_current_checkpoint_at(
    data_dir: &Dir,
    root_name: &str,
) -> Result<CheckpointOpen, CheckpointLoadError> {
    let root = match CheckpointRoot::open_existing(data_dir, root_name) {
        Ok(Some(root)) => root,
        Ok(None) => return Ok(CheckpointOpen::Cold),
        Err(e) => return Err(classify_open_error("open checkpoint root", e)),
    };
    let current = match read_current(&root) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(CheckpointOpen::Cold),
        Err(e) => return Err(classify_checkpoint_error(e)),
    };
    let generation_dir = root.open_dir(&current.directory).map_err(|e| {
        classify_open_error(
            &format!("open checkpoint generation {}", current.directory),
            e,
        )
    })?;
    Ok(CheckpointOpen::Selected {
        generation_dir,
        reference: current.reference().map_err(classify_checkpoint_error)?,
    })
}
