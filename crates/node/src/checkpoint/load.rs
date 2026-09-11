//! Authenticated checkpoint loading, strict payload validation, and typed corruption classification.

use super::COINSTATS_ARTIFACT_LEN;
use super::COINSTATS_FILE;
use super::COINSTATS_MAGIC;
use super::COINSTATS_VERSION;
use super::CURRENT_FILE;
use super::CURRENT_FORMAT;
use super::CURRENT_VERSION;
use super::CheckpointCorruption;
use super::CheckpointError;
use super::CheckpointLoadError;
use super::CheckpointManifestV1;
use super::CheckpointTipV1;
use super::CoinStatsArtifactV1;
use super::CurrentV1;
use super::HEADERS_FILE;
use super::MANIFEST_FILE;
use super::MANIFEST_FORMAT;
use super::MANIFEST_VERSION;
use super::MAX_CHECKPOINT_METADATA_BYTES;
use super::MAX_CHECKPOINT_PAYLOAD_BYTES;
use super::RestoredChainstate;
use super::UTXO_FILE;
use super::format::decode_hex;
use super::format::generation_name;
use super::format::hex_encode;
use super::format::network_name;
use super::format::valid_generation_name;
use super::headers;
use super::is_checkpoint_corruption;
use crate::checkpoint::fs::CheckpointRoot;
use crate::checkpoint::fs::open_file;
use crate::checkpoint::fs::read_file;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::read_snapshot_strict_v4_observed;
use bitcoin_rs_utxo::stats::CoinStats;
use bitcoin_rs_utxo::stats::CoinStatsAccumulator;
use bitcoin_rs_utxo::stats::coin_stats::COIN_STATS_ENCODED_LEN;
use cap_std::fs::Dir;
use cap_std::fs::File;
use sha2::Digest;
use sha2::Sha256;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;

pub(super) fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
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

pub(super) fn classify_open_error(operation: &str, error: std::io::Error) -> CheckpointLoadError {
    if is_checkpoint_corruption(&error) {
        return corrupt_checkpoint(format!("{operation} failed: {error}"));
    }
    CheckpointLoadError::Io(error)
}

pub(super) fn checkpoint_file_error(name: &str, error: std::io::Error) -> CheckpointError {
    if is_checkpoint_corruption(&error) {
        return CheckpointError::Invalid(format!("checkpoint file {name:?} failed: {error}"));
    }
    CheckpointError::Io(error)
}

pub(super) fn classify_checkpoint_io(error: std::io::Error) -> CheckpointLoadError {
    if is_checkpoint_corruption(&error) {
        return corrupt_checkpoint(error.to_string());
    }
    CheckpointLoadError::Io(error)
}

pub(super) fn corrupt_checkpoint(reason: impl Into<String>) -> CheckpointLoadError {
    CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid {
        reason: reason.into(),
    })
}

pub(super) fn read_current(root: &CheckpointRoot) -> Result<Option<CurrentV1>, CheckpointError> {
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

pub(super) fn read_manifest(
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

pub(super) fn load_headers(
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

pub(super) fn load_payloads(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    mut headers: headers::RestoredHeaders,
) -> Result<RestoredChainstate, CheckpointError> {
    let chain_tx_count = manifest.applied_tip.chain_tx_count;
    let (utxo, coin_stats) = load_payloads_inner(generation_dir, manifest, &headers)?;
    // Header reconstruction initializes counts to zero. Restore the exact
    // cumulative count on the applied tip; ancestor counts remain unknown.
    let mut cursor = Some(headers.applied_tip_id);
    while let Some(node_id) = cursor {
        let parent = headers
            .tree
            .node(node_id)
            .map_err(|error| CheckpointError::Header(error.into()))?
            .parent;
        headers.tree.restore_chain_tx_count(
            node_id,
            if node_id == headers.applied_tip_id {
                chain_tx_count
            } else {
                0
            },
        )?;
        cursor = parent;
    }
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

pub(super) fn load_payloads_inner(
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

pub(super) fn read_checkpoint_snapshot(
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

pub(super) fn validate_coinstats_manifest(
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

pub(super) fn open_regular_file(
    dir: &Dir,
    name: &str,
    expected_len: u64,
) -> Result<File, CheckpointError> {
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

pub(super) fn verify_artifact(
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

pub(super) fn decode_coinstats_artifact(bytes: &[u8]) -> Result<CoinStats, CheckpointError> {
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

pub(super) fn require_filename(actual: &str, expected: &str) -> Result<(), CheckpointError> {
    if actual != expected || Path::new(actual).components().count() != 1 {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint artifact filename {actual:?} is not {expected:?}"
        )));
    }
    Ok(())
}

pub(super) fn parse_tip(
    tip: &CheckpointTipV1,
) -> Result<headers::HeaderCheckpointTip, CheckpointError> {
    Ok(headers::HeaderCheckpointTip {
        height: tip.height,
        hash: Hash256::from_str_be(&tip.hash)
            .map_err(|error| CheckpointError::Invalid(error.to_string()))?,
        chainwork: ChainWork::from_be_bytes(decode_hex::<32>(&tip.chainwork)?),
    })
}
