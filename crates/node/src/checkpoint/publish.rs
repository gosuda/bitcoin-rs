//! One checkpoint publication transaction: prepare artifacts, sync, publish CURRENT, then retire old generations.

use super::CHECKPOINT_ROOT;
use super::COINSTATS_CODEC;
use super::COINSTATS_FILE;
use super::COINSTATS_MAGIC;
use super::COINSTATS_PAYLOAD_LEN;
use super::COINSTATS_VERSION;
use super::CURRENT_FORMAT;
use super::CURRENT_VERSION;
use super::CheckpointError;
use super::CheckpointFailpoint;
use super::CheckpointManifestV1;
use super::CheckpointTipV1;
use super::CheckpointWrite;
use super::CoinStatsArtifactV1;
use super::CurrentV1;
use super::GenerationPaths;
use super::HEADER_CODEC;
use super::HEADERS_FILE;
use super::HashingWriter;
use super::HeadersArtifactV1;
use super::MANIFEST_FILE;
use super::MANIFEST_FORMAT;
use super::MANIFEST_VERSION;
use super::UTXO_CODEC;
use super::UTXO_FILE;
use super::UTXO_VERSION;
use super::UtxoArtifactV1;
use super::format::generation_name;
use super::format::hex_encode;
use super::format::network_name;
use super::format::valid_current_temp_name;
use super::format::valid_generation_name;
use super::format::valid_staging_name;
use super::headers;
use super::io::rename_current;
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
use super::io::rename_generation;
use super::io::sync_checkpoint_dir;
use super::io::sync_file;
use super::io::sync_root;
use super::io::write_file;
use super::load::read_current;
use crate::checkpoint::fs::CheckpointRoot;
use crate::checkpoint::fs::create_file;
use crate::checkpoint::fs::remove_known_dir;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::CoinStatsAccumulator;
use bitcoin_rs_utxo::stats::CoinStatsListener;
use bitcoin_rs_utxo::write_snapshot_observed;
use cap_std::fs::Dir;
use parking_lot::RwLock;
use sha2::Digest;
use sha2::Sha256;
use std::io::Write;

pub(super) fn checkpoint_best_tip_id(
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
pub(super) fn write_checkpoint_inner(
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
    super::io::injected_io(failpoint, CheckpointFailpoint::GenerationRename)?;
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

pub(super) fn allocate_generation(
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

pub(super) fn generation_paths(generation: u64) -> GenerationPaths {
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

pub(super) fn cleanup_after_publication(root: &CheckpointRoot, current: &str) {
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

pub(super) fn manifest_tip(
    tip: headers::HeaderCheckpointTip,
    chain_tx_count: u64,
) -> CheckpointTipV1 {
    let chainwork: [u8; 32] = tip.chainwork.to_be_bytes();
    CheckpointTipV1 {
        height: tip.height,
        hash: tip.hash.to_string_be(),
        chainwork: hex_encode(&chainwork),
        chain_tx_count,
    }
}
