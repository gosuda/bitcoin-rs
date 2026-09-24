//! Checkpoint formats, loading, and publication.

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainTxCount;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_ARTIFACT_LEN;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_CODEC;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_FILE;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_MAGIC;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_PAYLOAD_LEN;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_VERSION;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::CURRENT_FILE;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::CheckpointCorruption;
use bitcoin_rs_storage::checkpoint::CheckpointError as StoreError;
pub(crate) use bitcoin_rs_storage::checkpoint::CheckpointFailpoint;
use bitcoin_rs_storage::checkpoint::CheckpointIdentity;
pub(crate) use bitcoin_rs_storage::checkpoint::CheckpointLoadError;
pub(crate) use bitcoin_rs_storage::checkpoint::CheckpointManifestV1;
pub(crate) use bitcoin_rs_storage::checkpoint::CheckpointOpen;
pub(crate) use bitcoin_rs_storage::checkpoint::CheckpointTipV1;
pub(crate) use bitcoin_rs_storage::checkpoint::CoinStatsArtifactV1;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::CurrentV1;
pub(crate) use bitcoin_rs_storage::checkpoint::HEADER_CODEC;
pub(crate) use bitcoin_rs_storage::checkpoint::HEADERS_FILE;
pub(crate) use bitcoin_rs_storage::checkpoint::HeadersArtifactV1;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::MANIFEST_FILE;
pub(crate) use bitcoin_rs_storage::checkpoint::MANIFEST_FORMAT;
pub(crate) use bitcoin_rs_storage::checkpoint::MANIFEST_VERSION;
pub(crate) use bitcoin_rs_storage::checkpoint::UTXO_CODEC;
pub(crate) use bitcoin_rs_storage::checkpoint::UTXO_FILE;
pub(crate) use bitcoin_rs_storage::checkpoint::UTXO_VERSION;
pub(crate) use bitcoin_rs_storage::checkpoint::UtxoArtifactV1;
use bitcoin_rs_storage::checkpoint::begin_publication;
pub(crate) use bitcoin_rs_storage::checkpoint::classify_checkpoint_io;
use bitcoin_rs_storage::checkpoint::coinstats_artifact_payload;
use bitcoin_rs_storage::checkpoint::commit_publication;
pub(crate) use bitcoin_rs_storage::checkpoint::corrupt_checkpoint;
use bitcoin_rs_storage::checkpoint::decode_hex;
pub(crate) use bitcoin_rs_storage::checkpoint::hex_encode;
use bitcoin_rs_storage::checkpoint::network_name;
use bitcoin_rs_storage::checkpoint::open_current_checkpoint;
#[cfg(test)]
use bitcoin_rs_storage::checkpoint::open_data_dir;
use bitcoin_rs_storage::checkpoint::read_manifest;
use bitcoin_rs_storage::checkpoint::require_filename;
use bitcoin_rs_storage::checkpoint::verify_artifact;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::read_snapshot_strict_v4_observed;
use bitcoin_rs_utxo::stats::CoinStats;
use bitcoin_rs_utxo::stats::CoinStatsAccumulator;
use bitcoin_rs_utxo::stats::CoinStatsListener;
use bitcoin_rs_utxo::stats::coin_stats::COIN_STATS_ENCODED_LEN;
use bitcoin_rs_utxo::write_snapshot_observed;
use cap_std::fs::Dir;
use cap_std::fs::File;
use parking_lot::RwLock;
use sha2::Digest;
use sha2::Sha256;
use std::io::BufReader;
use std::io::Read;
#[cfg(test)]
use std::path::Path;
use thiserror::Error;

#[path = "checkpoint_publisher.rs"]
pub(crate) mod publisher;

fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
    match error {
        // Direct checkpoint I/O or domain I/O failed transiently.
        CheckpointError::Io(error)
        | CheckpointError::FullRevalidationMarker(error)
        | CheckpointError::Utxo(bitcoin_rs_utxo::UtxoError::Io(error))
        | CheckpointError::Storage(bitcoin_rs_storage::StorageError::Io(error)) => {
            classify_checkpoint_io(error)
        }
        // Storage protocol validation failed and owns its classification.
        CheckpointError::Store(error) => {
            bitcoin_rs_storage::checkpoint::classify_checkpoint_error(error)
        }
        // Domain decoding or consistency validation failed.
        error => corrupt_checkpoint(error.to_string()),
    }
}

#[path = "checkpoint_headers.rs"]
pub(crate) mod headers;

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
    /// Cumulative transaction count through `applied_tip`.
    pub(crate) chain_tx_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointWrite {
    SkippedNoAppliedTip,
    Published { generation: u64 },
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("header checkpoint failed: {0}")]
    Header(#[from] headers::HeaderCheckpointError),
    #[error("checkpoint chain state failed: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error("UTXO checkpoint failed: {0}")]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error("CoinStats checkpoint decode failed: {0}")]
    CoinStats(#[from] bitcoin_rs_utxo::stats::CoinStatsDecodeError),
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint block-body durability failed: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("checkpoint refused while disconnect of block {hash} at height {height} is in flight")]
    DisconnectInFlight { hash: Hash256, height: u32 },
    #[error(
        "checkpoint of tip {tip} at height {tip_height} is ahead of the durable head {head} at height {head_height}"
    )]
    AheadOfDurableHead {
        tip: Hash256,
        tip_height: u32,
        head: Hash256,
        head_height: u32,
    },
    /// The replacement checkpoint's `CURRENT` is already durable; retiring the sticky
    /// full-revalidation marker failed. Retryable I/O owned by the checkpoint worker,
    /// not checkpoint corruption.
    #[error("failed to retire full-revalidation marker: {0}")]
    FullRevalidationMarker(std::io::Error),
}

#[allow(clippy::as_conversions)]
const _: () = assert!(COINSTATS_PAYLOAD_LEN as usize == COIN_STATS_ENCODED_LEN);

pub(crate) fn load_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = open_current_checkpoint(data_dir)?;
    let CheckpointOpen::Current {
        generation_dir,
        current,
    } = opened
    else {
        return Ok(CheckpointLoad::Cold);
    };
    let manifest = read_manifest(
        &generation_dir,
        &current,
        CheckpointIdentity {
            network: config.network,
            genesis: config.genesis,
        },
    )
    .map_err(|error| classify_checkpoint_error(error.into()))?;
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
        // Header codec reported a checkpoint version newer than this node.
        Err(CheckpointError::Header(headers::HeaderCheckpointError::UnsupportedVersion {
            actual,
        })) => {
            return Err(corrupt_checkpoint(format!(
                "headers checkpoint version {actual} is not current"
            )));
        }
        // Header loading failed for a non-version corruption or I/O reason.
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
        // Payload loading failed after authenticated metadata checks.
        Err(error) => Err(classify_checkpoint_error(error)),
    }
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
pub(crate) fn load_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let data_dir = match open_data_dir(data_dir) {
        Ok(data_dir) => data_dir,
        Err(_) => return Ok(CheckpointLoad::Cold),
    };
    load_checkpoint_from_dir(&data_dir, config)
}

#[cfg(test)]
std::thread_local! {
    static NEXT_CHECKPOINT_FAILPOINT: std::cell::Cell<Option<CheckpointFailpoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn inject_next_checkpoint_failpoint(failpoint: CheckpointFailpoint) {
    NEXT_CHECKPOINT_FAILPOINT.with(|slot| slot.set(Some(failpoint)));
}

fn load_headers(
    generation_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    manifest: &CheckpointManifestV1,
) -> Result<headers::RestoredHeaders, CheckpointError> {
    require_filename(&manifest.headers.file, HEADERS_FILE).map_err(CheckpointError::Store)?;
    let mut file = verify_artifact(
        generation_dir,
        HEADERS_FILE,
        manifest.headers.bytes,
        &manifest.headers.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let expected = headers::HeaderCheckpointMetadata {
        header_count: manifest.headers.header_count,
        best: parse_tip(&manifest.best_header_tip)?,
        applied: parse_tip(&manifest.applied_tip)?,
        best_chain_commitment: decode_hex(&manifest.headers.best_chain_sha256)?,
        applied_prefix_commitment: decode_hex(&manifest.headers.applied_chain_sha256)?,
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
    validate_chain_tx_count(chain_tx_count, &coin_stats)?;
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
                ChainTxCount::from_wire(chain_tx_count)
            } else {
                ChainTxCount::UNKNOWN
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
fn validate_chain_tx_count(chain_tx_count: u64, stats: &CoinStats) -> Result<(), CheckpointError> {
    // Zero is the existing unknown-chain-count sentinel, not a second known total.
    if chain_tx_count != 0 && chain_tx_count != stats.tx_count {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "chain transaction count does not match CoinStats".to_owned(),
        )));
    }
    Ok(())
}

fn load_payloads_inner(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    headers: &headers::RestoredHeaders,
) -> Result<(UtxoSet, CoinStats), CheckpointError> {
    require_filename(&manifest.utxo.file, UTXO_FILE).map_err(CheckpointError::Store)?;
    require_filename(&manifest.coinstats.file, COINSTATS_FILE).map_err(CheckpointError::Store)?;
    if manifest.coinstats.bytes != COINSTATS_ARTIFACT_LEN {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats artifact is not exactly 820 bytes".to_owned(),
        )));
    }
    let utxo_file = verify_artifact(
        generation_dir,
        UTXO_FILE,
        manifest.utxo.bytes,
        &manifest.utxo.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let mut coinstats_file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let expected_applied = parse_tip(&manifest.applied_tip)?;
    let (snapshot, mut derived) =
        read_checkpoint_snapshot(utxo_file, manifest.utxo.bytes, expected_applied.height)?;
    if (snapshot.height, snapshot.tip_hash) != (expected_applied.height, expected_applied.hash) {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO tip does not match manifest applied tip".to_owned(),
        )));
    }
    let record_count = u64::try_from(snapshot.set.record_count()).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "loaded UTXO record count does not fit u64".to_owned(),
        ))
    })?;
    if record_count != manifest.utxo.record_count {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO record count does not match manifest".to_owned(),
        )));
    }
    let trailer_digest: [u8; 32] = sha2::Sha256::digest(snapshot.muhash_trailer).into();
    if trailer_digest != decode_hex(&manifest.utxo.muhash_trailer_sha256)? {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO MuHash trailer digest does not match manifest".to_owned(),
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(COINSTATS_ARTIFACT_LEN).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "CoinStats artifact length does not fit usize".to_owned(),
        ))
    })?);
    coinstats_file.read_to_end(&mut bytes)?;
    let payload = coinstats_artifact_payload(&bytes).map_err(CheckpointError::Store)?;
    let coin_stats = CoinStats::from_bytes(payload)?;
    validate_coinstats_manifest(&coin_stats, &manifest.coinstats)?;
    // Transaction count is chain metadata and cannot be derived from live coins.
    derived.tx_count = coin_stats.tx_count;
    if derived != coin_stats {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats does not match loaded UTXO traversal".to_owned(),
        )));
    }
    if coin_stats.utxo_count != manifest.utxo.output_count {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO output count does not match manifest".to_owned(),
        )));
    }
    if snapshot.muhash_trailer != coin_stats.muhash.finalize() {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO trailer does not match restored CoinStats".to_owned(),
        )));
    }
    let applied = headers.tree.node(headers.applied_tip_id)?;
    if (applied.height, applied.hash) != (snapshot.height, snapshot.tip_hash) {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "restored header and UTXO applied tips differ".to_owned(),
        )));
    }
    Ok((snapshot.set, coin_stats))
}
fn read_checkpoint_snapshot(
    utxo_file: File,
    encoded_len: u64,
    height: u32,
) -> Result<(bitcoin_rs_utxo::SnapshotLoad, CoinStats), CheckpointError> {
    let mut limited =
        BufReader::new(utxo_file).take(encoded_len.checked_add(1).ok_or_else(|| {
            CheckpointError::Store(StoreError::Invalid("UTXO byte length overflow".to_owned()))
        })?);
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
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats fields do not match manifest".to_owned(),
        )));
    }
    Ok(())
}
fn parse_tip(tip: &CheckpointTipV1) -> Result<headers::HeaderCheckpointTip, CheckpointError> {
    Ok(headers::HeaderCheckpointTip {
        height: tip.height,
        hash: Hash256::from_str_be(&tip.hash)
            .map_err(|e| CheckpointError::Store(StoreError::Invalid(e.to_string())))?,
        chainwork: ChainWork::from_be_bytes(decode_hex::<32>(&tip.chainwork)?),
    })
}

fn checkpoint_best_tip_id(
    tree: &BlockTree,
    applied_tip: &TipSnapshot,
) -> Result<NodeId, CheckpointError> {
    let applied_id = tree.lookup(applied_tip.hash).ok_or_else(|| {
        CheckpointError::Store(StoreError::Invalid(
            "applied tip disappeared during checkpoint".to_owned(),
        ))
    })?;
    let best_tip_id = tree.tip_id().ok_or_else(|| {
        CheckpointError::Store(StoreError::Invalid(
            "applied tip exists without a best header tip".to_owned(),
        ))
    })?;
    if tree.node_at_height_from(best_tip_id, applied_tip.height) == Some(applied_id) {
        return Ok(best_tip_id);
    }
    Ok(applied_id)
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn write_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    chain_tx_count: u64,
) -> Result<CheckpointWrite, CheckpointError> {
    let Some(applied_tip) = applied_tip else {
        return Ok(CheckpointWrite::SkippedNoAppliedTip);
    };
    #[cfg(test)]
    let failpoint = NEXT_CHECKPOINT_FAILPOINT.with(std::cell::Cell::take);
    #[cfg(not(test))]
    let failpoint = None;
    let stage = begin_publication(data_dir, failpoint).map_err(CheckpointError::Store)?;
    let (headers_meta, headers_digest) = {
        let tree = block_tree.read();
        let (meta, digest) = stage.write_artifact(
            HEADERS_FILE,
            CheckpointFailpoint::HeadersWrite,
            CheckpointFailpoint::HeadersSync,
            |writer| {
                let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
                let point = headers::HeaderCheckpointPoint {
                    height: applied_tip.height,
                    hash: applied_tip.hash,
                };
                let metadata = if tree.tip_id() == Some(best_tip_id) {
                    headers::write_headers(writer, &tree, config, best_tip_id, point)?
                } else {
                    headers::write_selected_headers(writer, &tree, config, best_tip_id, point)?
                };
                Ok::<_, CheckpointError>(metadata)
            },
        )?;
        (meta, digest)
    };
    let (utxo_result, utxo_digest) = stage.write_artifact(
        UTXO_FILE,
        CheckpointFailpoint::UtxoWrite,
        CheckpointFailpoint::UtxoSync,
        |writer| {
            let (trailer, acc) = write_snapshot_observed(
                utxo,
                &applied_tip.hash,
                applied_tip.height,
                writer,
                CoinStatsAccumulator::with_parallel_muhash(applied_tip.height),
            )?;
            Ok::<_, CheckpointError>((trailer, acc))
        },
    )?;
    let (trailer, accumulator) = utxo_result;
    let listener_stats = coin_stats.snapshot();
    if listener_stats.height != applied_tip.height {
        return Err(CheckpointError::Store(StoreError::Invalid(format!(
            "CoinStats height {} does not match applied height {}",
            listener_stats.height, applied_tip.height
        ))));
    }
    validate_chain_tx_count(chain_tx_count, &listener_stats)?;
    let mut fused_stats = accumulator.into_stats();
    fused_stats.tx_count = listener_stats.tx_count;
    let record_count = utxo.record_count();
    if trailer == [0_u8; 384] {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "scanned UTXO snapshot has a zero MuHash trailer".to_owned(),
        )));
    }
    let persisted_stats = fused_stats;
    let ((), stats_digest) = stage.write_artifact(
        COINSTATS_FILE,
        CheckpointFailpoint::CoinStatsWrite,
        CheckpointFailpoint::CoinStatsSync,
        |writer| {
            writer.write_all(&COINSTATS_MAGIC)?;
            writer.write_all(&COINSTATS_VERSION.to_le_bytes())?;
            writer.write_all(&COINSTATS_PAYLOAD_LEN.to_le_bytes())?;
            writer.write_all(&persisted_stats.to_bytes())?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let tree = block_tree.read();
    let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
    let best = tree.node(best_tip_id)?;
    if best.hash != headers_meta.metadata.best.hash
        || best.height != headers_meta.metadata.best.height
        || best.chainwork != headers_meta.metadata.best.chainwork
    {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "best header tip changed during checkpoint".to_owned(),
        )));
    }
    drop(tree);
    let record_count = u64::try_from(record_count).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "UTXO record count does not fit u64".to_owned(),
        ))
    })?;
    let manifest = CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        version: MANIFEST_VERSION,
        generation: stage.generation(),
        network: network_name(config.network).to_owned(),
        network_magic: hex_encode(&config.network.magic()),
        genesis_hash: config.genesis.to_string_be(),
        applied_tip: manifest_tip(headers_meta.metadata.applied, chain_tx_count),
        best_header_tip: manifest_tip(headers_meta.metadata.best, 0),
        headers: HeadersArtifactV1 {
            file: HEADERS_FILE.to_owned(),
            codec: HEADER_CODEC.to_owned(),
            version: headers::HEADER_VERSION,
            bytes: headers_digest.bytes,
            sha256: hex_encode(&headers_digest.sha256),
            header_count: headers_meta.metadata.header_count,
            best_chain_sha256: hex_encode(&headers_meta.metadata.best_chain_commitment),
            applied_chain_sha256: hex_encode(&headers_meta.metadata.applied_prefix_commitment),
        },
        utxo: UtxoArtifactV1 {
            file: UTXO_FILE.to_owned(),
            codec: UTXO_CODEC.to_owned(),
            version: UTXO_VERSION,
            bytes: utxo_digest.bytes,
            sha256: hex_encode(&utxo_digest.sha256),
            record_count,
            output_count: persisted_stats.utxo_count,
            muhash_trailer_sha256: hex_encode(&Sha256::digest(trailer)),
        },
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_owned(),
            codec: COINSTATS_CODEC.to_owned(),
            version: COINSTATS_VERSION,
            bytes: stats_digest.bytes,
            sha256: hex_encode(&stats_digest.sha256),
            height: persisted_stats.height,
            total_amount: persisted_stats.total_amount,
            bogo_size: persisted_stats.bogo_size,
            tx_count: persisted_stats.tx_count,
            utxo_count: persisted_stats.utxo_count,
            muhash: hex_encode(&persisted_stats.muhash.finalize()),
        },
    };
    let generation = commit_publication(stage, &manifest)?;
    Ok(CheckpointWrite::Published { generation })
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

#[cfg(test)]
#[path = "../tests/unit/checkpoint/tests/mod.rs"]
mod tests;
