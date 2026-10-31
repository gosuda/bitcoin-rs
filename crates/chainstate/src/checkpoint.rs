use bitcoin_rs_chain::{BlockTree, ChainTxCount, ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::hex::hex_encode;
pub(crate) use bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_ARTIFACT_LEN;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_CODEC;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_FILE;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_MAGIC;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_PAYLOAD_LEN;
pub(crate) use bitcoin_rs_storage::checkpoint::COINSTATS_VERSION;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::CURRENT_FILE;
use bitcoin_rs_storage::checkpoint::CheckpointError as StoreError;
#[cfg(any(test, feature = "test-seam"))]
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
pub(crate) use bitcoin_rs_storage::checkpoint::classify_checkpoint_io;
pub(crate) use bitcoin_rs_storage::checkpoint::corrupt_checkpoint;
use bitcoin_rs_storage::checkpoint::decode_hex;
use bitcoin_rs_storage::checkpoint::network_name;
#[cfg(test)]
use bitcoin_rs_storage::checkpoint::open_data_dir;
use bitcoin_rs_storage::checkpoint::{ArtifactDigest, CheckpointStage};
use bitcoin_rs_storage::checkpoint::{coinstats_artifact_payload, commit_publication};
use bitcoin_rs_storage::checkpoint::{read_manifest, require_filename, verify_artifact};
use bitcoin_rs_utxo::snapshot::{SeedProvenance, V4Witness, VerifiedSnapshotArtifact};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsAccumulator, CoinStatsListener};
use bitcoin_rs_utxo::{UtxoSet, read_snapshot_strict_v4_witnessed, write_snapshot_witnessed};
use cap_std::fs::{Dir, File};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};
#[cfg(test)]
use std::path::Path;
use thiserror::Error;

pub(crate) mod publisher;

fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
    match error {
        CheckpointError::Io(error)
        | CheckpointError::FullRevalidationMarker(error)
        | CheckpointError::Utxo(bitcoin_rs_utxo::UtxoError::Io(error))
        | CheckpointError::Storage(bitcoin_rs_storage::StorageError::Io(error)) => {
            classify_checkpoint_io(error)
        }
        CheckpointError::Store(error) => {
            bitcoin_rs_storage::checkpoint::classify_checkpoint_error(error)
        }
        error => corrupt_checkpoint(error.to_string()),
    }
}

pub(crate) mod headers;

pub(crate) enum CheckpointLoad {
    Cold,
    Complete(Box<RestoredChainstate>),
}

pub(crate) struct RestoredChainstate {
    pub(crate) generation: u64,
    pub(crate) tree: BlockTree,
    pub(crate) utxo: UtxoSet,
    pub(crate) coin_stats: CoinStats,
    pub(crate) applied_tip: TipSnapshot,
    pub(crate) seed: Option<VerifiedSnapshotArtifact>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointWrite {
    SkippedNoAppliedTip,
    Published {
        reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
    },
}

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

#[derive(Debug, Error)]
pub enum CheckpointSetupError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("checkpointing requires a block body store")]
    MissingBlockBodyStore,
}

pub(crate) fn load_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    load_checkpoint_from_dir_at(
        data_dir,
        config,
        bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
    )
}

pub(crate) fn load_checkpoint_from_dir_at(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = bitcoin_rs_storage::checkpoint::open_current_checkpoint_at(data_dir, root_name)?;
    load_opened_checkpoint(opened, config)
}

pub(crate) fn load_checkpoint_generation_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
    reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = bitcoin_rs_storage::checkpoint::open_checkpoint_generation_at(
        data_dir, root_name, reference,
    )?;
    load_opened_checkpoint(opened, config)
}

fn load_opened_checkpoint(
    opened: CheckpointOpen,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let CheckpointOpen::Selected {
        generation_dir,
        reference,
    } = opened
    else {
        return Ok(CheckpointLoad::Cold);
    };
    let manifest = read_manifest(
        &generation_dir,
        &reference,
        CheckpointIdentity {
            network: config.network,
            genesis: config.genesis,
        },
    )
    .map_err(|error| classify_checkpoint_error(error.into()))?;
    if !headers::is_readable_version(manifest.headers.version) {
        return Err(corrupt_checkpoint(format!(
            "headers checkpoint version {} is not supported",
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
                "headers checkpoint version {actual} is not supported"
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
    match load_payloads(&generation_dir, &manifest, restored_headers, reference) {
        Ok(restored) => Ok(CheckpointLoad::Complete(Box::new(restored))),
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
    let (write, _) =
        write_checkpoint_from_dir(&data_dir, config, block_tree, utxo, coin_stats, applied_tip)?;
    Ok(write)
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

#[cfg(any(test, feature = "test-seam"))]
std::thread_local! {
    static NEXT_CHECKPOINT_FAILPOINT: std::cell::Cell<Option<CheckpointFailpoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(any(test, feature = "test-seam"))]
#[cfg_attr(not(test), expect(dead_code))]
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
        version: manifest.headers.version,
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
    reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
) -> Result<RestoredChainstate, CheckpointError> {
    let chain_tx_count = ChainTxCount::from_wire(manifest.applied_tip.chain_tx_count);
    let (utxo, coin_stats, seed) =
        load_payloads_inner(generation_dir, manifest, &headers, reference)?;
    validate_chain_tx_count(chain_tx_count, &coin_stats)?;
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
        chain_tx_count: applied_node.chain_tx_count,
    };
    Ok(RestoredChainstate {
        generation: manifest.generation,
        tree: headers.tree,
        utxo,
        coin_stats,
        applied_tip,
        seed: Some(seed),
    })
}
fn validate_chain_tx_count(
    chain_tx_count: ChainTxCount,
    stats: &CoinStats,
) -> Result<(), CheckpointError> {
    if chain_tx_count
        .get()
        .is_some_and(|count| count != stats.tx_count)
    {
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
    reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
) -> Result<(UtxoSet, CoinStats, VerifiedSnapshotArtifact), CheckpointError> {
    let (utxo_file, coinstats_file, expected_applied) =
        verify_payload_files(generation_dir, manifest)?;
    let (snapshot, derived, witness, utxo_file) =
        read_checkpoint_snapshot(utxo_file, manifest.utxo.bytes, expected_applied.height)?;
    validate_snapshot_payload(manifest, &snapshot, &expected_applied)?;
    let coin_stats = read_coinstats(coinstats_file, manifest)?;
    validate_derived_stats(manifest, &snapshot, derived, &coin_stats)?;
    let applied = headers.tree.node(headers.applied_tip_id)?;
    if (applied.height, applied.hash) != (snapshot.height, snapshot.tip_hash) {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "restored header and UTXO applied tips differ".to_owned(),
        )));
    }
    let expected_sha: [u8; 32] = decode_hex(&manifest.utxo.sha256)?;
    if witness.sha256() != expected_sha || witness.byte_len() != manifest.utxo.bytes {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO witness digest does not match manifest".to_owned(),
        )));
    }
    let seed =
        VerifiedSnapshotArtifact::seal(utxo_file, witness, SeedProvenance::Checkpoint(reference));
    Ok((snapshot.set, coin_stats, seed))
}

fn verify_payload_files(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
) -> Result<(File, File, headers::HeaderCheckpointTip), CheckpointError> {
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
    let coinstats_file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let expected_applied = parse_tip(&manifest.applied_tip)?;
    Ok((utxo_file, coinstats_file, expected_applied))
}

fn validate_snapshot_payload(
    manifest: &CheckpointManifestV1,
    snapshot: &bitcoin_rs_utxo::SnapshotLoad,
    expected_applied: &headers::HeaderCheckpointTip,
) -> Result<(), CheckpointError> {
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
    Ok(())
}

fn read_coinstats(
    coinstats_file: File,
    manifest: &CheckpointManifestV1,
) -> Result<CoinStats, CheckpointError> {
    let mut coinstats_file = coinstats_file;
    let mut bytes = Vec::with_capacity(usize::try_from(COINSTATS_ARTIFACT_LEN).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "CoinStats artifact length does not fit usize".to_owned(),
        ))
    })?);
    coinstats_file.read_to_end(&mut bytes)?;
    let payload = coinstats_artifact_payload(&bytes).map_err(CheckpointError::Store)?;
    let coin_stats = CoinStats::from_bytes(payload)?;
    validate_coinstats_manifest(&coin_stats, &manifest.coinstats)?;
    Ok(coin_stats)
}

fn validate_derived_stats(
    manifest: &CheckpointManifestV1,
    snapshot: &bitcoin_rs_utxo::SnapshotLoad,
    mut derived: CoinStats,
    coin_stats: &CoinStats,
) -> Result<(), CheckpointError> {
    derived.tx_count = coin_stats.tx_count;
    if derived != *coin_stats {
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
    Ok(())
}
fn read_checkpoint_snapshot(
    utxo_file: File,
    encoded_len: u64,
    height: u32,
) -> Result<
    (
        bitcoin_rs_utxo::SnapshotLoad,
        CoinStats,
        V4Witness,
        std::fs::File,
    ),
    CheckpointError,
> {
    let mut limited =
        BufReader::new(utxo_file).take(encoded_len.checked_add(1).ok_or_else(|| {
            CheckpointError::Store(StoreError::Invalid("UTXO byte length overflow".to_owned()))
        })?);
    let (snapshot, accumulator, witness) = read_snapshot_strict_v4_witnessed(
        &mut limited,
        CoinStatsAccumulator::with_parallel_muhash(height),
    )?;
    let utxo_file = limited.into_inner().into_inner().into_std();
    Ok((snapshot, accumulator.into_stats(), witness, utxo_file))
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
pub(crate) fn write_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
) -> Result<(CheckpointWrite, Option<V4Witness>), CheckpointError> {
    write_checkpoint_from_dir_at(
        data_dir,
        config,
        block_tree,
        utxo,
        coin_stats,
        applied_tip,
        bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
        bitcoin_rs_storage::checkpoint::CheckpointRetention::Replace,
    )
}

macro_rules! write_stage_artifact {
    ($stage:expr, $name:expr, $write_fp:ident, $sync_fp:ident, $write:expr) => {{
        #[cfg(any(test, feature = "test-seam"))]
        {
            $stage.write_artifact_with_failpoints(
                $name,
                CheckpointFailpoint::$write_fp,
                CheckpointFailpoint::$sync_fp,
                $write,
            )
        }
        #[cfg(not(any(test, feature = "test-seam")))]
        {
            $stage.write_artifact($name, $write)
        }
    }};
}

fn begin_checkpoint_stage(
    data_dir: &Dir,
    root_name: &str,
    retention: bitcoin_rs_storage::checkpoint::CheckpointRetention,
) -> Result<CheckpointStage, CheckpointError> {
    #[cfg(any(test, feature = "test-seam"))]
    {
        bitcoin_rs_storage::checkpoint::begin_publication_at_with_failpoint(
            data_dir,
            root_name,
            retention,
            NEXT_CHECKPOINT_FAILPOINT.with(std::cell::Cell::take),
        )
        .map_err(CheckpointError::Store)
    }
    #[cfg(not(any(test, feature = "test-seam")))]
    {
        bitcoin_rs_storage::checkpoint::begin_publication_at(data_dir, root_name, retention)
            .map_err(CheckpointError::Store)
    }
}

fn write_headers_artifact(
    stage: &CheckpointStage,
    block_tree: &RwLock<BlockTree>,
    config: headers::HeaderCheckpointConfig,
    applied_tip: &TipSnapshot,
) -> Result<(headers::HeaderCheckpointWrite, ArtifactDigest), CheckpointError> {
    let tree = block_tree.read();
    write_stage_artifact!(stage, HEADERS_FILE, HeadersWrite, HeadersSync, |writer| {
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
    })
}

type UtxoArtifact = (
    [u8; 384],
    CoinStatsAccumulator,
    Option<V4Witness>,
    ArtifactDigest,
);

fn write_utxo_artifact(
    stage: &CheckpointStage,
    utxo: &UtxoSet,
    applied_tip: &TipSnapshot,
) -> Result<UtxoArtifact, CheckpointError> {
    let (utxo_result, utxo_digest) =
        write_stage_artifact!(stage, UTXO_FILE, UtxoWrite, UtxoSync, |writer| {
            let (trailer, accumulator, witness) = write_snapshot_witnessed(
                utxo,
                &applied_tip.hash,
                applied_tip.height,
                writer,
                CoinStatsAccumulator::with_parallel_muhash(applied_tip.height),
            )?;
            Ok::<_, CheckpointError>((trailer, accumulator, witness))
        })?;
    let (trailer, accumulator, witness) = utxo_result;
    Ok((trailer, accumulator, witness, utxo_digest))
}

fn write_coinstats_artifact(
    stage: &CheckpointStage,
    stats: &CoinStats,
) -> Result<ArtifactDigest, CheckpointError> {
    let ((), stats_digest) = write_stage_artifact!(
        stage,
        COINSTATS_FILE,
        CoinStatsWrite,
        CoinStatsSync,
        |writer| {
            writer.write_all(&COINSTATS_MAGIC)?;
            writer.write_all(&COINSTATS_VERSION.to_le_bytes())?;
            writer.write_all(&COINSTATS_PAYLOAD_LEN.to_le_bytes())?;
            writer.write_all(&stats.to_bytes())?;
            Ok::<_, CheckpointError>(())
        }
    )?;
    Ok(stats_digest)
}

fn check_coinstats_listener(
    applied_tip: &TipSnapshot,
    chain_tx_count: ChainTxCount,
    listener_stats: &CoinStats,
) -> Result<(), CheckpointError> {
    if listener_stats.height != applied_tip.height {
        return Err(CheckpointError::Store(StoreError::Invalid(format!(
            "CoinStats height {} does not match applied height {}",
            listener_stats.height, applied_tip.height
        ))));
    }
    validate_chain_tx_count(chain_tx_count, listener_stats)
}

fn gated_witness(
    root_name: &str,
    stage_witness: Option<V4Witness>,
    utxo_digest: &ArtifactDigest,
    fused_stats: &CoinStats,
    listener_stats: &CoinStats,
) -> Option<V4Witness> {
    match stage_witness {
        Some(witness)
            if root_name == CHECKPOINT_ROOT
                && witness.sha256() == utxo_digest.sha256
                && witness.byte_len() == utxo_digest.bytes
                && fused_stats.height == listener_stats.height
                && fused_stats.total_amount == listener_stats.total_amount
                && fused_stats.bogo_size == listener_stats.bogo_size
                && fused_stats.utxo_count == listener_stats.utxo_count
                && fused_stats.muhash.finalize() == listener_stats.muhash.finalize() =>
        {
            Some(witness)
        }
        _ => None,
    }
}

fn check_best_tip_unchanged(
    block_tree: &RwLock<BlockTree>,
    applied_tip: &TipSnapshot,
    expected: &headers::HeaderCheckpointTip,
) -> Result<(), CheckpointError> {
    let tree = block_tree.read();
    let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
    let best = tree.node(best_tip_id)?;
    if best.hash != expected.hash
        || best.height != expected.height
        || best.chainwork != expected.chainwork
    {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "best header tip changed during checkpoint".to_owned(),
        )));
    }
    Ok(())
}

struct ManifestInputs<'a> {
    config: headers::HeaderCheckpointConfig,
    generation: u64,
    headers_meta: headers::HeaderCheckpointWrite,
    chain_tx_count: ChainTxCount,
    headers_digest: &'a ArtifactDigest,
    utxo_digest: &'a ArtifactDigest,
    record_count: u64,
    stats: &'a CoinStats,
    trailer: [u8; 384],
    stats_digest: &'a ArtifactDigest,
}

fn checkpoint_manifest(input: &ManifestInputs<'_>) -> CheckpointManifestV1 {
    let stats = input.stats;
    CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        version: MANIFEST_VERSION,
        generation: input.generation,
        network: network_name(input.config.network).to_owned(),
        network_magic: hex_encode(&input.config.network.magic()),
        genesis_hash: input.config.genesis.to_string_be(),
        applied_tip: manifest_tip(
            input.headers_meta.metadata.applied,
            input.chain_tx_count.to_wire(),
        ),
        best_header_tip: manifest_tip(input.headers_meta.metadata.best, 0),
        headers: HeadersArtifactV1 {
            file: HEADERS_FILE.to_owned(),
            codec: HEADER_CODEC.to_owned(),
            version: input.headers_meta.metadata.version,
            bytes: input.headers_digest.bytes,
            sha256: hex_encode(&input.headers_digest.sha256),
            header_count: input.headers_meta.metadata.header_count,
            best_chain_sha256: hex_encode(&input.headers_meta.metadata.best_chain_commitment),
            applied_chain_sha256: hex_encode(
                &input.headers_meta.metadata.applied_prefix_commitment,
            ),
        },
        utxo: UtxoArtifactV1 {
            file: UTXO_FILE.to_owned(),
            codec: UTXO_CODEC.to_owned(),
            version: UTXO_VERSION,
            bytes: input.utxo_digest.bytes,
            sha256: hex_encode(&input.utxo_digest.sha256),
            record_count: input.record_count,
            output_count: stats.utxo_count,
            muhash_trailer_sha256: hex_encode(&Sha256::digest(input.trailer)),
        },
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_owned(),
            codec: COINSTATS_CODEC.to_owned(),
            version: COINSTATS_VERSION,
            bytes: input.stats_digest.bytes,
            sha256: hex_encode(&input.stats_digest.sha256),
            height: stats.height,
            total_amount: stats.total_amount,
            bogo_size: stats.bogo_size,
            tx_count: stats.tx_count,
            utxo_count: stats.utxo_count,
            muhash: hex_encode(&stats.muhash.finalize()),
        },
    }
}

pub(crate) fn write_checkpoint_from_dir_at(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    root_name: &str,
    retention: bitcoin_rs_storage::checkpoint::CheckpointRetention,
) -> Result<(CheckpointWrite, Option<V4Witness>), CheckpointError> {
    let Some(applied_tip) = applied_tip else {
        return Ok((CheckpointWrite::SkippedNoAppliedTip, None));
    };
    let chain_tx_count = applied_tip.chain_tx_count;
    let stage = begin_checkpoint_stage(data_dir, root_name, retention)?;
    let (headers_meta, headers_digest) =
        write_headers_artifact(&stage, block_tree, config, applied_tip)?;
    let (trailer, accumulator, stage_witness, utxo_digest) =
        write_utxo_artifact(&stage, utxo, applied_tip)?;
    let listener_stats = coin_stats.snapshot();
    check_coinstats_listener(applied_tip, chain_tx_count, &listener_stats)?;
    let mut fused_stats = accumulator.into_stats();
    fused_stats.tx_count = listener_stats.tx_count;
    let gate_witness = gated_witness(
        root_name,
        stage_witness,
        &utxo_digest,
        &fused_stats,
        &listener_stats,
    );
    let record_count = utxo.record_count();
    if trailer == [0_u8; 384] {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "scanned UTXO snapshot has a zero MuHash trailer".to_owned(),
        )));
    }
    let stats_digest = write_coinstats_artifact(&stage, &fused_stats)?;
    check_best_tip_unchanged(block_tree, applied_tip, &headers_meta.metadata.best)?;
    let record_count = u64::try_from(record_count).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "UTXO record count does not fit u64".to_owned(),
        ))
    })?;
    let manifest = checkpoint_manifest(&ManifestInputs {
        config,
        generation: stage.generation(),
        headers_meta,
        chain_tx_count,
        headers_digest: &headers_digest,
        utxo_digest: &utxo_digest,
        record_count,
        stats: &fused_stats,
        trailer,
        stats_digest: &stats_digest,
    });
    let reference = commit_publication(stage, &manifest)?;
    Ok((CheckpointWrite::Published { reference }, gate_witness))
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
mod tests;
