use crate::chain::{BlockTree, ChainTxCount, ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_consensus::primitives::hex::hex_encode;
use bitcoin_rs_consensus::primitives::{Hash256, Network};
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
pub(crate) use bitcoin_rs_storage::checkpoint::classify_checkpoint_io;
pub(crate) use bitcoin_rs_storage::checkpoint::corrupt_checkpoint;
use bitcoin_rs_storage::checkpoint::decode_hex;
use bitcoin_rs_storage::checkpoint::network_name;
#[cfg(test)]
use bitcoin_rs_storage::checkpoint::open_data_dir;
use bitcoin_rs_storage::checkpoint::{ArtifactDigest, CheckpointStage};
use bitcoin_rs_storage::checkpoint::{coinstats_artifact_payload, commit_publication};
use bitcoin_rs_storage::checkpoint::{read_manifest, require_filename, verify_artifact};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use cap_std::fs::{Dir, File};
use parking_lot::RwLock;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

pub(crate) mod publisher;

fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
    match error {
        CheckpointError::Io(error)
        | CheckpointError::FullRevalidationMarker(error)
        | CheckpointError::Utxo(bitcoin_rs_storage::utxo::UtxoError::Io(error))
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
    pub(crate) engine: Option<std::sync::Arc<dyn bitcoin_rs_storage::KvStore>>,
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
    Chain(#[from] crate::chain::ChainError),
    #[error("UTXO checkpoint failed: {0}")]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
    #[error("CoinStats checkpoint decode failed: {0}")]
    CoinStats(#[from] bitcoin_rs_storage::utxo::stats::CoinStatsDecodeError),
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint block-body durability failed: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("checkpoint refused while disconnect of block {hash} at height {height} is in flight")]
    DisconnectInFlight { hash: Hash256, height: u32 },
    #[error("checkpoint refused while the chainstate is closed for recovery")]
    ClosedForRecovery,
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

#[expect(dead_code)]
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

#[expect(dead_code)]
pub(crate) fn load_checkpoint_from_dir_at(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    load_checkpoint_from_dir_with_path(data_dir, None, config, root_name)
}

pub(crate) fn load_checkpoint_from_dir_with_path(
    data_dir: &Dir,
    host_data_dir: Option<&Path>,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = bitcoin_rs_storage::checkpoint::open_current_checkpoint_at(data_dir, root_name)?;
    load_opened_checkpoint(
        opened,
        config,
        host_data_dir,
        root_name,
        UtxoPayloadPolicy::Refuse,
    )
}

#[expect(dead_code)]
pub(crate) fn load_checkpoint_generation_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
    reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    load_checkpoint_generation_from_dir_with_path(data_dir, None, config, root_name, reference)
}

pub(crate) fn load_checkpoint_generation_from_dir_with_path(
    data_dir: &Dir,
    host_data_dir: Option<&Path>,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
    reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = bitcoin_rs_storage::checkpoint::open_checkpoint_generation_at(
        data_dir, root_name, reference,
    )?;
    load_opened_checkpoint(
        opened,
        config,
        host_data_dir,
        root_name,
        UtxoPayloadPolicy::Refuse,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UtxoPayloadPolicy {
    Refuse,
    IgnoreForConversion,
}

/// Loads a generation as the source of an epoch-3 conversion. The converter
/// reads coins from the source's own UTXO payload, so this entry accepts a
/// generation that carries one. Node loads still refuse it.
pub(crate) fn load_conversion_source_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    root_name: &str,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = bitcoin_rs_storage::checkpoint::open_current_checkpoint_at(data_dir, root_name)?;
    load_opened_checkpoint(
        opened,
        config,
        None,
        root_name,
        UtxoPayloadPolicy::IgnoreForConversion,
    )
}

fn load_opened_checkpoint(
    opened: CheckpointOpen,
    config: headers::HeaderCheckpointConfig,
    host_data_dir: Option<&Path>,
    root_name: &str,
    policy: UtxoPayloadPolicy,
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
    if policy == UtxoPayloadPolicy::Refuse && manifest.utxo.is_some() {
        return Err(CheckpointLoadError::UtxoPayloadRetired {
            generation: manifest.generation,
        });
    }
    if manifest.coinstats.codec != COINSTATS_CODEC {
        return Err(corrupt_checkpoint(format!(
            "unexpected payload codec CoinStats={}",
            manifest.coinstats.codec
        )));
    }
    let store_path = host_data_dir.map(|host| {
        host.join(root_name)
            .join(format!("gen-{:020}", reference.generation))
            .join("chainstate")
    });
    match load_payloads(
        &generation_dir,
        &manifest,
        restored_headers,
        store_path.as_deref(),
    ) {
        Ok(restored) => Ok(CheckpointLoad::Complete(Box::new(restored))),
        Err(error) => Err(classify_checkpoint_error(error)),
    }
}

/// Validates a conversion source's canonical artifacts without opening its engine.
pub fn validate_conversion_checkpoint_artifacts(
    generation_dir: &Dir,
    reference: &bitcoin_rs_storage::checkpoint::CheckpointReference,
    network: Network,
) -> Result<(), CheckpointError> {
    let config = headers::HeaderCheckpointConfig {
        network,
        genesis: network.genesis_block_hash(),
    };
    let manifest = read_manifest(
        generation_dir,
        reference,
        CheckpointIdentity {
            network,
            genesis: config.genesis,
        },
    )?;
    if !headers::is_readable_version(manifest.headers.version)
        || manifest.headers.codec != HEADER_CODEC
        || manifest.coinstats.codec != COINSTATS_CODEC
    {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "unsupported conversion checkpoint artifact codec or version".to_owned(),
        )));
    }
    let _headers = load_headers(generation_dir, config, &manifest)?;
    require_filename(&manifest.coinstats.file, COINSTATS_FILE)?;
    let file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )?;
    let stats = read_coinstats(file, &manifest)?;
    if stats.height != manifest.applied_tip.height {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats height does not match applied tip".to_owned(),
        )));
    }
    validate_chain_tx_count(
        ChainTxCount::from_wire(manifest.applied_tip.chain_tx_count),
        &stats,
    )
}

#[cfg(test)]
pub(crate) fn write_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
) -> Result<CheckpointWrite, CheckpointError> {
    let dir = open_data_dir(data_dir)?;
    let store = engine_store_from_utxo(utxo)?;
    write_checkpoint_with_store(
        &dir,
        config,
        block_tree,
        coin_stats,
        applied_tip,
        CheckpointStoreTarget {
            store: &store,
            host_data_dir: data_dir,
        },
    )
}

#[cfg(test)]
fn engine_store_from_utxo(
    utxo: &UtxoSet,
) -> Result<bitcoin_rs_storage::memory_kv::MemoryKvStore, CheckpointError> {
    use bitcoin_rs_storage::KvStore;
    let mut coins: std::collections::HashMap<
        bitcoin_rs_consensus::primitives::Txid,
        Vec<bitcoin_rs_storage::utxo::record::OwnedUtxoOut>,
    > = std::collections::HashMap::new();
    utxo.with_stable_view(|view| {
        view.for_each_all(|outpoint, _| {
            if let Some(entry) = utxo.get_entry(outpoint) {
                coins.entry(outpoint.txid).or_default().push(
                    bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                        vout: outpoint.vout,
                        value: entry.txout.value.to_sat(),
                        script_pubkey: entry.txout.script_pubkey.as_bytes().to_vec(),
                        coinbase: entry.coinbase,
                        height: entry.height,
                    },
                );
            }
        });
    });
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::default();
    let mut batch = store.new_batch();
    for (txid, outputs) in coins {
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(txid.0, &outputs)?;
        batch.put(
            bitcoin_rs_storage::ColumnFamily::Coins,
            bitcoin_rs_storage::CoinKey(txid.0.to_le_bytes()).as_bytes(),
            record.bytes(),
        );
    }
    store.write(batch)?;
    Ok(store)
}

#[cfg(test)]
pub(crate) fn load_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let dir = match open_data_dir(data_dir) {
        Ok(dir) => dir,
        Err(_) => return Ok(CheckpointLoad::Cold),
    };
    load_checkpoint_from_dir_with_path(
        &dir,
        Some(data_dir),
        config,
        bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
    )
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
    store_path: Option<&std::path::Path>,
) -> Result<RestoredChainstate, CheckpointError> {
    let chain_tx_count = ChainTxCount::from_wire(manifest.applied_tip.chain_tx_count);
    let (utxo, coin_stats, engine) = load_payloads_inner(generation_dir, manifest, store_path)?;
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
        engine,
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

#[expect(clippy::type_complexity)]
fn load_payloads_inner(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    store_path: Option<&std::path::Path>,
) -> Result<
    (
        UtxoSet,
        CoinStats,
        Option<std::sync::Arc<dyn bitcoin_rs_storage::KvStore>>,
    ),
    CheckpointError,
> {
    let engine = open_generation_store(generation_dir, store_path)?;
    require_filename(&manifest.coinstats.file, COINSTATS_FILE).map_err(CheckpointError::Store)?;
    let coinstats_file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let coin_stats = read_coinstats(coinstats_file, manifest)?;
    Ok((UtxoSet::new(), coin_stats, engine))
}

/// Opens the engine image stored inside a checkpoint generation, if any.
///
/// A generation with no `chainstate` entry carries no image and restores as
/// `None`; the caller decides whether that is acceptable. An entry that is
/// present but cannot be opened as an engine image (an empty directory,
/// unknown files, several engines, a non-UTF-8 name) fails the load as a
/// corrupt checkpoint and is never read as an absent image.
fn open_generation_store(
    store_dir: &Dir,
    store_path: Option<&std::path::Path>,
) -> Result<Option<std::sync::Arc<dyn bitcoin_rs_storage::KvStore>>, CheckpointError> {
    let nested = match store_dir.open_dir("chainstate") {
        Ok(dir) => Some(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let memory_file = match nested.as_ref() {
        Some(dir) => dir.open(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE),
        None => store_dir.open(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE),
    };
    match memory_file {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(CheckpointError::from)?;
            let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::from_bytes(&bytes)
                .map_err(|e| CheckpointError::Store(StoreError::Invalid(e.to_string())))?;
            Ok(Some(std::sync::Arc::new(store)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (Some(_), Some(path)) = (nested.as_ref(), store_path) else {
                return Ok(None);
            };
            bitcoin_rs_storage::open_checkpoint_store(path)
                .map(Some)
                .map_err(|error| match error {
                    bitcoin_rs_storage::StorageError::IncompatibleData(reason) => {
                        CheckpointError::Store(StoreError::Invalid(format!(
                            "checkpoint engine image is unusable: {reason}"
                        )))
                    }
                    other => other.into(),
                })
        }
        Err(e) => Err(e.into()),
    }
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
pub(crate) struct CheckpointStoreTarget<'a> {
    pub store: &'a dyn bitcoin_rs_storage::KvStore,
    pub host_data_dir: &'a std::path::Path,
}

pub(crate) struct CheckpointWriteOptions<'a> {
    pub root_name: &'a str,
    pub retention: bitcoin_rs_storage::checkpoint::CheckpointRetention,
    pub target: CheckpointStoreTarget<'a>,
}

pub(crate) fn write_checkpoint_with_store(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    target: CheckpointStoreTarget<'_>,
) -> Result<CheckpointWrite, CheckpointError> {
    write_checkpoint_from_dir_at_inner(
        data_dir,
        config,
        block_tree,
        coin_stats,
        applied_tip,
        CheckpointWriteOptions {
            root_name: bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
            retention: bitcoin_rs_storage::checkpoint::CheckpointRetention::Replace,
            target,
        },
    )
}
pub(crate) fn write_historical_checkpoint_with_store(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    target: CheckpointStoreTarget<'_>,
) -> Result<CheckpointWrite, CheckpointError> {
    write_checkpoint_from_dir_at_inner(
        data_dir,
        config,
        block_tree,
        coin_stats,
        applied_tip,
        CheckpointWriteOptions {
            root_name: bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
            retention: bitcoin_rs_storage::checkpoint::CheckpointRetention::UntilReferenced,
            target,
        },
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
    stats: &'a CoinStats,
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
        utxo: None,
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
fn write_checkpoint_from_dir_at_inner(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    options: CheckpointWriteOptions<'_>,
) -> Result<CheckpointWrite, CheckpointError> {
    let Some(applied_tip) = applied_tip else {
        return Ok(CheckpointWrite::SkippedNoAppliedTip);
    };
    let chain_tx_count = applied_tip.chain_tx_count;
    let stage = begin_checkpoint_stage(data_dir, options.root_name, options.retention)?;
    stage
        .checkpoint_store(
            options.target.host_data_dir,
            options.root_name,
            options.target.store,
        )
        .map_err(CheckpointError::Store)?;
    let (headers_meta, headers_digest) =
        write_headers_artifact(&stage, block_tree, config, applied_tip)?;
    let listener_stats = coin_stats.snapshot();
    check_coinstats_listener(applied_tip, chain_tx_count, &listener_stats)?;
    let stats_digest = write_coinstats_artifact(&stage, &listener_stats)?;
    check_best_tip_unchanged(block_tree, applied_tip, &headers_meta.metadata.best)?;
    let manifest = checkpoint_manifest(&ManifestInputs {
        config,
        generation: stage.generation(),
        headers_meta,
        chain_tx_count,
        headers_digest: &headers_digest,
        stats: &listener_stats,
        stats_digest: &stats_digest,
    });
    let reference = commit_publication(stage, &manifest)?;
    Ok(CheckpointWrite::Published { reference })
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
