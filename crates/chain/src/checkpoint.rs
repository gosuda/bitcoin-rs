use crate::chain::{BlockTree, ChainTxCount, NodeId, TipSnapshot};
use bitcoin_rs_consensus::header_rules::ChainWork;
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
use bitcoin_rs_storage::checkpoint::EngineArtifactV1;
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
use bitcoin_rs_storage::checkpoint::verify_engine_artifact;
use bitcoin_rs_storage::checkpoint::{ArtifactDigest, CheckpointStage};
use bitcoin_rs_storage::checkpoint::{coinstats_artifact_payload, commit_publication};
use bitcoin_rs_storage::checkpoint::{read_manifest, require_filename, verify_artifact};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use cap_std::fs::{Dir, File};
use parking_lot::RwLock;
use sha2::Digest;
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
    pub(crate) engine_scratch: Option<EngineScratch>,
}

pub(crate) struct EngineScratch {
    path: std::path::PathBuf,
}
impl Drop for EngineScratch {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            tracing::warn!(path = %self.path.display(), %error, "checkpoint scratch cleanup failed");
        }
    }
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
    let (utxo, coin_stats, engine, engine_scratch) =
        load_payloads_inner(generation_dir, manifest, store_path)?;
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
        engine_scratch,
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
        Option<EngineScratch>,
    ),
    CheckpointError,
> {
    let (engine, scratch) =
        open_generation_store(generation_dir, store_path, manifest.engine.as_ref())?;
    require_filename(&manifest.coinstats.file, COINSTATS_FILE).map_err(CheckpointError::Store)?;
    let coinstats_file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let coin_stats = read_coinstats(coinstats_file, manifest)?;
    Ok((UtxoSet::new(), coin_stats, engine, scratch))
}

/// Opens the engine image stored inside a checkpoint generation, if any.
///
#[expect(clippy::type_complexity)]
fn open_generation_store(
    store_dir: &Dir,
    store_path: Option<&std::path::Path>,
    expected: Option<&EngineArtifactV1>,
) -> Result<
    (
        Option<std::sync::Arc<dyn bitcoin_rs_storage::KvStore>>,
        Option<EngineScratch>,
    ),
    CheckpointError,
> {
    let nested = match store_dir.open_dir(bitcoin_rs_storage::checkpoint::ENGINE_IMAGE_DIR) {
        Ok(dir) => Some(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if let (Some(nested), Some(expected)) = (nested.as_ref(), expected) {
        match nested.open(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE) {
            Ok(_) => {
                let Some(host) = store_path else {
                    verify_engine_artifact(nested, expected).map_err(CheckpointError::Store)?;
                    return Ok((Some(memory_image_store(nested, expected)?), None));
                };
                let scratch = scratch_copy(host, &expected.files)?;
                let scratch_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&scratch.path)
                    .map_err(CheckpointError::from)?;
                verify_engine_artifact(&scratch_dir, expected).map_err(CheckpointError::Store)?;
                return Ok((Some(memory_image_store(&scratch_dir, expected)?), None));
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            Err(_) => {}
        }
        let Some(host) = store_path else {
            return Err(CheckpointError::Store(StoreError::Invalid(
                "checkpoint engine image has no host path".to_owned(),
            )));
        };
        let scratch = scratch_copy(host, &expected.files)?;
        let scratch_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&scratch.path)
            .map_err(CheckpointError::from)?;
        verify_engine_artifact(&scratch_dir, expected).map_err(CheckpointError::Store)?;
        let store =
            bitcoin_rs_storage::open_checkpoint_store(&scratch.path).map_err(
                |error| match error {
                    bitcoin_rs_storage::StorageError::IncompatibleData(_) => {
                        CheckpointError::Store(StoreError::Invalid(
                            "checkpoint engine image is unrecognized".to_owned(),
                        ))
                    }
                    error => error.into(),
                },
            )?;
        return Ok((Some(store), Some(scratch)));
    }
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
            Ok((Some(std::sync::Arc::new(store)), None))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (Some(_), Some(path)) = (nested.as_ref(), store_path) else {
                return Ok((None, None));
            };
            bitcoin_rs_storage::open_checkpoint_store(path)
                .map(|store| (Some(store), None))
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

fn memory_image_store(
    image_dir: &Dir,
    expected: &EngineArtifactV1,
) -> Result<std::sync::Arc<dyn bitcoin_rs_storage::KvStore>, CheckpointError> {
    let record = expected
        .files
        .iter()
        .find(|record| record.file == bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE)
        .ok_or_else(|| {
            CheckpointError::Store(StoreError::Invalid(
                "checkpoint engine image is missing its memory store".to_owned(),
            ))
        })?;
    let mut file = image_dir
        .open(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE)
        .map_err(CheckpointError::from)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(CheckpointError::from)?;
    let actual: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    if u64::try_from(bytes.len()).ok() != Some(record.bytes)
        || actual != decode_hex::<32>(&record.sha256).map_err(CheckpointError::Store)?
    {
        return Err(CheckpointError::Store(StoreError::Invalid(format!(
            "checkpoint engine image {:?} length or SHA256 mismatch",
            bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE
        ))));
    }
    let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::from_bytes(&bytes)
        .map_err(|e| CheckpointError::Store(StoreError::Invalid(e.to_string())))?;
    Ok(std::sync::Arc::new(store))
}

fn scratch_copy(
    chainstate_path: &std::path::Path,
    files: &[bitcoin_rs_storage::checkpoint::EngineFileV1],
) -> Result<EngineScratch, CheckpointError> {
    static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    scratch_copy_with_sequence(&SCRATCH_SEQ, chainstate_path, files)
}

fn scratch_copy_with_sequence(
    sequence: &std::sync::atomic::AtomicU64,
    chainstate_path: &std::path::Path,
    files: &[bitcoin_rs_storage::checkpoint::EngineFileV1],
) -> Result<EngineScratch, CheckpointError> {
    let Some(parent) = chainstate_path.parent() else {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "checkpoint engine image path has no parent".to_owned(),
        )));
    };
    std::fs::create_dir_all(parent).map_err(CheckpointError::from)?;
    let pid = std::process::id();
    let scratch_path = loop {
        let seq = sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let candidate = parent.join(format!(".scratch-{pid}-{seq}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(CheckpointError::from(e)),
        }
    };
    let scratch = EngineScratch { path: scratch_path };
    for file in files {
        let source = chainstate_path.join(&file.file);
        let dest = scratch.path.join(&file.file);
        if let Some(dest_parent) = dest.parent() {
            std::fs::create_dir_all(dest_parent).map_err(CheckpointError::from)?;
        }
        std::fs::copy(&source, &dest).map_err(|error| {
            CheckpointError::Store(StoreError::Invalid(format!(
                "checkpoint engine image file {:?} failed: {error}",
                file.file
            )))
        })?;
    }
    Ok(scratch)
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
    engine: Option<EngineArtifactV1>,
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
        engine: input.engine.clone(),
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
    options
        .target
        .store
        .flush()
        .map_err(CheckpointError::Storage)?;
    stage
        .checkpoint_store(
            options.target.host_data_dir,
            options.root_name,
            options.target.store,
        )
        .map_err(CheckpointError::Store)?;
    let engine_artifact = stage
        .staged_engine_digest()
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
        engine: Some(engine_artifact),
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
mod tests {
    use super::headers;

    use std::fs;
    use std::io::Cursor;
    use std::path::Path;

    use crate::chain::regtest_fixture::mined_regtest_header;
    use crate::chain::{BlockTree, NodeId, TipSnapshot, accept_headers, compact_is_met_by};
    use bitcoin_rs_consensus::primitives::{
        Amount, BlockHash, CompactTarget, Hash256, Header, Network, OutPoint, Script, TxOut, Txid,
        deserialize,
    };
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener, scan_coin_stats};
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};

    use super::{
        CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CheckpointLoad, CheckpointLoadError,
        CheckpointManifestV1, CheckpointWrite, CurrentV1, HEADERS_FILE, MANIFEST_FILE,
        load_checkpoint,
    };
    use crate::test_fixtures::{TestError, TestResult};

    const NETWORK: Network = Network::Regtest;

    fn mutate_authenticated_artifact(
        data_dir: &Path,
        artifact: &str,
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> TestResult {
        let root = data_dir.join(CHECKPOINT_ROOT);
        let current_path = root.join(CURRENT_FILE);
        let mut current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)?;

        let generation = root.join(&current.directory);
        let manifest_path = generation.join(MANIFEST_FILE);
        let mut manifest: CheckpointManifestV1 = sonic_rs::from_slice(&fs::read(&manifest_path)?)?;
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
            COINSTATS_FILE => {
                manifest.coinstats.bytes = length;
                manifest.coinstats.sha256 = digest;
            }
            _ => return Err(TestError::UnexpectedSuccess("unknown checkpoint artifact")),
        }
        let manifest_bytes = sonic_rs::to_vec(&manifest)?;
        fs::write(&manifest_path, &manifest_bytes)?;
        current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
        fs::write(current_path, sonic_rs::to_vec(&current)?)?;
        Ok(())
    }
    fn mutate_authenticated_manifest(
        data_dir: &Path,
        mutate: impl FnOnce(&mut CheckpointManifestV1),
    ) -> TestResult {
        let root = data_dir.join(CHECKPOINT_ROOT);
        let current_path = root.join(CURRENT_FILE);
        let mut current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)?;
        let manifest_path = root.join(&current.directory).join(MANIFEST_FILE);
        let mut manifest: CheckpointManifestV1 = sonic_rs::from_slice(&fs::read(&manifest_path)?)?;
        mutate(&mut manifest);
        let manifest_bytes = sonic_rs::to_vec(&manifest)?;
        fs::write(&manifest_path, &manifest_bytes)?;
        current.manifest_sha256 = super::hex_encode(&Sha256::digest(&manifest_bytes));
        fs::write(current_path, sonic_rs::to_vec(&current)?)?;
        Ok(())
    }

    fn tip_snapshot(
        tree: &BlockTree,
        point: headers::HeaderCheckpointPoint,
    ) -> Result<TipSnapshot, headers::HeaderCheckpointError> {
        let id = tree
            .lookup(point.hash)
            .ok_or(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)?;
        let node = tree.node(id)?;
        Ok(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        })
    }

    fn config() -> headers::HeaderCheckpointConfig {
        headers::HeaderCheckpointConfig {
            network: NETWORK,
            genesis: NETWORK.genesis_block_hash(),
        }
    }

    #[test]
    fn coinstats_wire_length_matches_the_encoded_length() -> TestResult {
        assert_eq!(
            usize::try_from(bitcoin_rs_storage::checkpoint::COINSTATS_PAYLOAD_LEN)?,
            bitcoin_rs_storage::utxo::stats::coin_stats::COIN_STATS_ENCODED_LEN,
            "the CoinStats wire payload length must equal the in-memory encoded length"
        );
        Ok(())
    }

    fn write_checkpoint(
        tree: &BlockTree,
        best_tip_id: NodeId,
        applied: headers::HeaderCheckpointPoint,
    ) -> Result<(Vec<u8>, headers::HeaderCheckpointWrite), headers::HeaderCheckpointError> {
        let mut bytes = Vec::new();
        let written = headers::write_headers(&mut bytes, tree, config(), best_tip_id, applied)?;
        assert_eq!(u64::try_from(bytes.len()).ok(), Some(written.bytes_written));
        Ok((bytes, written))
    }

    fn chain_with_applied_height(
        best_height: u32,
        applied_height: u32,
    ) -> TestResult<(BlockTree, NodeId, headers::HeaderCheckpointPoint)> {
        let genesis = NETWORK.genesis_block().header;
        let mut tree = BlockTree::new();
        let mut current = accept_headers(
            &mut tree,
            core::slice::from_ref(&genesis),
            NETWORK,
            crate::chain::current_unix_seconds(),
            crate::chain::HeaderValidationMode::LiveAdmission,
        )?
        .ids[0];
        for height in 1..=best_height {
            let prev = BlockHash(tree.node(current)?.hash);
            let header = mined_regtest_header(prev, height)?;
            current = accept_headers(
                &mut tree,
                core::slice::from_ref(&header),
                NETWORK,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?
            .ids[0];
        }
        let applied_id = tree
            .node_at_height_from(current, applied_height)
            .ok_or(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)?;
        let applied = tree.node(applied_id)?;
        let height = applied.height;
        let hash = applied.hash;
        Ok((
            tree,
            current,
            headers::HeaderCheckpointPoint { height, hash },
        ))
    }

    fn mine_header_to_declared_target(
        header: &mut Header,
    ) -> Result<(), headers::HeaderCheckpointError> {
        crate::chain::regtest_fixture::mine_header_to_declared_target(header)
            .map_err(|error| headers::HeaderCheckpointError::Codec(error.to_string()))
    }

    fn header_from_row(row: &[u8]) -> Result<Header, headers::HeaderCheckpointError> {
        deserialize(row).map_err(|error| headers::HeaderCheckpointError::Codec(error.to_string()))
    }

    fn populated_utxo() -> Result<UtxoSet, bitcoin_rs_storage::utxo::UtxoError> {
        let utxo = UtxoSet::new();
        let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 3,
            value: 50_000,
            script_pubkey: vec![0x51, 0x21],
            coinbase: true,
            height: 0,
        };
        let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            Hash256::from_le_bytes(&[7_u8; 32]),
            &[out],
        )?;
        utxo.insert_parsed_record(record);

        Ok(utxo)
    }

    #[cfg(test)]
    mod headers_artifact {
        use super::*;

        #[test]
        fn round_trip_replays_consensus_validated_active_chain() -> TestResult {
            for (best_height, applied_height) in [(3, 1), (500, 499), (1_351, 1_350)] {
                let (tree, best_tip_id, applied) =
                    chain_with_applied_height(best_height, applied_height)?;
                let written = write_checkpoint(&tree, best_tip_id, applied)?;
                let mut reader = Cursor::new(written.0);

                let restored = headers::read_headers(&mut reader, config(), written.1.metadata)?;

                assert_eq!(restored.tree.len(), usize::try_from(best_height)? + 1);
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
            }
            Ok(())
        }

        #[test]
        fn reader_rejects_wrong_network_and_genesis() -> TestResult {
            let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
            let written = write_checkpoint(&tree, best_tip_id, applied)?;

            let wrong_network = headers::HeaderCheckpointConfig {
                network: Network::Testnet3,
                genesis: Network::Testnet3.genesis_block_hash(),
            };
            assert!(
                headers::read_headers(
                    &mut Cursor::new(&written.0),
                    wrong_network,
                    written.1.metadata
                )
                .is_err()
            );
            let configured_genesis_mismatch = headers::HeaderCheckpointConfig {
                network: NETWORK,
                genesis: Hash256::from_le_bytes(&[0x22; 32]),
            };
            assert!(matches!(
                headers::read_headers(
                    &mut Cursor::new(&written.0),
                    configured_genesis_mismatch,
                    written.1.metadata
                ),
                Err(headers::HeaderCheckpointError::ConfiguredGenesisMismatch { .. })
            ));
            let mut wrong_genesis = written.0;
            wrong_genesis[16] ^= 1;
            assert!(
                headers::read_headers(
                    &mut Cursor::new(wrong_genesis),
                    config(),
                    written.1.metadata
                )
                .is_err()
            );
            Ok(())
        }

        /// Regression coverage for the header-artifact wire contract in
        /// `crates/chain/src/checkpoint/headers.rs`: `prefix`/`parse_prefix` define the
        /// magic at bytes 0..8, version at 8..12, and count at 48..56; `read_headers` requires
        /// the encoded length to contain exactly the prefix, the 80-byte active headers, and
        /// the side section.
        ///
        /// Keep these offsets tied to that authoritative codec contract rather than treating
        /// them as incidental test fixture details.
        #[test]
        fn reader_rejects_bad_prefix_count_and_trailing_bytes() -> TestResult {
            let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
            let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

            let mut bad_magic = bytes.clone();
            bad_magic[0] ^= 1;
            assert!(
                headers::read_headers(&mut Cursor::new(bad_magic), config(), written.metadata)
                    .is_err()
            );
            let mut bad_version = bytes.clone();
            bad_version[8] ^= 1;
            assert!(
                headers::read_headers(&mut Cursor::new(bad_version), config(), written.metadata)
                    .is_err()
            );
            let mut bad_count = bytes.clone();
            bad_count[48] ^= 1;
            assert!(
                headers::read_headers(&mut Cursor::new(bad_count), config(), written.metadata)
                    .is_err()
            );
            let mut trailing = bytes;
            trailing.push(0);
            assert!(
                headers::read_headers(&mut Cursor::new(trailing), config(), written.metadata)
                    .is_err()
            );
            Ok(())
        }

        #[test]
        fn publication_selects_applied_ancestry_and_forgets_competing_fork() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (mut tree, main_best_id, applied_point) = chain_with_applied_height(3, 1)?;
            let main_best_hash = tree.node(main_best_id)?.hash;

            let genesis_hash = tree.node(NodeId::new(0))?.hash;
            let mut prev = BlockHash(genesis_hash);
            let mut fork_best_id = NodeId::new(0);
            for height in 1..=4 {
                let mut header = mined_regtest_header(prev, height)?;
                header.time = header.time.saturating_add(100);
                mine_header_to_declared_target(&mut header)?;
                fork_best_id = accept_headers(
                    &mut tree,
                    core::slice::from_ref(&header),
                    NETWORK,
                    crate::chain::current_unix_seconds(),
                    crate::chain::HeaderValidationMode::LiveAdmission,
                )?
                .ids[0];
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
                super::super::write_checkpoint(
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
                return Err(TestError::UnexpectedSuccess(
                    "checkpoint did not restore complete chainstate",
                ));
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
        fn utxo_payload_generation_is_refused_and_names_the_converter() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            super::super::write_checkpoint(
                dir.path(),
                config(),
                &RwLock::new(tree),
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            )?;
            mutate_authenticated_manifest(dir.path(), |manifest| {
                manifest.utxo = Some(bitcoin_rs_storage::checkpoint::UtxoArtifactV1 {
                    file: "utxo-snapshot.dat".to_owned(),
                    codec: bitcoin_rs_storage::checkpoint::UTXO_CODEC.to_owned(),
                    version: bitcoin_rs_storage::checkpoint::UTXO_VERSION,
                    bytes: 0,
                    sha256: "00".repeat(32),
                    record_count: 0,
                    output_count: 0,
                    muhash_trailer_sha256: "00".repeat(32),
                });
            })?;

            let Err(error) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "a generation carrying a utxo payload unexpectedly loaded",
                ));
            };
            assert!(
                matches!(
                    error,
                    bitcoin_rs_storage::checkpoint::CheckpointLoadError::UtxoPayloadRetired { .. }
                ),
                "a generation carrying a utxo payload must be refused as retired, got: {error:?}"
            );
            assert!(
                error.to_string().contains("bitcoin-rs-storage-convert"),
                "the refusal must name the converter, got: {error}"
            );
            Ok(())
        }

        #[test]
        fn semantic_utxo_trailing_byte_with_rebound_hashes_requires_resync() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(1, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            let utxo = UtxoSet::new();
            let listener = CoinStatsListener::new(CoinStats::new());
            super::super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
            )?;

            let root = dir.path().join(CHECKPOINT_ROOT);
            let current_path = root.join(CURRENT_FILE);
            let mut current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)?;
            let generation = root.join(&current.directory);
            let manifest_path = generation.join(MANIFEST_FILE);
            let mut manifest: CheckpointManifestV1 =
                sonic_rs::from_slice(&fs::read(&manifest_path)?)?;
            let headers_path = generation.join(HEADERS_FILE);
            let mut headers_bytes = fs::read(&headers_path)?;
            headers_bytes.push(0x5a);
            fs::write(&headers_path, &headers_bytes)?;
            manifest.headers.bytes = u64::try_from(headers_bytes.len())?;
            manifest.headers.sha256 = super::super::hex_encode(&Sha256::digest(&headers_bytes));
            let manifest_bytes = sonic_rs::to_vec(&manifest)?;
            fs::write(&manifest_path, &manifest_bytes)?;
            current.manifest_sha256 = super::super::hex_encode(&Sha256::digest(&manifest_bytes));
            fs::write(&current_path, sonic_rs::to_vec(&current)?)?;

            let Err(error) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "semantic UTXO corruption unexpectedly loaded",
                ));
            };
            assert!(
                matches!(error, CheckpointLoadError::Corrupt(_)),
                "unexpected checkpoint load error: {error}"
            );
            Ok(())
        }

        #[test]
        fn authenticated_inner_header_version_is_fatal() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            super::super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            )?;
            mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
                bytes[8..12].copy_from_slice(&(headers::HEADER_VERSION + 1).to_le_bytes());
            })?;

            assert!(matches!(
                load_checkpoint(dir.path(), config()),
                Err(super::super::CheckpointLoadError::Corrupt(_))
            ));
            Ok(())
        }

        fn applied_stats(height: u32) -> CoinStats {
            let mut stats = CoinStats::new();
            stats.height = height;
            stats
        }

        fn generation_files(
            data_dir: &Path,
        ) -> TestResult<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
            let root = data_dir.join(CHECKPOINT_ROOT);
            let current_path = root.join(CURRENT_FILE);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)?;
            let generation = root.join(&current.directory);
            Ok((
                current_path,
                generation.join(HEADERS_FILE),
                generation.join(MANIFEST_FILE),
            ))
        }

        fn write_generation_with_side_leaf(data_dir: &Path) -> TestResult<Hash256> {
            let (mut tree, best, applied) = chain_with_applied_height(3, 1)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let fork_parent = tree
                .node_at_height_from(best, 1)
                .ok_or(TestError::Missing("height one missing"))?;
            let parent_hash = tree.node(fork_parent)?.hash;
            let leaf = side_leaf(parent_hash, 0)?;
            accept_headers(
                &mut tree,
                core::slice::from_ref(&leaf),
                NETWORK,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?;
            super::super::write_checkpoint(
                data_dir,
                config(),
                &RwLock::new(tree),
                &UtxoSet::new(),
                &CoinStatsListener::new(applied_stats(applied.height)),
                Some(&applied_tip),
            )?;
            Ok(parent_hash)
        }

        fn side_leaf(parent_hash: Hash256, salt: u32) -> TestResult<Header> {
            let mut header = mined_regtest_header(BlockHash(parent_hash), 2)?;
            header.time = header.time.saturating_add(100 + salt);
            mine_header_to_declared_target(&mut header)?;
            Ok(header)
        }

        const SIDE_HEADER_NONCE_LOW_BYTE: usize = 76;

        // RCV-01, RCV-04
        #[test]
        fn side_header_nonce_flip_with_valid_pow_is_refused_by_manifest_sha() -> TestResult {
            let dir = tempfile::tempdir()?;
            write_generation_with_side_leaf(dir.path())?;
            let (current_path, headers_path, manifest_path) = generation_files(dir.path())?;
            let current_bytes = fs::read(&current_path)?;
            let manifest_bytes = fs::read(&manifest_path)?;
            let manifest: CheckpointManifestV1 = sonic_rs::from_slice(&manifest_bytes)?;
            let mut bytes = fs::read(&headers_path)?;
            let side_count_at =
                headers::HEADER_PREFIX_LEN + 80 * usize::try_from(manifest.headers.header_count)?;
            let side_header_at = side_count_at + 8;
            let side = bytes[side_header_at..side_header_at + 80].to_vec();
            let mask = (1_u8..=u8::MAX)
                .find(|mask| {
                    let mut candidate = side.clone();
                    candidate[SIDE_HEADER_NONCE_LOW_BYTE] ^= mask;
                    header_from_row(&candidate)
                        .is_ok_and(|header| compact_is_met_by(header.bits, header.compute_hash().0))
                })
                .ok_or(TestError::Missing("no nonce flip keeps proof of work"))?;
            bytes[side_header_at + SIDE_HEADER_NONCE_LOW_BYTE] ^= mask;
            fs::write(&headers_path, &bytes)?;

            assert!(matches!(
                load_checkpoint(dir.path(), config()),
                Err(CheckpointLoadError::Corrupt(_))
            ));
            assert_eq!(fs::read(&headers_path)?, bytes);
            assert_eq!(fs::read(&manifest_path)?, manifest_bytes);
            assert_eq!(fs::read(&current_path)?, current_bytes);
            Ok(())
        }

        // RCV-01, RCV-04
        #[test]
        fn appended_valid_side_header_is_refused_by_manifest_length() -> TestResult {
            let dir = tempfile::tempdir()?;
            let parent_hash = write_generation_with_side_leaf(dir.path())?;
            let (current_path, headers_path, manifest_path) = generation_files(dir.path())?;
            let current_bytes = fs::read(&current_path)?;
            let manifest_bytes = fs::read(&manifest_path)?;
            let manifest: CheckpointManifestV1 = sonic_rs::from_slice(&manifest_bytes)?;
            let mut bytes = fs::read(&headers_path)?;
            let side_count_at =
                headers::HEADER_PREFIX_LEN + 80 * usize::try_from(manifest.headers.header_count)?;
            let count = u64::from_le_bytes(bytes[side_count_at..side_count_at + 8].try_into()?);
            let incremented = count
                .checked_add(1)
                .ok_or(TestError::Missing("side count overflow"))?;
            bytes[side_count_at..side_count_at + 8].copy_from_slice(&incremented.to_le_bytes());
            bytes.extend_from_slice(&headers::encode_header(&side_leaf(parent_hash, 1)?)?);
            fs::write(&headers_path, &bytes)?;

            assert!(matches!(
                load_checkpoint(dir.path(), config()),
                Err(CheckpointLoadError::Corrupt(_))
            ));
            assert_eq!(fs::read(&headers_path)?, bytes);
            assert_eq!(fs::read(&manifest_path)?, manifest_bytes);
            assert_eq!(fs::read(&current_path)?, current_bytes);
            Ok(())
        }
    }

    #[cfg(test)]
    mod artifact_consistency {
        use super::*;

        use sha2::Digest;

        #[test]
        fn checkpoint_transaction_counts_must_agree_when_known() -> TestResult {
            for chain_tx_count in [0, 1] {
                let dir = tempfile::tempdir()?;
                let (tree, _, applied) = chain_with_applied_height(0, 0)?;
                let applied_tip = tip_snapshot(&tree, applied)?;
                let tree = RwLock::new(tree);
                let applied_tip = crate::chain::TipSnapshot {
                    chain_tx_count: crate::chain::ChainTxCount::from_wire(chain_tx_count),
                    ..applied_tip
                };
                let mut stats = CoinStats::new();
                stats.finish_block(0, 1);
                super::super::write_checkpoint(
                    dir.path(),
                    config(),
                    &tree,
                    &UtxoSet::new(),
                    &CoinStatsListener::new(stats),
                    Some(&applied_tip),
                )?;
                let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())?
                else {
                    return Err(TestError::UnexpectedSuccess(
                        "valid checkpoint did not load",
                    ));
                };
                assert_eq!(
                    restored.applied_tip.chain_tx_count.to_wire(),
                    chain_tx_count
                );
                assert_eq!(restored.coin_stats.tx_count, 1);

                mutate_authenticated_manifest(dir.path(), |manifest| {
                    manifest.applied_tip.chain_tx_count = 2;
                })?;
                let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config())
                else {
                    return Err(TestError::UnexpectedSuccess(
                        "inconsistent authenticated transaction counts were restored",
                    ));
                };
            }
            Ok(())
        }

        #[test]
        fn checkpoint_writer_refuses_inconsistent_transaction_counts() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let applied_tip = crate::chain::TipSnapshot {
                chain_tx_count: crate::chain::ChainTxCount::established(2),
                ..applied_tip
            };
            let result = super::super::write_checkpoint(
                dir.path(),
                config(),
                &RwLock::new(tree),
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            );
            let Err(_) = result else {
                return Err(TestError::UnexpectedSuccess(
                    "inconsistent transaction counts were published",
                ));
            };
            assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
            Ok(())
        }
        #[test]
        fn checkpoint_writer_refuses_height_mismatch() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let mut stats = CoinStats::new();
            stats.finish_block(1, 0);
            let result = super::super::write_checkpoint(
                dir.path(),
                config(),
                &RwLock::new(tree),
                &UtxoSet::new(),
                &CoinStatsListener::new(stats),
                Some(&applied_tip),
            );
            let Err(_) = result else {
                return Err(TestError::UnexpectedSuccess(
                    "stale CoinStats unexpectedly published",
                ));
            };
            assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
            Ok(())
        }

        #[test]
        fn authenticated_header_semantics_require_resync() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(2, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            super::super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            )?;
            mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
                bytes[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
            })?;

            let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "corrupt header checkpoint unexpectedly loaded",
                ));
            };
            Ok(())
        }

        /// The offsets below are the checkpoint envelope (16 bytes) followed by the stable
        /// `CoinStats::to_bytes` layout defined in `crates/storage/src/utxo/stats/coin_stats.rs`:
        /// `MuHash` numerator/denominator, then height, total amount, bogo size, transaction
        /// count, and UTXO count.
        ///
        /// The `full resync` assertion is the checkpoint recovery contract documented in
        /// `docs/policies/db-migration.md` and exercised by the loader.
        #[test]
        fn authenticated_coinstats_semantics_require_resync() -> TestResult {
            const COINSTATS_ENVELOPE_BYTES: usize = 16;
            const MUHASH_BYTES: usize = 384 + 384;
            const HEIGHT_BYTES: usize = 4;
            const U64_BYTES: usize = 8;
            const COINSTATS_FIELD_OFFSETS: [usize; 6] = [
                COINSTATS_ENVELOPE_BYTES,
                COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES,
                COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES,
                COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + U64_BYTES,
                COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 2 * U64_BYTES,
                COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 3 * U64_BYTES,
            ];

            for offset in COINSTATS_FIELD_OFFSETS {
                let dir = tempfile::tempdir()?;
                let (tree, _, applied) = chain_with_applied_height(0, 0)?;
                let applied_tip = tip_snapshot(&tree, applied)?;
                let tree = RwLock::new(tree);
                super::super::write_checkpoint(
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
                    return Err(TestError::UnexpectedSuccess(
                        "corrupt CoinStats checkpoint unexpectedly loaded",
                    ));
                };
                assert!(
                    matches!(error, CheckpointLoadError::Corrupt(_)),
                    "unexpected checkpoint load error: {error}"
                );
            }
            Ok(())
        }

        #[test]
        fn engine_image_tamper_requires_resync() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let data_dir = super::super::open_data_dir(dir.path())?;
            let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
            let write = super::super::write_checkpoint_with_store(
                &data_dir,
                config(),
                &RwLock::new(tree),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
                super::super::CheckpointStoreTarget {
                    store: &store,
                    host_data_dir: dir.path(),
                },
            )?;
            assert!(matches!(write, CheckpointWrite::Published { .. }));
            let root = dir.path().join(CHECKPOINT_ROOT);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
            let image = root
                .join(&current.directory)
                .join("chainstate")
                .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE);
            let mut image_bytes = fs::read(&image)?;
            image_bytes.pop();
            fs::write(&image, &image_bytes)?;
            let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "truncated engine image unexpectedly loaded",
                ));
            };
            Ok(())
        }

        #[test]
        fn engine_image_value_flip_requires_resync() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let data_dir = super::super::open_data_dir(dir.path())?;
            let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
                Hash256::from_le_bytes(&[7u8; 32]),
                &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                    vout: 0,
                    value: 50_000,
                    script_pubkey: vec![0x76, 0xa9, 0x14, 0, 0, 0x88, 0xac],
                    coinbase: true,
                    height: 0,
                }],
            )?;
            {
                use bitcoin_rs_storage::KvStore;
                let mut batch = store.new_batch();
                batch.put(
                    bitcoin_rs_storage::ColumnFamily::Coins,
                    bitcoin_rs_storage::CoinKey([7u8; 32]).as_bytes(),
                    record.bytes(),
                );
                store.write(batch)?;
            }
            let write = super::super::write_checkpoint_with_store(
                &data_dir,
                config(),
                &RwLock::new(tree),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
                super::super::CheckpointStoreTarget {
                    store: &store,
                    host_data_dir: dir.path(),
                },
            )?;
            assert!(matches!(write, CheckpointWrite::Published { .. }));
            let root = dir.path().join(CHECKPOINT_ROOT);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
            let image = root
                .join(&current.directory)
                .join("chainstate")
                .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE);
            let mut image_bytes = fs::read(&image)?;
            let needle = record.bytes().to_vec();
            let Some(offset) = image_bytes
                .windows(needle.len())
                .position(|window| window == needle.as_slice())
            else {
                return Err(TestError::UnexpectedSuccess(
                    "checkpoint image lacks the minted coin record",
                ));
            };
            image_bytes[offset + needle.len() / 2] ^= 0x01;
            fs::write(&image, &image_bytes)?;
            let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "flipped engine coin value unexpectedly loaded",
                ));
            };
            Ok(())
        }

        #[test]
        fn publish_swap_between_commit_and_open_yields_integrity() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let data_dir = super::super::open_data_dir(dir.path())?;
            let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
            let write = super::super::write_checkpoint_with_store(
                &data_dir,
                config(),
                &RwLock::new(tree),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
                super::super::CheckpointStoreTarget {
                    store: &store,
                    host_data_dir: dir.path(),
                },
            )?;
            assert!(matches!(write, CheckpointWrite::Published { .. }));
            let root = dir.path().join(CHECKPOINT_ROOT);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
            let manifest_path = root.join(&current.directory).join(MANIFEST_FILE);
            let mut manifest_bytes = fs::read(&manifest_path)?;
            manifest_bytes.push(b'\n');
            fs::write(&manifest_path, &manifest_bytes)?;
            let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "swapped manifest unexpectedly loaded",
                ));
            };
            Ok(())
        }

        fn write_engine_checkpoint(data_dir: &Path) -> TestResult<std::path::PathBuf> {
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let staged = super::super::open_data_dir(data_dir)?;
            let store = bitcoin_rs_storage::memory_kv::MemoryKvStore::new();
            let write = super::super::write_checkpoint_with_store(
                &staged,
                config(),
                &RwLock::new(tree),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
                super::super::CheckpointStoreTarget {
                    store: &store,
                    host_data_dir: data_dir,
                },
            )?;
            assert!(matches!(write, CheckpointWrite::Published { .. }));
            let root = data_dir.join(CHECKPOINT_ROOT);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
            Ok(root.join(current.directory))
        }

        #[test]
        fn engine_manifest_parent_traversal_is_refused() -> TestResult {
            let dir = tempfile::tempdir()?;
            let generation = write_engine_checkpoint(dir.path())?;
            std::fs::remove_file(
                generation
                    .join("chainstate")
                    .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE),
            )?;
            const SENTINEL: &[u8] = b"checkpoint traversal sentinel";
            let sentinel = generation.join("outside");
            std::fs::write(&sentinel, SENTINEL)?;
            let sentinel_len = u64::try_from(SENTINEL.len())?;
            let sentinel_sha = super::super::hex_encode(&sha2::Sha256::digest(SENTINEL));
            let mut rewrote_engine = false;
            mutate_authenticated_manifest(dir.path(), |manifest| {
                let Some(engine) = manifest.engine.as_mut() else {
                    return;
                };
                engine.files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
                    file: "../outside".to_owned(),
                    bytes: sentinel_len,
                    sha256: sentinel_sha.clone(),
                }];
                rewrote_engine = true;
            })?;
            if !rewrote_engine {
                return Err(TestError::UnexpectedSuccess(
                    "checkpoint lacks an engine image",
                ));
            }
            let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "parent-traversal engine record unexpectedly loaded",
                ));
            };
            assert_eq!(std::fs::read(&sentinel)?, SENTINEL);
            Ok(())
        }

        #[test]
        fn engine_manifest_absolute_path_is_refused() -> TestResult {
            let dir = tempfile::tempdir()?;
            let generation = write_engine_checkpoint(dir.path())?;
            std::fs::remove_file(
                generation
                    .join("chainstate")
                    .join(bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE),
            )?;
            const SENTINEL: &[u8] = b"checkpoint traversal sentinel";
            let sentinel = dir.path().join("abs-sentinel");
            std::fs::write(&sentinel, SENTINEL)?;
            let sentinel_len = u64::try_from(SENTINEL.len())?;
            let hostile = sentinel.to_string_lossy().into_owned();
            let sentinel_sha = super::super::hex_encode(&sha2::Sha256::digest(SENTINEL));
            let mut rewrote_engine = false;
            mutate_authenticated_manifest(dir.path(), |manifest| {
                let Some(engine) = manifest.engine.as_mut() else {
                    return;
                };
                engine.files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
                    file: hostile.clone(),
                    bytes: sentinel_len,
                    sha256: sentinel_sha.clone(),
                }];
                rewrote_engine = true;
            })?;
            if !rewrote_engine {
                return Err(TestError::UnexpectedSuccess(
                    "checkpoint lacks an engine image",
                ));
            }
            let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
                return Err(TestError::UnexpectedSuccess(
                    "absolute-path engine record unexpectedly loaded",
                ));
            };
            assert_eq!(std::fs::read(&sentinel)?, SENTINEL);
            Ok(())
        }

        #[test]
        fn engine_manifest_paths_are_refused_at_parse() -> TestResult {
            let dir = tempfile::tempdir()?;
            let generation = write_engine_checkpoint(dir.path())?;
            let generation_dir = super::super::open_data_dir(&generation)?;
            let identity = super::super::CheckpointIdentity {
                network: config().network,
                genesis: config().genesis,
            };
            let empty_sha = super::super::hex_encode(&Sha256::digest(b""));
            for (file, accepted) in [
                ("a/b", true),
                ("a//b", false),
                ("a/", false),
                ("a/.", false),
                ("./a", false),
                ("a/../b", false),
                ("", false),
            ] {
                let mut rewrote_engine = false;
                mutate_authenticated_manifest(dir.path(), |manifest| {
                    let Some(engine) = manifest.engine.as_mut() else {
                        return;
                    };
                    engine.files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
                        file: file.to_owned(),
                        bytes: 0,
                        sha256: empty_sha.clone(),
                    }];
                    rewrote_engine = true;
                })?;
                if !rewrote_engine {
                    return Err(TestError::UnexpectedSuccess(
                        "checkpoint lacks an engine image",
                    ));
                }
                let current: CurrentV1 = sonic_rs::from_slice(&fs::read(
                    dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE),
                )?)?;
                let manifest_bytes = fs::read(generation.join(MANIFEST_FILE))?;
                let reference = bitcoin_rs_storage::checkpoint::CheckpointReference {
                    generation: current.generation,
                    manifest_sha256: Sha256::digest(&manifest_bytes).into(),
                };
                let parsed = super::super::read_manifest(&generation_dir, &reference, identity);
                assert_eq!(parsed.is_ok(), accepted, "engine record {file:?}");
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod storage_roundtrip {
        use super::*;

        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

        const COINS: [(u8, u32, u64, &[u8], bool); 13] = [
            (7, 3, 50_000, &[0x51, 0x21], true),
            (0x11, 0, 1_000, &[0x51], false),
            (0x11, 3, 2_500, &[0x51, 0x52], false),
            (0x33, 0, 7, &[0x6a; 25], false),
            (0x39, 1, 10_000, &[0x51, 0x00, 0xac], true),
            (0x39, 4, 10_137, &[0x51, 0x01, 0xac], false),
            (0x39, 7, 10_274, &[0x51, 0x02, 0xac], true),
            (0x39, 10, 10_411, &[0x51, 0x03, 0xac], false),
            (0x39, 13, 10_548, &[0x51, 0x04, 0xac], true),
            (0x39, 16, 10_685, &[0x51, 0x05, 0xac], false),
            (0x39, 19, 10_822, &[0x51, 0x06, 0xac], true),
            (0x39, 22, 10_959, &[0x51, 0x07, 0xac], false),
            (0x39, 25, 11_096, &[0x51, 0x08, 0xac], true),
        ];
        const EXPECTED_UTXO_COUNT: u64 = 13;
        const EXPECTED_TOTAL_AMOUNT: u64 = 148_439;
        const EXPECTED_BOGO_SIZE: u64 = 52 + 51 + 52 + 75 + 53 * 9;

        fn record(
            txid_byte: u8,
            outputs: &[(u32, u64, &[u8], bool)],
        ) -> Result<UtxoRecord, bitcoin_rs_storage::utxo::UtxoError> {
            let outs: Vec<OwnedUtxoOut> = outputs
                .iter()
                .map(|&(vout, value, script, coinbase)| OwnedUtxoOut {
                    vout,
                    value,
                    script_pubkey: script.to_vec(),
                    coinbase,
                    height: 0,
                })
                .collect();
            UtxoRecord::from_owned_outputs(Hash256::from_le_bytes(&[txid_byte; 32]), &outs)
        }

        fn hand_built_utxo() -> Result<UtxoSet, bitcoin_rs_storage::utxo::UtxoError> {
            let utxo = populated_utxo()?;
            utxo.insert_parsed_record(record(
                0x11,
                &[(0, 1_000, &[0x51], false), (3, 2_500, &[0x51, 0x52], false)],
            )?);
            utxo.insert_parsed_record(record(0x33, &[(0, 7, &[0x6a; 25], false)])?);
            utxo.insert_parsed_record(record(
                0x39,
                &[
                    (1, 10_000, &[0x51, 0x00, 0xac], true),
                    (4, 10_137, &[0x51, 0x01, 0xac], false),
                    (7, 10_274, &[0x51, 0x02, 0xac], true),
                    (10, 10_411, &[0x51, 0x03, 0xac], false),
                    (13, 10_548, &[0x51, 0x04, 0xac], true),
                    (16, 10_685, &[0x51, 0x05, 0xac], false),
                    (19, 10_822, &[0x51, 0x06, 0xac], true),
                    (22, 10_959, &[0x51, 0x07, 0xac], false),
                    (25, 11_096, &[0x51, 0x08, 0xac], true),
                ],
            )?);
            Ok(utxo)
        }

        fn rolling_stats() -> CoinStats {
            let mut stats = CoinStats::new();
            for (txid_byte, vout, value, script, coinbase) in COINS {
                let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[txid_byte; 32])), vout);
                let txout = TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: Script::from_bytes(script.to_vec()),
                };
                stats.insert_utxo(&outpoint, &txout, 0, coinbase);
            }
            stats
        }

        #[test]
        fn scanned_trailer_restores_independently_scanned_stats() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            let utxo = hand_built_utxo()?;
            let expected = rolling_stats();
            assert_eq!(expected.utxo_count, EXPECTED_UTXO_COUNT);
            assert_eq!(expected.total_amount, EXPECTED_TOTAL_AMOUNT);
            assert_eq!(expected.bogo_size, EXPECTED_BOGO_SIZE);
            super::super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &CoinStatsListener::new(expected.clone()),
                Some(&applied_tip),
            )?;

            let root = dir.path().join(CHECKPOINT_ROOT);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
            let generation = root.join(current.directory);
            assert!(generation.join(HEADERS_FILE).exists());
            assert!(generation.join(COINSTATS_FILE).exists());

            let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
                return Err(std::io::Error::other("scanned generation did not restore").into());
            };
            assert_eq!(restored.coin_stats.utxo_count, EXPECTED_UTXO_COUNT);
            assert_eq!(restored.coin_stats.total_amount, EXPECTED_TOTAL_AMOUNT);
            assert_eq!(restored.coin_stats.bogo_size, EXPECTED_BOGO_SIZE);
            assert_eq!(restored.coin_stats, expected);

            let engine = restored.engine.as_ref().ok_or(TestError::Missing(
                "the checkpoint generation carries no engine image",
            ))?;
            let restored_utxo = utxo_from_engine(engine.as_ref())?;
            restored_utxo.with_stable_view(|view| -> Result<(), TestError> {
                assert_eq!(view.record_count(), 4);
                assert_eq!(view.len(), COINS.len());
                for (txid_byte, vout, value, script, coinbase) in COINS {
                    let outpoint =
                        OutPoint::new(Txid(Hash256::from_le_bytes(&[txid_byte; 32])), vout);
                    let coin = view.get_entry(&outpoint).ok_or(TestError::Missing(
                        "the restored engine image is missing a fixture output",
                    ))?;
                    assert_eq!(coin.outpoint, outpoint);
                    assert_eq!(coin.txout.value, Amount::from_sat(value));
                    assert_eq!(coin.txout.script_pubkey.as_bytes(), script);
                    assert_eq!(coin.coinbase, coinbase);
                    assert_eq!(coin.height, 0);
                }
                Ok(())
            })?;
            let rescanned = restored_utxo.with_stable_view(|view| {
                scan_coin_stats(view, restored.applied_tip.height, true)
            })?;
            assert_eq!(
                rescanned.to_bytes(),
                restored.coin_stats.to_bytes(),
                "the engine image must hold exactly the coins the coinstats artifact counted"
            );

            let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 42);
            let txout = TxOut {
                value: Amount::from_sat(123_456),
                script_pubkey: Script::from_bytes(vec![0x51, 0xac]),
            };
            let mut stats = expected;
            stats.insert_utxo(&outpoint, &txout, restored.applied_tip.height, false);
            let listener = CoinStatsListener::new(stats);
            let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                vout: 42,
                value: 123_456,
                script_pubkey: vec![0x51, 0xac],
                coinbase: false,
                height: restored.applied_tip.height,
            };
            let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
                Hash256::from_le_bytes(&[0x5a; 32]),
                &[out],
            )?;
            restored_utxo.insert_parsed_record(record);
            let continued = restored_utxo.with_stable_view(|view| {
                scan_coin_stats(view, restored.applied_tip.height, true)
            })?;
            assert_eq!(listener.snapshot().to_bytes(), continued.to_bytes());
            restored_utxo.with_stable_view(|view| {
                assert_eq!(view.record_count(), 5);
                assert_eq!(view.len(), COINS.len() + 1);
            });
            Ok(())
        }

        fn utxo_from_engine(
            engine: &dyn bitcoin_rs_storage::KvStore,
        ) -> Result<UtxoSet, TestError> {
            let utxo = UtxoSet::new();
            for row in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
                let (_key, value) = row?;
                let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(
                    value.into_boxed_slice(),
                )
                .map_err(|_| TestError::Missing("the engine image holds a corrupt coin record"))?;
                utxo.insert_parsed_record(record);
            }
            Ok(utxo)
        }
    }

    #[cfg(test)]
    mod engine_image {
        use super::*;

        use std::path::PathBuf;

        fn publish_checkpoint_with_engine_image(data_dir: &Path) -> TestResult<PathBuf> {
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            super::super::write_checkpoint(
                data_dir,
                config(),
                &RwLock::new(tree),
                &UtxoSet::new(),
                &CoinStatsListener::new(CoinStats::new()),
                Some(&applied_tip),
            )?;
            let root = data_dir.join(CHECKPOINT_ROOT);
            let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
            Ok(root.join(current.directory).join("chainstate"))
        }

        fn replace_image_with_files(image: &Path, names: &[std::ffi::OsString]) -> TestResult {
            fs::remove_dir_all(image)?;
            fs::create_dir(image)?;
            for name in names {
                fs::write(image.join(name), b"foreign")?;
            }
            Ok(())
        }

        // RCV-10
        #[test]
        fn a_published_engine_image_restores_with_its_engine() -> TestResult {
            let dir = tempfile::tempdir()?;
            crate::events::initialize_data_dir(dir.path())?;
            publish_checkpoint_with_engine_image(dir.path())?;
            let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
                return Err(TestError::UnexpectedSuccess(
                    "valid checkpoint did not load",
                ));
            };
            assert!(restored.engine.is_some());
            let Ok(runtime) =
                crate::recovery::prepare_initial_state_with_engine(dir.path(), NETWORK, None, None)
            else {
                return Err(TestError::UnexpectedSuccess(
                    "valid runtime checkpoint did not load",
                ));
            };
            assert!(runtime.engine.is_some());
            assert_eq!(
                runtime.initial.applied_tip.as_ref().map(|tip| tip.height),
                Some(0)
            );
            Ok(())
        }

        // RCV-10
        #[test]
        fn a_generation_without_an_engine_image_restores_without_an_engine() -> TestResult {
            let dir = tempfile::tempdir()?;
            let image = publish_checkpoint_with_engine_image(dir.path())?;
            fs::remove_dir_all(&image)?;
            let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
                return Err(TestError::UnexpectedSuccess(
                    "a generation without an engine image did not load",
                ));
            };
            assert!(restored.engine.is_none());
            Ok(())
        }

        // RCV-10
        #[test]
        fn runtime_rejects_a_missing_checkpoint_image() -> TestResult {
            let dir = tempfile::tempdir()?;
            crate::events::initialize_data_dir(dir.path())?;
            let image = publish_checkpoint_with_engine_image(dir.path())?;
            let root = dir.path().join(CHECKPOINT_ROOT);
            let current_before = fs::read(root.join(CURRENT_FILE))?;
            let generation = image
                .parent()
                .ok_or(TestError::Missing("checkpoint generation"))?;
            let headers_before = fs::read(generation.join(HEADERS_FILE))?;
            let stats_before = fs::read(generation.join(COINSTATS_FILE))?;
            let manifest_before = fs::read(generation.join(MANIFEST_FILE))?;
            fs::remove_dir_all(&image)?;

            let result =
                crate::recovery::prepare_initial_state_with_engine(dir.path(), NETWORK, None, None);
            assert!(matches!(
                result,
                Err(crate::recovery::RecoveryError::CheckpointEngineImageMissing)
            ));
            assert_eq!(fs::read(root.join(CURRENT_FILE))?, current_before);
            assert_eq!(fs::read(generation.join(HEADERS_FILE))?, headers_before);
            assert_eq!(fs::read(generation.join(COINSTATS_FILE))?, stats_before);
            assert_eq!(fs::read(generation.join(MANIFEST_FILE))?, manifest_before);
            assert!(!image.exists());
            Ok(())
        }

        // RCV-10
        #[test]
        fn an_engine_image_that_cannot_be_identified_fails_the_load_closed() -> TestResult {
            let shapes: [(&str, &[&str]); 3] = [
                ("empty directory", &[]),
                ("unknown files", &["junk"]),
                ("two engines", &["mdbx.dat", "CURRENT", "OPTIONS-000001"]),
            ];
            for (shape, names) in shapes {
                let dir = tempfile::tempdir()?;
                let image = publish_checkpoint_with_engine_image(dir.path())?;
                let names: Vec<std::ffi::OsString> = names.iter().map(Into::into).collect();
                replace_image_with_files(&image, &names)?;
                assert!(
                    matches!(
                        load_checkpoint(dir.path(), config()),
                        Err(CheckpointLoadError::Corrupt(_))
                    ),
                    "{shape}: an engine image that cannot be identified must fail the load closed"
                );
            }
            Ok(())
        }

        // RCV-10
        #[cfg(all(unix, not(target_os = "macos")))]
        #[test]
        fn an_engine_image_with_a_non_utf8_file_name_fails_the_load_closed() -> TestResult {
            use std::os::unix::ffi::OsStringExt as _;

            let dir = tempfile::tempdir_in("/tmp")?;
            let image = publish_checkpoint_with_engine_image(dir.path())?;
            let foreign = std::ffi::OsString::from_vec(b"\xff\xfenon-utf8".to_vec());
            replace_image_with_files(&image, &[foreign])?;
            assert!(
                matches!(
                    load_checkpoint(dir.path(), config()),
                    Err(CheckpointLoadError::Corrupt(_))
                ),
                "an engine image with a non-UTF-8 file name must fail the load closed"
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod tip_transitions {
        use super::*;

        #[test]
        fn writer_refuses_a_best_tip_that_is_not_active() -> TestResult {
            let (tree, _, applied) = chain_with_applied_height(3, 1)?;

            assert!(matches!(
                headers::write_headers(&mut Vec::new(), &tree, config(), NodeId::new(0), applied),
                Err(headers::HeaderCheckpointError::BestTipNotActive)
            ));
            Ok(())
        }

        #[test]
        fn writer_refuses_an_applied_tip_off_the_active_best_ancestry() -> TestResult {
            let (mut tree, best_tip_id, _) = chain_with_applied_height(3, 1)?;
            let genesis_hash = tree.node(NodeId::new(0))?.hash;
            let mut fork = mined_regtest_header(BlockHash(genesis_hash), 1)?;
            fork.time += 100;
            mine_header_to_declared_target(&mut fork)?;
            let fork_id = accept_headers(
                &mut tree,
                core::slice::from_ref(&fork),
                NETWORK,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?
            .ids[0];
            let fork = tree.node(fork_id)?;
            let applied = headers::HeaderCheckpointPoint {
                height: fork.height,
                hash: fork.hash,
            };

            assert!(matches!(
                headers::write_headers(&mut Vec::new(), &tree, config(), best_tip_id, applied),
                Err(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)
            ));
            Ok(())
        }

        #[test]
        fn immutable_generation_resumes_best_ahead_of_applied() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(3, 1)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            let utxo = UtxoSet::new();
            let mut stats = CoinStats::new();
            stats.height = applied.height;
            let listener = CoinStatsListener::new(stats);

            assert!(matches!(
                super::super::write_checkpoint(
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
                return Err(TestError::UnexpectedSuccess(
                    "checkpoint did not restore complete chainstate",
                ));
            };
            assert_eq!(restored.tree.tip().map(|tip| tip.height), Some(3));
            assert_eq!(restored.applied_tip.height, 1);
            assert_eq!(restored.applied_tip.hash, applied.hash);
            assert_eq!(restored.utxo.record_count(), 0);
            assert_eq!(restored.coin_stats.height, 1);
            Ok(())
        }

        #[test]
        fn no_applied_tip_skips_without_changing_current() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            let utxo = UtxoSet::new();
            let listener = CoinStatsListener::new(CoinStats::new());
            super::super::write_checkpoint(
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
                super::super::write_checkpoint(
                    dir.path(),
                    config(),
                    &tree,
                    &utxo,
                    &listener,
                    None
                )?,
                CheckpointWrite::SkippedNoAppliedTip
            );
            assert_eq!(fs::read(current_path)?, before);
            Ok(())
        }

        #[test]
        fn failed_publication_preserves_current() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (tree, _, applied) = chain_with_applied_height(0, 0)?;
            let applied_tip = tip_snapshot(&tree, applied)?;
            let tree = RwLock::new(tree);
            let utxo = UtxoSet::new();
            let listener = CoinStatsListener::new(CoinStats::new());

            super::super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
            )?;
            let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
            let before = fs::read(&current_path)?;

            super::super::inject_next_checkpoint_failpoint(
                super::super::CheckpointFailpoint::ManifestWrite,
            );
            let result = super::super::write_checkpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
            );
            let Err(error) = result else {
                panic!("manifest write failpoint must abort publication");
            };
            assert!(
                matches!(
                    error,
                    super::super::CheckpointError::Store(
                        bitcoin_rs_storage::checkpoint::CheckpointError::Io(ref io)
                    ) if io.raw_os_error() == Some(28)
                ),
                "ManifestWrite must surface the injected ENOSPC boundary"
            );
            assert_eq!(fs::read(current_path)?, before);
            Ok(())
        }
    }

    #[cfg(test)]
    mod headers_validation {
        use super::*;

        #[test]
        fn reader_rejects_mutated_linkage_and_invalid_pow_or_nbits() -> TestResult {
            let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
            let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

            let mut bad_prev = bytes.clone();
            bad_prev[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
            assert!(
                headers::read_headers(&mut Cursor::new(bad_prev), config(), written.metadata)
                    .is_err()
            );

            let mut bad_pow = bytes.clone();
            let header_offset = headers::HEADER_PREFIX_LEN + 80;
            let mut invalid = header_from_row(&bad_pow[header_offset..header_offset + 80])?;
            while compact_is_met_by(invalid.bits, invalid.compute_hash().0) {
                invalid.nonce = invalid
                    .nonce
                    .checked_add(1)
                    .ok_or(TestError::Missing("nonce exhausted"))?;
            }
            bad_pow[header_offset..header_offset + 80]
                .copy_from_slice(&headers::encode_header(&invalid)?);
            assert!(
                headers::read_headers(&mut Cursor::new(bad_pow), config(), written.metadata)
                    .is_err()
            );

            let mut bad_nbits = bytes;
            let previous = header_from_row(&bad_nbits[header_offset..header_offset + 80])?;
            let mut nbits_mismatch = Header {
                bits: CompactTarget::from_consensus(0x207f_fffe),
                ..previous
            };
            mine_header_to_declared_target(&mut nbits_mismatch)?;
            bad_nbits[header_offset..header_offset + 80]
                .copy_from_slice(&headers::encode_header(&nbits_mismatch)?);
            assert!(
                headers::read_headers(&mut Cursor::new(bad_nbits), config(), written.metadata)
                    .is_err()
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod side_branches {
        use super::*;
        use crate::chain::NodeStatus;
        use crate::test_fixtures::{TestError, TestResult};

        struct Branched {
            tree: BlockTree,
            best: NodeId,
            applied: headers::HeaderCheckpointPoint,
            invalid: Vec<Hash256>,
        }

        fn fork_header(
            tree: &mut BlockTree,
            parent: NodeId,
            height: u32,
            salt: u32,
        ) -> TestResult<NodeId> {
            let prev = BlockHash(tree.node(parent)?.hash);
            let mut header = mined_regtest_header(prev, height)?;
            header.time = header.time.saturating_add(100 + salt);
            mine_header_to_declared_target(&mut header)?;
            let accepted = accept_headers(
                tree,
                core::slice::from_ref(&header),
                NETWORK,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?;
            Ok(accepted.ids[0])
        }

        fn active_header(tree: &mut BlockTree, parent: NodeId, height: u32) -> TestResult<NodeId> {
            let header = mined_regtest_header(BlockHash(tree.node(parent)?.hash), height)?;
            let accepted = accept_headers(
                tree,
                core::slice::from_ref(&header),
                NETWORK,
                crate::chain::current_unix_seconds(),
                crate::chain::HeaderValidationMode::LiveAdmission,
            )?;
            Ok(accepted.ids[0])
        }

        fn branched() -> TestResult<Branched> {
            let (mut tree, main4, _) = chain_with_applied_height(4, 4)?;
            let at = |tree: &BlockTree, height| {
                tree.node_at_height_from(main4, height)
                    .ok_or(TestError::Missing("active height missing"))
            };
            let main2 = at(&tree, 2)?;
            let main3 = at(&tree, 3)?;
            let a4 = fork_header(&mut tree, main3, 4, 0)?;
            fork_header(&mut tree, a4, 5, 0)?;
            let main5 = active_header(&mut tree, main4, 5)?;
            fork_header(&mut tree, main4, 5, 1)?;
            let c3 = fork_header(&mut tree, main2, 3, 2)?;
            fork_header(&mut tree, c3, 4, 2)?;
            let invalid = tree.invalidate_subtree(c3)?;
            let best = active_header(&mut tree, main5, 6)?;
            fork_header(&mut tree, main5, 6, 3)?;
            assert_eq!(
                tree.tip_id(),
                Some(best),
                "equal work never displaces the best tip"
            );
            assert_eq!(invalid.invalid.len(), 2);
            let best_node = tree.node(best)?;
            let applied = headers::HeaderCheckpointPoint {
                height: best_node.height,
                hash: best_node.hash,
            };
            Ok(Branched {
                tree,
                best,
                applied,
                invalid: invalid.invalid,
            })
        }

        fn side_leaf_hashes(tree: &BlockTree, best: Hash256) -> TestResult<Vec<Hash256>> {
            let mut leaves = Vec::new();
            for id in tree.leaf_node_ids() {
                let node = tree.node(id)?;
                if node.status != NodeStatus::Invalid && node.hash != best {
                    leaves.push(node.hash);
                }
            }
            Ok(leaves)
        }

        fn publish(
            dir: &Path,
            tree: BlockTree,
            utxo: &UtxoSet,
            stats: CoinStats,
            applied: &TipSnapshot,
        ) -> TestResult {
            let published = super::super::write_checkpoint(
                dir,
                config(),
                &RwLock::new(tree),
                utxo,
                &CoinStatsListener::new(stats),
                Some(applied),
            )?;
            assert!(matches!(published, CheckpointWrite::Published { .. }));
            Ok(())
        }

        fn restore(dir: &Path) -> TestResult<super::super::RestoredChainstate> {
            match load_checkpoint(dir, config())? {
                CheckpointLoad::Complete(restored) => Ok(*restored),
                CheckpointLoad::Cold => {
                    Err(TestError::UnexpectedSuccess("checkpoint did not restore"))
                }
            }
        }

        fn applied_stats(height: u32) -> CoinStats {
            let mut stats = CoinStats::new();
            stats.height = height;
            stats
        }

        #[test]
        fn valid_side_branches_survive_restart_in_learn_order() -> TestResult {
            let dir = tempfile::tempdir()?;
            let fixture = branched()?;
            let original = &fixture.tree;
            let best_hash = original.node(fixture.best)?.hash;
            let expected_leaves = side_leaf_hashes(original, best_hash)?;
            assert_eq!(
                expected_leaves.len(),
                3,
                "a5, b5, and d6 are the valid side leaves"
            );
            let mut expected_all = Vec::new();
            for id in original.leaf_node_ids() {
                let node = original.node(id)?;
                if node.status != NodeStatus::Invalid {
                    expected_all.push(node.hash);
                }
            }
            let mut expected_nodes = Vec::new();
            for id in original.leaf_node_ids() {
                for ancestor in original.ancestor_chain(id)? {
                    let node = original.node(ancestor)?;
                    let parent = node
                        .parent
                        .map(|parent| original.node(parent).map(|parent| parent.hash))
                        .transpose()?;
                    expected_nodes.push((node.hash, node.height, node.chainwork, parent));
                }
            }
            let applied_tip = tip_snapshot(original, fixture.applied)?;
            let original_len = original.len();
            publish(
                dir.path(),
                fixture.tree,
                &UtxoSet::new(),
                applied_stats(fixture.applied.height),
                &applied_tip,
            )?;

            let super::super::RestoredChainstate {
                tree,
                utxo,
                coin_stats,
                applied_tip,
                ..
            } = restore(dir.path())?;
            publish(dir.path(), tree, &utxo, coin_stats, &applied_tip)?;
            let restored = restore(dir.path())?;
            let tree = &restored.tree;

            assert_eq!(tree.tip().map(|tip| tip.hash), Some(best_hash));
            assert_eq!(restored.applied_tip.hash, fixture.applied.hash);
            assert_eq!(tree.len(), original_len - fixture.invalid.len());
            for hash in &fixture.invalid {
                assert!(
                    tree.lookup(*hash).is_none(),
                    "invalid subtrees stay excluded"
                );
            }
            for (hash, height, chainwork, parent) in expected_nodes {
                if fixture.invalid.contains(&hash) {
                    continue;
                }
                let node = tree
                    .node_by_hash(hash)
                    .ok_or(TestError::Missing("retained node missing"))?;
                let restored_parent = node
                    .parent
                    .map(|parent| tree.node(parent).map(|parent| parent.hash))
                    .transpose()?;
                assert_eq!((node.height, node.chainwork), (height, chainwork));
                assert_eq!(restored_parent, parent);
                assert_ne!(node.status, NodeStatus::Invalid);
            }
            assert_eq!(
                side_leaf_hashes(tree, best_hash)?,
                expected_leaves,
                "side leaves keep their relative learn order across active-first restore"
            );
            let mut restored_all = Vec::new();
            for id in tree.leaf_node_ids() {
                restored_all.push(tree.node(id)?.hash);
            }
            assert_ne!(
                restored_all, expected_all,
                "active-first restore moves the best tip earlier while side-leaf order holds"
            );
            assert_ne!(
                tree.tip_id(),
                Some(fixture.best),
                "the fixture interleaves learning, so active-first restore moves slab positions"
            );
            Ok(())
        }

        #[test]
        fn active_only_artifact_still_loads_without_side_branches() -> TestResult {
            let dir = tempfile::tempdir()?;
            let fixture = branched()?;
            let tree = &fixture.tree;
            let best_hash = tree.node(fixture.best)?.hash;
            let mut ancestry = tree.ancestor_chain(fixture.best)?;
            ancestry.reverse();
            let mut active_only = Vec::new();
            active_only.extend_from_slice(b"BRSHEAD\0");
            active_only.extend_from_slice(&headers::ACTIVE_ONLY_HEADER_VERSION.to_le_bytes());
            active_only.extend_from_slice(&NETWORK.magic());
            active_only.extend_from_slice(&NETWORK.genesis_block_hash().to_le_bytes());
            active_only.extend_from_slice(&u64::try_from(ancestry.len())?.to_le_bytes());
            for id in &ancestry {
                active_only.extend_from_slice(&headers::encode_header(&tree.node(*id)?.header)?);
            }
            let applied_tip = tip_snapshot(tree, fixture.applied)?;
            publish(
                dir.path(),
                fixture.tree,
                &UtxoSet::new(),
                applied_stats(fixture.applied.height),
                &applied_tip,
            )?;
            mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
                *bytes = active_only;
            })?;
            mutate_authenticated_manifest(dir.path(), |manifest| {
                manifest.headers.version = headers::ACTIVE_ONLY_HEADER_VERSION;
            })?;

            let restored = restore(dir.path())?;
            assert_eq!(restored.tree.len(), ancestry.len());
            assert_eq!(restored.tree.tip().map(|tip| tip.hash), Some(best_hash));
            assert_eq!(restored.applied_tip.hash, fixture.applied.hash);
            Ok(())
        }

        #[test]
        fn reader_rejects_malformed_side_sections() -> TestResult {
            let fixture = branched()?;
            let (bytes, written) = write_checkpoint(&fixture.tree, fixture.best, fixture.applied)?;
            let metadata = written.metadata;
            let active_end = headers::HEADER_PREFIX_LEN + 80 * 7;
            let side_start = active_end + 8;
            let side_count = u64::from_le_bytes(bytes[active_end..side_start].try_into()?);
            assert_eq!(side_count, 4, "a4, a5, b5, and d6 are retained");
            let read = |bytes: Vec<u8>, metadata| {
                headers::read_headers(&mut Cursor::new(bytes), config(), metadata)
            };

            let truncated = bytes[..bytes.len() - 1].to_vec();
            assert!(matches!(
                read(truncated, metadata),
                Err(headers::HeaderCheckpointError::InvalidFileLength { .. })
            ));
            let mut inflated = bytes.clone();
            inflated[active_end..side_start].copy_from_slice(&(side_count + 1).to_le_bytes());
            assert!(matches!(
                read(inflated, metadata),
                Err(headers::HeaderCheckpointError::InvalidFileLength { .. })
            ));
            assert!(matches!(
                read(bytes[..active_end].to_vec(), metadata),
                Err(headers::HeaderCheckpointError::InvalidFileLength { .. })
            ));

            let first_active = headers::HEADER_PREFIX_LEN + 80;
            let mut duplicate = bytes.clone();
            duplicate.copy_within(first_active..first_active + 80, side_start);
            assert!(matches!(
                read(duplicate, metadata),
                Err(headers::HeaderCheckpointError::MalformedSideBranch { index: 0 })
            ));
            let mut orphan = bytes.clone();
            orphan[side_start + 4] ^= 1;
            assert!(matches!(
                read(orphan, metadata),
                Err(headers::HeaderCheckpointError::Chain(_))
            ));

            let best_hash = BlockHash(fixture.tree.node(fixture.best)?.hash);
            let heavier = mined_regtest_header(best_hash, 7)?;
            let mut displacing = bytes.clone();
            displacing[active_end..side_start].copy_from_slice(&(side_count + 1).to_le_bytes());
            displacing.extend_from_slice(&headers::encode_header(&heavier)?);
            assert!(matches!(
                read(displacing, metadata),
                Err(headers::HeaderCheckpointError::SideBranchDisplacedBestTip)
            ));

            let active_only_metadata = headers::HeaderCheckpointMetadata {
                version: headers::ACTIVE_ONLY_HEADER_VERSION,
                ..metadata
            };
            assert!(matches!(
                read(bytes[..active_end].to_vec(), active_only_metadata),
                Err(headers::HeaderCheckpointError::VersionMismatch {
                    manifest: 1,
                    artifact: 2,
                })
            ));
            Ok(())
        }
    }

    #[test]
    fn scratch_copy_isolates_owned_byte_copies_and_skips_stale_directories() -> TestResult {
        let dir = tempfile::tempdir()?;
        let chainstate = dir.path().join("chainstate");
        fs::create_dir_all(&chainstate)?;
        let original_bytes = b"authoritative-checkpoint-engine-bytes";
        fs::write(chainstate.join("CURRENT"), original_bytes)?;

        let files = vec![bitcoin_rs_storage::checkpoint::EngineFileV1 {
            file: "CURRENT".to_owned(),
            bytes: u64::try_from(original_bytes.len())?,
            sha256: super::hex_encode(&Sha256::digest(original_bytes)),
        }];

        let pid = std::process::id();
        let stale = dir.path().join(format!(".scratch-{pid}-0"));
        fs::create_dir_all(&stale)?;
        fs::write(stale.join("stale.dat"), b"stale-residue")?;

        let sequence = std::sync::atomic::AtomicU64::new(0);
        let scratch = super::scratch_copy_with_sequence(&sequence, &chainstate, &files)?;
        assert_eq!(scratch.path, dir.path().join(format!(".scratch-{pid}-1")));
        assert_ne!(scratch.path, stale);
        assert!(stale.exists());
        assert_eq!(fs::read(stale.join("stale.dat"))?, b"stale-residue");

        let scratch_file = scratch.path.join("CURRENT");
        assert_eq!(fs::read(&scratch_file)?, original_bytes);

        fs::write(&scratch_file, b"corrupted-scratch-mutation-payload")?;
        assert_eq!(
            fs::read(chainstate.join("CURRENT"))?,
            original_bytes,
            "overwriting scratch bytes must not mutate the published checkpoint bytes"
        );

        let scratch_path = scratch.path.clone();
        drop(scratch);
        assert!(!scratch_path.exists());
        assert!(stale.exists());

        Ok(())
    }
}
