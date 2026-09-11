//! Build, chain, and configuration identity bound into storage evidence.

use super::EvidenceIdentity;
use super::IndexWatermarkEvidence;
use super::MeasureStorageRequest;
use super::scan::io_from_footprint;
use crate::config::NodeConfig;
use crate::config::ScriptIndexMode;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::DataDirAnchor;
use bitcoin_rs_storage::clamp_dbcache_bytes;
use bitcoin_rs_storage::split_cache_budget;
use sha2::Digest;
use sha2::Sha256;
use std::io;
use std::io::Read;
use std::path::Path;

pub(super) fn evidence_identity(
    config: &NodeConfig,
    request: &MeasureStorageRequest,
    watermarks: IndexWatermarkEvidence,
    anchor: &DataDirAnchor,
) -> Result<EvidenceIdentity> {
    let indexes_enabled = config.indexes.txindex || config.indexes.script_index.is_enabled();
    let cache_budget = clamp_dbcache_bytes(config.storage.dbcache_mb);
    let shares = split_cache_budget(cache_budget, indexes_enabled);
    let genesis = config.network.genesis_block_hash().to_string_be();
    let (witness_height, witness_hash) = read_witness_from_anchor(anchor, &genesis)?;
    let (stop_height, stop_hash, stop_pinned) =
        resolve_stop(request, witness_height, witness_hash)?;
    Ok(EvidenceIdentity {
        pkg_version: env!("CARGO_PKG_VERSION").to_owned(),
        git_commit: option_env!("GIT_COMMIT").map(ToOwned::to_owned),
        rustc_release: option_env!("RUSTC_RELEASE").map(ToOwned::to_owned),
        rustc_commit: option_env!("RUSTC_COMMIT").map(ToOwned::to_owned),
        cargo_lock_sha256: cargo_lock_sha256(),
        binary_path: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        binary_sha256: std::env::current_exe()
            .ok()
            .and_then(|path| sha256_file(&path).ok()),
        features: compiled_features(),
        network: config.network.identity_name().to_owned(),
        backend: config.storage.backend.as_str().to_owned(),
        dbcache_mb: config.storage.dbcache_mb,
        cache_budget_bytes: cache_budget,
        chainstate_cache_bytes: shares[0].bytes,
        txindex_cache_bytes: shares[1].bytes,
        prune_target_mb: config.storage.prune_target_mb,
        txindex: config.indexes.txindex,
        script_index: script_index_name(config.indexes.script_index).to_owned(),
        blockfilterindex: false,
        index_lane: index_lane(config),
        stop_height,
        stop_hash,
        stop_pinned,
        index_watermarks: watermarks,
    })
}

pub(super) fn resolve_stop(
    request: &MeasureStorageRequest,
    witness_height: u32,
    witness_hash: String,
) -> Result<(u32, String, bool)> {
    match (request.stop_height, request.stop_hash.as_deref()) {
        (None, None) => Ok((witness_height, witness_hash, false)),
        (Some(_), None) | (None, Some(_)) => {
            bail!(
                "--measure-storage-stop-height and --measure-storage-stop-hash must be supplied together"
            );
        }
        (Some(height), Some(hash)) => {
            let parsed = Hash256::from_str_be(hash)
                .with_context(|| format!("invalid --measure-storage-stop-hash {hash:?}"))?;
            Ok((height, parsed.to_string_be(), true))
        }
    }
}

pub(super) fn read_witness_from_anchor(
    anchor: &DataDirAnchor,
    genesis: &str,
) -> Result<(u32, String)> {
    const CURRENT: &str = "applied-tip-witness.json";
    const PREV: &str = "applied-tip-witness.json.prev";
    for name in [CURRENT, PREV] {
        if let Some(bytes) = anchor
            .read_child_file(name, crate::recovery_evidence::MAX_FILE_BYTES)
            .map_err(|error| io_from_footprint(&error))?
        {
            if let Some(witness) =
                crate::recovery_evidence::decode_applied_tip_witness(&bytes, genesis)
            {
                return Ok((witness.height, witness.block_hash));
            }
        }
    }
    Ok((0, genesis.to_owned()))
}

pub(super) fn index_lane(config: &NodeConfig) -> String {
    if config.storage.prune_target_mb > 0 {
        return "pruned".to_owned();
    }
    match (config.indexes.txindex, config.indexes.script_index) {
        (false, ScriptIndexMode::Disabled) => "default".to_owned(),
        (true, ScriptIndexMode::Disabled) => "txindex".to_owned(),
        (false, ScriptIndexMode::Utxo) => "scriptindex-utxo".to_owned(),
        (false, ScriptIndexMode::Full) => "scriptindex-full".to_owned(),
        (true, ScriptIndexMode::Utxo) => "txindex+scriptindex-utxo".to_owned(),
        (true, ScriptIndexMode::Full) => "txindex+scriptindex-full".to_owned(),
    }
}

pub(super) fn script_index_name(mode: ScriptIndexMode) -> &'static str {
    match mode {
        ScriptIndexMode::Disabled => "disabled",
        ScriptIndexMode::Utxo => "utxo",
        ScriptIndexMode::Full => "full",
    }
}

pub(super) fn compiled_features() -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "fjall") {
        features.push("fjall".to_owned());
    }
    if cfg!(feature = "redb") {
        features.push("redb".to_owned());
    }
    if cfg!(feature = "rocksdb") {
        features.push("rocksdb".to_owned());
    }
    if cfg!(feature = "kernel") {
        features.push("kernel".to_owned());
    }
    if cfg!(feature = "zmq") {
        features.push("zmq".to_owned());
    }
    features
}

pub(super) fn cargo_lock_sha256() -> String {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
    hex_sha256(Sha256::digest(lock.as_bytes()).as_slice())
}

pub(super) fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_sha256(hasher.finalize().as_slice()))
}

pub(super) fn hex_sha256(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
