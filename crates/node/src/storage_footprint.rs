//! Custody-grade data-directory storage-footprint evidence.
//!
//! Explicit measurement command surface. Not an RPC method, background scanner,
//! or dashboard. Physical collection is anchored at one opened data-directory
//! descriptor; logical collection reads key-value owners afterwards.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bitcoin_rs_index::{IndexWatermark, Indexer};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{
    DataDirAnchor, FootprintError, LogicalLedger, LogicalOwner, PhysicalLedger,
    PhysicalObservationKind, StorageBackend, clamp_dbcache_bytes, logical_store_owners,
    split_cache_budget,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::Network;
use crate::config::{NodeConfig, ScriptIndexMode};

/// Default unpruned, no-index mainnet peak budget: `1_000_000_000_000` allocated bytes.
pub const DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES: u64 = 1_000_000_000_000;

/// Evidence format identifier.
pub const EVIDENCE_FORMAT: &str = "bitcoin-rs-storage-footprint-v1";

/// Optional overrides for one measurement invocation.
#[derive(Clone, Debug, Default)]
pub struct MeasureStorageRequest {
    /// Conservative peak allocated bytes from an isolated filesystem or project quota.
    pub high_water_allocated_bytes: Option<u64>,
    /// Override for the recorded stop height.
    pub stop_height: Option<u32>,
    /// Override for the recorded stop hash (RPC display hex).
    pub stop_hash: Option<String>,
}

/// One custody-grade storage-footprint record.
#[derive(Clone, Debug, Serialize)]
pub struct StorageFootprintEvidence {
    /// Format identifier.
    pub format: &'static str,
    /// Resolved run and binary identity.
    pub identity: EvidenceIdentity,
    /// Logical owner ledger. Do not add to `physical`.
    pub logical: LogicalEvidence,
    /// Physical namespace ledger. Source of the data-directory budget.
    pub physical: PhysicalEvidence,
    /// Default-node 1 TB peak verdict.
    pub budget: BudgetEvidence,
}

/// Identity fields required on every live IBD record.
#[derive(Clone, Debug, Serialize)]
pub struct EvidenceIdentity {
    /// Crate version compiled into this binary.
    pub pkg_version: String,
    /// `git rev-parse HEAD` at compile time, when available.
    pub git_commit: Option<String>,
    /// rustc release line.
    pub rustc_release: Option<String>,
    /// rustc commit hash.
    pub rustc_commit: Option<String>,
    /// SHA-256 of the workspace `Cargo.lock` compiled into this binary.
    pub cargo_lock_sha256: String,
    /// Path of the running binary.
    pub binary_path: Option<String>,
    /// SHA-256 of the running binary.
    pub binary_sha256: Option<String>,
    /// Compiled cargo features of `bitcoin-rs-node`.
    pub features: Vec<String>,
    /// Consensus network.
    pub network: String,
    /// Storage backend.
    pub backend: String,
    /// `dbcache` in MiB.
    pub dbcache_mb: u64,
    /// Process cache budget in bytes.
    pub cache_budget_bytes: u64,
    /// Chainstate cache share in bytes.
    pub chainstate_cache_bytes: u64,
    /// Txindex cache share in bytes.
    pub txindex_cache_bytes: u64,
    /// Prune target in MiB; `0` is unpruned.
    pub prune_target_mb: u64,
    /// Whether Core `txindex` is enabled.
    pub txindex: bool,
    /// Script index mode spelling.
    pub script_index: String,
    /// Whether `blockfilterindex` is enabled. Unsupported until that namespace exists.
    pub blockfilterindex: bool,
    /// Classification lane for this configuration.
    pub index_lane: String,
    /// Stop height recorded for this run.
    pub stop_height: u32,
    /// Stop hash in RPC display hex.
    pub stop_hash: String,
    /// Durable index watermarks, if the `txindex` namespace could be opened.
    pub index_watermarks: IndexWatermarkEvidence,
}

/// Durable capability watermarks.
#[derive(Clone, Debug, Serialize)]
pub struct IndexWatermarkEvidence {
    /// Transaction lookup cursor.
    pub tx_lookup: Option<WatermarkEvidence>,
    /// Script history cursor.
    pub script_history: Option<WatermarkEvidence>,
    /// Script live-output cursor.
    pub script_live: Option<WatermarkEvidence>,
}

/// One `(height, hash)` watermark.
#[derive(Clone, Debug, Serialize)]
pub struct WatermarkEvidence {
    /// Indexed height.
    pub height: u32,
    /// Block hash in RPC display hex.
    pub hash: String,
}

/// Logical ledger as emitted in evidence.
#[derive(Clone, Debug, Serialize)]
pub struct LogicalEvidence {
    /// Owners in stable name order.
    pub owners: Vec<LogicalOwnerEvidence>,
    /// Sum of serialized key and value bytes. Not a filesystem allocation.
    pub serialized_bytes: u64,
    /// Reminder that this ledger is not the budget.
    pub not_a_filesystem_allocation: bool,
}

/// One logical owner row.
#[derive(Clone, Debug, Serialize)]
pub struct LogicalOwnerEvidence {
    /// Owner name.
    pub name: String,
    /// Row or framed-record count.
    pub rows: u64,
    /// Serialized key bytes.
    pub key_bytes: u64,
    /// Serialized value bytes.
    pub value_bytes: u64,
    /// Key plus value bytes.
    pub serialized_bytes: u64,
}

/// Physical ledger as emitted in evidence.
#[derive(Clone, Debug, Serialize)]
pub struct PhysicalEvidence {
    /// Top-level namespaces.
    pub namespaces: Vec<PhysicalNamespaceEvidence>,
    /// Root-level residual.
    pub residual: PhysicalNamespaceEvidence,
    /// Allocated bytes of the data directory, hard links counted once.
    pub allocated_bytes: u64,
    /// Distinct inodes counted.
    pub inode_count: u64,
    /// Snapshot versus conservative high-water.
    pub observation_kind: String,
    /// Conservative peak when supplied.
    pub high_water_allocated_bytes: Option<u64>,
    /// Figure a budget gate reads.
    pub budget_bytes: u64,
}

/// One physical namespace row.
#[derive(Clone, Debug, Serialize)]
pub struct PhysicalNamespaceEvidence {
    /// Namespace name.
    pub name: String,
    /// Allocated bytes.
    pub allocated_bytes: u64,
    /// Category breakdown.
    pub categories: BTreeMap<String, u64>,
}

/// Default-node peak-budget classification.
#[derive(Clone, Debug, Serialize)]
pub struct BudgetEvidence {
    /// `1_000_000_000_000` allocated bytes.
    pub default_unpruned_limit_bytes: u64,
    /// Whether this record is the default unpruned no-index mainnet configuration.
    pub applies_to_this_record: bool,
    /// Verdict spelling.
    pub verdict: String,
}

/// Collects both ledgers for `config.data_dir` without starting the node.
pub fn measure_storage_footprint(
    config: &NodeConfig,
    request: &MeasureStorageRequest,
) -> Result<StorageFootprintEvidence> {
    config.validate()?;
    let data_dir = &config.data_dir;
    if !data_dir.exists() {
        bail!("data directory {} does not exist", data_dir.display());
    }

    let anchor = DataDirAnchor::open(data_dir).map_err(|error| io_from_footprint(&error))?;
    let mut physical = anchor
        .measure_physical()
        .map_err(|error| io_from_footprint(&error))?;
    if let Some(high_water) = request.high_water_allocated_bytes {
        physical = physical
            .with_high_water(high_water)
            .map_err(|error| io_from_footprint(&error))?;
    }

    let (logical, watermarks) = collect_logical(&anchor, config)?;
    let identity = evidence_identity(config, request, watermarks);
    let budget = budget_evidence(&identity, &physical);
    Ok(StorageFootprintEvidence {
        format: EVIDENCE_FORMAT,
        identity,
        logical: LogicalEvidence::from_ledger(&logical),
        physical: PhysicalEvidence::from_ledger(&physical),
        budget,
    })
}

fn collect_logical(
    anchor: &DataDirAnchor,
    config: &NodeConfig,
) -> Result<(LogicalLedger, IndexWatermarkEvidence)> {
    let mut logical = LogicalLedger::default();
    logical.push(
        anchor
            .logical_flat_block_files()
            .map_err(|error| io_from_footprint(&error))?,
    );

    let chainstate_dir = config.data_dir.join("chainstate");
    if dir_has_entries(&chainstate_dir)? {
        for owner in scan_store(config.storage.backend, &chainstate_dir, "chainstate")? {
            logical.push(owner);
        }
    }

    let mut watermarks = IndexWatermarkEvidence {
        tx_lookup: None,
        script_history: None,
        script_live: None,
    };
    let txindex_dir = config.data_dir.join("txindex");
    if dir_has_entries(&txindex_dir)? {
        let (owners, found) = scan_store_with_watermarks(config.storage.backend, &txindex_dir)?;
        for owner in owners {
            logical.push(owner);
        }
        if let Some(found) = found {
            watermarks = found;
        }
    }
    Ok((logical, watermarks))
}

fn evidence_identity(
    config: &NodeConfig,
    request: &MeasureStorageRequest,
    watermarks: IndexWatermarkEvidence,
) -> EvidenceIdentity {
    let indexes_enabled = config.indexes.txindex || config.indexes.script_index.is_enabled();
    let cache_budget = clamp_dbcache_bytes(config.storage.dbcache_mb);
    let shares = split_cache_budget(cache_budget, indexes_enabled);
    let genesis = config.network.genesis_block_hash().to_string_be();
    let (witness_height, witness_hash) =
        match crate::recovery_evidence::read_witness(&config.data_dir, &genesis) {
            Some(witness) => (witness.height, witness.block_hash),
            None => (0, genesis),
        };
    EvidenceIdentity {
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
        network: crate::checkpoint::network_name(config.network).to_owned(),
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
        stop_height: request.stop_height.unwrap_or(witness_height),
        stop_hash: request.stop_hash.clone().unwrap_or(witness_hash),
        index_watermarks: watermarks,
    }
}

fn dir_has_entries(path: &Path) -> io::Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name();
        if name != "." && name != ".." {
            return Ok(true);
        }
    }
    Ok(false)
}

impl LogicalEvidence {
    fn from_ledger(ledger: &LogicalLedger) -> Self {
        Self {
            owners: ledger
                .owners
                .iter()
                .map(|owner| LogicalOwnerEvidence {
                    name: owner.name.clone(),
                    rows: owner.rows,
                    key_bytes: owner.key_bytes,
                    value_bytes: owner.value_bytes,
                    serialized_bytes: owner.serialized_bytes,
                })
                .collect(),
            serialized_bytes: ledger.serialized_bytes(),
            not_a_filesystem_allocation: true,
        }
    }
}

impl PhysicalEvidence {
    fn from_ledger(ledger: &PhysicalLedger) -> Self {
        Self {
            namespaces: ledger
                .namespaces
                .iter()
                .map(PhysicalNamespaceEvidence::from_namespace)
                .collect(),
            residual: PhysicalNamespaceEvidence::from_namespace(&ledger.residual),
            allocated_bytes: ledger.allocated_bytes,
            inode_count: ledger.inode_count,
            observation_kind: ledger.observation_kind.as_str().to_owned(),
            high_water_allocated_bytes: ledger.high_water_allocated_bytes,
            budget_bytes: ledger.budget_bytes(),
        }
    }
}

impl PhysicalNamespaceEvidence {
    fn from_namespace(namespace: &bitcoin_rs_storage::PhysicalNamespace) -> Self {
        Self {
            name: namespace.name.clone(),
            allocated_bytes: namespace.allocated_bytes,
            categories: namespace
                .categories
                .iter()
                .map(|(name, bytes)| ((*name).to_owned(), *bytes))
                .collect(),
        }
    }
}

fn budget_evidence(identity: &EvidenceIdentity, physical: &PhysicalLedger) -> BudgetEvidence {
    let applies = is_default_unpruned_mainnet(identity);
    let verdict = if !applies {
        "inapplicable"
    } else if physical.observation_kind != PhysicalObservationKind::ConservativeHighWater {
        "snapshot_insufficient"
    } else if physical.budget_bytes() <= DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES {
        "pass"
    } else {
        "fail"
    };
    BudgetEvidence {
        default_unpruned_limit_bytes: DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES,
        applies_to_this_record: applies,
        verdict: verdict.to_owned(),
    }
}

fn is_default_unpruned_mainnet(identity: &EvidenceIdentity) -> bool {
    identity.network == "mainnet"
        && identity.backend == "fjall"
        && identity.prune_target_mb == 0
        && !identity.txindex
        && identity.script_index == "disabled"
        && !identity.blockfilterindex
}

fn index_lane(config: &NodeConfig) -> String {
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


fn script_index_name(mode: ScriptIndexMode) -> &'static str {
    match mode {
        ScriptIndexMode::Disabled => "disabled",
        ScriptIndexMode::Utxo => "utxo",
        ScriptIndexMode::Full => "full",
    }
}

fn compiled_features() -> Vec<String> {
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
    if cfg!(feature = "mdbx") {
        features.push("mdbx".to_owned());
    }
    if cfg!(feature = "kernel") {
        features.push("kernel".to_owned());
    }
    if cfg!(feature = "zmq") {
        features.push("zmq".to_owned());
    }
    features
}

fn cargo_lock_sha256() -> String {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
    hex_sha256(Sha256::digest(lock.as_bytes()).as_slice())
}

fn sha256_file(path: &Path) -> io::Result<String> {
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

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn io_from_footprint(error: &FootprintError) -> anyhow::Error {
    anyhow::Error::msg(error.to_string())
}

fn scan_store(backend: StorageBackend, path: &Path, namespace: &str) -> Result<Vec<LogicalOwner>> {
    match backend {
        #[cfg(feature = "fjall")]
        StorageBackend::Fjall => {
            let store = bitcoin_rs_storage::FjallStore::open(path).map_err(anyhow::Error::new)?;
            Ok(logical_store_owners(&store, namespace)?)
        }
        #[cfg(feature = "redb")]
        StorageBackend::Redb => {
            let store = bitcoin_rs_storage::RedbStore::open(path).map_err(anyhow::Error::new)?;
            Ok(logical_store_owners(&store, namespace)?)
        }
        #[cfg(feature = "rocksdb")]
        StorageBackend::RocksDb => {
            let store = bitcoin_rs_storage::RocksDbStore::open(path).map_err(anyhow::Error::new)?;
            Ok(logical_store_owners(&store, namespace)?)
        }
        #[cfg(feature = "mdbx")]
        StorageBackend::Mdbx => {
            let store = bitcoin_rs_storage::MdbxStore::open(path).map_err(anyhow::Error::new)?;
            Ok(logical_store_owners(&store, namespace)?)
        }
        #[cfg(any(
            not(feature = "rocksdb"),
            not(feature = "fjall"),
            not(feature = "redb"),
            not(feature = "mdbx")
        ))]
        other => bail!("unsupported storage backend for footprint scan: {other}"),
    }
}

fn scan_store_with_watermarks(
    backend: StorageBackend,
    path: &Path,
) -> Result<(Vec<LogicalOwner>, Option<IndexWatermarkEvidence>)> {
    match backend {
        #[cfg(feature = "fjall")]
        StorageBackend::Fjall => {
            let store =
                Arc::new(bitcoin_rs_storage::FjallStore::open(path).map_err(anyhow::Error::new)?);
            let owners = logical_store_owners(&*store, "txindex")?;
            let watermarks = Indexer::new(store)
                .watermarks()
                .ok()
                .map(watermark_evidence);
            Ok((owners, watermarks))
        }
        #[cfg(feature = "redb")]
        StorageBackend::Redb => {
            let store =
                Arc::new(bitcoin_rs_storage::RedbStore::open(path).map_err(anyhow::Error::new)?);
            let owners = logical_store_owners(&*store, "txindex")?;
            let watermarks = Indexer::new(store)
                .watermarks()
                .ok()
                .map(watermark_evidence);
            Ok((owners, watermarks))
        }
        #[cfg(feature = "rocksdb")]
        StorageBackend::RocksDb => {
            let store =
                Arc::new(bitcoin_rs_storage::RocksDbStore::open(path).map_err(anyhow::Error::new)?);
            let owners = logical_store_owners(&*store, "txindex")?;
            let watermarks = Indexer::new(store)
                .watermarks()
                .ok()
                .map(watermark_evidence);
            Ok((owners, watermarks))
        }
        #[cfg(feature = "mdbx")]
        StorageBackend::Mdbx => {
            let store =
                Arc::new(bitcoin_rs_storage::MdbxStore::open(path).map_err(anyhow::Error::new)?);
            let owners = logical_store_owners(&*store, "txindex")?;
            let watermarks = Indexer::new(store)
                .watermarks()
                .ok()
                .map(watermark_evidence);
            Ok((owners, watermarks))
        }
        #[cfg(any(
            not(feature = "rocksdb"),
            not(feature = "fjall"),
            not(feature = "redb"),
            not(feature = "mdbx")
        ))]
        other => bail!("unsupported storage backend for footprint scan: {other}"),
    }
}

fn watermark_evidence(watermarks: bitcoin_rs_index::IndexWatermarks) -> IndexWatermarkEvidence {
    IndexWatermarkEvidence {
        tx_lookup: watermarks.tx_lookup.map(watermark_json),
        script_history: watermarks.script_history.map(watermark_json),
        script_live: watermarks.script_live.map(watermark_json),
    }
}

fn watermark_json(watermark: IndexWatermark) -> WatermarkEvidence {
    WatermarkEvidence {
        height: watermark.height,
        hash: Hash256::from_le_bytes(&watermark.hash).to_string_be(),
    }
}

/// Writes pretty JSON evidence.
pub fn storage_footprint_json(evidence: &StorageFootprintEvidence) -> Result<String> {
    serde_json::to_string_pretty(evidence).context("serialize storage footprint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_storage::measure_physical_tree;
    use tempfile::tempdir;

    #[test]
    fn default_regtest_record_is_inapplicable_to_the_mainnet_budget() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
        assert_eq!(evidence.format, EVIDENCE_FORMAT);
        assert_eq!(evidence.identity.network, "regtest");
        assert_eq!(evidence.identity.index_lane, "default");
        assert!(!evidence.budget.applies_to_this_record);
        assert_eq!(evidence.budget.verdict, "inapplicable");
        assert!(evidence.logical.not_a_filesystem_allocation);
        assert_eq!(
            evidence.physical.observation_kind,
            PhysicalObservationKind::SnapshotLowerBound.as_str()
        );
        assert!(
            evidence
                .logical
                .owners
                .iter()
                .any(|owner| owner.name == "blocks.flat_files")
        );
        Ok(())
    }

    #[test]
    fn conservative_high_water_can_pass_the_default_mainnet_budget() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let mut config = NodeConfig::default_for_network(Network::Mainnet);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        config.p2p.dns_seeds_enabled = false;
        let snapshot =
            measure_physical_tree(dir.path()).map_err(|error| io_from_footprint(&error))?;
        let evidence = measure_storage_footprint(
            &config,
            &MeasureStorageRequest {
                high_water_allocated_bytes: Some(snapshot.allocated_bytes),
                stop_height: Some(0),
                stop_hash: None,
            },
        )?;
        assert!(evidence.budget.applies_to_this_record);
        assert_eq!(evidence.budget.verdict, "pass");
        assert_eq!(
            evidence.physical.observation_kind,
            PhysicalObservationKind::ConservativeHighWater.as_str()
        );
        Ok(())
    }

    #[test]
    fn snapshot_of_default_mainnet_is_insufficient_for_the_peak_gate() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let mut config = NodeConfig::default_for_network(Network::Mainnet);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        config.p2p.dns_seeds_enabled = false;
        let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
        assert!(evidence.budget.applies_to_this_record);
        assert_eq!(evidence.budget.verdict, "snapshot_insufficient");
        Ok(())
    }

    #[test]
    fn identity_names_the_txindex_lane() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        config.indexes.txindex = true;
        let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
        assert_eq!(evidence.identity.index_lane, "txindex");
        assert!(evidence.identity.txindex);
        assert!(!evidence.budget.applies_to_this_record);
        Ok(())
    }

    #[test]
    fn high_water_above_budget_fails_the_default_mainnet_gate() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let mut config = NodeConfig::default_for_network(Network::Mainnet);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        config.p2p.dns_seeds_enabled = false;
        let evidence = measure_storage_footprint(
            &config,
            &MeasureStorageRequest {
                high_water_allocated_bytes: Some(
                    DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES.saturating_add(1),
                ),
                stop_height: Some(0),
                stop_hash: None,
            },
        )?;
        assert!(evidence.budget.applies_to_this_record);
        assert_eq!(evidence.budget.verdict, "fail");
        Ok(())
    }

    #[test]
    fn empty_chainstate_directory_is_not_created_as_a_store() -> Result<()> {
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let chainstate = dir.path().join("chainstate");
        std::fs::create_dir(&chainstate)?;
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
        assert!(
            !evidence
                .logical
                .owners
                .iter()
                .any(|owner| owner.name.starts_with("chainstate.")),
            "empty chainstate must not be opened into column-family owners"
        );
        assert!(
            std::fs::read_dir(&chainstate)?.next().is_none(),
            "measurement must not initialize an empty chainstate directory"
        );
        Ok(())
    }

    #[cfg(feature = "fjall")]
    #[test]
    fn logical_chainstate_rows_are_named_owners() -> Result<()> {
        use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore, WriteBatch};
        let dir = tempdir()?;
        std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
        let chainstate = dir.path().join("chainstate");
        std::fs::create_dir(&chainstate)?;
        let store = FjallStore::open(&chainstate).map_err(anyhow::Error::new)?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::UndoData, b"k", b"value-bytes");
        store.write(batch).map_err(anyhow::Error::new)?;
        drop(store);
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
        let undo = evidence
            .logical
            .owners
            .iter()
            .find(|owner| owner.name == "chainstate.undo_data")
            .ok_or_else(|| anyhow::anyhow!("undo owner"))?;
        assert_eq!(undo.rows, 1);
        assert_eq!(undo.key_bytes, 1);
        assert_eq!(undo.value_bytes, 11);
        assert!(
            evidence
                .physical
                .namespaces
                .iter()
                .any(|namespace| namespace.name == "chainstate")
        );
        Ok(())
    }
}
