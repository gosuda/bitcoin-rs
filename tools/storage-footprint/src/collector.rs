//! Storage footprint measurement collector and identity projection.

use crate::evidence::StorageFootprintEvidence;
use anyhow::Result;
use bitcoin_rs_node::config::NodeConfig;

/// Optional overrides for one measurement invocation.
#[derive(Clone, Debug, Default)]
pub struct MeasureStorageRequest {
    /// Conservative peak allocated bytes from an isolated filesystem or project quota.
    pub high_water_allocated_bytes: Option<u64>,
    /// Pinned stop height. Pairing and hash format: `FP-03`.
    pub stop_height: Option<u32>,
    /// Pinned stop hash. Pairing and hash format: `FP-03`.
    pub stop_hash: Option<String>,
}

/// Collects both ledgers for `config.data_dir` without starting the node.
///
/// On non-Unix platforms, returns an error explaining that physical measurement requires POSIX `st_blocks`.
#[cfg(not(unix))]
pub fn measure_storage_footprint(
    _config: &NodeConfig,
    _request: &MeasureStorageRequest,
) -> Result<StorageFootprintEvidence> {
    anyhow::bail!(
        "physical storage-footprint measurement requires POSIX st_blocks and is only supported on Unix/Linux platforms"
    )
}

#[cfg(unix)]
pub use unix::measure_storage_footprint;

#[cfg(unix)]
mod unix {
    use super::{MeasureStorageRequest, StorageFootprintEvidence};
    use anyhow::{Context, bail};
    use bitcoin_rs_index::{IndexWatermark, Indexer};
    use bitcoin_rs_node::config::ScriptIndexMode;
    use bitcoin_rs_node::{StoreConsumer, open_store_inspection};
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_storage::cache_budget::{clamp_dbcache_bytes, split_cache_budget};
    use bitcoin_rs_storage::recovery_evidence::{AppliedTipWitness, MAX_FILE_BYTES};
    use bitcoin_rs_storage::{KvStore, StorageBackend};
    use sha2::{Digest, Sha256};
    use std::io::{self, Read};
    use std::os::fd::AsFd;
    use std::path::Path;
    use std::sync::Arc;

    use crate::evidence::{
        BudgetEvidence, EVIDENCE_FORMAT, EvidenceIdentity, IndexWatermarkEvidence, LogicalEvidence,
        PhysicalEvidence, WatermarkEvidence,
    };
    use crate::logical::{LogicalLedger, LogicalOwner, logical_store_owners};
    use crate::physical::{DataDirAnchor, dir_has_entries, opened_fd_path, opened_path_matches_fd};
    use crate::physical_types::FootprintError;

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

        let (logical, watermarks) = collect_logical(&anchor, config.storage.backend)?;
        let identity = evidence_identity(config, request, watermarks, &anchor)?;
        let budget = BudgetEvidence::evaluate(&identity, &physical);
        Ok(StorageFootprintEvidence {
            format: EVIDENCE_FORMAT,
            identity,
            logical: LogicalEvidence::from_ledger(&logical),
            physical: PhysicalEvidence::from_ledger(&physical),
            budget,
        })
    }

    struct LogicalScan<'a> {
        namespace: &'a str,
    }

    impl StoreConsumer for LogicalScan<'_> {
        type Output = Vec<LogicalOwner>;
        type Error = anyhow::Error;

        fn consume<S>(self, store: Arc<S>) -> Result<Self::Output>
        where
            S: KvStore,
        {
            Ok(logical_store_owners(&*store, self.namespace)?)
        }
    }

    struct TxIndexScan;

    impl StoreConsumer for TxIndexScan {
        type Output = (Vec<LogicalOwner>, IndexWatermarkEvidence);
        type Error = anyhow::Error;

        fn consume<S>(self, store: Arc<S>) -> Result<Self::Output>
        where
            S: KvStore,
        {
            let owners = logical_store_owners(&*store, "txindex")?;
            let watermarks = watermark_evidence(
                Indexer::new(store)
                    .watermarks()
                    .context("read txindex watermarks")?,
            );
            Ok((owners, watermarks))
        }
    }

    fn evidence_identity(
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

    fn read_witness_from_anchor(anchor: &DataDirAnchor, genesis: &str) -> Result<(u32, String)> {
        for name in ["applied-tip-witness.json", "applied-tip-witness.json.prev"] {
            if let Some(data) = anchor
                .read_child_file(name, MAX_FILE_BYTES)
                .map_err(|e| io_from_footprint(&e))?
            {
                if let Some(witness) = AppliedTipWitness::decode(&data, genesis) {
                    return Ok((witness.height, witness.block_hash));
                }
            }
        }
        Ok((0, genesis.to_owned()))
    }

    fn resolve_stop(
        request: &MeasureStorageRequest,
        witness_height: u32,
        witness_hash: String,
    ) -> Result<(u32, String, bool)> {
        match (request.stop_height, request.stop_hash.as_deref()) {
            (None, None) => Ok((witness_height, witness_hash, false)),
            (Some(_), None) | (None, Some(_)) => {
                bail!("--stop-height and --stop-hash must be supplied together");
            }
            (Some(height), Some(hash)) => {
                let parsed = Hash256::from_str_be(hash)
                    .with_context(|| format!("invalid --stop-hash {hash:?}"))?;
                Ok((height, parsed.to_string_be(), true))
            }
        }
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
        if StorageBackend::Fjall.is_compiled_in() {
            features.push("fjall".to_owned());
        }
        if StorageBackend::Redb.is_compiled_in() {
            features.push("redb".to_owned());
        }
        if StorageBackend::RocksDb.is_compiled_in() {
            features.push("rocksdb".to_owned());
        }
        features.sort();
        features
    }

    fn cargo_lock_sha256() -> String {
        let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
        bitcoin_rs_storage::checkpoint::hex_encode(&Sha256::digest(lock.as_bytes()))
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
        Ok(bitcoin_rs_storage::checkpoint::hex_encode(
            &hasher.finalize(),
        ))
    }

    fn collect_logical(
        anchor: &DataDirAnchor,
        backend: StorageBackend,
    ) -> Result<(LogicalLedger, IndexWatermarkEvidence)> {
        let mut logical = LogicalLedger::default();
        logical.push(
            anchor
                .logical_flat_block_files()
                .map_err(|error| io_from_footprint(&error))?,
        );

        if let Some(chainstate) = anchor
            .open_child_dir("chainstate")
            .map_err(|error| io_from_footprint(&error))?
        {
            if dir_has_entries(chainstate.as_fd()).map_err(|error| io_from_footprint(&error))? {
                let path = opened_fd_path(chainstate.as_fd());
                let owners = open_store_inspection(
                    backend,
                    &path,
                    LogicalScan {
                        namespace: "chainstate",
                    },
                )?;
                if !opened_path_matches_fd(chainstate.as_fd(), &path)? {
                    bail!("chainstate store directory replaced during footprint scan");
                }
                drop(chainstate);
                for owner in owners {
                    logical.push(owner);
                }
            }
        }

        let mut watermarks = IndexWatermarkEvidence {
            tx_lookup: None,
            script_history: None,
            script_live: None,
        };
        if let Some(txindex) = anchor
            .open_child_dir("txindex")
            .map_err(|error| io_from_footprint(&error))?
        {
            if dir_has_entries(txindex.as_fd()).map_err(|error| io_from_footprint(&error))? {
                let path = opened_fd_path(txindex.as_fd());
                let (owners, found) = open_store_inspection(backend, &path, TxIndexScan)?;
                if !opened_path_matches_fd(txindex.as_fd(), &path)? {
                    bail!("txindex store directory replaced during footprint scan");
                }
                drop(txindex);
                for owner in owners {
                    logical.push(owner);
                }
                watermarks = found;
            }
        }
        Ok((logical, watermarks))
    }

    fn io_from_footprint(error: &FootprintError) -> anyhow::Error {
        anyhow::Error::msg(error.to_string())
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
}
