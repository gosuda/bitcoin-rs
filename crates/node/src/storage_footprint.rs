//! Custody-grade data-directory storage-footprint evidence.
//!
//! Explicit measurement command surface. Not an RPC method, background scanner,
//! or dashboard. Physical collection is anchored at one opened data-directory
//! descriptor; logical collection reads key-value owners afterwards.

mod budget;
mod identity;
mod scan;

use crate::config::NodeConfig;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_index::Indexer;
use bitcoin_rs_storage::DataDirAnchor;
use bitcoin_rs_storage::LogicalLedger;
use bitcoin_rs_storage::LogicalOwner;
use bitcoin_rs_storage::PhysicalLedger;
#[cfg(test)]
use bitcoin_rs_storage::PhysicalObservationKind;
use bitcoin_rs_storage::logical_store_owners;
use budget::budget_evidence;
use identity::evidence_identity;
use scan::collect_logical;
use scan::io_from_footprint;
use scan::watermark_evidence;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Default unpruned, no-index mainnet peak budget: `1_000_000_000_000` allocated bytes.
pub const DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES: u64 = 1_000_000_000_000;

/// Evidence format identifier.
pub const EVIDENCE_FORMAT: &str = "bitcoin-rs-storage-footprint-v1";

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
    /// Whether both stop height and hash were supplied together by the caller.
    pub stop_pinned: bool,
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

    let (logical, watermarks) = collect_logical(&anchor, config.storage.backend)?;
    let identity = evidence_identity(config, request, watermarks, &anchor)?;
    let budget = budget_evidence(&identity, &physical);
    Ok(StorageFootprintEvidence {
        format: EVIDENCE_FORMAT,
        identity,
        logical: LogicalEvidence::from_ledger(&logical),
        physical: PhysicalEvidence::from_ledger(&physical),
        budget,
    })
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

struct LogicalScan<'a> {
    namespace: &'a str,
}

impl crate::storage_backend::StoreConsumer for LogicalScan<'_> {
    type Output = Vec<LogicalOwner>;
    type Error = anyhow::Error;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output>
    where
        S: bitcoin_rs_storage::KvStore,
    {
        Ok(logical_store_owners(&*store, self.namespace)?)
    }
}

struct TxIndexScan;

impl crate::storage_backend::StoreConsumer for TxIndexScan {
    type Output = (Vec<LogicalOwner>, Option<IndexWatermarkEvidence>);
    type Error = anyhow::Error;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output>
    where
        S: bitcoin_rs_storage::KvStore,
    {
        let owners = logical_store_owners(&*store, "txindex")?;
        let watermarks = Indexer::new(store)
            .watermarks()
            .ok()
            .map(watermark_evidence);
        Ok((owners, watermarks))
    }
}

/// Writes pretty JSON evidence.
pub fn storage_footprint_json(evidence: &StorageFootprintEvidence) -> Result<String> {
    serde_json::to_string_pretty(evidence).context("serialize storage footprint")
}

#[cfg(test)]
mod tests;
