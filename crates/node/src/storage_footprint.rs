//! Custody-grade data-directory storage-footprint evidence.
//!
//! Explicit measurement command surface. Not an RPC method, background scanner,
//! or dashboard. Physical collection is anchored at one opened data-directory
//! descriptor; logical collection reads key-value owners afterwards.
//!
//! The evidence record format and budget verdict are owned by
//! `bitcoin_rs_storage::footprint::evidence`; this module owns measurement
//! orchestration and identity projection only.

mod identity;
mod scan;

use crate::config::NodeConfig;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_index::Indexer;
use bitcoin_rs_storage::DataDirAnchor;
use bitcoin_rs_storage::LogicalOwner;
#[cfg(test)]
use bitcoin_rs_storage::PhysicalObservationKind;
use bitcoin_rs_storage::logical_store_owners;
use identity::evidence_identity;
use scan::collect_logical;
use scan::io_from_footprint;
use scan::watermark_evidence;
use std::sync::Arc;

use bitcoin_rs_storage::footprint::evidence::{
    BudgetEvidence, EVIDENCE_FORMAT, EvidenceIdentity, IndexWatermarkEvidence, LogicalEvidence,
    PhysicalEvidence, WatermarkEvidence,
};
pub use bitcoin_rs_storage::footprint::evidence::{
    StorageFootprintEvidence, storage_footprint_json,
};

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

#[cfg(test)]
mod tests;
