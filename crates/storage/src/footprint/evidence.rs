//! Storage-footprint evidence record format and default-lane budget verdict.
//!
//! The measurement orchestration and identity projection live in the node
//! crate; this module owns the emitted record shape and the FP-04 verdict
//! policy.

use serde::Serialize;

use crate::footprint::{
    LogicalLedger, LogicalOwner, PhysicalLedger, PhysicalNamespace, PhysicalObservationKind,
};

/// Default unpruned, no-index mainnet peak budget: `1_000_000_000_000` allocated bytes.
pub const DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES: u64 = 1_000_000_000_000;

/// Evidence format identifier.
pub const EVIDENCE_FORMAT: &str = "bitcoin-rs-storage-footprint-v1";

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
    pub owners: Vec<LogicalOwner>,
    /// Sum of serialized key and value bytes. Not a filesystem allocation.
    pub serialized_bytes: u64,
    /// Reminder that this ledger is not the budget.
    pub not_a_filesystem_allocation: bool,
}

/// Physical ledger as emitted in evidence.
#[derive(Clone, Debug, Serialize)]
pub struct PhysicalEvidence {
    /// Top-level namespaces.
    pub namespaces: Vec<PhysicalNamespace>,
    /// Root-level residual.
    pub residual: PhysicalNamespace,
    /// Allocated bytes of the data directory, hard links counted once.
    pub allocated_bytes: u64,
    /// Distinct inodes counted.
    pub inode_count: u64,
    /// Snapshot versus conservative high-water.
    pub observation_kind: PhysicalObservationKind,
    /// Conservative peak when supplied.
    pub high_water_allocated_bytes: Option<u64>,
    /// Figure a budget gate reads.
    pub budget_bytes: u64,
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

impl LogicalEvidence {
    /// Projects a logical ledger into evidence rows.
    pub fn from_ledger(ledger: &LogicalLedger) -> Self {
        Self {
            owners: ledger.owners.clone(),
            serialized_bytes: ledger.serialized_bytes(),
            not_a_filesystem_allocation: true,
        }
    }
}

impl PhysicalEvidence {
    /// Projects a physical ledger into evidence rows.
    pub fn from_ledger(ledger: &PhysicalLedger) -> Self {
        Self {
            namespaces: ledger.namespaces.clone(),
            residual: ledger.residual.clone(),
            allocated_bytes: ledger.allocated_bytes,
            inode_count: ledger.inode_count,
            observation_kind: ledger.observation_kind,
            high_water_allocated_bytes: ledger.high_water_allocated_bytes,
            budget_bytes: ledger.budget_bytes(),
        }
    }
}

impl BudgetEvidence {
    /// Evaluates the default unpruned peak budget against one record's
    /// identity and physical ledger.
    pub fn evaluate(identity: &EvidenceIdentity, physical: &PhysicalLedger) -> Self {
        let applies = is_default_unpruned_mainnet(identity);
        let over_budget = physical.budget_bytes() > DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES;
        let conservative_high_water =
            physical.observation_kind == PhysicalObservationKind::ConservativeHighWater;
        let verdict = if !applies {
            "inapplicable"
        } else if over_budget {
            "fail"
        } else if !conservative_high_water {
            "snapshot_insufficient"
        } else if !identity.stop_pinned {
            "tip_unpinned"
        } else {
            "pass"
        };
        Self {
            default_unpruned_limit_bytes: DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES,
            applies_to_this_record: applies,
            verdict: verdict.to_owned(),
        }
    }
}

fn is_default_unpruned_mainnet(identity: &EvidenceIdentity) -> bool {
    identity.network == "mainnet"
        && identity.backend == "fjall"
        && identity.prune_target_mb == 0
        && !identity.txindex
        && identity.script_index == "disabled"
        && !identity.blockfilterindex
        && identity.index_lane == "default"
}

/// Writes pretty JSON evidence.
pub fn storage_footprint_json(
    evidence: &StorageFootprintEvidence,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(evidence)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    // CONTRACT: `docs/contracts/storage-footprint.md` FP-01 owns the evidence
    // record shape and FP-04 owns the default-lane budget verdict policy;
    // these tests are proof, not policy.
    use super::*;

    fn identity(network: &str, stop_pinned: bool) -> EvidenceIdentity {
        EvidenceIdentity {
            pkg_version: "0.0.0".to_owned(),
            git_commit: None,
            rustc_release: None,
            rustc_commit: None,
            cargo_lock_sha256: "00".to_owned(),
            binary_path: None,
            binary_sha256: None,
            features: Vec::new(),
            network: network.to_owned(),
            backend: "fjall".to_owned(),
            dbcache_mb: 0,
            cache_budget_bytes: 0,
            chainstate_cache_bytes: 0,
            txindex_cache_bytes: 0,
            prune_target_mb: 0,
            txindex: false,
            script_index: "disabled".to_owned(),
            blockfilterindex: false,
            index_lane: "default".to_owned(),
            stop_height: 0,
            stop_hash: "00".to_owned(),
            stop_pinned,
            index_watermarks: IndexWatermarkEvidence {
                tx_lookup: None,
                script_history: None,
                script_live: None,
            },
        }
    }

    #[test]
    fn budget_verdict_orders_fail_snapshot_pin_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let snapshot = crate::footprint::measure_physical_tree(dir.path()).expect("measure");
        let allocated = snapshot.allocated_bytes;
        // Off the default lane the verdict is inapplicable.
        let budget = BudgetEvidence::evaluate(&identity("regtest", true), &snapshot);
        assert!(!budget.applies_to_this_record);
        assert_eq!(budget.verdict, "inapplicable");

        // A non-default index lane is inapplicable even when every other
        // field is default-shaped (FP-04 names the lane explicitly).
        let mut off_lane = identity("mainnet", true);
        off_lane.index_lane = "txindex".to_owned();
        let budget = BudgetEvidence::evaluate(&off_lane, &snapshot);
        assert!(!budget.applies_to_this_record);
        assert_eq!(budget.verdict, "inapplicable");

        // Snapshot alone cannot satisfy a peak gate.
        let budget = BudgetEvidence::evaluate(&identity("mainnet", true), &snapshot);
        assert!(budget.applies_to_this_record);
        assert_eq!(budget.verdict, "snapshot_insufficient");

        // High-water below budget but no pinned stop.
        let high_water = snapshot
            .clone()
            .with_high_water(allocated)
            .expect("high water");
        let budget = BudgetEvidence::evaluate(&identity("mainnet", false), &high_water);
        assert_eq!(budget.verdict, "tip_unpinned");

        // High-water below budget and pinned stop passes.
        let budget = BudgetEvidence::evaluate(&identity("mainnet", true), &high_water);
        assert_eq!(budget.verdict, "pass");

        // Over-budget fails regardless of pin state.
        let over = snapshot
            .with_high_water(DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES + 1)
            .expect("high water");
        let budget = BudgetEvidence::evaluate(&identity("mainnet", true), &over);
        assert_eq!(budget.verdict, "fail");
    }
}
