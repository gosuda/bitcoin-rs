use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FamilyReport {
    pub(crate) family: String,
    #[serde(alias = "count")]
    pub(crate) row_count: u64,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NamespaceReport {
    pub(crate) namespace: String,
    pub(crate) engine: String,
    pub(crate) families: Vec<FamilyReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CopiedFileReport {
    pub(crate) path: String,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CoinStatsReport {
    pub(crate) height: u32,
    pub(crate) utxo_count: u64,
    pub(crate) total_amount: u64,
    pub(crate) muhash: String,
    pub(crate) tx_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NormalizedUndoRowReport {
    pub(crate) height: u32,
    pub(crate) hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConversionReport {
    pub(crate) source_epoch: u32,
    pub(crate) target_epoch: u32,
    pub(crate) namespaces: Vec<NamespaceReport>,
    pub(crate) copied_files: Vec<CopiedFileReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) checkpoint_stats: Option<CoinStatsReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_stats: Option<CoinStatsReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) normalized_undo_rows: Vec<NormalizedUndoRowReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) carried_markers: Vec<String>,
    #[serde(default)]
    pub(crate) published_checkpoint: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RebuildIndexReport {
    pub(crate) datadir: String,
    pub(crate) engine: String,
    pub(crate) format_version: u32,
    pub(crate) blocks: u64,
    pub(crate) budget_refusals: u64,
    pub(crate) families: Vec<FamilyResetReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FamilyResetReport {
    pub(crate) family: String,
    pub(crate) rows_removed: u64,
}
