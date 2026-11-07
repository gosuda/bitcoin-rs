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
pub(crate) struct ConversionReport {
    pub(crate) source_epoch: u32,
    pub(crate) target_epoch: u32,
    pub(crate) namespaces: Vec<NamespaceReport>,
    pub(crate) copied_files: Vec<CopiedFileReport>,
}
