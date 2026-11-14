mod artifact;
mod chain;
mod compact_filters;
mod export;
mod manifest;
mod restore;
mod script_history;

use crate::writer::TxIndexWriter;
use crate::{IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark};
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_execution::chain::{BlockTreeReader, TipReader};
use bitcoin_rs_storage::block_body::BlockBodySource;
use std::path::{Path, PathBuf};

pub use crate::segment::spill::{RESTORE_SPILL_BUDGET_BYTES, SpillBudget};
pub use compact_filters::{CompactFilterArtifact, write_compact_filter_artifact};
pub(crate) use restore::reset_interrupted_import;
pub use restore::{
    attach_compact_filter_artifact, attach_script_history_artifact, attach_tx_lookup_artifact,
};
pub use script_history::{ScriptHistoryArtifact, write_script_history_artifact};
#[derive(Clone, Debug)]
pub struct IndexBundleRequest {
    pub dir: PathBuf,
    pub network: Network,
}

#[derive(Clone, Debug, Default)]
pub enum IndexBundleDirective {
    #[default]
    None,
    Restore(IndexBundleRequest),
    Export(IndexBundleRequest),
    AttachManifestArtifact(Box<ManifestArtifactTarget>),
    AttachManifestScriptHistory(Box<ManifestArtifactTarget>),
    AttachManifestCompactFilters(Box<ManifestArtifactTarget>),
    Manifest(Vec<IndexBundleDirective>),
}

#[derive(Clone, Debug)]
pub struct ManifestArtifactTarget {
    pub artifact_path: PathBuf,
    pub base_height: u32,
    pub base_hash: [u8; 32],
    pub floor: u32,
    pub network: Network,
    pub index_format: u32,
    pub sha256: [u8; 32],
    pub size_bytes: u64,
    pub chain_tx_count: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum IndexBundleError {
    #[error("portable index bundles need the txindex capability enabled")]
    TxLookupDisabled,
    #[error("portable script history bundles need the script history capability enabled")]
    ScriptHistoryDisabled,
    #[error("portable compact filter bundles need the compact filter capability enabled")]
    CompactFiltersDisabled,
    #[error("bundle I/O at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("export refused, index not ready: {0}")]
    NotReady(&'static str),
    #[error("export aborted: index watermarks moved while streaming")]
    Stale,
    #[error("a bundle file already exists at {}", .0.display())]
    ExistingBundle(PathBuf),
    #[error(transparent)]
    ScriptHistoryImport(#[from] crate::segment::import::ScriptHistoryImportError),
    #[error("bundle manifest invalid: {0}")]
    Manifest(String),
    #[error("bundle declares unsupported capability {0}")]
    UnsupportedCapability(&'static str),
    #[error("artifact {name} has {actual} bytes, the manifest declares {expected}")]
    ArtifactLength {
        name: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("artifact {name} SHA-256 does not match the manifest")]
    ArtifactHash { name: &'static str },
    #[error("artifact {name} header invalid: {reason}")]
    ArtifactHeader {
        name: &'static str,
        reason: &'static str,
    },
    #[error("artifact {name} record {record} invalid: {reason}")]
    ArtifactFraming {
        name: &'static str,
        record: u64,
        reason: &'static str,
    },
    #[error("bundle identity refused: {0}")]
    Identity(String),
    #[error("the txindex already has a watermark; restore needs a fresh capability")]
    NotFresh,
    #[error("a recorded locator at height {height} does not resolve to its transaction id")]
    Locator { height: u32 },
    #[error("bundle omits transactions at height {height}: expected {expected}, found {actual}")]
    Incomplete {
        height: u32,
        expected: u64,
        actual: u64,
    },
    #[error("block body read failed at height {height}: {reason}")]
    BodyRead { height: u32, reason: String },
    #[error("block body unavailable at height {height}; export needs every indexed block")]
    BodyUnavailable { height: u32 },
    #[error("source index row invalid at height {height}: {reason}")]
    SourceRow { height: u32, reason: &'static str },
    #[error("bundle operation cancelled")]
    Cancelled,
    #[error("index error: {0}")]
    Index(#[from] IndexError),
}

#[derive(Debug)]
pub(crate) enum BundleOutcome {
    Exported(ExportReport),
    Restored(RestoreReport),
    RestoreWithheld(Withheld),
}

#[derive(Debug)]
pub(crate) struct ExportReport {
    pub(crate) base: IndexWatermark,
    pub(crate) records: u64,
    pub(crate) bytes: u64,
}

#[derive(Debug)]
pub(crate) struct RestoreReport {
    pub(crate) base: IndexWatermark,
    pub(crate) records: u64,
    pub(crate) rows: usize,
}

#[derive(Debug)]
pub(crate) enum Withheld {
    NoBodySource,
    BodyUnavailable { height: u32 },
}

pub(crate) struct BundleHost<'a> {
    pub(crate) writer: &'a dyn TxIndexWriter,
    pub(crate) reader: &'a dyn IndexReader,
    pub(crate) block_tree: &'a BlockTreeReader,
    pub(crate) applied_tip: &'a TipReader,
    pub(crate) body_source: Option<&'a dyn BlockBodySource>,
    pub(crate) enabled: IndexCapabilities,
    pub(crate) cancelled: &'a dyn Fn() -> bool,
}

pub(crate) fn run(
    host: &BundleHost<'_>,
    directive: &IndexBundleDirective,
) -> Result<Option<BundleOutcome>, IndexBundleError> {
    match directive {
        IndexBundleDirective::None => Ok(None),
        IndexBundleDirective::Export(request) => {
            export::export(host, request).map(|report| Some(BundleOutcome::Exported(report)))
        }
        IndexBundleDirective::Restore(request) => restore::restore(host, request).map(Some),
        IndexBundleDirective::AttachManifestArtifact(target) => {
            attach_manifest_artifact(host, target)
        }
        IndexBundleDirective::AttachManifestScriptHistory(target) => {
            attach_manifest_script_history(host, target)
        }
        IndexBundleDirective::AttachManifestCompactFilters(target) => {
            attach_manifest_compact_filters(host, target)
        }
        IndexBundleDirective::Manifest(directives) => {
            let mut last = None;
            for directive in directives {
                if let Some(outcome) = run(host, directive)? {
                    last = Some(outcome);
                }
            }
            Ok(last)
        }
    }
}

fn attach_manifest_artifact(
    host: &BundleHost<'_>,
    target: &ManifestArtifactTarget,
) -> Result<Option<BundleOutcome>, IndexBundleError> {
    if !host.enabled.contains(IndexCapability::TxLookup) {
        return Err(IndexBundleError::TxLookupDisabled);
    }
    let (_, watermarks) = host
        .writer
        .fenced_watermarks()
        .map_err(IndexBundleError::Index)?;
    if watermarks
        .tx_lookup
        .is_some_and(|existing| existing.height >= target.base_height)
    {
        return Ok(None);
    }
    let base = IndexWatermark {
        height: target.base_height,
        hash: target.base_hash,
    };
    let tree = host.block_tree.read();
    let count = usize::try_from(target.base_height.saturating_add(1)).unwrap_or(0);
    let mut headers = Vec::with_capacity(count);
    let tip_hash = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&target.base_hash);
    let tip_node = tree.lookup(tip_hash).ok_or_else(|| {
        IndexBundleError::Identity(
            "the receiver chain has no header at the manifest base".to_owned(),
        )
    })?;
    for height in 0..=target.base_height {
        let id = tree.node_at_height_from(tip_node, height).ok_or_else(|| {
            IndexBundleError::Identity("missing header in active chain".to_owned())
        })?;
        let node = tree
            .node(id)
            .map_err(|_| IndexBundleError::Identity("node lookup failed".to_owned()))?;
        let mut header_bytes = [0_u8; 80];
        header_bytes.copy_from_slice(
            &bitcoin_rs_consensus::primitives::consensus_bytes(&node.header)[..80],
        );
        headers.push(header_bytes);
    }
    drop(tree);
    let scratch = target
        .artifact_path
        .parent()
        .unwrap_or(&target.artifact_path);
    let header_refs: Vec<&[u8; 80]> = headers.iter().collect();
    let budget = SpillBudget::new(RESTORE_SPILL_BUDGET_BYTES);
    let records =
        restore::attach_tx_lookup_artifact(host.writer, target, &header_refs, scratch, &budget)?;
    Ok(Some(BundleOutcome::Restored(RestoreReport {
        base,
        records,
        rows: usize::try_from(records).unwrap_or(usize::MAX),
    })))
}

fn attach_manifest_script_history(
    host: &BundleHost<'_>,
    target: &ManifestArtifactTarget,
) -> Result<Option<BundleOutcome>, IndexBundleError> {
    if !host.enabled.contains(IndexCapability::ScriptHistory) {
        return Err(IndexBundleError::ScriptHistoryDisabled);
    }
    let (_, watermarks) = host
        .writer
        .fenced_watermarks()
        .map_err(IndexBundleError::Index)?;
    if watermarks
        .script_history
        .is_some_and(|existing| existing.height >= target.base_height)
    {
        return Ok(None);
    }
    let base = IndexWatermark {
        height: target.base_height,
        hash: target.base_hash,
    };
    let scratch = target
        .artifact_path
        .parent()
        .unwrap_or(&target.artifact_path);
    let block_hashes = chain_block_hashes(host.block_tree, target.base_height, target.base_hash)?;
    let budget = SpillBudget::new(RESTORE_SPILL_BUDGET_BYTES);
    let rows = restore::attach_script_history_artifact(
        host.writer,
        target,
        &block_hashes,
        scratch,
        &budget,
    )?;
    Ok(Some(BundleOutcome::Restored(RestoreReport {
        base,
        records: rows,
        rows: usize::try_from(rows).unwrap_or(usize::MAX),
    })))
}

fn chain_block_hashes(
    block_tree: &BlockTreeReader,
    base_height: u32,
    base_hash: [u8; 32],
) -> Result<Vec<[u8; 32]>, IndexBundleError> {
    let tree = block_tree.read();
    let tip_node = tree
        .lookup(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
            &base_hash,
        ))
        .ok_or_else(|| {
            IndexBundleError::Identity(
                "the receiver chain has no header at the manifest base".to_owned(),
            )
        })?;
    let mut hashes = Vec::new();
    for height in 0..=base_height {
        let Some(id) = tree.node_at_height_from(tip_node, height) else {
            break;
        };
        let node = tree
            .node(id)
            .map_err(|_| IndexBundleError::Identity("node lookup failed".to_owned()))?;
        hashes.push(node.hash.to_le_bytes());
    }
    Ok(hashes)
}

fn attach_manifest_compact_filters(
    host: &BundleHost<'_>,
    target: &ManifestArtifactTarget,
) -> Result<Option<BundleOutcome>, IndexBundleError> {
    if !host.enabled.contains(IndexCapability::CompactFilters) {
        return Err(IndexBundleError::CompactFiltersDisabled);
    }
    let (_, watermarks) = host
        .writer
        .fenced_watermarks()
        .map_err(IndexBundleError::Index)?;
    if watermarks
        .compact_filters
        .is_some_and(|existing| existing.height >= target.base_height)
    {
        return Ok(None);
    }
    let base = IndexWatermark {
        height: target.base_height,
        hash: target.base_hash,
    };
    let scratch = target
        .artifact_path
        .parent()
        .unwrap_or(&target.artifact_path);
    let budget = SpillBudget::new(RESTORE_SPILL_BUDGET_BYTES);
    let records = restore::attach_compact_filter_artifact(host.writer, target, scratch, &budget)?;
    Ok(Some(BundleOutcome::Restored(RestoreReport {
        base,
        records,
        rows: usize::try_from(records).unwrap_or(usize::MAX),
    })))
}

fn io_error(path: &Path, source: std::io::Error) -> IndexBundleError {
    IndexBundleError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), IndexBundleError> {
    std::fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_error(dir, error))
}

#[cfg(windows)]
fn sync_dir(dir: &Path) -> Result<(), IndexBundleError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_error(dir, error))
}

#[cfg(not(any(unix, windows)))]
fn sync_dir(_dir: &Path) -> Result<(), IndexBundleError> {
    Ok(())
}

#[cfg(test)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    IndexBundle(#[from] IndexBundleError),
    #[error(transparent)]
    Index(#[from] crate::IndexError),
    #[error(transparent)]
    LiveValue(#[from] crate::types::ScriptLiveValueError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_execution::chain::ChainError),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error(transparent)]
    HexToBytes(#[from] bitcoin::hex::HexToBytesError),
    #[error(transparent)]
    HexToArray(#[from] bitcoin::hex::HexToArrayError),
    #[error(transparent)]
    ConsensusEncode(#[from] bitcoin::consensus::encode::Error),
    #[error(transparent)]
    Bip158(#[from] bitcoin::bip158::Error),
    #[error(transparent)]
    Query(#[from] crate::query_api::TxQueryError),
    #[error("missing {0}")]
    Missing(&'static str),
}

#[cfg(test)]
impl From<&'static str> for TestError {
    fn from(s: &'static str) -> Self {
        Self::Missing(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), TestError>;

    #[test]
    fn sync_dir_flushes_an_existing_bundle_directory() -> TestResult {
        let dir = tempfile::tempdir()?;
        sync_dir(dir.path())?;
        let missing = dir.path().join("missing");
        assert!(
            matches!(sync_dir(&missing), Err(IndexBundleError::Io { .. })),
            "a missing directory entry must fail, not silently succeed"
        );
        Ok(())
    }
}
