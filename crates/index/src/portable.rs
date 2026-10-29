//! Portable, versioned index bundles: export and restore of the `TxLookup` family.
//!
//! A bundle holds `txlookup-v1.dat` and, published last, `manifest.json`.
//!
//! Restore validates the whole bundle before mutating anything. Only `TxLookup`
//! bundles: `ScriptHistory` is refused as unqualified; `ScriptLive` is reseeded from
//! the UTXO set.

mod artifact;
mod chain;
mod export;
mod manifest;
mod restore;

use crate::writer::TxIndexWriter;
use crate::{IndexCapabilities, IndexError, IndexReader, IndexWatermark};
use bitcoin_rs_chain::{BlockBodySource, BlockTreeReader, TipReader};
use bitcoin_rs_primitives::Network;
use std::path::{Path, PathBuf};

pub(crate) use restore::reset_interrupted_import;

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
}

#[derive(Debug, thiserror::Error)]
pub enum IndexBundleError {
    #[error("portable index bundles need the txindex capability enabled")]
    TxLookupDisabled,
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
    /// A record violates framing, bounds, or ascending order.
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
    #[error("restore refused: bundle carries more than {limit_positions} positions")]
    RestoreTooLarge { limit_positions: usize },
    #[error("export refused: bundle would carry more than {limit_positions} positions")]
    ExportTooLarge { limit_positions: usize },
    #[error("bundle omits transactions at height {height}: expected {expected}, found {actual}")]
    Incomplete {
        /// First height where the bundle's count differs from the chain.
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

pub(crate) const MAX_RESTORE_POSITIONS: usize = 4_194_304;

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
    }
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
mod tests {
    use super::*;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    /// An incomplete bundle names the first height whose count differs, so an
    /// omitted record cannot silently receive the complete watermark.
    #[test]
    fn incomplete_reports_first_missing_height() {
        let error = IndexBundleError::Incomplete {
            height: 3,
            expected: 5,
            actual: 4,
        };
        let text = error.to_string();
        assert!(text.contains('3'), "missing height in {text}");
        assert!(text.contains('5'), "expected count in {text}");
        assert!(text.contains('4'), "actual count in {text}");
    }

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
