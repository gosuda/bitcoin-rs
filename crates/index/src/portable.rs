//! Portable, versioned index bundles: export and restore of the `TxLookup`
//! family.
//!
//! A bundle is a directory holding `txlookup-v1.dat` and, published last,
//! `manifest.json`. Export reads one coherent index snapshot at the applied
//! tip. Restore validates the whole bundle, including every locator against
//! the receiver's own block bodies, before it mutates anything, then imports
//! through the existing fenced [`crate::IndexWriter`] path. Both run on the
//! existing derived-index worker inside `open_and_run`; there is no second
//! store opener, writer, or RPC surface.
//!
//! `ScriptHistory` is not carried: its occurrence layout is not qualified,
//! so the manifest refuses it and `ScriptLive` is never a bundle capability
//! (it is always reseeded from the UTXO set).
//!
//! Remaining interface for the `ScriptHistory` artifact: a
//! `TxIndexFamily::HistoryOccurrence` variant with its streaming method arm,
//! a fixed 51-byte record codec beside `TxLookup` in `artifact.rs`, a manifest
//! family entry, and an import row variant committed through the same
//! fenced stream with the script-history watermark stamped only in the final
//! commit. None exists until the v6 schema is qualified.

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

/// Where a bundle lives and which network it belongs to.
#[derive(Clone, Debug)]
pub struct IndexBundleRequest {
    /// Bundle directory.
    pub dir: PathBuf,
    /// Network the node runs on.
    pub network: Network,
}

/// One-shot bundle request executed by the worker before its first
/// reconcile pass.
#[derive(Clone, Debug, Default)]
pub enum IndexBundleDirective {
    /// No bundle work.
    #[default]
    None,
    /// Restore `TxLookup` from the bundle into a fresh capability.
    Restore(IndexBundleRequest),
    /// Export `TxLookup` at the applied tip into a new bundle.
    Export(IndexBundleRequest),
}

/// Why a bundle request failed. Nothing is published or activated on error;
/// a failed restore leaves the capability un-watermarked.
#[derive(Debug, thiserror::Error)]
pub enum IndexBundleError {
    /// Bundle work needs the transaction index enabled.
    #[error("portable index bundles need the txindex capability enabled")]
    TxLookupDisabled,
    /// A bundle file or directory operation failed.
    #[error("bundle I/O at {}: {source}", path.display())]
    Io {
        /// File or directory involved.
        path: PathBuf,
        /// Underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// Export found the index not exactly at the applied tip.
    #[error("export refused, index not ready: {0}")]
    NotReady(&'static str),
    /// The index watermarks moved while an export was streaming.
    #[error("export aborted: index watermarks moved while streaming")]
    Stale,
    /// A bundle manifest or artifact already exists at the destination.
    #[error("a bundle file already exists at {}", .0.display())]
    ExistingBundle(PathBuf),
    /// The manifest is malformed or inconsistent.
    #[error("bundle manifest invalid: {0}")]
    Manifest(String),
    /// The bundle declares an index family this version cannot carry.
    #[error("bundle declares unsupported capability {0}")]
    UnsupportedCapability(&'static str),
    /// The artifact length differs from the manifest.
    #[error("artifact {name} has {actual} bytes, the manifest declares {expected}")]
    ArtifactLength {
        /// Artifact file name.
        name: &'static str,
        /// Length the manifest declares.
        expected: u64,
        /// Length found on disk.
        actual: u64,
    },
    /// The artifact SHA-256 differs from the manifest.
    #[error("artifact {name} SHA-256 does not match the manifest")]
    ArtifactHash {
        /// Artifact file name.
        name: &'static str,
    },
    /// The artifact header is malformed or disagrees with the manifest.
    #[error("artifact {name} header invalid: {reason}")]
    ArtifactHeader {
        /// Artifact file name.
        name: &'static str,
        /// First violated rule.
        reason: &'static str,
    },
    /// A record violates framing, bounds, or ascending order.
    #[error("artifact {name} record {record} invalid: {reason}")]
    ArtifactFraming {
        /// Artifact file name.
        name: &'static str,
        /// Zero-based record index.
        record: u64,
        /// First violated rule.
        reason: &'static str,
    },
    /// The bundle does not belong to the receiver's network, format, or chain.
    #[error("bundle identity refused: {0}")]
    Identity(String),
    /// The receiver already has a `TxLookup` watermark; restore needs a fresh
    /// capability and never resets a ready index.
    #[error("the txindex already has a watermark; restore needs a fresh capability")]
    NotFresh,
    /// A recorded locator does not resolve to the recorded full transaction id.
    #[error("a recorded locator at height {height} does not resolve to its transaction id")]
    Locator {
        /// Height of the block holding the locator.
        height: u32,
    },
    /// The restore locator pass would exceed its bounded position budget.
    #[error("restore refused: bundle carries more than {limit_positions} positions")]
    RestoreTooLarge {
        /// Position ceiling for the grouped locator pass.
        limit_positions: usize,
    },
    /// Export would produce a bundle the restore pass cannot accept.
    #[error("export refused: bundle would carry more than {limit_positions} positions")]
    ExportTooLarge {
        /// Position ceiling shared with restore.
        limit_positions: usize,
    },
    /// The bundle omits transactions in the covered range; stamping its base
    /// would claim a completeness the rows do not have.
    #[error("bundle omits transactions at height {height}: expected {expected}, found {actual}")]
    Incomplete {
        /// First height where the bundle's count differs from the chain.
        height: u32,
        /// Transactions the receiver's block holds.
        expected: u64,
        /// Positions the bundle carries for the height.
        actual: u64,
    },
    /// Reading a block body failed without establishing corruption.
    #[error("block body read failed at height {height}: {reason}")]
    BodyRead {
        /// Height of the unreadable block.
        height: u32,
        /// Underlying failure text.
        reason: String,
    },
    /// Export needs a block body that is not available.
    #[error("block body unavailable at height {height}; export needs every indexed block")]
    BodyUnavailable {
        /// Height of the missing block.
        height: u32,
    },
    /// A stored index row cannot be turned into a bundle record.
    #[error("source index row invalid at height {height}: {reason}")]
    SourceRow {
        /// Height of the offending row.
        height: u32,
        /// First violated rule.
        reason: &'static str,
    },
    /// Shutdown or abandonment stopped the bundle work.
    #[error("bundle operation cancelled")]
    Cancelled,
    /// The index writer or reader failed.
    #[error("index error: {0}")]
    Index(#[from] IndexError),
}

/// Terminal state of one directive.
#[derive(Debug)]
pub(crate) enum BundleOutcome {
    /// A bundle was published.
    Exported(ExportReport),
    /// The capability was imported and watermarked.
    Restored(RestoreReport),
    /// The bundle is valid but cannot be proven here; nothing was written and
    /// ordinary backfill proceeds.
    RestoreWithheld(Withheld),
}

/// Maximum transaction positions one bundle may carry. Export and restore
/// share this bound so export cannot publish an unimportable artifact.
pub(crate) const MAX_RESTORE_POSITIONS: usize = 4_194_304;

/// A published export.
#[derive(Debug)]
pub(crate) struct ExportReport {
    /// Watermark the bundle is anchored to.
    pub(crate) base: IndexWatermark,
    /// Records in the artifact.
    pub(crate) records: u64,
    /// Artifact length in bytes.
    pub(crate) bytes: u64,
}

/// A completed restore.
#[derive(Debug)]
pub(crate) struct RestoreReport {
    /// Watermark stamped on the capability.
    pub(crate) base: IndexWatermark,
    /// Records read from the artifact.
    pub(crate) records: u64,
    /// `TxConfirmed` rows written (records sharing a key fold into one).
    pub(crate) rows: usize,
}

/// Why a valid bundle was not activated.
#[derive(Debug)]
pub(crate) enum Withheld {
    /// The node has no block body source to verify locators or count
    /// transactions above the base against.
    NoBodySource,
    /// A block body that the locators, or the receiver's transaction count at
    /// the base, need is absent or pruned.
    BodyUnavailable {
        /// Height of the missing block.
        height: u32,
    },
}

/// Worker-owned handles a directive runs against.
pub(crate) struct BundleHost<'a> {
    /// The existing fenced index writer.
    pub(crate) writer: &'a dyn TxIndexWriter,
    /// The existing snapshot-capable reader.
    pub(crate) reader: &'a dyn IndexReader,
    /// Block tree reader for ancestry and header identity.
    pub(crate) block_tree: &'a BlockTreeReader,
    /// Published applied tip.
    pub(crate) applied_tip: &'a TipReader,
    /// The node's block body source, if any.
    pub(crate) body_source: Option<&'a dyn BlockBodySource>,
    /// Capabilities this worker maintains.
    pub(crate) enabled: IndexCapabilities,
    /// Shutdown, abandonment, or failure; polled every 4,096 records.
    pub(crate) cancelled: &'a dyn Fn() -> bool,
}

/// Executes `directive`; `None` does nothing and reports nothing.
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

/// Flushes a directory entry to disk so a just-created file survives a crash.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), IndexBundleError> {
    std::fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_error(dir, error))
}

/// Flushes a directory entry to durable storage on Windows.
///
/// Windows flushes a directory handle only when it carries `GENERIC_WRITE`
/// (`FlushFileBuffers` fails with `ERROR_ACCESS_DENIED` on a read-only
/// handle), so the open requests write access. `FILE_FLAG_BACKUP_SEMANTICS`
/// is what lets a directory be opened at all.
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

/// Directory handles cannot be opened for sync through `std` off Unix and
/// Windows; the file `sync_all` already made the contents durable.
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

    /// The bundle directory entry itself is flushed, so a just-created file
    /// survives a crash on either Unix or Windows.
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
