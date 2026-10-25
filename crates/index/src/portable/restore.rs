//! Restore: one validating pass, then one fenced applying pass.
//!
//! The validating pass streams the artifact once and, in that single read,
//! computes its SHA-256, checks its header against the manifest, frames and
//! orders every record, and (when the receiver's chain identity and a fresh
//! `TxLookup` allow it) resolves every locator to a full transaction id
//! through the receiver's own block bodies. Faults are reported in the
//! plan's strict order regardless of where they were found: manifest fields,
//! artifact length, SHA-256, header, record framing and order, chain
//! identity, a fresh `TxLookup`, locator mismatch. A missing or pruned body
//! is not corruption: the capability is withheld and ordinary backfill
//! proceeds. A bad bundle is refused before anything is written.
//!
//! Consistency: validation reads immutable bundle files and one captured
//! ancestry (snapshot isolation). The applying pass is a sequence of
//! linearizable fenced commits whose rows stay invisible, because the
//! capability has no watermark, until one final commit stamps the watermark
//! and floor, so readiness appears atomically or not at all. The applying
//! pass re-hashes the file it streams and aborts before that final commit if
//! the bytes changed since validation. A retry is idempotent: it needs a
//! fresh `TxLookup`, clears leftovers through the capability reset, and
//! rewrites identical rows from the same bytes.

use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, CANCEL_POLL_RECORDS, HEADER_LEN, ReadFault, RecordReader,
    RowAssembler, TxLookupRecord, into_digest, open_hashed,
};
use super::chain::{BodyReader, ChainBase, Located};
use super::manifest::{
    BundleFamily, IndexBundleManifestV1, MANIFEST_FILE, MAX_MANIFEST_BYTES, ValidatedManifest,
};
use super::{
    BundleHost, BundleOutcome, IndexBundleError, IndexBundleRequest, RestoreReport, Withheld,
    io_error,
};
use crate::index::PortableImportRow;
use crate::writer::TxIndexWriter;
use crate::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, TxIndexFamily,
};
use bitcoin_rs_chain::{BlockTreeReader, TipSnapshot};
use std::fs::{self, File};
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::path::Path;

/// Restores the `TxLookup` family from `request.dir`.
pub(super) fn restore(
    host: &BundleHost<'_>,
    request: &IndexBundleRequest,
) -> Result<BundleOutcome, IndexBundleError> {
    if !host.enabled.contains(IndexCapability::TxLookup) {
        return Err(IndexBundleError::TxLookupDisabled);
    }
    let dir = request.dir.as_path();
    let manifest = read_manifest(&dir.join(MANIFEST_FILE))?.validate()?;
    let artifact_path = dir.join(BundleFamily::TxLookup.file_name());
    let length = fs::metadata(&artifact_path)
        .map_err(|error| io_error(&artifact_path, error))?
        .len();
    if length != manifest.tx_lookup.bytes {
        return Err(IndexBundleError::ArtifactLength {
            name: BundleFamily::TxLookup.file_name(),
            expected: manifest.tx_lookup.bytes,
            actual: length,
        });
    }

    // Identity and freshness are computed first but reported after the
    // artifact's own faults; they only decide whether locators ride the pass.
    let identity = check_identity(host, request, &manifest);
    let fresh = ensure_fresh(host);
    let verify_with = match (&identity, &fresh) {
        (Ok(chain), Ok(())) => Some(chain),
        _ => None,
    };
    let (header, located) = validate_artifact(host, &artifact_path, &manifest, verify_with)?;
    let chain = identity?;
    fresh?;
    match located {
        LocatorOutcome::Verified => {}
        LocatorOutcome::Mismatch { height } => return Err(IndexBundleError::Locator { height }),
        LocatorOutcome::Withheld(withheld) => return Ok(BundleOutcome::RestoreWithheld(withheld)),
    }

    let plan = ImportPlan {
        host,
        path: &artifact_path,
        manifest: &manifest,
        header,
        chain: &chain,
    };
    let rows = plan.import()?;
    Ok(BundleOutcome::Restored(RestoreReport {
        base: IndexWatermark {
            height: manifest.identity.base_height,
            hash: manifest.identity.base_hash,
        },
        records: header.records,
        rows,
    }))
}

/// Clears `TxConfirmed` rows that carry no `TxLookup` watermark.
///
/// Ordinary commits write rows and watermark atomically, so rows without a
/// watermark exist only after an import was interrupted. The existing
/// capability-reset path removes them before the worker derives anything, so
/// no partial import can ever be served or mixed with derived rows. Returns
/// whether anything was reset.
pub(crate) fn reset_interrupted_import(
    writer: &dyn TxIndexWriter,
    reader: &dyn IndexReader,
) -> Result<bool, IndexError> {
    let (_, watermarks) = writer.fenced_watermarks()?;
    if watermarks.tx_lookup.is_some() {
        return Ok(false);
    }
    let mut leftover = false;
    reader
        .snapshot()?
        .for_each_row(TxIndexFamily::TxConfirmed, &mut |_, _| {
            leftover = true;
            Ok(ControlFlow::Break(()))
        })?;
    if leftover {
        writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
    }
    Ok(leftover)
}

fn read_manifest(path: &Path) -> Result<IndexBundleManifestV1, IndexBundleError> {
    let file = File::open(path).map_err(|error| io_error(path, error))?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_MANIFEST_BYTES) {
        return Err(IndexBundleError::Manifest(
            "manifest is larger than 1 MiB".to_owned(),
        ));
    }
    IndexBundleManifestV1::parse(&bytes)
}

/// Compares the bundle's chain and format identity with the receiver's.
fn check_identity(
    host: &BundleHost<'_>,
    request: &IndexBundleRequest,
    manifest: &ValidatedManifest,
) -> Result<ChainBase, IndexBundleError> {
    let identity = &manifest.identity;
    let refuse = |reason: &str| IndexBundleError::Identity(reason.to_owned());
    if identity.network != request.network {
        return Err(refuse("the bundle belongs to a different network"));
    }
    if identity.format_version != crate::index::index_format_version() {
        return Err(refuse("the bundle uses a different index format version"));
    }
    let tip: std::sync::Arc<TipSnapshot> = host
        .applied_tip
        .load_full()
        .ok_or_else(|| refuse("the receiver has no applied tip"))?;
    let chain = ChainBase::capture(host.block_tree, &tip, identity.base_height)?;
    if chain.genesis != identity.genesis {
        return Err(refuse("the bundle has a different genesis block"));
    }
    if chain.hash != identity.base_hash {
        return Err(refuse(
            "the bundle base is not on the receiver's active chain",
        ));
    }
    if chain.chainwork != identity.chainwork {
        return Err(refuse(
            "the receiver's chainwork differs at the bundle base",
        ));
    }
    if chain.chain_tx_count != identity.chain_tx_count {
        return Err(refuse(
            "the receiver's chain transaction count differs at the bundle base",
        ));
    }
    if !chain.validated {
        return Err(refuse("the receiver's base block is marked invalid"));
    }
    Ok(chain)
}

/// Restore only fills a fresh `TxLookup`; a ready index is never reset.
fn ensure_fresh(host: &BundleHost<'_>) -> Result<(), IndexBundleError> {
    let (_, watermarks) = host.writer.fenced_watermarks()?;
    if watermarks.tx_lookup.is_some() {
        return Err(IndexBundleError::NotFresh);
    }
    Ok(())
}

/// How locator verification ended.
enum LocatorOutcome {
    /// Every locator resolved to its recorded full transaction id.
    Verified,
    /// A locator at this height does not resolve to its recorded id.
    Mismatch { height: u32 },
    /// A body is unavailable, so the bundle cannot be proven here.
    Withheld(Withheld),
}

/// Locator verification that rides the validating pass. The first terminal
/// outcome sticks; later records are not looked up.
struct LocatorCheck<'a> {
    chain: &'a ChainBase,
    tree: &'a BlockTreeReader,
    bodies: BodyReader<'a>,
    outcome: LocatorOutcome,
}

impl LocatorCheck<'_> {
    /// Resolves every position of `record` and requires full transaction id
    /// equality; a prefix match never resolves a locator.
    fn check(&mut self, record: &TxLookupRecord<'_>) -> Result<(), IndexBundleError> {
        if !matches!(self.outcome, LocatorOutcome::Verified) {
            return Ok(());
        }
        let height = record.height;
        let hash = self.chain.hash_at(self.tree, height).ok_or_else(|| {
            IndexBundleError::Identity(
                "the receiver chain has no block at a record height".to_owned(),
            )
        })?;
        for &position in record.positions {
            match self.bodies.transaction(height, hash, position)? {
                Located::Found(tx) if tx.txid().0.to_le_bytes() == record.txid => {}
                Located::Found(_) | Located::Mismatch => {
                    self.outcome = LocatorOutcome::Mismatch { height };
                    return Ok(());
                }
                Located::BodyMissing => {
                    self.outcome = LocatorOutcome::Withheld(Withheld::BodyUnavailable { height });
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Streams the whole artifact once: SHA-256, header, record framing, and,
/// when `chain` is given, locator verification.
///
/// A framing or locator fault does not stop the hash: the rest of the file is
/// drained so a digest mismatch, which outranks every other artifact fault,
/// is reported first. Cancellation returns at once.
fn validate_artifact(
    host: &BundleHost<'_>,
    path: &Path,
    manifest: &ValidatedManifest,
    chain: Option<&ChainBase>,
) -> Result<(ArtifactHeader, LocatorOutcome), IndexBundleError> {
    let name = BundleFamily::TxLookup.file_name();
    let fail = |error| io_error(path, error);
    let mut reader = open_hashed(path).map_err(fail)?;
    let mut header_bytes = [0_u8; HEADER_LEN];
    let header = match reader.read_exact(&mut header_bytes) {
        Ok(()) => ArtifactHeader::decode(&header_bytes)
            .and_then(|header| check_header(&header, manifest).map(|()| header)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err("file ends inside the header")
        }
        Err(error) => return Err(fail(error)),
    };
    let mut locators = match (chain, host.body_source) {
        (Some(chain), Some(source)) => Some(LocatorCheck {
            chain,
            tree: host.block_tree,
            bodies: BodyReader::new(source),
            outcome: LocatorOutcome::Verified,
        }),
        _ => None,
    };
    let framing = match &header {
        Ok(header) => {
            let mut records = RecordReader::new(&mut reader, header, manifest.tx_lookup.floor);
            read_records(&mut records, host, path, |record| {
                if let Some(locators) = locators.as_mut() {
                    locators.check(record)?;
                }
                Ok(ControlFlow::Continue(()))
            })
        }
        Err(_) => Ok(()),
    };
    if matches!(&framing, Err(IndexBundleError::Cancelled)) {
        return Err(IndexBundleError::Cancelled);
    }
    io::copy(&mut reader, &mut io::sink()).map_err(fail)?;
    if into_digest(reader) != manifest.tx_lookup.sha256 {
        return Err(IndexBundleError::ArtifactHash { name });
    }
    let header = header.map_err(|reason| IndexBundleError::ArtifactHeader { name, reason })?;
    framing?;
    let outcome = match (chain, locators) {
        (Some(_), Some(check)) => check.outcome,
        (Some(_), None) => LocatorOutcome::Withheld(Withheld::NoBodySource),
        (None, _) => LocatorOutcome::Verified,
    };
    Ok((header, outcome))
}

/// Checks the header against the manifest: every one of the 73 bytes is
/// determined by manifest fields, so equality proves the header intact.
fn check_header(header: &ArtifactHeader, manifest: &ValidatedManifest) -> Result<(), &'static str> {
    let identity = &manifest.identity;
    if header.family != BundleFamily::TxLookup {
        return Err("family is not tx_lookup");
    }
    if header.artifact_version != ARTIFACT_VERSION {
        return Err("artifact version is not supported");
    }
    if header.index_format != identity.format_version {
        return Err("index format differs from the manifest");
    }
    if header.network_magic != identity.network.magic() {
        return Err("network magic differs from the manifest");
    }
    if header.base_height != identity.base_height || header.base_hash != identity.base_hash {
        return Err("base differs from the manifest");
    }
    if header.records != manifest.tx_lookup.records {
        return Err("record count differs from the manifest");
    }
    let payload = manifest
        .tx_lookup
        .bytes
        .checked_sub(u64::try_from(HEADER_LEN).unwrap_or(u64::MAX));
    if payload != Some(header.payload_bytes) {
        return Err("payload length differs from the manifest");
    }
    Ok(())
}

/// Polls cancellation every [`CANCEL_POLL_RECORDS`] records while `visit`
/// consumes each framed record; `Break` stops early.
fn read_records<R: Read>(
    records: &mut RecordReader<R>,
    host: &BundleHost<'_>,
    path: &Path,
    mut visit: impl FnMut(&TxLookupRecord<'_>) -> Result<ControlFlow<()>, IndexBundleError>,
) -> Result<(), IndexBundleError> {
    let name = BundleFamily::TxLookup.file_name();
    let mut seen = 0_u64;
    while let Some(record) = records.next_record().map_err(|fault| match fault {
        ReadFault::Io(error) => io_error(path, error),
        ReadFault::Framing { record, reason } => IndexBundleError::ArtifactFraming {
            name,
            record,
            reason,
        },
    })? {
        seen += 1;
        if seen.is_multiple_of(CANCEL_POLL_RECORDS) && (host.cancelled)() {
            return Err(IndexBundleError::Cancelled);
        }
        if visit(&record)?.is_break() {
            break;
        }
    }
    Ok(())
}

/// Everything the applying pass needs, all validated.
struct ImportPlan<'a> {
    host: &'a BundleHost<'a>,
    path: &'a Path,
    manifest: &'a ValidatedManifest,
    header: ArtifactHeader,
    chain: &'a ChainBase,
}

impl ImportPlan<'_> {
    /// Imports the validated bundle through the writer's fenced stream and
    /// returns the number of rows written.
    ///
    /// A failed attempt leaves only un-watermarked rows; they are cleared here
    /// when the capability is still without a watermark, and otherwise by the
    /// next start through the same capability reset.
    fn import(&self) -> Result<usize, IndexBundleError> {
        let base = IndexWatermark {
            height: self.manifest.identity.base_height,
            hash: self.manifest.identity.base_hash,
        };
        let mut failure: Option<IndexBundleError> = None;
        let imported = self.host.writer.import_tx_lookup_stream(
            &mut |emit| match self.stream_import(emit) {
                Ok(()) => Ok(()),
                Err(IndexBundleError::Index(error)) => Err(error),
                Err(error) => {
                    failure = Some(error);
                    Err(IndexError::Storage(
                        bitcoin_rs_storage::StorageError::InvalidOperation(
                            "portable index import aborted by its source",
                        ),
                    ))
                }
            },
            base,
            self.manifest.tx_lookup.floor,
        );
        let index_error = match imported {
            Ok(rows) => return Ok(rows),
            Err(error) => error,
        };
        let error = failure.unwrap_or(IndexBundleError::Index(index_error));
        if let Ok((_, watermarks)) = self.host.writer.fenced_watermarks() {
            if watermarks.tx_lookup.is_none() {
                if let Err(reset) = self
                    .host
                    .writer
                    .reset_capabilities(IndexCapabilities::TX_LOOKUP)
                {
                    tracing::warn!(%reset, "partial index import left rows; the next start clears them");
                }
            }
        }
        Err(error)
    }

    /// Emits the receiver's block identities and then every bundle row,
    /// re-hashing the artifact so a file changed since validation is refused
    /// before the final commit can stamp readiness.
    fn stream_import(
        &self,
        emit: &mut dyn FnMut(PortableImportRow<'_>) -> Result<(), IndexError>,
    ) -> Result<(), IndexBundleError> {
        let name = BundleFamily::TxLookup.file_name();
        let mut hashed = open_hashed(self.path).map_err(|error| io_error(self.path, error))?;
        let mut header_bytes = [0_u8; HEADER_LEN];
        hashed
            .read_exact(&mut header_bytes)
            .map_err(|error| io_error(self.path, error))?;
        if ArtifactHeader::decode(&header_bytes) != Ok(self.header) {
            return Err(IndexBundleError::ArtifactHash { name });
        }
        for height in 0..=self.manifest.identity.base_height {
            if u64::from(height) % CANCEL_POLL_RECORDS == 0 && (self.host.cancelled)() {
                return Err(IndexBundleError::Cancelled);
            }
            let header = self
                .chain
                .header_at(self.host.block_tree, height)
                .ok_or_else(|| {
                    IndexBundleError::Identity(
                        "the receiver chain has no header at a covered height".to_owned(),
                    )
                })?;
            emit(PortableImportRow::Header(&header))?;
        }
        let mut records =
            RecordReader::new(&mut hashed, &self.header, self.manifest.tx_lookup.floor);
        let mut rows = RowAssembler::default();
        read_records(&mut records, self.host, self.path, |record| {
            rows.push(record, &mut |row, value| {
                emit(PortableImportRow::TxLookup { row, value })
            })?;
            Ok(ControlFlow::Continue(()))
        })?;
        rows.flush(&mut |row, value| emit(PortableImportRow::TxLookup { row, value }))?;
        if into_digest(hashed) != self.manifest.tx_lookup.sha256 {
            return Err(IndexBundleError::ArtifactHash { name });
        }
        Ok(())
    }
}
