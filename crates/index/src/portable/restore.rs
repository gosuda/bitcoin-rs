//! Restore: one validating pass, then one fenced applying pass.
//!
//! The validating pass streams the artifact once and, in that single read,
//! computes its SHA-256, checks its header against the manifest, frames and
//! orders every record, and (when the receiver's chain identity and a fresh
//! `TxLookup` allow it) resolves every locator to a full transaction id
//! through the receiver's own block bodies. Every locator must equal a real
//! top-level block transaction boundary: bytes that merely decode to a
//! transaction elsewhere in the block (an embedded serialization inside a
//! script or witness) never resolve a locator. The pass also compares all
//! transactions in the covered range, so a bundle that omits a record cannot
//! receive the complete watermark. Faults are reported in the plan's strict
//! order regardless of where they were found: manifest fields, artifact
//! length, SHA-256, header, record framing and order, chain identity, a fresh
//! `TxLookup`, locator mismatch, omitted transactions. A missing or pruned
//! body is not corruption: the capability is withheld and ordinary backfill
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
use super::chain::{BaseCount, BodyReader, ChainBase, Located};
use super::manifest::{
    BundleFamily, IndexBundleManifestV1, MANIFEST_FILE, MAX_MANIFEST_BYTES, ValidatedManifest,
};
use super::{
    BundleHost, BundleOutcome, IndexBundleError, IndexBundleRequest, RestoreReport, Withheld,
    io_error,
};
use crate::index::PortableImportRow;
use crate::types::TxPosition;
use crate::writer::TxIndexWriter;
use crate::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWatermarks,
    TxIndexFamily,
};
use bitcoin_rs_chain::BlockTreeReader;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use std::collections::HashMap;
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
        (Ok((chain, None)), Ok(())) => Some(chain),
        _ => None,
    };
    let (header, located) = validate_artifact(host, &artifact_path, &manifest, verify_with)?;
    let (chain, count_withheld) = identity?;
    fresh?;
    // Without the receiver's count at the base the identity is unproven, so
    // the locator outcome above is unchecked and nothing activates.
    if let Some(withheld) = count_withheld {
        return Ok(BundleOutcome::RestoreWithheld(withheld));
    }
    match located {
        LocatorOutcome::Verified => {}
        LocatorOutcome::Mismatch { height } => return Err(IndexBundleError::Locator { height }),
        LocatorOutcome::Withheld(withheld) => return Ok(BundleOutcome::RestoreWithheld(withheld)),
        // Unreachable while the gates above run first: verification is only
        // skipped when identity or freshness already refused. Fails closed so
        // a future reorder can never activate an unchecked bundle.
        LocatorOutcome::NotChecked => {
            return Err(IndexBundleError::Identity(
                "locator verification was skipped".to_owned(),
            ));
        }
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
    // One bounded row decides the probe: any `TxConfirmed` row without a
    // watermark is leftover from an interrupted import. The old
    // whole-family visitor materialized the family on some backends just
    // to answer this existence check.
    let probe = reader.snapshot()?.scan_family_page(
        TxIndexFamily::TxConfirmed,
        None,
        bitcoin_rs_storage::PrefixScanLimit {
            max_rows: 1,
            max_bytes: usize::MAX,
        },
    )?;
    if probe.rows.is_empty() {
        return Ok(false);
    }
    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
    Ok(true)
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
///
/// Also returns why the receiver's chain transaction count at the base could
/// not be established, when a block body it needs is unavailable: that is a
/// withheld bundle, not a refusal, and it is reported after every refusal.
fn check_identity(
    host: &BundleHost<'_>,
    request: &IndexBundleRequest,
    manifest: &ValidatedManifest,
) -> Result<(ChainBase, Option<Withheld>), IndexBundleError> {
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
    let chain = ChainBase::capture(host.block_tree, &tip, identity.base_height, host.cancelled)?;
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
    if !chain.validated {
        return Err(refuse("the receiver's base block is marked invalid"));
    }
    let withheld = match chain.base_count(host.block_tree, host.body_source, host.cancelled)? {
        BaseCount::Known(count) if count != identity.chain_tx_count => {
            return Err(refuse(
                "the receiver's chain transaction count differs at the bundle base",
            ));
        }
        BaseCount::Known(_) => None,
        BaseCount::Withheld(withheld) => Some(withheld),
    };
    Ok((chain, withheld))
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
    /// Verification was skipped: no chain was proven, so no outcome exists.
    /// Never trusted; the gates in [`restore`] refuse before it is read.
    NotChecked,
}

/// Locator verification that rides the validating pass. The first terminal
/// outcome sticks; later records are not looked up.
///
/// Every locator must equal a real top-level block transaction boundary.
/// Bytes that merely decode to a transaction elsewhere in the block (an
/// embedded serialization inside a script or witness) never resolve a
/// locator, even when the decoded id matches. Verification runs in height
/// order after the stream: each covered body is loaded and parsed once no
/// matter how the txid-prefix-ordered records scatter one block's
/// transactions.
struct LocatorCheck<'a> {
    chain: &'a ChainBase,
    tree: &'a BlockTreeReader,
    bodies: BodyReader<'a>,
    /// Bundle positions grouped by height for the height-ordered pass.
    /// Streaming collects; verification drains in ascending height so each
    /// body is read and parsed once. This holds one small entry per bundle
    /// position until its height verifies: any bundle whose records can be
    /// validated in feasible time fits comfortably, while a per-record
    /// re-parse (the previous shape) never finishes large bundles at all.
    /// A bounded block cache cannot replace this grouping because records
    /// arrive in txid-prefix order, so every block's transactions scatter
    /// across the whole stream.
    pending: HashMap<u32, Vec<(TxPosition, [u8; 32])>>,
    /// Positions charged against [`MAX_RESTORE_POSITIONS`].
    pending_positions: usize,
    /// Positions the bundle carries per height, for the completeness check.
    counts: HashMap<u32, u64>,
    outcome: LocatorOutcome,
}

impl LocatorCheck<'_> {
    /// Files every position of `record` under its height for the
    /// height-ordered verification pass.
    ///
    /// Chain identity faults report at once, preserving the validating
    /// pass's fault order; bodies stay untouched here. The later pass loads
    /// each covered body once no matter how the txid-prefix-ordered records
    /// scatter one block's transactions.
    fn check(&mut self, record: &TxLookupRecord<'_>) -> Result<(), IndexBundleError> {
        if !matches!(self.outcome, LocatorOutcome::Verified) {
            return Ok(());
        }
        let height = record.height;
        self.chain.hash_at(self.tree, height).ok_or_else(|| {
            IndexBundleError::Identity(
                "the receiver chain has no block at a record height".to_owned(),
            )
        })?;
        let added = record.positions.len();
        if self.pending_positions.saturating_add(added) > super::MAX_RESTORE_POSITIONS {
            return Err(IndexBundleError::RestoreTooLarge {
                limit_positions: super::MAX_RESTORE_POSITIONS,
            });
        }
        self.pending.entry(height).or_default().extend(
            record
                .positions
                .iter()
                .map(|&position| (position, record.txid)),
        );
        self.pending_positions += added;
        Ok(())
    }

    /// Checks one height's collected positions against its block boundaries.
    ///
    /// The body is loaded and parsed once for the height; the parsed spans
    /// answer every scattered position, so a block shared by many records
    /// costs one read and one parse instead of one per record. A position
    /// matches only a real top-level transaction span with an equal full id:
    /// bytes that merely decode elsewhere never resolve. Returns the block's
    /// transaction count, or `None` when a terminal outcome was recorded
    /// (missing body or mismatch) and verification must stop.
    fn verify_height_positions(
        &mut self,
        height: u32,
        hash: Hash256,
        positions: &[(TxPosition, [u8; 32])],
    ) -> Result<Option<u64>, IndexBundleError> {
        for &(position, expected) in positions {
            match self.bodies.transaction(height, hash, position)? {
                Located::Found(tx) if tx.txid().0.to_le_bytes() == expected => {
                    *self.counts.entry(height).or_default() += 1;
                }
                Located::Found(_) | Located::Mismatch => {
                    self.outcome = LocatorOutcome::Mismatch { height };
                    return Ok(None);
                }
                Located::BodyMissing => {
                    self.outcome = LocatorOutcome::Withheld(Withheld::BodyUnavailable { height });
                    return Ok(None);
                }
            }
        }
        if let Some(count) = self.bodies.block_tx_count(height, hash)? {
            Ok(Some(count))
        } else {
            self.outcome = LocatorOutcome::Withheld(Withheld::BodyUnavailable { height });
            Ok(None)
        }
    }
    ///
    /// Strict checks run for every height before any completeness check, so
    /// the reported fault order keeps locator mismatch ahead of omitted
    /// transactions. Each covered body is loaded and parsed once; heights
    /// without bundle positions reuse the metadata count when the source
    /// keeps it. A missing body withholds instead of refusing; a count
    /// mismatch refuses before any write, so an incomplete bundle never
    /// receives the complete watermark.
    fn verify_locators(
        &mut self,
        floor: u32,
        base: u32,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), IndexBundleError> {
        let mut block_counts: HashMap<u32, u64> = HashMap::new();
        for height in floor..=base {
            if u64::from(height) % CANCEL_POLL_RECORDS == 0 && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            let hash = self.chain.hash_at(self.tree, height).ok_or_else(|| {
                IndexBundleError::Identity(
                    "the receiver chain has no block at a covered height".to_owned(),
                )
            })?;
            let count = match self.verify_height_count(height, hash)? {
                Some(count) => count,
                // A terminal locator outcome is already recorded;
                // completeness is unreachable.
                None => return Ok(()),
            };
            block_counts.insert(height, count);
        }
        for height in floor..=base {
            if u64::from(height) % CANCEL_POLL_RECORDS == 0 && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            // The strict phase above ran every height without a terminal
            // outcome, so a recorded count exists for each; zero fails
            // closed toward refusal.
            let expected = block_counts.get(&height).copied().unwrap_or(0);
            if let Some(error) = incomplete_at(&self.counts, height, expected) {
                return Err(error);
            }
        }
        Ok(())
    }
    /// Returns one height's transaction count for the completeness check:
    /// collected positions are verified against a single parse of the body,
    /// while a height without positions reuses the metadata count when the
    /// source keeps it. Returns `None` when a terminal outcome was recorded
    /// (missing body or mismatch) and verification must stop.
    fn verify_height_count(
        &mut self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<u64>, IndexBundleError> {
        if let Some(positions) = self.pending.remove(&height) {
            self.pending_positions = self.pending_positions.saturating_sub(positions.len());
            self.verify_height_positions(height, hash, &positions)
        } else if let Some(count) = self.bodies.block_tx_count(height, hash)? {
            Ok(Some(count))
        } else {
            self.outcome = LocatorOutcome::Withheld(Withheld::BodyUnavailable { height });
            Ok(None)
        }
    }
}

/// Reports the first height where the bundle's position count differs from
/// the chain's transaction count, or `None` when the height is complete.
fn incomplete_at(
    counts: &HashMap<u32, u64>,
    height: u32,
    expected: u64,
) -> Option<IndexBundleError> {
    let actual = counts.get(&height).copied().unwrap_or(0);
    (actual != expected).then_some(IndexBundleError::Incomplete {
        height,
        expected,
        actual,
    })
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
            pending: HashMap::new(),
            pending_positions: 0,
            counts: HashMap::new(),
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
    drain_remaining_for_hash(&mut reader, host.cancelled, path)?;
    if into_digest(reader) != manifest.tx_lookup.sha256 {
        return Err(IndexBundleError::ArtifactHash { name });
    }
    let header = header.map_err(|reason| IndexBundleError::ArtifactHeader { name, reason })?;
    framing?;
    if let Some(check) = locators.as_mut() {
        if matches!(check.outcome, LocatorOutcome::Verified) {
            check.verify_locators(
                manifest.tx_lookup.floor,
                manifest.identity.base_height,
                host.cancelled,
            )?;
        }
    }
    let outcome = match (chain, locators) {
        (Some(_), Some(check)) => check.outcome,
        (Some(_), None) => LocatorOutcome::Withheld(Withheld::NoBodySource),
        // No proven chain rode this pass, so there is no outcome to report;
        // the caller refuses on identity, freshness, or count before reading
        // it. Never `Verified`: correctness must not depend on that ordering.
        (None, _) => LocatorOutcome::NotChecked,
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

/// Drains `reader` to end through its hashing layer in bounded 4,096-byte
/// chunks, polling `cancelled` once per chunk ([`CANCEL_POLL_RECORDS`]).
///
/// A framing or locator fault does not stop the hash: the caller drains even
/// after such a fault so a digest mismatch, which outranks every other
/// artifact fault, is reported first. Cancellation returns at once with no
/// digest comparison, preserving that precedence.
fn drain_remaining_for_hash(
    reader: &mut super::artifact::HashedFile,
    cancelled: &dyn Fn() -> bool,
    path: &Path,
) -> Result<(), IndexBundleError> {
    // Bounded: one small stack buffer, no allocation per chunk. Each chunk
    // polls `cancelled` once, so a large invalid tail cannot block shutdown.
    const DRAIN_CHUNK: usize = 4_096;
    debug_assert!(
        matches!(u64::try_from(DRAIN_CHUNK), Ok(v) if v == CANCEL_POLL_RECORDS),
        "drain polls once per bounded chunk on the record interval"
    );
    let mut buf = [0_u8; DRAIN_CHUNK];
    if cancelled() {
        return Err(IndexBundleError::Cancelled);
    }
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|error| io_error(path, error))?;
        if n == 0 {
            break;
        }
        if cancelled() {
            return Err(IndexBundleError::Cancelled);
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
    /// A failed attempt clears its un-watermarked rows before returning. A
    /// cleanup failure is an `Index` error: the store is uncertain, so the
    /// worker must fail instead of reconciling over partial rows toward a
    /// readiness the bundle never earned.
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
        let watermarks = self
            .host
            .writer
            .fenced_watermarks()
            .map(|(_, watermarks)| watermarks);
        let reset = || {
            self.host
                .writer
                .reset_capabilities(IndexCapabilities::TX_LOOKUP)
        };
        Err(discard_partial_rows(error, watermarks, reset))
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
        // The chain may have reorged during the long stream: refuse to stamp
        // a watermark for a base that left the active chain. A tip advance
        // past the base is fine — restore supports an above-base tip and
        // backfill continues above it — so only the base identity is
        // rechecked. Un-watermarked rows are cleared by the existing reset
        // path, so a retry starts clean.
        let tip = self.host.applied_tip.load_full().ok_or_else(|| {
            IndexBundleError::Identity("the receiver has no applied tip".to_owned())
        })?;
        let base_height = self.manifest.identity.base_height;
        let still_active = {
            let tree = self.host.block_tree.read();
            tree.node_at_height_from(tip.tip_id, base_height)
                .and_then(|id| tree.node(id).ok())
                .is_some_and(|node| node.hash.to_le_bytes() == self.manifest.identity.base_hash)
        };
        if !still_active {
            return Err(IndexBundleError::Identity(
                "the bundle base is not on the receiver's active chain".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Clears a failed import's un-watermarked rows before its error is reported.
///
/// A cleanup failure is an `Index` error even when the import itself failed
/// with a bundle refusal: the store may hold partial rows, so the worker
/// must fail instead of reconciling over them toward a readiness the bundle
/// never earned. A watermarked capability needs no reset.
fn discard_partial_rows(
    error: IndexBundleError,
    watermarks: Result<IndexWatermarks, IndexError>,
    reset: impl FnOnce() -> Result<(), IndexError>,
) -> IndexBundleError {
    let watermarks = match watermarks {
        Ok(watermarks) => watermarks,
        Err(error) => return IndexBundleError::Index(error),
    };
    if watermarks.tx_lookup.is_none() {
        if let Err(error) = reset() {
            return IndexBundleError::Index(error);
        }
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable::chain::is_top_level_span;
    use crate::types::TxPosition;
    use std::cell::Cell;

    /// The invalid-bundle drain is a bounded chunked copy that polls
    /// cancellation once per 4,096-byte chunk: an untripped poll drains
    /// fully so the digest comparison can outrank framing faults, while a
    /// trip returns `Cancelled` at once with no digest comparison.
    #[test]
    fn invalid_tail_drain_polls_cancellation_per_bounded_chunk()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tail.dat");
        // Several poll intervals plus a short tail: the final chunk is
        // partial by construction, so the drain must not assert alignment.
        let interval = usize::try_from(CANCEL_POLL_RECORDS)?;
        let bytes = vec![0xAB_u8; 3 * interval + 17];
        std::fs::write(&path, &bytes)?;
        let expected = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest: [u8; 32] = hasher.finalize().into();
            digest
        };

        // No cancellation drains fully and hashes every byte.
        let mut reader = open_hashed(&path)?;
        drain_remaining_for_hash(&mut reader, &|| false, &path)?;
        assert_eq!(
            into_digest(reader),
            expected,
            "the bounded drain must hash the whole tail"
        );

        // Immediate cancellation stops before any digest comparison.
        let mut reader = open_hashed(&path)?;
        let immediate = drain_remaining_for_hash(&mut reader, &|| true, &path);
        assert!(
            matches!(immediate, Err(IndexBundleError::Cancelled)),
            "entry poll must stop the drain: {immediate:?}"
        );

        // A trip after the first chunk stops mid-tail, even though the
        // undrained digest would mismatch: cancellation outranks the hash.
        let polls = Cell::new(0_u32);
        let mut reader = open_hashed(&path)?;
        let mid = drain_remaining_for_hash(
            &mut reader,
            &|| {
                polls.set(polls.get() + 1);
                polls.get() > 1
            },
            &path,
        );
        assert!(
            matches!(mid, Err(IndexBundleError::Cancelled)),
            "mid-drain stop must return at once: {mid:?}"
        );
        assert!(polls.get() >= 2, "the drain must poll more than once");
        Ok(())
    }

    /// A locator must equal its top-level span exactly. An offset shifted
    /// into the transaction body (an embedded serialization), a truncated
    /// length, or an overlapping span never matches, even when the bytes at
    /// the shifted offset decode to a transaction elsewhere.
    #[test]
    fn top_level_spans_must_match_exactly() {
        let position = TxPosition::new(100, 200);
        assert!(is_top_level_span(position, 100, 200));
        assert!(
            !is_top_level_span(position, 101, 200),
            "an embedded offset inside the transaction is not its boundary"
        );
        assert!(
            !is_top_level_span(position, 100, 199),
            "a truncated length is not the transaction boundary"
        );
        assert!(
            !is_top_level_span(position, 90, 210),
            "an overlapping span is not the transaction boundary"
        );
    }

    /// Omitted records are refused at the first height whose bundle count
    /// differs from the chain, so an incomplete bundle never receives the
    /// complete watermark. A height with no bundle positions reports zero.
    #[test]
    fn omitted_positions_report_first_missing_height() {
        let counts = HashMap::from([(0_u32, 2_u64), (1_u32, 1_u64)]);
        assert!(incomplete_at(&counts, 0, 2).is_none());
        assert!(
            matches!(
                incomplete_at(&counts, 1, 2),
                Some(IndexBundleError::Incomplete {
                    height: 1,
                    expected: 2,
                    actual: 1,
                })
            ),
            "an omitted transaction must be refused at its height"
        );
        assert!(
            matches!(
                incomplete_at(&counts, 2, 1),
                Some(IndexBundleError::Incomplete {
                    height: 2,
                    expected: 1,
                    actual: 0,
                })
            ),
            "a height with no bundle positions reports zero"
        );
    }

    /// A failed import cleanup is an `Index` error even when the import
    /// itself failed with a bundle refusal: the store may hold partial rows,
    /// so the worker must fail instead of reconciling toward a readiness the
    /// bundle never earned. Each branch below drives `discard_partial_rows`
    /// — the exact tail `ImportPlan::import` returns through — with a failing
    /// writer equivalent, not a variant check.
    #[test]
    fn cleanup_failure_preserves_index_error() {
        // The reset fails after a bundle refusal: the `Index` error wins, so
        // the worker fails instead of reconciling over partial rows.
        let fatal = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Ok(IndexWatermarks::default()),
            || Err(IndexError::InvalidWatermark),
        );
        assert!(
            matches!(&fatal, IndexBundleError::Index(_)),
            "a failing reset must stop the worker, not report the refusal: {fatal}"
        );
        // The reset succeeds after a bundle refusal: the refusal is reported
        // and ordinary backfill proceeds.
        let refusal = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Ok(IndexWatermarks::default()),
            || Ok(()),
        );
        assert!(
            matches!(&refusal, IndexBundleError::Locator { height: 9 }),
            "a cleared import must report its refusal: {refusal}"
        );
        // The watermark read itself fails: the store is uncertain, so the
        // worker fails without running the reset.
        let uncertain = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Err(IndexError::InvalidWatermark),
            || panic!("the reset must not run when the watermarks are uncertain"),
        );
        assert!(
            matches!(&uncertain, IndexBundleError::Index(_)),
            "an unreadable fence must stop the worker: {uncertain}"
        );
        // The capability is watermarked: no partial rows exist, the reset is
        // skipped, and the original error is reported.
        let watermarked = IndexWatermarks {
            tx_lookup: Some(IndexWatermark {
                height: 1,
                hash: [0_u8; 32],
            }),
            ..IndexWatermarks::default()
        };
        let reported = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Ok(watermarked),
            || panic!("the reset must not run when the capability is watermarked"),
        );
        assert!(
            matches!(&reported, IndexBundleError::Locator { height: 9 }),
            "a watermarked capability needs no cleanup: {reported}"
        );
    }
}
