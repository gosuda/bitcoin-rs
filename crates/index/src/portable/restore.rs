//! Restore: one validating pass, then one fenced applying pass.

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

    let identity = check_identity(host, request, &manifest);
    let fresh = ensure_fresh(host);
    let verify_with = match (&identity, &fresh) {
        (Ok((chain, None)), Ok(())) => Some(chain),
        _ => None,
    };
    let (header, located) = validate_artifact(host, &artifact_path, &manifest, verify_with)?;
    let (chain, count_withheld) = identity?;
    fresh?;
    if let Some(withheld) = count_withheld {
        return Ok(BundleOutcome::RestoreWithheld(withheld));
    }
    match located {
        LocatorOutcome::Verified => {}
        LocatorOutcome::Mismatch { height } => return Err(IndexBundleError::Locator { height }),
        LocatorOutcome::Withheld(withheld) => return Ok(BundleOutcome::RestoreWithheld(withheld)),
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

pub(crate) fn reset_interrupted_import(
    writer: &dyn TxIndexWriter,
    reader: &dyn IndexReader,
) -> Result<bool, IndexError> {
    let (_, watermarks) = writer.fenced_watermarks()?;
    if watermarks.tx_lookup.is_some() {
        return Ok(false);
    }
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

fn ensure_fresh(host: &BundleHost<'_>) -> Result<(), IndexBundleError> {
    let (_, watermarks) = host.writer.fenced_watermarks()?;
    if watermarks.tx_lookup.is_some() {
        return Err(IndexBundleError::NotFresh);
    }
    Ok(())
}

enum LocatorOutcome {
    Verified,
    Mismatch { height: u32 },
    Withheld(Withheld),
    NotChecked,
}

struct LocatorCheck<'a> {
    chain: &'a ChainBase,
    tree: &'a BlockTreeReader,
    bodies: BodyReader<'a>,
    pending: HashMap<u32, Vec<(TxPosition, [u8; 32])>>,
    pending_positions: usize,
    counts: HashMap<u32, u64>,
    outcome: LocatorOutcome,
}

impl LocatorCheck<'_> {
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
                None => return Ok(()),
            };
            block_counts.insert(height, count);
        }
        for height in floor..=base {
            if u64::from(height) % CANCEL_POLL_RECORDS == 0 && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            let expected = block_counts.get(&height).copied().unwrap_or(0);
            if let Some(error) = incomplete_at(&self.counts, height, expected) {
                return Err(error);
            }
        }
        Ok(())
    }
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

/// Streams the whole artifact once: SHA-256, header, record framing, and, when `chain`
/// is given, locator verification.
///
/// A framing or locator fault does not stop the hash: the rest of the file is drained
/// so a digest mismatch, which outranks every other artifact fault, is reported first.
/// Cancellation returns at once.
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
        (None, _) => LocatorOutcome::NotChecked,
    };
    Ok((header, outcome))
}

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

/// A framing or locator fault does not stop the hash: the caller drains even
fn drain_remaining_for_hash(
    reader: &mut super::artifact::HashedFile,
    cancelled: &dyn Fn() -> bool,
    path: &Path,
) -> Result<(), IndexBundleError> {
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

struct ImportPlan<'a> {
    host: &'a BundleHost<'a>,
    path: &'a Path,
    manifest: &'a ValidatedManifest,
    header: ArtifactHeader,
    chain: &'a ChainBase,
}

impl ImportPlan<'_> {
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

    /// fully so the digest comparison can outrank framing faults, while a
    /// trip returns `Cancelled` at once with no digest comparison.
    #[test]
    fn invalid_tail_drain_polls_cancellation_per_bounded_chunk()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("tail.dat");
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

        let mut reader = open_hashed(&path)?;
        drain_remaining_for_hash(&mut reader, &|| false, &path)?;
        assert_eq!(
            into_digest(reader),
            expected,
            "the bounded drain must hash the whole tail"
        );

        let mut reader = open_hashed(&path)?;
        let immediate = drain_remaining_for_hash(&mut reader, &|| true, &path);
        assert!(
            matches!(immediate, Err(IndexBundleError::Cancelled)),
            "entry poll must stop the drain: {immediate:?}"
        );

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

    #[test]
    fn cleanup_failure_preserves_index_error() {
        let fatal = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Ok(IndexWatermarks::default()),
            || Err(IndexError::InvalidWatermark),
        );
        assert!(
            matches!(&fatal, IndexBundleError::Index(_)),
            "a failing reset must stop the worker, not report the refusal: {fatal}"
        );
        let refusal = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Ok(IndexWatermarks::default()),
            || Ok(()),
        );
        assert!(
            matches!(&refusal, IndexBundleError::Locator { height: 9 }),
            "a cleared import must report its refusal: {refusal}"
        );
        let uncertain = discard_partial_rows(
            IndexBundleError::Locator { height: 9 },
            Err(IndexError::InvalidWatermark),
            || panic!("the reset must not run when the watermarks are uncertain"),
        );
        assert!(
            matches!(&uncertain, IndexBundleError::Index(_)),
            "an unreadable fence must stop the worker: {uncertain}"
        );
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
