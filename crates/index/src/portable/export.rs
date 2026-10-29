//! Export: stream the `TxLookup` family of one coherent snapshot into a
//! hashed artifact, then publish the manifest last.
//!
//! Every exported locator must equal a real top-level block transaction
//! boundary: the recorded offset and length must match one parsed transaction
//! span of the block body, the same rule restore enforces.
//!
//! Consistency: the row stream is read from one point-in-time key-value
//! snapshot whose `TxLookup` watermark is the applied tip (snapshot
//! isolation). The writer's fenced watermark capture before and after the
//! stream is a linearizable compare; any movement aborts and removes the
//! output, so a published manifest always names a bundle taken at one
//! watermark. Re-running an export into a fresh directory is idempotent: it
//! reads state and writes only new files.

use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, CANCEL_POLL_RECORDS, HEADER_LEN, IO_BUFFER_BYTES, hash_file,
    write_record,
};
use super::chain::{BodyReader, ChainBase, Located};
use super::manifest::{
    BundleFamily, BundleIdentity, IndexBundleManifestV1, IndexMode, MANIFEST_FILE, TxLookupArtifact,
};
use super::{
    BundleHost, ExportReport, IndexBundleError, IndexBundleRequest, MAX_RESTORE_POSITIONS, io_error,
    sync_dir,
};
use crate::types::{HASH_PREFIX_ROW_SIZE, HashPrefixRow, TxPosition, TxPositionValue, positions_are_valid};
use crate::{
    IndexCapability, IndexError, IndexWatermark, IndexWriteFence, TxIndexFamily,
};
#[cfg(test)]
use crate::TxIndexSnapshot;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_storage::{PrefixScanLimit, StorageError};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zerocopy::IntoBytes;

/// Rows per export page. Export streams the family through bounded pages
/// over one snapshot, so export memory stays flat in family size on every
/// backend instead of materializing the whole family before emitting rows.
const EXPORT_PAGE_ROWS: usize = 1_024;
/// Cap on returned key-plus-value bytes per page after the first row.
const EXPORT_PAGE_BYTES: usize = 1 << 20;

/// Limit for one export page scan.
fn export_page_limit() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: EXPORT_PAGE_ROWS,
        max_bytes: EXPORT_PAGE_BYTES,
    }
}

/// Streams every `TxConfirmed` row of one snapshot in stored-key order
/// through bounded pages, calling `emit` once per row.
///
/// Cancellation is polled every [`CANCEL_POLL_RECORDS`] visited rows.
/// Pages concatenate to the family's stored order; a page scan that
/// returns an empty incomplete page can make no progress, so it refuses
/// rather than loops.
#[expect(
    clippy::type_complexity,
    reason = "the page emitter signature is the streaming interface; an alias would hide the output contract"
)]
#[cfg(test)]
fn stream_family_pages(
    snapshot: &dyn TxIndexSnapshot,
    limit: PrefixScanLimit,
    cancelled: &dyn Fn() -> bool,
    emit: &mut dyn FnMut(HashPrefixRow, &[u8]) -> Result<(u64, u64), IndexBundleError>,
) -> Result<(u64, u64), IndexBundleError> {
    let mut start_after: Option<Vec<u8>> = None;
    let mut visited = 0_u64;
    let mut totals = (0_u64, 0_u64);
    loop {
        let page =
            snapshot.scan_family_page(TxIndexFamily::TxConfirmed, start_after.as_deref(), limit)?;
        let mut last_key: Option<Vec<u8>> = None;
        for scan_row in page.rows {
            visited += 1;
            if visited.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            let (records, bytes) = emit(scan_row.row, &scan_row.value)?;
            totals.0 += records;
            totals.1 += bytes;
            last_key = Some(scan_row.row.to_db_row().to_vec());
        }
        if page.complete {
            return Ok(totals);
        }
        let Some(last) = last_key else {
            // A conforming page scan always returns its first row while rows
            // remain; without one there is no cursor to advance.
            return Err(IndexError::from(StorageError::InvalidOperation(
                "export page scan returned an empty incomplete page",
            ))
            .into());
        };
        // Stored keys are fixed-width: the suffixed key is the least key
        // strictly above the page, so the next page resumes without overlap
        // or gap.
        let mut next = last;
        next.push(0);
        start_after = Some(next);
    }
}

/// Directory fsync used by a [`Publication`].
type SyncDir = fn(&Path) -> Result<(), IndexBundleError>;

/// Owns every file one export creates in its bundle directory.
///
/// Files are created with create-new, so an entry that existed before the
/// export is never opened, replaced, or removed. Until [`Self::commit`]
/// makes the final directory entry durable, dropping the publication removes
/// the created files newest first: the manifest goes before the artifact it
/// names, and the artifact is removed only once the manifest's removal is
/// itself durable. A failed, stale, or cancelled export therefore never
/// leaves a manifest that names a missing artifact.
struct Publication {
    dir: PathBuf,
    /// Created paths, oldest first.
    created: Vec<PathBuf>,
    committed: bool,
    sync: SyncDir,
}

impl Publication {
    fn new(dir: &Path) -> Self {
        Self::with_sync(dir, sync_dir)
    }

    fn with_sync(dir: &Path, sync: SyncDir) -> Self {
        Self {
            dir: dir.to_path_buf(),
            created: Vec::new(),
            committed: false,
            sync,
        }
    }

    /// Creates `path`, refusing to overwrite anything already there, and
    /// takes ownership of its removal.
    fn create_new(&mut self, path: &Path) -> Result<File, IndexBundleError> {
        let file = create_new_file(path)?;
        self.created.push(path.to_path_buf());
        Ok(file)
    }

    /// Makes every created entry durable. Only success disarms the cleanup;
    /// a failed directory fsync is returned, never retried, and the drop
    /// removes the created files.
    fn commit(mut self) -> Result<(), IndexBundleError> {
        (self.sync)(&self.dir)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        while let Some(path) = self.created.pop() {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "cannot remove a file of an unpublished index bundle; leaving older files in place"
                    );
                    return;
                }
            }
            if let Err(error) = (self.sync)(&self.dir) {
                // The removal may not be durable; removing an older file now
                // could leave a surviving manifest naming a missing artifact.
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "cannot make an unpublished index bundle removal durable; leaving older files in place"
                );
                return;
            }
        }
    }
}

/// Creates `path`, refusing to overwrite anything already there.
fn create_new_file(path: &Path) -> Result<File, IndexBundleError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                IndexBundleError::ExistingBundle(path.to_path_buf())
            } else {
                io_error(path, error)
            }
        })
}

/// Exports the `TxLookup` family at the applied tip into `request.dir`.
pub(super) fn export(
    host: &BundleHost<'_>,
    request: &IndexBundleRequest,
) -> Result<ExportReport, IndexBundleError> {
    if !host.enabled.contains(IndexCapability::TxLookup) {
        return Err(IndexBundleError::TxLookupDisabled);
    }
    let dir = request.dir.as_path();
    let manifest_path = dir.join(MANIFEST_FILE);
    if manifest_path
        .try_exists()
        .map_err(|error| io_error(&manifest_path, error))?
    {
        return Err(IndexBundleError::ExistingBundle(manifest_path));
    }

    let captured = Captured::take(host)?;
    fs::create_dir_all(dir).map_err(|error| io_error(dir, error))?;
    let artifact_path = dir.join(BundleFamily::TxLookup.file_name());
    let mut publication = Publication::new(dir);
    let file = publication.create_new(&artifact_path)?;
    let identity = captured.identity(request);
    let artifact = captured.write_artifact(host, file, &artifact_path, &identity)?;

    // Abort stale output: the writer must still show exactly the captured
    // fence (reset state, ordinary revision, and watermarks), or the stream
    // may describe rows the index no longer holds; an equal watermark alone
    // would miss a completed reset and rebuild in between.
    let (after, _) = host.writer.fenced_watermarks()?;
    if after != captured.fence {
        return Err(IndexBundleError::Stale);
    }

    // The artifact's directory entry is durable before any manifest names it.
    sync_dir(dir)?;
    let mode = if host.enabled.contains(IndexCapability::ScriptHistory) {
        IndexMode::Full
    } else {
        IndexMode::Utxo
    };
    let manifest = IndexBundleManifestV1::for_tx_lookup(&identity, mode, captured.floor, &artifact);
    write_manifest(&mut publication, &manifest_path, &manifest.to_json()?)?;
    publication.commit()?;
    Ok(ExportReport {
        base: IndexWatermark {
            height: captured.chain.height,
            hash: captured.chain.hash,
        },
        records: artifact.records,
        bytes: artifact.bytes,
    })
}

/// Writes and fsyncs `manifest.json` with create-new. Its directory entry
/// becomes durable only through [`Publication::commit`]; until then the
/// publication removes it on failure.
fn write_manifest(
    publication: &mut Publication,
    path: &Path,
    json: &[u8],
) -> Result<(), IndexBundleError> {
    let mut file = publication.create_new(path)?;
    file.write_all(json)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

/// Everything an export fixes at its start: the exact watermarks, the chain
/// identity of the applied tip, and the base watermark every per-page
/// snapshot must still show.
struct Captured<'a> {
    fence: IndexWriteFence,
    chain: ChainBase,
    /// The applied tip's cumulative transaction count, which is the base's.
    chain_tx_count: u64,
    base: IndexWatermark,
    floor: u32,
    bodies: &'a dyn BlockBodySource,
}

impl<'a> Captured<'a> {
    /// Requires the `TxLookup` watermark to be exactly the applied tip and the
    /// snapshot to agree with it; otherwise nothing is written.
    fn take(host: &BundleHost<'a>) -> Result<Self, IndexBundleError> {
        let (fence, watermarks) = host.writer.fenced_watermarks()?;
        let base = watermarks
            .tx_lookup
            .ok_or(IndexBundleError::NotReady("txindex has no watermark"))?;
        let tip = host
            .applied_tip
            .load_full()
            .ok_or(IndexBundleError::NotReady("there is no applied tip"))?;
        if base.height != tip.height || base.hash != tip.hash.to_le_bytes() {
            return Err(IndexBundleError::NotReady(
                "the txindex watermark is not at the applied tip",
            ));
        }
        let chain = ChainBase::capture(host.block_tree, &tip, tip.height, host.cancelled)?;
        if !chain.validated {
            return Err(IndexBundleError::NotReady(
                "the base block is not on the active chain",
            ));
        }
        // The base is the applied tip, so no block lies above it to read.
        let chain_tx_count = chain.counted_base().ok_or(IndexBundleError::NotReady(
            "the chain transaction count at the base is not established",
        ))?;
        let bodies = host
            .body_source
            .ok_or(IndexBundleError::NotReady("there is no block body source"))?;
        let floor = {
            let snapshot = host.reader.snapshot()?;
            if snapshot.capability_watermark(IndexCapability::TxLookup)? != Some(base) {
                return Err(IndexBundleError::Stale);
            }
            snapshot.capability_floor(IndexCapability::TxLookup)?
        };
        Ok(Self {
            fence,
            chain,
            chain_tx_count,
            base,
            floor,
            bodies,
        })
    }

    fn identity(&self, request: &IndexBundleRequest) -> BundleIdentity {
        BundleIdentity {
            network: request.network,
            genesis: self.chain.genesis,
            format_version: crate::index::index_format_version(),
            base_height: self.chain.height,
            base_hash: self.chain.hash,
            chainwork: self.chain.chainwork,
            chain_tx_count: self.chain_tx_count,
        }
    }

    /// Streams the records, patches the final header over the placeholder,
    /// fsyncs, and returns the artifact's exact identity.
    ///
    /// The header's record and payload counts are known only after the row
    /// stream, and the digest covers the header first, so the digest is taken
    /// by one bounded hashed read of the final fsynced bytes rather than
    /// during the write: it names exactly the file a manifest will publish.
    fn write_artifact(
        &self,
        host: &BundleHost<'_>,
        file: File,
        path: &Path,
        identity: &BundleIdentity,
    ) -> Result<TxLookupArtifact, IndexBundleError> {
        let write = |error| io_error(path, error);
        let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
        out.write_all(&[0_u8; HEADER_LEN]).map_err(write)?;
        let mut rows = RowExporter {
            host,
            chain: &self.chain,
            floor: self.floor,
            reader: BodyReader::new(self.bodies),
            located: Vec::new(),
            positions: Vec::new(),
            positions_written: 0,
            path,
        };
        let (records, payload_bytes) = rows.stream(self.base, &mut out)?;
        let mut file = out
            .into_inner()
            .map_err(|error| io_error(path, error.into_error()))?;
        let header = ArtifactHeader {
            family: BundleFamily::TxLookup,
            artifact_version: ARTIFACT_VERSION,
            index_format: identity.format_version,
            network_magic: identity.network.magic(),
            base_height: identity.base_height,
            base_hash: identity.base_hash,
            records,
            payload_bytes,
        };
        file.seek(SeekFrom::Start(0)).map_err(write)?;
        file.write_all(&header.encode()).map_err(write)?;
        file.sync_all().map_err(write)?;
        drop(file);
        let (sha256, bytes) = hash_file(path).map_err(write)?;
        Ok(TxLookupArtifact {
            sha256,
            bytes,
            records,
            floor: self.floor,
        })
    }
}

/// Turns stored `TxConfirmed` rows into full-txid records, one row at a time.
struct RowExporter<'a> {
    host: &'a BundleHost<'a>,
    chain: &'a ChainBase,
    floor: u32,
    reader: BodyReader<'a>,
    /// `(txid, position)` pairs of the current row, sorted by id then position.
    located: Vec<([u8; 32], TxPosition)>,
    /// Scratch position list of the record being written.
    positions: Vec<TxPosition>,
    /// Positions already written to the artifact.
    positions_written: u64,
    path: &'a Path,
}

/// Sort key of one staged row entry: `height` big-endian then `sequence`
/// big-endian, so byte order is numeric order.
const STAGED_SORT_KEY_LEN: usize = 4 + 8;
/// Sort key of one resolved entry: `sequence` big-endian.
const RESOLVED_SORT_KEY_LEN: usize = 8;
/// Staged payload of one row: the fixed-width stored key, the value length,
/// then the value.
const STAGED_KEY_LEN: usize = HASH_PREFIX_ROW_SIZE;
/// Bytes accumulated per external-sort run. Runs are cut by bytes rather than
/// by entries so one run never exceeds a constant even when single rows carry
/// unusually large position lists.
const SORT_RUN_BYTES: usize = 4 << 20;
/// Sorted runs merged at once. The merge holds one decoded head entry plus
/// one open file per run, so descriptors and memory stay bounded no matter
/// how many runs a family needs.
const SORT_MERGE_FAN_IN: usize = 32;

/// One framed external-sort record: `sort_key || payload_len (u64 LE) ||
/// payload`. Merge passes compare only the fixed-width sort key, so one
/// implementation sorts both the staged file (keyed by height) and the
/// resolved file (keyed by sequence).
fn write_framed(out: &mut impl Write, key: &[u8], payload: &[u8]) -> io::Result<()> {
    out.write_all(key)?;
    out.write_all(&(payload.len() as u64).to_le_bytes())?;
    out.write_all(payload)
}

/// Reads one framed record, or `None` at a clean record boundary. A file
/// that ends inside a key, length, or payload is corruption, never a clean
/// end.
fn read_framed(
    reader: &mut impl Read,
    key_len: usize,
) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut key = vec![0_u8; key_len];
    match reader.read_exact(&mut key) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut len = [0_u8; 8];
    reader.read_exact(&mut len)?;
    let len = u64::from_le_bytes(len);
    let len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sort record too large"))?;
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some((key, payload)))
}

/// Sorts every framed record of `file` by its sort key, using bounded memory.
///
/// The file is split into sorted runs of at most [`SORT_RUN_BYTES`], then the
/// runs merge [`SORT_MERGE_FAN_IN`] at a time until one sorted file remains;
/// the file is rewritten in place and left at its start. Anonymous temp files
/// back the runs, so cancelling or failing the export removes every staging
/// byte with the file handles. Cancellation is polled every
/// [`CANCEL_POLL_RECORDS`] records during run generation and merging, and
/// once per bounded copy chunk, so a large sort stops promptly instead of
/// running to completion after shutdown.
fn external_sort(
    file: &mut File,
    key_len: usize,
    path: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), IndexBundleError> {
    let failed = move |error: io::Error| io_error(path, error);
    if cancelled() {
        return Err(IndexBundleError::Cancelled);
    }
    file.seek(SeekFrom::Start(0)).map_err(failed)?;
    let mut runs: Vec<File> = Vec::new();
    let mut at_end = false;
    let mut read = 0_u64;
    while !at_end {
        let mut chunk: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut chunk_bytes = 0_usize;
        while chunk_bytes < SORT_RUN_BYTES {
            match read_framed(file, key_len).map_err(failed)? {
                None => {
                    at_end = true;
                    break;
                }
                Some((key, payload)) => {
                    read = read.saturating_add(1);
                    if read.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                        return Err(IndexBundleError::Cancelled);
                    }
                    chunk_bytes = chunk_bytes
                        .saturating_add(key.len())
                        .saturating_add(8)
                        .saturating_add(payload.len());
                    chunk.push((key, payload));
                }
            }
        }
        if chunk.is_empty() {
            break;
        }
        if cancelled() {
            return Err(IndexBundleError::Cancelled);
        }
        chunk.sort_by(|left, right| left.0.cmp(&right.0));
        let mut run = tempfile::tempfile().map_err(failed)?;
        let mut written = 0_u64;
        for (key, payload) in &chunk {
            written = written.saturating_add(1);
            if written.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            write_framed(&mut run, key, payload).map_err(failed)?;
        }
        run.seek(SeekFrom::Start(0)).map_err(failed)?;
        runs.push(run);
    }
    while runs.len() > 1 {
        let mut merged: Vec<File> = Vec::with_capacity(runs.len().div_ceil(SORT_MERGE_FAN_IN));
        for group in runs.chunks_mut(SORT_MERGE_FAN_IN) {
            if cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            let mut out = tempfile::tempfile().map_err(failed)?;
            merge_runs(group, &mut out, key_len, path, cancelled)?;
            out.seek(SeekFrom::Start(0)).map_err(failed)?;
            merged.push(out);
        }
        runs = merged;
    }
    file.seek(SeekFrom::Start(0)).map_err(failed)?;
    file.set_len(0).map_err(failed)?;
    if let Some(mut run) = runs.pop() {
        run.seek(SeekFrom::Start(0)).map_err(failed)?;
        copy_sort_run(&mut run, &mut *file, path, cancelled)?;
    }
    file.seek(SeekFrom::Start(0)).map_err(failed)?;
    Ok(())
}

/// Copies one sorted run back into `file` in bounded chunks, polling
/// cancellation once per chunk so a large single-run copy cannot block
/// shutdown after the record passes already polled.
fn copy_sort_run(
    run: &mut File,
    file: &mut File,
    path: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), IndexBundleError> {
    let failed = move |error: io::Error| io_error(path, error);
    if cancelled() {
        return Err(IndexBundleError::Cancelled);
    }
    let mut buf = [0_u8; IO_BUFFER_BYTES];
    loop {
        let n = run.read(&mut buf).map_err(failed)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(failed)?;
        if cancelled() {
            return Err(IndexBundleError::Cancelled);
        }
    }
    Ok(())
}

/// Merges one group of sorted runs into `out`, holding one head entry and
/// one open file per run.
///
/// Cancellation is polled every [`CANCEL_POLL_RECORDS`] merged records, so a
/// large merge stops promptly instead of running to completion after
/// shutdown.
fn merge_runs(
    runs: &mut [File],
    out: &mut File,
    key_len: usize,
    path: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), IndexBundleError> {
    let failed = move |error: io::Error| io_error(path, error);
    if cancelled() {
        return Err(IndexBundleError::Cancelled);
    }
    let mut readers: Vec<BufReader<&mut File>> = runs.iter_mut().map(BufReader::new).collect();
    let mut heads: Vec<Option<(Vec<u8>, Vec<u8>)>> = Vec::with_capacity(readers.len());
    for reader in readers.iter_mut() {
        heads.push(read_framed(reader, key_len).map_err(failed)?);
    }
    let mut heap: BinaryHeap<Reverse<(Vec<u8>, usize)>> = BinaryHeap::new();
    for (index, head) in heads.iter().enumerate() {
        if let Some((key, _)) = head {
            heap.push(Reverse((key.clone(), index)));
        }
    }
    let mut merged = 0_u64;
    while let Some(Reverse((key, index))) = heap.pop() {
        let Some((_, payload)) = heads[index].take() else {
            return Err(IndexError::from(StorageError::InvalidOperation(
                "sort merge lost its head entry",
            ))
            .into());
        };
        write_framed(out, &key, &payload).map_err(failed)?;
        merged = merged.saturating_add(1);
        if merged.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
            return Err(IndexBundleError::Cancelled);
        }
        if let Some(next) = read_framed(&mut readers[index], key_len).map_err(failed)? {
            heap.push(Reverse((next.0.clone(), index)));
            heads[index] = Some(next);
        }
    }
    Ok(())
}

/// Staged payload of one stored row: the fixed-width stored key, the value
/// length, then the value.
fn encode_staged(key: &[u8; STAGED_KEY_LEN], value: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(STAGED_KEY_LEN + 8 + value.len());
    payload.extend_from_slice(key);
    payload.extend_from_slice(&(value.len() as u64).to_le_bytes());
    payload.extend_from_slice(value);
    payload
}

/// Splits one staged payload back into its stored key and value.
fn decode_staged(payload: &[u8]) -> Option<([u8; STAGED_KEY_LEN], &[u8])> {
    let key: [u8; STAGED_KEY_LEN] = payload.get(..STAGED_KEY_LEN)?.try_into().ok()?;
    let rest = payload.get(STAGED_KEY_LEN..)?;
    let len = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
    let len = usize::try_from(len).ok()?;
    let value = rest.get(8..)?;
    if value.len() != len {
        return None;
    }
    Some((key, value))
}

/// Resolved payload of one row: the height, the entry count, then one
/// `txid || position` pair per entry, with positions in [`TxPosition`]'s
/// little-endian 6-byte layout.
fn encode_resolved(height: u32, located: &[([u8; 32], TxPosition)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + located.len() * (32 + 6));
    payload.extend_from_slice(&height.to_le_bytes());
    payload.extend_from_slice(&(located.len() as u64).to_le_bytes());
    for (txid, position) in located {
        payload.extend_from_slice(txid);
        payload.extend_from_slice(position.as_bytes());
    }
    payload
}

/// Splits one resolved payload back into its height and located pairs.
fn decode_resolved(payload: &[u8]) -> Option<(u32, Vec<([u8; 32], TxPosition)>)> {
    if payload.len() < 12 {
        return None;
    }
    let height = u32::from_le_bytes(payload.get(..4)?.try_into().ok()?);
    let count = u64::from_le_bytes(payload.get(4..12)?.try_into().ok()?);
    let count = usize::try_from(count).ok()?;
    let mut rest = payload.get(12..)?;
    if rest.len() != count.checked_mul(32 + 6)? {
        return None;
    }
    let mut located = Vec::with_capacity(count);
    for _ in 0..count {
        let (txid, tail) = rest.split_at(32);
        let (raw, next) = tail.split_at(6);
        let offset = u32::from_le_bytes([raw[0], raw[1], raw[2], 0]);
        let len = u32::from_le_bytes([raw[3], raw[4], raw[5], 0]);
        located.push((txid.try_into().ok()?, TxPosition::new(offset, len)));
        rest = next;
    }
    Some((height, located))
}

impl RowExporter<'_> {
    /// Streams every row once, in stored-key order, and returns
    /// `(records, payload bytes)`.
    ///
    /// Stored order is transaction-id order while bodies are keyed by block,
    /// so resolving in stored order reloads and reparses one body per row,
    /// and grouping only within each page still reloads one body per page a
    /// block touches. The export instead stages every row into an anonymous
    /// temp file, sorts the staging file by `(height, sequence)`, resolves
    /// the height-ordered rows so each covered body is read and parsed once,
    /// then re-sorts the resolved rows by sequence and emits them in stored
    /// order. The artifact keeps its strictly ascending record order while
    /// body I/O stays height-local.
    ///
    /// Each page is read through a short-lived snapshot that must still show
    /// `base` at `self.floor`; snapshots are dropped before any body I/O, so
    /// a long export never pins one key-value snapshot across the whole
    /// family. Rows stream through bounded pages, sorts spill through bounded
    /// runs, and only one row is resolved or emitted at a time, so export
    /// memory stays flat in family size on every backend. Cancellation is
    /// polled every [`CANCEL_POLL_RECORDS`] scanned, resolved, or emitted
    /// rows, and on the same interval through both sorts (run generation,
    /// merging, and the final copy). The writer's end-to-end fence, checked
    /// after the stream, covers the whole external pass: any watermark
    /// movement aborts and removes the output.
    fn stream(
        &mut self,
        base: IndexWatermark,
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        // `host` is itself a shared reference, so copying the cancellation
        // probe out ends the borrow of `self` immediately.
        let cancelled = self.host.cancelled;
        let (mut staged, rows) = self.enumerate(base, cancelled)?;
        if rows == 0 {
            return Ok((0, 0));
        }
        external_sort(&mut staged, STAGED_SORT_KEY_LEN, self.path, cancelled)?;
        let mut resolved = self.resolve(&mut staged, rows, cancelled)?;
        external_sort(
            &mut resolved,
            RESOLVED_SORT_KEY_LEN,
            self.path,
            cancelled,
        )?;
        self.emit(&mut resolved, rows, out, cancelled)
    }

    /// Validates one stored row value and charges its positions against the
    /// running total, returning the new total. Invalid rows fail here with
    /// `SourceRow` before any staging write, matching the later resolve
    /// check. Totals past the shared restore bound fail with
    /// `ExportTooLarge` before the row is written or sorted, so an
    /// unimportable family never pays staging or sort I/O.
    fn charge_row(value: &[u8], height: u32, total: u64) -> Result<u64, IndexBundleError> {
        let positions = TxPositionValue::decode(value)
            .filter(|found| positions_are_valid(found))
            .ok_or_else(|| IndexBundleError::SourceRow {
                height,
                reason: "row carries no valid position list",
            })?;
        let total = total.saturating_add(u64::try_from(positions.len()).unwrap_or(u64::MAX));
        if total > u64::try_from(MAX_RESTORE_POSITIONS).unwrap_or(u64::MAX) {
            return Err(IndexBundleError::ExportTooLarge {
                limit_positions: MAX_RESTORE_POSITIONS,
            });
        }
        Ok(total)
    }

    /// Streams every stored row once, in stored-key order, into an anonymous
    /// staging file keyed by `(height, sequence)`.
    ///
    /// Each page is read through a short-lived snapshot that must still show
    /// `base` at `self.floor`; the snapshot is dropped before the next page,
    /// so a long export never pins one key-value snapshot across the whole
    /// family. No body I/O happens here: bodies are read once the staging
    /// file is sorted by height. Positions are decoded, validated, and
    /// counted against the shared restore bound before staging: over-limit
    /// families fail with `ExportTooLarge` before any write or sort, while
    /// corrupt rows fail with `SourceRow`. The later resolve and emit checks
    /// remain as defense. Cancellation is polled every
    /// [`CANCEL_POLL_RECORDS`] scanned rows. Returns the staging file, left
    /// at its start, and the stored-order row count.
    fn enumerate(
        &self,
        base: IndexWatermark,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(File, u64), IndexBundleError> {
        let path = self.path;
        let failed = move |error: io::Error| io_error(path, error);
        let limit = export_page_limit();
        let mut start_after: Option<Vec<u8>> = None;
        let mut staged = tempfile::tempfile().map_err(failed)?;
        let mut seq = 0_u64;
        let mut scanned = 0_u64;
        let mut positions_total = 0_u64;
        loop {
            let page = {
                let snapshot = self.host.reader.snapshot()?;
                if snapshot.capability_watermark(IndexCapability::TxLookup)? != Some(base) {
                    return Err(IndexBundleError::Stale);
                }
                if snapshot.capability_floor(IndexCapability::TxLookup)? != self.floor {
                    return Err(IndexBundleError::Stale);
                }
                snapshot.scan_family_page(
                    TxIndexFamily::TxConfirmed,
                    start_after.as_deref(),
                    limit,
                )?
            };
            for row in &page.rows {
                scanned = scanned.saturating_add(1);
                if scanned.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                    return Err(IndexBundleError::Cancelled);
                }
                positions_total = Self::charge_row(&row.value, row.row.height(), positions_total)?;
                let key = row.row.to_db_row();
                let mut sort_key = [0_u8; STAGED_SORT_KEY_LEN];
                sort_key[..4].copy_from_slice(&row.row.height().to_be_bytes());
                sort_key[4..].copy_from_slice(&seq.to_be_bytes());
                write_framed(&mut staged, &sort_key, &encode_staged(&key, &row.value))
                    .map_err(failed)?;
                seq = seq.saturating_add(1);
            }
            if page.complete {
                break;
            }
            let Some(last) = page.rows.last() else {
                // A conforming page scan always returns its first row while
                // rows remain; without one there is no cursor to advance.
                return Err(IndexError::from(StorageError::InvalidOperation(
                    "export page scan returned an empty incomplete page",
                ))
                .into());
            };
            // Stored keys are fixed-width: the suffixed key is the least key
            // strictly above the page, so the next page resumes without
            // overlap or gap.
            let mut next = last.row.to_db_row().to_vec();
            next.push(0);
            start_after = Some(next);
        }
        staged.seek(SeekFrom::Start(0)).map_err(failed)?;
        Ok((staged, seq))
    }

    /// Resolves the height-sorted staging file into a sequence-keyed resolved
    /// file, reading and parsing each covered body once.
    ///
    /// `staged` must already sort by `(height, sequence)`, so consecutive
    /// rows for one block resolve against one cached body no matter how the
    /// stored order scattered them across pages. One row is resolved and
    /// filed at a time; the body stays resident across its consecutive rows
    /// through the bounded LRU, and a block never recurs once its rows are
    /// filed. Every position still must equal a real top-level transaction
    /// span whose id carries the row's prefix, exactly as direct resolution
    /// enforces, and positions stop at the shared restore bound before the
    /// resolved file can outgrow an importable bundle. Cancellation is polled
    /// every [`CANCEL_POLL_RECORDS`] resolved rows. Returns the resolved
    /// file, left at its start, holding `rows` entries in height order.
    fn resolve(
        &mut self,
        staged: &mut File,
        rows: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<File, IndexBundleError> {
        let path = self.path;
        let failed = move |error: io::Error| io_error(path, error);
        let mut resolved = tempfile::tempfile().map_err(failed)?;
        let mut seen = 0_u64;
        let mut visited = 0_u64;
        let mut positions = 0_u64;
        while seen < rows {
            let Some((sort_key, payload)) =
                read_framed(staged, STAGED_SORT_KEY_LEN).map_err(failed)?
            else {
                return Err(IndexError::from(StorageError::InvalidOperation(
                    "export staging ended before every stored row resolved",
                ))
                .into());
            };
            seen = seen.saturating_add(1);
            let sequence_bytes: [u8; 8] = sort_key.get(4..12).and_then(|bytes| bytes.try_into().ok()).ok_or_else(
                || {
                    IndexError::from(StorageError::InvalidOperation(
                        "export staging carries a malformed sort key",
                    ))
                },
            )?;
            let sequence = u64::from_be_bytes(sequence_bytes);
            let (key, value) = decode_staged(&payload).ok_or_else(|| {
                IndexError::from(StorageError::InvalidOperation(
                    "export staging carries a malformed row",
                ))
            })?;
            let mut prefix = [0_u8; 8];
            prefix.copy_from_slice(&key[..8]);
            let mut encoded = [0_u8; 4];
            encoded.copy_from_slice(&key[8..12]);
            let row = HashPrefixRow {
                prefix,
                height: encoded,
            };
            visited = visited.saturating_add(1);
            if visited.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            self.locate(row, value)?;
            positions = positions.saturating_add(self.located.len() as u64);
            if positions > u64::try_from(MAX_RESTORE_POSITIONS).unwrap_or(u64::MAX) {
                return Err(IndexBundleError::ExportTooLarge {
                    limit_positions: MAX_RESTORE_POSITIONS,
                });
            }
            let mut sequence_key = [0_u8; RESOLVED_SORT_KEY_LEN];
            sequence_key.copy_from_slice(&sequence.to_be_bytes());
            write_framed(
                &mut resolved,
                &sequence_key,
                &encode_resolved(row.height(), &self.located),
            )
            .map_err(failed)?;
        }
        if read_framed(staged, STAGED_SORT_KEY_LEN)
            .map_err(failed)?
            .is_some()
        {
            return Err(IndexError::from(StorageError::InvalidOperation(
                "export staging holds more rows than the stored stream",
            ))
            .into());
        }
        resolved.seek(SeekFrom::Start(0)).map_err(failed)?;
        Ok(resolved)
    }

    /// Emits the sequence-sorted resolved file into the artifact in stored
    /// order, returning `(records, payload bytes)`.
    ///
    /// `resolved` must already sort by sequence, so emission follows the page
    /// stream's stored order exactly and the artifact keeps its strictly
    /// ascending record order. One row is held at a time; the position budget
    /// is re-checked while writing, exactly as direct emission does.
    /// Cancellation is polled every [`CANCEL_POLL_RECORDS`] emitted rows.
    fn emit(
        &mut self,
        resolved: &mut File,
        rows: u64,
        out: &mut impl Write,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(u64, u64), IndexBundleError> {
        let path = self.path;
        let failed = move |error: io::Error| io_error(path, error);
        let mut totals = (0_u64, 0_u64);
        let mut expected = 0_u64;
        while expected < rows {
            let Some((sort_key, payload)) =
                read_framed(resolved, RESOLVED_SORT_KEY_LEN).map_err(failed)?
            else {
                return Err(IndexError::from(StorageError::InvalidOperation(
                    "export staging ended before every stored row emitted",
                ))
                .into());
            };
            let sequence_bytes: [u8; RESOLVED_SORT_KEY_LEN] =
                sort_key.try_into().map_err(|_| {
                    IndexError::from(StorageError::InvalidOperation(
                        "export staging carries a malformed sort key",
                    ))
                })?;
            let sequence = u64::from_be_bytes(sequence_bytes);
            if sequence != expected {
                let height = decode_resolved(&payload)
                    .map(|(height, _)| height)
                    .unwrap_or(u32::MAX);
                return Err(IndexBundleError::SourceRow {
                    height,
                    reason: "resolved rows lost their stored order",
                });
            }
            let (height, located) = decode_resolved(&payload).ok_or_else(|| {
                IndexError::from(StorageError::InvalidOperation(
                    "export staging carries a malformed resolved row",
                ))
            })?;
            let (records, bytes) = self.emit_row(height, &located, out)?;
            totals.0 = totals.0.saturating_add(records);
            totals.1 = totals.1.saturating_add(bytes);
            expected = expected.saturating_add(1);
            if expected.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
        }
        if read_framed(resolved, RESOLVED_SORT_KEY_LEN)
            .map_err(failed)?
            .is_some()
        {
            return Err(IndexError::from(StorageError::InvalidOperation(
                "export staging holds more rows than the stored stream",
            ))
            .into());
        }
        Ok(totals)
    }

    /// Writes one record per distinct transaction id in `located`, which must
    /// already be sorted by id then position.
    fn emit_row(
        &mut self,
        height: u32,
        located: &[([u8; 32], TxPosition)],
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        let (mut records, mut bytes) = (0_u64, 0_u64);
        let mut index = 0;
        while index < located.len() {
            let txid = located[index].0;
            let run = located[index..]
                .iter()
                .take_while(|(candidate, _)| *candidate == txid)
                .count();
            self.positions.clear();
            self.positions
                .extend(located[index..index + run].iter().map(|(_, position)| *position));
            let added = u64::try_from(run).unwrap_or(u64::MAX);
            if self.positions_written.saturating_add(added)
                > u64::try_from(MAX_RESTORE_POSITIONS).unwrap_or(u64::MAX)
            {
                return Err(IndexBundleError::ExportTooLarge {
                    limit_positions: MAX_RESTORE_POSITIONS,
                });
            }
            self.positions_written += added;
            bytes += write_record(out, &txid, height, &self.positions)
                .map_err(|error| io_error(self.path, error))?;
            records += 1;
            index += run;
        }
        Ok((records, bytes))
    }

    /// Resolves every position of `row` to its full transaction id, refusing
    /// any position that is not a top-level transaction span whose id carries
    /// the row's prefix. Bytes that merely decode to a transaction elsewhere
    /// in the block never resolve a locator.
    fn locate(&mut self, row: HashPrefixRow, value: &[u8]) -> Result<(), IndexBundleError> {
        let height = row.height();
        let corrupt = |reason: &'static str| IndexBundleError::SourceRow { height, reason };
        if height < self.floor || height > self.chain.height {
            return Err(corrupt("row lies outside the covered heights"));
        }
        let positions = TxPositionValue::decode(value)
            .filter(|positions| positions_are_valid(positions))
            .ok_or_else(|| corrupt("row carries no valid position list"))?;
        let hash = self
            .chain
            .hash_at(self.host.block_tree, height)
            .ok_or_else(|| corrupt("no active-chain block at the row height"))?;
        self.located.clear();
        for &position in positions {
            let tx = match self.reader.transaction(height, hash, position)? {
                Located::Found(tx) => tx,
                Located::BodyMissing => return Err(IndexBundleError::BodyUnavailable { height }),
                Located::Mismatch => {
                    return Err(corrupt("position is not a top-level transaction span"));
                }
            };
            let txid = tx.txid().0.to_le_bytes();
            if txid[..8] != row.prefix {
                return Err(corrupt("transaction id does not match the row prefix"));
            }
            self.located.push((txid, position));
        }
        self.located.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test fixtures prove their own bounds")]
mod tests {
    use super::*;
    use crate::types::ScriptHash;
    use crate::{ScriptLiveScan, TxIndexPage, TxIndexScan, TxIndexScanRow};
    use bitcoin_rs_primitives::{OutPoint, Txid};
    use std::cell::Cell;
    use std::error::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestResult = Result<(), Box<dyn Error>>;

    thread_local! {
        static SYNC_CALLS: Cell<u32> = const { Cell::new(0) };
    }

    fn calls() -> u32 {
        SYNC_CALLS.with(Cell::get)
    }

    fn injected(dir: &Path) -> IndexBundleError {
        io_error(dir, io::Error::other("injected directory fsync failure"))
    }

    /// Fails only the first directory fsync: the publication's final commit.
    fn fail_first_sync(dir: &Path) -> Result<(), IndexBundleError> {
        let call = calls();
        SYNC_CALLS.with(|count| count.set(call + 1));
        if call == 0 {
            Err(injected(dir))
        } else {
            sync_dir(dir)
        }
    }

    fn fail_every_sync(dir: &Path) -> Result<(), IndexBundleError> {
        SYNC_CALLS.with(|count| count.set(count.get() + 1));
        Err(injected(dir))
    }

    /// Creates the artifact and manifest the way `export` does.
    fn stage(
        publication: &mut Publication,
        dir: &Path,
    ) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
        let artifact = dir.join(BundleFamily::TxLookup.file_name());
        let mut file = publication.create_new(&artifact)?;
        file.write_all(b"artifact")?;
        file.sync_all()?;
        drop(file);
        let manifest = dir.join(MANIFEST_FILE);
        write_manifest(publication, &manifest, b"{}")?;
        Ok((artifact, manifest))
    }

    #[test]
    fn failed_final_directory_sync_removes_the_manifest_and_its_artifact() -> TestResult {
        let dir = tempfile::tempdir()?;
        let operator = dir.path().join("operator.dat");
        fs::write(&operator, b"keep")?;
        SYNC_CALLS.with(|count| count.set(0));
        let mut publication = Publication::with_sync(dir.path(), fail_first_sync);
        let (artifact, manifest) = stage(&mut publication, dir.path())?;
        assert!(matches!(
            publication.commit(),
            Err(IndexBundleError::Io { .. })
        ));
        assert!(
            !manifest.exists(),
            "a manifest must not survive a failed commit"
        );
        assert!(
            !artifact.exists(),
            "the artifact is removed after the manifest"
        );
        assert_eq!(calls(), 3, "commit, then one fsync per durable removal");
        assert_eq!(fs::read(&operator)?, b"keep");
        Ok(())
    }

    #[test]
    fn undurable_manifest_removal_keeps_the_artifact_it_names() -> TestResult {
        let dir = tempfile::tempdir()?;
        SYNC_CALLS.with(|count| count.set(0));
        let mut publication = Publication::with_sync(dir.path(), fail_every_sync);
        let (artifact, manifest) = stage(&mut publication, dir.path())?;
        assert!(publication.commit().is_err());
        assert!(!manifest.exists());
        assert!(
            artifact.exists(),
            "an artifact is never removed before its manifest's removal is durable"
        );
        assert_eq!(calls(), 2, "the failed fsync is not retried");
        Ok(())
    }

    /// Small page size over a multi-page family: pages concatenate in
    /// stored-key order with no overlap, gap, or repeat.
    #[test]
    fn paged_stream_preserves_row_order_across_small_pages() {
        let fake = PagedFake::new(25);
        let expected: Vec<[u8; 12]> = fake.rows.iter().map(|(row, _)| row.to_db_row()).collect();
        assert!(
            expected.windows(2).all(|pair| pair[0] < pair[1]),
            "fixture keys strictly increase"
        );
        let limit = PrefixScanLimit {
            max_rows: 7,
            max_bytes: usize::MAX,
        };
        let mut seen = Vec::new();
        let (records, bytes) = stream_family_pages(&fake, limit, &|| false, &mut |row, value| {
            seen.push(row.to_db_row());
            let bytes = u64::try_from(value.len()).expect("test row value fits u64");
            Ok((1, bytes))
        })
        .expect("paged stream completes");
        assert_eq!(seen, expected, "pages concatenate in stored-key order");
        assert_eq!(records, 25);
        assert_eq!(bytes, 25);
        assert!(
            fake.pages.load(Ordering::SeqCst) > 1,
            "the small page size forced multiple pages"
        );
    }

    /// Cancellation trips mid-stream: the poll fires every
    /// `CANCEL_POLL_RECORDS` visited rows even across page boundaries.
    #[test]
    fn paged_stream_stops_at_cancellation() {
        let fake = PagedFake::new(5_000);
        let emitted = Cell::new(0_usize);
        let stop = Cell::new(false);
        let result = stream_family_pages(
            &fake,
            PrefixScanLimit {
                max_rows: 7,
                max_bytes: usize::MAX,
            },
            &|| stop.get(),
            &mut |_, _| {
                emitted.set(emitted.get() + 1);
                if emitted.get() == 100 {
                    stop.set(true);
                }
                Ok((1, 0))
            },
        );
        assert!(
            matches!(result, Err(IndexBundleError::Cancelled)),
            "cancellation aborts the page loop"
        );
        assert!(
            fake.pages.load(Ordering::SeqCst) > 1,
            "cancellation fired after several small pages"
        );
    }

    /// A cancelled sort aborts instead of running to completion: without
    /// the run-generation, merge, and copy polls this large file would sort
    /// fully and return `Ok`, blocking shutdown.
    #[test]
    fn external_sort_aborts_when_cancelled() -> TestResult {
        let mut file = tempfile::tempfile()?;
        let records = 10_000_u64;
        for i in 0..records {
            let key = (records - i).to_be_bytes();
            write_framed(&mut file, &key, b"payload")?;
        }
        file.seek(SeekFrom::Start(0))?;
        let path = Path::new("cancel-sort");
        let polls = AtomicUsize::new(0);
        let cancelled = || polls.fetch_add(1, Ordering::SeqCst) >= 3;
        let result = external_sort(&mut file, 8, path, &cancelled);
        assert!(
            matches!(result, Err(IndexBundleError::Cancelled)),
            "a cancelled sort must abort instead of running to completion"
        );
        Ok(())
    }

    /// Enumeration charges positions before staging: over-limit totals fail
    /// with `ExportTooLarge` before any write or sort, while corrupt values
    /// fail with `SourceRow` exactly as the later resolve check would.
    #[test]
    fn enumeration_charges_positions_before_staging() -> TestResult {
        let valid = TxPositionValue::encode(&[TxPosition::new(0, 1), TxPosition::new(1, 1)]);
        let ceiling = u64::try_from(MAX_RESTORE_POSITIONS).unwrap_or(u64::MAX);
        let almost_full = ceiling.saturating_sub(1);
        assert!(
            matches!(
                RowExporter::charge_row(&valid, 7, almost_full),
                Err(IndexBundleError::ExportTooLarge { .. })
            ),
            "over-limit positions must fail before staging"
        );
        let charged = RowExporter::charge_row(&valid, 7, 0)?;
        assert_eq!(charged, 2, "valid positions charge their exact count");
        assert!(
            matches!(
                RowExporter::charge_row(&[], 7, 0),
                Err(IndexBundleError::SourceRow { .. })
            ),
            "empty values must fail validation before staging"
        );
        let zero_len = TxPositionValue::encode(&[TxPosition::new(0, 0)]);
        assert!(
            matches!(
                RowExporter::charge_row(&zero_len, 7, 0),
                Err(IndexBundleError::SourceRow { .. })
            ),
            "zero-length positions must fail validation before staging"
        );
        Ok(())
    }

    /// An empty family completes with no rows and no error.
    #[test]
    fn paged_stream_accepts_an_empty_family() {
        let fake = PagedFake::new(0);
        let (records, bytes) = stream_family_pages(
            &fake,
            PrefixScanLimit {
                max_rows: 7,
                max_bytes: usize::MAX,
            },
            &|| false,
            &mut |_, _| Ok((1, 0)),
        )
        .expect("an empty family completes");
        assert_eq!((records, bytes), (0, 0));
        assert_eq!(fake.pages.load(Ordering::SeqCst), 1);
    }

    /// A page that returns no rows without completing can make no
    /// progress: the loop refuses instead of spinning.
    #[test]
    fn paged_stream_refuses_a_page_that_makes_no_progress() {
        let fake = PagedFake {
            rows: Vec::new(),
            pages: AtomicUsize::new(0),
            stuck: true,
        };
        let result = stream_family_pages(
            &fake,
            PrefixScanLimit {
                max_rows: 7,
                max_bytes: usize::MAX,
            },
            &|| false,
            &mut |_, _| Ok((1, 0)),
        );
        assert!(
            matches!(result, Err(IndexBundleError::Index(_))),
            "an empty incomplete page is a seam error, not a spin"
        );
    }

    /// In-memory `TxIndexSnapshot` that honors a page limit exactly like the
    /// storage seam: key order, first row always returned, byte accounting
    /// after it. Row lookups are never served: the page loop under test
    /// never calls them, and calling one is an explicit typed error rather
    /// than a panic.
    struct PagedFake {
        rows: Vec<(HashPrefixRow, Vec<u8>)>,
        pages: AtomicUsize,
        stuck: bool,
    }

    impl PagedFake {
        fn new(count: usize) -> Self {
            let mut rows = Vec::with_capacity(count);
            for index in 0..count {
                let prefix = u64::try_from(index)
                    .expect("test row count fits u64")
                    .to_be_bytes();
                let height = u32::try_from(index % 3).expect("test height residue fits u32");
                rows.push((HashPrefixRow::new(prefix, height), vec![0xA5]));
            }
            Self {
                rows,
                pages: AtomicUsize::new(0),
                stuck: false,
            }
        }

        fn lookup_error() -> IndexError {
            IndexError::from(StorageError::InvalidOperation(
                "the paged export test never calls row lookups",
            ))
        }
    }

    impl TxIndexSnapshot for PagedFake {
        fn capability_watermark(
            &self,
            _capability: IndexCapability,
        ) -> Result<Option<IndexWatermark>, IndexError> {
            Ok(None)
        }

        fn scan_family_page(
            &self,
            _family: TxIndexFamily,
            start_after: Option<&[u8]>,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexPage, IndexError> {
            self.pages.fetch_add(1, Ordering::SeqCst);
            if self.stuck {
                return Ok(TxIndexPage {
                    rows: Vec::new(),
                    complete: false,
                });
            }
            let mut rows = Vec::new();
            let mut bytes = 0_usize;
            for (row, value) in &self.rows {
                let key = row.to_db_row();
                if start_after.is_some_and(|cursor| key.as_slice() <= cursor) {
                    continue;
                }
                let row_bytes = key.len() + value.len();
                if rows.len() >= limit.max_rows
                    || (!rows.is_empty() && bytes.saturating_add(row_bytes) > limit.max_bytes)
                {
                    return Ok(TxIndexPage {
                        rows,
                        complete: false,
                    });
                }
                bytes = bytes.saturating_add(row_bytes);
                rows.push(TxIndexScanRow {
                    row: *row,
                    value: value.clone(),
                });
            }
            Ok(TxIndexPage {
                rows,
                complete: true,
            })
        }

        fn transaction_rows(
            &self,
            _txid: &Txid,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Err(Self::lookup_error())
        }

        fn funding_rows(
            &self,
            _scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Err(Self::lookup_error())
        }

        fn spending_rows(
            &self,
            _outpoint: &OutPoint,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Err(Self::lookup_error())
        }

        fn live_rows(
            &self,
            _scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<ScriptLiveScan, IndexError> {
            Err(Self::lookup_error())
        }
    }

    #[test]
    fn committed_publication_keeps_both_files_and_never_replaces_an_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut publication = Publication::new(dir.path());
        let (artifact, manifest) = stage(&mut publication, dir.path())?;
        publication.commit()?;
        assert_eq!(fs::read(&artifact)?, b"artifact");
        assert_eq!(fs::read(&manifest)?, b"{}");

        let mut again = Publication::new(dir.path());
        let refused = again.create_new(&manifest);
        assert!(
            matches!(&refused, Err(IndexBundleError::ExistingBundle(path)) if *path == manifest),
            "create-new must refuse an existing manifest"
        );
        drop(refused);
        drop(again);
        assert_eq!(
            fs::read(&manifest)?,
            b"{}",
            "a refused create leaves the existing entry untouched"
        );
        assert_eq!(fs::read(&artifact)?, b"artifact");
        Ok(())
    }
}
