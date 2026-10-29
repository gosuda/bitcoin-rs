//! Export: stream the `TxLookup` family of one coherent snapshot into a
//! hashed artifact, then publish the manifest last.

use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, CANCEL_POLL_RECORDS, HEADER_LEN, IO_BUFFER_BYTES, hash_file,
    write_record,
};
use super::chain::{BodyReader, ChainBase, Located};
use super::manifest::{
    BundleFamily, BundleIdentity, IndexBundleManifestV1, IndexMode, MANIFEST_FILE, TxLookupArtifact,
};
use super::{
    BundleHost, ExportReport, IndexBundleError, IndexBundleRequest, MAX_RESTORE_POSITIONS,
    io_error, sync_dir,
};
#[cfg(test)]
use crate::TxIndexSnapshot;
use crate::types::{
    HASH_PREFIX_ROW_SIZE, HashPrefixRow, TxPosition, TxPositionValue, positions_are_valid,
};
use crate::{IndexCapability, IndexError, IndexWatermark, IndexWriteFence, TxIndexFamily};
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_storage::{PrefixScanLimit, StorageError};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zerocopy::IntoBytes;

const EXPORT_PAGE_ROWS: usize = 1_024;
const EXPORT_PAGE_BYTES: usize = 1 << 20;

fn export_page_limit() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: EXPORT_PAGE_ROWS,
        max_bytes: EXPORT_PAGE_BYTES,
    }
}

/// Streams every `TxConfirmed` row of one snapshot in stored-key order
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
            return Err(IndexError::from(StorageError::InvalidOperation(
                "export page scan returned an empty incomplete page",
            ))
            .into());
        };
        let mut next = last;
        next.push(0);
        start_after = Some(next);
    }
}

type SyncDir = fn(&Path) -> Result<(), IndexBundleError>;

struct Publication {
    dir: PathBuf,
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

    /// takes ownership of its removal.
    fn create_new(&mut self, path: &Path) -> Result<File, IndexBundleError> {
        let file = create_new_file(path)?;
        self.created.push(path.to_path_buf());
        Ok(file)
    }

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

    let (after, _) = host.writer.fenced_watermarks()?;
    if after != captured.fence {
        return Err(IndexBundleError::Stale);
    }

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

struct Captured<'a> {
    fence: IndexWriteFence,
    chain: ChainBase,
    chain_tx_count: u64,
    base: IndexWatermark,
    floor: u32,
    bodies: &'a dyn BlockBodySource,
}

impl<'a> Captured<'a> {
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

struct RowExporter<'a> {
    host: &'a BundleHost<'a>,
    chain: &'a ChainBase,
    floor: u32,
    reader: BodyReader<'a>,
    located: Vec<([u8; 32], TxPosition)>,
    positions: Vec<TxPosition>,
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
const SORT_RUN_BYTES: usize = 4 << 20;
const SORT_MERGE_FAN_IN: usize = 32;

/// Writes one framed record: sort key, value length, then value.
fn write_framed(out: &mut impl Write, key: &[u8], payload: &[u8]) -> io::Result<()> {
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload length exceeds u64"))?;
    out.write_all(key)?;
    out.write_all(&payload_len.to_le_bytes())?;
    out.write_all(payload)
}

fn read_framed(reader: &mut impl Read, key_len: usize) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
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
    let mut buf = vec![0_u8; IO_BUFFER_BYTES];
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
    for reader in &mut readers {
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
fn encode_staged(key: &[u8; STAGED_KEY_LEN], value: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(STAGED_KEY_LEN + 8 + value.len());
    payload.extend_from_slice(key);
    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    payload.extend_from_slice(&value_len.to_le_bytes());
    payload.extend_from_slice(value);
    payload
}

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

/// `txid || position` pair per entry, with positions in [`TxPosition`]'s
/// little-endian 6-byte layout.
fn encode_resolved(height: u32, located: &[([u8; 32], TxPosition)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + located.len() * (32 + 6));
    payload.extend_from_slice(&height.to_le_bytes());
    let located_len = u64::try_from(located.len()).unwrap_or(u64::MAX);
    payload.extend_from_slice(&located_len.to_le_bytes());
    for (txid, position) in located {
        payload.extend_from_slice(txid);
        payload.extend_from_slice(position.as_bytes());
    }
    payload
}

type ResolvedPairs = Vec<([u8; 32], TxPosition)>;

fn decode_resolved(payload: &[u8]) -> Option<(u32, ResolvedPairs)> {
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
    fn stream(
        &mut self,
        base: IndexWatermark,
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        let cancelled = self.host.cancelled;
        let (mut staged, rows) = self.enumerate(base, cancelled)?;
        if rows == 0 {
            return Ok((0, 0));
        }
        external_sort(&mut staged, STAGED_SORT_KEY_LEN, self.path, cancelled)?;
        let mut resolved = self.resolve(&mut staged, rows, cancelled)?;
        external_sort(&mut resolved, RESOLVED_SORT_KEY_LEN, self.path, cancelled)?;
        self.emit(&mut resolved, rows, out, cancelled)
    }

    fn charge_row(value: &[u8], height: u32, total: u64) -> Result<u64, IndexBundleError> {
        let positions = TxPositionValue::decode(value)
            .filter(|found| positions_are_valid(found))
            .ok_or(IndexBundleError::SourceRow {
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
                return Err(IndexError::from(StorageError::InvalidOperation(
                    "export page scan returned an empty incomplete page",
                ))
                .into());
            };
            let mut next = last.row.to_db_row().to_vec();
            next.push(0);
            start_after = Some(next);
        }
        staged.seek(SeekFrom::Start(0)).map_err(failed)?;
        Ok((staged, seq))
    }

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
            let sequence_bytes: [u8; 8] = sort_key
                .get(4..12)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    IndexError::from(StorageError::InvalidOperation(
                        "export staging carries a malformed sort key",
                    ))
                })?;
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
            positions =
                positions.saturating_add(u64::try_from(self.located.len()).unwrap_or(u64::MAX));
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

    /// order, returning `(records, payload bytes)`.
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
                let height = decode_resolved(&payload).map_or(u32::MAX, |(height, _)| height);
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
            self.positions.extend(
                located[index..index + run]
                    .iter()
                    .map(|(_, position)| *position),
            );
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
mod tests;
