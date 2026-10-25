//! Export: stream the `TxLookup` family of one coherent snapshot into a
//! hashed artifact, then publish the manifest last.
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
    positions_are_valid, write_record,
};
use super::chain::{BodyReader, ChainBase, Located};
use super::manifest::{
    BundleFamily, BundleIdentity, IndexBundleManifestV1, IndexMode, MANIFEST_FILE, TxLookupArtifact,
};
use super::{BundleHost, ExportReport, IndexBundleError, IndexBundleRequest, io_error, sync_dir};
use crate::types::{HashPrefixRow, TxPosition, TxPositionValue};
use crate::{IndexCapability, IndexWatermark, IndexWatermarks, TxIndexFamily, TxIndexSnapshot};
use bitcoin_rs_chain::BlockBodySource;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

/// Removes a created file on every exit path until disarmed, so no
/// partial artifact outlives a failed, stale, or cancelled export.
struct CreatedFile {
    path: PathBuf,
    armed: bool,
}

impl CreatedFile {
    fn create_new(path: &Path) -> Result<(Self, File), IndexBundleError> {
        let file = create_new_file(path)?;
        Ok((
            Self {
                path: path.to_path_buf(),
                armed: true,
            },
            file,
        ))
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CreatedFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
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
    let (mut created, file) = CreatedFile::create_new(&artifact_path)?;
    let identity = captured.identity(request);
    let artifact = captured.write_artifact(host, file, &artifact_path, &identity)?;

    // Abort stale output: the writer must still show exactly the captured
    // watermarks, or the stream may describe rows the index no longer holds.
    let (_, after) = host.writer.fenced_watermarks()?;
    if after != captured.watermarks {
        return Err(IndexBundleError::Stale);
    }

    sync_dir(dir)?;
    let mode = if host.enabled.contains(IndexCapability::ScriptHistory) {
        IndexMode::Full
    } else {
        IndexMode::Utxo
    };
    let manifest = IndexBundleManifestV1::for_tx_lookup(&identity, mode, captured.floor, &artifact);
    publish_manifest(dir, &manifest_path, &manifest.to_json()?)?;
    created.disarm();
    Ok(ExportReport {
        base: IndexWatermark {
            height: captured.chain.height,
            hash: captured.chain.hash,
        },
        records: artifact.records,
        bytes: artifact.bytes,
    })
}

/// Publishes `manifest.json` with create-new, fsync, and directory fsync.
fn publish_manifest(dir: &Path, path: &Path, json: &[u8]) -> Result<(), IndexBundleError> {
    let mut file = create_new_file(path)?;
    let result = file
        .write_all(json)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    sync_dir(dir)
}

/// Everything an export fixes at its start: the exact watermarks, the chain
/// identity of the applied tip, and one snapshot taken at that watermark.
struct Captured<'a> {
    watermarks: IndexWatermarks,
    chain: ChainBase,
    snapshot: Box<dyn TxIndexSnapshot + 'a>,
    floor: u32,
    bodies: &'a dyn BlockBodySource,
}

impl<'a> Captured<'a> {
    /// Requires the `TxLookup` watermark to be exactly the applied tip and the
    /// snapshot to agree with it; otherwise nothing is written.
    fn take(host: &BundleHost<'a>) -> Result<Self, IndexBundleError> {
        let (_, watermarks) = host.writer.fenced_watermarks()?;
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
        let chain = ChainBase::capture(host.block_tree, &tip, tip.height)?;
        if !chain.validated {
            return Err(IndexBundleError::NotReady(
                "the base block is not on the active chain",
            ));
        }
        let bodies = host
            .body_source
            .ok_or(IndexBundleError::NotReady("there is no block body source"))?;
        let snapshot = host.reader.snapshot()?;
        if snapshot.capability_watermark(IndexCapability::TxLookup)? != Some(base) {
            return Err(IndexBundleError::Stale);
        }
        let floor = snapshot.capability_floor(IndexCapability::TxLookup)?;
        Ok(Self {
            watermarks,
            chain,
            snapshot,
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
            chain_tx_count: self.chain.chain_tx_count,
        }
    }

    /// Streams the records, patches the final header over the placeholder,
    /// fsyncs, and returns the artifact's exact identity.
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
            path,
        };
        let (records, payload_bytes) = rows.stream(self.snapshot.as_ref(), &mut out)?;
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
    path: &'a Path,
}

impl RowExporter<'_> {
    /// Visits every row of `snapshot` once and returns
    /// `(records, payload bytes)`. Cancellation is polled every
    /// [`CANCEL_POLL_RECORDS`] rows.
    fn stream(
        &mut self,
        snapshot: &dyn TxIndexSnapshot,
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        let mut visited = 0_u64;
        let mut totals = (0_u64, 0_u64);
        let mut failure: Option<IndexBundleError> = None;
        snapshot.for_each_row(TxIndexFamily::TxConfirmed, &mut |row, value| {
            visited += 1;
            if visited.is_multiple_of(CANCEL_POLL_RECORDS) && (self.host.cancelled)() {
                failure = Some(IndexBundleError::Cancelled);
                return Ok(ControlFlow::Break(()));
            }
            match self.export_row(row, value, out) {
                Ok((records, bytes)) => {
                    totals.0 += records;
                    totals.1 += bytes;
                    Ok(ControlFlow::Continue(()))
                }
                Err(error) => {
                    failure = Some(error);
                    Ok(ControlFlow::Break(()))
                }
            }
        })?;
        match failure {
            Some(error) => Err(error),
            None => Ok(totals),
        }
    }

    /// Writes one record per distinct transaction id filed under `row`.
    fn export_row(
        &mut self,
        row: HashPrefixRow,
        value: &[u8],
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        self.locate(row, value)?;
        let height = row.height();
        let (mut records, mut bytes) = (0_u64, 0_u64);
        let mut index = 0;
        while index < self.located.len() {
            let txid = self.located[index].0;
            let run = self.located[index..]
                .iter()
                .take_while(|(candidate, _)| *candidate == txid)
                .count();
            self.positions.clear();
            self.positions.extend(
                self.located[index..index + run]
                    .iter()
                    .map(|(_, position)| *position),
            );
            bytes += write_record(out, &txid, height, &self.positions)
                .map_err(|error| io_error(self.path, error))?;
            records += 1;
            index += run;
        }
        Ok((records, bytes))
    }

    /// Resolves every position of `row` to its full transaction id, refusing
    /// any position that does not decode to a transaction whose id carries the
    /// row's prefix.
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
                    return Err(corrupt("position does not decode to a transaction"));
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
