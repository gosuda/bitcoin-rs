use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, HEADER_LEN, IO_BUFFER_BYTES, ScriptFamily,
    check_script_entries, hash_file, record_height, write_script_record,
};
use super::export::create_new_file;
use super::manifest::BundleFamily;
use super::{IndexBundleError, io_error};
use crate::segment::{RecordPage, SegmentSnapshot};
use crate::{IndexCapability, IndexError, IndexWatermark, IndexWriter, TxIndexSnapshot};
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_storage::{KvStore, PrefixScanLimit, StorageError};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

const PAGE_LIMIT: PrefixScanLimit = PrefixScanLimit {
    max_rows: 1_024,
    max_bytes: 1 << 20,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptHistoryArtifact {
    pub base: IndexWatermark,
    pub floor: u32,
    pub records: u64,
    pub sha256: [u8; 32],
    pub bytes: u64,
}

#[derive(Default)]
pub(crate) struct Totals {
    pub(crate) records: u64,
    pub(crate) payload_bytes: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Cut<'a> {
    pub(crate) base: IndexWatermark,
    pub(crate) floor: u32,
    pub(crate) path: &'a Path,
}

pub fn write_script_history_artifact<S: KvStore>(
    writer: &IndexWriter<S>,
    network: Network,
    path: &Path,
) -> Result<ScriptHistoryArtifact, IndexBundleError> {
    let snapshot = writer.segment_snapshot()?;
    let base = snapshot
        .capability_watermark(IndexCapability::ScriptHistory)?
        .ok_or(IndexBundleError::NotReady(
            "the script history index has no watermark",
        ))?;
    let floor = snapshot.capability_floor(IndexCapability::ScriptHistory)?;
    let file = create_new_file(path)?;
    let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
    out.write_all(&[0_u8; HEADER_LEN])
        .map_err(|error| io_error(path, error))?;
    let totals = write_records(&snapshot, Cut { base, floor, path }, &mut out)?;
    let mut file = out
        .into_inner()
        .map_err(|error| io_error(path, error.into_error()))?;
    let header = ArtifactHeader {
        family: BundleFamily::ScriptHistory,
        artifact_version: ARTIFACT_VERSION,
        index_format: crate::index_format_version(),
        network_magic: network.magic(),
        base_height: base.height,
        base_hash: base.hash,
        records: totals.records,
        payload_bytes: totals.payload_bytes,
    };
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error(path, error))?;
    file.write_all(&header.encode())
        .map_err(|error| io_error(path, error))?;
    file.sync_all().map_err(|error| io_error(path, error))?;
    drop(file);
    let (sha256, bytes) = hash_file(path).map_err(|error| io_error(path, error))?;
    Ok(ScriptHistoryArtifact {
        base,
        floor,
        records: totals.records,
        sha256,
        bytes,
    })
}

// PRJ-07
pub(crate) fn write_records(
    snapshot: &SegmentSnapshot<'_>,
    cut: Cut<'_>,
    out: &mut impl Write,
) -> Result<Totals, IndexBundleError> {
    let mut totals = Totals::default();
    stream_family(cut, ScriptFamily::Funding, out, &mut totals, |after| {
        snapshot.funding_record_page(after, PAGE_LIMIT)
    })?;
    stream_family(cut, ScriptFamily::Spending, out, &mut totals, |after| {
        snapshot.spending_record_page(after, PAGE_LIMIT)
    })?;
    Ok(totals)
}

fn stream_family(
    cut: Cut<'_>,
    family: ScriptFamily,
    out: &mut impl Write,
    totals: &mut Totals,
    mut page: impl FnMut(Option<&[u8]>) -> Result<RecordPage, IndexError>,
) -> Result<(), IndexBundleError> {
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let current = page(cursor.as_deref())?;
        let Some(last) = write_page(cut, family, out, totals, current.rows)? else {
            if current.complete {
                return Ok(());
            }
            return Err(empty_page());
        };
        if current.complete {
            return Ok(());
        }
        cursor = Some(last);
    }
}

fn write_page(
    cut: Cut<'_>,
    family: ScriptFamily,
    out: &mut impl Write,
    totals: &mut Totals,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Option<Vec<u8>>, IndexBundleError> {
    let mut last = None;
    for (key, value) in rows {
        check_script_entries(family, &key, &value, cut.base.height, cut.floor).map_err(
            |reason| IndexBundleError::SourceRow {
                height: record_height(family, &key).unwrap_or(0),
                reason,
            },
        )?;
        let written = write_script_record(out, family, &key, &value)
            .map_err(|error| io_error(cut.path, error))?;
        totals.records += 1;
        totals.payload_bytes += written;
        last = Some(key);
    }
    Ok(last)
}

fn empty_page() -> IndexBundleError {
    IndexBundleError::Index(IndexError::from(StorageError::InvalidOperation(
        "script history page ended without rows before the family did",
    )))
}

#[cfg(test)]
mod tests;
