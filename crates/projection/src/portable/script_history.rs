use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, HEADER_LEN, IO_BUFFER_BYTES, SCRIPT_KEY_LEN, ScriptFamily,
    check_script_entries, hash_file, record_height, write_script_record,
};
use super::export::create_new_file;
use super::manifest::BundleFamily;
use super::{IndexBundleError, io_error};
use crate::{
    IndexCapability, IndexError, IndexReader, IndexWatermark, ScriptHistoryFamily, TxIndexSnapshot,
};
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_storage::{PrefixScanLimit, StorageError};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

const PAGE_LIMIT: PrefixScanLimit = PrefixScanLimit {
    max_rows: 1_024,
    max_bytes: 1 << 20,
};

const FAMILIES: [(ScriptHistoryFamily, ScriptFamily); 2] = [
    (ScriptHistoryFamily::Funding, ScriptFamily::Funding),
    (ScriptHistoryFamily::Spending, ScriptFamily::Spending),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptHistoryArtifact {
    pub base: IndexWatermark,
    pub floor: u32,
    pub records: u64,
    pub sha256: [u8; 32],
    pub bytes: u64,
}

#[derive(Default)]
struct Totals {
    records: u64,
    payload_bytes: u64,
}

struct Cut<'a> {
    snapshot: &'a dyn TxIndexSnapshot,
    base: IndexWatermark,
    floor: u32,
    path: &'a Path,
}

pub fn write_script_history_artifact(
    reader: &dyn IndexReader,
    network: Network,
    path: &Path,
) -> Result<ScriptHistoryArtifact, IndexBundleError> {
    let snapshot = reader.snapshot()?;
    let base = snapshot
        .capability_watermark(IndexCapability::ScriptHistory)?
        .ok_or(IndexBundleError::NotReady(
            "the script history index has no watermark",
        ))?;
    let floor = snapshot.capability_floor(IndexCapability::ScriptHistory)?;
    let cut = Cut {
        snapshot: snapshot.as_ref(),
        base,
        floor,
        path,
    };
    let file = create_new_file(path)?;
    let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
    out.write_all(&[0_u8; HEADER_LEN])
        .map_err(|error| io_error(path, error))?;
    let mut totals = Totals::default();
    for (family, kind) in FAMILIES {
        stream_family(&cut, family, kind, &mut out, &mut totals)?;
    }
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

fn stream_family(
    cut: &Cut<'_>,
    family: ScriptHistoryFamily,
    kind: ScriptFamily,
    out: &mut impl Write,
    totals: &mut Totals,
) -> Result<(), IndexBundleError> {
    let mut start_after: Option<Vec<u8>> = None;
    loop {
        let page =
            cut.snapshot
                .scan_script_history_page(family, start_after.as_deref(), PAGE_LIMIT)?;
        let mut last: Option<[u8; SCRIPT_KEY_LEN]> = None;
        for row in page.rows {
            let key = row.row.to_db_row();
            check_script_entries(kind, &key, &row.value, cut.base.height, cut.floor).map_err(
                |reason| IndexBundleError::SourceRow {
                    height: record_height(kind, &key),
                    reason,
                },
            )?;
            let written = write_script_record(out, kind, &key, &row.value)
                .map_err(|error| io_error(cut.path, error))?;
            totals.records += 1;
            totals.payload_bytes += written;
            last = Some(key);
        }
        if page.complete {
            return Ok(());
        }
        let Some(last) = last else {
            return Err(IndexBundleError::Index(IndexError::from(
                StorageError::InvalidOperation(
                    "script history page scan returned an empty incomplete page",
                ),
            )));
        };
        start_after = Some(last.to_vec());
    }
}
