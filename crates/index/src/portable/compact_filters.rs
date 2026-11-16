use super::artifact::{ARTIFACT_VERSION, ArtifactHeader, HEADER_LEN, IO_BUFFER_BYTES, hash_file};
use super::export::create_new_file;
use super::manifest::BundleFamily;
use super::{IndexBundleError, io_error};
use crate::writer::CompactFilterRow;
use crate::{IndexCapability, IndexReader, IndexWatermark};
use bitcoin_rs_consensus::primitives::{Network, encode::double_sha256};
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(super) const RECORD_FIXED_LEN: usize = 4 + 32 + 32 + 32 + 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactFilterArtifact {
    pub base: IndexWatermark,
    pub records: u64,
    pub sha256: [u8; 32],
    pub bytes: u64,
}

pub fn write_compact_filter_artifact(
    reader: &dyn IndexReader,
    network: Network,
    block_hashes: &[[u8; 32]],
    path: &Path,
) -> Result<CompactFilterArtifact, IndexBundleError> {
    let snapshot = reader.snapshot()?;
    let base = snapshot
        .capability_watermark(IndexCapability::CompactFilters)?
        .ok_or(IndexBundleError::NotReady(
            "the compact filter index has no watermark",
        ))?;
    let expected = usize::try_from(base.height)
        .ok()
        .and_then(|height| height.checked_add(1));
    if expected != Some(block_hashes.len()) || block_hashes.last() != Some(&base.hash) {
        return Err(IndexBundleError::Identity(
            "the block list does not end at the compact filter base".to_owned(),
        ));
    }
    let file = create_new_file(path)?;
    let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
    out.write_all(&[0_u8; HEADER_LEN])
        .map_err(|error| io_error(path, error))?;
    let mut previous = [0_u8; 32];
    let mut payload_bytes = 0_u64;
    for (index, block_hash) in block_hashes.iter().enumerate() {
        let height = u32::try_from(index).map_err(|_| {
            IndexBundleError::Identity("the block list exceeds the height range".to_owned())
        })?;
        let stored =
            snapshot
                .compact_filter(height, block_hash)?
                .ok_or(IndexBundleError::SourceRow {
                    height,
                    reason: "compact filter row missing at the base",
                })?;
        if double_sha256(&stored.filter).to_le_bytes() != stored.hash {
            return Err(IndexBundleError::SourceRow {
                height,
                reason: "filter hash does not match the filter bytes",
            });
        }
        if chain_header(&stored.hash, &previous) != stored.header {
            return Err(IndexBundleError::SourceRow {
                height,
                reason: "filter header chain is broken",
            });
        }
        let row = CompactFilterRow {
            height,
            block_hash: *block_hash,
            filter_hash: stored.hash,
            header: stored.header,
            filter: stored.filter,
        };
        payload_bytes += encode_record(&mut out, &row).map_err(|error| io_error(path, error))?;
        previous = row.header;
    }
    let mut file = out
        .into_inner()
        .map_err(|error| io_error(path, error.into_error()))?;
    let header = ArtifactHeader {
        family: BundleFamily::CompactFilters,
        artifact_version: ARTIFACT_VERSION,
        index_format: crate::index_format_version(),
        network_magic: network.magic(),
        base_height: base.height,
        base_hash: base.hash,
        records: u64::try_from(block_hashes.len()).unwrap_or(u64::MAX),
        payload_bytes,
    };
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error(path, error))?;
    file.write_all(&header.encode())
        .map_err(|error| io_error(path, error))?;
    file.sync_all().map_err(|error| io_error(path, error))?;
    drop(file);
    let (sha256, bytes) = hash_file(path).map_err(|error| io_error(path, error))?;
    Ok(CompactFilterArtifact {
        base,
        records: header.records,
        sha256,
        bytes,
    })
}

pub(super) fn chain_header(filter_hash: &[u8; 32], previous: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 64];
    input[..32].copy_from_slice(filter_hash);
    input[32..].copy_from_slice(previous);
    double_sha256(&input).to_le_bytes()
}

pub(super) fn encode_record(out: &mut impl Write, row: &CompactFilterRow) -> io::Result<u64> {
    let length = u32::try_from(row.filter.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "filter exceeds u32::MAX bytes")
    })?;
    out.write_all(&row.height.to_be_bytes())?;
    out.write_all(&row.block_hash)?;
    out.write_all(&row.filter_hash)?;
    out.write_all(&row.header)?;
    out.write_all(&length.to_le_bytes())?;
    out.write_all(&row.filter)?;
    Ok(u64::try_from(RECORD_FIXED_LEN + row.filter.len()).unwrap_or(u64::MAX))
}

pub(super) struct RecordFields {
    pub(super) height: u32,
    pub(super) block_hash: [u8; 32],
    pub(super) filter_hash: [u8; 32],
    pub(super) header: [u8; 32],
    pub(super) length: u32,
}

pub(super) fn decode_fixed(bytes: &[u8; RECORD_FIXED_LEN]) -> RecordFields {
    let mut height = [0_u8; 4];
    height.copy_from_slice(&bytes[..4]);
    let mut block_hash = [0_u8; 32];
    block_hash.copy_from_slice(&bytes[4..36]);
    let mut filter_hash = [0_u8; 32];
    filter_hash.copy_from_slice(&bytes[36..68]);
    let mut header = [0_u8; 32];
    header.copy_from_slice(&bytes[68..100]);
    let mut length = [0_u8; 4];
    length.copy_from_slice(&bytes[100..104]);
    RecordFields {
        height: u32::from_be_bytes(height),
        block_hash,
        filter_hash,
        header,
        length: u32::from_le_bytes(length),
    }
}

fn read_row(reader: &mut impl Read) -> io::Result<CompactFilterRow> {
    let mut fixed = [0_u8; RECORD_FIXED_LEN];
    reader.read_exact(&mut fixed)?;
    let fields = decode_fixed(&fixed);
    let length = usize::try_from(fields.length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "filter length overflows"))?;
    let mut filter = vec![0_u8; length];
    reader.read_exact(&mut filter)?;
    Ok(CompactFilterRow {
        height: fields.height,
        block_hash: fields.block_hash,
        filter_hash: fields.filter_hash,
        header: fields.header,
        filter,
    })
}

pub(super) fn decode_run_row(
    key: &[u8],
    value: &[u8],
) -> Result<CompactFilterRow, IndexBundleError> {
    const NAME: &str = "compact_filters.artifact";
    let framing = |reason: &'static str| IndexBundleError::ArtifactFraming {
        name: NAME,
        record: 0,
        reason,
    };
    if key.len() != 32 || value.len() < RECORD_FIXED_LEN {
        return Err(framing("spill run row is truncated"));
    }
    let mut block_hash = [0_u8; 32];
    block_hash.copy_from_slice(key);
    let mut fixed = [0_u8; RECORD_FIXED_LEN];
    fixed.copy_from_slice(&value[..RECORD_FIXED_LEN]);
    let fields = decode_fixed(&fixed);
    if block_hash != fields.block_hash {
        return Err(framing(
            "spill run key does not match the record block hash",
        ));
    }
    Ok(CompactFilterRow {
        height: fields.height,
        block_hash,
        filter_hash: fields.filter_hash,
        header: fields.header,
        filter: value[RECORD_FIXED_LEN..].to_vec(),
    })
}

pub(super) struct SpillFile {
    reader: BufReader<File>,
    path: PathBuf,
    rows_left: u64,
}

impl SpillFile {
    pub(super) fn open(path: PathBuf, rows: u64) -> Result<Self, IndexBundleError> {
        let file = File::open(&path).map_err(|error| io_error(&path, error))?;
        Ok(Self {
            reader: BufReader::with_capacity(IO_BUFFER_BYTES, file),
            path,
            rows_left: rows,
        })
    }
}

impl Iterator for SpillFile {
    type Item = Result<CompactFilterRow, IndexBundleError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rows_left == 0 {
            return None;
        }
        self.rows_left -= 1;
        Some(read_row(&mut self.reader).map_err(|error| io_error(&self.path, error)))
    }
}

pub(super) struct Rows<'a, I> {
    source: I,
    failure: &'a RefCell<Option<IndexBundleError>>,
}

impl<'a, I> Rows<'a, I> {
    pub(super) fn new(source: I, failure: &'a RefCell<Option<IndexBundleError>>) -> Self {
        Self { source, failure }
    }
}

impl<I> Iterator for Rows<'_, I>
where
    I: Iterator<Item = Result<CompactFilterRow, IndexBundleError>>,
{
    type Item = CompactFilterRow;

    fn next(&mut self) -> Option<CompactFilterRow> {
        match self.source.next()? {
            Ok(row) => Some(row),
            Err(error) => {
                let mut slot = self.failure.borrow_mut();
                if slot.is_none() {
                    *slot = Some(error);
                }
                None
            }
        }
    }
}
