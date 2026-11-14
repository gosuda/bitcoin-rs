use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, CANCEL_POLL_RECORDS, HEADER_LEN, ReadFault, RecordReader,
    ScriptFamily, ScriptRecordReader, TxLookupRecord, into_digest, open_hashed,
};
use super::artifact::{HashedFile, IO_BUFFER_BYTES};
use super::chain::{BaseCount, BodyReader, ChainBase, Located};
use super::compact_filters::{
    RECORD_FIXED_LEN, Rows, SpillFile, chain_header, decode_fixed, decode_run_row, encode_record,
};
use super::export::create_new_file;
use super::manifest::{
    BundleFamily, IndexBundleManifestV1, MANIFEST_FILE, MAX_MANIFEST_BYTES, ValidatedManifest,
};
use super::{
    BundleHost, BundleOutcome, IndexBundleError, IndexBundleRequest, ManifestArtifactTarget,
    RestoreReport, Withheld, io_error,
};
use crate::segment::format::PostingChunker;
use crate::segment::spill::{
    Merge, RESTORE_SPILL_BUDGET_BYTES, RunFile, SpillBudget, SpillSet, SpillSorter, merge,
};
use crate::types::TxPosition;
use crate::writer::TxIndexWriter;
use crate::writer::{CompactFilterAttachment, CompactFilterRow};
use crate::{IndexCapabilities, IndexCapability, IndexError, IndexWatermark, IndexWatermarks};
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::encode::double_sha256;
use bitcoin_rs_execution::chain::BlockTreeReader;
use bitcoin_rs_execution::chain::TipSnapshot;
use bitcoin_rs_storage::{ColumnFamily, StorageError};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
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
pub fn attach_tx_lookup_artifact(
    writer: &dyn TxIndexWriter,
    target: &ManifestArtifactTarget,
    headers: &[&[u8; crate::types::HEADER_ROW_SIZE]],
    scratch: &Path,
    budget: &SpillBudget,
) -> Result<u64, IndexBundleError> {
    const NAME: &str = "txlookup.artifact";
    let path = &target.artifact_path;
    let fail = |error| io_error(path, error);
    let length = fs::metadata(path).map_err(fail)?.len();
    if length != target.size_bytes {
        return Err(IndexBundleError::ArtifactLength {
            name: NAME,
            expected: target.size_bytes,
            actual: length,
        });
    }
    let mut hashed = open_hashed(path).map_err(fail)?;
    let mut header_bytes = [0_u8; HEADER_LEN];
    let header = match hashed.read_exact(&mut header_bytes) {
        Ok(()) => ArtifactHeader::decode(&header_bytes),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err("file ends inside the header")
        }
        Err(error) => return Err(fail(error)),
    };
    let expectation = ArtifactExpectation {
        family: BundleFamily::TxLookup,
        index_format: target.index_format,
        network_magic: target.network.magic(),
        base_height: target.base_height,
        base_hash: target.base_hash,
        records: None,
        payload_bytes: target
            .size_bytes
            .checked_sub(u64::try_from(HEADER_LEN).unwrap_or(u64::MAX)),
    };
    let header =
        match header.and_then(|header| check_header(&header, &expectation).map(|()| header)) {
            Ok(header) => header,
            Err(reason) => return Err(IndexBundleError::ArtifactHeader { name: NAME, reason }),
        };
    let work = scratch.join(TX_LOOKUP_WORK_DIR);
    match fs::remove_dir_all(&work) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(fail(error)),
    }
    fs::create_dir_all(&work).map_err(fail)?;
    let set = SpillSet::new(budget, work.clone());
    let stream = TxLookupStream {
        floor: target.floor,
        path,
        headers,
        set,
    };
    let outcome = stream
        .decode(&mut hashed, &header, &|| false)
        .and_then(|decoded| {
            drain_remaining_for_hash(&mut hashed, &|| false, path)?;
            if into_digest(hashed) != target.sha256 {
                return Err(IndexBundleError::ArtifactHash { name: NAME });
            }
            let (family, count, ordinal_base) = stream.order(decoded, target.chain_tx_count)?;
            let seal = crate::segment::import::tx_lookup_seal(
                target.floor,
                target.base_height,
                target.base_hash,
                count,
                ordinal_base,
            )
            .map_err(IndexBundleError::Index)?;
            let attachment = crate::writer::TxLookupAttachment {
                headers,
                base: IndexWatermark {
                    height: target.base_height,
                    hash: target.base_hash,
                },
                floor: target.floor,
                scratch,
            };
            writer
                .attach_streamed_tx_lookup(&family, &seal, &attachment)
                .map_err(IndexBundleError::Index)
        });
    let _ = fs::remove_dir_all(&work);
    outcome
}

const TX_LOOKUP_WORK_DIR: &str = "tx-lookup-attach";

struct TxLookupRuns {
    occurrences: Vec<crate::segment::spill::RunFile>,
    count: u64,
}

struct TxLookupStream<'a> {
    floor: u32,
    path: &'a Path,
    headers: &'a [&'a [u8; crate::types::HEADER_ROW_SIZE]],
    set: SpillSet<'a>,
}

impl TxLookupStream<'_> {
    fn decode(
        &self,
        hashed: &mut HashedFile,
        header: &ArtifactHeader,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<TxLookupRuns, IndexBundleError> {
        decode_tx_lookup_artifact(
            hashed,
            header,
            self.floor,
            self.path,
            self.headers,
            &self.set,
            cancelled,
        )
    }

    fn order(
        &self,
        decoded: TxLookupRuns,
        chain_tx_count: u64,
    ) -> Result<(crate::segment::import::StreamedFamily, u64, u32), IndexBundleError> {
        order_tx_lookup_runs(decoded, chain_tx_count, &self.set, self.path)
    }
}
fn decode_tx_lookup_artifact(
    hashed: &mut HashedFile,
    header: &ArtifactHeader,
    floor: u32,
    path: &Path,
    headers: &[&[u8; crate::types::HEADER_ROW_SIZE]],
    set: &SpillSet,
    cancelled: &dyn Fn() -> bool,
) -> Result<TxLookupRuns, IndexBundleError> {
    const NAME: &str = "txlookup.artifact";
    let mut occurrences = set.sorter("tx-lookup-occ");
    let mut count = 0_u64;
    {
        let mut records = RecordReader::new(hashed, header, floor);
        while let Some(record) = records.next_record().map_err(|fault| match fault {
            ReadFault::Io(error) => io_error(path, error),
            ReadFault::Framing { record, reason } => IndexBundleError::ArtifactFraming {
                name: NAME,
                record,
                reason,
            },
        })? {
            count += 1;
            if count.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            let [position] = record.positions else {
                return Err(IndexBundleError::Identity(
                    "a restored tx lookup record must name exactly one position".to_owned(),
                ));
            };
            let header = headers
                .get(usize::try_from(record.height).unwrap_or(usize::MAX))
                .ok_or_else(|| {
                    IndexBundleError::Identity("a restored record height has no header".to_owned())
                })?;
            let mut key = Vec::with_capacity(40);
            key.extend_from_slice(&record.height.to_be_bytes());
            key.extend_from_slice(&position.offset().to_be_bytes());
            key.extend_from_slice(&record.txid);
            let mut value = Vec::with_capacity(36);
            value.extend_from_slice(&double_sha256(&header[..]).to_le_bytes());
            value.extend_from_slice(&position.byte_len().to_be_bytes());
            occurrences
                .push(key, value)
                .map_err(|error| io_error(path, error))?;
        }
    }
    let runs = occurrences
        .finish()
        .map_err(|error| io_error(path, error))?;
    Ok(TxLookupRuns {
        occurrences: runs,
        count,
    })
}

fn order_tx_lookup_runs(
    decoded: TxLookupRuns,
    chain_tx_count: u64,
    set: &SpillSet,
    path: &Path,
) -> Result<(crate::segment::import::StreamedFamily, u64, u32), IndexBundleError> {
    const NAME: &str = "txlookup.artifact";
    let ordinal_base = tx_ordinal_base(
        chain_tx_count,
        usize::try_from(decoded.count).unwrap_or(usize::MAX),
    )?;
    let count32 = u32::try_from(decoded.count).map_err(|_| {
        IndexBundleError::Index(IndexError::Storage(StorageError::IncompatibleData(
            "restored segment exceeds u32 ordinals".to_owned(),
        )))
    })?;
    ordinal_base.checked_add(count32).ok_or_else(|| {
        IndexBundleError::Index(IndexError::Storage(StorageError::IncompatibleData(
            "restored segment exceeds u32 ordinals".to_owned(),
        )))
    })?;
    let mut dir = set.sorter("tx-lookup-dir");
    let mut rows = 0_u64;
    let mut ordinal = ordinal_base;
    let merged = merge(&decoded.occurrences).map_err(|error| io_error(path, error))?;
    for (index, record) in merged.enumerate() {
        let (key, value) = record.map_err(|error| io_error(path, error))?;
        if key.len() != 40 || value.len() != 36 {
            return Err(IndexBundleError::ArtifactFraming {
                name: NAME,
                record: u64::try_from(index).unwrap_or(u64::MAX),
                reason: "spill run row is truncated",
            });
        }
        let mut height = [0_u8; 4];
        height.copy_from_slice(&key[..4]);
        let mut offset = [0_u8; 4];
        offset.copy_from_slice(&key[4..8]);
        let mut txid = [0_u8; 32];
        txid.copy_from_slice(&key[8..40]);
        let mut block_hash = [0_u8; 32];
        block_hash.copy_from_slice(&value[..32]);
        let mut byte_len = [0_u8; 4];
        byte_len.copy_from_slice(&value[32..36]);
        let height = u32::from_be_bytes(height);
        let offset = u32::from_be_bytes(offset);
        let byte_len = u32::from_be_bytes(byte_len);
        let dir_key = crate::segment::format::encode_tx_dir_key(0, &txid, height).to_vec();
        let dir_value =
            crate::segment::format::encode_tx_dir_value(&block_hash, ordinal, offset, byte_len)
                .to_vec();
        dir.push(dir_key, dir_value)
            .map_err(|error| io_error(path, error))?;
        rows += 1;
        let ordinal_key = crate::segment::format::encode_tx_ordinal_key(0, ordinal).to_vec();
        let ordinal_value =
            crate::segment::format::encode_tx_ordinal_value(&txid, height, offset, byte_len)
                .to_vec();
        dir.push(ordinal_key, ordinal_value)
            .map_err(|error| io_error(path, error))?;
        rows += 1;
        ordinal = ordinal.checked_add(1).ok_or_else(|| {
            IndexBundleError::Index(IndexError::Storage(StorageError::IncompatibleData(
                "restored segment exceeds u32 ordinals".to_owned(),
            )))
        })?;
    }
    let runs = dir.finish().map_err(|error| io_error(path, error))?;
    Ok((
        crate::segment::import::StreamedFamily { runs, rows },
        decoded.count,
        ordinal_base,
    ))
}
fn tx_ordinal_base(chain_tx_count: u64, restored: usize) -> Result<u32, IndexBundleError> {
    let restored = u64::try_from(restored).unwrap_or(u64::MAX);
    let base = chain_tx_count.checked_sub(restored).ok_or_else(|| {
        IndexBundleError::Identity(
            "the bundle restores more transactions than its chain count admits".to_owned(),
        )
    })?;
    u32::try_from(base).map_err(|_| {
        IndexBundleError::Identity("the chain-global ordinal base exceeds u32".to_owned())
    })
}

pub fn attach_script_history_artifact(
    writer: &dyn TxIndexWriter,
    target: &ManifestArtifactTarget,
    block_hashes: &[[u8; 32]],
    scratch: &Path,
    budget: &SpillBudget,
) -> Result<u64, IndexBundleError> {
    const NAME: &str = "scripthistory.artifact";
    let path = &target.artifact_path;
    let fail = |error| io_error(path, error);
    let length = fs::metadata(path).map_err(fail)?.len();
    if length != target.size_bytes {
        return Err(IndexBundleError::ArtifactLength {
            name: NAME,
            expected: target.size_bytes,
            actual: length,
        });
    }
    let mut hashed = open_hashed(path).map_err(fail)?;
    let mut header_bytes = [0_u8; HEADER_LEN];
    let header = match hashed.read_exact(&mut header_bytes) {
        Ok(()) => ArtifactHeader::decode(&header_bytes),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err("file ends inside the header")
        }
        Err(error) => return Err(fail(error)),
    };
    let expectation = ArtifactExpectation {
        family: BundleFamily::ScriptHistory,
        index_format: target.index_format,
        network_magic: target.network.magic(),
        base_height: target.base_height,
        base_hash: target.base_hash,
        records: None,
        payload_bytes: target
            .size_bytes
            .checked_sub(u64::try_from(HEADER_LEN).unwrap_or(u64::MAX)),
    };
    let header =
        match header.and_then(|header| check_header(&header, &expectation).map(|()| header)) {
            Ok(header) => header,
            Err(reason) => return Err(IndexBundleError::ArtifactHeader { name: NAME, reason }),
        };
    let work = scratch.join(SCRIPT_HISTORY_WORK_DIR);
    match fs::remove_dir_all(&work) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(fail(error)),
    }
    fs::create_dir_all(&work).map_err(fail)?;
    let set = SpillSet::new(budget, work.clone());
    let stream = ScriptHistoryStream {
        floor: target.floor,
        path,
        set,
        chain_tx_count: target.chain_tx_count,
        block_hashes,
        base: IndexWatermark {
            height: target.base_height,
            hash: target.base_hash,
        },
    };
    let outcome = stream
        .decode(&mut hashed, &header, &|| false)
        .and_then(|decoded| {
            drain_remaining_for_hash(&mut hashed, &|| false, path)?;
            if into_digest(hashed) != target.sha256 {
                return Err(IndexBundleError::ArtifactHash { name: NAME });
            }
            let (families, seal) = stream.order(decoded)?;
            let attachment = crate::writer::ScriptHistoryAttachment {
                base: stream.base,
                floor: stream.floor,
                scratch,
            };
            writer
                .attach_streamed_script_history(&families, &seal, &attachment)
                .map_err(IndexBundleError::Index)
        });
    let _ = fs::remove_dir_all(&work);
    outcome
}

const SCRIPT_HISTORY_WORK_DIR: &str = "script-history-attach";

struct DecodedScriptHistory {
    funding: Vec<crate::segment::spill::RunFile>,
    spending: Vec<crate::segment::spill::RunFile>,
    funding_records: u64,
    spending_records: u64,
}

struct ScriptHistoryStream<'a> {
    floor: u32,
    path: &'a Path,
    set: SpillSet<'a>,
    chain_tx_count: u64,
    block_hashes: &'a [[u8; 32]],
    base: IndexWatermark,
}

fn script_record_error(height: u32, reason: &'static str) -> IndexBundleError {
    IndexBundleError::ScriptHistoryImport(
        crate::segment::import::ScriptHistoryImportError::Record { height, reason },
    )
}

fn script_too_many(transactions: usize, chain_tx_count: u64) -> IndexBundleError {
    IndexBundleError::ScriptHistoryImport(
        crate::segment::import::ScriptHistoryImportError::TooManyTransactions {
            transactions,
            chain_tx_count,
        },
    )
}

impl ScriptHistoryStream<'_> {
    fn decode(
        &self,
        hashed: &mut HashedFile,
        header: &ArtifactHeader,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DecodedScriptHistory, IndexBundleError> {
        const NAME: &str = "scripthistory.artifact";
        let path = self.path;
        let mut funding = self.set.sorter("sh-funded");
        let mut spending = self.set.sorter("sh-spend");
        let mut funding_records = 0_u64;
        let mut spending_records = 0_u64;
        {
            let mut records = ScriptRecordReader::new(hashed, header, self.floor);
            let mut seen = 0_u64;
            while let Some(record) = records.next_record().map_err(|fault| match fault {
                ReadFault::Io(error) => io_error(path, error),
                ReadFault::Framing { record, reason } => IndexBundleError::ArtifactFraming {
                    name: NAME,
                    record,
                    reason,
                },
            })? {
                if seen.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                    return Err(IndexBundleError::Cancelled);
                }
                seen += 1;
                match record.family {
                    ScriptFamily::Funding => {
                        funding_records += 1;
                        let mut height_bytes = [0_u8; 4];
                        height_bytes.copy_from_slice(
                            &record.key
                                [crate::types::HASH_PREFIX_LEN..crate::types::HASH_PREFIX_ROW_SIZE],
                        );
                        let height = crate::types::decode_history_height(height_bytes);
                        let occurrences =
                            crate::types::ScriptHistoryOccurrence::decode_all(&record.value)
                                .ok_or(IndexBundleError::ArtifactFraming {
                                    name: NAME,
                                    record: seen,
                                    reason: "entries are not history occurrences",
                                })?;
                        for occurrence in occurrences {
                            let mut key = [0_u8; 12];
                            key[..4].copy_from_slice(&height.to_be_bytes());
                            key[4..8].copy_from_slice(&occurrence.position.offset().to_be_bytes());
                            key[8..12]
                                .copy_from_slice(&occurrence.position.byte_len().to_be_bytes());
                            let mut value = [0_u8; 65];
                            value[..32].copy_from_slice(&occurrence.scripthash.to_byte_array());
                            value[32..64].copy_from_slice(&occurrence.txid);
                            value[64] = occurrence.flags;
                            funding
                                .push(key.to_vec(), value.to_vec())
                                .map_err(|error| io_error(path, error))?;
                        }
                    }
                    ScriptFamily::Spending => {
                        spending_records += 1;
                        let spend = decode_spend_record(&record.key, &record.value)?;
                        let mut key = [0_u8; 12];
                        key[..4].copy_from_slice(&spend.height.to_be_bytes());
                        key[4..8].copy_from_slice(&spend.offset.to_be_bytes());
                        key[8..12].copy_from_slice(&spend.len.to_be_bytes());
                        let mut value = [0_u8; 36];
                        value[..32].copy_from_slice(&spend.txid);
                        value[32..36].copy_from_slice(&spend.vout.to_be_bytes());
                        spending
                            .push(key.to_vec(), value.to_vec())
                            .map_err(|error| io_error(path, error))?;
                    }
                }
            }
        }
        let funding = funding.finish().map_err(|error| io_error(path, error))?;
        let spending = spending.finish().map_err(|error| io_error(path, error))?;
        Ok(DecodedScriptHistory {
            funding,
            spending,
            funding_records,
            spending_records,
        })
    }
}

struct DecodedSpend {
    txid: [u8; 32],
    vout: u32,
    height: u32,
    offset: u32,
    len: u32,
}

fn decode_spend_record(key: &[u8], value: &[u8]) -> Result<DecodedSpend, IndexBundleError> {
    let mut height_bytes = [0_u8; 4];
    height_bytes.copy_from_slice(&key[key.len() - 4..]);
    let height = u32::from_be_bytes(height_bytes);
    let positions = crate::types::TxPositionValue::decode(value)
        .ok_or_else(|| script_record_error(height, "entries are not positions"))?;
    let [position] = positions else {
        return Err(script_record_error(
            height,
            "a spent outpoint names exactly one spending transaction",
        ));
    };
    let mut txid = [0_u8; 32];
    txid.copy_from_slice(&key[..32]);
    let mut vout_bytes = [0_u8; 4];
    vout_bytes.copy_from_slice(&key[32..36]);
    let vout = u32::from_be_bytes(vout_bytes);
    if vout > crate::types::U24_MAX {
        return Err(script_record_error(
            height,
            "vout exceeds the spend directory range",
        ));
    }
    Ok(DecodedSpend {
        txid,
        vout,
        height,
        offset: position.offset(),
        len: position.byte_len(),
    })
}

type MergeRow = (Vec<u8>, Vec<u8>);

struct MergeCursor<'a> {
    source: Merge,
    path: &'a Path,
    current: Option<MergeRow>,
}

impl<'a> MergeCursor<'a> {
    fn open(runs: &[RunFile], path: &'a Path) -> Result<Self, IndexBundleError> {
        let mut source = merge(runs).map_err(|error| io_error(path, error))?;
        let current = match source.next() {
            None => None,
            Some(Ok(row)) => Some(row),
            Some(Err(error)) => return Err(io_error(path, error)),
        };
        Ok(Self {
            source,
            path,
            current,
        })
    }

    fn key(&self) -> Option<&[u8]> {
        self.current.as_ref().map(|(key, _)| key.as_slice())
    }

    fn take(&mut self) -> Result<Option<MergeRow>, IndexBundleError> {
        let taken = self.current.take();
        self.current = match self.source.next() {
            None => None,
            Some(Ok(row)) => Some(row),
            Some(Err(error)) => return Err(io_error(self.path, error)),
        };
        Ok(taken)
    }
}

fn truncated_run() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "spill run row is truncated",
    )
}

fn split_identity(key: &[u8]) -> Result<(u32, u32, u32), std::io::Error> {
    if key.len() != 12 {
        return Err(truncated_run());
    }
    let mut height = [0_u8; 4];
    height.copy_from_slice(&key[..4]);
    let mut offset = [0_u8; 4];
    offset.copy_from_slice(&key[4..8]);
    let mut len = [0_u8; 4];
    len.copy_from_slice(&key[8..12]);
    Ok((
        u32::from_be_bytes(height),
        u32::from_be_bytes(offset),
        u32::from_be_bytes(len),
    ))
}

fn take_funded_group(
    cursor: &mut MergeCursor<'_>,
    path: &Path,
) -> Result<([u8; 12], [u8; 32]), IndexBundleError> {
    let Some((key, value)) = cursor.take()? else {
        return Err(IndexBundleError::Identity(
            "the funded merge ended inside a group".to_owned(),
        ));
    };
    if key.len() != 12 || value.len() != 65 {
        return Err(io_error(path, truncated_run()));
    }
    let mut identity = [0_u8; 12];
    identity.copy_from_slice(&key);
    let mut txid = [0_u8; 32];
    txid.copy_from_slice(&value[32..64]);
    let mut height_bytes = [0_u8; 4];
    height_bytes.copy_from_slice(&identity[..4]);
    let height = u32::from_be_bytes(height_bytes);
    loop {
        match cursor.key() {
            Some(next) if next == identity => {
                let (_, next_value) = cursor.take()?.ok_or_else(|| {
                    IndexBundleError::Identity("the funded merge ended inside a group".to_owned())
                })?;
                if next_value.len() != 65 {
                    return Err(io_error(path, truncated_run()));
                }
                let mut next_txid = [0_u8; 32];
                next_txid.copy_from_slice(&next_value[32..64]);
                if next_txid != txid {
                    return Err(script_record_error(
                        height,
                        "one position names two transactions",
                    ));
                }
            }
            _ => break,
        }
    }
    Ok((identity, txid))
}
fn take_spend_row(
    cursor: &mut MergeCursor<'_>,
) -> Result<([u8; 12], [u8; 32], u32), IndexBundleError> {
    let Some((key, value)) = cursor.take()? else {
        return Err(IndexBundleError::Identity(
            "the spending merge ended inside a row".to_owned(),
        ));
    };
    if key.len() != 12 || value.len() != 36 {
        return Err(io_error(cursor.path, truncated_run()));
    }
    let mut identity = [0_u8; 12];
    identity.copy_from_slice(&key);
    let mut txid = [0_u8; 32];
    txid.copy_from_slice(&value[..32]);
    let mut vout = [0_u8; 4];
    vout.copy_from_slice(&value[32..36]);
    Ok((identity, txid, u32::from_be_bytes(vout)))
}

fn skip_spend_group(
    cursor: &mut MergeCursor<'_>,
    identity: &[u8; 12],
) -> Result<(), IndexBundleError> {
    while matches!(cursor.key(), Some(key) if key == identity.as_slice()) {
        cursor.take()?;
    }
    Ok(())
}

fn push_spend2_row(
    spend2: &mut SpillSorter,
    path: &Path,
    spent_txid: &[u8; 32],
    spending: u32,
    vout: u32,
) -> Result<(), IndexBundleError> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(spent_txid);
    key.extend_from_slice(&spending.to_be_bytes());
    spend2
        .push(key, vout.to_be_bytes().to_vec())
        .map_err(|error| io_error(path, error))
}
impl ScriptHistoryStream<'_> {
    fn order(
        &self,
        decoded: DecodedScriptHistory,
    ) -> Result<
        (
            Vec<(ColumnFamily, crate::segment::import::StreamedFamily)>,
            crate::segment::import::StreamedSeal,
        ),
        IndexBundleError,
    > {
        let (ord_runs, distinct) = self.enumerate(&decoded)?;
        let (base, next_ordinal) = ordinal_window(self.chain_tx_count, distinct)?;
        let mut emission = ScriptEmission::new(self, base, distinct);
        emission.join_funded(&decoded.funding, &ord_runs)?;
        let (spend2_runs, created_runs) = emission.join_spenders(&decoded.spending, &ord_runs)?;
        let spend_raw_runs = emission.spend_rows(&spend2_runs, &created_runs)?;
        let spend_family = emission.finish_spend_dir(&spend_raw_runs)?;
        let post_in_runs = emission.take_post_in()?;
        let (dict_family, post_family) = emission.posting_families(&post_in_runs)?;
        let dir_family = emission.take_dir()?;
        let families = vec![
            (ColumnFamily::TxDir, dir_family),
            (ColumnFamily::ScriptDict, dict_family),
            (ColumnFamily::ScriptPost, post_family),
            (ColumnFamily::SpendDir, spend_family),
        ];
        let seal = crate::segment::import::StreamedSeal {
            coverage: crate::segment::Coverage::new(self.floor, self.base.height, self.base.hash),
            next_ordinal,
            records: decoded
                .funding_records
                .saturating_add(decoded.spending_records),
        };
        Ok((families, seal))
    }
}

struct ScriptEmission<'a> {
    set: &'a SpillSet<'a>,
    path: &'a Path,
    block_hashes: &'a [[u8; 32]],
    base: u64,
    chain_tx_count: u64,
    distinct: u64,
    dir: Option<SpillSorter<'a>>,
    dir_rows: u64,
    post_in: Option<SpillSorter<'a>>,
    post_in_rows: u64,
    created: Option<SpillSorter<'a>>,
}
impl<'a> ScriptEmission<'a> {
    fn new(stream: &'a ScriptHistoryStream<'_>, base: u64, distinct: u64) -> ScriptEmission<'a> {
        ScriptEmission {
            set: &stream.set,
            path: stream.path,
            block_hashes: stream.block_hashes,
            base,
            chain_tx_count: stream.chain_tx_count,
            distinct,
            dir: Some(stream.set.sorter("sh-txdir")),
            dir_rows: 0,
            post_in: Some(stream.set.sorter("sh-post-in")),
            post_in_rows: 0,
            created: Some(stream.set.sorter("sh-created")),
        }
    }

    fn ordinal(&self, rank: u32) -> Result<u32, IndexBundleError> {
        self.base
            .checked_add(u64::from(rank))
            .and_then(|ordinal| u32::try_from(ordinal).ok())
            .ok_or_else(|| {
                script_too_many(
                    usize::try_from(rank).unwrap_or(usize::MAX),
                    self.chain_tx_count,
                )
            })
    }

    fn block_hash(&self, height: u32) -> Result<[u8; 32], IndexBundleError> {
        self.block_hashes
            .get(usize::try_from(height).unwrap_or(usize::MAX))
            .copied()
            .ok_or(IndexBundleError::ScriptHistoryImport(
                crate::segment::import::ScriptHistoryImportError::MissingHeader { height },
            ))
    }

    fn take_created(&mut self) -> Result<SpillSorter<'a>, IndexBundleError> {
        self.created.take().ok_or_else(|| {
            IndexBundleError::Identity("the created sorter is already staged".to_owned())
        })
    }

    fn take_post_in(&mut self) -> Result<Vec<RunFile>, IndexBundleError> {
        let sorter = self.post_in.take().ok_or_else(|| {
            IndexBundleError::Identity("the posting sorter is already staged".to_owned())
        })?;
        sorter.finish().map_err(|error| io_error(self.path, error))
    }

    fn take_dir(&mut self) -> Result<crate::segment::import::StreamedFamily, IndexBundleError> {
        let sorter = self.dir.take().ok_or_else(|| {
            IndexBundleError::Identity("the directory sorter is already staged".to_owned())
        })?;
        let runs = sorter
            .finish()
            .map_err(|error| io_error(self.path, error))?;
        Ok(crate::segment::import::StreamedFamily {
            runs,
            rows: self.dir_rows,
        })
    }
}

fn ordinal_window(chain_tx_count: u64, distinct: u64) -> Result<(u64, u32), IndexBundleError> {
    let count = usize::try_from(distinct).unwrap_or(usize::MAX);
    let next_ordinal =
        u32::try_from(chain_tx_count).map_err(|_| script_too_many(count, chain_tx_count))?;
    if distinct > chain_tx_count {
        return Err(script_too_many(count, chain_tx_count));
    }
    Ok((chain_tx_count - distinct, next_ordinal))
}

impl ScriptHistoryStream<'_> {
    fn push_ord(
        &self,
        sorter: &mut SpillSorter,
        identity: &[u8; 12],
        rank: u64,
        funded: bool,
    ) -> Result<(), IndexBundleError> {
        let rank32 = u32::try_from(rank).map_err(|_| {
            script_too_many(
                usize::try_from(rank).unwrap_or(usize::MAX),
                self.chain_tx_count,
            )
        })?;
        let mut value = [0_u8; 5];
        value[..4].copy_from_slice(&rank32.to_be_bytes());
        value[4] = u8::from(funded);
        sorter
            .push(identity.to_vec(), value.to_vec())
            .map_err(|error| io_error(self.path, error))
    }

    fn enumerate(
        &self,
        decoded: &DecodedScriptHistory,
    ) -> Result<(Vec<RunFile>, u64), IndexBundleError> {
        let mut ord = self.set.sorter("sh-ord");
        let mut funded = MergeCursor::open(&decoded.funding, self.path)?;
        let mut spending = MergeCursor::open(&decoded.spending, self.path)?;
        let mut distinct = 0_u64;
        loop {
            let order = match (funded.key(), spending.key()) {
                (None, None) => break,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(b),
            };
            match order {
                Ordering::Less => {
                    let (identity, _) = take_funded_group(&mut funded, self.path)?;
                    self.push_ord(&mut ord, &identity, distinct, true)?;
                    distinct += 1;
                }
                Ordering::Greater => {
                    let (identity, _, _) = take_spend_row(&mut spending)?;
                    skip_spend_group(&mut spending, &identity)?;
                    self.push_ord(&mut ord, &identity, distinct, false)?;
                    distinct += 1;
                }
                Ordering::Equal => {
                    let (identity, _) = take_funded_group(&mut funded, self.path)?;
                    take_spend_row(&mut spending)?;
                    skip_spend_group(&mut spending, &identity)?;
                    self.push_ord(&mut ord, &identity, distinct, true)?;
                    distinct += 1;
                }
            }
        }
        let runs = ord.finish().map_err(|error| io_error(self.path, error))?;
        Ok((runs, distinct))
    }
}

fn split_ord(value: &[u8], path: &Path) -> Result<(u32, bool), IndexBundleError> {
    if value.len() != 5 {
        return Err(io_error(path, truncated_run()));
    }
    let mut rank = [0_u8; 4];
    rank.copy_from_slice(&value[..4]);
    Ok((u32::from_be_bytes(rank), value[4] != 0))
}

fn ord_at(
    cursor: &mut MergeCursor<'_>,
    current: &mut Option<(Vec<u8>, Vec<u8>)>,
    key: &[u8],
    path: &Path,
) -> Result<(u32, bool), IndexBundleError> {
    loop {
        match current.take() {
            Some((okey, oval)) => match okey.as_slice().cmp(key) {
                Ordering::Less => {
                    *current = cursor.take()?;
                }
                Ordering::Equal => {
                    let out = split_ord(&oval, path)?;
                    *current = Some((okey, oval));
                    return Ok(out);
                }
                Ordering::Greater => {
                    return Err(IndexBundleError::Identity(
                        "the ordinal map skips an identity".to_owned(),
                    ));
                }
            },
            None => {
                return Err(IndexBundleError::Identity(
                    "the ordinal map skips an identity".to_owned(),
                ));
            }
        }
    }
}

fn split_funded(value: &[u8]) -> Result<([u8; 32], [u8; 32], u8), std::io::Error> {
    if value.len() != 65 {
        return Err(truncated_run());
    }
    let mut scripthash = [0_u8; 32];
    scripthash.copy_from_slice(&value[..32]);
    let mut txid = [0_u8; 32];
    txid.copy_from_slice(&value[32..64]);
    Ok((scripthash, txid, value[64]))
}

struct TxIdentity<'a> {
    txid: &'a [u8; 32],
    height: u32,
    offset: u32,
    len: u32,
}

impl ScriptEmission<'_> {
    fn push_tx_rows(
        &mut self,
        tx: &TxIdentity,
        block_hash: &[u8; 32],
        ordinal: u32,
    ) -> Result<(), IndexBundleError> {
        let Some(dir) = self.dir.as_mut() else {
            return Err(IndexBundleError::Identity(
                "the directory sorter is already staged".to_owned(),
            ));
        };
        let path = self.path;
        let dir_key = crate::segment::format::encode_tx_dir_key(0, tx.txid, tx.height).to_vec();
        let dir_value =
            crate::segment::format::encode_tx_dir_value(block_hash, ordinal, tx.offset, tx.len)
                .to_vec();
        dir.push(dir_key, dir_value)
            .map_err(|error| io_error(path, error))?;
        self.dir_rows += 1;
        let ordinal_key = crate::segment::format::encode_tx_ordinal_key(0, ordinal).to_vec();
        let ordinal_value =
            crate::segment::format::encode_tx_ordinal_value(tx.txid, tx.height, tx.offset, tx.len)
                .to_vec();
        dir.push(ordinal_key, ordinal_value)
            .map_err(|error| io_error(path, error))?;
        self.dir_rows += 1;
        Ok(())
    }
    fn push_spend_only_ordinal(
        &mut self,
        height: u32,
        offset: u32,
        len: u32,
        ordinal: u32,
    ) -> Result<(), IndexBundleError> {
        let Some(dir) = self.dir.as_mut() else {
            return Err(IndexBundleError::Identity(
                "the directory sorter is already staged".to_owned(),
            ));
        };
        let path = self.path;
        let key = crate::segment::format::encode_tx_ordinal_key(0, ordinal).to_vec();
        let value =
            crate::segment::format::encode_tx_ordinal_value(&[0_u8; 32], height, offset, len)
                .to_vec();
        dir.push(key, value)
            .map_err(|error| io_error(path, error))?;
        self.dir_rows += 1;
        Ok(())
    }

    fn push_posting_input(
        &mut self,
        scripthash: &[u8; 32],
        ordinal: u32,
        flags: u8,
    ) -> Result<(), IndexBundleError> {
        let Some(post_in) = self.post_in.as_mut() else {
            return Err(IndexBundleError::Identity(
                "the posting sorter is already staged".to_owned(),
            ));
        };
        let path = self.path;
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(scripthash);
        key.extend_from_slice(&ordinal.to_be_bytes());
        post_in
            .push(key, vec![flags])
            .map_err(|error| io_error(path, error))?;
        self.post_in_rows += 1;
        Ok(())
    }

    fn push_created(&mut self, txid: &[u8; 32], ordinal: u32) -> Result<(), IndexBundleError> {
        let Some(created) = self.created.as_mut() else {
            return Err(IndexBundleError::Identity(
                "the created sorter is already staged".to_owned(),
            ));
        };
        let path = self.path;
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(txid);
        key.extend_from_slice(&ordinal.to_be_bytes());
        created
            .push(key, Vec::new())
            .map_err(|error| io_error(path, error))?;
        Ok(())
    }

    fn join_funded(
        &mut self,
        funding_runs: &[RunFile],
        ord_runs: &[RunFile],
    ) -> Result<(), IndexBundleError> {
        let mut funded = MergeCursor::open(funding_runs, self.path)?;
        let mut ord = MergeCursor::open(ord_runs, self.path)?;
        let mut current_ord = ord.take()?;
        let mut prev: Option<Vec<u8>> = None;
        while let Some((fkey, fval)) = funded.take()? {
            let (height, offset, len) =
                split_identity(&fkey).map_err(|error| io_error(self.path, error))?;
            let (scripthash, txid, flags) =
                split_funded(&fval).map_err(|error| io_error(self.path, error))?;
            let fresh = prev.as_deref() != Some(fkey.as_slice());
            let (orank, _) = ord_at(&mut ord, &mut current_ord, &fkey, self.path)?;
            let ordinal = self.ordinal(orank)?;
            if fresh {
                prev = Some(fkey.clone());
                let block_hash = self.block_hash(height)?;
                let tx = TxIdentity {
                    txid: &txid,
                    height,
                    offset,
                    len,
                };
                self.push_tx_rows(&tx, &block_hash, ordinal)?;
            }
            self.push_posting_input(&scripthash, ordinal, flags)?;
            self.push_created(&txid, ordinal)?;
        }
        Ok(())
    }

    fn join_spenders(
        &mut self,
        spending_runs: &[RunFile],
        ord_runs: &[RunFile],
    ) -> Result<(Vec<RunFile>, Vec<RunFile>), IndexBundleError> {
        let mut spending = MergeCursor::open(spending_runs, self.path)?;
        let mut ord = MergeCursor::open(ord_runs, self.path)?;
        let mut current_ord = ord.take()?;
        let mut spend2 = self.set.sorter("sh-spend2");
        while spending.key().is_some() {
            let (skey, spent_txid, vout) = take_spend_row(&mut spending)?;
            let (height, offset, len) =
                split_identity(&skey).map_err(|error| io_error(self.path, error))?;
            let (orank, ofunded) = ord_at(&mut ord, &mut current_ord, &skey, self.path)?;
            let sos = self.ordinal(orank)?;
            push_spend2_row(&mut spend2, self.path, &spent_txid, sos, vout)?;
            loop {
                if !matches!(spending.key(), Some(key) if key == skey.as_slice()) {
                    break;
                }
                let (_, spent_txid, vout) = take_spend_row(&mut spending)?;
                push_spend2_row(&mut spend2, self.path, &spent_txid, sos, vout)?;
            }
            if !ofunded {
                self.push_spend_only_ordinal(height, offset, len, sos)?;
            }
        }
        let spend2_runs = spend2
            .finish()
            .map_err(|error| io_error(self.path, error))?;
        let created = self.take_created()?;
        let created_runs = created
            .finish()
            .map_err(|error| io_error(self.path, error))?;
        Ok((spend2_runs, created_runs))
    }
}

fn split_spend_key(key: &[u8]) -> Result<([u8; 32], u32), std::io::Error> {
    if key.len() != 36 {
        return Err(truncated_run());
    }
    let mut txid = [0_u8; 32];
    txid.copy_from_slice(&key[..32]);
    let mut ordinal = [0_u8; 4];
    ordinal.copy_from_slice(&key[32..36]);
    Ok((txid, u32::from_be_bytes(ordinal)))
}

impl ScriptEmission<'_> {
    fn spend_rows(
        &self,
        spend2_runs: &[RunFile],
        created_runs: &[RunFile],
    ) -> Result<Vec<RunFile>, IndexBundleError> {
        let mut spend_raw = self.set.sorter("sh-spendraw");
        let mut spends = MergeCursor::open(spend2_runs, self.path)?;
        let mut creations = MergeCursor::open(created_runs, self.path)?;
        let mut current_spend = spends.take()?;
        let mut current_creation = creations.take()?;
        let mut active: Option<[u8; 32]> = None;
        let mut last: Option<u32> = None;
        while let Some((skey, sval)) = current_spend {
            let (spent_txid, spending) =
                split_spend_key(&skey).map_err(|error| io_error(self.path, error))?;
            if sval.len() != 4 {
                return Err(io_error(self.path, truncated_run()));
            }
            let mut vout = [0_u8; 4];
            vout.copy_from_slice(&sval);
            let vout = u32::from_be_bytes(vout);
            if active != Some(spent_txid) {
                active = Some(spent_txid);
                last = None;
            }
            while let Some((ckey, _)) = &current_creation {
                let (created_txid, creation) =
                    split_spend_key(ckey).map_err(|error| io_error(self.path, error))?;
                if created_txid < spent_txid {
                    current_creation = creations.take()?;
                    continue;
                }
                if created_txid != spent_txid {
                    break;
                }
                if creation < spending {
                    last = Some(creation);
                    current_creation = creations.take()?;
                    continue;
                }
                break;
            }
            if let Some(creation) = last {
                let key = crate::segment::format::encode_spend_dir_key(0, creation, vout).to_vec();
                let value = crate::segment::format::encode_spend_dir_value(spending).to_vec();
                spend_raw
                    .push(key, value)
                    .map_err(|error| io_error(self.path, error))?;
            }
            current_spend = spends.take()?;
        }
        spend_raw
            .finish()
            .map_err(|error| io_error(self.path, error))
    }

    fn finish_spend_dir(
        &self,
        raw_runs: &[RunFile],
    ) -> Result<crate::segment::import::StreamedFamily, IndexBundleError> {
        let mut dir = self.set.sorter("sh-spenddir");
        let mut merged = MergeCursor::open(raw_runs, self.path)?;
        let mut current = merged.take()?;
        let mut previous: Option<Vec<u8>> = None;
        let mut rows = 0_u64;
        while let Some((key, value)) = current {
            if previous.as_deref() == Some(key.as_slice()) {
                return Err(script_record_error(0, "a spent outpoint appears twice"));
            }
            previous = Some(key.clone());
            dir.push(key, value)
                .map_err(|error| io_error(self.path, error))?;
            rows += 1;
            current = merged.take()?;
        }
        let runs = dir.finish().map_err(|error| io_error(self.path, error))?;
        Ok(crate::segment::import::StreamedFamily { runs, rows })
    }
    fn posting_families(
        &self,
        post_in_runs: &[RunFile],
    ) -> Result<
        (
            crate::segment::import::StreamedFamily,
            crate::segment::import::StreamedFamily,
        ),
        IndexBundleError,
    > {
        let mut dict = self.set.sorter("sh-dict");
        let mut dict_rows = 0_u64;
        let mut post = self.set.sorter("sh-post");
        let mut post_rows = 0_u64;
        let mut merged = MergeCursor::open(post_in_runs, self.path)?;
        let mut current = merged.take()?;
        let mut script_id = 0_u32;
        while let Some((pkey, _)) = current.clone() {
            if pkey.len() != 36 {
                return Err(io_error(self.path, truncated_run()));
            }
            let mut script = [0_u8; 32];
            script.copy_from_slice(&pkey[..32]);
            let mut chunker = PostingChunker::new(0, script_id);
            let mut previous = 0_u32;
            while let Some((ckey, cval)) = current {
                if ckey.len() != 36 || cval.len() != 1 {
                    return Err(io_error(self.path, truncated_run()));
                }
                if ckey[..32] != script {
                    current = Some((ckey, cval));
                    break;
                }
                let mut ordinal = [0_u8; 4];
                ordinal.copy_from_slice(&ckey[32..36]);
                let ordinal = u32::from_be_bytes(ordinal);
                let delta = ordinal.wrapping_sub(previous);
                previous = ordinal;
                if let Some(row) = chunker.push(delta, cval[0]) {
                    post.push(row.0, row.1)
                        .map_err(|error| io_error(self.path, error))?;
                    post_rows += 1;
                }
                current = merged.take()?;
            }
            if let Some(row) = chunker.finish() {
                post.push(row.0, row.1)
                    .map_err(|error| io_error(self.path, error))?;
                post_rows += 1;
            }
            let dict_key = crate::segment::format::encode_script_dict_key(0, &script).to_vec();
            let dict_value = crate::segment::format::encode_script_dict_value(script_id).to_vec();
            dict.push(dict_key, dict_value)
                .map_err(|error| io_error(self.path, error))?;
            dict_rows += 1;
            script_id = script_id.checked_add(1).ok_or_else(|| {
                script_too_many(
                    usize::try_from(self.distinct).unwrap_or(usize::MAX),
                    self.chain_tx_count,
                )
            })?;
        }
        let dict_runs = dict.finish().map_err(|error| io_error(self.path, error))?;
        let post_runs = post.finish().map_err(|error| io_error(self.path, error))?;
        Ok((
            crate::segment::import::StreamedFamily {
                runs: dict_runs,
                rows: dict_rows,
            },
            crate::segment::import::StreamedFamily {
                runs: post_runs,
                rows: post_rows,
            },
        ))
    }
}

pub fn attach_compact_filter_artifact(
    writer: &dyn TxIndexWriter,
    target: &ManifestArtifactTarget,
    scratch: &Path,
    budget: &SpillBudget,
) -> Result<u64, IndexBundleError> {
    const NAME: &str = "compact_filters.artifact";
    let path = &target.artifact_path;
    let fail = |error| io_error(path, error);
    if target.floor != 0 {
        return Err(IndexBundleError::ArtifactHeader {
            name: NAME,
            reason: "compact filter coverage starts at height zero",
        });
    }
    let length = fs::metadata(path).map_err(fail)?.len();
    if length != target.size_bytes {
        return Err(IndexBundleError::ArtifactLength {
            name: NAME,
            expected: target.size_bytes,
            actual: length,
        });
    }
    let mut hashed = open_hashed(path).map_err(fail)?;
    let mut header_bytes = [0_u8; HEADER_LEN];
    let header = match hashed.read_exact(&mut header_bytes) {
        Ok(()) => ArtifactHeader::decode(&header_bytes),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err("file ends inside the header")
        }
        Err(error) => return Err(fail(error)),
    };
    let expectation = ArtifactExpectation {
        family: BundleFamily::CompactFilters,
        index_format: target.index_format,
        network_magic: target.network.magic(),
        base_height: target.base_height,
        base_hash: target.base_hash,
        records: Some(u64::from(target.base_height) + 1),
        payload_bytes: target
            .size_bytes
            .checked_sub(u64::try_from(HEADER_LEN).unwrap_or(u64::MAX)),
    };
    let header =
        match header.and_then(|header| check_header(&header, &expectation).map(|()| header)) {
            Ok(header) => header,
            Err(reason) => return Err(IndexBundleError::ArtifactHeader { name: NAME, reason }),
        };
    let work = scratch.join(COMPACT_FILTERS_WORK_DIR);
    match fs::remove_dir_all(&work) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(fail(error)),
    }
    fs::create_dir_all(&work).map_err(fail)?;
    let outcome =
        stage_verified(hashed, &header, target, &work, budget).and_then(|(staged, digest)| {
            if digest != target.sha256 {
                return Err(IndexBundleError::ArtifactHash { name: NAME });
            }
            ingest_staged(writer, target, staged, &work)
        });
    let _ = fs::remove_dir_all(&work);
    outcome
}

const COMPACT_FILTERS_WORK_DIR: &str = "compact-filters-attach";

struct Staged {
    heights: PathBuf,
    runs: Vec<crate::segment::spill::RunFile>,
}

/// Largest compact filter a bundle record may carry. A block holds at most
/// `MAX_BLOCK_SERIALIZED_SIZE / 9` basic-filter elements: an output script
/// costs at least 9 block bytes and a spent script at least one 41-byte
/// input. BIP158 Golomb-Rice coding with `P = 19` and `M = 784931` spends
/// fewer than `N * (M / 2^P + P + 1)` bits on `N` elements, which stays
/// under 1_194_300 bytes with the CompactSize prefix.
const MAX_COMPACT_FILTER_BYTES: u32 = 1_200_000;

fn stage_verified(
    mut hashed: HashedFile,
    header: &ArtifactHeader,
    target: &ManifestArtifactTarget,
    work: &Path,
    budget: &SpillBudget,
) -> Result<(Staged, [u8; 32]), IndexBundleError> {
    const NAME: &str = "compact_filters.artifact";
    let path = &target.artifact_path;
    let heights_path = work.join("heights.bin");
    let mut heights = BufWriter::with_capacity(IO_BUFFER_BYTES, create_new_file(&heights_path)?);
    let set = SpillSet::new(budget, work.to_path_buf());
    let mut runs = set.sorter("compact-filter");
    let mut previous = [0_u8; 32];
    let mut last_block = [0_u8; 32];
    let mut payload_left = header.payload_bytes;
    for height in 0..=target.base_height {
        let record = u64::from(height);
        let framing = |reason: &'static str| IndexBundleError::ArtifactFraming {
            name: NAME,
            record,
            reason,
        };
        let mut fixed = [0_u8; RECORD_FIXED_LEN];
        read_record_bytes(&mut hashed, &mut fixed, record, path)?;
        let fields = decode_fixed(&fixed);
        if fields.height != height {
            return Err(framing("heights are not contiguous from zero"));
        }
        let total = u64::try_from(RECORD_FIXED_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(fields.length));
        if total > payload_left {
            return Err(framing("record overruns the declared payload"));
        }
        if fields.length > MAX_COMPACT_FILTER_BYTES {
            return Err(framing("filter exceeds the BIP158 size bound"));
        }
        let mut filter = Vec::new();
        (&mut hashed)
            .take(u64::from(fields.length))
            .read_to_end(&mut filter)
            .map_err(|error| io_error(path, error))?;
        if u64::try_from(filter.len()).ok() != Some(u64::from(fields.length)) {
            return Err(framing("file ends inside a record"));
        }
        payload_left -= total;
        if double_sha256(&filter).to_le_bytes() != fields.filter_hash {
            return Err(framing("filter hash does not match the filter bytes"));
        }
        if chain_header(&fields.filter_hash, &previous) != fields.header {
            return Err(framing("filter header chain is broken"));
        }
        previous = fields.header;
        last_block = fields.block_hash;
        let row = CompactFilterRow {
            height,
            block_hash: fields.block_hash,
            filter_hash: fields.filter_hash,
            header: fields.header,
            filter,
        };
        encode_record(&mut heights, &row).map_err(|error| io_error(&heights_path, error))?;
        let mut encoded = Vec::with_capacity(RECORD_FIXED_LEN + row.filter.len());
        encode_record(&mut encoded, &row).map_err(|error| io_error(path, error))?;
        runs.push(row.block_hash.to_vec(), encoded)
            .map_err(|error| io_error(path, error))?;
    }
    let tail = u64::from(target.base_height) + 1;
    if payload_left != 0 {
        return Err(IndexBundleError::ArtifactFraming {
            name: NAME,
            record: tail,
            reason: "payload is longer than its records",
        });
    }
    let mut probe = [0_u8; 1];
    match hashed.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => {
            return Err(IndexBundleError::ArtifactFraming {
                name: NAME,
                record: tail,
                reason: "bytes follow the final record",
            });
        }
        Err(error) => return Err(io_error(path, error)),
    }
    if last_block != target.base_hash {
        return Err(IndexBundleError::ArtifactFraming {
            name: NAME,
            record: u64::from(target.base_height),
            reason: "final record is not the base block",
        });
    }
    let digest = into_digest(hashed);
    heights
        .into_inner()
        .map_err(|error| io_error(&heights_path, error.into_error()))?;
    let runs = runs.finish().map_err(|error| io_error(path, error))?;
    Ok((
        Staged {
            heights: heights_path,
            runs,
        },
        digest,
    ))
}

fn ingest_staged(
    writer: &dyn TxIndexWriter,
    target: &ManifestArtifactTarget,
    staged: Staged,
    work: &Path,
) -> Result<u64, IndexBundleError> {
    const NAME: &str = "compact_filters.artifact";
    let records = u64::from(target.base_height) + 1;
    let mut previous = None;
    let merged = merge(&staged.runs).map_err(|error| io_error(work, error))?;
    for record in merged {
        let (key, value) = record.map_err(|error| io_error(work, error))?;
        let row = decode_run_row(&key, &value)?;
        if previous == Some(row.block_hash) {
            return Err(IndexBundleError::ArtifactFraming {
                name: NAME,
                record: u64::from(row.height),
                reason: "two records name the same block",
            });
        }
        previous = Some(row.block_hash);
    }
    let failure: RefCell<Option<IndexBundleError>> = RefCell::new(None);
    let outcome = {
        let mut by_height = Rows::new(SpillFile::open(staged.heights, records)?, &failure);
        let attachment = CompactFilterAttachment {
            base: IndexWatermark {
                height: target.base_height,
                hash: target.base_hash,
            },
            records,
            scratch: work,
        };
        writer.attach_compact_filter_segment(&mut by_height, &attachment)
    };
    if let Some(error) = failure.into_inner() {
        return Err(error);
    }
    outcome.map_err(IndexBundleError::Index)
}

fn read_record_bytes(
    reader: &mut impl Read,
    buffer: &mut [u8],
    record: u64,
    path: &Path,
) -> Result<(), IndexBundleError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            IndexBundleError::ArtifactFraming {
                name: "compact_filters.artifact",
                record,
                reason: "file ends inside a record",
            }
        } else {
            io_error(path, error)
        }
    })
}
pub(crate) fn reset_interrupted_import(writer: &dyn TxIndexWriter) -> Result<(), IndexError> {
    let (_, watermarks) = writer.fenced_watermarks()?;
    if watermarks.tx_lookup.is_some() {
        return Ok(());
    }
    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)
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

fn validate_artifact(
    host: &BundleHost<'_>,
    path: &Path,
    manifest: &ValidatedManifest,
    chain: Option<&ChainBase>,
) -> Result<(ArtifactHeader, LocatorOutcome), IndexBundleError> {
    let name = BundleFamily::TxLookup.file_name();
    let fail = |error| io_error(path, error);
    let expectation = manifest_artifact_expectation(manifest)?;
    let mut reader = open_hashed(path).map_err(fail)?;
    let mut header_bytes = [0_u8; HEADER_LEN];
    let header = match reader.read_exact(&mut header_bytes) {
        Ok(()) => ArtifactHeader::decode(&header_bytes)
            .and_then(|header| check_header(&header, &expectation).map(|()| header)),
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

pub(super) struct ArtifactExpectation {
    pub(super) family: BundleFamily,
    pub(super) index_format: u32,
    pub(super) network_magic: [u8; 4],
    pub(super) base_height: u32,
    pub(super) base_hash: [u8; 32],
    pub(super) records: Option<u64>,
    pub(super) payload_bytes: Option<u64>,
}

fn manifest_artifact_expectation(
    manifest: &ValidatedManifest,
) -> Result<ArtifactExpectation, IndexBundleError> {
    let identity = &manifest.identity;
    let payload_bytes = manifest
        .tx_lookup
        .bytes
        .checked_sub(u64::try_from(HEADER_LEN).unwrap_or(u64::MAX));
    if payload_bytes.is_none() {
        return Err(IndexBundleError::ArtifactHeader {
            name: BundleFamily::TxLookup.file_name(),
            reason: "manifest declares an artifact shorter than its header",
        });
    }
    Ok(ArtifactExpectation {
        family: BundleFamily::TxLookup,
        index_format: identity.format_version,
        network_magic: identity.network.magic(),
        base_height: identity.base_height,
        base_hash: identity.base_hash,
        records: Some(manifest.tx_lookup.records),
        payload_bytes,
    })
}

fn check_header(
    header: &ArtifactHeader,
    expected: &ArtifactExpectation,
) -> Result<(), &'static str> {
    if header.family != expected.family {
        return Err("family differs from the expected family");
    }
    if header.artifact_version != ARTIFACT_VERSION {
        return Err("artifact version is not supported");
    }
    if header.index_format != expected.index_format {
        return Err("index format differs from the manifest");
    }
    if header.network_magic != expected.network_magic {
        return Err("network magic differs from the manifest");
    }
    if header.base_height != expected.base_height || header.base_hash != expected.base_hash {
        return Err("base differs from the manifest");
    }
    if expected
        .records
        .is_some_and(|records| header.records != records)
    {
        return Err("record count differs from the manifest");
    }
    if expected.payload_bytes != Some(header.payload_bytes) {
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
        let name = BundleFamily::TxLookup.file_name();
        let mut hashed = open_hashed(self.path).map_err(|error| io_error(self.path, error))?;
        let mut header_bytes = [0_u8; HEADER_LEN];
        hashed
            .read_exact(&mut header_bytes)
            .map_err(|error| io_error(self.path, error))?;
        if ArtifactHeader::decode(&header_bytes) != Ok(self.header) {
            return Err(IndexBundleError::ArtifactHash { name });
        }
        let count =
            usize::try_from(self.manifest.identity.base_height.saturating_add(1)).unwrap_or(0);
        let mut headers = Vec::with_capacity(count);
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
            headers.push(header);
        }
        let header_refs: Vec<&[u8; crate::types::HEADER_ROW_SIZE]> = headers.iter().collect();
        let scratch = self.path.parent().unwrap_or(self.path);
        let work = scratch.join(TX_LOOKUP_WORK_DIR);
        match fs::remove_dir_all(&work) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(self.path, error)),
        }
        fs::create_dir_all(&work).map_err(|error| io_error(self.path, error))?;
        let result = self.import_streamed(&header_refs, &work, hashed, base);
        let _ = fs::remove_dir_all(&work);
        result
    }

    fn import_streamed(
        &self,
        header_refs: &[&[u8; crate::types::HEADER_ROW_SIZE]],
        work: &Path,
        mut hashed: HashedFile,
        base: IndexWatermark,
    ) -> Result<usize, IndexBundleError> {
        let name = BundleFamily::TxLookup.file_name();
        let budget = SpillBudget::new(RESTORE_SPILL_BUDGET_BYTES);
        let set = SpillSet::new(&budget, work.to_path_buf());
        let stream = TxLookupStream {
            floor: self.manifest.tx_lookup.floor,
            path: self.path,
            headers: header_refs,
            set,
        };
        let decoded = stream.decode(&mut hashed, &self.header, self.host.cancelled)?;
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
        let (family, count, ordinal_base) =
            stream.order(decoded, self.manifest.identity.chain_tx_count)?;
        let seal = crate::segment::import::tx_lookup_seal(
            self.manifest.tx_lookup.floor,
            base.height,
            base.hash,
            count,
            ordinal_base,
        )
        .map_err(IndexBundleError::Index)?;
        let attachment = crate::writer::TxLookupAttachment {
            headers: header_refs,
            base,
            floor: self.manifest.tx_lookup.floor,
            scratch: self.path.parent().unwrap_or(self.path),
        };
        let imported = self
            .host
            .writer
            .attach_streamed_tx_lookup(&family, &seal, &attachment)
            .map_err(IndexBundleError::Index);
        let count = match imported {
            Ok(count) => return Ok(usize::try_from(count).unwrap_or(usize::MAX)),
            Err(error) => error,
        };
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
        Err(discard_partial_rows(count, watermarks, reset))
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

    #[test]
    fn invalid_tail_drain_polls_cancellation_per_bounded_chunk()
    -> Result<(), crate::portable::TestError> {
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

    #[test]
    fn oversized_filter_record_is_refused_before_allocation()
    -> Result<(), crate::portable::TestError> {
        for length in [u32::MAX, 1_200_001] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("compact_filters.artifact");
            let mut record = vec![0_u8; RECORD_FIXED_LEN];
            record[RECORD_FIXED_LEN - 4..].copy_from_slice(&length.to_le_bytes());
            std::fs::write(&path, &record)?;
            let network = bitcoin_rs_consensus::primitives::Network::Mainnet;
            let header = ArtifactHeader {
                family: BundleFamily::CompactFilters,
                artifact_version: ARTIFACT_VERSION,
                index_format: crate::index_format_version(),
                network_magic: network.magic(),
                base_height: 0,
                base_hash: [0_u8; 32],
                records: 1,
                payload_bytes: u64::try_from(RECORD_FIXED_LEN)? + u64::from(length),
            };
            let target = ManifestArtifactTarget {
                artifact_path: path.clone(),
                base_height: 0,
                base_hash: [0_u8; 32],
                floor: 0,
                network,
                index_format: crate::index_format_version(),
                sha256: [0_u8; 32],
                size_bytes: u64::try_from(record.len())?,
                chain_tx_count: 0,
            };
            let work = dir.path().join("work");
            std::fs::create_dir_all(&work)?;
            let budget = SpillBudget::new(1 << 20);
            let hashed = open_hashed(&path)?;
            let Err(error) = stage_verified(hashed, &header, &target, &work, &budget) else {
                return Err("an oversized filter record was staged".into());
            };
            assert!(
                matches!(
                    error,
                    IndexBundleError::ArtifactFraming {
                        reason: "filter exceeds the BIP158 size bound",
                        ..
                    }
                ),
                "a {length}-byte filter record must be refused by the bound: {error}"
            );
        }
        Ok(())
    }
}
