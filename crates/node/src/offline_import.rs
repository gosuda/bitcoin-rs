use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use sha2::Digest as _;

use crate::NodeConfig;

const CORE_FRAMED_SCHEMA: &str = "core-framed-archive-manifest-v1";
const CORPUS_SCHEMA: &str = "bitcoin-rs-corpus-manifest";
const CORPUS_VERSION: u32 = 1;

#[derive(Debug, serde::Deserialize)]
struct ManifestBlock {
    height: u32,
    hash: String,
    offset: u64,
    payload_length: usize,
}

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    network: String,
    network_magic: String,
    start_height: u32,
    stop_height: u32,
    archive_sha256: String,
    archive_bytes: u64,
    blocks: Vec<ManifestBlock>,
}

#[derive(Debug, serde::Deserialize)]
struct CorpusRange {
    start_height: u32,
    stop_height: u32,
}

#[derive(Debug, serde::Deserialize)]
struct CorpusArchive {
    sha256: String,
    size: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum RawManifest {
    Framed {
        schema: String,
        network: String,
        network_magic: String,
        start_height: u32,
        stop_height: u32,
        archive_sha256: String,
        archive_bytes: u64,
        blocks: Vec<ManifestBlock>,
    },
    Corpus {
        schema: String,
        version: u32,
        network: String,
        network_magic: String,
        range: CorpusRange,
        archive: CorpusArchive,
        entries: Vec<ManifestBlock>,
    },
}

#[derive(Debug, serde::Serialize)]
struct CertifiedState {
    height: u32,
    bestblock: String,
    txouts: u64,
    total_amount_sat: u64,
    muhash: String,
    utxo_hash_serialized_3: String,
    bodies_available: bool,
    disconnect_ready: bool,
}

const HEADER_LEN: usize = 80;
const MAX_PAYLOAD: usize = 4_000_000;
const MAX_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OfflineImportError {
    #[error(transparent)]
    NodeOpen(Box<crate::state::open::NodeOpenError>),
    #[error("offline import requires --assume-valid-height 0 for full validation")]
    AssumeValidHeightRequired,
    #[error("offline import requires auxiliary indexes off")]
    AuxiliaryIndexesRequiredOff,
    #[error(
        "stale persisted derived index at {namespace}: remove it or revalidate with an indexed start, then re-run"
    )]
    StalePersistedIndex { namespace: PathBuf },
    #[error("cannot read manifest {path}")]
    ManifestRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("manifest exceeds its byte bound")]
    ManifestExceedsBound,
    #[error("manifest {path} is not valid JSON")]
    ManifestJson {
        path: PathBuf,
        #[source]
        source: sonic_rs::Error,
    },
    #[error("manifest schema must be {0}")]
    ManifestSchema(&'static str),
    #[error("manifest version {version} is not supported")]
    ManifestVersion { version: u32 },
    #[error("manifest network magic does not match the node network")]
    ManifestNetworkMagicMismatch,
    #[error("manifest network does not match the node network")]
    ManifestNetworkMismatch,
    #[error("network magic must be 8 hex characters")]
    ManifestMagicHex,
    #[error("manifest blocks must list every height exactly once")]
    ManifestBlocksListEveryHeight,
    #[error("manifest stop is before start")]
    ManifestStopBeforeStart,
    #[error("manifest range overflow")]
    ManifestRangeOverflow,
    #[error("manifest range does not fit")]
    ManifestRangeDoesNotFit {
        #[source]
        source: core::num::TryFromIntError,
    },
    #[error("manifest index does not fit")]
    ManifestIndexDoesNotFit {
        #[source]
        source: core::num::TryFromIntError,
    },
    #[error("manifest height overflow")]
    ManifestHeightOverflow,
    #[error("manifest heights must be contiguous from start_height")]
    ManifestHeightsNotContiguous,
    #[error("manifest entry payload is outside consensus bounds")]
    ManifestEntryPayloadBounds,
    #[error("manifest entry hash must be 64 hex characters")]
    ManifestEntryHashLength,
    #[error("manifest entry offset is not packed")]
    ManifestEntryOffsetNotPacked,
    #[error("manifest cursor overflow")]
    ManifestCursorOverflow,
    #[error("payload length does not fit")]
    ManifestPayloadLengthDoesNotFit {
        #[source]
        source: core::num::TryFromIntError,
    },
    #[error("manifest entry overruns the archive")]
    ManifestEntryOverrunsArchive,
    #[error("manifest does not consume the archive exactly")]
    ManifestDoesNotConsumeArchive,
    #[error("applied tip height {height} is outside the manifest range")]
    AppliedTipOutsideRange { height: u32 },
    #[error("applied tip height does not match the manifest entry")]
    AppliedTipHeightMismatch,
    #[error("applied tip hash does not match the manifest entry")]
    AppliedTipHashMismatch,
    #[error("applied tip overflow")]
    AppliedTipOverflow,
    #[error("tip height does not fit")]
    TipHeightDoesNotFit {
        #[source]
        source: core::num::TryFromIntError,
    },
    #[error("cannot open corpus {path}")]
    CorpusOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot stat corpus {path}")]
    CorpusStat {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("corpus is not a regular file")]
    CorpusNotRegularFile,
    #[error("manifest entry at height {height} is outside consensus bounds")]
    ManifestEntryOutOfBounds { height: u32 },
    #[error("archive ended inside record header at height {height}")]
    ArchiveHeaderTruncated {
        height: u32,
        #[source]
        source: std::io::Error,
    },
    #[error("archive record at height {height} has the wrong network magic")]
    ArchiveRecordMagic { height: u32 },
    #[error("record length does not fit")]
    RecordLengthDoesNotFit {
        #[source]
        source: core::num::TryFromIntError,
    },
    #[error("archive record at height {height} length diverged")]
    ArchiveRecordLength { height: u32 },
    #[error("archive ended inside block payload at height {height}")]
    ArchivePayloadTruncated {
        height: u32,
        #[source]
        source: std::io::Error,
    },
    #[error("block at height {height} is shorter than a header")]
    PayloadShorterThanHeader { height: u32 },
    #[error("block at height {height} header hash diverged")]
    BlockHeaderHashDiverged { height: u32 },
    #[error("block at height {height} does not decode: {decode_error}")]
    BlockDecode {
        height: u32,
        decode_error: bitcoin_rs_consensus::primitives::DecodeError,
    },
    #[error("connect at block {hash} failed: {connect_error}")]
    ConnectFailed {
        hash: bitcoin_rs_consensus::primitives::BlockHash,
        connect_error: Box<crate::ConnectMutationError>,
    },
    #[error("cannot check archive trailing bytes: {io_error}")]
    TrailingBytesCheck { io_error: std::io::Error },
    #[error("archive contains trailing bytes after the last record")]
    ArchiveTrailingBytes,
    #[error("archive size does not match the manifest")]
    ArchiveSizeMismatch,
    #[error("archive digest does not match the manifest")]
    ArchiveDigestMismatch,
    #[error("cannot read provenance {path}: {source}")]
    ProvenanceRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("provenance {path} exceeds its bound")]
    ProvenanceExceedsBound { path: PathBuf },
    #[error("provenance {path} is not valid JSON: {source}")]
    ProvenanceJson {
        path: PathBuf,
        #[source]
        source: sonic_rs::Error,
    },
    #[error("provenance {path} has an unknown schema")]
    ProvenanceUnknownSchema { path: PathBuf },
    #[error(
        "offline import refuses to resume over the applied tip at height {tip_height}: the full-validation provenance record binds height {record_height} and no longer matches this tip, so revalidate from a fresh data directory"
    )]
    ProvenanceResumeMismatch { tip_height: u32, record_height: u32 },
    #[error(
        "offline import refuses to resume over the applied tip at height {tip_height}: no readable full-validation provenance record ({detail}), so revalidate from a fresh data directory"
    )]
    ProvenanceUnreadable { tip_height: u32, detail: String },
    #[error("cannot encode provenance")]
    ProvenanceEncode {
        #[source]
        source: sonic_rs::Error,
    },
    #[error("cannot write provenance {path}")]
    ProvenanceWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot open provenance {path}")]
    ProvenanceOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot fsync provenance {path}")]
    ProvenanceFsync {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot publish provenance")]
    ProvenancePublish {
        #[source]
        source: std::io::Error,
    },
    #[error("cannot open data dir {path}")]
    DataDirOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot fsync data dir {path}")]
    DataDirFsync {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("offline import produced no applied tip")]
    NoAppliedTip,
    #[error("manifest has no stop entry")]
    NoStopEntry,
    #[error("applied tip height does not equal the manifest stop")]
    AppliedTipStopMismatch,
    #[error("applied tip height does not equal the manifest stop entry")]
    AppliedTipStopEntryMismatch,
    #[error("applied tip hash does not equal the manifest stop hash")]
    AppliedTipStopHashMismatch,
    #[error("running node has no block body store")]
    NoBlockBodyStore,
    #[error("body proof failed: {body_error}")]
    BodyProof {
        body_error: bitcoin_rs_storage::StorageError,
    },
    #[error("tip body is not available")]
    TipBodyUnavailable,
    #[error("verification skipped data this node should hold at height {height}")]
    VerificationSkippedData { height: u32 },
    #[error("verification of the applied tip failed: {verify_error}")]
    VerificationFailed {
        verify_error: Box<bitcoin_rs_chain::verify::VerifyError>,
    },
    #[error("stable UTXO view rebuild failed: {source}")]
    StableViewRebuild {
        #[source]
        source: bitcoin_rs_storage::utxo::UtxoError,
    },
    #[error("coin stats scan failed: {scan_error}")]
    CoinStatsScan {
        scan_error: bitcoin_rs_storage::utxo::UtxoError,
    },
    #[error("hash_serialized_3 failed: {hash_error}")]
    HashSerialized3 {
        hash_error: bitcoin_rs_storage::utxo::UtxoError,
    },
    #[error("txout count does not fit: {count_error}")]
    TxoutCountDoesNotFit {
        count_error: core::num::TryFromIntError,
    },
    #[error("clean checkpoint publication failed: {checkpoint_error}")]
    CheckpointPublicationFailed {
        checkpoint_error: Box<bitcoin_rs_chain::CheckpointError>,
    },
    #[error("clean checkpoint publication skipped: no applied tip")]
    CheckpointPublicationSkipped,
    #[error("cannot create state dir {path}")]
    StateDirCreate {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot create state file {path}")]
    StateFileCreate {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot encode certified state")]
    StateEncode {
        #[source]
        source: sonic_rs::Error,
    },
    #[error("cannot write state file {path}")]
    StateFileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot fsync state file {path}")]
    StateFileFsync {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot open state dir {path}")]
    StateDirOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot fsync state dir {path}")]
    StateDirFsync {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl From<crate::state::open::NodeOpenError> for OfflineImportError {
    fn from(error: crate::state::open::NodeOpenError) -> Self {
        Self::NodeOpen(Box::new(error))
    }
}

pub fn run_offline_import(
    mut config: NodeConfig,
    corpus: &Path,
    manifest: &Path,
    state: &Path,
) -> Result<(), OfflineImportError> {
    let manifest_doc = validate_offline_import_config_and_manifest(&mut config, manifest)?;
    let data_dir = config.data_dir.clone();
    let expected_magic = config.network.magic();
    let node = crate::state::NodeState::open(config, None)?;
    let skip = determine_resume_skip(&manifest_doc, &node.chainstate(), &data_dir)?;
    import_corpus_archive(
        CorpusImportTask {
            corpus,
            manifest: &manifest_doc,
            expected_magic,
            skip,
        },
        &node,
    )?;
    verify_and_certify(&node, &data_dir, &manifest_doc, state)?;
    Ok(())
}

fn validate_offline_import_config_and_manifest(
    config: &mut NodeConfig,
    manifest: &Path,
) -> Result<Manifest, OfflineImportError> {
    if config.validation.assume_valid_height != 0 {
        return Err(OfflineImportError::AssumeValidHeightRequired);
    }
    config.validation.mode = resolve_offline_validation_mode(config.validation.mode);
    if config.indexes.txindex
        || config.indexes.blockfilterindex
        || config.indexes.script_index.is_enabled()
    {
        return Err(OfflineImportError::AuxiliaryIndexesRequiredOff);
    }
    refuse_stale_persisted_indexes(&config.data_dir)?;
    let manifest_doc = read_manifest(manifest)?;
    let expected_magic = config.network.magic();
    let manifest_magic = parse_magic_hex(&manifest_doc.network_magic)?;
    if manifest_magic != expected_magic {
        return Err(OfflineImportError::ManifestNetworkMagicMismatch);
    }
    check_manifest_network(&manifest_doc, config.network.identity_name())?;
    check_manifest_shape(&manifest_doc)?;
    Ok(manifest_doc)
}

fn determine_resume_skip(
    manifest_doc: &Manifest,
    chainstate: &bitcoin_rs_chain::Chainstate,
    data_dir: &Path,
) -> Result<usize, OfflineImportError> {
    let already = chainstate.applied_tip_snapshot();
    let skip = match already.as_ref() {
        None => 0usize,
        Some(tip) => {
            let height = tip.height;
            let entry_index = block_index_for_height(manifest_doc.start_height, height)?;
            let entry = manifest_doc
                .blocks
                .get(entry_index)
                .ok_or(OfflineImportError::AppliedTipOutsideRange { height })?;
            if entry.height != height {
                return Err(OfflineImportError::AppliedTipHeightMismatch);
            }
            if !entry.hash.eq_ignore_ascii_case(&tip.hash.to_string()) {
                return Err(OfflineImportError::AppliedTipHashMismatch);
            }
            require_full_validation_provenance(data_dir, tip)?;
            if height == manifest_doc.stop_height {
                manifest_doc.blocks.len()
            } else {
                let next = height
                    .checked_add(1)
                    .ok_or(OfflineImportError::AppliedTipOverflow)?;
                block_index_for_height(manifest_doc.start_height, next)?
            }
        }
    };
    Ok(skip)
}

#[derive(Clone, Copy)]
struct CorpusImportTask<'a> {
    corpus: &'a Path,
    manifest: &'a Manifest,
    expected_magic: [u8; 4],
    skip: usize,
}

fn import_corpus_archive(
    task: CorpusImportTask<'_>,
    node: &crate::state::NodeState,
) -> Result<(), OfflineImportError> {
    let mut stream = open_corpus(task.corpus)?;
    let mut hasher = sha2::Sha256::new();
    let mut total: u64 = 0;
    let mut payloads: Vec<bitcoin_rs_consensus::primitives::BlockImage> = Vec::new();
    for (index, entry) in task.manifest.blocks.iter().enumerate() {
        let record = read_record(&mut stream, task.expected_magic, entry)?;
        check_payload_against_entry(entry, &record.payload)?;
        hasher.update(&record.framed);
        total += u64::try_from(record.framed.len())
            .map_err(|source| OfflineImportError::RecordLengthDoesNotFit { source })?;
        if index < task.skip {
            continue;
        }
        let payload =
            bitcoin_rs_consensus::primitives::BlockImage::from_raw(Bytes::from(record.payload))
                .map_err(|decode_error| OfflineImportError::BlockDecode {
                    height: entry.height,
                    decode_error,
                })?;
        if !payload
            .block_hash()
            .to_string()
            .eq_ignore_ascii_case(&entry.hash)
        {
            return Err(OfflineImportError::BlockHeaderHashDiverged {
                height: entry.height,
            });
        }
        payloads.push(payload);
        if payloads.len() >= 128 {
            connect_batch(node, &mut payloads)?;
        }
    }
    if !payloads.is_empty() {
        connect_batch(node, &mut payloads)?;
    }
    let trailing = {
        let mut one = [0u8; 1];
        match stream.file.read(&mut one) {
            Ok(0) => false,
            Ok(_) => true,
            Err(io_error) => return Err(OfflineImportError::TrailingBytesCheck { io_error }),
        }
    };
    if trailing {
        return Err(OfflineImportError::ArchiveTrailingBytes);
    }
    if total != task.manifest.archive_bytes {
        return Err(OfflineImportError::ArchiveSizeMismatch);
    }
    let digest = bitcoin_rs_consensus::primitives::hex::hex_encode(&hasher.finalize());
    if digest != task.manifest.archive_sha256.to_ascii_lowercase() {
        return Err(OfflineImportError::ArchiveDigestMismatch);
    }
    Ok(())
}

struct FramedRecord {
    framed: Vec<u8>,
    payload: Vec<u8>,
}

struct CorpusStream {
    file: File,
}

fn open_corpus(path: &Path) -> Result<CorpusStream, OfflineImportError> {
    let file = File::open(path).map_err(|source| OfflineImportError::CorpusOpen {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| OfflineImportError::CorpusStat {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(OfflineImportError::CorpusNotRegularFile);
    }
    Ok(CorpusStream { file })
}

fn read_record(
    stream: &mut CorpusStream,
    expected_magic: [u8; 4],
    entry: &ManifestBlock,
) -> Result<FramedRecord, OfflineImportError> {
    if entry.payload_length < HEADER_LEN || entry.payload_length > MAX_PAYLOAD {
        return Err(OfflineImportError::ManifestEntryOutOfBounds {
            height: entry.height,
        });
    }
    let mut header = [0u8; 8];
    stream.file.read_exact(&mut header).map_err(|source| {
        OfflineImportError::ArchiveHeaderTruncated {
            height: entry.height,
            source,
        }
    })?;
    if header[..4] != expected_magic {
        return Err(OfflineImportError::ArchiveRecordMagic {
            height: entry.height,
        });
    }
    let length = usize::try_from(u32::from_le_bytes([
        header[4], header[5], header[6], header[7],
    ]))
    .map_err(|source| OfflineImportError::RecordLengthDoesNotFit { source })?;
    if length != entry.payload_length {
        return Err(OfflineImportError::ArchiveRecordLength {
            height: entry.height,
        });
    }
    let mut payload = vec![0u8; length];
    stream.file.read_exact(&mut payload).map_err(|source| {
        OfflineImportError::ArchivePayloadTruncated {
            height: entry.height,
            source,
        }
    })?;
    let mut framed = Vec::with_capacity(8 + length);
    framed.extend_from_slice(&header);
    framed.extend_from_slice(&payload);
    Ok(FramedRecord { framed, payload })
}

fn connect_batch(
    node: &crate::state::NodeState,
    batch: &mut Vec<bitcoin_rs_consensus::primitives::BlockImage>,
) -> Result<(), OfflineImportError> {
    let chainstate = node.chainstate();
    let followers = node.chain_followers();
    for payload in batch.drain(..) {
        let hash = payload.block_hash();
        if let Err(error) = followers.apply_connect(&chainstate, &payload) {
            return Err(OfflineImportError::ConnectFailed {
                hash,
                connect_error: Box::new(error),
            });
        }
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Manifest, OfflineImportError> {
    let raw = read_bounded(path, MAX_MANIFEST_BYTES)?;
    let raw_doc: RawManifest =
        sonic_rs::from_slice(&raw).map_err(|source| OfflineImportError::ManifestJson {
            path: path.to_path_buf(),
            source,
        })?;
    raw_doc.normalize()
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, OfflineImportError> {
    let file = File::open(path).map_err(|source| OfflineImportError::ManifestRead {
        path: path.to_path_buf(),
        source,
    })?;
    let mut raw = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|source| OfflineImportError::ManifestRead {
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > limit {
        return Err(OfflineImportError::ManifestExceedsBound);
    }
    Ok(raw)
}

impl RawManifest {
    fn normalize(self) -> Result<Manifest, OfflineImportError> {
        match self {
            Self::Framed {
                schema,
                network,
                network_magic,
                start_height,
                stop_height,
                archive_sha256,
                archive_bytes,
                blocks,
            } => {
                if schema != CORE_FRAMED_SCHEMA {
                    return Err(OfflineImportError::ManifestSchema(CORE_FRAMED_SCHEMA));
                }
                Ok(Manifest {
                    network,
                    network_magic,
                    start_height,
                    stop_height,
                    archive_sha256,
                    archive_bytes,
                    blocks,
                })
            }
            Self::Corpus {
                schema,
                version,
                network,
                network_magic,
                range,
                archive,
                entries,
            } => {
                if schema != CORPUS_SCHEMA {
                    return Err(OfflineImportError::ManifestSchema(CORPUS_SCHEMA));
                }
                if version != CORPUS_VERSION {
                    return Err(OfflineImportError::ManifestVersion { version });
                }
                Ok(Manifest {
                    network,
                    network_magic,
                    start_height: range.start_height,
                    stop_height: range.stop_height,
                    archive_sha256: archive.sha256,
                    archive_bytes: archive.size,
                    blocks: entries,
                })
            }
        }
    }
}

fn check_manifest_network(
    doc: &Manifest,
    expected_network: &str,
) -> Result<(), OfflineImportError> {
    if doc.network != expected_network {
        return Err(OfflineImportError::ManifestNetworkMismatch);
    }
    Ok(())
}

const FULL_VALIDATION_PROVENANCE_FILE: &str = "offline-full-validation-provenance.json";
const FULL_VALIDATION_PROVENANCE_SCHEMA: &str = "offline-full-validation-provenance-v1";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct FullValidationProvenance {
    schema: String,
    height: u32,
    tip_hash: String,
}

fn block_index_for_height(start_height: u32, height: u32) -> Result<usize, OfflineImportError> {
    let offset = height
        .checked_sub(start_height)
        .ok_or(OfflineImportError::AppliedTipOutsideRange { height })?;
    usize::try_from(offset).map_err(|source| OfflineImportError::TipHeightDoesNotFit { source })
}

fn require_full_validation_provenance(
    data_dir: &Path,
    tip: &bitcoin_rs_chain::chain::TipSnapshot,
) -> Result<(), OfflineImportError> {
    match read_full_validation_provenance(data_dir) {
        Ok(record)
            if record.height == tip.height
                && record.tip_hash.eq_ignore_ascii_case(&tip.hash.to_string()) =>
        {
            Ok(())
        }
        Ok(record) => Err(OfflineImportError::ProvenanceResumeMismatch {
            tip_height: tip.height,
            record_height: record.height,
        }),
        Err(error) => Err(OfflineImportError::ProvenanceUnreadable {
            tip_height: tip.height,
            detail: error.to_string(),
        }),
    }
}

fn provenance_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FULL_VALIDATION_PROVENANCE_FILE)
}

fn read_full_validation_provenance(
    data_dir: &Path,
) -> Result<FullValidationProvenance, OfflineImportError> {
    let path = provenance_path(data_dir);
    let raw = std::fs::read(&path).map_err(|source| OfflineImportError::ProvenanceRead {
        path: path.clone(),
        source,
    })?;
    if raw.len() > 4096 {
        return Err(OfflineImportError::ProvenanceExceedsBound { path });
    }
    let doc: FullValidationProvenance =
        sonic_rs::from_slice(&raw).map_err(|source| OfflineImportError::ProvenanceJson {
            path: path.clone(),
            source,
        })?;
    if doc.schema != FULL_VALIDATION_PROVENANCE_SCHEMA {
        return Err(OfflineImportError::ProvenanceUnknownSchema { path });
    }
    Ok(doc)
}

fn write_full_validation_provenance(
    data_dir: &Path,
    tip: &bitcoin_rs_chain::chain::TipSnapshot,
) -> Result<(), OfflineImportError> {
    let doc = FullValidationProvenance {
        schema: FULL_VALIDATION_PROVENANCE_SCHEMA.to_owned(),
        height: tip.height,
        tip_hash: tip.hash.to_string(),
    };
    let mut raw = sonic_rs::to_vec_pretty(&doc)
        .map_err(|source| OfflineImportError::ProvenanceEncode { source })?;
    raw.push(b'\n');
    let tmp = data_dir.join(".offline-full-validation-provenance.json.tmp");
    std::fs::write(&tmp, &raw).map_err(|source| OfflineImportError::ProvenanceWrite {
        path: tmp.clone(),
        source,
    })?;
    File::open(&tmp)
        .map_err(|source| OfflineImportError::ProvenanceOpen {
            path: tmp.clone(),
            source,
        })?
        .sync_all()
        .map_err(|source| OfflineImportError::ProvenanceFsync {
            path: tmp.clone(),
            source,
        })?;
    std::fs::rename(&tmp, provenance_path(data_dir))
        .map_err(|source| OfflineImportError::ProvenancePublish { source })?;
    File::open(data_dir)
        .map_err(|source| OfflineImportError::DataDirOpen {
            path: data_dir.to_path_buf(),
            source,
        })?
        .sync_all()
        .map_err(|source| OfflineImportError::DataDirFsync {
            path: data_dir.to_path_buf(),
            source,
        })?;
    Ok(())
}

fn resolve_offline_validation_mode(
    _inherited: bitcoin_rs_chain::ValidationMode,
) -> bitcoin_rs_chain::ValidationMode {
    bitcoin_rs_chain::ValidationMode::Full
}

fn check_payload_against_entry(
    entry: &ManifestBlock,
    payload: &[u8],
) -> Result<(), OfflineImportError> {
    let header = payload
        .get(..HEADER_LEN)
        .ok_or(OfflineImportError::PayloadShorterThanHeader {
            height: entry.height,
        })?;
    let hash = bitcoin_rs_consensus::primitives::encode::double_sha256(header);
    if !hash.to_string().eq_ignore_ascii_case(&entry.hash) {
        return Err(OfflineImportError::BlockHeaderHashDiverged {
            height: entry.height,
        });
    }
    Ok(())
}

fn refuse_stale_persisted_indexes(data_dir: &Path) -> Result<(), OfflineImportError> {
    let namespace = data_dir.join("txindex");
    if !namespace_has_content(&namespace) {
        return Ok(());
    }
    Err(OfflineImportError::StalePersistedIndex { namespace })
}

fn namespace_has_content(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => std::fs::symlink_metadata(path).is_ok(),
    }
}

fn parse_magic_hex(text: &str) -> Result<[u8; 4], OfflineImportError> {
    bitcoin_rs_consensus::primitives::hex::hex_decode_array(text)
        .map_err(|_| OfflineImportError::ManifestMagicHex)
}

fn check_manifest_shape(doc: &Manifest) -> Result<(), OfflineImportError> {
    if doc.blocks.is_empty() {
        return Err(OfflineImportError::ManifestBlocksListEveryHeight);
    }
    if doc.stop_height < doc.start_height {
        return Err(OfflineImportError::ManifestStopBeforeStart);
    }
    let expected = usize::try_from(
        doc.stop_height
            .checked_sub(doc.start_height)
            .ok_or(OfflineImportError::ManifestStopBeforeStart)?
            .checked_add(1)
            .ok_or(OfflineImportError::ManifestRangeOverflow)?,
    )
    .map_err(|source| OfflineImportError::ManifestRangeDoesNotFit { source })?;
    if doc.blocks.len() != expected || doc.blocks.len() > 2_000_000 {
        return Err(OfflineImportError::ManifestBlocksListEveryHeight);
    }
    let mut cursor: u64 = 0;
    for (index, entry) in doc.blocks.iter().enumerate() {
        let index_height = u32::try_from(index)
            .map_err(|source| OfflineImportError::ManifestIndexDoesNotFit { source })?;
        if entry.height
            != doc
                .start_height
                .checked_add(index_height)
                .ok_or(OfflineImportError::ManifestHeightOverflow)?
        {
            return Err(OfflineImportError::ManifestHeightsNotContiguous);
        }
        if entry.payload_length < HEADER_LEN || entry.payload_length > MAX_PAYLOAD {
            return Err(OfflineImportError::ManifestEntryPayloadBounds);
        }
        if entry.hash.len() != 64 {
            return Err(OfflineImportError::ManifestEntryHashLength);
        }
        if entry.offset != cursor {
            return Err(OfflineImportError::ManifestEntryOffsetNotPacked);
        }
        cursor =
            cursor
                .checked_add(8)
                .ok_or(OfflineImportError::ManifestCursorOverflow)?
                .checked_add(u64::try_from(entry.payload_length).map_err(|source| {
                    OfflineImportError::ManifestPayloadLengthDoesNotFit { source }
                })?)
                .ok_or(OfflineImportError::ManifestCursorOverflow)?;
        if cursor > doc.archive_bytes {
            return Err(OfflineImportError::ManifestEntryOverrunsArchive);
        }
    }
    if cursor != doc.archive_bytes {
        return Err(OfflineImportError::ManifestDoesNotConsumeArchive);
    }
    Ok(())
}

fn verify_and_certify(
    node: &crate::state::NodeState,
    data_dir: &Path,
    manifest: &Manifest,
    state_path: &Path,
) -> Result<(), OfflineImportError> {
    let chainstate = node.chainstate();
    let tip = chainstate
        .applied_tip_snapshot()
        .ok_or(OfflineImportError::NoAppliedTip)?;
    let stop_entry = manifest
        .blocks
        .last()
        .ok_or(OfflineImportError::NoStopEntry)?;
    if tip.height != manifest.stop_height {
        return Err(OfflineImportError::AppliedTipStopMismatch);
    }
    if tip.height != stop_entry.height {
        return Err(OfflineImportError::AppliedTipStopEntryMismatch);
    }
    if !tip.hash.to_string().eq_ignore_ascii_case(&stop_entry.hash) {
        return Err(OfflineImportError::AppliedTipStopHashMismatch);
    }
    let body_store = chainstate
        .block_body_store_handle()
        .ok_or(OfflineImportError::NoBlockBodyStore)?;
    let body = body_store
        .load_block_body(tip.height, tip.hash)
        .map_err(|body_error| OfflineImportError::BodyProof { body_error })?;
    if body.is_none() {
        return Err(OfflineImportError::TipBodyUnavailable);
    }
    let request = bitcoin_rs_chain::verify::VerifyRequest {
        level: bitcoin_rs_chain::verify::CheckLevel::CheckUndoAndCommitments,
        depth: NonZeroU32::new(1),
        cancellation: None,
    };
    match bitcoin_rs_chain::verify::verify_recent_blocks(&chainstate, request) {
        Ok(bitcoin_rs_chain::verify::VerifyOutcome::Passed { .. }) => {}
        Ok(bitcoin_rs_chain::verify::VerifyOutcome::SkippedNoBlockData { height }) => {
            return Err(OfflineImportError::VerificationSkippedData { height });
        }
        Err(verify_error) => {
            return Err(OfflineImportError::VerificationFailed {
                verify_error: Box::new(verify_error),
            });
        }
    }
    let (txouts, total_amount_sat, muhash, set_hash) = node
        .chainstate()
        .utxo_reader()
        .with_stable_view(|view| {
            let stats = bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, tip.height, true)
                .map_err(|scan_error| OfflineImportError::CoinStatsScan { scan_error })?;
            let set_hash = view
                .hash_serialized_3()
                .map_err(|hash_error| OfflineImportError::HashSerialized3 { hash_error })?;
            Ok::<_, OfflineImportError>((
                u64::try_from(view.len()).map_err(|count_error| {
                    OfflineImportError::TxoutCountDoesNotFit { count_error }
                })?,
                stats.total_amount,
                stats.muhash.finalize_hash().to_string(),
                set_hash.to_string(),
            ))
        })
        .map_err(|source| OfflineImportError::StableViewRebuild { source })??;
    let certified = CertifiedState {
        height: tip.height,
        bestblock: tip.hash.to_string(),
        txouts,
        total_amount_sat,
        muhash,
        utxo_hash_serialized_3: set_hash,
        bodies_available: true,
        disconnect_ready: true,
    };
    let generation = node.publish_checkpoint().map_err(|checkpoint_error| {
        OfflineImportError::CheckpointPublicationFailed {
            checkpoint_error: Box::new(checkpoint_error),
        }
    })?;
    if generation.is_none() {
        return Err(OfflineImportError::CheckpointPublicationSkipped);
    }
    write_full_validation_provenance(data_dir, &tip)?;
    write_state(state_path, &certified)?;
    Ok(())
}

fn write_state(path: &Path, state: &CertifiedState) -> Result<(), OfflineImportError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| {
                OfflineImportError::StateDirCreate {
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| OfflineImportError::StateFileCreate {
            path: path.to_path_buf(),
            source,
        })?;
    let mut raw = sonic_rs::to_vec_pretty(state)
        .map_err(|source| OfflineImportError::StateEncode { source })?;
    raw.push(b'\n');
    file.write_all(&raw)
        .map_err(|source| OfflineImportError::StateFileWrite {
            path: path.to_path_buf(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| OfflineImportError::StateFileFsync {
            path: path.to_path_buf(),
            source,
        })?;
    drop(file);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let dir = File::open(parent).map_err(|source| OfflineImportError::StateDirOpen {
                path: parent.to_path_buf(),
                source,
            })?;
            dir.sync_all()
                .map_err(|source| OfflineImportError::StateDirFsync {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures panic on setup failure")]

    use super::*;

    fn entry(height: u32, hash: &str, offset: u64, len: usize) -> ManifestBlock {
        ManifestBlock {
            height,
            hash: hash.to_owned(),
            offset,
            payload_length: len,
        }
    }

    #[test]
    fn offline_import_assume_valid_height_bail_is_typed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = offline_import_config(&dir.path().join("node"));
        config.validation.assume_valid_height = 100;
        let error = run_offline_import(
            config,
            std::path::Path::new("corpus"),
            std::path::Path::new("manifest"),
            std::path::Path::new("state"),
        )
        .expect_err("nonzero assume-valid height must refuse offline import");
        assert!(
            matches!(error, OfflineImportError::AssumeValidHeightRequired),
            "assume-valid refusal must be OfflineImportError::AssumeValidHeightRequired, got: {error:?}"
        );
    }

    #[test]
    fn offline_import_auxiliary_indexes_bail_is_typed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = offline_import_config(&dir.path().join("node"));
        config.indexes.txindex = true;
        let error = run_offline_import(
            config,
            std::path::Path::new("corpus"),
            std::path::Path::new("manifest"),
            std::path::Path::new("state"),
        )
        .expect_err("enabled txindex must refuse offline import");
        assert!(
            matches!(error, OfflineImportError::AuxiliaryIndexesRequiredOff),
            "index refusal must be OfflineImportError::AuxiliaryIndexesRequiredOff, got: {error:?}"
        );
    }

    #[test]
    fn manifest_shape_rejects_gaps() {
        let doc = Manifest {
            network: "mainnet".to_owned(),
            network_magic: "f9beb4d9".to_owned(),
            start_height: 0,
            stop_height: 1,
            archive_sha256: "ab".repeat(32),
            archive_bytes: 200,
            blocks: vec![
                entry(0, &"ab".repeat(32), 0, 90),
                entry(0, &"ab".repeat(32), 98, 90),
            ],
        };
        assert!(check_manifest_shape(&doc).is_err());
    }

    #[test]
    fn manifest_shape_rejects_unpacked_offset() {
        let doc = Manifest {
            network: "mainnet".to_owned(),
            network_magic: "f9beb4d9".to_owned(),
            start_height: 0,
            stop_height: 0,
            archive_sha256: "ab".repeat(32),
            archive_bytes: 98,
            blocks: vec![entry(0, &"ab".repeat(32), 8, 90)],
        };
        assert!(check_manifest_shape(&doc).is_err());
    }

    #[test]
    fn magic_hex_rejects_short_input() {
        assert!(parse_magic_hex("f9be").is_err());
        assert_eq!(
            parse_magic_hex("f9beb4d9").expect("valid magic"),
            [0xf9, 0xbe, 0xb4, 0xd9]
        );
    }

    #[test]
    fn manifest_reader_rejects_non_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, b"not json").expect("write");
        assert!(read_manifest(&path).is_err());
    }

    #[test]
    fn corpus_open_rejects_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(open_corpus(dir.path()).is_err());
    }

    #[test]
    fn state_writer_refuses_to_clobber() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let state = CertifiedState {
            height: 1,
            bestblock: "ab".repeat(32),
            txouts: 2,
            total_amount_sat: 5_000_000_000,
            muhash: "cd".repeat(32),
            utxo_hash_serialized_3: "ef".repeat(32),
            bodies_available: true,
            disconnect_ready: true,
        };
        write_state(&path, &state).expect("first write");
        assert!(write_state(&path, &state).is_err());
    }
    fn corpus_manifest_bytes(network: &str, magic: &str) -> Vec<u8> {
        format!(
            concat!(
                r#"{{"archive":{{"sha256":"{archive}","size":196}},"corpus_id":"C150","entries":"#,
                r#"[{{"height":100,"hash":"{h0}","offset":0,"payload_length":90}},"#,
                r#"{{"height":101,"hash":"{h1}","offset":98,"payload_length":90}}],"#,
                r#""genesis_hash":"{h0}","manifest_sha256":"{msha}","#,
                r#""network":"{network}","network_magic":"{magic}","#,
                r#""range":{{"start_height":100,"stop_height":101}},"#,
                r#""schema":"bitcoin-rs-corpus-manifest","#,
                r#""source_tip_hash":"{h1}","version":1}}"#
            ),
            archive = "ab".repeat(32),
            h0 = "ab".repeat(32),
            h1 = "cd".repeat(32),
            msha = "00".repeat(32),
            network = network,
            magic = magic,
        )
        .into_bytes()
    }

    #[test]
    fn corpus_schema_normalizes_to_internal_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, corpus_manifest_bytes("regtest", "fabfb5da")).expect("write");
        let doc = read_manifest(&path).expect("corpus manifest parses");
        assert_eq!(doc.network, "regtest");
        assert_eq!(doc.start_height, 100);
        assert_eq!(doc.stop_height, 101);
        assert_eq!(doc.archive_bytes, 196);
        assert_eq!(doc.blocks.len(), 2);
        assert_eq!(doc.blocks[0].height, 100);
        assert_eq!(doc.blocks[1].offset, 98);
        assert!(check_manifest_shape(&doc).is_ok());
    }

    #[test]
    fn manifest_reader_rejects_unknown_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            br#"{"schema":"unknown-manifest-v9","network":"regtest","network_magic":"fabfb5da","start_height":0,"stop_height":0,"archive_sha256":"ab","archive_bytes":0,"blocks":[]}"#,
        )
        .expect("write");
        assert!(read_manifest(&path).is_err());
    }

    #[test]
    fn manifest_reader_rejects_unsupported_corpus_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        let mut raw = corpus_manifest_bytes("regtest", "fabfb5da");
        let text = String::from_utf8(raw.clone()).expect("utf8");
        raw = text
            .replace(r#""version":1"#, r#""version":2"#)
            .into_bytes();
        std::fs::write(&path, raw).expect("write");
        assert!(read_manifest(&path).is_err());
    }

    #[test]
    fn manifest_network_matches_configured_identity() {
        let regtest = bitcoin_rs_consensus::primitives::Network::Regtest.identity_name();
        assert_eq!(regtest, "regtest");
        let doc = Manifest {
            network: "regtest".to_owned(),
            network_magic: "fabfb5da".to_owned(),
            start_height: 100,
            stop_height: 101,
            archive_sha256: "ab".repeat(32),
            archive_bytes: 196,
            blocks: vec![
                entry(100, &"ab".repeat(32), 0, 90),
                entry(101, &"cd".repeat(32), 98, 90),
            ],
        };
        assert!(check_manifest_network(&doc, regtest).is_ok());
        assert!(check_manifest_network(&doc, "mainnet").is_err());
    }

    #[test]
    fn offline_import_pins_full_validation_mode() {
        use bitcoin_rs_chain::ValidationMode;
        for inherited in [ValidationMode::Full, ValidationMode::AssumeValid] {
            assert_eq!(
                resolve_offline_validation_mode(inherited),
                ValidationMode::Full
            );
        }
    }

    fn binding_entry(height: u32, hash: &str) -> ManifestBlock {
        entry(height, hash, 0, HEADER_LEN)
    }

    fn header_hash_hex(header: &[u8; HEADER_LEN]) -> String {
        bitcoin_rs_consensus::primitives::encode::double_sha256(header).to_string()
    }

    #[test]
    fn connected_records_stay_bound_to_the_manifest() {
        let header = [7u8; HEADER_LEN];
        let doc_hash = header_hash_hex(&header);
        let good = binding_entry(3, &doc_hash);
        let mut payload = header.to_vec();
        check_payload_against_entry(&good, &payload).expect("bound record");
        let upper = binding_entry(3, &doc_hash.to_ascii_uppercase());
        check_payload_against_entry(&upper, &payload).expect("case-insensitive");
        payload[10] ^= 0x01;
        assert!(check_payload_against_entry(&good, &payload).is_err());
        let wrong = binding_entry(3, &"ab".repeat(32));
        assert!(check_payload_against_entry(&wrong, &header).is_err());
        let runt = binding_entry(3, &doc_hash);
        assert!(check_payload_against_entry(&runt, &header[..HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn offline_import_refuses_stale_persisted_index_namespace() {
        let fresh = tempfile::tempdir().expect("tempdir");
        refuse_stale_persisted_indexes(fresh.path()).expect("absent namespace");
        std::fs::create_dir(fresh.path().join("txindex")).expect("empty namespace");
        refuse_stale_persisted_indexes(fresh.path()).expect("empty namespace");
        std::fs::write(fresh.path().join("txindex").join("CURRENT"), b"stale")
            .expect("seed stale row");
        assert!(refuse_stale_persisted_indexes(fresh.path()).is_err());
        let stray = tempfile::tempdir().expect("tempdir");
        std::fs::write(stray.path().join("txindex"), b"stale").expect("seed stray file");
        assert!(refuse_stale_persisted_indexes(stray.path()).is_err());
    }

    struct TwoBlockArchive {
        blocks: Vec<bitcoin_rs_consensus::primitives::Block>,
        corpus: Vec<u8>,
        manifest: Vec<u8>,
        stop_hash: String,
    }

    fn two_block_archive() -> TwoBlockArchive {
        use sha2::Digest as _;
        let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
        let child = bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_child_at(
            genesis.block_hash(),
            1,
        )
        .expect("mine child");
        let blocks = vec![genesis, child];
        let magic = bitcoin_rs_consensus::primitives::Network::Regtest.magic();
        let mut corpus = Vec::new();
        let mut entries = Vec::new();
        let mut offset: u64 = 0;
        for (index, block) in blocks.iter().enumerate() {
            let payload = bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone());
            let raw = payload.bytes();
            let mut framed = Vec::with_capacity(8 + raw.len());
            framed.extend_from_slice(&magic);
            framed.extend_from_slice(
                &u32::try_from(raw.len())
                    .expect("payload fits")
                    .to_le_bytes(),
            );
            framed.extend_from_slice(raw);
            entries.push(format!(
                r#"{{"height":{index},"hash":"{hash}","offset":{offset},"payload_length":{len}}}"#,
                index = u32::try_from(index).expect("index fits"),
                hash = block.block_hash(),
                len = raw.len()
            ));
            offset += u64::try_from(framed.len()).expect("offset fits");
            corpus.extend_from_slice(&framed);
        }
        let mut hasher = sha2::Sha256::new();
        hasher.update(&corpus);
        let manifest = format!(
            r#"{{"schema":"core-framed-archive-manifest-v1","network":"regtest","network_magic":"fabfb5da","start_height":0,"stop_height":1,"archive_sha256":"{digest}","archive_bytes":{bytes},"blocks":[{blocks}]}}"#,
            digest = bitcoin_rs_consensus::primitives::hex::hex_encode(&hasher.finalize()),
            bytes = corpus.len(),
            blocks = entries.join(",")
        );
        let stop_hash = blocks[1].block_hash().to_string();
        TwoBlockArchive {
            blocks,
            corpus,
            manifest: manifest.into_bytes(),
            stop_hash,
        }
    }

    fn offline_import_config(data_dir: &std::path::Path) -> crate::NodeConfig {
        let mut config = crate::NodeConfig::default_for_network(
            bitcoin_rs_consensus::primitives::Network::Regtest,
        );
        config.data_dir = data_dir.to_path_buf();
        config.p2p.listen.clear();
        config
    }

    fn write_archive_fixture(
        dir: &std::path::Path,
        archive: &TwoBlockArchive,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let corpus = dir.join("corpus.bin");
        let manifest = dir.join("manifest.json");
        std::fs::write(&corpus, &archive.corpus).expect("write corpus");
        std::fs::write(&manifest, &archive.manifest).expect("write manifest");
        (corpus, manifest)
    }

    #[test]
    fn offline_import_fresh_dir_validates_and_records_provenance() {
        let archive = two_block_archive();
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("node");
        let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
        let state = dir.path().join("state.json");
        run_offline_import(offline_import_config(&data_dir), &corpus, &manifest, &state)
            .expect("fresh import succeeds");
        let record = read_full_validation_provenance(&data_dir).expect("provenance recorded");
        assert_eq!(record.height, 1, "provenance binds the certified tip");
        assert!(
            record.tip_hash.eq_ignore_ascii_case(&archive.stop_hash),
            "provenance binds the certified tip hash"
        );
        let text = String::from_utf8(std::fs::read(&state).expect("read state")).expect("utf8");
        assert!(text.contains("\"height\": 1"), "state certifies height 1");
        assert!(
            text.contains(&archive.stop_hash),
            "state certifies the archive tip"
        );
    }

    #[test]
    fn offline_import_certified_dir_resumes_idempotently() {
        let archive = two_block_archive();
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("node");
        let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
        run_offline_import(
            offline_import_config(&data_dir),
            &corpus,
            &manifest,
            &dir.path().join("state.json"),
        )
        .expect("first import succeeds");
        let resume_state = dir.path().join("state-resume.json");
        run_offline_import(
            offline_import_config(&data_dir),
            &corpus,
            &manifest,
            &resume_state,
        )
        .expect("certified directory resumes");
        let text =
            String::from_utf8(std::fs::read(&resume_state).expect("read state")).expect("utf8");
        assert!(
            text.contains("\"height\": 1"),
            "resume still certifies height 1"
        );
        assert!(
            text.contains(&archive.stop_hash),
            "resume still certifies the archive tip"
        );
    }

    #[test]
    fn offline_import_refuses_tip_without_provenance() {
        let archive = two_block_archive();
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("node");
        {
            let live = crate::state::NodeState::open(offline_import_config(&data_dir), None)
                .expect("open node");
            for block in &archive.blocks {
                live.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block.clone(),
                ))
                .expect("connect");
            }
        }
        let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
        let error = run_offline_import(
            offline_import_config(&data_dir),
            &corpus,
            &manifest,
            &dir.path().join("state.json"),
        )
        .expect_err("tip without provenance refuses");
        let message = error.to_string();
        assert!(
            message.contains("provenance") && message.contains("fresh data directory"),
            "refusal must name provenance and the remedy, got: {message}"
        );
    }

    #[test]
    fn network_magic_refuses_non_hex_without_panicking() {
        assert_eq!(
            parse_magic_hex("f9beb4d9").expect("hex"),
            [0xf9, 0xbe, 0xb4, 0xd9]
        );
        assert!(parse_magic_hex("\u{e9}\u{e9}f9be").is_err());
        assert!(parse_magic_hex("+fbeb4d9").is_err());
        assert!(parse_magic_hex("f9beb4d").is_err());
    }

    #[test]
    fn manifest_read_refuses_oversized_input_without_buffering_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, [b' '; 17]).expect("manifest");
        assert_eq!(read_bounded(&path, 17).expect("at bound").len(), 17);
        let error = read_bounded(&path, 16).expect_err("oversized manifest");
        assert!(
            matches!(error, OfflineImportError::ManifestExceedsBound),
            "{error:?}"
        );
    }

    #[test]
    fn offline_import_classifies_malformed_coin_row_as_stable_view_rebuild() {
        let archive = two_block_archive();
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("node");
        let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
        let state_path = dir.path().join("state.json");
        let mut config = offline_import_config(&data_dir);
        config.storage.backend = bitcoin_rs_storage::StorageBackend::RocksDb;

        run_offline_import(config.clone(), &corpus, &manifest, &state_path)
            .expect("initial offline import succeeds");
        let state_before = std::fs::read(&state_path).expect("read certified state");
        let provenance_before =
            std::fs::read(provenance_path(&data_dir)).expect("read certification provenance");

        {
            use bitcoin_rs_storage::KvStore as _;

            let store = bitcoin_rs_storage::RocksDbStore::open(data_dir.join("chainstate"))
                .expect("open configured RocksDB chainstate");
            let malformed_key = [0xa5_u8; 32];
            store
                .put(
                    bitcoin_rs_storage::ColumnFamily::Coins,
                    &malformed_key,
                    b"malformed",
                )
                .expect("insert malformed coin row");
            store.flush().expect("flush malformed coin row");
        }

        let resume_state = dir.path().join("state-resume.json");
        let error = run_offline_import(config, &corpus, &manifest, &resume_state)
            .expect_err("malformed coin row must refuse certification");
        match error {
            OfflineImportError::StableViewRebuild { source } => {
                assert!(
                    matches!(&source, bitcoin_rs_storage::utxo::UtxoError::CorruptRecord),
                    "stable-view failure must preserve the corrupt-record source, got {source:?}"
                );
            }
            other => {
                panic!("malformed coin row must fail during stable-view rebuild, got {other:?}")
            }
        }
        assert_eq!(
            std::fs::read(&state_path).expect("read certified state after refusal"),
            state_before,
            "certified state must remain unchanged on refusal"
        );
        assert_eq!(
            std::fs::read(provenance_path(&data_dir)).expect("read provenance after refusal"),
            provenance_before,
            "certification provenance must remain unchanged on refusal"
        );
        assert!(
            !resume_state.exists(),
            "refusal must not write a replacement certified state"
        );
    }
}
