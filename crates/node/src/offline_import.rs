//! Foreground offline import for the strict full-validation comparator.
//!
//! Consistency: chain mutation holds the exclusive chain-transition lock
//! (linearizable single-writer per transition); certified reads use the
//! stable whole-set view (snapshot isolation over the UTXO set, blocking
//! commits for the scan); the manifest plus archive pin is bound by hash
//! (a transactional outbox is unnecessary here because publication is a
//! single atomic `create_new` state file after the checkpoint, and reruns
//! either resume by tip comparison under a matching full-validation
//! provenance record or are refused, so no exactly-once delivery is
//! assumed).
//!
//! Consumes the single regular Core-framed archive file bound by
//! `{corpus_path}` (the custody archive pin, parity-bound to the indexed
//! logical stream), the manifest at `{manifest_path}`, and the output state
//! path at `{state_path}`, all alongside the resolved [`NodeConfig`].
//!
//! Asymmetry is explicit: Bitcoin Core consumes the same file through its
//! checked-in `-loadblock` family (`bitcoin-core/src/init.cpp:529`,
//! `2128-2136` into `ImportBlocks`, `bitcoin-core/src/node/blockstorage.cpp:1270`,
//! `bitcoin-core/src/validation.cpp:4975` `LoadExternalBlockFile`); this
//! module is the bitcoin-rs counterpart. It never takes the custody
//! `sources` directory: that directory holds multiple `blkNNNNN.dat` files
//! while the timed command expects one regular corpus file.
//!
//! Guarantees: exact bytes (framing walk plus per-record manifest binding
//! plus archive digest, verified for skipped prefix records and on reopen
//! too), full validation (`--assume-valid-height 0` with the validation mode
//! pinned to `Full` instead of any inherited live mode, indexes off, no
//! stale persisted derived-index namespace, and no resumed prefix without a
//! matching full-validation provenance record), durable bodies plus undo
//! (authoritative commit path), production clean checkpoint (nonzero when
//! publication fails), foreground only (no fork, no daemonize, no spawned
//! descendants), and an eight-field certified state. Reopen against the same
//! data directory resumes the applied prefix only when the provenance record
//! this importer wrote at certification matches the applied tip; otherwise
//! the rerun is refused and the operator revalidates from a fresh directory.

use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use sha2::Digest as _;

use crate::NodeConfig;

/// Accepted manifest schemas (subsets used here).
///
/// The authoritative C150 archive producer writes
/// `bitcoin-rs-corpus-manifest` version 1 with `archive {sha256,size}`,
/// `range {start_height,stop_height}`, and `entries`; the comparator-facing
/// shape is `core-framed-archive-manifest-v1` with `archive_sha256`,
/// `archive_bytes`, `start_height`/`stop_height`, and `blocks`. Both
/// normalize into the internal [`Manifest`]; unknown schemas and
/// unsupported corpus versions are refused at the boundary.
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

/// Typed untagged view over the two accepted on-disk shapes. Extra
/// producer members (`corpus_id`, `genesis_hash`, `manifest_sha256`,
/// `source_tip_hash`) are ignored here; pinning beyond archive identity
/// stays with the producer and the comparator.
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

/// Certified state written to `{state_path}` (matches the comparator).
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
/// Byte bound on the manifest, enforced while reading so an oversized or
/// unbounded path (a device, a huge file) is refused without buffering it.
const MAX_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;

/// Runs the foreground offline import and writes the certified state.
///
/// PRE: `corpus`, `manifest`, and `state` are the expanded placeholder
/// paths; `config` carries `--assume-valid-height 0` with auxiliary
/// indexes off.
/// POST: every archive record is validated and connected, bodies plus undo
/// are durable, the production clean checkpoint is published, and `state`
/// holds the eight certified fields.
/// INVARIANT: no background workers start, no child is spawned, and any
/// refusal fails closed with a nonzero exit (the caller maps `Err` to
/// `ExitCode::FAILURE`).
pub fn run_offline_import(
    mut config: NodeConfig,
    corpus: &Path,
    manifest: &Path,
    state: &Path,
) -> Result<()> {
    if config.validation.assume_valid_height != 0 {
        bail!("offline import requires --assume-valid-height 0 for full validation");
    }
    // Offline fast-forward never inherits a live validation mode: the
    // comparator contract carries no validation-mode token and the default
    // mode skips scripts, so the mode is pinned here, before the chainstate
    // opens, instead of flowing from operator config.
    config.validation.mode = resolve_offline_validation_mode(config.validation.mode);
    if config.indexes.txindex
        || config.indexes.blockfilterindex
        || config.indexes.script_index.is_enabled()
    {
        bail!("offline import requires auxiliary indexes off");
    }
    refuse_stale_persisted_indexes(&config.data_dir)?;
    let manifest_doc = read_manifest(manifest)?;
    let expected_magic = config.network.magic();
    let manifest_magic = parse_magic_hex(&manifest_doc.network_magic)?;
    if manifest_magic != expected_magic {
        bail!("manifest network magic does not match the node network");
    }
    check_manifest_network(&manifest_doc, config.network.identity_name())?;
    check_manifest_shape(&manifest_doc)?;

    let data_dir = config.data_dir.clone();
    let node = crate::state::NodeState::open(config, None)?;
    let chainstate = node.chainstate();

    let already = chainstate.applied_tip_snapshot();
    let skip = match already.as_ref() {
        None => 0usize,
        Some(tip) => {
            let height = tip.height;
            let entry_index = block_index_for_height(manifest_doc.start_height, height)?;
            let entry = manifest_doc.blocks.get(entry_index).with_context(|| {
                format!("applied tip height {height} is outside the manifest range")
            })?;
            if entry.height != height {
                bail!("applied tip height does not match the manifest entry");
            }
            if !entry.hash.eq_ignore_ascii_case(&tip.hash.to_string()) {
                bail!("applied tip hash does not match the manifest entry");
            }
            // Fail closed on provenance: `TipSnapshot`/`DurableHead` record
            // height, hash, work, and transaction count but not the
            // `ValidationMode` that committed the prefix, so a prefix
            // connected under `AssumeValid`/`Fast` (scripts skipped) is
            // indistinguishable from a `Full` one. The skip below runs only
            // when this importer's provenance record binds the same tip;
            // otherwise the rerun is refused and the operator revalidates
            // from a fresh data directory.
            require_full_validation_provenance(&data_dir, tip)?;
            if height == manifest_doc.stop_height {
                // Tip already current: connect nothing, but still walk the
                // archive below so the reopen re-binds every record and the
                // digest instead of trusting the bytes it skips.
                manifest_doc.blocks.len()
            } else {
                let next = height.checked_add(1).context("applied tip overflow")?;
                block_index_for_height(manifest_doc.start_height, next)?
            }
        }
    };

    let mut stream = open_corpus(corpus)?;
    let mut hasher = sha2::Sha256::new();
    let mut total: u64 = 0;
    let mut payloads: Vec<bitcoin_rs_primitives::BlockPayload> = Vec::new();
    for (index, entry) in manifest_doc.blocks.iter().enumerate() {
        let record = read_record(&mut stream, expected_magic, entry)?;
        // Per-record binding runs before the resume skip: already-applied
        // prefix bytes stay bound to their indexed entry instead of coasting
        // on framing plus the trailing digest.
        check_payload_against_entry(entry, &record.payload)?;
        hasher.update(&record.framed);
        total += u64::try_from(record.framed.len()).context("record length does not fit")?;
        if index < skip {
            continue;
        }
        let payload = bitcoin_rs_primitives::BlockPayload::from_raw(Bytes::from(record.payload))
            .map_err(|error| {
                anyhow::anyhow!("block at height {} does not decode: {error}", entry.height)
            })?;
        if !payload
            .block()
            .block_hash()
            .to_string()
            .eq_ignore_ascii_case(&entry.hash)
        {
            bail!("block at height {} header hash diverged", entry.height);
        }
        payloads.push(payload);
        if payloads.len() >= 128 {
            connect_batch(&node, &mut payloads)?;
        }
    }
    if !payloads.is_empty() {
        connect_batch(&node, &mut payloads)?;
    }
    let trailing = {
        let mut one = [0u8; 1];
        match stream.file.read(&mut one) {
            Ok(0) => false,
            Ok(_) => true,
            Err(error) => bail!("cannot check archive trailing bytes: {error}"),
        }
    };
    if trailing {
        bail!("archive contains trailing bytes after the last record");
    }
    if total != manifest_doc.archive_bytes {
        bail!("archive size does not match the manifest");
    }
    let digest = bitcoin_rs_primitives::encode::hex_encode(&hasher.finalize());
    if digest != manifest_doc.archive_sha256.to_ascii_lowercase() {
        bail!("archive digest does not match the manifest");
    }

    verify_and_certify(&node, &data_dir, &manifest_doc, state)?;
    Ok(())
}

struct FramedRecord {
    framed: Vec<u8>,
    payload: Vec<u8>,
}

struct CorpusStream {
    file: File,
}

fn open_corpus(path: &Path) -> Result<CorpusStream> {
    let file =
        File::open(path).with_context(|| format!("cannot open corpus {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot stat corpus {}", path.display()))?;
    if !metadata.is_file() {
        bail!("corpus is not a regular file");
    }
    Ok(CorpusStream { file })
}

fn read_record(
    stream: &mut CorpusStream,
    expected_magic: [u8; 4],
    entry: &ManifestBlock,
) -> Result<FramedRecord> {
    if entry.payload_length < HEADER_LEN || entry.payload_length > MAX_PAYLOAD {
        bail!(
            "manifest entry at height {} is outside consensus bounds",
            entry.height
        );
    }
    let mut header = [0u8; 8];
    stream.file.read_exact(&mut header).with_context(|| {
        format!(
            "archive ended inside record header at height {}",
            entry.height
        )
    })?;
    if header[..4] != expected_magic {
        bail!(
            "archive record at height {} has the wrong network magic",
            entry.height
        );
    }
    let length = usize::try_from(u32::from_le_bytes([
        header[4], header[5], header[6], header[7],
    ]))
    .context("record length does not fit")?;
    if length != entry.payload_length {
        bail!("archive record at height {} length diverged", entry.height);
    }
    let mut payload = vec![0u8; length];
    stream.file.read_exact(&mut payload).with_context(|| {
        format!(
            "archive ended inside block payload at height {}",
            entry.height
        )
    })?;
    let mut framed = Vec::with_capacity(8 + length);
    framed.extend_from_slice(&header);
    framed.extend_from_slice(&payload);
    Ok(FramedRecord { framed, payload })
}

/// Connects one batch of archive blocks, relieving journal retention pressure
/// inline.
///
/// The foreground import runs no maintenance worker, so a retention-limit
/// refusal would otherwise abort the whole import even though the refused
/// block committed nothing and the tip is unchanged. On a
/// [`bitcoin_rs_chainstate::ApplyError::JournalBackpressure`] refusal
/// carrying a retention limit, this publishes one synchronous clean
/// checkpoint — the same foreground publication the import performs at the
/// end, which compacts the journal — and retries the uncommitted block
/// exactly once. Any other failure, a skipped publication (no applied tip to
/// checkpoint), or a second refusal propagates.
///
/// Neither the refused attempt nor the checkpoint moves the applied tip, so
/// the inline retry resumes from the same durable state. A cross-process
/// rerun over the same data directory resumes by tip comparison only under
/// a matching provenance record; without one it is refused, so the operator
/// wipes the data directory and revalidates from genesis.
fn connect_batch(
    node: &crate::state::NodeState,
    batch: &mut Vec<bitcoin_rs_primitives::BlockPayload>,
) -> Result<()> {
    let chainstate = node.chainstate();
    let followers = node.chain_followers();
    for payload in batch.drain(..) {
        let hash = payload.block().block_hash();
        if let Err(error) = followers.apply_connect(&chainstate, &payload) {
            let retention_limited = matches!(
                &error,
                crate::ConnectMutationError::NotCommitted(
                    bitcoin_rs_chainstate::ApplyError::JournalBackpressure(inner)
                ) if matches!(
                    inner.as_ref(),
                    bitcoin_rs_storage::chainstate_journal::JournalWriterError::RetentionLimit { .. }
                )
            );
            if !retention_limited {
                bail!("connect at block {hash} failed: {error}");
            }
            let generation = node.publish_checkpoint().with_context(|| {
                format!("journal backpressure relief checkpoint failed at block {hash}")
            })?;
            if generation.is_none() {
                bail!(
                    "journal backpressure relief checkpoint skipped at block {hash}: no applied tip"
                );
            }
            tracing::info!(
                %hash,
                "compacted the chainstate journal during offline import; retrying the refused block"
            );
            followers
                .apply_connect(&chainstate, &payload)
                .map_err(|error| anyhow::anyhow!("connect at block {hash} failed: {error}"))?;
        }
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Manifest> {
    let raw = read_bounded(path, MAX_MANIFEST_BYTES)?;
    // No duplicate-key `Value` is used here: the manifest is decoded into
    // typed structs with contiguous-height and packed-offset checks, so a
    // duplicated key cannot smuggle a second chain view.
    let raw_doc: RawManifest = sonic_rs::from_slice(&raw)
        .with_context(|| format!("manifest {} is not valid JSON", path.display()))?;
    raw_doc.normalize()
}

/// Reads at most `limit` bytes, refusing a longer input before buffering
/// more than one byte past the bound.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file =
        File::open(path).with_context(|| format!("cannot read manifest {}", path.display()))?;
    let mut raw = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut raw)
        .with_context(|| format!("cannot read manifest {}", path.display()))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > limit {
        bail!("manifest exceeds its byte bound");
    }
    Ok(raw)
}

impl RawManifest {
    fn normalize(self) -> Result<Manifest> {
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
                    bail!("manifest schema must be {CORE_FRAMED_SCHEMA}");
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
                    bail!("manifest schema must be {CORPUS_SCHEMA}");
                }
                if version != CORPUS_VERSION {
                    bail!("manifest version {version} is not supported");
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

fn check_manifest_network(doc: &Manifest, expected_network: &str) -> Result<()> {
    if doc.network != expected_network {
        bail!("manifest network does not match the node network");
    }
    Ok(())
}

/// Sidecar binding the applied tip this importer fully validated.
///
/// The persisted tip (`TipSnapshot`) and commit point (`DurableHead`) record
/// height, hash, work, and transaction count, but not the `ValidationMode`
/// that committed each block. A prefix connected under `AssumeValid`
/// (scripts skipped below the anchor while the gate trusted it) or `Fast`
/// (scripts skipped below the header tip) is therefore indistinguishable at
/// reopen from one connected under `Full`. This record closes that gap: it is
/// written only after this importer certifies the tip under the pinned
/// `Full` mode, and a resume skips its prefix only while the record still
/// binds the same tip.
const FULL_VALIDATION_PROVENANCE_FILE: &str = "offline-full-validation-provenance.json";
const FULL_VALIDATION_PROVENANCE_SCHEMA: &str = "offline-full-validation-provenance-v1";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct FullValidationProvenance {
    schema: String,
    height: u32,
    tip_hash: String,
}

/// Maps an absolute block height to its position in the packed
/// `blocks`/`entries` array. Both the reopen entry lookup and the skip
/// count after a tip at `height` go through this coordinate, so a resume
/// at height `H` over a range starting at `S` reads entry `H - S` and
/// skips `H + 1 - S` records. For `S == 0` this is the old `height` /
/// `height + 1` behavior exactly.
fn block_index_for_height(start_height: u32, height: u32) -> Result<usize> {
    let offset = height
        .checked_sub(start_height)
        .with_context(|| format!("applied tip height {height} is outside the manifest range"))?;
    usize::try_from(offset).context("tip height does not fit")
}

/// Allows the resume skip only while the provenance record binds the tip.
///
/// Refuses when the record is absent, unreadable, the wrong schema, or names
/// a different tip: a normal live run under `AssumeValid`/`Fast` leaves no
/// such record, and a stale record (older certification, foreign data dir,
/// torn write) never matches the current tip. Failing closed here keeps the
/// skip from certifying unexecuted scripts as fully validated; the remedy is
/// a fresh data directory, which revalidates every record from genesis.
fn require_full_validation_provenance(
    data_dir: &Path,
    tip: &bitcoin_rs_chain::TipSnapshot,
) -> Result<()> {
    match read_full_validation_provenance(data_dir) {
        Ok(record)
            if record.height == tip.height
                && record.tip_hash.eq_ignore_ascii_case(&tip.hash.to_string()) =>
        {
            Ok(())
        }
        Ok(record) => bail!(
            "offline import refuses to resume over the applied tip at height {}: the full-validation provenance record binds height {} and no longer matches this tip, so revalidate from a fresh data directory",
            tip.height,
            record.height
        ),
        Err(error) => bail!(
            "offline import refuses to resume over the applied tip at height {}: no readable full-validation provenance record ({error:#}), so revalidate from a fresh data directory",
            tip.height
        ),
    }
}

fn provenance_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FULL_VALIDATION_PROVENANCE_FILE)
}

fn read_full_validation_provenance(data_dir: &Path) -> Result<FullValidationProvenance> {
    let path = provenance_path(data_dir);
    let raw = std::fs::read(&path)
        .with_context(|| format!("cannot read provenance {}", path.display()))?;
    if raw.len() > 4096 {
        bail!("provenance {} exceeds its bound", path.display());
    }
    let doc: FullValidationProvenance = sonic_rs::from_slice(&raw)
        .with_context(|| format!("provenance {} is not valid JSON", path.display()))?;
    if doc.schema != FULL_VALIDATION_PROVENANCE_SCHEMA {
        bail!("provenance {} has an unknown schema", path.display());
    }
    Ok(doc)
}

/// Atomically publishes the full-validation provenance for `tip`.
///
/// The tmp-file plus rename keeps a torn write from ever reading as a
/// match: a crash between write and rename leaves the previous record (or
/// none), and the resume gate refuses anything but an exact tip bind.
fn write_full_validation_provenance(
    data_dir: &Path,
    tip: &bitcoin_rs_chain::TipSnapshot,
) -> Result<()> {
    let doc = FullValidationProvenance {
        schema: FULL_VALIDATION_PROVENANCE_SCHEMA.to_owned(),
        height: tip.height,
        tip_hash: tip.hash.to_string(),
    };
    let mut raw = sonic_rs::to_vec_pretty(&doc).context("cannot encode provenance")?;
    raw.push(b'\n');
    let tmp = data_dir.join(".offline-full-validation-provenance.json.tmp");
    std::fs::write(&tmp, &raw)
        .with_context(|| format!("cannot write provenance {}", tmp.display()))?;
    File::open(&tmp)
        .with_context(|| format!("cannot open provenance {}", tmp.display()))?
        .sync_all()
        .with_context(|| format!("cannot fsync provenance {}", tmp.display()))?;
    std::fs::rename(&tmp, provenance_path(data_dir)).context("cannot publish provenance")?;
    File::open(data_dir)
        .with_context(|| format!("cannot open data dir {}", data_dir.display()))?
        .sync_all()
        .with_context(|| format!("cannot fsync data dir {}", data_dir.display()))?;
    Ok(())
}

/// Pins the offline-import validation mode, refusing to inherit.
///
/// Every incoming mode maps to `Full`: the certified state claims full
/// script validation, so fast-forward must execute every script regardless
/// of the live posture the operator config carries. There is no refusal
/// here because the comparator contract carries no validation-mode token
/// (its default resolves to `AssumeValid`); silently inheriting that
/// default would be the accident this pin prevents.
fn resolve_offline_validation_mode(
    _inherited: bitcoin_rs_chainstate::ValidationMode,
) -> bitcoin_rs_chainstate::ValidationMode {
    bitcoin_rs_chainstate::ValidationMode::Full
}

/// Binds one archive record to its manifest block index.
///
/// Framing (`read_record`) proves network magic and length only, and the
/// trailing archive digest binds bytes late. This check binds early and per
/// record: the payload's header hash must equal the indexed entry hash,
/// including records the resume cursor skips.
fn check_payload_against_entry(entry: &ManifestBlock, payload: &[u8]) -> Result<()> {
    let header = payload
        .get(..HEADER_LEN)
        .with_context(|| format!("block at height {} is shorter than a header", entry.height))?;
    // The same computation `Block::block_hash` performs, in `Display` order
    // to match the indexed entry hash.
    let hash = bitcoin_rs_primitives::encode::double_sha256(header);
    if !hash.to_string().eq_ignore_ascii_case(&entry.hash) {
        bail!("block at height {} header hash diverged", entry.height);
    }
    Ok(())
}

/// Refuses when the data dir carries persisted derived-index content that
/// this index-off import will neither maintain nor revalidate.
///
/// [`crate::state::NodeState::open`] leaves the derived-index host disabled
/// under the posture gate above, so a `<data_dir>/txindex` namespace left by
/// an earlier index-enabled run would sit untouched while the chainstate tip
/// moves underneath it. The documented revalidation path is a normal indexed
/// start, whose worker startup reconciles (rewind or rebuild from retained
/// canonical chainstate) the namespace back to the applied tip; this
/// foreground import runs no workers, so it refuses instead. Remove or
/// quarantine the namespace, or revalidate it first, then re-run.
fn refuse_stale_persisted_indexes(data_dir: &Path) -> Result<()> {
    let namespace = data_dir.join("txindex");
    if !namespace_has_content(&namespace) {
        return Ok(());
    }
    bail!(
        "stale persisted derived index at {}: remove it or revalidate with an indexed start, then re-run",
        namespace.display()
    );
}

/// True when `path` holds persisted content: a missing path or an empty
/// directory holds nothing stale; anything else (rows, a stray file, a
/// symlink, or an unreadable directory) is state this import will not
/// revalidate.
fn namespace_has_content(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => std::fs::symlink_metadata(path).is_ok(),
    }
}

fn parse_magic_hex(text: &str) -> Result<[u8; 4]> {
    if text.len() != 8 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("network magic must be 8 hex characters");
    }
    let mut out = [0u8; 4];
    for (index, chunk) in out.iter_mut().enumerate() {
        let byte: u8 = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .with_context(|| "network magic is not hex")?;
        *chunk = byte;
    }
    Ok(out)
}

fn check_manifest_shape(doc: &Manifest) -> Result<()> {
    if doc.blocks.is_empty() {
        bail!("manifest blocks must list every height exactly once");
    }
    if doc.stop_height < doc.start_height {
        bail!("manifest stop is before start");
    }
    let expected = usize::try_from(
        doc.stop_height
            .checked_sub(doc.start_height)
            .context("manifest stop is before start")?
            .checked_add(1)
            .context("manifest range overflow")?,
    )
    .context("manifest range does not fit")?;
    if doc.blocks.len() != expected || doc.blocks.len() > 2_000_000 {
        bail!("manifest blocks must list every height exactly once");
    }
    let mut cursor: u64 = 0;
    for (index, entry) in doc.blocks.iter().enumerate() {
        let index_height = u32::try_from(index).context("manifest index does not fit")?;
        if entry.height
            != doc
                .start_height
                .checked_add(index_height)
                .context("manifest height overflow")?
        {
            bail!("manifest heights must be contiguous from start_height");
        }
        if entry.payload_length < HEADER_LEN || entry.payload_length > MAX_PAYLOAD {
            bail!("manifest entry payload is outside consensus bounds");
        }
        if entry.hash.len() != 64 {
            bail!("manifest entry hash must be 64 hex characters");
        }
        if entry.offset != cursor {
            bail!("manifest entry offset is not packed");
        }
        // Linearizable cursor advance: single-writer offsets are packed, so a
        // failed add refuses rather than wrapping to a second view.
        cursor = cursor
            .checked_add(8)
            .context("manifest cursor overflow")?
            .checked_add(
                u64::try_from(entry.payload_length).context("payload length does not fit")?,
            )
            .context("manifest cursor overflow")?;
        if cursor > doc.archive_bytes {
            bail!("manifest entry overruns the archive");
        }
    }
    if cursor != doc.archive_bytes {
        bail!("manifest does not consume the archive exactly");
    }
    Ok(())
}

fn verify_and_certify(
    node: &crate::state::NodeState,
    data_dir: &Path,
    manifest: &Manifest,
    state_path: &Path,
) -> Result<()> {
    let chainstate = node.chainstate();
    let tip = chainstate
        .applied_tip_snapshot()
        .context("offline import produced no applied tip")?;
    let stop_entry = manifest
        .blocks
        .last()
        .context("manifest has no stop entry")?;
    if tip.height != manifest.stop_height {
        bail!("applied tip height does not equal the manifest stop");
    }
    if tip.height != stop_entry.height {
        bail!("applied tip height does not equal the manifest stop entry");
    }
    if !tip.hash.to_string().eq_ignore_ascii_case(&stop_entry.hash) {
        bail!("applied tip hash does not equal the manifest stop hash");
    }
    let body_store = chainstate
        .block_body_store_handle()
        .context("running node has no block body store")?;
    let body = body_store
        .load_block_body(tip.height, tip.hash)
        .map_err(|error| anyhow::anyhow!("body proof failed: {error}"))?;
    if body.is_none() {
        bail!("tip body is not available");
    }
    let request = bitcoin_rs_chainstate::verify::VerifyRequest {
        level: bitcoin_rs_chainstate::verify::CheckLevel::CheckUndoAndCommitments,
        depth: NonZeroU32::new(1),
        cancellation: None,
    };
    match bitcoin_rs_chainstate::verify::verify_recent_blocks(&chainstate, request) {
        Ok(bitcoin_rs_chainstate::verify::VerifyOutcome::Passed { .. }) => {}
        Ok(bitcoin_rs_chainstate::verify::VerifyOutcome::SkippedNoBlockData { height }) => {
            bail!("verification skipped data this node should hold at height {height}")
        }
        Err(error) => bail!("verification of the applied tip failed: {error}"),
    }
    let (txouts, total_amount_sat, muhash, set_hash) =
        node.chainstate().utxo_reader().with_stable_view(|view| {
            let stats = bitcoin_rs_utxo::stats::scan_coin_stats(view, tip.height, true)
                .map_err(|error| anyhow::anyhow!("coin stats scan failed: {error}"))?;
            let set_hash = view
                .hash_serialized_3()
                .map_err(|error| anyhow::anyhow!("hash_serialized_3 failed: {error}"))?;
            // Snapshot-isolated read: the stable view blocks commits for the
            // scan, so txout counts and hashes belong to one tip. No
            // exactly-once delivery is assumed; reruns resume by tip
            // comparison under a matching provenance record, and are refused
            // without one.
            Ok::<_, anyhow::Error>((
                u64::try_from(view.len())
                    .map_err(|error| anyhow::anyhow!("txout count does not fit: {error}"))?,
                stats.total_amount,
                stats.muhash.finalize_hash().to_string(),
                set_hash.to_string(),
            ))
        })?;
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
    let generation = node
        .publish_checkpoint()
        .map_err(|error| anyhow::anyhow!("clean checkpoint publication failed: {error}"))?;
    if generation.is_none() {
        bail!("clean checkpoint publication skipped: no applied tip");
    }
    // Bind full-validation provenance to the certified tip before publishing
    // the certified state: the tip below already passed full validation
    // (every record connected under the pinned `Full` mode, bodies plus undo
    // durable, tip re-verified, checkpoint published), so the record is true
    // the moment it lands. Ordering it first keeps a later `write_state`
    // failure (for example `create_new` refusing a reused state path)
    // resumable: the rerun still matches provenance and re-certifies instead
    // of forcing a from-genesis revalidation.
    write_full_validation_provenance(data_dir, &tip)?;
    write_state(state_path, &certified)?;
    Ok(())
}

fn write_state(path: &Path, state: &CertifiedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create state dir {}", parent.display()))?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create state file {}", path.display()))?;
    let mut raw = sonic_rs::to_vec_pretty(state).context("cannot encode certified state")?;
    raw.push(b'\n');
    file.write_all(&raw)
        .with_context(|| format!("cannot write state file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot fsync state file {}", path.display()))?;
    drop(file);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let dir = File::open(parent)
                .with_context(|| format!("cannot open state dir {}", parent.display()))?;
            dir.sync_all()
                .with_context(|| format!("cannot fsync state dir {}", parent.display()))?;
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

    #[test]
    fn connect_batch_relieve_journal_retention_pressure() {
        use bitcoin_rs_chain::regtest_fixture;

        // The foreground import runs no maintenance worker, so retention
        // pressure must be relieved inline: a batch connect that the journal
        // refuses publishes one synchronous checkpoint (compacting the
        // journal, including the pressure below) and retries the uncommitted
        // block once. Without the relief this second connect would abort the
        // import exactly like the proved refusal below.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config =
            crate::NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        config.data_dir = dir.path().join("backpressure-node");
        config.p2p.listen.clear();
        config.chainstate_journal.max_journal_mib = 1;
        config.chainstate_journal.rotate_mib = 1;

        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let state = crate::state::NodeState::open(config.clone(), None).expect("open node");
        let genesis_tip = state
            .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
                genesis.clone(),
            ))
            .expect("genesis");
        state.publish_checkpoint().expect("baseline checkpoint");

        // Inflate the measured journal size past the retention budget: the
        // next apply is refused before any tip mutation while the pressure
        // stands. The relief checkpoint compacts every superseded segment,
        // so this same file is gone before the retry runs.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(
                config
                    .data_dir
                    .join("chainstate-journal/segment-9999999999.log"),
            )
            .expect("pressure file")
            .set_len(1024 * 1024)
            .expect("pressure size");

        let child =
            regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1).expect("mine child");
        assert!(
            matches!(
                state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
                    child.clone()
                )),
                Err(crate::ConnectMutationError::NotCommitted(
                    bitcoin_rs_chainstate::ApplyError::JournalBackpressure(_)
                ))
            ),
            "the fixture must prove retention pressure refuses the child"
        );

        let mut batch = vec![bitcoin_rs_primitives::BlockPayload::from_local(child)];
        connect_batch(&state, &mut batch).expect("relief retries the refused block");
        assert!(
            batch.is_empty(),
            "the batch drains even through the relief path"
        );
        let tip = state
            .chainstate()
            .applied_tip_snapshot()
            .expect("relief must commit the child");
        assert_ne!(
            tip.as_ref(),
            &genesis_tip,
            "the tip must advance past genesis"
        );
        assert_eq!(tip.height, 1, "the retried child commits at height 1");
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
        let regtest = bitcoin_rs_primitives::Network::Regtest.identity_name();
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
        use bitcoin_rs_chainstate::ValidationMode;
        // The pin refuses to inherit: every incoming live mode maps to Full,
        // so an operator default (AssumeValid) or a fast sync posture can
        // never leak script skipping into the certified state.
        for inherited in [
            ValidationMode::Full,
            ValidationMode::AssumeValid,
            ValidationMode::Fast,
        ] {
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
        // Same computation the binding check performs, so the fixture hash
        // is pinned to the indexed display order rather than the helper.
        bitcoin_rs_primitives::encode::double_sha256(header).to_string()
    }

    #[test]
    fn connected_records_stay_bound_to_the_manifest() {
        // The per-record binding covers every record the import connects, so
        // a corrupted payload of the right length is still refused.
        let header = [7u8; HEADER_LEN];
        let doc_hash = header_hash_hex(&header);
        let good = binding_entry(3, &doc_hash);
        let mut payload = header.to_vec();
        check_payload_against_entry(&good, &payload).expect("bound record");
        // Uppercase manifest hashes normalize the same way.
        let upper = binding_entry(3, &doc_hash.to_ascii_uppercase());
        check_payload_against_entry(&upper, &payload).expect("case-insensitive");
        // One flipped payload bit diverges from the indexed entry.
        payload[10] ^= 0x01;
        assert!(check_payload_against_entry(&good, &payload).is_err());
        // A wrong entry hash refuses even with intact bytes.
        let wrong = binding_entry(3, &"ab".repeat(32));
        assert!(check_payload_against_entry(&wrong, &header).is_err());
        // A runt that framing would already reject never binds.
        let runt = binding_entry(3, &doc_hash);
        assert!(check_payload_against_entry(&runt, &header[..HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn offline_import_refuses_stale_persisted_index_namespace() {
        // No namespace, or an empty one, holds nothing stale.
        let fresh = tempfile::tempdir().expect("tempdir");
        refuse_stale_persisted_indexes(fresh.path()).expect("absent namespace");
        std::fs::create_dir(fresh.path().join("txindex")).expect("empty namespace");
        refuse_stale_persisted_indexes(fresh.path()).expect("empty namespace");
        // Rows left by an earlier index-enabled run refuse, even though the
        // config posture gate already passed with indexes off.
        std::fs::write(fresh.path().join("txindex").join("CURRENT"), b"stale")
            .expect("seed stale row");
        assert!(refuse_stale_persisted_indexes(fresh.path()).is_err());
        // A stray non-directory artifact is state this import will not
        // revalidate either.
        let stray = tempfile::tempdir().expect("tempdir");
        std::fs::write(stray.path().join("txindex"), b"stale").expect("seed stray file");
        assert!(refuse_stale_persisted_indexes(stray.path()).is_err());
    }

    /// Two real regtest blocks (genesis plus one mined child) framed as a
    /// Core archive with a matching manifest, so the provenance tests run the
    /// real entry point instead of asserting on helpers alone.
    struct TwoBlockArchive {
        blocks: Vec<bitcoin_rs_primitives::Block>,
        corpus: Vec<u8>,
        manifest: Vec<u8>,
        stop_hash: String,
    }

    fn two_block_archive() -> TwoBlockArchive {
        use sha2::Digest as _;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let child = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(
            genesis.block_hash(),
            1,
        )
        .expect("mine child");
        let blocks = vec![genesis, child];
        let magic = bitcoin_rs_primitives::Network::Regtest.magic();
        let mut corpus = Vec::new();
        let mut entries = Vec::new();
        let mut offset: u64 = 0;
        for (index, block) in blocks.iter().enumerate() {
            let payload =
                bitcoin_rs_primitives::BlockPayload::from_local(block.clone());
            let raw = payload.bytes();
            let mut framed = Vec::with_capacity(8 + raw.len());
            framed.extend_from_slice(&magic);
            framed.extend_from_slice(
                &u32::try_from(raw.len()).expect("payload fits").to_le_bytes(),
            );
            framed.extend_from_slice(raw);
            entries.push(format!(
                r#"{{"height":{index},"hash":"{hash}","offset":{offset},"payload_length":{len}}}"#,
                index = u32::try_from(index).expect("index fits"),
                hash = block.block_hash().to_string(),
                len = raw.len()
            ));
            offset += u64::try_from(framed.len()).expect("offset fits");
            corpus.extend_from_slice(&framed);
        }
        let mut hasher = sha2::Sha256::new();
        hasher.update(&corpus);
        let manifest = format!(
            r#"{{"schema":"core-framed-archive-manifest-v1","network":"regtest","network_magic":"fabfb5da","start_height":0,"stop_height":1,"archive_sha256":"{digest}","archive_bytes":{bytes},"blocks":[{blocks}]}}"#,
            digest = bitcoin_rs_primitives::encode::hex_encode(&hasher.finalize()),
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
        let mut config =
            crate::NodeConfig::default_for_network(bitcoin_rs_primitives::Network::Regtest);
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
        // Fresh data directory: every record is connected under the pinned
        // `Full` mode, the tip certifies, and the provenance record binds the
        // certified tip for later resumes.
        let archive = two_block_archive();
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("node");
        let (corpus, manifest) = write_archive_fixture(dir.path(), &archive);
        let state = dir.path().join("state.json");
        run_offline_import(offline_import_config(&data_dir), &corpus, &manifest, &state)
            .expect("fresh import succeeds");
        let record =
            read_full_validation_provenance(&data_dir).expect("provenance recorded");
        assert_eq!(record.height, 1, "provenance binds the certified tip");
        assert!(
            record.tip_hash.eq_ignore_ascii_case(&archive.stop_hash),
            "provenance binds the certified tip hash"
        );
        let text =
            String::from_utf8(std::fs::read(&state).expect("read state")).expect("utf8");
        assert!(text.contains("\"height\": 1"), "state certifies height 1");
        assert!(
            text.contains(&archive.stop_hash),
            "state certifies the archive tip"
        );
    }

    #[test]
    fn offline_import_certified_dir_resumes_idempotently() {
        // The provenance record this importer wrote at certification lets a
        // rerun skip the already-validated prefix: the tip is current, so no
        // block is reconnected, but the archive is still walked and rebound.
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
        assert!(text.contains("\"height\": 1"), "resume still certifies height 1");
        assert!(
            text.contains(&archive.stop_hash),
            "resume still certifies the archive tip"
        );
    }

    #[test]
    fn offline_import_refuses_tip_without_provenance() {
        // A data directory whose tip came from anywhere but this importer
        // (here: blocks connected directly, as a live `AssumeValid`/`Fast`
        // run would leave them) carries no provenance record, so the import
        // refuses instead of skipping unexecuted scripts into a full-validation
        // certificate. The corpus path is never even opened: the tip check
        // runs first.
        let archive = two_block_archive();
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("node");
        {
            let live =
                crate::state::NodeState::open(offline_import_config(&data_dir), None)
                    .expect("open node");
            for block in &archive.blocks {
                live.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
                    block.clone(),
                ))
                .expect("connect");
            }
            // No provenance written; dropping releases the data-dir lock so
            // the entry point below can reopen the directory.
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
        // Eight bytes but multibyte UTF-8: refused, not sliced off a char
        // boundary.
        assert!(parse_magic_hex("\u{e9}\u{e9}f9be").is_err());
        // Sign prefixes `from_str_radix` would accept are not hex digits.
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
        assert!(error.to_string().contains("byte bound"), "{error}");
    }
}
