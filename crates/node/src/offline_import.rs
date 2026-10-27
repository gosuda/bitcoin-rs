//! Foreground offline import for the strict full-validation comparator.
//!
//! Consistency: chain mutation holds the exclusive chain-transition lock
//! (linearizable single-writer per transition); certified reads use the
//! stable whole-set view (snapshot isolation over the UTXO set, blocking
//! commits for the scan); the manifest plus archive pin is bound by hash
//! (a transactional outbox is unnecessary here because publication is a
//! single atomic `create_new` state file after the checkpoint, and reruns
//! are idempotent by tip comparison, so no exactly-once delivery is
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
//! Guarantees: exact bytes (framing walk plus manifest binding plus archive
//! digest), full validation (`--assume-valid-height 0`, indexes off),
//! durable bodies plus undo (authoritative commit path), production clean
//! checkpoint (nonzero when publication fails), foreground only (no fork,
//! no daemonize, no spawned descendants), and an eight-field certified
//! state. Reopen against the same data directory is idempotent: when the
//! applied tip already equals the manifest stop, no block is reconnected.

use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::Path;

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
    config: NodeConfig,
    corpus: &Path,
    manifest: &Path,
    state: &Path,
) -> Result<()> {
    if config.validation.assume_valid_height != 0 {
        bail!("offline import requires --assume-valid-height 0 for full validation");
    }
    if config.indexes.txindex || config.indexes.blockfilterindex {
        bail!("offline import requires auxiliary indexes off");
    }
    let manifest_doc = read_manifest(manifest)?;
    let expected_magic = config.network.magic();
    let manifest_magic = parse_magic_hex(&manifest_doc.network_magic)?;
    if manifest_magic != expected_magic {
        bail!("manifest network magic does not match the node network");
    }
    check_manifest_network(&manifest_doc, config.network.identity_name())?;
    check_manifest_shape(&manifest_doc)?;

    let node = crate::state::NodeState::open(config, None)?;
    let chainstate = node.chainstate();
    let followers = node.chain_followers();

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
            if height == manifest_doc.stop_height {
                verify_and_certify(&node, &manifest_doc, state)?;
                return Ok(());
            }
            let next = height.checked_add(1).context("applied tip overflow")?;
            block_index_for_height(manifest_doc.start_height, next)?
        }
    };

    let mut stream = open_corpus(corpus)?;
    let mut hasher = sha2::Sha256::new();
    let mut total: u64 = 0;
    let mut payloads: Vec<bitcoin_rs_primitives::BlockPayload> = Vec::new();
    for (index, entry) in manifest_doc.blocks.iter().enumerate() {
        let record = read_record(&mut stream, expected_magic, entry)?;
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
            connect_batch(&chainstate, &followers, &mut payloads)?;
        }
    }
    if !payloads.is_empty() {
        connect_batch(&chainstate, &followers, &mut payloads)?;
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

    verify_and_certify(&node, &manifest_doc, state)?;
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

fn connect_batch(
    chainstate: &bitcoin_rs_chainstate::Chainstate,
    followers: &crate::ChainFollowers,
    batch: &mut Vec<bitcoin_rs_primitives::BlockPayload>,
) -> Result<()> {
    for payload in batch.drain(..) {
        followers
            .apply_connect(chainstate, &payload)
            .map_err(|error| {
                anyhow::anyhow!(
                    "connect at block {} failed: {error}",
                    payload.block().block_hash()
                )
            })?;
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Manifest> {
    let raw =
        std::fs::read(path).with_context(|| format!("cannot read manifest {}", path.display()))?;
    if raw.len() > 512 * 1024 * 1024 {
        bail!("manifest exceeds its byte bound");
    }
    // No duplicate-key `Value` is used here: the manifest is decoded into
    // typed structs with contiguous-height and packed-offset checks, so a
    // duplicated key cannot smuggle a second chain view.
    let raw_doc: RawManifest = sonic_rs::from_slice(&raw)
        .with_context(|| format!("manifest {} is not valid JSON", path.display()))?;
    raw_doc.normalize()
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

fn parse_magic_hex(text: &str) -> Result<[u8; 4]> {
    if text.len() != 8 {
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
            // exactly-once delivery is assumed; reruns are idempotent by tip.
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
    fn nonzero_start_height_maps_index_and_skip() {
        let doc = Manifest {
            network: "regtest".to_owned(),
            network_magic: "fabfb5da".to_owned(),
            start_height: 100,
            stop_height: 102,
            archive_sha256: "ab".repeat(32),
            archive_bytes: 294,
            blocks: vec![
                entry(100, &"ab".repeat(32), 0, 90),
                entry(101, &"cd".repeat(32), 98, 90),
                entry(102, &"ef".repeat(32), 196, 90),
            ],
        };
        assert!(check_manifest_shape(&doc).is_ok());
        // Resume at H=101 reads entry 101-100=1 and skips 101+1-100=2 records.
        assert_eq!(
            block_index_for_height(doc.start_height, 101).expect("index"),
            1
        );
        let next = 101u32.checked_add(1).expect("next");
        assert_eq!(
            block_index_for_height(doc.start_height, next).expect("skip"),
            2
        );
        // Below-range heights are refused rather than underflowing.
        assert!(block_index_for_height(doc.start_height, 99).is_err());
        // Start-at-zero behavior is unchanged.
        assert_eq!(block_index_for_height(0, 1).expect("index"), 1);
        assert_eq!(block_index_for_height(0, 2).expect("skip"), 2);
    }
}
