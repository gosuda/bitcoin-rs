use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
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

pub fn run_offline_import(
    mut config: NodeConfig,
    corpus: &Path,
    manifest: &Path,
    state: &Path,
) -> Result<()> {
    if config.validation.assume_valid_height != 0 {
        bail!("offline import requires --assume-valid-height 0 for full validation");
    }
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
            require_full_validation_provenance(&data_dir, tip)?;
            if height == manifest_doc.stop_height {
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
    let raw_doc: RawManifest = sonic_rs::from_slice(&raw)
        .with_context(|| format!("manifest {} is not valid JSON", path.display()))?;
    raw_doc.normalize()
}

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

const FULL_VALIDATION_PROVENANCE_FILE: &str = "offline-full-validation-provenance.json";
const FULL_VALIDATION_PROVENANCE_SCHEMA: &str = "offline-full-validation-provenance-v1";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct FullValidationProvenance {
    schema: String,
    height: u32,
    tip_hash: String,
}

fn block_index_for_height(start_height: u32, height: u32) -> Result<usize> {
    let offset = height
        .checked_sub(start_height)
        .with_context(|| format!("applied tip height {height} is outside the manifest range"))?;
    usize::try_from(offset).context("tip height does not fit")
}

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

fn resolve_offline_validation_mode(
    _inherited: bitcoin_rs_chainstate::ValidationMode,
) -> bitcoin_rs_chainstate::ValidationMode {
    bitcoin_rs_chainstate::ValidationMode::Full
}

fn check_payload_against_entry(entry: &ManifestBlock, payload: &[u8]) -> Result<()> {
    let header = payload
        .get(..HEADER_LEN)
        .with_context(|| format!("block at height {} is shorter than a header", entry.height))?;
    let hash = bitcoin_rs_primitives::encode::double_sha256(header);
    if !hash.to_string().eq_ignore_ascii_case(&entry.hash) {
        bail!("block at height {} header hash diverged", entry.height);
    }
    Ok(())
}

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
        bitcoin_rs_primitives::encode::double_sha256(header).to_string()
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
        blocks: Vec<bitcoin_rs_primitives::Block>,
        corpus: Vec<u8>,
        manifest: Vec<u8>,
        stop_hash: String,
    }

    fn two_block_archive() -> TwoBlockArchive {
        use sha2::Digest as _;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let child =
            bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
                .expect("mine child");
        let blocks = vec![genesis, child];
        let magic = bitcoin_rs_primitives::Network::Regtest.magic();
        let mut corpus = Vec::new();
        let mut entries = Vec::new();
        let mut offset: u64 = 0;
        for (index, block) in blocks.iter().enumerate() {
            let payload = bitcoin_rs_primitives::BlockPayload::from_local(block.clone());
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
                live.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
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
        assert!(error.to_string().contains("byte bound"), "{error}");
    }
}
