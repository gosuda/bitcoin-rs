#![cfg(any(feature = "mdbx", feature = "surrealkv"))]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[cfg(feature = "mdbx")]
use bitcoin_rs_storage::MdbxStore;
#[cfg(feature = "surrealkv")]
use bitcoin_rs_storage::SurrealKvStore;
use bitcoin_rs_storage::checkpoint::{
    CHECKPOINT_ROOT, COINSTATS_CODEC, COINSTATS_FILE, CURRENT_FILE, CURRENT_FORMAT,
    CURRENT_VERSION, CheckpointManifestV1, CheckpointTipV1, CoinStatsArtifactV1, CurrentV1,
    EngineArtifactV1, HEADER_CODEC, HEADERS_FILE, HISTORICAL_CHECKPOINT_ROOT, HeadersArtifactV1,
    MANIFEST_FILE, MANIFEST_FORMAT, digest_engine_dir, verify_engine_artifact,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore, StorageBackend};
use cap_std::ambient_authority;
use cap_std::fs::Dir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{
    NamespaceReport, compute_oracle_digest, parse_report, recursive_dir_digest, run_converter,
};
use super::support::oracle::{
    FamilyRows, assert_independent_files_copied_and_ignored_skipped, read_rocksdb_all_rows,
    write_independent_files, write_rocksdb_namespace, write_schema_marker,
};

fn verify_namespace_families(
    report: &NamespaceReport,
    expected_data: &[FamilyRows],
    oracle_digests: &BTreeMap<(&str, &str), String>,
    hop_label: &str,
) -> TestResult<()> {
    for (cf, expected_rows) in expected_data {
        let expected_digest = &oracle_digests[&(report.namespace.as_str(), cf.name())];
        let fam_rep = report
            .families
            .iter()
            .find(|f| f.family == cf.name())
            .ok_or_else(|| {
                TestError::Assertion(format!(
                    "missing family {} in {} report",
                    cf.name(),
                    hop_label
                ))
            })?;
        let expected_count = u64::try_from(expected_rows.len())
            .map_err(|_| TestError::Assertion("row count does not fit in u64".into()))?;
        if fam_rep.digest != *expected_digest || fam_rep.row_count != expected_count {
            return Err(TestError::Assertion(format!(
                "family {} digest/count mismatch in {}",
                cf.name(),
                hop_label
            )));
        }
    }
    Ok(())
}

fn verify_final_rocksdb_data(
    path: &Path,
    ns: &str,
    expected_data: &[FamilyRows],
) -> TestResult<()> {
    let actual_rows = read_rocksdb_all_rows(&path.join(ns))?;
    for (cf, expected_rows) in expected_data {
        let (_, rows) = actual_rows
            .iter()
            .find(|(c, _)| c == cf)
            .ok_or_else(|| TestError::Assertion(format!("missing cf in final: {}", cf.name())))?;
        let mut sorted_expected = expected_rows.clone();
        sorted_expected.sort_by(|a, b| a.0.cmp(&b.0));
        if rows != &sorted_expected {
            return Err(TestError::Assertion(format!(
                "rows differ for cf {} in ns {} after round-trip: expected {sorted_expected:?}, got {rows:?}",
                cf.name(),
                ns
            )));
        }
    }
    Ok(())
}

fn undo_key(height: u32, hash_byte: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(37);
    key.push(b'u');
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&[hash_byte; 32]);
    key
}

fn undo_value_v1_empty(hash_byte: u8) -> Vec<u8> {
    let mut value = Vec::with_capacity(41);
    value.push(1);
    value.extend_from_slice(&[hash_byte; 32]);
    value.extend_from_slice(&0u32.to_le_bytes());
    value.extend_from_slice(&0u32.to_le_bytes());
    value
}

fn undo_value_v2(hash_byte: u8) -> Vec<u8> {
    let mut value = Vec::with_capacity(37);
    value.push(2);
    value.extend_from_slice(&[hash_byte; 32]);
    value.extend_from_slice(&0u32.to_le_bytes());
    value
}

fn make_test_datasets() -> (Vec<FamilyRows>, Vec<FamilyRows>) {
    let chainstate_data = vec![
        (
            ColumnFamily::UtxoMeta,
            vec![
                (b"head:height".to_vec(), 101_u64.to_le_bytes().to_vec()),
                (
                    b"head:tip".to_vec(),
                    b"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_vec(),
                ),
            ],
        ),
        (
            ColumnFamily::UndoData,
            vec![
                (undo_key(101, 0x11), undo_value_v1_empty(0x11)),
                (undo_key(102, 0x22), undo_value_v1_empty(0x22)),
            ],
        ),
    ];

    let txindex_data = vec![(
        ColumnFamily::BlockHeaders,
        vec![
            (b"header:00000001".to_vec(), vec![10u8; 80]),
            (b"header:00000002".to_vec(), vec![11u8; 80]),
        ],
    )];

    (chainstate_data, txindex_data)
}

/// Literal rows for nested checkpoint images: independent of make_test_datasets,
/// multiple column families, parameterized by tag so every generation differs.
fn checkpoint_image_rows(tag: &str) -> TestResult<Vec<FamilyRows>> {
    let tag_len = u8::try_from(tag.len())
        .map_err(|_| TestError::Assertion("checkpoint image tag too long".into()))?;
    let mut meta_key = b"ckpt:meta:".to_vec();
    meta_key.extend_from_slice(tag.as_bytes());
    let mut coin_key = b"ckpt:coin:".to_vec();
    coin_key.extend_from_slice(tag.as_bytes());
    let mut header_key = b"ckpt:header:".to_vec();
    header_key.extend_from_slice(tag.as_bytes());
    Ok(vec![
        (
            ColumnFamily::UtxoMeta,
            vec![(meta_key, vec![0xA5u8, 0x5A, tag_len, 7])],
        ),
        (
            ColumnFamily::Coins,
            vec![(coin_key, vec![0xC0u8, 0xDE, tag_len])],
        ),
        (
            ColumnFamily::BlockHeaders,
            vec![(header_key, vec![0x80u8; 80])],
        ),
    ])
}

fn to_u64(n: usize) -> TestResult<u64> {
    u64::try_from(n).map_err(|_| TestError::Assertion("usize does not fit in u64".into()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

struct GenerationFixture {
    generation: u64,
    rows: Vec<FamilyRows>,
    /// Byte-exact metadata artifacts, keyed by path relative to the checkpoint root.
    metadata: BTreeMap<String, Vec<u8>>,
}

struct NestedCheckpointFixture {
    /// Metadata bytes at the checkpoint root (the CURRENT file).
    root_metadata: Vec<u8>,
    generations: Vec<GenerationFixture>,
}

fn checkpoint_tip(height: u32, tag: &[u8]) -> TestResult<CheckpointTipV1> {
    let used = tag.len().min(4);
    let mut hash = [0u8; 32];
    hash[..used].copy_from_slice(&tag[..used]);
    let mut chainwork = [0u8; 32];
    chainwork[..used].copy_from_slice(&tag[..used]);
    Ok(CheckpointTipV1 {
        height,
        hash: hex_lower(&hash),
        chainwork: hex_lower(&chainwork),
        chain_tx_count: u64::from(height) + 1,
    })
}

fn artifact_bytes(tag: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(tag.len() + 8);
    bytes.extend_from_slice(b"BRSCkPt");
    bytes.extend_from_slice(tag);
    bytes
}

/// One generation directory: canonical gen-{generation:020} name, sonic_rs
/// manifest whose artifact commitments match the literal bytes we stage, a
/// headers-v1.dat and coinstats-v1.dat artifact, and, when an image is supplied, a
/// flushed backend checkpoint under `chainstate`, pinned by the manifest engine
/// commitment. The manifest carries no utxo artifact.
fn stage_generation(
    root: &Path,
    generation: u64,
    tag: &str,
    image: Option<(StorageBackend, u32)>,
) -> TestResult<GenerationFixture> {
    let directory = format!("gen-{generation:020}");
    let generation_path = root.join(&directory);
    fs::create_dir_all(&generation_path)?;

    let headers_bytes = artifact_bytes(tag.as_bytes());
    let coinstats_bytes = artifact_bytes(format!("cs-{tag}").as_bytes());
    let headers_sha = Sha256::digest(&headers_bytes);
    let coinstats_sha = Sha256::digest(&coinstats_bytes);
    let tip = checkpoint_tip(2_500_000, tag.as_bytes())?;

    let mut manifest = CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        version: 1,
        generation,
        network: "regtest".to_owned(),
        network_magic: "fabfb5da".to_owned(),
        genesis_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206".to_owned(),
        applied_tip: tip.clone(),
        best_header_tip: tip,
        headers: HeadersArtifactV1 {
            file: HEADERS_FILE.to_owned(),
            codec: HEADER_CODEC.to_owned(),
            version: 1,
            bytes: to_u64(headers_bytes.len())?,
            sha256: hex_lower(&headers_sha),
            header_count: 1,
            best_chain_sha256: hex_lower(&headers_sha),
            applied_chain_sha256: hex_lower(&headers_sha),
        },
        utxo: None,
        engine: None,
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_owned(),
            codec: COINSTATS_CODEC.to_owned(),
            version: 1,
            bytes: to_u64(coinstats_bytes.len())?,
            sha256: hex_lower(&coinstats_sha),
            height: 2_500_000,
            total_amount: 2_100_000_000_000_000,
            bogo_size: 86_400_000,
            tx_count: 0,
            utxo_count: 0,
            muhash: hex_lower(&Sha256::digest(tag.as_bytes())),
        },
    };

    fs::write(root.join(&directory).join(HEADERS_FILE), &headers_bytes)?;
    fs::write(root.join(&directory).join(COINSTATS_FILE), &coinstats_bytes)?;

    let rows = if let Some((backend, source_epoch)) = image {
        let mut image_rows = checkpoint_image_rows(tag)?;
        if source_epoch == 5 {
            image_rows.push((
                ColumnFamily::UndoData,
                vec![(undo_key(101, 0x33), undo_value_v1_empty(0x33))],
            ));
        }
        let staging_path = generation_path.join("chainstate-staging");
        let store = open_engine_store(&staging_path, backend)?;
        for (family, rows) in &image_rows {
            for (key, value) in rows {
                store.put(*family, key, value)?;
            }
        }
        store.flush()?;
        store.checkpoint(&generation_path.join("chainstate"))?;
        drop(store);
        fs::remove_dir_all(&staging_path)?;
        image_rows
    } else {
        Vec::new()
    };

    if image.is_some() {
        let image_dir =
            Dir::open_ambient_dir(generation_path.join("chainstate"), ambient_authority())?;
        manifest.engine = Some(digest_engine_dir(&image_dir).map_err(|error| {
            TestError::Assertion(format!("staged engine image digest failed: {error}"))
        })?);
    }
    let manifest_bytes = sonic_rs::to_vec(&manifest)
        .map_err(|error| TestError::Assertion(format!("manifest serialization failed: {error}")))?;
    let manifest_rel = format!("{directory}/{MANIFEST_FILE}");
    fs::write(root.join(&manifest_rel), &manifest_bytes)?;
    let mut metadata = BTreeMap::new();
    metadata.insert(manifest_rel, manifest_bytes);
    metadata.insert(format!("{directory}/{HEADERS_FILE}"), headers_bytes);
    metadata.insert(format!("{directory}/{COINSTATS_FILE}"), coinstats_bytes);

    Ok(GenerationFixture {
        generation,
        rows,
        metadata,
    })
}

/// Stage real engine checkpoint images with canonical 20-digit generation names
/// under an ordinary (`chainstate-checkpoints`) or historical
/// (`assumeutxo-historical-checkpoints`) checkpoint root, including a CURRENT
/// file, a retained non-current generation, and one metadata-only generation
/// that deliberately carries no chainstate image.
fn stage_nested_checkpoints(
    root: &Path,
    current_generation: u64,
) -> TestResult<NestedCheckpointFixture> {
    stage_nested_checkpoints_for_epoch(root, current_generation, StorageBackend::RocksDb, 4)
}

fn stage_nested_checkpoints_for_epoch(
    root: &Path,
    current_generation: u64,
    backend: StorageBackend,
    source_epoch: u32,
) -> TestResult<NestedCheckpointFixture> {
    fs::create_dir_all(root)?;
    let image = Some((backend, source_epoch));
    let retained = stage_generation(root, current_generation - 1, "old", image)?;
    let current = stage_generation(root, current_generation, "cur", image)?;
    let bare = stage_generation(root, current_generation + 1, "bare", None)?;

    let current_manifest = current
        .metadata
        .get(&format!("gen-{current_generation:020}/{MANIFEST_FILE}"))
        .ok_or_else(|| TestError::Assertion("current generation manifest missing".into()))?;
    let current_entry = CurrentV1 {
        format: CURRENT_FORMAT.to_owned(),
        version: CURRENT_VERSION,
        generation: current.generation,
        directory: format!("gen-{current_generation:020}"),
        manifest_sha256: hex_lower(&Sha256::digest(current_manifest)),
    };
    let current_bytes = sonic_rs::to_vec(&current_entry)
        .map_err(|error| TestError::Assertion(format!("CURRENT serialization failed: {error}")))?;
    fs::write(root.join(CURRENT_FILE), &current_bytes)?;

    Ok(NestedCheckpointFixture {
        root_metadata: current_bytes,
        generations: vec![retained, current, bare],
    })
}

fn open_engine_store(path: &Path, backend: StorageBackend) -> TestResult<Box<dyn KvStore>> {
    match backend {
        StorageBackend::RocksDb => Ok(Box::new(RocksDbStore::open_with_cache(path, 0)?)),
        #[cfg(feature = "mdbx")]
        StorageBackend::Mdbx => Ok(Box::new(MdbxStore::open(path)?)),
        #[cfg(not(feature = "mdbx"))]
        StorageBackend::Mdbx => Err(TestError::Assertion(
            "mdbx feature not enabled for this test build".into(),
        )),
        #[cfg(feature = "surrealkv")]
        StorageBackend::SurrealKv => Ok(Box::new(SurrealKvStore::open(path)?)),
        #[cfg(not(feature = "surrealkv"))]
        StorageBackend::SurrealKv => Err(TestError::Assertion(
            "surrealkv feature not enabled for this test build".into(),
        )),
    }
}

fn read_store_rows(store: &dyn KvStore) -> TestResult<Vec<FamilyRows>> {
    let snapshot = store.snapshot()?;
    let mut result = Vec::new();
    for cf in ColumnFamily::ALL {
        let mut rows = Vec::new();
        for item in snapshot.iter_prefix(*cf, &[])? {
            let (key, value) = item?;
            rows.push((key, value));
        }
        result.push((*cf, rows));
    }
    Ok(result)
}

struct HopSite<'a> {
    root: &'a Path,
    checkpoint_root: &'a str,
    hop_label: &'a str,
}

impl HopSite<'_> {
    fn fail(&self, message: String) -> TestError {
        TestError::Assertion(format!(
            "checkpoint {} {} in {}",
            self.checkpoint_root, message, self.hop_label
        ))
    }
}

struct GenerationCheck<'a> {
    generation: &'a GenerationFixture,
    directory: String,
    generation_root: std::path::PathBuf,
    source_manifest_bytes: &'a [u8],
}

impl GenerationCheck<'_> {
    fn image(&self) -> std::path::PathBuf {
        self.generation_root.join("chainstate")
    }

    fn manifest_path(&self) -> std::path::PathBuf {
        self.generation_root.join(MANIFEST_FILE)
    }
}

/// After a hop, every canonical generation under `root` must keep its
/// headers and coinstats artifacts byte-identical, the retained and current
/// images must be readable with exactly the requested backend engine and hold
/// the staged rows, and the generation staged without an image must still
/// have no image. Generations carrying an image must pin that actual
/// destination image in their manifest engine commitment while every other
/// manifest field stays equal to the source manifest, and CURRENT must keep
/// its identity fields while pinning the exact destination manifest bytes.
fn verify_nested_checkpoint_images(
    dest_data_root: &Path,
    checkpoint_root: &str,
    fixture: &NestedCheckpointFixture,
    expected_backend: StorageBackend,
    hop_label: &str,
) -> TestResult<()> {
    let root = dest_data_root.join(checkpoint_root);
    let site = HopSite {
        root: &root,
        checkpoint_root,
        hop_label,
    };
    verify_current_rebind(&site, fixture)?;
    for generation in &fixture.generations {
        verify_generation_after_hop(&site, generation, expected_backend)?;
    }
    Ok(())
}

fn verify_current_rebind(site: &HopSite<'_>, fixture: &NestedCheckpointFixture) -> TestResult<()> {
    let current_bytes = fs::read(site.root.join(CURRENT_FILE))?;
    let source_current: CurrentV1 = sonic_rs::from_slice(&fixture.root_metadata)?;
    let dest_current: CurrentV1 = sonic_rs::from_slice(&current_bytes)?;
    let identity_unchanged = dest_current.format == source_current.format
        && dest_current.version == source_current.version
        && dest_current.generation == source_current.generation
        && dest_current.directory == source_current.directory;
    if !identity_unchanged {
        return Err(site.fail("CURRENT identity changed".to_owned()));
    }
    let current_manifest_bytes = fs::read(
        site.root
            .join(&source_current.directory)
            .join(MANIFEST_FILE),
    )?;
    let pinned_manifest = hex_lower(&Sha256::digest(&current_manifest_bytes));
    if dest_current.manifest_sha256 != pinned_manifest {
        return Err(
            site.fail("CURRENT manifest_sha256 does not pin the destination manifest".to_owned())
        );
    }
    Ok(())
}

fn verify_generation_after_hop(
    site: &HopSite<'_>,
    generation: &GenerationFixture,
    expected_backend: StorageBackend,
) -> TestResult<()> {
    let directory = format!("gen-{:020}", generation.generation);
    let source_manifest_bytes = generation
        .metadata
        .get(&format!("{directory}/{MANIFEST_FILE}"))
        .ok_or_else(|| {
            TestError::Assertion(format!(
                "fixture is missing staged manifest for {}/{directory}",
                site.checkpoint_root
            ))
        })?;
    let generation_root = site.root.join(&directory);
    let check = GenerationCheck {
        generation,
        directory,
        generation_root,
        source_manifest_bytes,
    };
    verify_artifacts_byte_identical(site, &check)?;
    if generation.rows.is_empty() {
        return verify_metadata_only_generation(site, &check);
    }
    verify_image_engine(site, &check, expected_backend)?;
    let expected_engine = verify_image_manifest_binding(site, &check)?;
    verify_image_rows_in_scratch_copy(site, &check, expected_backend, &expected_engine)
}

fn verify_artifacts_byte_identical(
    site: &HopSite<'_>,
    check: &GenerationCheck<'_>,
) -> TestResult<()> {
    for name in [HEADERS_FILE, COINSTATS_FILE] {
        let expected = &check.generation.metadata[&format!("{}/{name}", check.directory)];
        let actual = fs::read(check.generation_root.join(name))?;
        if actual != *expected {
            return Err(site.fail(format!("{}/{name} bytes changed", check.directory)));
        }
    }
    Ok(())
}

fn verify_metadata_only_generation(
    site: &HopSite<'_>,
    check: &GenerationCheck<'_>,
) -> TestResult<()> {
    if check.image().exists() {
        return Err(site.fail(format!(
            "{} gained an image it did not have",
            check.directory
        )));
    }
    let dest_manifest_bytes = fs::read(check.manifest_path())?;
    if dest_manifest_bytes != check.source_manifest_bytes {
        return Err(site.fail(format!(
            "{} metadata-only manifest changed",
            check.directory
        )));
    }
    Ok(())
}

fn verify_image_engine(
    site: &HopSite<'_>,
    check: &GenerationCheck<'_>,
    expected_backend: StorageBackend,
) -> TestResult<()> {
    let detected = bitcoin_rs_storage::detect_engine(&check.image())?;
    if detected != Some(expected_backend) {
        return Err(site.fail(format!(
            "{} image engine is {:?}, expected {}",
            check.directory,
            detected,
            expected_backend.as_str()
        )));
    }
    Ok(())
}

fn verify_image_rows_in_scratch_copy(
    site: &HopSite<'_>,
    check: &GenerationCheck<'_>,
    expected_backend: StorageBackend,
    engine: &EngineArtifactV1,
) -> TestResult<()> {
    let scratch = tempdir()?;
    for file in &engine.files {
        let destination = scratch.path().join(&file.file);
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| site.fail(format!("engine file {:?} has no parent", file.file)))?,
        )?;
        fs::copy(check.image().join(&file.file), &destination)?;
    }
    let store = open_engine_store(scratch.path(), expected_backend)?;
    let actual_rows = read_store_rows(store.as_ref())?;
    drop(store);
    for (cf, expected_rows) in &check.generation.rows {
        let (_, rows) = actual_rows
            .iter()
            .find(|(actual_cf, _)| actual_cf == cf)
            .ok_or_else(|| {
                site.fail(format!(
                    "{} image missing family {}",
                    check.directory,
                    cf.name()
                ))
            })?;
        let mut sorted_expected = expected_rows.clone();
        sorted_expected.sort_by(|a, b| a.0.cmp(&b.0));
        if rows != &sorted_expected {
            return Err(site.fail(format!(
                "{} family {} rows differ",
                check.directory,
                cf.name()
            )));
        }
    }
    Ok(())
}

fn verify_image_manifest_binding(
    site: &HopSite<'_>,
    check: &GenerationCheck<'_>,
) -> TestResult<EngineArtifactV1> {
    let dest_manifest: CheckpointManifestV1 =
        sonic_rs::from_slice(&fs::read(check.manifest_path())?)?;
    let expected_engine = dest_manifest.engine.clone().ok_or_else(|| {
        site.fail(format!(
            "{} manifest carries no engine commitment",
            check.directory
        ))
    })?;
    let image_dir = Dir::open_ambient_dir(check.image(), ambient_authority())?;
    let actual_engine = digest_engine_dir(&image_dir).map_err(|error| {
        site.fail(format!(
            "{} destination image digest failed: {error}",
            check.directory
        ))
    })?;
    if actual_engine != expected_engine {
        return Err(site.fail(format!(
            "{} manifest engine commitment does not match the actual destination image",
            check.directory
        )));
    }
    verify_engine_artifact(&image_dir, &expected_engine).map_err(|error| {
        site.fail(format!(
            "{} destination image failed engine verification: {error}",
            check.directory
        ))
    })?;
    let mut stripped_source: CheckpointManifestV1 =
        sonic_rs::from_slice(check.source_manifest_bytes)?;
    stripped_source.engine = None;
    let mut stripped_dest = dest_manifest;
    stripped_dest.engine = None;
    let dest_metadata_bytes = sonic_rs::to_vec(&stripped_dest).map_err(|error| {
        site.fail(format!(
            "{} manifest re-encode failed: {error}",
            check.directory
        ))
    })?;
    let source_metadata_bytes = sonic_rs::to_vec(&stripped_source).map_err(|error| {
        site.fail(format!(
            "{} source manifest re-encode failed: {error}",
            check.directory
        ))
    })?;
    if dest_metadata_bytes != source_metadata_bytes {
        return Err(site.fail(format!("{} manifest metadata changed", check.directory)));
    }
    Ok(expected_engine)
}

const ORDINARY_CKPT_CURRENT_GENERATION: u64 = 77_102_004;
const HISTORICAL_CKPT_CURRENT_GENERATION: u64 = 5_004_411;

fn copy_memory_fixture_tree(from: &Path, to: &Path) -> TestResult<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_memory_fixture_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

// RCV-09, RCV-10
#[test]
fn engine_copy_preserves_memory_checkpoint_for_historical_restore() -> TestResult<()> {
    for epoch in [4, 5, 6] {
        check_memory_checkpoint_for_historical_restore(epoch)?;
    }
    Ok(())
}

fn check_memory_checkpoint_for_historical_restore(epoch: u32) -> TestResult<()> {
    use bitcoin_rs_consensus::primitives::{Hash256, Network};
    use bitcoin_rs_execution::{AssumeUtxoManager, HistoricalCheckpointRef};
    use bitcoin_rs_storage::checkpoint::CheckpointReference;
    use bitcoin_rs_storage::memory_kv::{MEMORY_KV_FILE, MemoryKvStore};
    use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

    let temporary = tempdir()?;
    let legacy = temporary.path().join("legacy");
    let seed = temporary.path().join("seed");
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    copy_memory_fixture_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest"),
        &legacy,
    )?;
    let path_text = |path: &Path| -> TestResult<String> {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| TestError::Assertion("non-UTF8 fixture path".into()))
    };
    parse_report(&run_converter(&[
        "--from",
        &path_text(&legacy)?,
        "--to",
        &path_text(&seed)?,
    ])?)?;
    fs::create_dir_all(&source)?;
    write_schema_marker(&source, epoch)?;
    let ordinary_root = seed.join(CHECKPOINT_ROOT);
    let current_bytes = fs::read(ordinary_root.join(CURRENT_FILE))?;
    let current: CurrentV1 = sonic_rs::from_slice(&current_bytes)?;
    let historical_root = source.join(HISTORICAL_CHECKPOINT_ROOT);
    let generation = historical_root.join(&current.directory);
    fs::create_dir_all(&generation)?;
    fs::write(historical_root.join(CURRENT_FILE), &current_bytes)?;
    for artifact in [MANIFEST_FILE, HEADERS_FILE, COINSTATS_FILE] {
        fs::copy(
            ordinary_root.join(&current.directory).join(artifact),
            generation.join(artifact),
        )?;
    }
    let manifest_bytes = fs::read(generation.join(MANIFEST_FILE))?;
    let mut manifest: CheckpointManifestV1 = sonic_rs::from_slice(&manifest_bytes)?;
    manifest.engine = None;
    let manifest_bytes = sonic_rs::to_vec(&manifest)?;
    fs::write(generation.join(MANIFEST_FILE), &manifest_bytes)?;
    let mut historical_current = current.clone();
    historical_current.manifest_sha256 = hex_lower(&Sha256::digest(&manifest_bytes));
    fs::write(
        historical_root.join(CURRENT_FILE),
        sonic_rs::to_vec(&historical_current)?,
    )?;
    let reference = HistoricalCheckpointRef {
        checkpoint: CheckpointReference {
            generation: current.generation,
            manifest_sha256: Sha256::digest(&manifest_bytes).into(),
        },
        height: manifest.applied_tip.height,
        hash: Hash256::from_str_be(&manifest.applied_tip.hash)
            .map_err(|error| TestError::Assertion(error.to_string()))?,
    };
    let memory = MemoryKvStore::new();
    let coin_key = [0x67; 32];
    let record = UtxoRecord::from_owned_outputs(
        Hash256::from_le_bytes(&coin_key),
        &[OwnedUtxoOut {
            vout: 3,
            value: 27_001,
            script_pubkey: vec![0x51],
            coinbase: false,
            height: 1,
        }],
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    let undo_hash = Hash256::from_le_bytes(&[0x38; 32]);
    let spent = bitcoin_rs_consensus::primitives::OutPoint::new(
        bitcoin_rs_consensus::primitives::Txid(Hash256::from_le_bytes(&[0x92; 32])),
        7,
    );
    let undo = bitcoin_rs_storage::utxo::contract::UndoBatch::from_parts(
        vec![bitcoin_rs_storage::utxo::contract::UtxoAdd::new(
            spent,
            bitcoin_rs_consensus::primitives::TxOut {
                value: bitcoin_rs_consensus::primitives::Amount::from_sat(19_003),
                script_pubkey: bitcoin_rs_consensus::primitives::Script::from_bytes(vec![0x51]),
            },
            false,
            1,
        )],
        Vec::new(),
    );
    let target_undo = bitcoin_rs_storage::utxo::contract::encode_undo_record(&undo, undo_hash);
    let undo_value = if epoch < 6 {
        let mut value = undo_value_v1_empty(0x38);
        value.truncate(33);
        value.extend_from_slice(&1_u32.to_le_bytes());
        value.extend_from_slice(&[0x92; 32]);
        value.extend_from_slice(&7_u32.to_le_bytes());
        value.extend_from_slice(&19_003_u64.to_le_bytes());
        value.extend_from_slice(&[1, 0x51, 0]);
        value.extend_from_slice(&1_u32.to_le_bytes());
        value.extend_from_slice(&0_u32.to_le_bytes());
        value
    } else {
        target_undo.clone()
    };
    let mut rows = vec![
        (ColumnFamily::UndoData, undo_key(2, 0x38), undo_value),
        (
            ColumnFamily::Coins,
            coin_key.to_vec(),
            record.bytes().to_vec(),
        ),
        (
            ColumnFamily::UtxoMeta,
            b"memory:identity".to_vec(),
            vec![0x46, 0x19],
        ),
    ];
    for family in ColumnFamily::ALL.iter().copied() {
        if !matches!(
            family,
            ColumnFamily::Coins | ColumnFamily::UndoData | ColumnFamily::UtxoMeta
        ) {
            rows.push((family, b"preserved:identity".to_vec(), vec![0xa7, 0x23]));
        }
    }
    for (family, key, value) in &rows {
        memory.put(*family, key, value)?;
    }
    memory.checkpoint(&generation.join("chainstate"))?;
    let memory_bytes = fs::read(generation.join("chainstate").join(MEMORY_KV_FILE))?;
    let source_digest = recursive_dir_digest(&source)?;
    #[cfg(feature = "mdbx")]
    let backend = "mdbx";
    #[cfg(not(feature = "mdbx"))]
    let backend = "surrealkv";
    parse_report(&run_converter(&[
        "--from",
        &path_text(&source)?,
        "--to",
        &path_text(&destination)?,
        "--to-engine",
        backend,
    ])?)?;
    assert_eq!(recursive_dir_digest(&source)?, source_digest);
    let restored_generation = destination
        .join(HISTORICAL_CHECKPOINT_ROOT)
        .join(&current.directory);
    if epoch == 6 {
        assert_eq!(
            fs::read(restored_generation.join("chainstate").join(MEMORY_KV_FILE))?,
            memory_bytes,
        );
    }
    for artifact in [HEADERS_FILE, COINSTATS_FILE] {
        assert_eq!(
            fs::read(restored_generation.join(artifact))?,
            fs::read(generation.join(artifact))?,
        );
    }
    let published_bytes = fs::read(restored_generation.join(MANIFEST_FILE))?;
    let published: CheckpointManifestV1 = sonic_rs::from_slice(&published_bytes)?;
    let published_current: CurrentV1 = sonic_rs::from_slice(&fs::read(
        destination
            .join(HISTORICAL_CHECKPOINT_ROOT)
            .join(CURRENT_FILE),
    )?)?;
    assert_eq!(
        published_current.manifest_sha256,
        hex_lower(&Sha256::digest(&published_bytes)),
    );
    let engine_dir =
        Dir::open_ambient_dir(restored_generation.join("chainstate"), ambient_authority())?;
    verify_engine_artifact(
        &engine_dir,
        published
            .engine
            .as_ref()
            .ok_or_else(|| TestError::Assertion("missing engine digest".into()))?,
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    let reference = HistoricalCheckpointRef {
        checkpoint: CheckpointReference {
            manifest_sha256: Sha256::digest(&published_bytes).into(),
            ..reference.checkpoint
        },
        ..reference
    };
    let restored =
        AssumeUtxoManager::historical_checkpoint_engine(Network::Regtest, destination, &reference)
            .map_err(|error| TestError::Assertion(error.to_string()))?
            .ok_or_else(|| TestError::Assertion("memory checkpoint engine missing".into()))?;
    for (family, key, value) in &rows {
        let expected = if *family == ColumnFamily::UndoData {
            target_undo.as_slice()
        } else {
            value.as_slice()
        };
        assert_eq!(restored.get(*family, key)?.as_deref(), Some(expected));
    }
    let restored_undo = restored
        .get(ColumnFamily::UndoData, &undo_key(2, 0x38))?
        .ok_or_else(|| TestError::Assertion("missing undo".into()))?;
    let decoded = bitcoin_rs_storage::utxo::contract::decode_undo_record(&restored_undo, undo_hash)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    assert_eq!(decoded.restores().len(), 1);
    assert_eq!(decoded.restores()[0].outpoint, spent);
    assert_eq!(decoded.restores()[0].txout.value.to_sat(), 19_003);
    assert_eq!(
        decoded.restores()[0].txout.script_pubkey.as_bytes(),
        &[0x51]
    );
    assert_eq!(decoded.restores()[0].height, 1);
    assert!(!decoded.restores()[0].coinbase);
    assert!(decoded.removes().is_empty());
    for family in ColumnFamily::ALL.iter().copied() {
        let actual = restored
            .iter_prefix(family, &[])?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            actual.len(),
            rows.iter().filter(|(cf, _, _)| *cf == family).count()
        );
    }
    fs::write(
        generation.join("chainstate").join("foreign-engine"),
        b"unknown",
    )?;
    let mixed_source_digest = recursive_dir_digest(&source)?;
    let refused = temporary.path().join("refused");
    let output = run_converter(&[
        "--from",
        &path_text(&source)?,
        "--to",
        &path_text(&refused)?,
        "--to-engine",
        backend,
    ])?;
    assert!(!output.status.success());
    assert!(!refused.join("CURRENT_SCHEMA").exists());
    assert_eq!(recursive_dir_digest(&source)?, mixed_source_digest);
    Ok(())
}
#[cfg(feature = "mdbx")]
#[test]
fn engine_copy_rocksdb_to_mdbx_and_back_is_identical() -> TestResult<()> {
    let source_temp = tempdir()?;
    let mdbx_temp = tempdir()?;
    let final_rocks_temp = tempdir()?;

    let from_path = source_temp.path();
    let mdbx_path = mdbx_temp.path().join("converted_mdbx");
    let final_path = final_rocks_temp.path().join("converted_rocksdb");

    write_schema_marker(from_path, 4)?;

    let (chainstate_data, txindex_data) = make_test_datasets();
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;
    write_rocksdb_namespace(&from_path.join("txindex"), &txindex_data)?;
    let ordinary_checkpoints = stage_nested_checkpoints(
        &from_path.join(CHECKPOINT_ROOT),
        ORDINARY_CKPT_CURRENT_GENERATION,
    )?;
    let historical_checkpoints = stage_nested_checkpoints(
        &from_path.join(HISTORICAL_CHECKPOINT_ROOT),
        HISTORICAL_CKPT_CURRENT_GENERATION,
    )?;
    let all_files = write_independent_files(from_path)?;
    let independent_files: Vec<_> = all_files
        .into_iter()
        .filter(|(p, _)| !p.starts_with("chainstate-journal"))
        .collect();
    let mut oracle_digests = BTreeMap::new();
    for (cf, rows) in &chainstate_data {
        oracle_digests.insert(("chainstate", cf.name()), compute_oracle_digest(rows));
    }
    for (cf, rows) in &txindex_data {
        oracle_digests.insert(("txindex", cf.name()), compute_oracle_digest(rows));
    }
    let recoded_undo_rows = vec![
        (undo_key(101, 0x11), undo_value_v2(0x11)),
        (undo_key(102, 0x22), undo_value_v2(0x22)),
    ];
    let mut expected_recoded_chainstate = Vec::new();
    for (cf, rows) in &chainstate_data {
        if *cf == ColumnFamily::UndoData {
            expected_recoded_chainstate.push((*cf, recoded_undo_rows.clone()));
        } else {
            expected_recoded_chainstate.push((*cf, rows.clone()));
        }
    }
    let mut recoded_digests = oracle_digests.clone();
    recoded_digests.insert(
        ("chainstate", ColumnFamily::UndoData.name()),
        compute_oracle_digest(&recoded_undo_rows),
    );

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let mdbx_str = mdbx_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output1 = run_converter(&["--from", from_str, "--to", mdbx_str, "--to-engine", "mdbx"])?;

    if !output1.status.success() {
        return Err(TestError::Assertion(format!(
            "RocksDB to mdbx conversion failed with stderr: {}",
            String::from_utf8_lossy(&output1.stderr)
        )));
    }

    let source_digest_after1 = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after1 {
        return Err(TestError::Assertion(
            "source directory was modified during RocksDB to mdbx conversion".into(),
        ));
    }

    let report1 = parse_report(&output1)?;
    if report1.source_epoch != 4 || report1.target_epoch != 6 {
        return Err(TestError::Assertion(
            "epoch mismatch in hop 1 report".into(),
        ));
    }

    let cs_report1 = report1
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate in hop 1 report".into()))?;
    if cs_report1.engine != "rocksdb" {
        return Err(TestError::Assertion(format!(
            "expected source engine rocksdb, got {}",
            cs_report1.engine
        )));
    }
    verify_namespace_families(
        cs_report1,
        &expected_recoded_chainstate,
        &recoded_digests,
        "hop 1 cs",
    )?;

    let tx_report1 = report1
        .namespaces
        .iter()
        .find(|n| n.namespace == "txindex")
        .ok_or_else(|| TestError::Assertion("missing txindex in hop 1 report".into()))?;
    if tx_report1.engine != "rocksdb" {
        return Err(TestError::Assertion(format!(
            "expected source engine rocksdb, got {}",
            tx_report1.engine
        )));
    }
    verify_namespace_families(tx_report1, &txindex_data, &oracle_digests, "hop 1 tx")?;

    let dest_schema1 = fs::read_to_string(mdbx_path.join("CURRENT_SCHEMA"))?;
    if dest_schema1 != "6\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 6 in hop 1".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&mdbx_path, &independent_files)?;

    verify_nested_checkpoint_images(
        &mdbx_path,
        CHECKPOINT_ROOT,
        &ordinary_checkpoints,
        StorageBackend::Mdbx,
        "hop 1 ordinary checkpoints",
    )?;
    verify_nested_checkpoint_images(
        &mdbx_path,
        HISTORICAL_CHECKPOINT_ROOT,
        &historical_checkpoints,
        StorageBackend::Mdbx,
        "hop 1 historical checkpoints",
    )?;

    let final_str = final_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output2 = run_converter(&[
        "--from",
        mdbx_str,
        "--to",
        final_str,
        "--to-engine",
        "rocksdb",
    ])?;

    if !output2.status.success() {
        return Err(TestError::Assertion(format!(
            "mdbx to RocksDB conversion failed with stderr: {}",
            String::from_utf8_lossy(&output2.stderr)
        )));
    }

    let report2 = parse_report(&output2)?;
    if report2.source_epoch != 6 || report2.target_epoch != 6 {
        return Err(TestError::Assertion(
            "epoch mismatch in hop 2 report".into(),
        ));
    }

    let cs_report2 = report2
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate in hop 2 report".into()))?;
    if cs_report2.engine != "mdbx" {
        return Err(TestError::Assertion(format!(
            "expected source engine mdbx, got {}",
            cs_report2.engine
        )));
    }
    verify_namespace_families(
        cs_report2,
        &expected_recoded_chainstate,
        &recoded_digests,
        "hop 2 cs",
    )?;

    let tx_report2 = report2
        .namespaces
        .iter()
        .find(|n| n.namespace == "txindex")
        .ok_or_else(|| TestError::Assertion("missing txindex in hop 2 report".into()))?;
    if tx_report2.engine != "mdbx" {
        return Err(TestError::Assertion(format!(
            "expected source engine mdbx, got {}",
            tx_report2.engine
        )));
    }
    verify_namespace_families(tx_report2, &txindex_data, &oracle_digests, "hop 2 tx")?;

    let dest_schema2 = fs::read_to_string(final_path.join("CURRENT_SCHEMA"))?;
    if dest_schema2 != "6\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 6 in hop 2".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&final_path, &independent_files)?;

    verify_nested_checkpoint_images(
        &final_path,
        CHECKPOINT_ROOT,
        &ordinary_checkpoints,
        StorageBackend::RocksDb,
        "hop 2 ordinary checkpoints",
    )?;
    verify_nested_checkpoint_images(
        &final_path,
        HISTORICAL_CHECKPOINT_ROOT,
        &historical_checkpoints,
        StorageBackend::RocksDb,
        "hop 2 historical checkpoints",
    )?;

    verify_final_rocksdb_data(&final_path, "chainstate", &expected_recoded_chainstate)?;
    verify_final_rocksdb_data(&final_path, "txindex", &txindex_data)?;

    Ok(())
}

#[cfg(feature = "surrealkv")]
#[test]
fn engine_copy_rocksdb_to_surrealkv_and_back_is_identical() -> TestResult<()> {
    let source_temp = tempdir()?;
    let surrealkv_temp = tempdir()?;
    let final_rocks_temp = tempdir()?;

    let from_path = source_temp.path();
    let surrealkv_path = surrealkv_temp.path().join("converted_surrealkv");
    let final_path = final_rocks_temp.path().join("converted_rocksdb");

    write_schema_marker(from_path, 4)?;

    let (chainstate_data, txindex_data) = make_test_datasets();
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;
    write_rocksdb_namespace(&from_path.join("txindex"), &txindex_data)?;
    let ordinary_checkpoints = stage_nested_checkpoints(
        &from_path.join(CHECKPOINT_ROOT),
        ORDINARY_CKPT_CURRENT_GENERATION,
    )?;
    let historical_checkpoints = stage_nested_checkpoints(
        &from_path.join(HISTORICAL_CHECKPOINT_ROOT),
        HISTORICAL_CKPT_CURRENT_GENERATION,
    )?;
    let all_files = write_independent_files(from_path)?;
    let independent_files: Vec<_> = all_files
        .into_iter()
        .filter(|(p, _)| !p.starts_with("chainstate-journal"))
        .collect();

    let mut oracle_digests = BTreeMap::new();
    for (cf, rows) in &chainstate_data {
        oracle_digests.insert(("chainstate", cf.name()), compute_oracle_digest(rows));
    }
    for (cf, rows) in &txindex_data {
        oracle_digests.insert(("txindex", cf.name()), compute_oracle_digest(rows));
    }
    let recoded_undo_rows = vec![
        (undo_key(101, 0x11), undo_value_v2(0x11)),
        (undo_key(102, 0x22), undo_value_v2(0x22)),
    ];
    let mut expected_recoded_chainstate = Vec::new();
    for (cf, rows) in &chainstate_data {
        if *cf == ColumnFamily::UndoData {
            expected_recoded_chainstate.push((*cf, recoded_undo_rows.clone()));
        } else {
            expected_recoded_chainstate.push((*cf, rows.clone()));
        }
    }
    let mut recoded_digests = oracle_digests.clone();
    recoded_digests.insert(
        ("chainstate", ColumnFamily::UndoData.name()),
        compute_oracle_digest(&recoded_undo_rows),
    );

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let surrealkv_str = surrealkv_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output1 = run_converter(&[
        "--from",
        from_str,
        "--to",
        surrealkv_str,
        "--to-engine",
        "surrealkv",
    ])?;

    if !output1.status.success() {
        return Err(TestError::Assertion(format!(
            "RocksDB to surrealkv conversion failed with stderr: {}",
            String::from_utf8_lossy(&output1.stderr)
        )));
    }

    let source_digest_after1 = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after1 {
        return Err(TestError::Assertion(
            "source directory was modified during RocksDB to surrealkv conversion".into(),
        ));
    }

    let report1 = parse_report(&output1)?;
    if report1.source_epoch != 4 || report1.target_epoch != 6 {
        return Err(TestError::Assertion(
            "epoch mismatch in hop 1 report".into(),
        ));
    }

    let cs_report1 = report1
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate in hop 1 report".into()))?;
    if cs_report1.engine != "rocksdb" {
        return Err(TestError::Assertion(format!(
            "expected source engine rocksdb, got {}",
            cs_report1.engine
        )));
    }
    verify_namespace_families(
        cs_report1,
        &expected_recoded_chainstate,
        &recoded_digests,
        "hop 1 cs",
    )?;
    let tx_report1 = report1
        .namespaces
        .iter()
        .find(|n| n.namespace == "txindex")
        .ok_or_else(|| TestError::Assertion("missing txindex in hop 1 report".into()))?;
    if tx_report1.engine != "rocksdb" {
        return Err(TestError::Assertion(format!(
            "expected source engine rocksdb, got {}",
            tx_report1.engine
        )));
    }
    verify_namespace_families(tx_report1, &txindex_data, &oracle_digests, "hop 1 tx")?;

    let dest_schema1 = fs::read_to_string(surrealkv_path.join("CURRENT_SCHEMA"))?;
    if dest_schema1 != "6\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 6 in hop 1".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&surrealkv_path, &independent_files)?;

    verify_nested_checkpoint_images(
        &surrealkv_path,
        CHECKPOINT_ROOT,
        &ordinary_checkpoints,
        StorageBackend::SurrealKv,
        "hop 1 ordinary checkpoints",
    )?;
    verify_nested_checkpoint_images(
        &surrealkv_path,
        HISTORICAL_CHECKPOINT_ROOT,
        &historical_checkpoints,
        StorageBackend::SurrealKv,
        "hop 1 historical checkpoints",
    )?;

    let final_str = final_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output2 = run_converter(&[
        "--from",
        surrealkv_str,
        "--to",
        final_str,
        "--to-engine",
        "rocksdb",
    ])?;

    if !output2.status.success() {
        return Err(TestError::Assertion(format!(
            "surrealkv to RocksDB conversion failed with stderr: {}",
            String::from_utf8_lossy(&output2.stderr)
        )));
    }

    let report2 = parse_report(&output2)?;
    if report2.source_epoch != 6 || report2.target_epoch != 6 {
        return Err(TestError::Assertion(
            "epoch mismatch in hop 2 report".into(),
        ));
    }

    let cs_report2 = report2
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate in hop 2 report".into()))?;
    if cs_report2.engine != "surrealkv" {
        return Err(TestError::Assertion(format!(
            "expected source engine surrealkv, got {}",
            cs_report2.engine
        )));
    }
    verify_namespace_families(
        cs_report2,
        &expected_recoded_chainstate,
        &recoded_digests,
        "hop 2 cs",
    )?;

    let tx_report2 = report2
        .namespaces
        .iter()
        .find(|n| n.namespace == "txindex")
        .ok_or_else(|| TestError::Assertion("missing txindex in hop 2 report".into()))?;
    if tx_report2.engine != "surrealkv" {
        return Err(TestError::Assertion(format!(
            "expected source engine surrealkv, got {}",
            tx_report2.engine
        )));
    }
    verify_namespace_families(tx_report2, &txindex_data, &oracle_digests, "hop 2 tx")?;

    let dest_schema2 = fs::read_to_string(final_path.join("CURRENT_SCHEMA"))?;
    if dest_schema2 != "6\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 6 in hop 2".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&final_path, &independent_files)?;

    verify_nested_checkpoint_images(
        &final_path,
        CHECKPOINT_ROOT,
        &ordinary_checkpoints,
        StorageBackend::RocksDb,
        "hop 2 ordinary checkpoints",
    )?;
    verify_nested_checkpoint_images(
        &final_path,
        HISTORICAL_CHECKPOINT_ROOT,
        &historical_checkpoints,
        StorageBackend::RocksDb,
        "hop 2 historical checkpoints",
    )?;

    verify_final_rocksdb_data(&final_path, "chainstate", &expected_recoded_chainstate)?;
    verify_final_rocksdb_data(&final_path, "txindex", &txindex_data)?;

    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn engine_copy_current_epoch_undo_row_copies_verbatim() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted_mdbx");
    write_schema_marker(from_path, 6)?;
    let chainstate_data = vec![
        (
            ColumnFamily::UtxoMeta,
            vec![(b"head:height".to_vec(), 101_u64.to_le_bytes().to_vec())],
        ),
        (
            ColumnFamily::UndoData,
            vec![(undo_key(101, 0x33), undo_value_v2(0x33))],
        ),
    ];
    let txindex_data = vec![(
        ColumnFamily::BlockHeaders,
        vec![(b"header:00000001".to_vec(), vec![10u8; 80])],
    )];
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;
    write_rocksdb_namespace(&from_path.join("txindex"), &txindex_data)?;
    let all_files = write_independent_files(from_path)?;
    let independent_files: Vec<_> = all_files
        .into_iter()
        .filter(|(p, _)| !p.starts_with("chainstate-journal"))
        .collect();
    let mut oracle_digests = BTreeMap::new();
    for (cf, rows) in &chainstate_data {
        oracle_digests.insert(("chainstate", cf.name()), compute_oracle_digest(rows));
    }
    for (cf, rows) in &txindex_data {
        oracle_digests.insert(("txindex", cf.name()), compute_oracle_digest(rows));
    }
    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let output = run_converter(&["--from", from_str, "--to", to_str, "--to-engine", "mdbx"])?;
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "current-epoch engine copy failed with stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let report = parse_report(&output)?;
    if report.source_epoch != 6 || report.target_epoch != 6 {
        return Err(TestError::Assertion(
            "epoch mismatch in current-epoch copy".into(),
        ));
    }
    let cs_report = report
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate report".into()))?;
    verify_namespace_families(cs_report, &chainstate_data, &oracle_digests, "current cs")?;
    let tx_report = report
        .namespaces
        .iter()
        .find(|n| n.namespace == "txindex")
        .ok_or_else(|| TestError::Assertion("missing txindex report".into()))?;
    verify_namespace_families(tx_report, &txindex_data, &oracle_digests, "current tx")?;
    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "6\n" {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA != 6 in current-epoch copy".into(),
        ));
    }
    assert_independent_files_copied_and_ignored_skipped(&to_path, &independent_files)?;
    Ok(())
}

#[cfg(feature = "surrealkv")]
#[test]
fn epoch5_nested_images_reopen_as_rocksdb_with_schema6_undo() -> TestResult<()> {
    let source = tempdir()?;
    let destination = tempdir()?;
    let from = source.path();
    let to = destination.path().join("converted");
    write_schema_marker(from, 5)?;
    let store = open_engine_store(&from.join("chainstate"), StorageBackend::SurrealKv)?;
    store.put(
        ColumnFamily::UndoData,
        &undo_key(101, 0x33),
        &undo_value_v1_empty(0x33),
    )?;
    store.flush()?;
    drop(store);
    let mut fixtures = Vec::new();
    for (root, generation) in [
        (CHECKPOINT_ROOT, ORDINARY_CKPT_CURRENT_GENERATION),
        (
            HISTORICAL_CHECKPOINT_ROOT,
            HISTORICAL_CKPT_CURRENT_GENERATION,
        ),
    ] {
        let mut fixture = stage_nested_checkpoints_for_epoch(
            &from.join(root),
            generation,
            StorageBackend::SurrealKv,
            5,
        )?;
        for image in &mut fixture.generations {
            for (family, rows) in &mut image.rows {
                if *family == ColumnFamily::UndoData {
                    *rows = vec![(undo_key(101, 0x33), undo_value_v2(0x33))];
                }
            }
        }
        fixtures.push((root, fixture));
    }
    let historical_directory = format!("gen-{HISTORICAL_CKPT_CURRENT_GENERATION:020}");
    let historical_bytes = fs::read(
        from.join(HISTORICAL_CHECKPOINT_ROOT)
            .join(&historical_directory)
            .join(MANIFEST_FILE),
    )?;
    let historical_manifest: CheckpointManifestV1 = sonic_rs::from_slice(&historical_bytes)?;
    let historical_hash = bitcoin_rs_consensus::primitives::Hash256::from_str_be(
        &historical_manifest.applied_tip.hash,
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    let reference = bitcoin_rs_storage::assumeutxo::HistoricalCheckpointRef {
        checkpoint: bitcoin_rs_storage::checkpoint::CheckpointReference {
            generation: HISTORICAL_CKPT_CURRENT_GENERATION,
            manifest_sha256: Sha256::digest(&historical_bytes).into(),
        },
        height: historical_manifest.applied_tip.height,
        hash: historical_hash,
    };
    let head = bitcoin_rs_storage::durable_head::DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Validating {
            base_height: reference.height,
            base_hash: reference.hash,
            expected_hash_serialized: reference.hash,
            chain_tx_count: 0,
            historical_height: reference.height,
            historical_hash: reference.hash,
            pending: None,
            checkpoint: Some(reference),
        },
        commit_id: 1,
        height: historical_manifest.applied_tip.height,
        tip: historical_hash,
        chain_tx_count: 0,
        body_extent: None,
        undo_extent: None,
    };
    let ordinary_directory = format!("gen-{ORDINARY_CKPT_CURRENT_GENERATION:020}");
    let ordinary_root = from.join(CHECKPOINT_ROOT);
    let image_path = ordinary_root.join(&ordinary_directory).join("chainstate");
    let store = open_engine_store(&image_path, StorageBackend::SurrealKv)?;
    store.put(
        ColumnFamily::UtxoMeta,
        bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
        &head.encode(),
    )?;
    store.flush()?;
    drop(store);
    let manifest_path = ordinary_root.join(&ordinary_directory).join(MANIFEST_FILE);
    let mut manifest: CheckpointManifestV1 = sonic_rs::from_slice(&fs::read(&manifest_path)?)?;
    let image_dir = Dir::open_ambient_dir(&image_path, ambient_authority())?;
    manifest.engine = Some(
        digest_engine_dir(&image_dir).map_err(|error| TestError::Assertion(error.to_string()))?,
    );
    let manifest_bytes = sonic_rs::to_vec(&manifest)?;
    fs::write(manifest_path, &manifest_bytes)?;
    let mut current: CurrentV1 =
        sonic_rs::from_slice(&fs::read(ordinary_root.join(CURRENT_FILE))?)?;
    current.manifest_sha256 = hex_lower(&Sha256::digest(&manifest_bytes));
    let current_bytes = sonic_rs::to_vec(&current)?;
    fs::write(ordinary_root.join(CURRENT_FILE), &current_bytes)?;
    let ordinary_fixture = &mut fixtures[0].1;
    ordinary_fixture.root_metadata = current_bytes;
    ordinary_fixture.generations[1].metadata.insert(
        format!("{ordinary_directory}/{MANIFEST_FILE}"),
        manifest_bytes,
    );
    let mut live_head = head;
    live_head.assumeutxo = bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized;
    let store = open_engine_store(&from.join("chainstate"), StorageBackend::SurrealKv)?;
    store.put(
        ColumnFamily::UtxoMeta,
        bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
        &live_head.encode(),
    )?;
    store.flush()?;
    drop(store);
    let before = recursive_dir_digest(from)?;
    let output = run_converter(&[
        "--from",
        from.to_str()
            .ok_or_else(|| TestError::Assertion("utf8 source".into()))?,
        "--to",
        to.to_str()
            .ok_or_else(|| TestError::Assertion("utf8 destination".into()))?,
        "--to-engine",
        "rocksdb",
    ])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(recursive_dir_digest(from)?, before);
    let report = parse_report(&output)?;
    assert_eq!((report.source_epoch, report.target_epoch), (5, 6));
    assert_eq!(fs::read(to.join("CURRENT_SCHEMA"))?, b"6\n");
    verify_final_rocksdb_data(
        &to,
        "chainstate",
        &[(
            ColumnFamily::UndoData,
            vec![(undo_key(101, 0x33), undo_value_v2(0x33))],
        )],
    )?;
    verify_final_rocksdb_data(
        &to,
        "chainstate",
        &[(
            ColumnFamily::UtxoMeta,
            vec![(
                bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY.to_vec(),
                live_head.encode().to_vec(),
            )],
        )],
    )?;
    let destination_manifest = fs::read(
        to.join(HISTORICAL_CHECKPOINT_ROOT)
            .join(historical_directory)
            .join(MANIFEST_FILE),
    )?;
    let destination_manifest_sha256: [u8; 32] = Sha256::digest(destination_manifest).into();
    let mut expected_head = head;
    let bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Validating {
        checkpoint: Some(expected_reference),
        ..
    } = &mut expected_head.assumeutxo
    else {
        return Err(TestError::Assertion(
            "fixture historical reference missing".into(),
        ));
    };
    expected_reference.checkpoint.manifest_sha256 = destination_manifest_sha256;
    let ordinary_rows = &mut fixtures[0].1.generations[1].rows;
    let (_, metadata_rows) = ordinary_rows
        .iter_mut()
        .find(|(family, _)| *family == ColumnFamily::UtxoMeta)
        .ok_or_else(|| TestError::Assertion("fixture metadata family missing".into()))?;
    metadata_rows.push((
        bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY.to_vec(),
        expected_head.encode().to_vec(),
    ));
    for (root, fixture) in fixtures {
        verify_nested_checkpoint_images(
            &to,
            root,
            &fixture,
            StorageBackend::RocksDb,
            "epoch 5 to 6",
        )?;
    }
    Ok(())
}

fn assert_root_marker_survives_conversion(source_epoch: u32) -> TestResult<()> {
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_execution::recovery::{
        ResumeSource, prepare_initial_state_with_engine, requires_full_revalidation,
    };
    use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;

    let source = tempdir()?;
    let destination = tempdir()?;
    let to = destination.path().join("converted");
    write_schema_marker(source.path(), source_epoch)?;
    write_rocksdb_namespace(&source.path().join("chainstate"), &[])?;
    fs::write(source.path().join(FULL_REVALIDATION_MARKER), b"required\n")?;
    let before = recursive_dir_digest(source.path())?;
    let output = run_converter(&[
        "--from",
        source
            .path()
            .to_str()
            .ok_or_else(|| TestError::Assertion("utf8 source".into()))?,
        "--to",
        to.to_str()
            .ok_or_else(|| TestError::Assertion("utf8 destination".into()))?,
    ])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(recursive_dir_digest(source.path())?, before);
    assert_eq!(fs::read(to.join(FULL_REVALIDATION_MARKER))?, b"required\n");
    assert_eq!(
        parse_report(&output)?.carried_markers,
        vec![FULL_REVALIDATION_MARKER]
    );
    assert!(requires_full_revalidation(&to));
    let state = prepare_initial_state_with_engine(&to, Network::Regtest, None, None)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    assert_eq!(state.initial.resume_source, ResumeSource::Cold);
    assert!(state.engine.is_none());
    Ok(())
}

#[test]
fn epoch5_root_marker_preserves_full_replay_startup() -> TestResult<()> {
    assert_root_marker_survives_conversion(5)
}

#[test]
fn epoch6_root_marker_preserves_full_replay_startup() -> TestResult<()> {
    assert_root_marker_survives_conversion(6)
}
