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
    HEADER_CODEC, HEADERS_FILE, HISTORICAL_CHECKPOINT_ROOT, HeadersArtifactV1, MANIFEST_FILE,
    MANIFEST_FORMAT,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore, StorageBackend};

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
                (b"undo:00000001".to_vec(), vec![1u8; 128]),
                (b"undo:00000002".to_vec(), vec![2u8; 256]),
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
/// headers-v1.dat and coinstats-v1.dat artifact, and, when `with_image`, a
/// real RocksDB checkpoint image written with `write_rocksdb_namespace`.
/// The manifest carries no utxo artifact, matching the epoch-4 published form.
fn stage_generation(
    root: &Path,
    generation: u64,
    tag: &str,
    with_image: bool,
) -> TestResult<GenerationFixture> {
    let directory = format!("gen-{generation:020}");
    let generation_path = root.join(&directory);
    fs::create_dir_all(&generation_path)?;

    let headers_bytes = artifact_bytes(tag.as_bytes());
    let coinstats_bytes = artifact_bytes(format!("cs-{tag}").as_bytes());
    let headers_sha = Sha256::digest(&headers_bytes);
    let coinstats_sha = Sha256::digest(&coinstats_bytes);
    let tip = checkpoint_tip(2_500_000, tag.as_bytes())?;

    let manifest = CheckpointManifestV1 {
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
    let manifest_bytes = sonic_rs::to_vec(&manifest)
        .map_err(|error| TestError::Assertion(format!("manifest serialization failed: {error}")))?;

    let mut metadata = BTreeMap::new();
    metadata.insert(format!("{directory}/{MANIFEST_FILE}"), manifest_bytes);
    metadata.insert(format!("{directory}/{HEADERS_FILE}"), headers_bytes);
    metadata.insert(format!("{directory}/{COINSTATS_FILE}"), coinstats_bytes);
    for (rel, bytes) in &metadata {
        fs::write(root.join(rel), bytes)?;
    }

    let rows = if with_image {
        let image_rows = checkpoint_image_rows(tag)?;
        super::support::oracle::write_rocksdb_namespace(
            &generation_path.join("chainstate"),
            &image_rows,
        )?;
        image_rows
    } else {
        Vec::new()
    };

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
    fs::create_dir_all(root)?;
    let retained = stage_generation(root, current_generation - 1, "old", true)?;
    let current = stage_generation(root, current_generation, "cur", true)?;
    let bare = stage_generation(root, current_generation + 1, "bare", false)?;

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

/// After a hop, every canonical generation under `root` must keep its
/// metadata byte-identical, the retained and current images must be readable
/// with exactly the requested backend engine and hold the staged rows, and the
/// generation staged without an image must still have no image.
fn verify_nested_checkpoint_images(
    dest_data_root: &Path,
    checkpoint_root: &str,
    fixture: &NestedCheckpointFixture,
    expected_backend: StorageBackend,
    hop_label: &str,
) -> TestResult<()> {
    let root = dest_data_root.join(checkpoint_root);
    let current_bytes = fs::read(root.join(CURRENT_FILE))?;
    if current_bytes != fixture.root_metadata {
        return Err(TestError::Assertion(format!(
            "checkpoint {checkpoint_root} CURRENT bytes changed during {hop_label}"
        )));
    }
    for generation in &fixture.generations {
        let directory = format!("gen-{:020}", generation.generation);
        for (rel, expected) in &generation.metadata {
            let actual = fs::read(root.join(rel))?;
            if actual != *expected {
                return Err(TestError::Assertion(format!(
                    "checkpoint {checkpoint_root}/{rel} metadata bytes changed during {hop_label}"
                )));
            }
        }
        let image = root.join(&directory).join("chainstate");
        if generation.rows.is_empty() {
            if image.exists() {
                return Err(TestError::Assertion(format!(
                    "checkpoint {checkpoint_root}/{directory} gained an image it did not have in {hop_label}"
                )));
            }
            continue;
        }
        let detected = bitcoin_rs_storage::detect_engine(&image)?;
        if detected != Some(expected_backend) {
            return Err(TestError::Assertion(format!(
                "checkpoint {checkpoint_root}/{directory} image engine is {:?}, expected {} in {hop_label}",
                detected,
                expected_backend.as_str()
            )));
        }
        let store = open_engine_store(&image, expected_backend)?;
        let actual_rows = read_store_rows(store.as_ref())?;
        for (cf, expected_rows) in &generation.rows {
            let (_, rows) = actual_rows
                .iter()
                .find(|(actual_cf, _)| actual_cf == cf)
                .ok_or_else(|| {
                    TestError::Assertion(format!(
                        "checkpoint {checkpoint_root}/{directory} image missing family {} in {hop_label}",
                        cf.name()
                    ))
                })?;
            let mut sorted_expected = expected_rows.clone();
            sorted_expected.sort_by(|a, b| a.0.cmp(&b.0));
            if rows != &sorted_expected {
                return Err(TestError::Assertion(format!(
                    "checkpoint {checkpoint_root}/{directory} family {} rows differ in {hop_label}",
                    cf.name()
                )));
            }
        }
    }
    Ok(())
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

// RCV-04
#[test]
fn engine_copy_preserves_memory_checkpoint_for_historical_restore() -> TestResult<()> {
    use bitcoin_rs_consensus::primitives::{Hash256, Network};
    use bitcoin_rs_execution::{AssumeUtxoManager, HistoricalCheckpointRef};
    use bitcoin_rs_storage::checkpoint::CheckpointReference;
    use bitcoin_rs_storage::memory_kv::{MEMORY_KV_FILE, MemoryKvStore};
    use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

    let temporary = tempdir()?;
    let legacy = temporary.path().join("legacy");
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
        &path_text(&source)?,
    ])?)?;
    let ordinary_root = source.join(CHECKPOINT_ROOT);
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
    let manifest: CheckpointManifestV1 = sonic_rs::from_slice(&manifest_bytes)?;
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
    let rows = [
        (
            ColumnFamily::UndoData,
            vec![0x29; 36],
            bitcoin_rs_storage::utxo::contract::encode_undo_record(
                &bitcoin_rs_storage::utxo::contract::UndoBatch::from_parts(
                    Vec::new(),
                    vec![bitcoin_rs_consensus::primitives::OutPoint::new(
                        bitcoin_rs_consensus::primitives::Txid(Hash256::from_le_bytes(&[0x92; 32])),
                        7,
                    )],
                ),
                Hash256::from_le_bytes(&[0x38; 32]),
            ),
        ),
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
    assert_eq!(
        fs::read(restored_generation.join("chainstate").join(MEMORY_KV_FILE))?,
        memory_bytes,
    );
    for artifact in [HEADERS_FILE, COINSTATS_FILE] {
        assert_eq!(
            fs::read(restored_generation.join(artifact))?,
            fs::read(generation.join(artifact))?,
        );
    }
    assert_eq!(
        fs::read(restored_generation.join(MANIFEST_FILE))?,
        manifest_bytes
    );
    assert_eq!(
        fs::read(
            destination
                .join(HISTORICAL_CHECKPOINT_ROOT)
                .join(CURRENT_FILE)
        )?,
        current_bytes
    );
    let restored =
        AssumeUtxoManager::historical_checkpoint_engine(Network::Regtest, destination, &reference)
            .map_err(|error| TestError::Assertion(error.to_string()))?
            .ok_or_else(|| TestError::Assertion("memory checkpoint engine missing".into()))?;
    for (family, key, value) in &rows {
        assert_eq!(
            restored.get(*family, key)?.as_deref(),
            Some(value.as_slice())
        );
    }
    fs::write(
        generation.join("chainstate").join("foreign-engine"),
        b"unknown",
    )?;
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
    if report1.source_epoch != 4 || report1.target_epoch != 4 {
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
    verify_namespace_families(cs_report1, &chainstate_data, &oracle_digests, "hop 1 cs")?;

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
    if dest_schema1 != "4\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 1".into()));
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
    if report2.source_epoch != 4 || report2.target_epoch != 4 {
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
    verify_namespace_families(cs_report2, &chainstate_data, &oracle_digests, "hop 2 cs")?;

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
    if dest_schema2 != "4\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 2".into()));
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

    verify_final_rocksdb_data(&final_path, "chainstate", &chainstate_data)?;
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
    if report1.source_epoch != 4 || report1.target_epoch != 4 {
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
    verify_namespace_families(cs_report1, &chainstate_data, &oracle_digests, "hop 1 cs")?;
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
    if dest_schema1 != "4\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 1".into()));
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
    if report2.source_epoch != 4 || report2.target_epoch != 4 {
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
    verify_namespace_families(cs_report2, &chainstate_data, &oracle_digests, "hop 2 cs")?;

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
    if dest_schema2 != "4\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 2".into()));
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

    verify_final_rocksdb_data(&final_path, "chainstate", &chainstate_data)?;
    verify_final_rocksdb_data(&final_path, "txindex", &txindex_data)?;

    Ok(())
}
