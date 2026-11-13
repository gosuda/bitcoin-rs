use std::fs;
use std::path::{Path, PathBuf};

use bitcoin_rs_consensus::primitives::{Hash256, Network, OutPoint, Txid};
use bitcoin_rs_execution::{AssumeUtxoManager, HistoricalCheckpointRef};
use bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus;
use bitcoin_rs_storage::checkpoint::{
    COINSTATS_FILE, CheckpointManifestV1, CheckpointReference, HEADERS_FILE,
    HISTORICAL_CHECKPOINT_ROOT, MANIFEST_FILE,
};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::snapshot::read_snapshot_strict_v4;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, recursive_dir_digest, run_converter};

const GENERATION: &str = "gen-00000000000000000001";
const UTXO_FILE: &str = "utxo-v4.dat";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest")
}

fn copy_tree(from: &Path, to: &Path) -> TestResult<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn stage_historical_source(from: &Path) -> TestResult<()> {
    copy_tree(&fixture_dir(), from)?;
    let checkpoint = from.join("chainstate-checkpoints").join(GENERATION);
    let historical = from.join(HISTORICAL_CHECKPOINT_ROOT).join(GENERATION);
    copy_tree(&checkpoint, &historical)
}

fn str_path(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

fn converted_generation(to: &Path) -> PathBuf {
    to.join(HISTORICAL_CHECKPOINT_ROOT).join(GENERATION)
}

fn read_manifest(generation: &Path) -> TestResult<(Vec<u8>, CheckpointManifestV1)> {
    let bytes = fs::read(generation.join(MANIFEST_FILE))?;
    let manifest: CheckpointManifestV1 = sonic_rs::from_slice(&bytes)
        .map_err(|error| TestError::Assertion(format!("manifest: {error}")))?;
    Ok((bytes, manifest))
}

fn historical_reference(generation: &Path) -> TestResult<HistoricalCheckpointRef> {
    let (bytes, manifest) = read_manifest(generation)?;
    let manifest_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let hash = Hash256::from_str_be(&manifest.applied_tip.hash)
        .map_err(|error| TestError::Assertion(format!("tip hash: {error}")))?;
    Ok(HistoricalCheckpointRef {
        checkpoint: CheckpointReference {
            generation: 1,
            manifest_sha256,
        },
        height: manifest.applied_tip.height,
        hash,
    })
}

#[test]
fn converted_historical_generation_loads_epoch3_coins_through_assumeutxo() -> TestResult {
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    stage_historical_source(from)?;
    let old_reference = historical_reference(&converted_generation(from))?;
    fs::copy(
        from.join("chainstate-checkpoints").join("CURRENT"),
        from.join(HISTORICAL_CHECKPOINT_ROOT).join("CURRENT"),
    )?;
    let source_head = {
        let store = RocksDbStore::open(from.join("chainstate"))?;
        let bytes = store
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
            .ok_or_else(|| TestError::Assertion("source head missing".into()))?;
        let mut head = DurableHead::decode(&bytes)
            .ok_or_else(|| TestError::Assertion("source head malformed".into()))?;
        head.assumeutxo = AssumeUtxoDiskStatus::Validating {
            base_height: head.height,
            base_hash: head.tip,
            expected_hash_serialized: Hash256::default(),
            chain_tx_count: head.chain_tx_count,
            historical_height: old_reference.height,
            historical_hash: old_reference.hash,
            pending: None,
            checkpoint: Some(old_reference),
        };
        store.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode())?;
        head
    };
    let source_digest = recursive_dir_digest(from)?;

    let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
    parse_report(&output)?;

    let generation = converted_generation(&to);
    let (_, manifest) = read_manifest(&generation)?;
    if manifest.utxo.is_some() {
        return Err(TestError::Assertion(
            "converted historical manifest must not carry a utxo payload".into(),
        ));
    }
    if generation.join(UTXO_FILE).exists() {
        return Err(TestError::Assertion(
            "converted historical generation must not carry utxo-v4.dat".into(),
        ));
    }
    let converted_head = {
        let store = RocksDbStore::open(to.join("chainstate"))?;
        let bytes = store
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
            .ok_or_else(|| TestError::Assertion("converted head missing".into()))?;
        DurableHead::decode(&bytes)
            .ok_or_else(|| TestError::Assertion("converted head malformed".into()))?
    };
    let AssumeUtxoDiskStatus::Validating {
        checkpoint: Some(reference),
        ..
    } = converted_head.assumeutxo
    else {
        return Err(TestError::Assertion(
            "persisted historical reference lost".into(),
        ));
    };
    assert_ne!(
        reference.checkpoint.manifest_sha256,
        old_reference.checkpoint.manifest_sha256
    );
    let mut expected_head = source_head;
    if let AssumeUtxoDiskStatus::Validating { checkpoint, .. } = &mut expected_head.assumeutxo {
        *checkpoint = Some(reference);
    }
    assert_eq!(converted_head, expected_head);
    let root = bitcoin_rs_storage::checkpoint::open_data_dir(&to)?;
    match bitcoin_rs_storage::checkpoint::open_current_checkpoint_at(
        &root,
        HISTORICAL_CHECKPOINT_ROOT,
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?
    {
        bitcoin_rs_storage::checkpoint::CheckpointOpen::Selected {
            reference: selected,
            ..
        } => {
            assert_eq!(selected, reference.checkpoint);
        }
        bitcoin_rs_storage::checkpoint::CheckpointOpen::Cold => {
            return Err(TestError::Assertion("historical CURRENT lost".into()));
        }
    }
    assert_eq!(recursive_dir_digest(from)?, source_digest);

    let engine =
        AssumeUtxoManager::historical_checkpoint_engine(Network::Regtest, to.clone(), &reference)
            .map_err(|error| TestError::Assertion(error.to_string()))?
            .ok_or_else(|| {
                TestError::Assertion("historical checkpoint must restore an engine".into())
            })?;

    let source_generation = from.join(HISTORICAL_CHECKPOINT_ROOT).join(GENERATION);
    let mut snapshot_file = fs::File::open(source_generation.join(UTXO_FILE))?;
    let snapshot = read_snapshot_strict_v4(&mut snapshot_file)
        .map_err(|error| TestError::Assertion(format!("epoch-3 utxo-v4.dat: {error}")))?;

    let rows = engine
        .iter_prefix(ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()?;
    let mut outputs = 0_u64;
    for (key, value) in &rows {
        let txid_bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| TestError::Assertion("coin key must be a 32-byte txid".into()))?;
        let txid = Txid(Hash256::from_le_bytes(&txid_bytes));
        let record = UtxoRecord::from_encoded(value.clone().into_boxed_slice())
            .map_err(|error| TestError::Assertion(format!("coin record: {error}")))?;
        for out in record.outputs() {
            outputs += 1;
            let coin = snapshot
                .set
                .get_entry(&OutPoint::new(txid, out.vout))
                .ok_or_else(|| {
                    TestError::Assertion("engine coin absent from utxo-v4.dat".into())
                })?;
            if coin.txout.value.to_sat() != out.value
                || coin.txout.script_pubkey.as_bytes() != out.script_pubkey
                || coin.coinbase != out.coinbase
                || coin.height != out.height
            {
                return Err(TestError::Assertion(
                    "engine coin differs from the epoch-3 utxo-v4.dat coin".into(),
                ));
            }
        }
    }

    let source_utxo = read_manifest(&source_generation)?
        .1
        .utxo
        .ok_or_else(|| TestError::Assertion("source historical manifest must carry utxo".into()))?;
    let record_count =
        u64::try_from(rows.len()).map_err(|error| TestError::Assertion(error.to_string()))?;
    if record_count != source_utxo.record_count {
        return Err(TestError::Assertion(format!(
            "engine holds {} coin records, epoch-3 utxo-v4.dat holds {}",
            rows.len(),
            source_utxo.record_count
        )));
    }
    if outputs != source_utxo.output_count {
        return Err(TestError::Assertion(format!(
            "engine holds {outputs} outputs, epoch-3 utxo-v4.dat holds {}",
            source_utxo.output_count
        )));
    }
    Ok(())
}

#[test]
fn historical_payload_requires_independent_manifest_commitments() -> TestResult {
    for corrupt_length in [true, false] {
        let source = tempdir()?;
        let dest = tempdir()?;
        let from = source.path();
        let to = dest.path().join("converted");
        stage_historical_source(from)?;
        let generation = converted_generation(from);
        let payload = fs::read(generation.join(UTXO_FILE))?;
        let (_, mut manifest) = read_manifest(&generation)?;
        let utxo = manifest.utxo.as_mut().ok_or_else(|| {
            TestError::Assertion("fixture must contain a payload commitment".into())
        })?;
        if corrupt_length {
            utxo.bytes += 1;
        } else {
            utxo.sha256 = "00".repeat(32);
        }
        let manifest_bytes =
            sonic_rs::to_vec(&manifest).map_err(|error| TestError::Assertion(error.to_string()))?;
        fs::write(generation.join(MANIFEST_FILE), &manifest_bytes)?;
        let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
        assert!(
            !output.status.success(),
            "uncommitted historical payload must refuse"
        );
        assert!(!to.join("CURRENT_SCHEMA").exists());
        let target_generation = converted_generation(&to);
        assert!(!target_generation.join("chainstate").exists());
        assert_eq!(fs::read(generation.join(UTXO_FILE))?, payload);
        assert_eq!(fs::read(generation.join(MANIFEST_FILE))?, manifest_bytes);
    }
    Ok(())
}

#[test]
fn retained_historical_artifacts_require_manifest_commitments() -> TestResult {
    for artifact in [HEADERS_FILE, COINSTATS_FILE] {
        let source = tempdir()?;
        let dest = tempdir()?;
        let from = source.path();
        let to = dest.path().join("converted");
        stage_historical_source(from)?;
        let generation = converted_generation(from);
        let payload = fs::read(generation.join(artifact))?;
        let manifest_bytes = fs::read(generation.join(MANIFEST_FILE))?;
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0xff;
        fs::write(generation.join(artifact), &corrupted)?;
        let source_digest = recursive_dir_digest(from)?;

        let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
        assert!(
            !output.status.success(),
            "retained historical {artifact} without a matching manifest commitment must refuse"
        );
        assert!(!to.join("CURRENT_SCHEMA").exists());
        let target_generation = converted_generation(&to);
        assert!(!target_generation.join("chainstate").exists());
        assert!(
            target_generation.join(UTXO_FILE).exists(),
            "refusal must retire no historical utxo payload"
        );
        assert_eq!(
            fs::read(target_generation.join(MANIFEST_FILE))?,
            manifest_bytes
        );
        assert_eq!(recursive_dir_digest(from)?, source_digest);
    }
    Ok(())
}

#[test]
fn authenticated_malformed_canonical_artifacts_refuse_equal_head_conversion() -> TestResult {
    use bitcoin_rs_consensus::primitives::hex::hex_encode;
    use bitcoin_rs_storage::checkpoint::{
        CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CurrentV1, HEADERS_FILE,
    };
    for artifact in [HEADERS_FILE, COINSTATS_FILE] {
        let source = tempdir()?;
        let dest = tempdir()?;
        let from = source.path();
        let to = dest.path().join("converted");
        copy_tree(&fixture_dir(), from)?;
        let checkpoint_root = from.join(CHECKPOINT_ROOT);
        let generation = checkpoint_root.join(GENERATION);
        let path = generation.join(artifact);
        let mut payload = fs::read(&path)?;
        payload[0] ^= 0xff;
        fs::write(&path, &payload)?;
        let (_, mut manifest) = read_manifest(&generation)?;
        let digest = hex_encode(&Sha256::digest(&payload));
        if artifact == HEADERS_FILE {
            manifest.headers.sha256 = digest;
        } else {
            manifest.coinstats.sha256 = digest;
        }
        let bytes =
            sonic_rs::to_vec(&manifest).map_err(|error| TestError::Assertion(error.to_string()))?;
        fs::write(generation.join(MANIFEST_FILE), &bytes)?;
        let current_path = checkpoint_root.join(CURRENT_FILE);
        let mut current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)
            .map_err(|error| TestError::Assertion(error.to_string()))?;
        current.manifest_sha256 = hex_encode(&Sha256::digest(&bytes));
        fs::write(
            &current_path,
            sonic_rs::to_vec(&current).map_err(|error| TestError::Assertion(error.to_string()))?,
        )?;
        let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
        assert!(
            !output.status.success(),
            "authenticated malformed artifact must refuse"
        );
        assert!(!to.join("CURRENT_SCHEMA").exists());
        assert!(!to.join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
        assert_eq!(fs::read(path)?, payload);
        assert_eq!(fs::read(generation.join(MANIFEST_FILE))?, bytes);
    }
    Ok(())
}

#[test]
fn historical_current_with_wrong_source_digest_is_not_reauthenticated() -> TestResult {
    use bitcoin_rs_storage::checkpoint::{CHECKPOINT_ROOT, CURRENT_FILE, CurrentV1};
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    stage_historical_source(from)?;
    let mut current: CurrentV1 =
        sonic_rs::from_slice(&fs::read(from.join(CHECKPOINT_ROOT).join(CURRENT_FILE))?)
            .map_err(|error| TestError::Assertion(error.to_string()))?;
    current.manifest_sha256 = "00".repeat(32);
    let bytes =
        sonic_rs::to_vec(&current).map_err(|error| TestError::Assertion(error.to_string()))?;
    let current_path = from.join(HISTORICAL_CHECKPOINT_ROOT).join(CURRENT_FILE);
    fs::write(&current_path, &bytes)?;
    let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
    assert!(
        !output.status.success(),
        "untrusted source reference must refuse"
    );
    assert!(!to.join("CURRENT_SCHEMA").exists());
    assert_eq!(fs::read(current_path)?, bytes);
    Ok(())
}

fn streaming_tree_digest(root: &Path) -> TestResult<[u8; 32]> {
    use std::io::Read;
    fn visit(path: &Path, hash: &mut Sha256) -> TestResult {
        let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            hash.update(entry.file_name().as_encoded_bytes());
            if entry.file_type()?.is_dir() {
                hash.update(b"directory");
                visit(&entry.path(), hash)?;
            } else {
                hash.update(fs::metadata(entry.path())?.len().to_le_bytes());
                let mut file = fs::File::open(entry.path())?;
                let mut buffer = [0_u8; 16 * 1024];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&buffer[..count]);
                }
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    visit(root, &mut hash)?;
    Ok(hash.finalize().into())
}

#[test]
fn equal_head_epoch3_conversion_preserves_canonical_headers_over_64_mib() -> TestResult {
    use bitcoin_rs_consensus::primitives::hex::hex_encode;
    use bitcoin_rs_consensus::primitives::{Header, deserialize};
    use bitcoin_rs_execution::chain::compact_is_met_by;
    use bitcoin_rs_storage::checkpoint::{CHECKPOINT_ROOT, CURRENT_FILE, CurrentV1};
    use std::io::{BufWriter, Read, Write};

    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    copy_tree(&fixture_dir(), from)?;
    let checkpoint_root = from.join(CHECKPOINT_ROOT);
    let generation = checkpoint_root.join(GENERATION);
    let (_, mut manifest) = read_manifest(&generation)?;
    let path = generation.join(HEADERS_FILE);
    let original = fs::read(&path)?;
    let active_end = 56
        + usize::try_from(manifest.headers.header_count)
            .map_err(|error| TestError::Assertion(error.to_string()))?
            * Header::LEN;
    assert_eq!(original.len(), active_end + 8);
    assert_eq!(&original[active_end..], &0_u64.to_le_bytes());
    let genesis: Header = deserialize(&original[56..56 + Header::LEN])
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    let mut sibling: Header = deserialize(&original[56 + Header::LEN..56 + 2 * Header::LEN])
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    assert_eq!(sibling.prev_blockhash, genesis.compute_hash());
    let active_bytes =
        u64::try_from(active_end).map_err(|error| TestError::Assertion(error.to_string()))?;
    let side_count = (64_u64 * 1024 * 1024 - active_bytes - 8) / 80 + 1;
    let mut digest = Sha256::new();
    let mut writer = BufWriter::new(fs::File::create(&path)?);
    writer.write_all(&original[..active_end])?;
    digest.update(&original[..active_end]);
    writer.write_all(&side_count.to_le_bytes())?;
    digest.update(side_count.to_le_bytes());
    for index in 0..side_count {
        let mut root = [0_u8; 32];
        root[..8].copy_from_slice(&index.to_le_bytes());
        root[31] = 0xa5;
        sibling.merkle_root = Hash256::from_le_bytes(&root);
        sibling.nonce = 0;
        while !compact_is_met_by(sibling.bits, Hash256::from(sibling.compute_hash())) {
            sibling.nonce = sibling
                .nonce
                .checked_add(1)
                .ok_or_else(|| TestError::Assertion("fixture nonce exhausted".into()))?;
        }
        let encoded = sibling.to_bytes();
        writer.write_all(&encoded)?;
        digest.update(encoded);
    }
    writer.flush()?;
    drop(writer);
    manifest.headers.bytes = active_bytes + 8 + side_count * 80;
    assert!(manifest.headers.bytes > 64 * 1024 * 1024);
    assert_eq!(fs::metadata(&path)?.len(), manifest.headers.bytes);
    manifest.headers.sha256 = hex_encode(&digest.finalize());
    let manifest_bytes =
        sonic_rs::to_vec(&manifest).map_err(|error| TestError::Assertion(error.to_string()))?;
    fs::write(generation.join(MANIFEST_FILE), &manifest_bytes)?;
    let reference = CheckpointReference {
        generation: manifest.generation,
        manifest_sha256: Sha256::digest(&manifest_bytes).into(),
    };
    let current_path = checkpoint_root.join(CURRENT_FILE);
    let mut current: CurrentV1 = sonic_rs::from_slice(&fs::read(&current_path)?)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    current.manifest_sha256 = hex_encode(&reference.manifest_sha256);
    fs::write(
        &current_path,
        sonic_rs::to_vec(&current).map_err(|error| TestError::Assertion(error.to_string()))?,
    )?;
    let source_head = {
        let store = RocksDbStore::open(from.join("chainstate"))?;
        store
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
            .ok_or_else(|| TestError::Assertion("source head missing".into()))?
    };
    let head = DurableHead::decode(&source_head)
        .ok_or_else(|| TestError::Assertion("source head malformed".into()))?;
    assert_eq!(head.height, manifest.applied_tip.height);
    assert_eq!(head.tip.to_string_be(), manifest.applied_tip.hash);
    let dir = bitcoin_rs_storage::checkpoint::open_data_dir(&generation)?;
    bitcoin_rs_execution::recovery::validate_conversion_checkpoint_artifacts(
        &dir,
        &reference,
        Network::Regtest,
    )
    .map_err(|error| TestError::Assertion(format!("canonical precondition: {error}")))?;
    drop(dir);
    let source_digest = streaming_tree_digest(from)?;
    let output = run_converter(&["--from", str_path(from)?, "--to", str_path(&to)?])?;
    assert_eq!(streaming_tree_digest(from)?, source_digest);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("checkpoint entry \"headers-v1.dat\" exceeds its size bound"),
            "conversion failed before the publication size guard: {stderr}"
        );
        panic!("valid canonical artifact exceeds only the whole-file publication limit: {stderr}");
    }
    parse_report(&output)?;
    assert_eq!(fs::read(to.join("CURRENT_SCHEMA"))?, b"4\n");
    let target_generation = to.join(CHECKPOINT_ROOT).join(GENERATION);
    for artifact in [HEADERS_FILE, COINSTATS_FILE] {
        let mut source_file = fs::File::open(generation.join(artifact))?;
        let mut target_file = fs::File::open(target_generation.join(artifact))?;
        assert_eq!(source_file.metadata()?.len(), target_file.metadata()?.len());
        let mut expected = [0_u8; 16 * 1024];
        let mut actual = [0_u8; 16 * 1024];
        loop {
            let count = source_file.read(&mut expected)?;
            if count == 0 {
                break;
            }
            target_file.read_exact(&mut actual[..count])?;
            assert_eq!(&actual[..count], &expected[..count]);
        }
    }
    let (_, target_manifest) = read_manifest(&target_generation)?;
    manifest.utxo = None;
    assert_eq!(
        sonic_rs::to_vec(&target_manifest)
            .map_err(|error| TestError::Assertion(error.to_string()))?,
        sonic_rs::to_vec(&manifest).map_err(|error| TestError::Assertion(error.to_string()))?
    );
    let target_current: CurrentV1 =
        sonic_rs::from_slice(&fs::read(to.join(CHECKPOINT_ROOT).join(CURRENT_FILE))?)
            .map_err(|error| TestError::Assertion(error.to_string()))?;
    assert_eq!(target_current.generation, reference.generation);
    assert_eq!(target_current.directory, GENERATION);
    assert_eq!(
        target_current.manifest_sha256,
        hex_encode(&Sha256::digest(fs::read(
            target_generation.join(MANIFEST_FILE)
        )?))
    );
    let target_store = RocksDbStore::open(to.join("chainstate"))?;
    assert_eq!(
        target_store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?,
        Some(source_head)
    );
    Ok(())
}
