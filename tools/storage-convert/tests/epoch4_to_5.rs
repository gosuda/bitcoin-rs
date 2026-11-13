use std::fs;
use std::path::Path;
use tempfile::tempdir;

use bitcoin_rs_consensus::primitives::{Header, Network, consensus_bytes, deserialize};
use bitcoin_rs_execution::recovery::{ResumeSource, prepare_initial_state_with_engine};
use bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus;
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::utxo::core_snapshot::{SnapshotLimits, read_and_verify};
use bitcoin_rs_storage::utxo::snapshot::{V4Declaration, write_snapshot_records_v4};
use bitcoin_rs_storage::utxo::stats::scan_coin_stats;
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, run_converter};
use super::support::oracle::write_schema_marker;

fn path_str(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("utf8 path".into()))
}

pub(super) fn regtest_pin() -> TestResult<&'static bitcoin_rs_consensus::primitives::AssumeUtxoData>
{
    Network::Regtest
        .assume_utxo_for_height(200)
        .ok_or_else(|| TestError::Assertion("regtest height-200 anchor".into()))
}

fn core_headers() -> TestResult<Vec<Header>> {
    let raw: Vec<String> = sonic_rs::from_str(include_str!(
        "../../../crates/storage/tests/fixtures/core-v2/blocks200.json"
    ))?;
    raw.iter()
        .map(|hex| {
            let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)
                .map_err(|error| TestError::Assertion(error.to_string()))?;
            deserialize(&bitcoin::consensus::serialize(&block.header))
                .map_err(|error| TestError::Assertion(error.to_string()))
        })
        .collect()
}

fn write_snapshot_archive(from: &Path) -> TestResult<()> {
    let pinned = regtest_pin()?;
    let raw = include_bytes!("../../../crates/storage/tests/fixtures/core-v2/core200.dat");
    let loaded = read_and_verify(
        &mut raw.as_slice(),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    assert_eq!(
        loaded.anchor.block_hash, pinned.block_hash,
        "core200 fixture must match the compiled regtest anchor"
    );
    let stats = loaded
        .set
        .with_stable_view(|view| scan_coin_stats(view, pinned.height, true))
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    assert_eq!(
        loaded.hash_serialized, pinned.hash_serialized,
        "core200 commitment must match the compiled regtest anchor"
    );
    let dir = from.join("assumeutxo").join(pinned.block_hash.to_string());
    fs::create_dir_all(&dir)?;
    let mut headers_file = fs::File::create(dir.join("headers.dat"))?;
    use std::io::Write as _;
    let genesis = Network::Regtest.genesis_block().header;
    for header in std::iter::once(genesis).chain(core_headers()?) {
        headers_file.write_all(&consensus_bytes(&header))?;
    }
    headers_file.sync_all()?;
    let records = loaded.set.all_records();
    let record_count = u64::try_from(records.len())?;
    let declaration = V4Declaration {
        tip_hash: &pinned.block_hash,
        height: pinned.height,
        record_count,
    };
    let trailer = stats.muhash.finalize();
    let mut coins_file = fs::File::create(dir.join("coins.dat"))?;
    write_snapshot_records_v4(
        records
            .into_iter()
            .map(Ok::<_, bitcoin_rs_storage::utxo::UtxoError>),
        declaration,
        &mut coins_file,
        &trailer,
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    coins_file.sync_all()?;
    Ok(())
}

fn write_snapshot_engine(from: &Path) -> TestResult<()> {
    let pinned = regtest_pin()?;
    let raw = include_bytes!("../../../crates/storage/tests/fixtures/core-v2/core200.dat");
    let loaded = read_and_verify(
        &mut raw.as_slice(),
        Network::Regtest,
        SnapshotLimits::default(),
    )
    .map_err(|error| TestError::Assertion(error.to_string()))?;
    let mut rows = Vec::new();
    for record in loaded.set.all_records() {
        rows.push((
            record.txid().to_le_bytes().to_vec(),
            record.bytes().to_vec(),
        ));
    }
    let store = RocksDbStore::open(from.join("chainstate"))?;
    let mut batch = store.new_batch();
    for (key, value) in &rows {
        batch.put(ColumnFamily::Coins, key, value);
    }
    let head = DurableHead {
        assumeutxo: AssumeUtxoDiskStatus::Validating {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
            expected_hash_serialized: pinned.hash_serialized,
            chain_tx_count: pinned.chain_tx_count,
            historical_height: 0,
            historical_hash: Network::Regtest.genesis_block_hash(),
            pending: None,
            checkpoint: None,
        },
        commit_id: 1,
        height: pinned.height,
        tip: pinned.block_hash,
        chain_tx_count: pinned.chain_tx_count,
        body_extent: None,
        undo_extent: None,
    };
    batch.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode());
    store.write_durable(batch)?;
    drop(store);
    Ok(())
}

pub(super) fn write_valid_epoch4_snapshot_source(from: &Path) -> TestResult<()> {
    write_schema_marker(from, 4)?;
    write_snapshot_engine(from)?;
    write_snapshot_archive(from)?;
    Ok(())
}

fn converted_report(
    to: &Path,
    from: &Path,
) -> TestResult<super::support::harness::ConversionReport> {
    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(to)?])?;
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    parse_report(&output)
}

#[test]
fn epoch4_valid_archive_converts_and_node_resumes_at_base() -> TestResult<()> {
    let pinned = regtest_pin()?;
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_valid_epoch4_snapshot_source(from)?;

    let report = converted_report(&to, from)?;
    if report.source_epoch != 4 || report.target_epoch != 6 {
        return Err(TestError::Assertion(format!(
            "expected report 4 -> 6, got {} -> {}",
            report.source_epoch, report.target_epoch
        )));
    }
    if !report.published_checkpoint {
        return Err(TestError::Assertion(
            "a valid archive without a checkpoint must publish one".into(),
        ));
    }
    if to.join("assumeutxo").exists() {
        return Err(TestError::Assertion(
            "the archive must not be copied into the new datadir".into(),
        ));
    }
    if fs::read_to_string(to.join("CURRENT_SCHEMA"))? != "6\n" {
        return Err(TestError::Assertion(
            "destination marker must be epoch 6".into(),
        ));
    }
    let store = RocksDbStore::open(to.join("chainstate"))?;
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("converted durable head missing".into()))?;
    let head = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("converted durable head undecodable".into()))?;
    drop(store);

    let state = prepare_initial_state_with_engine(&to, Network::Regtest, Some(&head), None)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if state.initial.resume_source != ResumeSource::Checkpoint {
        return Err(TestError::Assertion(
            "the converted datadir must resume from the published checkpoint".into(),
        ));
    }
    let applied = state
        .initial
        .applied_tip
        .ok_or_else(|| TestError::Assertion("restored tip missing".into()))?;
    if applied.height != pinned.height || applied.hash != pinned.block_hash {
        return Err(TestError::Assertion(
            "the converted datadir must resume at the snapshot base".into(),
        ));
    }
    let engine = state
        .engine
        .ok_or_else(|| TestError::Assertion("restored engine image missing".into()))?;
    let restored_coins = bitcoin_rs_storage::utxo::UtxoSet::new();
    for row in engine.iter_prefix(ColumnFamily::Coins, &[])? {
        let (_key, value) = row?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|error| TestError::Assertion(error.to_string()))?;
        restored_coins.insert_parsed_record(record);
    }
    let restored_hash = restored_coins
        .lock_stable_view()
        .hash_serialized_3_at_height(pinned.height)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if restored_hash != pinned.hash_serialized {
        return Err(TestError::Assertion(
            "restored coin statistics must equal the pinned hash".into(),
        ));
    }
    if state.initial.coin_stats.tx_count != pinned.chain_tx_count {
        return Err(TestError::Assertion(
            "restored coin statistics must equal the pinned transaction count".into(),
        ));
    }
    Ok(())
}

#[test]
fn epoch4_tampered_archive_refuses_without_marker() -> TestResult<()> {
    let pinned = regtest_pin()?;
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_valid_epoch4_snapshot_source(from)?;
    let coins_path = from
        .join("assumeutxo")
        .join(pinned.block_hash.to_string())
        .join("coins.dat");
    let mut bytes = fs::read(&coins_path)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    fs::write(&coins_path, bytes)?;

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "converter must refuse a tampered snapshot archive".into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("failed verification") {
        return Err(TestError::Assertion(format!(
            "refusal must name the archive verification failure, got: {stderr}"
        )));
    }
    if to.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "a refused conversion must write no marker".into(),
        ));
    }
    Ok(())
}

#[test]
fn epoch4_tampered_headers_refuse_without_marker() -> TestResult<()> {
    let pinned = regtest_pin()?;
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_valid_epoch4_snapshot_source(from)?;
    let headers_path = from
        .join("assumeutxo")
        .join(pinned.block_hash.to_string())
        .join("headers.dat");
    let mut bytes = fs::read(&headers_path)?;
    let linkage = 100 * 80 + 10;
    bytes[linkage] ^= 0x01;
    fs::write(&headers_path, bytes)?;

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "converter must refuse a snapshot archive with broken header linkage".into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("checkpoint publication at the durable head failed") {
        return Err(TestError::Assertion(format!(
            "refusal must name the checkpoint publication failure, got: {stderr}"
        )));
    }
    if to.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "a refused conversion must write no marker".into(),
        ));
    }
    Ok(())
}

#[test]
fn epoch4_head_above_base_refuses_without_marker() -> TestResult<()> {
    let pinned = regtest_pin()?;
    let source = tempdir()?;
    let dest = tempdir()?;
    let from = source.path();
    let to = dest.path().join("converted");
    write_valid_epoch4_snapshot_source(from)?;
    let store = RocksDbStore::open(from.join("chainstate"))?;
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("source durable head missing".into()))?;
    let mut head = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("source durable head undecodable".into()))?;
    head.height = pinned.height + 1;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head.encode());
    store.write_durable(batch)?;
    drop(store);

    let output = run_converter(&["--from", path_str(from)?, "--to", path_str(&to)?])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "converter must refuse a head that sits above the snapshot base".into(),
        ));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("missing complete chainstate checkpoint") {
        return Err(TestError::Assertion(format!(
            "refusal must name the missing checkpoint, got: {stderr}"
        )));
    }
    if to.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "a refused conversion must write no marker".into(),
        ));
    }
    Ok(())
}

#[test]
fn epoch4_checkpoint_compatible_source_drops_archive() -> TestResult<()> {
    let pinned = regtest_pin()?;
    let first = tempdir()?;
    let from = first.path().join("converted-once");
    let seed = tempdir()?;
    write_valid_epoch4_snapshot_source(seed.path())?;
    let seed_report = converted_report(&from, seed.path())?;
    if !seed_report.published_checkpoint {
        return Err(TestError::Assertion("seed conversion must publish".into()));
    }
    fs::write(from.join("CURRENT_SCHEMA"), "4\n")?;
    let archive = from.join("assumeutxo").join(pinned.block_hash.to_string());
    fs::create_dir_all(&archive)?;
    fs::write(archive.join("coins.dat"), b"operator-planted archive")?;
    let second = tempdir()?;
    let to = second.path().join("converted-twice");
    let output = run_converter(&[
        "--from",
        path_str(&from)?,
        "--to",
        path_str(&to)?,
        "--to-engine",
        "rocksdb",
    ])?;
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter failed on a checkpoint-compatible source: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let report = parse_report(&output)?;
    if report.source_epoch != 4 || report.target_epoch != 6 {
        return Err(TestError::Assertion(format!(
            "expected report 4 -> 6, got {} -> {}",
            report.source_epoch, report.target_epoch
        )));
    }
    if report.published_checkpoint {
        return Err(TestError::Assertion(
            "a compatible checkpoint must not be republished".into(),
        ));
    }
    if to.join("assumeutxo").exists() {
        return Err(TestError::Assertion(
            "the archive must not be copied into the new datadir".into(),
        ));
    }
    let store = RocksDbStore::open(to.join("chainstate"))?;
    let raw = store
        .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
        .ok_or_else(|| TestError::Assertion("converted durable head missing".into()))?;
    let head = DurableHead::decode(&raw)
        .ok_or_else(|| TestError::Assertion("converted durable head undecodable".into()))?;
    drop(store);
    let state = prepare_initial_state_with_engine(&to, Network::Regtest, Some(&head), None)
        .map_err(|error| TestError::Assertion(error.to_string()))?;
    if state.initial.resume_source != ResumeSource::Checkpoint {
        return Err(TestError::Assertion(
            "the converted datadir must resume from the checkpoint".into(),
        ));
    }
    Ok(())
}
