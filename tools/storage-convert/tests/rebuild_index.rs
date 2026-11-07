use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_projection::{IndexWatermark, IndexWriter};
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};
use serde::Deserialize;

use crate::support::error::{TestError, TestResult};
use crate::support::harness::run_converter;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct FamilyResetReport {
    family: String,
    rows_removed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct RebuildIndexReport {
    datadir: String,
    engine: String,
    format_version: u32,
    families: Vec<FamilyResetReport>,
}

fn parse_rebuild_report(output: &Output) -> TestResult<RebuildIndexReport> {
    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "rebuild-index exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let report: RebuildIndexReport = sonic_rs::from_slice(&output.stdout)?;
    Ok(report)
}

fn seeded_datadir(root: &Path) -> TestResult<PathBuf> {
    let datadir = root.join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "3\n")?;
    let store = Arc::new(RocksDbStore::open(datadir.join("txindex"))?);
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let scripthash = bitcoin_rs_projection::ScriptHash::from_script_bytes(&[0x51, 0x01]);
    let coins = (0_u32..3)
        .map(|vout| {
            (
                OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11_u8; 32])), vout),
                bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 1_000, 5, false),
            )
        })
        .collect::<Vec<_>>();
    writer.seed_script_live(
        coins,
        IndexWatermark {
            height: 5,
            hash: [0x05_u8; 32],
        },
    )?;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Funding, &[0xAA; 10], &[0x01, 0x02]);
    batch.put(ColumnFamily::TxConfirmed, &[0xBB; 10], &[0x03]);
    store.write_durable(batch)?;
    drop(writer);
    drop(store);
    Ok(datadir)
}

fn count_rows(store: &RocksDbStore, cf: ColumnFamily) -> TestResult<u64> {
    let scan = store.scan_prefix_bounded(
        cf,
        &[],
        bitcoin_rs_storage::PrefixScanLimit {
            max_rows: 100_000,
            max_bytes: usize::MAX,
        },
    )?;
    Ok(u64::try_from(scan.rows.len())?)
}

fn family_removed(report: &RebuildIndexReport, family: &str) -> u64 {
    report
        .families
        .iter()
        .find(|entry| entry.family == family)
        .map_or(0, |entry| entry.rows_removed)
}

#[test]
fn rebuild_index_resets_derived_rows_and_stamps_format_eight() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;

    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    let report = parse_rebuild_report(&output)?;
    assert_eq!(report.engine, "rocksdb");
    assert_eq!(report.format_version, 8);
    assert_eq!(family_removed(&report, "script_live"), 3);
    assert_eq!(family_removed(&report, "funding"), 1);
    assert_eq!(family_removed(&report, "tx_confirmed"), 1);

    let store = RocksDbStore::open(datadir.join("txindex"))?;
    assert_eq!(count_rows(&store, ColumnFamily::ScriptLive)?, 0);
    assert_eq!(count_rows(&store, ColumnFamily::Funding)?, 0);
    assert_eq!(count_rows(&store, ColumnFamily::TxConfirmed)?, 0);
    let marker = store
        .get(ColumnFamily::UtxoMeta, &[0x00, b'V'])?
        .expect("reset stamps the format marker");
    assert_eq!(marker.as_slice(), &[0x08, 0x00, 0x00, 0x00]);
    drop(store);

    let store = Arc::new(RocksDbStore::open(datadir.join("txindex"))?);
    let writer = IndexWriter::open(Arc::clone(&store), 2)?;
    assert_eq!(writer.watermarks()?.script_live, None);
    Ok(())
}

#[test]
fn rebuild_index_is_idempotent_on_a_reset_datadir() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;
    for _ in 0..2 {
        let output = run_converter(&[
            "rebuild-index",
            "--datadir",
            datadir.to_string_lossy().as_ref(),
        ])?;
        parse_rebuild_report(&output)?;
    }
    let store = RocksDbStore::open(datadir.join("txindex"))?;
    assert_eq!(count_rows(&store, ColumnFamily::ScriptLive)?, 0);
    Ok(())
}

#[test]
fn rebuild_index_refuses_an_unknown_epoch() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "9\n")?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("epoch"),
        "refusal must name the epoch problem: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_refuses_a_datadir_without_txindex() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = root.path().join("datadir");
    fs::create_dir_all(&datadir)?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "3\n")?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("txindex"),
        "refusal must name the missing namespace: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_refuses_missing_current_schema() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = seeded_datadir(root.path())?;
    fs::remove_file(datadir.join("CURRENT_SCHEMA"))?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("epoch"),
        "missing CURRENT_SCHEMA must be refused with epoch error: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_refuses_empty_txindex_when_chainstate_engine_undetectable() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = root.path().join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "3\n")?;
    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot detect storage engine"),
        "empty txindex without chainstate engine must refuse: {stderr}"
    );
    Ok(())
}

#[test]
fn rebuild_index_empty_txindex_follows_detected_chainstate_engine() -> TestResult {
    let root = tempfile::tempdir()?;
    let datadir = root.path().join("datadir");
    fs::create_dir_all(datadir.join("txindex"))?;
    fs::create_dir_all(datadir.join("chainstate"))?;
    fs::write(datadir.join("CURRENT_SCHEMA"), "3\n")?;
    let cs_store = RocksDbStore::open(datadir.join("chainstate"))?;
    drop(cs_store);

    let output = run_converter(&[
        "rebuild-index",
        "--datadir",
        datadir.to_string_lossy().as_ref(),
    ])?;
    let report = parse_rebuild_report(&output)?;
    assert_eq!(report.engine, "rocksdb");
    assert_eq!(report.format_version, 8);

    let store = RocksDbStore::open(datadir.join("txindex"))?;
    let marker = store
        .get(ColumnFamily::UtxoMeta, &[0x00, b'V'])?
        .expect("format marker in UtxoMeta");
    assert_eq!(marker.as_slice(), &[0x08, 0x00, 0x00, 0x00]);
    let desc = store
        .get(
            ColumnFamily::IdxMeta,
            &bitcoin_rs_projection::segment::meta_gen_key(
                bitcoin_rs_projection::IndexCapability::TxLookup,
            ),
        )?
        .expect("generation descriptor in IdxMeta");
    assert!(!desc.is_empty());
    let idx_meta_marker = store.get(ColumnFamily::IdxMeta, &[0x00, b'V'])?;
    assert!(idx_meta_marker.is_none());
    Ok(())
}
