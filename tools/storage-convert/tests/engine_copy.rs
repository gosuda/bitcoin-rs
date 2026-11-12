#![cfg(any(feature = "mdbx", feature = "surrealkv"))]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

use bitcoin_rs_storage::ColumnFamily;

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
        let expected_count = u64::try_from(expected_rows.len()).expect("row count fits in u64");
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

#[cfg(feature = "mdbx")]
#[test]
fn engine_copy_rocksdb_to_mdbx_and_back_is_identical() -> TestResult<()> {
    let source_temp = tempdir()?;
    let mdbx_temp = tempdir()?;
    let final_rocks_temp = tempdir()?;

    let from_path = source_temp.path();
    let mdbx_path = mdbx_temp.path().join("converted_mdbx");
    let final_path = final_rocks_temp.path().join("converted_rocksdb");

    write_schema_marker(from_path, 3)?;

    let (chainstate_data, txindex_data) = make_test_datasets();
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;
    write_rocksdb_namespace(&from_path.join("txindex"), &txindex_data)?;
    let independent_files = write_independent_files(from_path)?;

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
    if report1.source_epoch != 3 || report1.target_epoch != 3 {
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
    if dest_schema1 != "3\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 1".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&mdbx_path, &independent_files)?;

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
    if report2.source_epoch != 3 || report2.target_epoch != 3 {
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
    if dest_schema2 != "3\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 2".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&final_path, &independent_files)?;

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

    write_schema_marker(from_path, 3)?;

    let (chainstate_data, txindex_data) = make_test_datasets();
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;
    write_rocksdb_namespace(&from_path.join("txindex"), &txindex_data)?;
    let independent_files = write_independent_files(from_path)?;

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
    if report1.source_epoch != 3 || report1.target_epoch != 3 {
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
    if dest_schema1 != "3\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 1".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&surrealkv_path, &independent_files)?;

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
    if report2.source_epoch != 3 || report2.target_epoch != 3 {
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
    if dest_schema2 != "3\n" {
        return Err(TestError::Assertion("CURRENT_SCHEMA != 3 in hop 2".into()));
    }
    assert_independent_files_copied_and_ignored_skipped(&final_path, &independent_files)?;

    verify_final_rocksdb_data(&final_path, "chainstate", &chainstate_data)?;
    verify_final_rocksdb_data(&final_path, "txindex", &txindex_data)?;

    Ok(())
}
