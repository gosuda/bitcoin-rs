use std::fs;
use tempfile::tempdir;

use bitcoin_rs_storage::ColumnFamily;

use super::support::error::{TestError, TestResult};
use super::support::harness::{
    compute_oracle_digest, parse_report, recursive_dir_digest, run_converter,
};
use super::support::oracle::{read_rocksdb_all_rows, write_fjall_namespace, write_schema_marker};

#[test]
fn pool_ledger_converts_with_paired_flags_and_preserves_rows() -> TestResult<()> {
    let node_from_temp = tempdir()?;
    let node_to_temp = tempdir()?;
    let pool_from_temp = tempdir()?;
    let pool_to_temp = tempdir()?;

    let node_from = node_from_temp.path();
    let node_to = node_to_temp.path().join("converted_node");
    let pool_from = pool_from_temp.path();
    let pool_to = pool_to_temp.path().join("converted_pool");

    write_schema_marker(node_from, 2)?;

    let pool_rows = vec![
        (
            b"pool-ledger/v1/share/00000001".to_vec(),
            b"share_record_payload_alpha".to_vec(),
        ),
        (
            b"pool-ledger/v1/share/00000002".to_vec(),
            b"share_record_payload_beta".to_vec(),
        ),
        (
            b"pool-ledger/v1/payout/00000001".to_vec(),
            b"payout_record_payload_gamma".to_vec(),
        ),
    ];
    let pool_data = vec![(ColumnFamily::PoolLedger, pool_rows.clone())];
    write_fjall_namespace(&pool_from.join("ledger"), &pool_data)?;

    let node_digest_before = recursive_dir_digest(node_from)?;
    let pool_digest_before = recursive_dir_digest(pool_from)?;

    let output = run_converter(&[
        "--from",
        node_from.to_str().expect("valid utf8 path"),
        "--to",
        node_to.to_str().expect("valid utf8 path"),
        "--pool-from",
        pool_from.to_str().expect("valid utf8 path"),
        "--pool-to",
        pool_to.to_str().expect("valid utf8 path"),
    ])?;

    let report = parse_report(&output)?;

    let node_digest_after = recursive_dir_digest(node_from)?;
    let pool_digest_after = recursive_dir_digest(pool_from)?;
    if node_digest_before != node_digest_after {
        return Err(TestError::Assertion(
            "node source digest changed during pool conversion".into(),
        ));
    }
    if pool_digest_before != pool_digest_after {
        return Err(TestError::Assertion(
            "pool source digest changed during pool conversion".into(),
        ));
    }

    let dest_schema = fs::read_to_string(node_to.join("CURRENT_SCHEMA"))?;
    if dest_schema != "3\n" {
        return Err(TestError::Assertion(format!(
            "expected destination CURRENT_SCHEMA '3\\n', got '{dest_schema}'"
        )));
    }

    let actual_pool_db = read_rocksdb_all_rows(&pool_to.join("ledger"))?;
    let actual_pool_rows = actual_pool_db
        .iter()
        .find(|(c, _)| *c == ColumnFamily::PoolLedger)
        .map(|(_, r)| r)
        .ok_or_else(|| TestError::Assertion("missing PoolLedger CF in converted pool".into()))?;

    let mut expected_sorted = pool_rows.clone();
    expected_sorted.sort_by(|a, b| a.0.cmp(&b.0));

    if actual_pool_rows != &expected_sorted {
        return Err(TestError::Assertion(format!(
            "pool rows mismatch: expected {:?}, got {:?}",
            expected_sorted, actual_pool_rows
        )));
    }

    let pool_ns_report = report
        .namespaces
        .iter()
        .find(|n| n.namespace == "pool" || n.namespace == "ledger")
        .ok_or_else(|| {
            TestError::Assertion("missing pool namespace in conversion report".into())
        })?;

    let fam_report = pool_ns_report
        .families
        .iter()
        .find(|f| f.family == ColumnFamily::PoolLedger.name())
        .ok_or_else(|| TestError::Assertion("missing PoolLedger family in report".into()))?;

    let expected_count =
        u64::try_from(pool_rows.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
    if fam_report.row_count != expected_count {
        return Err(TestError::Assertion(format!(
            "pool family row_count expected {}, got {}",
            expected_count, fam_report.row_count
        )));
    }

    let expected_digest = compute_oracle_digest(&pool_rows);
    if fam_report.digest != expected_digest {
        return Err(TestError::Assertion(format!(
            "pool family digest mismatch: expected {}, got {}",
            expected_digest, fam_report.digest
        )));
    }

    Ok(())
}
