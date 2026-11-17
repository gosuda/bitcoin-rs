use std::fs;
use tempfile::tempdir;

use bitcoin_rs_storage::ColumnFamily;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, recursive_dir_digest, run_converter};
use super::support::oracle::{read_rocksdb_all_rows, write_fjall_namespace, write_schema_marker};

#[test]
fn missing_or_empty_namespaces_succeed_with_zero_rows() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let chainstate_data = vec![(
        ColumnFamily::UtxoMeta,
        vec![(b"meta:key".to_vec(), b"meta:value".to_vec())],
    )];
    write_fjall_namespace(&from_path.join("chainstate"), &chainstate_data)?;

    let empty_txindex = from_path.join("txindex");
    fs::create_dir_all(&empty_txindex)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;

    let report = parse_report(&output)?;

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory recursive digest changed during empty namespace conversion".into(),
        ));
    }

    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "3\n" {
        return Err(TestError::Assertion(format!(
            "expected destination CURRENT_SCHEMA '3\\n', got '{dest_schema}'"
        )));
    }

    let actual_cs = read_rocksdb_all_rows(&to_path.join("chainstate"))?;
    let Some((_, rows)) = actual_cs.iter().find(|(c, _)| *c == ColumnFamily::UtxoMeta) else {
        return Err(TestError::Assertion(
            "missing UtxoMeta CF in chainstate".into(),
        ));
    };
    if rows != &chainstate_data[0].1 {
        return Err(TestError::Assertion(
            "chainstate rows mismatch in empty txindex scenario".into(),
        ));
    }

    if let Some(tx_rep) = report.namespaces.iter().find(|n| n.namespace == "txindex") {
        let total_rows: u64 = tx_rep.families.iter().map(|f| f.row_count).sum();
        if total_rows != 0 {
            return Err(TestError::Assertion(format!(
                "expected 0 rows for empty txindex, got {total_rows}"
            )));
        }
    }

    Ok(())
}
