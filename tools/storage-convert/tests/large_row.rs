use std::fs;
use tempfile::tempdir;

use bitcoin_rs_storage::ColumnFamily;

use super::support::error::{TestError, TestResult};
use super::support::harness::{
    compute_oracle_digest, parse_report, recursive_dir_digest, run_converter,
};
use super::support::oracle::{read_rocksdb_all_rows, write_fjall_namespace, write_schema_marker};

#[test]
fn indivisible_large_row_exceeding_64mib_preserved_exactly() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let prec0_len = 30 * 1024 * 1024;
    let mut prec0_val = Vec::with_capacity(prec0_len);
    for i in 0..prec0_len {
        prec0_val.push(u8::try_from(i % 239).expect("fits in u8"));
    }

    let prec1_len = 30 * 1024 * 1024;
    let mut prec1_val = Vec::with_capacity(prec1_len);
    for i in 0..prec1_len {
        prec1_val.push(u8::try_from(i % 241).expect("fits in u8"));
    }

    let large_value_len = 66 * 1024 * 1024;
    let mut large_value = Vec::with_capacity(large_value_len);
    for i in 0..large_value_len {
        large_value.push(u8::try_from(i % 251).expect("fits in u8"));
    }

    let foll_len = 1024 * 1024;
    let mut foll_val = Vec::with_capacity(foll_len);
    for i in 0..foll_len {
        foll_val.push(u8::try_from(i % 233).expect("fits in u8"));
    }

    let prec0_key = b"undo:block_00000000_0".to_vec();
    let prec1_key = b"undo:block_00000000_1".to_vec();
    let undo_key = b"undo:block_00000001".to_vec();
    let foll_key = b"undo:block_00000002".to_vec();

    let undo_rows = vec![
        (prec0_key, prec0_val),
        (prec1_key, prec1_val),
        (undo_key.clone(), large_value.clone()),
        (foll_key, foll_val),
    ];
    let chainstate_data = vec![(ColumnFamily::UndoData, undo_rows.clone())];

    write_fjall_namespace(&from_path.join("chainstate"), &chainstate_data)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
        "--to-engine",
        "rocksdb",
    ])?;

    let report = parse_report(&output)?;

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory recursive digest changed during large row conversion".into(),
        ));
    }
    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "3\n" {
        return Err(TestError::Assertion(format!(
            "expected destination CURRENT_SCHEMA '3\\n', got '{dest_schema}'"
        )));
    }

    let actual_chainstate = read_rocksdb_all_rows(&to_path.join("chainstate"))?;
    let actual_undo = actual_chainstate
        .iter()
        .find(|(c, _)| *c == ColumnFamily::UndoData)
        .map(|(_, r)| r)
        .ok_or_else(|| TestError::Assertion("missing UndoData in converted rocksdb".into()))?;

    if actual_undo != &undo_rows {
        return Err(TestError::Assertion(
            "UndoData rows content or length mismatch in destination".into(),
        ));
    }

    let large_row = actual_undo
        .iter()
        .find(|(k, _)| k == &undo_key)
        .ok_or_else(|| {
            TestError::Assertion("missing large undo row in converted rocksdb".into())
        })?;
    if large_row.1.len() != large_value_len || large_row.1 != large_value {
        return Err(TestError::Assertion(
            "large row value was mutated, truncated, or split".into(),
        ));
    }

    let cs_report = report
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate in report".into()))?;

    let fam_report = cs_report
        .families
        .iter()
        .find(|f| f.family == ColumnFamily::UndoData.name())
        .ok_or_else(|| TestError::Assertion("missing UndoData family in report".into()))?;

    let expected_row_count = u64::try_from(undo_rows.len()).expect("row count fits in u64");
    if fam_report.row_count != expected_row_count {
        return Err(TestError::Assertion(format!(
            "expected UndoData row_count {expected_row_count}, got {}",
            fam_report.row_count
        )));
    }

    let expected_digest = compute_oracle_digest(&undo_rows);
    if fam_report.digest != expected_digest {
        return Err(TestError::Assertion(format!(
            "large row digest mismatch: expected {}, got {}",
            expected_digest, fam_report.digest
        )));
    }

    Ok(())
}
