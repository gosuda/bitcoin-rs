use std::fs;
use tempfile::tempdir;

use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};

use super::support::error::{TestError, TestResult};
use super::support::harness::{
    compute_oracle_digest, parse_report, recursive_dir_digest, run_converter,
};
use super::support::oracle::{
    assert_independent_files_copied_and_ignored_skipped, read_rocksdb_all_rows,
    write_independent_files, write_rocksdb_namespace, write_schema_marker,
};

#[test]
fn epoch5_rocksdb_to_rocksdb_copies_current_epoch_verbatim() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 5)?;

    let chainstate_data = vec![
        (
            ColumnFamily::UtxoMeta,
            vec![(b"meta:head".to_vec(), b"head_payload_epoch5".to_vec())],
        ),
        (
            ColumnFamily::BlockBodies,
            vec![(b"body:00000001".to_vec(), b"block_body_bytes".to_vec())],
        ),
    ];
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;

    let txindex_data = vec![(
        ColumnFamily::TxConfirmed,
        vec![(b"tx_id_epoch5".to_vec(), b"confirmed_tx_bytes".to_vec())],
    )];
    write_rocksdb_namespace(&from_path.join("txindex"), &txindex_data)?;

    let independent_files = write_independent_files(from_path)?;

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
            "source directory recursive digest changed during epoch 5 copy".into(),
        ));
    }

    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "6\n" {
        return Err(TestError::Assertion(format!(
            "expected destination CURRENT_SCHEMA '6\\n', got '{dest_schema}'"
        )));
    }

    let actual_cs = read_rocksdb_all_rows(&to_path.join("chainstate"))?;
    for (cf, expected_rows) in &chainstate_data {
        let Some((_, actual_rows)) = actual_cs.iter().find(|(c, _)| c == cf) else {
            return Err(TestError::Assertion(format!("missing cf {}", cf.name())));
        };
        if actual_rows != expected_rows {
            return Err(TestError::Assertion(format!(
                "row mismatch in CF {}: expected {:?}, got {:?}",
                cf.name(),
                expected_rows,
                actual_rows
            )));
        }
    }

    let actual_tx = read_rocksdb_all_rows(&to_path.join("txindex"))?;
    for (cf, expected_rows) in &txindex_data {
        let Some((_, actual_rows)) = actual_tx.iter().find(|(c, _)| c == cf) else {
            return Err(TestError::Assertion(format!("missing cf {}", cf.name())));
        };
        if actual_rows != expected_rows {
            return Err(TestError::Assertion(format!(
                "row mismatch in txindex CF {}: expected {:?}, got {:?}",
                cf.name(),
                expected_rows,
                actual_rows
            )));
        }
    }

    let expected_files: Vec<_> = independent_files
        .into_iter()
        .filter(|(path, _)| !path.starts_with("chainstate-journal"))
        .collect();
    assert_independent_files_copied_and_ignored_skipped(&to_path, &expected_files)?;

    if report.source_epoch != 5 {
        return Err(TestError::Assertion(format!(
            "expected report source_epoch 5, got {}",
            report.source_epoch
        )));
    }
    if report.target_epoch != 6 {
        return Err(TestError::Assertion(format!(
            "expected report target_epoch 6, got {}",
            report.target_epoch
        )));
    }

    let cs_report = report
        .namespaces
        .iter()
        .find(|n| n.namespace == "chainstate")
        .ok_or_else(|| TestError::Assertion("missing chainstate report".into()))?;
    if cs_report.engine != "rocksdb" {
        return Err(TestError::Assertion(format!(
            "expected chainstate engine 'rocksdb', got '{}'",
            cs_report.engine
        )));
    }

    for (cf, rows) in &chainstate_data {
        let fam = cs_report
            .families
            .iter()
            .find(|f| f.family == cf.name())
            .ok_or_else(|| TestError::Assertion(format!("missing family {}", cf.name())))?;
        let expected_count =
            u64::try_from(rows.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
        if fam.row_count != expected_count {
            return Err(TestError::Assertion(format!(
                "count mismatch: expected {expected_count}, got {}",
                fam.row_count
            )));
        }
        let expected_digest = compute_oracle_digest(rows);
        if fam.digest != expected_digest {
            return Err(TestError::Assertion(format!(
                "digest mismatch: expected {expected_digest}, got {}",
                fam.digest
            )));
        }
    }

    Ok(())
}

#[test]
fn epoch5_rocksdb_empty_key_empty_value_row_copies_exactly() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 5)?;

    let chainstate_data = vec![(ColumnFamily::UtxoMeta, vec![(Vec::new(), Vec::new())])];
    write_rocksdb_namespace(&from_path.join("chainstate"), &chainstate_data)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str, "--to-engine", "rocksdb"])?;

    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter unexpectedly failed on empty-key empty-value row: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory recursive digest changed during empty-key empty-value copy".into(),
        ));
    }

    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "6\n" {
        return Err(TestError::Assertion(format!(
            "expected destination CURRENT_SCHEMA '6\\n', got '{dest_schema}'"
        )));
    }

    let dest_store = RocksDbStore::open_with_cache(to_path.join("chainstate"), 0)?;
    let dest_snapshot = dest_store.snapshot()?;
    let stored_val = dest_snapshot.get(ColumnFamily::UtxoMeta, &[])?;
    if stored_val != Some(Vec::new()) {
        return Err(TestError::Assertion(format!(
            "expected destination snapshot to contain Some(empty) at empty key, got {stored_val:?}"
        )));
    }

    Ok(())
}
