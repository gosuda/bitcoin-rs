use std::fs;
use tempfile::tempdir;

use bitcoin_rs_storage::ColumnFamily;

use super::support::error::{TestError, TestResult};
use super::support::harness::{
    ConversionReport, compute_oracle_digest, parse_report, recursive_dir_digest, run_converter,
};
use super::support::oracle::{
    FamilyRows, RedbTxIndexFixture, assert_independent_files_copied_and_ignored_skipped,
    read_rocksdb_all_rows, write_fjall_namespace, write_ignored_files, write_independent_files,
    write_redb_txindex, write_schema_marker,
};

fn build_chainstate_oracle() -> Vec<FamilyRows> {
    ColumnFamily::ALL
        .iter()
        .map(|cf| {
            let rows = vec![
                (
                    format!("{}_key_1", cf.name()).into_bytes(),
                    format!("{}_val_1", cf.name()).into_bytes(),
                ),
                (
                    format!("{}_key_2", cf.name()).into_bytes(),
                    format!("{}_val_2", cf.name()).into_bytes(),
                ),
            ];
            (*cf, rows)
        })
        .collect()
}

fn build_txindex_fixture() -> RedbTxIndexFixture {
    RedbTxIndexFixture {
        confirmed: vec![
            ([1u8; 12], Some(b"tx_confirmed_value_1".to_vec())),
            ([2u8; 12], None),
            ([3u8; 12], Some(b"tx_confirmed_value_3".to_vec())),
        ],
        funding: vec![
            ([11u8; 12], b"funding_value_1".to_vec()),
            ([12u8; 12], b"funding_value_2".to_vec()),
        ],
        spending: vec![([21u8; 12], b"spending_value_1".to_vec())],
        headers: vec![[31u8; 80], [32u8; 80]],
        script_live: vec![[41u8; 43], [42u8; 43]],
        meta: vec![
            (vec![0x00, b'V'], vec![0x06, 0, 0, 0]),
            (
                b"meta_key_secondary".to_vec(),
                b"meta_value_secondary".to_vec(),
            ),
        ],
    }
}

fn build_expected_txindex() -> Vec<FamilyRows> {
    let mut exp_confirmed = vec![
        ([1u8; 12].to_vec(), b"tx_confirmed_value_1".to_vec()),
        ([2u8; 12].to_vec(), Vec::new()),
        ([3u8; 12].to_vec(), b"tx_confirmed_value_3".to_vec()),
    ];
    exp_confirmed.sort_by(|a, b| a.0.cmp(&b.0));

    let mut exp_funding = vec![
        ([11u8; 12].to_vec(), b"funding_value_1".to_vec()),
        ([12u8; 12].to_vec(), b"funding_value_2".to_vec()),
    ];
    exp_funding.sort_by(|a, b| a.0.cmp(&b.0));

    let exp_spending = vec![([21u8; 12].to_vec(), b"spending_value_1".to_vec())];

    let mut exp_headers = vec![
        ([31u8; 80].to_vec(), Vec::new()),
        ([32u8; 80].to_vec(), Vec::new()),
    ];
    exp_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let mut exp_script = vec![
        ([41u8; 43].to_vec(), Vec::new()),
        ([42u8; 43].to_vec(), Vec::new()),
    ];
    exp_script.sort_by(|a, b| a.0.cmp(&b.0));

    let mut exp_meta = vec![
        (vec![0x00, b'V'], vec![0x06, 0, 0, 0]),
        (
            b"meta_key_secondary".to_vec(),
            b"meta_value_secondary".to_vec(),
        ),
    ];
    exp_meta.sort_by(|a, b| a.0.cmp(&b.0));

    ColumnFamily::ALL
        .iter()
        .map(|cf| {
            let rows = match cf {
                ColumnFamily::TxConfirmed => exp_confirmed.clone(),
                ColumnFamily::Funding => exp_funding.clone(),
                ColumnFamily::Spending => exp_spending.clone(),
                ColumnFamily::BlockHeaders => exp_headers.clone(),
                ColumnFamily::ScriptLive => exp_script.clone(),
                ColumnFamily::UtxoMeta => exp_meta.clone(),
                _ => Vec::new(),
            };
            (*cf, rows)
        })
        .collect()
}

fn verify_cf_rows(
    namespace: &str,
    actual: &[FamilyRows],
    expected: &[FamilyRows],
) -> TestResult<()> {
    for (cf, expected_rows) in expected {
        let Some((_, actual_rows)) = actual.iter().find(|(c, _)| c == cf) else {
            return Err(TestError::Assertion(format!(
                "missing cf {} in {namespace}",
                cf.name()
            )));
        };
        if actual_rows != expected_rows {
            return Err(TestError::Assertion(format!(
                "{namespace} CF {} rows mismatch: expected {:?}, got {:?}",
                cf.name(),
                expected_rows,
                actual_rows
            )));
        }
    }
    Ok(())
}

fn verify_namespace_report(
    report: &ConversionReport,
    ns_name: &str,
    expected_engine: &str,
    expected_data: &[FamilyRows],
) -> TestResult<()> {
    let Some(ns_rep) = report.namespaces.iter().find(|n| n.namespace == ns_name) else {
        return Err(TestError::Assertion(format!("missing {ns_name} in report")));
    };
    if ns_rep.engine != expected_engine {
        return Err(TestError::Assertion(format!(
            "expected {ns_name} engine '{expected_engine}', got '{}'",
            ns_rep.engine
        )));
    }
    for (cf, rows) in expected_data {
        let Some(fam_rep) = ns_rep.families.iter().find(|f| f.family == cf.name()) else {
            return Err(TestError::Assertion(format!(
                "missing family {} in {ns_name} report",
                cf.name()
            )));
        };
        let expected_count =
            u64::try_from(rows.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
        if fam_rep.row_count != expected_count {
            return Err(TestError::Assertion(format!(
                "{ns_name} family {} count expected {expected_count}, got {}",
                cf.name(),
                fam_rep.row_count
            )));
        }
        let expected_digest = compute_oracle_digest(rows);
        if fam_rep.digest != expected_digest {
            return Err(TestError::Assertion(format!(
                "{ns_name} family {} digest mismatch: expected {expected_digest}, got {}",
                cf.name(),
                fam_rep.digest
            )));
        }
    }
    Ok(())
}

fn verify_copied_files_report(
    report: &ConversionReport,
    expected_files: &[(String, Vec<u8>)],
) -> TestResult<()> {
    if report.copied_files.len() != expected_files.len() {
        return Err(TestError::Assertion(format!(
            "copied files count mismatch: expected {}, got {}",
            expected_files.len(),
            report.copied_files.len()
        )));
    }
    for (expected_path, expected_bytes) in expected_files {
        let Some(file_rep) = report
            .copied_files
            .iter()
            .find(|f| f.path == *expected_path)
        else {
            return Err(TestError::Assertion(format!(
                "expected copied file missing in report: {expected_path}"
            )));
        };
        let expected_len =
            u64::try_from(expected_bytes.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
        if file_rep.bytes != expected_len {
            return Err(TestError::Assertion(format!(
                "file {expected_path} byte count mismatch in report: expected {expected_len}, got {}",
                file_rep.bytes
            )));
        }
    }
    Ok(())
}

// RCV-09
#[test]
fn epoch2_fjall_and_redb_convert_to_epoch3_rocksdb_preserves_all_rows_and_files() -> TestResult<()>
{
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let chainstate_oracle = build_chainstate_oracle();
    write_fjall_namespace(&from_path.join("chainstate"), &chainstate_oracle)?;

    let txindex_fixture = build_txindex_fixture();
    write_redb_txindex(&from_path.join("txindex"), &txindex_fixture)?;

    let independent_files = write_independent_files(from_path)?;
    write_ignored_files(from_path)?;

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
            "source directory recursive digest changed during conversion".into(),
        ));
    }

    let dest_schema = fs::read_to_string(to_path.join("CURRENT_SCHEMA"))?;
    if dest_schema != "3\n" {
        return Err(TestError::Assertion(format!(
            "expected destination CURRENT_SCHEMA '3\\n', got '{dest_schema}'"
        )));
    }

    let actual_chainstate = read_rocksdb_all_rows(&to_path.join("chainstate"))?;
    verify_cf_rows("chainstate", &actual_chainstate, &chainstate_oracle)?;

    let expected_txindex = build_expected_txindex();
    let actual_txindex = read_rocksdb_all_rows(&to_path.join("txindex"))?;
    verify_cf_rows("txindex", &actual_txindex, &expected_txindex)?;

    assert_independent_files_copied_and_ignored_skipped(&to_path, &independent_files)?;

    if report.source_epoch != 2 {
        return Err(TestError::Assertion(format!(
            "report source_epoch expected 2, got {}",
            report.source_epoch
        )));
    }
    if report.target_epoch != 3 {
        return Err(TestError::Assertion(format!(
            "report target_epoch expected 3, got {}",
            report.target_epoch
        )));
    }

    verify_namespace_report(&report, "chainstate", "fjall", &chainstate_oracle)?;
    verify_namespace_report(&report, "txindex", "redb", &expected_txindex)?;
    verify_copied_files_report(&report, &independent_files)?;

    Ok(())
}
