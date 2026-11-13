use std::fs;
use tempfile::tempdir;

use bitcoin_rs_storage::ColumnFamily;
use redb::{Database, MultimapTableDefinition, ReadableDatabase, TableDefinition};

use super::support::error::{TestError, TestResult};
use super::support::harness::{recursive_dir_digest, run_converter};
use super::support::oracle::{write_fjall_namespace, write_schema_marker};

// RCV-09
#[test]
fn unrecognized_engine_in_nonempty_namespace_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let foreign_ns = from_path.join("chainstate");
    fs::create_dir_all(&foreign_ns)?;
    fs::write(
        foreign_ns.join("unrecognized_storage.dat"),
        b"foreign_bytes",
    )?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded on unrecognized non-empty engine namespace".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on unrecognized engine rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA was created on unrecognized engine rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn corrupt_fjall_marker_in_nonempty_namespace_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let corrupt_ns = from_path.join("chainstate");
    fs::create_dir_all(corrupt_ns.join("keyspaces").join("0"))?;
    fs::write(corrupt_ns.join("version"), b"CORRUPT_NOT_FJL3")?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded on corrupt fjall version marker".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on corrupt fjall marker rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA was created on corrupt fjall marker rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn epoch3_fjall_source_is_rejected() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 3)?;

    let chainstate_data = vec![(
        ColumnFamily::UtxoMeta,
        vec![(b"meta:key".to_vec(), b"meta:value".to_vec())],
    )];
    write_fjall_namespace(&from_path.join("chainstate"), &chainstate_data)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when epoch 3 datadir used fjall".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on epoch 3 fjall rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA was created on epoch 3 fjall rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn txindex_incompatible_table_width_is_rejected_and_preserves_source() -> TestResult<()> {
    let wrong_table: redb::TableDefinition<&[u8; 44], ()> =
        redb::TableDefinition::new("txindex_v1_script_live");

    for populated in [false, true] {
        let source_temp = tempdir()?;
        let dest_temp = tempdir()?;
        let from_path = source_temp.path();
        let to_path = dest_temp.path().join("converted");

        write_schema_marker(from_path, 2)?;

        let chainstate_data = vec![(
            ColumnFamily::UtxoMeta,
            vec![(b"meta:head".to_vec(), b"head_data".to_vec())],
        )];
        write_fjall_namespace(&from_path.join("chainstate"), &chainstate_data)?;

        let txindex_dir = from_path.join("txindex");
        fs::create_dir_all(&txindex_dir)?;
        let db_path = txindex_dir.join("redb.db");
        {
            let db = redb::Database::create(&db_path)?;
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(wrong_table)?;
                if populated {
                    table.insert(&[7u8; 44], ())?;
                }
            }
            write_txn.commit()?;
        }

        let source_digest_before = recursive_dir_digest(from_path)?;

        let from_str = from_path
            .to_str()
            .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
        let to_str = to_path
            .to_str()
            .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

        let output = run_converter(&["--from", from_str, "--to", to_str])?;

        if output.status.success() {
            return Err(TestError::Assertion(format!(
                "converter unexpectedly succeeded with incompatible txindex table width (populated={populated})"
            )));
        }

        let source_digest_after = recursive_dir_digest(from_path)?;
        if source_digest_before != source_digest_after {
            return Err(TestError::Assertion(format!(
                "source directory was modified on incompatible table width rejection (populated={populated})"
            )));
        }

        if to_path.join("CURRENT_SCHEMA").exists() {
            return Err(TestError::Assertion(format!(
                "CURRENT_SCHEMA was created on incompatible table width rejection (populated={populated})"
            )));
        }

        let db = redb::Database::open(&db_path)?;
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(wrong_table)?;
        let is_present = table.get(&[7u8; 44])?.is_some();
        if is_present != populated {
            return Err(TestError::Assertion(format!(
                "incompatible table entry presence mismatch in source database: expected {populated}, got {is_present}"
            )));
        }
    }

    Ok(())
}

// RCV-09
#[cfg(unix)]
#[test]
fn non_utf8_filename_only_namespace_is_rejected_and_preserves_source() -> TestResult<()> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let source_temp = tempfile::tempdir_in("/tmp")?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let chainstate_ns = from_path.join("chainstate");
    fs::create_dir_all(&chainstate_ns)?;

    let non_utf8_name =
        OsString::from_vec(vec![b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0xff, 0xfe]);
    let non_utf8_file = chainstate_ns.join(non_utf8_name);
    fs::write(&non_utf8_file, b"actual_nonempty_bytes_in_non_utf8_file")?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded on namespace containing only non-utf8 filename"
                .into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on non-utf8 filename rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA was created on non-utf8 filename rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn overlaid_recognized_engines_in_namespace_is_rejected_and_preserves_source() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let chainstate_dir = from_path.join("chainstate");
    let fjall_data = vec![(
        ColumnFamily::UtxoMeta,
        vec![(b"meta:fjall_key".to_vec(), b"fjall_value".to_vec())],
    )];
    write_fjall_namespace(&chainstate_dir, &fjall_data)?;

    let standalone_redb_dir = tempdir()?;
    let standalone_redb_path = standalone_redb_dir.path().join("redb.db");
    const REDB_TABLE: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("redb_table");
    {
        let db = redb::Database::create(&standalone_redb_path)?;
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(REDB_TABLE)?;
            table.insert("redb_key", "redb_value")?;
        }
        write_txn.commit()?;
    }

    fs::copy(&standalone_redb_path, chainstate_dir.join("redb.db"))?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded when two recognized engines are overlaid in one namespace".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on overlaid engine rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "CURRENT_SCHEMA was created on overlaid engine rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn redb_with_foreign_table_is_rejected_and_preserves_source() -> TestResult<()> {
    let foreign_table: TableDefinition<&str, &str> = TableDefinition::new("foreign_table_name");

    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let chainstate_dir = from_path.join("chainstate");
    fs::create_dir_all(&chainstate_dir)?;
    let db_path = chainstate_dir.join("redb.db");
    {
        let db = Database::create(&db_path)?;
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(foreign_table)?;
            table.insert("k", "v")?;
        }
        write_txn.commit()?;
    }

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if output.status.success() {
        return Err(TestError::Assertion(
            "converter unexpectedly succeeded with foreign table in redb database".into(),
        ));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on foreign table redb rejection".into(),
        ));
    }

    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was published on foreign table redb rejection".into(),
        ));
    }

    Ok(())
}

// RCV-09
#[test]
fn redb_unknown_prefixed_regular_table_is_rejected_before_publication() -> TestResult<()> {
    let table: TableDefinition<&str, &str> = TableDefinition::new("txindex_v1_custom");
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");
    write_schema_marker(from_path, 2)?;

    let chainstate_dir = from_path.join("chainstate");
    fs::create_dir_all(&chainstate_dir)?;
    {
        let db = Database::create(chainstate_dir.join("redb.db"))?;
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(table)?;
            table.insert("must-not-be-dropped", "row")?;
        }
        write_txn.commit()?;
    }
    let source_digest_before = recursive_dir_digest(from_path)?;
    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "converter accepted unreadable prefixed regular-table rows".into(),
        ));
    }
    if recursive_dir_digest(from_path)? != source_digest_before {
        return Err(TestError::Assertion(
            "source changed while rejecting unknown regular-table rows".into(),
        ));
    }
    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination schema published despite unknown regular-table rows".into(),
        ));
    }
    Ok(())
}

fn assert_orphan_value_rejected(
    write_main_row: impl FnOnce(&redb::WriteTransaction) -> TestResult<()>,
    case: &str,
) -> TestResult<()> {
    let values_table: TableDefinition<&[u8; 12], &[u8]> =
        TableDefinition::new("txindex_v1_tx_confirmed_values");
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");
    write_schema_marker(from_path, 2)?;

    let chainstate_dir = from_path.join("chainstate");
    fs::create_dir_all(&chainstate_dir)?;
    {
        let db = Database::create(chainstate_dir.join("redb.db"))?;
        let write_txn = db.begin_write()?;
        {
            write_main_row(&write_txn)?;
            let mut values = write_txn.open_table(values_table)?;
            values.insert(&[2_u8; 12], b"orphan-value".as_slice())?;
        }
        write_txn.commit()?;
    }
    let source_digest_before = recursive_dir_digest(from_path)?;
    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;
    if output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter accepted an orphan value-table row ({case})"
        )));
    }
    if recursive_dir_digest(from_path)? != source_digest_before {
        return Err(TestError::Assertion(
            "source changed while rejecting orphan value row".into(),
        ));
    }
    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination schema published despite orphan value row".into(),
        ));
    }
    Ok(())
}

// RCV-09
#[test]
fn redb_orphan_value_row_with_main_table_is_rejected_before_publication() -> TestResult<()> {
    assert_orphan_value_rejected(
        |write_txn| {
            let main_table: TableDefinition<&[u8; 12], ()> =
                TableDefinition::new("txindex_v1_tx_confirmed");
            let mut main = write_txn.open_table(main_table)?;
            main.insert(&[1_u8; 12], ())?;
            Ok(())
        },
        "main table present",
    )
}

// RCV-09
#[test]
fn redb_orphan_value_row_without_main_table_is_rejected_before_publication() -> TestResult<()> {
    assert_orphan_value_rejected(|_| Ok(()), "main table absent")
}

// RCV-09
#[test]
fn redb_multimap_rows_are_rejected_before_publication() -> TestResult<()> {
    let multimap: MultimapTableDefinition<&str, &str> =
        MultimapTableDefinition::new("txindex_v1_custom");
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");
    write_schema_marker(from_path, 2)?;

    let chainstate_dir = from_path.join("chainstate");
    fs::create_dir_all(&chainstate_dir)?;
    {
        let db = Database::create(chainstate_dir.join("redb.db"))?;
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_multimap_table(multimap)?;
            table.insert("must-not-be-dropped", "row")?;
        }
        write_txn.commit()?;
    }
    let source_digest_before = recursive_dir_digest(from_path)?;
    let output = run_converter(&[
        "--from",
        from_path.to_str().expect("valid utf8 path"),
        "--to",
        to_path.to_str().expect("valid utf8 path"),
    ])?;
    if output.status.success() {
        return Err(TestError::Assertion(
            "converter published a conversion while ignoring multimap rows".into(),
        ));
    }
    if recursive_dir_digest(from_path)? != source_digest_before {
        return Err(TestError::Assertion(
            "source changed while rejecting multimap rows".into(),
        ));
    }
    if to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination schema published despite unreadable multimap rows".into(),
        ));
    }
    Ok(())
}

// RCV-09
#[test]
fn empty_redb_is_converted_successfully_and_preserves_source() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, 2)?;

    let chainstate_dir = from_path.join("chainstate");
    fs::create_dir_all(&chainstate_dir)?;
    let db_path = chainstate_dir.join("redb.db");
    {
        let db = Database::create(&db_path)?;
        drop(db);
    }

    let source_digest_before = recursive_dir_digest(from_path)?;

    let from_str = from_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;
    let to_str = to_path
        .to_str()
        .ok_or_else(|| TestError::Assertion("invalid utf-8 path".into()))?;

    let output = run_converter(&["--from", from_str, "--to", to_str])?;

    if !output.status.success() {
        return Err(TestError::Assertion(format!(
            "converter unexpectedly failed on empty redb: stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory was modified on empty redb conversion".into(),
        ));
    }

    if !to_path.join("CURRENT_SCHEMA").exists() {
        return Err(TestError::Assertion(
            "destination CURRENT_SCHEMA was not published on empty redb conversion".into(),
        ));
    }

    Ok(())
}
