use std::fs;
use std::path::Path;

use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, recursive_dir_digest, run_converter};
use super::support::oracle::write_schema_marker;

const BASE_HASH: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2200";
const HEADERS_PAYLOAD: &[u8] = b"assumeutxo-headers-immutable-archive-bytes";
const COINS_PAYLOAD: &[u8] = b"assumeutxo-coins-immutable-archive-bytes";

fn write_snapshot_archive(source: &Path) -> TestResult<()> {
    let generation_dir = source.join("assumeutxo").join(BASE_HASH);
    fs::create_dir_all(&generation_dir)?;
    fs::write(generation_dir.join("headers.dat"), HEADERS_PAYLOAD)?;
    fs::write(generation_dir.join("coins.dat"), COINS_PAYLOAD)?;
    Ok(())
}

fn assert_archive_file_copied(dest_root: &Path, file_name: &str, payload: &[u8]) -> TestResult<()> {
    let path = dest_root.join("assumeutxo").join(BASE_HASH).join(file_name);
    if !path.is_file() {
        return Err(TestError::Assertion(format!(
            "converted datadir is missing the immutable snapshot archive file \
             assumeutxo/{BASE_HASH}/{file_name} that snapshot recovery verifies at open"
        )));
    }
    let bytes = fs::read(&path)?;
    if bytes != payload {
        return Err(TestError::Assertion(format!(
            "converted snapshot archive file assumeutxo/{BASE_HASH}/{file_name} is not \
             byte-identical to the source archive"
        )));
    }
    Ok(())
}

fn convert_and_assert_snapshot_archive(source_epoch: u32) -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    write_schema_marker(from_path, source_epoch)?;
    write_snapshot_archive(from_path)?;

    let source_digest_before = recursive_dir_digest(from_path)?;

    let Some(from_str) = from_path.to_str() else {
        return Err(TestError::Assertion(
            "source tempdir path is not valid utf8".into(),
        ));
    };
    let Some(to_str) = to_path.to_str() else {
        return Err(TestError::Assertion(
            "target tempdir path is not valid utf8".into(),
        ));
    };

    let output = run_converter(&[
        "--from",
        from_str,
        "--to",
        to_str,
        "--to-engine",
        "rocksdb",
    ])?;
    let report = parse_report(&output)?;

    let source_digest_after = recursive_dir_digest(from_path)?;
    if source_digest_before != source_digest_after {
        return Err(TestError::Assertion(
            "source directory recursive digest changed while converting the snapshot archive"
                .into(),
        ));
    }

    assert_archive_file_copied(&to_path, "headers.dat", HEADERS_PAYLOAD)?;
    assert_archive_file_copied(&to_path, "coins.dat", COINS_PAYLOAD)?;

    for (file_name, payload) in [
        ("headers.dat", HEADERS_PAYLOAD),
        ("coins.dat", COINS_PAYLOAD),
    ] {
        let rel_path = format!("assumeutxo/{BASE_HASH}/{file_name}");
        let Some(entry) = report
            .copied_files
            .iter()
            .find(|copied| copied.path == rel_path)
        else {
            return Err(TestError::Assertion(format!(
                "verification report omits the copied snapshot archive file {rel_path}"
            )));
        };
        let expected_bytes = u64::try_from(payload.len()).map_err(|_| {
            TestError::Assertion(format!("payload length for {rel_path} does not fit u64"))
        })?;
        if entry.bytes != expected_bytes {
            return Err(TestError::Assertion(format!(
                "verification report records the wrong size for {rel_path}"
            )));
        }
    }

    Ok(())
}

#[test]
fn epoch3_source_copies_snapshot_archive_for_anchored_head_reopen() -> TestResult<()> {
    convert_and_assert_snapshot_archive(3)
}

#[test]
fn epoch2_source_copies_snapshot_archive_into_epoch3_target() -> TestResult<()> {
    convert_and_assert_snapshot_archive(2)
}
