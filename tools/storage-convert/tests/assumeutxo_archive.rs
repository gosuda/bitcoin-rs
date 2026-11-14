use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, recursive_dir_digest, run_converter};
use super::support::oracle::write_schema_marker;

const ANCHORED_BASE_HASH: &str = "06e5c2437917d314b424eb249ad2ae9d5408e530b7abf33b03cb0d0a084ca528";
const HEADERS_PAYLOAD: &[u8] = b"assumeutxo-headers-immutable-archive-bytes";
const COINS_PAYLOAD: &[u8] = b"assumeutxo-coins-immutable-archive-bytes";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch3-regtest")
}

fn copy_tree(from: &Path, to: &Path) -> TestResult<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn write_snapshot_archive(source: &Path) -> TestResult<()> {
    let generation_dir = source.join("assumeutxo").join(ANCHORED_BASE_HASH);
    fs::create_dir_all(&generation_dir)?;
    fs::write(generation_dir.join("headers.dat"), HEADERS_PAYLOAD)?;
    fs::write(generation_dir.join("coins.dat"), COINS_PAYLOAD)?;
    Ok(())
}

fn assert_archive_file_copied(dest_root: &Path, file_name: &str, payload: &[u8]) -> TestResult<()> {
    let path = dest_root
        .join("assumeutxo")
        .join(ANCHORED_BASE_HASH)
        .join(file_name);
    if !path.is_file() {
        return Err(TestError::Assertion(format!(
            "converted datadir is missing the immutable snapshot archive file \
             assumeutxo/{ANCHORED_BASE_HASH}/{file_name} that snapshot recovery verifies at open"
        )));
    }
    let bytes = fs::read(&path)?;
    if bytes != payload {
        return Err(TestError::Assertion(format!(
            "converted snapshot archive file assumeutxo/{ANCHORED_BASE_HASH}/{file_name} is not \
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

    if source_epoch == 3 {
        copy_tree(&fixture_dir(), from_path)?;
    } else {
        write_schema_marker(from_path, source_epoch)?;
    }
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

    let output = run_converter(&["--from", from_str, "--to", to_str, "--to-engine", "rocksdb"])?;
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
        let rel_path = format!("assumeutxo/{ANCHORED_BASE_HASH}/{file_name}");
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
