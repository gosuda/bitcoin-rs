use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

use super::support::error::{TestError, TestResult};
use super::support::harness::{parse_report, run_converter};

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

fn path_str(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| TestError::Assertion("test path is not valid UTF-8".into()))
}

fn cmp_equal(first: &Path, second: &Path) -> TestResult<()> {
    let status = Command::new("cmp").arg(first).arg(second).status()?;
    if !status.success() {
        return Err(TestError::Assertion(format!(
            "external cmp mismatch: {} vs {}",
            first.display(),
            second.display()
        )));
    }
    Ok(())
}

#[test]
fn scoped_peers_books_convert_byte_identical_with_legacy_book() -> TestResult<()> {
    let source_temp = tempdir()?;
    let dest_temp = tempdir()?;
    let from_path = source_temp.path();
    let to_path = dest_temp.path().join("converted");

    copy_tree(&fixture_dir(), from_path)?;

    let legacy_bytes = b"stale-legacy-peers-book".to_vec();
    let mainnet_bytes = b"live-scoped-mainnet-peers-book".to_vec();
    let regtest_bytes = b"live-scoped-regtest-peers-book".to_vec();
    fs::write(from_path.join("peers.dat"), &legacy_bytes)?;
    fs::write(from_path.join("peers-f9beb4d9.dat"), &mainnet_bytes)?;
    fs::write(from_path.join("peers-fabfb5da.dat"), &regtest_bytes)?;
    fs::write(from_path.join("peers-backup.dat"), b"operator-backup")?;

    let output = run_converter(&["--from", path_str(from_path)?, "--to", path_str(&to_path)?])?;
    let report = parse_report(&output)?;

    for (name, expected) in [
        ("peers.dat", &legacy_bytes),
        ("peers-f9beb4d9.dat", &mainnet_bytes),
        ("peers-fabfb5da.dat", &regtest_bytes),
    ] {
        cmp_equal(&from_path.join(name), &to_path.join(name))?;
        let Some(entry) = report.copied_files.iter().find(|f| f.path == name) else {
            return Err(TestError::Assertion(format!(
                "converted peers file missing from report: {name}"
            )));
        };
        let expected_len =
            u64::try_from(expected.len()).map_err(|e| TestError::Assertion(e.to_string()))?;
        if entry.bytes != expected_len {
            return Err(TestError::Assertion(format!(
                "report byte count mismatch for {name}: expected {expected_len}, got {}",
                entry.bytes
            )));
        }
    }

    if to_path.join("peers-backup.dat").exists() {
        return Err(TestError::Assertion(
            "unrecognized peers file was erroneously copied to destination".into(),
        ));
    }

    Ok(())
}
