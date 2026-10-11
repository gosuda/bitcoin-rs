//! Public CLI trust labels, exit codes, and read-only behavior against a Core fixture.

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;
use tempfile::tempdir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/utxo/tests/fixtures/core-v2/core200.dat")
}

fn run(args: &[&str], file: &Path) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_bitcoin-rs-snapshot"))
        .args(args)
        .arg(file)
        .output()
}

fn report(output: &Output) -> Result<Value, Box<dyn Error>> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, b"");
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn core_file_inspection_and_verification_are_distinct_read_only_operations()
-> Result<(), Box<dyn Error>> {
    let path = fixture();
    let original = fs::read(&path)?;
    let inspected = report(&run(&["inspect", "--json"], &path)?)?;
    assert_eq!(inspected["validation"], "metadata_only");
    assert_eq!(inspected["historical_validation_performed"], false);
    assert_eq!(inspected["network"], "regtest");
    assert_eq!(inspected["network_magic"], "fabfb5da");
    assert_eq!(inspected["version"], 2);
    assert_eq!(inspected["declared_coins"], 200);
    assert_eq!(inspected["file_bytes"], u64::try_from(original.len())?);
    assert_eq!(inspected["known_anchor"]["height"], 200);
    assert_eq!(inspected["known_anchor"]["chain_tx_count"], 201);
    assert!(inspected["verification"].is_null());

    let verified = report(&run(&["verify", "--network", "regtest", "--json"], &path)?)?;
    assert_eq!(verified["validation"], "pinned_state_verified");
    assert_eq!(verified["historical_validation_performed"], false);
    assert_eq!(verified["verification"]["actual_coins"], 200);
    assert_eq!(
        verified["verification"]["bytes_read"],
        u64::try_from(original.len())?
    );
    // Independent Core v31.1 regtest-200 values, not computed by the CLI.
    assert_eq!(
        verified["base_block_hash"],
        "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"
    );
    assert_eq!(
        verified["verification"]["hash_serialized_3"],
        "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"
    );
    assert_eq!(fs::read(path)?, original);
    Ok(())
}

#[test]
fn a_complete_header_can_be_inspected_without_verifying_a_truncated_body()
-> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("header-only.dat");
    let original = fs::read(fixture())?;
    // Core SnapshotMetadata: 5-byte magic, u16 version, 4 network bytes,
    // 32-byte block hash, u64 coin count.
    fs::write(&path, &original[..51])?;
    let inspected = report(&run(&["inspect", "--json"], &path)?)?;
    assert_eq!(inspected["validation"], "metadata_only");
    assert!(inspected["verification"].is_null());
    let failed = run(&["verify", "--network", "regtest", "--json"], &path)?;
    assert_eq!(failed.status.code(), Some(4));
    assert_eq!(failed.stdout, b"");
    assert_ne!(failed.stderr, b"");
    assert_eq!(fs::read(path)?, original[..51]);
    Ok(())
}

#[test]
fn verification_rejects_wrong_network_and_resource_limits() -> Result<(), Box<dyn Error>> {
    for args in [
        vec!["verify", "--network", "mainnet"],
        vec!["verify", "--network", "regtest", "--max-coins", "199"],
        vec!["verify", "--network", "regtest", "--max-file-bytes", "51"],
    ] {
        let failed = run(&args, &fixture())?;
        assert_eq!(failed.status.code(), Some(4));
        assert_eq!(failed.stdout, b"");
    }
    Ok(())
}

#[test]
fn unpinned_base_is_metadata_only_and_never_verifies() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("unknown-base.dat");
    let mut bytes = fs::read(fixture())?;
    bytes[11..43].fill(0);
    fs::write(&path, &bytes)?;
    let inspected = report(&run(&["inspect", "--json"], &path)?)?;
    assert_eq!(inspected["validation"], "metadata_only");
    assert!(inspected["known_anchor"].is_null());
    assert_eq!(
        run(&["verify", "--network", "regtest"], &path)?
            .status
            .code(),
        Some(4)
    );
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}

#[test]
fn corrupt_and_native_files_fail_with_nonzero_status_without_mutation() -> Result<(), Box<dyn Error>>
{
    let dir = tempdir()?;
    let fixture = fs::read(fixture())?;
    let mut cases = Vec::new();
    let mut bad_magic = fixture.clone();
    bad_magic[0] ^= 1;
    cases.push(("magic", bad_magic, true));
    let mut bad_version = fixture.clone();
    bad_version[5] = 3;
    cases.push(("version", bad_version, true));
    let mut trailing = fixture.clone();
    trailing.push(0);
    cases.push(("trailing", trailing, false));
    cases.push(("truncated", fixture[..fixture.len() - 1].to_vec(), false));
    let native = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/utxo/tests/fixtures/utxo-v4-golden.dat"),
    )?;
    cases.push(("native-v4", native, true));
    for (name, bytes, header_invalid) in cases {
        let path = dir.path().join(name);
        fs::write(&path, &bytes)?;
        let verified = run(&["verify", "--network", "regtest"], &path)?;
        assert_eq!(verified.status.code(), Some(4), "{name}");
        assert_eq!(verified.stdout, b"");
        if header_invalid {
            assert_eq!(run(&["inspect"], &path)?.status.code(), Some(4), "{name}");
        }
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[test]
fn help_usage_and_input_errors_have_stable_exit_codes() -> Result<(), Box<dyn Error>> {
    let binary = env!("CARGO_BIN_EXE_bitcoin-rs-snapshot");
    let help = Command::new(binary).arg("--help").output()?;
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout)?;
    assert!(text.contains("inspect") && text.contains("verify"));
    assert_eq!(Command::new(binary).output()?.status.code(), Some(2));
    assert_eq!(run(&["verify"], &fixture())?.status.code(), Some(2));
    let dir = tempdir()?;
    assert_eq!(
        run(&["inspect"], &dir.path().join("missing.dat"))?
            .status
            .code(),
        Some(3)
    );
    assert_eq!(run(&["inspect"], dir.path())?.status.code(), Some(3));
    Ok(())
}

#[test]
fn human_output_preserves_the_inspection_and_historical_validation_boundaries()
-> Result<(), Box<dyn Error>> {
    let inspected = run(&["inspect"], &fixture())?;
    assert!(inspected.status.success());
    assert!(String::from_utf8(inspected.stdout)?.contains("contents are NOT verified"));
    let verified = run(&["verify", "--network", "regtest"], &fixture())?;
    assert!(verified.status.success());
    let text = String::from_utf8(verified.stdout)?;
    assert!(text.contains("pinned state verified"));
    assert!(text.contains("Historical genesis-to-base validation was not performed"));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn pipes_are_rejected_as_inputs() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("not-a-snapshot.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    assert_eq!(run(&["inspect"], &path)?.status.code(), Some(3));
    assert_eq!(
        run(&["verify", "--network", "regtest"], &path)?
            .status
            .code(),
        Some(3)
    );
    Ok(())
}
