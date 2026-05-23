//! Smoke tests for the G2 Bitcoin Core `MuHash` collection helper.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn script_prints_required_g2_heights() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("bash")
        .arg(script_path())
        .args(["--print-heights", "20001"])
        .output()?;

    assert_success(&output);
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "0\n10000\n20000\n20001\n"
    );
    Ok(())
}

#[test]
fn script_normalizes_bitcoind_muhash_responses() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), false)?;
    let output = Command::new("bash")
        .arg(script_path())
        .arg("20001")
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert_success(&output);
    assert_eq!(
        String::from_utf8(output.stdout)?,
        expected_samples([0, 10_000, 20_000, 20_001])
    );
    Ok(())
}

#[test]
fn script_rejects_bitcoind_height_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), true)?;
    let output = Command::new("bash")
        .arg(script_path())
        .arg("1")
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected 0"));
    Ok(())
}

fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/collect-g2-bitcoind-muhash-samples.sh")
}

fn fake_bitcoin_cli(dir: &Path, wrong_height: bool) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("bitcoin-cli");
    let height_expr = if wrong_height { "height + 1" } else { "height" };
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import json
import sys

if len(sys.argv) != 5 or sys.argv[1] != "gettxoutsetinfo" or sys.argv[2] != "muhash" or sys.argv[4] != "true":
    raise SystemExit(f"unexpected arguments: {{sys.argv[1:]!r}}")

height = int(sys.argv[3])
print(json.dumps({{"height": {height_expr}, "muhash": f"{{height:064x}}"}}))
"#,
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn expected_samples<const N: usize>(heights: [u32; N]) -> String {
    let body = heights
        .into_iter()
        .map(|height| format!("{height}:{height:064x}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{body}\n")
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
