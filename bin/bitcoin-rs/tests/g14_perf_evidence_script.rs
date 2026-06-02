//! Smoke tests for the G14 performance-evidence helper.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn script_normalizes_g14_perf_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), false)?;
    let evidence = evidence_json(temp.path(), 0, 10)?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("export G14_MEASUREMENT_TARGET=mainnet-ibd\n"));
    assert!(stdout.contains("export G14_REFERENCE_IMPL=bitcoin-core\n"));
    assert!(stdout.contains("export G14_IBD_START_HEIGHT=0\n"));
    assert!(stdout.contains("export G14_IBD_STOP_HEIGHT=10\n"));
    assert!(stdout.contains("export G14_BITCOIN_RS_IBD_BLOCKS=11\n"));
    assert!(stdout.contains("export G14_BITCOIN_CORE_IBD_BLOCKS=11\n"));
    assert!(stdout.contains("export G14_IBD_START_HASH=0000000000000000000000000000000000000000000000000000000000000000\n"));
    assert!(stdout.contains("export G14_IBD_STOP_HASH=000000000000000000000000000000000000000000000000000000000000000a\n"));
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_COMMAND_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_COMMAND_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_CONFIG_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_CONFIG_SHA256");
    Ok(())
}

#[test]
fn script_rejects_malformed_bitcoin_core_block_hash() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), true)?;
    let evidence = evidence_json(temp.path(), 0, 1)?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bitcoin-cli start hash"));
    Ok(())
}

fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/collect-g14-perf-evidence.sh")
}

fn evidence_json(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14.json");
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": {start_height},
  "ibd_stop_height": {stop_height},
  "bitcoin_rs_elapsed_seconds": 1.25,
  "bitcoin_core_elapsed_seconds": 2.50,
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=rocksdb\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
        ),
    )?;
    Ok(path)
}

fn fake_bitcoin_cli(
    dir: &Path,
    malformed_hash: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("bitcoin-cli");
    let hash_expr = if malformed_hash {
        r#""not-a-hash""#
    } else {
        r#"f"{height:064x}""#
    };
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import sys

if len(sys.argv) != 3 or sys.argv[1] != "getblockhash":
    raise SystemExit(f"unexpected arguments: {{sys.argv[1:]!r}}")

height = int(sys.argv[2])
print({hash_expr})
"#,
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_64_hex_export(stdout: &str, key: &str) {
    let prefix = format!("export {key}=");
    let line = stdout
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing {key} export in {stdout}"));
    let value = &line[prefix.len()..];
    assert_eq!(value.len(), 64, "{key} value length");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{key} must be lowercase hex, got {value}"
    );
}
