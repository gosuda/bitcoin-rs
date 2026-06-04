//! Smoke tests for the G14 performance-evidence helper.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn script_normalizes_g14_perf_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
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
    assert!(
        stdout.contains("export G14_BITCOIN_RS_CRITERION_BENCHMARK_ID=bitcoin-rs/mainnet-ibd\n")
    );
    assert!(
        stdout
            .contains("export G14_BITCOIN_CORE_CRITERION_BENCHMARK_ID=bitcoin-core/mainnet-ibd\n")
    );
    assert!(stdout.contains("export G14_IBD_START_HASH=0000000000000000000000000000000000000000000000000000000000000000\n"));
    assert!(stdout.contains("export G14_IBD_STOP_HASH=000000000000000000000000000000000000000000000000000000000000000a\n"));
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_COMMAND_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_COMMAND_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_CONFIG_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_CONFIG_SHA256");
    assert_64_hex_export(&stdout, "G14_BENCHMARK_ARTIFACT_SHA256");
    Ok(())
}

#[test]
fn producer_marks_command_wrapper_manifest_as_non_criterion()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_command = fake_ibd_command(temp.path(), "bitcoin-rs-ibd", "0.01")?;
    let bitcoin_core_command = fake_ibd_command(temp.path(), "bitcoin-core-ibd", "0.05")?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = write_text(temp.path(), "criterion.json", "{\"ok\":true}\n")?;
    let manifest = temp.path().join("g14-produced.json");

    let producer_output = Command::new("bash")
        .arg(producer_script_path())
        .args([
            "--output",
            manifest.to_str().ok_or("non-UTF-8 manifest path")?,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--bitcoin-rs-command",
            bitcoin_rs_command
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs command")?,
            "--bitcoin-core-command",
            bitcoin_core_command
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core command")?,
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
            "--bitcoin-core-version",
            "v27.0.0",
            "--bitcoin-core-commit",
            "1111111111111111111111111111111111111111",
            "--benchmark-artifact",
            artifact.to_str().ok_or("non-UTF-8 artifact")?,
            "--utxo-commit-p95-ms",
            "12.5",
            "--electrum-get-history-p95-ms",
            "20.0",
            "--rss-bytes",
            "1024",
        ])
        .output()?;
    assert_success(&producer_output);

    let manifest_json = fs::read_to_string(&manifest)?;
    assert!(manifest_json.contains(r#""ibd_start_height": 0"#));
    assert!(manifest_json.contains(r#""ibd_stop_height": 10"#));
    assert!(manifest_json.contains(r#""bench_tool": "wall-clock-command-wrapper""#));
    assert!(manifest_json.contains(r#""elapsed_seconds_source": "wall-clock-command-wrapper""#));
    assert!(manifest_json.contains(r#""bitcoin_rs_command":"#));
    assert!(manifest_json.contains(r#""bitcoin_core_command":"#));
    assert!(!manifest_json.contains("ibd_start_hash"));
    assert!(!manifest_json.contains("bitcoin_core_chain_info"));

    let collector_output = Command::new("bash")
        .arg(script_path())
        .arg(&manifest)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;
    assert!(!collector_output.status.success());
    assert!(String::from_utf8_lossy(&collector_output.stderr).contains("bench_tool"));
    Ok(())
}

#[test]
fn producer_emits_collectable_manifest_with_explicit_criterion_elapsed_seconds()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = write_text(temp.path(), "criterion.json", "{\"ok\":true}\n")?;
    let manifest = temp.path().join("g14-produced-criterion.json");

    let producer_output = Command::new("bash")
        .arg(producer_script_path())
        .args([
            "--output",
            manifest.to_str().ok_or("non-UTF-8 manifest path")?,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--bitcoin-rs-command",
            "false",
            "--bitcoin-core-command",
            "false",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "1.25",
            "--criterion-bitcoin-core-elapsed-seconds",
            "2.50",
            "--criterion-bitcoin-rs-benchmark-id",
            "bitcoin-rs/mainnet-ibd",
            "--criterion-bitcoin-core-benchmark-id",
            "bitcoin-core/mainnet-ibd",
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
            "--bitcoin-core-version",
            "v27.0.0",
            "--bitcoin-core-commit",
            "1111111111111111111111111111111111111111",
            "--benchmark-artifact",
            artifact.to_str().ok_or("non-UTF-8 artifact")?,
            "--utxo-commit-p95-ms",
            "12.5",
            "--electrum-get-history-p95-ms",
            "20.0",
            "--rss-bytes",
            "1024",
        ])
        .output()?;
    assert_success(&producer_output);

    let manifest_json = fs::read_to_string(&manifest)?;
    assert!(manifest_json.contains(r#""bench_tool": "criterion""#));
    assert!(manifest_json.contains(r#""elapsed_seconds_source": "criterion""#));
    assert!(
        manifest_json.contains(r#""criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd""#)
    );
    assert!(
        manifest_json
            .contains(r#""criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd""#)
    );
    assert!(manifest_json.contains(r#""bitcoin_rs_elapsed_seconds": 1.25"#));
    assert!(manifest_json.contains(r#""bitcoin_core_elapsed_seconds": 2.5"#));

    let collector_output = Command::new("bash")
        .arg(script_path())
        .arg(&manifest)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;
    assert_success(&collector_output);
    Ok(())
}

#[test]
fn producer_rejects_partial_criterion_elapsed_seconds() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = write_text(temp.path(), "criterion.json", "{\"ok\":true}\n")?;
    let manifest = temp.path().join("g14-produced-partial.json");

    let producer_output = Command::new("bash")
        .arg(producer_script_path())
        .args([
            "--output",
            manifest.to_str().ok_or("non-UTF-8 manifest path")?,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--bitcoin-rs-command",
            "false",
            "--bitcoin-core-command",
            "false",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "1.25",
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
            "--bitcoin-core-version",
            "v27.0.0",
            "--bitcoin-core-commit",
            "1111111111111111111111111111111111111111",
            "--benchmark-artifact",
            artifact.to_str().ok_or("non-UTF-8 artifact")?,
            "--utxo-commit-p95-ms",
            "12.5",
            "--electrum-get-history-p95-ms",
            "20.0",
            "--rss-bytes",
            "1024",
        ])
        .output()?;

    assert!(!producer_output.status.success());
    assert!(String::from_utf8_lossy(&producer_output.stderr).contains("must be supplied together"));
    assert!(!manifest.exists());
    Ok(())
}

#[test]
fn script_rejects_offline_core_metadata_without_cli() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let evidence = offline_evidence_json(temp.path(), 0, 10)?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", temp.path().join("missing-bitcoin-cli"))
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("offline Bitcoin Core metadata"));
    Ok(())
}

#[test]
fn script_rejects_slower_bitcoin_rs_ibd_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_elapsed(temp.path(), 0, 10, "3.0", "2.0")?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bitcoin-rs initial sync evidence"));
    Ok(())
}

#[test]
fn script_rejects_malformed_bitcoin_core_block_hash() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::MalformedHash)?;
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

#[test]
fn script_rejects_non_mainnet_bitcoin_core_node() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::WrongChain)?;
    let evidence = evidence_json(temp.path(), 0, 1)?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("connected to mainnet"));
    Ok(())
}

#[test]
fn script_rejects_bitcoin_core_node_below_stop_block() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::ShortBlocks)?;
    let evidence = evidence_json(temp.path(), 0, 10)?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("blocks=9 is below ibd_stop_height=10")
    );
    Ok(())
}

#[test]
fn script_rejects_bitcoin_core_node_below_stop_header() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::ShortHeaders)?;
    let evidence = evidence_json(temp.path(), 0, 10)?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("headers=9 is below ibd_stop_height=10")
    );
    Ok(())
}

fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/collect-g14-perf-evidence.sh")
}

fn producer_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/produce-g14-ibd-manifest.sh")
}

fn write_text(
    dir: &Path,
    name: &str,
    contents: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(&path, contents)?;
    Ok(path)
}

fn fake_ibd_command(
    dir: &Path,
    name: &str,
    sleep_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            r"#!/usr/bin/env python3
import time

time.sleep({sleep_seconds})
",
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn evidence_json(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    evidence_json_with_elapsed(dir, start_height, stop_height, "1.25", "2.50")
}

fn evidence_json_with_elapsed(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14.json");
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": {start_height},
  "ibd_stop_height": {stop_height},
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": {bitcoin_rs_elapsed_seconds},
  "bitcoin_core_elapsed_seconds": {bitcoin_core_elapsed_seconds},
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
        ),
    )?;
    Ok(path)
}

fn offline_evidence_json(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    offline_evidence_json_with_elapsed(dir, start_height, stop_height, "1.25", "2.50")
}

fn offline_evidence_json_with_elapsed(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14-offline.json");
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": {start_height},
  "ibd_stop_height": {stop_height},
  "ibd_start_hash": "2222222222222222222222222222222222222222222222222222222222222222",
  "ibd_stop_hash": "3333333333333333333333333333333333333333333333333333333333333333",
  "bitcoin_core_chain_info": {{"chain": "main", "blocks": 10, "headers": 10}},
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": {bitcoin_rs_elapsed_seconds},
  "bitcoin_core_elapsed_seconds": {bitcoin_core_elapsed_seconds},
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
        ),
    )?;
    Ok(path)
}

#[derive(Clone, Copy)]
enum FakeBitcoinCliMode {
    Mainnet,
    MalformedHash,
    WrongChain,
    ShortBlocks,
    ShortHeaders,
}

fn fake_bitcoin_cli(
    dir: &Path,
    mode: FakeBitcoinCliMode,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("bitcoin-cli");
    let hash_expr = match mode {
        FakeBitcoinCliMode::MalformedHash => r#""not-a-hash""#,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders => r#"f"{height:064x}""#,
    };
    let chain = match mode {
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders => "main",
        FakeBitcoinCliMode::WrongChain => "regtest",
    };
    let blocks = match mode {
        FakeBitcoinCliMode::ShortBlocks => 9,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortHeaders => 10,
    };
    let headers = match mode {
        FakeBitcoinCliMode::ShortHeaders => 9,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks => 10,
    };
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import json
import sys

if len(sys.argv) == 2 and sys.argv[1] == "getblockchaininfo":
    print(json.dumps({{"chain": "{chain}", "blocks": {blocks}, "headers": {headers}}}))
    raise SystemExit(0)

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
