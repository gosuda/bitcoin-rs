//! Smoke tests for the G14 performance-evidence helper.
#![cfg(unix)]

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

type FakeElectrumServer = (thread::JoinHandle<std::io::Result<()>>, u16);
type FakeElectrumRecordingServer = (thread::JoinHandle<std::io::Result<Vec<String>>>, u16);

struct FakeBitcoinRsProcess {
    child: Child,
}

impl FakeBitcoinRsProcess {
    fn pid(&self) -> String {
        self.child.id().to_string()
    }
}

impl Drop for FakeBitcoinRsProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const DIRECT_BITCOIN_RS_COMMAND_SHA256: &str =
    "e321b331d0f8168adf37d502710c2a26adf2c452c5eb25c0cd72f69cbb041099";
const DIRECT_BITCOIN_CORE_COMMAND_SHA256: &str =
    "022e36196e1baa86c9f90b731e17f501823bc65a65603e64876cb970cb7a5193";
const DIRECT_BITCOIN_RS_CONFIG_SHA256: &str =
    "83dfe453d078861eaf0d230622275942d382edb597ab52dc7ee3e5edfef7c062";
const DIRECT_BITCOIN_CORE_CONFIG_SHA256: &str =
    "71f61114f6dfa4ea4bdb00565e18759a4264f4ad6200d7e951b15076c7e258cc";
const PRODUCER_FALSE_COMMAND_SHA256: &str =
    "fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa";
const PRODUCER_BITCOIN_RS_CONFIG_SHA256: &str =
    "e09d513a25da5fb122b789d9296f1ebc7988b0ad9950eb5b8d33a8f28da15bb2";
const PRODUCER_BITCOIN_CORE_CONFIG_SHA256: &str =
    "fa2075ea5013454e21228fa9261aa51a36a3ac196892af528829dc0a3ebac1c1";
const BENCHMARK_HOST_ID: &str = "g14-test-host";

#[derive(Clone, Copy)]
struct CriterionArtifactBinding<'a> {
    benchmark_host_id: &'a str,
    start_hash: &'a str,
    stop_hash: &'a str,
    bitcoin_rs_command_sha256: &'a str,
    bitcoin_core_command_sha256: &'a str,
    bitcoin_rs_config_sha256: &'a str,
    bitcoin_core_config_sha256: &'a str,
}

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
    assert!(stdout.contains(&format!("export G14_COMMIT_SHA={}\n", current_head()?)));
    assert!(stdout.contains("export G14_STORAGE_BACKEND=fjall\n"));
    assert!(stdout.contains("export G14_INDEXES=all\n"));
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
    assert!(stdout.contains("export G14_BENCHMARK_RUN_ID=g14-mainnet-window-00000000\n"));
    assert!(stdout.contains("export G14_BENCHMARK_HOST_ID=g14-test-host\n"));
    assert!(stdout.contains("export G14_IBD_START_HASH=0000000000000000000000000000000000000000000000000000000000000000\n"));
    assert!(stdout.contains("export G14_IBD_STOP_HASH=000000000000000000000000000000000000000000000000000000000000000a\n"));
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_COMMAND_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_COMMAND_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_CONFIG_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_CONFIG_SHA256");
    assert_64_hex_export(&stdout, "G14_BENCHMARK_ARTIFACT_SHA256");
    assert!(stdout.contains("export G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH="));
    assert!(stdout.contains("export G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH="));
    assert_64_hex_export(&stdout, "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_SHA256");
    assert_64_hex_export(&stdout, "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_SHA256");
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
fn producer_emits_collectable_manifest_with_artifact_bound_criterion_elapsed_seconds()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = producer_criterion_artifact_json(temp.path(), "criterion.json", "1.25", "2.50")?;
    let measurement = electrum_rss_measurement_json(
        temp.path(),
        "electrum-rss.json",
        "g14-electrum-rss-measurement-v1",
        "evidence",
        10,
        "000000000000000000000000000000000000000000000000000000000000000a",
    )?;
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
            "--electrum-rss-measurement",
            measurement.to_str().ok_or("non-UTF-8 measurement")?,
        ])
        .output()?;
    assert_success(&producer_output);

    let manifest_json = fs::read_to_string(&manifest)?;
    assert!(manifest_json.contains(r#""bench_tool": "criterion""#));
    assert!(manifest_json.contains(r#""elapsed_seconds_source": "criterion""#));
    assert!(manifest_json.contains(&format!(r#""bitcoin_rs_commit": "{}""#, current_head()?)));
    assert!(manifest_json.contains(r#""storage_backend": "fjall""#));
    assert!(manifest_json.contains(r#""indexes": "all""#));
    assert!(manifest_json.contains(r#""criterion_artifact_schema": "g14-criterion-artifact-v1""#));
    assert!(manifest_json.contains(r#""benchmark_run_id": "g14-mainnet-window-00000000""#));
    assert!(manifest_json.contains(r#""benchmark_host_id": "g14-test-host""#));
    assert!(manifest_json.contains(r#""benchmark_artifact_path":"#));
    assert!(manifest_json.contains(r#""criterion_bitcoin_rs_raw_output_path":"#));
    assert!(manifest_json.contains(r#""criterion_bitcoin_rs_raw_output_sha256":"#));
    assert!(manifest_json.contains(r#""criterion_bitcoin_core_raw_output_path":"#));
    assert!(manifest_json.contains(r#""criterion_bitcoin_core_raw_output_sha256":"#));
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
fn producer_emits_collectable_manifest_with_electrum_rss_measurement()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = producer_criterion_artifact_json(temp.path(), "criterion.json", "1.25", "2.50")?;
    let measurement = electrum_rss_measurement_json(
        temp.path(),
        "electrum-rss.json",
        "g14-electrum-rss-measurement-v1",
        "evidence",
        10,
        "000000000000000000000000000000000000000000000000000000000000000a",
    )?;
    let manifest = temp.path().join("g14-produced-with-electrum-rss.json");

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
            "--electrum-rss-measurement",
            measurement.to_str().ok_or("non-UTF-8 measurement")?,
        ])
        .output()?;
    assert_success(&producer_output);

    let manifest_json = fs::read_to_string(&manifest)?;
    assert!(manifest_json.contains(r#""electrum_get_history_p95_ms": 20.0"#));
    assert!(manifest_json.contains(r#""rss_bytes": 1024"#));
    assert!(
        manifest_json
            .contains(r#""electrum_rss_measurement_schema": "g14-electrum-rss-measurement-v1""#)
    );
    assert!(manifest_json.contains(r#""electrum_rss_measurement_sample_size": 10000"#));
    assert!(manifest_json.contains(r#""electrum_rss_measurement_non_empty_history_count": 10000"#));
    assert!(manifest_json.contains(r#""electrum_rss_measurement_sha256":"#));

    let collector_output = Command::new("bash")
        .arg(script_path())
        .arg(&manifest)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;
    assert_success(&collector_output);
    Ok(())
}

#[test]
fn producer_rejects_smoke_electrum_rss_measurement() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = producer_criterion_artifact_json(temp.path(), "criterion.json", "1.25", "2.50")?;
    let measurement = electrum_rss_measurement_json(
        temp.path(),
        "electrum-rss-smoke.json",
        "g14-electrum-rss-smoke-v1",
        "smoke",
        10,
        "000000000000000000000000000000000000000000000000000000000000000a",
    )?;
    let manifest = temp
        .path()
        .join("g14-produced-with-smoke-electrum-rss.json");

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
            "--electrum-rss-measurement",
            measurement.to_str().ok_or("non-UTF-8 measurement")?,
        ])
        .output()?;

    assert!(!producer_output.status.success());
    assert!(String::from_utf8_lossy(&producer_output.stderr).contains("schema"));
    assert!(!manifest.exists());
    Ok(())
}

#[test]
fn artifact_producer_emits_collectable_same_window_criterion_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_command = fake_ibd_command(temp.path(), "bitcoin-rs-live-ibd", "0.01")?;
    let bitcoin_core_command = fake_ibd_command(temp.path(), "bitcoin-core-live-ibd", "0.05")?;
    let bitcoin_rs_command = bitcoin_rs_command
        .to_str()
        .ok_or("non-UTF-8 bitcoin-rs command")?;
    let bitcoin_core_command = bitcoin_core_command
        .to_str()
        .ok_or("non-UTF-8 Bitcoin Core command")?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let measurement = electrum_rss_measurement_json(
        temp.path(),
        "electrum-rss-live.json",
        "g14-electrum-rss-measurement-v1",
        "evidence",
        10,
        "000000000000000000000000000000000000000000000000000000000000000a",
    )?;
    let artifact = temp.path().join("g14-criterion-artifact.json");
    let manifest = temp.path().join("g14-live-produced.json");

    let artifact_output = produce_g14_criterion_artifact(
        &artifact,
        bitcoin_rs_command,
        bitcoin_core_command,
        &bitcoin_rs_config,
        &bitcoin_core_config,
        &bitcoin_cli,
    )?;
    assert_success(&artifact_output);

    let artifact_json = fs::read_to_string(&artifact)?;
    assert!(artifact_json.contains(r#""schema": "g14-criterion-artifact-v1""#));
    assert!(artifact_json.contains(r#""benchmark_run_id": "g14-mainnet-window-live""#));
    assert!(artifact_json.contains(r#""benchmark_host_id": "g14-test-host""#));
    assert!(artifact_json.contains(
        r#""ibd_start_hash": "0000000000000000000000000000000000000000000000000000000000000000""#
    ));
    assert!(artifact_json.contains(
        r#""ibd_stop_hash": "000000000000000000000000000000000000000000000000000000000000000a""#
    ));

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
            bitcoin_rs_command,
            "--bitcoin-core-command",
            bitcoin_core_command,
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
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--utxo-commit-p95-ms",
            "12.5",
            "--electrum-rss-measurement",
            measurement.to_str().ok_or("non-UTF-8 measurement")?,
        ])
        .output()?;
    assert_success(&producer_output);

    let collector_output = Command::new("bash")
        .arg(script_path())
        .arg(&manifest)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;
    assert_success(&collector_output);
    Ok(())
}

fn produce_g14_criterion_artifact(
    artifact: &Path,
    bitcoin_rs_command: &str,
    bitcoin_core_command: &str,
    bitcoin_rs_config: &Path,
    bitcoin_core_config: &Path,
    bitcoin_cli: &Path,
) -> Result<Output, Box<dyn std::error::Error>> {
    let artifact_dir = artifact.parent().ok_or("artifact path has no parent")?;
    let start_height = 0;
    let stop_height = 10;
    let start_hash = format!("{start_height:064x}");
    let stop_hash = format!("{stop_height:064x}");
    let bitcoin_rs_command_sha256 = sha256_text(bitcoin_rs_command);
    let bitcoin_core_command_sha256 = sha256_text(bitcoin_core_command);
    let bitcoin_rs_config_sha256 = sha256_text(&fs::read_to_string(bitcoin_rs_config)?);
    let bitcoin_core_config_sha256 = sha256_text(&fs::read_to_string(bitcoin_core_config)?);
    let bitcoin_rs_raw_output = write_text(
        artifact_dir,
        "bitcoin-rs-criterion-raw-output.txt",
        &criterion_raw_output_with_proof(
            "bitcoin-rs/mainnet-ibd",
            "1.25",
            "g14-mainnet-window-live",
            BENCHMARK_HOST_ID,
            start_height,
            stop_height,
            &start_hash,
            &stop_hash,
            &bitcoin_rs_command_sha256,
            &bitcoin_rs_config_sha256,
        ),
    )?;
    let bitcoin_core_raw_output = write_text(
        artifact_dir,
        "bitcoin-core-criterion-raw-output.txt",
        &criterion_raw_output_with_proof(
            "bitcoin-core/mainnet-ibd",
            "2.50",
            "g14-mainnet-window-live",
            BENCHMARK_HOST_ID,
            start_height,
            stop_height,
            &start_hash,
            &stop_hash,
            &bitcoin_core_command_sha256,
            &bitcoin_core_config_sha256,
        ),
    )?;
    Ok(Command::new("bash")
        .arg(artifact_producer_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-live",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "1.25",
            "--criterion-bitcoin-core-elapsed-seconds",
            "2.50",
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--bitcoin-rs-command",
            bitcoin_rs_command,
            "--bitcoin-core-command",
            bitcoin_core_command,
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?)
}

#[test]
fn artifact_producer_rejects_invalid_elapsed_seconds() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let bitcoin_rs_raw_output = write_text(
        temp.path(),
        "bitcoin-rs-criterion-raw-output.txt",
        &criterion_raw_output("bitcoin-rs/mainnet-ibd", "1.25"),
    )?;
    let bitcoin_core_raw_output = write_text(
        temp.path(),
        "bitcoin-core-criterion-raw-output.txt",
        &criterion_raw_output("bitcoin-core/mainnet-ibd", "2.50"),
    )?;
    let artifact = temp.path().join("g14-failed-artifact.json");
    fs::write(&artifact, "stale artifact\n")?;

    let artifact_output = Command::new("bash")
        .arg(artifact_producer_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--force",
            "--benchmark-run-id",
            "g14-mainnet-window-failed",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "0.0",
            "--criterion-bitcoin-core-elapsed-seconds",
            "2.50",
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--bitcoin-rs-command",
            "target/release/bitcoin-rs --network mainnet",
            "--bitcoin-core-command",
            "bitcoind -chain=main",
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!artifact_output.status.success());
    assert!(
        String::from_utf8_lossy(&artifact_output.stderr)
            .contains("--criterion-bitcoin-rs-elapsed-seconds")
    );
    assert!(!artifact.exists());
    Ok(())
}

#[test]
fn artifact_producer_rejects_elapsed_seconds_not_in_raw_output()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let bitcoin_rs_raw_output = write_text(
        temp.path(),
        "bitcoin-rs-criterion-raw-output.txt",
        &criterion_raw_output("bitcoin-rs/mainnet-ibd", "1.25"),
    )?;
    let bitcoin_core_raw_output = write_text(
        temp.path(),
        "bitcoin-core-criterion-raw-output.txt",
        &criterion_raw_output("bitcoin-core/mainnet-ibd", "2.50"),
    )?;
    let artifact = temp.path().join("g14-mismatched-artifact.json");

    let artifact_output = Command::new("bash")
        .arg(artifact_producer_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-mismatched",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "1.26",
            "--criterion-bitcoin-core-elapsed-seconds",
            "2.50",
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--bitcoin-rs-command",
            "target/release/bitcoin-rs --network mainnet",
            "--bitcoin-core-command",
            "bitcoind -chain=main",
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!artifact_output.status.success());
    let stderr = String::from_utf8_lossy(&artifact_output.stderr);
    assert!(stderr.contains("--criterion-bitcoin-rs-elapsed-seconds"));
    assert!(stderr.contains("does not match"));
    assert!(!artifact.exists());
    Ok(())
}

#[test]
fn artifact_producer_rejects_non_exact_raw_output_benchmark_id()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let bitcoin_rs_raw_output = write_text(
        temp.path(),
        "bitcoin-rs-criterion-raw-output.txt",
        "Benchmarking bitcoin-rs/mainnet-ibd\nbitcoin-rs/mainnet-ibd-cache-warm\ntime:   [1.00 s 1.25 s 3.00 s]\n",
    )?;
    let bitcoin_core_raw_output = write_text(
        temp.path(),
        "bitcoin-core-criterion-raw-output.txt",
        &criterion_raw_output("bitcoin-core/mainnet-ibd", "2.50"),
    )?;
    let artifact = temp.path().join("g14-wrong-benchmark-artifact.json");

    let artifact_output = Command::new("bash")
        .arg(artifact_producer_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-wrong-benchmark",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "1.25",
            "--criterion-bitcoin-core-elapsed-seconds",
            "2.50",
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--bitcoin-rs-command",
            "target/release/bitcoin-rs --network mainnet",
            "--bitcoin-core-command",
            "bitcoind -chain=main",
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!artifact_output.status.success());
    let stderr = String::from_utf8_lossy(&artifact_output.stderr);
    assert!(stderr.contains("--criterion-bitcoin-rs-raw-output"));
    assert!(stderr.contains("bitcoin-rs/mainnet-ibd"));
    assert!(!artifact.exists());
    Ok(())
}

#[test]
fn artifact_producer_rejects_unlabeled_raw_output_time() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let bitcoin_rs_raw_output = write_text(
        temp.path(),
        "bitcoin-rs-criterion-raw-output.txt",
        "Benchmarking bitcoin-rs/mainnet-ibd\nunrelated text\ntime:   [1.00 s 1.25 s 3.00 s]\n",
    )?;
    let bitcoin_core_raw_output = write_text(
        temp.path(),
        "bitcoin-core-criterion-raw-output.txt",
        &criterion_raw_output("bitcoin-core/mainnet-ibd", "2.50"),
    )?;
    let artifact = temp.path().join("g14-unlabeled-time-artifact.json");

    let artifact_output = Command::new("bash")
        .arg(artifact_producer_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-unlabeled-time",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--criterion-bitcoin-rs-elapsed-seconds",
            "1.25",
            "--criterion-bitcoin-core-elapsed-seconds",
            "2.50",
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--bitcoin-rs-command",
            "target/release/bitcoin-rs --network mainnet",
            "--bitcoin-core-command",
            "bitcoind -chain=main",
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!artifact_output.status.success());
    let stderr = String::from_utf8_lossy(&artifact_output.stderr);
    assert!(stderr.contains("--criterion-bitcoin-rs-raw-output"));
    assert!(stderr.contains("bitcoin-rs/mainnet-ibd"));
    assert!(!artifact.exists());
    Ok(())
}

#[test]
fn criterion_runner_emits_artifact_with_canonical_raw_outputs()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let bitcoin_rs_command = fake_criterion_command(
        temp.path(),
        "bitcoin-rs-runner-criterion",
        "bitcoin-rs/mainnet-ibd",
        "1.25",
    )?;
    let bitcoin_core_command = fake_criterion_command(
        temp.path(),
        "bitcoin-core-runner-criterion",
        "bitcoin-core/mainnet-ibd",
        "2.50",
    )?;
    let artifact = temp.path().join("g14-runner-artifact.json");
    let bitcoin_rs_raw_output = temp.path().join("bitcoin-rs-runner-raw.txt");
    let bitcoin_core_raw_output = temp.path().join("bitcoin-core-runner-raw.txt");

    let output = Command::new("bash")
        .arg(criterion_runner_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-runner",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
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
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--",
            "-datadir=/tmp/fake-core",
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert_success(&output);
    let artifact_json = fs::read_to_string(&artifact)?;
    assert!(artifact_json.contains(r#""schema": "g14-criterion-artifact-v1""#));
    assert!(artifact_json.contains(r#""benchmark_id": "bitcoin-rs/mainnet-ibd""#));
    assert!(artifact_json.contains(r#""benchmark_id": "bitcoin-core/mainnet-ibd""#));
    assert!(artifact_json.contains(r#""raw_output_path":"#));
    let bitcoin_rs_raw = fs::read_to_string(&bitcoin_rs_raw_output)?;
    let bitcoin_core_raw = fs::read_to_string(&bitcoin_core_raw_output)?;
    assert!(bitcoin_rs_raw.contains("Benchmarking bitcoin-rs/mainnet-ibd"));
    assert!(bitcoin_rs_raw.contains("bitcoin-rs/mainnet-ibd   time:"));
    assert!(bitcoin_core_raw.contains("Benchmarking bitcoin-core/mainnet-ibd"));
    assert!(bitcoin_core_raw.contains("bitcoin-core/mainnet-ibd   time:"));
    Ok(())
}

#[test]
fn bitcoin_rs_mainnet_ibd_wrapper_emits_canonical_criterion_output()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let replay_command = fake_mainnet_prefix_replay_command(
        temp.path(),
        "bitcoin-rs-mainnet-prefix-replay",
        "1.25",
    )?;
    let replay_output = temp.path().join("bitcoin-rs-mainnet-prefix-replay.json");

    let output = Command::new("bash")
        .arg(bitcoin_rs_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--replay-command",
            replay_command
                .to_str()
                .ok_or("non-UTF-8 replay command path")?,
            "--replay-output",
            replay_output
                .to_str()
                .ok_or("non-UTF-8 replay output path")?,
        ])
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Benchmarking bitcoin-rs/mainnet-ibd\n"));
    assert!(stdout.contains("bitcoin-rs/mainnet-ibd   time:   [1.25 s 1.25 s 1.25 s]\n"));
    assert!(replay_output.exists());
    Ok(())
}

#[test]
fn bitcoin_rs_mainnet_ibd_wrapper_rejects_invalid_replay_json()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let replay_command = fake_mainnet_prefix_replay_command_with_body(
        temp.path(),
        "bitcoin-rs-invalid-mainnet-prefix-replay",
        r#"{"schema":"not-mainnet-prefix-replay","elapsed_seconds":1.25}"#,
    )?;

    let output = Command::new("bash")
        .arg(bitcoin_rs_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--replay-command",
            replay_command
                .to_str()
                .ok_or("non-UTF-8 replay command path")?,
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("replay artifact schema"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn bitcoin_rs_mainnet_ibd_wrapper_rejects_wrong_replay_window()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let replay_command = fake_mainnet_prefix_replay_command_with_window(
        temp.path(),
        "bitcoin-rs-wrong-window-mainnet-prefix-replay",
        "1.25",
        0,
        9,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000009",
    )?;

    let output = Command::new("bash")
        .arg(bitcoin_rs_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--replay-command",
            replay_command
                .to_str()
                .ok_or("non-UTF-8 replay command path")?,
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("replay artifact stop_height"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn bitcoin_core_mainnet_ibd_wrapper_emits_canonical_criterion_output()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(temp.path(), "bitcoin.conf", "chain=main\n")?;
    let datadir = temp.path().join("core-datadir");
    fs::create_dir(&datadir)?;
    let stop_file = temp.path().join("fake-bitcoind.stop");
    let bitcoind = fake_bitcoind_command(temp.path(), "bitcoind", &stop_file)?;
    let bitcoin_cli = fake_measured_bitcoin_core_cli(
        temp.path(),
        "bitcoin-cli",
        FakeBitcoinCliMode::Mainnet,
        &stop_file,
    )?;
    let command_output = temp.path().join("bitcoind.log");

    let output = Command::new("bash")
        .arg(bitcoin_core_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-core-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoind-command",
            bitcoind.to_str().ok_or("non-UTF-8 bitcoind path")?,
            "--bitcoin-cli-command",
            bitcoin_cli.to_str().ok_or("non-UTF-8 bitcoin-cli path")?,
            "--command-output",
            command_output.to_str().ok_or("non-UTF-8 command output")?,
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Benchmarking bitcoin-core/mainnet-ibd\n"));
    assert!(stdout.contains("bitcoin-core/mainnet-ibd   time:"));
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn bitcoin_core_mainnet_ibd_wrapper_retries_rpc_startup() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let config = write_text(temp.path(), "bitcoin.conf", "chain=main\n")?;
    let datadir = temp.path().join("core-datadir");
    fs::create_dir(&datadir)?;
    let stop_file = temp.path().join("fake-bitcoind.stop");
    let bitcoind = fake_bitcoind_command(temp.path(), "bitcoind", &stop_file)?;
    let bitcoin_cli = fake_measured_bitcoin_core_cli(
        temp.path(),
        "bitcoin-cli",
        FakeBitcoinCliMode::RpcWarmup,
        &stop_file,
    )?;

    let output = Command::new("bash")
        .arg(bitcoin_core_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-core-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoind-command",
            bitcoind.to_str().ok_or("non-UTF-8 bitcoind path")?,
            "--bitcoin-cli-command",
            bitcoin_cli.to_str().ok_or("non-UTF-8 bitcoin-cli path")?,
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Benchmarking bitcoin-core/mainnet-ibd\n"));
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn bitcoin_core_mainnet_ibd_wrapper_rejects_non_mainnet_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(temp.path(), "bitcoin.conf", "chain=main\n")?;
    let datadir = temp.path().join("core-datadir");
    fs::create_dir(&datadir)?;
    let stop_file = temp.path().join("fake-bitcoind.stop");
    let bitcoind = fake_bitcoind_command(temp.path(), "bitcoind", &stop_file)?;
    let bitcoin_cli = fake_measured_bitcoin_core_cli(
        temp.path(),
        "bitcoin-cli",
        FakeBitcoinCliMode::WrongChain,
        &stop_file,
    )?;

    let output = Command::new("bash")
        .arg(bitcoin_core_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-core-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoind-command",
            bitcoind.to_str().ok_or("non-UTF-8 bitcoind path")?,
            "--bitcoin-cli-command",
            bitcoin_cli.to_str().ok_or("non-UTF-8 bitcoin-cli path")?,
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mainnet"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn bitcoin_core_mainnet_ibd_wrapper_rejects_wrong_stop_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(temp.path(), "bitcoin.conf", "chain=main\n")?;
    let datadir = temp.path().join("core-datadir");
    fs::create_dir(&datadir)?;
    let stop_file = temp.path().join("fake-bitcoind.stop");
    let bitcoind = fake_bitcoind_command(temp.path(), "bitcoind", &stop_file)?;
    let bitcoin_cli = fake_measured_bitcoin_core_cli(
        temp.path(),
        "bitcoin-cli",
        FakeBitcoinCliMode::Mainnet,
        &stop_file,
    )?;

    let output = Command::new("bash")
        .arg(bitcoin_core_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000b",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-core-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoind-command",
            bitcoind.to_str().ok_or("non-UTF-8 bitcoind path")?,
            "--bitcoin-cli-command",
            bitcoin_cli.to_str().ok_or("non-UTF-8 bitcoin-cli path")?,
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .env("TMPDIR", temp.path())
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stop hash"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn bitcoin_core_mainnet_ibd_wrapper_rejects_already_synced_datadir()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(temp.path(), "bitcoin.conf", "chain=main\n")?;
    let datadir = temp.path().join("core-datadir");
    fs::create_dir(&datadir)?;
    let stop_file = temp.path().join("fake-bitcoind.stop");
    let bitcoind = fake_bitcoind_command(temp.path(), "bitcoind", &stop_file)?;
    let bitcoin_cli = fake_measured_bitcoin_core_cli(
        temp.path(),
        "bitcoin-cli",
        FakeBitcoinCliMode::AlreadySynced,
        &stop_file,
    )?;

    let output = Command::new("bash")
        .arg(bitcoin_core_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-core-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoind-command",
            bitcoind.to_str().ok_or("non-UTF-8 bitcoind path")?,
            "--bitcoin-cli-command",
            bitcoin_cli.to_str().ok_or("non-UTF-8 bitcoin-cli path")?,
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("starts past requested IBD start height"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_emits_canonical_criterion_output()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-bitcoin-rs.stop");
    let bitcoin_rs = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "bitcoin-rs",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::Mainnet,
        &stop_file,
    )?;
    let command_output = temp.path().join("bitcoin-rs.log");
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            &rpc_url,
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--command-output",
            command_output.to_str().ok_or("non-UTF-8 command output")?,
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Benchmarking bitcoin-rs/mainnet-ibd\n"));
    assert!(stdout.contains("bitcoin-rs/mainnet-ibd   time:"));
    assert!(stop_file.exists());
    assert!(
        command_output.is_file(),
        "explicit --command-output path must be preserved"
    );
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_removes_auto_command_output_on_success()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-bitcoin-rs.stop");
    let bitcoin_rs = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "bitcoin-rs",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::Mainnet,
        &stop_file,
    )?;
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            &rpc_url,
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .env("TMPDIR", temp.path())
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Benchmarking bitcoin-rs/mainnet-ibd\n"));
    assert!(stdout.contains("bitcoin-rs/mainnet-ibd   time:"));
    let stale_outputs: Vec<_> = fs::read_dir(temp.path())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("bitcoin-rs-daemon-mainnet-ibd-"))
        })
        .collect();
    assert!(
        stale_outputs.is_empty(),
        "auto-created --command-output temp files must be removed on success: {stale_outputs:?}"
    );
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_shuts_down_promptly_with_large_startup_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-bitcoin-rs.stop");
    let bitcoin_rs = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "bitcoin-rs",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::Mainnet,
        &stop_file,
    )?;
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");
    let started = Instant::now();

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            &rpc_url,
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "900",
        ])
        .output()?;

    assert_success(&output);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "shutdown must not wait for --startup-timeout-seconds before reaping the direct child; elapsed={:?}",
        started.elapsed()
    );
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_rejects_wrong_stop_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-bitcoin-rs.stop");
    let bitcoin_rs = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "bitcoin-rs",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::Mainnet,
        &stop_file,
    )?;
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000b",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            &rpc_url,
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .env("TMPDIR", temp.path())
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stop hash"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stop_file.exists());
    let stale_outputs: Vec<_> = fs::read_dir(temp.path())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("bitcoin-rs-daemon-mainnet-ibd-"))
        })
        .collect();
    assert!(stale_outputs.is_empty(), "stale outputs: {stale_outputs:?}");
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_rejects_rpc_startup_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-bitcoin-rs.stop");
    let bitcoin_rs = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "bitcoin-rs-no-rpc",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::RpcStartupTimeout,
        &stop_file,
    )?;
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            &rpc_url,
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "0.2",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("RPC startup"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_translates_localhost_rpc_url()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-bitcoin-rs.stop");
    let bitcoin_rs = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "bitcoin-rs",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::Mainnet,
        &stop_file,
    )?;
    let rpc_url = format!("http://localhost:{rpc_port}/");

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            &rpc_url,
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--poll-interval-seconds",
            "0.01",
            "--startup-timeout-seconds",
            "5",
        ])
        .output()?;

    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Benchmarking bitcoin-rs/mainnet-ibd\n"));
    assert!(stdout.contains("bitcoin-rs/mainnet-ibd   time:"));
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_rejects_dns_rpc_url()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--rpc-url",
            "http://bitcoin-rs.example:8332/",
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("IP literal or localhost"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_rejects_addnode_option()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--rpc-url",
            "http://127.0.0.1:8332/",
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--addnode",
            "127.0.0.1:8333",
        ])
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized arguments") && stderr.contains("--addnode"),
        "stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn bitcoin_rs_daemon_mainnet_ibd_wrapper_rejects_addnode_passthrough()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let datadir = temp.path().join("bitcoin-rs-datadir");
    fs::create_dir(&datadir)?;
    let bitcoin_rs = fake_failing_command(temp.path(), "bitcoin-rs")?;

    let output = Command::new("bash")
        .arg(bitcoin_rs_daemon_mainnet_ibd_script_path())
        .args([
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--ibd-start-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--ibd-stop-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--datadir",
            datadir.to_str().ok_or("non-UTF-8 datadir path")?,
            "--bitcoin-rs-config",
            config.to_str().ok_or("non-UTF-8 config path")?,
            "--bitcoin-rs-command",
            bitcoin_rs.to_str().ok_or("non-UTF-8 bitcoin-rs command")?,
            "--rpc-url",
            "http://127.0.0.1:8332/",
            "--rpc-user",
            "g14-user",
            "--rpc-password",
            "g14-pass",
            "--",
            "--addnode",
            "127.0.0.1:8333",
        ])
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bitcoin-rs daemon CLI does not support --addnode"),
        "stderr: {stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(7),
        "passthrough rejection must occur before launching --bitcoin-rs-command"
    );
    Ok(())
}

#[test]
fn criterion_runner_accepts_bitcoin_rs_daemon_mainnet_ibd_wrapper()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let datadir = temp.path().join("bitcoin-rs-runner-datadir");
    fs::create_dir(&datadir)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);
    let stop_file = temp.path().join("fake-runner-bitcoin-rs.stop");
    let bitcoin_rs_daemon = fake_bitcoin_rs_daemon_command(
        temp.path(),
        "runner-bitcoin-rs",
        rpc_port,
        "g14-user",
        "g14-pass",
        FakeBitcoinRsRpcMode::Mainnet,
        &stop_file,
    )?;
    let command_output = temp.path().join("runner-bitcoin-rs.log");
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/");
    let bitcoin_rs_command = format!(
        "bash {} --ibd-start-height 0 --ibd-stop-height 10 --ibd-start-hash 0000000000000000000000000000000000000000000000000000000000000000 --ibd-stop-hash 000000000000000000000000000000000000000000000000000000000000000a --datadir {} --bitcoin-rs-config {} --bitcoin-rs-command {} --rpc-url {} --rpc-user g14-user --rpc-password g14-pass --command-output {} --force --poll-interval-seconds 0.01 --startup-timeout-seconds 5",
        bitcoin_rs_daemon_mainnet_ibd_script_path().display(),
        datadir.display(),
        bitcoin_rs_config.display(),
        bitcoin_rs_daemon.display(),
        rpc_url,
        command_output.display()
    );
    let bitcoin_core_command = fake_criterion_command(
        temp.path(),
        "bitcoin-core-runner-criterion",
        "bitcoin-core/mainnet-ibd",
        "2.50",
    )?;
    let artifact = temp.path().join("g14-daemon-wrapper-runner-artifact.json");
    let bitcoin_rs_raw_output = temp.path().join("bitcoin-rs-daemon-wrapper-runner-raw.txt");
    let bitcoin_core_raw_output = temp
        .path()
        .join("bitcoin-core-daemon-wrapper-runner-raw.txt");

    let output = Command::new("bash")
        .arg(criterion_runner_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-daemon-wrapper-runner",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--bitcoin-rs-command",
            &bitcoin_rs_command,
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
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--",
            "-datadir=/tmp/fake-core",
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert_success(&output);
    let artifact_json = fs::read_to_string(&artifact)?;
    assert!(artifact_json.contains(r#""schema": "g14-criterion-artifact-v1""#));
    let bitcoin_rs_raw = fs::read_to_string(&bitcoin_rs_raw_output)?;
    assert!(bitcoin_rs_raw.contains("Benchmarking bitcoin-rs/mainnet-ibd"));
    assert!(bitcoin_rs_raw.contains("bitcoin-rs/mainnet-ibd   time:"));
    assert!(bitcoin_rs_raw.contains("G14_IBD_COMPLETION_PROOF "));
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn criterion_runner_accepts_bitcoin_rs_mainnet_ibd_wrapper()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let replay_command = fake_mainnet_prefix_replay_command(
        temp.path(),
        "bitcoin-rs-runner-mainnet-prefix-replay",
        "1.25",
    )?;
    let replay_output = temp
        .path()
        .join("bitcoin-rs-runner-mainnet-prefix-replay.json");
    let bitcoin_rs_command = format!(
        "bash {} --ibd-start-height 0 --ibd-stop-height 10 --ibd-start-hash 0000000000000000000000000000000000000000000000000000000000000000 --ibd-stop-hash 000000000000000000000000000000000000000000000000000000000000000a --replay-command {} --replay-output {} --force",
        bitcoin_rs_mainnet_ibd_script_path().display(),
        replay_command.display(),
        replay_output.display()
    );
    let bitcoin_core_command = fake_criterion_command(
        temp.path(),
        "bitcoin-core-runner-criterion",
        "bitcoin-core/mainnet-ibd",
        "2.50",
    )?;
    let artifact = temp.path().join("g14-wrapper-runner-artifact.json");
    let bitcoin_rs_raw_output = temp.path().join("bitcoin-rs-wrapper-runner-raw.txt");
    let bitcoin_core_raw_output = temp.path().join("bitcoin-core-wrapper-runner-raw.txt");

    let output = Command::new("bash")
        .arg(criterion_runner_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-wrapper-runner",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--bitcoin-rs-command",
            &bitcoin_rs_command,
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
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--",
            "-datadir=/tmp/fake-core",
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert_success(&output);
    let artifact_json = fs::read_to_string(&artifact)?;
    assert!(artifact_json.contains(r#""schema": "g14-criterion-artifact-v1""#));
    let bitcoin_rs_raw = fs::read_to_string(&bitcoin_rs_raw_output)?;
    assert!(bitcoin_rs_raw.contains("Benchmarking bitcoin-rs/mainnet-ibd"));
    assert!(bitcoin_rs_raw.contains("bitcoin-rs/mainnet-ibd   time:"));
    assert!(bitcoin_rs_raw.contains("G14_IBD_COMPLETION_PROOF "));
    assert!(replay_output.exists());
    Ok(())
}

#[test]
fn criterion_runner_accepts_bitcoin_core_mainnet_ibd_wrapper()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let bitcoin_rs_command = fake_criterion_command(
        temp.path(),
        "bitcoin-rs-runner-criterion",
        "bitcoin-rs/mainnet-ibd",
        "1.25",
    )?;
    let datadir = temp.path().join("core-wrapper-runner-datadir");
    fs::create_dir(&datadir)?;
    let stop_file = temp.path().join("fake-runner-bitcoind.stop");
    let bitcoind = fake_bitcoind_command(temp.path(), "runner-bitcoind", &stop_file)?;
    let measured_bitcoin_cli = fake_measured_bitcoin_core_cli(
        temp.path(),
        "runner-bitcoin-cli",
        FakeBitcoinCliMode::Mainnet,
        &stop_file,
    )?;
    let command_output = temp.path().join("runner-bitcoind.log");
    let bitcoin_core_command = format!(
        "bash {} --ibd-start-height 0 --ibd-stop-height 10 --ibd-start-hash 0000000000000000000000000000000000000000000000000000000000000000 --ibd-stop-hash 000000000000000000000000000000000000000000000000000000000000000a --datadir {} --bitcoin-core-config {} --bitcoind-command {} --bitcoin-cli-command {} --command-output {} --force --poll-interval-seconds 0.01 --startup-timeout-seconds 5",
        bitcoin_core_mainnet_ibd_script_path().display(),
        datadir.display(),
        bitcoin_core_config.display(),
        bitcoind.display(),
        measured_bitcoin_cli.display(),
        command_output.display()
    );
    let artifact = temp.path().join("g14-core-wrapper-runner-artifact.json");
    let bitcoin_rs_raw_output = temp.path().join("bitcoin-rs-core-wrapper-runner-raw.txt");
    let bitcoin_core_raw_output = temp.path().join("bitcoin-core-wrapper-runner-raw.txt");

    let output = Command::new("bash")
        .arg(criterion_runner_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-core-wrapper-runner",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
            "--ibd-start-height",
            "0",
            "--ibd-stop-height",
            "10",
            "--bitcoin-rs-command",
            bitcoin_rs_command
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs command")?,
            "--bitcoin-core-command",
            &bitcoin_core_command,
            "--bitcoin-rs-config",
            bitcoin_rs_config
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs config")?,
            "--bitcoin-core-config",
            bitcoin_core_config
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core config")?,
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
            "--",
            "-datadir=/tmp/fake-core",
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert_success(&output);
    let artifact_json = fs::read_to_string(&artifact)?;
    assert!(artifact_json.contains(r#""schema": "g14-criterion-artifact-v1""#));
    let bitcoin_core_raw = fs::read_to_string(&bitcoin_core_raw_output)?;
    assert!(bitcoin_core_raw.contains("Benchmarking bitcoin-core/mainnet-ibd"));
    assert!(bitcoin_core_raw.contains("bitcoin-core/mainnet-ibd   time:"));
    assert!(bitcoin_core_raw.contains("G14_IBD_COMPLETION_PROOF "));
    assert!(stop_file.exists());
    Ok(())
}

#[test]
fn criterion_runner_removes_partial_outputs_when_command_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let bitcoin_rs_command = fake_criterion_command(
        temp.path(),
        "bitcoin-rs-runner-criterion",
        "bitcoin-rs/mainnet-ibd",
        "1.25",
    )?;
    let bitcoin_core_command = fake_failing_command(temp.path(), "bitcoin-core-runner-fails")?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = temp.path().join("g14-runner-failed-artifact.json");
    let bitcoin_rs_raw_output = temp.path().join("bitcoin-rs-runner-failed-raw.txt");
    let bitcoin_core_raw_output = temp.path().join("bitcoin-core-runner-failed-raw.txt");

    let output = Command::new("bash")
        .arg(criterion_runner_script_path())
        .args([
            "--output",
            artifact.to_str().ok_or("non-UTF-8 artifact path")?,
            "--benchmark-run-id",
            "g14-mainnet-window-runner-failed",
            "--benchmark-host-id",
            BENCHMARK_HOST_ID,
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
            "--criterion-bitcoin-rs-raw-output",
            bitcoin_rs_raw_output
                .to_str()
                .ok_or("non-UTF-8 bitcoin-rs raw output")?,
            "--criterion-bitcoin-core-raw-output",
            bitcoin_core_raw_output
                .to_str()
                .ok_or("non-UTF-8 Bitcoin Core raw output")?,
        ])
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--bitcoin-core-command failed"));
    assert!(!artifact.exists());
    assert!(!bitcoin_rs_raw_output.exists());
    assert!(!bitcoin_core_raw_output.exists());
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
    let artifact = producer_criterion_artifact_json(temp.path(), "criterion.json", "1.25", "2.50")?;
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
fn producer_rejects_criterion_elapsed_seconds_not_bound_to_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = producer_criterion_artifact_json(temp.path(), "criterion.json", "1.25", "2.50")?;
    let manifest = temp.path().join("g14-produced-mismatched-artifact.json");

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
            "1.26",
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

    assert!(!producer_output.status.success());
    assert!(
        String::from_utf8_lossy(&producer_output.stderr)
            .contains("must match the hashed Criterion artifact")
    );
    assert!(!manifest.exists());
    Ok(())
}

#[test]
fn producer_rejects_criterion_artifact_for_different_ibd_window()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = producer_criterion_artifact_json_with_window(
        temp.path(),
        "criterion-wrong-window.json",
        "1.25",
        "2.50",
        1,
        10,
    )?;
    let manifest = temp.path().join("g14-produced-wrong-window.json");

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

    assert!(!producer_output.status.success());
    assert!(String::from_utf8_lossy(&producer_output.stderr).contains("ibd_start_height"));
    assert!(!manifest.exists());
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_for_different_command_config()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_artifact_command_hash(
        temp.path(),
        0,
        10,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bitcoin_rs_command_sha256"));
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_for_different_benchmark_host()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_artifact_host_id(temp.path(), 0, 10, "g14-other-host")?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("benchmark_host_id"));
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_with_stop_hash_not_matching_live_core()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_artifact_window(
        temp.path(),
        0,
        10,
        "1.25",
        "2.50",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ibd_stop_hash"));
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_with_mixed_benchmark_run_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_mixed_benchmark_run_ids(temp.path())?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("benchmark_run_id"));
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_missing_raw_output_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_missing_raw_output_sha256(temp.path())?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("raw_output_sha256"));
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_missing_raw_output_path()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_missing_raw_output_path(temp.path())?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("raw_output_path"));
    Ok(())
}

#[test]
fn script_rejects_criterion_artifact_with_tampered_raw_output()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_tampered_raw_output(temp.path())?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("raw_output_sha256"));
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
fn script_rejects_renamed_criterion_benchmark_identity() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_benchmark_ids(
        temp.path(),
        "bitcoin-rs/not-mainnet-ibd",
        "bitcoin-core/mainnet-ibd",
    )?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("criterion_bitcoin_rs_benchmark_id"));
    Ok(())
}

#[test]
fn producer_rejects_renamed_criterion_benchmark_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let bitcoin_rs_config = write_text(
        temp.path(),
        "bitcoin-rs.toml",
        "storage_backend=fjall\nindexes=all\n",
    )?;
    let bitcoin_core_config = write_text(temp.path(), "bitcoin.conf", "chain=main\ndbcache=450\n")?;
    let artifact = producer_criterion_artifact_json(temp.path(), "criterion.json", "1.25", "2.50")?;
    let manifest = temp.path().join("g14-produced-renamed-benchmark.json");

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
            "--criterion-bitcoin-rs-benchmark-id",
            "bitcoin-rs/not-mainnet-ibd",
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

    assert!(!producer_output.status.success());
    assert!(
        String::from_utf8_lossy(&producer_output.stderr)
            .contains("--criterion-bitcoin-rs-benchmark-id")
    );
    assert!(!manifest.exists());
    Ok(())
}

#[test]
fn script_rejects_evidence_from_different_bitcoin_rs_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_binding_fields(
        temp.path(),
        0,
        10,
        "1.25",
        "2.50",
        "2222222222222222222222222222222222222222",
        "fjall",
        "all",
    )?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("bitcoin_rs_commit must match git HEAD")
    );
    Ok(())
}

#[test]
fn script_rejects_evidence_from_wrong_storage_backend() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_binding_fields(
        temp.path(),
        0,
        10,
        "1.25",
        "2.50",
        &current_head()?,
        "rocksdb",
        "all",
    )?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("storage_backend must be 'fjall'"));
    Ok(())
}

#[test]
fn script_rejects_evidence_from_wrong_index_set() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let bitcoin_cli = fake_bitcoin_cli(temp.path(), FakeBitcoinCliMode::Mainnet)?;
    let evidence = evidence_json_with_binding_fields(
        temp.path(),
        0,
        10,
        "1.25",
        "2.50",
        &current_head()?,
        "fjall",
        "txindex",
    )?;

    let output = Command::new("bash")
        .arg(script_path())
        .arg(evidence)
        .env("BITCOIN_CLI", bitcoin_cli)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("indexes must be 'all'"));
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

#[test]
#[cfg(target_os = "linux")]
fn electrum_rss_measurement_emits_g14_fragment() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let (_server, port) = fake_electrum_server(3)?;
    let output = temp.path().join("electrum-rss.json");

    let command_output = Command::new("bash")
        .arg(electrum_rss_script_path())
        .args([
            "--output",
            output.to_str().ok_or("non-UTF-8 output path")?,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--pid",
            &std::process::id().to_string(),
            "--tip-height",
            "10",
            "--tip-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--sample-size",
            "3",
            "--seed",
            "smoke",
            "--timeout-seconds",
            "5",
            "--generate-empty-scripthashes-for-smoke-test",
        ])
        .output()?;

    assert_success(&command_output);
    let measurement = fs::read_to_string(output)?;
    let measurement: serde_json::Value = serde_json::from_str(&measurement)?;
    assert_eq!(measurement["schema"], "g14-electrum-rss-smoke-v1");
    assert_eq!(measurement["measurement_kind"], "smoke");
    assert_eq!(measurement["method"], "blockchain.scripthash.get_history");
    assert_eq!(measurement["electrum_sample_size"], 3);
    assert_eq!(
        measurement["electrum_scripthash_corpus"],
        "generated-empty-scripthashes-for-smoke-test"
    );
    assert!(
        measurement["electrum_get_history_p95_ms"]
            .as_f64()
            .is_some_and(|value| value > 0.0)
    );
    assert!(
        measurement["rss_bytes"]
            .as_u64()
            .is_some_and(|value| value > 0)
    );
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn electrum_rss_measurement_samples_real_corpus_by_seeded_order()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let (server, port) = fake_electrum_history_server(3)?;
    let fake_node = fake_bitcoin_rs_process()?;
    let output = temp.path().join("electrum-rss.json");
    let corpus_contents = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "5555555555555555555555555555555555555555555555555555555555555555",
        "6666666666666666666666666666666666666666666666666666666666666666",
    ]
    .join("\n")
        + "\n";
    let corpus = write_text(temp.path(), "scripthashes.txt", &corpus_contents)?;

    let command_output = Command::new("bash")
        .arg(electrum_rss_script_path())
        .args([
            "--output",
            output.to_str().ok_or("non-UTF-8 output path")?,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--pid",
            &fake_node.pid(),
            "--tip-height",
            "10",
            "--tip-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--sample-size",
            "3",
            "--seed",
            "sample-seed",
            "--scripthashes",
            corpus.to_str().ok_or("non-UTF-8 corpus path")?,
            "--timeout-seconds",
            "5",
        ])
        .output()?;

    assert_success(&command_output);
    let requested = server
        .join()
        .map_err(|_| "fake Electrum server panicked")??;
    assert_eq!(
        requested,
        vec![
            String::from("3333333333333333333333333333333333333333333333333333333333333333"),
            String::from("2222222222222222222222222222222222222222222222222222222222222222"),
            String::from("4444444444444444444444444444444444444444444444444444444444444444"),
        ]
    );
    let measurement = fs::read_to_string(output)?;
    let measurement: serde_json::Value = serde_json::from_str(&measurement)?;
    assert_eq!(
        measurement["electrum_scripthash_corpus_sha256"],
        "cd75f59f8322b0a49d400a0147d14087d187bbdf0f03cb61bbc8019825e454b0"
    );
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn electrum_rss_measurement_rejects_malformed_tip_hash() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("electrum-rss.json");

    let command_output = Command::new("bash")
        .arg(electrum_rss_script_path())
        .args([
            "--output",
            output.to_str().ok_or("non-UTF-8 output path")?,
            "--host",
            "127.0.0.1",
            "--port",
            "50001",
            "--pid",
            &std::process::id().to_string(),
            "--tip-height",
            "10",
            "--tip-hash",
            "not-a-hash",
            "--sample-size",
            "1",
        ])
        .output()?;

    assert!(!command_output.status.success());
    assert!(String::from_utf8_lossy(&command_output.stderr).contains("--tip-hash"));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn electrum_rss_measurement_requires_real_scripthash_corpus()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("electrum-rss.json");

    let command_output = Command::new("bash")
        .arg(electrum_rss_script_path())
        .args([
            "--output",
            output.to_str().ok_or("non-UTF-8 output path")?,
            "--host",
            "127.0.0.1",
            "--port",
            "50001",
            "--pid",
            &std::process::id().to_string(),
            "--tip-height",
            "10",
            "--tip-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--sample-size",
            "1",
        ])
        .output()?;

    assert!(!command_output.status.success());
    assert!(String::from_utf8_lossy(&command_output.stderr).contains("--scripthashes is required"));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn electrum_rss_measurement_rejects_empty_history_for_real_corpus()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let (_server, port) = fake_electrum_server(1)?;
    let fake_node = fake_bitcoin_rs_process()?;
    let output = temp.path().join("electrum-rss.json");
    let corpus = write_text(
        temp.path(),
        "scripthashes.txt",
        "1111111111111111111111111111111111111111111111111111111111111111\n",
    )?;

    let command_output = Command::new("bash")
        .arg(electrum_rss_script_path())
        .args([
            "--output",
            output.to_str().ok_or("non-UTF-8 output path")?,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--pid",
            &fake_node.pid(),
            "--tip-height",
            "10",
            "--tip-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--sample-size",
            "1",
            "--scripthashes",
            corpus.to_str().ok_or("non-UTF-8 corpus path")?,
            "--timeout-seconds",
            "5",
        ])
        .output()?;

    assert!(!command_output.status.success());
    assert!(
        String::from_utf8_lossy(&command_output.stderr).contains("returned empty history"),
        "stderr: {}",
        String::from_utf8_lossy(&command_output.stderr)
    );
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn electrum_rss_measurement_rejects_smoke_flag_with_real_corpus()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("electrum-rss.json");
    let corpus = write_text(
        temp.path(),
        "scripthashes.txt",
        "1111111111111111111111111111111111111111111111111111111111111111\n",
    )?;

    let command_output = Command::new("bash")
        .arg(electrum_rss_script_path())
        .args([
            "--output",
            output.to_str().ok_or("non-UTF-8 output path")?,
            "--host",
            "127.0.0.1",
            "--port",
            "50001",
            "--pid",
            &std::process::id().to_string(),
            "--tip-height",
            "10",
            "--tip-hash",
            "000000000000000000000000000000000000000000000000000000000000000a",
            "--sample-size",
            "1",
            "--scripthashes",
            corpus.to_str().ok_or("non-UTF-8 corpus path")?,
            "--generate-empty-scripthashes-for-smoke-test",
        ])
        .output()?;

    assert!(!command_output.status.success());
    assert!(
        String::from_utf8_lossy(&command_output.stderr).contains("cannot be combined"),
        "stderr: {}",
        String::from_utf8_lossy(&command_output.stderr)
    );
    Ok(())
}

fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/collect-g14-perf-evidence.sh")
}

fn producer_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/produce-g14-ibd-manifest.sh")
}

fn electrum_rss_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/measure-g14-electrum-rss.sh")
}

fn artifact_producer_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/produce-g14-criterion-artifact.sh")
}

fn criterion_runner_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-g14-mainnet-ibd-criterion.sh")
}

fn bitcoin_rs_mainnet_ibd_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-g14-bitcoin-rs-mainnet-ibd.sh")
}

fn bitcoin_core_mainnet_ibd_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-g14-bitcoin-core-mainnet-ibd.sh")
}

fn bitcoin_rs_daemon_mainnet_ibd_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/run-g14-bitcoin-rs-daemon-mainnet-ibd.sh")
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

fn criterion_raw_output(benchmark_id: &str, elapsed_seconds: &str) -> String {
    let (command_sha256, config_sha256) = if benchmark_id == "bitcoin-core/mainnet-ibd" {
        (
            DIRECT_BITCOIN_CORE_COMMAND_SHA256,
            DIRECT_BITCOIN_CORE_CONFIG_SHA256,
        )
    } else {
        (
            DIRECT_BITCOIN_RS_COMMAND_SHA256,
            DIRECT_BITCOIN_RS_CONFIG_SHA256,
        )
    };
    criterion_raw_output_with_proof(
        benchmark_id,
        elapsed_seconds,
        "g14-mainnet-window-00000000",
        BENCHMARK_HOST_ID,
        0,
        10,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000a",
        command_sha256,
        config_sha256,
    )
}

fn criterion_raw_output_without_proof(benchmark_id: &str, elapsed_seconds: &str) -> String {
    format!(
        "Benchmarking {benchmark_id}\nBenchmarking {benchmark_id}: Warming up for 1.0000 s\nBenchmarking {benchmark_id}: Collecting 100 samples in estimated 5.0000 s\nBenchmarking {benchmark_id}: Analyzing\n{benchmark_id}   time:   [1.00 s {elapsed_seconds} s 3.00 s]\n"
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test fixture mirrors the G14 proof schema"
)]
fn criterion_raw_output_with_proof(
    benchmark_id: &str,
    elapsed_seconds: &str,
    benchmark_run_id: &str,
    benchmark_host_id: &str,
    start_height: u32,
    stop_height: u32,
    start_hash: &str,
    stop_hash: &str,
    command_sha256: &str,
    config_sha256: &str,
) -> String {
    format!(
        "Benchmarking {benchmark_id}\nBenchmarking {benchmark_id}: Warming up for 1.0000 s\nBenchmarking {benchmark_id}: Collecting 100 samples in estimated 5.0000 s\nBenchmarking {benchmark_id}: Analyzing\n{benchmark_id}   time:   [1.00 s {elapsed_seconds} s 3.00 s]\nG14_IBD_COMPLETION_PROOF {{\"schema\":\"g14-ibd-completion-proof-v1\",\"benchmark_id\":\"{benchmark_id}\",\"benchmark_run_id\":\"{benchmark_run_id}\",\"benchmark_host_id\":\"{benchmark_host_id}\",\"ibd_start_height\":{start_height},\"ibd_start_hash\":\"{start_hash}\",\"ibd_stop_height\":{stop_height},\"ibd_stop_hash\":\"{stop_hash}\",\"ibd_blocks\":{},\"command_sha256\":\"{command_sha256}\",\"config_sha256\":\"{config_sha256}\"}}\n",
        stop_height - start_height + 1
    )
}

fn write_criterion_raw_output(
    dir: &Path,
    name: &str,
    benchmark_id: &str,
    elapsed_seconds: &str,
) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
    write_criterion_raw_output_with_proof(
        dir,
        name,
        benchmark_id,
        elapsed_seconds,
        "g14-mainnet-window-00000000",
        BENCHMARK_HOST_ID,
        0,
        10,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000a",
        if benchmark_id == "bitcoin-core/mainnet-ibd" {
            DIRECT_BITCOIN_CORE_COMMAND_SHA256
        } else {
            DIRECT_BITCOIN_RS_COMMAND_SHA256
        },
        if benchmark_id == "bitcoin-core/mainnet-ibd" {
            DIRECT_BITCOIN_CORE_CONFIG_SHA256
        } else {
            DIRECT_BITCOIN_RS_CONFIG_SHA256
        },
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test fixture mirrors the G14 proof schema"
)]
fn write_criterion_raw_output_with_proof(
    dir: &Path,
    name: &str,
    benchmark_id: &str,
    elapsed_seconds: &str,
    benchmark_run_id: &str,
    benchmark_host_id: &str,
    start_height: u32,
    stop_height: u32,
    start_hash: &str,
    stop_hash: &str,
    command_sha256: &str,
    config_sha256: &str,
) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
    let path = write_text(
        dir,
        name,
        &criterion_raw_output_with_proof(
            benchmark_id,
            elapsed_seconds,
            benchmark_run_id,
            benchmark_host_id,
            start_height,
            stop_height,
            start_hash,
            stop_hash,
            command_sha256,
            config_sha256,
        ),
    )?;
    let sha256 = sha256_file(&path)?;
    Ok((path, sha256))
}

fn criterion_artifact_json(
    dir: &Path,
    name: &str,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    criterion_artifact_json_with_window(
        dir,
        name,
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
        0,
        10,
    )
}

fn criterion_artifact_json_with_window(
    dir: &Path,
    name: &str,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
    start_height: u32,
    stop_height: u32,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let start_hash = format!("{start_height:064x}");
    let stop_hash = format!("{stop_height:064x}");
    criterion_artifact_json_with_window_and_hashes(
        dir,
        name,
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
        start_height,
        stop_height,
        CriterionArtifactBinding {
            benchmark_host_id: BENCHMARK_HOST_ID,
            start_hash: &start_hash,
            stop_hash: &stop_hash,
            bitcoin_rs_command_sha256: DIRECT_BITCOIN_RS_COMMAND_SHA256,
            bitcoin_core_command_sha256: DIRECT_BITCOIN_CORE_COMMAND_SHA256,
            bitcoin_rs_config_sha256: DIRECT_BITCOIN_RS_CONFIG_SHA256,
            bitcoin_core_config_sha256: DIRECT_BITCOIN_CORE_CONFIG_SHA256,
        },
    )
}

fn producer_criterion_artifact_json(
    dir: &Path,
    name: &str,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    producer_criterion_artifact_json_with_window(
        dir,
        name,
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
        0,
        10,
    )
}

fn producer_criterion_artifact_json_with_window(
    dir: &Path,
    name: &str,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
    start_height: u32,
    stop_height: u32,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let start_hash = format!("{start_height:064x}");
    let stop_hash = format!("{stop_height:064x}");
    criterion_artifact_json_with_window_and_hashes(
        dir,
        name,
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
        start_height,
        stop_height,
        CriterionArtifactBinding {
            benchmark_host_id: BENCHMARK_HOST_ID,
            start_hash: &start_hash,
            stop_hash: &stop_hash,
            bitcoin_rs_command_sha256: PRODUCER_FALSE_COMMAND_SHA256,
            bitcoin_core_command_sha256: PRODUCER_FALSE_COMMAND_SHA256,
            bitcoin_rs_config_sha256: PRODUCER_BITCOIN_RS_CONFIG_SHA256,
            bitcoin_core_config_sha256: PRODUCER_BITCOIN_CORE_CONFIG_SHA256,
        },
    )
}

fn criterion_artifact_json_with_window_and_hashes(
    dir: &Path,
    name: &str,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
    start_height: u32,
    stop_height: u32,
    binding: CriterionArtifactBinding<'_>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let (bitcoin_rs_raw_output, bitcoin_rs_raw_output_sha256) =
        write_criterion_raw_output_with_proof(
            dir,
            &format!("{name}.bitcoin-rs.raw.txt"),
            "bitcoin-rs/mainnet-ibd",
            bitcoin_rs_elapsed_seconds,
            "g14-mainnet-window-00000000",
            binding.benchmark_host_id,
            start_height,
            stop_height,
            binding.start_hash,
            binding.stop_hash,
            binding.bitcoin_rs_command_sha256,
            binding.bitcoin_rs_config_sha256,
        )?;
    let (bitcoin_core_raw_output, bitcoin_core_raw_output_sha256) =
        write_criterion_raw_output_with_proof(
            dir,
            &format!("{name}.bitcoin-core.raw.txt"),
            "bitcoin-core/mainnet-ibd",
            bitcoin_core_elapsed_seconds,
            "g14-mainnet-window-00000000",
            binding.benchmark_host_id,
            start_height,
            stop_height,
            binding.start_hash,
            binding.stop_hash,
            binding.bitcoin_core_command_sha256,
            binding.bitcoin_core_config_sha256,
        )?;
    let bitcoin_rs_raw_output_path = bitcoin_rs_raw_output
        .to_str()
        .ok_or("non-UTF-8 bitcoin-rs raw output path")?;
    let bitcoin_core_raw_output_path = bitcoin_core_raw_output
        .to_str()
        .ok_or("non-UTF-8 Bitcoin Core raw output path")?;
    write_text(
        dir,
        name,
        &format!(
            r#"{{
  "schema": "g14-criterion-artifact-v1",
  "benchmark_run_id": "g14-mainnet-window-00000000",
  "benchmark_host_id": "{benchmark_host_id}",
  "ibd_start_height": {start_height},
  "ibd_start_hash": "{start_hash}",
  "ibd_stop_height": {stop_height},
  "ibd_stop_hash": "{stop_hash}",
  "bitcoin_rs_command_sha256": "{bitcoin_rs_command_sha256}",
  "bitcoin_core_command_sha256": "{bitcoin_core_command_sha256}",
  "bitcoin_rs_config_sha256": "{bitcoin_rs_config_sha256}",
  "bitcoin_core_config_sha256": "{bitcoin_core_config_sha256}",
  "benchmarks": [
    {{"benchmark_id": "bitcoin-rs/mainnet-ibd", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": {bitcoin_rs_elapsed_seconds}, "raw_output_path": "{bitcoin_rs_raw_output_path}", "raw_output_sha256": "{bitcoin_rs_raw_output_sha256}"}},
    {{"benchmark_id": "bitcoin-core/mainnet-ibd", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": {bitcoin_core_elapsed_seconds}, "raw_output_path": "{bitcoin_core_raw_output_path}", "raw_output_sha256": "{bitcoin_core_raw_output_sha256}"}}
  ]
}}
"#,
            benchmark_host_id = binding.benchmark_host_id,
            start_hash = binding.start_hash,
            stop_hash = binding.stop_hash,
            bitcoin_rs_command_sha256 = binding.bitcoin_rs_command_sha256,
            bitcoin_core_command_sha256 = binding.bitcoin_core_command_sha256,
            bitcoin_rs_config_sha256 = binding.bitcoin_rs_config_sha256,
            bitcoin_core_config_sha256 = binding.bitcoin_core_config_sha256,
            bitcoin_rs_raw_output_path = bitcoin_rs_raw_output_path,
            bitcoin_core_raw_output_path = bitcoin_core_raw_output_path,
            bitcoin_rs_raw_output_sha256 = bitcoin_rs_raw_output_sha256,
            bitcoin_core_raw_output_sha256 = bitcoin_core_raw_output_sha256,
        ),
    )
}

fn electrum_rss_measurement_json(
    dir: &Path,
    name: &str,
    schema: &str,
    measurement_kind: &str,
    tip_height: u32,
    tip_hash: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_text(
        dir,
        name,
        &format!(
            r#"{{
  "schema": "{schema}",
  "measurement_kind": "{measurement_kind}",
  "method": "blockchain.scripthash.get_history",
  "electrum_host": "127.0.0.1",
  "electrum_port": 50001,
  "electrum_tip_height": {tip_height},
  "electrum_tip_hash": "{tip_hash}",
  "electrum_sample_size": 10000,
  "electrum_sample_seed": "g14-test",
  "electrum_non_empty_history_count": 10000,
  "electrum_scripthash_corpus": "/tmp/g14-scripthashes.txt",
  "electrum_scripthash_corpus_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "electrum_get_history_p50_ms": 10.0,
  "electrum_get_history_p95_ms": 20.0,
  "electrum_get_history_p99_ms": 25.0,
  "electrum_get_history_min_ms": 1.0,
  "electrum_get_history_max_ms": 30.0,
  "electrum_measurement_elapsed_seconds": 60.0,
  "rss_bytes": 1024,
  "rss_final_bytes": 900,
  "rss_pid": 4242,
  "rss_pid_argv0_basename": "bitcoin-rs",
  "rss_pid_exe_basename": "bitcoin-rs",
  "rss_source": "/proc/4242/status VmRSS"
}}"#,
        ),
    )
}

fn evidence_json_with_artifact_command_hash(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
    artifact_bitcoin_rs_command_sha256: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let start_hash = format!("{start_height:064x}");
    let stop_hash = format!("{stop_height:064x}");
    evidence_json_with_artifact_binding(
        dir,
        "criterion-wrong-command.json",
        start_height,
        stop_height,
        CriterionArtifactBinding {
            benchmark_host_id: BENCHMARK_HOST_ID,
            start_hash: &start_hash,
            stop_hash: &stop_hash,
            bitcoin_rs_command_sha256: artifact_bitcoin_rs_command_sha256,
            bitcoin_core_command_sha256: DIRECT_BITCOIN_CORE_COMMAND_SHA256,
            bitcoin_rs_config_sha256: DIRECT_BITCOIN_RS_CONFIG_SHA256,
            bitcoin_core_config_sha256: DIRECT_BITCOIN_CORE_CONFIG_SHA256,
        },
    )
}

fn evidence_json_with_artifact_host_id(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
    artifact_benchmark_host_id: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let start_hash = format!("{start_height:064x}");
    let stop_hash = format!("{stop_height:064x}");
    evidence_json_with_artifact_binding(
        dir,
        "criterion-wrong-host.json",
        start_height,
        stop_height,
        CriterionArtifactBinding {
            benchmark_host_id: artifact_benchmark_host_id,
            start_hash: &start_hash,
            stop_hash: &stop_hash,
            bitcoin_rs_command_sha256: DIRECT_BITCOIN_RS_COMMAND_SHA256,
            bitcoin_core_command_sha256: DIRECT_BITCOIN_CORE_COMMAND_SHA256,
            bitcoin_rs_config_sha256: DIRECT_BITCOIN_RS_CONFIG_SHA256,
            bitcoin_core_config_sha256: DIRECT_BITCOIN_CORE_CONFIG_SHA256,
        },
    )
}

fn evidence_json_with_artifact_binding(
    dir: &Path,
    artifact_name: &str,
    start_height: u32,
    stop_height: u32,
    binding: CriterionArtifactBinding<'_>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14.json");
    let artifact = criterion_artifact_json_with_window_and_hashes(
        dir,
        artifact_name,
        "1.25",
        "2.50",
        start_height,
        stop_height,
        binding,
    )?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": {start_height},
  "ibd_stop_height": {stop_height},
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": 1.25,
  "bitcoin_core_elapsed_seconds": 2.50,
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{}",
  "storage_backend": "fjall",
  "indexes": "all",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
            current_head()?,
        ),
    )?;
    Ok(path)
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("sha256sum").arg(path).output()?;
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    let digest = stdout
        .split_whitespace()
        .next()
        .ok_or("sha256sum did not print a digest")?;
    Ok(digest.to_owned())
}

fn sha256_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        digest.push(char::from(HEX[usize::from(byte >> 4)]));
        digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    digest
}

fn current_head() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;
    assert_success(&output);
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
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

fn fake_criterion_command(
    dir: &Path,
    name: &str,
    benchmark_id: &str,
    elapsed_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            r"#!/usr/bin/env python3
print({raw_output:?}, end='')
",
            raw_output = criterion_raw_output_without_proof(benchmark_id, elapsed_seconds),
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_failing_command(dir: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(
        &path,
        r"#!/usr/bin/env python3
raise SystemExit(7)
",
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_bitcoind_command(
    dir: &Path,
    name: &str,
    stop_file: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import pathlib
import time

stop_file = pathlib.Path({stop_file:?})
deadline = time.monotonic() + 10.0
while not stop_file.exists():
    if time.monotonic() >= deadline:
        raise SystemExit("fake bitcoind stop timeout")
    time.sleep(0.01)
"#,
            stop_file = stop_file.display().to_string()
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_mainnet_prefix_replay_command(
    dir: &Path,
    name: &str,
    elapsed_seconds: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fake_mainnet_prefix_replay_command_with_window(
        dir,
        name,
        elapsed_seconds,
        0,
        10,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000a",
    )
}

fn fake_mainnet_prefix_replay_command_with_window(
    dir: &Path,
    name: &str,
    elapsed_seconds: &str,
    start_height: u32,
    stop_height: u32,
    start_hash: &str,
    stop_hash: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fake_mainnet_prefix_replay_command_with_body(
        dir,
        name,
        &format!(
            r#"{{
  "schema": "mainnet-prefix-replay-v1",
  "measurement_target": "mainnet-prefix-replay",
  "start_height": {start_height},
  "start_hash": "{start_hash}",
  "stop_height": {stop_height},
  "stop_hash": "{stop_hash}",
  "block_count": {},
  "elapsed_seconds": {elapsed_seconds},
  "blocks_per_second": 8.8
}}"#,
            stop_height - start_height + 1
        ),
    )
}

fn fake_mainnet_prefix_replay_command_with_body(
    dir: &Path,
    name: &str,
    body: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import pathlib
import sys

args = sys.argv[1:]
try:
    output_index = args.index("--output")
except ValueError:
    raise SystemExit("--output is required")
pathlib.Path(args[output_index + 1]).write_text({body:?} + "\n", encoding="utf-8")
"#
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
    evidence_json_with_binding_fields(
        dir,
        start_height,
        stop_height,
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
        &current_head()?,
        "fjall",
        "all",
    )
}

fn evidence_json_with_artifact_window(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
    artifact_start_hash: &str,
    artifact_stop_hash: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14.json");
    let artifact = criterion_artifact_json_with_window_and_hashes(
        dir,
        "criterion-direct.json",
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
        start_height,
        stop_height,
        CriterionArtifactBinding {
            benchmark_host_id: BENCHMARK_HOST_ID,
            start_hash: artifact_start_hash,
            stop_hash: artifact_stop_hash,
            bitcoin_rs_command_sha256: DIRECT_BITCOIN_RS_COMMAND_SHA256,
            bitcoin_core_command_sha256: DIRECT_BITCOIN_CORE_COMMAND_SHA256,
            bitcoin_rs_config_sha256: DIRECT_BITCOIN_RS_CONFIG_SHA256,
            bitcoin_core_config_sha256: DIRECT_BITCOIN_CORE_CONFIG_SHA256,
        },
    )?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": {start_height},
  "ibd_stop_height": {stop_height},
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": {bitcoin_rs_elapsed_seconds},
  "bitcoin_core_elapsed_seconds": {bitcoin_core_elapsed_seconds},
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{}",
  "storage_backend": "fjall",
  "indexes": "all",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
            current_head()?,
        ),
    )?;
    Ok(path)
}

fn evidence_json_with_mixed_benchmark_run_ids(
    dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14-mixed-run-id.json");
    let artifact = criterion_artifact_json_with_mixed_benchmark_run_ids(dir)?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": 0,
  "ibd_stop_height": 10,
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": 1.25,
  "bitcoin_core_elapsed_seconds": 2.50,
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{}",
  "storage_backend": "fjall",
  "indexes": "all",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
            current_head()?,
        ),
    )?;
    Ok(path)
}

fn criterion_artifact_json_with_mixed_benchmark_run_ids(
    dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let (bitcoin_rs_raw_output, bitcoin_rs_raw_output_sha256) = write_criterion_raw_output(
        dir,
        "criterion-mixed-run-id.bitcoin-rs.raw.txt",
        "bitcoin-rs/mainnet-ibd",
        "1.25",
    )?;
    let (bitcoin_core_raw_output, bitcoin_core_raw_output_sha256) = write_criterion_raw_output(
        dir,
        "criterion-mixed-run-id.bitcoin-core.raw.txt",
        "bitcoin-core/mainnet-ibd",
        "2.50",
    )?;
    let bitcoin_rs_raw_output_path = bitcoin_rs_raw_output
        .to_str()
        .ok_or("non-UTF-8 bitcoin-rs raw output path")?;
    let bitcoin_core_raw_output_path = bitcoin_core_raw_output
        .to_str()
        .ok_or("non-UTF-8 Bitcoin Core raw output path")?;
    write_text(
        dir,
        "criterion-mixed-run-id.json",
        &format!(
            r#"{{
  "schema": "g14-criterion-artifact-v1",
  "benchmark_run_id": "g14-mainnet-window-00000000",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "ibd_start_height": 0,
  "ibd_start_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ibd_stop_height": 10,
  "ibd_stop_hash": "000000000000000000000000000000000000000000000000000000000000000a",
  "bitcoin_rs_command_sha256": "{DIRECT_BITCOIN_RS_COMMAND_SHA256}",
  "bitcoin_core_command_sha256": "{DIRECT_BITCOIN_CORE_COMMAND_SHA256}",
  "bitcoin_rs_config_sha256": "{DIRECT_BITCOIN_RS_CONFIG_SHA256}",
  "bitcoin_core_config_sha256": "{DIRECT_BITCOIN_CORE_CONFIG_SHA256}",
  "benchmarks": [
    {{"benchmark_id": "bitcoin-rs/mainnet-ibd", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": 1.25, "raw_output_path": "{bitcoin_rs_raw_output_path}", "raw_output_sha256": "{bitcoin_rs_raw_output_sha256}"}},
    {{"benchmark_id": "bitcoin-core/mainnet-ibd", "benchmark_run_id": "g14-mainnet-window-11111111", "elapsed_seconds": 2.50, "raw_output_path": "{bitcoin_core_raw_output_path}", "raw_output_sha256": "{bitcoin_core_raw_output_sha256}"}}
  ]
}}
"#
        ),
    )
}

fn evidence_json_with_missing_raw_output_sha256(
    dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14-missing-raw-output-hash.json");
    let (bitcoin_rs_raw_output, _) = write_criterion_raw_output(
        dir,
        "criterion-missing-raw-output-hash.bitcoin-rs.raw.txt",
        "bitcoin-rs/mainnet-ibd",
        "1.25",
    )?;
    let (bitcoin_core_raw_output, bitcoin_core_raw_output_sha256) = write_criterion_raw_output(
        dir,
        "criterion-missing-raw-output-hash.bitcoin-core.raw.txt",
        "bitcoin-core/mainnet-ibd",
        "2.50",
    )?;
    let bitcoin_rs_raw_output_path = bitcoin_rs_raw_output
        .to_str()
        .ok_or("non-UTF-8 bitcoin-rs raw output path")?;
    let bitcoin_core_raw_output_path = bitcoin_core_raw_output
        .to_str()
        .ok_or("non-UTF-8 Bitcoin Core raw output path")?;
    let artifact = write_text(
        dir,
        "criterion-missing-raw-output-hash.json",
        &format!(
            r#"{{
  "schema": "g14-criterion-artifact-v1",
  "benchmark_run_id": "g14-mainnet-window-00000000",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "ibd_start_height": 0,
  "ibd_start_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ibd_stop_height": 10,
  "ibd_stop_hash": "000000000000000000000000000000000000000000000000000000000000000a",
  "bitcoin_rs_command_sha256": "{DIRECT_BITCOIN_RS_COMMAND_SHA256}",
  "bitcoin_core_command_sha256": "{DIRECT_BITCOIN_CORE_COMMAND_SHA256}",
  "bitcoin_rs_config_sha256": "{DIRECT_BITCOIN_RS_CONFIG_SHA256}",
  "bitcoin_core_config_sha256": "{DIRECT_BITCOIN_CORE_CONFIG_SHA256}",
  "benchmarks": [
    {{"benchmark_id": "bitcoin-rs/mainnet-ibd", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": 1.25, "raw_output_path": "{bitcoin_rs_raw_output_path}"}},
    {{"benchmark_id": "bitcoin-core/mainnet-ibd", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": 2.50, "raw_output_path": "{bitcoin_core_raw_output_path}", "raw_output_sha256": "{bitcoin_core_raw_output_sha256}"}}
  ]
}}
"#
        ),
    )?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": 0,
  "ibd_stop_height": 10,
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": 1.25,
  "bitcoin_core_elapsed_seconds": 2.50,
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{}",
  "storage_backend": "fjall",
  "indexes": "all",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
            current_head()?,
        ),
    )?;
    Ok(path)
}

fn evidence_json_with_missing_raw_output_path(
    dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let artifact = criterion_artifact_json(
        dir,
        "criterion-missing-raw-output-path.json",
        "1.25",
        "2.50",
    )?;
    let bitcoin_rs_raw_output_path = dir
        .join("criterion-missing-raw-output-path.json.bitcoin-rs.raw.txt")
        .to_str()
        .ok_or("non-UTF-8 bitcoin-rs raw output path")?
        .to_owned();
    let artifact_json = fs::read_to_string(&artifact)?;
    let artifact_json = artifact_json.replace(
        &format!(r#""raw_output_path": "{bitcoin_rs_raw_output_path}", "#),
        "",
    );
    fs::write(&artifact, artifact_json)?;
    evidence_json_for_artifact(dir, "g14-missing-raw-output-path.json", &artifact)
}

fn evidence_json_with_tampered_raw_output(
    dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let artifact =
        criterion_artifact_json(dir, "criterion-tampered-raw-output.json", "1.25", "2.50")?;
    let bitcoin_rs_raw_output = dir.join("criterion-tampered-raw-output.json.bitcoin-rs.raw.txt");
    fs::write(
        bitcoin_rs_raw_output,
        criterion_raw_output("bitcoin-rs/mainnet-ibd", "9.00"),
    )?;
    evidence_json_for_artifact(dir, "g14-tampered-raw-output.json", &artifact)
}

fn evidence_json_for_artifact(
    dir: &Path,
    name: &str,
    artifact: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(artifact)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": 0,
  "ibd_stop_height": 10,
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": 1.25,
  "bitcoin_core_elapsed_seconds": 2.50,
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{}",
  "storage_backend": "fjall",
  "indexes": "all",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
            current_head()?,
        ),
    )?;
    Ok(path)
}

fn evidence_json_with_binding_fields(
    dir: &Path,
    start_height: u32,
    stop_height: u32,
    bitcoin_rs_elapsed_seconds: &str,
    bitcoin_core_elapsed_seconds: &str,
    bitcoin_rs_commit: &str,
    storage_backend: &str,
    indexes: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14.json");
    let stop_hash = format!("{stop_height:064x}");
    let artifact = criterion_artifact_json(
        dir,
        "criterion-direct.json",
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
    )?;
    let measurement = electrum_rss_measurement_json(
        dir,
        "electrum-rss-direct.json",
        "g14-electrum-rss-measurement-v1",
        "evidence",
        stop_height,
        &stop_hash,
    )?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
    let measurement_path = measurement.to_str().ok_or("non-UTF-8 measurement path")?;
    let measurement_sha256 = sha256_file(&measurement)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": {start_height},
  "ibd_stop_height": {stop_height},
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "bitcoin-rs/mainnet-ibd",
  "criterion_bitcoin_core_benchmark_id": "bitcoin-core/mainnet-ibd",
  "bitcoin_rs_elapsed_seconds": {bitcoin_rs_elapsed_seconds},
  "bitcoin_core_elapsed_seconds": {bitcoin_core_elapsed_seconds},
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{bitcoin_rs_commit}",
  "storage_backend": "{storage_backend}",
  "indexes": "{indexes}",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024,
  "electrum_rss_measurement_path": "{measurement_path}",
  "electrum_rss_measurement_sha256": "{measurement_sha256}",
  "electrum_rss_measurement_schema": "g14-electrum-rss-measurement-v1",
  "electrum_rss_measurement_tip_height": {stop_height},
  "electrum_rss_measurement_tip_hash": "{stop_hash}",
  "electrum_rss_measurement_sample_size": 10000,
  "electrum_rss_measurement_non_empty_history_count": 10000,
  "electrum_scripthash_corpus": "/tmp/g14-scripthashes.txt",
  "electrum_scripthash_corpus_sha256": "1111111111111111111111111111111111111111111111111111111111111111"
}}"#,
        ),
    )?;
    Ok(path)
}

fn evidence_json_with_benchmark_ids(
    dir: &Path,
    bitcoin_rs_benchmark_id: &str,
    bitcoin_core_benchmark_id: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("g14-renamed-benchmark.json");
    let (bitcoin_rs_raw_output, bitcoin_rs_raw_output_sha256) = write_criterion_raw_output(
        dir,
        "criterion-renamed-benchmark.bitcoin-rs.raw.txt",
        bitcoin_rs_benchmark_id,
        "1.25",
    )?;
    let (bitcoin_core_raw_output, bitcoin_core_raw_output_sha256) = write_criterion_raw_output(
        dir,
        "criterion-renamed-benchmark.bitcoin-core.raw.txt",
        bitcoin_core_benchmark_id,
        "2.50",
    )?;
    let bitcoin_rs_raw_output_path = bitcoin_rs_raw_output
        .to_str()
        .ok_or("non-UTF-8 bitcoin-rs raw output path")?;
    let bitcoin_core_raw_output_path = bitcoin_core_raw_output
        .to_str()
        .ok_or("non-UTF-8 Bitcoin Core raw output path")?;
    let artifact = write_text(
        dir,
        "criterion-renamed-benchmark.json",
        &format!(
            r#"{{
  "schema": "g14-criterion-artifact-v1",
  "benchmark_run_id": "g14-mainnet-window-00000000",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "ibd_start_height": 0,
  "ibd_start_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ibd_stop_height": 10,
  "ibd_stop_hash": "000000000000000000000000000000000000000000000000000000000000000a",
  "bitcoin_rs_command_sha256": "{DIRECT_BITCOIN_RS_COMMAND_SHA256}",
  "bitcoin_core_command_sha256": "{DIRECT_BITCOIN_CORE_COMMAND_SHA256}",
  "bitcoin_rs_config_sha256": "{DIRECT_BITCOIN_RS_CONFIG_SHA256}",
  "bitcoin_core_config_sha256": "{DIRECT_BITCOIN_CORE_CONFIG_SHA256}",
  "benchmarks": [
    {{"benchmark_id": "{bitcoin_rs_benchmark_id}", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": 1.25, "raw_output_path": "{bitcoin_rs_raw_output_path}", "raw_output_sha256": "{bitcoin_rs_raw_output_sha256}"}},
    {{"benchmark_id": "{bitcoin_core_benchmark_id}", "benchmark_run_id": "g14-mainnet-window-00000000", "elapsed_seconds": 2.50, "raw_output_path": "{bitcoin_core_raw_output_path}", "raw_output_sha256": "{bitcoin_core_raw_output_sha256}"}}
  ]
}}
"#
        ),
    )?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
    fs::write(
        &path,
        format!(
            r#"{{
  "ibd_start_height": 0,
  "ibd_stop_height": 10,
  "bench_tool": "criterion",
  "elapsed_seconds_source": "criterion",
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
  "criterion_bitcoin_rs_benchmark_id": "{bitcoin_rs_benchmark_id}",
  "criterion_bitcoin_core_benchmark_id": "{bitcoin_core_benchmark_id}",
  "bitcoin_rs_elapsed_seconds": 1.25,
  "bitcoin_core_elapsed_seconds": 2.50,
  "bitcoin_core_version": "v27.0.0",
  "bitcoin_rs_commit": "{}",
  "storage_backend": "fjall",
  "indexes": "all",
  "bitcoin_core_commit": "1111111111111111111111111111111111111111",
  "bitcoin_rs_command": "target/release/bitcoin-rs --network mainnet",
  "bitcoin_core_command": "bitcoind -chain=main",
  "bitcoin_rs_config": "storage_backend=fjall\nindexes=all",
  "bitcoin_core_config": "dbcache=450\ncoinstatsindex=1",
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
            current_head()?,
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
    let artifact = criterion_artifact_json(
        dir,
        "criterion-offline.json",
        bitcoin_rs_elapsed_seconds,
        bitcoin_core_elapsed_seconds,
    )?;
    let artifact_path = artifact.to_str().ok_or("non-UTF-8 artifact path")?;
    let artifact_sha256 = sha256_file(&artifact)?;
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
  "criterion_artifact_schema": "g14-criterion-artifact-v1",
  "benchmark_host_id": "{BENCHMARK_HOST_ID}",
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
  "benchmark_artifact_path": "{artifact_path}",
  "benchmark_artifact_sha256": "{artifact_sha256}",
  "utxo_commit_p95_ms": 12.5,
  "electrum_get_history_p95_ms": 20.0,
  "rss_bytes": 1024
}}"#,
        ),
    )?;
    Ok(path)
}

#[derive(Clone, Copy)]
enum FakeBitcoinRsRpcMode {
    Mainnet,
    RpcStartupTimeout,
}

fn fake_bitcoin_rs_daemon_command(
    dir: &Path,
    name: &str,
    rpc_port: u16,
    rpc_user: &str,
    rpc_password: &str,
    mode: FakeBitcoinRsRpcMode,
    stop_file: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    let state_file = dir.join(format!("{name}.chaininfo-calls"));
    let chain = "main";
    let initial_blocks = 0;
    let target_blocks = 10;
    let rpc_startup_timeout = matches!(mode, FakeBitcoinRsRpcMode::RpcStartupTimeout);
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import base64
import json
import pathlib
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = {rpc_port}
RPC_USER = {rpc_user:?}
RPC_PASSWORD = {rpc_password:?}
CHAIN = {chain:?}
INITIAL_BLOCKS = {initial_blocks}
TARGET_BLOCKS = {target_blocks}
RPC_STARTUP_TIMEOUT = {rpc_startup_timeout}
STOP_FILE = pathlib.Path({stop_file:?})
STATE_FILE = pathlib.Path({state_file:?})


def authorized(header: str) -> bool:
    prefix = "Basic "
    if not header.startswith(prefix):
        return False
    try:
        decoded = base64.b64decode(header[len(prefix):]).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    user, sep, password = decoded.partition(":")
    return sep == ":" and user == RPC_USER and password == RPC_PASSWORD


class RpcHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        if not authorized(self.headers.get("Authorization", "")):
            self.send_response(401)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        method = body.get("method")
        params = body.get("params", [])
        if method == "getblockchaininfo":
            call_count = int(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else 0
            STATE_FILE.write_text(str(call_count + 1), encoding="utf-8")
            blocks = INITIAL_BLOCKS if call_count <= 0 else TARGET_BLOCKS
            result = {{"chain": CHAIN, "blocks": blocks, "headers": TARGET_BLOCKS}}
        elif method == "getblockhash":
            height = int(params[0])
            result = f"{{height:064x}}"
        else:
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps({{"jsonrpc": "2.0", "id": body.get("id", 1), "result": result}})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))


def shutdown_handler(signum, frame):
    STOP_FILE.write_text("stop\n", encoding="utf-8")
    raise SystemExit(0)


signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

if RPC_STARTUP_TIMEOUT:
    while True:
        time.sleep(1)

server = HTTPServer(("127.0.0.1", PORT), RpcHandler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
while True:
    time.sleep(1)
"#,
            stop_file = stop_file.display().to_string(),
            state_file = state_file.display().to_string(),
            rpc_startup_timeout = if rpc_startup_timeout { "True" } else { "False" },
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

#[derive(Clone, Copy)]
enum FakeBitcoinCliMode {
    Mainnet,
    MalformedHash,
    WrongChain,
    ShortBlocks,
    ShortHeaders,
    AlreadySynced,
    RpcWarmup,
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
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => r#"f"{height:064x}""#,
    };
    let chain = match mode {
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => "main",
        FakeBitcoinCliMode::WrongChain => "regtest",
    };
    let blocks = match mode {
        FakeBitcoinCliMode::ShortBlocks => 9,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => 10,
    };
    let headers = match mode {
        FakeBitcoinCliMode::ShortHeaders => 9,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => 10,
    };
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import json
import sys

args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

if len(args) == 1 and args[0] == "getblockchaininfo":
    print(json.dumps({{"chain": "{chain}", "blocks": {blocks}, "headers": {headers}}}))
    raise SystemExit(0)

if len(args) != 2 or args[0] != "getblockhash":
    raise SystemExit(f"unexpected arguments: {{sys.argv[1:]!r}}")

height = int(args[1])
print({hash_expr})
"#,
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_measured_bitcoin_core_cli(
    dir: &Path,
    name: &str,
    mode: FakeBitcoinCliMode,
    stop_file: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    let state_file = dir.join(format!("{name}.chaininfo-calls"));
    let hash_expr = match mode {
        FakeBitcoinCliMode::MalformedHash => r#""not-a-hash""#,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => r#"f"{height:064x}""#,
    };
    let chain = match mode {
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => "main",
        FakeBitcoinCliMode::WrongChain => "regtest",
    };
    let initial_blocks = match mode {
        FakeBitcoinCliMode::AlreadySynced => 10,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::RpcWarmup => 0,
    };
    let initial_headers = match mode {
        FakeBitcoinCliMode::AlreadySynced => 10,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::RpcWarmup => 0,
    };
    let blocks = match mode {
        FakeBitcoinCliMode::ShortBlocks => 9,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortHeaders
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => 10,
    };
    let headers = match mode {
        FakeBitcoinCliMode::ShortHeaders => 9,
        FakeBitcoinCliMode::Mainnet
        | FakeBitcoinCliMode::MalformedHash
        | FakeBitcoinCliMode::WrongChain
        | FakeBitcoinCliMode::ShortBlocks
        | FakeBitcoinCliMode::AlreadySynced
        | FakeBitcoinCliMode::RpcWarmup => 10,
    };
    let rpc_warmup = if matches!(mode, FakeBitcoinCliMode::RpcWarmup) {
        "True"
    } else {
        "False"
    };
    fs::write(
        &path,
        format!(
            r#"#!/usr/bin/env python3
import json
import pathlib
import sys

args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

if len(args) == 1 and args[0] == "stop":
    pathlib.Path({stop_file:?}).write_text("stop\n", encoding="utf-8")
    print("Bitcoin Core stopping")
    raise SystemExit(0)

if len(args) == 1 and args[0] == "getblockchaininfo":
    state_file = pathlib.Path({state_file:?})
    call_count = int(state_file.read_text(encoding="utf-8")) if state_file.exists() else 0
    if {rpc_warmup} and not state_file.exists():
        state_file.write_text("-1", encoding="utf-8")
        raise SystemExit("RPC server not ready")
    state_file.write_text(str(call_count + 1), encoding="utf-8")
    blocks = {initial_blocks} if call_count <= 0 else {blocks}
    headers = {initial_headers} if call_count <= 0 else {headers}
    print(json.dumps({{"chain": "{chain}", "blocks": blocks, "headers": headers}}))
    raise SystemExit(0)

if len(args) != 2 or args[0] != "getblockhash":
    raise SystemExit(f"unexpected arguments: {{sys.argv[1:]!r}}")

height = int(args[1])
print({hash_expr})
"#,
            stop_file = stop_file.display().to_string(),
            state_file = state_file.display().to_string()
        ),
    )?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)?;
    Ok(path)
}

fn fake_electrum_server(
    response_count: usize,
) -> Result<FakeElectrumServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = thread::spawn(move || -> std::io::Result<()> {
        let (stream, _addr) = listener.accept()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        let mut line = String::new();
        for request_id in 1..=response_count {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            writeln!(writer, r#"{{"id":{request_id},"result":[]}}"#)?;
            writer.flush()?;
        }
        Ok(())
    });
    Ok((handle, port))
}

fn fake_electrum_history_server(
    response_count: usize,
) -> Result<FakeElectrumRecordingServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = thread::spawn(move || -> std::io::Result<Vec<String>> {
        let (stream, _addr) = listener.accept()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        let mut line = String::new();
        let mut requested = Vec::with_capacity(response_count);
        for request_id in 1..=response_count {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let request: serde_json::Value = serde_json::from_str(line.trim_end())
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let scripthash = request
                .get("params")
                .and_then(serde_json::Value::as_array)
                .and_then(|params| params.first())
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "request missing scripthash param",
                    )
                })?;
            requested.push(scripthash.to_owned());
            writeln!(
                writer,
                r#"{{"id":{request_id},"result":[{{"height":1,"tx_hash":"0000000000000000000000000000000000000000000000000000000000000001"}}]}}"#
            )?;
            writer.flush()?;
        }
        Ok(requested)
    });
    Ok((handle, port))
}

fn fake_bitcoin_rs_process() -> Result<FakeBitcoinRsProcess, Box<dyn std::error::Error>> {
    let child = Command::new("bash")
        .args(["-c", "exec -a bitcoin-rs sleep 30"])
        .spawn()?;
    let cmdline = PathBuf::from(format!("/proc/{}/cmdline", child.id()));
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if fs::read(&cmdline).is_ok_and(|contents| {
            contents
                .split(|byte| *byte == 0)
                .next()
                .is_some_and(|argv0| argv0 == b"bitcoin-rs")
        }) {
            return Ok(FakeBitcoinRsProcess { child });
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(FakeBitcoinRsProcess { child })
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
