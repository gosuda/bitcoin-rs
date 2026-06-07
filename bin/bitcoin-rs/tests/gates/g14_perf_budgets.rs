//! G14 — Performance budgets.
//! **G14 — Performance budgets.**
//! - Initial block sync throughput is faster than Bitcoin Core's blocks-per-second on identical mainnet IBD (measured via `criterion`).
//! - UTXO commit p95 ≤ 50 ms per 4 MiB block.
//! - Electrum `scripthash.get_history` p95 ≤ 30 ms over a 10 000-call random sample at tip.
//! - RSS ≤ 16 GiB at mainnet tip with fjall default + all indexes enabled.
//!
//! This ignored gate does not run the live mainnet benchmarks itself. It verifies
//! externally collected evidence and fails closed when the evidence contract is
//! missing or malformed.

use std::{env, fs::File, io::Read, path::Path, process::Command};

use serde_json::Value;
use sha2::{Digest, Sha256};

const MIN_INITIAL_SYNC_RATIO_VS_BITCOIN_CORE: f64 = 1.0;
const MAX_UTXO_COMMIT_P95_MS: f64 = 50.0;
const MAX_ELECTRUM_GET_HISTORY_P95_MS: f64 = 30.0;
const MAX_RSS_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FOUR_MIB_BYTES: u64 = 4 * 1024 * 1024;
const EXPECTED_ELECTRUM_SAMPLE_SIZE: u64 = 10_000;
const ELECTRUM_RSS_MEASUREMENT_SCHEMA: &str = "g14-electrum-rss-measurement-v1";
const ELECTRUM_HISTORY_METHOD: &str = "blockchain.scripthash.get_history";

const EVIDENCE_HELP: &str = "required G14 evidence env: \
G14_COMMIT_SHA=<current git HEAD as 40 lowercase hex>, \
G14_MEASUREMENT_TARGET=mainnet-ibd, \
G14_STORAGE_BACKEND=fjall, \
G14_INDEXES=all, \
G14_REFERENCE_IMPL=bitcoin-core, \
G14_BENCH_TOOL=criterion, \
G14_BLOCK_SIZE_BYTES=4194304, \
G14_ELECTRUM_SAMPLE_SIZE=10000, \
G14_IBD_START_HEIGHT, \
G14_IBD_START_HASH=<64 lowercase hex>, \
G14_IBD_STOP_HEIGHT, \
G14_IBD_STOP_HASH=<64 lowercase hex>, \
G14_BITCOIN_RS_IBD_BLOCKS, \
G14_BITCOIN_CORE_IBD_BLOCKS, \
G14_BITCOIN_RS_ELAPSED_SECONDS, \
G14_BITCOIN_CORE_ELAPSED_SECONDS, \
G14_BITCOIN_RS_CRITERION_BENCHMARK_ID, \
G14_BITCOIN_CORE_CRITERION_BENCHMARK_ID, \
G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH, \
G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH, \
G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_SHA256=<64 lowercase hex>, \
G14_BENCHMARK_RUN_ID, \
G14_BENCHMARK_HOST_ID, \
G14_BITCOIN_CORE_VERSION, \
G14_BITCOIN_CORE_COMMIT=<40 lowercase hex>, \
G14_BITCOIN_RS_COMMAND_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_COMMAND_SHA256=<64 lowercase hex>, \
G14_BITCOIN_RS_CONFIG_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_CONFIG_SHA256=<64 lowercase hex>, \
G14_BENCHMARK_ARTIFACT_SHA256=<64 lowercase hex>, \
G14_UTXO_COMMIT_P95_MS, \
G14_ELECTRUM_GET_HISTORY_P95_MS, \
G14_RSS_BYTES, \
G14_ELECTRUM_RSS_MEASUREMENT_PATH, \
G14_ELECTRUM_RSS_MEASUREMENT_SHA256=<64 lowercase hex>, \
G14_ELECTRUM_RSS_MEASUREMENT_SCHEMA=g14-electrum-rss-measurement-v1, \
G14_ELECTRUM_RSS_MEASUREMENT_SAMPLE_SIZE=10000, \
G14_ELECTRUM_RSS_MEASUREMENT_NON_EMPTY_HISTORY_COUNT=10000, \
G14_ELECTRUM_RSS_MEASUREMENT_TIP_HEIGHT=G14_IBD_STOP_HEIGHT, \
G14_ELECTRUM_RSS_MEASUREMENT_TIP_HASH=G14_IBD_STOP_HASH, \
G14_ELECTRUM_SCRIPTHASH_CORPUS, \
G14_ELECTRUM_SCRIPTHASH_CORPUS_SHA256=<64 lowercase hex>";

struct G14Evidence {
    commit_sha: String,
    start_height: u64,
    start_hash: String,
    stop_height: u64,
    stop_hash: String,
    bitcoin_rs_ibd_blocks: u64,
    bitcoin_core_ibd_blocks: u64,
    bitcoin_rs_elapsed_seconds: f64,
    bitcoin_core_elapsed_seconds: f64,
    bitcoin_rs_criterion_benchmark_id: String,
    bitcoin_core_criterion_benchmark_id: String,
    criterion_raw_output: CriterionRawOutputCustody,
    benchmark_run_id: String,
    benchmark_host_id: String,
    bitcoin_core_version: String,
    bitcoin_core_commit: String,
    bitcoin_rs_command_sha256: String,
    bitcoin_core_command_sha256: String,
    bitcoin_rs_config_sha256: String,
    bitcoin_core_config_sha256: String,
    benchmark_artifact_sha256: String,
    initial_sync_bps: f64,
    bitcoin_core_initial_sync_bps: f64,
    utxo_commit_p95_ms: f64,
    electrum_get_history_p95_ms: f64,
    rss_bytes: u64,
    electrum_rss_measurement_path: String,
    electrum_rss_measurement_sha256: String,
    electrum_scripthash_corpus: String,
    electrum_scripthash_corpus_sha256: String,
}

struct CriterionRawOutputCustody {
    bitcoin_rs_path: String,
    bitcoin_rs_sha256: String,
    bitcoin_core_path: String,
    bitcoin_core_sha256: String,
}

/// Gate G14 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g14_perf_budgets -- --ignored --nocapture`
/// with externally collected mainnet-tip evidence described in this file.
#[test]
#[ignore = "requires externally collected G14 mainnet performance evidence"]
fn performance_budgets() {
    let evidence = G14Evidence::from_env();
    evidence.assert_budgets();
    evidence.report();
}

impl G14Evidence {
    fn from_env() -> Self {
        let commit_sha = required_commit_sha();
        require_literal("G14_MEASUREMENT_TARGET", "mainnet-ibd");
        require_literal("G14_STORAGE_BACKEND", "fjall");
        require_literal("G14_INDEXES", "all");
        require_literal("G14_REFERENCE_IMPL", "bitcoin-core");
        require_literal("G14_BENCH_TOOL", "criterion");
        require_exact_u64("G14_BLOCK_SIZE_BYTES", FOUR_MIB_BYTES);
        require_exact_u64("G14_ELECTRUM_SAMPLE_SIZE", EXPECTED_ELECTRUM_SAMPLE_SIZE);
        let start_height = positive_or_zero_u64("G14_IBD_START_HEIGHT");
        let start_hash = required_hex("G14_IBD_START_HASH", 64);
        let stop_height = positive_or_zero_u64("G14_IBD_STOP_HEIGHT");
        let stop_hash = required_hex("G14_IBD_STOP_HASH", 64);
        let bitcoin_rs_ibd_blocks = positive_u64("G14_BITCOIN_RS_IBD_BLOCKS");
        let bitcoin_core_ibd_blocks = positive_u64("G14_BITCOIN_CORE_IBD_BLOCKS");
        let bitcoin_rs_elapsed_seconds = positive_f64("G14_BITCOIN_RS_ELAPSED_SECONDS");
        let bitcoin_core_elapsed_seconds = positive_f64("G14_BITCOIN_CORE_ELAPSED_SECONDS");
        let bitcoin_rs_criterion_benchmark_id =
            required_env("G14_BITCOIN_RS_CRITERION_BENCHMARK_ID");
        assert_eq!(
            bitcoin_rs_criterion_benchmark_id, "bitcoin-rs/mainnet-ibd",
            "G14_BITCOIN_RS_CRITERION_BENCHMARK_ID must identify bitcoin-rs mainnet IBD"
        );
        let bitcoin_core_criterion_benchmark_id =
            required_env("G14_BITCOIN_CORE_CRITERION_BENCHMARK_ID");
        assert_eq!(
            bitcoin_core_criterion_benchmark_id, "bitcoin-core/mainnet-ibd",
            "G14_BITCOIN_CORE_CRITERION_BENCHMARK_ID must identify Bitcoin Core mainnet IBD"
        );
        let criterion_raw_output = CriterionRawOutputCustody::from_env();
        let benchmark_run_id = required_env("G14_BENCHMARK_RUN_ID");
        let benchmark_host_id = required_env("G14_BENCHMARK_HOST_ID");
        let bitcoin_core_version = required_env("G14_BITCOIN_CORE_VERSION");
        let bitcoin_core_commit = required_hex("G14_BITCOIN_CORE_COMMIT", 40);
        let bitcoin_rs_command_sha256 = required_hex("G14_BITCOIN_RS_COMMAND_SHA256", 64);
        let bitcoin_core_command_sha256 = required_hex("G14_BITCOIN_CORE_COMMAND_SHA256", 64);
        let bitcoin_rs_config_sha256 = required_hex("G14_BITCOIN_RS_CONFIG_SHA256", 64);
        let bitcoin_core_config_sha256 = required_hex("G14_BITCOIN_CORE_CONFIG_SHA256", 64);
        let benchmark_artifact_sha256 = required_hex("G14_BENCHMARK_ARTIFACT_SHA256", 64);
        let electrum_scripthash_corpus = required_env("G14_ELECTRUM_SCRIPTHASH_CORPUS");
        let electrum_scripthash_corpus_sha256 =
            required_hex("G14_ELECTRUM_SCRIPTHASH_CORPUS_SHA256", 64);
        let utxo_commit_p95_ms = positive_f64("G14_UTXO_COMMIT_P95_MS");
        let electrum_get_history_p95_ms = positive_f64("G14_ELECTRUM_GET_HISTORY_P95_MS");
        let rss_bytes = positive_u64("G14_RSS_BYTES");
        let (electrum_rss_measurement_path, electrum_rss_measurement_sha256) =
            verified_electrum_rss_measurement_from_env(
                stop_height,
                &stop_hash,
                electrum_get_history_p95_ms,
                rss_bytes,
                &electrum_scripthash_corpus,
                &electrum_scripthash_corpus_sha256,
            );
        let initial_sync_bps = measured_bps(bitcoin_rs_ibd_blocks, bitcoin_rs_elapsed_seconds);
        let bitcoin_core_initial_sync_bps =
            measured_bps(bitcoin_core_ibd_blocks, bitcoin_core_elapsed_seconds);

        Self {
            commit_sha,
            start_height,
            start_hash,
            stop_height,
            stop_hash,
            bitcoin_rs_ibd_blocks,
            bitcoin_core_ibd_blocks,
            bitcoin_rs_elapsed_seconds,
            bitcoin_core_elapsed_seconds,
            bitcoin_rs_criterion_benchmark_id,
            bitcoin_core_criterion_benchmark_id,
            criterion_raw_output,
            benchmark_run_id,
            benchmark_host_id,
            bitcoin_core_version,
            bitcoin_core_commit,
            bitcoin_rs_command_sha256,
            bitcoin_core_command_sha256,
            bitcoin_rs_config_sha256,
            bitcoin_core_config_sha256,
            benchmark_artifact_sha256,
            initial_sync_bps,
            bitcoin_core_initial_sync_bps,
            utxo_commit_p95_ms,
            electrum_get_history_p95_ms,
            rss_bytes,
            electrum_rss_measurement_path,
            electrum_rss_measurement_sha256,
            electrum_scripthash_corpus,
            electrum_scripthash_corpus_sha256,
        }
    }

    fn assert_budgets(&self) {
        let measured_range = self
            .stop_height
            .checked_sub(self.start_height)
            .and_then(|distance| distance.checked_add(1))
            .unwrap_or_else(|| {
                panic!(
                    "G14 IBD range is invalid: start_height={}, stop_height={}",
                    self.start_height, self.stop_height
                )
            });
        assert_eq!(
            self.bitcoin_rs_ibd_blocks, measured_range,
            "G14 bitcoin-rs block count must match inclusive IBD range"
        );
        assert_eq!(
            self.bitcoin_core_ibd_blocks, measured_range,
            "G14 Bitcoin Core block count must match inclusive IBD range"
        );
        let required_sync_bps =
            self.bitcoin_core_initial_sync_bps * MIN_INITIAL_SYNC_RATIO_VS_BITCOIN_CORE;
        let initial_sync_speedup_vs_bitcoin_core =
            self.initial_sync_bps / self.bitcoin_core_initial_sync_bps;
        assert!(
            self.initial_sync_bps > required_sync_bps,
            "G14 initial sync throughput failed: bitcoin-rs {} blocks/s, Bitcoin Core {} blocks/s, speedup {}x, required faster than {} blocks/s",
            self.initial_sync_bps,
            self.bitcoin_core_initial_sync_bps,
            initial_sync_speedup_vs_bitcoin_core,
            required_sync_bps,
        );
        assert!(
            self.utxo_commit_p95_ms <= MAX_UTXO_COMMIT_P95_MS,
            "G14 UTXO commit p95 failed: {} ms > {} ms",
            self.utxo_commit_p95_ms,
            MAX_UTXO_COMMIT_P95_MS,
        );
        assert!(
            self.electrum_get_history_p95_ms <= MAX_ELECTRUM_GET_HISTORY_P95_MS,
            "G14 Electrum scripthash.get_history p95 failed: {} ms > {} ms",
            self.electrum_get_history_p95_ms,
            MAX_ELECTRUM_GET_HISTORY_P95_MS,
        );
        assert!(
            self.rss_bytes <= MAX_RSS_BYTES,
            "G14 RSS budget failed: {} bytes > {} bytes",
            self.rss_bytes,
            MAX_RSS_BYTES,
        );
    }

    fn report(&self) {
        let commit_sha = &self.commit_sha;
        let start_height = self.start_height;
        let start_hash = &self.start_hash;
        let stop_height = self.stop_height;
        let stop_hash = &self.stop_hash;
        let bitcoin_rs_ibd_blocks = self.bitcoin_rs_ibd_blocks;
        let bitcoin_core_ibd_blocks = self.bitcoin_core_ibd_blocks;
        let bitcoin_rs_elapsed_seconds = self.bitcoin_rs_elapsed_seconds;
        let bitcoin_core_elapsed_seconds = self.bitcoin_core_elapsed_seconds;
        let bitcoin_rs_criterion_benchmark_id = &self.bitcoin_rs_criterion_benchmark_id;
        let bitcoin_core_criterion_benchmark_id = &self.bitcoin_core_criterion_benchmark_id;
        let bitcoin_rs_criterion_raw_output_path = &self.criterion_raw_output.bitcoin_rs_path;
        let bitcoin_rs_criterion_raw_output_sha256 = &self.criterion_raw_output.bitcoin_rs_sha256;
        let bitcoin_core_criterion_raw_output_path = &self.criterion_raw_output.bitcoin_core_path;
        let bitcoin_core_criterion_raw_output_sha256 =
            &self.criterion_raw_output.bitcoin_core_sha256;
        let benchmark_run_id = &self.benchmark_run_id;
        let benchmark_host_id = &self.benchmark_host_id;
        let bitcoin_core_version = &self.bitcoin_core_version;
        let bitcoin_core_commit = &self.bitcoin_core_commit;
        let bitcoin_rs_command_sha256 = &self.bitcoin_rs_command_sha256;
        let bitcoin_core_command_sha256 = &self.bitcoin_core_command_sha256;
        let bitcoin_rs_config_sha256 = &self.bitcoin_rs_config_sha256;
        let bitcoin_core_config_sha256 = &self.bitcoin_core_config_sha256;
        let benchmark_artifact_sha256 = &self.benchmark_artifact_sha256;
        let initial_sync_bps = self.initial_sync_bps;
        let bitcoin_core_initial_sync_bps = self.bitcoin_core_initial_sync_bps;
        let initial_sync_speedup_vs_bitcoin_core =
            self.initial_sync_bps / self.bitcoin_core_initial_sync_bps;
        let utxo_commit_p95_ms = self.utxo_commit_p95_ms;
        let electrum_get_history_p95_ms = self.electrum_get_history_p95_ms;
        let rss_bytes = self.rss_bytes;
        let electrum_rss_measurement_path = &self.electrum_rss_measurement_path;
        let electrum_rss_measurement_sha256 = &self.electrum_rss_measurement_sha256;
        let electrum_scripthash_corpus = &self.electrum_scripthash_corpus;
        let electrum_scripthash_corpus_sha256 = &self.electrum_scripthash_corpus_sha256;
        println!("G14 evidence accepted for current git HEAD {commit_sha}");
        println!("ibd_start_height={start_height}");
        println!("ibd_start_hash={start_hash}");
        println!("ibd_stop_height={stop_height}");
        println!("ibd_stop_hash={stop_hash}");
        println!("bitcoin_rs_ibd_blocks={bitcoin_rs_ibd_blocks}");
        println!("bitcoin_core_ibd_blocks={bitcoin_core_ibd_blocks}");
        println!("bitcoin_rs_elapsed_seconds={bitcoin_rs_elapsed_seconds}");
        println!("bitcoin_core_elapsed_seconds={bitcoin_core_elapsed_seconds}");
        println!("bitcoin_rs_criterion_benchmark_id={bitcoin_rs_criterion_benchmark_id}");
        println!("bitcoin_core_criterion_benchmark_id={bitcoin_core_criterion_benchmark_id}");
        println!("bitcoin_rs_criterion_raw_output_path={bitcoin_rs_criterion_raw_output_path}");
        println!("bitcoin_rs_criterion_raw_output_sha256={bitcoin_rs_criterion_raw_output_sha256}");
        println!("bitcoin_core_criterion_raw_output_path={bitcoin_core_criterion_raw_output_path}");
        println!(
            "bitcoin_core_criterion_raw_output_sha256={bitcoin_core_criterion_raw_output_sha256}"
        );
        println!("benchmark_run_id={benchmark_run_id}");
        println!("benchmark_host_id={benchmark_host_id}");
        println!("bitcoin_core_version={bitcoin_core_version}");
        println!("bitcoin_core_commit={bitcoin_core_commit}");
        println!("bitcoin_rs_command_sha256={bitcoin_rs_command_sha256}");
        println!("bitcoin_core_command_sha256={bitcoin_core_command_sha256}");
        println!("bitcoin_rs_config_sha256={bitcoin_rs_config_sha256}");
        println!("bitcoin_core_config_sha256={bitcoin_core_config_sha256}");
        println!("benchmark_artifact_sha256={benchmark_artifact_sha256}");
        println!("initial_sync_bps={initial_sync_bps}");
        println!("bitcoin_core_initial_sync_bps={bitcoin_core_initial_sync_bps}");
        println!("initial_sync_speedup_vs_bitcoin_core={initial_sync_speedup_vs_bitcoin_core}");
        println!("utxo_commit_p95_ms={utxo_commit_p95_ms}");
        println!("electrum_get_history_p95_ms={electrum_get_history_p95_ms}");
        println!("rss_bytes={rss_bytes}");
        println!("electrum_rss_measurement_path={electrum_rss_measurement_path}");
        println!("electrum_rss_measurement_sha256={electrum_rss_measurement_sha256}");
        println!("electrum_scripthash_corpus={electrum_scripthash_corpus}");
        println!("electrum_scripthash_corpus_sha256={electrum_scripthash_corpus_sha256}");
    }
}

impl CriterionRawOutputCustody {
    fn from_env() -> Self {
        Self::from_values(
            required_env("G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH"),
            required_hex("G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_SHA256", 64),
            required_env("G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH"),
            required_hex("G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_SHA256", 64),
        )
    }

    fn from_values(
        bitcoin_rs_path: String,
        bitcoin_rs_sha256: String,
        bitcoin_core_path: String,
        bitcoin_core_sha256: String,
    ) -> Self {
        require_sha256_file(
            &bitcoin_rs_path,
            &bitcoin_rs_sha256,
            "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
        );
        require_sha256_file(
            &bitcoin_core_path,
            &bitcoin_core_sha256,
            "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
        );
        Self {
            bitcoin_rs_path,
            bitcoin_rs_sha256,
            bitcoin_core_path,
            bitcoin_core_sha256,
        }
    }
}

fn required_env(name: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => panic!("{name} must not be empty; {EVIDENCE_HELP}"),
        Err(env::VarError::NotPresent) => panic!("missing {name}; {EVIDENCE_HELP}"),
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8; {EVIDENCE_HELP}"),
    }
}

fn required_commit_sha() -> String {
    let value = required_env("G14_COMMIT_SHA");
    assert!(
        is_lower_hex_sha(&value),
        "G14_COMMIT_SHA must be a 40-character lowercase hex commit sha, got {value:?}",
    );
    let current_head = current_git_head();
    assert_eq!(
        value, current_head,
        "G14_COMMIT_SHA must match current git HEAD; evidence {value}, current HEAD {current_head}",
    );
    require_clean_tracked_tree();
    value
}

fn current_git_head() -> String {
    let output = match Command::new("git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "rev-parse",
            "--verify",
            "HEAD",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run git rev-parse for G14_COMMIT_SHA binding: {error}"),
    };
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed while validating G14_COMMIT_SHA: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(error) => panic!("git rev-parse HEAD did not return UTF-8: {error}"),
    };
    let head = stdout.trim().to_owned();
    assert!(
        is_lower_hex_sha(&head),
        "git rev-parse HEAD returned invalid sha {head:?}",
    );
    head
}

fn require_clean_tracked_tree() {
    let output = match Command::new("git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run git status for G14 clean-tree binding: {error}"),
    };
    assert!(
        output.status.success(),
        "git status failed while validating G14 clean-tree binding: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stdout.is_empty(),
        "G14 evidence requires a clean tracked working tree for G14_COMMIT_SHA; tracked changes:\n{}",
        String::from_utf8_lossy(&output.stdout),
    );
}

fn is_lower_hex_sha(value: &str) -> bool {
    is_lower_hex_len(value, 40)
}

fn is_lower_hex_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn required_hex(name: &str, len: usize) -> String {
    let value = required_env(name);
    assert!(
        is_lower_hex_len(&value, len),
        "{name} must be a {len}-character lowercase hex value, got {value:?}",
    );
    value
}

fn require_literal(name: &str, expected: &str) {
    let value = required_env(name);
    assert_eq!(
        value, expected,
        "{name} must be {expected:?} for G14 evidence, got {value:?}",
    );
}

fn verified_electrum_rss_measurement_from_env(
    stop_height: u64,
    stop_hash: &str,
    electrum_get_history_p95_ms: f64,
    rss_bytes: u64,
    electrum_scripthash_corpus: &str,
    electrum_scripthash_corpus_sha256: &str,
) -> (String, String) {
    require_literal(
        "G14_ELECTRUM_RSS_MEASUREMENT_SCHEMA",
        ELECTRUM_RSS_MEASUREMENT_SCHEMA,
    );
    require_exact_u64(
        "G14_ELECTRUM_RSS_MEASUREMENT_SAMPLE_SIZE",
        EXPECTED_ELECTRUM_SAMPLE_SIZE,
    );
    require_exact_u64(
        "G14_ELECTRUM_RSS_MEASUREMENT_NON_EMPTY_HISTORY_COUNT",
        EXPECTED_ELECTRUM_SAMPLE_SIZE,
    );
    require_exact_u64("G14_ELECTRUM_RSS_MEASUREMENT_TIP_HEIGHT", stop_height);
    let electrum_rss_measurement_tip_hash =
        required_hex("G14_ELECTRUM_RSS_MEASUREMENT_TIP_HASH", 64);
    assert_eq!(
        electrum_rss_measurement_tip_hash, stop_hash,
        "G14_ELECTRUM_RSS_MEASUREMENT_TIP_HASH must match G14_IBD_STOP_HASH"
    );
    let path = required_env("G14_ELECTRUM_RSS_MEASUREMENT_PATH");
    let sha256 = required_hex("G14_ELECTRUM_RSS_MEASUREMENT_SHA256", 64);
    require_sha256_file(&path, &sha256, "G14_ELECTRUM_RSS_MEASUREMENT_PATH");
    verify_electrum_rss_measurement_json(
        &path,
        stop_height,
        stop_hash,
        electrum_get_history_p95_ms,
        rss_bytes,
        electrum_scripthash_corpus,
        electrum_scripthash_corpus_sha256,
    );
    (path, sha256)
}

fn verify_electrum_rss_measurement_json(
    path: &str,
    stop_height: u64,
    stop_hash: &str,
    electrum_get_history_p95_ms: f64,
    rss_bytes: u64,
    electrum_scripthash_corpus: &str,
    electrum_scripthash_corpus_sha256: &str,
) {
    let data = read_json_object(path, "G14_ELECTRUM_RSS_MEASUREMENT_PATH");
    require_json_literal(
        &data,
        "schema",
        ELECTRUM_RSS_MEASUREMENT_SCHEMA,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    require_json_literal(
        &data,
        "measurement_kind",
        "evidence",
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    require_json_literal(
        &data,
        "method",
        ELECTRUM_HISTORY_METHOD,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    require_json_exact_u64(
        &data,
        "electrum_sample_size",
        EXPECTED_ELECTRUM_SAMPLE_SIZE,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    require_json_exact_u64(
        &data,
        "electrum_non_empty_history_count",
        EXPECTED_ELECTRUM_SAMPLE_SIZE,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    require_json_exact_u64(
        &data,
        "electrum_tip_height",
        stop_height,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    let measurement_tip_hash = require_json_hex(
        &data,
        "electrum_tip_hash",
        64,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    assert_eq!(
        measurement_tip_hash, stop_hash,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH electrum_tip_hash must match G14_IBD_STOP_HASH",
    );
    require_json_literal(
        &data,
        "electrum_scripthash_corpus",
        electrum_scripthash_corpus,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    let measurement_corpus_sha256 = require_json_hex(
        &data,
        "electrum_scripthash_corpus_sha256",
        64,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    assert_eq!(
        measurement_corpus_sha256, electrum_scripthash_corpus_sha256,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH electrum_scripthash_corpus_sha256 must match G14_ELECTRUM_SCRIPTHASH_CORPUS_SHA256",
    );
    require_json_exact_f64(
        &data,
        "electrum_get_history_p95_ms",
        electrum_get_history_p95_ms,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
    require_json_exact_u64(
        &data,
        "rss_bytes",
        rss_bytes,
        "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
    );
}

fn read_json_object(path: &str, name: &str) -> Value {
    let file = match File::open(Path::new(path)) {
        Ok(file) => file,
        Err(error) => panic!("{name} must be a readable JSON file at {path}: {error}"),
    };
    let data = match serde_json::from_reader::<_, Value>(file) {
        Ok(data) => data,
        Err(error) => panic!("{name} must point to valid JSON at {path}: {error}"),
    };
    assert!(data.is_object(), "{name} must point to a JSON object");
    data
}

fn require_json_literal(data: &Value, key: &str, expected: &str, source: &str) {
    let value = match data.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value,
        _ => panic!("{source} {key} must be a non-empty string"),
    };
    assert_eq!(value, expected, "{source} {key} must be {expected:?}");
}

fn require_json_hex(data: &Value, key: &str, len: usize, source: &str) -> String {
    let value = match data.get(key).and_then(Value::as_str) {
        Some(value) => value,
        None => panic!("{source} {key} must be a string"),
    };
    assert!(
        is_lower_hex_len(value, len),
        "{source} {key} must be a {len}-character lowercase hex value, got {value:?}",
    );
    value.to_owned()
}

fn require_json_exact_u64(data: &Value, key: &str, expected: u64, source: &str) {
    let value = match data.get(key).and_then(Value::as_u64) {
        Some(value) => value,
        None => panic!("{source} {key} must be a non-negative integer"),
    };
    assert_eq!(value, expected, "{source} {key} must be {expected}");
}

fn require_json_exact_f64(data: &Value, key: &str, expected: f64, source: &str) {
    let value = match data.get(key).and_then(Value::as_f64) {
        Some(value) if value.is_finite() && value > 0.0 => value,
        _ => panic!("{source} {key} must be a finite positive number"),
    };
    assert!(
        (value - expected).abs() <= 1e-12,
        "{source} {key} must match final G14 evidence env; measurement={value}, env={expected}",
    );
}

fn require_sha256_file(path: &str, expected_sha256: &str, name: &str) {
    let actual_sha256 = sha256_file(path, name);
    assert_eq!(
        actual_sha256, expected_sha256,
        "{name} content hash must match its G14 SHA-256 binding",
    );
}

fn sha256_file(path: &str, name: &str) -> String {
    let path = Path::new(path);
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => panic!(
            "{name} must be a readable file at {}: {error}",
            path.display()
        ),
    };
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => panic!("{name} could not be read at {}: {error}", path.display()),
        };
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    lower_hex(&digest.finalize())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn require_exact_u64(name: &str, expected: u64) {
    let value = positive_u64(name);
    assert_eq!(
        value, expected,
        "{name} must be {expected} for G14 evidence, got {value}",
    );
}

fn measured_bps(blocks: u64, elapsed_seconds: f64) -> f64 {
    let blocks = match u32::try_from(blocks) {
        Ok(blocks) => blocks,
        Err(error) => panic!("G14 block count does not fit f64 conversion path: {error}"),
    };
    f64::from(blocks) / elapsed_seconds
}

fn positive_f64(name: &str) -> f64 {
    let raw = required_env(name);
    let value = match raw.parse::<f64>() {
        Ok(value) => value,
        Err(error) => panic!("{name} must be a finite positive decimal, got {raw:?}: {error}"),
    };
    assert!(
        value.is_finite() && value > 0.0,
        "{name} must be finite and positive, got {value}",
    );
    value
}

fn positive_or_zero_u64(name: &str) -> u64 {
    let raw = required_env(name);
    match raw.parse::<u64>() {
        Ok(value) => value,
        Err(error) => panic!("{name} must be a non-negative integer, got {raw:?}: {error}"),
    }
}

fn positive_u64(name: &str) -> u64 {
    let raw = required_env(name);
    let value = match raw.parse::<u64>() {
        Ok(value) => value,
        Err(error) => panic!("{name} must be a positive integer, got {raw:?}: {error}"),
    };
    assert_ne!(value, 0, "{name} must be positive");
    value
}

#[cfg(test)]
mod tests {
    use std::{fs, panic};

    use tempfile::tempdir;

    use super::*;

    const TEST_TIP_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_CORPUS_SHA256: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TEST_CORPUS_PATH: &str = "/tmp/g14-scripthashes.txt";

    #[test]
    fn final_gate_accepts_hash_bound_local_custody_files() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let bitcoin_rs_raw = dir.path().join("bitcoin-rs.raw");
        let bitcoin_core_raw = dir.path().join("bitcoin-core.raw");
        fs::write(&bitcoin_rs_raw, b"Benchmarking bitcoin-rs/mainnet-ibd\n")
            .unwrap_or_else(|error| panic!("write bitcoin-rs raw failed: {error}"));
        fs::write(
            &bitcoin_core_raw,
            b"Benchmarking bitcoin-core/mainnet-ibd\n",
        )
        .unwrap_or_else(|error| panic!("write bitcoin-core raw failed: {error}"));

        let custody = CriterionRawOutputCustody::from_values(
            bitcoin_rs_raw.display().to_string(),
            sha256_file(
                &bitcoin_rs_raw.display().to_string(),
                "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
            ),
            bitcoin_core_raw.display().to_string(),
            sha256_file(
                &bitcoin_core_raw.display().to_string(),
                "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
            ),
        );

        assert_eq!(
            custody.bitcoin_rs_path,
            bitcoin_rs_raw.display().to_string()
        );
        assert_eq!(
            custody.bitcoin_core_path,
            bitcoin_core_raw.display().to_string()
        );
    }

    #[test]
    fn final_gate_rejects_tampered_criterion_raw_output() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let bitcoin_rs_raw = dir.path().join("bitcoin-rs.raw");
        let bitcoin_core_raw = dir.path().join("bitcoin-core.raw");
        fs::write(&bitcoin_rs_raw, b"Benchmarking bitcoin-rs/mainnet-ibd\n")
            .unwrap_or_else(|error| panic!("write bitcoin-rs raw failed: {error}"));
        fs::write(
            &bitcoin_core_raw,
            b"Benchmarking bitcoin-core/mainnet-ibd\n",
        )
        .unwrap_or_else(|error| panic!("write bitcoin-core raw failed: {error}"));
        let stale_bitcoin_rs_sha = sha256_file(
            &bitcoin_rs_raw.display().to_string(),
            "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
        );
        let bitcoin_core_sha = sha256_file(
            &bitcoin_core_raw.display().to_string(),
            "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
        );
        fs::write(&bitcoin_rs_raw, b"tampered\n")
            .unwrap_or_else(|error| panic!("tamper bitcoin-rs raw failed: {error}"));

        let result = panic::catch_unwind(|| {
            CriterionRawOutputCustody::from_values(
                bitcoin_rs_raw.display().to_string(),
                stale_bitcoin_rs_sha,
                bitcoin_core_raw.display().to_string(),
                bitcoin_core_sha,
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_rejects_tampered_electrum_rss_measurement() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let measurement = dir.path().join("electrum-rss.json");
        fs::write(
            &measurement,
            br#"{"schema":"g14-electrum-rss-measurement-v1"}"#,
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));
        let stale_sha = sha256_file(
            &measurement.display().to_string(),
            "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
        );
        fs::write(&measurement, br#"{"schema":"tampered"}"#)
            .unwrap_or_else(|error| panic!("tamper measurement failed: {error}"));

        let result = panic::catch_unwind(|| {
            require_sha256_file(
                &measurement.display().to_string(),
                &stale_sha,
                "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_accepts_electrum_rss_measurement_contents() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let measurement = dir.path().join("electrum-rss.json");
        fs::write(
            &measurement,
            electrum_rss_measurement_json(20.0, 1024, TEST_TIP_HASH),
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));

        verify_electrum_rss_measurement_json(
            &measurement.display().to_string(),
            800_000,
            TEST_TIP_HASH,
            20.0,
            1024,
            TEST_CORPUS_PATH,
            TEST_CORPUS_SHA256,
        );
    }

    #[test]
    fn final_gate_rejects_electrum_rss_measurement_content_mismatch() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let measurement = dir.path().join("electrum-rss.json");
        fs::write(
            &measurement,
            electrum_rss_measurement_json(25.0, 1024, TEST_TIP_HASH),
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));
        let matching_file_hash = sha256_file(
            &measurement.display().to_string(),
            "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
        );
        require_sha256_file(
            &measurement.display().to_string(),
            &matching_file_hash,
            "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
        );

        let result = panic::catch_unwind(|| {
            verify_electrum_rss_measurement_json(
                &measurement.display().to_string(),
                800_000,
                TEST_TIP_HASH,
                20.0,
                1024,
                TEST_CORPUS_PATH,
                TEST_CORPUS_SHA256,
            );
        });

        assert!(result.is_err());
    }

    fn electrum_rss_measurement_json(p95_ms: f64, rss_bytes: u64, tip_hash: &str) -> String {
        format!(
            r#"{{
  "schema": "g14-electrum-rss-measurement-v1",
  "measurement_kind": "evidence",
  "method": "blockchain.scripthash.get_history",
  "electrum_sample_size": 10000,
  "electrum_non_empty_history_count": 10000,
  "electrum_tip_height": 800000,
  "electrum_tip_hash": "{tip_hash}",
  "electrum_scripthash_corpus": "{TEST_CORPUS_PATH}",
  "electrum_scripthash_corpus_sha256": "{TEST_CORPUS_SHA256}",
  "electrum_get_history_p95_ms": {p95_ms},
  "rss_bytes": {rss_bytes}
}}"#
        )
    }
}
