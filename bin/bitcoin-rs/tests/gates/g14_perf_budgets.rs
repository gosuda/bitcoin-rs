//! G14 — Performance budgets.
//! **G14 — Performance budgets.**
//! - Initial block sync throughput is faster than Bitcoin Core's blocks-per-second on identical mainnet IBD (measured via `criterion`).
//! - UTXO commit p95 ≤ 50 ms per 4 MiB block.
//! - Electrum `scripthash.get_history` p95 ≤ 30 ms over a 10 000-call random sample at tip.
//! - RSS ≤ 16 GiB at mainnet tip with rocksdb default + all indexes enabled.
//!
//! This ignored gate does not run the live mainnet benchmarks itself. It verifies
//! externally collected evidence and fails closed when the evidence contract is
//! missing or malformed.

use std::{env, process::Command};

const MIN_INITIAL_SYNC_RATIO_VS_BITCOIN_CORE: f64 = 1.0;
const MAX_UTXO_COMMIT_P95_MS: f64 = 50.0;
const MAX_ELECTRUM_GET_HISTORY_P95_MS: f64 = 30.0;
const MAX_RSS_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FOUR_MIB_BYTES: u64 = 4 * 1024 * 1024;
const EXPECTED_ELECTRUM_SAMPLE_SIZE: u64 = 10_000;

const EVIDENCE_HELP: &str = "required G14 evidence env: \
G14_COMMIT_SHA=<current git HEAD as 40 lowercase hex>, \
G14_MEASUREMENT_TARGET=mainnet-ibd, \
G14_STORAGE_BACKEND=rocksdb, \
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
G14_BITCOIN_CORE_VERSION, \
G14_BITCOIN_CORE_COMMIT=<40 lowercase hex>, \
G14_BITCOIN_RS_COMMAND_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_COMMAND_SHA256=<64 lowercase hex>, \
G14_BITCOIN_RS_CONFIG_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_CONFIG_SHA256=<64 lowercase hex>, \
G14_UTXO_COMMIT_P95_MS, \
G14_ELECTRUM_GET_HISTORY_P95_MS, \
G14_RSS_BYTES";

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
    bitcoin_core_version: String,
    bitcoin_core_commit: String,
    bitcoin_rs_command_sha256: String,
    bitcoin_core_command_sha256: String,
    bitcoin_rs_config_sha256: String,
    bitcoin_core_config_sha256: String,
    initial_sync_bps: f64,
    bitcoin_core_initial_sync_bps: f64,
    utxo_commit_p95_ms: f64,
    electrum_get_history_p95_ms: f64,
    rss_bytes: u64,
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
        require_literal("G14_STORAGE_BACKEND", "rocksdb");
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
        let bitcoin_core_version = required_env("G14_BITCOIN_CORE_VERSION");
        let bitcoin_core_commit = required_hex("G14_BITCOIN_CORE_COMMIT", 40);
        let bitcoin_rs_command_sha256 = required_hex("G14_BITCOIN_RS_COMMAND_SHA256", 64);
        let bitcoin_core_command_sha256 = required_hex("G14_BITCOIN_CORE_COMMAND_SHA256", 64);
        let bitcoin_rs_config_sha256 = required_hex("G14_BITCOIN_RS_CONFIG_SHA256", 64);
        let bitcoin_core_config_sha256 = required_hex("G14_BITCOIN_CORE_CONFIG_SHA256", 64);
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
            bitcoin_core_version,
            bitcoin_core_commit,
            bitcoin_rs_command_sha256,
            bitcoin_core_command_sha256,
            bitcoin_rs_config_sha256,
            bitcoin_core_config_sha256,
            initial_sync_bps,
            bitcoin_core_initial_sync_bps,
            utxo_commit_p95_ms: positive_f64("G14_UTXO_COMMIT_P95_MS"),
            electrum_get_history_p95_ms: positive_f64("G14_ELECTRUM_GET_HISTORY_P95_MS"),
            rss_bytes: positive_u64("G14_RSS_BYTES"),
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
        assert!(
            self.initial_sync_bps > required_sync_bps,
            "G14 initial sync throughput failed: bitcoin-rs {} blocks/s, Bitcoin Core {} blocks/s, required faster than {} blocks/s",
            self.initial_sync_bps,
            self.bitcoin_core_initial_sync_bps,
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
        let bitcoin_core_version = &self.bitcoin_core_version;
        let bitcoin_core_commit = &self.bitcoin_core_commit;
        let bitcoin_rs_command_sha256 = &self.bitcoin_rs_command_sha256;
        let bitcoin_core_command_sha256 = &self.bitcoin_core_command_sha256;
        let bitcoin_rs_config_sha256 = &self.bitcoin_rs_config_sha256;
        let bitcoin_core_config_sha256 = &self.bitcoin_core_config_sha256;
        let initial_sync_bps = self.initial_sync_bps;
        let bitcoin_core_initial_sync_bps = self.bitcoin_core_initial_sync_bps;
        let utxo_commit_p95_ms = self.utxo_commit_p95_ms;
        let electrum_get_history_p95_ms = self.electrum_get_history_p95_ms;
        let rss_bytes = self.rss_bytes;
        println!("G14 evidence accepted for current git HEAD {commit_sha}");
        println!("ibd_start_height={start_height}");
        println!("ibd_start_hash={start_hash}");
        println!("ibd_stop_height={stop_height}");
        println!("ibd_stop_hash={stop_hash}");
        println!("bitcoin_rs_ibd_blocks={bitcoin_rs_ibd_blocks}");
        println!("bitcoin_core_ibd_blocks={bitcoin_core_ibd_blocks}");
        println!("bitcoin_rs_elapsed_seconds={bitcoin_rs_elapsed_seconds}");
        println!("bitcoin_core_elapsed_seconds={bitcoin_core_elapsed_seconds}");
        println!("bitcoin_core_version={bitcoin_core_version}");
        println!("bitcoin_core_commit={bitcoin_core_commit}");
        println!("bitcoin_rs_command_sha256={bitcoin_rs_command_sha256}");
        println!("bitcoin_core_command_sha256={bitcoin_core_command_sha256}");
        println!("bitcoin_rs_config_sha256={bitcoin_rs_config_sha256}");
        println!("bitcoin_core_config_sha256={bitcoin_core_config_sha256}");
        println!("initial_sync_bps={initial_sync_bps}");
        println!("bitcoin_core_initial_sync_bps={bitcoin_core_initial_sync_bps}");
        println!("utxo_commit_p95_ms={utxo_commit_p95_ms}");
        println!("electrum_get_history_p95_ms={electrum_get_history_p95_ms}");
        println!("rss_bytes={rss_bytes}");
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
