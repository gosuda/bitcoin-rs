//! G14 — Performance budgets.
//! **G14 — Performance budgets.**
//! - Block validation throughput ≥ 80 % of `gocoin`'s blocks-per-second on identical mainnet IBD (measured via `criterion`).
//! - UTXO commit p95 ≤ 50 ms per 4 MiB block.
//! - Electrum `scripthash.get_history` p95 ≤ 30 ms over a 10 000-call random sample at tip.
//! - RSS ≤ 16 GiB at mainnet tip with rocksdb default + all indexes enabled.
//!
//! This ignored gate does not run the live mainnet benchmarks itself. It verifies
//! externally collected evidence and fails closed when the evidence contract is
//! missing or malformed.

use std::{env, process::Command};

const MIN_BLOCK_VALIDATION_RATIO: f64 = 0.80;
const MAX_UTXO_COMMIT_P95_MS: f64 = 50.0;
const MAX_ELECTRUM_GET_HISTORY_P95_MS: f64 = 30.0;
const MAX_RSS_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FOUR_MIB_BYTES: u64 = 4 * 1024 * 1024;
const EXPECTED_ELECTRUM_SAMPLE_SIZE: u64 = 10_000;

const EVIDENCE_HELP: &str = "required G14 evidence env: \
G14_COMMIT_SHA=<current git HEAD as 40 lowercase hex>, \
G14_MEASUREMENT_TARGET=mainnet-tip, \
G14_STORAGE_BACKEND=rocksdb, \
G14_INDEXES=all, \
G14_REFERENCE_IMPL=gocoin, \
G14_BENCH_TOOL=criterion, \
G14_BLOCK_SIZE_BYTES=4194304, \
G14_ELECTRUM_SAMPLE_SIZE=10000, \
G14_BLOCK_VALIDATION_BPS, \
G14_GOCOIN_BLOCK_VALIDATION_BPS, \
G14_UTXO_COMMIT_P95_MS, \
G14_ELECTRUM_GET_HISTORY_P95_MS, \
G14_RSS_BYTES";

struct G14Evidence {
    commit_sha: String,
    block_validation_bps: f64,
    gocoin_block_validation_bps: f64,
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
        require_literal("G14_MEASUREMENT_TARGET", "mainnet-tip");
        require_literal("G14_STORAGE_BACKEND", "rocksdb");
        require_literal("G14_INDEXES", "all");
        require_literal("G14_REFERENCE_IMPL", "gocoin");
        require_literal("G14_BENCH_TOOL", "criterion");
        require_exact_u64("G14_BLOCK_SIZE_BYTES", FOUR_MIB_BYTES);
        require_exact_u64("G14_ELECTRUM_SAMPLE_SIZE", EXPECTED_ELECTRUM_SAMPLE_SIZE);

        Self {
            commit_sha,
            block_validation_bps: positive_f64("G14_BLOCK_VALIDATION_BPS"),
            gocoin_block_validation_bps: positive_f64("G14_GOCOIN_BLOCK_VALIDATION_BPS"),
            utxo_commit_p95_ms: positive_f64("G14_UTXO_COMMIT_P95_MS"),
            electrum_get_history_p95_ms: positive_f64("G14_ELECTRUM_GET_HISTORY_P95_MS"),
            rss_bytes: positive_u64("G14_RSS_BYTES"),
        }
    }

    fn assert_budgets(&self) {
        let required_block_bps = self.gocoin_block_validation_bps * MIN_BLOCK_VALIDATION_RATIO;
        assert!(
            self.block_validation_bps >= required_block_bps,
            "G14 block validation throughput failed: bitcoin-rs {} blocks/s, gocoin {} blocks/s, required at least {} blocks/s (80%)",
            self.block_validation_bps,
            self.gocoin_block_validation_bps,
            required_block_bps,
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
        let block_validation_bps = self.block_validation_bps;
        let gocoin_block_validation_bps = self.gocoin_block_validation_bps;
        let utxo_commit_p95_ms = self.utxo_commit_p95_ms;
        let electrum_get_history_p95_ms = self.electrum_get_history_p95_ms;
        let rss_bytes = self.rss_bytes;
        println!("G14 evidence accepted for current git HEAD {commit_sha}");
        println!("block_validation_bps={block_validation_bps}");
        println!("gocoin_block_validation_bps={gocoin_block_validation_bps}");
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

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
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

fn positive_u64(name: &str) -> u64 {
    let raw = required_env(name);
    let value = match raw.parse::<u64>() {
        Ok(value) => value,
        Err(error) => panic!("{name} must be a positive integer, got {raw:?}: {error}"),
    };
    assert_ne!(value, 0, "{name} must be positive");
    value
}
