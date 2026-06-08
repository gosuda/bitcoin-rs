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

use std::{
    env,
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MIN_INITIAL_SYNC_RATIO_VS_BITCOIN_CORE: f64 = 1.0;
const MAX_UTXO_COMMIT_P95_MS: f64 = 50.0;
const MAX_ELECTRUM_GET_HISTORY_P95_MS: f64 = 30.0;
const MAX_RSS_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FOUR_MIB_BYTES: u64 = 4 * 1024 * 1024;
const EXPECTED_ELECTRUM_SAMPLE_SIZE: u64 = 10_000;
const ELECTRUM_RSS_MEASUREMENT_SCHEMA: &str = "g14-electrum-rss-measurement-v1";
const UTXO_COMMIT_MEASUREMENT_SCHEMA: &str = "g14-utxo-commit-measurement-v1";
const ELECTRUM_HISTORY_METHOD: &str = "blockchain.scripthash.get_history";
const IBD_COMPLETION_PROOF_SCHEMA: &str = "g14-ibd-completion-proof-v1";
const IBD_COMPLETION_PROOF_PREFIX: &str = "G14_IBD_COMPLETION_PROOF ";
const BITCOIN_RS_CRITERION_BENCHMARK_ID: &str = "bitcoin-rs/mainnet-ibd";
const BITCOIN_CORE_CRITERION_BENCHMARK_ID: &str = "bitcoin-core/mainnet-ibd";
const BITCOIN_RS_IBD_ADAPTER: &str = "bitcoin-rs-daemon-mainnet-ibd-v1";
const BITCOIN_RS_DAEMON_ADAPTER_BASENAME: &str = "run-g14-bitcoin-rs-daemon-mainnet-ibd.sh";
const BITCOIN_RS_REPLAY_ADAPTER_BASENAME: &str = "run-g14-bitcoin-rs-mainnet-ibd.sh";

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
G14_BITCOIN_RS_IBD_ADAPTER=bitcoin-rs-daemon-mainnet-ibd-v1, \
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
G14_BITCOIN_RS_COMMAND, \
G14_BITCOIN_RS_COMMAND_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_COMMAND_SHA256=<64 lowercase hex>, \
G14_BITCOIN_RS_CONFIG_SHA256=<64 lowercase hex>, \
G14_BITCOIN_CORE_CONFIG_SHA256=<64 lowercase hex>, \
G14_BENCHMARK_ARTIFACT_SHA256=<64 lowercase hex>, \
G14_UTXO_COMMIT_P95_MS, \
G14_UTXO_COMMIT_MEASUREMENT_PATH, \
G14_UTXO_COMMIT_MEASUREMENT_SHA256=<64 lowercase hex>, \
G14_UTXO_COMMIT_MEASUREMENT_SCHEMA=g14-utxo-commit-measurement-v1, \
G14_UTXO_COMMIT_MEASUREMENT_SAMPLE_COUNT, \
G14_UTXO_COMMIT_MEASUREMENT_START_HEIGHT=G14_IBD_START_HEIGHT, \
G14_UTXO_COMMIT_MEASUREMENT_START_HASH=G14_IBD_START_HASH, \
G14_UTXO_COMMIT_MEASUREMENT_STOP_HEIGHT=G14_IBD_STOP_HEIGHT, \
G14_UTXO_COMMIT_MEASUREMENT_STOP_HASH=G14_IBD_STOP_HASH, \
G14_UTXO_COMMIT_BLOCK_SIZE_THRESHOLD_BYTES=4194304, \
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
    utxo_commit_measurement_path: String,
    utxo_commit_measurement_sha256: String,
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

struct UtxoCommitMeasurementEvidence {
    p95_ms: f64,
    path: String,
    sha256: String,
}

struct ElectrumRssMeasurementEvidence {
    get_history_p95_ms: f64,
    rss_bytes: u64,
    measurement_path: String,
    measurement_sha256: String,
    scripthash_corpus: String,
    scripthash_corpus_sha256: String,
}

#[derive(Clone, Copy)]
struct IbdCompletionProofContext<'a> {
    benchmark_id: &'a str,
    benchmark_run_id: &'a str,
    benchmark_host_id: &'a str,
    start_height: u64,
    start_hash: &'a str,
    stop_height: u64,
    stop_hash: &'a str,
    command_sha256: &'a str,
    config_sha256: &'a str,
}

#[derive(Clone, Copy)]
struct IbdCompletionProofEnv<'a> {
    benchmark_run_id: &'a str,
    benchmark_host_id: &'a str,
    start_height: u64,
    start_hash: &'a str,
    stop_height: u64,
    stop_hash: &'a str,
}

#[derive(Clone, Copy)]
struct IbdCompletionProofEntry<'a> {
    benchmark_id: &'a str,
    command_sha256: &'a str,
    config_sha256: &'a str,
    elapsed_seconds: f64,
}

impl<'a> IbdCompletionProofEntry<'a> {
    fn new(
        benchmark_id: &'a str,
        command_sha256: &'a str,
        config_sha256: &'a str,
        elapsed_seconds: f64,
    ) -> Self {
        Self {
            benchmark_id,
            command_sha256,
            config_sha256,
            elapsed_seconds,
        }
    }
}

impl<'a> IbdCompletionProofEnv<'a> {
    fn new(
        benchmark_run_id: &'a str,
        benchmark_host_id: &'a str,
        start_height: u64,
        start_hash: &'a str,
        stop_height: u64,
        stop_hash: &'a str,
    ) -> Self {
        Self {
            benchmark_run_id,
            benchmark_host_id,
            start_height,
            start_hash,
            stop_height,
            stop_hash,
        }
    }

    fn context(
        self,
        benchmark_id: &'a str,
        command_sha256: &'a str,
        config_sha256: &'a str,
    ) -> IbdCompletionProofContext<'a> {
        IbdCompletionProofContext {
            benchmark_id,
            benchmark_run_id: self.benchmark_run_id,
            benchmark_host_id: self.benchmark_host_id,
            start_height: self.start_height,
            start_hash: self.start_hash,
            stop_height: self.stop_height,
            stop_hash: self.stop_hash,
            command_sha256,
            config_sha256,
        }
    }

    fn raw_output_from_env(
        self,
        bitcoin_rs: IbdCompletionProofEntry<'a>,
        bitcoin_core: IbdCompletionProofEntry<'a>,
    ) -> CriterionRawOutputCustody {
        CriterionRawOutputCustody::from_env(
            self.context(
                bitcoin_rs.benchmark_id,
                bitcoin_rs.command_sha256,
                bitcoin_rs.config_sha256,
            ),
            bitcoin_rs.elapsed_seconds,
            self.context(
                bitcoin_core.benchmark_id,
                bitcoin_core.command_sha256,
                bitcoin_core.config_sha256,
            ),
            bitcoin_core.elapsed_seconds,
        )
    }
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
        require_g14_static_env();
        let start_height = positive_or_zero_u64("G14_IBD_START_HEIGHT");
        let start_hash = required_hex("G14_IBD_START_HASH", 64);
        let stop_height = positive_or_zero_u64("G14_IBD_STOP_HEIGHT");
        let stop_hash = required_hex("G14_IBD_STOP_HASH", 64);
        let bitcoin_rs_ibd_blocks = positive_u64("G14_BITCOIN_RS_IBD_BLOCKS");
        let bitcoin_core_ibd_blocks = positive_u64("G14_BITCOIN_CORE_IBD_BLOCKS");
        let bitcoin_rs_elapsed_seconds = positive_f64("G14_BITCOIN_RS_ELAPSED_SECONDS");
        let bitcoin_core_elapsed_seconds = positive_f64("G14_BITCOIN_CORE_ELAPSED_SECONDS");
        let bitcoin_rs_criterion_benchmark_id = required_criterion_benchmark_id(
            "G14_BITCOIN_RS_CRITERION_BENCHMARK_ID",
            BITCOIN_RS_CRITERION_BENCHMARK_ID,
        );
        let bitcoin_core_criterion_benchmark_id = required_criterion_benchmark_id(
            "G14_BITCOIN_CORE_CRITERION_BENCHMARK_ID",
            BITCOIN_CORE_CRITERION_BENCHMARK_ID,
        );
        require_literal("G14_BITCOIN_RS_IBD_ADAPTER", BITCOIN_RS_IBD_ADAPTER);
        let benchmark_run_id = required_env("G14_BENCHMARK_RUN_ID");
        let benchmark_host_id = required_env("G14_BENCHMARK_HOST_ID");
        let bitcoin_core_version = required_env("G14_BITCOIN_CORE_VERSION");
        let bitcoin_core_commit = required_hex("G14_BITCOIN_CORE_COMMIT", 40);
        let bitcoin_rs_command = required_env("G14_BITCOIN_RS_COMMAND");
        let bitcoin_rs_command_sha256 = required_hex("G14_BITCOIN_RS_COMMAND_SHA256", 64);
        verify_bitcoin_rs_command_sha_binding(&bitcoin_rs_command, &bitcoin_rs_command_sha256);
        let bitcoin_core_command_sha256 = required_hex("G14_BITCOIN_CORE_COMMAND_SHA256", 64);
        let bitcoin_rs_config_sha256 = required_hex("G14_BITCOIN_RS_CONFIG_SHA256", 64);
        let bitcoin_core_config_sha256 = required_hex("G14_BITCOIN_CORE_CONFIG_SHA256", 64);
        let proof_env = IbdCompletionProofEnv::new(
            &benchmark_run_id,
            &benchmark_host_id,
            start_height,
            &start_hash,
            stop_height,
            &stop_hash,
        );
        let criterion_raw_output = proof_env.raw_output_from_env(
            IbdCompletionProofEntry::new(
                &bitcoin_rs_criterion_benchmark_id,
                &bitcoin_rs_command_sha256,
                &bitcoin_rs_config_sha256,
                bitcoin_rs_elapsed_seconds,
            ),
            IbdCompletionProofEntry::new(
                &bitcoin_core_criterion_benchmark_id,
                &bitcoin_core_command_sha256,
                &bitcoin_core_config_sha256,
                bitcoin_core_elapsed_seconds,
            ),
        );
        let benchmark_artifact_sha256 = required_hex("G14_BENCHMARK_ARTIFACT_SHA256", 64);
        let utxo_commit = UtxoCommitMeasurementEvidence::from_env(
            &commit_sha,
            start_height,
            &start_hash,
            stop_height,
            &stop_hash,
        );
        let electrum = ElectrumRssMeasurementEvidence::from_env(stop_height, &stop_hash);
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
            utxo_commit_p95_ms: utxo_commit.p95_ms,
            utxo_commit_measurement_path: utxo_commit.path,
            utxo_commit_measurement_sha256: utxo_commit.sha256,
            electrum_get_history_p95_ms: electrum.get_history_p95_ms,
            rss_bytes: electrum.rss_bytes,
            electrum_rss_measurement_path: electrum.measurement_path,
            electrum_rss_measurement_sha256: electrum.measurement_sha256,
            electrum_scripthash_corpus: electrum.scripthash_corpus,
            electrum_scripthash_corpus_sha256: electrum.scripthash_corpus_sha256,
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
        let utxo_commit_measurement_path = &self.utxo_commit_measurement_path;
        let utxo_commit_measurement_sha256 = &self.utxo_commit_measurement_sha256;
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
        println!("utxo_commit_measurement_path={utxo_commit_measurement_path}");
        println!("utxo_commit_measurement_sha256={utxo_commit_measurement_sha256}");
        println!("electrum_get_history_p95_ms={electrum_get_history_p95_ms}");
        println!("rss_bytes={rss_bytes}");
        println!("electrum_rss_measurement_path={electrum_rss_measurement_path}");
        println!("electrum_rss_measurement_sha256={electrum_rss_measurement_sha256}");
        println!("electrum_scripthash_corpus={electrum_scripthash_corpus}");
        println!("electrum_scripthash_corpus_sha256={electrum_scripthash_corpus_sha256}");
    }
}

impl CriterionRawOutputCustody {
    fn from_env(
        bitcoin_rs_context: IbdCompletionProofContext<'_>,
        bitcoin_rs_elapsed_seconds: f64,
        bitcoin_core_context: IbdCompletionProofContext<'_>,
        bitcoin_core_elapsed_seconds: f64,
    ) -> Self {
        Self::from_values(
            required_env("G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH"),
            required_hex("G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_SHA256", 64),
            bitcoin_rs_context,
            bitcoin_rs_elapsed_seconds,
            required_env("G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH"),
            required_hex("G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_SHA256", 64),
            bitcoin_core_context,
            bitcoin_core_elapsed_seconds,
        )
    }

    fn from_values(
        bitcoin_rs_path: String,
        bitcoin_rs_sha256: String,
        bitcoin_rs_context: IbdCompletionProofContext<'_>,
        bitcoin_rs_elapsed_seconds: f64,
        bitcoin_core_path: String,
        bitcoin_core_sha256: String,
        bitcoin_core_context: IbdCompletionProofContext<'_>,
        bitcoin_core_elapsed_seconds: f64,
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
        verify_criterion_raw_output_elapsed(
            &bitcoin_rs_path,
            "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
            bitcoin_rs_context.benchmark_id,
            bitcoin_rs_elapsed_seconds,
        );
        verify_ibd_completion_proof(
            &bitcoin_rs_path,
            "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
            bitcoin_rs_context,
        );
        verify_criterion_raw_output_elapsed(
            &bitcoin_core_path,
            "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
            bitcoin_core_context.benchmark_id,
            bitcoin_core_elapsed_seconds,
        );
        verify_ibd_completion_proof(
            &bitcoin_core_path,
            "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
            bitcoin_core_context,
        );
        Self {
            bitcoin_rs_path,
            bitcoin_rs_sha256,
            bitcoin_core_path,
            bitcoin_core_sha256,
        }
    }
}

fn token_basename(token: &str) -> &str {
    Path::new(token)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(token)
}

fn shell_split(command: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in command.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if !in_single => escape = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }

    if escape || in_single || in_double {
        return Err("command must be shell-parseable".to_owned());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn validate_bitcoin_rs_ibd_command(command: &str, name: &str) {
    let command = command.trim();
    assert!(!command.is_empty(), "{name} must not be empty");
    let tokens = shell_split(command).unwrap_or_else(|message| panic!("{name} {message}"));
    assert!(!tokens.is_empty(), "{name} must not be empty");
    let basenames: Vec<_> = tokens.iter().map(|token| token_basename(token)).collect();
    assert!(
        !basenames.contains(&BITCOIN_RS_REPLAY_ADAPTER_BASENAME),
        "{name} must not invoke the mainnet prefix replay wrapper {BITCOIN_RS_REPLAY_ADAPTER_BASENAME:?}"
    );
    assert_eq!(
        basenames[0], BITCOIN_RS_DAEMON_ADAPTER_BASENAME,
        "{name} must start with the bitcoin-rs daemon IBD adapter {BITCOIN_RS_DAEMON_ADAPTER_BASENAME:?}, got {:?}",
        basenames[0]
    );
}

fn sha256_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    lower_hex(&hasher.finalize())
}

fn verify_bitcoin_rs_command_sha_binding(command: &str, expected_sha256: &str) {
    validate_bitcoin_rs_ibd_command(command, "G14_BITCOIN_RS_COMMAND");
    let computed_sha256 = sha256_text(command);
    assert_eq!(
        computed_sha256, expected_sha256,
        "G14_BITCOIN_RS_COMMAND_SHA256 must match SHA-256(G14_BITCOIN_RS_COMMAND)"
    );
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

fn require_g14_static_env() {
    require_literal("G14_MEASUREMENT_TARGET", "mainnet-ibd");
    require_literal("G14_STORAGE_BACKEND", "fjall");
    require_literal("G14_INDEXES", "all");
    require_literal("G14_REFERENCE_IMPL", "bitcoin-core");
    require_literal("G14_BENCH_TOOL", "criterion");
    require_exact_u64("G14_BLOCK_SIZE_BYTES", FOUR_MIB_BYTES);
    require_exact_u64("G14_ELECTRUM_SAMPLE_SIZE", EXPECTED_ELECTRUM_SAMPLE_SIZE);
}

fn required_criterion_benchmark_id(name: &str, expected: &str) -> String {
    let value = required_env(name);
    assert_eq!(
        value, expected,
        "{name} must identify the canonical mainnet IBD benchmark",
    );
    value
}

fn verify_criterion_raw_output_elapsed(
    path: &str,
    name: &str,
    benchmark_id: &str,
    expected_elapsed_seconds: f64,
) {
    let raw_output = read_text_file(path, name);
    let parsed_elapsed_seconds = criterion_elapsed_seconds(&raw_output, benchmark_id, name);
    assert!(
        (parsed_elapsed_seconds - expected_elapsed_seconds).abs() <= 1e-12,
        "{name} Criterion raw output elapsed seconds must match final G14 evidence env for {benchmark_id}; raw={parsed_elapsed_seconds}, env={expected_elapsed_seconds}",
    );
}

fn verify_ibd_completion_proof(path: &str, name: &str, context: IbdCompletionProofContext<'_>) {
    let raw_output = read_text_file(path, name);
    let payloads: Vec<_> = raw_output
        .lines()
        .filter_map(|line| line.strip_prefix(IBD_COMPLETION_PROOF_PREFIX))
        .map(str::trim)
        .collect();
    assert_eq!(
        payloads.len(),
        1,
        "{name} must contain exactly one {} line",
        IBD_COMPLETION_PROOF_PREFIX.trim(),
    );
    let proof: Value = serde_json::from_str(payloads[0])
        .unwrap_or_else(|error| panic!("{name} IBD completion proof must be JSON: {error}"));
    require_json_literal(&proof, "schema", IBD_COMPLETION_PROOF_SCHEMA, name);
    require_json_literal(&proof, "benchmark_id", context.benchmark_id, name);
    require_json_literal(&proof, "benchmark_run_id", context.benchmark_run_id, name);
    require_json_literal(&proof, "benchmark_host_id", context.benchmark_host_id, name);
    require_json_exact_u64(&proof, "ibd_start_height", context.start_height, name);
    require_json_literal(&proof, "ibd_start_hash", context.start_hash, name);
    require_json_exact_u64(&proof, "ibd_stop_height", context.stop_height, name);
    require_json_literal(&proof, "ibd_stop_hash", context.stop_hash, name);
    require_json_exact_u64(
        &proof,
        "ibd_blocks",
        context.stop_height - context.start_height + 1,
        name,
    );
    require_json_literal(&proof, "command_sha256", context.command_sha256, name);
    require_json_literal(&proof, "config_sha256", context.config_sha256, name);
    if context.benchmark_id == BITCOIN_RS_CRITERION_BENCHMARK_ID {
        require_json_literal(&proof, "ibd_adapter", BITCOIN_RS_IBD_ADAPTER, name);
    } else if proof.get("ibd_adapter").is_some() {
        panic!(
            "{name} IBD completion proof must not include ibd_adapter for {}",
            context.benchmark_id
        );
    }
}

fn criterion_elapsed_seconds(raw_output: &str, benchmark_id: &str, name: &str) -> f64 {
    let lines: Vec<_> = raw_output.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !criterion_label_matches(line, benchmark_id) {
            continue;
        }
        for (offset, candidate) in lines[index..lines.len().min(index.saturating_add(16))]
            .iter()
            .enumerate()
        {
            if offset > 0 && criterion_phase_matches(candidate, benchmark_id) {
                continue;
            }
            if offset > 0
                && criterion_label_like(candidate)
                && !criterion_label_matches(candidate, benchmark_id)
            {
                break;
            }
            if candidate.contains("time:")
                && !criterion_time_prefix_matches(candidate, benchmark_id)
            {
                break;
            }
            if let Some(elapsed_seconds) = criterion_time_elapsed_seconds(candidate, name) {
                return elapsed_seconds;
            }
        }
    }
    panic!("{name} must contain Criterion time output for benchmark {benchmark_id:?}");
}

fn criterion_label_matches(line: &str, benchmark_id: &str) -> bool {
    let stripped = line.trim();
    stripped == benchmark_id || stripped == format!("Benchmarking {benchmark_id}")
}

fn criterion_phase_matches(line: &str, benchmark_id: &str) -> bool {
    line.trim()
        .starts_with(&format!("Benchmarking {benchmark_id}:"))
}

fn criterion_label_like(line: &str) -> bool {
    let stripped = line.trim();
    let candidate = stripped
        .strip_prefix("Benchmarking ")
        .map_or(stripped, |rest| {
            rest.split_once(':').map_or(rest, |(label, _)| label).trim()
        });
    candidate.contains('/')
        && !candidate.starts_with('/')
        && !candidate.ends_with('/')
        && candidate.chars().all(|ch| !ch.is_whitespace() && ch != ':')
}

fn criterion_time_prefix_matches(line: &str, benchmark_id: &str) -> bool {
    let Some((prefix, _time)) = line.split_once("time:") else {
        return false;
    };
    prefix.trim() == benchmark_id
}

fn criterion_time_elapsed_seconds(line: &str, name: &str) -> Option<f64> {
    let (_prefix, time) = line.split_once("time:")?;
    if let Some(start) = time.find('[') {
        let interval = &time[start + 1..];
        let end = interval
            .find(']')
            .unwrap_or_else(|| panic!("{name} Criterion interval time line is missing ']'"));
        let tokens: Vec<_> = interval[..end].split_whitespace().collect();
        assert!(
            tokens.len() >= 4,
            "{name} Criterion interval time line must include low, estimate, and high values",
        );
        return Some(criterion_seconds(tokens[2], tokens[3], name));
    }

    let tokens: Vec<_> = time.split_whitespace().collect();
    assert!(
        tokens.len() >= 2,
        "{name} Criterion time line must include a value and unit",
    );
    Some(criterion_seconds(tokens[0], tokens[1], name))
}

fn criterion_seconds(value: &str, unit: &str, name: &str) -> f64 {
    let value = match value.parse::<f64>() {
        Ok(value) if value.is_finite() && value > 0.0 => value,
        Ok(value) => panic!("{name} Criterion time value must be finite and positive, got {value}"),
        Err(error) => panic!("{name} Criterion time value {value:?} is not decimal: {error}"),
    };
    let scale = match unit {
        "ns" => 0.000_000_001,
        "us" | "\u{00b5}s" => 0.000_001,
        "ms" => 0.001,
        "s" => 1.0,
        _ => panic!("{name} Criterion time unit {unit:?} is not supported"),
    };
    value * scale
}

fn utxo_percentile_ms(samples_ms: &[f64], numerator: u64, denominator: u64) -> f64 {
    assert!(
        !samples_ms.is_empty(),
        "cannot calculate percentile for an empty sample"
    );
    assert!(denominator > 0, "percentile denominator must be positive");
    let mut ordered = samples_ms.to_vec();
    ordered.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let len = ordered.len();
    let len_u64 = u64::try_from(len).unwrap_or_else(|_| {
        panic!("cannot calculate percentile when sample length exceeds u64::MAX")
    });
    let rank = len_u64
        .saturating_mul(numerator)
        .saturating_add(denominator.saturating_sub(1))
        / denominator;
    let index = usize::try_from(rank)
        .unwrap_or_else(|_| panic!("percentile rank exceeds usize::MAX"))
        .saturating_sub(1)
        .min(len - 1);
    ordered[index]
}

fn utxo_positive_sample_float(value: &Value, name: &str) -> f64 {
    let number = match value {
        Value::Number(number) => number.as_f64(),
        _ => None,
    };
    let number = number.unwrap_or_else(|| panic!("{name} must be a finite positive number"));
    assert!(
        number.is_finite() && number > 0.0,
        "{name} must be finite and positive"
    );
    number
}

fn utxo_sample_non_negative_u64(value: Option<&Value>, field_name: &str) -> u64 {
    match value {
        Some(Value::Number(number)) => {
            if let Some(value) = number.as_u64() {
                return value;
            }
            let signed = number
                .as_i64()
                .unwrap_or_else(|| panic!("{field_name} must be a non-negative integer"));
            u64::try_from(signed)
                .unwrap_or_else(|_| panic!("{field_name} must be a non-negative integer"))
        }
        _ => panic!("{field_name} must be a non-negative integer"),
    }
}

fn utxo_sample_height(value: Option<&Value>, index: usize) -> u64 {
    utxo_sample_non_negative_u64(value, &format!("sample[{index}].height"))
}

fn utxo_sample_block_size(value: Option<&Value>, index: usize) -> u64 {
    utxo_sample_non_negative_u64(value, &format!("sample[{index}].block_size_bytes"))
}

fn read_utxo_samples_from_path(path: &Path, source: &str) -> Vec<Value> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => panic!(
            "{source} sample_source_path must be readable at {}: {error}",
            path.display()
        ),
    };
    let payload = match serde_json::from_reader::<_, Value>(file) {
        Ok(payload) => payload,
        Err(error) => panic!(
            "{source} sample_source_path must be valid JSON at {}: {error}",
            path.display()
        ),
    };
    if let Value::Array(samples) = payload {
        return samples;
    }
    if let Value::Object(object) = payload {
        if let Some(Value::Array(samples)) = object.get("samples") {
            return samples.clone();
        }
    }
    panic!("{source} sample source must be a JSON array or an object with a samples array");
}

fn utxo_sample_commit_ms(sample: &Value, index: usize) -> f64 {
    let object = sample.as_object().unwrap_or_else(|| {
        panic!("sample[{index}] must be an object");
    });
    let has_ms = object.contains_key("utxo_commit_ms");
    let has_us = object.contains_key("utxo_commit_us");
    assert!(
        !(has_ms && has_us),
        "sample[{index}] must not include both utxo_commit_ms and utxo_commit_us"
    );
    if let Some(value) = object.get("utxo_commit_ms") {
        return utxo_positive_sample_float(value, &format!("sample[{index}].utxo_commit_ms"));
    }
    if let Some(value) = object.get("utxo_commit_us") {
        return utxo_positive_sample_float(value, &format!("sample[{index}].utxo_commit_us"))
            / 1000.0;
    }
    panic!("sample[{index}] must include utxo_commit_ms or utxo_commit_us");
}

fn parse_utxo_sample(
    sample: &Value,
    index: usize,
    start_height: u64,
    stop_height: u64,
    threshold_bytes: u64,
) -> Option<f64> {
    let object = sample.as_object().unwrap_or_else(|| {
        panic!("sample[{index}] must be an object");
    });
    let height = utxo_sample_height(object.get("height"), index);
    assert!(
        height >= start_height && height <= stop_height,
        "sample[{index}].height must be within the IBD window"
    );
    let _block_hash = require_json_hex(
        &Value::Object(object.clone()),
        "block_hash",
        64,
        &format!("sample[{index}]"),
    );
    let block_size = utxo_sample_block_size(object.get("block_size_bytes"), index);
    if block_size < threshold_bytes {
        return None;
    }
    Some(utxo_sample_commit_ms(sample, index))
}

fn qualifying_utxo_commit_samples_ms(
    samples_path: &Path,
    source: &str,
    start_height: u64,
    stop_height: u64,
    threshold_bytes: u64,
) -> Vec<f64> {
    read_utxo_samples_from_path(samples_path, source)
        .iter()
        .enumerate()
        .filter_map(|(index, sample)| {
            parse_utxo_sample(sample, index, start_height, stop_height, threshold_bytes)
        })
        .collect()
}

fn utxo_sample_hash_at_height(samples: &[Value], height: u64, source: &str) -> String {
    let mut matched: Option<String> = None;
    for (index, sample) in samples.iter().enumerate() {
        let object = sample.as_object().unwrap_or_else(|| {
            panic!("{source}[{index}] must be an object");
        });
        let sample_height = utxo_sample_height(object.get("height"), index);
        if sample_height != height {
            continue;
        }
        let block_hash = require_json_hex(sample, "block_hash", 64, &format!("{source}[{index}]"));
        if let Some(existing) = &matched {
            assert_eq!(
                existing, &block_hash,
                "{source} contains conflicting block_hash values for height {height}"
            );
        }
        matched = Some(block_hash);
    }
    matched.unwrap_or_else(|| panic!("{source} must include a sample at height {height}"))
}

#[derive(Copy, Clone)]
struct UtxoIbdWindow<'a> {
    start_height: u64,
    start_hash: &'a str,
    stop_height: u64,
    stop_hash: &'a str,
}

fn verify_utxo_boundary_sample_hashes(
    samples_path: &Path,
    source: &str,
    window: UtxoIbdWindow<'_>,
) {
    let samples = read_utxo_samples_from_path(samples_path, source);
    let start_sample_hash = utxo_sample_hash_at_height(&samples, window.start_height, source);
    assert_eq!(
        start_sample_hash, window.start_hash,
        "{source} block_hash at ibd_start_height must match expected start hash"
    );
    let stop_sample_hash = utxo_sample_hash_at_height(&samples, window.stop_height, source);
    assert_eq!(
        stop_sample_hash, window.stop_hash,
        "{source} block_hash at ibd_stop_height must match expected stop hash"
    );
}

fn verify_utxo_commit_sample_custody(
    data: &Value,
    source: &str,
    window: UtxoIbdWindow<'_>,
    threshold_bytes: u64,
    expected_sample_count: u64,
    expected_p95_ms: f64,
) {
    let sample_source_path = data
        .get("sample_source_path")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("{source} sample_source_path must be a non-empty string"));
    let path = Path::new(sample_source_path);
    assert!(
        path.is_file(),
        "{source} sample_source_path is not a readable file: {sample_source_path}"
    );
    let expected_sample_sha = require_json_hex(data, "sample_source_sha256", 64, source);
    let actual_sample_sha = sha256_file(sample_source_path, source);
    assert_eq!(
        actual_sample_sha, expected_sample_sha,
        "{source} sample_source_sha256 must match sample_source_path"
    );
    verify_utxo_boundary_sample_hashes(path, source, window);
    require_json_exact_u64(data, "sample_count", expected_sample_count, source);
    let qualifying_ms = qualifying_utxo_commit_samples_ms(
        path,
        source,
        window.start_height,
        window.stop_height,
        threshold_bytes,
    );
    let qualifying_count = u64::try_from(qualifying_ms.len())
        .unwrap_or_else(|_| panic!("{source} sample_count exceeds u64::MAX"));
    assert_eq!(
        qualifying_count, expected_sample_count,
        "{source} sample_count must match qualifying samples from sample_source_path"
    );
    let recomputed_p95_ms = utxo_percentile_ms(&qualifying_ms, 95, 100);
    assert!(
        (recomputed_p95_ms - expected_p95_ms).abs() <= 1e-12,
        "{source} utxo_commit_p95_ms must match sample_source_path"
    );
}

impl UtxoCommitMeasurementEvidence {
    fn from_env(
        commit_sha: &str,
        start_height: u64,
        start_hash: &str,
        stop_height: u64,
        stop_hash: &str,
    ) -> Self {
        let p95_ms = positive_f64("G14_UTXO_COMMIT_P95_MS");
        require_literal(
            "G14_UTXO_COMMIT_MEASUREMENT_SCHEMA",
            UTXO_COMMIT_MEASUREMENT_SCHEMA,
        );
        require_exact_u64("G14_UTXO_COMMIT_MEASUREMENT_START_HEIGHT", start_height);
        let measurement_start_hash = required_hex("G14_UTXO_COMMIT_MEASUREMENT_START_HASH", 64);
        assert_eq!(
            measurement_start_hash, start_hash,
            "G14_UTXO_COMMIT_MEASUREMENT_START_HASH must match G14_IBD_START_HASH"
        );
        require_exact_u64("G14_UTXO_COMMIT_MEASUREMENT_STOP_HEIGHT", stop_height);
        let measurement_stop_hash = required_hex("G14_UTXO_COMMIT_MEASUREMENT_STOP_HASH", 64);
        assert_eq!(
            measurement_stop_hash, stop_hash,
            "G14_UTXO_COMMIT_MEASUREMENT_STOP_HASH must match G14_IBD_STOP_HASH"
        );
        require_exact_u64("G14_UTXO_COMMIT_BLOCK_SIZE_THRESHOLD_BYTES", FOUR_MIB_BYTES);
        let sample_count = positive_u64("G14_UTXO_COMMIT_MEASUREMENT_SAMPLE_COUNT");
        let path = required_env("G14_UTXO_COMMIT_MEASUREMENT_PATH");
        let sha256 = required_hex("G14_UTXO_COMMIT_MEASUREMENT_SHA256", 64);
        require_sha256_file(&path, &sha256, "G14_UTXO_COMMIT_MEASUREMENT_PATH");
        verify_utxo_commit_measurement_json(
            &path,
            commit_sha,
            sample_count,
            start_height,
            start_hash,
            stop_height,
            stop_hash,
            p95_ms,
        );
        Self {
            p95_ms,
            path,
            sha256,
        }
    }
}

fn verify_utxo_commit_measurement_json(
    path: &str,
    commit_sha: &str,
    expected_sample_count: u64,
    start_height: u64,
    start_hash: &str,
    stop_height: u64,
    stop_hash: &str,
    utxo_commit_p95_ms: f64,
) {
    let data = read_json_object(path, "G14_UTXO_COMMIT_MEASUREMENT_PATH");
    require_json_literal(
        &data,
        "schema",
        UTXO_COMMIT_MEASUREMENT_SCHEMA,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    require_json_literal(
        &data,
        "measurement_kind",
        "evidence",
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    let measurement_commit = require_json_hex(
        &data,
        "bitcoin_rs_commit",
        40,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    assert_eq!(
        measurement_commit, commit_sha,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH bitcoin_rs_commit must match G14_COMMIT_SHA"
    );
    require_json_exact_u64(
        &data,
        "ibd_start_height",
        start_height,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    let measurement_start_hash = require_json_hex(
        &data,
        "ibd_start_hash",
        64,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    assert_eq!(
        measurement_start_hash, start_hash,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH ibd_start_hash must match G14_IBD_START_HASH",
    );
    require_json_exact_u64(
        &data,
        "ibd_stop_height",
        stop_height,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    let measurement_stop_hash = require_json_hex(
        &data,
        "ibd_stop_hash",
        64,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    assert_eq!(
        measurement_stop_hash, stop_hash,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH ibd_stop_hash must match G14_IBD_STOP_HASH",
    );
    require_json_exact_u64(
        &data,
        "block_size_threshold_bytes",
        FOUR_MIB_BYTES,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    require_json_exact_u64(
        &data,
        "sample_count",
        expected_sample_count,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    require_json_exact_f64(
        &data,
        "utxo_commit_p95_ms",
        utxo_commit_p95_ms,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
    );
    verify_utxo_commit_sample_custody(
        &data,
        "G14_UTXO_COMMIT_MEASUREMENT_PATH",
        UtxoIbdWindow {
            start_height,
            start_hash,
            stop_height,
            stop_hash,
        },
        FOUR_MIB_BYTES,
        expected_sample_count,
        utxo_commit_p95_ms,
    );
}

impl ElectrumRssMeasurementEvidence {
    fn from_env(stop_height: u64, stop_hash: &str) -> Self {
        let get_history_p95_ms = positive_f64("G14_ELECTRUM_GET_HISTORY_P95_MS");
        let rss_bytes = positive_u64("G14_RSS_BYTES");
        let scripthash_corpus = required_env("G14_ELECTRUM_SCRIPTHASH_CORPUS");
        let scripthash_corpus_sha256 = required_hex("G14_ELECTRUM_SCRIPTHASH_CORPUS_SHA256", 64);
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
        let measurement_path = required_env("G14_ELECTRUM_RSS_MEASUREMENT_PATH");
        let measurement_sha256 = required_hex("G14_ELECTRUM_RSS_MEASUREMENT_SHA256", 64);
        require_sha256_file(
            &measurement_path,
            &measurement_sha256,
            "G14_ELECTRUM_RSS_MEASUREMENT_PATH",
        );
        verify_electrum_rss_measurement_json(
            &measurement_path,
            stop_height,
            stop_hash,
            get_history_p95_ms,
            rss_bytes,
            &scripthash_corpus,
            &scripthash_corpus_sha256,
        );
        Self {
            get_history_p95_ms,
            rss_bytes,
            measurement_path,
            measurement_sha256,
            scripthash_corpus,
            scripthash_corpus_sha256,
        }
    }
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

fn read_text_file(path: &str, name: &str) -> String {
    let value = match fs::read_to_string(Path::new(path)) {
        Ok(value) => value,
        Err(error) => panic!("{name} must be a readable UTF-8 file at {path}: {error}"),
    };
    assert!(!value.trim().is_empty(), "{name} must not be empty");
    value
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
    const TEST_START_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const TEST_RUN_ID: &str = "g14-mainnet-window-test";
    const TEST_RS_COMMAND_SHA256: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const TEST_CORE_COMMAND_SHA256: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const TEST_RS_CONFIG_SHA256: &str =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const TEST_CORE_CONFIG_SHA256: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn final_gate_accepts_hash_bound_local_custody_files() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let bitcoin_rs_raw = dir.path().join("bitcoin-rs.raw");
        let bitcoin_core_raw = dir.path().join("bitcoin-core.raw");
        fs::write(
            &bitcoin_rs_raw,
            criterion_raw_output(BITCOIN_RS_CRITERION_BENCHMARK_ID, 1.25),
        )
        .unwrap_or_else(|error| panic!("write bitcoin-rs raw failed: {error}"));
        fs::write(
            &bitcoin_core_raw,
            criterion_raw_output(BITCOIN_CORE_CRITERION_BENCHMARK_ID, 2.50),
        )
        .unwrap_or_else(|error| panic!("write bitcoin-core raw failed: {error}"));

        let custody = CriterionRawOutputCustody::from_values(
            bitcoin_rs_raw.display().to_string(),
            sha256_file(
                &bitcoin_rs_raw.display().to_string(),
                "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
            ),
            test_completion_context(BITCOIN_RS_CRITERION_BENCHMARK_ID),
            1.25,
            bitcoin_core_raw.display().to_string(),
            sha256_file(
                &bitcoin_core_raw.display().to_string(),
                "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
            ),
            test_completion_context(BITCOIN_CORE_CRITERION_BENCHMARK_ID),
            2.50,
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
    fn final_gate_rejects_ibd_completion_proof_mismatches() {
        let context = test_completion_context(BITCOIN_RS_CRITERION_BENCHMARK_ID);

        for (name, raw_output) in ibd_completion_proof_mismatch_cases(context) {
            let dir =
                tempdir().unwrap_or_else(|error| panic!("tempdir failed for {name}: {error}"));
            let raw = dir.path().join("bitcoin-rs.raw");
            fs::write(&raw, raw_output)
                .unwrap_or_else(|error| panic!("write raw failed for {name}: {error}"));

            let result = panic::catch_unwind(|| {
                verify_ibd_completion_proof(
                    &raw.display().to_string(),
                    "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
                    context,
                );
            });

            assert!(result.is_err(), "{name} unexpectedly passed");
        }
    }

    #[test]
    fn final_gate_rejects_tampered_criterion_raw_output() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let bitcoin_rs_raw = dir.path().join("bitcoin-rs.raw");
        let bitcoin_core_raw = dir.path().join("bitcoin-core.raw");
        fs::write(
            &bitcoin_rs_raw,
            criterion_raw_output(BITCOIN_RS_CRITERION_BENCHMARK_ID, 1.25),
        )
        .unwrap_or_else(|error| panic!("write bitcoin-rs raw failed: {error}"));
        fs::write(
            &bitcoin_core_raw,
            criterion_raw_output(BITCOIN_CORE_CRITERION_BENCHMARK_ID, 2.50),
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
                test_completion_context(BITCOIN_RS_CRITERION_BENCHMARK_ID),
                1.25,
                bitcoin_core_raw.display().to_string(),
                bitcoin_core_sha,
                test_completion_context(BITCOIN_CORE_CRITERION_BENCHMARK_ID),
                2.50,
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_rejects_criterion_raw_output_elapsed_mismatch() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let bitcoin_rs_raw = dir.path().join("bitcoin-rs.raw");
        let bitcoin_core_raw = dir.path().join("bitcoin-core.raw");
        fs::write(
            &bitcoin_rs_raw,
            criterion_raw_output(BITCOIN_RS_CRITERION_BENCHMARK_ID, 9.00),
        )
        .unwrap_or_else(|error| panic!("write bitcoin-rs raw failed: {error}"));
        fs::write(
            &bitcoin_core_raw,
            criterion_raw_output(BITCOIN_CORE_CRITERION_BENCHMARK_ID, 2.50),
        )
        .unwrap_or_else(|error| panic!("write bitcoin-core raw failed: {error}"));

        let result = panic::catch_unwind(|| {
            CriterionRawOutputCustody::from_values(
                bitcoin_rs_raw.display().to_string(),
                sha256_file(
                    &bitcoin_rs_raw.display().to_string(),
                    "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
                ),
                test_completion_context(BITCOIN_RS_CRITERION_BENCHMARK_ID),
                1.25,
                bitcoin_core_raw.display().to_string(),
                sha256_file(
                    &bitcoin_core_raw.display().to_string(),
                    "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH",
                ),
                test_completion_context(BITCOIN_CORE_CRITERION_BENCHMARK_ID),
                2.50,
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_rejects_non_exact_criterion_raw_output_label() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let raw = dir.path().join("bitcoin-rs.raw");
        fs::write(
            &raw,
            criterion_raw_output("bitcoin-rs/mainnet-ibd-renamed", 1.25),
        )
        .unwrap_or_else(|error| panic!("write raw failed: {error}"));

        let result = panic::catch_unwind(|| {
            verify_criterion_raw_output_elapsed(
                &raw.display().to_string(),
                "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
                BITCOIN_RS_CRITERION_BENCHMARK_ID,
                1.25,
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_rejects_unlabeled_criterion_raw_output_time() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let raw = dir.path().join("bitcoin-rs.raw");
        fs::write(
            &raw,
            "Benchmarking bitcoin-rs/mainnet-ibd\nBenchmarking bitcoin-rs/mainnet-ibd: Analyzing\ntime:   [1.00 s 1.25 s 3.00 s]\n",
        )
        .unwrap_or_else(|error| panic!("write raw failed: {error}"));

        let result = panic::catch_unwind(|| {
            verify_criterion_raw_output_elapsed(
                &raw.display().to_string(),
                "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH",
                BITCOIN_RS_CRITERION_BENCHMARK_ID,
                1.25,
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

    #[test]
    fn final_gate_rejects_tampered_utxo_commit_measurement() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let measurement = dir.path().join("utxo-commit.json");
        fs::write(
            &measurement,
            br#"{"schema":"g14-utxo-commit-measurement-v1"}"#,
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));
        let stale_sha = sha256_file(
            &measurement.display().to_string(),
            "G14_UTXO_COMMIT_MEASUREMENT_PATH",
        );
        fs::write(&measurement, br#"{"schema":"tampered"}"#)
            .unwrap_or_else(|error| panic!("tamper measurement failed: {error}"));

        let result = panic::catch_unwind(|| {
            require_sha256_file(
                &measurement.display().to_string(),
                &stale_sha,
                "G14_UTXO_COMMIT_MEASUREMENT_PATH",
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_accepts_utxo_commit_measurement_contents() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let commit_sha = current_git_head();
        let measurement = write_utxo_commit_measurement_fixture(
            dir.path(),
            &commit_sha,
            0,
            800_000,
            TEST_START_HASH,
            TEST_TIP_HASH,
            12.5,
        );

        verify_utxo_commit_measurement_json(
            &measurement.display().to_string(),
            &commit_sha,
            20,
            0,
            TEST_START_HASH,
            800_000,
            TEST_TIP_HASH,
            12.5,
        );
    }

    #[test]
    fn final_gate_rejects_utxo_commit_measurement_content_mismatch() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let measurement = dir.path().join("utxo-commit.json");
        fs::write(
            &measurement,
            utxo_commit_measurement_json(25.0, TEST_START_HASH, TEST_TIP_HASH),
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));
        let matching_file_hash = sha256_file(
            &measurement.display().to_string(),
            "G14_UTXO_COMMIT_MEASUREMENT_PATH",
        );
        require_sha256_file(
            &measurement.display().to_string(),
            &matching_file_hash,
            "G14_UTXO_COMMIT_MEASUREMENT_PATH",
        );

        let result = panic::catch_unwind(|| {
            verify_utxo_commit_measurement_json(
                &measurement.display().to_string(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                20,
                0,
                TEST_START_HASH,
                800_000,
                TEST_TIP_HASH,
                12.5,
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_rejects_utxo_commit_measurement_commit_mismatch() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let commit_sha = current_git_head();
        let measurement = write_utxo_commit_measurement_fixture(
            dir.path(),
            &commit_sha,
            0,
            800_000,
            TEST_START_HASH,
            TEST_TIP_HASH,
            12.5,
        );

        let result = panic::catch_unwind(|| {
            verify_utxo_commit_measurement_json(
                &measurement.display().to_string(),
                "cccccccccccccccccccccccccccccccccccccccc",
                20,
                0,
                TEST_START_HASH,
                800_000,
                TEST_TIP_HASH,
                12.5,
            );
        });

        assert!(result.is_err());
    }

    #[test]
    fn final_gate_rejects_utxo_commit_measurement_sample_count_mismatch() {
        let dir = tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let commit_sha = current_git_head();
        let measurement = write_utxo_commit_measurement_fixture(
            dir.path(),
            &commit_sha,
            0,
            800_000,
            TEST_START_HASH,
            TEST_TIP_HASH,
            12.5,
        );

        let result = panic::catch_unwind(|| {
            verify_utxo_commit_measurement_json(
                &measurement.display().to_string(),
                &commit_sha,
                99,
                0,
                TEST_START_HASH,
                800_000,
                TEST_TIP_HASH,
                12.5,
            );
        });

        assert!(result.is_err());
    }

    fn write_utxo_commit_samples(
        dir: &std::path::Path,
        start_height: u64,
        stop_height: u64,
        p95_ms: f64,
        start_hash: &str,
        stop_hash: &str,
    ) -> std::path::PathBuf {
        let span = stop_height - start_height + 1;
        let mut heights = Vec::with_capacity(20);
        heights.push(start_height);
        if stop_height != start_height {
            heights.push(stop_height);
        }
        let mut cursor = 0u64;
        while heights.len() < 20 {
            heights.push(start_height + (cursor % span));
            cursor += 1;
        }
        let mut samples = Vec::new();
        for (index, height) in heights.iter().copied().enumerate() {
            let block_hash = if height == start_height {
                start_hash.to_owned()
            } else if height == stop_height {
                stop_hash.to_owned()
            } else {
                format!("{height:064x}")
            };
            let commit_ms = match index {
                18 => p95_ms,
                19 => p95_ms + 7.5,
                _ => 10.0,
            };
            samples.push(format!(
                r#"{{"height": {height}, "block_hash": "{block_hash}", "block_size_bytes": 4194304, "utxo_commit_ms": {commit_ms}}}"#
            ));
        }
        let samples_path = dir.join("utxo-commit-samples.json");
        fs::write(&samples_path, format!("[{}]", samples.join(",")))
            .unwrap_or_else(|error| panic!("write utxo samples failed: {error}"));
        samples_path
    }

    fn write_utxo_commit_measurement_fixture(
        dir: &std::path::Path,
        commit_sha: &str,
        start_height: u64,
        stop_height: u64,
        start_hash: &str,
        stop_hash: &str,
        p95_ms: f64,
    ) -> std::path::PathBuf {
        let samples_path = write_utxo_commit_samples(
            dir,
            start_height,
            stop_height,
            p95_ms,
            start_hash,
            stop_hash,
        );
        let sample_source_sha256 = sha256_file(
            &samples_path.display().to_string(),
            "utxo commit sample source",
        );
        let measurement = dir.join("utxo-commit.json");
        fs::write(
            &measurement,
            format!(
                r#"{{
  "schema": "g14-utxo-commit-measurement-v1",
  "measurement_kind": "evidence",
  "bitcoin_rs_commit": "{commit_sha}",
  "ibd_start_height": {start_height},
  "ibd_start_hash": "{start_hash}",
  "ibd_stop_height": {stop_height},
  "ibd_stop_hash": "{stop_hash}",
  "block_size_threshold_bytes": 4194304,
  "sample_source_path": "{sample_source_path}",
  "sample_source_sha256": "{sample_source_sha256}",
  "sample_count": 20,
  "utxo_commit_p50_ms": 10.0,
  "utxo_commit_p95_ms": {p95_ms},
  "utxo_commit_p99_ms": 30.0,
  "utxo_commit_max_ms": 40.0
}}"#,
                sample_source_path = samples_path.display(),
            ),
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));
        measurement
    }

    #[test]
    fn utxo_commit_measurement_rejects_mismatched_boundary_sample_hashes() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        let commit_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let start_height = 0;
        let stop_height = 10;
        let start_hash = format!("{start_height:064x}");
        let stop_hash = format!("{stop_height:064x}");
        let measurement = write_utxo_commit_measurement_fixture(
            dir.path(),
            commit_sha,
            start_height,
            stop_height,
            &start_hash,
            &stop_hash,
            12.5,
        );
        let measurement_text = fs::read_to_string(&measurement)
            .unwrap_or_else(|error| panic!("read measurement failed: {error}"));
        let mut measurement_json: serde_json::Value = serde_json::from_str(&measurement_text)
            .unwrap_or_else(|error| panic!("parse measurement failed: {error}"));
        let samples_path = std::path::PathBuf::from(
            measurement_json["sample_source_path"]
                .as_str()
                .unwrap_or_else(|| panic!("sample_source_path must be a string")),
        );
        fs::write(
            &samples_path,
            r#"[{"height":0,"block_hash":"000000000000000000000000000000000000000000000000000000000000000a","block_size_bytes":4194304,"utxo_commit_ms":12.5}]"#,
        )
        .unwrap_or_else(|error| panic!("write tampered samples failed: {error}"));
        let tampered_sha = sha256_file(
            &samples_path.display().to_string(),
            "tampered utxo commit sample source",
        );
        measurement_json["sample_source_sha256"] = serde_json::Value::String(tampered_sha);
        fs::write(
            &measurement,
            serde_json::to_string_pretty(&measurement_json)
                .unwrap_or_else(|error| panic!("encode measurement failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("write measurement failed: {error}"));
        let result = panic::catch_unwind(|| {
            verify_utxo_commit_measurement_json(
                &measurement.display().to_string(),
                commit_sha,
                20,
                start_height,
                &start_hash,
                stop_height,
                &stop_hash,
                12.5,
            );
        });
        assert!(result.is_err());
    }

    fn utxo_commit_measurement_json(p95_ms: f64, start_hash: &str, stop_hash: &str) -> String {
        format!(
            r#"{{
  "schema": "g14-utxo-commit-measurement-v1",
  "measurement_kind": "evidence",
  "bitcoin_rs_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "ibd_start_height": 0,
  "ibd_start_hash": "{start_hash}",
  "ibd_stop_height": 800000,
  "ibd_stop_hash": "{stop_hash}",
  "block_size_threshold_bytes": 4194304,
  "sample_source_path": "/tmp/g14-utxo-samples.json",
  "sample_source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sample_count": 20,
  "utxo_commit_p50_ms": 10.0,
  "utxo_commit_p95_ms": {p95_ms},
  "utxo_commit_p99_ms": 30.0,
  "utxo_commit_max_ms": 40.0
}}"#
        )
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

    fn criterion_raw_output(benchmark_id: &str, elapsed_seconds: f64) -> String {
        let context = test_completion_context(benchmark_id);
        criterion_raw_output_with_proofs(
            benchmark_id,
            elapsed_seconds,
            &[completion_proof_value(context)],
        )
    }

    fn criterion_raw_output_without_proof(benchmark_id: &str, elapsed_seconds: f64) -> String {
        criterion_raw_output_with_proofs(benchmark_id, elapsed_seconds, &[])
    }

    fn ibd_completion_proof_mismatch_cases(
        context: IbdCompletionProofContext<'_>,
    ) -> Vec<(&'static str, String)> {
        let valid_proof = completion_proof_value(context);
        let mut cases = vec![
            (
                "missing proof",
                criterion_raw_output_without_proof(BITCOIN_RS_CRITERION_BENCHMARK_ID, 1.25),
            ),
            (
                "duplicate proof",
                criterion_raw_output_with_proofs(
                    BITCOIN_RS_CRITERION_BENCHMARK_ID,
                    1.25,
                    &[valid_proof.clone(), valid_proof],
                ),
            ),
        ];
        cases.extend([
            proof_mismatch_case(context, "bad schema", "schema", json!("wrong-schema")),
            proof_mismatch_case(
                context,
                "bad benchmark id",
                "benchmark_id",
                json!("bitcoin-rs/not-mainnet-ibd"),
            ),
            proof_mismatch_case(
                context,
                "bad run id",
                "benchmark_run_id",
                json!("wrong-run"),
            ),
            proof_mismatch_case(
                context,
                "bad host id",
                "benchmark_host_id",
                json!("wrong-host"),
            ),
            proof_mismatch_case(context, "bad start height", "ibd_start_height", json!(1)),
            proof_mismatch_case(
                context,
                "bad start hash",
                "ibd_start_hash",
                json!(TEST_TIP_HASH),
            ),
            proof_mismatch_case(context, "bad stop height", "ibd_stop_height", json!(11)),
            proof_mismatch_case(
                context,
                "bad stop hash",
                "ibd_stop_hash",
                json!(TEST_START_HASH),
            ),
            proof_mismatch_case(context, "bad block count", "ibd_blocks", json!(9)),
            proof_mismatch_case(
                context,
                "bad command hash",
                "command_sha256",
                json!(TEST_CORE_COMMAND_SHA256),
            ),
            proof_mismatch_case(
                context,
                "bad config hash",
                "config_sha256",
                json!(TEST_CORE_CONFIG_SHA256),
            ),
        ]);
        cases
    }

    fn proof_mismatch_case(
        context: IbdCompletionProofContext<'_>,
        name: &'static str,
        key: &str,
        value: Value,
    ) -> (&'static str, String) {
        (
            name,
            criterion_raw_output_with_mutated_proof(context, key, value),
        )
    }

    fn criterion_raw_output_with_mutated_proof(
        context: IbdCompletionProofContext<'_>,
        key: &str,
        value: Value,
    ) -> String {
        let mut proof = completion_proof_value(context);
        let object = proof
            .as_object_mut()
            .unwrap_or_else(|| panic!("completion proof fixture must be an object"));
        object.insert(key.to_owned(), value);
        criterion_raw_output_with_proofs(context.benchmark_id, 1.25, &[proof])
    }

    fn criterion_raw_output_with_proofs(
        benchmark_id: &str,
        elapsed_seconds: f64,
        proofs: &[Value],
    ) -> String {
        let mut raw_output = format!(
            "Benchmarking {benchmark_id}\nBenchmarking {benchmark_id}: Warming up for 1.0000 s\nBenchmarking {benchmark_id}: Collecting 100 samples in estimated 5.0000 s\nBenchmarking {benchmark_id}: Analyzing\n{benchmark_id}   time:   [1.00 s {elapsed_seconds} s 3.00 s]\n"
        );
        for proof in proofs {
            raw_output.push_str(IBD_COMPLETION_PROOF_PREFIX);
            raw_output.push_str(
                &serde_json::to_string(proof)
                    .unwrap_or_else(|error| panic!("serialize completion proof failed: {error}")),
            );
            raw_output.push('\n');
        }
        raw_output
    }

    fn completion_proof_value(context: IbdCompletionProofContext<'_>) -> Value {
        let mut proof = json!({
            "schema": IBD_COMPLETION_PROOF_SCHEMA,
            "benchmark_id": context.benchmark_id,
            "benchmark_run_id": context.benchmark_run_id,
            "benchmark_host_id": context.benchmark_host_id,
            "ibd_start_height": context.start_height,
            "ibd_start_hash": context.start_hash,
            "ibd_stop_height": context.stop_height,
            "ibd_stop_hash": context.stop_hash,
            "ibd_blocks": context.stop_height - context.start_height + 1,
            "command_sha256": context.command_sha256,
            "config_sha256": context.config_sha256,
        });
        if context.benchmark_id == BITCOIN_RS_CRITERION_BENCHMARK_ID {
            proof["ibd_adapter"] = json!(BITCOIN_RS_IBD_ADAPTER);
        }
        proof
    }

    #[test]
    fn final_gate_rejects_replay_bitcoin_rs_command() {
        let replay_command = "/tmp/g14-fixture/run-g14-bitcoin-rs-mainnet-ibd.sh --replay";
        let result = panic::catch_unwind(|| {
            validate_bitcoin_rs_ibd_command(replay_command, "G14_BITCOIN_RS_COMMAND");
        });
        assert!(result.is_err(), "replay wrapper command must be rejected");
    }

    #[test]
    fn final_gate_rejects_bitcoin_rs_command_sha_mismatch() {
        let command = "/tmp/g14-fixture/run-g14-bitcoin-rs-daemon-mainnet-ibd.sh";
        let result = panic::catch_unwind(|| {
            verify_bitcoin_rs_command_sha_binding(command, TEST_RS_COMMAND_SHA256);
        });
        assert!(result.is_err(), "command/SHA mismatch must be rejected");
    }

    #[test]
    fn final_gate_accepts_daemon_argv0_bitcoin_rs_command_sha_binding() {
        let command = "/tmp/g14-fixture/run-g14-bitcoin-rs-daemon-mainnet-ibd.sh";
        verify_bitcoin_rs_command_sha_binding(command, &sha256_text(command));
    }

    fn test_completion_context(benchmark_id: &str) -> IbdCompletionProofContext<'_> {
        let (command_sha256, config_sha256) = if benchmark_id == BITCOIN_CORE_CRITERION_BENCHMARK_ID
        {
            (TEST_CORE_COMMAND_SHA256, TEST_CORE_CONFIG_SHA256)
        } else {
            (TEST_RS_COMMAND_SHA256, TEST_RS_CONFIG_SHA256)
        };
        IbdCompletionProofContext {
            benchmark_id,
            benchmark_run_id: TEST_RUN_ID,
            benchmark_host_id: "g14-test-host",
            start_height: 0,
            start_hash: TEST_START_HASH,
            stop_height: 10,
            stop_hash: TEST_TIP_HASH,
            command_sha256,
            config_sha256,
        }
    }
}
