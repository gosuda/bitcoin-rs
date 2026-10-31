use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_node::test_support::TestError;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::BlockPayload;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const RECORDS: u32 = 10_000;
const MAX_REPLAY: Duration = Duration::from_mins(1);
const MAX_RSS_DELTA_KIB: u64 = 256 * 1024;
const PROBE_ENV: &str = "BITCOIN_RS_10K_REPLAY_PROBE";
const DATA_DIR_ENV: &str = "BITCOIN_RS_10K_REPLAY_DATADIR";
const RESULT_ENV: &str = "BITCOIN_RS_10K_REPLAY_RESULT";

#[derive(Debug, Deserialize, Serialize)]
struct ProbeResult {
    records: u32,
    elapsed_ms: u128,
    rss_before_kib: u64,
    rss_after_kib: u64,
    rss_delta_kib: u64,
    tip_height: u32,
    tip_hash: String,
}
fn main() -> Result<(), TestError> {
    if std::env::var_os(PROBE_ENV).is_some() {
        replay_10k_subprocess_probe()
    } else {
        replay_10k_records_with_bounded_time_and_memory()
    }
}
fn replay_10k_records_with_bounded_time_and_memory() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("node");
    let result_path = temp.path().join("probe.json");
    let config = test_config(data_dir.clone());
    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config, None)?;
    let genesis_payload = BlockPayload::from_local(genesis.clone());
    state.apply_block(&genesis_payload)?;
    if state.publish_checkpoint()?.is_none() {
        return Err(TestError::message(
            "checkpoint must publish at genesis before the 10k replay",
        ));
    }

    let mut previous = genesis.block_hash();
    for height in 1..=RECORDS {
        let block = regtest_fixture::mined_regtest_child_at(previous, height)?;
        previous = block.block_hash();
        let payload = BlockPayload::from_local(block);
        state.apply_block(&payload)?;
    }
    drop(state);

    let status = Command::new(std::env::current_exe()?)
        .env(PROBE_ENV, "1")
        .env(DATA_DIR_ENV, &data_dir)
        .env(RESULT_ENV, &result_path)
        .stdin(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(TestError::message(format!(
            "10k replay probe exited with {status}"
        )));
    }

    let result: ProbeResult = sonic_rs::from_slice(&std::fs::read(&result_path)?)?;
    eprintln!(
        "10k journal replay: {} ms, peak RSS delta {} KiB ({} -> {} KiB)",
        result.elapsed_ms, result.rss_delta_kib, result.rss_before_kib, result.rss_after_kib
    );
    assert_eq!(result.records, RECORDS);
    assert_eq!(result.tip_height, RECORDS);
    assert_eq!(result.tip_hash, previous.0.to_string_be());
    assert!(
        result.elapsed_ms < MAX_REPLAY.as_millis(),
        "10k replay exceeded {MAX_REPLAY:?}: {result:?}"
    );
    assert!(
        result.rss_delta_kib < MAX_RSS_DELTA_KIB,
        "10k replay exceeded {MAX_RSS_DELTA_KIB} KiB RSS delta: {result:?}"
    );
    Ok(())
}

fn replay_10k_subprocess_probe() -> Result<(), TestError> {
    let data_dir = PathBuf::from(
        std::env::var(DATA_DIR_ENV).map_err(|error| TestError::message(error.to_string()))?,
    );
    let result_path = PathBuf::from(
        std::env::var(RESULT_ENV).map_err(|error| TestError::message(error.to_string()))?,
    );
    let rss_before_kib = peak_rss_kib()?;
    let started = Instant::now();
    let state = NodeState::open(test_config(data_dir), None)?;
    let elapsed_ms = started.elapsed().as_millis();
    let rss_after_kib = peak_rss_kib()?;
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("10k replay produced no applied tip"))?;
    let result = ProbeResult {
        records: RECORDS,
        elapsed_ms,
        rss_before_kib,
        rss_after_kib,
        rss_delta_kib: rss_after_kib.saturating_sub(rss_before_kib),
        tip_height: tip.height,
        tip_hash: tip.hash.to_string_be(),
    };
    std::fs::write(result_path, sonic_rs::to_vec_pretty(&result)?)?;
    Ok(())
}
fn peak_rss_kib() -> Result<u64, TestError> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or_else(|| std::io::Error::other("VmHWM is missing from /proc/self/status"))?;
    let value = line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("VmHWM value is missing"))?
        .parse()?;
    Ok(value)
}
fn test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 100;
    config.chainstate_journal.max_lag_blocks = 200;
    config
}
