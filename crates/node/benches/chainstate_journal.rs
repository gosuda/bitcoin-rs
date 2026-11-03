use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_node::test_support::TestError;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::BlockPayload;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

#[path = "../../../tools/benchmark-support/disk_backed_tmpdir.rs"]
mod disk_backed_tmpdir;

#[path = "../../../tools/benchmark-support/measured_samples.rs"]
mod measured_samples;

const RECORDS: u32 = 10_000;
const COUNTED_ROW: &str = "chainstate_journal_replay/10k";
const PROBE_ENV: &str = "BITCOIN_RS_10K_REPLAY_PROBE";
const DATA_DIR_ENV: &str = "BITCOIN_RS_10K_REPLAY_DATADIR";
const TIP_ENV: &str = "BITCOIN_RS_10K_REPLAY_TIP";

#[derive(Debug, thiserror::Error)]
enum BenchError {
    #[error(transparent)]
    TempDir(#[from] disk_backed_tmpdir::TempDirMountError),
    #[error(transparent)]
    Probe(#[from] TestError),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), BenchError> {
    measured_samples::verify_stopping_rule();
    if std::env::var_os(PROBE_ENV).is_some() {
        replay_10k_samples()?;
        return Ok(());
    }
    let mount = disk_backed_tmpdir::require_disk_backed_temp_dir()?;
    eprintln!(
        "10k journal replay: temp dir {} on {} ({}) mounted at {}",
        mount.temp_dir.display(),
        mount.fstype,
        mount.device,
        mount.mount_point
    );
    build_10k_journal()?;
    Ok(())
}

fn build_10k_journal() -> Result<(), TestError> {
    let temp = tempfile::tempdir().map_err(TestError::from)?;
    let data_dir = temp.path().join("node");
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

    let status = Command::new(std::env::current_exe().map_err(TestError::from)?)
        .env(PROBE_ENV, "1")
        .env(DATA_DIR_ENV, &data_dir)
        .env(TIP_ENV, previous.0.to_string_be())
        .stdin(Stdio::null())
        .status()
        .map_err(TestError::from)?;
    if !status.success() {
        return Err(TestError::message(format!(
            "10k replay probe exited with {status}"
        )));
    }
    Ok(())
}

fn replay_10k_samples() -> Result<(), TestError> {
    let data_dir = PathBuf::from(
        std::env::var(DATA_DIR_ENV).map_err(|error| TestError::message(error.to_string()))?,
    );
    let expected_tip =
        std::env::var(TIP_ENV).map_err(|error| TestError::message(error.to_string()))?;
    let config = test_config(data_dir);
    let rss_before_kib = peak_rss_kib()?;
    measured_samples::run(COUNTED_ROW, || {
        let config = config.clone();
        let started = Instant::now();
        let state = NodeState::open(config, None)
            .unwrap_or_else(|error| panic!("10k replay probe cannot open the journal: {error}"));
        let elapsed = started.elapsed();
        let tip = state
            .chainstate()
            .applied_tip_snapshot()
            .unwrap_or_else(|| panic!("10k replay produced no applied tip"));
        assert_eq!(tip.height, RECORDS, "10k replay reached the wrong height");
        assert_eq!(
            tip.hash.to_string_be(),
            expected_tip,
            "10k replay replayed the wrong tip"
        );
        elapsed
    });
    let rss_after_kib = peak_rss_kib()?;
    eprintln!(
        "10k journal replay: peak RSS {} KiB ({} -> {} KiB), tip {}",
        rss_after_kib.saturating_sub(rss_before_kib),
        rss_before_kib,
        rss_after_kib,
        expected_tip
    );
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
