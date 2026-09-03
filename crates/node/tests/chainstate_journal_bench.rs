//! Opt-in 10,000-record journal replay performance and memory gate.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_consensus::block_subsidy;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

#[test]
#[ignore = "10k record performance gate; run explicitly before release"]
fn replay_10k_records_with_bounded_time_and_memory() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("node");
    let result_path = temp.path().join("probe.json");
    let config = test_config(data_dir.clone());
    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config, None)?;
    state.apply_block(&genesis)?;
    state.publish_checkpoint()?;

    let mut previous = genesis.block_hash();
    for height in 1..=RECORDS {
        let block = mined_regtest_child_at(previous, height)?;
        previous = block.block_hash();
        state.apply_block(&block)?;
    }
    drop(state);

    let status = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "replay_10k_subprocess_probe",
            "--nocapture",
        ])
        .env(PROBE_ENV, "1")
        .env(DATA_DIR_ENV, &data_dir)
        .env(RESULT_ENV, &result_path)
        .stdin(Stdio::null())
        .status()
        .context("run isolated 10k replay probe")?;
    if !status.success() {
        bail!("10k replay probe exited with {status}");
    }

    let result: ProbeResult = serde_json::from_slice(&std::fs::read(&result_path)?)?;
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

#[test]
#[ignore = "spawned explicitly by replay_10k_records_with_bounded_time_and_memory"]
fn replay_10k_subprocess_probe() -> Result<()> {
    if std::env::var_os(PROBE_ENV).is_none() {
        return Ok(());
    }
    let data_dir = PathBuf::from(std::env::var(DATA_DIR_ENV)?);
    let result_path = PathBuf::from(std::env::var(RESULT_ENV)?);
    let rss_before_kib = peak_rss_kib()?;
    let started = Instant::now();
    let state = NodeState::open(test_config(data_dir), None)?;
    let elapsed_ms = started.elapsed().as_millis();
    let rss_after_kib = peak_rss_kib()?;
    let tip = state
        .applied_tip()
        .load_full()
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
    std::fs::write(result_path, serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}

fn peak_rss_kib() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")
        .context("read Linux /proc/self/status for peak RSS")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or_else(|| std::io::Error::other("VmHWM is missing from /proc/self/status"))?;
    line.split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("VmHWM value is missing"))?
        .parse()
        .context("parse VmHWM KiB")
}

fn test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir;
    config.p2p_listen.clear();
    config.chainstate_journal.blocks = 100;
    config.chainstate_journal.max_lag_blocks = 200;
    config
}

fn mined_regtest_child_at(prev_blockhash: BlockHash, height: u32) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: bip34_height_script(height),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: block_subsidy(height, Network::Regtest.subsidy_halving_interval()),
            script_pubkey: Vec::new(),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: Network::Regtest.genesis_block().header.time + height,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    while !pow_met(block.header.bits, block.block_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
    }
    Ok(block)
}

fn bip34_height_script(height: u32) -> Vec<u8> {
    let mut value = height;
    let mut encoded = Vec::new();
    while value != 0 {
        encoded.push(value.to_le_bytes()[0]);
        value >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    let mut script = Vec::with_capacity(encoded.len() + 1);
    script.push(u8::try_from(encoded.len()).unwrap_or(u8::MAX));
    script.extend(encoded);
    script
}

fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if leaves.is_empty() {
        return None;
    }
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair));
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = u8::try_from(bits >> 24).unwrap_or(0);
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let low = usize::from(exponent - 3);
    let window =
        u32::from(bytes[low]) | u32::from(bytes[low + 1]) << 8 | u32::from(bytes[low + 2]) << 16;
    window <= mantissa && bytes[usize::from(exponent)..].iter().all(|&byte| byte == 0)
}
