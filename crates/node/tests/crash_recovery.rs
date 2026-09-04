//! Process-level crash and upgrade compatibility tests for chainstate recovery.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};
use sha2::{Digest, Sha256};

const CHILD_ENV: &str = "BITCOIN_RS_CRASH_TEST_CHILD";
const DATA_DIR_ENV: &str = "BITCOIN_RS_CRASH_TEST_DATADIR";
const SCENARIO_ENV: &str = "BITCOIN_RS_CRASH_TEST_SCENARIO";

#[test]
fn sigkill_restarts_at_valid_journal_frontier() -> Result<()> {
    for scenario in ["journal", "reorg", "publication"] {
        run_sigkill_scenario(scenario)?;
    }
    Ok(())
}

#[test]
fn upgrade_matrix_falls_back_without_misclassifying_corruption() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("upgrade-node");
    let genesis = Network::Regtest.genesis_block();

    let mut old_config = test_config(data_dir.clone());
    old_config.chainstate_journal.enabled = false;
    let old = NodeState::open(old_config.clone(), None)?;
    let genesis_tip = old.apply_block(&genesis)?;
    old.publish_checkpoint()?;
    drop(old);

    let journal_dir = data_dir.join("chainstate-journal");
    std::fs::create_dir_all(&journal_dir)?;
    std::fs::write(journal_dir.join("head.json.tmp"), b"partial head")?;
    std::fs::write(
        journal_dir.join("segment-0000000000.log"),
        b"partial record",
    )?;
    std::fs::write(data_dir.join("recovery_meta.json"), b"stale v1 sidecar")?;

    let enabled = test_config(data_dir);
    let recovered = NodeState::open(enabled.clone(), None)?;
    assert_tip(&recovered, &genesis_tip)?;
    drop(recovered);

    let head_path = journal_dir.join("head.json");
    let mut head = std::fs::read(&head_path)?;
    if head.len() < 5 {
        bail!("journal head is too short for a version byte");
    }
    head[4] = u8::MAX;
    std::fs::write(&head_path, head)?;
    let version_fallback = NodeState::open(enabled.clone(), None)?;
    assert_tip(&version_fallback, &genesis_tip)?;
    drop(version_fallback);

    let generation_change = NodeState::open(old_config, None)?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let block1_tip = generation_change.apply_block(&block1)?;
    generation_change.publish_checkpoint()?;
    drop(generation_change);

    let generation_fallback = NodeState::open(enabled, None)?;
    assert_tip(&generation_fallback, &block1_tip)?;
    Ok(())
}

#[test]
#[ignore = "spawned explicitly by sigkill_restarts_at_valid_journal_frontier"]
fn crash_recovery_subprocess_worker() -> Result<()> {
    if std::env::var_os(CHILD_ENV).is_none() {
        return Ok(());
    }
    let data_dir = PathBuf::from(std::env::var(DATA_DIR_ENV)?);
    let scenario = std::env::var(SCENARIO_ENV)?;
    let config = test_config(data_dir.clone());
    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config, None)?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;

    match scenario.as_str() {
        "journal" => {
            state.apply_block(&block1)?;
        }
        "reorg" => {
            let tip1 = state.apply_block(&block1)?;
            let block2 = mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
            state.apply_block(&block2)?;
            bitcoin_rs_node::apply::disconnect_block(&state.apply_handles(), &block2)?;
        }
        "publication" => {
            state.apply_block(&genesis)?;
            state.publish_checkpoint()?;
            state.apply_block(&block1)?;
        }
        other => bail!("unknown crash scenario {other}"),
    }

    std::fs::write(data_dir.join("crash-test-ready"), scenario.as_bytes())?;
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

fn run_sigkill_scenario(scenario: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join(format!("{scenario}-node"));
    let config = test_config(data_dir.clone());
    let genesis = Network::Regtest.genesis_block();
    if scenario != "publication" {
        let base = NodeState::open(config.clone(), None)?;
        base.apply_block(&genesis)?;
        base.publish_checkpoint()?;
        drop(base);
    }

    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "crash_recovery_subprocess_worker",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(DATA_DIR_ENV, &data_dir)
        .env(SCENARIO_ENV, scenario)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn crash worker for {scenario}"))?;

    let ready = data_dir.join("crash-test-ready");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.is_file() {
        if let Some(status) = child.try_wait()? {
            let stderr = child.stderr.take().map_or_else(String::new, |stderr| {
                read_stderr(stderr).unwrap_or_default()
            });
            bail!("crash worker for {scenario} exited early ({status}): {stderr}");
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            bail!("crash worker for {scenario} did not become ready");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let status = child.wait()?;
    if status.success() {
        bail!("crash worker for {scenario} exited successfully instead of being killed");
    }

    let resumed = NodeState::open(config, None)
        .with_context(|| format!("restart after SIGKILL in {scenario}"))?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let expected_hash = block1.block_hash().0;
    let tip = resumed
        .applied_tip()
        .load_full()
        .ok_or_else(|| std::io::Error::other("restarted node has no applied tip"))?;
    assert_eq!(tip.height, 1, "scenario {scenario}");
    assert_eq!(tip.hash, expected_hash, "scenario {scenario}");
    Ok(())
}

fn read_stderr(mut stderr: std::process::ChildStderr) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut output = String::new();
    stderr.read_to_string(&mut output)?;
    Ok(output)
}

fn test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;
    config
}

fn assert_tip(state: &NodeState, expected: &bitcoin_rs_chain::TipSnapshot) -> Result<()> {
    let tip = state
        .applied_tip()
        .load_full()
        .ok_or_else(|| std::io::Error::other("recovered node has no applied tip"))?;
    assert_eq!(tip.as_ref(), expected);
    Ok(())
}

fn mined_regtest_child_at(prev_blockhash: BlockHash, height: u32) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: vec![1, u8::try_from(height)?],
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 1,
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
