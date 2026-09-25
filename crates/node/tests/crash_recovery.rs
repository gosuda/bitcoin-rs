//! Process-level crash and upgrade compatibility tests for chainstate recovery.

use anyhow::{Context as _, Result, bail};

use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};

use sha2::{Digest, Sha256};

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

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

/// The executed prune frontier is a durable fact, not process state: after a
/// SIGKILL the restarted node still refuses a lease over the rows the killed
/// process deleted, and those rows stay gone (#1151).
#[test]
fn pruned_frontier_survives_sigkill_and_refuses_deleted_history() -> Result<()> {
    use bitcoin_rs_storage::pruning::RetentionError;

    const FRONTIER: u32 = 12;
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("prune-node");
    let config = prune_test_config(data_dir.clone());

    crash_child("prune", &data_dir, Duration::from_mins(2))?;

    let resumed = NodeState::open(config, None).context("restart after SIGKILL in prune")?;
    let retention = resumed.chainstate().retention_handle();
    assert_eq!(
        retention.pruned_below(),
        FRONTIER,
        "the restarted authority starts from the frontier the killed process committed"
    );
    assert!(
        matches!(
            retention.acquire(FRONTIER - 1),
            Err(RetentionError::PrunedBelow {
                requested: 11,
                pruned_below: 12,
            })
        ),
        "deleted history is refused, not granted and discovered by a failed read"
    );
    retention.acquire(FRONTIER)?.release();

    let tree = resumed.chainstate().block_tree_handle();
    let hash_at = |height: u32| -> Result<Hash256> {
        let tree = tree.read();
        let tip = tree.tip().context("restarted node has no chain tip")?;
        let id = tree
            .node_at_height_from(tip.tip_id, height)
            .context("chain is shorter than the sample height")?;
        Ok(tree.node(id)?.hash)
    };
    let bodies = resumed
        .chainstate()
        .block_body_store_handle()
        .context("pruned node has a body store")?;
    assert!(
        bodies.load_block_body(5, hash_at(5)?)?.is_none(),
        "a body the killed pass deleted stays gone"
    );
    assert!(
        bodies.load_block_body(20, hash_at(20)?)?.is_some(),
        "history the frontier retains survives the restart"
    );
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
#[ignore = "spawned explicitly by the SIGKILL scenario runners in this file"]
fn crash_recovery_subprocess_worker() -> Result<()> {
    if std::env::var_os(CHILD_ENV).is_none() {
        return Ok(());
    }
    let data_dir = PathBuf::from(std::env::var(DATA_DIR_ENV)?);
    let scenario = std::env::var(SCENARIO_ENV)?;
    let genesis = Network::Regtest.genesis_block();
    // The prune scenario needs the manual prune service, which exists only
    // when a prune target is configured.
    let config = if scenario == "prune" {
        prune_test_config(data_dir.clone())
    } else {
        test_config(data_dir.clone())
    };
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
            state.chainstate().disconnect_block(&block2)?;
        }
        "publication" => {
            state.apply_block(&genesis)?;
            state.publish_checkpoint()?;
            state.apply_block(&block1)?;
        }
        "prune" => {
            // A chain long enough that the durable checkpoint leaves a real
            // deletion range below the Core reorg margin, then one manual
            // prune whose frontier must outlive the process.
            state.apply_block(&genesis)?;
            let mut previous = genesis.block_hash();
            for height in 1..=300_u32 {
                let block = mined_regtest_child_at(previous, height)?;
                state.apply_block(&block)?;
                previous = block.block_hash();
            }
            state.publish_checkpoint()?;
            let Some(service) = state.prune_service() else {
                bail!("prune scenario needs the prune service");
            };
            service
                .prune_to_height(12)
                .map_err(|error| anyhow::anyhow!("prune failed: {error}"))?;
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

    crash_child(scenario, &data_dir, Duration::from_secs(15))?;

    let resumed = NodeState::open(config, None)
        .with_context(|| format!("restart after SIGKILL in {scenario}"))?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let expected_hash = block1.block_hash().0;
    let tip = resumed
        .chainstate()
        .applied_tip_handle()
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
/// Spawns the ignored child worker for `scenario`, waits until it reports
/// readiness, then kills it and proves it died by signal rather than exiting.
fn crash_child(scenario: &str, data_dir: &Path, budget: Duration) -> Result<()> {
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "crash_recovery_subprocess_worker",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(DATA_DIR_ENV, data_dir)
        .env(SCENARIO_ENV, scenario)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn crash worker for {scenario}"))?;

    let ready = data_dir.join("crash-test-ready");
    let deadline = Instant::now() + budget;
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
    Ok(())
}

fn test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;
    config
}

/// The same configuration with the manual prune service enabled.
fn prune_test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = test_config(data_dir);
    config.storage.prune_target_mb = 1;
    config
}

fn assert_tip(state: &NodeState, expected: &bitcoin_rs_chain::TipSnapshot) -> Result<()> {
    let tip = state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("recovered node has no applied tip"))?;
    assert_eq!(tip.as_ref(), expected);
    Ok(())
}

fn mined_regtest_child_at(prev_blockhash: BlockHash, height: u32) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(coinbase_height_push(height)?),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: Network::Regtest.genesis_block().header.time + height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    while !pow_met(block.header.bits.to_consensus(), block.block_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
    }

    Ok(block)
}

/// The coinbase push that names `height`: one byte below 256, two bytes from
/// there up, so a chain past the Core reorg margin mines without an
/// overflowing narrowing conversion and without repeating a coinbase.
fn coinbase_height_push(height: u32) -> Result<Vec<u8>> {
    if height < 256 {
        return Ok(vec![1, u8::try_from(height)?]);
    }
    Ok([&[2_u8][..], &u16::try_from(height)?.to_le_bytes()].concat())
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
