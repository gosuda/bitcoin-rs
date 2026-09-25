//! Process-level crash and upgrade compatibility tests for chainstate recovery.

use anyhow::{Context as _, Result, bail};

use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};

use sha2::{Digest, Sha256};

use parking_lot::Mutex;

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
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
/// A rolled-back disconnect marker that survives the kill no longer
/// refuses startup: reopening reconciles the durable head — the disconnect
/// parent — onto the restored state, publishes a clean checkpoint, and
/// retires the marker only after that publication.
#[test]
fn torn_disconnect_replays_parent_tip() -> Result<()> {
    let (_temp, _config, state) = run_marker_scenario("disconnect-rolledback")?;
    let genesis = Network::Regtest.genesis_block();
    assert_eq!(
        state
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map(|tip| (tip.hash, tip.height)),
        Some((Hash256::from(genesis.block_hash()), 0)),
        "recovery must land on the disconnect parent the durable head certifies"
    );
    assert!(
        state.undo_store().load_disconnect_marker()?.is_none(),
        "the marker retires once the repaired state is durable"
    );
    Ok(())
}

/// A durable head that still names the disconnected block — the kill beat
/// the rollback — is certified by the head: recovery replays the restored
/// (possibly stale) state up to it and retires the marker.
#[test]
fn torn_disconnect_cold_replays_head() -> Result<()> {
    let (_temp, _config, state) = run_marker_scenario("inflight-cold")?;
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    assert_eq!(
        state
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map(|tip| (tip.hash, tip.height)),
        Some((Hash256::from(block1.block_hash()), 1)),
        "cold replay must reconstruct the chain the durable head certifies"
    );
    assert!(
        state.undo_store().load_disconnect_marker()?.is_none(),
        "the marker retires once the repaired state is durable"
    );
    Ok(())
}

/// A checkpoint published above the block the disconnect rewinds past
/// restores at or above the rewound durable head. That is a stale
/// checkpoint, not divergence: recovery rolls the restored coins back to
/// the head the batch certified — the Core `ReplayBlocks`
/// roll-back-to-fork-point shape — then warns with the recovery mode,
/// publishes a clean checkpoint, and retires the marker.
#[test]
fn torn_disconnect_checkpoint_above_head_rewinds_to_head() -> Result<()> {
    let log = SharedLog::default();
    install_log_capture(log.clone());
    let (_temp, config, state) = run_marker_scenario("disconnect-above-head")?;
    let genesis = Network::Regtest.genesis_block();
    let landed = Some((Hash256::from(genesis.block_hash()), 0));
    assert_eq!(
        state
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map(|tip| (tip.hash, tip.height)),
        landed,
        "the rewind must land on the durable head the disconnect certified"
    );
    assert!(
        state.undo_store().load_disconnect_marker()?.is_none(),
        "the marker retires once the repaired state is durable"
    );
    assert_eq!(
        state.chainstate().coin_stats_handle().snapshot().height,
        0,
        "the coin statistics must rewind to the durable head with the applied tip"
    );
    let log = log.contents();
    assert!(
        log.contains("automatic disconnect recovery replayed the certified head chain"),
        "the mandatory recovery warning must be observed: {log}"
    );
    assert!(
        log.contains(r#"mode="checkpoint-rewind""#),
        "the recovery warning must name the mode that ran: {log}"
    );
    let recovered = state
        .durable_head()
        .load()?
        .context("the durable head must survive recovery")?;
    drop(state);
    // The refusal this defect produced repeated on every restart. A second
    // restart must come up on the repaired checkpoint, with no marker and no
    // new recovery work.
    let reopened =
        NodeState::open(config, None).context("reopening after completed recovery must succeed")?;
    assert_eq!(
        reopened
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map(|tip| (tip.hash, tip.height)),
        landed,
        "the repaired state must be what the next restart restores"
    );
    assert!(
        reopened.undo_store().load_disconnect_marker()?.is_none(),
        "the retired marker must stay retired across restarts"
    );
    let after = reopened
        .durable_head()
        .load()?
        .context("the durable head must survive the second restart")?;
    assert_eq!(
        after.commit_id, recovered.commit_id,
        "recovery rewinds the applied state; it must not re-commit the durable head"
    );
    Ok(())
}

/// A checkpoint far below the durable head is a replay base, not a
/// refusal: reopening replays a whole authenticated gap one block wider
/// than a commit group, lands on the durable head, and leaves the head
/// untouched.
#[test]
fn checkpoint_fallback_replays_wide_gap_to_durable_head() -> Result<()> {
    // The durable head commits one group of 64 blocks; this gap exceeds
    // one group by one.
    const GAP_BLOCKS: u32 = 65;
    let temp = tempfile::tempdir()?;
    let mut config = test_config(temp.path().join("node"));
    config.chainstate_journal.enabled = false;
    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config.clone(), None)?;
    state.apply_block(&genesis)?;
    state.publish_checkpoint()?;
    let mut parent = genesis.block_hash();
    for height in 1..=GAP_BLOCKS {
        let block = mined_regtest_child_at(parent, height)?;
        parent = block.block_hash();
        state.apply_block(&block)?;
    }
    let before = state
        .durable_head()
        .load()?
        .context("durable head must be committed")?;
    drop(state);

    let state = NodeState::open(config, None)?;
    let landed = state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .context("recovery must publish a tip")?;
    assert_eq!(landed.hash, Hash256::from(parent));
    assert_eq!(landed.height, GAP_BLOCKS);
    let after = state
        .durable_head()
        .load()?
        .context("durable head must survive")?;
    assert_eq!(
        after.commit_id, before.commit_id,
        "recovery replays the committed gap; it must not re-commit the head"
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
#[ignore = "spawned explicitly by sigkill_restarts_at_valid_journal_frontier"]
fn crash_recovery_subprocess_worker() -> Result<()> {
    if std::env::var_os(CHILD_ENV).is_none() {
        return Ok(());
    }
    let data_dir = PathBuf::from(std::env::var(DATA_DIR_ENV)?);
    let scenario = std::env::var(SCENARIO_ENV)?;
    let config = crash_config(&scenario, data_dir.clone());
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
            state.chainstate().disconnect_block(&block2)?;
        }
        "publication" => {
            state.apply_block(&genesis)?;
            state.publish_checkpoint()?;
            state.apply_block(&block1)?;
        }
        "disconnect-rolledback" => {
            state.apply_block(&block1)?;
            // The rollback completes; the kill arrives before any
            // publication clears the marker.
            state.chainstate().disconnect_block(&block1)?;
        }
        "inflight-cold" => {
            state.apply_block(&block1)?;
            // The durable head still names this block: recovery replays
            // the certified chain onto the restored state and retires it.
            state
                .undo_store()
                .arm_disconnect(1, Hash256::from(block1.block_hash()))?;
        }
        "disconnect-above-head" => {
            state.apply_block(&block1)?;
            // The checkpoint lands above the block the disconnect then
            // rewinds past: the restored tip sits at or above the durable
            // head.
            state.publish_checkpoint()?;
            // The rollback completes; the journal is disabled, so nothing
            // clears the marker on the way down.
            state.chainstate().disconnect_block(&block1)?;
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
    let config = crash_config(scenario, data_dir.clone());
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
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("restarted node has no applied tip"))?;
    assert_eq!(tip.height, 1, "scenario {scenario}");
    assert_eq!(tip.hash, expected_hash, "scenario {scenario}");
    Ok(())
}
/// The scenario's node config. A marker that survives the kill must not be
/// disarmed by journal rewind on the way down, so the marker scenarios run
/// without the journal.
fn crash_config(scenario: &str, data_dir: PathBuf) -> NodeConfig {
    let mut config = test_config(data_dir);
    if matches!(
        scenario,
        "disconnect-rolledback" | "inflight-cold" | "disconnect-above-head"
    ) {
        config.chainstate_journal.enabled = false;
    }
    config
}

/// Build the checkpointed base, let a parked child drive the node to the
/// marker state and die to `SIGKILL`, then reopen in this process.
fn run_marker_scenario(scenario: &str) -> Result<(tempfile::TempDir, NodeConfig, NodeState)> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join(format!("{scenario}-node"));
    let config = crash_config(scenario, data_dir.clone());
    let genesis = Network::Regtest.genesis_block();
    let base = NodeState::open(config.clone(), None)?;
    base.apply_block(&genesis)?;
    base.publish_checkpoint()?;
    drop(base);

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
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        if let Some(status) = child.try_wait()? {
            let stderr = child
                .stderr
                .take()
                .map(read_stderr)
                .transpose()?
                .unwrap_or_default();
            bail!("crash worker {scenario} died before ready: {status}: {stderr}");
        }
        if Instant::now() > deadline {
            child.kill()?;
            bail!("crash worker {scenario} never became ready");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let status = child.wait()?;
    if status.success() {
        bail!("crash worker for {scenario} exited successfully instead of being killed");
    }

    let resumed = NodeState::open(config.clone(), None)
        .with_context(|| format!("reopening {scenario} after SIGKILL must complete recovery"))?;
    Ok((temp, config, resumed))
}

#[derive(Clone, Default)]
struct SharedLog(Arc<Mutex<Vec<u8>>>);

impl SharedLog {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock()).into_owned()
    }
}

impl std::io::Write for SharedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Captures `tracing` events for one assertion. Each nextest test runs in
/// its own process, so the global subscriber set here sees only this
/// test's events; under plain `cargo test` an already-set subscriber wins
/// and is ignored.
fn install_log_capture(log: SharedLog) {
    let _already_set = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || log.clone())
            .finish(),
    );
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
            script_sig: Script::from_bytes(vec![1, u8::try_from(height)?]),
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
