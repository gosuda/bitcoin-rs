use bitcoin_rs_node::test_support::TestError;

type Result<T, E = TestError> = core::result::Result<T, E>;

use bitcoin_rs_execution::chain::regtest_fixture;
use bitcoin_rs_node::{Network, NodeConfig, NodeOpenError, state::NodeState};
use bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY;
use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageBackend};

use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Witness,
};

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const CHILD_ENV: &str = "BITCOIN_RS_CRASH_TEST_CHILD";
const DATA_DIR_ENV: &str = "BITCOIN_RS_CRASH_TEST_DATADIR";
const SCENARIO_ENV: &str = "BITCOIN_RS_CRASH_TEST_SCENARIO";
const CRASH_TEST_BACKEND_ENV: &str = "BITCOIN_RS_CRASH_TEST_BACKEND";

#[test]
fn sigkill_restarts_at_the_engine_commit_frontier() -> Result<()> {
    for scenario in ["apply", "reorg", "publication"] {
        run_sigkill_scenario(scenario)?;
    }
    Ok(())
}
#[test]
fn torn_disconnect_replays_parent_tip() -> Result<()> {
    let (_temp, _config, state) = run_marker_scenario("disconnect-rolledback")?;
    let genesis = Network::Regtest.genesis_block();
    assert_eq!(
        state
            .chainstate()
            .applied_tip_snapshot()
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

#[test]
fn torn_disconnect_cold_replays_head() -> Result<()> {
    let (_temp, _config, state) = run_marker_scenario("inflight-cold")?;
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    assert_eq!(
        state
            .chainstate()
            .applied_tip_snapshot()
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

#[test]
fn torn_disconnect_checkpoint_above_head_rewinds_to_head() -> Result<()> {
    let (_temp, config, state) = run_marker_scenario("disconnect-above-head")?;
    let genesis = Network::Regtest.genesis_block();
    let landed = Some((Hash256::from(genesis.block_hash()), 0));
    assert_eq!(
        state
            .chainstate()
            .applied_tip_snapshot()
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
    let recovered = state
        .durable_head()
        .load()?
        .ok_or_else(|| TestError::message("the durable head must survive recovery"))?;
    drop(state);
    let reopened = NodeState::open(config, None)?;
    assert_eq!(
        reopened
            .chainstate()
            .applied_tip_snapshot()
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
        .ok_or_else(|| TestError::message("the durable head must survive the second restart"))?;
    assert_eq!(
        after.commit_id, recovered.commit_id,
        "recovery rewinds the applied state; it must not re-commit the durable head"
    );
    Ok(())
}

#[test]
fn checkpoint_fallback_replays_wide_gap_to_durable_head() -> Result<()> {
    const GAP_BLOCKS: u32 = 65;
    let temp = tempfile::tempdir()?;
    let config = test_config(temp.path().join("node"));
    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config.clone(), None)?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    state.publish_checkpoint()?;
    let mut parent = genesis.block_hash();
    for height in 1..=GAP_BLOCKS {
        let block = mined_regtest_child_at(parent, height)?;
        parent = block.block_hash();
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block,
        ))?;
    }
    let before = state
        .durable_head()
        .load()?
        .ok_or_else(|| TestError::message("durable head must be committed"))?;
    drop(state);

    let state = NodeState::open(config, None)?;
    let landed = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| TestError::message("recovery must publish a tip"))?;
    assert_eq!(landed.hash, Hash256::from(parent));
    assert_eq!(landed.height, GAP_BLOCKS);
    let after = state
        .durable_head()
        .load()?
        .ok_or_else(|| TestError::message("durable head must survive"))?;
    assert_eq!(
        after.commit_id, before.commit_id,
        "recovery replays the committed gap; it must not re-commit the head"
    );
    Ok(())
}

#[test]
fn pruned_frontier_survives_sigkill_and_preserves_boundary() -> Result<()> {
    const FRONTIER: u32 = 12;
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("prune-node");
    let config = prune_test_config(data_dir.clone());

    crash_child("prune", &data_dir, Duration::from_mins(2))?;

    let resumed = NodeState::open(config, None)?;
    let tree = resumed.chainstate().block_tree_handle();
    let hash_at = |height: u32| -> Result<Hash256> {
        let tree = tree.read();
        let tip = tree
            .tip()
            .ok_or_else(|| TestError::message("restarted node has no chain tip"))?;
        let id = tree
            .node_at_height_from(tip.tip_id, height)
            .ok_or_else(|| TestError::message("chain is shorter than the sample height"))?;
        Ok(tree.node(id)?.hash)
    };
    let bodies = resumed
        .chainstate()
        .block_body_store_handle()
        .ok_or_else(|| TestError::message("pruned node has a body store"))?;
    let deleted_height = FRONTIER - 7;
    assert!(
        bodies
            .load_block_body(deleted_height, hash_at(deleted_height)?)?
            .is_none(),
        "a body the killed pass deleted stays gone"
    );
    let retained_height = FRONTIER + 8;
    assert!(
        bodies
            .load_block_body(retained_height, hash_at(retained_height)?)?
            .is_some(),
        "history the frontier retains survives the restart"
    );
    Ok(())
}

#[test]
fn upgrade_matrix_falls_back_without_misclassifying_corruption() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("upgrade-node");
    let genesis = Network::Regtest.genesis_block();

    let old_config = test_config(data_dir.clone());
    let old = NodeState::open(old_config.clone(), None)?;
    let genesis_tip = old.apply_block(
        &bitcoin_rs_consensus::primitives::BlockImage::from_local(genesis.clone()),
    )?;
    old.publish_checkpoint()?;
    drop(old);

    std::fs::write(data_dir.join("recovery_meta.json"), b"stale v1 sidecar")?;

    let enabled = test_config(data_dir.clone());
    let recovered = NodeState::open(enabled.clone(), None)?;
    assert_tip(&recovered, &genesis_tip)?;
    drop(recovered);

    let generation_change = NodeState::open(old_config, None)?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let block1_tip = generation_change.apply_block(
        &bitcoin_rs_consensus::primitives::BlockImage::from_local(block1),
    )?;
    generation_change.publish_checkpoint()?;
    drop(generation_change);

    let generation_fallback = NodeState::open(enabled.clone(), None)?;
    assert_tip(&generation_fallback, &block1_tip)?;
    drop(generation_fallback);

    corrupt_durable_head_row(&data_dir.join("chainstate"), enabled.storage.backend)?;
    let refusal = NodeState::open(enabled, None)
        .err()
        .ok_or_else(|| TestError::message("a corrupt durable head row must refuse startup"))?;
    assert!(
        matches!(
            &refusal,
            NodeOpenError::Storage(
                bitcoin_rs_storage::StorageError::IncompatibleData(message),
            ) if message.contains("refusing to treat it as absent"),
        ),
        "a corrupt durable head row must be refused as unreadable, not treated as absent: {refusal:#}"
    );
    Ok(())
}

#[test]
#[ignore = "spawned explicitly by the SIGKILL scenario runners in this file"]
fn crash_recovery_subprocess_worker() -> Result<()> {
    if std::env::var_os(CHILD_ENV).is_none() {
        return Ok(());
    }
    let data_dir = PathBuf::from(
        std::env::var(DATA_DIR_ENV).map_err(|error| TestError::message(error.to_string()))?,
    );
    let scenario =
        std::env::var(SCENARIO_ENV).map_err(|error| TestError::message(error.to_string()))?;
    let config = if scenario == "prune" {
        prune_test_config(data_dir.clone())
    } else {
        crash_config(&scenario, data_dir.clone())
    };
    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config, None)?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;

    match scenario.as_str() {
        "apply" => {
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block1,
            ))?;
        }
        "reorg" => {
            let tip1 = state.apply_block(
                &bitcoin_rs_consensus::primitives::BlockImage::from_local(block1),
            )?;
            let block2 = mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block2.clone(),
            ))?;
            state.chainstate().disconnect_block(&block2)?;
        }
        "publication" => {
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis,
            ))?;
            state.publish_checkpoint()?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block1,
            ))?;
        }
        "disconnect-rolledback" => {
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block1.clone(),
            ))?;
            state.chainstate().disconnect_block(&block1)?;
        }
        "inflight-cold" => {
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block1.clone(),
            ))?;
            state
                .undo_store()
                .arm_disconnect(1, Hash256::from(block1.block_hash()))?;
        }
        "disconnect-above-head" => {
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                block1.clone(),
            ))?;
            state.publish_checkpoint()?;
            state.chainstate().disconnect_block(&block1)?;
        }
        "prune" => {
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                genesis.clone(),
            ))?;
            let mut previous = genesis.block_hash();
            for height in 1..=300_u32 {
                let block = mined_regtest_child_at(previous, height)?;
                state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                    block.clone(),
                ))?;
                previous = block.block_hash();
            }
            state.publish_checkpoint()?;
            let Some(service) = state.prune_service() else {
                return Err(TestError::message("prune scenario needs the prune service"));
            };
            service.prune_to_height(12)?;
        }
        "window-commit" => {
            run_window_commit_worker(&state, &data_dir)?;
        }
        other => {
            return Err(TestError::message(format!(
                "unknown crash scenario {other}"
            )));
        }
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
        base.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            genesis.clone(),
        ))?;
        base.publish_checkpoint()?;
        drop(base);
    }

    spawn_and_kill_worker(scenario, &data_dir, Duration::from_secs(15))?;

    let resumed = NodeState::open(config, None)?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let expected_hash = block1.block_hash().0;
    let tip = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("restarted node has no applied tip"))?;
    assert_eq!(tip.height, 1, "scenario {scenario}");
    assert_eq!(tip.hash, expected_hash, "scenario {scenario}");
    Ok(())
}
fn spawn_and_kill_worker(scenario: &str, data_dir: &Path, ready_after: Duration) -> Result<()> {
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
        .spawn()?;

    let ready = data_dir.join("crash-test-ready");
    let deadline = Instant::now() + ready_after;
    while !ready.exists() {
        if let Some(status) = child.try_wait()? {
            let stderr = child
                .stderr
                .take()
                .map(read_stderr)
                .transpose()?
                .unwrap_or_default();
            return Err(TestError::message(format!(
                "crash worker {scenario} died before ready: {status}: {stderr}"
            )));
        }
        if Instant::now() > deadline {
            child.kill()?;
            let _ = child.wait();
            return Err(TestError::message(format!(
                "crash worker for {scenario} did not become ready"
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let status = child.wait()?;
    if status.success() {
        return Err(TestError::message(format!(
            "crash worker for {scenario} exited successfully instead of being killed"
        )));
    }
    Ok(())
}

fn crash_config(_scenario: &str, data_dir: PathBuf) -> NodeConfig {
    test_config(data_dir)
}

fn run_marker_scenario(scenario: &str) -> Result<(tempfile::TempDir, NodeConfig, NodeState)> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join(format!("{scenario}-node"));
    let config = crash_config(scenario, data_dir.clone());
    let genesis = Network::Regtest.genesis_block();
    let base = NodeState::open(config.clone(), None)?;
    base.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis,
    ))?;
    base.publish_checkpoint()?;
    drop(base);

    spawn_and_kill_worker(scenario, &data_dir, Duration::from_secs(30))?;

    let resumed = NodeState::open(config.clone(), None)?;
    Ok((temp, config, resumed))
}

fn read_stderr(mut stderr: std::process::ChildStderr) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut output = String::new();
    stderr.read_to_string(&mut output)?;
    Ok(output)
}
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
        .spawn()?;

    let ready = data_dir.join("crash-test-ready");
    let deadline = Instant::now() + budget;
    while !ready.is_file() {
        if let Some(status) = child.try_wait()? {
            let stderr = child.stderr.take().map_or_else(String::new, |stderr| {
                read_stderr(stderr).unwrap_or_default()
            });
            return Err(TestError::message(format!(
                "crash worker for {scenario} exited early ({status}): {stderr}"
            )));
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err(TestError::message(format!(
                "crash worker for {scenario} did not become ready"
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let status = child.wait()?;
    if status.success() {
        return Err(TestError::message(format!(
            "crash worker for {scenario} exited successfully instead of being killed"
        )));
    }
    Ok(())
}
fn crash_test_backend(
    default: bitcoin_rs_storage::StorageBackend,
) -> bitcoin_rs_storage::StorageBackend {
    let value = match std::env::var(CRASH_TEST_BACKEND_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return default,
        Err(error) => panic!("invalid {CRASH_TEST_BACKEND_ENV}: {error}"),
    };
    let backend: bitcoin_rs_storage::StorageBackend = match value.parse() {
        Ok(backend) => backend,
        Err(error) => panic!("invalid {CRASH_TEST_BACKEND_ENV} {value:?}: {error}"),
    };
    assert!(
        backend.is_compiled_in(),
        "BITCOIN_RS_CRASH_TEST_BACKEND {value:?} is not compiled into this test binary"
    );
    backend
}
fn corrupt_durable_head_row(chainstate_dir: &Path, backend: StorageBackend) -> Result<()> {
    fn flip_payload_bit<S: KvStore>(store: &S) -> Result<()> {
        let frame = store
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?
            .ok_or_else(|| TestError::message("the durable head row must exist"))?;
        let mut corrupted = frame;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x80;
        store.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &corrupted)?;
        Ok(())
    }
    match backend {
        StorageBackend::RocksDb => {
            flip_payload_bit(&bitcoin_rs_storage::RocksDbStore::open_with_cache(
                chainstate_dir,
                0,
            )?)?;
        }
        #[cfg(feature = "surrealkv")]
        StorageBackend::SurrealKv => {
            flip_payload_bit(&bitcoin_rs_storage::SurrealKvStore::open_with_cache(
                chainstate_dir,
                0,
            )?)?;
        }
        #[cfg(not(feature = "surrealkv"))]
        StorageBackend::SurrealKv => {
            return Err(TestError::message(
                "surrealkv is not compiled into this test binary",
            ));
        }
        #[cfg(feature = "mdbx")]
        StorageBackend::Mdbx => {
            flip_payload_bit(&bitcoin_rs_storage::MdbxStore::open_with_cache(
                chainstate_dir,
                0,
            )?)?;
        }
        #[cfg(not(feature = "mdbx"))]
        StorageBackend::Mdbx => {
            return Err(TestError::message(
                "mdbx is not compiled into this test binary",
            ));
        }
    }
    Ok(())
}

fn test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    config
}

fn prune_test_config(data_dir: PathBuf) -> NodeConfig {
    let mut config = test_config(data_dir);
    config.storage.prune_target_mb = 1;
    config
}

fn assert_tip(
    state: &NodeState,
    expected: &bitcoin_rs_execution::chain::TipSnapshot,
) -> Result<()> {
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("recovered node has no applied tip"))?;
    assert_eq!(tip.as_ref(), expected);
    Ok(())
}

fn mined_regtest_child_at(prev_blockhash: BlockHash, height: u32) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(coinbase_height_push(height)?),
            sequence: Sequence::MAX,
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
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;

    Ok(block)
}

fn coinbase_height_push(height: u32) -> Result<Vec<u8>> {
    let mut bytes = height.to_le_bytes().to_vec();
    while bytes.len() > 1 && bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    let mut push = vec![u8::try_from(bytes.len())?];
    push.extend(bytes);
    Ok(push)
}

const WINDOW_OUTPUT_SAT: u64 = 1;

struct BlockCommitUntilKilled {
    marker: PathBuf,
    height: u32,
}

impl bitcoin_rs_storage::commit::CommitFault for BlockCommitUntilKilled {
    fn before_commit(
        &self,
        prefix: &bitcoin_rs_storage::commit::AcceptedPrefix,
    ) -> core::result::Result<(), bitcoin_rs_storage::CommitError> {
        if prefix.next_head.height != self.height {
            return Ok(());
        }
        std::fs::write(&self.marker, b"window-commit").map_err(|error| {
            bitcoin_rs_storage::CommitError::Storage(bitcoin_rs_storage::StorageError::backend(
                error.to_string(),
            ))
        })?;
        loop {
            std::thread::sleep(Duration::from_mins(1));
        }
    }
}

fn window_spend_tx(previous_output: OutPoint) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(WINDOW_OUTPUT_SAT),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    }
}

fn mined_block_with_txs(prev_blockhash: BlockHash, height: u32, txs: Vec<Tx>) -> Result<Block> {
    let mut block = mined_regtest_child_at(prev_blockhash, height)?;
    block.txs.extend(txs);
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

fn window_commit_blocks() -> Result<(Vec<Block>, Vec<Block>, Vec<Block>)> {
    let mut parent = Network::Regtest.genesis_block().block_hash();
    let mut prefix = Vec::new();
    for height in 1..=100_u32 {
        let block = mined_regtest_child_at(parent, height)?;
        parent = block.block_hash();
        prefix.push(block);
    }
    let funding = OutPoint::new(prefix[0].txs[0].txid(), 0);
    let a1 = window_spend_tx(funding);
    let a1_out = OutPoint::new(a1.txid(), 0);
    let block101 = mined_block_with_txs(parent, 101, vec![a1])?;
    let a2 = window_spend_tx(a1_out);
    let a2_out = OutPoint::new(a2.txid(), 0);
    let a3 = window_spend_tx(a2_out);
    let a3_out = OutPoint::new(a3.txid(), 0);
    let block102 = mined_block_with_txs(block101.block_hash(), 102, vec![a2, a3])?;
    let b1 = window_spend_tx(a3_out);
    let block103 = mined_block_with_txs(block102.block_hash(), 103, vec![b1])?;
    Ok((prefix, vec![block101, block102], vec![block103]))
}

fn run_window_commit_worker(state: &NodeState, data_dir: &Path) -> Result<()> {
    let (prefix, window_a, window_b) = window_commit_blocks()?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        Network::Regtest.genesis_block(),
    ))?;
    for block in &prefix {
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block.clone(),
        ))?;
    }
    let chain = state.chainstate();
    let window_a_images: Vec<_> = window_a
        .iter()
        .cloned()
        .map(bitcoin_rs_consensus::primitives::BlockImage::from_local)
        .collect();
    let window_a_refs: Vec<_> = window_a_images.iter().collect();
    chain
        .apply_window(&window_a_refs)
        .map_err(|error| TestError::message(format!("{error:?}")))?;

    chain.set_commit_fault(std::sync::Arc::new(BlockCommitUntilKilled {
        marker: data_dir.join("crash-test-ready"),
        height: 103,
    }));
    let window_b_images: Vec<_> = window_b
        .iter()
        .cloned()
        .map(bitcoin_rs_consensus::primitives::BlockImage::from_local)
        .collect();
    let window_b_refs: Vec<_> = window_b_images.iter().collect();
    chain
        .apply_window(&window_b_refs)
        .map_err(|error| TestError::message(format!("{error:?}")))?;
    Ok(())
}

fn coin_records(
    state: &NodeState,
    txids: &[bitcoin_rs_consensus::primitives::Txid],
) -> Result<Vec<Option<Vec<u8>>>> {
    let coins = state.coins();
    txids
        .iter()
        .map(|txid| {
            let key = bitcoin_rs_storage::CoinKey(txid.0.to_le_bytes());
            let record = coins
                .get(&key)
                .map_err(|error| TestError::message(error.to_string()))?;
            Ok(record.map(|bytes| bytes.to_vec()))
        })
        .collect()
}

// RCV-04
#[test]
fn sigkill_during_window_commit_restarts_to_sequential_prefix() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data_dir = temp.path().join("window-commit-node");
    spawn_and_kill_worker("window-commit", &data_dir, Duration::from_secs(120))?;

    let resumed = NodeState::open(crash_config("window-commit", data_dir), None)?;
    let oracle = NodeState::open(
        crash_config("window-commit", temp.path().join("oracle-node")),
        None,
    )?;
    let (prefix, window_a, window_b) = window_commit_blocks()?;
    let touched: Vec<_> = prefix
        .iter()
        .chain(&window_a)
        .chain(&window_b)
        .flat_map(|block| {
            block
                .txs
                .iter()
                .map(bitcoin_rs_consensus::primitives::Tx::txid)
        })
        .collect();
    let genesis =
        bitcoin_rs_consensus::primitives::BlockImage::from_local(Network::Regtest.genesis_block());
    oracle.apply_block(&genesis)?;
    for block in prefix.iter().chain(&window_a) {
        oracle.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block.clone(),
        ))?;
    }

    let last_committed = window_a
        .last()
        .ok_or_else(|| std::io::Error::other("window A has blocks"))?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("restarted node has no applied tip"))?;
    assert_eq!(
        (resumed_tip.height, resumed_tip.hash),
        (102, last_committed.block_hash().0),
        "a window killed inside its commit must leave the last durable window as the tip"
    );
    assert_eq!(
        coin_records(&resumed, &touched)?,
        coin_records(&oracle, &touched)?,
        "restarted coins must equal sequential execution of the durable prefix"
    );
    Ok(())
}
