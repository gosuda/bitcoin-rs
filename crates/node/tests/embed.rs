use std::task::{Context, Poll, Waker};

use anyhow::{Result, bail};
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_index::query_api::HistoricalQueryError;
use bitcoin_rs_mempool::MutationOutcome;
use bitcoin_rs_node::ScriptIndexMode;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, Node, NodeConfig, NodeError};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx,
    TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_script::push_int;

const SEED_BLOCKS: u32 = 100;
const SEED_BASE_TIME: u32 = 1_296_688_603;
const SEED_BLOCK_INTERVAL: u32 = 600;
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const MEMPOOL_TX_FEE_SATS: u64 = 10_000;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn embedded_node_lifecycle_round_trip() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");

    let (seed_tip_hash, first_block_hash, first_block_bytes) = {
        let state = NodeState::open(seed_config(&data_dir), None)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        let outcome = seed_chain(&state, SEED_BLOCKS)?;
        let _ = state.publish_checkpoint()?;
        drop(state);
        outcome
    };

    let spawn_config = embedded_config(&data_dir)?;
    let reopen_config = spawn_config.clone();
    let node = block_on(Node::start(
        spawn_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;

    assert_embedded_node_readiness(&node, seed_tip_hash, first_block_hash, &first_block_bytes)?;

    let before_import = node.snapshot();
    let summary = node.chainstates_summary()?;
    assert!(summary.active_chainstate.validated);
    assert!(summary.historical_chainstate.is_none());
    let invalid_snapshot = dir.path().join("invalid-snapshot.dat");
    std::fs::write(&invalid_snapshot, b"not a UTXO snapshot")?;
    assert!(matches!(
        block_on(node.activate_assumeutxo_snapshot_file(&invalid_snapshot)),
        Err(NodeError::Snapshot(_))
    ));
    assert_eq!(node.snapshot(), before_import);

    assert_broadcast_and_lookups(&node)?;

    block_on(node.shutdown())?;

    let node = block_on(Node::start(
        reopen_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;
    assert_eq!(
        node.snapshot().tip_height,
        SEED_BLOCKS,
        "reopen must resume the seeded chain"
    );
    assert_eq!(
        node.mempool_info().txs,
        1,
        "clean restart restores the admitted spend"
    );
    let spend = seed_coinbase_spend();
    assert_eq!(
        consensus_bytes(&block_on(node.tx_by_id(spend.txid()))?),
        consensus_bytes(&spend)
    );
    block_on(node.shutdown())?;
    Ok(())
}

#[test]
fn clean_shutdown_and_reopen_preserve_rejected_fee_history() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    {
        let state = NodeState::open(seed_config(&data_dir), None)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        state.publish_checkpoint()?;
    }
    let history_path = data_dir.join("fee-estimator-history.dat");
    let rejected = [0xff; 128];
    std::fs::write(&history_path, rejected)?;

    let node = block_on(Node::start(
        embedded_config(&data_dir)?,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;
    assert_eq!(node.fee_estimate(1), None);
    block_on(node.shutdown())?;
    assert_eq!(std::fs::read(&history_path)?, rejected);
    assert!(!data_dir.join("fee-estimator-history.dat.tmp").exists());
    Ok(())
}

fn assert_embedded_node_readiness(
    node: &Node,
    seed_tip_hash: Hash256,
    first_block_hash: Hash256,
    first_block_bytes: &[u8],
) -> Result<()> {
    let snapshot = node.snapshot();
    assert_eq!(snapshot.tip_height, SEED_BLOCKS, "seeded tip must be live");
    assert_eq!(snapshot.tip_hash, seed_tip_hash);
    assert!(snapshot.epoch >= 1, "the process epoch is allocated");
    assert_eq!(
        snapshot.sequence, 0,
        "no commit has happened in this run yet"
    );
    let progress = node.sync_progress();
    assert_eq!(progress.network, Network::Regtest);
    assert_eq!(progress.blocks, SEED_BLOCKS);
    assert_eq!(progress.headers, SEED_BLOCKS);
    assert_eq!(progress.best_block_hash, seed_tip_hash);
    assert!(
        progress.verification_progress > 0.0 && progress.verification_progress <= 1.0,
        "progress must be a fraction in (0, 1], got {}",
        progress.verification_progress
    );
    assert!(
        progress.initial_block_download,
        "a 2011-dated tip keeps the node in IBD"
    );
    assert!(
        !progress.pruned && progress.prune_height.is_none(),
        "default config does not prune"
    );

    let capabilities = node.capabilities();
    assert!(
        !capabilities.capabilities.is_empty(),
        "the registry reports its compiled capabilities"
    );
    assert!(
        capabilities
            .capabilities
            .iter()
            .all(|capability| capability.compiled),
        "compiled rows are reported regardless of the runtime toggle"
    );

    let first_block = block_on(node.block_by_hash(BlockHash::from(first_block_hash)))?
        .unwrap_or_else(|| panic!("seeded block must resolve"));
    assert_eq!(first_block.block_hash(), BlockHash::from(first_block_hash));
    assert_eq!(
        consensus_bytes(&first_block),
        first_block_bytes,
        "resolved bytes must round-trip"
    );
    let unknown_hash = Hash256::from_le_bytes(&[0x07; 32]);
    assert!(
        block_on(node.block_by_hash(BlockHash::from(unknown_hash)))?.is_none(),
        "an unknown hash is a clean None"
    );
    Ok(())
}

fn assert_broadcast_and_lookups(node: &Node) -> Result<()> {
    let spend = seed_coinbase_spend();
    let spend_txid = spend.txid();
    let mutation = block_on(node.broadcast(spend))?;
    assert_eq!(mutation.len(), 1, "one admission, one change");
    assert_eq!(
        mutation.changes[0].outcome,
        MutationOutcome::Accepted,
        "the funded spend must be accepted"
    );
    assert_eq!(
        mutation.sequence_of(0),
        Some(1),
        "first change of the run carries mempool sequence 1"
    );

    let read_back = block_on(node.tx_by_id(spend_txid))?;
    assert_eq!(read_back.txid(), spend_txid);
    assert_eq!(node.mempool_info().txs, 1, "the spend sits in the pool");

    assert_eq!(
        node.fee_estimate(6),
        None,
        "an estimator without history must refuse, not fabricate"
    );

    let unknown_txid = Txid(Hash256::from_le_bytes(&[0xAA; 32]));
    match block_on(node.tx_by_id(unknown_txid)) {
        Err(NodeError::Unavailable(message)) => {
            assert!(
                message.contains("txindex"),
                "the gate must name the missing capability: {message}"
            );
        }
        other => bail!("expected the TxLookup gate error, got {other:?}"),
    }
    Ok(())
}

fn seed_config(data_dir: &std::path::Path) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir.to_path_buf();
    config.p2p.listen.clear();
    config
}

fn embedded_config(data_dir: &std::path::Path) -> Result<NodeConfig> {
    let mut config = seed_config(data_dir);
    let rpc_bind: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    config.rpc.bind = rpc_bind;
    Ok(config)
}

fn historical_config(data_dir: &std::path::Path) -> Result<NodeConfig> {
    let mut config = seed_config(data_dir);
    config.indexes.txindex = true;
    config.indexes.script_index = ScriptIndexMode::Full;
    let rpc_bind: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    config.rpc.bind = rpc_bind;
    Ok(config)
}

fn wait_historical_transaction(
    node: &Node,
    txid: &Txid,
) -> Result<bitcoin_rs_index::query_api::AtPrefix<Option<(u32, Tx)>>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match node.transaction_at_prefix(txid) {
            Ok(answer) => return Ok(answer),
            Err(HistoricalQueryError::Retry | HistoricalQueryError::Unavailable(_)) => {}
            Err(HistoricalQueryError::Storage(message)) => {
                bail!("historical index storage error while waiting: {message}")
            }
        }
        if std::time::Instant::now() >= deadline {
            bail!("historical index did not become ready in 60s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn embedded_node_historical_prefix_queries() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");

    {
        let state = NodeState::open(seed_config(&data_dir), None)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        let _ = seed_chain(&state, SEED_BLOCKS)?;
        let _ = state.publish_checkpoint()?;
    }

    let node = block_on(Node::start(
        historical_config(&data_dir)?,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;

    let known_tx = seed_coinbase(1);
    let known_txid = known_tx.txid();
    let known_outpoint = OutPoint::new(known_txid, 0);
    let script = ScriptHash::from_script_bytes(&[0x51]);

    let ready = wait_historical_transaction(&node, &known_txid)?;
    assert_eq!(ready.prefix.floor, 0, "seeded chain covers from genesis");
    assert_eq!(ready.prefix.height, SEED_BLOCKS);
    assert_eq!(ready.prefix.hash, node.snapshot().tip_hash);

    let at = node.transaction_at_prefix(&known_txid)?;
    assert_eq!(at.prefix.floor, 0);
    assert_eq!(at.prefix.height, SEED_BLOCKS);
    assert_eq!(at.prefix.hash, node.snapshot().tip_hash);
    let Some((height, tx)) = at.answer else {
        bail!("known seed coinbase must resolve historically")
    };
    assert_eq!(height, 1);
    assert!(at.prefix.floor <= height && height <= at.prefix.height);
    assert_eq!(consensus_bytes(&tx), consensus_bytes(&known_tx));

    let unknown_txid = Txid(Hash256::from_le_bytes(&[0xAA; 32]));
    let absent = node.transaction_at_prefix(&unknown_txid)?;
    assert!(absent.answer.is_none(), "unknown txid is a scoped None");
    assert_eq!(absent.prefix.height, SEED_BLOCKS);
    assert_eq!(absent.prefix.hash, node.snapshot().tip_hash);

    let history = node.script_history_at_prefix(script)?;
    assert_eq!(history.prefix.floor, 0);
    assert_eq!(history.prefix.height, SEED_BLOCKS);
    assert_eq!(history.prefix.hash, node.snapshot().tip_hash);
    assert!(
        history
            .answer
            .history
            .iter()
            .any(|record| record.height == 1),
        "history must contain the height-1 funding"
    );
    assert!(
        history
            .answer
            .history
            .iter()
            .all(|record| history.prefix.floor <= record.height
                && record.height <= history.prefix.height),
        "history rows stay inside the covered prefix"
    );

    let spend = node.spender_at_prefix(known_outpoint)?;
    assert_eq!(spend.prefix.height, SEED_BLOCKS);
    assert_eq!(spend.prefix.hash, node.snapshot().tip_hash);
    assert!(
        spend.answer.is_none(),
        "unspent seed outpoint has no spend in range"
    );

    let via_index = block_on(node.tx_by_id(known_txid))?;
    assert_eq!(consensus_bytes(&via_index), consensus_bytes(&known_tx));

    block_on(node.shutdown())?;
    Ok(())
}

fn seed_chain(state: &NodeState, count: u32) -> Result<(Hash256, Hash256, Vec<u8>)> {
    let applied = state.chainstate().applied_tip_reader();
    let mut tip = applied
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("genesis must publish an applied tip"))?;
    let mut first_block: Option<(Hash256, Vec<u8>)> = None;
    for height in 1..=count {
        let coinbase = seed_coinbase(height);
        let mut block = Block {
            header: bitcoin_rs_primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| anyhow::anyhow!("seed block must have a merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            block.clone(),
        ))?;
        tip = applied
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("applied tip must exist after apply"))?;
        assert_eq!(tip.height, height, "seed block must become the tip");
        if height == 1 {
            first_block = Some((Hash256::from(block.block_hash()), consensus_bytes(&block)));
        }
    }
    let (first_hash, first_bytes) =
        first_block.ok_or_else(|| anyhow::anyhow!("at least one block must be seeded"))?;
    Ok((tip.hash, first_hash, first_bytes))
}

fn seed_coinbase(height: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: [push_int(i64::from(height)), push_int(0)].concat().into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: vec![0x51].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn seed_coinbase_spend() -> Tx {
    let seed_coinbase = seed_coinbase(1);
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - MEMPOOL_TX_FEE_SATS),
            script_pubkey: [vec![0x00, 0x14], vec![0x11; 20]].concat().into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

#[test]
fn dropped_node_releases_services_and_datadir_for_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");

    let (_seed_tip_hash, _first, _bytes) = {
        let state = NodeState::open(seed_config(&data_dir), None)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        let outcome = seed_chain(&state, 1)?;
        let _ = state.publish_checkpoint()?;
        drop(state);
        outcome
    };
    let current_path = data_dir.join("chainstate-checkpoints").join("CURRENT");
    let seeded_current = std::fs::read(&current_path)?;

    {
        let node = block_on(Node::start(
            embedded_config(&data_dir)?,
            bitcoin_rs_node::RuntimeInputs::default(),
        ))?;
        assert_eq!(node.snapshot().tip_height, 1);
    }
    assert_eq!(
        std::fs::read(&current_path)?,
        seeded_current,
        "a dropped node must not publish a clean-shutdown checkpoint"
    );

    let resumed = NodeState::open(seed_config(&data_dir), None)?;
    let tip = resumed
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("seeded checkpoint must restore an applied tip"));
    assert_eq!(tip.height, 1);
    drop(resumed);

    Ok(())
}

#[test]
fn startup_failure_after_state_open_rolls_back_releases_state() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let held_dir = dir.path().join("held");
    let failed_dir = dir.path().join("failed");

    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?;
    drop(probe);

    let mut held_config = embedded_config(&held_dir)?;
    held_config.rpc.bind = port;
    let held = block_on(Node::start(
        held_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;

    let mut failed_config = embedded_config(&failed_dir)?;
    failed_config.rpc.bind = port;
    match block_on(Node::start(
        failed_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    )) {
        Err(NodeError::Startup(message)) => {
            let lowered = message.to_lowercase();
            assert!(
                lowered.contains("address")
                    || lowered.contains("bind")
                    || lowered.contains("10048")
                    || lowered.contains("주소"),
                "the failure should name the bind conflict, got: {message}"
            );
        }
        other => bail!(
            "expected a startup failure on the held port, got {:?}",
            other.err()
        ),
    }

    let resumed = NodeState::open(seed_config(&failed_dir), None)?;
    drop(resumed);

    block_on(held.shutdown())?;
    Ok(())
}
