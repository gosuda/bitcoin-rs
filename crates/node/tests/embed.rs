//! Embedded node lifecycle: start → observe → broadcast → read back →
//! shutdown → reopen, all in process.
//!
//! This is the executable contract for `docs/contracts/embedding.md`: one
//! `Node` on the caller's (here: std-only) executor, no daemon subprocess,
//! no reachable RPC socket — the JSON-RPC listener is bound ephemeral and
//! never contacted.
use std::task::{Context, Poll, Waker};

use anyhow::{Result, bail};
use bitcoin_rs_mempool::MutationOutcome;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, Node, NodeConfig, NodeError};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};

const SEED_BLOCKS: u32 = 100;
const SEED_BASE_TIME: u32 = 1_296_688_603;
const SEED_BLOCK_INTERVAL: u32 = 600;
const REGTEST_BITS: u32 = 0x207f_ffff;
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const MEMPOOL_TX_FEE_SATS: u64 = 10_000;

/// Polls an embedding future to completion without a runtime.
///
/// `Node::start` and `Node::shutdown` drive the node's own threads
/// synchronously, so they never park; one poll finishes the work. This
/// helper exists so the test needs no async executor dependency.
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

    // --- seed chain state on the same datadir through the public types ------
    // The height-1 coinbase (anyone-can-spend OP_1) becomes spendable by the
    // next block once the tip reaches height 100 — the same fixture shape
    // the mining e2e test uses.
    let (seed_tip_hash, first_block_hash, first_block_bytes) = {
        let state = NodeState::open(seed_config(&data_dir), None)?;
        state.apply_block(&Network::Regtest.genesis_block())?;
        let outcome = seed_chain(&state, SEED_BLOCKS)?;
        state.publish_checkpoint()?;
        drop(state);
        outcome
    };

    // --- start an embedded node on the seeded datadir -----------------------
    let spawn_config = embedded_config(&data_dir)?;
    let reopen_config = spawn_config.clone();
    let node = block_on(Node::start(
        spawn_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;

    assert_embedded_node_readiness(&node, seed_tip_hash, first_block_hash, &first_block_bytes)?;

    assert_broadcast_and_lookups(&node)?;

    // Consuming shutdown: ordered drain and clean checkpoint, exactly once.
    block_on(node.shutdown())?;

    // Reopen the same datadir: the clean checkpoint resumes without a daemon.
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
        0,
        "the mempool starts empty after restart"
    );
    block_on(node.shutdown())?;
    Ok(())
}

/// Readiness, sync progress, capability snapshot, and the typed block
/// read-back for the first seeded block — the observational half of the
/// embedded lifecycle that must hold the moment `Node::start` returns.
fn assert_embedded_node_readiness(
    node: &Node,
    seed_tip_hash: Hash256,
    first_block_hash: Hash256,
    first_block_bytes: &[u8],
) -> Result<()> {
    // Readiness: the snapshot resumes the seeded tip; progress is typed and
    // agrees with it.
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

    // Capability snapshot comes from the node registry: both compiled
    // capabilities are reported even while disabled by runtime toggles.
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

    // Typed block query: the first seeded block resolves with its bytes.
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

/// Broadcast, mempool read-back, fee estimate, and the `TxLookup` capability
/// gate — the mutation half of the embedded lifecycle.
fn assert_broadcast_and_lookups(node: &Node) -> Result<()> {
    // Broadcast: spend the matured height-1 coinbase through the production
    // gateway admission path.
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

    // Read back by id: the mempool answers without any index.
    let read_back = block_on(node.tx_by_id(spend_txid))?;
    assert_eq!(read_back.txid(), spend_txid);
    assert_eq!(node.mempool_info().txs, 1, "the spend sits in the pool");

    // Fee estimate: no confirmation history yet, so the honest answer is None.
    assert_eq!(
        node.fee_estimate(6),
        None,
        "an estimator without history must refuse, not fabricate"
    );

    // Confirmed lookup is TxLookup-gated: with txindex and scriptindex off,
    // an unknown txid is Unavailable (capability missing), never NotFound.
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

/// `NodeConfig` for chain seeding: isolated regtest datadir, P2P listeners off.
fn seed_config(data_dir: &std::path::Path) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir.to_path_buf();
    config.p2p.listen.clear();
    config
}

/// `NodeConfig` for the embedded node: ephemeral RPC bind on the seeded datadir.
fn embedded_config(data_dir: &std::path::Path) -> Result<NodeConfig> {
    let mut config = seed_config(data_dir);
    let rpc_bind: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    config.rpc.bind = rpc_bind;
    Ok(config)
}

/// Applies genesis plus `count` trivial-PoW regtest blocks through ordinary
/// validation; each coinbase pays the anyone-can-spend `OP_1` script.
///
/// Returns the final tip hash, the first seeded block's hash, and its
/// consensus bytes for the read-back assertion.
fn seed_chain(state: &NodeState, count: u32) -> Result<(Hash256, Hash256, Vec<u8>)> {
    let applied = state.applied_tip();
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
                bits: REGTEST_BITS,
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = compute_merkle_root(&block.txs)
            .ok_or_else(|| anyhow::anyhow!("seed block must have a merkle root"))?;
        grind_pow(&mut block)?;
        state.apply_block(&block)?;
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

/// The height-`height` seed coinbase: BIP34 height push, `OP_1` payout.
fn seed_coinbase(height: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // BIP34 height push plus one pad byte: consensus requires a
            // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
            script_sig: [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REGTEST_SUBSIDY_SATS,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

/// The transaction this test broadcasts: a `MEMPOOL_TX_FEE_SATS`-fee spend
/// of the height-1 seed coinbase, matured once the tip passes height 100.
fn seed_coinbase_spend() -> Tx {
    let seed_coinbase = seed_coinbase(1);
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.txid(), 0),
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: REGTEST_SUBSIDY_SATS - MEMPOOL_TX_FEE_SATS,
            // P2WPKH. The prevout is anyone-can-spend, but the mempool also
            // enforces output standardness, which a bare OP_TRUE output fails.
            script_pubkey: [vec![0x00, 0x14], vec![0x11; 20]].concat(),
        }],
        lock_time: 0,
    }
}

/// The one-input null-prevout coinbase outpoint (Core `COINBASE_OUTPOINT`).
fn null_prevout() -> OutPoint {
    OutPoint::new(Txid::default(), u32::MAX)
}

/// Minimal script push of a small integer, mirroring rust-bitcoin
/// `Builder::push_int`: `OP_0` for zero, `OP_N` for 1..=16, otherwise a
/// length-prefixed little-endian payload (BIP34 heights).
fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        // `value` is pinned to 1..=16 by the match arm.
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                // Low byte only; the shift below consumes it fully.
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut out = Vec::with_capacity(payload.len() + 1);
            // A small-int push never exceeds 8 payload bytes.
            out.push(u8::try_from(payload.len()).unwrap_or_default());
            out.extend(payload);
            out
        }
    }
}

/// Grinds the header nonce until the hash meets the compact bits target.
fn grind_pow(block: &mut Block) -> Result<()> {
    loop {
        if pow_is_met(block.header.bits, &block.header.compute_hash().into()) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            bail!("nonce exhausted while grinding block");
        };
        block.header.nonce = next;
    }
}

/// Returns true when the header hash, read as a little-endian integer, meets
/// the compact bits target (Core `CheckProofOfWork` shape).
fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    // Little-endian target bytes: mantissa placed `shift` bytes from the
    // least-significant end (mantissa is masked below 2^24, so three bytes).
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift + offset;
        if position < 32 {
            target[position] = *byte;
        }
    }
    // Both sides are little-endian 32-byte integers: compare from the most
    // significant byte downward (Core `CheckProofOfWork`).
    let hash_le = hash.to_le_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Native BIP141-style txid merkle fold with the odd-leaf duplication rule.
fn compute_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Dropping a node without `shutdown` must still run the ordered teardown in
/// startup-abort mode: services stop and join, the datadir is released, and
/// no clean-shutdown checkpoint is published over the seed's own.
#[test]
fn dropped_node_releases_services_and_datadir_for_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");

    let (_seed_tip_hash, _first, _bytes) = {
        let state = NodeState::open(seed_config(&data_dir), None)?;
        state.apply_block(&Network::Regtest.genesis_block())?;
        let outcome = seed_chain(&state, 1)?;
        state.publish_checkpoint()?;
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
        // Deliberately no `shutdown`: the Drop impl must stop every service
        // and release the storage before this block ends — and must not
        // publish a checkpoint for the aborted run.
    }
    assert_eq!(
        std::fs::read(&current_path)?,
        seeded_current,
        "a dropped node must not publish a clean-shutdown checkpoint"
    );

    // The released datadir reopens and resumes the seeded checkpoint.
    let resumed = NodeState::open(seed_config(&data_dir), None)?;
    let tip = resumed
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("seeded checkpoint must restore an applied tip"));
    assert_eq!(tip.height, 1);
    drop(resumed);

    // And a whole second embedded lifecycle starts and stops cleanly on it.
    let node = block_on(Node::start(
        embedded_config(&data_dir)?,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;
    assert_eq!(node.snapshot().tip_height, 1);
    block_on(node.shutdown())?;
    Ok(())
}

/// A startup that fails after state is open — an RPC port already held by
/// another node — must roll the partially built graph back through the
/// shared teardown: the error surfaces as [`NodeError::Startup`], and the
/// rolled-back datadir is immediately reusable (its storage locks were
/// released by the same teardown that joined the graph's workers).
#[test]
fn startup_failure_after_state_open_rolls_back_releases_state() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let held_dir = dir.path().join("held");
    let failed_dir = dir.path().join("failed");

    // Reserve a port, release the probe, and let node A hold it.
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?;
    drop(probe);

    let mut held_config = embedded_config(&held_dir)?;
    held_config.rpc.bind = port;
    let held = block_on(Node::start(
        held_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    ))?;

    // Node B targets the same port: `start_node` opens B's state first,
    // then fails at the RPC bind. The rollback must release B's state.
    let mut failed_config = embedded_config(&failed_dir)?;
    failed_config.rpc.bind = port;
    match block_on(Node::start(
        failed_config,
        bitcoin_rs_node::RuntimeInputs::default(),
    )) {
        Err(NodeError::Startup(message)) => {
            let lowered = message.to_lowercase();
            assert!(
                lowered.contains("address") || lowered.contains("bind"),
                "the failure should name the bind conflict, got: {message}"
            );
        }
        other => bail!(
            "expected a startup failure on the held port, got {:?}",
            other.err()
        ),
    }

    // B's datadir is free: open it directly.
    let resumed = NodeState::open(seed_config(&failed_dir), None)?;
    drop(resumed);

    // A is unaffected and still shuts down cleanly.
    block_on(held.shutdown())?;
    Ok(())
}
