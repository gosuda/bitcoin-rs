//! End-to-end crash-recovery coverage for the chainstate journal.

use anyhow::Result;

use bitcoin_rs_chainstate::ApplyError;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};

use sha2::{Digest, Sha256};

use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn stable_utxo_hash(
    view: &bitcoin_rs_utxo::UtxoSetView<'_>,
) -> Result<Hash256, bitcoin_rs_utxo::UtxoError> {
    view.hash_serialized_3()
}

#[test]
fn restart_replays_durable_journal_suffix_above_checkpoint() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;

    let genesis = Network::Regtest.genesis_block();
    let initial = NodeState::open(config.clone(), None)?;
    initial.apply_block(&genesis)?;
    initial.publish_checkpoint()?;

    // Publication must rebase the live writer in the same process.
    let child = mined_regtest_child(genesis.block_hash())?;
    let expected_tip = initial.apply_block(&child)?;
    let expected_utxo = initial
        .chainstate()
        .utxo_handle()
        .with_stable_view(stable_utxo_hash)?;
    let expected_stats = initial.chainstate().coin_stats_handle().snapshot();
    let expected_tx_count = initial
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .map_or(bitcoin_rs_chain::ChainTxCount::UNKNOWN, |tip| {
            tip.chain_tx_count
        });
    drop(initial);

    // No checkpoint was published for `child`: only the journal can recover it.
    let resumed = NodeState::open(config, None)?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("journal replay did not publish a tip"))?;
    assert_eq!(resumed_tip.as_ref(), &expected_tip);
    assert_eq!(
        resumed
            .chainstate()
            .utxo_handle()
            .with_stable_view(stable_utxo_hash)?,
        expected_utxo
    );
    assert_eq!(
        resumed
            .chainstate()
            .coin_stats_handle()
            .snapshot()
            .to_bytes(),
        expected_stats.to_bytes()
    );
    assert_eq!(
        resumed
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map_or(bitcoin_rs_chain::ChainTxCount::UNKNOWN, |tip| tip
                .chain_tx_count),
        expected_tx_count
    );
    Ok(())
}

#[test]
fn disconnect_rewrites_durable_head_before_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("reorg-node");
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;

    let genesis = Network::Regtest.genesis_block();
    let initial = NodeState::open(config.clone(), None)?;
    initial.apply_block(&genesis)?;
    initial.publish_checkpoint()?;
    drop(initial);

    let state = NodeState::open(config.clone(), None)?;
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let tip1 = state.apply_block(&block1)?;
    let block2 = mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
    state.apply_block(&block2)?;
    state.chainstate().disconnect_block(&block2)?;
    let expected_utxo = state
        .chainstate()
        .utxo_handle()
        .with_stable_view(stable_utxo_hash)?;
    let expected_stats = state.chainstate().coin_stats_handle().snapshot();
    drop(state);

    let resumed = NodeState::open(config.clone(), None)?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("reorg replay did not publish a tip"))?;
    assert_eq!(resumed_tip.as_ref(), &tip1);
    assert_eq!(
        resumed
            .chainstate()
            .utxo_handle()
            .with_stable_view(stable_utxo_hash)?,
        expected_utxo
    );
    assert_semantic_coin_stats_eq(
        &resumed.chainstate().coin_stats_handle().snapshot(),
        &expected_stats,
    );

    let mut replacement = mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
    replacement.header.time = replacement.header.time.saturating_add(1);
    replacement.header.nonce = 0;
    while !pow_met(
        replacement.header.bits.to_consensus(),
        replacement.block_hash().0,
    ) {
        replacement.header.nonce = replacement
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("replacement nonce exhausted"))?;
    }
    assert_ne!(replacement.block_hash(), block2.block_hash());
    let replacement_tip = resumed.apply_block(&replacement)?;
    drop(resumed);

    let replaced = NodeState::open(config, None)?;
    let persisted_tip = replaced
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("replacement journal tip missing"))?;
    assert_eq!(persisted_tip.as_ref(), &replacement_tip);
    Ok(())
}

#[test]
fn disconnect_below_checkpoint_base_forces_full_validation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("deep-reorg-node");
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;

    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let initial = NodeState::open(config.clone(), None)?;
    let genesis_tip = initial.apply_block(&genesis)?;
    initial.apply_block(&block1)?;
    initial.publish_checkpoint()?;
    drop(initial);

    let state = NodeState::open(config.clone(), None)?;
    state.chainstate().disconnect_block(&block1)?;
    drop(state);

    let resumed = NodeState::open(config.clone(), None)?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("durable head replay did not publish a tip"))?;
    assert_eq!(
        resumed_tip.as_ref(),
        &genesis_tip,
        "a checkpoint above the fork must not be trusted; the node resumes on the durable head"
    );
    drop(resumed);

    let resumed_again = NodeState::open(config.clone(), None)?;
    let resumed_again_tip = resumed_again
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("durable head replay did not publish a tip"))?;
    assert_eq!(
        resumed_again_tip.as_ref(),
        &genesis_tip,
        "full validation must remain sticky until a replacement checkpoint"
    );
    let replacement_tip = resumed_again.apply_block(&block1)?;
    resumed_again.publish_checkpoint()?;
    drop(resumed_again);

    let recovered = NodeState::open(config, None)?;
    let recovered_tip = recovered
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("replacement checkpoint was ignored"))?;
    assert_eq!(recovered_tip.as_ref(), &replacement_tip);
    Ok(())
}

#[test]
fn idle_journal_batch_flushes_on_wall_clock_deadline() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("idle-flush-node");
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 100;
    config.chainstate_journal.seconds = 1;
    config.chainstate_journal.max_lag_blocks = 100;

    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config.clone(), None)?;
    state.apply_block(&genesis)?;
    let _ = state.publish_checkpoint()?;
    let child = mined_regtest_child_at(genesis.block_hash(), 1)?;
    let expected_tip = state.apply_block(&child)?;
    let worker = state.start_chainstate_maintenance()?;
    std::thread::sleep(Duration::from_secs(3));
    state.shutdown().store(true, Ordering::Release);
    worker
        .join()
        .map_err(|_| std::io::Error::other("chainstate maintenance worker panicked"))?;
    drop(state);

    let resumed = NodeState::open(config, None)?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("idle journal record was not durable"))?;
    assert_eq!(resumed_tip.as_ref(), &expected_tip);
    Ok(())
}

/// Retention enforcement still runs without the periodic worker (#634):
/// the chainstate maintenance worker answers journal retention pressure
/// with a checkpoint publication used purely as a compaction-base advance
/// (`RCV-10`); the durable root stays the only recovery authority.
#[test]
fn maintenance_worker_drains_retention_pressure_with_a_publication() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("maintenance-drain-node");
    config.p2p.listen.clear();
    config.chainstate_journal.max_journal_mib = 1;
    config.chainstate_journal.rotate_mib = 1;

    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config.clone(), None)?;
    state.apply_block(&genesis)?;
    let _ = state.publish_checkpoint()?;
    let current = config.data_dir.join("chainstate-checkpoints/CURRENT");
    let baseline = std::fs::read_to_string(&current)?;

    // Inflate the measured journal size past the retention budget: apply
    // is refused before any tip mutation while the pressure stands.
    let pressure = config
        .data_dir
        .join("chainstate-journal/segment-9999999999.log");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pressure)?
        .set_len(1024 * 1024)?;

    let worker = state.start_chainstate_maintenance()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if std::fs::read_to_string(&current)? != baseline {
            break;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(
                "maintenance worker did not publish under retention pressure",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    state.shutdown().store(true, Ordering::Release);
    worker
        .join()
        .map_err(|_| std::io::Error::other("chainstate maintenance worker panicked"))?;
    Ok(())
}

#[test]
fn retention_pressure_stops_apply_before_tip_mutation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("retention-node");
    config.p2p.listen.clear();
    config.chainstate_journal.max_journal_mib = 1;
    config.chainstate_journal.rotate_mib = 1;

    let genesis = Network::Regtest.genesis_block();
    let state = NodeState::open(config.clone(), None)?;
    let genesis_tip = state.apply_block(&genesis)?;
    let _ = state.publish_checkpoint()?;
    let pressure = config
        .data_dir
        .join("chainstate-journal/segment-9999999999.log");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pressure)?
        .set_len(1024 * 1024)?;

    let child = mined_regtest_child_at(genesis.block_hash(), 1)?;
    assert!(matches!(
        state.apply_block(&child),
        Err(ApplyError::JournalBackpressure(_))
    ));
    let tip = state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("genesis tip missing"))?;
    assert_eq!(tip.as_ref(), &genesis_tip);
    Ok(())
}

fn assert_semantic_coin_stats_eq(
    left: &bitcoin_rs_utxo::stats::CoinStats,
    right: &bitcoin_rs_utxo::stats::CoinStats,
) {
    assert_eq!(left.height, right.height);
    assert_eq!(left.total_amount, right.total_amount);
    assert_eq!(left.bogo_size, right.bogo_size);
    assert_eq!(left.tx_count, right.tx_count);
    assert_eq!(left.utxo_count, right.utxo_count);
    assert_eq!(left.muhash.finalize_hash(), right.muhash.finalize_hash());
}

fn mined_regtest_child(prev_blockhash: BlockHash) -> Result<Block> {
    mined_regtest_child_at(prev_blockhash, 1)
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
