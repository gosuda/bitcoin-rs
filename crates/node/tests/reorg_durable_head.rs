use bitcoin_rs_node::test_support::TestError;

type Result<T, E = TestError> = core::result::Result<T, E>;

use bitcoin_rs_execution::chain::regtest_fixture;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};

use bitcoin_rs_consensus::primitives::{BlockHash, Hash256};

fn stable_utxo_hash(
    view: &bitcoin_rs_storage::utxo::UtxoSetView<'_>,
) -> Result<Hash256, bitcoin_rs_storage::utxo::UtxoError> {
    view.hash_serialized_3()
}

#[test]
fn disconnect_rewrites_durable_head_before_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("reorg-node");
    config.p2p.listen.clear();

    let genesis = Network::Regtest.genesis_block();
    let initial = NodeState::open(config.clone(), None)?;
    initial.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let _ = initial.publish_checkpoint()?;
    drop(initial);

    let state = NodeState::open(config.clone(), None)?;
    let block1 = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
    let tip1 = state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block1,
    ))?;
    let block2 = regtest_fixture::mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block2.clone(),
    ))?;
    state.chainstate().disconnect_block(&block2)?;
    let expected_utxo = state
        .chainstate()
        .utxo_reader()
        .with_stable_view(stable_utxo_hash)??;
    let expected_stats = state.chainstate().coin_stats_handle().snapshot();
    drop(state);

    let resumed = NodeState::open(config.clone(), None)?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("reorg replay did not publish a tip"))?;
    assert_eq!(resumed_tip.as_ref(), &tip1);
    assert_eq!(
        resumed
            .chainstate()
            .utxo_reader()
            .with_stable_view(stable_utxo_hash)??,
        expected_utxo
    );
    assert_semantic_coin_stats_eq(
        &resumed.chainstate().coin_stats_handle().snapshot(),
        &expected_stats,
    );

    let mut replacement = regtest_fixture::mined_regtest_child_at(BlockHash(tip1.hash), 2)?;
    replacement.header.time = replacement.header.time.saturating_add(1);
    replacement.header.nonce = 0;
    regtest_fixture::mine_block_to_declared_target(&mut replacement)?;
    assert_ne!(replacement.block_hash(), block2.block_hash());
    let replacement_tip = resumed.apply_block(
        &bitcoin_rs_consensus::primitives::BlockImage::from_local(replacement),
    )?;
    drop(resumed);

    let replaced = NodeState::open(config, None)?;
    let persisted_tip = replaced
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("replacement durable head tip missing"))?;
    assert_eq!(persisted_tip.as_ref(), &replacement_tip);
    Ok(())
}

#[test]
fn disconnect_below_checkpoint_base_forces_full_validation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("deep-reorg-node");
    config.p2p.listen.clear();

    let genesis = Network::Regtest.genesis_block();
    let block1 = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
    let initial = NodeState::open(config.clone(), None)?;
    let genesis_tip = initial.apply_block(
        &bitcoin_rs_consensus::primitives::BlockImage::from_local(genesis),
    )?;
    initial.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block1.clone(),
    ))?;
    let _ = initial.publish_checkpoint()?;
    drop(initial);

    let state = NodeState::open(config.clone(), None)?;
    state.chainstate().disconnect_block(&block1)?;
    drop(state);

    let resumed = NodeState::open(config.clone(), None)?;
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_snapshot()
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
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("durable head replay did not publish a tip"))?;
    assert_eq!(
        resumed_again_tip.as_ref(),
        &genesis_tip,
        "full validation must remain sticky until a replacement checkpoint"
    );
    let replacement_tip = resumed_again.apply_block(
        &bitcoin_rs_consensus::primitives::BlockImage::from_local(block1),
    )?;
    let _ = resumed_again.publish_checkpoint()?;
    drop(resumed_again);

    let recovered = NodeState::open(config, None)?;
    let recovered_tip = recovered
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("replacement checkpoint was ignored"))?;
    assert_eq!(recovered_tip.as_ref(), &replacement_tip);
    Ok(())
}

// SYNC-05
#[test]
fn recovery_publication_keeps_committed_coin_stats_across_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("recovery-stats-node");
    config.p2p.listen.clear();

    let genesis = Network::Regtest.genesis_block();
    let block1 = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
    let block2 = regtest_fixture::mined_regtest_child_at(block1.block_hash(), 2)?;

    let base = NodeState::open(config.clone(), None)?;
    base.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    base.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block1.clone(),
    ))?;
    let _ = base.publish_checkpoint()?;
    drop(base);

    let state = NodeState::open(config.clone(), None)?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block2.clone(),
    ))?;
    state
        .undo_store()
        .arm_disconnect(2, block2.block_hash().0)?;
    drop(state);

    let recovered = NodeState::open(config.clone(), None)?;
    drop(recovered);

    let resumed = NodeState::open(config, None)?;
    let tip = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("recovery replay did not publish a tip"))?;
    let expected = resumed
        .chainstate()
        .utxo_reader()
        .with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, tip.height, true)
        })??;
    let served = resumed.chainstate().coin_stats_handle().snapshot();
    assert_eq!(
        served.height, expected.height,
        "listener height must equal the committed tip height"
    );
    assert_eq!(
        served.total_amount, expected.total_amount,
        "listener amount must equal a full scan of the committed coin set"
    );
    assert_eq!(
        served.bogo_size, expected.bogo_size,
        "listener bogo_size must equal a full scan of the committed coin set"
    );
    assert_eq!(
        served.utxo_count, expected.utxo_count,
        "listener output count must equal a full scan of the committed coin set"
    );
    assert_eq!(
        served.muhash.finalize_hash(),
        expected.muhash.finalize_hash(),
        "listener MuHash must equal a full scan of the committed coin set"
    );
    Ok(())
}

fn assert_semantic_coin_stats_eq(
    left: &bitcoin_rs_storage::utxo::stats::CoinStats,
    right: &bitcoin_rs_storage::utxo::stats::CoinStats,
) {
    assert_eq!(left.height, right.height);
    assert_eq!(left.total_amount, right.total_amount);
    assert_eq!(left.bogo_size, right.bogo_size);
    assert_eq!(left.tx_count, right.tx_count);
    assert_eq!(left.utxo_count, right.utxo_count);
    assert_eq!(left.muhash.finalize_hash(), right.muhash.finalize_hash());
}
