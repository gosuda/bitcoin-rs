use super::*;
use crate::test_support::TestError;
use sonic_rs::JsonValueTrait as _;

use bitcoin_rs_consensus::primitives::BlockImage;

#[test]
fn the_chain_transaction_count_survives_a_checkpoint_restart() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let expected = {
        let state = NodeState::open(config.clone(), None)?;
        assert_eq!(
            applied_chain_tx_count(&state),
            bitcoin_rs_execution::chain::ChainTxCount::UNKNOWN,
            "a node that has applied nothing cannot know the count"
        );

        let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
        let genesis_tx_count = u64::try_from(genesis.txs.len())?;
        let _tip = state.apply_block(&BlockImage::from_local(genesis))?;
        let counted = applied_chain_tx_count(&state);
        assert_eq!(
            counted,
            bitcoin_rs_execution::chain::ChainTxCount::established(genesis_tx_count),
            "genesis establishes the count"
        );

        assert!(state.publish_checkpoint()?.is_some());
        counted
    };

    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    assert!(
        resumed.block_log_reader().read().is_empty(),
        "the record log really does start empty; the count cannot come from it"
    );
    assert_eq!(applied_chain_tx_count(&resumed), expected);
    Ok(())
}

#[test]
fn clean_checkpoint_reopens_and_applies_the_next_block() -> Result<(), TestError> {
    fn stable_hash(
        view: &bitcoin_rs_storage::utxo::UtxoSetView<'_>,
    ) -> Result<bitcoin_rs_consensus::primitives::Hash256, bitcoin_rs_storage::utxo::UtxoError>
    {
        view.hash_serialized_3()
    }
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis =
        BlockImage::from_local(bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block());
    let genesis_tip = state.apply_block(&genesis)?;
    let expected_utxo_hash = state
        .chainstate()
        .utxo_reader()
        .with_stable_view(stable_hash)??;
    let expected_stats = state.chainstate().coin_stats_handle().snapshot();
    assert!(state.publish_checkpoint()?.is_some());
    drop(state);

    let mut reopen_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    reopen_config.data_dir = data_dir.clone();
    reopen_config.p2p.listen.clear();
    let resumed = NodeState::open(reopen_config.clone(), None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    let applied = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
    assert_eq!(applied.height, genesis_tip.height);
    assert_eq!(applied.hash, genesis_tip.hash);
    assert_eq!(
        resumed.chainstate().header_tip().as_deref(),
        Some(applied.as_ref())
    );
    assert_eq!(
        resumed
            .chainstate()
            .utxo_reader()
            .with_stable_view(stable_hash)??,
        expected_utxo_hash
    );
    assert_eq!(
        resumed.chainstate().coin_stats_handle().snapshot(),
        expected_stats
    );
    assert!(resumed.block_log_reader().read().is_empty());
    assert!(resumed.mempool().read().is_empty());

    let next = BlockImage::from_local(regtest_fixture::mined_regtest_child_at(
        genesis.block_hash(),
        1,
    )?);
    let next_tip = resumed.apply_block(&next)?;
    assert_eq!(next_tip.height, 1);
    assert_eq!(
        next_tip.hash.to_le_bytes(),
        next.block_hash().0.to_le_bytes()
    );
    let listener_after_apply = resumed.chainstate().coin_stats_handle().snapshot();
    let mut rescanned = resumed
        .chainstate()
        .utxo_reader()
        .with_stable_view(|view| {
            bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, next_tip.height, true)
        })??;
    rescanned.tx_count = listener_after_apply.tx_count;
    assert_eq!(
        listener_after_apply.total_amount, rescanned.total_amount,
        "checkpoint resume must keep rolling CoinStats attached to UTXO commits"
    );
    let _ = resumed.publish_checkpoint()?;

    let root = data_dir.join("chainstate-checkpoints");
    let current: sonic_rs::Value = sonic_rs::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
    let directory = current
        .get("directory")
        .and_then(|value| value.as_str())
        .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
    assert!(root.join(directory).join("chainstate").exists());
    assert!(root.join(directory).join("headers-v1.dat").exists());
    assert!(root.join(directory).join("coinstats-v1.dat").exists());
    let manifest_bytes = std::fs::read(root.join(directory).join("manifest-v1.json"))?;
    let manifest: sonic_rs::Value = sonic_rs::from_slice(&manifest_bytes)?;
    assert!(manifest.get("utxo").is_none_or(|v| v.is_null()));
    let image =
        bitcoin_rs_storage::open_checkpoint_store(&root.join(directory).join("chainstate"))?;
    let image_coins = image
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()?;
    drop(image);
    let committed_coins = resumed
        .chainstate()
        .coins()
        .scan_snapshot()?
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        !committed_coins.is_empty(),
        "the committed set must hold the next block's coinbase"
    );
    assert_eq!(
        image_coins, committed_coins,
        "the checkpoint generation must carry exactly the committed coin rows"
    );
    drop(resumed);

    let resumed_again = NodeState::open(reopen_config, None)?;
    assert_eq!(resumed_again.resume_source(), ResumeSource::Checkpoint);
    assert_eq!(
        resumed_again.chainstate().coin_stats_handle().snapshot(),
        rescanned
    );
    Ok(())
}

#[test]
fn clean_checkpoint_lifecycle_is_backend_neutral() -> Result<(), TestError> {
    let backends: Vec<&str> = vec!["rocksdb"];

    for backend in backends {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join(backend);
        config.storage.backend = match backend {
            "rocksdb" => bitcoin_rs_storage::StorageBackend::RocksDb,
            _ => {
                return Err(TestError::ExpectationFailed(
                    "a compiled-in storage backend",
                ));
            }
        };
        config.p2p.listen.clear();
        let genesis = BlockImage::from_local(
            bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
        );
        let state = NodeState::open(config.clone(), None)?;
        state.apply_block(&genesis)?;
        let _ = state.publish_checkpoint()?;
        drop(state);

        let resumed = NodeState::open(config, None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        resumed.apply_block(&BlockImage::from_local(
            regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?,
        ))?;
    }
    Ok(())
}

#[test]
fn durable_head_replay_restores_state_above_checkpoint() -> Result<(), TestError> {
    fn stable_hash(
        view: &bitcoin_rs_storage::utxo::UtxoSetView<'_>,
    ) -> Result<bitcoin_rs_consensus::primitives::Hash256, bitcoin_rs_storage::utxo::UtxoError>
    {
        view.hash_serialized_3()
    }

    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("checkpoint-resume");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();

    let genesis =
        BlockImage::from_local(bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block());
    let first = NodeState::open(config.clone(), None)?;
    first.apply_block(&genesis)?;
    let _ = first.publish_checkpoint()?;
    drop(first);

    let base = NodeState::open(config.clone(), None)?;
    assert_eq!(base.resume_source(), ResumeSource::Checkpoint);
    let child = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
    let expected_tip = base.apply_block(&BlockImage::from_local(child))?;
    let expected_utxo = base
        .chainstate()
        .utxo_handle()
        .with_stable_view(stable_hash)?;
    let expected_stats = base.chainstate().coin_stats_handle().snapshot();
    let expected_tx_count = expected_tip.chain_tx_count;
    drop(base);

    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    let resumed_tip = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("checkpoint replay did not publish a tip"))?;
    assert_eq!(resumed_tip.as_ref(), &expected_tip);
    assert_eq!(
        resumed
            .chainstate()
            .utxo_handle()
            .with_stable_view(stable_hash)?,
        expected_utxo
    );
    assert_eq!(
        resumed.chainstate().coin_stats_handle().snapshot(),
        expected_stats
    );
    assert_eq!(resumed_tip.chain_tx_count, expected_tx_count);
    Ok(())
}

#[test]
fn publish_checkpoint_returns_none_when_no_applied_tip() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    assert_eq!(
        state.publish_checkpoint()?,
        None,
        "a node that applied no block has no tip to checkpoint"
    );
    Ok(())
}

#[test]
fn publish_checkpoint_returns_generation_and_reopens() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    let tip = state.apply_block(&BlockImage::from_local(genesis))?;
    let generation = state.publish_checkpoint()?;
    assert!(
        generation.is_some_and(|published| published > 0),
        "published checkpoint must have a positive generation"
    );
    drop(state);

    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    let applied = resumed
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
    assert_eq!(applied.height, tip.height);
    assert_eq!(applied.hash, tip.hash);
    Ok(())
}
