use super::*;

/// Undo pruning must respect the durable tip, not the in-memory one.
///
/// The applied tip can run far ahead of the last clean checkpoint. Pruning
/// undo to the in-memory tip deletes the record for the block the
/// checkpoint names, and a crash then restores a chainstate that cannot
/// disconnect its own tip.
#[test]
fn the_chain_transaction_count_survives_a_checkpoint_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let expected = {
        let state = NodeState::open(config.clone(), None)?;
        assert_eq!(
            state
                .chainstate()
                .applied_tip_handle()
                .load_full()
                .map_or(bitcoin_rs_chain::ChainTxCount::UNKNOWN, |tip| tip
                    .chain_tx_count),
            bitcoin_rs_chain::ChainTxCount::UNKNOWN,
            "a node that has applied nothing cannot know the count"
        );

        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let genesis_tx_count = u64::try_from(genesis.txs.len())?;
        let _tip = state.apply_block(&genesis)?;
        let counted = state
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map_or(bitcoin_rs_chain::ChainTxCount::UNKNOWN, |tip| {
                tip.chain_tx_count
            });
        assert_eq!(
            counted,
            bitcoin_rs_chain::ChainTxCount::established(genesis_tx_count),
            "genesis establishes the count"
        );

        assert!(state.write_clean_checkpoint()?.is_some());
        counted
    };

    // The block-record log is rebuilt empty on every open, so before this
    // change the count was unrecoverable after a restart: the applied tip
    // came back from the checkpoint at its real height with nothing behind
    // it to sum. The number now rides along with the tip.
    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    assert!(
        resumed.blocks().read().is_empty(),
        "the record log really does start empty; the count cannot come from it"
    );
    assert_eq!(
        resumed
            .chainstate()
            .applied_tip_handle()
            .load_full()
            .map_or(bitcoin_rs_chain::ChainTxCount::UNKNOWN, |tip| tip
                .chain_tx_count),
        expected
    );
    Ok(())
}

#[test]
fn clean_checkpoint_reopens_and_applies_the_next_block() -> anyhow::Result<()> {
    fn stable_hash(
        view: &bitcoin_rs_utxo::UtxoSetView<'_>,
    ) -> Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_utxo::UtxoError> {
        view.hash_serialized_3()
    }
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let genesis_tip = state.apply_block(&genesis)?;
    let expected_utxo_hash = state
        .chainstate()
        .utxo_handle()
        .with_stable_view(stable_hash)?;
    let expected_stats = state.chainstate().coin_stats_handle().snapshot();
    assert!(state.write_clean_checkpoint()?.is_some());
    drop(state);

    let mut reopen_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    reopen_config.data_dir = data_dir.clone();
    reopen_config.p2p.listen.clear();
    let resumed = NodeState::open(reopen_config.clone(), None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    let applied = resumed
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
    assert_eq!(applied.height, genesis_tip.height);
    assert_eq!(applied.hash, genesis_tip.hash);
    assert_eq!(
        resumed
            .chainstate()
            .chain_tip_handle()
            .load_full()
            .as_deref(),
        Some(applied.as_ref())
    );
    assert_eq!(
        resumed
            .chainstate()
            .utxo_handle()
            .with_stable_view(stable_hash)?,
        expected_utxo_hash
    );
    assert_eq!(
        resumed.chainstate().coin_stats_handle().snapshot(),
        expected_stats
    );
    assert!(resumed.blocks().read().is_empty());
    assert!(resumed.transactions().read().is_empty());
    assert!(resumed.mempool().read().is_empty());

    let next = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
    let next_tip = resumed.apply_block(&next)?;
    assert_eq!(next_tip.height, 1);
    assert_eq!(
        next_tip.hash.to_le_bytes(),
        next.block_hash().0.to_le_bytes()
    );
    let listener_after_apply = resumed.chainstate().coin_stats_handle().snapshot();
    let mut rescanned = resumed
        .chainstate()
        .utxo_handle()
        .with_stable_view(|view| {
            bitcoin_rs_utxo::stats::scan_coin_stats(view, next_tip.height, true)
        })?;
    rescanned.tx_count = listener_after_apply.tx_count;
    assert_eq!(
        listener_after_apply.total_amount, rescanned.total_amount,
        "checkpoint resume must keep rolling CoinStats attached to UTXO commits"
    );
    resumed.write_clean_checkpoint()?;

    let root = data_dir.join("chainstate-checkpoints");
    let current: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
    let directory = current
        .get("directory")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
    let snapshot_file = std::fs::File::open(root.join(directory).join("utxo-v4.dat"))?;
    let mut snapshot_reader = std::io::BufReader::new(snapshot_file);
    let snapshot = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut snapshot_reader)?;
    assert_ne!(snapshot.muhash_trailer, [0_u8; 384]);
    assert_eq!(snapshot.muhash_trailer, rescanned.muhash.finalize());
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
fn clean_checkpoint_lifecycle_is_backend_neutral() -> anyhow::Result<()> {
    let backends: Vec<&str> = vec![
        #[cfg(feature = "fjall")]
        "fjall",
        #[cfg(feature = "rocksdb")]
        "rocksdb",
        #[cfg(feature = "redb")]
        "redb",
    ];

    for backend in backends {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join(backend);
        config.storage.backend = backend.parse().map_err(anyhow::Error::msg)?;
        config.p2p.listen.clear();
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let state = NodeState::open(config.clone(), None)?;
        state.apply_block(&genesis)?;
        state.write_clean_checkpoint()?;
        drop(state);

        let resumed = NodeState::open(config, None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        resumed.apply_block(&regtest_fixture::mined_regtest_child_at(
            genesis.block_hash(),
            1,
        )?)?;
    }
    Ok(())
}

#[test]
fn rolling_coinstats_resume_continues_through_next_block() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node-g2");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let before = state.chainstate().coin_stats_handle().snapshot();
    state.write_clean_checkpoint()?;
    drop(state);

    let mut reopen_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    reopen_config.data_dir = data_dir;
    reopen_config.p2p.listen.clear();
    let resumed = NodeState::open(reopen_config, None)?;
    assert_eq!(resumed.chainstate().coin_stats_handle().snapshot(), before);
    resumed.apply_block(&regtest_fixture::mined_regtest_child_at(
        genesis.block_hash(),
        1,
    )?)?;
    let rolling = resumed.chainstate().coin_stats_handle().snapshot();
    let mut scanned = resumed
        .chainstate()
        .utxo_handle()
        .with_stable_view(|view| {
            bitcoin_rs_utxo::stats::scan_coin_stats(view, rolling.height, true)
        })?;
    scanned.tx_count = rolling.tx_count;
    // The listener is attached only after checkpoint/journal restoration,
    // then tracks subsequent live UTXO mutations without double-counting
    // the restored snapshot.
    assert_eq!(
        rolling.total_amount, scanned.total_amount,
        "restored state must receive subsequent rolling UTXO notifications"
    );
    Ok(())
}

#[test]
fn journal_replay_restores_state_above_checkpoint() -> anyhow::Result<()> {
    fn stable_hash(
        view: &bitcoin_rs_utxo::UtxoSetView<'_>,
    ) -> Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_utxo::UtxoError> {
        view.hash_serialized_3()
    }

    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("journal-resume");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.blocks = 1;

    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let first = NodeState::open(config.clone(), None)?;
    first.apply_block(&genesis)?;
    first.write_clean_checkpoint()?;
    drop(first);

    // The first reopen discards the pre-checkpoint journal generation and
    // initializes one whose authenticated base is the published checkpoint.
    let base = NodeState::open(config.clone(), None)?;
    assert_eq!(base.resume_source(), ResumeSource::Checkpoint);
    let child = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
    let expected_tip = base.apply_block(&child)?;
    let expected_utxo = base
        .chainstate()
        .utxo_handle()
        .with_stable_view(stable_hash)?;
    let expected_stats = base.chainstate().coin_stats_handle().snapshot();
    let expected_tx_count = expected_tip.chain_tx_count;
    drop(base);

    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Journal);
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
fn publish_checkpoint_refuses_when_no_applied_tip() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let Err(error) = state.publish_checkpoint() else {
        anyhow::bail!("checkpoint publication succeeded without an applied tip");
    };
    assert!(
        error.to_string().contains("no applied tip"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn publish_checkpoint_returns_generation_and_reopens() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let tip = state.apply_block(&genesis)?;
    let generation = state.publish_checkpoint()?;
    assert!(
        generation > 0,
        "published checkpoint must have a positive generation"
    );
    drop(state);

    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    let applied = resumed
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
    assert_eq!(applied.height, tip.height);
    assert_eq!(applied.hash, tip.hash);
    Ok(())
}
