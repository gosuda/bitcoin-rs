use super::*;

/// IDX-01: scriptindex mode selects `ScriptLive` and/or `ScriptHistory`.
#[test]
fn script_index_capabilities_match_the_storage_contract() {
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.indexes.txindex = false;

    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    assert_eq!(tx_index_capabilities(&config), IndexCapabilities::NONE);

    config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
    assert_eq!(
        tx_index_capabilities(&config),
        IndexCapabilities::SCRIPT_LIVE,
        "utxo mode owns only the compact live-output view"
    );

    config.indexes.script_index = crate::config::ScriptIndexMode::Full;
    assert_eq!(tx_index_capabilities(&config), IndexCapabilities::ALL);

    config.indexes.txindex = true;
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    assert_eq!(tx_index_capabilities(&config), IndexCapabilities::TX_LOOKUP);

    config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
    assert_eq!(
        tx_index_capabilities(&config),
        IndexCapabilities {
            tx_lookup: true,
            script_history: false,
            script_live: true,
        }
    );
}

#[test]
fn open_skips_tx_index_when_disabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;

    assert!(
        state.tx_index_query().is_none(),
        "txindex disabled by default"
    );
    assert!(
        !state.data_dir().join("txindex").exists(),
        "disabled txindex must not create storage"
    );
    Ok(())
}

#[test]
fn open_constructs_tx_index_when_enabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let mut state = NodeState::open(config, None)?;
    state.start_index_workers()?;
    let (Some(a), Some(b)) = (state.tx_index_query(), state.tx_index_query()) else {
        panic!("txindex query engine missing when enabled");
    };
    assert!(Arc::ptr_eq(&a, &b), "txindex query handle must be stable");
    // The worker opens the store asynchronously; the directory appears
    // once its open completes, not during NodeState::open.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !state.data_dir().join("txindex").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "enabled txindex worker did not create storage within 30s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
fn index_workers_start_only_when_asked() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let mut state = NodeState::open(config, None)?;

    assert!(state.tx_index_lifecycle.as_ref().is_some_and(|lifecycle| {
        matches!(
            lifecycle.load().as_ref(),
            crate::txindex::TxIndexLifecycle::Opening
        )
    }));
    assert!(state.tx_index_worker.is_none());

    state.start_index_workers()?;
    assert!(state.tx_index_worker.is_some());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while state.tx_index_lifecycle.as_ref().is_some_and(|lifecycle| {
        matches!(
            lifecycle.load().as_ref(),
            crate::txindex::TxIndexLifecycle::Opening
        )
    }) {
        assert!(
            std::time::Instant::now() < deadline,
            "txindex lifecycle remained Opening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
fn script_index_builds_without_advertising_core_txindex() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Full;

    let mut state = NodeState::open(config, None)?;
    state.start_index_workers()?;

    assert!(state.chain_followers().effects().tx_index().is_some());
    assert!(state.tx_index_query().is_none());
    assert!(state.esplora_tx_index_query().is_some());
    assert!(state.script_index_query().is_some());
    // The script-index worker shares the txindex storage; it is created
    // asynchronously once the worker's open completes.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !state.data_dir().join("txindex").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "script-index worker did not create storage within 30s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Opens a node in each accepted `scriptindex` mode and asserts the
/// concrete answer for `unspent_outputs`, rather than only the `full` path.
///
/// `utxo` must be independently usable while historical rows are absent;
/// this test pins that both enabled modes converge to a concrete answer.
#[test]
fn script_index_modes_give_concrete_unspent_outputs_answers() -> anyhow::Result<()> {
    use bitcoin_rs_index::ScriptHash;
    use bitcoin_rs_rpc::context::TxQueryError;

    // Genesis is applied in each case so the index worker has a published
    // chain tip to anchor. The disabled case has no adapter; the enabled
    // modes must publish their own capability watermarks independently.
    let scripthash = ScriptHash::from_script_bytes(&[0x51, 0x01]);

    // `disabled`: no script index at all, so no query adapter is handed
    // out. The answer is a definite "not available", not a retry.
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    let state = NodeState::open(config, None)?;
    let _ = state.apply_block(&crate::Network::Regtest.genesis_block())?;
    assert!(
        state.script_index_query().is_none(),
        "disabled must not hand out a script-index query adapter"
    );
    drop(state);

    // `utxo`: the compact live-output view is independently usable while
    // historical script rows are not maintained.
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
    let mut state = NodeState::open(config, None)?;
    state.start_index_workers()?;
    let _ = state.apply_block(&crate::Network::Regtest.genesis_block())?;
    let Some(query) = state.script_index_query() else {
        panic!("utxo mode must hand out a script-index query adapter")
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match query.unspent_outputs(scripthash) {
            Ok(records) => {
                assert!(records.is_empty(), "an unfunded script has no outputs");
                match query.history_snapshot(scripthash) {
                    Err(TxQueryError::Unavailable(reason)) => {
                        assert!(
                            reason.contains("script history is disabled"),
                            "utxo history must be disabled, not lagging: {reason}"
                        );
                    }
                    other => panic!("utxo mode must fail history as disabled, got {other:?}"),
                }
                break;
            }
            Err(TxQueryError::Retry | TxQueryError::Unavailable(_)) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "utxo mode must converge on the live view"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("unexpected script-index error: {error}"),
        }
    }

    // `full`: the accepted mode. It converges on a concrete answer — an
    // empty set for an unfunded script — rather than retrying forever.
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Full;
    let mut state = NodeState::open(config, None)?;
    state.start_index_workers()?;
    let _ = state.apply_block(&crate::Network::Regtest.genesis_block())?;
    let Some(query) = state.script_index_query() else {
        panic!("full mode must hand out a script-index query adapter")
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match query.unspent_outputs(scripthash) {
            Ok(records) => {
                assert!(
                    records.is_empty(),
                    "an unfunded script has no unspent outputs"
                );
                break;
            }
            // The worker indexes asynchronously, so it is legitimately
            // still opening for a bounded interval.
            Err(TxQueryError::Retry | TxQueryError::Unavailable(_)) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "full mode must converge on a concrete answer, not retry forever"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("unexpected script-index error: {error}"),
        }
    }
    Ok(())
}

#[test]
fn drop_joins_txindex_worker_before_reopen() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;

    {
        let mut state = NodeState::open(config.clone(), None)?;
        state.start_index_workers()?;
        assert!(state.tx_index_query().is_some());
    }

    let reopened = NodeState::open(config, None)?;
    assert!(reopened.tx_index_query().is_some());
    Ok(())
}

#[test]
fn open_rejects_txindex_with_pruning() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    config.storage.prune_target_mb = 1;

    let error = match NodeState::open(config, None) {
        Ok(_) => anyhow::bail!("txindex with pruning must be rejected"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("transaction and script indexing are not compatible with -prune"),
        "unexpected error: {error:#}"
    );
    Ok(())
}

#[test]
fn apply_handles_follow_txindex_availability() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("without-txindex");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    let state = NodeState::open(config, None)?;
    assert!(state.chain_followers().effects().tx_index().is_none());

    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("with-txindex");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let state = NodeState::open(config, None)?;
    assert!(state.chain_followers().effects().tx_index().is_some());
    Ok(())
}
