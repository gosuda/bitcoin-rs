use super::*;

/// IDX-01: scriptindex mode selects `ScriptLive` and/or `ScriptHistory`.
#[test]
fn script_index_capabilities_match_the_storage_contract() {
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.indexes.txindex = false;

    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    assert_eq!(derived_index_capabilities(&config), IndexCapabilities::NONE);

    config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
    assert_eq!(
        derived_index_capabilities(&config),
        IndexCapabilities::SCRIPT_LIVE,
        "utxo mode owns only the compact live-output view"
    );

    config.indexes.script_index = crate::config::ScriptIndexMode::Full;
    assert_eq!(derived_index_capabilities(&config), IndexCapabilities::ALL);

    config.indexes.txindex = true;
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    assert_eq!(
        derived_index_capabilities(&config),
        IndexCapabilities::TX_LOOKUP
    );

    config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
    assert_eq!(
        derived_index_capabilities(&config),
        IndexCapabilities::TX_LOOKUP_SCRIPT_LIVE
    );
}

#[test]
fn open_skips_tx_index_when_disabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;

    assert!(state.chain_followers().derived_index().is_none());
    assert!(
        state.derived_index_query().is_none(),
        "txindex disabled by default"
    );
    assert!(
        !state.data_dir().join("txindex").exists(),
        "disabled txindex must not create storage"
    );
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

    assert!(state.chain_followers().derived_index().is_some());
    assert!(state.derived_index.lifecycle_is_opening());
    assert!(
        !state.derived_index.is_running(),
        "no worker may exist before start_index_workers"
    );

    state.start_index_workers()?;
    assert!(state.derived_index.is_running());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while state.derived_index.lifecycle_is_opening() {
        assert!(
            std::time::Instant::now() < deadline,
            "txindex lifecycle remained Opening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// C1: `start_index_workers` is idempotent — a second call after the worker
/// runs is a safe no-op, not a second spawn.
#[test]
fn start_index_workers_twice_is_idempotent() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let mut state = NodeState::open(config, None)?;

    state.start_index_workers()?;
    assert!(state.derived_index.is_running());
    state.start_index_workers()?;
    assert!(
        state.derived_index.is_running(),
        "the second call must leave the one worker running"
    );
    assert_eq!(
        state.derived_index.spawn_count(),
        1,
        "the second call must not have spawned another worker"
    );
    Ok(())
}

/// C6: `derived_index_status` answers a concrete row in every phase,
/// including a config with no index capability at all.
#[test]
fn derived_index_status_answers_when_disabled() -> anyhow::Result<()> {
    use bitcoin_rs_index::CapabilityState;

    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    let state = NodeState::open(config, None)?;

    let status = state.derived_index_status();
    assert_eq!(
        status.capability().state,
        CapabilityState::Disabled,
        "a disabled config must answer a concrete Disabled row"
    );
    Ok(())
}

/// Bounded shutdown turns `Running` into `Stopped`, is idempotent, and
/// leaves the store released for a clean reopen on the same data dir.
#[test]
fn bounded_shutdown_stops_the_worker_and_allows_reopen() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let mut state = NodeState::open(config.clone(), None)?;
    state.start_index_workers()?;
    assert!(state.derived_index.is_running());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while state.derived_index.lifecycle_is_opening() {
        assert!(
            std::time::Instant::now() < deadline,
            "txindex lifecycle remained Opening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    state.bounded_index_shutdown(Duration::from_secs(5))?;
    assert!(!state.derived_index.is_running());
    // A second call is a no-op, not a second stop or a panic.
    state.bounded_index_shutdown(Duration::from_secs(5))?;
    drop(state);

    // The worker joined cleanly, so the namespace is free and the store
    // reopens: a replacement worker starts, opens the store, and leaves
    // Opening for a real capability state — never Failed or abandoned.
    let mut reopened = NodeState::open(config, None)?;
    reopened.start_index_workers()?;
    assert!(reopened.derived_index.is_running());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while reopened.derived_index.lifecycle_is_opening() {
        assert!(
            std::time::Instant::now() < deadline,
            "replacement txindex worker remained Opening"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // The lifecycle slot — not the derived capability row — is the durable
    // open signal: a progress read that raced a moving watermark answers a
    // transient `Failed` while the worker is Serving.
    assert!(
        !reopened.derived_index.lifecycle_is_failed(),
        "the replacement worker must open the reclaimed namespace"
    );
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

    assert!(state.chain_followers().derived_index().is_some());
    assert!(state.derived_index_query().is_none());
    assert!(state.esplora_derived_index_query().is_some());
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
        assert!(state.derived_index_query().is_some());
    }

    let reopened = NodeState::open(config, None)?;
    assert!(reopened.derived_index_query().is_some());
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
