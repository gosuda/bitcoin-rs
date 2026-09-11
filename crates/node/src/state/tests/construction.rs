use super::*;

#[test]
fn open_constructs_empty_handles() -> anyhow::Result<()> {
    use tempfile::tempdir;

    let dir = tempdir()?;
    let config = crate::NodeConfig {
        data_dir: dir.path().join("node"),
        ..crate::NodeConfig::default_for_network(crate::Network::Regtest)
    };

    let state = NodeState::open(config, None)?;
    let utxo = state.utxo();
    let mempool = state.mempool();

    assert!(
        Arc::strong_count(&utxo) >= 2,
        "caller and NodeState should both hold a strong ref"
    );
    assert!(Arc::strong_count(&mempool) >= 2);
    assert_eq!(mempool.read().len(), 0, "fresh mempool must be empty");

    Ok(())
}

#[test]
fn open_constructs_empty_block_tree() -> anyhow::Result<()> {
    use tempfile::tempdir;

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let tree = state.block_tree();

    assert!(
        tree.read().is_empty(),
        "freshly opened tree has zero headers"
    );
    Ok(())
}

#[test]
fn open_constructs_coin_stats_listener() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let snapshot = state.coin_stats().snapshot();
    assert_eq!(
        snapshot.tx_count, 0,
        "freshly opened coin_stats has zero txs"
    );
    Ok(())
}

#[test]
fn open_constructs_block_sync_orchestrator() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let sync_a = state.sync();
    let sync_b = state.sync();
    assert!(
        Arc::ptr_eq(&sync_a, &sync_b),
        "sync handle is stable across calls"
    );
    Ok(())
}

#[test]
fn open_constructs_empty_applied_tip() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;

    assert!(
        state.applied_tip().load_full().is_none(),
        "freshly opened applied_tip is empty"
    );
    Ok(())
}

#[test]
fn open_constructs_empty_peer_table() -> anyhow::Result<()> {
    use tempfile::tempdir;

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;

    assert!(
        state.peer_table().is_empty(),
        "freshly opened table is empty"
    );
    Ok(())
}

#[test]
fn zmq_publisher_handle_defaults_to_noop() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let publisher = state.zmq_publisher();
    // No-op publisher accepts publish calls silently.
    publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
    Ok(())
}

#[cfg(feature = "zmq")]
#[test]
fn zmq_publisher_handle_reports_active_metadata() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.notifications.zmq = vec![
        bitcoin_rs_rpc::zmq::ZmqEndpointConfig {
            endpoint: "inproc://state-zmq-block".to_owned(),
            topics: vec![
                bitcoin_rs_rpc::zmq::ZmqTopic::HashBlock,
                bitcoin_rs_rpc::zmq::ZmqTopic::RawBlock,
            ],
            hwm: Some(17),
        },
        bitcoin_rs_rpc::zmq::ZmqEndpointConfig {
            endpoint: "inproc://state-zmq-tx".to_owned(),
            topics: vec![
                bitcoin_rs_rpc::zmq::ZmqTopic::HashTx,
                bitcoin_rs_rpc::zmq::ZmqTopic::RawTx,
            ],
            hwm: Some(20),
        },
    ];
    let state = NodeState::open(config, None)?;

    let notifications = state.zmq_publisher().active_notifiers();
    let notification_types: Vec<_> = notifications
        .iter()
        .map(|notification| notification.topic.notifier_type())
        .collect();
    let hwms: Vec<_> = notifications
        .iter()
        .map(|notification| notification.hwm)
        .collect();
    assert_eq!(
        notification_types,
        ["pubhashblock", "pubrawblock", "pubhashtx", "pubrawtx"]
    );
    assert_eq!(hwms, [17, 17, 20, 20]);
    Ok(())
}

#[test]
fn inbound_headers_sender_is_unbounded_clone_target() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let tx1 = state.inbound_headers_sender();
    let tx2 = state.inbound_headers_sender();
    tx1.send(bitcoin_rs_p2p::InboundHeaders {
        headers: Vec::new(),
        source: None,
    })
    .map_err(|err| anyhow::anyhow!("send via tx1 failed: {err}"))?;
    tx2.send(bitcoin_rs_p2p::InboundHeaders {
        headers: Vec::new(),
        source: None,
    })
    .map_err(|err| anyhow::anyhow!("send via tx2 failed: {err}"))?;
    Ok(())
}

#[test]
fn inbound_blocks_sender_is_clonable_into_listener_threads() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let _tx1 = state.inbound_blocks_sender();
    let _tx2 = state.inbound_blocks_sender();
    Ok(())
}

#[test]
fn inbound_blocks_channel_is_bounded_against_flood() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let tx = state.inbound_blocks_sender();
    let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    // No `tick` drains the channel in this unit test, so it fills to the
    // bound; the block past the limit must be rejected rather than queued
    // (the OOM-flood guard), proving backpressure engages at the producer.
    for _ in 0..super::INBOUND_BLOCK_CHANNEL_LIMIT {
        tx.try_send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
            .unwrap_or_else(|e| panic!("send within the bound must succeed: {e}"));
    }
    let overflow = tx.try_send(bitcoin_rs_p2p::InboundBlock::from_decoded(block));
    assert!(
        matches!(overflow, Err(crossbeam_channel::TrySendError::Full(_))),
        "channel must reject blocks past INBOUND_BLOCK_CHANNEL_LIMIT, got {overflow:?}",
    );
    Ok(())
}

#[test]
fn inbound_tx_channel_is_bounded_against_flood() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let sender = state.inbound_tx_sender();
    let (lease_tx, _lease_rx) = crossbeam_channel::unbounded();
    let lease = bitcoin_rs_p2p::PeerLease::new(lease_tx);
    let source = lease.source(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
    let tx = bitcoin_rs_primitives::Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: LockTime::from_consensus(0),
    };
    for _ in 0..super::INBOUND_TX_CHANNEL_LIMIT {
        sender
            .try_send(bitcoin_rs_p2p::InboundTx::new(tx.clone(), source))
            .unwrap_or_else(|error| panic!("send within the bound must succeed: {error}"));
    }
    let overflow = sender.try_send(bitcoin_rs_p2p::InboundTx::new(tx, source));
    assert!(
        matches!(overflow, Err(crossbeam_channel::TrySendError::Full(_))),
        "channel must reject txs past INBOUND_TX_CHANNEL_LIMIT, got {overflow:?}",
    );
    Ok(())
}

#[test]
fn open_constructs_full_rpc_handle_set() -> anyhow::Result<()> {
    use tempfile::tempdir;

    let dir = tempdir()?;
    let config = crate::NodeConfig {
        data_dir: dir.path().join("node"),
        ..crate::NodeConfig::default_for_network(crate::Network::Regtest)
    };

    let state = NodeState::open(config, None)?;
    let chain_tip = state.chain_tip();
    let blocks = state.blocks();
    let transactions = state.transactions();
    let network = state.network();

    assert!(chain_tip.load().is_none(), "fresh chain tip must be empty");
    assert!(blocks.read().is_empty(), "fresh blocks must be empty");
    assert!(
        transactions.read().is_empty(),
        "fresh transactions must be empty"
    );
    assert_eq!(network.read().connection_count, 0);

    Ok(())
}

#[test]
fn new_datadir_initializes_current_schema_before_storage() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::write(config.data_dir.join(".CURRENT_SCHEMA.tmp"), b"partial")?;

    let data_dir = config.data_dir.clone();
    let _state = NodeState::open(config, None)?;
    assert_eq!(
        std::fs::read(data_dir.join(crate::checkpoint_fs::CURRENT_SCHEMA_FILE))?,
        crate::checkpoint_fs::current_schema_bytes()
    );
    assert!(!data_dir.join(".CURRENT_SCHEMA.tmp").exists());
    assert!(data_dir.join("chainstate").exists());
    Ok(())
}

#[test]
fn unmarked_nonempty_datadir_adopts_baseline_schema() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("legacy-node");
    config.p2p.listen.clear();
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::write(config.data_dir.join("legacy-state"), b"old")?;

    let data_dir = config.data_dir.clone();
    let _state = NodeState::open(config, None)?;
    assert_eq!(
        std::fs::read(data_dir.join(crate::checkpoint_fs::CURRENT_SCHEMA_FILE))?,
        b"0\n"
    );
    assert!(
        data_dir.join("chainstate").exists(),
        "baseline adoption must initialize storage"
    );
    Ok(())
}

#[test]
fn mismatched_datadir_schema_is_refused_before_storage_opens() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("old-node");
    config.p2p.listen.clear();
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::write(
        config
            .data_dir
            .join(crate::checkpoint_fs::CURRENT_SCHEMA_FILE),
        b"1\n",
    )?;

    let data_dir = config.data_dir.clone();
    let Err(error) = NodeState::open(config, None) else {
        anyhow::bail!("mismatched datadir schema unexpectedly opened");
    };
    let message = format!("{error:#}");
    assert!(message.contains("CURRENT_SCHEMA is not the current datadir schema epoch"));
    assert!(message.contains("full resync"));
    assert!(!data_dir.join("chainstate").exists());
    Ok(())
}

#[test]
fn shutdown_arc_is_shared_with_apply_handles() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    assert!(Arc::ptr_eq(&state.shutdown(), &state.chainstate().shutdown));
    Ok(())
}
