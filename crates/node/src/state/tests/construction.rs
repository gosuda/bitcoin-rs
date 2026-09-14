use super::*;

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
        std::fs::read(data_dir.join(crate::checkpoint::fs::CURRENT_SCHEMA_FILE))?,
        crate::checkpoint::fs::current_schema_bytes()
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
        std::fs::read(data_dir.join(crate::checkpoint::fs::CURRENT_SCHEMA_FILE))?,
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
            .join(crate::checkpoint::fs::CURRENT_SCHEMA_FILE),
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
