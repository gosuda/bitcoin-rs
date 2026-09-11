use super::*;

#[test]
fn process_epoch_is_strictly_monotonic_across_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let first = NodeState::open(config.clone(), None)?
        .active_chain_snapshot()
        .epoch;
    let second = NodeState::open(config.clone(), None)?
        .active_chain_snapshot()
        .epoch;
    let third = NodeState::open(config, None)?.active_chain_snapshot().epoch;
    assert!(first > 0, "a fresh data dir allocates epoch 1, got {first}");
    assert!(
        second > first,
        "restart must never reuse an epoch: {first} -> {second}"
    );
    assert!(
        third > second,
        "restart must never reuse an epoch: {second} -> {third}"
    );
    Ok(())
}

#[test]
fn active_chain_snapshot_starts_at_genesis_on_fresh_node() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let state = NodeState::open(config.clone(), None)?;
    let epoch = state.chain_event_publisher().epoch();
    assert_eq!(
        state.active_chain_snapshot(),
        ChainSnapshot {
            epoch,
            sequence: 0,
            tip_hash: config.network.genesis_block_hash(),
            tip_height: 0,
        },
        "a node that committed nothing anchors at genesis with sequence 0"
    );
    Ok(())
}

#[test]
fn active_chain_snapshot_anchors_at_restored_tip_after_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let (tip, first_epoch) = {
        let state = NodeState::open(config.clone(), None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let tip = state.apply_block(&genesis)?;
        assert!(matches!(
            state.write_clean_checkpoint()?,
            crate::checkpoint::CheckpointWrite::Published { .. }
        ));
        (tip, state.active_chain_snapshot().epoch)
    };

    let resumed = NodeState::open(config, None)?;
    assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
    let snapshot = resumed.active_chain_snapshot();
    assert_eq!(snapshot.tip_hash, tip.hash);
    assert_eq!(snapshot.tip_height, tip.height);
    assert_eq!(
        snapshot.sequence, 0,
        "a restart resets the sequence, never the epoch"
    );
    assert!(
        snapshot.epoch > first_epoch,
        "restart must advance the epoch: {} -> {}",
        first_epoch,
        snapshot.epoch
    );
    Ok(())
}

#[test]
fn record_publishes_snapshot_and_hints_in_commit_order() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let state = NodeState::open(config, None)?;
    let publisher = state.chain_event_publisher();
    let epoch = publisher.epoch();
    let hash_a = Hash256::from_le_bytes(&[0xAA; 32]);
    let hash_b = Hash256::from_le_bytes(&[0xBB; 32]);

    let first = publisher.record(HintKind::Connected, 1, hash_a);
    let second = publisher.record(HintKind::Disconnected, 0, hash_b);

    let expected_first = ChainEventHint {
        kind: HintKind::Connected,
        height: 1,
        hash: hash_a,
        epoch,
        sequence: 1,
    };
    let expected_second = ChainEventHint {
        kind: HintKind::Disconnected,
        height: 0,
        hash: hash_b,
        epoch,
        sequence: 2,
    };
    assert_eq!(first, expected_first);
    assert_eq!(second, expected_second);
    assert_eq!(
        publisher.snapshot(),
        state.active_chain_snapshot(),
        "node and publisher expose one snapshot view"
    );
    assert_eq!(
        state.active_chain_snapshot(),
        ChainSnapshot {
            epoch,
            sequence: 2,
            tip_hash: hash_b,
            tip_height: 0,
        },
        "the last committed event wins the snapshot cell"
    );

    let rx = state.chain_event_hints();
    let mut hints = Vec::new();
    let hint_rx = rx.lock();
    while let Ok(hint) = hint_rx.try_recv() {
        hints.push(hint);
    }
    assert_eq!(
        hints,
        vec![expected_first, expected_second],
        "one hint per committed event, in commit order"
    );
    Ok(())
}

#[test]
fn record_drops_hints_when_channel_full() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let state = NodeState::open(config, None)?;
    let publisher = state.chain_event_publisher();
    let rx = state.chain_event_hints();
    for sequence in 1..=super::CHAIN_HINT_CHANNEL_LIMIT {
        let sequence = u64::try_from(sequence)?;
        let mut tip = [0_u8; 32];
        tip[..8].copy_from_slice(&sequence.to_le_bytes());
        publisher.record(
            HintKind::Connected,
            u32::try_from(sequence)?,
            Hash256::from_le_bytes(&tip),
        );
    }

    // The next record finds a full channel: the hint is dropped by
    // design, while the commit itself still lands and the snapshot
    // still advances. Dropping never blocks or fails the commit path.
    let overflow = publisher.record(
        HintKind::Connected,
        u32::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)?,
        Hash256::from_le_bytes(&[0xFF; 32]),
    );
    assert_eq!(
        overflow.sequence,
        u64::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)? + 1,
        "the record itself is sequenced even when its hint is dropped"
    );
    assert_eq!(
        state.active_chain_snapshot(),
        ChainSnapshot {
            epoch: publisher.epoch(),
            sequence: overflow.sequence,
            tip_hash: Hash256::from_le_bytes(&[0xFF; 32]),
            tip_height: u32::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)?,
        },
    );

    let mut drained = Vec::new();
    let drain_rx = rx.lock();
    while let Ok(hint) = drain_rx.try_recv() {
        drained.push(hint.sequence);
    }
    assert_eq!(
        drained.len(),
        super::CHAIN_HINT_CHANNEL_LIMIT,
        "exactly the bounded hints are queued"
    );
    assert_eq!(drained[0], 1, "the oldest hint survives at the front");
    assert_eq!(
        drained.last().copied(),
        Some(u64::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)?),
        "the overflow hint is the one that was dropped"
    );
    Ok(())
}

#[test]
fn corrupt_process_epoch_file_refuses_start() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(&data_dir)?;
    std::fs::write(data_dir.join("process-epoch"), b"seven\n")?;

    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();

    let Err(error) = NodeState::open(config, None) else {
        anyhow::bail!("a corrupt process-epoch file must refuse startup");
    };
    assert!(
        error.to_string().contains("process-epoch"),
        "the refusal names the corrupt file: {error}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("node").join("process-epoch"))?,
        b"seven\n",
        "the refusal must not reset the persisted epoch"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_epoch_lock_refuses_start() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(&data_dir)?;
    std::fs::write(data_dir.join("process-epoch"), b"41\n")?;
    std::os::unix::fs::symlink("process-epoch", data_dir.join(".process-epoch.lock"))?;

    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();

    let Err(error) = NodeState::open(config, None) else {
        anyhow::bail!("a symlinked epoch lock must refuse startup");
    };
    assert!(
        error.to_string().contains("process epoch lock"),
        "the refusal names the lock target: {error:#}"
    );
    assert_eq!(
        std::fs::read_to_string(data_dir.join("process-epoch"))?,
        "41\n",
        "the symlink must not be followed and the epoch must not reset"
    );
    Ok(())
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
#[cfg(not(target_vendor = "apple"))]
fn non_regular_epoch_lock_refuses_start() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(&data_dir)?;
    std::fs::write(data_dir.join("process-epoch"), b"7\n")?;
    let lock_dir = cap_std::fs::Dir::open_ambient_dir(&data_dir, cap_std::ambient_authority())?;
    rustix::fs::mkfifoat(
        &lock_dir,
        ".process-epoch.lock",
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;

    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();

    let Err(error) = NodeState::open(config, None) else {
        anyhow::bail!("a non-regular epoch lock must refuse startup");
    };
    assert!(
        error.to_string().contains("not a regular file"),
        "the refusal names the lock type: {error:#}"
    );
    assert_eq!(
        std::fs::read_to_string(data_dir.join("process-epoch"))?,
        "7\n",
        "the refusal must not reset the persisted epoch"
    );
    Ok(())
}
