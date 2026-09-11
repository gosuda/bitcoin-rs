use super::*;

#[test]
fn full_revalidation_marker_is_sticky_when_journal_is_disabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.chainstate_journal.enabled = false;
    let journal_dir = config.data_dir.join(CHAINSTATE_JOURNAL_DIR);
    let marker = journal_dir.join(crate::chainstate_journal::FULL_REVALIDATION_MARKER);
    std::fs::create_dir_all(&journal_dir)?;
    std::fs::write(&marker, b"force full validation\n")?;

    assert!(requires_full_revalidation(&config.data_dir));
    Ok(())
}

#[test]
fn checkpoint_refuses_inflight_disconnect_and_preserves_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    assert!(matches!(
        state.write_clean_checkpoint()?,
        crate::checkpoint::CheckpointWrite::Published { .. }
    ));

    let checkpoint_root = data_dir.join("chainstate-checkpoints");
    let armed_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xab; 32]);
    let armed_height = 10;
    state
        .chainstate()
        .undo_store
        .arm_disconnect(armed_height, armed_hash)?;
    let marker_before = state.chainstate().undo_store.load_disconnect_marker()?;
    let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
    let mut dirs_before = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&checkpoint_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs_before.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }

    let result = state.write_clean_checkpoint();
    let Err(crate::checkpoint::CheckpointError::DisconnectInFlight { hash, height }) = result
    else {
        anyhow::bail!("expected DisconnectInFlight refusal, got {result:?}");
    };
    assert_eq!(hash, armed_hash);
    assert_eq!(height, armed_height);

    let marker_after = state.chainstate().undo_store.load_disconnect_marker()?;
    let current_after = std::fs::read(checkpoint_root.join("CURRENT"))?;
    let mut dirs_after = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&checkpoint_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs_after.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }

    assert_eq!(marker_before, marker_after);
    assert_eq!(current_before, current_after);
    assert_eq!(dirs_before, dirs_after);
    Ok(())
}

#[test]
fn torn_disconnect_refusal_names_authoritative_stores_to_remove() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config.clone(), None)?;
    state.chainstate().undo_store.arm_disconnect(
        10,
        bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xcd; 32]),
    )?;
    drop(state);

    let error = match NodeState::open(config, None) {
        Ok(_) => anyhow::bail!("node reopened with an armed disconnect marker"),
        Err(error) => error,
    };
    let message = error.to_string();
    for store in ["chainstate", "chainstate-checkpoints", "txindex"] {
        let path = data_dir.join(store);
        assert!(
            message.contains(&path.display().to_string()),
            "startup refusal omitted {}: {message}",
            path.display()
        );
    }
    Ok(())
}

#[test]
fn invalidate_block_settles_disconnect_debt() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    // Journal rewind disarms disconnect markers itself. These tests own the
    // checkpoint-settlement path that remains when the journal cannot.
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let current_before = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    let block_two = mined_regtest_child_at(block_one.block_hash(), genesis.header.time + 2, 2)?;
    state.apply_block(&block_two)?;

    crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_two.block_hash()),
    )?;

    assert!(
        state
            .chainstate()
            .undo_store
            .load_disconnect_marker()?
            .is_none()
    );
    let current_after = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    assert!(current_after > current_before);
    assert_eq!(state.durable_tip_height.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn invalidate_block_settlement_failure_is_not_success() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let block_two = mined_regtest_child_at(block_one.block_hash(), genesis.header.time + 2, 2)?;
    state.apply_block(&block_two)?;

    crate::checkpoint::inject_next_checkpoint_failpoint(
        crate::checkpoint::CheckpointFailpoint::ManifestWrite,
    );
    let result = crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_two.block_hash()),
    );
    let Err(crate::reorg::ReorgError::CheckpointSettlement(_)) = result else {
        anyhow::bail!("expected CheckpointSettlement, got {result:?}");
    };

    let marker = state
        .chainstate()
        .undo_store
        .load_disconnect_marker()?
        .ok_or_else(|| anyhow::anyhow!("settlement failure cleared the disconnect marker"))?;
    assert_eq!(
        marker.phase,
        bitcoin_rs_storage::DisconnectPhase::RolledBack
    );

    drop(state);
    let error = match NodeState::open(config, None) {
        Ok(_) => anyhow::bail!("node reopened with unsettled RolledBack debt"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("did not reach a clean checkpoint"),
        "startup refusal omitted the checkpoint debt: {error}"
    );
    Ok(())
}

#[test]
fn switch_to_branch_settles_disconnect_debt() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let current_before = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;

    let genesis_id = state
        .block_tree
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block =
            mined_regtest_child_at(previous_hash, genesis.header.time + 10 + height, height)?;
        let node_id = state.block_tree.write().insert_node(
            Some(parent),
            block.header,
            bitcoin_rs_chain::node::NodeStatus::HeaderValid,
        )?;
        fork_bodies.insert(
            Hash256::from(block.block_hash()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        parent = node_id;
        previous_hash = block.block_hash();
    }

    let handles = state.chainstate();
    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        parent,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    )?;

    assert!(
        state
            .chainstate()
            .undo_store
            .load_disconnect_marker()?
            .is_none()
    );
    let current_after = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    assert!(current_after > current_before);
    assert_eq!(state.durable_tip_height.load(Ordering::Acquire), 2);
    Ok(())
}

// -----------------------------------------------------------------------
// A2 cycle 3: witness is published only after CURRENT root fsync
// -----------------------------------------------------------------------

#[test]
fn witness_is_published_only_after_current_root_sync() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();

    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let tip = state.apply_block(&genesis)?;

    // Publish a checkpoint — witness must be written after Published.
    state.publish_checkpoint()?;
    let witness_path = data_dir.join("applied-tip-witness.json");
    assert!(
        witness_path.exists(),
        "witness file must exist after checkpoint publication"
    );
    let genesis_hex = config.network.genesis_block_hash().to_string_be();
    let witness = crate::recovery_evidence::read_witness(&data_dir, &genesis_hex)
        .ok_or_else(|| anyhow::anyhow!("witness must be readable"))?;
    assert_eq!(witness.height, tip.height);
    assert_eq!(witness.block_hash, tip.hash.to_string_be());
    drop(state);

    // Now inject a failpoint at CurrentRootSync — the last stage before
    // the checkpoint is considered Published. The checkpoint must fail,
    // and no new witness must be written for the failed checkpoint.
    let dir2 = tempfile::tempdir()?;
    let data_dir2 = dir2.path().join("node");
    let mut config2 = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config2.data_dir = data_dir2.clone();
    config2.p2p.listen.clear();

    let state2 = NodeState::open(config2.clone(), None)?;
    let genesis2 = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state2.apply_block(&genesis2)?;

    // Inject failpoint at the final root fsync — checkpoint fails before
    // returning Published, so no witness should be written.
    crate::checkpoint::inject_next_checkpoint_failpoint(
        crate::checkpoint::CheckpointFailpoint::CurrentRootSync,
    );
    let result = state2.publish_checkpoint();
    assert!(
        result.is_err(),
        "checkpoint must fail when CurrentRootSync fails"
    );
    let witness_path2 = data_dir2.join("applied-tip-witness.json");
    assert!(
        !witness_path2.exists(),
        "no witness must be written when checkpoint fails before publication"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// #208: a checkpoint restore far behind the durable witness must be loud
// -----------------------------------------------------------------------

#[test]
fn stale_checkpoint_restore_surfaces_warning_not_silence() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;

    // Apply genesis and publish a checkpoint at height 0.
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    state.write_clean_checkpoint()?;
    drop(state);

    // Simulate the #208 scenario: the node previously ran far ahead
    // (height 5000) and published a checkpoint there, writing a witness
    // at that height. A crash or clean stop left the checkpoint tree
    // pinned at height 0 while the witness records height 5000.
    let genesis_hex = config.network.genesis_block_hash().to_string_be();
    let stale_witness = crate::recovery_evidence::AppliedTipWitness::new(
        genesis_hex,
        1, // older epoch
        5000,
        "cccc",
        1000,
    );
    crate::recovery_evidence::write_witness(&data_dir, &stale_witness)?;

    // Reopen: the checkpoint at height 0 is restored, the witness at
    // 5000 triggers checkpoint-fallback detection. The warning store
    // must carry the fallback warning — the restore must not be silent.
    let resumed = NodeState::open(config.clone(), None)?;
    let warnings = resumed.warning_store().warnings();
    assert!(
        !warnings.is_empty(),
        "a stale checkpoint restore 5000 blocks behind the witness must \
         produce at least one rollback warning, not silence"
    );
    assert!(
        warnings.iter().any(|w| w.contains("height 5000")),
        "the warning must name the witness height; got: {warnings:?}"
    );
    assert_eq!(
        resumed.resume_source(),
        ResumeSource::Checkpoint,
        "the checkpoint is still accepted — it is valid, just stale"
    );
    Ok(())
}
