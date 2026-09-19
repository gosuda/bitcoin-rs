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
    let witness = bitcoin_rs_storage::recovery_evidence::read_witness(&data_dir, &genesis_hex)
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
    let stale_witness = bitcoin_rs_storage::recovery_evidence::AppliedTipWitness::new(
        genesis_hex,
        1, // older epoch
        5000,
        "cccc",
        1000,
    );
    bitcoin_rs_storage::recovery_evidence::write_witness(&data_dir, &stale_witness)?;

    // Reopen: the checkpoint at height 0 is restored, the witness at
    // 5000 triggers checkpoint-fallback detection. The warning store
    // must carry the fallback warning — the restore must not be silent.
    let resumed = NodeState::open(config.clone(), None)?;
    let warnings = resumed.recovery_reporter().0.warnings();
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

/// Builds the two-block fork fixture: applied genesis plus one mined child,
/// a checkpoint published, and a sibling two-block fork known to the header
/// tree with staged bodies.
type ForkFixture = (
    tempfile::TempDir,
    NodeState,
    bitcoin_rs_chain::NodeId,
    HashMap<bitcoin_rs_primitives::Hash256, (bitcoin_rs_primitives::Block, bytes::Bytes)>,
);

fn forked_regtest_state() -> anyhow::Result<ForkFixture> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

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
    Ok((dir, state, parent, fork_bodies))
}

/// A completed switch holds its retention lease only for its own duration:
/// the authority is back with pruning exactly once when it settles.
#[test]
fn switch_to_branch_releases_retention_authority_once() -> anyhow::Result<()> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    assert_eq!(handles.retention.active_leases(), 0);

    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        fork_tip,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    )?;

    assert_eq!(handles.retention.active_leases(), 0);
    Ok(())
}

/// Old-branch history a prune already deleted refuses the switch before
/// the first mutation: typed unavailable result, applied tip untouched,
/// and no lease left behind (`RCV-08`).
#[test]
fn switch_to_branch_refuses_history_the_prune_line_crossed() -> anyhow::Result<()> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    let tip_before = handles.applied_tip.load_full().map(|tip| tip.hash);
    handles.retention.record_pruned_below(5);

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        fork_tip,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    );

    assert!(matches!(
        outcome,
        Err(crate::reorg::ReorgError::RetentionUnavailable { floor: 1, .. })
    ));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        tip_before
    );
    assert_eq!(handles.retention.active_leases(), 0);
    // A refused lease must not close admission: nothing was mutated.
    assert!(handles.lock_transition().is_ok());
    Ok(())
}

// -----------------------------------------------------------------------
// #655: restart on a committed-but-unpublished gap replays the durable
// head chain and never re-commits it.
// -----------------------------------------------------------------------

/// Applies the regtest genesis plus `heights` mined children, publishing a
/// checkpoint after the first block so a later restore has a base under the
/// journal, with manual pruning enabled. Returns the temp dir, the node,
/// and a config for reopening the same datadir.
fn applied_regtest_chain(
    heights: u32,
) -> anyhow::Result<(tempfile::TempDir, NodeState, crate::NodeConfig)> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let mut previous = genesis.block_hash();
    let mut time = genesis.header.time;
    for height in 1..=heights {
        time += 1;
        let block = mined_regtest_child_at(previous, time, height)?;
        state.apply_block(&block)?;
        previous = block.block_hash();
        if height == 1 {
            state.publish_checkpoint()?;
        }
    }
    Ok((dir, state, config))
}

/// Rewinds only the publication tail of the last `count` applied blocks.
///
/// The durable head stays where it committed; the derived state returns to
/// exactly what a crash between the batch and the publication leaves:
/// journal rewound to the parent, applied tip on the parent, transaction
/// count rewound.
fn simulate_lost_publication(state: &NodeState, count: u32) -> anyhow::Result<()> {
    for _ in 0..count {
        let tip = state
            .chainstate()
            .applied_tip
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("no applied tip to rewind"))?;
        let (parent_tip, grandparent_hash, parent_tx_count) = {
            let tree = state.block_tree.read();
            let node = tree.node(tip.tip_id)?;
            let parent_id = node
                .parent
                .ok_or_else(|| anyhow::anyhow!("tip has no parent"))?;
            let parent = tree.node(parent_id)?;
            let grandparent_hash = match parent.parent {
                Some(grandparent) => tree.node(grandparent)?.hash.to_le_bytes(),
                None => [0_u8; 32],
            };
            let snapshot = bitcoin_rs_chain::TipSnapshot {
                tip_id: parent_id,
                height: parent.height,
                chainwork: parent.chainwork,
                hash: parent.hash,
            };
            (snapshot, grandparent_hash, parent.chain_tx_count)
        };
        if let Some(journal) = state.chainstate().journal.as_ref() {
            journal.lock().rewind_to(
                parent_tip.height,
                parent_tip.hash.to_le_bytes(),
                grandparent_hash,
                parent_tx_count,
            )?;
        }
        state
            .chain_tx_count
            .store(parent_tx_count, Ordering::Release);
        state
            .chainstate()
            .applied_tip
            .store(Some(std::sync::Arc::new(parent_tip)));
    }
    Ok(())
}

/// A restart on a committed-but-unpublished gap replays the durable head
/// chain through the ordinary commit path, lands exactly on the stored
/// head, keeps its `commit_id` untouched, and leaves a node that operates
/// normally — including a second restart that finds nothing to replay.
#[test]
fn boot_replays_the_committed_gap_without_recommitting_the_head() -> anyhow::Result<()> {
    let (_dir, state, config) = applied_regtest_chain(4)?;
    let head = state
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
    let config_head_tip = head.tip;
    let config_head_commit = head.commit_id;

    simulate_lost_publication(&state, 2)?;
    drop(state);

    let reopened = NodeState::open(config.clone(), None)?;
    let landed = reopened
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("replay must publish a tip"))?;
    assert_eq!(landed.hash, config_head_tip);
    assert_eq!(landed.height, 4);
    let head = reopened
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("head must survive the restart"))?;
    assert_eq!(head.tip, config_head_tip);
    assert_eq!(head.commit_id, config_head_commit);
    assert!(matches!(
        reopened.resume_source(),
        ResumeSource::Journal | ResumeSource::Checkpoint
    ));

    // The replay caught the journal up: a second restart replays nothing
    // and lands on the same head.
    drop(reopened);
    let second = NodeState::open(config, None)?;
    let landed = second
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("second boot must publish a tip"))?;
    assert_eq!(landed.hash, config_head_tip);
    assert_eq!(landed.height, 4);
    Ok(())
}

/// Restart at each committed ancestor is valid: whatever prefix the
/// crash-stranded publication represents, the replay lands on the head.
#[test]
fn boot_replays_from_every_committed_ancestor() -> anyhow::Result<()> {
    for lost in 0..=2_u32 {
        let (_dir, state, config) = applied_regtest_chain(4)?;
        let head = state
            .chainstate()
            .durable_head
            .load()?
            .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
        simulate_lost_publication(&state, lost)?;
        drop(state);

        let reopened = NodeState::open(config, None)?;
        let landed = reopened
            .chainstate()
            .applied_tip
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("replay must publish a tip"))?;
        assert_eq!(landed.hash, head.tip, "lost {lost} publications");
        assert_eq!(landed.height, head.height, "lost {lost} publications");
    }
    Ok(())
}

/// A gap whose durable facts are gone fails closed: the node refuses to
/// start rather than publish a fabricated history (`RCV-07`).
#[test]
fn boot_refuses_a_gap_whose_body_is_gone() -> anyhow::Result<()> {
    let (_dir, state, _config) = applied_regtest_chain(3)?;
    let head = state
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
    simulate_lost_publication(&state, 1)?;
    // Replace the gap block's locator row with one naming bytes that do
    // not exist: the body is durable-gone as far as replay can tell.
    state.storage.write_test_rows(&[(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        bitcoin_rs_storage::pruning::block_body_key(head.height, head.tip).to_vec(),
        bitcoin_rs_storage::BlockFilePosition {
            file_no: 99,
            offset: 0,
            len: 1,
        }
        .encode()
        .to_vec(),
    )])?;
    let config = state.config.clone();
    drop(state);

    let opened = NodeState::open(config, None);
    let error = opened
        .err()
        .ok_or_else(|| anyhow::anyhow!("open must fail"))?;
    let rendered = error.to_string();
    assert!(
        rendered.contains("cannot be replayed"),
        "open must fail on the unrecoverable gap, not silently: {rendered}"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// #634: restart with periodic full-checkpoint publication disabled.
// -----------------------------------------------------------------------

/// A checkpoint at height N with the journal and durable head advanced
/// past it restores the exact pre-restart tip and `commit_id` on restart
/// (`RCV-10`): the durable root is the recovery authority and the last
/// checkpoint is only the replay base, so progress made since it stays
/// recoverable with no periodic publisher running.
#[test]
fn restart_without_periodic_publication_restores_tip_and_commit_id() -> anyhow::Result<()> {
    // The checkpoint lands at height 1; blocks 2-4 exist only in the
    // journal suffix and the durable head chain.
    let (_dir, state, config) = applied_regtest_chain(4)?;
    let head = state
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
    let pre_tip = state
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("applied tip missing before restart"))?;
    assert_eq!(pre_tip.height, 4);
    drop(state);

    // `NodeState::open` spawns no workers: this restart runs with periodic
    // full-checkpoint publication disabled, recovery riding the stored
    // checkpoint, the journal suffix, and the durable head.
    let reopened = NodeState::open(config.clone(), None)?;
    let landed = reopened
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("restart must publish a tip"))?;
    assert_eq!(landed.as_ref(), pre_tip.as_ref());
    assert_eq!(landed.height, head.height);
    let restored = reopened
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("head must survive the restart"))?;
    assert_eq!(restored.tip, head.tip);
    assert_eq!(restored.commit_id, head.commit_id);
    assert!(matches!(
        reopened.resume_source(),
        ResumeSource::Journal | ResumeSource::Checkpoint
    ));

    // The replay caught the journal up: a second restart, still with no
    // periodic publisher, lands on the same head untouched.
    drop(reopened);
    let second = NodeState::open(config, None)?;
    let landed = second
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("second restart must publish a tip"))?;
    assert_eq!(landed.hash, head.tip);
    assert_eq!(landed.height, head.height);
    Ok(())
}

// -----------------------------------------------------------------------
// #655: prune-then-reorg and bounded deep-reorg scenarios.
// -----------------------------------------------------------------------

/// What one fork plan needs: the fork tip's node id, its staged bodies by
/// hash, and its blocks in height order.
type ForkPlan = (
    bitcoin_rs_chain::NodeId,
    HashMap<bitcoin_rs_primitives::Hash256, (bitcoin_rs_primitives::Block, bytes::Bytes)>,
    Vec<(u32, bitcoin_rs_primitives::Hash256)>,
);

/// Mines a `depth`-block fork off the active chain at `fork_height` and
/// inserts its headers, leaving its bodies for the caller's stager.
fn plan_fork(
    state: &NodeState,
    fork_height: u32,
    depth: u32,
    time_base: u32,
) -> anyhow::Result<ForkPlan> {
    let ancestor = {
        let tree = state.block_tree.read();
        let tip = tree.tip().ok_or_else(|| anyhow::anyhow!("no chain tip"))?;
        tree.node_at_height_from(tip.tip_id, fork_height)
            .ok_or_else(|| anyhow::anyhow!("no active node at height {fork_height}"))?
    };
    let ancestor_hash = state.block_tree.read().node(ancestor)?.hash;
    let mut parent = ancestor;
    let mut previous = BlockHash::from(ancestor_hash);
    let mut bodies = HashMap::new();
    let mut ordered = Vec::new();
    for height in fork_height + 1..=fork_height + depth {
        let block = mined_regtest_child_at(previous, time_base.wrapping_add(height), height)?;
        let hash = Hash256::from(block.block_hash());
        let node_id = state.block_tree.write().insert_node(
            Some(parent),
            block.header,
            bitcoin_rs_chain::node::NodeStatus::HeaderValid,
        )?;
        bodies.insert(
            hash,
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        ordered.push((height, hash));
        parent = node_id;
        previous = block.block_hash();
    }
    Ok((parent, bodies, ordered))
}

/// Pruning may delete what a future deep reorg needs; the reorg then
/// refuses with the defined unavailable result and the node stays whole.
/// A reorg whose ancestor survives pruning still switches exactly.
#[test]
fn prune_then_reorg_refuses_deleted_history_but_keeps_retained_reorgs() -> anyhow::Result<()> {
    let (_dir, state, _config) = applied_regtest_chain(320)?;
    state.durable_tip_height.store(320, Ordering::Release);
    let (deep_tip, deep_bodies, _deep_order) = plan_fork(&state, 20, 2, 1_400_000_000)?;
    let (shallow_tip, shallow_bodies, _shallow_order) = plan_fork(&state, 100, 2, 1_500_000_000)?;
    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };

    // The completed prune deletes every row below height 30 (the line is
    // the durable tip minus the 288-block margin) and records that line.
    service
        .prune_to_height(30)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
    let handles = state.chainstate();
    assert_eq!(handles.retention.pruned_below(), 30);

    // A reorg rooted below the recorded line needs deleted bodies; the
    // retention lease is refused before the first mutation.
    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        deep_tip,
        |hash| deep_bodies.get(&hash).cloned(),
        |_| {},
    );
    let Err(error) = outcome else {
        panic!("a reorg rooted in pruned history must be refused");
    };
    assert!(
        matches!(
            &error,
            crate::reorg::ReorgError::RetentionUnavailable { floor: 21, .. }
        ),
        "deep reorg must refuse deleted history, got: {error:?}"
    );
    assert_eq!(handles.retention.active_leases(), 0);

    // A reorg rooted above the line still switches, disconnecting 220
    // blocks exactly and reconnecting the fork.
    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        shallow_tip,
        |hash| shallow_bodies.get(&hash).cloned(),
        |_| {},
    )?;
    let landed = handles
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("reorg must publish a tip"))?;
    assert_eq!(landed.height, 102);
    assert_eq!(handles.retention.active_leases(), 0);
    Ok(())
}

/// A deep reorg streams in bounded prefixes: the stager offers a window at
/// a time, the switch commits each verified prefix, and the final coins,
/// tip, and transaction count match an independently replayed reference.
#[test]
fn deep_reorg_streams_bounded_prefixes_to_the_exact_reference() -> anyhow::Result<()> {
    // A 16-body stager window keeps every switch's connect side bounded.
    const STAGED_PREFIX: u32 = 16;
    let (_dir, state, _config) = applied_regtest_chain(320)?;
    let (fork_tip, fork_bodies, ordered) = plan_fork(&state, 20, 300, 1_600_000_000)?;
    let height_of: HashMap<bitcoin_rs_primitives::Hash256, u32> = ordered
        .iter()
        .map(|(height, hash)| (*hash, *height))
        .collect();
    let height_of = std::sync::Arc::new(height_of);

    // The reference applies the winning branch linearly on top of the same
    // deterministic first 20 blocks.
    let (_ref_dir, reference, _ref_config) = applied_regtest_chain(20)?;
    for (height, hash) in &ordered {
        let (block, _) = fork_bodies
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("fork body {height} missing from the plan"))?;
        reference.apply_block(block)?;
    }

    let handles = state.chainstate();
    // The rolling stager tracks fork progress through the connected-body
    // callback: each switch may connect at most STAGED_PREFIX new blocks,
    // and already-applied fork blocks stay servable for the disconnect
    // walk, exactly like an external bounded stager holding staged forks.
    let served_through = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(20));
    let mut switches = 0_u32;
    loop {
        switches += 1;
        assert!(
            switches <= 48,
            "bounded stepping did not converge after {switches} switches"
        );
        let served = served_through.clone();
        let reporter = served_through.clone();
        let reporter_heights = std::sync::Arc::clone(&height_of);
        let outcome = crate::reorg::switch_to_branch(
            &handles,
            &state.chain_followers(),
            fork_tip,
            |hash| match height_of.get(&hash) {
                Some(height) if *height <= served.load(Ordering::Acquire) + STAGED_PREFIX => {
                    fork_bodies.get(&hash).cloned()
                }
                _ => None,
            },
            move |hash| {
                if let Some(height) = reporter_heights.get(&hash) {
                    reporter.store(*height, Ordering::Release);
                }
            },
        );
        match outcome {
            Ok(()) => break,
            Err(crate::reorg::ReorgError::MissingBody { .. }) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    assert!(
        switches > 1,
        "a 300-block reorg through a 16-body stager must take multiple bounded switches"
    );

    let landed = handles
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("reorg must publish a tip"))?;
    let reference_tip = reference
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("reference must publish a tip"))?;
    assert_eq!(landed.hash, reference_tip.hash);
    assert_eq!(landed.height, reference_tip.height);
    assert_eq!(
        state.chain_tx_count.load(Ordering::Acquire),
        reference.chain_tx_count.load(Ordering::Acquire)
    );
    assert_eq!(handles.retention.active_leases(), 0);
    Ok(())
}
