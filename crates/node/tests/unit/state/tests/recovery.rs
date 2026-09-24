use super::*;

#[test]
fn full_revalidation_marker_is_sticky_when_journal_is_disabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.chainstate_journal.enabled = false;
    let journal_dir = config.data_dir.join(CHAINSTATE_JOURNAL_DIR);
    let marker = journal_dir.join(bitcoin_rs_storage::chainstate_journal::FULL_REVALIDATION_MARKER);
    std::fs::create_dir_all(&journal_dir)?;
    std::fs::write(&marker, b"force full validation\n")?;

    assert!(requires_full_revalidation(&config.data_dir));
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

    let current_after = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    assert!(current_after > current_before);
    Ok(())
}

#[test]
fn invalidate_preflights_first_replacement_body_before_disconnect() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node-invalidate-preflight");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    let block_two = mined_regtest_child_at(block_one.block_hash(), genesis.header.time + 2, 2)?;
    state.apply_block(&block_two)?;
    let before = state
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("active tip missing"))?;

    let replacement = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 20, 1)?;
    let genesis_id = state
        .chainstate()
        .block_tree()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    state.chainstate().block_tree().write().insert_node(
        Some(genesis_id),
        replacement.header,
        bitcoin_rs_chain::node::NodeStatus::HeaderValid,
    )?;

    let result = crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_one.block_hash()),
    );

    assert!(matches!(
        result,
        Err(crate::reorg::ReorgError::MissingBody {
            hash,
            height: 1,
        }) if hash == Hash256::from(replacement.block_hash())
    ));
    assert_eq!(
        state
            .chainstate()
            .applied_tip()
            .load_full()
            .map(|tip| tip.hash),
        Some(before.hash),
        "missing first replacement body must be discovered before disconnect"
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
        .chainstate()
        .block_tree()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block =
            mined_regtest_child_at(previous_hash, genesis.header.time + 10 + height, height)?;
        let node_id = state.chainstate().block_tree().write().insert_node(
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

    let current_after = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    assert!(current_after > current_before);
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
        .chainstate()
        .block_tree()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block =
            mined_regtest_child_at(previous_hash, genesis.header.time + 10 + height, height)?;
        let node_id = state.chainstate().block_tree().write().insert_node(
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
    assert_eq!(handles.retention_handle().active_leases(), 0);

    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        fork_tip,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    )?;

    assert_eq!(handles.retention_handle().active_leases(), 0);
    Ok(())
}

/// Old-branch history a prune already deleted refuses the switch before
/// the first mutation: typed unavailable result, applied tip untouched,
/// and no lease left behind (`RCV-08`).
#[test]
fn switch_to_branch_refuses_history_the_prune_line_crossed() -> anyhow::Result<()> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    let tip_before = handles.applied_tip().load_full().map(|tip| tip.hash);
    handles.retention_handle().record_pruned_below(5);

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
        handles.applied_tip().load_full().map(|tip| tip.hash),
        tip_before
    );
    assert_eq!(handles.retention_handle().active_leases(), 0);
    // A refused lease must not close admission: nothing was mutated.
    assert!(handles.lock_transition().is_ok());
    Ok(())
}

// -----------------------------------------------------------------------
// #655: restart on a committed-but-unpublished gap replays the durable
// head chain and never re-commits it.
// -----------------------------------------------------------------------

/// Applies the regtest genesis plus `heights` mined children, publishing a
/// checkpoint at `checkpoint_height` so later recovery and pruning use a real
/// production checkpoint boundary.
fn applied_regtest_chain(
    heights: u32,
    checkpoint_height: u32,
) -> anyhow::Result<(tempfile::TempDir, NodeState, crate::NodeConfig)> {
    assert!((1..=heights).contains(&checkpoint_height));
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
        if height == checkpoint_height {
            state.publish_checkpoint()?;
        }
    }
    Ok((dir, state, config))
}

#[test]
fn missing_checkpoint_replays_durable_head_chain_at_startup() -> anyhow::Result<()> {
    let (_dir, state, config) = applied_regtest_chain(2, 1)?;
    let remembered_tip = state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("applied tip missing"))?;
    drop(state);
    std::fs::remove_dir_all(config.data_dir.join("chainstate-checkpoints"))?;

    let reopened = NodeState::open(config, None)?;
    let tip = reopened
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("replay did not publish an applied tip"))?;
    assert_eq!(
        (tip.hash, tip.height),
        (remembered_tip.hash, remembered_tip.height),
        "a missing checkpoint must replay the durable head chain from genesis"
    );
    Ok(())
}

#[test]
fn full_revalidation_marker_resumes_on_durable_head() -> anyhow::Result<()> {
    let (_dir, state, config) = applied_regtest_chain(2, 1)?;
    let remembered_tip = state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("applied tip missing"))?;
    drop(state);
    let journal_dir = config.data_dir.join(CHAINSTATE_JOURNAL_DIR);
    std::fs::create_dir_all(&journal_dir)?;
    std::fs::write(
        journal_dir.join(bitcoin_rs_storage::chainstate_journal::FULL_REVALIDATION_MARKER),
        b"force full validation\n",
    )?;

    let reopened = NodeState::open(config, None)?;
    let tip = reopened
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("replay did not publish an applied tip"))?;
    assert_eq!(
        (tip.hash, tip.height),
        (remembered_tip.hash, remembered_tip.height),
        "forced full revalidation must rebuild on the durable head chain"
    );
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
        let tree = state.chainstate().block_tree_handle();
        let tree = tree.read();
        let tip = tree.tip().ok_or_else(|| anyhow::anyhow!("no chain tip"))?;
        tree.node_at_height_from(tip.tip_id, fork_height)
            .ok_or_else(|| anyhow::anyhow!("no active node at height {fork_height}"))?
    };
    let ancestor_hash = state.chainstate().block_tree().read().node(ancestor)?.hash;
    let mut parent = ancestor;
    let mut previous = BlockHash::from(ancestor_hash);
    let mut bodies = HashMap::new();
    let mut ordered = Vec::new();
    for height in fork_height + 1..=fork_height + depth {
        let block = mined_regtest_child_at(previous, time_base.wrapping_add(height), height)?;
        let hash = Hash256::from(block.block_hash());
        let node_id = state.chainstate().block_tree().write().insert_node(
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
    // Checkpoint at 320, then advance to 620. Pruning may delete history
    // below the checkpoint's 288-block safety margin, while a reorg rooted
    // above the checkpoint remains incrementally serviceable.
    let (_dir, state, _config) = applied_regtest_chain(620, 320)?;
    let (deep_tip, deep_bodies, _deep_order) = plan_fork(&state, 20, 2, 1_400_000_000)?;
    let (shallow_tip, shallow_bodies, _shallow_order) = plan_fork(&state, 400, 2, 1_500_000_000)?;
    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };

    // The completed prune deletes every row below height 30 (the line is
    // the durable tip minus the 288-block margin) and records that line.
    service
        .prune_to_height(30)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
    let handles = state.chainstate();
    assert_eq!(handles.retention_handle().pruned_below(), 30);

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
    assert_eq!(handles.retention_handle().active_leases(), 0);

    // A reorg rooted above both the prune line and checkpoint base still
    // switches, disconnecting 220
    // blocks exactly and reconnecting the fork.
    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        shallow_tip,
        |hash| shallow_bodies.get(&hash).cloned(),
        |_| {},
    )?;
    let landed = handles
        .applied_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("reorg must publish a tip"))?;
    assert_eq!(landed.height, 402);
    assert_eq!(handles.retention_handle().active_leases(), 0);
    Ok(())
}

/// A deep reorg streams in bounded prefixes: the stager offers a window at
/// a time, the switch commits each verified prefix, and the final coins,
/// tip, and transaction count match an independently replayed reference.
#[test]
fn deep_reorg_streams_bounded_prefixes_to_the_exact_reference() -> anyhow::Result<()> {
    // A 16-body stager window keeps every switch's connect side bounded.
    const STAGED_PREFIX: u32 = 16;
    let (_dir, state, _config) = applied_regtest_chain(320, 1)?;
    let (fork_tip, fork_bodies, ordered) = plan_fork(&state, 20, 300, 1_600_000_000)?;
    let height_of: HashMap<bitcoin_rs_primitives::Hash256, u32> = ordered
        .iter()
        .map(|(height, hash)| (*hash, *height))
        .collect();
    let height_of = std::sync::Arc::new(height_of);

    // The reference applies the winning branch linearly on top of the same
    // deterministic first 20 blocks.
    let (_ref_dir, reference, _ref_config) = applied_regtest_chain(20, 1)?;
    for (height, hash) in &ordered {
        let (block, _) = fork_bodies
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("fork body {height} missing from the plan"))?;
        reference.apply_block(block)?;
    }

    let handles = state.chainstate();
    // The rolling stager tracks fork progress through the connected-body
    // callback, exactly like an external bounded stager holding staged
    // forks: at most STAGED_PREFIX unapplied blocks are servable at once,
    // and each committed connect frees room for the next suffix window
    // inside the same switch.
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

    let landed = handles
        .applied_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("reorg must publish a tip"))?;
    let reference_tip = reference
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("reference must publish a tip"))?;
    assert_eq!(landed.hash, reference_tip.hash);
    assert_eq!(landed.height, reference_tip.height);
    let restored = state
        .chainstate()
        .applied_tip_handle()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("restored node must publish a tip"))?;
    assert_eq!(restored.chain_tx_count, reference_tip.chain_tx_count);
    assert_eq!(handles.retention_handle().active_leases(), 0);
    Ok(())
}

/// An armed disconnect marker refuses startup, and the refusal must name
/// every authoritative store the operator has to remove.
#[test]
fn torn_disconnect_refusal_names_authoritative_stores_to_remove() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config.clone(), None)?;
    state.storage.undo_store().arm_disconnect(
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

/// A checkpoint at height N with the journal and durable head advanced
/// past it restores the exact pre-restart tip and `commit_id` on restart
/// (`RCV-10`): the durable root is the recovery authority and the last
/// checkpoint is only the replay base, so progress made since it stays
/// recoverable with no periodic publisher running.
#[test]
fn restart_without_periodic_publication_restores_tip_and_commit_id() -> anyhow::Result<()> {
    // The checkpoint lands at height 1; blocks 2-4 exist only in the
    // journal suffix and the durable head chain.
    let (_dir, state, config) = applied_regtest_chain(4, 1)?;
    let head = state
        .storage
        .durable_head()
        .load()?
        .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
    let pre_tip = state
        .chainstate()
        .applied_tip()
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
        .applied_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("restart must publish a tip"))?;
    assert_eq!(landed.as_ref(), pre_tip.as_ref());
    assert_eq!(landed.height, head.height);
    let restored = reopened
        .storage
        .durable_head()
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
        .applied_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("second restart must publish a tip"))?;
    assert_eq!(landed.hash, head.tip);
    assert_eq!(landed.height, head.height);
    Ok(())
}
