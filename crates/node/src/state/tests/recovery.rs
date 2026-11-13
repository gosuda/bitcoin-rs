use super::*;
use crate::state::open::NodeOpenError;
use crate::test_support::TestError;
use sonic_rs::JsonValueTrait as _;

const CRASH_TEST_BACKEND_ENV: &str = "BITCOIN_RS_CRASH_TEST_BACKEND";

fn crash_test_backend(
    default: bitcoin_rs_storage::StorageBackend,
) -> bitcoin_rs_storage::StorageBackend {
    let value = match std::env::var(CRASH_TEST_BACKEND_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return default,
        Err(error) => panic!("invalid {CRASH_TEST_BACKEND_ENV}: {error}"),
    };
    let backend: bitcoin_rs_storage::StorageBackend = match value.parse() {
        Ok(backend) => backend,
        Err(error) => panic!("invalid {CRASH_TEST_BACKEND_ENV} {value:?}: {error}"),
    };
    assert!(
        backend.is_compiled_in(),
        "BITCOIN_RS_CRASH_TEST_BACKEND {value:?} is not compiled into this test binary"
    );
    backend
}

#[test]
fn full_revalidation_marker_is_sticky_in_the_datadir() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    std::fs::create_dir_all(&config.data_dir)?;
    let marker = config
        .data_dir
        .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER);
    std::fs::write(&marker, b"force full validation\n")?;

    assert!(requires_full_revalidation(&config.data_dir));
    Ok(())
}

#[test]
fn invalidate_block_settles_disconnect_debt() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let block_one = regtest_fixture::mined_regtest_child_at_time(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_one.clone(),
    ))?;
    state.publish_checkpoint()?;

    let block_two = regtest_fixture::mined_regtest_child_at_time(
        block_one.block_hash(),
        genesis.header.time + 2,
        2,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_two.clone(),
    ))?;

    crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_two.block_hash()),
    )?;

    let head = state
        .storage
        .durable_head()
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(head.height, 1);
    assert_eq!(head.tip, Hash256::from(block_one.block_hash()));
    assert!(
        state.undo_store().load_disconnect_marker()?.is_none(),
        "settling debt against the engine disarms the disconnect marker"
    );
    let tip = state
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("applied tip after invalidation"))?;
    assert_eq!(tip.height, 1);
    assert_eq!(tip.hash, Hash256::from(block_one.block_hash()));

    drop(state);
    let reopened = NodeState::open(config, None)?;
    let reopened_tip = reopened
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("reopened tip"))?;
    assert_eq!(reopened_tip.height, 1);
    assert_eq!(reopened_tip.hash, Hash256::from(block_one.block_hash()));
    Ok(())
}

#[test]
fn below_base_invalidate_settles_debt_against_engine() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let block_one = regtest_fixture::mined_regtest_child_at_time(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_one.clone(),
    ))?;
    state.publish_checkpoint()?;
    let block_two = regtest_fixture::mined_regtest_child_at_time(
        block_one.block_hash(),
        genesis.header.time + 2,
        2,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_two,
    ))?;

    crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_one.block_hash()),
    )?;

    let head = state
        .storage
        .durable_head()
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        (head.height, head.tip),
        (0, Hash256::from(genesis.block_hash())),
        "settlement must record the rolled-back head in the engine"
    );
    assert!(
        state.undo_store().load_disconnect_marker()?.is_none(),
        "settling debt against the engine disarms the disconnect marker"
    );
    let tip = state
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("applied tip after invalidation"))?;
    assert_eq!(
        (tip.height, tip.hash),
        (0, Hash256::from(genesis.block_hash()))
    );

    let mut previous = genesis.block_hash();
    for height in 1..=2 {
        let replacement = regtest_fixture::mined_regtest_child_at_time(
            previous,
            genesis.header.time + 10 + height,
            height,
        )?;
        previous = replacement.block_hash();
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            replacement,
        ))?;
    }
    let tip = state
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("rebuilt tip"))?;
    assert_eq!(tip.height, 2);

    drop(state);
    let reopened = NodeState::open(config, None)?;
    let reopened_tip = reopened
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("reopened tip"))?;
    assert_eq!(
        (reopened_tip.height, reopened_tip.hash),
        (2, Hash256::from(previous)),
    );
    Ok(())
}

#[test]
fn invalidate_preflights_first_replacement_body_before_disconnect() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node-invalidate-preflight");
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let block_one = regtest_fixture::mined_regtest_child_at_time(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_one.clone(),
    ))?;
    let block_two = regtest_fixture::mined_regtest_child_at_time(
        block_one.block_hash(),
        genesis.header.time + 2,
        2,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_two,
    ))?;
    let before = state
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("active tip"))?;

    let replacement = regtest_fixture::mined_regtest_child_at_time(
        genesis.block_hash(),
        genesis.header.time + 20,
        1,
    )?;
    let genesis_id = state
        .chainstate()
        .block_tree()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or(TestError::Missing("genesis node"))?;
    crate::sync::fixture_insert_header_node(
        &state.chainstate(),
        genesis_id,
        replacement.header,
        bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
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
fn switch_to_branch_settles_disconnect_debt() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let block_one = regtest_fixture::mined_regtest_child_at_time(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_one,
    ))?;
    state.publish_checkpoint()?;

    let genesis_id = state
        .chainstate()
        .block_tree()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or(TestError::Missing("genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block = regtest_fixture::mined_regtest_child_at_time(
            previous_hash,
            genesis.header.time + 10 + height,
            height,
        )?;
        let node_id = crate::sync::fixture_insert_header_node(
            &state.chainstate(),
            parent,
            block.header,
            bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
        )?;
        fork_bodies.insert(
            Hash256::from(block.block_hash()),
            bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
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

    let head = state
        .storage
        .durable_head()
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(head.height, 2);
    assert_eq!(head.tip, Hash256::from(previous_hash));
    assert!(state.undo_store().load_disconnect_marker()?.is_none());
    let tip = handles
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("applied tip after branch switch"))?;
    assert_eq!(tip.height, 2);
    assert_eq!(tip.hash, Hash256::from(previous_hash));

    drop(handles);
    drop(state);
    let reopened = NodeState::open(config, None)?;
    let reopened_tip = reopened
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("reopened tip"))?;
    assert_eq!(reopened_tip.height, 2);
    assert_eq!(reopened_tip.hash, Hash256::from(previous_hash));
    Ok(())
}

#[test]
fn witness_is_published_only_after_current_root_sync() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);

    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    let tip = state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis,
    ))?;

    state.publish_checkpoint()?;
    let witness_path = data_dir.join("applied-tip-witness.json");
    assert!(
        witness_path.exists(),
        "witness file must exist after checkpoint publication"
    );
    let genesis_hex = config.network.genesis_block_hash().to_string_be();
    let witness = bitcoin_rs_storage::recovery_evidence::read_witness(&data_dir, &genesis_hex)
        .ok_or(TestError::Missing("durable witness"))?;
    assert_eq!(witness.height, tip.height);
    assert_eq!(witness.block_hash, tip.hash.to_string_be());
    drop(state);

    Ok(())
}

#[test]
fn stale_checkpoint_restore_surfaces_warning_not_silence() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;

    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis,
    ))?;
    assert!(state.publish_checkpoint()?.is_some());
    drop(state);

    let genesis_hex = config.network.genesis_block_hash().to_string_be();
    let stale_witness = bitcoin_rs_storage::recovery_evidence::AppliedTipWitness::new(
        genesis_hex,
        1,
        5000,
        "cccc",
        1000,
    );
    bitcoin_rs_storage::recovery_evidence::write_witness(&data_dir, &stale_witness)?;

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

type ForkFixture = (
    tempfile::TempDir,
    NodeState,
    bitcoin_rs_execution::chain::NodeId,
    HashMap<
        bitcoin_rs_consensus::primitives::Hash256,
        bitcoin_rs_consensus::primitives::BlockImage,
    >,
);

fn forked_regtest_state() -> Result<ForkFixture, TestError> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let block_one = regtest_fixture::mined_regtest_child_at_time(
        genesis.block_hash(),
        genesis.header.time + 1,
        1,
    )?;
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        block_one,
    ))?;
    state.publish_checkpoint()?;

    let genesis_id = state
        .chainstate()
        .block_tree()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or(TestError::Missing("genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block = regtest_fixture::mined_regtest_child_at_time(
            previous_hash,
            genesis.header.time + 10 + height,
            height,
        )?;
        let node_id = crate::sync::fixture_insert_header_node(
            &state.chainstate(),
            parent,
            block.header,
            bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
        )?;
        fork_bodies.insert(
            Hash256::from(block.block_hash()),
            bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
        );
        parent = node_id;
        previous_hash = block.block_hash();
    }
    Ok((dir, state, parent, fork_bodies))
}

#[test]
fn switch_to_branch_releases_retention_authority_once() -> Result<(), TestError> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    assert_eq!(state.storage.retention().active_leases(), 0);

    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        fork_tip,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    )?;

    assert_eq!(state.storage.retention().active_leases(), 0);
    Ok(())
}

#[test]
fn switch_to_branch_refuses_history_the_prune_line_crossed() -> Result<(), TestError> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    let tip_before = handles.applied_tip().load_full().map(|tip| tip.hash);
    let reservation = state.storage.retention().reserve(5);
    reservation.commit(5);

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
    assert_eq!(state.storage.retention().active_leases(), 0);
    assert!(handles.lock_transition().is_ok());
    Ok(())
}

fn applied_regtest_chain(
    heights: u32,
    checkpoint_height: u32,
) -> Result<(tempfile::TempDir, NodeState, crate::NodeConfig), TestError> {
    assert!((1..=heights).contains(&checkpoint_height));
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.backend = crash_test_backend(config.storage.backend);
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
        genesis.clone(),
    ))?;
    let mut previous = genesis.block_hash();
    let mut time = genesis.header.time;
    for height in 1..=heights {
        time += 1;
        let block = regtest_fixture::mined_regtest_child_at_time(previous, time, height)?;
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            block.clone(),
        ))?;
        previous = block.block_hash();
        if height == checkpoint_height {
            state.publish_checkpoint()?;
        }
    }
    Ok((dir, state, config))
}

#[test]
fn missing_checkpoint_replays_durable_head_chain_at_startup() -> Result<(), TestError> {
    let (_dir, state, config) = applied_regtest_chain(2, 1)?;
    let remembered_tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    let committed_coins = state
        .chainstate()
        .coins()
        .scan_snapshot()?
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()?;
    let root = config.data_dir.join("chainstate-checkpoints");
    let current: sonic_rs::Value = sonic_rs::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
    let directory = current
        .get("directory")
        .and_then(|value| value.as_str())
        .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
    let image = root.join(directory).join("chainstate");
    let missing_image = root.join(directory).join("chainstate.missing");
    std::fs::rename(&image, &missing_image)?;
    drop(state);

    let open_result = NodeState::open(config.clone(), None);
    std::fs::rename(&missing_image, &image)?;
    let error = open_result.err().ok_or(TestError::UnexpectedSuccess(
        "missing checkpoint engine image was accepted",
    ))?;
    assert!(
        matches!(
            &error,
            NodeOpenError::Recovery(source)
                if matches!(
                    source.as_ref(),
                    bitcoin_rs_execution::recovery::RecoveryError::CheckpointEngineImageMissing
                )
        ),
        "unexpected missing-image refusal: {error:#}"
    );

    std::fs::remove_dir_all(root)?;
    let reopened = NodeState::open(config, None)?;
    let tip = reopened
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("replayed applied tip"))?;
    assert_eq!(
        (tip.hash, tip.height),
        (remembered_tip.hash, remembered_tip.height),
        "a missing checkpoint must replay the durable head chain from genesis"
    );
    let reopened_coins = reopened
        .chainstate()
        .coins()
        .scan_snapshot()?
        .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        reopened_coins, committed_coins,
        "newer committed coin rows must survive the missing-image refusal"
    );
    Ok(())
}

#[test]
fn committed_frame_corruption_refuses_startup_and_preserves_all_bytes() -> Result<(), TestError> {
    for keep_checkpoint in [false, true] {
        for corrupt_length in [false, true] {
            let (_dir, state, config) = applied_regtest_chain(2, 2)?;
            drop(state);
            if !keep_checkpoint {
                std::fs::remove_dir_all(config.data_dir.join("chainstate-checkpoints"))?;
            }
            let path = config.data_dir.join("blocks/blk00000.dat");
            let mut damaged = std::fs::read(&path)?;
            let genesis_len = u32::from_le_bytes(damaged[4..8].try_into()?);
            let middle = 44 + usize::try_from(genesis_len)?;
            assert_eq!(&damaged[middle..middle + 4], b"BRSB");
            if corrupt_length {
                damaged[middle + 4..middle + 8].copy_from_slice(&u32::MAX.to_le_bytes());
            } else {
                damaged[middle] ^= 0xff;
            }
            std::fs::write(&path, &damaged)?;
            let error = NodeState::open(config, None)
                .err()
                .ok_or(TestError::UnexpectedSuccess(
                    "committed corruption was accepted",
                ))?;
            assert!(
                matches!(
                    error,
                    NodeOpenError::Storage(bitcoin_rs_storage::StorageError::IncompatibleData(_))
                ),
                "unexpected refusal: {error:#}"
            );
            assert_eq!(std::fs::read(path)?, damaged);
        }
    }
    Ok(())
}

#[test]
fn startup_verification_refuses_a_corrupt_tip_body() -> Result<(), TestError> {
    use bitcoin_rs_execution::verify::VerifyError;

    let (_dir, state, config) = applied_regtest_chain(2, 2)?;
    drop(state);
    let data_dir = config.data_dir.clone();
    let path = data_dir.join("blocks/blk00000.dat");
    let mut damaged = std::fs::read(&path)?;
    *damaged.last_mut().ok_or(TestError::Missing("block file"))? ^= 0xff;
    std::fs::write(&path, &damaged)?;

    let error = NodeState::open(config, None)
        .err()
        .ok_or(TestError::UnexpectedSuccess(
            "a damaged tip body was accepted",
        ))?;
    let NodeOpenError::StartupVerification { paths, source, .. } = &error else {
        return Err(TestError::ExpectationFailed(
            "a damaged tip body must refuse startup verification",
        ));
    };
    assert!(
        matches!(source, VerifyError::Binding { height: 2, .. }),
        "unexpected refusal: {error:#}"
    );
    assert_eq!(
        paths.checkpoints,
        data_dir.join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT),
        "the operator must be pointed at the checkpoint root that holds the files"
    );
    assert!(
        paths.checkpoints.is_dir(),
        "the named checkpoint directory must exist: {}",
        paths.checkpoints.display()
    );
    assert_eq!(
        paths.txindex,
        data_dir.join(crate::state::TXINDEX_NAMESPACE),
        "the operator must be pointed at the txindex namespace directory"
    );
    assert_eq!(
        std::fs::read(&path)?,
        damaged,
        "refusing to start must not repair or truncate the block file"
    );
    Ok(())
}

#[test]
fn checkpoint_resume_discards_only_incomplete_uncommitted_tail() -> Result<(), TestError> {
    use std::io::Write as _;

    let (_dir, state, config) = applied_regtest_chain(2, 2)?;
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("fixture tip"))?;
    drop(state);
    let path = config.data_dir.join("blocks/blk00000.dat");
    let committed = std::fs::read(&path)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(b"BR")?;
    let reopened = NodeState::open(config, None)?;
    assert_eq!(std::fs::read(&path)?, committed);
    assert_eq!(
        reopened
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| tip.hash),
        Some(tip.hash)
    );
    Ok(())
}

#[test]
fn full_revalidation_marker_resumes_on_durable_head() -> Result<(), TestError> {
    let (_dir, state, config) = applied_regtest_chain(2, 1)?;
    let remembered_tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    drop(state);
    std::fs::write(
        config
            .data_dir
            .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER),
        b"force full validation\n",
    )?;

    let reopened = NodeState::open(config, None)?;
    let tip = reopened
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("replayed applied tip"))?;
    assert_eq!(
        (tip.hash, tip.height),
        (remembered_tip.hash, remembered_tip.height),
        "forced full revalidation must rebuild on the durable head chain"
    );
    Ok(())
}
// SYNC-05
#[test]
fn full_revalidation_cold_open_wipes_stale_engine_coins() -> Result<(), TestError> {
    let (_dir, state, config) = applied_regtest_chain(2, 1)?;
    let remembered_tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    let stale = bitcoin_rs_storage::CoinKey([0xA5; 32]);
    assert!(
        state.chainstate().coins().get(&stale)?.is_none(),
        "the probe key must start absent from the engine coin namespace"
    );
    state.chainstate().coins().ingest_sorted(std::iter::once((
        stale,
        bitcoin_rs_storage::Bytes::from_static(b"stale"),
    )))?;
    assert!(
        state.chainstate().coins().get(&stale)?.is_some(),
        "the seeded row must read back before the cold reopen"
    );
    drop(state);
    std::fs::write(
        config
            .data_dir
            .join(bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER),
        b"force full validation\n",
    )?;
    let reopened = NodeState::open(config, None)?;
    assert!(
        reopened.chainstate().coins().get(&stale)?.is_none(),
        "a cold open with no engine image must wipe stale engine coin rows before replay"
    );
    let tip = reopened
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("replayed applied tip"))?;
    assert_eq!(
        (tip.hash, tip.height),
        (remembered_tip.hash, remembered_tip.height),
        "the wipe must keep the durable head chain that replay rebuilds"
    );
    Ok(())
}

type ForkPlan = (
    bitcoin_rs_execution::chain::NodeId,
    HashMap<
        bitcoin_rs_consensus::primitives::Hash256,
        bitcoin_rs_consensus::primitives::BlockImage,
    >,
    Vec<(u32, bitcoin_rs_consensus::primitives::Hash256)>,
);

fn plan_fork(
    state: &NodeState,
    fork_height: u32,
    depth: u32,
    time_base: u32,
) -> Result<ForkPlan, TestError> {
    let ancestor = {
        let tree = state.chainstate().block_tree_reader();
        let tree = tree.read();
        let tip = tree.tip().ok_or(TestError::Missing("chain tip"))?;
        tree.node_at_height_from(tip.tip_id, fork_height)
            .ok_or(TestError::Missing("active node at the fork height"))?
    };
    let ancestor_hash = state.chainstate().block_tree().read().node(ancestor)?.hash;
    let mut parent = ancestor;
    let mut previous = BlockHash::from(ancestor_hash);
    let mut bodies = HashMap::new();
    let mut ordered = Vec::new();
    for height in fork_height + 1..=fork_height + depth {
        let block = regtest_fixture::mined_regtest_child_at_time(
            previous,
            time_base.wrapping_add(height),
            height,
        )?;
        let hash = Hash256::from(block.block_hash());
        let node_id = crate::sync::fixture_insert_header_node(
            &state.chainstate(),
            parent,
            block.header,
            bitcoin_rs_execution::chain::node::NodeStatus::HeaderValid,
        )?;
        bodies.insert(
            hash,
            bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone()),
        );
        ordered.push((height, hash));
        parent = node_id;
        previous = block.block_hash();
    }
    Ok((parent, bodies, ordered))
}

#[test]
fn prune_then_reorg_refuses_deleted_history_but_keeps_retained_reorgs() -> Result<(), TestError> {
    let (_dir, state, _config) = applied_regtest_chain(620, 320)?;
    let (deep_tip, deep_bodies, _deep_order) = plan_fork(&state, 20, 2, 1_400_000_000)?;
    let (shallow_tip, shallow_bodies, _shallow_order) = plan_fork(&state, 400, 2, 1_500_000_000)?;
    let Some(service) = state.prune_service() else {
        return Err(TestError::Missing("prune service with prune_target_mb > 0"));
    };

    service.prune_to_height(30).map_err(TestError::from)?;
    let handles = state.chainstate();
    assert_eq!(state.storage.retention().pruned_below(), 30);

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
    assert_eq!(state.storage.retention().active_leases(), 0);

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
        .ok_or(TestError::Missing("reorg-published tip"))?;
    assert_eq!(landed.height, 402);
    assert_eq!(state.storage.retention().active_leases(), 0);
    Ok(())
}

#[test]
fn deep_reorg_streams_bounded_prefixes_to_the_exact_reference() -> Result<(), TestError> {
    const STAGED_PREFIX: u32 = 16;
    let (_dir, state, _config) = applied_regtest_chain(320, 1)?;
    let (fork_tip, fork_bodies, ordered) = plan_fork(&state, 20, 300, 1_600_000_000)?;
    let height_of: HashMap<bitcoin_rs_consensus::primitives::Hash256, u32> = ordered
        .iter()
        .map(|(height, hash)| (*hash, *height))
        .collect();
    let height_of = std::sync::Arc::new(height_of);

    let (_ref_dir, reference, _ref_config) = applied_regtest_chain(20, 1)?;
    for (_height, hash) in &ordered {
        let block = fork_bodies
            .get(hash)
            .ok_or(TestError::Missing("fork body in the plan"))?;
        reference.apply_block(block)?;
    }

    let handles = state.chainstate();
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
        .ok_or(TestError::Missing("reorg-published tip"))?;
    let reference_tip = reference
        .chainstate()
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("reference-published tip"))?;
    assert_eq!(landed.hash, reference_tip.hash);
    assert_eq!(landed.height, reference_tip.height);
    let restored = state
        .chainstate()
        .applied_tip_reader()
        .load_full()
        .ok_or(TestError::Missing("restored-node published tip"))?;
    assert_eq!(restored.chain_tx_count, reference_tip.chain_tx_count);
    assert_eq!(state.storage.retention().active_leases(), 0);
    Ok(())
}

#[test]
fn restart_without_periodic_publication_restores_tip_and_commit_id() -> Result<(), TestError> {
    let (_dir, state, config) = applied_regtest_chain(4, 1)?;
    let head = state
        .storage
        .durable_head()
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    let pre_tip = state
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("applied tip before restart"))?;
    assert_eq!(pre_tip.height, 4);
    drop(state);

    let reopened = NodeState::open(config.clone(), None)?;
    let landed = reopened
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("restart-published tip"))?;
    assert_eq!(landed.as_ref(), pre_tip.as_ref());
    assert_eq!(landed.height, head.height);
    let restored = reopened
        .storage
        .durable_head()
        .load()?
        .ok_or(TestError::Missing("surviving durable head"))?;
    assert_eq!(restored.tip, head.tip);
    assert_eq!(restored.commit_id, head.commit_id);
    assert!(matches!(reopened.resume_source(), ResumeSource::Checkpoint));

    drop(reopened);
    let second = NodeState::open(config, None)?;
    let landed = second
        .chainstate()
        .applied_tip()
        .load_full()
        .ok_or(TestError::Missing("second-restart published tip"))?;
    assert_eq!(landed.hash, head.tip);
    assert_eq!(landed.height, head.height);
    Ok(())
}

// RCV-02
#[test]
fn stored_prune_height_comes_from_the_datadir_not_the_config() -> Result<(), TestError> {
    let (_dir, state, config) = applied_regtest_chain(620, 320)?;
    let service = state
        .prune_service()
        .ok_or(TestError::Missing("prune service with prune_target_mb > 0"))?;
    service.prune_to_height(30).map_err(TestError::from)?;
    drop(service);
    drop(state);

    let mut reopen = config;
    reopen.storage.prune_target_mb = 0;
    let state = NodeState::open(reopen, None)?;
    assert_eq!(
        state.storage.stored_prune_height(),
        Some(30),
        "a datadir pruned before keeps its prune height after the config drops it"
    );
    Ok(())
}
