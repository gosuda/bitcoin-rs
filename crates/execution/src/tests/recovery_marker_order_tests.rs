use std::fs;
use std::path::Path;

use crate::chain::{BlockTree, TipSnapshot, accept_headers};
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};
use parking_lot::RwLock;

use crate::checkpoint;
use crate::checkpoint::headers::HeaderCheckpointConfig;
use crate::checkpoint::{CHECKPOINT_ROOT, CURRENT_FILE, MANIFEST_FILE};
use crate::recovery::{
    ResumeSource, prepare_initial_chainstate, prepare_initial_state_with_engine,
};

use crate::test_fixtures::TestResult;
const NETWORK: Network = Network::Regtest;

fn arm_full_revalidation_marker(data_dir: &Path) {
    fs::write(data_dir.join(FULL_REVALIDATION_MARKER), b"")
        .unwrap_or_else(|e| panic!("arm marker: {e}"));
}

fn genesis_tip() -> TestResult<(RwLock<BlockTree>, TipSnapshot)> {
    let genesis = NETWORK.genesis_block().header;
    let mut tree = BlockTree::new();
    let accepted = accept_headers(
        &mut tree,
        core::slice::from_ref(&genesis),
        NETWORK,
        crate::chain::current_unix_seconds(),
        crate::chain::HeaderValidationMode::LiveAdmission,
    )?;
    let tip_id = accepted.ids[0];
    let node = tree.node(tip_id)?;
    let tip = TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    };
    Ok((RwLock::new(tree), tip))
}

fn checkpoint_config() -> HeaderCheckpointConfig {
    HeaderCheckpointConfig {
        network: NETWORK,
        genesis: NETWORK.genesis_block_hash(),
    }
}

// RCV-10
#[test]
fn corrupt_checkpoint_with_marker_selects_cold_replay() -> TestResult {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    crate::events::initialize_data_dir(data_dir)?;

    let gen_name = format!("gen-{:020}", 1u64);
    let checkpoint_root = data_dir.join(CHECKPOINT_ROOT);
    fs::create_dir_all(checkpoint_root.join(gen_name.as_str()))?;
    fs::write(
        checkpoint_root.join(gen_name.as_str()).join(MANIFEST_FILE),
        b"not valid json",
    )?;
    let current_json = format!(
        r#"{{"format":"bitcoin-rs-chainstate-current","version":1,"generation":1,"directory":"{gen_name}","manifest_sha256":"{}"}}"#,
        "00".repeat(32)
    );
    fs::write(checkpoint_root.join(CURRENT_FILE), current_json)?;

    let preload = checkpoint::load_checkpoint(data_dir, checkpoint_config());
    assert!(
        matches!(preload, Err(checkpoint::CheckpointLoadError::Corrupt(_))),
        "corrupt fixture must fail to load before the marker is armed"
    );

    arm_full_revalidation_marker(data_dir);

    let state = prepare_initial_chainstate(data_dir, NETWORK, None, None)?;

    assert!(
        matches!(state.resume_source, ResumeSource::Cold),
        "expected Cold resume source, got {:?}",
        state.resume_source
    );
    Ok(())
}

// RCV-10
#[test]
fn valid_checkpoint_with_marker_selects_cold_replay() -> TestResult {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    crate::events::initialize_data_dir(data_dir)?;

    let (tree, tip) = genesis_tip()?;
    let store = bitcoin_rs_storage::checkpoint::open_data_dir(data_dir)?;
    let _ = checkpoint::write_checkpoint(
        data_dir,
        checkpoint_config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&tip),
    )?;
    drop(store);

    let no_marker = prepare_initial_chainstate(data_dir, NETWORK, None, None)?;
    assert!(
        matches!(no_marker.resume_source, ResumeSource::Checkpoint),
        "a valid checkpoint without a marker must restore to Checkpoint, got {:?}",
        no_marker.resume_source
    );

    arm_full_revalidation_marker(data_dir);

    let state = prepare_initial_chainstate(data_dir, NETWORK, None, None)?;

    assert!(
        matches!(state.resume_source, ResumeSource::Cold),
        "a valid checkpoint must be bypassed when the marker is armed, got {:?}",
        state.resume_source
    );
    Ok(())
}

#[test]
fn older_published_checkpoint_with_activation_marker_returns_cold_and_no_engine_image() -> TestResult
{
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    crate::events::initialize_data_dir(data_dir)?;

    let (tree, tip) = genesis_tip()?;
    let store = bitcoin_rs_storage::checkpoint::open_data_dir(data_dir)?;
    let _ = checkpoint::write_checkpoint(
        data_dir,
        checkpoint_config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&tip),
    )?;
    drop(store);

    let restored = prepare_initial_state_with_engine(data_dir, NETWORK, None, None)?;
    assert!(
        matches!(restored.initial.resume_source, ResumeSource::Checkpoint),
        "marker-free checkpoint must restore to Checkpoint, got {:?}",
        restored.initial.resume_source
    );
    assert!(
        restored.engine.is_some(),
        "marker-free checkpoint must restore with its engine image"
    );

    let in_flight = bitcoin_rs_storage::SnapshotActivationMarker {
        base_hash: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0x42; 32]),
        coin_count: 100,
        coin_digest: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0x77; 32]),
    };

    let in_flight_state =
        prepare_initial_state_with_engine(data_dir, NETWORK, None, Some(&in_flight))?;
    assert!(
        matches!(in_flight_state.initial.resume_source, ResumeSource::Cold),
        "in-flight activation marker must select Cold resume, got {:?}",
        in_flight_state.initial.resume_source
    );
    assert!(
        in_flight_state.engine.is_none(),
        "in-flight activation marker must return no engine image (None)"
    );

    Ok(())
}
