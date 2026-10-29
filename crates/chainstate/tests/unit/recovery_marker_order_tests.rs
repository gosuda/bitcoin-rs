use std::fs;
use std::path::Path;

use bitcoin_rs_chain::{BlockTree, TipSnapshot, accept_headers};
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::chainstate_journal::{FULL_REVALIDATION_MARKER, JOURNAL_DIR_NAME};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use parking_lot::RwLock;

use crate::checkpoint::headers::HeaderCheckpointConfig;
use crate::checkpoint::{CHECKPOINT_ROOT, CURRENT_FILE, MANIFEST_FILE};
use crate::recovery::{ResumeSource, prepare_initial_chainstate};
use crate::{ChainstateJournalConfig, checkpoint};

const NETWORK: Network = Network::Regtest;

fn arm_full_revalidation_marker(data_dir: &Path) {
    let journal_dir = data_dir.join(JOURNAL_DIR_NAME);
    fs::create_dir_all(&journal_dir).unwrap_or_else(|e| panic!("create journal dir: {e}"));
    fs::write(journal_dir.join(FULL_REVALIDATION_MARKER), b"")
        .unwrap_or_else(|e| panic!("arm marker: {e}"));
}

fn genesis_tip() -> Result<(RwLock<BlockTree>, TipSnapshot), Box<dyn std::error::Error>> {
    let genesis = NETWORK.genesis_block().header;
    let mut tree = BlockTree::new();
    let accepted = accept_headers(
        &mut tree,
        core::slice::from_ref(&genesis),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
        bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
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

#[test]
fn corrupt_checkpoint_with_marker_selects_cold_replay() -> Result<(), Box<dyn std::error::Error>> {
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

    let config = ChainstateJournalConfig::default();
    let state = prepare_initial_chainstate(data_dir, NETWORK, config, None)?;

    assert!(
        matches!(state.resume_source, ResumeSource::Cold),
        "expected Cold resume source, got {:?}",
        state.resume_source
    );
    Ok(())
}

#[test]
fn valid_checkpoint_with_marker_selects_cold_replay() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    crate::events::initialize_data_dir(data_dir)?;

    let (tree, tip) = genesis_tip()?;
    let store = bitcoin_rs_storage::checkpoint::open_data_dir(data_dir)?;
    let _ = checkpoint::write_checkpoint_from_dir(
        &store,
        checkpoint_config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&tip),
    )?;
    drop(store);

    let no_marker =
        prepare_initial_chainstate(data_dir, NETWORK, ChainstateJournalConfig::default(), None)?;
    assert!(
        matches!(no_marker.resume_source, ResumeSource::Checkpoint),
        "a valid checkpoint without a marker must restore to Checkpoint, got {:?}",
        no_marker.resume_source
    );

    arm_full_revalidation_marker(data_dir);

    let config = ChainstateJournalConfig::default();
    let state = prepare_initial_chainstate(data_dir, NETWORK, config, None)?;

    assert!(
        matches!(state.resume_source, ResumeSource::Cold),
        "a valid checkpoint must be bypassed when the marker is armed, got {:?}",
        state.resume_source
    );
    Ok(())
}
