//! Integration tests for the bitcoin-rs node.

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Config, Network, crash_recovery, state::NodeState};

#[cfg(feature = "redb")]
#[test]
fn recovery_replays_from_last_committed_height_to_tip() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.storage_backend = "redb".to_owned();
    config.p2p_listen.clear();

    {
        let state = NodeState::open(config.clone())?;
        for height in 1..=10 {
            state.record_synthetic_block_for_recovery(height)?;
        }
        crash_recovery::set_last_committed_height(&state, 7)?;
    }

    let restarted = NodeState::open(config)?;
    crash_recovery::recover_if_needed(&restarted)?;

    let meta = crash_recovery::read_meta(&restarted)?.context("missing recovery metadata")?;
    assert_eq!(meta.height, 10);
    assert_eq!(meta.last_committed_height, 10);
    assert_eq!(restarted.replayed_heights(), vec![8, 9, 10]);
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn recovery_meta_write_leaves_readable_sidecar_without_tmp() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.storage_backend = "redb".to_owned();
    config.p2p_listen.clear();

    let meta_path = config.data_dir.join("recovery_meta.json");
    let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
    {
        let state = NodeState::open(config)?;
        state.record_synthetic_block_for_recovery(3)?;
    }

    assert!(meta_path.exists());
    let bytes = std::fs::read(&meta_path)
        .with_context(|| format!("read recovery metadata {}", meta_path.display()))?;
    let meta: crash_recovery::Meta = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse recovery metadata {}", meta_path.display()))?;
    assert_eq!(meta.height, 3);
    assert_eq!(meta.last_committed_height, 3);
    assert!(!tmp_path.exists());
    Ok(())
}
