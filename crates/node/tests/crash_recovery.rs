//! Integration tests for the bitcoin-rs node.

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Config, Network, crash_recovery, state::NodeState};

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
