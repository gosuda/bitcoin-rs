//! Isolated regtest `NodeState` shared by the node integration suites.

use anyhow::Result;
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, NodeConfig};

/// Opens an isolated regtest `NodeState`; the returned guard keeps the data
/// directory alive for the whole test body (freed when the guard drops).
pub(crate) fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}
