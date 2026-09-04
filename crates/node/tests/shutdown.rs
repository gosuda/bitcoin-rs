//! Integration tests for the bitcoin-rs node.
#![cfg(feature = "redb")]

use anyhow::{Context as _, Result, anyhow};
use bitcoin_rs_node::{Auth, Network, NodeConfig, RuntimeInputs, run};
use crossbeam_channel::bounded;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

#[cfg(feature = "redb")]
#[test]
fn run_exits_cleanly_after_fast_shutdown_signal() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (shutdown_tx, shutdown_rx) = bounded(1);
    let (done_tx, done_rx) = bounded(1);

    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.storage.backend = bitcoin_rs_storage::StorageBackend::Redb;
    config.rpc.bind = loopback(0);
    config.rpc.auth = Auth::basic("user", "password");
    config.indexes.script_index = bitcoin_rs_node::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;
    let runtime = RuntimeInputs::default().with_shutdown(shutdown_rx);

    thread::spawn(move || {
        let result = run(config, runtime);
        let _ignored = done_tx.send(result.map_err(|error| error.to_string()));
    });

    shutdown_tx.send(())?;
    let result = done_rx
        .recv_timeout(Duration::from_secs(6))
        .context("node did not stop within shutdown deadline")?;
    result.map_err(|message| anyhow!(message))?;
    Ok(())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}
