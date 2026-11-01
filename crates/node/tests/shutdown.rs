#![cfg(any(feature = "fjall", feature = "redb"))]

use crate::support::block_on;
use bitcoin_rs_node::test_support::TestError;
use bitcoin_rs_node::{Auth, Network, NodeConfig, RuntimeInputs, run};
use crossbeam_channel::bounded;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

#[test]
fn run_exits_cleanly_after_fast_shutdown_signal() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let (shutdown_tx, shutdown_rx) = bounded(1);
    let (done_tx, done_rx) = bounded(1);

    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.storage.backend = test_storage_backend();
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

    shutdown_tx
        .send(())
        .map_err(|_| TestError::message("failed to send shutdown signal"))?;
    let result = done_rx
        .recv_timeout(Duration::from_secs(6))
        .map_err(|_| TestError::message("node did not stop within shutdown deadline"))?;
    result.map_err(TestError::message)?;
    Ok(())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn test_storage_backend() -> bitcoin_rs_storage::StorageBackend {
    #[cfg(feature = "fjall")]
    {
        bitcoin_rs_storage::StorageBackend::Fjall
    }
    #[cfg(not(feature = "fjall"))]
    {
        bitcoin_rs_storage::StorageBackend::Redb
    }
}

#[test]
fn shutdown_signal_before_startup_exits_cleanly() -> Result<(), TestError> {
    let temp = tempfile::tempdir()?;
    let (shutdown_tx, shutdown_rx) = bounded(1);
    let (done_tx, done_rx) = bounded(1);

    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node-pre-shutdown");
    config.storage.backend = test_storage_backend();
    config.rpc.bind = loopback(0);
    config.rpc.auth = Auth::basic("user", "password");
    config.indexes.script_index = bitcoin_rs_node::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;

    shutdown_tx
        .send(())
        .map_err(|_| TestError::message("failed to pre-send shutdown signal"))?;

    let runtime = RuntimeInputs::default().with_shutdown(shutdown_rx);

    thread::spawn(move || {
        let result = run(config, runtime);
        let _ignored = done_tx.send(result.map_err(|error| error.to_string()));
    });

    let result = done_rx
        .recv_timeout(Duration::from_secs(6))
        .map_err(|_| TestError::message("pre-shutdown node did not exit within deadline"))?;
    result.map_err(TestError::message)?;
    Ok(())
}

#[test]
fn subscribe_and_use_after_shutdown_are_refused() -> Result<(), TestError> {
    use bitcoin_rs_node::{Node, NodeError};

    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node-sub-shutdown");
    config.storage.backend = test_storage_backend();
    config.rpc.bind = loopback(0);
    config.rpc.auth = Auth::basic("user", "password");
    config.indexes.script_index = bitcoin_rs_node::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;

    let (shutdown_tx, shutdown_rx) = bounded(2);
    let runtime = RuntimeInputs::default().with_shutdown(shutdown_rx);
    let node = block_on(Node::start(config, runtime))
        .map_err(|error| TestError::message(error.to_string()))?;

    let mut sub = node
        .subscribe_chain()
        .map_err(|error| TestError::message(error.to_string()))?;

    shutdown_tx
        .send(())
        .map_err(|_| TestError::message("failed to send first shutdown signal"))?;
    match shutdown_tx.try_send(()) {
        Ok(()) | Err(crossbeam_channel::TrySendError::Disconnected(_)) => {}
        Err(crossbeam_channel::TrySendError::Full(_)) => {
            panic!("the shutdown channel has room for a repeated signal")
        }
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while node.subscribe_chain().is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "shutdown must become observable"
        );
        thread::sleep(Duration::from_millis(5));
    }

    let sub_after = node.subscribe_chain();
    assert!(
        matches!(&sub_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
        "subscribe after shutdown must return Unavailable"
    );

    let poll_after = node.poll_chain(&mut sub);
    assert!(
        matches!(&poll_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
        "poll after shutdown must return Unavailable"
    );

    let pin_after = node.pin_chain();
    assert!(
        matches!(&pin_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
        "pin after shutdown must return Unavailable"
    );

    let settled_after = node.settled_snapshot();
    assert!(
        matches!(&settled_after, Err(NodeError::Unavailable(msg)) if msg.contains("shutting down")),
        "settled_snapshot after shutdown must return Unavailable"
    );

    block_on(node.shutdown()).map_err(|error| TestError::message(error.to_string()))?;
    Ok(())
}
