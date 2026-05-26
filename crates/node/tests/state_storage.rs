//! Integration test: `NodeState` opens the configured storage backend.

use anyhow::Result;
use bitcoin_rs_node::{Config, Network, state::NodeState};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn opens_storage_backend() -> Result<()> {
    #[cfg(feature = "rocksdb")]
    assert_backend_opens("rocksdb")?;
    #[cfg(feature = "fjall")]
    assert_backend_opens("fjall")?;
    #[cfg(feature = "redb")]
    assert_backend_opens("redb")?;
    #[cfg(feature = "mdbx")]
    assert_backend_opens("mdbx")?;

    Ok(())
}

#[test]
fn optional_indexes_are_not_opened_when_disabled() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.p2p_listen.clear();
    config.txindex = false;
    config.blockfilterindex = false;

    let state = NodeState::open(config)?;

    assert!(state.tx_index().is_none());
    assert!(state.filter_index().is_none());
    assert!(!state.data_dir().join("txindex").exists());
    assert!(!state.data_dir().join("filters").exists());
    Ok(())
}

#[test]
fn electrum_bind_requires_txindex() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.p2p_listen.clear();
    config.electrum_bind = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    config.txindex = false;

    let error = match config.validate() {
        Ok(()) => anyhow::bail!("electrum without txindex unexpectedly validated"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("electrum_bind requires txindex"));
    Ok(())
}

fn assert_backend_opens(backend: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(backend);
    backend.clone_into(&mut config.storage_backend);
    config.p2p_listen.clear();

    let state = NodeState::open(config)?;

    assert_eq!(state.storage_kind(), backend);
    assert!(state.data_dir().join("chainstate").is_dir());
    Ok(())
}
