//! Integration test: `NodeState` opens the configured storage backend.

use anyhow::Result;
use bitcoin_rs_node::{Config, Network, state::NodeState};

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
