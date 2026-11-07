use bitcoin_rs_node::test_support::TestError;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_storage::StorageBackend;

type Result<T, E = TestError> = core::result::Result<T, E>;

// ARCH-03
#[cfg(feature = "mdbx")]
#[test]
fn node_refuses_datadir_of_another_engine() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("datadir");
    config.storage.backend = StorageBackend::RocksDb;
    config.p2p.listen.clear();

    let state = NodeState::open(config.clone(), None)?;
    drop(state);

    config.storage.backend = StorageBackend::Mdbx;
    let err = match NodeState::open(config, None) {
        Ok(_) => panic!("opening rocksdb datadir with mdbx must fail"),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        msg.contains(
            "chainstate was created by rocksdb; start with --storage-backend rocksdb or convert with bitcoin-rs-storage-convert"
        ),
        "unexpected error message: {msg}"
    );

    Ok(())
}
