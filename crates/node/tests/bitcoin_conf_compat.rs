//! Integration tests for the bitcoin-rs node.

use anyhow::Result;
use bitcoin_rs_node::{Auth, Network, NodeConfig, bitcoin_conf_compat};
use std::fs;

#[test]
fn bitcoin_conf_core_keys_map_into_config() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let conf_path = temp.path().join("bitcoin.conf");
    fs::write(
        &conf_path,
        r"
# Global Core options may carry a leading dash.
-prune=550
-rpcuser=foo
-rpcpassword=bar
-server=1
-listen=0
-txindex=1
-dbcache=768
",
    )?;

    let mut config = NodeConfig::default();
    bitcoin_conf_compat::apply_file(&mut config, &conf_path)?;

    assert_eq!(config.prune_target_mb, 550);
    assert_auth(&config.rpc_auth, "foo", "bar");
    assert!(config.p2p_listen.is_empty());
    assert!(config.txindex);
    assert_eq!(config.dbcache_mb, 768);
    Ok(())
}

#[test]
fn bitcoin_conf_network_sections_override_globals_for_selected_network() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let conf_path = temp.path().join("bitcoin.conf");
    fs::write(
        &conf_path,
        r"
-prune=550
[regtest]
-prune=900
-rpcuser=regtest-user
-rpcpassword=regtest-pass
",
    )?;

    let mut config = NodeConfig::default_for_network(bitcoin_rs_node::Network::Regtest);
    bitcoin_conf_compat::apply_file(&mut config, &conf_path)?;

    assert_eq!(config.prune_target_mb, 900);
    assert_auth(&config.rpc_auth, "regtest-user", "regtest-pass");
    Ok(())
}

#[test]
fn bitcoin_conf_zmq_keys_are_not_promoted_into_node_config() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let conf_path = temp.path().join("bitcoin.conf");
    fs::write(
        &conf_path,
        r"
-zmqpubhashblock=tcp://127.0.0.1:28332
-zmqpubhashblock=tcp://127.0.0.1:28333
-zmqpubhashblockhwm=5
[regtest]
-zmqpubrawtx=tcp://127.0.0.1:28334
-zmqpubrawtxhwm=6
-zmqpubsequence=tcp://127.0.0.1:28335
-zmqpubsequencehwm=7
",
    )?;

    let mut config = NodeConfig::default_for_network(bitcoin_rs_node::Network::Regtest);
    bitcoin_conf_compat::apply_file(&mut config, &conf_path)?;

    assert!(config.notifications.zmq.is_empty());
    Ok(())
}

#[test]
fn bitcoin_conf_assumevalid_is_not_mapped_to_height_only_setting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let conf_path = temp.path().join("bitcoin.conf");
    fs::write(
        &conf_path,
        r"
assumevalid=0000000000000000000000000000000000000000000000000000000000000000
",
    )?;

    let mut config = NodeConfig::default();
    bitcoin_conf_compat::apply_file(&mut config, &conf_path)?;

    assert_eq!(
        config.assume_valid_height,
        Network::Mainnet
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height),
        "Bitcoin Core hash-based assumevalid must not alter the hash-pinned assume_valid_height default"
    );
    Ok(())
}

fn assert_auth(auth: &Auth, expected_user: &str, expected_password: &str) {
    match auth {
        Auth::Basic { user, password } => {
            assert_eq!(user, expected_user);
            assert_eq!(password, expected_password);
        }
        Auth::Cookie { .. } => panic!("expected basic auth"),
    }
}
