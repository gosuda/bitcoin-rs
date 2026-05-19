//! Integration tests for the bitcoin-rs node.

use anyhow::Result;
use bitcoin_rs_node::{Auth, Config, bitcoin_conf_compat};
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
-blockfilterindex=1
-dbcache=768
",
    )?;

    let mut config = Config::default();
    bitcoin_conf_compat::apply_file(&mut config, &conf_path)?;

    assert_eq!(config.prune_target_mb, 550);
    assert_auth(&config.rpc_auth, "foo", "bar");
    assert!(config.p2p_listen.is_empty());
    assert!(config.txindex);
    assert!(config.blockfilterindex);
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

    let mut config = Config::default_for_network(bitcoin_rs_node::Network::Regtest);
    bitcoin_conf_compat::apply_file(&mut config, &conf_path)?;

    assert_eq!(config.prune_target_mb, 900);
    assert_auth(&config.rpc_auth, "regtest-user", "regtest-pass");
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
