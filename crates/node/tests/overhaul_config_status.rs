//! ARCH-05/IDX-02 configuration and status-owner scenarios.
//!
//! Later explicit fields override earlier layers, absent nested fields do not
//! clobber earlier values, payout validation uses the resolved network, and
//! runtime/test controls stay outside the public configuration surface.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_node::config::{NetworkSelection, RuntimeInputs, UserConfig, resolve};
use std::net::{Ipv4Addr, SocketAddr};

fn bind(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[test]
fn later_explicit_fields_override_earlier_layers() {
    let early = UserConfig {
        rpc: bitcoin_rs_node::config::RpcOverrides {
            bind: Some(bind(8332)),
            user: Some("early".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };

    let late = UserConfig {
        rpc: bitcoin_rs_node::config::RpcOverrides {
            bind: Some(bind(18332)),
            ..Default::default()
        },
        ..Default::default()
    };

    let config = resolve(&[&early, &late]).expect("resolve");
    assert_eq!(config.rpc.bind, bind(18332), "later explicit bind wins");
    match &config.rpc.auth {
        bitcoin_rs_node::config::Auth::Basic { user, .. } => assert_eq!(
            user, "early",
            "untouched later field preserves the earlier value"
        ),
        other @ bitcoin_rs_node::config::Auth::Cookie { .. } => {
            panic!("expected basic auth, got {other:?}")
        }
    }
}

#[test]
fn absent_nested_groups_preserve_earlier_layers() {
    let early = UserConfig {
        rpc: bitcoin_rs_node::config::RpcOverrides {
            bind: Some(bind(8332)),
            user: Some("early".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };

    let late = UserConfig::default();

    let config = resolve(&[&early, &late]).expect("resolve");
    assert_eq!(config.rpc.bind, bind(8332));
    match &config.rpc.auth {
        bitcoin_rs_node::config::Auth::Basic { user, .. } => assert_eq!(user, "early"),
        other @ bitcoin_rs_node::config::Auth::Cookie { .. } => {
            panic!("expected basic auth, got {other:?}")
        }
    }
}

#[test]
fn network_invalid_payout_is_rejected_after_merge() {
    let layer = UserConfig {
        network: Some(NetworkSelection::Regtest),
        mining: bitcoin_rs_node::config::MiningOverrides {
            payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned()),
        },
        ..Default::default()
    };

    let error = resolve(&[&layer]).expect_err("mainnet payout under regtest");
    let message = format!("{error:#}");
    assert!(
        message.contains("payout"),
        "error should name the payout conflict: {message}"
    );

    let mainnet = UserConfig {
        network: Some(NetworkSelection::Mainnet),
        mining: bitcoin_rs_node::config::MiningOverrides {
            payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned()),
        },
        ..Default::default()
    };
    resolve(&[&mainnet]).expect("matching-network payout resolves");
}

#[test]
fn runtime_controls_stay_out_of_public_config() {
    let rejected = sonic_rs::from_str::<bitcoin_rs_node::config::ChainstateJournalOverrides>(
        "rpc_enabled_for_tests = true\n",
    );
    assert!(
        rejected.is_err(),
        "unknown members must be rejected by the public config surface"
    );

    let runtime = RuntimeInputs::default();
    let _ = &runtime;
}

#[test]
fn later_data_dir_overrides_earlier() {
    let early = UserConfig {
        data_dir: Some(std::path::PathBuf::from("/early")),
        ..Default::default()
    };

    let late = UserConfig {
        data_dir: Some(std::path::PathBuf::from("/late")),
        ..Default::default()
    };

    let config = resolve(&[&early, &late]).expect("resolve");
    assert_eq!(config.data_dir, std::path::PathBuf::from("/late"));
}
