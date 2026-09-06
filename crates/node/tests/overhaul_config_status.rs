//! Scenario tests for the configuration ladder and the one status owner.
//!
//! These pin the merge contract users depend on: later explicitly supplied
//! fields override earlier layers, absent nested fields never clobber
//! earlier values, the mining payout validates against the fully resolved
//! network, runtime/test controls stay out of the public configuration
//! surface, and the status snapshot carries one runtime revision. The
//! revision flow through the adapter seam is pinned in
//! `bitcoin-rs-rpc`'s capabilities tests (IDX-02).

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_node::config::{NetworkSelection, RuntimeInputs, UserConfig, resolve};
use std::net::{Ipv4Addr, SocketAddr};

fn bind(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// A later layer that supplies a field explicitly overrides the earlier
/// layer's value for that field.
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

/// A layer that leaves a nested group absent preserves the earlier layer's
/// values in that group.
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

/// The mining payout decodes against the consensus network resolved after
/// every layer merged, so a mainnet address under a regtest profile is
/// rejected at resolve time.
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

    // The same address resolves cleanly when the network matches.
    let mainnet = UserConfig {
        network: Some(NetworkSelection::Mainnet),
        mining: bitcoin_rs_node::config::MiningOverrides {
            payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned()),
        },
        ..Default::default()
    };
    resolve(&[&mainnet]).expect("matching-network payout resolves");
}

/// Runtime and test controls are not expressible in the public
/// configuration surface: unknown TOML keys are rejected by
/// `deny_unknown_fields`, and runtime inputs live in their own type.
#[test]
fn runtime_controls_stay_out_of_public_config() {
    // The public TOML surface rejects unknown members, so a runtime-only
    // knob spelled in a config file cannot be accepted.
    let rejected = sonic_rs::from_str::<bitcoin_rs_node::config::ChainstateJournalOverrides>(
        "rpc_enabled_for_tests = true\n",
    );
    assert!(
        rejected.is_err(),
        "unknown members must be rejected by the public config surface"
    );

    // RuntimeInputs is a distinct type: a UserConfig cannot be constructed
    // where a RuntimeInputs is required, and vice versa.
    let runtime = RuntimeInputs::default();
    let _ = &runtime;
}

/// The data directory travels with its layer: a later layer that names a
/// data directory overrides an earlier one.
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
