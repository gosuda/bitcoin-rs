//! Resolver tests for grouped node configuration layers.

use std::str::FromStr as _;

use anyhow::Result;
use bitcoin_rs_node::{
    NetworkSelection, NodeConfig, NotificationConfig, P2pOverrides, ScriptIndexMode, UserConfig,
    ValidationOverrides, ZmqEndpointConfig, resolve,
};
use bitcoin_rs_primitives::Network;
use bitcoin_rs_rpc::zmq::ZmqTopic;

#[test]
fn public_listener_is_opt_in_and_budgets_resolve_independently() -> Result<()> {
    let defaults = NodeConfig::default_for_network(Network::Regtest);
    assert_eq!(defaults.rpc.public_bind, None);
    assert_eq!(defaults.rpc.max_connections, 128);
    assert_eq!(defaults.rpc.public_max_connections, 128);
    let file: UserConfig = toml::from_str(
        "public_bind = '0.0.0.0:8080'\nrpc_max_connections = 8\npublic_max_connections = 32",
    )?;
    let mut environment = UserConfig::default();
    environment.apply_env(
        "BITCOIN_RS_PUBLIC_BIND",
        std::ffi::OsStr::new("127.0.0.1:9090"),
    )?;
    environment.apply_env(
        "BITCOIN_RS_PUBLIC_MAX_CONNECTIONS",
        std::ffi::OsStr::new("16"),
    )?;
    let config = resolve(&[&file, &environment])?;
    assert_eq!(config.rpc.public_bind, Some("127.0.0.1:9090".parse()?));
    assert_eq!(config.rpc.max_connections, 8);
    assert_eq!(config.rpc.public_max_connections, 16);
    for invalid in [
        "rpc_max_connections = 0",
        "public_max_connections = 0",
        "rpc_bind = '127.0.0.1:8332'\npublic_bind = '127.0.0.1:8332'",
    ] {
        let layer: UserConfig = toml::from_str(invalid)?;
        assert!(resolve(&[&layer]).is_err(), "{invalid}");
    }
    Ok(())
}

#[test]
fn public_listener_bind_validation_handles_wildcards_and_ephemeral_ports() -> Result<()> {
    for (management, public, valid) in [
        ("127.0.0.1:8332", "127.0.0.1:8332", false),
        ("0.0.0.0:8332", "127.0.0.1:8332", false),
        ("127.0.0.1:8332", "0.0.0.0:8332", false),
        ("[::]:8332", "[::1]:8332", false),
        ("[::1]:8332", "[::]:8332", false),
        ("127.0.0.1:8332", "127.0.0.2:8332", true),
        ("127.0.0.1:8332", "127.0.0.1:8080", true),
        ("0.0.0.0:0", "0.0.0.0:0", true),
        ("127.0.0.1:0", "127.0.0.1:8332", true),
        ("127.0.0.1:8332", "127.0.0.1:0", true),
    ] {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.rpc.bind = management.parse()?;
        config.rpc.public_bind = Some(public.parse()?);
        config.rpc.auth = bitcoin_rs_node::Auth::basic("operator", "secret");
        let result = config.validate();
        assert_eq!(result.is_ok(), valid, "{management}, {public}: {result:?}");
        if let Err(error) = result {
            assert!(error.to_string().contains("must not overlap"), "{error}");
        }
    }
    // Both sockets stay bound: the second port-zero bind must select a
    // different available port rather than reuse the first listener's port.
    let management = std::net::TcpListener::bind("0.0.0.0:0")?;
    let public = std::net::TcpListener::bind("0.0.0.0:0")?;
    assert_ne!(management.local_addr()?.port(), public.local_addr()?.port());
    Ok(())
}

#[test]
fn overlay_routing_is_opt_in_and_layered_without_implicit_fallback() -> Result<()> {
    let default = NodeConfig::default_for_network(Network::Regtest);
    assert!(default.p2p.overlay.proxy.is_none());
    assert!(default.p2p.overlay.onion_proxy.is_none());
    assert!(default.p2p.overlay.i2p_sam.is_none());
    let file: UserConfig = toml::from_str(
        r#"
        network = "regtest"
        onion_proxy = "127.0.0.1:9050"
        onlynet = ["onion"]
        proxy_randomize_credentials = false
        overlay_port = 18445
    "#,
    )?;
    let mut environment = UserConfig::default();
    environment.apply_env("BITCOIN_RS_ONLYNET", std::ffi::OsStr::new("onion,i2p"))?;
    environment.apply_env("BITCOIN_RS_I2P_SAM", std::ffi::OsStr::new("127.0.0.1:7656"))?;
    let config = resolve(&[&file, &environment])?;
    assert!(
        config
            .p2p
            .overlay
            .allows(bitcoin_rs_primitives::PeerNetwork::Onion)
    );
    assert!(
        config
            .p2p
            .overlay
            .allows(bitcoin_rs_primitives::PeerNetwork::I2p)
    );
    assert!(
        !config
            .p2p
            .overlay
            .allows(bitcoin_rs_primitives::PeerNetwork::Ipv4)
    );
    assert!(!config.p2p.overlay.randomize_credentials);
    assert_eq!(config.p2p.overlay.port, 18445);
    for text in [
        "onlynet = ['onion']",
        "i2p_accept = true",
        "onion_proxy = '8.8.8.8:9050'",
        "tor_control = '127.0.0.1:9051'",
    ] {
        let layer: UserConfig = toml::from_str(text)?;
        assert!(resolve(&[&layer]).is_err(), "{text}");
    }
    Ok(())
}

#[test]
fn blank_onlynet_environment_clears_an_inherited_network_list() -> Result<()> {
    let file: UserConfig = toml::from_str("onlynet = ['ipv4']")?;
    let mut environment = UserConfig::default();
    environment.apply_env("BITCOIN_RS_ONLYNET", std::ffi::OsStr::new("  "))?;
    assert_eq!(
        resolve(&[&file, &environment])?.p2p.overlay.onlynet,
        Vec::<bitcoin_rs_primitives::PeerNetwork>::new()
    );
    assert!(
        environment
            .apply_env("BITCOIN_RS_ONLYNET", std::ffi::OsStr::new("ipv4,"))
            .is_err()
    );
    Ok(())
}

#[test]
fn silent_payments_toml_overlay_preserves_explicit_disable() -> Result<()> {
    assert!(
        !NodeConfig::default_for_network(Network::Regtest)
            .rpc
            .silent_payments
    );
    let enabled: UserConfig = toml::from_str("silent_payments = true")?;
    let disabled: UserConfig = toml::from_str("silent_payments = false")?;
    assert!(!resolve(&[&enabled, &disabled])?.rpc.silent_payments);
    let mut environment = UserConfig::default();
    environment.apply_env("BITCOIN_RS_SILENT_PAYMENTS", std::ffi::OsStr::new("false"))?;
    assert!(!resolve(&[&enabled, &environment])?.rpc.silent_payments);
    let result = resolve(&[&disabled, &enabled]);
    if cfg!(feature = "silent-payments") {
        assert!(result?.rpc.silent_payments);
    } else {
        assert!(
            result.is_err_and(|error| error.to_string().contains("silent-payments build feature"))
        );
    }
    Ok(())
}

#[test]
fn standard_network_uses_builtin_defaults() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Testnet4),
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Testnet4);
    assert_eq!(config.p2p.magic, Network::Testnet4.magic());
    assert_eq!(config.p2p.connect, Vec::<String>::new());
    assert!(config.p2p.dns_seeds_enabled);
    Ok(())
}

#[test]
fn drynet4_network_applies_atomic_p2p_profile() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Drynet4),
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.p2p.magic, [0xec, 0xa5, 0xd4, 0x04]);
    assert_eq!(config.p2p.connect, vec!["drynet4.drivechain.dev:8533"]);
    assert!(!config.p2p.dns_seeds_enabled);
    Ok(())
}

#[test]
fn p2p_magic_override_preserves_consensus_network() -> Result<()> {
    let layer = UserConfig {
        p2p: P2pOverrides {
            magic: Some([0xec, 0xa5, 0xd4, 0x34]),
            dns_seeds: Some(false),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.p2p.magic, [0xec, 0xa5, 0xd4, 0x34]);
    assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
    assert!(!config.p2p.dns_seeds_enabled);
    Ok(())
}

#[test]
fn same_layer_explicit_overrides_follow_network_profile() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Drynet4),
        p2p: P2pOverrides {
            magic: Some([1, 2, 3, 4]),
            connect: Some(vec!["127.0.0.1:8333".to_owned()]),
            dns_seeds: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.p2p.magic, [1, 2, 3, 4]);
    assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
    Ok(())
}

#[test]
fn p2p_magic_override_requires_explicit_peer_and_disabled_seeds() {
    let layer = UserConfig {
        p2p: P2pOverrides {
            magic: Some([0xec, 0xa5, 0xd4, 0x34]),
            dns_seeds: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let error = match resolve(&[&layer]) {
        Ok(_) => panic!("magic overrides need a peer"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("at least one --connect peer"));
}

#[test]
fn script_index_is_valid_without_core_txindex() -> Result<()> {
    let layer = UserConfig {
        indexes: bitcoin_rs_node::IndexOverrides {
            script_index: Some(ScriptIndexMode::Full),
            txindex: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert!(!config.indexes.txindex);
    assert!(config.indexes.script_index.is_enabled());
    Ok(())
}

#[test]
fn scriptindex_utxo_mode_is_live_only() -> Result<()> {
    // IDX-01: `scriptindex=utxo` enables ScriptLive only; history stays off.
    let layer = UserConfig {
        indexes: bitcoin_rs_node::IndexOverrides {
            script_index: Some(ScriptIndexMode::Utxo),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.indexes.script_index, ScriptIndexMode::Utxo);
    assert!(config.indexes.script_index.is_enabled());
    assert_eq!(
        config
            .indexes
            .script_index
            .enabled_capabilities(config.indexes.txindex),
        bitcoin_rs_index::IndexCapabilities::SCRIPT_LIVE
    );
    Ok(())
}

#[test]
fn zmq_endpoint_groups_keep_topics_and_publisher_default_hwm() -> Result<()> {
    let layer = UserConfig {
        notifications: Some(NotificationConfig {
            zmq: vec![
                ZmqEndpointConfig {
                    endpoint: "tcp://127.0.0.1:28332".to_owned(),
                    topics: vec![ZmqTopic::HashBlock, ZmqTopic::RawBlock, ZmqTopic::Sequence],
                    hwm: None,
                },
                ZmqEndpointConfig {
                    endpoint: "tcp://127.0.0.1:28333".to_owned(),
                    topics: vec![ZmqTopic::HashTx, ZmqTopic::RawTx],
                    hwm: Some(5_000),
                },
            ],
        }),
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    let endpoints = config.notifications.zmq;
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].endpoint, "tcp://127.0.0.1:28332");
    assert_eq!(
        endpoints[0]
            .topics
            .iter()
            .map(|topic| topic.as_str())
            .collect::<Vec<_>>(),
        ["hashblock", "rawblock", "sequence"]
    );
    assert_eq!(endpoints[0].hwm, None);
    assert_eq!(endpoints[0].effective_hwm(), 1_000);
    assert_eq!(endpoints[1].endpoint, "tcp://127.0.0.1:28333");
    assert_eq!(endpoints[1].effective_hwm(), 5_000);
    Ok(())
}

#[test]
fn higher_layer_replaces_zmq_endpoint_groups() -> Result<()> {
    let lower = UserConfig {
        notifications: Some(NotificationConfig {
            zmq: vec![
                ZmqEndpointConfig {
                    endpoint: "tcp://127.0.0.1:28332".to_owned(),
                    topics: vec![ZmqTopic::HashBlock],
                    hwm: Some(42),
                },
                ZmqEndpointConfig {
                    endpoint: "tcp://127.0.0.1:28333".to_owned(),
                    topics: vec![ZmqTopic::RawTx],
                    hwm: None,
                },
            ],
        }),
        ..Default::default()
    };
    let higher = UserConfig {
        notifications: Some(NotificationConfig {
            zmq: vec![ZmqEndpointConfig {
                endpoint: "tcp://127.0.0.1:28334".to_owned(),
                topics: vec![ZmqTopic::HashBlock],
                hwm: Some(7),
            }],
        }),
        ..Default::default()
    };

    let config = resolve(&[&lower, &higher])?;
    assert_eq!(
        config.notifications.zmq,
        vec![ZmqEndpointConfig {
            endpoint: "tcp://127.0.0.1:28334".to_owned(),
            topics: vec![ZmqTopic::HashBlock],
            hwm: Some(7),
        }]
    );
    Ok(())
}

#[test]
fn absent_higher_layer_notifications_preserve_lower_layer() -> Result<()> {
    let lower = UserConfig {
        notifications: Some(NotificationConfig {
            zmq: vec![ZmqEndpointConfig {
                endpoint: "tcp://127.0.0.1:28332".to_owned(),
                topics: vec![ZmqTopic::HashBlock],
                hwm: Some(42),
            }],
        }),
        ..Default::default()
    };
    let higher = UserConfig::default();
    let config = resolve(&[&lower, &higher])?;
    assert_eq!(config.notifications.zmq[0].effective_hwm(), 42);
    Ok(())
}

#[test]
fn zmq_endpoint_groups_reject_duplicate_socket_and_topic_ownership() {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.notifications.zmq = vec![
        ZmqEndpointConfig {
            endpoint: "tcp://127.0.0.1:28332".to_owned(),
            topics: vec![ZmqTopic::HashBlock],
            hwm: None,
        },
        ZmqEndpointConfig {
            endpoint: "tcp://127.0.0.1:28332".to_owned(),
            topics: vec![ZmqTopic::RawBlock],
            hwm: Some(5_000),
        },
    ];
    assert!(config.validate().is_err());

    config.notifications.zmq.truncate(1);
    config.notifications.zmq[0].topics.push(ZmqTopic::HashBlock);
    assert!(config.validate().is_err());
}

#[test]
fn resolved_zmq_hwm_is_validated() {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.notifications.zmq.push(ZmqEndpointConfig {
        endpoint: "tcp://127.0.0.1:28332".to_owned(),
        topics: vec![ZmqTopic::HashBlock],
        hwm: Some(2_147_483_648),
    });
    let error = match config.validate() {
        Ok(()) => panic!("out-of-range resolved ZMQ HWM must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("ZMQ HWM exceeds libzmq"));

    config.notifications.zmq[0].hwm = Some(0);
    let Err(error) = config.validate() else {
        panic!("zero disables libzmq's outbound queue limit");
    };
    assert!(error.to_string().contains("ZMQ HWM must be positive"));

    for hwm in [Some(1), Some(2_147_483_647), None] {
        config.notifications.zmq[0].hwm = hwm;
        assert!(config.validate().is_ok(), "valid ZMQ HWM rejected: {hwm:?}");
    }
}

#[test]
fn connect_hostnames_are_preserved_for_later_resolution() -> Result<()> {
    let layer = UserConfig {
        p2p: P2pOverrides {
            connect: Some(vec!["localhost:18444".to_owned()]),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.p2p.connect, vec!["localhost:18444"]);
    Ok(())
}

#[test]
fn assume_valid_height_override_has_precedence() -> Result<()> {
    let low = UserConfig {
        validation: ValidationOverrides {
            assume_valid_height: Some(10_000),
            mode: None,
            engine: None,
        },
        ..Default::default()
    };
    let high = UserConfig {
        validation: ValidationOverrides {
            assume_valid_height: Some(30_000),
            mode: None,
            engine: None,
        },
        ..Default::default()
    };
    let config = resolve(&[&low, &high])?;
    assert_eq!(config.validation.assume_valid_height, 30_000);
    Ok(())
}

#[test]
fn assume_valid_height_defaults_to_mainnet_anchor() -> Result<()> {
    let config = resolve(&[])?;
    assert_eq!(
        config.validation.assume_valid_height,
        Network::Mainnet
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height)
    );
    Ok(())
}

#[test]
fn chainstate_journal_defaults_resolve() -> Result<()> {
    let config = resolve(&[])?;
    let journal = config.chainstate_journal;
    assert!(journal.enabled);
    assert_eq!(journal.blocks, 500);
    assert_eq!(journal.seconds, 5);
    assert_eq!(journal.rotate_mib, 256);
    assert_eq!(journal.max_journal_mib, 2048);
    assert_eq!(journal.max_lag_blocks, 500);
    assert_eq!(journal.max_lag_seconds, 30);
    Ok(())
}

#[test]
fn chainstate_journal_higher_layer_overrides_blocks() -> Result<()> {
    let lower = UserConfig {
        chainstate_journal: bitcoin_rs_node::ChainstateJournalOverrides {
            enabled: Some(true),
            blocks: Some(100),
            ..Default::default()
        },
        ..Default::default()
    };
    let higher = UserConfig {
        chainstate_journal: bitcoin_rs_node::ChainstateJournalOverrides {
            blocks: Some(200),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&lower, &higher])?;
    assert!(config.chainstate_journal.enabled);
    assert_eq!(config.chainstate_journal.blocks, 200);
    assert_eq!(config.chainstate_journal.seconds, 5);
    Ok(())
}

#[test]
fn chainstate_journal_off_keeps_other_defaults() -> Result<()> {
    let layer = UserConfig {
        chainstate_journal: bitcoin_rs_node::ChainstateJournalOverrides {
            enabled: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert!(!config.chainstate_journal.enabled);
    assert_eq!(config.chainstate_journal.blocks, 500);
    Ok(())
}

#[test]
fn chainstate_journal_rejects_invalid_values() {
    let zero_blocks = UserConfig {
        chainstate_journal: bitcoin_rs_node::ChainstateJournalOverrides {
            blocks: Some(0),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(resolve(&[&zero_blocks]).is_err());

    let lag_below_batch = UserConfig {
        chainstate_journal: bitcoin_rs_node::ChainstateJournalOverrides {
            max_lag_blocks: Some(10),
            blocks: Some(500),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(resolve(&[&lag_below_batch]).is_err());

    let retention_below_rotation = UserConfig {
        chainstate_journal: bitcoin_rs_node::ChainstateJournalOverrides {
            rotate_mib: Some(512),
            max_journal_mib: Some(256),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(resolve(&[&retention_below_rotation]).is_err());
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn mining_payout_address_decodes_after_all_layers() -> Result<()> {
    use bitcoin_rs_node::MiningOverrides;

    const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let network = UserConfig {
        network: Some(NetworkSelection::Regtest),
        ..Default::default()
    };
    let payout = UserConfig {
        mining: MiningOverrides {
            payout_address: Some(ADDRESS.to_owned()),
        },
        ..Default::default()
    };
    let config = resolve(&[&network, &payout])?;
    let expected = bitcoin::Address::from_str(ADDRESS)?
        .require_network(bitcoin::Network::Regtest)?
        .script_pubkey()
        .as_bytes()
        .to_vec();
    assert_eq!(config.mining.payout_script, expected);
    Ok(())
}

#[test]
fn mining_payout_address_must_match_the_resolved_network() {
    use bitcoin_rs_node::MiningOverrides;

    let layer = UserConfig {
        network: Some(NetworkSelection::Regtest),
        mining: MiningOverrides {
            payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned()),
        },
        ..Default::default()
    };
    assert!(resolve(&[&layer]).is_err());
}

#[test]
fn operator_noban_defaults_empty_and_uses_the_subnet_owner() -> Result<()> {
    assert_eq!(
        NodeConfig::default_for_network(Network::Regtest)
            .p2p
            .noban_subnets,
        Vec::<bitcoin_rs_node::options::IpSubnet>::new()
    );
    let layer: UserConfig = toml::from_str(
        r#"network = "regtest"
p2p_noban = ["192.0.2.99/24", "::1"]
"#,
    )?;
    let config = resolve(&[&layer])?;
    assert_eq!(config.p2p.noban_subnets[0].to_string(), "192.0.2.0/24");
    assert!(config.p2p.noban_subnets[0].contains("::ffff:192.0.2.1".parse()?));
    assert_eq!(config.p2p.noban_subnets[1].to_string(), "::1/128");
    assert!(toml::from_str::<UserConfig>(r#"p2p_noban = ["192.0.2.0/99"]"#).is_err());
    let mut environment = UserConfig::default();
    environment.apply_env(
        "BITCOIN_RS_P2P_NOBAN",
        std::ffi::OsStr::new("198.51.100.1, ::1"),
    )?;
    let config = resolve(&[&layer, &environment])?;
    assert_eq!(config.p2p.noban_subnets[0].to_string(), "198.51.100.1/32");
    assert_eq!(config.p2p.noban_subnets.len(), 2);
    environment.apply_env("BITCOIN_RS_P2P_NOBAN", std::ffi::OsStr::new(""))?;
    assert_eq!(
        resolve(&[&layer, &environment])?.p2p.noban_subnets,
        Vec::<bitcoin_rs_node::options::IpSubnet>::new()
    );
    assert!(
        environment
            .apply_env("BITCOIN_RS_P2P_NOBAN", std::ffi::OsStr::new("bad-subnet"))
            .is_err()
    );
    Ok(())
}
