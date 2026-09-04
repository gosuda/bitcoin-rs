//! Resolver tests for grouped node configuration layers.

use anyhow::Result;
use bitcoin_rs_node::zmq_publisher::ZmqTopic;
use bitcoin_rs_node::{
    NetworkSelection, NodeConfig, NotificationConfig, P2pOverrides, ScriptIndexMode, UserConfig,
    ValidationOverrides, ZmqEndpointConfig, resolve,
};
use bitcoin_rs_primitives::Network;

#[test]
fn standard_network_uses_builtin_defaults() -> Result<()> {
    let layer = UserConfig {
        network: Some(NetworkSelection::Testnet4),
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert_eq!(config.network, Network::Testnet4);
    assert_eq!(config.p2p.magic, Network::Testnet4.magic());
    assert!(config.p2p.connect.is_empty());
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
        },
        ..Default::default()
    };
    let config = resolve(&[&layer])?;
    assert!(!config.indexes.txindex);
    assert!(config.indexes.script_index.is_enabled());
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
    let endpoints = config.zmq_endpoints();
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
    assert_eq!(config.zmq_endpoints()[0].effective_hwm(), 42);
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
        },
        ..Default::default()
    };
    let high = UserConfig {
        validation: ValidationOverrides {
            assume_valid_height: Some(30_000),
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
        chainstate_journal: Some(bitcoin_rs_node::ChainstateJournalOverrides {
            enabled: Some(true),
            blocks: Some(100),
            ..Default::default()
        }),
        ..Default::default()
    };
    let higher = UserConfig {
        chainstate_journal: Some(bitcoin_rs_node::ChainstateJournalOverrides {
            blocks: Some(200),
            ..Default::default()
        }),
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
        chainstate_journal: Some(bitcoin_rs_node::ChainstateJournalOverrides {
            enabled: Some(false),
            ..Default::default()
        }),
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
        chainstate_journal: Some(bitcoin_rs_node::ChainstateJournalOverrides {
            blocks: Some(0),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(resolve(&[&zero_blocks]).is_err());

    let lag_below_batch = UserConfig {
        chainstate_journal: Some(bitcoin_rs_node::ChainstateJournalOverrides {
            max_lag_blocks: Some(10),
            blocks: Some(500),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(resolve(&[&lag_below_batch]).is_err());

    let retention_below_rotation = UserConfig {
        chainstate_journal: Some(bitcoin_rs_node::ChainstateJournalOverrides {
            rotate_mib: Some(512),
            max_journal_mib: Some(256),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(resolve(&[&retention_below_rotation]).is_err());
}
