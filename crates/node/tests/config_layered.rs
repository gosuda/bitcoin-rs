//! Integration tests for the bitcoin-rs node.

use anyhow::Result;
use bitcoin_rs_node::{Auth, Network, NodeConfig, ScriptIndexMode};
use std::fs;
use std::net::SocketAddr;

type EnvPair = (&'static str, &'static str);

#[test]
fn config_layers_resolve_defaults_bitcoin_conf_toml_env_then_cli() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");
    let bitcoin_conf_path = temp.path().join("bitcoin.conf");

    fs::write(
        &toml_path,
        r#"
network = "regtest"
storage_backend = "fjall"
prune_target_mb = 1000
dbcache_mb = 512
log_level = "debug"
rpc_user = "toml-user"
rpc_password = "toml-pass"
"#,
    )?;
    fs::write(
        &bitcoin_conf_path,
        r"
-prune=550
-rpcuser=conf-user
-rpcpassword=conf-pass
-txindex=1
",
    )?;

    let env: [EnvPair; 3] = [
        ("BITCOIN_RS_STORAGE_BACKEND", "redb"),
        ("BITCOIN_RS_DBCACHE_MB", "1024"),
        ("BITCOIN_RS_LOG_LEVEL", "warn"),
    ];
    let config = NodeConfig::from_layered_sources(
        Some(&toml_path),
        Some(&bitcoin_conf_path),
        env,
        [
            "bitcoin-rs-node",
            "--storage-backend",
            "mdbx",
            "--dbcache-mb",
            "2048",
            "--log-level",
            "trace",
        ],
    )?;

    assert_eq!(config.network, Network::Regtest);
    assert_eq!(config.storage_backend, "mdbx");
    assert_eq!(config.prune_target_mb, 1000);
    assert_eq!(config.dbcache_mb, 2048);
    assert_eq!(config.log_level, "trace");
    assert!(config.txindex);
    assert_auth_user(&config.rpc_auth, "toml-user");
    Ok(())
}

#[test]
fn cli_can_override_socket_and_vector_fields() -> Result<()> {
    let listen: SocketAddr = "127.0.0.1:18444".parse()?;
    let metrics: SocketAddr = "127.0.0.1:19090".parse()?;
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        [
            "bitcoin-rs-node",
            "--network",
            "regtest",
            "--p2p-listen",
            "127.0.0.1:18444",
            "--metrics-bind",
            "127.0.0.1:19090",
            "--dns-seeds-enabled",
            "false",
        ],
    )?;

    assert_eq!(config.network, Network::Regtest);
    assert_eq!(config.p2p_listen, vec![listen]);
    assert_eq!(config.metrics_bind, Some(metrics));
    assert!(!config.dns_seeds_enabled);
    Ok(())
}

#[test]
fn p2p_magic_override_preserves_consensus_network() -> Result<()> {
    let peer = "127.0.0.1:8333".to_owned();
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        [
            "bitcoin-rs-node",
            "--p2p-magic",
            "eca5d434",
            "--dns-seeds-enabled",
            "false",
            "--connect",
            "127.0.0.1:8333",
        ],
    )?;

    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.p2p_magic, [0xec, 0xa5, 0xd4, 0x34]);
    assert_eq!(config.connect, vec![peer]);
    assert!(!config.dns_seeds_enabled);
    Ok(())
}

#[test]
fn drynet4_network_applies_atomic_p2p_profile() -> Result<()> {
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        [("BITCOIN_RS_NETWORK", "drynet4")],
        ["bitcoin-rs-node"],
    )?;

    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.p2p_magic, [0xec, 0xa5, 0xd4, 0x04]);
    assert_eq!(config.connect, vec!["drynet4.drivechain.dev:8533"]);
    assert!(!config.dns_seeds_enabled);
    Ok(())
}

#[test]
fn explicit_fields_override_network_defaults_within_the_same_layer() -> Result<()> {
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        [
            ("BITCOIN_RS_NETWORK", "drynet4"),
            ("BITCOIN_RS_CONNECT", "127.0.0.1:8333"),
        ],
        ["bitcoin-rs-node", "--p2p-magic", "01020304"],
    )?;

    assert_eq!(config.p2p_magic, [1, 2, 3, 4]);
    assert_eq!(config.connect, vec!["127.0.0.1:8333"]);
    Ok(())
}

#[test]
fn toml_p2p_topology_survives_cli_operational_overrides() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("bounded-sync.toml");
    fs::write(
        &toml_path,
        r#"
storage_backend = "fjall"
p2p_listen = []
dns_seeds_enabled = false
connect = ["127.0.0.1:18444"]
"#,
    )?;

    let config = NodeConfig::from_layered_sources(
        Some(&toml_path),
        None,
        core::iter::empty::<EnvPair>(),
        [
            "bitcoin-rs-node",
            "--rpc-bind",
            "127.0.0.1:18445",
            "--rpc-user",
            "benchmark",
        ],
    )?;

    assert_eq!(config.network, Network::Mainnet);
    assert!(config.p2p_listen.is_empty());
    assert!(!config.dns_seeds_enabled);
    assert_eq!(config.connect, vec!["127.0.0.1:18444"]);
    assert_eq!(config.rpc_bind, "127.0.0.1:18445".parse()?);
    Ok(())
}

#[test]
fn standard_network_uses_builtin_defaults() -> Result<()> {
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        [("BITCOIN_RS_NETWORK", "testnet4")],
        ["bitcoin-rs-node"],
    )?;

    assert_eq!(config.network, Network::Testnet4);
    assert_eq!(config.p2p_magic, Network::Testnet4.magic());
    assert!(config.connect.is_empty());
    assert!(config.dns_seeds_enabled);
    Ok(())
}

#[test]
fn p2p_magic_override_requires_an_explicit_peer() {
    let result = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        [
            "bitcoin-rs-node",
            "--p2p-magic",
            "eca5d434",
            "--dns-seeds-enabled",
            "false",
        ],
    );
    assert!(result.is_err_and(|error| error.to_string().contains("at least one --connect peer")));
}

#[test]
fn script_index_is_valid_without_core_txindex() -> Result<()> {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.script_index = ScriptIndexMode::Full;
    config.txindex = false;

    config.validate()?;
    Ok(())
}

#[test]
fn scriptindex_cli_flag_enables_the_index() -> Result<()> {
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node", "--scriptindex"],
    )?;

    assert!(config.script_index.is_enabled());
    Ok(())
}

#[test]
fn scriptindex_environment_enables_the_index() -> Result<()> {
    let config = NodeConfig::from_layered_sources(
        None,
        None,
        [
            ("BITCOIN_RS_TXINDEX", "false"),
            ("BITCOIN_RS_SCRIPTINDEX", "true"),
        ],
        ["bitcoin-rs-node"],
    )?;

    assert!(!config.txindex);
    assert!(config.script_index.is_enabled());
    Ok(())
}

#[test]
fn zmq_toml_groups_topics_by_endpoint_and_uses_publisher_default_hwm() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");

    fs::write(
        &toml_path,
        r#"
[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28332"
topics = ["hashblock", "rawblock", "sequence"]

[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28333"
topics = ["hashtx", "rawtx"]
hwm = 5000
"#,
    )?;

    let config = NodeConfig::from_layered_sources(
        Some(&toml_path),
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;

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
fn legacy_flat_zmq_toml_is_rejected() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");
    fs::write(&toml_path, r#"zmqpubhashblock = ["tcp://127.0.0.1:28332"]"#)?;

    let error = NodeConfig::from_layered_sources(
        Some(&toml_path),
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )
    .err()
    .ok_or_else(|| anyhow::anyhow!("legacy flat ZMQ keys must not be silently accepted"))?;
    assert!(error.to_string().contains("failed to parse TOML config"));
    Ok(())
}

#[test]
fn zmq_endpoint_groups_reject_duplicate_socket_and_topic_ownership() {
    use bitcoin_rs_node::{ZmqEndpointConfig, ZmqTopic};

    let mut config = NodeConfig::default();
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
fn assume_valid_height_layers_use_cli_env_toml_precedence() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");

    fs::write(
        &toml_path,
        r"
assume_valid_height = 10000
",
    )?;

    let toml_config = NodeConfig::from_layered_sources(
        Some(&toml_path),
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(toml_config.assume_valid_height, 10_000);

    let env_config = NodeConfig::from_layered_sources(
        Some(&toml_path),
        None,
        [("BITCOIN_RS_ASSUME_VALID_HEIGHT", "20000")],
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(env_config.assume_valid_height, 20_000);

    let cli_config = NodeConfig::from_layered_sources(
        Some(&toml_path),
        None,
        [("BITCOIN_RS_ASSUME_VALID_HEIGHT", "20000")],
        ["bitcoin-rs-node", "--assume-valid-height", "30000"],
    )?;
    assert_eq!(cli_config.assume_valid_height, 30_000);

    let default_config = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(
        default_config.assume_valid_height,
        Network::Mainnet
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height)
    );
    Ok(())
}

#[test]
fn connect_layers_parse_cli_and_env_peer_lists() -> Result<()> {
    let cli_config = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        [
            "bitcoin-rs-node",
            "--connect",
            "127.0.0.1:8333,10.0.0.2:8333",
        ],
    )?;
    assert_eq!(cli_config.connect, vec!["127.0.0.1:8333", "10.0.0.2:8333"]);

    let env_config = NodeConfig::from_layered_sources(
        None,
        None,
        [("BITCOIN_RS_CONNECT", "192.0.2.5:8333")],
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(env_config.connect, vec!["192.0.2.5:8333"]);

    let hostname_config = NodeConfig::from_layered_sources(
        None,
        None,
        [("BITCOIN_RS_CONNECT", "localhost:18444")],
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(hostname_config.connect, vec!["localhost:18444"]);

    let default_config = NodeConfig::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;
    assert!(default_config.connect.is_empty());
    Ok(())
}

fn assert_auth_user(auth: &Auth, expected: &str) {
    match auth {
        Auth::Basic { user, .. } => assert_eq!(user, expected),
        Auth::Cookie { .. } => panic!("expected basic auth"),
    }
}
