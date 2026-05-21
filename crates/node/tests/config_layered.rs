//! Integration tests for the bitcoin-rs node.

use anyhow::Result;
use bitcoin_rs_node::{Auth, Config, Network};
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

    let env: [EnvPair; 4] = [
        ("BITCOIN_RS_STORAGE_BACKEND", "redb"),
        ("BITCOIN_RS_DBCACHE_MB", "1024"),
        ("BITCOIN_RS_BLOCKFILTERINDEX", "true"),
        ("BITCOIN_RS_LOG_LEVEL", "warn"),
    ];
    let config = Config::from_layered_sources(
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
    assert!(config.blockfilterindex);
    assert_auth_user(&config.rpc_auth, "toml-user");
    Ok(())
}

#[test]
fn cli_can_override_socket_and_vector_fields() -> Result<()> {
    let listen: SocketAddr = "127.0.0.1:18444".parse()?;
    let metrics: SocketAddr = "127.0.0.1:19090".parse()?;
    let config = Config::from_layered_sources(
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
fn zmq_layers_parse_precedence_and_publication_order() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");
    let bitcoin_conf_path = temp.path().join("bitcoin.conf");

    fs::write(
        &toml_path,
        r#"
zmqpubhashblock = ["tcp://127.0.0.1:28332", "tcp://127.0.0.1:28333"]
zmqpubhashblockhwm = 9
"#,
    )?;
    fs::write(
        &bitcoin_conf_path,
        r"
-zmqpubhashblock=tcp://127.0.0.1:18332
-zmqpubhashblockhwm=3
",
    )?;

    let env: [EnvPair; 2] = [
        (
            "BITCOIN_RS_ZMQPUBRAWTX",
            "tcp://127.0.0.1:28334,tcp://127.0.0.1:28335",
        ),
        ("BITCOIN_RS_ZMQPUBRAWTXHWM", "11"),
    ];
    let config = Config::from_layered_sources(
        Some(&toml_path),
        Some(&bitcoin_conf_path),
        env,
        [
            "bitcoin-rs-node",
            "--zmqpubhashtx",
            "tcp://127.0.0.1:28336",
            "--zmqpubrawtx",
            "tcp://127.0.0.1:28337",
            "--zmqpubrawtxhwm",
            "12",
        ],
    )?;

    let publications = config.zmq_publications();
    let topics: Vec<_> = publications
        .iter()
        .map(|publication| publication.topic.as_str())
        .collect();
    let endpoints: Vec<_> = publications
        .iter()
        .map(|publication| publication.endpoint.as_str())
        .collect();
    let hwms: Vec<_> = publications
        .iter()
        .map(|publication| publication.hwm)
        .collect();

    assert_eq!(topics, ["hashblock", "hashblock", "hashtx", "rawtx"]);
    assert_eq!(
        endpoints,
        [
            "tcp://127.0.0.1:28332",
            "tcp://127.0.0.1:28333",
            "tcp://127.0.0.1:28336",
            "tcp://127.0.0.1:28337",
        ]
    );
    assert_eq!(hwms, [9, 9, 1_000, 12]);
    Ok(())
}

fn assert_auth_user(auth: &Auth, expected: &str) {
    match auth {
        Auth::Basic { user, .. } => assert_eq!(user, expected),
        Auth::Cookie { .. } => panic!("expected basic auth"),
    }
}
