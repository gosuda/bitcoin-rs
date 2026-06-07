//! Integration tests for the bitcoin-rs node.

use anyhow::Result;
use bitcoin_rs_node::{Auth, Config, Network};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

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
fn electrum_bind_requires_txindex() -> Result<()> {
    let mut config = Config::default_for_network(Network::Regtest);
    config.electrum_bind = Some("127.0.0.1:50001".parse()?);
    config.txindex = false;

    match config.validate() {
        Ok(()) => panic!("electrum_bind without txindex unexpectedly validated"),
        Err(error) => assert_eq!(error.to_string(), "electrum_bind requires txindex"),
    }
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

#[test]
fn g2_muhash_sample_path_layers_use_cli_env_toml_precedence() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");

    fs::write(
        &toml_path,
        r#"
g2_muhash_samples = "toml.samples"
g2_muhash_tip_height = 10000
"#,
    )?;

    let toml_config = Config::from_layered_sources(
        Some(&toml_path),
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(
        toml_config.g2_muhash_samples,
        Some(PathBuf::from("toml.samples"))
    );
    assert_eq!(toml_config.g2_muhash_tip_height, Some(10_000));

    let env_config = Config::from_layered_sources(
        Some(&toml_path),
        None,
        [
            ("BITCOIN_RS_G2_MUHASH_SAMPLES", "env.samples"),
            ("BITCOIN_RS_G2_MUHASH_TIP_HEIGHT", "20000"),
        ],
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(
        env_config.g2_muhash_samples,
        Some(PathBuf::from("env.samples"))
    );
    assert_eq!(env_config.g2_muhash_tip_height, Some(20_000));

    let cli_config = Config::from_layered_sources(
        Some(&toml_path),
        None,
        [
            ("BITCOIN_RS_G2_MUHASH_SAMPLES", "env.samples"),
            ("BITCOIN_RS_G2_MUHASH_TIP_HEIGHT", "20000"),
        ],
        [
            "bitcoin-rs-node",
            "--g2-muhash-samples",
            "cli.samples",
            "--g2-muhash-tip-height",
            "30000",
        ],
    )?;
    assert_eq!(
        cli_config.g2_muhash_samples,
        Some(PathBuf::from("cli.samples"))
    );
    assert_eq!(cli_config.g2_muhash_tip_height, Some(30_000));
    Ok(())
}

#[test]
fn g2_muhash_tip_height_requires_sample_path() {
    let result = Config::from_layered_sources(
        None,
        None,
        [("BITCOIN_RS_G2_MUHASH_TIP_HEIGHT", "10000")],
        ["bitcoin-rs-node"],
    );
    let Err(error) = result else {
        panic!("tip height without sample path must be rejected");
    };

    assert!(
        error
            .to_string()
            .contains("g2_muhash_tip_height requires g2_muhash_samples")
    );
}

#[test]
fn g2_muhash_sample_path_requires_tip_height() {
    let result = Config::from_layered_sources(
        None,
        None,
        [("BITCOIN_RS_G2_MUHASH_SAMPLES", "g2.samples")],
        ["bitcoin-rs-node"],
    );
    let Err(error) = result else {
        panic!("sample path without tip height must be rejected");
    };

    assert!(
        error
            .to_string()
            .contains("g2_muhash_samples requires g2_muhash_tip_height")
    );
}

#[test]
fn g2_muhash_tip_height_must_be_positive() {
    let result = Config::from_layered_sources(
        None,
        None,
        [
            ("BITCOIN_RS_G2_MUHASH_SAMPLES", "g2.samples"),
            ("BITCOIN_RS_G2_MUHASH_TIP_HEIGHT", "0"),
        ],
        ["bitcoin-rs-node"],
    );
    let Err(error) = result else {
        panic!("zero G2 tip height must be rejected");
    };

    assert!(
        error
            .to_string()
            .contains("g2_muhash_tip_height must be greater than zero")
    );
}

#[test]
fn assume_valid_height_layers_use_cli_env_toml_precedence() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let toml_path = temp.path().join("node.toml");

    fs::write(
        &toml_path,
        r#"
assume_valid_height = 10000
"#,
    )?;

    let toml_config = Config::from_layered_sources(
        Some(&toml_path),
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(toml_config.assume_valid_height, 10_000);

    let env_config = Config::from_layered_sources(
        Some(&toml_path),
        None,
        [("BITCOIN_RS_ASSUME_VALID_HEIGHT", "20000")],
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(env_config.assume_valid_height, 20_000);

    let cli_config = Config::from_layered_sources(
        Some(&toml_path),
        None,
        [("BITCOIN_RS_ASSUME_VALID_HEIGHT", "20000")],
        ["bitcoin-rs-node", "--assume-valid-height", "30000"],
    )?;
    assert_eq!(cli_config.assume_valid_height, 30_000);

    let default_config = Config::from_layered_sources(
        None,
        None,
        core::iter::empty::<EnvPair>(),
        ["bitcoin-rs-node"],
    )?;
    assert_eq!(default_config.assume_valid_height, 0);
    Ok(())
}

fn assert_auth_user(auth: &Auth, expected: &str) {
    match auth {
        Auth::Basic { user, .. } => assert_eq!(user, expected),
        Auth::Cookie { .. } => panic!("expected basic auth"),
    }
}
