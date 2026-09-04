//! `bitcoin-rs` — node binary entry point.
//!
//! Starts the configured `bitcoin-rs` node with crash recovery, signal handling,
//! metrics/tracing setup, and graceful shutdown.

#![allow(missing_docs)]
#![allow(unreachable_pub)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

mod cli;
mod env;
mod toml;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn load(
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> anyhow::Result<bitcoin_rs_node::NodeConfig> {
    let cli = match <cli::CliArgs as clap::Parser>::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let mut layers = Vec::new();
    if let Some(path) = &cli.config {
        layers.push(toml::user_config_from_path(path)?);
    }
    layers.push(env::user_config_from_env(vars)?);
    layers.push(cli.into_user_config());
    let layer_refs: Vec<_> = layers.iter().collect();
    bitcoin_rs_node::resolve(&layer_refs)
}

fn main() -> ExitCode {
    match load(std::env::args_os(), std::env::vars_os())
        .and_then(|config| bitcoin_rs_node::run(config, bitcoin_rs_node::RuntimeInputs::default()))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitcoin-rs: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use bitcoin_rs_node::{Auth, Network, ScriptIndexMode};

    #[test]
    fn environment_is_overridden_by_cli() {
        let config = super::load(
            [
                "bitcoin-rs",
                "--network",
                "regtest",
                "--data-dir",
                "/tmp/cli-node",
                "--rpc-user",
                "cli-user",
            ],
            [
                ("BITCOIN_RS_NETWORK", "testnet4"),
                ("BITCOIN_RS_DATA_DIR", "/tmp/env-node"),
                ("BITCOIN_RS_RPC_USER", "env-user"),
            ]
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));

        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.data_dir, std::path::PathBuf::from("/tmp/cli-node"));
        assert_eq!(
            config.rpc.auth,
            Auth::Basic {
                user: "cli-user".to_owned(),
                password: "bitcoin-rs".to_owned(),
            }
        );
    }

    #[test]
    fn environment_parses_script_index() {
        let config = super::load(
            ["bitcoin-rs"],
            std::iter::once(("BITCOIN_RS_SCRIPTINDEX", "full"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid environment configuration: {error}"));

        assert_eq!(config.indexes.script_index, ScriptIndexMode::Full);
    }

    #[test]
    fn environment_parses_script_index_utxo() {
        let config = super::load(
            ["bitcoin-rs"],
            std::iter::once(("BITCOIN_RS_SCRIPTINDEX", "utxo"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid environment configuration: {error}"));

        assert_eq!(config.indexes.script_index, ScriptIndexMode::Utxo);
    }

    #[test]
    fn toml_groups_zmq_topics_by_endpoint() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = dir.path().join("node.toml");
        std::fs::write(
            &path,
            r#"
[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28332"
topics = ["hashblock", "rawblock", "sequence"]

[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28333"
topics = ["hashtx", "rawtx"]
hwm = 5000
"#,
        )
        .unwrap_or_else(|error| panic!("write toml: {error}"));

        let config = super::load(
            [
                "bitcoin-rs",
                "--config",
                path.to_str().unwrap_or_else(|| panic!("utf-8 path")),
            ],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid toml configuration: {error}"));

        let endpoints = config.zmq_endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].endpoint, "tcp://127.0.0.1:28332");
        assert_eq!(endpoints[0].effective_hwm(), 1_000);
        assert_eq!(endpoints[1].effective_hwm(), 5_000);
    }

    #[test]
    fn legacy_flat_zmq_toml_is_rejected() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = dir.path().join("node.toml");
        std::fs::write(&path, r#"zmqpubhashblock = ["tcp://127.0.0.1:28332"]"#)
            .unwrap_or_else(|error| panic!("write toml: {error}"));

        let error = match super::load(
            [
                "bitcoin-rs",
                "--config",
                path.to_str().unwrap_or_else(|| panic!("utf-8 path")),
            ],
            std::iter::empty(),
        ) {
            Ok(_) => panic!("legacy flat ZMQ keys must not be silently accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("failed to parse TOML config"));
    }

    #[test]
    fn cli_network_profile_precedes_cli_explicit_p2p_overrides() {
        let config = super::load(
            [
                "bitcoin-rs",
                "--network",
                "drynet4",
                "--p2p-magic",
                "01020304",
                "--connect",
                "127.0.0.1:8333",
                "--dns-seeds-enabled",
                "false",
            ],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));

        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.p2p.magic, [1, 2, 3, 4]);
        assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333"]);
        assert!(!config.p2p.dns_seeds_enabled);
    }

    #[test]
    fn cli_scriptindex_flag_enables_full_index() {
        let config = super::load(
            ["bitcoin-rs", "--txindex=false", "--scriptindex"],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid CLI configuration: {error}"));

        assert!(!config.indexes.txindex);
        assert_eq!(config.indexes.script_index, ScriptIndexMode::Full);
    }

    #[test]
    fn cli_scriptindex_utxo_enables_live_only_index() {
        let config = super::load(
            ["bitcoin-rs", "--txindex=false", "--scriptindex=utxo"],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid CLI configuration: {error}"));

        assert!(!config.indexes.txindex);
        assert_eq!(config.indexes.script_index, ScriptIndexMode::Utxo);
    }

    #[test]
    fn cli_parses_socket_and_peer_lists() {
        let config = super::load(
            [
                "bitcoin-rs",
                "--network",
                "regtest",
                "--p2p-listen",
                "127.0.0.1:18444",
                "--metrics-bind",
                "127.0.0.1:19090",
                "--dns-seeds-enabled=false",
                "--connect",
                "localhost:18444,10.0.0.2:8333",
            ],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid CLI configuration: {error}"));

        assert_eq!(
            config.p2p.listen,
            vec![
                "127.0.0.1:18444"
                    .parse()
                    .unwrap_or_else(|error| panic!("socket address: {error}"))
            ]
        );
        assert_eq!(
            config.observability.metrics_bind,
            Some(
                "127.0.0.1:19090"
                    .parse()
                    .unwrap_or_else(|error| panic!("socket address: {error}")),
            )
        );
        assert!(!config.p2p.dns_seeds_enabled);
        assert_eq!(config.p2p.connect, vec!["localhost:18444", "10.0.0.2:8333"]);
    }

    #[test]
    fn environment_cookie_auth_is_resolved_and_redacted() {
        let config = super::load(
            ["bitcoin-rs"],
            std::iter::once(("BITCOIN_RS_RPC_COOKIE", "/secret/.cookie"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid environment configuration: {error}"));

        assert_eq!(
            config.rpc.auth,
            Auth::Cookie {
                path: std::path::PathBuf::from("/secret/.cookie")
            }
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("/secret/.cookie"));
    }

    #[cfg(unix)]
    #[test]
    fn unrelated_non_utf8_environment_value_is_ignored() {
        let config = super::load(
            ["bitcoin-rs"],
            std::iter::once((OsString::from("UNRELATED"), OsString::from_vec(vec![0xff]))),
        )
        .unwrap_or_else(|error| panic!("unrelated environment variable: {error}"));

        assert_eq!(config.network, Network::Mainnet);
    }

    #[test]
    fn toml_chainstate_journal_is_overridden_by_environment() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = dir.path().join("node.toml");
        std::fs::write(
            &path,
            r"
[chainstate_journal]
enabled = true
blocks = 100
",
        )
        .unwrap_or_else(|error| panic!("write toml: {error}"));

        let config = super::load(
            [
                "bitcoin-rs",
                "--config",
                path.to_str().unwrap_or_else(|| panic!("utf-8 path")),
            ],
            std::iter::once(("BITCOIN_RS_CHAINSTATE_JOURNAL_BLOCKS", "200"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid journal configuration: {error}"));

        assert!(config.chainstate_journal.enabled);
        assert_eq!(config.chainstate_journal.blocks, 200);
        assert_eq!(config.chainstate_journal.seconds, 5);
    }

    #[test]
    fn environment_rejects_invalid_chainstate_journal_boolean() {
        let error = match super::load(
            ["bitcoin-rs"],
            std::iter::once(("BITCOIN_RS_CHAINSTATE_JOURNAL", "sometimes"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        ) {
            Ok(_) => panic!("invalid journal boolean must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid boolean"));
    }

    #[cfg(unix)]
    #[test]
    fn known_non_utf8_environment_value_is_rejected() {
        let error = match super::load(
            ["bitcoin-rs"],
            std::iter::once((
                OsString::from("BITCOIN_RS_DATA_DIR"),
                OsString::from_vec(vec![0xff]),
            )),
        ) {
            Ok(_) => panic!("known environment variable must be valid UTF-8"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("environment variable BITCOIN_RS_DATA_DIR is not valid UTF-8")
        );
    }
}
