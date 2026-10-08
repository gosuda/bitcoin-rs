//! `bitcoin-rs` — node binary entry point.
//!
//! Starts the configured `bitcoin-rs` node with crash recovery, signal handling,
//! metrics/tracing setup, and graceful shutdown.

#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

mod config;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(test)]
fn load(
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> anyhow::Result<bitcoin_rs_node::NodeConfig> {
    let cli = <config::CliArgs as clap::Parser>::try_parse_from(args)?;
    config::resolve(cli, vars)
}

fn main() -> ExitCode {
    let cli = match <config::CliArgs as clap::Parser>::try_parse() {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let result = config::resolve(cli, std::env::vars_os())
        .and_then(|config| bitcoin_rs_node::run(config, bitcoin_rs_node::RuntimeInputs::default()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bitcoin-rs: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn measurement_options_are_not_node_options() {
        use clap::Parser as _;
        for option in [
            "--measure-storage",
            "--measure-storage-output",
            "--measure-storage-stop-height",
            "--measure-storage-stop-hash",
            "--storage-high-water-bytes",
        ] {
            let error = super::config::CliArgs::try_parse_from(["bitcoin-rs", option])
                .err()
                .unwrap_or_else(|| panic!("measurement option accepted: {option}"));
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use bitcoin_rs_chainstate::ValidationMode;
    use bitcoin_rs_node::{Auth, Network, ScriptIndexMode};

    fn load_file(
        flag: &str,
        text: &str,
        args: &[&str],
        vars: impl Iterator<Item = (OsString, OsString)>,
    ) -> anyhow::Result<bitcoin_rs_node::NodeConfig> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config");
        std::fs::write(&path, text)?;
        let mut argv = vec![
            OsString::from("bitcoin-rs"),
            OsString::from(flag),
            path.into_os_string(),
        ];
        argv.extend(args.iter().map(OsString::from));
        super::load(argv, vars)
    }

    #[test]
    fn bitcoin_conf_is_applied_before_environment_and_cli() {
        let config = load_file("--bitcoin-conf", "prune=777\n", &[], std::iter::empty())
            .unwrap_or_else(|error| panic!("valid bitcoin.conf configuration: {error}"));

        assert_eq!(config.storage.prune_target_mb, 777);
    }

    #[test]
    fn bitcoin_conf_is_overridden_by_cli() {
        let config = load_file(
            "--bitcoin-conf",
            "prune=777\n",
            &["--prune-target-mb", "100"],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));

        assert_eq!(config.storage.prune_target_mb, 100);
    }

    #[test]
    fn earlier_toml_connect_survives_later_cli_network() {
        let config = load_file(
            "--config",
            "connect = [\"10.0.0.5:8333\"]\n",
            &["--network", "regtest"],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));

        assert_eq!(config.network, Network::Regtest);
        assert_eq!(
            config.p2p.connect,
            vec!["10.0.0.5:8333"],
            "a later bare CLI network selection fills profile fields, it does not reset them"
        );
    }

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
    fn fast_sync_defaults_off_and_enables_from_flag_or_environment() {
        let config = super::load(["bitcoin-rs"], std::iter::empty::<(OsString, OsString)>())
            .unwrap_or_else(|error| panic!("valid default configuration: {error}"));
        assert!(!config.p2p.fast_sync);

        let config = super::load(
            ["bitcoin-rs", "--fast-sync"],
            std::iter::empty::<(OsString, OsString)>(),
        )
        .unwrap_or_else(|error| panic!("valid CLI configuration: {error}"));
        assert!(config.p2p.fast_sync);

        let config = super::load(
            ["bitcoin-rs", "--fast-sync=false"],
            std::iter::once(("BITCOIN_RS_FAST_SYNC", "true"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));
        assert!(!config.p2p.fast_sync);
    }

    /// #1117: the startup failure for `validation.engine = "kernel"` on a
    /// build without bitcoinkernel support. The engine selection is resolved
    /// and checked during configuration — before the data directory, chain
    /// state, or any worker is created — and must name the missing capability.
    #[test]
    #[cfg(not(feature = "kernel"))]
    fn validation_engine_kernel_is_rejected_without_kernel_support() {
        let error = match super::load(
            ["bitcoin-rs", "--validation-engine", "kernel"],
            std::iter::empty::<(OsString, OsString)>(),
        ) {
            Ok(_) => panic!("unsupported engine must fail startup from the CLI"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("not compiled"),
            "unsupported-build error must say so, got {error:#}"
        );

        let error = match super::load(
            ["bitcoin-rs"],
            std::iter::once(("BITCOIN_RS_VALIDATION_ENGINE", "kernel"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        ) {
            Ok(_) => panic!("unsupported engine must fail startup from the environment"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("not compiled"),
            "unsupported-build error must say so, got {error:#}"
        );

        let error = match load_file(
            "--config",
            "validation_engine = \"kernel\"\n",
            &[],
            std::iter::empty::<(OsString, OsString)>(),
        ) {
            Ok(_) => panic!("unsupported engine must fail startup from TOML too"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("not compiled"),
            "unsupported-build error must say so, got {error:#}"
        );
    }

    #[test]
    fn validation_engine_defaults_to_native_and_layers_flag_over_environment() {
        use bitcoin_rs_node::ValidationEngine;

        let config = super::load(["bitcoin-rs"], std::iter::empty::<(OsString, OsString)>())
            .unwrap_or_else(|error| panic!("valid default configuration: {error}"));
        assert_eq!(config.validation.engine, ValidationEngine::Native);

        let config = super::load(
            ["bitcoin-rs", "--validation-engine", "native"],
            std::iter::once(("BITCOIN_RS_VALIDATION_ENGINE", "kernel"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));
        assert_eq!(config.validation.engine, ValidationEngine::Native);
    }

    #[test]
    fn validation_mode_defaults_to_assume_valid_and_layers_flag_over_environment() {
        let config = super::load(["bitcoin-rs"], std::iter::empty::<(OsString, OsString)>())
            .unwrap_or_else(|error| panic!("valid default configuration: {error}"));
        assert_eq!(config.validation.mode, ValidationMode::AssumeValid);

        let config = super::load(
            ["bitcoin-rs", "--validation-mode", "full"],
            std::iter::once(("BITCOIN_RS_VALIDATION_MODE", "fast"))
                .map(|(key, value)| (OsString::from(key), OsString::from(value))),
        )
        .unwrap_or_else(|error| panic!("valid layered configuration: {error}"));
        assert_eq!(config.validation.mode, ValidationMode::Full);
        assert_eq!(ValidationMode::parse("lenient"), None);
    }

    #[test]
    fn toml_groups_zmq_topics_by_endpoint() {
        let config = load_file(
            "--config",
            r#"
[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28332"
topics = ["hashblock", "rawblock", "sequence"]

[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28333"
topics = ["hashtx", "rawtx"]
hwm = 5000
"#,
            &[],
            std::iter::empty(),
        )
        .unwrap_or_else(|error| panic!("valid toml configuration: {error}"));

        let endpoints = &config.notifications.zmq;
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].endpoint, "tcp://127.0.0.1:28332");
        assert_eq!(endpoints[0].effective_hwm(), 1_000);
        assert_eq!(endpoints[1].effective_hwm(), 5_000);
    }

    #[test]
    fn legacy_flat_zmq_toml_is_rejected() {
        let error = match load_file(
            "--config",
            r#"zmqpubhashblock = ["tcp://127.0.0.1:28332"]"#,
            &[],
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

    /// IDX-01: `--scriptindex` without a value means `full`.
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

    /// IDX-01: `--scriptindex=utxo` enables `ScriptLive` only.
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
        let config = load_file(
            "--config",
            r"
[chainstate_journal]
enabled = true
blocks = 100
",
            &[],
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
