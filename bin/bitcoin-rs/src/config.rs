use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use bitcoin_rs_chainstate::ValidationMode;
use bitcoin_rs_node::options::{
    PoolOverrides, parse_connect_endpoint, parse_network, parse_p2p_magic, parse_script_index,
    parse_storage_backend, parse_validation_engine, parse_validation_mode,
};
use bitcoin_rs_node::{
    ChainstateJournalOverrides, IndexOverrides, MiningOverrides, Network, NetworkSelection,
    NotificationConfig, ObservabilityOverrides, P2pOverrides, RpcOverrides, ScriptIndexMode,
    StorageOverrides, UserConfig, ValidationEngine, ValidationOverrides,
};
use bitcoin_rs_storage::StorageBackend;
use clap::Parser;

macro_rules! emit_cli {
    (
        fields {
            $(
                $(#[$fdoc:meta])*
                $fid:ident : $fty:ty {
                    cli[ $($fcli:tt)* ]
                    $( env[ $ekey:literal, $egram:expr ] )?
                    $( toml $tmode:ident ( $tkey:literal $(, $tgram:expr )? ) )?
                    $( conf[ $ckey:literal ] )?
                }
            )*
        }
        groups {
            $(
                $(#[$gdoc:meta])*
                group $gid:ident : $gty:ident $(table($gkey:literal))? $(#[$gattr:meta])*
                {
                    $(
                        $(#[$rdoc:meta])*
                        $rfield:ident as $rid:ident : $rty:ty {
                            cli[ $($gcli:tt)* ]
                            $( env[ $gekey:literal, $gegram:expr ] )?
                            $( toml $gtmode:ident ( $gtkey:literal $(, $gtgram:expr )? ) )?
                            $( conf[ $gckey:literal ] )?
                        }
                    )*
                }
            )*
        }
    ) => {
        #[derive(Parser)]
        #[command(name = "bitcoin-rs", about = "Run a bitcoin-rs node")]
        pub(crate) struct CliArgs {
            #[arg(long)]
            pub(crate) config: Option<PathBuf>,
            #[arg(long = "bitcoin-conf")]
            pub(crate) bitcoin_conf: Option<PathBuf>,
            /// Single regular Core-framed archive file for foreground offline import.
            #[arg(long)]
            pub(crate) corpus: Option<PathBuf>,
            /// Archive manifest binding the corpus identity and stop tip.
            #[arg(long)]
            pub(crate) manifest: Option<PathBuf>,
            /// Output certified-state JSON for the offline import.
            #[arg(long)]
            pub(crate) state: Option<PathBuf>,
            $(
                $(#[$fdoc])*
                $($fcli)*
                pub(crate) $fid: $fty,
            )*
            $(
                $(
                    $(#[$rdoc])*
                    $($gcli)*
                    pub(crate) $rid: $rty,
                )*
            )*

        }

        impl CliArgs {
            fn into_user_config(self) -> UserConfig {
                UserConfig {
                    $( $fid: self.$fid, )*
                    $(
                        $gid: $gty { $( $rfield: self.$rid, )* },
                    )*
                }
            }
        }
    };
}

bitcoin_rs_node::option_rows!(emit_cli);

pub(crate) fn resolve(
    mut cli: CliArgs,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<bitcoin_rs_node::NodeConfig> {
    let mut layers = Vec::new();
    if let Some(path) = &cli.config {
        layers.push(user_config_from_toml(path)?);
    }
    let env_layer = user_config_from_env(vars)?;
    let bitcoin_conf_path = cli.bitcoin_conf.take();
    let cli_layer = cli.into_user_config();
    if let Some(path) = bitcoin_conf_path {
        let network = network_from_layers(layers.iter().chain([&env_layer, &cli_layer]));
        layers.extend(user_config_from_bitcoin_conf(&path, network)?);
    }
    layers.push(env_layer);
    layers.push(cli_layer);
    let layer_refs: Vec<_> = layers.iter().collect();
    bitcoin_rs_node::resolve(&layer_refs)
}

fn network_from_layers<'a>(layers: impl IntoIterator<Item = &'a UserConfig>) -> Network {
    let mut network = Network::Mainnet;
    for layer in layers {
        if let Some(selection) = layer.network {
            network = selection.consensus_network();
        }
    }
    network
}

fn user_config_from_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Result<UserConfig> {
    let mut layer = UserConfig::default();
    for (key, value) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        layer.apply_env(key, &value)?;
    }
    Ok(layer)
}

fn user_config_from_toml(path: &Path) -> Result<UserConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse TOML config {}", path.display()))
}

fn user_config_from_bitcoin_conf(path: &Path, network: Network) -> Result<[UserConfig; 2]> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bitcoin.conf {}", path.display()))?;
    parse_for_network(&text, network)
}

fn parse_for_network(text: &str, network: Network) -> Result<[UserConfig; 2]> {
    let mut global = UserConfig::default();
    let mut selected = UserConfig::default();
    let mut current_section_selected = None;
    let mut errors = Vec::new();

    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = parse_section(line) {
            current_section_selected = Some(section_matches_network(section, network));
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim().trim_start_matches('-');
        let value = raw_value.trim();
        let outcome = match current_section_selected {
            None => apply_core_key(&mut global, key, value),
            Some(true) => apply_core_key(&mut selected, key, value),
            Some(false) => Ok(()),
        };
        if let Err(error) = outcome {
            errors.push(error);
        }
    }

    if errors.is_empty() {
        Ok([global, selected])
    } else {
        Err(anyhow::anyhow!(
            "invalid bitcoin.conf value{}: {}",
            if errors.len() == 1 { "" } else { "s" },
            errors.join("; ")
        ))
    }
}

macro_rules! emit_core_conf {
    (
        fields {
            $(
                $(#[$fdoc:meta])*
                $fid:ident : $fty:ty {
                    cli[ $($fcli:tt)* ]
                    $( env[ $ekey:literal, $egram:expr ] )?
                    $( toml $tmode:ident ( $tkey:literal $(, $tgram:expr )? ) )?
                    $( conf[ $fckey:literal ] )?
                }
            )*
        }
        groups {
            $(
                $(#[$gdoc:meta])*
                group $gid:ident : $gty:ident $(table($gkey:literal))? $(#[$gattr:meta])*
                {
                    $(
                        $(#[$rdoc:meta])*
                        $rfield:ident as $rid:ident : $rty:ty {
                            cli[ $($gcli:tt)* ]
                            $( env[ $gekey:literal, $gegram:expr ] )?
                            $( toml $gtmode:ident ( $gtkey:literal $(, $gtgram:expr )? ) )?
                            $( conf[ $gckey:literal ] )?
                        }
                    )*
                }
            )*
        }
    ) => {
        fn apply_core_key(layer: &mut UserConfig, key: &str, value: &str) -> Result<(), String> {
            if apply_core_exception(layer, key, value) {
                return Ok(());
            }
            match key {
                $(
                    $( $fckey => CoreValue::apply(key, value, &mut layer.$fid), )?
                )*
                $(
                    $(
                        $( $gckey => CoreValue::apply(key, value, &mut layer.$gid.$rfield), )?
                    )*
                )*
                _ => Ok(()),
            }
        }
    };
}

bitcoin_rs_node::option_rows!(emit_core_conf);

trait CoreValue {
    fn apply(key: &str, value: &str, slot: &mut Self) -> Result<(), String>;
}

impl CoreValue for Option<bool> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = parse_core_bool(value);
        Ok(())
    }
}

impl CoreValue for Option<u64> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        if let Ok(number) = value.parse() {
            *slot = Some(number);
        }
        Ok(())
    }
}

impl CoreValue for Option<String> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = Some(value.to_owned());
        Ok(())
    }
}

impl CoreValue for Option<PathBuf> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = Some(PathBuf::from(value));
        Ok(())
    }
}

impl CoreValue for Option<SocketAddr> {
    fn apply(key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        match value.parse() {
            Ok(addr) => {
                *slot = Some(addr);
                Ok(())
            }
            Err(_) => Err(format!("{key}={value:?} is not a valid socket address")),
        }
    }
}

impl CoreValue for Option<Vec<bitcoin_rs_node::options::NetworkLabel>> {
    fn apply(key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        let mut parsed = Vec::new();
        for item in value.split(',') {
            match bitcoin_rs_node::options::parse_network_label(item.trim()) {
                Ok(label) => {
                    if !parsed.contains(&label) {
                        parsed.push(label);
                    }
                }
                Err(_) => {
                    return Err(format!("{key}={value:?} names an unknown network"));
                }
            }
        }
        let entries = slot.get_or_insert_with(Vec::new);
        for label in parsed {
            if !entries.contains(&label) {
                entries.push(label);
            }
        }
        Ok(())
    }
}

impl CoreValue for Option<Vec<bitcoin_rs_node::options::PeerNetwork>> {
    fn apply(key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        let mut parsed = Vec::new();
        for item in value.split(',') {
            match bitcoin_rs_node::options::parse_peer_network(item.trim()) {
                Ok(label) => {
                    if !parsed.contains(&label) {
                        parsed.push(label);
                    }
                }
                Err(_) => {
                    return Err(format!("{key}={value:?} names an unknown network"));
                }
            }
        }
        let entries = slot.get_or_insert_with(Vec::new);
        for label in parsed {
            if !entries.contains(&label) {
                entries.push(label);
            }
        }
        Ok(())
    }
}
fn apply_core_exception(layer: &mut UserConfig, key: &str, value: &str) -> bool {
    if key != "listen" {
        return false;
    }
    if parse_core_bool(value).is_some_and(|listen| !listen) {
        layer.p2p.listen = Some(Vec::new());
    }
    true
}

fn parse_core_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_section(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']').map(str::trim)
}

fn section_matches_network(section: &str, network: Network) -> bool {
    match section.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" => network == Network::Mainnet,
        "test" | "testnet" | "testnet3" => network == Network::Testnet3,
        "testnet4" => network == Network::Testnet4,
        "signet" => network == Network::Signet,
        "regtest" => network == Network::Regtest,
        _ => false,
    }
}

fn strip_inline_comment(line: &str) -> &str {
    &line[..line.find(['#', ';']).unwrap_or(line.len())]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::parse_for_network;
    use bitcoin_rs_node::{Network, resolve};

    #[test]
    fn network_section_overrides_globals() {
        let layers = parse_for_network(
            "
-prune=550
[regtest]
-prune=900
-rpcuser=regtest-user
-rpcpassword=regtest-pass
",
            Network::Regtest,
        )
        .unwrap_or_else(|error| panic!("valid fixture parses: {error}"));
        let layer_refs: Vec<_> = layers.iter().collect();
        let config = resolve(&layer_refs).unwrap_or_else(|error| panic!("layer resolves: {error}"));
        assert_eq!(config.storage.prune_target_mb, 900);
    }

    #[test]
    fn every_table_core_key_reaches_its_slot() {
        let layers = parse_for_network(
            "
dbcache=450
prune=550
rest=1
txindex=true
rpcuser=someuser
rpcpassword=somepass
rpccookiefile=/tmp/.cookie
listen=0
",
            Network::Regtest,
        )
        .unwrap_or_else(|error| panic!("valid fixture parses: {error}"));
        let global = &layers[0];
        assert_eq!(global.storage.dbcache_mb, Some(450));
        assert_eq!(global.storage.prune_target_mb, Some(550));
        assert_eq!(global.rpc.rest, Some(true));
        assert_eq!(global.indexes.txindex, Some(true));
        assert_eq!(global.rpc.user.as_deref(), Some("someuser"));
        assert_eq!(global.rpc.password.as_deref(), Some("somepass"));
        assert_eq!(
            global.rpc.cookie.as_deref(),
            Some(Path::new("/tmp/.cookie"))
        );
        assert_eq!(global.p2p.listen, Some(Vec::new()));
    }

    #[test]
    fn an_unparseable_core_number_sets_nothing() {
        let layers = parse_for_network("dbcache=large\nrest=maybe\n", Network::Regtest)
            .unwrap_or_else(|error| panic!("non-routing keys stay lenient: {error}"));
        assert_eq!(layers[0].storage.dbcache_mb, None);
        assert_eq!(layers[0].rpc.rest, None);
    }
}

#[cfg(test)]
mod compat_tests {
    use super::user_config_from_bitcoin_conf;
    use anyhow::Result;
    use bitcoin_rs_node::{Auth, Network, NodeConfig, resolve};
    use std::fs;
    use std::net::SocketAddr;

    fn load_conf(text: &str, network: Network) -> Result<NodeConfig> {
        let temp = tempfile::tempdir()?;
        let conf_path = temp.path().join("bitcoin.conf");
        fs::write(&conf_path, text)?;
        let layers = user_config_from_bitcoin_conf(&conf_path, network)?;
        let layer_refs: Vec<_> = layers.iter().collect();
        resolve(&layer_refs)
    }

    #[test]
    fn bitcoin_conf_core_keys_map_into_config() -> Result<()> {
        let config = load_conf(
            r"
# Global Core options may carry a leading dash.
-prune=550
-rpcuser=foo
-rpcpassword=bar
-server=1
-listen=0
-txindex=1
-dbcache=768
",
            Network::Mainnet,
        )?;

        assert_eq!(config.storage.prune_target_mb, 550);
        assert_auth(&config.rpc.auth, "foo", "bar");
        assert_eq!(config.p2p.listen, []);
        assert!(config.indexes.txindex);
        assert_eq!(config.storage.dbcache_mb, 768);

        let conf_with_overlays = load_conf(
            r"
proxy=127.0.0.1:9050
onion=127.0.0.1:9051
dnsseed=0
proxyrandomize=1
torcontrol=127.0.0.1:9052
i2psam=127.0.0.1:7656
i2pacceptincoming=1
onlynet=onion,i2p
",
            Network::Mainnet,
        )?;
        assert_eq!(
            conf_with_overlays.p2p.overlay.proxy,
            Some(SocketAddr::from(([127, 0, 0, 1], 9050)))
        );
        assert_eq!(
            conf_with_overlays.p2p.overlay.onion_proxy,
            Some(SocketAddr::from(([127, 0, 0, 1], 9051)))
        );
        assert!(conf_with_overlays.p2p.overlay.randomize_credentials);
        assert_eq!(
            conf_with_overlays.p2p.overlay.tor_control,
            Some(SocketAddr::from(([127, 0, 0, 1], 9052)))
        );
        assert_eq!(conf_with_overlays.p2p.overlay.tor_cookie.as_deref(), None);
        assert_eq!(
            conf_with_overlays.p2p.overlay.i2p_sam,
            Some(SocketAddr::from(([127, 0, 0, 1], 7656)))
        );
        assert!(conf_with_overlays.p2p.overlay.i2p_accept);
        assert_eq!(
            conf_with_overlays.p2p.overlay.onlynet,
            vec![
                bitcoin_rs_node::options::PeerNetwork::Onion,
                bitcoin_rs_node::options::PeerNetwork::I2p
            ]
        );
        Ok(())
    }

    #[test]
    fn bitcoin_conf_malformed_proxy_names_the_key() {
        let error = match load_conf("proxy=localhost:9050\n", Network::Mainnet) {
            Ok(_) => panic!("a hostname proxy must not degrade to direct dialing"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("proxy"),
            "refusal names the key: {error}"
        );
    }

    #[test]
    fn bitcoin_conf_malformed_onlynet_names_the_key() {
        let error = match load_conf("onlynet=onnion\n", Network::Mainnet) {
            Ok(_) => panic!("a mis-typed onlynet must not degrade to unrestricted dialing"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("onlynet"),
            "refusal names the key: {error}"
        );
    }

    #[test]
    fn bitcoin_conf_network_sections_override_globals_for_selected_network() -> Result<()> {
        let config = load_conf(
            r"
-prune=550
[regtest]
-prune=900
-rpcuser=regtest-user
-rpcpassword=regtest-pass
",
            Network::Regtest,
        )?;

        assert_eq!(config.storage.prune_target_mb, 900);
        assert_auth(&config.rpc.auth, "regtest-user", "regtest-pass");
        Ok(())
    }

    #[test]
    fn bitcoin_conf_zmq_keys_are_not_promoted_into_node_config() -> Result<()> {
        let config = load_conf(
            r"
-zmqpubhashblock=tcp://127.0.0.1:28332
-zmqpubhashblock=tcp://127.0.0.1:28333
-zmqpubhashblockhwm=5
[regtest]
-zmqpubrawtx=tcp://127.0.0.1:28334
-zmqpubrawtxhwm=6
-zmqpubsequence=tcp://127.0.0.1:28335
-zmqpubsequencehwm=7
",
            Network::Regtest,
        )?;

        assert_eq!(config.notifications.zmq, []);
        Ok(())
    }

    #[test]
    fn bitcoin_conf_assumevalid_is_not_mapped_to_height_only_setting() -> Result<()> {
        let config = load_conf(
            r"
assumevalid=0000000000000000000000000000000000000000000000000000000000000000
",
            Network::Mainnet,
        )?;

        assert_eq!(
            config.validation.assume_valid_height,
            Network::Mainnet
                .assume_valid_anchor()
                .map_or(0, |(height, _)| height),
            "Bitcoin Core hash-based assumevalid must not alter the hash-pinned assume_valid_height default"
        );
        Ok(())
    }

    fn assert_auth(auth: &Auth, expected_user: &str, expected_password: &str) {
        match auth {
            Auth::Basic { user, password } => {
                assert_eq!(user, expected_user);
                assert_eq!(password, expected_password);
            }
            Auth::Cookie { .. } | Auth::GeneratedCookie => panic!("expected basic auth"),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod feature_option_tests {
    use std::ffi::OsString;
    use std::path::Path;

    use anyhow::Result;
    use bitcoin_rs_node::{Network, NodeConfig};
    use clap::Parser as _;

    use super::{CliArgs, parse_for_network, resolve};

    fn load(args: &[&str], vars: &[(&str, &str)]) -> Result<NodeConfig> {
        let argv = std::iter::once("bitcoin-rs").chain(args.iter().copied());
        let cli = CliArgs::try_parse_from(argv)?;
        resolve(
            cli,
            vars.iter()
                .map(|(key, value)| (OsString::from(*key), OsString::from(*value))),
        )
    }

    fn refusal(args: &[&str], vars: &[(&str, &str)]) -> String {
        match load(args, vars) {
            Ok(_) => panic!("configuration must be refused"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn relay_switches_are_bare_cli_flags_and_the_command_line_beats_environment() -> Result<()> {
        let off = load(&[], &[])?.p2p;
        assert!(
            !off.relay_offers.package_relay
                && !off.relay_offers.stale_tip_relay
                && !off.relay_offers.stale_tip_prefers_blocks
        );

        let on = load(
            &[
                "--p2p-package-relay",
                "--p2p-stale-tip-relay",
                "--p2p-stale-tip-prefers-blocks",
            ],
            &[],
        )?
        .p2p;
        assert!(
            on.relay_offers.package_relay
                && on.relay_offers.stale_tip_relay
                && on.relay_offers.stale_tip_prefers_blocks
        );

        let env_on = load(&[], &[("BITCOIN_RS_P2P_PACKAGE_RELAY", "true")])?.p2p;
        assert!(env_on.relay_offers.package_relay);
        let cli_off = load(
            &["--p2p-package-relay=false"],
            &[("BITCOIN_RS_P2P_PACKAGE_RELAY", "true")],
        )?
        .p2p;
        assert!(!cli_off.relay_offers.package_relay);

        let dangling = refusal(&["--p2p-stale-tip-prefers-blocks"], &[]);
        assert!(dangling.contains("--p2p-stale-tip-relay"));
        Ok(())
    }

    #[test]
    fn index_bundle_directories_resolve_from_the_command_line_and_stay_exclusive() -> Result<()> {
        let import = load(&["--txindex=true", "--index-bundle-import", "/srv/in"], &[])?.indexes;
        assert_eq!(import.bundle_import.as_deref(), Some(Path::new("/srv/in")));
        assert_eq!(import.bundle_export, None);

        let export = load(
            &["--txindex=true"],
            &[("BITCOIN_RS_INDEX_BUNDLE_EXPORT", "/srv/out")],
        )?
        .indexes;
        assert_eq!(export.bundle_export.as_deref(), Some(Path::new("/srv/out")));

        let conflict = refusal(
            &["--txindex=true", "--index-bundle-import", "/srv/in"],
            &[("BITCOIN_RS_INDEX_BUNDLE_EXPORT", "/srv/out")],
        );
        assert!(conflict.contains("mutually exclusive"));
        assert!(refusal(&["--index-bundle-export", "/srv/out"], &[]).contains("--txindex"));
        Ok(())
    }

    #[test]
    fn empty_index_bundle_directories_are_refused_by_clap_and_the_environment() {
        for flag in ["--index-bundle-import", "--index-bundle-export"] {
            assert!(CliArgs::try_parse_from(["bitcoin-rs", flag, ""]).is_err());
            assert!(CliArgs::try_parse_from(["bitcoin-rs", flag, "  "]).is_err());
            assert!(CliArgs::try_parse_from(["bitcoin-rs", flag]).is_err());
        }
        for key in [
            "BITCOIN_RS_INDEX_BUNDLE_IMPORT",
            "BITCOIN_RS_INDEX_BUNDLE_EXPORT",
        ] {
            assert!(load(&["--txindex=true"], &[(key, "")]).is_err());
        }
    }

    #[test]
    fn bitcoin_conf_cannot_request_a_bundle() {
        let layers = parse_for_network(
            "
index-bundle-import=/srv/in
indexbundleexport=/srv/out
",
            Network::Regtest,
        )
        .expect("fixture parses");
        for layer in &layers {
            assert_eq!(layer.indexes.bundle_import, None);
            assert_eq!(layer.indexes.bundle_export, None);
        }
    }
}
