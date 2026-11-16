use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bitcoin_rs_execution::ValidationMode;
use bitcoin_rs_node::options::{
    PoolOverrides, parse_connect_endpoint, parse_network, parse_p2p_magic, parse_script_index,
    parse_storage_backend, parse_validation_engine, parse_validation_mode,
};
use bitcoin_rs_node::{
    IndexOverrides, MiningOverrides, Network, NetworkSelection, NotificationConfig,
    ObservabilityOverrides, P2pOverrides, RpcOverrides, ScriptIndexMode, StorageOverrides,
    UserConfig, ValidationEngine, ValidationOverrides,
};
use bitcoin_rs_storage::StorageBackend;
use clap::Parser;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BinError {
    #[error(transparent)]
    Config(#[from] bitcoin_rs_node::ConfigError),
    #[error(transparent)]
    Run(#[from] bitcoin_rs_node::RunError),
    #[error(transparent)]
    OfflineImport(#[from] bitcoin_rs_node::OfflineImportError),
    #[error(transparent)]
    NodeOpen(#[from] bitcoin_rs_node::NodeOpenError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("failed to read TOML config {}", .path.display())]
    ReadTomlConfig {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TOML config {}", .path.display())]
    ParseTomlConfig {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to read bitcoin.conf {}", .path.display())]
    ReadBitcoinConf {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid bitcoin.conf: {details}")]
    InvalidBitcoinConf { details: String },
    #[error("--corpus, --manifest, and --state must be given together")]
    IncompleteOfflineImportArguments,
}

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
            /// Print the node version and license notice, then exit.
            #[arg(long)]
            pub(crate) version: bool,
            #[arg(long, help = "Core-framed corpus archive to replay offline")]
            pub(crate) corpus: Option<PathBuf>,
            #[arg(long, help = "Corpus manifest pinning the archive and stop height")]
            pub(crate) manifest: Option<PathBuf>,
            #[arg(long, help = "Directory for offline-import certification state")]
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
) -> Result<bitcoin_rs_node::NodeConfig, BinError> {
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
    Ok(bitcoin_rs_node::resolve(&layer_refs)?)
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

fn user_config_from_env(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<UserConfig, BinError> {
    let mut layer = UserConfig::default();
    for (key, value) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        layer.apply_env(key, &value)?;
    }
    Ok(layer)
}

fn user_config_from_toml(path: &Path) -> Result<UserConfig, BinError> {
    let text = std::fs::read_to_string(path).map_err(|source| BinError::ReadTomlConfig {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| BinError::ParseTomlConfig {
        path: path.to_path_buf(),
        source,
    })
}

fn user_config_from_bitcoin_conf(
    path: &Path,
    network: Network,
) -> Result<[UserConfig; 2], BinError> {
    let text = std::fs::read_to_string(path).map_err(|source| BinError::ReadBitcoinConf {
        path: path.to_path_buf(),
        source,
    })?;
    parse_for_network(&text, network)
}

fn trim_conf_space(value: &str) -> &str {
    value.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

fn parse_for_network(text: &str, network: Network) -> Result<[UserConfig; 2], BinError> {
    let mut global = UserConfig::default();
    let mut selected = UserConfig::default();
    let mut current_section_selected = None;
    let mut errors = Vec::new();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = trim_conf_space(strip_inline_comment(raw_line));
        if line.is_empty() {
            continue;
        }
        if let Some(section) = parse_section(line) {
            current_section_selected = Some(section_matches_network(section, network));
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            errors.push(format!(
                "line {line_number}: {line:?} is not a key=value entry"
            ));
            continue;
        };
        let key = trim_conf_space(raw_key);
        if key.starts_with('-') {
            errors.push(format!(
                "parse error on line {line_number}: {line}, options in configuration file must be specified without leading -"
            ));
            continue;
        }
        if key == "rpcpassword" && raw_line.contains('#') {
            errors.push(format!(
                "line {line_number}: rpcpassword contains '#', which is ambiguous"
            ));
            continue;
        }
        let value = trim_conf_space(raw_value);
        let outcome = match current_section_selected {
            None => apply_core_key(&mut global, key, value),
            Some(true) => apply_core_key(&mut selected, key, value),
            Some(false) => Ok(()),
        };
        if let Err(error) = outcome {
            errors.push(format!("line {line_number}: {error}"));
        }
    }
    if errors.is_empty() {
        Ok([global, selected])
    } else {
        Err(BinError::InvalidBitcoinConf {
            details: errors.join("; "),
        })
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
            if let Some(stripped) = key.strip_prefix("no") {
                if apply_core_negation(layer, key, stripped, value)? {
                    return Ok(());
                }
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

        fn apply_core_negation(
            layer: &mut UserConfig,
            key: &str,
            stripped: &str,
            value: &str,
        ) -> Result<bool, String> {
            let stored = !parse_core_bool(value);
            match stripped {
                $(
                    $( $fckey => {
                        CoreValue::negate(key, stored, &mut layer.$fid)?;
                        Ok(true)
                    }, )?
                )*
                $(
                    $(
                        $( $gckey => {
                            CoreValue::negate(key, stored, &mut layer.$gid.$rfield)?;
                            Ok(true)
                        }, )?
                    )*
                )*
                _ => Ok(false),
            }
        }
    };
}

bitcoin_rs_node::option_rows!(emit_core_conf);

trait CoreValue {
    fn apply(key: &str, value: &str, slot: &mut Self) -> Result<(), String>;
    fn negate(key: &str, stored: bool, slot: &mut Self) -> Result<(), String>;
}

impl CoreValue for Option<bool> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = Some(parse_core_bool(value));
        Ok(())
    }

    fn negate(_key: &str, stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(stored);
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

    fn negate(_key: &str, stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(u64::from(stored));
        Ok(())
    }
}

impl CoreValue for Option<usize> {
    fn apply(key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = Some(
            value
                .parse()
                .map_err(|_| format!("{key}={value:?} is not a valid nonnegative entry limit"))?,
        );
        Ok(())
    }

    fn negate(_key: &str, stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(usize::from(stored));
        Ok(())
    }
}

impl CoreValue for Option<String> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = Some(value.to_owned());
        Ok(())
    }

    fn negate(_key: &str, stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(if stored { "1" } else { "0" }.to_owned());
        Ok(())
    }
}

impl CoreValue for Option<Vec<String>> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        let entries = slot.get_or_insert_with(Vec::new);
        entries.push(value.to_owned());
        Ok(())
    }

    fn negate(_key: &str, _stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(Vec::new());
        Ok(())
    }
}

impl CoreValue for Option<PathBuf> {
    fn apply(_key: &str, value: &str, slot: &mut Self) -> Result<(), String> {
        *slot = Some(PathBuf::from(value));
        Ok(())
    }

    fn negate(_key: &str, stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = stored.then(|| PathBuf::from("1"));
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

    fn negate(key: &str, stored: bool, slot: &mut Self) -> Result<(), String> {
        if stored {
            return Self::apply(key, "1", slot);
        }
        *slot = None;
        Ok(())
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

    fn negate(_key: &str, _stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(Vec::new());
        Ok(())
    }
}

impl CoreValue for Option<Vec<bitcoin_rs_wire::PeerNetwork>> {
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

    fn negate(_key: &str, _stored: bool, slot: &mut Self) -> Result<(), String> {
        *slot = Some(Vec::new());
        Ok(())
    }
}

fn apply_core_exception(layer: &mut UserConfig, key: &str, value: &str) -> bool {
    let (name, negated) = match key.strip_prefix("no") {
        Some(rest) => (rest, true),
        None => (key, false),
    };
    if name != "listen" {
        return false;
    }
    let clears = if negated {
        parse_core_bool(value)
    } else {
        !parse_core_bool(value)
    };
    if clears {
        layer.p2p.listen = Some(Vec::new());
    }
    true
}

fn parse_core_bool(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    locale_independent_atoi(value) != 0
}

fn locale_independent_atoi(value: &str) -> i32 {
    let trimmed =
        value.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}'));
    let unsigned = match trimmed.strip_prefix('+') {
        Some(rest) if rest.starts_with('-') => return 0,
        Some(rest) => rest,
        None => trimmed,
    };
    let (negative, digits) = match unsigned.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, unsigned),
    };
    let digits = &digits[..digits
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(digits.len())];
    if digits.is_empty() {
        return 0;
    }
    let limit = i64::from(i32::MAX) + 1;
    let mut magnitude: i64 = 0;
    for byte in digits.bytes() {
        magnitude = (magnitude * 10 + i64::from(byte - b'0')).min(limit);
        if magnitude == limit {
            break;
        }
    }
    let signed = if negative {
        -magnitude
    } else {
        magnitude.min(i64::from(i32::MAX))
    };
    i32::try_from(signed).unwrap_or(if negative { i32::MIN } else { i32::MAX })
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
    &line[..line.find('#').unwrap_or(line.len())]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::parse_for_network;
    use bitcoin_rs_node::Network;

    #[test]
    fn every_table_core_key_reaches_its_slot() {
        let layers = parse_for_network(
            "
dbcache=450
prune=550
rest=1
txindex=1
rpcuser=someuser
rpcpassword=somepass
rpccookiefile=/tmp/.cookie
listen=0
uacomment=testnode0
uacomment=foo
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
        // Repeated conf keys accumulate, mirroring Core's multi-value
        // `-uacomment`.
        assert_eq!(
            global.p2p.ua_comments,
            Some(vec!["testnode0".to_owned(), "foo".to_owned()])
        );
    }

    #[test]
    fn an_unparseable_number_keeps_the_default_and_a_word_bool_is_false() {
        let layers = parse_for_network("dbcache=large\nrest=maybe\n", Network::Regtest)
            .unwrap_or_else(|error| panic!("non-routing keys stay lenient: {error}"));
        assert_eq!(layers[0].storage.dbcache_mb, None);
        assert_eq!(
            layers[0].rpc.rest,
            Some(false),
            "Core's InterpretBool answers atoi, so a non-integer word is false"
        );
    }

    #[test]
    fn negated_core_keys_store_core_reading_of_the_negated_setting() {
        let layers = parse_for_network(
            "
nolisten=1
nodnsseed=1
nodbcache=1
noprune=1
nouacomment=1
noproxy=1
noonion=1
noi2psam=1
notorcontrol=1
noi2pacceptincoming=1
noproxyrandomize=1
noonlynet=1
nov2transport=1
norest=1
norpcuser=1
norpcpassword=1
norpccookiefile=1
noscripthash-limit=1
notxindex=1
noblockfilterindex=1
nomaxmempool=1
",
            Network::Regtest,
        )
        .unwrap_or_else(|error| panic!("negations parse: {error}"));
        let layer = &layers[0];
        assert_eq!(layer.p2p.listen, Some(Vec::new()));
        assert_eq!(layer.p2p.dns_seeds, Some(false));
        assert_eq!(layer.storage.dbcache_mb, Some(0));
        assert_eq!(layer.storage.prune_target_mb, Some(0));
        assert_eq!(layer.p2p.ua_comments, Some(Vec::new()));
        assert_eq!(layer.p2p.proxy, None);
        assert_eq!(layer.p2p.onion_proxy, None);
        assert_eq!(layer.p2p.i2p_sam, None);
        assert_eq!(layer.p2p.tor_control, None);
        assert_eq!(layer.p2p.i2p_accept, Some(false));
        assert_eq!(layer.p2p.proxy_randomize_credentials, Some(false));
        assert_eq!(layer.p2p.onlynet, Some(Vec::new()));
        assert_eq!(layer.p2p.v2_transport, Some(false));
        assert_eq!(layer.rpc.rest, Some(false));
        assert_eq!(layer.rpc.user.as_deref(), Some("0"));
        assert_eq!(layer.rpc.password.as_deref(), Some("0"));
        assert_eq!(layer.rpc.cookie, None);
        assert_eq!(layer.indexes.scripthash_limit, Some(0));
        assert_eq!(layer.indexes.txindex, Some(false));
        assert_eq!(layer.indexes.blockfilterindex, Some(false));
    }

    #[test]
    fn double_negatives_store_core_reading_of_true() {
        let layers = parse_for_network(
            "
nolisten=0
nodnsseed=0
nodbcache=0
nouacomment=0
norpcuser=0
norpccookiefile=0
noscripthash-limit=0
",
            Network::Regtest,
        )
        .unwrap_or_else(|error| panic!("double negatives parse: {error}"));
        let layer = &layers[0];
        assert_eq!(layer.p2p.listen, None);
        assert_eq!(layer.p2p.dns_seeds, Some(true));
        assert_eq!(layer.storage.dbcache_mb, Some(1));
        assert_eq!(layer.p2p.ua_comments, Some(Vec::new()));
        assert_eq!(layer.rpc.user.as_deref(), Some("1"));
        assert_eq!(layer.rpc.cookie.as_deref(), Some(Path::new("1")));
        assert_eq!(layer.indexes.scripthash_limit, Some(1));
    }

    #[test]
    fn a_double_negative_on_an_address_key_names_the_key_as_invalid() {
        let error = match parse_for_network("noonion=0\n", Network::Regtest) {
            Ok(_) => panic!("the stored word 1 is not an address"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("noonion"),
            "the refusal names the negated key: {error}"
        );
    }

    #[test]
    fn conf_trimming_uses_core_s_ascii_set_only() {
        let unknown_key = parse_for_network("\u{00a0}dnsseed=1\n", Network::Regtest)
            .unwrap_or_else(|error| panic!("fixture parses: {error}"));
        assert_eq!(
            unknown_key[0].p2p.dns_seeds, None,
            "Core trims a key with the space, tab, CR, and LF set only (config.cpp:45-57), so the non-breaking space is part of the key"
        );
        let padded_value = parse_for_network("dnsseed=\u{00a0}1\n", Network::Regtest)
            .unwrap_or_else(|error| panic!("fixture parses: {error}"));
        assert_eq!(
            padded_value[0].p2p.dns_seeds,
            Some(false),
            "Core keeps a non-breaking space in the value, and InterpretBool's atoi answer is 0 (config.cpp:57, args.cpp:57-62)"
        );
    }
}

#[cfg(test)]
mod compat_tests {
    use super::user_config_from_bitcoin_conf;
    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Bin(#[from] super::BinError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Config(#[from] bitcoin_rs_node::ConfigError),
    }

    use bitcoin_rs_node::{Auth, Network, NodeConfig, resolve};
    use std::fs;
    use std::net::SocketAddr;

    fn load_conf(text: &str, network: Network) -> Result<NodeConfig, TestError> {
        let temp = tempfile::tempdir()?;
        let conf_path = temp.path().join("bitcoin.conf");
        fs::write(&conf_path, text)?;
        let layers = user_config_from_bitcoin_conf(&conf_path, network)?;
        let layer_refs: Vec<_> = layers.iter().collect();
        Ok(resolve(&layer_refs)?)
    }

    #[test]
    fn bitcoin_conf_core_keys_map_into_config() -> Result<(), TestError> {
        let config = load_conf(
            r"
# Global Core options
prune=550
rpcuser=foo
rpcpassword=bar
server=1
listen=0
dbcache=768
",
            Network::Mainnet,
        )?;

        assert_eq!(config.storage.prune_target_mb, 550);
        assert_auth(&config.rpc.auth, "foo", "bar");
        assert_eq!(config.p2p.listen, []);
        assert_eq!(config.storage.dbcache_mb, 768);

        let indexed = load_conf("txindex=1\n", Network::Mainnet)?;
        assert!(indexed.indexes.txindex);

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
                bitcoin_rs_wire::PeerNetwork::Onion,
                bitcoin_rs_wire::PeerNetwork::I2p
            ]
        );
        Ok(())
    }

    #[test]
    fn bitcoin_conf_refuses_a_leading_dash_like_core() {
        let error = match load_conf("-prune=550\n", Network::Mainnet) {
            Ok(_) => panic!("a leading dash must be refused like Core"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                TestError::Bin(super::BinError::InvalidBitcoinConf { .. })
            ),
            "a leading dash must surface as a conf parse refusal: {error}"
        );
    }

    #[test]
    fn bitcoin_conf_bool_values_follow_core_interpret_bool() -> Result<(), TestError> {
        let empty_is_true = load_conf("dnsseed=\n", Network::Mainnet)?;
        assert!(
            empty_is_true.p2p.dns_seeds_enabled,
            "Core treats an empty bool value as true"
        );
        let nonzero_is_true = load_conf("dnsseed=2\n", Network::Mainnet)?;
        assert!(nonzero_is_true.p2p.dns_seeds_enabled);
        let minus_one_is_true = load_conf("dnsseed=-1\n", Network::Mainnet)?;
        assert!(minus_one_is_true.p2p.dns_seeds_enabled);
        let zero_is_false = load_conf("dnsseed=0\n", Network::Mainnet)?;
        assert!(!zero_is_false.p2p.dns_seeds_enabled);
        let word_is_false = load_conf("dnsseed=true\n", Network::Mainnet)?;
        assert!(
            !word_is_false.p2p.dns_seeds_enabled,
            "Core's InterpretBool answers atoi, so a non-integer word is false"
        );
        let leading_plus_is_true = load_conf("dnsseed=+1\n", Network::Mainnet)?;
        assert!(
            leading_plus_is_true.p2p.dns_seeds_enabled,
            "Core strips one leading '+' before from_chars (strencodings.h LocaleIndependentAtoi)"
        );
        let plus_minus_is_false = load_conf("dnsseed=+-1\n", Network::Mainnet)?;
        assert!(
            !plus_minus_is_false.p2p.dns_seeds_enabled,
            "Core answers 0 for a '+-' prefix"
        );
        let double_minus_is_false = load_conf("dnsseed=--1\n", Network::Mainnet)?;
        assert!(
            !double_minus_is_false.p2p.dns_seeds_enabled,
            "Core's from_chars rejects a second minus sign"
        );
        let minus_plus_is_false = load_conf("dnsseed=-+1\n", Network::Mainnet)?;
        assert!(
            !minus_plus_is_false.p2p.dns_seeds_enabled,
            "Core's from_chars rejects a sign after the minus sign"
        );
        let numeric_prefix_is_true = load_conf("dnsseed=1abc\n", Network::Mainnet)?;
        assert!(
            numeric_prefix_is_true.p2p.dns_seeds_enabled,
            "Core's from_chars parses the numeric prefix, so '1abc' is 1"
        );
        let overflow_is_true = load_conf("dnsseed=2147483648\n", Network::Mainnet)?;
        assert!(
            overflow_is_true.p2p.dns_seeds_enabled,
            "Core saturates out-of-range atoi input at i32::MAX, which is nonzero"
        );
        let underflow_is_true = load_conf("dnsseed=-2147483649\n", Network::Mainnet)?;
        assert!(
            underflow_is_true.p2p.dns_seeds_enabled,
            "Core saturates out-of-range atoi input at i32::MIN, which is nonzero"
        );
        let wide_overflow_is_true = load_conf("dnsseed=99999999999999999999\n", Network::Mainnet)?;
        assert!(
            wide_overflow_is_true.p2p.dns_seeds_enabled,
            "Core saturates atoi input wider than i64 at i32::MAX, which is nonzero"
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
    fn bitcoin_conf_keeps_semicolons_inside_values() -> Result<(), TestError> {
        let config = load_conf(
            r"
rpcuser=ab;cd
rpcpassword=xy;z
",
            Network::Mainnet,
        )?;

        assert_auth(&config.rpc.auth, "ab;cd", "xy;z");
        Ok(())
    }

    #[test]
    fn bitcoin_conf_refuses_a_hash_inside_rpcpassword() {
        let error = match load_conf("rpcpassword=ab#cd\n", Network::Mainnet) {
            Ok(_) => panic!("an ambiguous rpcpassword must not be truncated silently"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("rpcpassword"),
            "the refusal names the key: {error}"
        );
    }

    #[test]
    fn bitcoin_conf_refuses_a_line_without_an_equals_sign() {
        let error = match load_conf("prune 550\n", Network::Mainnet) {
            Ok(_) => panic!("a line without = must not be dropped silently"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("prune 550"),
            "the refusal quotes the malformed line: {error}"
        );
    }

    #[test]
    fn bitcoin_conf_network_sections_override_globals_for_selected_network() -> Result<(), TestError>
    {
        let config = load_conf(
            r"
prune=550
[regtest]
prune=900
rpcuser=regtest-user
rpcpassword=regtest-pass
",
            Network::Regtest,
        )?;

        assert_eq!(config.storage.prune_target_mb, 900);
        assert_auth(&config.rpc.auth, "regtest-user", "regtest-pass");
        Ok(())
    }

    #[test]
    fn bitcoin_conf_zmq_keys_are_not_promoted_into_node_config() -> Result<(), TestError> {
        let config = load_conf(
            r"
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashblock=tcp://127.0.0.1:28333
zmqpubhashblockhwm=5
[regtest]
zmqpubrawtx=tcp://127.0.0.1:28334
zmqpubrawtxhwm=6
zmqpubsequence=tcp://127.0.0.1:28335
zmqpubsequencehwm=7
",
            Network::Regtest,
        )?;

        assert_eq!(config.notifications.zmq, []);
        Ok(())
    }

    #[test]
    fn bitcoin_conf_assumevalid_is_not_mapped_to_height_only_setting() -> Result<(), TestError> {
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

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Bin(#[from] super::BinError),
        #[error(transparent)]
        Clap(#[from] clap::error::Error),
    }

    use bitcoin_rs_node::{Network, NodeConfig};
    use clap::Parser as _;

    use super::{CliArgs, parse_for_network, resolve};

    fn load(args: &[&str], vars: &[(&str, &str)]) -> Result<NodeConfig, TestError> {
        let argv = std::iter::once("bitcoin-rs").chain(args.iter().copied());
        let cli = CliArgs::try_parse_from(argv)?;
        Ok(resolve(
            cli,
            vars.iter()
                .map(|(key, value)| (OsString::from(*key), OsString::from(*value))),
        )?)
    }

    fn refusal(args: &[&str], vars: &[(&str, &str)]) -> String {
        match load(args, vars) {
            Ok(_) => panic!("configuration must be refused"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn relay_switches_are_bare_cli_flags_and_the_command_line_beats_environment()
    -> Result<(), TestError> {
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
    fn index_bundle_directories_resolve_from_the_command_line_and_stay_exclusive()
    -> Result<(), TestError> {
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

    #[test]
    fn numeric_flags_stop_at_their_declared_width() {
        for (flag, widest) in [
            ("--overlay-port", "65535"),
            ("--pool-fee-bps", "65535"),
            ("--assume-valid-height", "4294967295"),
            ("--mempool-snapshot-max-mb", "18446744073709551615"),
        ] {
            assert!(
                CliArgs::try_parse_from(["bitcoin-rs", flag, widest]).is_ok(),
                "{flag} accepts its widest value"
            );
            let mut over = widest.to_owned();
            over.push('0');
            assert!(
                CliArgs::try_parse_from(["bitcoin-rs", flag, &over]).is_err(),
                "{flag} refuses a value one digit past its width"
            );
            assert!(
                CliArgs::try_parse_from(["bitcoin-rs", flag, "-1"]).is_err(),
                "{flag} refuses a negative value"
            );
        }
    }
}
