//! Bitcoin Core `bitcoin.conf` as a process-input source.
//!
//! Reads the file, selects the network section against the already-resolved
//! network, and produces the global and selected-section [`UserConfig`]
//! layers, in precedence order. `node` never opens this file.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Network, UserConfig};

/// Parses `path` into user-config layers for `network`, lowest precedence first.
pub fn load_file(path: &Path, network: Network) -> Result<Vec<UserConfig>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bitcoin.conf {}", path.display()))?;
    Ok(parse_for_network(&text, network))
}

fn parse_for_network(text: &str, network: Network) -> Vec<UserConfig> {
    let mut global = UserConfig::default();
    let mut selected = UserConfig::default();
    let mut current_section_selected = None;

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
        match current_section_selected {
            None => apply_core_key(&mut global, key, value),
            Some(true) => apply_core_key(&mut selected, key, value),
            Some(false) => {}
        }
    }

    vec![global, selected]
}

/// Expands the option table into the `bitcoin.conf` key map: one arm per row
/// that names a Core key.
///
/// PRE: a row's `conf` column holds its Core key name.
/// POST: `apply_core_key` writes a recognized key into its row's slot.
/// INVARIANT: the file's key names and target slots come from the table, so a
/// key cannot drift from the option it sets. A Core key whose meaning has no
/// row stays in `apply_core_exception`.
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
        fn apply_core_key(layer: &mut UserConfig, key: &str, value: &str) {
            if apply_core_exception(layer, key, value) {
                return;
            }
            match key {
                $(
                    $( $fckey => CoreValue::apply(value, &mut layer.$fid), )?
                )*
                $(
                    $(
                        $( $gckey => CoreValue::apply(value, &mut layer.$gid.$rfield), )?
                    )*
                )*
                _ => {}
            }
        }
    };
}

bitcoin_rs_node::option_rows!(emit_core_conf);

/// Applies one `bitcoin.conf` value to an option-table slot.
///
/// PRE: `value` is the text after the key's equals sign.
/// POST: the slot holds the value, or holds nothing where a numeric or
/// boolean key carries no parseable value.
/// INVARIANT: each impl matches Bitcoin Core's reading of its key type: a
/// string or path is taken verbatim, a number is taken only when it parses,
/// and a boolean takes Core's truth words and false words.
trait CoreValue {
    fn apply(value: &str, slot: &mut Self);
}

impl CoreValue for Option<bool> {
    fn apply(value: &str, slot: &mut Self) {
        *slot = parse_core_bool(value);
    }
}

impl CoreValue for Option<u64> {
    fn apply(value: &str, slot: &mut Self) {
        if let Ok(number) = value.parse() {
            *slot = Some(number);
        }
    }
}

impl CoreValue for Option<String> {
    fn apply(value: &str, slot: &mut Self) {
        *slot = Some(value.to_owned());
    }
}

impl CoreValue for Option<PathBuf> {
    fn apply(value: &str, slot: &mut Self) {
        *slot = Some(PathBuf::from(value));
    }
}

/// Sets the one Core key that no table row can express: `listen` is a boolean
/// switch over the bind list, not an address, and only its false value is an
/// override. Returns whether it consumed `key`.
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
    let hash = line.find('#');
    let semicolon = line.find(';');
    match (hash, semicolon) {
        (Some(left), Some(right)) => &line[..left.min(right)],
        (Some(index), None) | (None, Some(index)) => &line[..index],
        (None, None) => line,
    }
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
        );
        let layer_refs: Vec<_> = layers.iter().collect();
        let config = resolve(&layer_refs).unwrap_or_else(|error| panic!("layer resolves: {error}"));
        assert_eq!(config.storage.prune_target_mb, 900);
    }

    /// Every Core key the option table names reaches the slot the table names.
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
        );
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

    /// A number the file states in a form Core cannot read sets nothing.
    #[test]
    fn an_unparseable_core_number_sets_nothing() {
        let layers = parse_for_network("dbcache=large\nrest=maybe\n", Network::Regtest);
        assert_eq!(layers[0].storage.dbcache_mb, None);
        assert_eq!(layers[0].rpc.rest, None);
    }
}

#[cfg(test)]
mod compat_tests {
    use super::load_file;
    use anyhow::Result;
    use bitcoin_rs_node::{Auth, Network, resolve};
    use std::fs;

    #[test]
    fn bitcoin_conf_core_keys_map_into_config() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let conf_path = temp.path().join("bitcoin.conf");
        fs::write(
            &conf_path,
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
        )?;

        let layer = load_file(&conf_path, Network::Mainnet)?;
        let layer_refs: Vec<_> = layer.iter().collect();
        let config = resolve(&layer_refs)?;

        assert_eq!(config.storage.prune_target_mb, 550);
        assert_auth(&config.rpc.auth, "foo", "bar");
        assert!(config.p2p.listen.is_empty());
        assert!(config.indexes.txindex);
        assert_eq!(config.storage.dbcache_mb, 768);
        Ok(())
    }

    #[test]
    fn bitcoin_conf_network_sections_override_globals_for_selected_network() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let conf_path = temp.path().join("bitcoin.conf");
        fs::write(
            &conf_path,
            r"
-prune=550
[regtest]
-prune=900
-rpcuser=regtest-user
-rpcpassword=regtest-pass
",
        )?;

        let layer = load_file(&conf_path, Network::Regtest)?;
        let layer_refs: Vec<_> = layer.iter().collect();
        let config = resolve(&layer_refs)?;

        assert_eq!(config.storage.prune_target_mb, 900);
        assert_auth(&config.rpc.auth, "regtest-user", "regtest-pass");
        Ok(())
    }

    #[test]
    fn bitcoin_conf_zmq_keys_are_not_promoted_into_node_config() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let conf_path = temp.path().join("bitcoin.conf");
        fs::write(
            &conf_path,
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
        )?;

        let layer = load_file(&conf_path, Network::Regtest)?;
        let layer_refs: Vec<_> = layer.iter().collect();
        let config = resolve(&layer_refs)?;

        assert!(config.notifications.zmq.is_empty());
        Ok(())
    }

    #[test]
    fn bitcoin_conf_assumevalid_is_not_mapped_to_height_only_setting() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let conf_path = temp.path().join("bitcoin.conf");
        fs::write(
            &conf_path,
            r"
assumevalid=0000000000000000000000000000000000000000000000000000000000000000
",
        )?;

        let layer = load_file(&conf_path, Network::Mainnet)?;
        let layer_refs: Vec<_> = layer.iter().collect();
        let config = resolve(&layer_refs)?;

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
            Auth::Cookie { .. } => panic!("expected basic auth"),
        }
    }
}
