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

fn apply_core_key(layer: &mut UserConfig, key: &str, value: &str) {
    match key {
        "prune" => {
            if let Ok(prune_target_mb) = value.parse() {
                layer.storage.prune_target_mb = Some(prune_target_mb);
            }
        }
        "rpcuser" => layer.rpc.user = Some(value.to_owned()),
        "rpcpassword" => layer.rpc.password = Some(value.to_owned()),
        "rpccookiefile" => layer.rpc.cookie = Some(PathBuf::from(value)),
        "rest" => layer.rpc.rest = parse_core_bool(value),
        "listen" if parse_core_bool(value).is_some_and(|listen| !listen) => {
            layer.p2p.listen = Some(Vec::new());
        }
        "txindex" => layer.indexes.txindex = parse_core_bool(value),
        "dbcache" => {
            if let Ok(dbcache_mb) = value.parse() {
                layer.storage.dbcache_mb = Some(dbcache_mb);
            }
        }
        _ => {}
    }
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
