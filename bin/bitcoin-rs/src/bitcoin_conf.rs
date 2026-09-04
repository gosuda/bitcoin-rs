//! Bitcoin Core `bitcoin.conf` as a process-input source.
//!
//! Reads the file, selects the network section against the already-resolved
//! network, and produces one [`UserConfig`] layer. `node` never opens this
//! file.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Network, UserConfig};

/// Parses `path` into one user-config layer for `network`.
pub fn load_file(path: &Path, network: Network) -> Result<UserConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bitcoin.conf {}", path.display()))?;
    Ok(parse_for_network(&text, network))
}

fn parse_for_network(text: &str, network: Network) -> UserConfig {
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

    global.overlay(&selected);
    global
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
        let layer = parse_for_network(
            "
-prune=550
[regtest]
-prune=900
-rpcuser=regtest-user
-rpcpassword=regtest-pass
",
            Network::Regtest,
        );
        let config = resolve(&[&layer]).unwrap_or_else(|error| panic!("layer resolves: {error}"));
        assert_eq!(config.storage.prune_target_mb, 900);
    }
}
