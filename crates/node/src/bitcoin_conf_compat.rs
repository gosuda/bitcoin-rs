use std::path::Path;

use anyhow::{Context as _, Result};

use crate::config::{Auth, NodeConfig, UserConfig};
use bitcoin_rs_primitives::Network;

/// Applies a Bitcoin Core `bitcoin.conf` file to `config`.
pub fn apply_file(config: &mut NodeConfig, path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bitcoin.conf {}", path.display()))?;
    let layer = parse_for_network(&text, config.network);
    layer.apply_to(config)?;
    Ok(())
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
            None => apply_key(&mut global, key, value),
            Some(true) => apply_key(&mut selected, key, value),
            Some(false) => {}
        }
    }

    global.apply_from(&selected);
    global
}

fn apply_key(layer: &mut UserConfig, key: &str, value: &str) {
    match key {
        "prune" => {
            if let Ok(prune_target_mb) = value.parse() {
                layer.prune_target_mb = Some(prune_target_mb);
            }
        }
        "rpcuser" => layer.rpc_user = Some(value.to_owned()),
        "rpcpassword" => layer.rpc_password = Some(value.to_owned()),
        "rpccookiefile" => layer.rpc_cookie = Some(value.into()),
        "rest" => layer.rest = parse_core_bool(value),
        "listen" if parse_core_bool(value).is_some_and(|listen| !listen) => {
            layer.p2p_listen = Some(Vec::new());
        }
        "txindex" => layer.txindex = parse_core_bool(value),
        "dbcache" => {
            if let Ok(dbcache_mb) = value.parse() {
                layer.dbcache_mb = Some(dbcache_mb);
            }
        }
        _ => {}
    }
    if layer.rpc_user.is_some() || layer.rpc_password.is_some() {
        let user = layer
            .rpc_user
            .clone()
            .unwrap_or_else(|| "bitcoin-rs".to_owned());
        let password = layer.rpc_password.clone().unwrap_or_default();
        layer.rpc_auth = Some(Auth::basic(user, password));
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

trait UserConfigMerge {
    fn apply_from(&mut self, other: &Self);
}

impl UserConfigMerge for UserConfig {
    fn apply_from(&mut self, other: &Self) {
        if other.network.is_some() {
            self.network = other.network;
        }
        if other.data_dir.is_some() {
            self.data_dir.clone_from(&other.data_dir);
        }
        if other.storage_backend.is_some() {
            self.storage_backend.clone_from(&other.storage_backend);
        }
        if other.rpc_bind.is_some() {
            self.rpc_bind = other.rpc_bind;
        }
        if other.rest.is_some() {
            self.rest = other.rest;
        }
        if other.rpc_auth.is_some() {
            self.rpc_auth.clone_from(&other.rpc_auth);
        }
        if other.rpc_user.is_some() {
            self.rpc_user.clone_from(&other.rpc_user);
        }
        if other.rpc_password.is_some() {
            self.rpc_password.clone_from(&other.rpc_password);
        }
        if other.rpc_cookie.is_some() {
            self.rpc_cookie.clone_from(&other.rpc_cookie);
        }
        // An unparseable value is preserved verbatim so the merge stays
        // infallible; `NodeConfig::apply_layer` rejects it at the layer boundary
        // where an error can be reported with the key it came from.
        if other.script_index.is_some() {
            self.script_index.clone_from(&other.script_index);
        }
        if other.p2p_listen.is_some() {
            self.p2p_listen.clone_from(&other.p2p_listen);
        }
        if other.dns_seeds_enabled.is_some() {
            self.dns_seeds_enabled = other.dns_seeds_enabled;
        }
        if other.prune_target_mb.is_some() {
            self.prune_target_mb = other.prune_target_mb;
        }
        if other.txindex.is_some() {
            self.txindex = other.txindex;
        }
        if other.dbcache_mb.is_some() {
            self.dbcache_mb = other.dbcache_mb;
        }
        if other.log_level.is_some() {
            self.log_level.clone_from(&other.log_level);
        }
        if other.metrics_bind.is_some() {
            self.metrics_bind = other.metrics_bind;
        }
    }
}
