use std::path::Path;

use anyhow::{Context as _, Result};

use crate::config::{Auth, Config, ConfigLayer};
use bitcoin_rs_primitives::Network;

/// Applies a Bitcoin Core `bitcoin.conf` file to `config`.
pub fn apply_file(config: &mut Config, path: &Path) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read bitcoin.conf {}", path.display()))?;
    let layer = parse_for_network(&text, config.network);
    layer.apply_to(config);
    Ok(())
}

fn parse_for_network(text: &str, network: Network) -> ConfigLayer {
    let mut global = ConfigLayer::default();
    let mut selected = ConfigLayer::default();
    let mut applies_to_selected = true;

    for raw_line in text.lines() {
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = parse_section(line) {
            applies_to_selected = section_matches_network(section, network);
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim().trim_start_matches('-');
        let value = raw_value.trim();
        if applies_to_selected {
            apply_key(&mut selected, key, value);
        } else {
            apply_key(&mut global, key, value);
        }
    }

    global.apply_from(&selected);
    global
}

fn apply_key(layer: &mut ConfigLayer, key: &str, value: &str) {
    match key {
        "prune" => {
            if let Ok(prune_target_mb) = value.parse() {
                layer.prune_target_mb = Some(prune_target_mb);
            }
        }
        "rpcuser" => layer.rpc_user = Some(value.to_owned()),
        "rpcpassword" => layer.rpc_password = Some(value.to_owned()),
        "rpccookiefile" => layer.rpc_cookie = Some(value.into()),
        "server" => {}
        "listen" => {
            if parse_core_bool(value).is_some_and(|listen| !listen) {
                layer.p2p_listen = Some(Vec::new());
            }
        }
        "txindex" => layer.txindex = parse_core_bool(value),
        "blockfilterindex" => layer.blockfilterindex = parse_core_bool(value),
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

trait ConfigLayerMerge {
    fn apply_from(&mut self, other: &Self);
}

impl ConfigLayerMerge for ConfigLayer {
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
        if other.electrum_bind.is_some() {
            self.electrum_bind = other.electrum_bind;
        }
        if other.electrum_tls_cert.is_some() {
            self.electrum_tls_cert.clone_from(&other.electrum_tls_cert);
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
        if other.utreexo_mode.is_some() {
            self.utreexo_mode = other.utreexo_mode;
        }
        if other.txindex.is_some() {
            self.txindex = other.txindex;
        }
        if other.blockfilterindex.is_some() {
            self.blockfilterindex = other.blockfilterindex;
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
