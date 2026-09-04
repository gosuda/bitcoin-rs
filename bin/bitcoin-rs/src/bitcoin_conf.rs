//! Bitcoin Core `bitcoin.conf` as a process-input source.
//!
//! Reads the file, selects the network section against the already-resolved
//! network, and produces one [`UserConfig`] layer. `node` never opens this
//! file.

use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Network, NodeConfig, UserConfig};

/// Loads node configuration from CLI, optional TOML, environment, and
/// optional `bitcoin.conf`.
pub fn load_node_config<I, T>(args: I) -> Result<NodeConfig>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = UserConfig::parse_from_or_exit(args);
    let env = UserConfig::from_process_env()?;
    let toml = cli
        .config_path()
        .map(UserConfig::load_toml_file)
        .transpose()?;
    let network = NodeConfig::network_from_layers(toml.as_ref(), &env, &cli);
    let bitcoin_conf = cli
        .bitcoin_conf_path()
        .map(|path| load_file(path, network))
        .transpose()?;
    NodeConfig::from_user_layers(toml.as_ref(), bitcoin_conf.as_ref(), Some(&env), &cli)
}

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
            None => global.apply_core_key(key, value),
            Some(true) => selected.apply_core_key(key, value),
            Some(false) => {}
        }
    }

    global.overlay(&selected);
    global
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
    use bitcoin_rs_node::{Network, NodeConfig, UserConfig};

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
        let config = NodeConfig::from_user_layers(None, Some(&layer), None, &UserConfig::default())
            .expect("layer resolves");
        assert_eq!(config.prune_target_mb, 900);
    }
}
