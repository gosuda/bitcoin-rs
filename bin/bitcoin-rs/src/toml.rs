use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin_rs_node::UserConfig;

/// Resolves the TOML layer from a configuration file.
pub(crate) fn user_config_from_path(path: &Path) -> Result<UserConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse TOML config {}", path.display()))
}
