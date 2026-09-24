use std::ffi::OsString;

use anyhow::Result;
use bitcoin_rs_node::UserConfig;

/// Builds the environment layer from the process environment.
pub(crate) fn user_config_from_env(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Result<UserConfig> {
    let mut layer = UserConfig::default();
    for (key, value) in vars {
        let Some(key) = key.to_str() else {
            continue;
        };
        layer.apply_env(key, &value)?;
    }
    Ok(layer)
}
