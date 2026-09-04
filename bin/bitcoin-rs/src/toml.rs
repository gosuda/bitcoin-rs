use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{
    ChainstateJournalOverrides, IndexOverrides, NetworkSelection, NotificationConfig,
    ObservabilityOverrides, P2pOverrides, RpcOverrides, ScriptIndexMode, StorageOverrides,
    UserConfig, ValidationOverrides,
};
use bitcoin_rs_storage::StorageBackend;
use serde::Deserialize;

use crate::cli::{parse_connect_endpoint, parse_p2p_magic};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TomlFile {
    network: Option<NetworkSelection>,
    p2p_magic: Option<String>,
    data_dir: Option<PathBuf>,
    storage_backend: Option<String>,
    rpc_bind: Option<SocketAddr>,
    rest: Option<bool>,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    rpc_cookie: Option<PathBuf>,
    script_index: Option<String>,
    p2p_listen: Option<Vec<SocketAddr>>,
    dns_seeds_enabled: Option<bool>,
    connect: Option<Vec<String>>,
    prune_target_mb: Option<u64>,
    txindex: Option<bool>,
    dbcache_mb: Option<u64>,
    log_level: Option<String>,
    metrics_bind: Option<SocketAddr>,
    notifications: Option<NotificationConfig>,
    chainstate_journal: Option<ChainstateJournalOverrides>,
    assume_valid_height: Option<u32>,
}

pub(crate) fn user_config_from_path(path: &Path) -> Result<UserConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    let file: TomlFile = toml::from_str(&text)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
    file.into_user_config()
        .with_context(|| format!("failed to interpret TOML config {}", path.display()))
}

impl TomlFile {
    fn into_user_config(self) -> Result<UserConfig> {
        let connect = self
            .connect
            .map(|peers| {
                peers
                    .into_iter()
                    .map(|peer| parse_connect_endpoint(&peer).map_err(anyhow::Error::msg))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        Ok(UserConfig {
            network: self.network,
            data_dir: self.data_dir,
            storage: StorageOverrides {
                backend: self
                    .storage_backend
                    .as_deref()
                    .map(str::parse::<StorageBackend>)
                    .transpose()
                    .map_err(anyhow::Error::msg)?,
                dbcache_mb: self.dbcache_mb,
                prune_target_mb: self.prune_target_mb,
            },
            p2p: P2pOverrides {
                magic: self.p2p_magic.as_deref().map(parse_p2p_magic).transpose()?,
                listen: self.p2p_listen,
                dns_seeds: self.dns_seeds_enabled,
                connect,
            },
            rpc: RpcOverrides {
                bind: self.rpc_bind,
                rest: self.rest,
                user: self.rpc_user,
                password: self.rpc_password,
                cookie: self.rpc_cookie,
            },
            indexes: IndexOverrides {
                txindex: self.txindex,
                script_index: self
                    .script_index
                    .as_deref()
                    .map(|value| {
                        ScriptIndexMode::parse(value).ok_or_else(|| {
                            anyhow::anyhow!(
                                "invalid scriptindex value `{value}`: expected `utxo`, `full`, or a boolean"
                            )
                        })
                    })
                    .transpose()?,
            },
            observability: ObservabilityOverrides {
                log_level: self.log_level,
                metrics_bind: self.metrics_bind,
            },
            notifications: self.notifications,
            chainstate_journal: self.chainstate_journal,
            validation: ValidationOverrides {
                assume_valid_height: self.assume_valid_height,
            },
        })
    }
}
