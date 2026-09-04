use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, bail, ensure};
use bitcoin_rs_node::{
    IndexOverrides, NetworkSelection, ObservabilityOverrides, P2pOverrides, RpcOverrides,
    ScriptIndexMode, StorageOverrides, UserConfig, ValidationOverrides,
};
use bitcoin_rs_storage::StorageBackend;
use clap::Parser;

#[derive(Clone, Debug, Parser)]
#[command(name = "bitcoin-rs", about = "Run a bitcoin-rs node")]
pub(crate) struct CliArgs {
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long, value_parser = parse_network)]
    pub(crate) network: Option<NetworkSelection>,
    #[arg(long = "p2p-magic", value_parser = parse_p2p_magic)]
    pub(crate) p2p_magic: Option<[u8; 4]>,
    #[arg(long = "data-dir")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(long = "storage-backend", value_parser = parse_storage_backend)]
    pub(crate) storage_backend: Option<StorageBackend>,
    #[arg(long = "rpc-bind")]
    pub(crate) rpc_bind: Option<SocketAddr>,
    #[arg(long)]
    pub(crate) rest: Option<bool>,
    #[arg(long = "rpc-user")]
    pub(crate) rpc_user: Option<String>,
    #[arg(long = "rpc-password")]
    pub(crate) rpc_password: Option<String>,
    #[arg(long = "rpc-cookie")]
    pub(crate) rpc_cookie: Option<PathBuf>,
    #[arg(
        long = "scriptindex",
        visible_alias = "script-index",
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = parse_script_index
    )]
    pub(crate) script_index: Option<ScriptIndexMode>,
    #[arg(long = "p2p-listen", value_delimiter = ',')]
    pub(crate) p2p_listen: Option<Vec<SocketAddr>>,
    #[arg(long = "dns-seeds-enabled")]
    pub(crate) dns_seeds_enabled: Option<bool>,
    #[arg(long = "connect", value_delimiter = ',', value_parser = parse_connect_endpoint)]
    pub(crate) connect: Option<Vec<String>>,
    #[arg(long = "prune-target-mb")]
    pub(crate) prune_target_mb: Option<u64>,
    #[arg(long)]
    pub(crate) txindex: Option<bool>,
    #[arg(long = "dbcache-mb")]
    pub(crate) dbcache_mb: Option<u64>,
    #[arg(long = "log-level")]
    pub(crate) log_level: Option<String>,
    #[arg(long = "metrics-bind")]
    pub(crate) metrics_bind: Option<SocketAddr>,
    #[arg(long = "assume-valid-height")]
    pub(crate) assume_valid_height: Option<u32>,
}

impl CliArgs {
    pub(crate) fn into_user_config(self) -> UserConfig {
        UserConfig {
            network: self.network,
            data_dir: self.data_dir,
            storage: StorageOverrides {
                backend: self.storage_backend,
                dbcache_mb: self.dbcache_mb,
                prune_target_mb: self.prune_target_mb,
            },
            p2p: P2pOverrides {
                magic: self.p2p_magic,
                listen: self.p2p_listen,
                dns_seeds: self.dns_seeds_enabled,
                connect: self.connect,
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
                script_index: self.script_index,
            },
            observability: ObservabilityOverrides {
                log_level: self.log_level,
                metrics_bind: self.metrics_bind,
            },
            notifications: None,
            chainstate_journal: None,
            validation: ValidationOverrides {
                assume_valid_height: self.assume_valid_height,
            },
        }
    }
}

fn parse_network(value: &str) -> std::result::Result<NetworkSelection, String> {
    NetworkSelection::from_str(value)
}

fn parse_storage_backend(value: &str) -> std::result::Result<StorageBackend, String> {
    StorageBackend::from_str(value)
}

fn parse_script_index(value: &str) -> std::result::Result<ScriptIndexMode, String> {
    ScriptIndexMode::parse(value).ok_or_else(|| {
        format!("invalid scriptindex value `{value}`: expected `utxo`, `full`, or a boolean")
    })
}

pub(crate) fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}

pub(crate) fn parse_p2p_magic(value: &str) -> Result<[u8; 4]> {
    let value = value.trim();
    ensure!(
        value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "p2p magic must be exactly eight hexadecimal characters"
    );
    let mut magic = [0; 4];
    for (index, slot) in magic.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(magic)
}

pub(crate) fn parse_connect_endpoint(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(value.to_owned());
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(format!("connect peer `{value}` must include a port"));
    };
    if host.is_empty() {
        return Err(format!("connect peer `{value}` has an empty hostname"));
    }
    port.parse::<u16>()
        .map_err(|error| format!("connect peer `{value}` has an invalid port: {error}"))?;
    Ok(value.to_owned())
}

pub(crate) fn parse_socket_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| Ok(part.trim().parse()?))
        .collect()
}

pub(crate) fn parse_connect_list(value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_connect_endpoint(part.trim()).map_err(anyhow::Error::msg))
        .collect()
}
