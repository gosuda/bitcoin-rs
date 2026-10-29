use std::convert::Infallible;
use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr as _;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde::de::{Error as _, MapAccess, Visitor};

use crate::config::{NetworkSelection, NotificationConfig, ScriptIndexMode};
use bitcoin::hex::FromHex;
use bitcoin_rs_chainstate::ValidationMode;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_storage::StorageBackend;

pub use bitcoin_rs_p2p::{IpSubnet, PeerNetwork};
pub use bitcoin_rs_primitives::NetworkLabel;

pub fn parse_network(value: &str) -> std::result::Result<NetworkSelection, String> {
    NetworkSelection::from_str(value)
}

pub fn parse_storage_backend(value: &str) -> std::result::Result<StorageBackend, String> {
    StorageBackend::from_str(value)
}

pub fn parse_script_index(value: &str) -> std::result::Result<ScriptIndexMode, String> {
    ScriptIndexMode::parse(value).ok_or_else(|| {
        format!("invalid scriptindex value `{value}`: expected `utxo`, `full`, or a boolean")
    })
}

pub fn check_index_bundle_path(
    path: &std::path::Path,
) -> std::result::Result<(), IndexBundleDirError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() || bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(IndexBundleDirError::Empty);
    }
    if bytes.contains(&0) {
        return Err(IndexBundleDirError::Nul);
    }
    Ok(())
}

pub fn parse_index_bundle_dir(value: &str) -> std::result::Result<PathBuf, IndexBundleDirError> {
    let path = PathBuf::from(value);
    check_index_bundle_path(&path)?;
    Ok(path)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IndexBundleDirError {
    #[error("index bundle directory must not be empty")]
    Empty,
    #[error("index bundle directory must not contain a NUL byte")]
    Nul,
}

pub fn parse_validation_mode(value: &str) -> std::result::Result<ValidationMode, String> {
    ValidationMode::parse(value).ok_or_else(|| {
        format!(
            "invalid validation-mode value `{value}`: expected `full`, `assume-valid`, or `fast`"
        )
    })
}

pub fn parse_validation_engine(value: &str) -> std::result::Result<ValidationEngine, String> {
    ValidationEngine::parse(value).ok_or_else(|| {
        format!("invalid validation-engine value `{value}`: expected `native` or `kernel`")
    })
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}

pub fn parse_p2p_magic(value: &str) -> Result<[u8; 4]> {
    let value = value.trim();
    <[u8; 4]>::from_hex(value)
        .map_err(|_| anyhow::anyhow!("p2p magic must be exactly eight hexadecimal characters"))
}

pub fn parse_connect_endpoint(value: &str) -> std::result::Result<String, String> {
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

pub fn parse_peer_network(value: &str) -> std::result::Result<bitcoin_rs_p2p::PeerNetwork, String> {
    value.parse().map_err(str::to_owned)
}
fn parse_peer_networks(value: &str) -> Result<Vec<bitcoin_rs_p2p::PeerNetwork>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|network| parse_peer_network(network.trim()).map_err(anyhow::Error::msg))
        .collect()
}

fn parse_socket_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| Ok(part.trim().parse()?))
        .collect()
}

fn parse_connect_list(value: &str) -> Result<Vec<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|part| parse_connect_endpoint(part.trim()).map_err(anyhow::Error::msg))
        .collect()
}

pub fn parse_network_label(
    value: &str,
) -> std::result::Result<bitcoin_rs_primitives::NetworkLabel, String> {
    match value {
        "ipv4" => Ok(bitcoin_rs_primitives::NetworkLabel::Ipv4),
        "ipv6" => Ok(bitcoin_rs_primitives::NetworkLabel::Ipv6),
        "onion" => Ok(bitcoin_rs_primitives::NetworkLabel::Onion),
        "i2p" => Ok(bitcoin_rs_primitives::NetworkLabel::I2p),
        other => Err(format!("unknown network label: {other}")),
    }
}

pub fn parse_noban_subnet(
    value: &str,
) -> std::result::Result<bitcoin_rs_p2p::IpSubnet, bitcoin_rs_p2p::SubnetParseError> {
    value.parse()
}

fn parse_noban_list(value: &str) -> Result<Vec<bitcoin_rs_p2p::IpSubnet>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|part| parse_noban_subnet(part.trim()).map_err(Into::into))
        .collect()
}

#[expect(clippy::unnecessary_wraps)]
fn parse_text(value: &str) -> std::result::Result<String, Infallible> {
    Ok(value.to_owned())
}

#[expect(clippy::unnecessary_wraps)]
fn parse_path(value: &str) -> std::result::Result<PathBuf, Infallible> {
    Ok(PathBuf::from(value))
}

fn parsed<T, E: fmt::Display>(
    value: &str,
    grammar: fn(&str) -> std::result::Result<T, E>,
) -> Result<T> {
    grammar(value).map_err(|error| anyhow::anyhow!("{error}"))
}

fn environment_text<'a>(key: &str, value: &'a OsStr) -> Result<&'a str> {
    value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("environment variable {key} is not valid UTF-8"))
}

macro_rules! toml_row {
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, native($want:literal)) => {
        if $key == $want {
            $($slot).* = Some($map.next_value()?);
            $matched = true;
        }
    };
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, text($want:literal, $gram:expr)) => {
        if $key == $want {
            let value: String = $map.next_value()?;
            $($slot).* = Some(
                $crate::options::parsed(&value, $gram)
                    .map_err($crate::options::toml_error::<_, A::Error>)?,
            );
            $matched = true;
        }
    };
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, each($want:literal, $gram:expr)) => {
        if $key == $want {
            let values: Vec<String> = $map.next_value()?;
            $($slot).* = Some(
                values
                    .into_iter()
                    .map(|value| {
                        $crate::options::parsed(&value, $gram)
                            .map_err($crate::options::toml_error::<_, A::Error>)
                    })
                    .collect::<std::result::Result<_, _>>()?,
            );
            $matched = true;
        }
    };
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, table($want:literal)) => {
        if $key == $want {
            $($slot).* = $map.next_value()?;
            $matched = true;
        }
    };
}

fn toml_error<E: fmt::Display, F: serde::de::Error>(error: E) -> F {
    F::custom(error)
}

macro_rules! emit_user_config {
    (
        fields {
            $(
                $(#[$fdoc:meta])*
                $fid:ident : $fty:ty {
                    cli[ $($fcli:tt)* ]
                    $( env[ $ekey:literal, $egram:expr ] )?
                    $( toml $tmode:ident ( $tkey:literal $(, $tgram:expr )? ) )?
                    $( conf[ $ckey:literal ] )?
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
        $(
            $(#[$gdoc])*
            #[derive(Clone, Debug, Default)]
            $(#[$gattr])*
            pub struct $gty {
                $(
                    $(#[$rdoc])*
                    pub $rfield: $rty,
                )*
            }
        )*

        #[derive(Clone, Debug, Default)]
        pub struct UserConfig {
            $(
                $(#[$fdoc])*
                pub $fid: $fty,
            )*
            $(
                $(#[$gdoc])*
                pub $gid: $gty,
            )*
        }

        impl UserConfig {
            pub fn overlay(&mut self, upper: &Self) {
                $(
                    if upper.$fid.is_some() {
                        self.$fid.clone_from(&upper.$fid);
                    }
                )*
                $(
                    $(
                        if upper.$gid.$rfield.is_some() {
                            self.$gid.$rfield.clone_from(&upper.$gid.$rfield);
                        }
                    )*
                )*
                if upper.rpc.cookie.is_some() {
                    self.rpc.user = None;
                    self.rpc.password = None;
                } else if upper.rpc.user.is_some() || upper.rpc.password.is_some() {
                    self.rpc.cookie = None;
                }
            }

            pub fn apply_env(&mut self, key: &str, value: &OsStr) -> Result<()> {
                match key {
                    $(
                        $(
                            $ekey => {
                                let text = $crate::options::environment_text(key, value)?;
                                self.$fid = Some($crate::options::parsed(text, $egram)?);
                            }
                        )?
                    )*
                    $(
                        $(
                            $(
                                $gekey => {
                                    let text =
                                        $crate::options::environment_text(key, value)?;
                                    self.$gid.$rfield =
                                        Some($crate::options::parsed(text, $gegram)?);
                                }
                            )?
                        )*
                    )*
                    _ => {}
                }
                Ok(())
            }
        }

        impl<'de> Deserialize<'de> for UserConfig {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                const TOML_KEYS: &[&str] = &[
                    $(
                        $( $tkey, )?
                    )*
                    $(
                        $( $( $gtkey, )? )*
                        $( $gkey, )?
                    )*
                ];

                struct LayerVisitor;

                impl<'de> Visitor<'de> for LayerVisitor {
                    type Value = UserConfig;

                    fn expecting(
                        &self,
                        formatter: &mut fmt::Formatter<'_>,
                    ) -> fmt::Result {
                        formatter.write_str("a node configuration layer")
                    }

                    fn visit_map<A>(
                        self,
                        mut map: A,
                    ) -> std::result::Result<UserConfig, A::Error>
                    where
                        A: MapAccess<'de>,
                    {
                        let mut config = UserConfig::default();
                        while let Some(key) = map.next_key::<String>()? {
                            let mut matched = false;
                            $(
                                $(
                                    toml_row!(
                                        key, config.$fid, map, matched,
                                        $tmode ( $tkey $(, $tgram )? )
                                    );
                                )?
                            )*
                            $(
                                $(
                                    $(
                                        toml_row!(
                                            key, config.$gid.$rfield, map, matched,
                                            $gtmode ( $gtkey $(, $gtgram )? )
                                        );
                                    )?
                                )*
                                $(
                                    toml_row!(
                                        key, config.$gid, map, matched, table($gkey)
                                    );
                                )?
                            )*
                            if !matched {
                                return Err(A::Error::unknown_field(&key, TOML_KEYS));
                            }
                        }
                        Ok(config)
                    }
                }

                deserializer.deserialize_map(LayerVisitor)
            }
        }
    };
}

#[macro_export]
macro_rules! option_rows {
    ($m:ident) => {
        $m! {
            fields {
                network: Option<NetworkSelection> {
                    cli[#[arg(long = "network", value_parser = parse_network)]]
                    env["BITCOIN_RS_NETWORK", parse_network]
                    toml text("network", parse_network)
                }
                data_dir: Option<PathBuf> {
                    cli[#[arg(long = "data-dir")]]
                    env["BITCOIN_RS_DATA_DIR", parse_path]
                    toml native("data_dir")
                }
                persist_mempool: Option<bool> {
                    cli[#[arg(long = "persist-mempool")]]
                    env["BITCOIN_RS_PERSIST_MEMPOOL", parse_bool]
                    toml native("persist_mempool")
                }
                mempool_snapshot_max_mb: Option<u64> {
                    cli[#[arg(long = "mempool-snapshot-max-mb")]]
                    env["BITCOIN_RS_MEMPOOL_SNAPSHOT_MAX_MB", str::parse]
                    toml native("mempool_snapshot_max_mb")
                }
                mempool_snapshot_restore_timeout_secs: Option<u64> {
                    cli[#[arg(long = "mempool-snapshot-restore-timeout-secs")]]
                    env["BITCOIN_RS_MEMPOOL_SNAPSHOT_RESTORE_TIMEOUT_SECS", str::parse]
                    toml native("mempool_snapshot_restore_timeout_secs")
                }
                notifications: Option<NotificationConfig> {
                    cli[#[arg(skip)]]
                    toml native("notifications")
                }
            }
            groups {
                group storage: StorageOverrides {
                    backend as storage_backend: Option<StorageBackend> {
                        cli[#[arg(long = "storage-backend", value_parser = parse_storage_backend)]]
                        env["BITCOIN_RS_STORAGE_BACKEND", parse_storage_backend]
                        toml text("storage_backend", parse_storage_backend)
                    }
                    dbcache_mb as dbcache_mb: Option<u64> {
                        cli[#[arg(long = "dbcache-mb")]]
                        env["BITCOIN_RS_DBCACHE_MB", str::parse]
                        toml native("dbcache_mb")
                        conf["dbcache"]
                    }
                    prune_target_mb as prune_target_mb: Option<u64> {
                        cli[#[arg(long = "prune-target-mb")]]
                        env["BITCOIN_RS_PRUNE_TARGET_MB", str::parse]
                        toml native("prune_target_mb")
                        conf["prune"]
                    }
                }
                group p2p: P2pOverrides {
                    magic as p2p_magic: Option<[u8; 4]> {
                        cli[#[arg(long = "p2p-magic", value_parser = parse_p2p_magic)]]
                        env["BITCOIN_RS_P2P_MAGIC", parse_p2p_magic]
                        toml text("p2p_magic", parse_p2p_magic)
                    }
                    listen as p2p_listen: Option<Vec<SocketAddr>> {
                        cli[#[arg(long = "p2p-listen", value_delimiter = ',')]]
                        env["BITCOIN_RS_P2P_LISTEN", parse_socket_list]
                        toml native("p2p_listen")
                    }
                    dns_seeds as dns_seeds_enabled: Option<bool> {
                        cli[#[arg(long = "dns-seeds-enabled")]]
                        env["BITCOIN_RS_DNS_SEEDS_ENABLED", parse_bool]
                        toml native("dns_seeds_enabled")
                        conf["dnsseed"]
                    }
                    asmap as asmap: Option<PathBuf> {
                        cli[#[arg(long = "asmap")]]
                        env["BITCOIN_RS_ASMAP", parse_path]
                        toml native("asmap")
                    }
                    noban_subnets as p2p_noban: Option<Vec<$crate::options::IpSubnet>> {
                        cli[#[arg(long = "p2p-noban", value_delimiter = ',', value_parser = $crate::options::parse_noban_subnet)]]
                        env["BITCOIN_RS_P2P_NOBAN", parse_noban_list]
                        toml each("p2p_noban", parse_noban_subnet)
                    }
                    connect as connect: Option<Vec<String>> {
                        cli[#[arg(long = "connect", value_delimiter = ',', value_parser = parse_connect_endpoint)]]
                        env["BITCOIN_RS_CONNECT", parse_connect_list]
                        toml each("connect", parse_connect_endpoint)
                    }
                    proxy as proxy: Option<SocketAddr> {
                        cli[#[arg(long = "proxy")]]
                        env["BITCOIN_RS_PROXY", str::parse]
                        toml native("proxy")
                        conf["proxy"]
                    }
                    onion_proxy as onion_proxy: Option<SocketAddr> {
                        cli[#[arg(long = "onion-proxy")]]
                        env["BITCOIN_RS_ONION_PROXY", str::parse]
                        toml native("onion_proxy")
                        conf["onion"]
                    }
                    i2p_sam as i2p_sam: Option<SocketAddr> {
                        cli[#[arg(long = "i2p-sam")]]
                        env["BITCOIN_RS_I2P_SAM", str::parse]
                        toml native("i2p_sam")
                        conf["i2psam"]
                    }
                    tor_control as tor_control: Option<SocketAddr> {
                        cli[#[arg(long = "tor-control")]]
                        env["BITCOIN_RS_TOR_CONTROL", str::parse]
                        toml native("tor_control")
                        conf["torcontrol"]
                    }
                    tor_cookie as tor_cookie: Option<PathBuf> {
                        cli[#[arg(long = "tor-cookie")]]
                        env["BITCOIN_RS_TOR_COOKIE", parse_path]
                        toml native("tor_cookie")
                    }
                    i2p_accept as i2p_accept: Option<bool> {
                        cli[#[arg(long = "i2p-accept", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_I2P_ACCEPT", parse_bool]
                        toml native("i2p_accept")
                        conf["i2pacceptincoming"]
                    }
                    proxy_randomize_credentials as proxy_randomize_credentials: Option<bool> {
                        cli[#[arg(long = "proxy-randomize-credentials", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_PROXY_RANDOMIZE_CREDENTIALS", parse_bool]
                        toml native("proxy_randomize_credentials")
                        conf["proxyrandomize"]
                    }
                    overlay_port as overlay_port: Option<u16> {
                        cli[#[arg(long = "overlay-port")]]
                        env["BITCOIN_RS_OVERLAY_PORT", str::parse]
                        toml native("overlay_port")
                    }
                    onlynet as onlynet: Option<Vec<$crate::options::PeerNetwork>> {
                        cli[#[arg(long = "onlynet", value_delimiter = ',', value_parser = $crate::options::parse_peer_network)]]
                        env["BITCOIN_RS_ONLYNET", parse_peer_networks]
                        toml each("onlynet", parse_peer_network)
                        conf["onlynet"]
                    }
                    fast_sync as fast_sync: Option<bool> {
                        cli[#[arg(long = "fast-sync", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_FAST_SYNC", parse_bool]
                        toml native("fast_sync")
                    }
                    v2_transport as v2_transport: Option<bool> {
                        cli[#[arg(long = "v2transport", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_V2_TRANSPORT", parse_bool]
                        toml native("v2_transport")
                        conf["v2transport"]
                    }
                    package_relay as p2p_package_relay: Option<bool> {
                        cli[#[arg(long = "p2p-package-relay", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_P2P_PACKAGE_RELAY", parse_bool]
                        toml native("p2p_package_relay")
                    }
                    stale_tip_relay as p2p_stale_tip_relay: Option<bool> {
                        cli[#[arg(long = "p2p-stale-tip-relay", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_P2P_STALE_TIP_RELAY", parse_bool]
                        toml native("p2p_stale_tip_relay")
                    }
                    stale_tip_prefers_blocks as p2p_stale_tip_prefers_blocks: Option<bool> {
                        cli[#[arg(long = "p2p-stale-tip-prefers-blocks", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_P2P_STALE_TIP_PREFERS_BLOCKS", parse_bool]
                        toml native("p2p_stale_tip_prefers_blocks")
                    }
                }
                group rpc: RpcOverrides {
                    silent_payments as silent_payments: Option<bool> {
                        cli[#[arg(long = "silent-payments", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_SILENT_PAYMENTS", parse_bool]
                        toml native("silent_payments")
                    }
                    compressed_transactions as compressed_transactions: Option<bool> {
                        cli[#[arg(long = "compressed-transactions", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_COMPRESSED_TRANSACTIONS", parse_bool]
                        toml native("compressed_transactions")
                    }
                    bind as rpc_bind: Option<SocketAddr> {
                        cli[#[arg(long = "rpc-bind")]]
                        env["BITCOIN_RS_RPC_BIND", str::parse]
                        toml native("rpc_bind")
                    }
                    public_bind as public_bind: Option<SocketAddr> {
                        cli[#[arg(long = "public-bind")]]
                        env["BITCOIN_RS_PUBLIC_BIND", str::parse]
                        toml native("public_bind")
                    }
                    max_connections as rpc_max_connections: Option<usize> {
                        cli[#[arg(long = "rpc-max-connections")]]
                        env["BITCOIN_RS_RPC_MAX_CONNECTIONS", str::parse]
                        toml native("rpc_max_connections")
                    }
                    public_max_connections as public_max_connections: Option<usize> {
                        cli[#[arg(long = "public-max-connections")]]
                        env["BITCOIN_RS_PUBLIC_MAX_CONNECTIONS", str::parse]
                        toml native("public_max_connections")
                    }
                    rest as rest: Option<bool> {
                        cli[#[arg(long = "rest")]]
                        env["BITCOIN_RS_REST", parse_bool]
                        toml native("rest")
                        conf["rest"]
                    }
                    user as rpc_user: Option<String> {
                        cli[#[arg(long = "rpc-user")]]
                        env["BITCOIN_RS_RPC_USER", parse_text]
                        toml native("rpc_user")
                        conf["rpcuser"]
                    }
                    password as rpc_password: Option<String> {
                        cli[#[arg(long = "rpc-password")]]
                        env["BITCOIN_RS_RPC_PASSWORD", parse_text]
                        toml native("rpc_password")
                        conf["rpcpassword"]
                    }
                    cookie as rpc_cookie: Option<PathBuf> {
                        cli[#[arg(long = "rpc-cookie")]]
                        env["BITCOIN_RS_RPC_COOKIE", parse_path]
                        toml native("rpc_cookie")
                        conf["rpccookiefile"]
                    }
                }
                group indexes: IndexOverrides {
                    txindex as txindex: Option<bool> {
                        cli[#[arg(long = "txindex")]]
                        env["BITCOIN_RS_TXINDEX", parse_bool]
                        toml native("txindex")
                        conf["txindex"]
                    }
                    blockfilterindex as blockfilterindex: Option<bool> {
                        cli[#[arg(long = "blockfilterindex", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_BLOCKFILTERINDEX", parse_bool]
                        toml native("blockfilterindex")
                        conf["blockfilterindex"]
                    }
                    script_index as script_index: Option<ScriptIndexMode> {
                        cli[#[arg(long = "scriptindex", visible_alias = "script-index", num_args = 0..=1, default_missing_value = "true", value_parser = parse_script_index)]]
                        env["BITCOIN_RS_SCRIPTINDEX", parse_script_index]
                        toml text("script_index", parse_script_index)
                    }
                    bundle_import as index_bundle_import: Option<PathBuf> {
                        cli[#[arg(long = "index-bundle-import", value_parser = $crate::options::parse_index_bundle_dir)]]
                        env["BITCOIN_RS_INDEX_BUNDLE_IMPORT", parse_index_bundle_dir]
                        toml text("index_bundle_import", parse_index_bundle_dir)
                    }
                    bundle_export as index_bundle_export: Option<PathBuf> {
                        cli[#[arg(long = "index-bundle-export", value_parser = $crate::options::parse_index_bundle_dir)]]
                        env["BITCOIN_RS_INDEX_BUNDLE_EXPORT", parse_index_bundle_dir]
                        toml text("index_bundle_export", parse_index_bundle_dir)
                    }
                }
                group observability: ObservabilityOverrides {
                    log_level as log_level: Option<String> {
                        cli[#[arg(long = "log-level")]]
                        env["BITCOIN_RS_LOG_LEVEL", parse_text]
                        toml native("log_level")
                    }
                    metrics_bind as metrics_bind: Option<SocketAddr> {
                        cli[#[arg(long = "metrics-bind")]]
                        env["BITCOIN_RS_METRICS_BIND", str::parse]
                        toml native("metrics_bind")
                    }
                }
                group validation: ValidationOverrides {
                    assume_valid_height as assume_valid_height: Option<u32> {
                        cli[#[arg(long = "assume-valid-height")]]
                        env["BITCOIN_RS_ASSUME_VALID_HEIGHT", str::parse]
                        toml native("assume_valid_height")
                    }
                    mode as validation_mode: Option<ValidationMode> {
                        cli[#[arg(long = "validation-mode", value_parser = parse_validation_mode)]]
                        env["BITCOIN_RS_VALIDATION_MODE", parse_validation_mode]
                        toml text("validation_mode", parse_validation_mode)
                    }
                    engine as validation_engine: Option<ValidationEngine> {
                        cli[#[arg(long = "validation-engine", value_parser = parse_validation_engine)]]
                        env["BITCOIN_RS_VALIDATION_ENGINE", parse_validation_engine]
                        toml text("validation_engine", parse_validation_engine)
                    }
                }
                group mining: MiningOverrides {
                    payout_address as mining_payout_address: Option<String> {
                        cli[#[arg(long = "mining-payout-address")]]
                        env["BITCOIN_RS_MINING_PAYOUT_ADDRESS", parse_text]
                        toml native("mining_payout_address")
                    }
                }
                group pool: PoolOverrides {
                    enabled as pool: Option<bool> {
                        cli[#[arg(long = "pool", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_POOL", parse_bool]
                        toml native("pool")
                    }
                    datadir as pool_datadir: Option<PathBuf> {
                        cli[#[arg(long = "pool-datadir")]]
                        env["BITCOIN_RS_POOL_DATADIR", parse_path]
                        toml native("pool_datadir")
                    }
                    v1_bind as pool_v1_bind: Option<SocketAddr> {
                        cli[#[arg(long = "pool-v1-bind")]]
                        env["BITCOIN_RS_POOL_V1_BIND", str::parse]
                        toml native("pool_v1_bind")
                    }
                    sv2_bind as pool_sv2_bind: Option<SocketAddr> {
                        cli[#[arg(long = "pool-sv2-bind")]]
                        env["BITCOIN_RS_POOL_SV2_BIND", str::parse]
                        toml native("pool_sv2_bind")
                    }
                    sv2_authority_key as pool_sv2_authority_key: Option<PathBuf> {
                        cli[#[arg(long = "pool-sv2-authority-key")]]
                        env["BITCOIN_RS_POOL_SV2_AUTHORITY_KEY", parse_path]
                        toml native("pool_sv2_authority_key")
                    }
                    allow_non_loopback as pool_allow_non_loopback: Option<bool> {
                        cli[#[arg(long = "pool-allow-non-loopback", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_POOL_ALLOW_NON_LOOPBACK", parse_bool]
                        toml native("pool_allow_non_loopback")
                    }
                    max_connections as pool_max_connections: Option<u32> {
                        cli[#[arg(long = "pool-max-connections")]]
                        env["BITCOIN_RS_POOL_MAX_CONNECTIONS", str::parse]
                        toml native("pool_max_connections")
                    }
                    max_connections_per_ip as pool_max_connections_per_ip: Option<u32> {
                        cli[#[arg(long = "pool-max-connections-per-ip")]]
                        env["BITCOIN_RS_POOL_MAX_CONNECTIONS_PER_IP", str::parse]
                        toml native("pool_max_connections_per_ip")
                    }
                    share_difficulty as pool_share_difficulty: Option<String> {
                        cli[#[arg(long = "pool-share-difficulty")]]
                        env["BITCOIN_RS_POOL_SHARE_DIFFICULTY", parse_text]
                        toml native("pool_share_difficulty")
                    }
                    window_work as pool_window_work: Option<u64> {
                        cli[#[arg(long = "pool-window-work")]]
                        env["BITCOIN_RS_POOL_WINDOW_WORK", str::parse]
                        toml native("pool_window_work")
                    }
                    fee_bps as pool_fee_bps: Option<u16> {
                        cli[#[arg(long = "pool-fee-bps")]]
                        env["BITCOIN_RS_POOL_FEE_BPS", str::parse]
                        toml native("pool_fee_bps")
                    }
                    reward_script as pool_reward_script: Option<String> {
                        cli[#[arg(long = "pool-reward-script")]]
                        env["BITCOIN_RS_POOL_REWARD_SCRIPT", parse_text]
                        toml native("pool_reward_script")
                    }
                    maturity as pool_maturity: Option<u32> {
                        cli[#[arg(long = "pool-maturity")]]
                        env["BITCOIN_RS_POOL_MATURITY", str::parse]
                        toml native("pool_maturity")
                    }
                    payout_confirmations as pool_payout_confirmations: Option<u32> {
                        cli[#[arg(long = "pool-payout-confirmations")]]
                        env["BITCOIN_RS_POOL_PAYOUT_CONFIRMATIONS", str::parse]
                        toml native("pool_payout_confirmations")
                    }
                    reorg_watch_depth as pool_reorg_watch_depth: Option<u32> {
                        cli[#[arg(long = "pool-reorg-watch-depth")]]
                        env["BITCOIN_RS_POOL_REORG_WATCH_DEPTH", str::parse]
                        toml native("pool_reorg_watch_depth")
                    }
                    min_payout_sat as pool_min_payout_sat: Option<u64> {
                        cli[#[arg(long = "pool-min-payout-sat")]]
                        env["BITCOIN_RS_POOL_MIN_PAYOUT_SAT", str::parse]
                        toml native("pool_min_payout_sat")
                    }
                    max_payout_outputs as pool_max_payout_outputs: Option<u32> {
                        cli[#[arg(long = "pool-max-payout-outputs")]]
                        env["BITCOIN_RS_POOL_MAX_PAYOUT_OUTPUTS", str::parse]
                        toml native("pool_max_payout_outputs")
                    }
                }
                group chainstate_journal: ChainstateJournalOverrides
                table("chainstate_journal")
                #[derive(serde::Deserialize)]
                #[serde(default, deny_unknown_fields)]
                {
                    enabled as enabled: Option<bool> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL", parse_bool]
                    }
                    blocks as blocks: Option<u32> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_BLOCKS", str::parse]
                    }
                    seconds as seconds: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_SECONDS", str::parse]
                    }
                    rotate_mib as rotate_mib: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_ROTATE_MIB", str::parse]
                    }
                    max_journal_mib as max_journal_mib: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_MAX_JOURNAL_MIB", str::parse]
                    }
                    max_lag_blocks as max_lag_blocks: Option<u32> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_MAX_LAG_BLOCKS", str::parse]
                    }
                    max_lag_seconds as max_lag_seconds: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_MAX_LAG_SECONDS", str::parse]
                    }
                }
            }
        }
    };
}

option_rows!(emit_user_config);
