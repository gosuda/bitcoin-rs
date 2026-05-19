use core::fmt;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use crossbeam_channel::Receiver;
use serde::Deserialize;

use bitcoin_rs_primitives::Network;

const DEFAULT_STORAGE_BACKEND: &str = "rocksdb";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";
const DEFAULT_DBCACHE_MB: u64 = 450;

/// RPC authentication configuration before it is converted into the RPC crate's runtime policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    /// HTTP Basic credentials.
    Basic {
        /// RPC username.
        user: String,
        /// RPC password retained until startup hashes it into the RPC runtime policy.
        password: String,
    },
    /// Bitcoin Core cookie-auth file.
    Cookie {
        /// Cookie file path.
        path: PathBuf,
    },
}

impl Auth {
    /// Constructs Basic authentication credentials.
    #[must_use]
    pub fn basic(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            user: user.into(),
            password: password.into(),
        }
    }

    /// Converts this configuration into the RPC crate's runtime auth policy.
    pub fn to_rpc_auth(&self) -> Result<bitcoin_rs_rpc::Auth> {
        match self {
            Self::Basic { user, password } => {
                Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
            }
            Self::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
        }
    }

    fn basic_parts(&self) -> (String, String) {
        match self {
            Self::Basic { user, password } => (user.clone(), password.clone()),
            Self::Cookie { .. } => (DEFAULT_RPC_USER.to_owned(), DEFAULT_RPC_PASSWORD.to_owned()),
        }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self::basic(DEFAULT_RPC_USER, DEFAULT_RPC_PASSWORD)
    }
}

/// Fully resolved node configuration.
#[derive(Clone, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// Bitcoin network selected for consensus and default ports.
    #[serde(deserialize_with = "deserialize_network")]
    pub network: Network,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Storage backend name: `rocksdb`, `fjall`, `redb`, or `mdbx`.
    pub storage_backend: String,
    /// JSON-RPC bind address.
    pub rpc_bind: SocketAddr,
    /// JSON-RPC authentication configuration.
    pub rpc_auth: Auth,
    /// Optional Electrum TCP bind address.
    pub electrum_bind: Option<SocketAddr>,
    /// Optional Electrum TLS certificate path.
    pub electrum_tls_cert: Option<PathBuf>,
    /// P2P listener bind addresses.
    pub p2p_listen: Vec<SocketAddr>,
    /// Whether DNS seeds are used for peer bootstrap.
    pub dns_seeds_enabled: bool,
    /// Pruning target in MiB. Zero disables pruning.
    pub prune_target_mb: u64,
    /// Whether utreexo mode is enabled.
    pub utreexo_mode: bool,
    /// Whether the transaction index is enabled.
    pub txindex: bool,
    /// Whether the compact block filter index is enabled.
    pub blockfilterindex: bool,
    /// Database cache target in MiB.
    pub dbcache_mb: u64,
    /// Tracing filter level used when `RUST_LOG` is unset.
    pub log_level: String,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
    #[serde(skip)]
    pub(crate) shutdown_signal: Option<Receiver<()>>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("network", &self.network)
            .field("data_dir", &self.data_dir)
            .field("storage_backend", &self.storage_backend)
            .field("rpc_bind", &self.rpc_bind)
            .field("rpc_auth", &self.rpc_auth)
            .field("electrum_bind", &self.electrum_bind)
            .field("electrum_tls_cert", &self.electrum_tls_cert)
            .field("p2p_listen", &self.p2p_listen)
            .field("dns_seeds_enabled", &self.dns_seeds_enabled)
            .field("prune_target_mb", &self.prune_target_mb)
            .field("utreexo_mode", &self.utreexo_mode)
            .field("txindex", &self.txindex)
            .field("blockfilterindex", &self.blockfilterindex)
            .field("dbcache_mb", &self.dbcache_mb)
            .field("log_level", &self.log_level)
            .field("metrics_bind", &self.metrics_bind)
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_for_network(Network::Mainnet)
    }
}

impl Config {
    /// Returns defaults for `network`, including network-specific RPC and P2P ports.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        Self {
            network,
            data_dir: PathBuf::from(".bitcoin-rs"),
            storage_backend: DEFAULT_STORAGE_BACKEND.to_owned(),
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port())),
            rpc_auth: Auth::default(),
            electrum_bind: None,
            electrum_tls_cert: None,
            p2p_listen: vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))],
            dns_seeds_enabled: true,
            prune_target_mb: 0,
            utreexo_mode: false,
            txindex: false,
            blockfilterindex: false,
            dbcache_mb: DEFAULT_DBCACHE_MB,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            metrics_bind: None,
            shutdown_signal: None,
        }
    }

    /// Loads configuration from defaults, optional Core/TOML files, environment, and CLI args.
    pub fn load_from_args<I, T>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = ConfigLayer::try_parse_from(args)?;
        let env = std::env::vars();
        Self::from_layers(cli.config.as_ref(), cli.bitcoin_conf.as_ref(), env, &cli)
    }

    /// Testable layered loader with an explicit environment source.
    pub fn from_layered_sources<E, K, V, A, T>(
        toml_path: Option<&Path>,
        bitcoin_conf_path: Option<&Path>,
        env: E,
        args: A,
    ) -> Result<Self>
    where
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
        A: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut cli = ConfigLayer::try_parse_from(args)?;
        if cli.config.is_none() {
            cli.config = toml_path.map(Path::to_path_buf);
        }
        if cli.bitcoin_conf.is_none() {
            cli.bitcoin_conf = bitcoin_conf_path.map(Path::to_path_buf);
        }
        Self::from_layers(cli.config.as_ref(), cli.bitcoin_conf.as_ref(), env, &cli)
    }

    /// Returns a copy that receives an extra in-process shutdown notification channel.
    #[must_use]
    pub fn with_shutdown_receiver(mut self, rx: Receiver<()>) -> Self {
        self.shutdown_signal = Some(rx);
        self
    }

    /// Validates backend names and simple cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        match self.storage_backend.as_str() {
            "rocksdb" | "fjall" | "redb" | "mdbx" => {}
            other => bail!("unsupported storage backend {other}"),
        }
        if self.electrum_tls_cert.is_some() && self.electrum_bind.is_none() {
            bail!("electrum_tls_cert requires electrum_bind");
        }
        Ok(())
    }

    fn from_layers<E, K, V>(
        toml_path: Option<&PathBuf>,
        bitcoin_conf_path: Option<&PathBuf>,
        env: E,
        cli: &ConfigLayer,
    ) -> Result<Self>
    where
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let toml_layer = match toml_path {
            Some(path) => Some(load_toml_layer(path)?),
            None => None,
        };
        let env_layer = ConfigLayer::from_env(env)?;
        let network = effective_network(toml_layer.as_ref(), &env_layer, cli);
        let mut config = Self::default_for_network(network);

        if let Some(path) = &bitcoin_conf_path {
            crate::bitcoin_conf_compat::apply_file(&mut config, path)?;
        }
        if let Some(layer) = &toml_layer {
            config.apply_layer(layer);
        }
        config.apply_layer(&env_layer);
        config.apply_layer(cli);
        config.validate()?;
        Ok(config)
    }

    fn apply_layer(&mut self, layer: &ConfigLayer) {
        if let Some(network) = layer.network {
            self.network = network;
        }
        if let Some(data_dir) = &layer.data_dir {
            self.data_dir.clone_from(data_dir);
        }
        if let Some(storage_backend) = &layer.storage_backend {
            self.storage_backend.clone_from(storage_backend);
        }
        if let Some(rpc_bind) = layer.rpc_bind {
            self.rpc_bind = rpc_bind;
        }
        if let Some(auth) = &layer.rpc_auth {
            self.rpc_auth = auth.clone();
        }
        if let Some(path) = &layer.rpc_cookie {
            self.rpc_auth = Auth::Cookie { path: path.clone() };
        } else if layer.rpc_user.is_some() || layer.rpc_password.is_some() {
            let (old_user, old_password) = self.rpc_auth.basic_parts();
            self.rpc_auth = Auth::basic(
                layer.rpc_user.clone().unwrap_or(old_user),
                layer.rpc_password.clone().unwrap_or(old_password),
            );
        }
        if let Some(electrum_bind) = layer.electrum_bind {
            self.electrum_bind = Some(electrum_bind);
        }
        if layer.clear_electrum_bind {
            self.electrum_bind = None;
        }
        if let Some(electrum_tls_cert) = &layer.electrum_tls_cert {
            self.electrum_tls_cert = Some(electrum_tls_cert.clone());
        }
        if let Some(p2p_listen) = &layer.p2p_listen {
            self.p2p_listen.clone_from(p2p_listen);
        }
        if let Some(dns_seeds_enabled) = layer.dns_seeds_enabled {
            self.dns_seeds_enabled = dns_seeds_enabled;
        }
        if let Some(prune_target_mb) = layer.prune_target_mb {
            self.prune_target_mb = prune_target_mb;
        }
        if let Some(utreexo_mode) = layer.utreexo_mode {
            self.utreexo_mode = utreexo_mode;
        }
        if let Some(txindex) = layer.txindex {
            self.txindex = txindex;
        }
        if let Some(blockfilterindex) = layer.blockfilterindex {
            self.blockfilterindex = blockfilterindex;
        }
        if let Some(dbcache_mb) = layer.dbcache_mb {
            self.dbcache_mb = dbcache_mb;
        }
        if let Some(log_level) = &layer.log_level {
            self.log_level.clone_from(log_level);
        }
        if let Some(metrics_bind) = layer.metrics_bind {
            self.metrics_bind = Some(metrics_bind);
        }
        if layer.clear_metrics_bind {
            self.metrics_bind = None;
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Parser)]
#[command(name = "bitcoin-rs-node", about = "Run a bitcoin-rs node")]
#[serde(default)]
pub(crate) struct ConfigLayer {
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long = "bitcoin-conf")]
    pub(crate) bitcoin_conf: Option<PathBuf>,
    #[arg(long, value_parser = parse_network)]
    #[serde(deserialize_with = "deserialize_optional_network")]
    pub(crate) network: Option<Network>,
    #[arg(long = "data-dir")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(long = "storage-backend")]
    pub(crate) storage_backend: Option<String>,
    #[arg(long = "rpc-bind")]
    pub(crate) rpc_bind: Option<SocketAddr>,
    #[arg(skip)]
    pub(crate) rpc_auth: Option<Auth>,
    #[arg(long = "rpc-user")]
    pub(crate) rpc_user: Option<String>,
    #[arg(long = "rpc-password")]
    pub(crate) rpc_password: Option<String>,
    #[arg(long = "rpc-cookie")]
    pub(crate) rpc_cookie: Option<PathBuf>,
    #[arg(long = "electrum-bind")]
    pub(crate) electrum_bind: Option<SocketAddr>,
    #[arg(skip)]
    pub(crate) clear_electrum_bind: bool,
    #[arg(long = "electrum-tls-cert")]
    pub(crate) electrum_tls_cert: Option<PathBuf>,
    #[arg(long = "p2p-listen", value_delimiter = ',')]
    pub(crate) p2p_listen: Option<Vec<SocketAddr>>,
    #[arg(long = "dns-seeds-enabled")]
    pub(crate) dns_seeds_enabled: Option<bool>,
    #[arg(long = "prune-target-mb")]
    pub(crate) prune_target_mb: Option<u64>,
    #[arg(long = "utreexo-mode")]
    pub(crate) utreexo_mode: Option<bool>,
    #[arg(long)]
    pub(crate) txindex: Option<bool>,
    #[arg(long)]
    pub(crate) blockfilterindex: Option<bool>,
    #[arg(long = "dbcache-mb")]
    pub(crate) dbcache_mb: Option<u64>,
    #[arg(long = "log-level")]
    pub(crate) log_level: Option<String>,
    #[arg(long = "metrics-bind")]
    pub(crate) metrics_bind: Option<SocketAddr>,
    #[arg(skip)]
    pub(crate) clear_metrics_bind: bool,
}

impl ConfigLayer {
    pub(crate) fn apply_to(&self, config: &mut Config) {
        config.apply_layer(self);
    }

    fn from_env<E, K, V>(env: E) -> Result<Self>
    where
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut layer = Self::default();
        for (key, value) in env {
            let key = key.as_ref();
            let value = value.as_ref();
            match key {
                "BITCOIN_RS_NETWORK" => layer.network = Some(parse_network(value)?),
                "BITCOIN_RS_DATA_DIR" => layer.data_dir = Some(PathBuf::from(value)),
                "BITCOIN_RS_STORAGE_BACKEND" => layer.storage_backend = Some(value.to_owned()),
                "BITCOIN_RS_RPC_BIND" => layer.rpc_bind = Some(value.parse()?),
                "BITCOIN_RS_RPC_USER" => layer.rpc_user = Some(value.to_owned()),
                "BITCOIN_RS_RPC_PASSWORD" => layer.rpc_password = Some(value.to_owned()),
                "BITCOIN_RS_RPC_COOKIE" => layer.rpc_cookie = Some(PathBuf::from(value)),
                "BITCOIN_RS_ELECTRUM_BIND" => layer.electrum_bind = Some(value.parse()?),
                "BITCOIN_RS_ELECTRUM_TLS_CERT" => {
                    layer.electrum_tls_cert = Some(PathBuf::from(value));
                }
                "BITCOIN_RS_P2P_LISTEN" => layer.p2p_listen = Some(parse_socket_list(value)?),
                "BITCOIN_RS_DNS_SEEDS_ENABLED" => {
                    layer.dns_seeds_enabled = Some(parse_bool(value)?);
                }
                "BITCOIN_RS_PRUNE_TARGET_MB" => layer.prune_target_mb = Some(value.parse()?),
                "BITCOIN_RS_UTREEXO_MODE" => layer.utreexo_mode = Some(parse_bool(value)?),
                "BITCOIN_RS_TXINDEX" => layer.txindex = Some(parse_bool(value)?),
                "BITCOIN_RS_BLOCKFILTERINDEX" => layer.blockfilterindex = Some(parse_bool(value)?),
                "BITCOIN_RS_DBCACHE_MB" => layer.dbcache_mb = Some(value.parse()?),
                "BITCOIN_RS_LOG_LEVEL" => layer.log_level = Some(value.to_owned()),
                "BITCOIN_RS_METRICS_BIND" => layer.metrics_bind = Some(value.parse()?),
                _ => {}
            }
        }
        Ok(layer)
    }
}

fn load_toml_layer(path: &Path) -> Result<ConfigLayer> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    let layer = toml::from_str(&text)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
    Ok(layer)
}

fn effective_network(toml: Option<&ConfigLayer>, env: &ConfigLayer, cli: &ConfigLayer) -> Network {
    cli.network
        .or(env.network)
        .or_else(|| toml.and_then(|layer| layer.network))
        .unwrap_or(Network::Mainnet)
}

fn parse_socket_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| Ok(part.trim().parse()?))
        .collect()
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}

fn parse_network(value: &str) -> anyhow::Result<Network> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(Network::Mainnet),
        "test" | "testnet" | "testnet3" => Ok(Network::Testnet3),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => bail!("unsupported network {other}"),
    }
}

fn deserialize_network<'de, D>(deserializer: D) -> core::result::Result<Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_network(&raw).map_err(serde::de::Error::custom)
}

fn deserialize_optional_network<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<Network>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    raw.as_deref()
        .map(parse_network)
        .transpose()
        .map_err(serde::de::Error::custom)
}
