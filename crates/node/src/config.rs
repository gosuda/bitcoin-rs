use core::fmt;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use crossbeam_channel::Receiver;
use serde::Deserialize;

use bitcoin_rs_primitives::Network;

const DEFAULT_STORAGE_BACKEND: &str = "fjall";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";
const DEFAULT_DBCACHE_MB: u64 = 450;
const DEFAULT_ZMQ_HWM: u32 = 1_000;

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

/// One configured ZMQ PUB notification endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmqPublication {
    /// Notification topic name.
    pub topic: crate::zmq_publisher::ZmqTopic,
    /// ZMQ endpoint to bind.
    pub endpoint: String,
    /// PUB socket high-water mark.
    pub hwm: u32,
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
    /// Optional path for applied-block G2 `MuHash` samples.
    pub g2_muhash_samples: Option<PathBuf>,
    /// Optional final applied height to include in G2 `MuHash` samples.
    pub g2_muhash_tip_height: Option<u32>,
    /// ZMQ `hashblock` PUB bind endpoints.
    pub zmqpubhashblock: Vec<String>,
    /// ZMQ `hashtx` PUB bind endpoints.
    pub zmqpubhashtx: Vec<String>,
    /// ZMQ `rawblock` PUB bind endpoints.
    pub zmqpubrawblock: Vec<String>,
    /// ZMQ `rawtx` PUB bind endpoints.
    pub zmqpubrawtx: Vec<String>,
    /// Optional `hashblock` PUB socket high-water mark.
    pub zmqpubhashblockhwm: Option<u32>,
    /// Optional `hashtx` PUB socket high-water mark.
    pub zmqpubhashtxhwm: Option<u32>,
    /// Optional `rawblock` PUB socket high-water mark.
    pub zmqpubrawblockhwm: Option<u32>,
    /// Optional `rawtx` PUB socket high-water mark.
    pub zmqpubrawtxhwm: Option<u32>,
    /// Block height at or below which script verification is skipped during block apply.
    ///
    /// Height-only trust shortcut for faster catch-up. This is **not** equivalent to Bitcoin
    /// Core's hash-based `-assumevalid`, which pins a trusted block hash. Zero disables script
    /// skipping and preserves full consensus checks.
    pub assume_valid_height: u32,
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
            .field("g2_muhash_samples", &self.g2_muhash_samples)
            .field("g2_muhash_tip_height", &self.g2_muhash_tip_height)
            .field("zmqpubhashblock", &self.zmqpubhashblock)
            .field("zmqpubhashtx", &self.zmqpubhashtx)
            .field("zmqpubrawblock", &self.zmqpubrawblock)
            .field("zmqpubrawtx", &self.zmqpubrawtx)
            .field("zmqpubhashblockhwm", &self.zmqpubhashblockhwm)
            .field("zmqpubhashtxhwm", &self.zmqpubhashtxhwm)
            .field("zmqpubrawblockhwm", &self.zmqpubrawblockhwm)
            .field("zmqpubrawtxhwm", &self.zmqpubrawtxhwm)
            .field("assume_valid_height", &self.assume_valid_height)
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
            g2_muhash_samples: None,
            g2_muhash_tip_height: None,
            zmqpubhashblock: Vec::new(),
            zmqpubhashtx: Vec::new(),
            zmqpubrawblock: Vec::new(),
            zmqpubrawtx: Vec::new(),
            zmqpubhashblockhwm: None,
            zmqpubhashtxhwm: None,
            zmqpubrawblockhwm: None,
            zmqpubrawtxhwm: None,
            assume_valid_height: 0,
            shutdown_signal: None,
        }
    }

    /// Loads configuration from defaults, optional Core/TOML files, environment, and CLI args.
    pub fn load_from_args<I, T>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = match ConfigLayer::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                err.exit();
            }
        };
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
        if self.electrum_bind.is_some() && !self.txindex {
            bail!("electrum_bind requires txindex");
        }
        match (&self.g2_muhash_samples, self.g2_muhash_tip_height) {
            (Some(_), Some(0)) => bail!("g2_muhash_tip_height must be greater than zero"),
            (Some(_), None) => bail!("g2_muhash_samples requires g2_muhash_tip_height"),
            (None, Some(_)) => bail!("g2_muhash_tip_height requires g2_muhash_samples"),
            (None, None) | (Some(_), Some(_)) => {}
        }
        for (name, hwm) in [
            ("zmqpubhashblockhwm", self.zmqpubhashblockhwm),
            ("zmqpubhashtxhwm", self.zmqpubhashtxhwm),
            ("zmqpubrawblockhwm", self.zmqpubrawblockhwm),
            ("zmqpubrawtxhwm", self.zmqpubrawtxhwm),
        ] {
            if hwm.is_some_and(|value| value > 2_147_483_647) {
                bail!("{name} exceeds libzmq SNDHWM range");
            }
        }
        Ok(())
    }

    /// Returns active ZMQ publications in Core notification order.
    #[must_use]
    pub fn zmq_publications(&self) -> Vec<ZmqPublication> {
        let mut publications = Vec::new();
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::HashBlock,
            &self.zmqpubhashblock,
            self.zmqpubhashblockhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::HashTx,
            &self.zmqpubhashtx,
            self.zmqpubhashtxhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::RawBlock,
            &self.zmqpubrawblock,
            self.zmqpubrawblockhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::RawTx,
            &self.zmqpubrawtx,
            self.zmqpubrawtxhwm,
        );
        publications
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
        if let Some(path) = &layer.g2_muhash_samples {
            self.g2_muhash_samples = Some(path.clone());
        }
        if let Some(height) = layer.g2_muhash_tip_height {
            self.g2_muhash_tip_height = Some(height);
        }
        if let Some(endpoints) = &layer.zmqpubhashblock {
            self.zmqpubhashblock.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubhashtx {
            self.zmqpubhashtx.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubrawblock {
            self.zmqpubrawblock.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubrawtx {
            self.zmqpubrawtx.clone_from(endpoints);
        }
        if let Some(hwm) = layer.zmqpubhashblockhwm {
            self.zmqpubhashblockhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubhashtxhwm {
            self.zmqpubhashtxhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubrawblockhwm {
            self.zmqpubrawblockhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubrawtxhwm {
            self.zmqpubrawtxhwm = Some(hwm);
        }
        if let Some(height) = layer.assume_valid_height {
            self.assume_valid_height = height;
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
    #[arg(long = "g2-muhash-samples")]
    pub(crate) g2_muhash_samples: Option<PathBuf>,
    #[arg(long = "g2-muhash-tip-height")]
    pub(crate) g2_muhash_tip_height: Option<u32>,
    #[arg(long = "zmqpubhashblock", value_delimiter = ',')]
    pub(crate) zmqpubhashblock: Option<Vec<String>>,
    #[arg(long = "zmqpubhashtx", value_delimiter = ',')]
    pub(crate) zmqpubhashtx: Option<Vec<String>>,
    #[arg(long = "zmqpubrawblock", value_delimiter = ',')]
    pub(crate) zmqpubrawblock: Option<Vec<String>>,
    #[arg(long = "zmqpubrawtx", value_delimiter = ',')]
    pub(crate) zmqpubrawtx: Option<Vec<String>>,
    #[arg(long = "zmqpubhashblockhwm")]
    pub(crate) zmqpubhashblockhwm: Option<u32>,
    #[arg(long = "zmqpubhashtxhwm")]
    pub(crate) zmqpubhashtxhwm: Option<u32>,
    #[arg(long = "zmqpubrawblockhwm")]
    pub(crate) zmqpubrawblockhwm: Option<u32>,
    #[arg(long = "zmqpubrawtxhwm")]
    pub(crate) zmqpubrawtxhwm: Option<u32>,
    #[arg(long = "assume-valid-height")]
    pub(crate) assume_valid_height: Option<u32>,
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
                "BITCOIN_RS_G2_MUHASH_SAMPLES" => {
                    layer.g2_muhash_samples = Some(PathBuf::from(value));
                }
                "BITCOIN_RS_G2_MUHASH_TIP_HEIGHT" => {
                    layer.g2_muhash_tip_height = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBHASHBLOCK" => {
                    layer.zmqpubhashblock = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBHASHTX" => {
                    layer.zmqpubhashtx = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBRAWBLOCK" => {
                    layer.zmqpubrawblock = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBRAWTX" => {
                    layer.zmqpubrawtx = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBHASHBLOCKHWM" => {
                    layer.zmqpubhashblockhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBHASHTXHWM" => {
                    layer.zmqpubhashtxhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBRAWBLOCKHWM" => {
                    layer.zmqpubrawblockhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBRAWTXHWM" => {
                    layer.zmqpubrawtxhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ASSUME_VALID_HEIGHT" => {
                    layer.assume_valid_height = Some(value.parse()?);
                }
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

fn parse_string_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn push_zmq_publications(
    publications: &mut Vec<ZmqPublication>,
    topic: crate::zmq_publisher::ZmqTopic,
    endpoints: &[String],
    hwm: Option<u32>,
) {
    let hwm = hwm.unwrap_or(DEFAULT_ZMQ_HWM);
    publications.extend(endpoints.iter().cloned().map(|endpoint| ZmqPublication {
        topic,
        endpoint,
        hwm,
    }));
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
