//! Node configuration split across three lifetimes.
//!
//! 1. [`UserConfig`] — what a user may supply. Every field is an optional
//!    override; absence means that source did not specify a value. Source
//!    adapters (CLI, environment, TOML, Bitcoin Core `bitcoin.conf`) produce
//!    this type. It carries no runtime defaults.
//! 2. [`NodeConfig`] — the fully resolved, validated configuration consumed by
//!    the runtime. Defaults are applied exactly once, at the [`NodeConfig`]
//!    resolution boundary, and the type is not constructible without going
//!    through it. It carries no parser annotations and no `Option` that merely
//!    represents source absence.
//! 3. [`RuntimeInputs`] — process and test dependencies (`shutdown` receiver,
//!    `mempool` observer) that are not configuration and must never be
//!    serialized or merged.
//!
//! The previous design used one flat [`Config`] type for all three jobs: a user
//! could deserialize a partial file straight into it (silently picking up
//! per-field defaults), read an unresolved `Option<[u8; 4]>` P2P magic where a
//! resolved value was expected, and inject a shutdown channel through a
//! "configuration" field. Separating the types makes those confusions
//! impossible: a caller holding a [`NodeConfig`] has a resolved, validated fact,
//! and a caller holding a [`UserConfig`] has an unresolved wish.

use core::fmt;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail, ensure};
use clap::Parser;
use crossbeam_channel::Receiver;
use serde::Deserialize;

use bitcoin_rs_primitives::Network;

const DEFAULT_STORAGE_BACKEND: &str = "fjall";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";
const DEFAULT_DBCACHE_MB: u64 = 450;

const DRYNET4_CONNECT: &str = "drynet4.drivechain.dev:8533";
const DRYNET4_P2P_MAGIC: [u8; 4] = [0xec, 0xa5, 0xd4, 0x04];

/// A complete built-in node network selection.
///
/// Unlike [`Network`], which selects consensus rules, this also selects P2P
/// bootstrap behavior. Low-level settings in the same or a later configuration
/// layer may explicitly override the network-derived defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkSelection {
    /// Bitcoin mainnet.
    Mainnet,
    /// Legacy Bitcoin testnet.
    Testnet3,
    /// Bitcoin testnet4.
    Testnet4,
    /// Bitcoin signet.
    Signet,
    /// Local regression-test network.
    Regtest,
    /// ecash drynet4: mainnet consensus history on a distinct P2P network.
    Drynet4,
}

impl NetworkSelection {
    const fn consensus_network(self) -> Network {
        match self {
            Self::Mainnet | Self::Drynet4 => Network::Mainnet,
            Self::Testnet3 => Network::Testnet3,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

/// RPC authentication configuration before it is converted into the RPC crate's
/// runtime policy.
///
/// [`Debug`](fmt::Debug) redacts the password and cookie path so secrets never
/// reach tracing, error messages, or serialized resolved configuration.
#[derive(Clone, Eq, PartialEq, Deserialize)]
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

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { user, .. } => f
                .debug_struct("Auth::Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            Self::Cookie { .. } => f
                .debug_struct("Auth::Cookie")
                .field("path", &"<redacted>")
                .finish(),
        }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self::basic(DEFAULT_RPC_USER, DEFAULT_RPC_PASSWORD)
    }
}

/// Node notification adapters, grouped below the node-level configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    /// ZMQ PUB sockets, each owning its endpoint, topics, and optional HWM override.
    pub zmq: Vec<crate::zmq_publisher::ZmqEndpointConfig>,
}

/// How much of the derived `ScriptIndex` a node maintains.
///
/// `ScriptIndex` is rebuildable derived state, so the mode is a capability
/// selection rather than a storage compatibility question: `full` adds
/// historical funding/spending rows while still maintaining the live-output
/// view.
///
/// The boolean spellings remain behaviorally compatible: `--scriptindex`,
/// `--scriptindex=true`, and `BITCOIN_RS_SCRIPTINDEX=true` all mean
/// [`Self::Full`], and `false` means [`Self::Disabled`].
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptIndexMode {
    /// No `ScriptIndex` capability is maintained.
    #[default]
    Disabled,
    /// Maintain both the live-output view and historical script activity.
    Full,
}

impl ScriptIndexMode {
    /// Whether any `ScriptIndex` capability is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Whether historical funding/spending rows are maintained.
    #[must_use]
    pub const fn keeps_history(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Parses a mode from a configuration value.
    ///
    /// Accepts the historical boolean spellings for compatibility: `true`
    /// means `full` and `false` means disabled. Parsing is case-insensitive.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            // `true` is the historical boolean spelling and must keep meaning
            // `full`; it is a separate pattern for that readability, not a
            // distinct outcome.
            "full" | "true" | "1" | "yes" => Some(Self::Full),
            "false" | "0" | "no" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Fully resolved, validated node configuration consumed by the runtime.
///
/// Fixed-peer hostnames are intentionally resolved later by the P2P bootstrap
/// worker, not here. This type is not deserializable and has no [`Default`]:
/// the only way to obtain one is [`NodeConfig::resolve`],
/// [`NodeConfig::load_from_args`], [`NodeConfig::from_layered_sources`], or
/// [`NodeConfig::default_for_network`] (which applies the network profile
/// defaults). That guarantees a caller holding a [`NodeConfig`] has a resolved
/// fact, not an unresolved user wish.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct NodeConfig {
    /// Bitcoin network selected for consensus and default ports.
    pub network: Network,
    /// Effective P2P message-start bytes, resolved from the network profile or
    /// an explicit override. Unlike the source layer this is never `None`: the
    /// resolution boundary applies the network default exactly once.
    pub p2p_magic: [u8; 4],
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Storage backend name: `rocksdb`, `fjall`, `redb`, or `mdbx`.
    pub storage_backend: String,
    /// JSON-RPC bind address.
    pub rpc_bind: SocketAddr,
    /// Whether the Bitcoin Core-compatible REST gateway is enabled.
    pub rest: bool,
    /// JSON-RPC authentication configuration.
    pub rpc_auth: Auth,
    /// Which `ScriptIndex` capabilities the node maintains.
    pub script_index: ScriptIndexMode,
    /// P2P listener bind addresses.
    pub p2p_listen: Vec<SocketAddr>,
    /// Whether DNS seeds are used for peer bootstrap.
    pub dns_seeds_enabled: bool,
    /// Fixed outbound peer endpoints to connect to. Hostnames remain unresolved
    /// until the P2P dial path so transient DNS failures do not prevent
    /// startup. When non-empty, DNS seed bootstrap is disabled and the node
    /// dials only these endpoints (Bitcoin Core `-connect`).
    pub connect: Vec<String>,
    /// Pruning target in MiB. Zero disables pruning.
    pub prune_target_mb: u64,
    /// Whether the transaction index is enabled.
    pub txindex: bool,
    /// Database cache budget in MiB, divided across the chainstate and
    /// transaction-index namespaces (shares of disabled namespaces redistribute
    /// to chainstate).
    ///
    /// Bounds: values are clamped to the byte range
    /// `[16 MiB, 1 TiB]` — a zero or tiny value clamps up to the 16 MiB floor
    /// so the engines keep a workable cache, and an overflowing value clamps
    /// down so share arithmetic stays exact. Effective per-namespace
    /// capacities are logged at startup (`opened storage backend`).
    pub dbcache_mb: u64,
    /// Tracing filter level used when `RUST_LOG` is unset.
    pub log_level: String,
    /// Optional Prometheus metrics bind address. `None` disables metrics.
    pub metrics_bind: Option<SocketAddr>,
    /// External notification adapters.
    pub notifications: NotificationConfig,
    /// Block height at or below which script verification is skipped during block apply.
    ///
    /// On mainnet the default is the hash-pinned assume-valid anchor
    /// ([`Network::assume_valid_anchor`]): blocks at or below the anchor
    /// height skip script execution only while the active header chain is
    /// verified to contain the pinned anchor block, matching Bitcoin Core's
    /// `-assumevalid` posture. Setting `0` opts into full script verification
    /// of every block. Any other custom height applies the height-only trust
    /// shortcut without a hash pin.
    pub assume_valid_height: u32,
}

impl fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeConfig")
            .field("network", &self.network)
            .field("p2p_magic", &self.p2p_magic)
            .field("data_dir", &self.data_dir)
            .field("storage_backend", &self.storage_backend)
            .field("rpc_bind", &self.rpc_bind)
            .field("rest", &self.rest)
            .field("rpc_auth", &self.rpc_auth)
            .field("script_index", &self.script_index)
            .field("p2p_listen", &self.p2p_listen)
            .field("dns_seeds_enabled", &self.dns_seeds_enabled)
            .field("connect", &self.connect)
            .field("prune_target_mb", &self.prune_target_mb)
            .field("txindex", &self.txindex)
            .field("dbcache_mb", &self.dbcache_mb)
            .field("log_level", &self.log_level)
            .field("metrics_bind", &self.metrics_bind)
            .field("notifications", &self.notifications)
            .field("assume_valid_height", &self.assume_valid_height)
            .finish()
    }
}

/// Delegates to [`NodeConfig::default_for_network`] for `Mainnet`. This is the
/// resolved mainnet default — not a partial or unresolved value — so struct
/// literal construction with `..Default::default()` starts from a fully
/// resolved base. The type remains non-deserializable: a partial file cannot
/// silently become a resolved config.
impl Default for NodeConfig {
    fn default() -> Self {
        Self::default_for_network(Network::Mainnet)
    }
}

impl NodeConfig {
    /// Returns the resolved defaults for `network`, including network-specific
    /// RPC and P2P ports and the network P2P magic. This is the single site
    /// that owns runtime defaults; [`NodeConfig::resolve`] and the layered
    /// loaders funnel through it.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        Self {
            network,
            p2p_magic: network.magic(),
            data_dir: PathBuf::from(".bitcoin-rs"),
            storage_backend: DEFAULT_STORAGE_BACKEND.to_owned(),
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port())),
            rest: false,
            rpc_auth: Auth::default(),
            script_index: ScriptIndexMode::Disabled,
            p2p_listen: vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))],
            dns_seeds_enabled: true,
            connect: Vec::new(),
            prune_target_mb: 0,
            txindex: false,
            dbcache_mb: DEFAULT_DBCACHE_MB,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            metrics_bind: None,
            notifications: NotificationConfig::default(),
            assume_valid_height: network
                .assume_valid_anchor()
                .map_or(0, |(height, _)| height),
        }
    }

    /// Resolves a single merged user configuration into a validated
    /// [`NodeConfig`]. Defaults are applied exactly once — through
    /// [`NodeConfig::default_for_network`] — then the user overrides are
    /// applied, then cross-field validation runs. This is the named boundary
    /// between an unresolved wish and a resolved fact.
    pub fn resolve(user: &UserConfig) -> Result<Self> {
        let network = user
            .network
            .map_or(Network::Mainnet, NetworkSelection::consensus_network);
        let mut config = Self::default_for_network(network);
        config.apply_layer(user)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from defaults, optional Core/TOML files,
    /// environment, and CLI args, resolving and validating in one step.
    pub fn load_from_args<I, T>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = match UserConfig::try_parse_from(args) {
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
        let mut cli = UserConfig::try_parse_from(args)?;
        if cli.config.is_none() {
            cli.config = toml_path.map(Path::to_path_buf);
        }
        if cli.bitcoin_conf.is_none() {
            cli.bitcoin_conf = bitcoin_conf_path.map(Path::to_path_buf);
        }
        Self::from_layers(cli.config.as_ref(), cli.bitcoin_conf.as_ref(), env, &cli)
    }

    /// Validates backend names and simple cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        if self.p2p_magic != self.network.magic() {
            ensure!(
                self.network == Network::Mainnet,
                "P2P magic overrides currently require --network mainnet"
            );
            ensure!(
                !self.connect.is_empty(),
                "P2P magic overrides require at least one --connect peer"
            );
            ensure!(
                !self.dns_seeds_enabled,
                "P2P magic overrides require --dns-seeds-enabled=false"
            );
        }
        match self.storage_backend.as_str() {
            "rocksdb" | "fjall" | "redb" | "mdbx" => {}
            other => bail!("unsupported storage backend {other}"),
        }
        crate::zmq_publisher::validate_endpoint_configs(&self.notifications.zmq)?;
        Ok(())
    }

    /// Returns configured ZMQ endpoint groups.
    #[must_use]
    pub fn zmq_endpoints(&self) -> &[crate::zmq_publisher::ZmqEndpointConfig] {
        &self.notifications.zmq
    }

    fn from_layers<E, K, V>(
        toml_path: Option<&PathBuf>,
        bitcoin_conf_path: Option<&PathBuf>,
        env: E,
        cli: &UserConfig,
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
        let env_layer = UserConfig::from_env(env)?;
        let network = effective_network(toml_layer.as_ref(), &env_layer, cli);
        let mut config = Self::default_for_network(network);

        if let Some(path) = &bitcoin_conf_path {
            crate::bitcoin_conf_compat::apply_file(&mut config, path)?;
        }
        if let Some(layer) = &toml_layer {
            config.apply_layer(layer)?;
        }
        config.apply_layer(&env_layer)?;
        config.apply_layer(cli)?;
        config.validate()?;
        Ok(config)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_layer(&mut self, layer: &UserConfig) -> Result<()> {
        if let Some(network) = layer.network {
            self.apply_network_selection(network);
        }
        if let Some(p2p_magic) = layer.p2p_magic {
            self.p2p_magic = p2p_magic;
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
        if let Some(rest) = layer.rest {
            self.rest = rest;
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
        if let Some(script_index) = &layer.script_index {
            self.script_index = ScriptIndexMode::parse(script_index).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid scriptindex value `{script_index}`: expected `full` or a boolean"
                )
            })?;
        }
        if let Some(p2p_listen) = &layer.p2p_listen {
            self.p2p_listen.clone_from(p2p_listen);
        }
        if let Some(dns_seeds_enabled) = layer.dns_seeds_enabled {
            self.dns_seeds_enabled = dns_seeds_enabled;
        }
        if let Some(connect) = &layer.connect {
            self.connect.clone_from(connect);
        }
        if let Some(prune_target_mb) = layer.prune_target_mb {
            self.prune_target_mb = prune_target_mb;
        }
        if let Some(txindex) = layer.txindex {
            self.txindex = txindex;
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
        if let Some(notifications) = &layer.notifications {
            self.notifications.clone_from(notifications);
        }
        if let Some(height) = layer.assume_valid_height {
            self.assume_valid_height = height;
        }
        Ok(())
    }

    fn apply_network_selection(&mut self, selection: NetworkSelection) {
        let network = selection.consensus_network();
        self.network = network;
        self.p2p_magic = network.magic();
        self.rpc_bind = SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port()));
        self.p2p_listen = vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))];
        self.dns_seeds_enabled = true;
        self.connect.clear();

        if selection == NetworkSelection::Drynet4 {
            self.p2p_magic = DRYNET4_P2P_MAGIC;
            self.dns_seeds_enabled = false;
            self.connect = vec![DRYNET4_CONNECT.to_owned()];
        }
    }
}

/// Process and test dependencies that are not configuration.
///
/// These never participate in source parsing, merging, serialization, or
/// defaults. [`run`](crate::run) and [`embed::Node::start`](crate::embed::Node)
/// accept them alongside a resolved [`NodeConfig`] so a shutdown channel or
/// test observer cannot be mistaken for a user-supplied setting.
#[derive(Default)]
pub struct RuntimeInputs {
    /// Optional in-process shutdown notification receiver. `None` lets the
    /// daemon install its own SIGINT/SIGTERM handler.
    pub shutdown: Option<Receiver<()>>,
    /// Optional test-only observer installed on the node-owned mempool
    /// gateway.
    pub mempool_observer: Option<Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
}

impl RuntimeInputs {
    /// Returns a copy with the given shutdown receiver.
    #[must_use]
    pub fn with_shutdown(mut self, rx: Receiver<()>) -> Self {
        self.shutdown = Some(rx);
        self
    }

    /// Returns a copy with the given mempool observer.
    #[must_use]
    pub fn with_mempool_observer(
        mut self,
        observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver>,
    ) -> Self {
        self.mempool_observer = Some(observer);
        self
    }
}

/// What a user may supply: every field is an optional override and absence
/// means that source did not specify a value.
///
/// Source adapters (CLI, environment, TOML, Bitcoin Core `bitcoin.conf`)
/// produce this type. It carries no runtime defaults — those live solely in
/// [`NodeConfig::default_for_network`].
#[derive(Clone, Debug, Default, Deserialize, Parser)]
#[command(name = "bitcoin-rs-node", about = "Run a bitcoin-rs node")]
#[serde(default, deny_unknown_fields)]
pub struct UserConfig {
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long = "bitcoin-conf")]
    pub(crate) bitcoin_conf: Option<PathBuf>,
    /// Select the Bitcoin or fork network, including its P2P bootstrap profile.
    #[arg(long, value_parser = parse_network_selection)]
    pub(crate) network: Option<NetworkSelection>,
    /// Override the four P2P message-start bytes for a fork network.
    #[arg(long = "p2p-magic", value_parser = parse_p2p_magic)]
    #[serde(deserialize_with = "deserialize_optional_p2p_magic")]
    pub(crate) p2p_magic: Option<[u8; 4]>,
    #[arg(long = "data-dir")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(long = "storage-backend")]
    pub(crate) storage_backend: Option<String>,
    #[arg(long = "rpc-bind")]
    pub(crate) rpc_bind: Option<SocketAddr>,
    /// Enable the Bitcoin Core-compatible REST gateway.
    #[arg(long)]
    pub(crate) rest: Option<bool>,
    #[arg(skip)]
    pub(crate) rpc_auth: Option<Auth>,
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
        default_missing_value = "true"
    )]
    pub(crate) script_index: Option<String>,
    #[arg(long = "p2p-listen", value_delimiter = ',')]
    pub(crate) p2p_listen: Option<Vec<SocketAddr>>,
    #[arg(long = "dns-seeds-enabled")]
    pub(crate) dns_seeds_enabled: Option<bool>,
    #[arg(
        long = "connect",
        value_delimiter = ',',
        value_parser = parse_connect_endpoint
    )]
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
    /// Notification configuration is intentionally file-only; adapter internals
    /// are not promoted back to flat process flags.
    #[arg(skip)]
    pub(crate) notifications: Option<NotificationConfig>,
    #[arg(long = "assume-valid-height")]
    pub(crate) assume_valid_height: Option<u32>,
}

impl UserConfig {
    pub(crate) fn apply_to(&self, config: &mut NodeConfig) -> Result<()> {
        config.apply_layer(self)
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
                "BITCOIN_RS_NETWORK" => layer.network = Some(parse_network_selection(value)?),
                "BITCOIN_RS_P2P_MAGIC" => layer.p2p_magic = Some(parse_p2p_magic(value)?),
                "BITCOIN_RS_DATA_DIR" => layer.data_dir = Some(PathBuf::from(value)),
                "BITCOIN_RS_STORAGE_BACKEND" => layer.storage_backend = Some(value.to_owned()),
                "BITCOIN_RS_RPC_BIND" => layer.rpc_bind = Some(value.parse()?),
                "BITCOIN_RS_REST" => layer.rest = Some(parse_bool(value)?),
                "BITCOIN_RS_RPC_USER" => layer.rpc_user = Some(value.to_owned()),
                "BITCOIN_RS_RPC_PASSWORD" => layer.rpc_password = Some(value.to_owned()),
                "BITCOIN_RS_RPC_COOKIE" => layer.rpc_cookie = Some(PathBuf::from(value)),
                "BITCOIN_RS_SCRIPTINDEX" => layer.script_index = Some(value.to_owned()),
                "BITCOIN_RS_P2P_LISTEN" => layer.p2p_listen = Some(parse_socket_list(value)?),
                "BITCOIN_RS_DNS_SEEDS_ENABLED" => {
                    layer.dns_seeds_enabled = Some(parse_bool(value)?);
                }
                "BITCOIN_RS_CONNECT" => layer.connect = Some(parse_connect_list(value)?),
                "BITCOIN_RS_PRUNE_TARGET_MB" => layer.prune_target_mb = Some(value.parse()?),
                "BITCOIN_RS_TXINDEX" => layer.txindex = Some(parse_bool(value)?),
                "BITCOIN_RS_DBCACHE_MB" => layer.dbcache_mb = Some(value.parse()?),
                "BITCOIN_RS_LOG_LEVEL" => layer.log_level = Some(value.to_owned()),
                "BITCOIN_RS_METRICS_BIND" => layer.metrics_bind = Some(value.parse()?),
                "BITCOIN_RS_ASSUME_VALID_HEIGHT" => {
                    layer.assume_valid_height = Some(value.parse()?);
                }
                _ => {}
            }
        }
        Ok(layer)
    }
}

fn load_toml_layer(path: &Path) -> Result<UserConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    let layer = toml::from_str(&text)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
    Ok(layer)
}

fn effective_network(toml: Option<&UserConfig>, env: &UserConfig, cli: &UserConfig) -> Network {
    layer_network(cli)
        .or_else(|| layer_network(env))
        .or_else(|| toml.and_then(layer_network))
        .unwrap_or(Network::Mainnet)
}

fn layer_network(layer: &UserConfig) -> Option<Network> {
    layer.network.map(NetworkSelection::consensus_network)
}

fn parse_socket_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| Ok(part.trim().parse()?))
        .collect()
}

fn parse_connect_endpoint(value: &str) -> std::result::Result<String, String> {
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

fn parse_connect_list(value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_connect_endpoint(part.trim()).map_err(anyhow::Error::msg))
        .collect()
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}

fn parse_p2p_magic(value: &str) -> Result<[u8; 4]> {
    let value = value.trim();
    ensure!(
        value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "p2p magic must be exactly eight hexadecimal characters"
    );
    let mut magic = [0_u8; 4];
    for (index, slot) in magic.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16)?;
    }
    Ok(magic)
}

fn parse_network_selection(value: &str) -> anyhow::Result<NetworkSelection> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(NetworkSelection::Mainnet),
        "test" | "testnet" | "testnet3" => Ok(NetworkSelection::Testnet3),
        "testnet4" => Ok(NetworkSelection::Testnet4),
        "signet" => Ok(NetworkSelection::Signet),
        "regtest" => Ok(NetworkSelection::Regtest),
        "drynet4" => Ok(NetworkSelection::Drynet4),
        other => bail!("unknown network {other}"),
    }
}

fn deserialize_optional_p2p_magic<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<[u8; 4]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    raw.as_deref()
        .map(parse_p2p_magic)
        .transpose()
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Resolution applies the network profile exactly once: a resolved
    /// [`NodeConfig`] carries the network's P2P magic as a concrete
    /// `[u8; 4]`, never an unresolved `Option`.
    ///
    /// Mutation: delete the `self.p2p_magic = network.magic()` line in
    /// `default_for_network` (leaving `[0, 0, 0, 0]`). This test fails because
    /// the resolved magic no longer matches the network profile.
    #[test]
    fn resolve_applies_network_p2p_magic_exactly_once() {
        let config = NodeConfig::resolve(&UserConfig {
            network: Some(NetworkSelection::Testnet4),
            ..Default::default()
        })
        .expect("testnet4 with no overrides resolves");
        // The resolved magic is the network's own magic — the profile was
        // applied, not left as a default zero or an Option::None.
        assert_eq!(
            config.p2p_magic,
            Network::Testnet4.magic(),
            "resolution must apply the network P2P magic exactly once"
        );
        // A caller reading the resolved value gets a concrete array, not an
        // Option: the type system enforces this, and the value proves the
        // profile ran.
        assert_eq!(config.p2p_magic.len(), 4);
    }

    /// An explicit P2P magic override wins over the network profile applied in
    /// the same layer: the profile runs first, then the override replaces it.
    /// This is the "same-layer network selection precedes explicit low-level
    /// overrides" invariant.
    ///
    /// Mutation: in `apply_layer`, move the `p2p_magic` override block *before*
    /// the `apply_network_selection` call. The network profile then clobbers
    /// the override and this test fails.
    #[test]
    fn explicit_p2p_magic_override_wins_over_network_profile() {
        let custom: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let config = NodeConfig::resolve(&UserConfig {
            network: Some(NetworkSelection::Mainnet),
            p2p_magic: Some(custom),
            connect: Some(vec!["127.0.0.1:18444".to_owned()]),
            dns_seeds_enabled: Some(false),
            ..Default::default()
        })
        .expect("mainnet with explicit magic + connect resolves");
        assert_eq!(
            config.p2p_magic, custom,
            "explicit override must win over the network-profile magic"
        );
        assert_eq!(config.network, Network::Mainnet);
    }

    /// A resolved [`NodeConfig`] cannot carry an unresolved value: the P2P
    /// magic field is a concrete `[u8; 4]`, not an `Option`. Resolving the
    /// default (no network specified) still produces a fully resolved mainnet
    /// config.
    ///
    /// Mutation: revert `p2p_magic` to `Option<[u8; 4]>` and leave it `None` in
    /// `default_for_network`. This test fails to compile (the field is no
    /// longer `[u8; 4]`), proving the type-level guarantee bites.
    #[test]
    fn resolved_config_has_no_unresolved_p2p_magic() {
        let config =
            NodeConfig::resolve(&UserConfig::default()).expect("empty user config resolves");
        assert_eq!(config.p2p_magic, Network::Mainnet.magic());
        assert_eq!(config.network, Network::Mainnet);
    }

    /// `drynet4` resolves consensus and P2P identity atomically: mainnet
    /// consensus, a distinct P2P magic, DNS seeds disabled, and a fixed
    /// connect peer — all from the single network selection, with no partial
    /// identity possible.
    #[test]
    fn drynet4_resolves_atomic_identity() {
        let config = NodeConfig::resolve(&UserConfig {
            network: Some(NetworkSelection::Drynet4),
            ..Default::default()
        })
        .expect("drynet4 resolves");
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.p2p_magic, DRYNET4_P2P_MAGIC);
        assert!(!config.dns_seeds_enabled);
        assert_eq!(config.connect, vec![DRYNET4_CONNECT]);
    }

    /// `Auth::Debug` never exposes the password or cookie path.
    #[test]
    fn auth_debug_redacts_secrets() {
        let auth = Auth::basic("operator", "s3cret");
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("operator"));
        assert!(!rendered.contains("s3cret"));
        assert!(rendered.contains("<redacted>"));
    }
}
