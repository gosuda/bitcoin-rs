//! Node configuration DTOs, resolution, and validation.

use core::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use crossbeam_channel::Receiver;
use serde::Deserialize;

const DEFAULT_STORAGE_BACKEND: StorageBackend = StorageBackend::Fjall;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";
const DEFAULT_DBCACHE_MB: u64 = 450;
const DRYNET4_CONNECT: &str = "drynet4.drivechain.dev:8533";
const DRYNET4_P2P_MAGIC: [u8; 4] = [0xec, 0xa5, 0xd4, 0x04];

/// A built-in node network and its associated P2P bootstrap profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkSelection {
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
    /// Parses the accepted network spellings.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "main" | "mainnet" | "bitcoin" => Some(Self::Mainnet),
            "test" | "testnet" | "testnet3" => Some(Self::Testnet3),
            "testnet4" => Some(Self::Testnet4),
            "signet" => Some(Self::Signet),
            "regtest" => Some(Self::Regtest),
            "drynet4" => Some(Self::Drynet4),
            _ => None,
        }
    }

    /// Returns the consensus network selected by this profile.
    #[must_use]
    pub const fn consensus_network(self) -> Network {
        match self {
            Self::Mainnet | Self::Drynet4 => Network::Mainnet,
            Self::Testnet3 => Network::Testnet3,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

impl FromStr for NetworkSelection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("unknown network {value}"))
    }
}

impl From<Network> for NetworkSelection {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::Mainnet,
            Network::Testnet3 => Self::Testnet3,
            Network::Testnet4 => Self::Testnet4,
            Network::Signet => Self::Signet,
            Network::Regtest => Self::Regtest,
        }
    }
}

/// RPC authentication configuration.
#[derive(Clone, Eq, PartialEq)]
pub enum Auth {
    /// HTTP Basic credentials.
    Basic {
        /// RPC username.
        user: String,
        /// RPC password.
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
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
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
    #[must_use]
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

/// User-supplied storage overrides.
#[derive(Clone, Debug, Default)]
pub struct StorageOverrides {
    /// Selected storage backend.
    pub backend: Option<StorageBackend>,
    /// Database cache budget in MiB.
    pub dbcache_mb: Option<u64>,
    /// Pruning target in MiB.
    pub prune_target_mb: Option<u64>,
}

/// User-supplied P2P overrides.
#[derive(Clone, Debug, Default)]
pub struct P2pOverrides {
    /// P2P message-start bytes.
    pub magic: Option<[u8; 4]>,
    /// P2P listener bind addresses.
    pub listen: Option<Vec<SocketAddr>>,
    /// Whether DNS seeds are enabled.
    pub dns_seeds: Option<bool>,
    /// Fixed outbound peer endpoints.
    pub connect: Option<Vec<String>>,
}

/// User-supplied RPC overrides.
#[derive(Clone, Debug, Default)]
pub struct RpcOverrides {
    /// JSON-RPC bind address.
    pub bind: Option<SocketAddr>,
    /// Whether the REST gateway is enabled.
    pub rest: Option<bool>,
    /// Basic-auth username.
    pub user: Option<String>,
    /// Basic-auth password.
    pub password: Option<String>,
    /// Cookie-auth path.
    pub cookie: Option<PathBuf>,
}

/// User-supplied index overrides.
#[derive(Clone, Debug, Default)]
pub struct IndexOverrides {
    /// Whether the transaction index is enabled.
    pub txindex: Option<bool>,
    /// Script index mode.
    pub script_index: Option<ScriptIndexMode>,
}

/// User-supplied observability overrides.
#[derive(Clone, Debug, Default)]
pub struct ObservabilityOverrides {
    /// Tracing filter level.
    pub log_level: Option<String>,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
}

/// User-supplied validation overrides.
#[derive(Clone, Debug, Default)]
pub struct ValidationOverrides {
    /// Height through which script verification may be skipped.
    pub assume_valid_height: Option<u32>,
}

/// User-supplied chainstate journal overrides.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ChainstateJournalOverrides {
    /// Whether the journal is active.
    pub enabled: Option<bool>,
    /// Durability batch size, in blocks.
    pub blocks: Option<u32>,
    /// Durability batch period, in seconds.
    pub seconds: Option<u64>,
    /// Active-segment rotation threshold, in MiB.
    pub rotate_mib: Option<u64>,
    /// Total-journal retention bound, in MiB.
    pub max_journal_mib: Option<u64>,
    /// Backpressure threshold, in blocks.
    pub max_lag_blocks: Option<u32>,
    /// Backpressure threshold, in seconds.
    pub max_lag_seconds: Option<u64>,
}

impl ChainstateJournalOverrides {
    fn apply_to(self, config: &mut ChainstateJournalConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(blocks) = self.blocks {
            config.blocks = blocks;
        }
        if let Some(seconds) = self.seconds {
            config.seconds = seconds;
        }
        if let Some(rotate_mib) = self.rotate_mib {
            config.rotate_mib = rotate_mib;
        }
        if let Some(max_journal_mib) = self.max_journal_mib {
            config.max_journal_mib = max_journal_mib;
        }
        if let Some(max_lag_blocks) = self.max_lag_blocks {
            config.max_lag_blocks = max_lag_blocks;
        }
        if let Some(max_lag_seconds) = self.max_lag_seconds {
            config.max_lag_seconds = max_lag_seconds;
        }
    }
}

/// Chainstate journal settings (`[chainstate_journal]`, issue #230).
///
/// The journal bounds crash-recovery work between checkpoint publications:
/// instead of re-validating the whole chain, boot replays only the records
/// the durable head covers. `enabled = false` restores the checkpoint-only
/// recovery behavior exactly as it was before the journal existed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainstateJournalConfig {
    /// Whether the journal is active. `false` = checkpoint-only recovery.
    pub enabled: bool,
    /// Durability batch size, in blocks (head advances at least this often).
    pub blocks: u32,
    /// Durability batch period, in seconds (time-based boundary trigger).
    pub seconds: u64,
    /// Active-segment rotation threshold, in MiB.
    pub rotate_mib: u64,
    /// Retention bound on total journal size, in MiB.
    pub max_journal_mib: u64,
    /// Backpressure threshold: max blocks applied beyond the durable head.
    pub max_lag_blocks: u32,
    /// Backpressure threshold: max seconds the head may lag the applied tip.
    pub max_lag_seconds: u64,
}

impl Default for ChainstateJournalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocks: 500,
            seconds: 5,
            rotate_mib: 256,
            max_journal_mib: 2048,
            max_lag_blocks: 500,
            max_lag_seconds: 30,
        }
    }
}

/// A parser-independent source layer.
#[derive(Clone, Debug, Default)]
pub struct UserConfig {
    /// Network profile.
    pub network: Option<NetworkSelection>,
    /// Node data directory.
    pub data_dir: Option<PathBuf>,
    /// Storage settings.
    pub storage: StorageOverrides,
    /// P2P settings.
    pub p2p: P2pOverrides,
    /// RPC settings.
    pub rpc: RpcOverrides,
    /// Index settings.
    pub indexes: IndexOverrides,
    /// Logging and metrics settings.
    pub observability: ObservabilityOverrides,
    /// Notification adapters. `None` means this layer does not speak to them.
    pub notifications: Option<NotificationConfig>,
    /// Chainstate journal settings. `None` means this layer does not speak to them.
    pub chainstate_journal: Option<ChainstateJournalOverrides>,
    /// Validation settings.
    pub validation: ValidationOverrides,
}

/// Resolved storage configuration.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Selected storage backend.
    pub backend: StorageBackend,
    /// Database cache budget in MiB.
    pub dbcache_mb: u64,
    /// Pruning target in MiB.
    pub prune_target_mb: u64,
}

/// Resolved P2P configuration.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// P2P message-start bytes.
    pub magic: [u8; 4],
    /// P2P listener bind addresses.
    pub listen: Vec<SocketAddr>,
    /// Whether DNS seeds are enabled.
    pub dns_seeds_enabled: bool,
    /// Fixed outbound peer endpoints.
    pub connect: Vec<String>,
}

/// Resolved RPC configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// JSON-RPC bind address.
    pub bind: SocketAddr,
    /// Whether REST is enabled.
    pub rest: bool,
    /// RPC authentication.
    pub auth: Auth,
}

/// Resolved index configuration.
#[derive(Clone, Debug)]
pub struct IndexConfig {
    /// Whether txindex is enabled.
    pub txindex: bool,
    /// Script index mode.
    pub script_index: ScriptIndexMode,
}

/// Resolved observability configuration.
#[derive(Clone, Debug)]
pub struct ObservabilityConfig {
    /// Tracing filter level.
    pub log_level: String,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
}

/// Resolved validation configuration.
#[derive(Clone, Debug)]
pub struct ValidationConfig {
    /// Height through which script verification may be skipped.
    pub assume_valid_height: u32,
}

/// Fully resolved, validated node configuration consumed by the runtime.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Consensus network.
    pub network: Network,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Storage settings.
    pub storage: StorageConfig,
    /// P2P settings.
    pub p2p: P2pConfig,
    /// RPC settings.
    pub rpc: RpcConfig,
    /// Index settings.
    pub indexes: IndexConfig,
    /// Logging and metrics settings.
    pub observability: ObservabilityConfig,
    /// External notification adapters.
    pub notifications: NotificationConfig,
    /// Chainstate journal settings.
    pub chainstate_journal: ChainstateJournalConfig,
    /// Validation settings.
    pub validation: ValidationConfig,
}

impl NodeConfig {
    /// Returns resolved defaults for a network.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        let mut config = Self {
            network: Network::Mainnet,
            data_dir: PathBuf::from(".bitcoin-rs"),
            storage: StorageConfig {
                backend: DEFAULT_STORAGE_BACKEND,
                dbcache_mb: DEFAULT_DBCACHE_MB,
                prune_target_mb: 0,
            },
            p2p: P2pConfig {
                magic: Network::Mainnet.magic(),
                listen: Vec::new(),
                dns_seeds_enabled: true,
                connect: Vec::new(),
            },
            rpc: RpcConfig {
                bind: SocketAddr::from(([127, 0, 0, 1], Network::Mainnet.default_rpc_port())),
                rest: false,
                auth: Auth::default(),
            },
            indexes: IndexConfig {
                txindex: false,
                script_index: ScriptIndexMode::Disabled,
            },
            observability: ObservabilityConfig {
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                metrics_bind: None,
            },
            notifications: NotificationConfig::default(),
            chainstate_journal: ChainstateJournalConfig::default(),
            validation: ValidationConfig {
                assume_valid_height: 0,
            },
        };
        config.apply_network_selection(NetworkSelection::from(network));
        config
    }

    /// Resolves one source layer.
    pub fn resolve(user: &UserConfig) -> Result<Self> {
        resolve(&[user])
    }

    /// Returns configured ZMQ endpoint groups.
    #[must_use]
    pub fn zmq_endpoints(&self) -> &[crate::zmq_publisher::ZmqEndpointConfig] {
        &self.notifications.zmq
    }

    /// Validates backend availability and cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.storage.backend.is_compiled_in(),
            "unsupported storage backend {}",
            self.storage.backend
        );
        if self.p2p.magic != self.network.magic() {
            anyhow::ensure!(
                self.network == Network::Mainnet,
                "P2P magic overrides currently require --network mainnet"
            );
            anyhow::ensure!(
                !self.p2p.connect.is_empty(),
                "P2P magic overrides require at least one --connect peer"
            );
            anyhow::ensure!(
                !self.p2p.dns_seeds_enabled,
                "P2P magic overrides require --dns-seeds-enabled=false"
            );
        }
        crate::zmq_publisher::validate_endpoint_configs(&self.notifications.zmq)?;
        let journal = &self.chainstate_journal;
        anyhow::ensure!(
            journal.blocks > 0,
            "chainstate_journal.blocks must be positive"
        );
        anyhow::ensure!(
            journal.seconds > 0,
            "chainstate_journal.seconds must be positive"
        );
        anyhow::ensure!(
            journal.rotate_mib > 0,
            "chainstate_journal.rotate_mib must be positive"
        );
        anyhow::ensure!(
            journal.max_journal_mib >= journal.rotate_mib,
            "chainstate_journal.max_journal_mib must be >= rotate_mib"
        );
        anyhow::ensure!(
            journal.max_lag_blocks >= journal.blocks,
            "chainstate_journal.max_lag_blocks must be >= blocks"
        );
        anyhow::ensure!(
            journal.max_lag_seconds > 0,
            "chainstate_journal.max_lag_seconds must be positive"
        );
        Ok(())
    }

    fn apply_layer(&mut self, layer: &UserConfig) {
        if let Some(network) = layer.network {
            self.apply_network_selection(network);
        }
        if let Some(magic) = layer.p2p.magic {
            self.p2p.magic = magic;
        }
        if let Some(data_dir) = &layer.data_dir {
            self.data_dir.clone_from(data_dir);
        }
        if let Some(backend) = layer.storage.backend {
            self.storage.backend = backend;
        }
        if let Some(value) = layer.storage.dbcache_mb {
            self.storage.dbcache_mb = value;
        }
        if let Some(value) = layer.storage.prune_target_mb {
            self.storage.prune_target_mb = value;
        }
        if let Some(bind) = layer.rpc.bind {
            self.rpc.bind = bind;
        }
        if let Some(rest) = layer.rpc.rest {
            self.rpc.rest = rest;
        }
        if let Some(path) = &layer.rpc.cookie {
            self.rpc.auth = Auth::Cookie { path: path.clone() };
        } else if layer.rpc.user.is_some() || layer.rpc.password.is_some() {
            let (old_user, old_password) = self.rpc.auth.basic_parts();
            self.rpc.auth = Auth::basic(
                layer.rpc.user.clone().unwrap_or(old_user),
                layer.rpc.password.clone().unwrap_or(old_password),
            );
        }
        if let Some(value) = layer.indexes.txindex {
            self.indexes.txindex = value;
        }
        if let Some(value) = layer.indexes.script_index {
            self.indexes.script_index = value;
        }
        if let Some(value) = &layer.observability.log_level {
            self.observability.log_level.clone_from(value);
        }
        if let Some(value) = layer.observability.metrics_bind {
            self.observability.metrics_bind = Some(value);
        }
        if let Some(value) = &layer.p2p.listen {
            self.p2p.listen.clone_from(value);
        }
        if let Some(value) = layer.p2p.dns_seeds {
            self.p2p.dns_seeds_enabled = value;
        }
        if let Some(value) = &layer.p2p.connect {
            self.p2p.connect.clone_from(value);
        }
        if let Some(notifications) = &layer.notifications {
            self.notifications.clone_from(notifications);
        }
        if let Some(journal) = layer.chainstate_journal {
            journal.apply_to(&mut self.chainstate_journal);
        }
        if let Some(value) = layer.validation.assume_valid_height {
            self.validation.assume_valid_height = value;
        }
    }

    fn apply_network_selection(&mut self, selection: NetworkSelection) {
        let network = selection.consensus_network();
        self.network = network;
        self.p2p.magic = network.magic();
        self.rpc.bind = SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port()));
        self.p2p.listen = vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))];
        self.p2p.dns_seeds_enabled = true;
        self.p2p.connect.clear();
        self.validation.assume_valid_height = network
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height);
        if selection == NetworkSelection::Drynet4 {
            self.p2p.magic = DRYNET4_P2P_MAGIC;
            self.p2p.dns_seeds_enabled = false;
            self.p2p.connect = vec![DRYNET4_CONNECT.to_owned()];
        }
    }
}

/// Resolves layers from lowest to highest precedence.
pub fn resolve(layers: &[&UserConfig]) -> Result<NodeConfig> {
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    for layer in layers {
        config.apply_layer(layer);
    }
    config.validate()?;
    Ok(config)
}

/// Process and test dependencies that are not configuration.
#[derive(Default)]
pub struct RuntimeInputs {
    /// Optional in-process shutdown notification receiver.
    pub shutdown: Option<Receiver<()>>,
    /// Optional test-only mempool observer.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_secrets() {
        let auth = Auth::basic("operator", "s3cret");
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("operator"));
        assert!(!rendered.contains("s3cret"));
        assert!(rendered.contains("<redacted>"));

        let auth = Auth::Cookie {
            path: PathBuf::from("/secret/.cookie"),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("/secret/.cookie"));
        assert!(rendered.contains("<redacted>"));
    }
}
