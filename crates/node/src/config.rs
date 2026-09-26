//! Node configuration DTOs, resolution, and validation.

use crate::options::{ChainstateJournalOverrides, UserConfig};
use anyhow::Result;
use bitcoin_rs_chainstate::{ChainstateJournalConfig, ValidationMode};
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use core::fmt;
use crossbeam_channel::Receiver;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

/// Node notification adapters, grouped below the node-level configuration.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    /// ZMQ PUB sockets, each owning its endpoint, topics, and optional HWM override.
    pub zmq: Vec<bitcoin_rs_rpc::zmq::ZmqEndpointConfig>,
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
///
/// [`Self::Utxo`] is the live-only selection; see `IDX-01`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum ScriptIndexMode {
    /// No `ScriptIndex` capability is maintained.
    #[default]
    Disabled,
    /// Compact live-output view only (`IDX-01`).
    Utxo,
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

    /// Derived-index capabilities this mode and txindex jointly enable.
    ///
    /// PRE: none.
    /// POST: one of `NONE`, `TX_LOOKUP`, `SCRIPT_LIVE`, `TX_LOOKUP_SCRIPT_LIVE`,
    /// `ALL`. Full always includes `TxLookup` regardless of txindex (Esplora
    /// prevout and fee rendering needs exact historical transactions); the
    /// RPC-visible `derived_index_query` gate still requires an explicit
    /// `--txindex`.
    /// INVARIANT: the match is exhaustive over `(bool, Self)`; an
    /// unreachable combination is not spellable from `crates/node`.
    #[must_use]
    pub const fn enabled_capabilities(self, txindex: bool) -> IndexCapabilities {
        match (txindex, self) {
            (false, Self::Disabled) => IndexCapabilities::NONE,
            (true, Self::Disabled) => IndexCapabilities::TX_LOOKUP,
            (false, Self::Utxo) => IndexCapabilities::SCRIPT_LIVE,
            (true, Self::Utxo) => IndexCapabilities::TX_LOOKUP_SCRIPT_LIVE,
            (_, Self::Full) => IndexCapabilities::ALL,
        }
    }

    /// Parses a mode from a configuration value.
    ///
    /// Accepts the historical boolean spellings for compatibility: `true`
    /// means `full` and `false` means disabled. Parsing is case-insensitive.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "utxo" => Some(Self::Utxo),
            // `true` is the historical boolean spelling and must keep meaning
            // `full`; it is a separate pattern for that readability, not a
            // distinct outcome.
            "full" | "true" | "1" | "yes" => Some(Self::Full),
            "false" | "0" | "no" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Applies one journal layer field by field onto the resolved settings.
fn apply_journal_overrides(
    layer: &ChainstateJournalOverrides,
    config: &mut ChainstateJournalConfig,
) {
    if let Some(enabled) = layer.enabled {
        config.enabled = enabled;
    }
    if let Some(blocks) = layer.blocks {
        config.blocks = blocks;
    }
    if let Some(seconds) = layer.seconds {
        config.seconds = seconds;
    }
    if let Some(rotate_mib) = layer.rotate_mib {
        config.rotate_mib = rotate_mib;
    }
    if let Some(max_journal_mib) = layer.max_journal_mib {
        config.max_journal_mib = max_journal_mib;
    }
    if let Some(max_lag_blocks) = layer.max_lag_blocks {
        config.max_lag_blocks = max_lag_blocks;
    }
    if let Some(max_lag_seconds) = layer.max_lag_seconds {
        config.max_lag_seconds = max_lag_seconds;
    }
}

const DEFAULT_STORAGE_BACKEND: StorageBackend = StorageBackend::Fjall;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_DBCACHE_MB: u64 = 450;

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
    /// Whether fast sync (shallow, early fan-out over a larger outbound set) is enabled.
    pub fast_sync: bool,
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
    /// Which script verification the apply path may skip.
    pub mode: ValidationMode,
}

/// Resolved mining configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MiningConfig {
    /// Coinbase `scriptPubKey` bytes. Empty means transport-only GBT assembly:
    /// the coordinator does not own a miner payout.
    pub payout_script: Vec<u8>,
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
    /// Mining settings.
    pub mining: MiningConfig,
}

impl NodeConfig {
    /// Returns resolved defaults for a network.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        Self::materialize(&UserConfig::default(), NetworkSelection::from(network))
    }

    /// Materializes the resolved settings from one folded layer.
    ///
    /// PRE: `settings` is the overlay of every source layer and `selection`
    /// is the network named by the highest-precedence layer that named one.
    /// POST: every field holds the operator's value, or the winning
    /// profile's value for a field no layer set.
    /// INVARIANT: a network selection never overwrites a field an operator
    /// set on any layer; it only fills the gaps (`ARCH-05`).
    fn materialize(settings: &UserConfig, selection: NetworkSelection) -> Self {
        let profile = NetworkProfile::for_selection(selection);
        let mut chainstate_journal = ChainstateJournalConfig::default();
        apply_journal_overrides(&settings.chainstate_journal, &mut chainstate_journal);
        Self {
            network: selection.consensus_network(),
            data_dir: settings
                .data_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".bitcoin-rs")),
            storage: StorageConfig {
                backend: settings.storage.backend.unwrap_or(DEFAULT_STORAGE_BACKEND),
                dbcache_mb: settings.storage.dbcache_mb.unwrap_or(DEFAULT_DBCACHE_MB),
                prune_target_mb: settings.storage.prune_target_mb.unwrap_or(0),
            },
            p2p: P2pConfig {
                magic: settings.p2p.magic.unwrap_or(profile.magic),
                listen: settings.p2p.listen.clone().unwrap_or(profile.listen),
                dns_seeds_enabled: settings.p2p.dns_seeds.unwrap_or(profile.dns_seeds),
                connect: settings.p2p.connect.clone().unwrap_or(profile.connect),
                fast_sync: settings.p2p.fast_sync.unwrap_or(false),
            },
            rpc: RpcConfig {
                bind: settings.rpc.bind.unwrap_or(profile.rpc_bind),
                rest: settings.rpc.rest.unwrap_or(false),
                auth: rpc_auth(settings),
            },
            indexes: IndexConfig {
                txindex: settings.indexes.txindex.unwrap_or(false),
                script_index: settings
                    .indexes
                    .script_index
                    .unwrap_or(ScriptIndexMode::Disabled),
            },
            observability: ObservabilityConfig {
                log_level: settings
                    .observability
                    .log_level
                    .clone()
                    .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_owned()),
                metrics_bind: settings.observability.metrics_bind,
            },
            notifications: settings.notifications.clone().unwrap_or_default(),
            chainstate_journal,
            validation: ValidationConfig {
                assume_valid_height: settings
                    .validation
                    .assume_valid_height
                    .unwrap_or(profile.assume_valid_height),
                mode: settings
                    .validation
                    .mode
                    .unwrap_or(ValidationMode::AssumeValid),
            },
            mining: MiningConfig::default(),
        }
    }

    /// Returns configured ZMQ endpoint groups.
    #[must_use]
    pub fn zmq_endpoints(&self) -> &[bitcoin_rs_rpc::zmq::ZmqEndpointConfig] {
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
        bitcoin_rs_rpc::zmq::validate_endpoint_configs(&self.notifications.zmq)?;
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
}

/// Resolves layers from lowest to highest precedence.
///
/// The layers fold field-wise into one set of settings, the winning network
/// selection fills the profile-owned fields no layer set, and the mining
/// payout decodes once against that resolved network.
pub fn resolve(layers: &[&UserConfig]) -> Result<NodeConfig> {
    let mut settings = UserConfig::default();
    for layer in layers {
        settings.overlay(layer);
    }
    let selection = settings.network.unwrap_or(NetworkSelection::Mainnet);
    let mut config = NodeConfig::materialize(&settings, selection);
    if let Some(address) = settings.mining.payout_address {
        config.mining.payout_script = decode_payout_script(config.network, &address)?;
    }
    config.validate()?;
    Ok(config)
}

/// Resolves the RPC authentication mode from the folded auth group.
///
/// PRE: `UserConfig::overlay` kept the group coherent: a cookie path and
/// basic credentials are never both set.
/// POST: a cookie path selects cookie auth; otherwise the two basic halves
/// fall back to the built-in credentials.
fn rpc_auth(settings: &UserConfig) -> Auth {
    if let Some(path) = &settings.rpc.cookie {
        return Auth::Cookie { path: path.clone() };
    }
    Auth::basic(
        settings.rpc.user.as_deref().unwrap_or(DEFAULT_RPC_USER),
        settings
            .rpc
            .password
            .as_deref()
            .unwrap_or(DEFAULT_RPC_PASSWORD),
    )
}

/// The P2P bootstrap, RPC bind, and assume-valid values one network
/// selection owns. A selection supplies these only for fields no operator
/// layer set.
struct NetworkProfile {
    magic: [u8; 4],
    listen: Vec<SocketAddr>,
    dns_seeds: bool,
    connect: Vec<String>,
    rpc_bind: SocketAddr,
    assume_valid_height: u32,
}

impl NetworkProfile {
    fn for_selection(selection: NetworkSelection) -> Self {
        let network = selection.consensus_network();
        let drynet4 = selection == NetworkSelection::Drynet4;
        Self {
            magic: if drynet4 {
                DRYNET4_P2P_MAGIC
            } else {
                network.magic()
            },
            listen: vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))],
            dns_seeds: !drynet4,
            connect: if drynet4 {
                vec![DRYNET4_CONNECT.to_owned()]
            } else {
                Vec::new()
            },
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port())),
            assume_valid_height: network
                .assume_valid_anchor()
                .map_or(0, |(height, _)| height),
        }
    }
}

fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet3 => bitcoin::Network::Testnet,
        Network::Testnet4 => bitcoin::Network::Testnet4,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

fn decode_payout_script(network: Network, address: &str) -> Result<Vec<u8>> {
    use std::str::FromStr as _;

    let parsed = bitcoin::Address::from_str(address)
        .map_err(|err| anyhow::anyhow!("invalid mining payout address: {err}"))?;
    let checked = parsed
        .require_network(bitcoin_network(network))
        .map_err(|err| {
            anyhow::anyhow!(
                "mining payout address is not valid for {}: {err}",
                network.identity_name()
            )
        })?;
    Ok(checked.script_pubkey().as_bytes().to_vec())
}

const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";

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

pub(super) const DRYNET4_CONNECT: &str = "drynet4.drivechain.dev:8533";
pub(super) const DRYNET4_P2P_MAGIC: [u8; 4] = [0xec, 0xa5, 0xd4, 0x04];

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
#[path = "../tests/unit/config/tests.rs"]
mod tests;
