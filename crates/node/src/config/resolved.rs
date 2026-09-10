//! Resolved node settings, network defaults, and cross-field validation.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use serde::Deserialize;

use super::network::{DRYNET4_CONNECT, DRYNET4_P2P_MAGIC};
use super::{Auth, ChainstateJournalConfig, MiningOverrides, NetworkSelection, UserConfig};

const DEFAULT_STORAGE_BACKEND: StorageBackend = StorageBackend::Fjall;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_DBCACHE_MB: u64 = 450;

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
            mining: MiningConfig::default(),
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
    let mut mining = MiningOverrides::default();
    for layer in layers {
        mining.overlay(&layer.mining);
    }
    if let Some(address) = mining.payout_address.as_deref() {
        config.mining.payout_script = decode_payout_script(config.network, address)?;
    }
    config.validate()?;
    Ok(config)
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
