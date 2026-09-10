//! Resolved runtime settings, network defaults, and cross-field validation.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use serde::Deserialize;

use super::{
    Auth, ChainstateJournalConfig, NetworkSelection, ScriptIndexMode, UserConfig, resolve,
};

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
        self.chainstate_journal.validate()
    }
}
