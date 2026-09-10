//! Resolved configuration values consumed by node subsystems.

use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use serde::Deserialize;

use super::Auth;

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
