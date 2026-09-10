//! Parser-independent source layers and last-set-value-wins merging.

use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin_rs_storage::StorageBackend;
use serde::Deserialize;

use super::{ChainstateJournalConfig, NetworkSelection, NotificationConfig, ScriptIndexMode};

/// Copies a value only when the incoming layer actually specifies it.
/// Explicit `false`, zero, and empty collections are values, not absence.
fn overlay_field<T: Clone>(target: &mut Option<T>, source: &Option<T>) {
    if source.is_some() {
        target.clone_from(source);
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

impl StorageOverrides {
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.backend, &other.backend);
        overlay_field(&mut self.dbcache_mb, &other.dbcache_mb);
        overlay_field(&mut self.prune_target_mb, &other.prune_target_mb);
    }
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

impl P2pOverrides {
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.magic, &other.magic);
        overlay_field(&mut self.listen, &other.listen);
        overlay_field(&mut self.dns_seeds, &other.dns_seeds);
        overlay_field(&mut self.connect, &other.connect);
    }
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

impl RpcOverrides {
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.bind, &other.bind);
        overlay_field(&mut self.rest, &other.rest);
        overlay_field(&mut self.user, &other.user);
        overlay_field(&mut self.password, &other.password);
        overlay_field(&mut self.cookie, &other.cookie);
    }
}

/// User-supplied index overrides.
#[derive(Clone, Debug, Default)]
pub struct IndexOverrides {
    /// Whether the transaction index is enabled.
    pub txindex: Option<bool>,
    /// Script index mode.
    pub script_index: Option<ScriptIndexMode>,
}

impl IndexOverrides {
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.txindex, &other.txindex);
        overlay_field(&mut self.script_index, &other.script_index);
    }
}

/// User-supplied observability overrides.
#[derive(Clone, Debug, Default)]
pub struct ObservabilityOverrides {
    /// Tracing filter level.
    pub log_level: Option<String>,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
}

impl ObservabilityOverrides {
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.log_level, &other.log_level);
        overlay_field(&mut self.metrics_bind, &other.metrics_bind);
    }
}

/// User-supplied validation overrides.
#[derive(Clone, Debug, Default)]
pub struct ValidationOverrides {
    /// Height through which script verification may be skipped.
    pub assume_valid_height: Option<u32>,
}

impl ValidationOverrides {
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.assume_valid_height, &other.assume_valid_height);
    }
}

/// User-supplied mining overrides.
#[derive(Clone, Debug, Default)]
pub struct MiningOverrides {
    /// Watch-only coinbase payout address. Decoded after every config layer
    /// has been applied, against the resolved consensus network.
    pub payout_address: Option<String>,
}

impl MiningOverrides {
    pub(super) fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.payout_address, &other.payout_address);
    }
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
    fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.enabled, &other.enabled);
        overlay_field(&mut self.blocks, &other.blocks);
        overlay_field(&mut self.seconds, &other.seconds);
        overlay_field(&mut self.rotate_mib, &other.rotate_mib);
        overlay_field(&mut self.max_journal_mib, &other.max_journal_mib);
        overlay_field(&mut self.max_lag_blocks, &other.max_lag_blocks);
        overlay_field(&mut self.max_lag_seconds, &other.max_lag_seconds);
    }

    pub(super) fn apply_to(self, config: &mut ChainstateJournalConfig) {
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
    /// Mining settings.
    pub mining: MiningOverrides,
}

impl UserConfig {
    /// Applies set fields from `other` over this layer. `other` wins.
    pub fn overlay(&mut self, other: &Self) {
        overlay_field(&mut self.network, &other.network);
        overlay_field(&mut self.data_dir, &other.data_dir);
        self.storage.overlay(&other.storage);
        self.p2p.overlay(&other.p2p);
        self.rpc.overlay(&other.rpc);
        self.indexes.overlay(&other.indexes);
        self.observability.overlay(&other.observability);
        overlay_field(&mut self.notifications, &other.notifications);
        if let Some(other_journal) = other.chainstate_journal {
            if let Some(journal) = &mut self.chainstate_journal {
                journal.overlay(&other_journal);
            } else {
                self.chainstate_journal = Some(other_journal);
            }
        }
        self.validation.overlay(&other.validation);
        self.mining.overlay(&other.mining);
    }
}
