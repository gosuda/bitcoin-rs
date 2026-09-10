//! Parser-independent source layers and their merge semantics.

use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin_rs_storage::StorageBackend;

use super::{ChainstateJournalOverrides, NetworkSelection, NotificationConfig, ScriptIndexMode};

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

/// User-supplied mining overrides.
#[derive(Clone, Debug, Default)]
pub struct MiningOverrides {
    /// Watch-only coinbase payout address. Decoded after every config layer
    /// has been applied, against the resolved consensus network.
    pub payout_address: Option<String>,
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

impl StorageOverrides {
    fn overlay(&mut self, other: &Self) {
        if other.backend.is_some() {
            self.backend = other.backend;
        }
        if other.dbcache_mb.is_some() {
            self.dbcache_mb = other.dbcache_mb;
        }
        if other.prune_target_mb.is_some() {
            self.prune_target_mb = other.prune_target_mb;
        }
    }
}

impl P2pOverrides {
    fn overlay(&mut self, other: &Self) {
        if other.magic.is_some() {
            self.magic = other.magic;
        }
        if other.listen.is_some() {
            self.listen.clone_from(&other.listen);
        }
        if other.dns_seeds.is_some() {
            self.dns_seeds = other.dns_seeds;
        }
        if other.connect.is_some() {
            self.connect.clone_from(&other.connect);
        }
    }
}

impl RpcOverrides {
    fn overlay(&mut self, other: &Self) {
        if other.bind.is_some() {
            self.bind = other.bind;
        }
        if other.rest.is_some() {
            self.rest = other.rest;
        }
        if other.user.is_some() {
            self.user.clone_from(&other.user);
        }
        if other.password.is_some() {
            self.password.clone_from(&other.password);
        }
        if other.cookie.is_some() {
            self.cookie.clone_from(&other.cookie);
        }
    }
}

impl IndexOverrides {
    fn overlay(&mut self, other: &Self) {
        if other.txindex.is_some() {
            self.txindex = other.txindex;
        }
        if other.script_index.is_some() {
            self.script_index = other.script_index;
        }
    }
}

impl ObservabilityOverrides {
    fn overlay(&mut self, other: &Self) {
        if other.log_level.is_some() {
            self.log_level.clone_from(&other.log_level);
        }
        if other.metrics_bind.is_some() {
            self.metrics_bind = other.metrics_bind;
        }
    }
}

impl ValidationOverrides {
    fn overlay(&mut self, other: &Self) {
        if other.assume_valid_height.is_some() {
            self.assume_valid_height = other.assume_valid_height;
        }
    }
}

impl MiningOverrides {
    pub(super) fn overlay(&mut self, other: &Self) {
        if other.payout_address.is_some() {
            self.payout_address.clone_from(&other.payout_address);
        }
    }
}

impl UserConfig {
    /// Applies set fields from `other` over this layer. `other` wins.
    pub fn overlay(&mut self, other: &Self) {
        if other.network.is_some() {
            self.network = other.network;
        }
        if other.data_dir.is_some() {
            self.data_dir.clone_from(&other.data_dir);
        }
        self.storage.overlay(&other.storage);
        self.p2p.overlay(&other.p2p);
        self.rpc.overlay(&other.rpc);
        self.indexes.overlay(&other.indexes);
        self.observability.overlay(&other.observability);
        if other.notifications.is_some() {
            self.notifications.clone_from(&other.notifications);
        }
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
