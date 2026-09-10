//! Parser-independent input layers and last-set-field-wins merging.

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

impl UserConfig {
    /// Applies set fields from `other` over this layer. `other` wins.
    pub fn overlay(&mut self, other: &Self) {
        overlay_some(&mut self.network, &other.network);
        overlay_some(&mut self.data_dir, &other.data_dir);
        overlay_some(&mut self.storage.backend, &other.storage.backend);
        overlay_some(&mut self.storage.dbcache_mb, &other.storage.dbcache_mb);
        overlay_some(
            &mut self.storage.prune_target_mb,
            &other.storage.prune_target_mb,
        );
        overlay_some(&mut self.p2p.magic, &other.p2p.magic);
        overlay_some(&mut self.p2p.listen, &other.p2p.listen);
        overlay_some(&mut self.p2p.dns_seeds, &other.p2p.dns_seeds);
        overlay_some(&mut self.p2p.connect, &other.p2p.connect);
        overlay_some(&mut self.rpc.bind, &other.rpc.bind);
        overlay_some(&mut self.rpc.rest, &other.rpc.rest);
        overlay_some(&mut self.rpc.user, &other.rpc.user);
        overlay_some(&mut self.rpc.password, &other.rpc.password);
        overlay_some(&mut self.rpc.cookie, &other.rpc.cookie);
        overlay_some(&mut self.indexes.txindex, &other.indexes.txindex);
        overlay_some(&mut self.indexes.script_index, &other.indexes.script_index);
        overlay_some(
            &mut self.observability.log_level,
            &other.observability.log_level,
        );
        overlay_some(
            &mut self.observability.metrics_bind,
            &other.observability.metrics_bind,
        );
        overlay_some(&mut self.notifications, &other.notifications);
        if let Some(other_journal) = other.chainstate_journal {
            if let Some(journal) = &mut self.chainstate_journal {
                journal.overlay(&other_journal);
            } else {
                self.chainstate_journal = Some(other_journal);
            }
        }
        overlay_some(
            &mut self.validation.assume_valid_height,
            &other.validation.assume_valid_height,
        );
        overlay_some(
            &mut self.mining.payout_address,
            &other.mining.payout_address,
        );
    }
}

/// An absent field is not an instruction to clear a lower-precedence value.
/// In particular, `Some(false)`, `Some(0)`, and `Some(Vec::new())` still win.
pub(super) fn overlay_some<T: Clone>(target: &mut Option<T>, source: &Option<T>) {
    if source.is_some() {
        target.clone_from(source);
    }
}
