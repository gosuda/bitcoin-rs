//! Node configuration DTOs, resolution, and validation.

use crate::options::{ChainstateJournalOverrides, UserConfig, check_index_bundle_path};
use anyhow::Result;
use bitcoin_rs_chainstate::{ChainstateJournalConfig, ValidationMode};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_index::IndexCapabilities;
#[cfg(feature = "pool")]
use bitcoin_rs_mining::pool::ledger as pool_ledger;
use bitcoin_rs_p2p::endpoint::{ClassifiedEndpoint, classify_endpoint};
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use core::fmt;
use crossbeam_channel::Receiver;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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

    /// Derived-index capabilities this mode and txindex jointly enable.
    ///
    /// PRE: none.
    /// POST: one of `NONE`, `TX_LOOKUP`, `SCRIPT_LIVE`, `TX_LOOKUP_SCRIPT_LIVE`,
    /// `TX_AND_SCRIPTS`. Full always includes `TxLookup` regardless of txindex (Esplora
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
            (_, Self::Full) => IndexCapabilities::TX_AND_SCRIPTS,
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

/// Resolved noncustodial pool policy. No path is opened during resolution.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Dedicated ledger directory.
    pub datadir: PathBuf,
    /// Explicit SV1 listener, if enabled.
    pub v1_bind: Option<SocketAddr>,
    /// Explicit SV2 listener, if enabled.
    pub sv2_bind: Option<SocketAddr>,
    /// Authority key path, validated only by the service.
    pub sv2_authority_key: Option<PathBuf>,
    /// Operator consent to non-loopback listeners.
    pub allow_non_loopback: bool,
    /// Shared connection limit.
    pub max_connections: u32,
    /// Shared per-IP connection limit.
    pub max_connections_per_ip: u32,
    /// Fixed exact decimal share difficulty.
    pub share_difficulty: String,
    /// Target resolved by the authoritative share arithmetic owner.
    #[cfg(feature = "pool")]
    pub share_target: bitcoin_rs_mining::pool::ShareTarget,
    /// Immutable PPLNS work window.
    pub window_work: u64,
    /// Immutable fee basis points.
    pub fee_bps: u16,
    /// Externally controlled reward scriptPubKey.
    pub reward_script: Vec<u8>,
    /// Coinbase confirmation requirement.
    pub maturity: u32,
    /// Payout confirmation requirement.
    pub payout_confirmations: u32,
    /// Depth of reorg monitoring.
    pub reorg_watch_depth: u32,
    /// Minimum payout in satoshis.
    pub min_payout_sat: u64,
    /// Maximum outputs per payout batch.
    pub max_payout_outputs: u32,
}

impl PoolConfig {
    /// Immutable ledger policy, shared by ledger creation and reopen validation.
    /// Abandon depth stays fixed at the ledger's six-confirmation default;
    /// dust stays at 546 satoshis and no signer change scripts are authorized.
    #[cfg(feature = "pool")]
    #[must_use]
    pub fn ledger_config(&self) -> pool_ledger::PoolConfig {
        let mut config =
            pool_ledger::PoolConfig::new(u128::from(self.window_work), self.reward_script.clone());
        config.pool_fee_bps = self.fee_bps;
        config.coinbase_maturity = self.maturity;
        config.payout_confirmations = self.payout_confirmations;
        config.reorg_watch_depth = self.reorg_watch_depth;
        config
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            cfg!(feature = "pool"),
            "--pool requires the pool build feature"
        );
        anyhow::ensure!(
            !self.datadir.as_os_str().is_empty(),
            "--pool-datadir must not be empty"
        );
        anyhow::ensure!(
            self.v1_bind.is_some() || self.sv2_bind.is_some(),
            "--pool requires an explicit --pool-v1-bind or --pool-sv2-bind"
        );
        anyhow::ensure!(
            self.v1_bind.is_none() || self.v1_bind != self.sv2_bind,
            "pool listener addresses must differ"
        );
        for bind in [self.v1_bind, self.sv2_bind].into_iter().flatten() {
            anyhow::ensure!(
                bind.port() != 0,
                "pool listener ports must be explicit and nonzero"
            );
            anyhow::ensure!(
                bind.ip().is_loopback() || self.allow_non_loopback,
                "non-loopback pool bind requires --pool-allow-non-loopback"
            );
        }
        anyhow::ensure!(
            self.sv2_bind.is_none() || cfg!(feature = "pool-sv2"),
            "SV2 requires the pool-sv2 build feature"
        );
        anyhow::ensure!(
            self.sv2_bind.is_some() == self.sv2_authority_key.is_some(),
            "--pool-sv2-bind and --pool-sv2-authority-key must be configured together"
        );
        anyhow::ensure!(
            self.sv2_authority_key
                .as_ref()
                .is_none_or(|path| !path.as_os_str().is_empty()),
            "pool SV2 authority key path must not be empty"
        );
        anyhow::ensure!(
            self.max_connections > 0
                && self.max_connections_per_ip > 0
                && self.max_connections_per_ip <= self.max_connections,
            "pool connection limits must be positive and per-IP must not exceed total"
        );
        anyhow::ensure!(
            usize::try_from(self.max_connections).is_ok()
                && usize::try_from(self.max_connections_per_ip).is_ok(),
            "pool connection limits exceed platform bounds"
        );
        anyhow::ensure!(self.window_work > 0, "--pool-window-work must be positive");
        anyhow::ensure!(
            self.fee_bps <= 10_000,
            "--pool-fee-bps must be at most 10000"
        );
        anyhow::ensure!(
            self.maturity >= 100 && self.payout_confirmations > 0,
            "pool maturity must be at least 100 and payout confirmations must be positive"
        );
        anyhow::ensure!(
            self.reorg_watch_depth >= self.maturity.max(self.payout_confirmations).max(6),
            "pool reorg watch depth must cover maturity, payout and abandon confirmations"
        );
        anyhow::ensure!(
            self.min_payout_sat >= 546 && self.min_payout_sat <= 2_100_000_000_000_000,
            "pool minimum payout must be between 546 and MAX_MONEY satoshis"
        );
        anyhow::ensure!(
            (1..=2500).contains(&self.max_payout_outputs),
            "pool maximum payout outputs must be in 1..=2500"
        );
        anyhow::ensure!(
            !self.reward_script.is_empty()
                && self.reward_script.len() <= 10_000
                && self.reward_script[0] != 0x6a,
            "pool reward script must be spendable and bounded"
        );
        anyhow::ensure!(
            bitcoin::Script::from_bytes(&self.reward_script)
                .instructions_minimal()
                .all(|instruction| instruction.is_ok()),
            "pool reward script must have canonical script encoding"
        );
        #[cfg(feature = "pool")]
        {
            self.ledger_config().validate()?;
            let target = bitcoin_rs_mining::pool::ShareTarget::from_pool_difficulty_decimal(
                &self.share_difficulty,
            )
            .map_err(|error| anyhow::anyhow!("invalid pool share difficulty: {error}"))?;
            anyhow::ensure!(
                target == self.share_target,
                "pool share target must match configured difficulty"
            );
        }
        Ok(())
    }
}

fn resolve_pool(settings: &UserConfig) -> Result<Option<PoolConfig>> {
    let pool = &settings.pool;
    if !pool.enabled.unwrap_or(false) {
        anyhow::ensure!(
            pool.datadir.is_none()
                && pool.v1_bind.is_none()
                && pool.sv2_bind.is_none()
                && pool.sv2_authority_key.is_none()
                && pool.allow_non_loopback.is_none()
                && pool.max_connections.is_none()
                && pool.max_connections_per_ip.is_none()
                && pool.share_difficulty.is_none()
                && pool.window_work.is_none()
                && pool.fee_bps.is_none()
                && pool.reward_script.is_none()
                && pool.maturity.is_none()
                && pool.payout_confirmations.is_none()
                && pool.reorg_watch_depth.is_none()
                && pool.min_payout_sat.is_none()
                && pool.max_payout_outputs.is_none(),
            "pool sub-options require --pool"
        );
        return Ok(None);
    }
    let reward = pool
        .reward_script
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--pool requires --pool-reward-script"))?;
    anyhow::ensure!(
        reward.len() <= 20_000 && reward.len().is_multiple_of(2),
        "pool reward script must be bounded even-length hex"
    );
    let (pairs, remainder) = reward.as_bytes().as_chunks::<2>();
    anyhow::ensure!(
        remainder.is_empty(),
        "pool reward script must be even-length hex"
    );
    let reward_script = pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => Ok(high * 16 + low),
                _ => Err(anyhow::anyhow!("pool reward script must be hex")),
            }
        })
        .collect::<Result<Vec<u8>>>()?;
    Ok(Some(PoolConfig {
        datadir: pool
            .datadir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--pool requires --pool-datadir"))?,
        v1_bind: pool.v1_bind,
        sv2_bind: pool.sv2_bind,
        sv2_authority_key: pool.sv2_authority_key.clone(),
        allow_non_loopback: pool.allow_non_loopback.unwrap_or(false),
        max_connections: pool.max_connections.unwrap_or(128),
        max_connections_per_ip: pool.max_connections_per_ip.unwrap_or(8),
        share_difficulty: pool
            .share_difficulty
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--pool requires --pool-share-difficulty"))?,
        #[cfg(feature = "pool")]
        share_target: bitcoin_rs_mining::pool::ShareTarget::from_pool_difficulty_decimal(
            pool.share_difficulty
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--pool requires --pool-share-difficulty"))?,
        )
        .map_err(|error| anyhow::anyhow!("invalid pool share difficulty: {error}"))?,
        window_work: pool
            .window_work
            .ok_or_else(|| anyhow::anyhow!("--pool requires --pool-window-work"))?,
        fee_bps: pool.fee_bps.unwrap_or(0),
        reward_script,
        maturity: pool.maturity.unwrap_or(100),
        payout_confirmations: pool.payout_confirmations.unwrap_or(6),
        reorg_watch_depth: pool.reorg_watch_depth.unwrap_or(1000),
        min_payout_sat: pool.min_payout_sat.unwrap_or(546),
        max_payout_outputs: pool.max_payout_outputs.unwrap_or(2500),
    }))
}

/// Resolved storage configuration.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub dbcache_mb: u64,
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
    /// Optional Bitcoin Core `ASMap` classifier file.
    pub asmap: Option<PathBuf>,
    /// Operator subnets exempt from automatic discouragement.
    pub noban_subnets: Vec<bitcoin_rs_p2p::IpSubnet>,
    /// Fixed outbound peer endpoints.
    pub connect: Vec<String>,
    /// Whether fast sync (shallow, early fan-out over a larger outbound set) is enabled.
    pub fast_sync: bool,
    /// Whether BIP324 v2 encrypted connections are attempted and accepted, and
    /// `NODE_P2P_V2` is advertised. On by default, as Core's `-v2transport` is;
    /// off keeps every connection on v1.
    pub v2_transport: bool,
    /// The opt-in relay capabilities offered to peers. Every switch is off by
    /// default and peers relay packages or stale tips only after both sides
    /// negotiate them. BIP332 stale-tip relay is off by default on every
    /// network; setting it on a test network is the explicit test override.
    pub relay_offers: bitcoin_rs_p2p::RelayOffers,
    /// Overlay transport configuration (Tor/I2P). Defaults disable every
    /// overlay and preserve direct IP behavior.
    pub overlay: bitcoin_rs_p2p::OverlayConfig,
}

/// Resolved RPC configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind: SocketAddr,
    /// Opt-in separate public REST/Esplora listener.
    pub public_bind: Option<SocketAddr>,
    /// Connection budget of the shared or management listener.
    pub max_connections: usize,
    /// Independent connection budget of the public listener.
    pub public_max_connections: usize,
    pub rest: bool,
    /// Optional experimental keyless BIP352 read service, off by default.
    pub silent_payments: bool,
    /// Optional BIP337 compressed-transaction RPCs, off by default.
    pub compressed_transactions: bool,
    pub auth: Auth,
}

/// Resolved index configuration.
#[derive(Clone, Debug)]
pub struct IndexConfig {
    pub txindex: bool,
    /// Optional basic compact-filter index; disabled by default.
    pub blockfilterindex: bool,
    pub script_index: ScriptIndexMode,
    /// One-shot startup restore of a portable index bundle from this
    /// directory. Never set by default; excludes [`Self::bundle_export`].
    pub bundle_import: Option<PathBuf>,
    /// One-shot startup export of a portable index bundle into this
    /// directory. Never set by default; excludes [`Self::bundle_import`].
    pub bundle_export: Option<PathBuf>,
}

/// Resolved observability configuration.
#[derive(Clone, Debug)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub metrics_bind: Option<SocketAddr>,
}

/// Resolved validation configuration.
#[derive(Clone, Debug)]
pub struct ValidationConfig {
    /// Height through which script verification may be skipped.
    pub assume_valid_height: u32,
    /// Which script verification the apply path may skip.
    pub mode: ValidationMode,
    /// The one script-verification engine this run executes: resolved here
    /// exactly once from defaults -> file -> environment -> CLI, checked
    /// against this build's capability in [`NodeConfig::validate`], and passed
    /// down to the consensus seams that dispatch between script backends.
    pub engine: ValidationEngine,
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
    /// Save and revalidate the optional mempool snapshot across clean restarts.
    pub persist_mempool: bool,
    /// Maximum restart snapshot file size, including metadata and checksum.
    pub mempool_snapshot_max_bytes: u64,
    /// Cooperative startup timeout for mempool snapshot revalidation.
    pub mempool_snapshot_restore_timeout_secs: u64,
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
    /// Native keyless pool, disabled unless explicitly configured.
    pub pool: Option<PoolConfig>,
}

impl NodeConfig {
    /// Returns resolved defaults for a network.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        Self::materialize(&UserConfig::default(), NetworkSelection::from(network))
    }

    fn materialize_overlay(
        settings: &UserConfig,
        selection: NetworkSelection,
        data_dir: &Path,
    ) -> bitcoin_rs_p2p::OverlayConfig {
        bitcoin_rs_p2p::OverlayConfig {
            proxy: settings.p2p.proxy,
            onion: settings.p2p.onion,
            proxy_randomize_credentials: settings.p2p.proxy_randomize_credentials.unwrap_or(true),
            tor_control: settings.p2p.torcontrol.clone(),
            tor_password: settings.p2p.torpassword.clone(),
            tor_virtual_port: selection.consensus_network().default_p2p_port(),
            onion_key_path: Some(data_dir.join("onion_v3_private_key")),
            i2p_sam: settings.p2p.i2psam,
            i2p_accept_incoming: settings.p2p.i2pacceptincoming.unwrap_or(false),
            i2p_key_path: Some(data_dir.join("i2p_private_key")),
            onlynet: settings.p2p.onlynet.clone().unwrap_or_default(),
        }
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
        let mempool_snapshot_max_bytes = settings
            .mempool_snapshot_max_mb
            .unwrap_or(bitcoin_rs_mempool::snapshot::DEFAULT_MAX_BYTES / (1024 * 1024))
            .saturating_mul(1024 * 1024);
        let mempool_snapshot_restore_timeout_secs = settings
            .mempool_snapshot_restore_timeout_secs
            .unwrap_or_else(|| std::cmp::max(60, mempool_snapshot_max_bytes / (1024 * 1024)));
        let data_dir = settings
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".bitcoin-rs"));
        let overlay = Self::materialize_overlay(settings, selection, &data_dir);
        Self {
            network: selection.consensus_network(),
            persist_mempool: settings.persist_mempool.unwrap_or(true),
            mempool_snapshot_max_bytes,
            mempool_snapshot_restore_timeout_secs,
            data_dir,
            storage: StorageConfig {
                backend: settings.storage.backend.unwrap_or(DEFAULT_STORAGE_BACKEND),
                dbcache_mb: settings.storage.dbcache_mb.unwrap_or(DEFAULT_DBCACHE_MB),
                prune_target_mb: settings.storage.prune_target_mb.unwrap_or(0),
            },
            p2p: P2pConfig {
                magic: settings.p2p.magic.unwrap_or(profile.magic),
                listen: settings.p2p.listen.clone().unwrap_or(profile.listen),
                dns_seeds_enabled: settings.p2p.dns_seeds.unwrap_or(profile.dns_seeds),
                asmap: settings.p2p.asmap.clone(),
                noban_subnets: settings.p2p.noban_subnets.clone().unwrap_or_default(),
                connect: settings.p2p.connect.clone().unwrap_or(profile.connect),
                fast_sync: settings.p2p.fast_sync.unwrap_or(false),
                v2_transport: settings.p2p.v2_transport.unwrap_or(true),
                relay_offers: bitcoin_rs_p2p::RelayOffers {
                    package_relay: settings.p2p.package_relay.unwrap_or(false),
                    stale_tip_relay: settings.p2p.stale_tip_relay.unwrap_or(false),
                    stale_tip_prefers_blocks: settings
                        .p2p
                        .stale_tip_prefers_blocks
                        .unwrap_or(false),
                },
                overlay,
            },
            rpc: RpcConfig {
                bind: settings.rpc.bind.unwrap_or(profile.rpc_bind),
                public_bind: settings.rpc.public_bind,
                max_connections: settings.rpc.max_connections.unwrap_or(128),
                public_max_connections: settings.rpc.public_max_connections.unwrap_or(128),
                rest: settings.rpc.rest.unwrap_or(false),
                silent_payments: settings.rpc.silent_payments.unwrap_or(false),
                compressed_transactions: settings.rpc.compressed_transactions.unwrap_or(false),
                auth: rpc_auth(settings),
            },
            indexes: IndexConfig {
                txindex: settings.indexes.txindex.unwrap_or(false),
                blockfilterindex: settings.indexes.blockfilterindex.unwrap_or(false),
                script_index: settings
                    .indexes
                    .script_index
                    .unwrap_or(ScriptIndexMode::Disabled),
                bundle_import: settings.indexes.bundle_import.clone(),
                bundle_export: settings.indexes.bundle_export.clone(),
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
                engine: settings
                    .validation
                    .engine
                    .unwrap_or(ValidationEngine::Native),
            },
            mining: MiningConfig::default(),
            pool: None,
        }
    }

    /// Validates backend availability and cross-field constraints.
    ///
    /// This is the fail-early gate for engine selection: an engine this build
    /// cannot execute is rejected here — before the data directory opens,
    /// chainstate exists, or any worker starts.
    pub fn validate(&self) -> Result<()> {
        if let Some(pool) = &self.pool {
            pool.validate()?;
            anyhow::ensure!(
                !self.mining.payout_script.is_empty(),
                "--pool requires --mining-payout-address"
            );
        }
        anyhow::ensure!(
            self.mempool_snapshot_max_bytes >= 1024 * 1024
                && self.mempool_snapshot_max_bytes < u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            "mempool-snapshot-max-mb must be positive and fit the platform byte limit"
        );
        anyhow::ensure!(
            self.mempool_snapshot_restore_timeout_secs > 0
                && std::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(
                        self.mempool_snapshot_restore_timeout_secs
                    ))
                    .is_some(),
            "mempool-snapshot-restore-timeout-secs must be positive and fit the platform clock range"
        );
        anyhow::ensure!(
            !self.rpc.silent_payments || cfg!(feature = "silent-payments"),
            "--silent-payments requires the silent-payments build feature"
        );
        if let Auth::Basic { user, password } = &self.rpc.auth {
            anyhow::ensure!(
                !user.is_empty() && !password.is_empty(),
                "RPC Basic authentication requires a nonempty username and password"
            );
            anyhow::ensure!(
                password != "bitcoin-rs",
                "RPC password must not use the publicly known legacy default"
            );
        }
        anyhow::ensure!(
            self.rpc.bind.ip().is_loopback() || self.rpc.auth != Auth::GeneratedCookie,
            "non-loopback RPC bind requires explicit credentials (--rpc-password or --rpc-cookie)"
        );
        anyhow::ensure!(
            self.rpc.max_connections > 0 && self.rpc.public_max_connections > 0,
            "RPC and public connection limits must be positive"
        );
        anyhow::ensure!(
            self.rpc.public_bind.is_none_or(|address| {
                let management = self.rpc.bind;
                // Port zero asks the OS for an unused port. Distinct
                // concrete IPs may share a port; a same-family wildcard
                // overlaps every concrete address on that port.
                // Cross-family dual-stack conflicts remain OS-checked at bind.
                address.port() == 0
                    || address.port() != management.port()
                    || (address.ip() != management.ip()
                        && (address.is_ipv4() != management.is_ipv4()
                            || (!address.ip().is_unspecified()
                                && !management.ip().is_unspecified())))
            }),
            "public-bind and rpc-bind must not overlap"
        );
        anyhow::ensure!(
            self.storage.backend.is_compiled_in(),
            "unsupported storage backend {}",
            self.storage.backend
        );
        anyhow::ensure!(
            self.validation.engine.is_supported(),
            "validation engine `{}` is not supported by this build: bitcoinkernel \
             support is not compiled in (enable the `kernel` feature)",
            self.validation.engine
        );
        self.validate_overlay()?;
        anyhow::ensure!(
            !self.p2p.relay_offers.stale_tip_prefers_blocks
                || self.p2p.relay_offers.stale_tip_relay,
            "--p2p-stale-tip-prefers-blocks requires --p2p-stale-tip-relay"
        );
        self.validate_index_bundle()?;
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
        self.validate_journal()
    }

    /// Validates journal durability and lag bounds without opening storage.
    fn validate_journal(&self) -> Result<()> {
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

    /// Validates the portable index bundle request.
    ///
    /// PRE: none; this reads only resolved fields and opens no path.
    /// POST: at most one nonempty bundle directory is set, and it is set only
    /// when the transaction index it moves is enabled.
    /// INVARIANT: the bundle is an explicit one-shot operator request, so a
    /// request this node cannot honor fails before any worker starts instead
    /// of being dropped.
    fn validate_index_bundle(&self) -> Result<()> {
        let indexes = &self.indexes;
        anyhow::ensure!(
            indexes.bundle_import.is_none() || indexes.bundle_export.is_none(),
            "--index-bundle-import and --index-bundle-export are mutually exclusive"
        );
        for (flag, dir) in [
            ("--index-bundle-import", &indexes.bundle_import),
            ("--index-bundle-export", &indexes.bundle_export),
        ] {
            let Some(dir) = dir else {
                continue;
            };
            check_index_bundle_path(dir).map_err(|error| anyhow::anyhow!("{flag}: {error}"))?;
            anyhow::ensure!(indexes.txindex, "{flag} requires --txindex");
        }
        Ok(())
    }

    /// Validates cross-field overlay transport constraints.
    ///
    /// Overlay targets require their routes: an onion target without
    /// an onion/general proxy, an I2P target without a SAM bridge, or
    /// an onlynet naming an overlay without its route is refused
    /// before any worker starts.
    ///
    /// A configured privacy route (general/onion proxy or I2P SAM bridge)
    /// additionally forbids local DNS: DNS seeds resolve through the system
    /// resolver and ordinary hostname `--connect` peers resolve via
    /// `resolve()` on the dial path, so both would bypass the overlay.
    /// They fail fast here instead of leaking or silently downgrading
    /// privacy; typed IP, Tor, and I2P endpoints stay supported.
    fn validate_overlay(&self) -> Result<()> {
        let overlay = &self.p2p.overlay;
        let onion_route = overlay.onion.is_some() || overlay.proxy.is_some();
        let privacy_route = onion_route || overlay.i2p_sam.is_some();
        anyhow::ensure!(
            !privacy_route || !self.p2p.dns_seeds_enabled,
            "proxy/overlay routing requires --dns-seeds-enabled=false; DNS seeds resolve via local DNS and would bypass the privacy route"
        );
        anyhow::ensure!(
            !overlay
                .onlynet
                .contains(&bitcoin_rs_primitives::NetworkLabel::Onion)
                || onion_route,
            "--onlynet=onion requires an onion route (--onion or --proxy)"
        );
        anyhow::ensure!(
            !overlay
                .onlynet
                .contains(&bitcoin_rs_primitives::NetworkLabel::I2p)
                || overlay.i2p_sam.is_some(),
            "--onlynet=i2p requires an I2P SAM bridge (--i2psam)"
        );
        anyhow::ensure!(
            !overlay.i2p_accept_incoming || overlay.i2p_sam.is_some(),
            "--i2pacceptincoming requires an I2P SAM bridge (--i2psam)"
        );
        for target in &self.p2p.connect {
            match classify_endpoint(target) {
                ClassifiedEndpoint::InvalidOverlay => {
                    anyhow::bail!("--connect target `{target}` is an invalid overlay endpoint");
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::TorV3 {
                    ..
                }) => {
                    anyhow::ensure!(
                        onion_route,
                        "--connect onion target requires an onion route (--onion or --proxy)"
                    );
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::I2p { .. }) => {
                    anyhow::ensure!(
                        overlay.i2p_sam.is_some(),
                        "--connect I2P target requires an I2P SAM bridge (--i2psam)"
                    );
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::Ip(..)) => {}
                ClassifiedEndpoint::NonOverlay => {
                    anyhow::ensure!(
                        !privacy_route,
                        "--connect target `{target}` is a hostname that would resolve via local DNS; with a proxy/overlay route configured, use a literal IP or overlay endpoint"
                    );
                }
            }
        }
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
    config.pool = resolve_pool(&settings)?;
    anyhow::ensure!(
        config.pool.is_none() || settings.mining.payout_address.is_some(),
        "--pool requires --mining-payout-address"
    );
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
/// POST: an explicit cookie wins; absent credentials select a fresh per-start
/// cookie; Basic auth never receives a fixed password fallback.
fn rpc_auth(settings: &UserConfig) -> Auth {
    if let Some(path) = &settings.rpc.cookie {
        return Auth::Cookie { path: path.clone() };
    }
    match (
        settings.rpc.user.as_deref(),
        settings.rpc.password.as_deref(),
    ) {
        (None, None) => Auth::GeneratedCookie,
        (user, password) => Auth::basic(user.unwrap_or(DEFAULT_RPC_USER), password.unwrap_or("")),
    }
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
        /// Operator-provided cookie file path.
        path: PathBuf,
    },
    /// New private cookie at `<data_dir>/.cookie`, written when the RPC
    /// listener starts so it always follows the final data directory.
    /// The file contains `__cookie__:<password>` without a trailing newline.
    GeneratedCookie,
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
    /// A generated cookie is written into `data_dir`.
    pub(crate) fn to_rpc_auth(&self, data_dir: &Path) -> Result<bitcoin_rs_rpc::Auth> {
        match self {
            Self::Basic { user, password } => {
                Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
            }
            Self::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
            Self::GeneratedCookie => generate_rpc_cookie(&data_dir.join(".cookie")),
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
            Self::GeneratedCookie => f.write_str("Auth::GeneratedCookie"),
        }
    }
}

/// Replaces the previous run's cookie with a new 256-bit OS-random secret
/// before the RPC socket is bound. A same-directory temporary file, named
/// independently of the secret and created fresh, avoids following a stale
/// symlink and is atomically renamed on Unix.
fn generate_rpc_cookie(path: &Path) -> Result<bitcoin_rs_rpc::Auth> {
    use bitcoin::secp256k1::rand::{RngCore as _, rngs::OsRng};
    use std::fmt::Write as _;
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| anyhow::anyhow!("failed to generate RPC cookie randomness: {error}"))?;
    let mut password = String::with_capacity(64);
    for byte in bytes {
        write!(&mut password, "{byte:02x}")?;
    }

    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let written = (|| -> std::io::Result<()> {
        // A temporary file left by an interrupted start is discarded, so
        // `create_new` never opens an existing file or symlink.
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = options.open(&temporary)?;
        write!(file, "__cookie__:{password}")?;
        file.sync_all()?;
        // Windows rename cannot replace an existing file. Both operations
        // occur before binding the listener, while the new secret is private.
        #[cfg(windows)]
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map_err(|error| {
        anyhow::anyhow!("failed to create RPC cookie {}: {error}", path.display())
    })?;
    Ok(bitcoin_rs_rpc::Auth::cookie(path)?)
}

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
    fn parse(value: &str) -> Option<Self> {
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
    #[cfg(test)]
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
