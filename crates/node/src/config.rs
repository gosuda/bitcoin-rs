use crate::options::{IndexBundleDirError, OptionParseError, UserConfig, check_index_bundle_path};
use bitcoin_rs_chain::ValidationMode;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_p2p::PeerNetwork;
use bitcoin_rs_p2p::endpoint::{ClassifiedEndpoint, classify_endpoint};
#[cfg(feature = "pool")]
use bitcoin_rs_rpc::mining::pool::ledger as pool_ledger;
use bitcoin_rs_storage::StorageBackend;
use core::fmt;
use crossbeam_channel::Receiver;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("environment variable {key} is not valid UTF-8")]
    EnvNotUtf8 { key: String },
    #[error(transparent)]
    OptionParse(#[from] OptionParseError),
    #[error(transparent)]
    IndexBundleDir(#[from] IndexBundleDirError),
    #[error(transparent)]
    Subnet(#[from] bitcoin_rs_p2p::SubnetParseError),
    #[error(transparent)]
    SocketAddr(#[from] std::net::AddrParseError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    Infallible(#[from] core::convert::Infallible),
    #[error("invalid boolean {0}")]
    InvalidBoolean(String),
    #[error("--pool requires the pool build feature")]
    PoolFeatureRequired,
    #[error("--pool-datadir must not be empty")]
    PoolDatadirEmpty,
    #[error("data-dir must not be empty")]
    DataDirEmpty,
    #[error("--pool requires an explicit --pool-v1-bind or --pool-sv2-bind")]
    PoolBindMissing,
    #[error("pool listener addresses must differ")]
    PoolBindsEqual,
    #[error("pool listener ports must be explicit and nonzero")]
    PoolPortZero,
    #[error("non-loopback pool bind requires --pool-allow-non-loopback")]
    PoolNonLoopback,
    #[error("SV2 requires the pool-sv2 build feature")]
    Sv2FeatureRequired,
    #[error("--pool-sv2-bind and --pool-sv2-authority-key must be configured together")]
    Sv2PairingRequired,
    #[error("pool SV2 authority key path must not be empty")]
    Sv2AuthorityKeyEmpty,
    #[error("pool connection limits must be positive and per-IP must not exceed total")]
    PoolConnectionLimits,
    #[error("pool connection limits exceed platform bounds")]
    PoolConnectionLimitsBounds,
    #[error("--pool-window-work is required")]
    PoolWindowWorkMissing,
    #[error("--pool-window-work must be positive")]
    PoolWindowWork,
    #[error("--pool-fee-bps must be at most 10000")]
    PoolFeeBps,
    #[error("pool maturity must be at least 100 and payout confirmations must be positive")]
    PoolMaturity,
    #[error("pool reorg watch depth must cover maturity, payout and abandon confirmations")]
    PoolReorgWatchDepth,
    #[error("pool minimum payout must be between 546 and MAX_MONEY satoshis")]
    PoolMinPayout,
    #[error("pool maximum payout outputs must be in 1..=2500")]
    PoolMaxPayoutOutputs,
    #[error("pool reward script must be spendable and bounded")]
    PoolRewardScriptBounded,
    #[error("pool reward script must have canonical script encoding")]
    PoolRewardScriptCanonical,
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolLedger(#[from] bitcoin_rs_rpc::mining::pool::ledger::LedgerError),
    #[cfg(feature = "pool")]
    #[error("invalid pool share difficulty: {difficulty_error}")]
    PoolShareDifficulty {
        difficulty_error: bitcoin_rs_rpc::mining::pool::JobError,
    },
    #[error("pool share target must match configured difficulty")]
    PoolShareTargetMismatch,
    #[error("pool sub-options require --pool")]
    PoolSuboptionsWithoutPool,
    #[error("--pool requires --pool-reward-script")]
    PoolRewardScriptMissing,
    #[error("pool reward script must be bounded even-length hex")]
    PoolRewardScriptBoundedHex,
    #[error("pool reward script must be even-length hex")]
    PoolRewardScriptEvenHex,
    #[error("pool reward script must be hex")]
    PoolRewardScriptHex,
    #[error("--pool requires --pool-datadir")]
    PoolDatadirMissing,
    #[error("--pool requires --pool-share-difficulty")]
    PoolShareDifficultyMissing,
    #[error("--pool requires --mining-payout-address")]
    PoolPayoutAddressMissing,
    #[error("invalid mining payout address: {parse_error}")]
    PayoutAddressInvalid {
        parse_error: Box<bitcoin::address::ParseError>,
    },
    #[error("mining payout address is not valid for {network}: {network_error}")]
    PayoutAddressNetwork {
        network: &'static str,
        network_error: Box<bitcoin::address::ParseError>,
    },
    #[error("mempool-snapshot-max-mb must be positive and fit the platform byte limit")]
    MempoolSnapshotBytes,
    #[error(
        "mempool-snapshot-restore-timeout-secs must be positive and fit the platform clock range"
    )]
    MempoolSnapshotTimeout,
    #[error("--silent-payments requires the silent-payments build feature")]
    SilentPaymentsFeatureRequired,
    #[error("RPC Basic authentication requires a nonempty username and password")]
    RpcBasicAuthEmpty,
    #[error("RPC password must not use the publicly known legacy default")]
    RpcPasswordDefault,
    #[error("non-loopback RPC bind requires explicit credentials (--rpc-password or --rpc-cookie)")]
    RpcNonLoopbackNeedsAuth,
    #[error("RPC and public connection limits must be positive")]
    RpcConnectionLimits,
    #[error("Esplora query limit must be positive")]
    EsploraMaxQueries,
    #[error("public-bind and rpc-bind must not overlap")]
    RpcBindOverlap,
    #[error("unsupported storage backend {backend}")]
    StorageBackendUnsupported { backend: StorageBackend },
    #[error(
        "validation engine `{engine}` is not supported by this build: bitcoinkernel support is not compiled in (enable the `kernel` feature)"
    )]
    ValidationEngineUnsupported { engine: ValidationEngine },
    #[error("--p2p-stale-tip-prefers-blocks requires --p2p-stale-tip-relay")]
    StaleTipPrefersBlocks,
    #[error(transparent)]
    Zmq(#[from] bitcoin_rs_rpc::zmq::ZmqConfigError),
    #[error(transparent)]
    Overlay(#[from] std::io::Error),
    #[error("P2P magic overrides currently require --network mainnet")]
    MagicRequiresMainnet,
    #[error("P2P magic overrides require at least one --connect peer")]
    MagicRequiresConnect,
    #[error("P2P magic overrides require --dns-seeds-enabled=false")]
    MagicRequiresDnsOff,
    #[error("User Agent comment ({0}) contains unsafe characters.")]
    UaCommentUnsafe(String),
    #[error(
        "Total length of network version string ({length}) exceeds maximum length ({max}). \
         Reduce the number or size of uacomments."
    )]
    SubVersionTooLong { length: usize, max: usize },
    #[error(
        "proxy/overlay routing requires --dns-seeds-enabled=false; DNS seeds resolve via local DNS and would bypass the privacy route"
    )]
    PrivacyRequiresDnsOff,
    #[error("--onlynet=onion requires an onion route (--onion-proxy or --proxy)")]
    OnlynetOnion,
    #[error("--onlynet=i2p requires an I2P SAM bridge (--i2p-sam)")]
    OnlynetI2p,
    #[error("--i2p-accept requires an I2P SAM bridge (--i2p-sam)")]
    I2pAcceptRequiresSam,
    #[error("--connect target `{target}` is an invalid overlay endpoint")]
    ConnectInvalidOverlay { target: String },
    #[error("--connect onion target requires an onion route (--onion-proxy or --proxy)")]
    ConnectOnionRequiresRoute,
    #[error("--connect I2P target requires an I2P SAM bridge (--i2p-sam)")]
    ConnectI2pRequiresSam,
    #[error(
        "--connect target `{target}` is a hostname that would resolve via local DNS; with a proxy/overlay route configured, use a literal IP or overlay endpoint"
    )]
    ConnectHostnameWithProxy { target: String },
    #[error("--index-bundle-import and --index-bundle-export are mutually exclusive")]
    IndexBundleImportExportExclusive,
    #[error("{flag}: {path_error}")]
    IndexBundlePath {
        flag: &'static str,
        path_error: IndexBundleDirError,
    },
    #[error("{flag} requires --txindex")]
    IndexBundleRequiresTxindex { flag: &'static str },
    #[error("transaction, script and compact-filter indexing are not compatible with -prune")]
    PruneWithIndexes,
    #[error(transparent)]
    RpcAuth(#[from] bitcoin_rs_rpc::auth::AuthError),
    #[error("failed to generate RPC cookie randomness: {randomness_error}")]
    CookieRandomness {
        randomness_error: bitcoin::secp256k1::rand::Error,
    },
    #[error(transparent)]
    CookieFormat(#[from] core::fmt::Error),
    #[error("failed to create RPC cookie {path}: {io_error}")]
    CookieCreate {
        path: PathBuf,
        io_error: std::io::Error,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    pub zmq: Vec<bitcoin_rs_rpc::zmq::ZmqEndpointConfig>,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum ScriptIndexMode {
    #[default]
    Disabled,
    Utxo,
    Full,
}

impl ScriptIndexMode {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

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

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "utxo" => Some(Self::Utxo),
            "full" | "true" | "1" | "yes" => Some(Self::Full),
            "false" | "0" | "no" => Some(Self::Disabled),
            _ => None,
        }
    }
}

const DEFAULT_STORAGE_BACKEND: StorageBackend = StorageBackend::RocksDb;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_DBCACHE_MB: u64 = 450;

#[derive(Clone, Debug)]
pub struct PoolConfig {
    pub datadir: PathBuf,
    pub v1_bind: Option<SocketAddr>,
    pub sv2_bind: Option<SocketAddr>,
    pub sv2_authority_key: Option<PathBuf>,
    pub allow_non_loopback: bool,
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub share_difficulty: String,
    #[cfg(feature = "pool")]
    pub share_target: bitcoin_rs_rpc::mining::pool::ShareTarget,
    pub window_work: u64,
    pub fee_bps: u16,
    pub reward_script: Vec<u8>,
    pub maturity: u32,
    pub payout_confirmations: u32,
    pub reorg_watch_depth: u32,
    pub min_payout_sat: u64,
    pub max_payout_outputs: u32,
}

impl PoolConfig {
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

    fn validate(&self) -> Result<(), ConfigError> {
        self.validate_binds()?;
        self.validate_limits_and_payout()?;
        #[cfg(feature = "pool")]
        {
            self.ledger_config().validate()?;
            match bitcoin_rs_rpc::mining::pool::ShareTarget::from_pool_difficulty_decimal(
                &self.share_difficulty,
            ) {
                Ok(target) if target == self.share_target => Ok(()),
                Ok(_) => Err(ConfigError::PoolShareTargetMismatch),
                Err(difficulty_error) => Err(ConfigError::PoolShareDifficulty { difficulty_error }),
            }
        }
        #[cfg(not(feature = "pool"))]
        Ok(())
    }

    fn validate_binds(&self) -> Result<(), ConfigError> {
        if !cfg!(feature = "pool") {
            return Err(ConfigError::PoolFeatureRequired);
        }
        if self.datadir.as_os_str().is_empty() {
            return Err(ConfigError::PoolDatadirEmpty);
        }
        if self.v1_bind.is_none() && self.sv2_bind.is_none() {
            return Err(ConfigError::PoolBindMissing);
        }
        if self.v1_bind.is_some() && self.v1_bind == self.sv2_bind {
            return Err(ConfigError::PoolBindsEqual);
        }
        for bind in [self.v1_bind, self.sv2_bind].into_iter().flatten() {
            if bind.port() == 0 {
                return Err(ConfigError::PoolPortZero);
            }
            if !(bind.ip().is_loopback() || self.allow_non_loopback) {
                return Err(ConfigError::PoolNonLoopback);
            }
        }
        if self.sv2_bind.is_some() && !cfg!(feature = "pool-sv2") {
            return Err(ConfigError::Sv2FeatureRequired);
        }
        if self.sv2_bind.is_some() != self.sv2_authority_key.is_some() {
            return Err(ConfigError::Sv2PairingRequired);
        }
        if self
            .sv2_authority_key
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::Sv2AuthorityKeyEmpty);
        }
        Ok(())
    }

    fn validate_limits_and_payout(&self) -> Result<(), ConfigError> {
        if !(self.max_connections > 0
            && self.max_connections_per_ip > 0
            && self.max_connections_per_ip <= self.max_connections)
        {
            return Err(ConfigError::PoolConnectionLimits);
        }
        if !(usize::try_from(self.max_connections).is_ok()
            && usize::try_from(self.max_connections_per_ip).is_ok())
        {
            return Err(ConfigError::PoolConnectionLimitsBounds);
        }
        if self.window_work == 0 {
            return Err(ConfigError::PoolWindowWork);
        }
        if self.fee_bps > 10_000 {
            return Err(ConfigError::PoolFeeBps);
        }
        if !(self.maturity >= 100 && self.payout_confirmations > 0) {
            return Err(ConfigError::PoolMaturity);
        }
        if self.reorg_watch_depth < self.maturity.max(self.payout_confirmations).max(6) {
            return Err(ConfigError::PoolReorgWatchDepth);
        }
        if !(self.min_payout_sat >= 546 && self.min_payout_sat <= 2_100_000_000_000_000) {
            return Err(ConfigError::PoolMinPayout);
        }
        if !(1..=2500).contains(&self.max_payout_outputs) {
            return Err(ConfigError::PoolMaxPayoutOutputs);
        }
        if self.reward_script.is_empty()
            || self.reward_script.len() > 10_000
            || self.reward_script[0] == 0x6a
        {
            return Err(ConfigError::PoolRewardScriptBounded);
        }
        if !bitcoin::Script::from_bytes(&self.reward_script)
            .instructions_minimal()
            .all(|instruction| instruction.is_ok())
        {
            return Err(ConfigError::PoolRewardScriptCanonical);
        }
        Ok(())
    }
}
fn parse_reward_script_hex(reward: &str) -> Result<Vec<u8>, ConfigError> {
    if reward.len() > 20_000 || !reward.len().is_multiple_of(2) {
        return Err(ConfigError::PoolRewardScriptBoundedHex);
    }
    let (pairs, remainder) = reward.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ConfigError::PoolRewardScriptEvenHex);
    }
    pairs
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
                _ => Err(ConfigError::PoolRewardScriptHex),
            }
        })
        .collect::<Result<Vec<u8>, ConfigError>>()
}

fn resolve_pool(settings: &UserConfig) -> Result<Option<PoolConfig>, ConfigError> {
    let pool = &settings.pool;
    if !pool.enabled.unwrap_or(false) {
        if pool.datadir.is_some()
            || pool.v1_bind.is_some()
            || pool.sv2_bind.is_some()
            || pool.sv2_authority_key.is_some()
            || pool.allow_non_loopback.is_some()
            || pool.max_connections.is_some()
            || pool.max_connections_per_ip.is_some()
            || pool.share_difficulty.is_some()
            || pool.window_work.is_some()
            || pool.fee_bps.is_some()
            || pool.reward_script.is_some()
            || pool.maturity.is_some()
            || pool.payout_confirmations.is_some()
            || pool.reorg_watch_depth.is_some()
            || pool.min_payout_sat.is_some()
            || pool.max_payout_outputs.is_some()
        {
            return Err(ConfigError::PoolSuboptionsWithoutPool);
        }
        return Ok(None);
    }
    let reward = pool
        .reward_script
        .as_deref()
        .ok_or(ConfigError::PoolRewardScriptMissing)?;
    let reward_script = parse_reward_script_hex(reward)?;
    Ok(Some(PoolConfig {
        datadir: pool
            .datadir
            .clone()
            .ok_or(ConfigError::PoolDatadirMissing)?,
        v1_bind: pool.v1_bind,
        sv2_bind: pool.sv2_bind,
        sv2_authority_key: pool.sv2_authority_key.clone(),
        allow_non_loopback: pool.allow_non_loopback.unwrap_or(false),
        max_connections: pool.max_connections.unwrap_or(128),
        max_connections_per_ip: pool.max_connections_per_ip.unwrap_or(8),
        share_difficulty: pool
            .share_difficulty
            .clone()
            .ok_or(ConfigError::PoolShareDifficultyMissing)?,
        #[cfg(feature = "pool")]
        share_target: {
            let text = pool
                .share_difficulty
                .as_deref()
                .ok_or(ConfigError::PoolShareDifficultyMissing)?;
            bitcoin_rs_rpc::mining::pool::ShareTarget::from_pool_difficulty_decimal(text)
                .map_err(|difficulty_error| ConfigError::PoolShareDifficulty { difficulty_error })?
        },
        window_work: pool.window_work.ok_or(ConfigError::PoolWindowWorkMissing)?,
        fee_bps: pool.fee_bps.unwrap_or(0),
        reward_script,
        maturity: pool.maturity.unwrap_or(100),
        payout_confirmations: pool.payout_confirmations.unwrap_or(6),
        reorg_watch_depth: pool.reorg_watch_depth.unwrap_or(1000),
        min_payout_sat: pool.min_payout_sat.unwrap_or(546),
        max_payout_outputs: pool.max_payout_outputs.unwrap_or(2500),
    }))
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub dbcache_mb: u64,
    pub prune_target_mb: u64,
}

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub overlay: bitcoin_rs_p2p::overlay::OverlayConfig,
    pub magic: [u8; 4],
    pub listen: Vec<SocketAddr>,
    pub dns_seeds_enabled: bool,
    pub asmap: Option<PathBuf>,
    pub noban_subnets: Vec<bitcoin_rs_p2p::IpSubnet>,
    pub connect: Vec<String>,
    pub fast_sync: bool,
    pub v2_transport: bool,
    pub relay_offers: bitcoin_rs_p2p::RelayOffers,
    /// `-uacomment` values, composed into the subversion exactly as Core's
    /// `InitSubversion` does (`crates/primitives` `sub_version`).
    pub ua_comments: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind: SocketAddr,
    pub public_bind: Option<SocketAddr>,
    pub max_connections: usize,
    pub public_max_connections: usize,
    pub esplora_max_queries: usize,
    pub rest: bool,
    pub silent_payments: bool,
    pub compressed_transactions: bool,
    pub auth: Auth,
}

#[derive(Clone, Debug)]
pub struct IndexConfig {
    pub scripthash_limit: usize,
    pub txindex: bool,
    pub blockfilterindex: bool,
    pub script_index: ScriptIndexMode,
    pub bundle_import: Option<PathBuf>,
    pub bundle_export: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub metrics_bind: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct ValidationConfig {
    pub assume_valid_height: u32,
    pub mode: ValidationMode,
    pub engine: ValidationEngine,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MiningConfig {
    pub payout_script: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub network: Network,
    pub data_dir: PathBuf,
    pub persist_mempool: bool,
    pub assumeutxo_manifest: Option<PathBuf>,
    pub mempool_snapshot_max_bytes: u64,
    pub mempool_snapshot_restore_timeout_secs: u64,
    pub storage: StorageConfig,
    pub p2p: P2pConfig,
    pub rpc: RpcConfig,
    pub indexes: IndexConfig,
    pub observability: ObservabilityConfig,
    pub notifications: NotificationConfig,
    pub validation: ValidationConfig,
    pub mining: MiningConfig,
    pub pool: Option<PoolConfig>,
}

impl NodeConfig {
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        Self::materialize(&UserConfig::default(), NetworkSelection::from(network))
    }

    fn materialize(settings: &UserConfig, selection: NetworkSelection) -> Self {
        let profile = NetworkProfile::for_selection(selection);
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
        Self {
            network: selection.consensus_network(),
            persist_mempool: settings.persist_mempool.unwrap_or(true),
            mempool_snapshot_max_bytes,
            mempool_snapshot_restore_timeout_secs,
            data_dir,
            assumeutxo_manifest: settings.assumeutxo_manifest.clone(),
            storage: StorageConfig {
                backend: settings.storage.backend.unwrap_or(DEFAULT_STORAGE_BACKEND),
                dbcache_mb: settings.storage.dbcache_mb.unwrap_or(DEFAULT_DBCACHE_MB),
                prune_target_mb: settings.storage.prune_target_mb.unwrap_or(0),
            },
            p2p: materialize_p2p(&settings.p2p, &profile, selection.consensus_network()),
            rpc: materialize_rpc(&settings.rpc, &profile, rpc_auth(settings)),
            indexes: IndexConfig {
                scripthash_limit: settings
                    .indexes
                    .scripthash_limit
                    .unwrap_or(bitcoin_rs_index::runtime::DEFAULT_SCRIPTHASH_LIMIT),
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

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::DataDirEmpty);
        }
        if let Some(pool) = &self.pool {
            pool.validate()?;
            if self.mining.payout_script.is_empty() {
                return Err(ConfigError::PoolPayoutAddressMissing);
            }
        }
        if !(self.mempool_snapshot_max_bytes >= 1024 * 1024
            && self.mempool_snapshot_max_bytes < u64::try_from(usize::MAX).unwrap_or(u64::MAX))
        {
            return Err(ConfigError::MempoolSnapshotBytes);
        }
        if !(self.mempool_snapshot_restore_timeout_secs > 0
            && std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(
                    self.mempool_snapshot_restore_timeout_secs,
                ))
                .is_some())
        {
            return Err(ConfigError::MempoolSnapshotTimeout);
        }
        if self.rpc.silent_payments && !cfg!(feature = "silent-payments") {
            return Err(ConfigError::SilentPaymentsFeatureRequired);
        }
        if let Auth::Basic { user, password } = &self.rpc.auth {
            if user.is_empty() || password.is_empty() {
                return Err(ConfigError::RpcBasicAuthEmpty);
            }
            if password == "bitcoin-rs" {
                return Err(ConfigError::RpcPasswordDefault);
            }
        }
        if !(self.rpc.bind.ip().is_loopback() || self.rpc.auth != Auth::GeneratedCookie) {
            return Err(ConfigError::RpcNonLoopbackNeedsAuth);
        }
        if !(self.rpc.max_connections > 0 && self.rpc.public_max_connections > 0) {
            return Err(ConfigError::RpcConnectionLimits);
        }
        if self.rpc.esplora_max_queries == 0 {
            return Err(ConfigError::EsploraMaxQueries);
        }
        if !self.rpc.public_bind.is_none_or(|address| {
            let management = self.rpc.bind;
            address.port() == 0
                || address.port() != management.port()
                || (address.ip() != management.ip()
                    && (address.is_ipv4() != management.is_ipv4()
                        || (!address.ip().is_unspecified() && !management.ip().is_unspecified())))
        }) {
            return Err(ConfigError::RpcBindOverlap);
        }
        if !self.storage.backend.is_compiled_in() {
            return Err(ConfigError::StorageBackendUnsupported {
                backend: self.storage.backend,
            });
        }
        if !self.validation.engine.is_supported() {
            return Err(ConfigError::ValidationEngineUnsupported {
                engine: self.validation.engine,
            });
        }
        if self.p2p.relay_offers.stale_tip_prefers_blocks && !self.p2p.relay_offers.stale_tip_relay
        {
            return Err(ConfigError::StaleTipPrefersBlocks);
        }
        if self.storage.prune_target_mb > 0
            && (self.indexes.txindex
                || self.indexes.blockfilterindex
                || self.indexes.script_index != ScriptIndexMode::Disabled)
        {
            return Err(ConfigError::PruneWithIndexes);
        }
        self.validate_index_bundle()?;
        self.validate_p2p_network()?;
        self.p2p.overlay.validate()?;
        bitcoin_rs_rpc::zmq::validate_endpoint_configs(&self.notifications.zmq)?;
        Ok(())
    }

    fn validate_p2p_network(&self) -> Result<(), ConfigError> {
        self.validate_overlay()?;
        self.validate_ua_comments()?;
        if self.p2p.magic != self.network.magic() {
            if self.network != Network::Mainnet {
                return Err(ConfigError::MagicRequiresMainnet);
            }
            if self.p2p.connect.is_empty() {
                return Err(ConfigError::MagicRequiresConnect);
            }
            if self.p2p.dns_seeds_enabled {
                return Err(ConfigError::MagicRequiresDnsOff);
            }
        }
        Ok(())
    }

    /// Core's `InitSubversion` (`src/init.cpp`): every `-uacomment` must sit
    /// in the BIP-0014 safe subset and the composed subversion within
    /// `MAX_SUBVERSION_LENGTH`, or startup fails with Core's messages.
    fn validate_ua_comments(&self) -> Result<(), ConfigError> {
        for comment in &self.p2p.ua_comments {
            if !bitcoin_rs_consensus::primitives::ua_comment_is_safe(comment) {
                return Err(ConfigError::UaCommentUnsafe(comment.clone()));
            }
        }
        let sub_version = bitcoin_rs_consensus::primitives::sub_version(&self.p2p.ua_comments);
        let max = bitcoin_rs_consensus::primitives::MAX_SUBVERSION_LENGTH;
        if sub_version.len() > max {
            return Err(ConfigError::SubVersionTooLong {
                length: sub_version.len(),
                max,
            });
        }
        Ok(())
    }

    fn validate_overlay(&self) -> Result<(), ConfigError> {
        let overlay = &self.p2p.overlay;
        let onion_route = overlay.onion_proxy.is_some() || overlay.proxy.is_some();
        let privacy_route = onion_route || overlay.i2p_sam.is_some();
        if privacy_route && self.p2p.dns_seeds_enabled {
            return Err(ConfigError::PrivacyRequiresDnsOff);
        }
        if overlay.onlynet.contains(&PeerNetwork::Onion) && !onion_route {
            return Err(ConfigError::OnlynetOnion);
        }
        if overlay.onlynet.contains(&PeerNetwork::I2p) && overlay.i2p_sam.is_none() {
            return Err(ConfigError::OnlynetI2p);
        }
        if overlay.i2p_accept && overlay.i2p_sam.is_none() {
            return Err(ConfigError::I2pAcceptRequiresSam);
        }
        for target in &self.p2p.connect {
            match classify_endpoint(target) {
                ClassifiedEndpoint::InvalidOverlay => {
                    return Err(ConfigError::ConnectInvalidOverlay {
                        target: target.clone(),
                    });
                }
                ClassifiedEndpoint::Valid(
                    bitcoin_rs_consensus::primitives::PeerEndpoint::TorV3 { .. },
                ) => {
                    if !onion_route {
                        return Err(ConfigError::ConnectOnionRequiresRoute);
                    }
                }
                ClassifiedEndpoint::Valid(
                    bitcoin_rs_consensus::primitives::PeerEndpoint::I2p { .. },
                ) => {
                    if overlay.i2p_sam.is_none() {
                        return Err(ConfigError::ConnectI2pRequiresSam);
                    }
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_consensus::primitives::PeerEndpoint::Ip(
                    ..,
                )) => {}
                ClassifiedEndpoint::NonOverlay => {
                    if privacy_route {
                        return Err(ConfigError::ConnectHostnameWithProxy {
                            target: target.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_index_bundle(&self) -> Result<(), ConfigError> {
        let indexes = &self.indexes;
        if indexes.bundle_import.is_some() && indexes.bundle_export.is_some() {
            return Err(ConfigError::IndexBundleImportExportExclusive);
        }
        for (flag, dir) in [
            ("--index-bundle-import", &indexes.bundle_import),
            ("--index-bundle-export", &indexes.bundle_export),
        ] {
            let Some(dir) = dir else {
                continue;
            };
            check_index_bundle_path(dir)
                .map_err(|path_error| ConfigError::IndexBundlePath { flag, path_error })?;
            if !indexes.txindex {
                return Err(ConfigError::IndexBundleRequiresTxindex { flag });
            }
        }
        Ok(())
    }
}
fn materialize_p2p(
    settings: &crate::options::P2pOverrides,
    profile: &NetworkProfile,
    network: Network,
) -> P2pConfig {
    P2pConfig {
        overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
            proxy: settings.proxy,
            onion_proxy: settings.onion_proxy,
            onlynet: settings.onlynet.clone().unwrap_or_default(),
            randomize_credentials: settings.proxy_randomize_credentials.unwrap_or(true),
            i2p_sam: settings.i2p_sam,
            i2p_accept: settings.i2p_accept.unwrap_or(false),
            tor_control: settings.tor_control,
            tor_cookie: settings.tor_cookie.clone(),
            identity_dir: PathBuf::from(format!(
                "overlay-{:08x}",
                u32::from_be_bytes(settings.magic.unwrap_or(profile.magic))
            )),
            port: settings
                .overlay_port
                .unwrap_or_else(|| network.default_p2p_port()),
        },
        magic: settings.magic.unwrap_or(profile.magic),
        listen: settings
            .listen
            .clone()
            .unwrap_or_else(|| profile.listen.clone()),
        dns_seeds_enabled: settings.dns_seeds.unwrap_or(profile.dns_seeds),
        asmap: settings.asmap.clone(),
        noban_subnets: settings.noban_subnets.clone().unwrap_or_default(),
        connect: settings
            .connect
            .clone()
            .unwrap_or_else(|| profile.connect.clone()),
        fast_sync: settings.fast_sync.unwrap_or(false),
        v2_transport: settings.v2_transport.unwrap_or(true),
        relay_offers: bitcoin_rs_p2p::RelayOffers {
            package_relay: settings.package_relay.unwrap_or(false),
            stale_tip_relay: settings.stale_tip_relay.unwrap_or(false),
            stale_tip_prefers_blocks: settings.stale_tip_prefers_blocks.unwrap_or(false),
        },
        ua_comments: settings.ua_comments.clone().unwrap_or_default(),
    }
}

fn materialize_rpc(
    settings: &crate::options::RpcOverrides,
    profile: &NetworkProfile,
    auth: Auth,
) -> RpcConfig {
    RpcConfig {
        bind: settings.bind.unwrap_or(profile.rpc_bind),
        public_bind: settings.public_bind,
        max_connections: settings.max_connections.unwrap_or(128),
        public_max_connections: settings.public_max_connections.unwrap_or(128),
        esplora_max_queries: settings
            .esplora_max_queries
            .unwrap_or(bitcoin_rs_rpc::esplora::DEFAULT_MAX_QUERIES.get()),
        rest: settings.rest.unwrap_or(false),
        silent_payments: settings.silent_payments.unwrap_or(false),
        compressed_transactions: settings.compressed_transactions.unwrap_or(false),
        auth,
    }
}

pub fn resolve(layers: &[&UserConfig]) -> Result<NodeConfig, ConfigError> {
    let mut settings = UserConfig::default();
    for layer in layers {
        settings.overlay(layer);
    }
    let selection = settings.network.unwrap_or(NetworkSelection::Mainnet);
    let mut config = NodeConfig::materialize(&settings, selection);
    config.pool = resolve_pool(&settings)?;
    if config.pool.is_some() && settings.mining.payout_address.is_none() {
        return Err(ConfigError::PoolPayoutAddressMissing);
    }
    if let Some(address) = settings.mining.payout_address {
        config.mining.payout_script = decode_payout_script(config.network, &address)?;
    }
    config.validate()?;
    Ok(config)
}

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

fn decode_payout_script(network: Network, address: &str) -> Result<Vec<u8>, ConfigError> {
    use std::str::FromStr as _;

    let parse_error = match bitcoin::Address::from_str(address) {
        Ok(parsed) => parsed,
        Err(parse_error) => {
            return Err(ConfigError::PayoutAddressInvalid {
                parse_error: Box::new(parse_error),
            });
        }
    };
    let checked = parse_error
        .require_network(bitcoin_network(network))
        .map_err(|network_error| ConfigError::PayoutAddressNetwork {
            network: network.identity_name(),
            network_error: Box::new(network_error),
        })?;
    Ok(checked.script_pubkey().as_bytes().to_vec())
}

const DEFAULT_RPC_USER: &str = "bitcoin-rs";

#[derive(Clone, Eq, PartialEq)]
pub enum Auth {
    Basic { user: String, password: String },
    Cookie { path: PathBuf },
    GeneratedCookie,
}

impl Auth {
    #[must_use]
    pub fn basic(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            user: user.into(),
            password: password.into(),
        }
    }

    pub(crate) fn to_rpc_auth(&self, data_dir: &Path) -> Result<bitcoin_rs_rpc::Auth, ConfigError> {
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

fn generate_rpc_cookie(path: &Path) -> Result<bitcoin_rs_rpc::Auth, ConfigError> {
    use bitcoin::secp256k1::rand::{RngCore as _, rngs::OsRng};
    use std::fmt::Write as _;
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|randomness_error| ConfigError::CookieRandomness { randomness_error })?;
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
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = options.open(&temporary)?;
        write!(file, "__cookie__:{password}")?;
        file.sync_all()?;
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
    written.map_err(|io_error| ConfigError::CookieCreate {
        path: path.to_path_buf(),
        io_error,
    })?;
    Ok(bitcoin_rs_rpc::Auth::cookie(path)?)
}

const DRYNET4_CONNECT: &str = "drynet4.drivechain.dev:8533";
const DRYNET4_P2P_MAGIC: [u8; 4] = [0xec, 0xa5, 0xd4, 0x04];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkSelection {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
    Drynet4,
}

impl NetworkSelection {
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
    type Err = OptionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| OptionParseError::Network {
            value: value.to_owned(),
        })
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

#[derive(Default)]
pub struct RuntimeInputs {
    pub shutdown: Option<Receiver<()>>,
    pub mempool_observer: Option<Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
}

impl RuntimeInputs {
    #[must_use]
    pub fn with_shutdown(mut self, rx: Receiver<()>) -> Self {
        self.shutdown = Some(rx);
        self
    }

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
mod tests {
    use crate::test_support::TestError;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use super::{
        Auth, ConfigError, NetworkSelection, NodeConfig, ScriptIndexMode, ValidationEngine,
    };
    use crate::options::{
        P2pOverrides, RpcOverrides, StorageOverrides, UserConfig, ValidationOverrides,
    };

    fn pool_layer() -> UserConfig {
        UserConfig {
            pool: crate::options::PoolOverrides {
                enabled: Some(true),
                datadir: Some(PathBuf::from("/nonexistent/operator-pool-ledger")),
                v1_bind: Some(SocketAddr::from(([127, 0, 0, 1], 3333))),
                share_difficulty: Some("1".to_owned()),
                window_work: Some(1000),
                reward_script: Some("51".to_owned()),
                ..Default::default()
            },
            mining: crate::options::MiningOverrides {
                payout_address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_owned()),
            },
            ..Default::default()
        }
    }

    #[test]
    fn pool_defaults_off_and_suboptions_require_enablement() {
        assert!(resolved(&[]).pool.is_none());
        let mut layer = pool_layer();
        layer.pool.enabled = Some(false);
        assert!(super::resolve(&[&layer]).is_err());
        layer.pool = crate::options::PoolOverrides::default();
        assert!(super::resolve(&[&layer]).is_ok());
    }

    #[cfg(not(feature = "pool"))]
    #[test]
    fn pool_requires_compiled_feature() {
        match super::resolve(&[&pool_layer()]) {
            Ok(config) => {
                panic!(
                    "pool configuration must be refused without the pool build feature: {config:?}"
                )
            }
            Err(error) => assert!(
                matches!(error, ConfigError::PoolFeatureRequired),
                "{error:?}"
            ),
        }
    }

    // POOL-01
    #[cfg(feature = "pool")]
    #[test]
    fn pool_requires_explicit_policy_and_listener() {
        for missing in 0..7 {
            let mut layer = pool_layer();
            match missing {
                0 => layer.pool.datadir = None,
                1 => layer.pool.v1_bind = None,
                2 => layer.pool.share_difficulty = None,
                3 => layer.pool.window_work = None,
                4 => layer.pool.reward_script = None,
                5 => layer.mining.payout_address = None,
                6 => layer.pool.datadir = Some(PathBuf::new()),
                _ => unreachable!(),
            }
            assert!(
                super::resolve(&[&layer]).is_err(),
                "missing explicit input {missing}"
            );
        }
    }

    #[cfg(feature = "pool")]
    #[test]
    fn an_absent_window_work_is_not_reported_as_non_positive() {
        let mut layer = pool_layer();
        layer.pool.window_work = None;
        match super::resolve(&[&layer]) {
            Err(ConfigError::PoolWindowWorkMissing) => {}
            other => panic!("an absent window work is a required value, not a zero: {other:?}"),
        }

        let mut layer = pool_layer();
        layer.pool.window_work = Some(0);
        match super::resolve(&[&layer]) {
            Err(ConfigError::PoolWindowWork) => {}
            other => panic!("zero window work keeps the positive-value refusal: {other:?}"),
        }
    }

    #[cfg(feature = "pool")]
    #[test]
    fn pool_composed_connection_defaults_are_pinned() {
        let config = resolved(&[&pool_layer()]);
        let pool = config
            .pool
            .as_ref()
            .unwrap_or_else(|| panic!("pool layer must enable the pool"));
        assert_eq!(
            pool.max_connections, 128,
            "shared total connection default must stay 128"
        );
        assert_eq!(
            pool.max_connections_per_ip, 8,
            "shared per-IP connection default must stay 8"
        );
    }

    #[cfg(feature = "pool")]
    #[test]
    fn pool_layers_preserve_explicit_fields_and_override_policy() -> Result<(), TestError> {
        let base = pool_layer();
        let later = UserConfig {
            pool: crate::options::PoolOverrides {
                fee_bps: Some(125),
                share_difficulty: Some("2.5".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = super::resolve(&[&base, &later])?;
        let pool = config
            .pool
            .ok_or(TestError::Missing("pool configuration"))?;
        let expected_datadir = base
            .pool
            .datadir
            .ok_or(TestError::Missing("pool directory"))?;
        assert_eq!(pool.datadir, expected_datadir);
        assert_eq!(pool.v1_bind, base.pool.v1_bind);
        assert!(pool.sv2_bind.is_none());
        assert_eq!(pool.fee_bps, 125);
        assert_eq!(pool.share_difficulty, "2.5");
        let mut share_target_bytes = [0_u8; 32];
        share_target_bytes[26] = 0x66;
        share_target_bytes[27] = 0x66;
        assert_eq!(
            pool.share_target,
            bitcoin_rs_rpc::mining::pool::ShareTarget::from_le_bytes(share_target_bytes)?
        );
        assert_eq!(pool.ledger_config().window_work, 1000);
        assert_eq!(pool.ledger_config().pool_fee_bps, 125);
        Ok(())
    }

    #[cfg(feature = "pool")]
    #[test]
    fn pool_non_loopback_requires_explicit_opt_in() {
        let mut layer = pool_layer();
        layer.pool.v1_bind = Some(SocketAddr::from(([0, 0, 0, 0], 3333)));
        assert!(super::resolve(&[&layer]).is_err());
        layer.pool.allow_non_loopback = Some(true);
        assert!(super::resolve(&[&layer]).is_ok());
        layer.pool.v1_bind = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
        assert!(super::resolve(&[&layer]).is_err());
    }

    // POOL-01
    #[cfg(feature = "pool")]
    #[test]
    fn pool_money_depth_and_capacity_bounds_are_validated() {
        for invalid in 0..15 {
            let mut layer = pool_layer();
            match invalid {
                0 => layer.pool.window_work = Some(0),
                1 => layer.pool.fee_bps = Some(10_001),
                2 => layer.pool.maturity = Some(99),
                3 => layer.pool.payout_confirmations = Some(0),
                4 => layer.pool.reorg_watch_depth = Some(99),
                5 => layer.pool.payout_confirmations = Some(1001),
                6 => layer.pool.min_payout_sat = Some(545),
                7 => layer.pool.min_payout_sat = Some(u64::MAX),
                8 => layer.pool.max_payout_outputs = Some(0),
                9 => layer.pool.max_payout_outputs = Some(2501),
                10 => layer.pool.max_connections = Some(0),
                11 => layer.pool.max_connections_per_ip = Some(0),
                12 => layer.pool.max_connections_per_ip = Some(129),
                13 => layer.pool.reward_script = Some("6a".to_owned()),
                14 => layer.pool.reward_script = Some("4c0151".to_owned()),
                _ => unreachable!(),
            }
            assert!(
                super::resolve(&[&layer]).is_err(),
                "invalid policy {invalid}"
            );
        }
        let mut boundary = pool_layer();
        boundary.pool.fee_bps = Some(10_000);
        boundary.pool.max_payout_outputs = Some(2500);
        assert!(super::resolve(&[&boundary]).is_ok());
    }

    #[cfg(feature = "pool")]
    #[test]
    fn pool_exact_difficulty_and_script_parsing_reject_invalid_inputs() {
        for value in [
            "",
            "0",
            "-1",
            "NaN",
            "1e3",
            "18446744073709551616",
            "1.00000000000000000000",
        ] {
            let mut layer = pool_layer();
            layer.pool.share_difficulty = Some(value.to_owned());
            assert!(super::resolve(&[&layer]).is_err(), "difficulty {value}");
        }
        for script in ["", "0", "zz", "4c"] {
            let mut layer = pool_layer();
            layer.pool.reward_script = Some(script.to_owned());
            assert!(super::resolve(&[&layer]).is_err(), "script {script}");
        }
    }

    #[cfg(feature = "pool")]
    #[test]
    fn pool_sv2_requires_feature_and_paired_authority_path_without_opening_it() {
        let mut layer = pool_layer();
        layer.pool.sv2_bind = Some(SocketAddr::from(([127, 0, 0, 1], 3334)));
        assert!(super::resolve(&[&layer]).is_err());
        layer.pool.sv2_authority_key = Some(PathBuf::from("/nonexistent/pool-authority-key"));
        #[cfg(feature = "pool-sv2")]
        {
            assert!(
                super::resolve(&[&layer]).is_ok(),
                "key IO belongs to service startup"
            );
            layer.pool.sv2_bind = layer.pool.v1_bind;
            assert!(super::resolve(&[&layer]).is_err());
        }
        #[cfg(not(feature = "pool-sv2"))]
        {
            let Err(error) = super::resolve(&[&layer]) else {
                panic!("resolve must fail without pool-sv2 feature");
            };
            assert!(error.to_string().contains("pool-sv2"));
        }
        layer.pool.sv2_bind = None;
        assert!(super::resolve(&[&layer]).is_err());
    }

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

    /// Core's `InitSubversion` (`src/init.cpp`): unsafe comment characters and a
    /// composed subversion over `MAX_SUBVERSION_LENGTH` each fail startup with
    /// Core's exact message; safe comments resolve into `p2p.ua_comments`.
    #[test]
    fn ua_comments_are_validated_and_resolved_in_cores_shape() {
        let layer = UserConfig {
            p2p: crate::options::P2pOverrides {
                ua_comments: Some(vec!["testnode0".to_owned(), "foo".to_owned()]),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = resolved(&[&layer]);
        assert_eq!(config.p2p.ua_comments, ["testnode0", "foo"]);

        for unsafe_comment in ["/", ":", "(", ")", "₿", "🏃"] {
            let layer = UserConfig {
                p2p: crate::options::P2pOverrides {
                    ua_comments: Some(vec![unsafe_comment.to_owned()]),
                    ..Default::default()
                },
                ..Default::default()
            };
            let Err(error) = super::resolve(&[&layer]) else {
                panic!("an unsafe uacomment must fail startup");
            };
            assert_eq!(
                error.to_string(),
                format!("User Agent comment ({unsafe_comment}) contains unsafe characters.")
            );
        }

        let overflow = "a".repeat(bitcoin_rs_consensus::primitives::MAX_SUBVERSION_LENGTH);
        let layer = UserConfig {
            p2p: crate::options::P2pOverrides {
                ua_comments: Some(vec![overflow]),
                ..Default::default()
            },
            ..Default::default()
        };
        let expected_len = bitcoin_rs_consensus::primitives::sub_version(
            layer.p2p.ua_comments.as_deref().unwrap_or_default(),
        )
        .len();
        let Err(error) = super::resolve(&[&layer]) else {
            panic!("an oversized subversion must fail startup");
        };
        assert_eq!(
            error.to_string(),
            format!(
                "Total length of network version string ({expected_len}) exceeds maximum length (256). \
             Reduce the number or size of uacomments."
            )
        );
    }

    #[test]
    fn mempool_persistence_can_be_disabled_without_changing_other_settings() {
        assert!(
            NodeConfig::default_for_network(bitcoin_rs_consensus::primitives::Network::Regtest)
                .persist_mempool
        );
        let layer = UserConfig {
            persist_mempool: Some(false),
            ..Default::default()
        };
        let config = resolved(&[&layer]);
        assert!(!config.persist_mempool);
        assert_eq!(config.storage.dbcache_mb, 450);
        let enable = UserConfig {
            persist_mempool: Some(true),
            ..Default::default()
        };
        assert!(resolved(&[&layer, &enable]).persist_mempool);
    }

    #[test]
    fn mempool_snapshot_budget_is_configurable_and_bounded() {
        let defaults = resolved(&[]);
        assert_eq!(
            defaults.mempool_snapshot_max_bytes,
            bitcoin_rs_mempool::snapshot::DEFAULT_MAX_BYTES
        );
        let layer = UserConfig {
            mempool_snapshot_max_mb: Some(2048),
            ..Default::default()
        };
        assert_eq!(
            resolved(&[&layer]).mempool_snapshot_max_bytes,
            2048 * 1024 * 1024
        );
        for mb in [0, u64::MAX] {
            let layer = UserConfig {
                mempool_snapshot_max_mb: Some(mb),
                ..Default::default()
            };
            assert!(super::resolve(&[&layer]).is_err());
        }
    }

    #[test]
    fn mempool_snapshot_restore_timeout_is_configurable_and_scales_with_budget() {
        let defaults = resolved(&[]);
        assert_eq!(defaults.mempool_snapshot_restore_timeout_secs, 64);

        let large_budget = UserConfig {
            mempool_snapshot_max_mb: Some(120),
            ..Default::default()
        };
        assert_eq!(
            resolved(&[&large_budget]).mempool_snapshot_restore_timeout_secs,
            120
        );

        let explicit = UserConfig {
            mempool_snapshot_max_mb: Some(120),
            mempool_snapshot_restore_timeout_secs: Some(300),
            ..Default::default()
        };
        assert_eq!(
            resolved(&[&explicit]).mempool_snapshot_restore_timeout_secs,
            300
        );

        for seconds in [0, u64::MAX] {
            let invalid = UserConfig {
                mempool_snapshot_restore_timeout_secs: Some(seconds),
                ..Default::default()
            };
            assert!(super::resolve(&[&invalid]).is_err());
            let mut config =
                NodeConfig::default_for_network(bitcoin_rs_consensus::primitives::Network::Regtest);
            config.mempool_snapshot_restore_timeout_secs = seconds;
            assert!(
                config.validate().is_err(),
                "direct embedding config must also reject {seconds}"
            );
        }
    }

    #[test]
    fn default_rpc_auth_uses_a_generated_cookie() {
        let layer = UserConfig {
            data_dir: Some(PathBuf::from("test-node")),
            ..UserConfig::default()
        };
        let config = resolved(&[&layer]);
        assert_eq!(config.rpc.auth, Auth::GeneratedCookie);
    }

    #[test]
    fn generated_rpc_cookie_is_private_and_rotates() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".cookie");
        std::fs::write(dir.path().join(".cookie.tmp"), "stale")?;
        let auth = Auth::GeneratedCookie;

        auth.to_rpc_auth(dir.path())?;
        let first = std::fs::read_to_string(&path)?;
        assert!(!dir.path().join(".cookie.tmp").exists());
        assert!(first.starts_with("__cookie__:"));
        assert_eq!(first.len(), "__cookie__:".len() + 64);
        assert!(
            !first.ends_with('\n'),
            "the generated cookie carries no trailing newline"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
        }

        auth.to_rpc_auth(dir.path())?;
        let second = std::fs::read_to_string(&path)?;
        assert_ne!(first, second, "each startup must rotate the cookie");
        Ok(())
    }

    #[test]
    fn overlay_targets_without_routes_are_rejected() -> Result<(), TestError> {
        let onlynet_onion = UserConfig {
            p2p: P2pOverrides {
                onlynet: Some(vec![bitcoin_rs_p2p::PeerNetwork::Onion]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(super::resolve(&[&onlynet_onion]).is_err());

        let onlynet_i2p = UserConfig {
            p2p: P2pOverrides {
                onlynet: Some(vec![bitcoin_rs_p2p::PeerNetwork::I2p]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(super::resolve(&[&onlynet_i2p]).is_err());

        let accept_without_sam = UserConfig {
            p2p: P2pOverrides {
                i2p_accept: Some(true),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(super::resolve(&[&accept_without_sam]).is_err());

        let routed = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
                i2p_sam: Some(SocketAddr::from(([127, 0, 0, 1], 7656))),
                i2p_accept: Some(true),
                onlynet: Some(vec![
                    bitcoin_rs_p2p::PeerNetwork::Onion,
                    bitcoin_rs_p2p::PeerNetwork::I2p,
                ]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = super::resolve(&[&routed])?;
        assert_eq!(
            config.p2p.overlay.onion_proxy,
            Some(SocketAddr::from(([127, 0, 0, 1], 9050)))
        );
        assert!(config.p2p.overlay.i2p_accept);
        assert_eq!(config.p2p.overlay.onlynet.len(), 2);
        assert!(
            !config.p2p.overlay.identity_dir.as_os_str().is_empty(),
            "inbound overlay services require an identity directory"
        );
        assert_eq!(
            config.p2p.overlay.port,
            NetworkSelection::Mainnet
                .consensus_network()
                .default_p2p_port()
        );
        Ok(())
    }

    #[test]
    fn malformed_overlay_connect_targets_are_rejected() -> Result<(), TestError> {
        let good_tor = bitcoin_rs_p2p::endpoint::format_endpoint(
            bitcoin_rs_consensus::primitives::PeerEndpoint::TorV3 {
                key: [3u8; 32],
                port: 8333,
            },
        );
        let (good_onion_host, _) = good_tor
            .split_once(':')
            .ok_or(TestError::Missing("Tor endpoint port separator"))?;

        let routes_layer = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };

        let valid_user_config = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![good_tor.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let valid_config = super::resolve(&[&routes_layer, &valid_user_config])?;
        assert_eq!(valid_config.p2p.connect, vec![good_tor.clone()]);

        let mut chars: Vec<char> = good_tor.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let bad_checksum_onion: String = chars.into_iter().collect();

        let missing_port_onion = good_onion_host.to_owned();

        let non_numeric_port = format!("{good_onion_host}:notaport");
        let overflow_port = format!("{good_onion_host}:99999");

        let zero_port_onion = format!("{good_onion_host}:0");

        let rejected_targets = [
            bad_checksum_onion,
            missing_port_onion,
            non_numeric_port,
            overflow_port,
            zero_port_onion,
        ];

        for target in rejected_targets {
            let invalid_config = UserConfig {
                p2p: P2pOverrides {
                    connect: Some(vec![target.clone()]),
                    ..P2pOverrides::default()
                },
                ..UserConfig::default()
            };
            assert!(super::resolve(&[&invalid_config]).is_err());
            assert!(super::resolve(&[&routes_layer, &invalid_config]).is_err());
        }
        Ok(())
    }

    #[test]
    fn malformed_i2p_with_routes_configured_rejects_target_not_missing_route()
    -> Result<(), TestError> {
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));
        let routes_layer = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                i2p_sam: Some(SocketAddr::from(([127, 0, 0, 1], 7656))),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };

        let valid_user_config = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![good_i2p.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let valid_config = super::resolve(&[&routes_layer, &valid_user_config])?;
        assert_eq!(valid_config.p2p.connect, vec![good_i2p]);

        let zero_port_i2p = format!("{}.b32.i2p:0", "a".repeat(52));
        let zero_port_user_config = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![zero_port_i2p.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let zero_port_config = super::resolve(&[&routes_layer, &zero_port_user_config])?;
        assert_eq!(zero_port_config.p2p.connect, vec![zero_port_i2p.clone()]);
        assert_eq!(
            bitcoin_rs_p2p::endpoint::classify_endpoint(&zero_port_i2p),
            bitcoin_rs_p2p::endpoint::ClassifiedEndpoint::Valid(
                bitcoin_rs_consensus::primitives::PeerEndpoint::I2p {
                    hash: [0u8; 32],
                    port: 0,
                }
            )
        );

        let malformed_i2p_targets = [
            format!("{}.b32.i2p:8333", "a".repeat(51)),
            format!("{}.b32.i2p:8333", "a".repeat(53)),
            format!("{}.b32.i2p", "a".repeat(52)),
            format!("{}.b32.i2p:notaport", "a".repeat(52)),
            "invalid.b32.i2p:8333".to_owned(),
        ];

        for target in malformed_i2p_targets {
            let invalid_config = UserConfig {
                p2p: P2pOverrides {
                    connect: Some(vec![target.clone()]),
                    ..P2pOverrides::default()
                },
                ..UserConfig::default()
            };
            assert!(super::resolve(&[&invalid_config]).is_err());
            assert!(super::resolve(&[&routes_layer, &invalid_config]).is_err());
        }
        Ok(())
    }

    #[test]
    fn ordinary_hostname_connect_targets_remain_accepted_at_startup() -> Result<(), TestError> {
        for target in [
            "drynet4.drivechain.dev:8533",
            "seed.bitcoin.sipa.be:8333",
            "dnsseed.bluematt.me:8333",
        ] {
            let user_config = UserConfig {
                p2p: P2pOverrides {
                    connect: Some(vec![target.to_owned()]),
                    ..P2pOverrides::default()
                },
                ..UserConfig::default()
            };
            let config = super::resolve(&[&user_config])?;
            assert_eq!(config.p2p.connect, vec![target.to_owned()]);
        }
        Ok(())
    }

    #[test]
    fn valid_overlay_connect_targets_enforce_routes() -> Result<(), TestError> {
        let good_tor = bitcoin_rs_p2p::endpoint::format_endpoint(
            bitcoin_rs_consensus::primitives::PeerEndpoint::TorV3 {
                key: [3u8; 32],
                port: 8333,
            },
        );
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));

        let tor_no_route = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![good_tor.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(super::resolve(&[&tor_no_route]).is_err());

        let i2p_no_route = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec![good_i2p.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(super::resolve(&[&i2p_no_route]).is_err());

        let routed = UserConfig {
            p2p: P2pOverrides {
                onion_proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
                dns_seeds: Some(false),
                i2p_sam: Some(SocketAddr::from(([127, 0, 0, 1], 7656))),
                connect: Some(vec![good_tor.clone(), good_i2p.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = super::resolve(&[&routed])?;
        assert_eq!(config.p2p.connect, vec![good_tor.clone(), good_i2p]);

        let proxy_routed = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
                connect: Some(vec![good_tor.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let proxy_config = super::resolve(&[&proxy_routed])?;
        assert_eq!(proxy_config.p2p.connect, vec![good_tor]);

        Ok(())
    }

    #[test]
    fn privacy_routes_with_default_dns_seeds_are_rejected() {
        let proxy = SocketAddr::from(([127, 0, 0, 1], 9050));
        let sam = SocketAddr::from(([127, 0, 0, 1], 7656));
        for p2p in [
            P2pOverrides {
                proxy: Some(proxy),
                ..P2pOverrides::default()
            },
            P2pOverrides {
                onion_proxy: Some(proxy),
                ..P2pOverrides::default()
            },
            P2pOverrides {
                i2p_sam: Some(sam),
                ..P2pOverrides::default()
            },
        ] {
            let layer = UserConfig {
                p2p,
                ..UserConfig::default()
            };
            let Err(error) = super::resolve(&[&layer]) else {
                panic!("a privacy route with default DNS seeds must fail validation");
            };
            assert!(
                matches!(error, ConfigError::PrivacyRequiresDnsOff),
                "{error:?}"
            );
        }
    }

    #[test]
    fn privacy_route_with_dns_disabled_accepts_literal_ip() -> Result<(), TestError> {
        let layer = UserConfig {
            p2p: P2pOverrides {
                proxy: Some(SocketAddr::from(([127, 0, 0, 1], 9050))),
                dns_seeds: Some(false),
                connect: Some(vec!["127.0.0.1:8333".to_owned()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = super::resolve(&[&layer])?;
        assert!(!config.p2p.dns_seeds_enabled);
        assert_eq!(config.p2p.connect, vec!["127.0.0.1:8333".to_owned()]);
        Ok(())
    }

    #[test]
    fn hostname_connect_targets_are_rejected_with_privacy_route() {
        let proxy = SocketAddr::from(([127, 0, 0, 1], 9050));
        let sam = SocketAddr::from(([127, 0, 0, 1], 7656));
        for p2p in [
            P2pOverrides {
                proxy: Some(proxy),
                dns_seeds: Some(false),
                connect: Some(vec!["seed.bitcoin.sipa.be:8333".to_owned()]),
                ..P2pOverrides::default()
            },
            P2pOverrides {
                onion_proxy: Some(proxy),
                dns_seeds: Some(false),
                connect: Some(vec!["seed.bitcoin.sipa.be:8333".to_owned()]),
                ..P2pOverrides::default()
            },
            P2pOverrides {
                i2p_sam: Some(sam),
                dns_seeds: Some(false),
                connect: Some(vec!["seed.bitcoin.sipa.be:8333".to_owned()]),
                ..P2pOverrides::default()
            },
        ] {
            let layer = UserConfig {
                p2p,
                ..UserConfig::default()
            };
            let Err(error) = super::resolve(&[&layer]) else {
                panic!("a hostname --connect target with a privacy route must fail validation");
            };
            assert!(error.to_string().contains("--connect"), "{error}");
        }
    }

    #[test]
    fn typed_overlay_connect_targets_are_accepted_with_dns_disabled() -> Result<(), TestError> {
        let good_tor = bitcoin_rs_p2p::endpoint::format_endpoint(
            bitcoin_rs_consensus::primitives::PeerEndpoint::TorV3 {
                key: [9u8; 32],
                port: 8333,
            },
        );
        let good_i2p = format!("{}.b32.i2p:8333", "a".repeat(52));
        let proxy = SocketAddr::from(([127, 0, 0, 1], 9050));
        let sam = SocketAddr::from(([127, 0, 0, 1], 7656));

        let onion_routed = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                onion_proxy: Some(proxy),
                connect: Some(vec![good_tor.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert_eq!(
            super::resolve(&[&onion_routed])?.p2p.connect,
            vec![good_tor.clone()]
        );

        let proxy_routed = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                proxy: Some(proxy),
                connect: Some(vec![good_tor.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert_eq!(
            super::resolve(&[&proxy_routed])?.p2p.connect,
            vec![good_tor]
        );

        let i2p_routed = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                i2p_sam: Some(sam),
                connect: Some(vec![good_i2p.clone()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert_eq!(super::resolve(&[&i2p_routed])?.p2p.connect, vec![good_i2p]);

        let ip_routed = UserConfig {
            p2p: P2pOverrides {
                dns_seeds: Some(false),
                proxy: Some(proxy),
                connect: Some(vec!["192.0.2.1:8333".to_owned()]),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = super::resolve(&[&ip_routed])?;
        assert!(!config.p2p.dns_seeds_enabled);
        assert_eq!(config.p2p.connect, vec!["192.0.2.1:8333".to_owned()]);
        Ok(())
    }

    #[test]
    fn rpc_rejects_missing_or_public_credentials() {
        let binding = SocketAddr::from(([0, 0, 0, 0], 8332));
        let exposed = UserConfig {
            rpc: RpcOverrides {
                bind: Some(binding),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&exposed]) else {
            panic!("a non-loopback bind without credentials must fail validation");
        };
        assert!(
            matches!(error, ConfigError::RpcNonLoopbackNeedsAuth),
            "{error:?}"
        );

        let user_without_password = UserConfig {
            rpc: RpcOverrides {
                user: Some("operator".to_owned()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&user_without_password]) else {
            panic!("a user without a password must fail validation");
        };
        assert!(matches!(error, ConfigError::RpcBasicAuthEmpty), "{error:?}");

        let legacy_password = UserConfig {
            rpc: RpcOverrides {
                user: Some("bitcoin-rs".to_owned()),
                password: Some("bitcoin-rs".to_owned()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&legacy_password]) else {
            panic!("the legacy public password must fail validation");
        };
        assert!(
            matches!(error, ConfigError::RpcPasswordDefault),
            "{error:?}"
        );

        let explicit_password = UserConfig {
            rpc: RpcOverrides {
                bind: Some(binding),
                password: Some("non-default-secret".to_owned()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolved(&[&explicit_password]);
        assert_eq!(
            basic_auth(&config.rpc.auth),
            ("bitcoin-rs".to_owned(), "non-default-secret".to_owned())
        );

        let explicit_cookie = UserConfig {
            rpc: RpcOverrides {
                bind: Some(binding),
                cookie: Some(PathBuf::from("/operator/auth.cookie")),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        assert!(matches!(
            resolved(&[&explicit_cookie]).rpc.auth,
            Auth::Cookie { .. }
        ));
    }

    fn resolved(layers: &[&UserConfig]) -> NodeConfig {
        super::resolve(layers)
            .unwrap_or_else(|error| panic!("valid layered configuration: {error}"))
    }

    #[test]
    fn apply_env_routes_unknown_network_through_the_option_parse_variant() {
        let Err(error) =
            UserConfig::default().apply_env("BITCOIN_RS_NETWORK", std::ffi::OsStr::new("bogus"))
        else {
            panic!("unknown network must fail");
        };
        assert!(
            matches!(
                error,
                crate::config::ConfigError::OptionParse(
                    crate::options::OptionParseError::Network { ref value }
                ) if value == "bogus"
            ),
            "apply_env failures must stay typed as ConfigError::OptionParse, got: {error:?}"
        );
    }

    #[test]
    fn pool_suboptions_without_enablement_are_their_own_variant() {
        let mut layer = UserConfig::default();
        layer.pool.datadir = Some(PathBuf::from("/tmp/pool-without-flag"));
        let Err(error) = super::resolve(&[&layer]) else {
            panic!("pool sub-options require --pool");
        };
        assert!(
            matches!(error, crate::config::ConfigError::PoolSuboptionsWithoutPool),
            "pool sub-options without --pool must be PoolSuboptionsWithoutPool, got: {error:?}"
        );
    }

    fn basic_auth(auth: &Auth) -> (String, String) {
        match auth {
            Auth::Basic { user, password } => (user.clone(), password.clone()),
            Auth::Cookie { .. } | Auth::GeneratedCookie => panic!("expected basic auth"),
        }
    }

    #[test]
    fn resolve_prefers_higher_layers_field_by_field() {
        let base = UserConfig {
            storage: StorageOverrides {
                prune_target_mb: Some(550),
                dbcache_mb: Some(300),
                ..StorageOverrides::default()
            },
            rpc: RpcOverrides {
                user: Some("lower-user".to_owned()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let higher = UserConfig {
            storage: StorageOverrides {
                prune_target_mb: Some(900),
                ..StorageOverrides::default()
            },
            rpc: RpcOverrides {
                password: Some("higher-password".to_owned()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolved(&[&base, &higher]);
        assert_eq!(config.storage.prune_target_mb, 900);
        assert_eq!(
            config.storage.dbcache_mb, 300,
            "a field absent in the higher layer keeps the lower layer's value"
        );
        let (user, password) = basic_auth(&config.rpc.auth);
        assert_eq!(user, "lower-user");
        assert_eq!(password, "higher-password");
    }

    #[test]
    fn resolve_keeps_absent_nested_fields_at_their_network_defaults() {
        let layer = UserConfig {
            network: Some(NetworkSelection::Regtest),
            storage: StorageOverrides {
                dbcache_mb: Some(120),
                ..StorageOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolved(&[&layer]);
        assert_eq!(config.storage.dbcache_mb, 120);
        assert_eq!(config.storage.prune_target_mb, 0);
        assert!(!config.indexes.txindex);
        assert_eq!(config.indexes.script_index, ScriptIndexMode::Disabled);
        assert_eq!(config.observability.metrics_bind, None);
        assert_eq!(
            config.validation.assume_valid_height, 0,
            "regtest pins no assume-valid anchor"
        );
    }

    #[test]
    fn validation_engine_defaults_to_native_and_layers_field_by_field() {
        let config = resolved(&[]);
        assert_eq!(config.validation.engine, ValidationEngine::Native);

        let base = UserConfig {
            network: Some(NetworkSelection::Regtest),
            validation: ValidationOverrides {
                engine: Some(ValidationEngine::Native),
                ..ValidationOverrides::default()
            },
            ..UserConfig::default()
        };
        let higher = UserConfig::default();
        let config = resolved(&[&base, &higher]);
        assert_eq!(
            config.validation.engine,
            ValidationEngine::Native,
            "an explicit `native` setting resolves in every build"
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn validation_engine_kernel_is_supported_when_compiled() {
        let layer = UserConfig {
            validation: ValidationOverrides {
                engine: Some(ValidationEngine::Kernel),
                ..ValidationOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolved(&[&layer]);
        assert_eq!(config.validation.engine, ValidationEngine::Kernel);
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn validation_engine_layering_keeps_the_lower_layer_value() {
        let base = UserConfig {
            validation: ValidationOverrides {
                engine: Some(ValidationEngine::Kernel),
                ..ValidationOverrides::default()
            },
            ..UserConfig::default()
        };
        let higher = UserConfig::default();
        let config = resolved(&[&base, &higher]);
        assert_eq!(
            config.validation.engine,
            ValidationEngine::Kernel,
            "an engine absent in the higher layer keeps the lower layer's value"
        );

        let higher = UserConfig {
            validation: ValidationOverrides {
                engine: Some(ValidationEngine::Native),
                ..ValidationOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolved(&[&base, &higher]);
        assert_eq!(
            config.validation.engine,
            ValidationEngine::Native,
            "a higher layer that names an engine wins"
        );
    }

    #[test]
    #[cfg(not(feature = "kernel"))]
    fn validation_engine_kernel_is_rejected_without_kernel_support() {
        let layer = UserConfig {
            validation: ValidationOverrides {
                engine: Some(ValidationEngine::Kernel),
                ..ValidationOverrides::default()
            },
            ..UserConfig::default()
        };
        let error = match super::resolve(&[&layer]) {
            Ok(_) => panic!("a build without kernel support must reject engine = kernel"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                ConfigError::ValidationEngineUnsupported {
                    engine: ValidationEngine::Kernel
                }
            ),
            "unsupported-build error must name the missing capability: {error:?}"
        );
    }

    #[test]
    fn rpc_cookie_and_credential_layers_keep_one_auth_source() {
        let cookie = UserConfig {
            rpc: RpcOverrides {
                cookie: Some(PathBuf::from("/secure/.cookie")),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let credentials = UserConfig {
            rpc: RpcOverrides {
                user: Some("later-user".to_owned()),
                password: Some("later-password".to_owned()),
                ..RpcOverrides::default()
            },
            ..UserConfig::default()
        };
        let config = resolved(&[&credentials, &cookie]);
        assert!(
            matches!(config.rpc.auth, Auth::Cookie { .. }),
            "a higher cookie layer wins over lower credentials"
        );
        let config = resolved(&[&cookie, &credentials]);
        let (user, password) = basic_auth(&config.rpc.auth);
        assert_eq!(user, "later-user");
        assert_eq!(password, "later-password");
    }

    #[test]
    fn p2p_magic_override_is_cross_field_validated() {
        let magic = [1, 2, 3, 4];
        let connect = || vec!["127.0.0.1:8333".to_owned()];

        let regtest = UserConfig {
            network: Some(NetworkSelection::Regtest),
            p2p: P2pOverrides {
                magic: Some(magic),
                connect: Some(connect()),
                dns_seeds: Some(false),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&regtest]) else {
            panic!("a non-mainnet magic override must fail validation");
        };
        assert!(
            matches!(error, ConfigError::MagicRequiresMainnet),
            "{error:?}"
        );

        let without_connect = UserConfig {
            p2p: P2pOverrides {
                magic: Some(magic),
                dns_seeds: Some(false),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&without_connect]) else {
            panic!("a magic override without a connect peer must fail validation");
        };
        assert!(
            matches!(error, ConfigError::MagicRequiresConnect),
            "{error:?}"
        );

        let with_dns_seeds = UserConfig {
            p2p: P2pOverrides {
                magic: Some(magic),
                connect: Some(connect()),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&with_dns_seeds]) else {
            panic!("a magic override with dns seeds on must fail validation");
        };
        assert!(
            matches!(error, ConfigError::MagicRequiresDnsOff),
            "{error:?}"
        );

        let valid = UserConfig {
            p2p: P2pOverrides {
                magic: Some(magic),
                connect: Some(connect()),
                dns_seeds: Some(false),
                ..P2pOverrides::default()
            },
            ..UserConfig::default()
        };
        assert_eq!(resolved(&[&valid]).p2p.magic, magic);
    }

    #[test]
    fn earlier_set_fields_survive_a_later_bare_network_selection() {
        let overrides = UserConfig {
            p2p: P2pOverrides {
                connect: Some(vec!["127.0.0.1:8333".to_owned()]),
                dns_seeds: Some(false),
                ..P2pOverrides::default()
            },
            validation: ValidationOverrides {
                assume_valid_height: Some(7),
                mode: None,
                engine: None,
            },
            ..UserConfig::default()
        };
        let selection = UserConfig {
            network: Some(NetworkSelection::Regtest),
            ..UserConfig::default()
        };
        let config = resolved(&[&overrides, &selection]);
        assert_eq!(
            config.network,
            bitcoin_rs_consensus::primitives::Network::Regtest
        );
        assert_eq!(
            config.p2p.connect,
            vec!["127.0.0.1:8333"],
            "a later bare network selection keeps the peer list an operator set"
        );
        assert!(
            !config.p2p.dns_seeds_enabled,
            "a later bare network selection keeps the seed choice an operator set"
        );
        assert_eq!(
            config.validation.assume_valid_height, 7,
            "a later bare network selection keeps the height an operator pinned"
        );
        assert_eq!(
            config.p2p.magic,
            bitcoin_rs_consensus::primitives::Network::Regtest.magic(),
            "a field no layer set still fills from the winning profile"
        );
    }

    #[test]
    fn prune_rejects_conflicting_index_options() {
        for mode in [
            (true, false, ScriptIndexMode::Disabled),
            (false, true, ScriptIndexMode::Disabled),
            (false, false, ScriptIndexMode::Utxo),
            (false, false, ScriptIndexMode::Full),
        ] {
            let prune_with_index = UserConfig {
                storage: StorageOverrides {
                    prune_target_mb: Some(1000),
                    ..StorageOverrides::default()
                },
                indexes: crate::options::IndexOverrides {
                    txindex: Some(mode.0),
                    blockfilterindex: Some(mode.1),
                    script_index: Some(mode.2),
                    ..crate::options::IndexOverrides::default()
                },
                ..UserConfig::default()
            };
            let Err(error) = super::resolve(&[&prune_with_index]) else {
                panic!("prune with indexes must fail validation");
            };
            assert!(matches!(error, ConfigError::PruneWithIndexes), "{error:?}");
        }
    }

    #[test]
    fn empty_data_dir_is_rejected_by_config_validation() {
        let empty_dir = UserConfig {
            data_dir: Some(std::path::PathBuf::from("")),
            ..UserConfig::default()
        };
        let Err(error) = super::resolve(&[&empty_dir]) else {
            panic!("empty data_dir must fail config validation");
        };
        assert!(matches!(error, ConfigError::DataDirEmpty), "{error:?}");
    }

    // ARCH-03
    #[test]
    fn storage_backend_gate_admits_exactly_the_compiled_engines() {
        for backend in [
            bitcoin_rs_storage::StorageBackend::RocksDb,
            bitcoin_rs_storage::StorageBackend::SurrealKv,
            bitcoin_rs_storage::StorageBackend::Mdbx,
        ] {
            let mut config =
                NodeConfig::default_for_network(bitcoin_rs_consensus::primitives::Network::Regtest);
            config.storage.backend = backend;
            let result = config.validate();
            if backend.is_compiled_in() {
                assert!(
                    result.is_ok(),
                    "{backend:?} is compiled in and must pass validation, got {result:?}"
                );
            } else {
                assert!(
                    matches!(
                        &result,
                        Err(ConfigError::StorageBackendUnsupported { backend: rejected })
                            if *rejected == backend
                    ),
                    "{backend:?} is not compiled in and must be refused by name, got {result:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod shared_service_port_tests {
    use super::*;

    #[test]
    fn overlay_service_port_is_the_network_default_p2p_port_on_every_network() {
        for selection in [
            NetworkSelection::Mainnet,
            NetworkSelection::Testnet3,
            NetworkSelection::Testnet4,
            NetworkSelection::Signet,
            NetworkSelection::Regtest,
            NetworkSelection::Drynet4,
        ] {
            let config = NodeConfig::default_for_network(selection.consensus_network());
            assert_eq!(
                config.p2p.overlay.port,
                selection.consensus_network().default_p2p_port(),
                "shared Bitcoin service port must follow {selection:?}",
            );
        }
    }
}
