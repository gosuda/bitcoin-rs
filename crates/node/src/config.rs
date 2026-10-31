use crate::options::{
    ChainstateJournalOverrides, IndexBundleDirError, OptionParseError, UserConfig,
    check_index_bundle_path,
};
use bitcoin_rs_chainstate::{ChainstateJournalConfig, ValidationMode};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_index::IndexCapabilities;
#[cfg(feature = "pool")]
use bitcoin_rs_mining::pool::ledger as pool_ledger;
use bitcoin_rs_p2p::PeerNetwork;
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
    PoolLedger(#[from] bitcoin_rs_mining::pool::ledger::LedgerError),
    #[cfg(feature = "pool")]
    #[error("invalid pool share difficulty: {difficulty_error}")]
    PoolShareDifficulty {
        difficulty_error: bitcoin_rs_mining::pool::JobError,
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
    #[error("chainstate_journal.blocks must be positive")]
    JournalBlocks,
    #[error("chainstate_journal.seconds must be positive")]
    JournalSeconds,
    #[error("chainstate_journal.rotate_mib must be positive")]
    JournalRotateMib,
    #[error("chainstate_journal.max_journal_mib must be >= rotate_mib")]
    JournalMaxJournalMib,
    #[error("chainstate_journal.max_lag_blocks must be >= blocks")]
    JournalMaxLagBlocks,
    #[error("chainstate_journal.max_lag_seconds must be positive")]
    JournalMaxLagSeconds,
    #[error("P2P magic overrides currently require --network mainnet")]
    MagicRequiresMainnet,
    #[error("P2P magic overrides require at least one --connect peer")]
    MagicRequiresConnect,
    #[error("P2P magic overrides require --dns-seeds-enabled=false")]
    MagicRequiresDnsOff,
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
    pub share_target: bitcoin_rs_mining::pool::ShareTarget,
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
            match bitcoin_rs_mining::pool::ShareTarget::from_pool_difficulty_decimal(
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
            bitcoin_rs_mining::pool::ShareTarget::from_pool_difficulty_decimal(text)
                .map_err(|difficulty_error| ConfigError::PoolShareDifficulty { difficulty_error })?
        },
        window_work: pool.window_work.ok_or(ConfigError::PoolWindowWork)?,
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
}

#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind: SocketAddr,
    pub public_bind: Option<SocketAddr>,
    pub max_connections: usize,
    pub public_max_connections: usize,
    pub rest: bool,
    pub silent_payments: bool,
    pub compressed_transactions: bool,
    pub auth: Auth,
}

#[derive(Clone, Debug)]
pub struct IndexConfig {
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
    pub mempool_snapshot_max_bytes: u64,
    pub mempool_snapshot_restore_timeout_secs: u64,
    pub storage: StorageConfig,
    pub p2p: P2pConfig,
    pub rpc: RpcConfig,
    pub indexes: IndexConfig,
    pub observability: ObservabilityConfig,
    pub notifications: NotificationConfig,
    pub chainstate_journal: ChainstateJournalConfig,
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
            p2p: materialize_p2p(&settings.p2p, &profile, selection.consensus_network()),
            rpc: materialize_rpc(&settings.rpc, &profile, rpc_auth(settings)),
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

    pub fn validate(&self) -> Result<(), ConfigError> {
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
        self.validate_index_bundle()?;
        self.validate_p2p_network()?;
        self.p2p.overlay.validate()?;
        bitcoin_rs_rpc::zmq::validate_endpoint_configs(&self.notifications.zmq)?;
        self.validate_chainstate_journal()?;
        Ok(())
    }

    fn validate_chainstate_journal(&self) -> Result<(), ConfigError> {
        let journal = &self.chainstate_journal;
        if journal.blocks == 0 {
            return Err(ConfigError::JournalBlocks);
        }
        if journal.seconds == 0 {
            return Err(ConfigError::JournalSeconds);
        }
        if journal.rotate_mib == 0 {
            return Err(ConfigError::JournalRotateMib);
        }
        if journal.max_journal_mib < journal.rotate_mib {
            return Err(ConfigError::JournalMaxJournalMib);
        }
        if journal.max_lag_blocks < journal.blocks {
            return Err(ConfigError::JournalMaxLagBlocks);
        }
        if journal.max_lag_seconds == 0 {
            return Err(ConfigError::JournalMaxLagSeconds);
        }
        Ok(())
    }

    fn validate_p2p_network(&self) -> Result<(), ConfigError> {
        self.validate_overlay()?;
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
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::TorV3 {
                    ..
                }) => {
                    if !onion_route {
                        return Err(ConfigError::ConnectOnionRequiresRoute);
                    }
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::I2p { .. }) => {
                    if overlay.i2p_sam.is_none() {
                        return Err(ConfigError::ConnectI2pRequiresSam);
                    }
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::Ip(..)) => {}
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
mod tests;

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
