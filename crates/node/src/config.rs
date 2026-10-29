use crate::options::{ChainstateJournalOverrides, UserConfig, check_index_bundle_path};
use anyhow::Result;
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

    #[expect(
        clippy::too_many_lines,
        reason = "One fold of every resolved field keeps precedence auditable in one place"
    )]
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
            p2p: P2pConfig {
                overlay: bitcoin_rs_p2p::overlay::OverlayConfig {
                    proxy: settings.p2p.proxy,
                    onion_proxy: settings.p2p.onion_proxy,
                    onlynet: settings.p2p.onlynet.clone().unwrap_or_default(),
                    randomize_credentials: settings.p2p.proxy_randomize_credentials.unwrap_or(true),
                    i2p_sam: settings.p2p.i2p_sam,
                    i2p_accept: settings.p2p.i2p_accept.unwrap_or(false),
                    tor_control: settings.p2p.tor_control,
                    tor_cookie: settings.p2p.tor_cookie.clone(),
                    identity_dir: PathBuf::from(format!(
                        "overlay-{:08x}",
                        u32::from_be_bytes(settings.p2p.magic.unwrap_or(profile.magic))
                    )),
                    port: settings
                        .p2p
                        .overlay_port
                        .unwrap_or_else(|| selection.consensus_network().default_p2p_port()),
                },
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
        anyhow::ensure!(
            !self.p2p.relay_offers.stale_tip_prefers_blocks
                || self.p2p.relay_offers.stale_tip_relay,
            "--p2p-stale-tip-prefers-blocks requires --p2p-stale-tip-relay"
        );
        self.validate_index_bundle()?;
        self.validate_p2p_network()?;
        self.p2p.overlay.validate()?;
        bitcoin_rs_rpc::zmq::validate_endpoint_configs(&self.notifications.zmq)?;
        self.validate_chainstate_journal()?;
        Ok(())
    }

    fn validate_chainstate_journal(&self) -> Result<()> {
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

    fn validate_p2p_network(&self) -> Result<()> {
        self.validate_overlay()?;
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
        Ok(())
    }

    fn validate_overlay(&self) -> Result<()> {
        let overlay = &self.p2p.overlay;
        let onion_route = overlay.onion_proxy.is_some() || overlay.proxy.is_some();
        let privacy_route = onion_route || overlay.i2p_sam.is_some();
        anyhow::ensure!(
            !privacy_route || !self.p2p.dns_seeds_enabled,
            "proxy/overlay routing requires --dns-seeds-enabled=false; DNS seeds resolve via local DNS and would bypass the privacy route"
        );
        anyhow::ensure!(
            !overlay.onlynet.contains(&PeerNetwork::Onion) || onion_route,
            "--onlynet=onion requires an onion route (--onion-proxy or --proxy)"
        );
        anyhow::ensure!(
            !overlay.onlynet.contains(&PeerNetwork::I2p) || overlay.i2p_sam.is_some(),
            "--onlynet=i2p requires an I2P SAM bridge (--i2p-sam)"
        );
        anyhow::ensure!(
            !overlay.i2p_accept || overlay.i2p_sam.is_some(),
            "--i2p-accept requires an I2P SAM bridge (--i2p-sam)"
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
                        "--connect onion target requires an onion route (--onion-proxy or --proxy)"
                    );
                }
                ClassifiedEndpoint::Valid(bitcoin_rs_primitives::PeerEndpoint::I2p { .. }) => {
                    anyhow::ensure!(
                        overlay.i2p_sam.is_some(),
                        "--connect I2P target requires an I2P SAM bridge (--i2p-sam)"
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
}

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
    written.map_err(|error| {
        anyhow::anyhow!("failed to create RPC cookie {}: {error}", path.display())
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
#[path = "../tests/unit/config/tests.rs"]
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
