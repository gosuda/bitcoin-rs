use core::fmt;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use clap::Parser;
use crossbeam_channel::Receiver;
use serde::Deserialize;

use bitcoin_rs_primitives::Network;

const DEFAULT_STORAGE_BACKEND: &str = "fjall";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";
const DEFAULT_DBCACHE_MB: u64 = 450;
const DEFAULT_ZMQ_HWM: u32 = 1_000;
const DRYNET4_CONNECT: &str = "drynet4.drivechain.dev:8533";
const DRYNET4_P2P_MAGIC: [u8; 4] = [0xec, 0xa5, 0xd4, 0x04];

/// A complete built-in node network selection.
///
/// Unlike [`Network`], which selects consensus rules, this also selects P2P
/// bootstrap behavior. Low-level settings in the same or a later configuration
/// layer may explicitly override the network-derived defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum NetworkSelection {
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
    const fn consensus_network(self) -> Network {
        match self {
            Self::Mainnet | Self::Drynet4 => Network::Mainnet,
            Self::Testnet3 => Network::Testnet3,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

/// RPC authentication configuration before it is converted into the RPC crate's runtime policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    /// HTTP Basic credentials.
    Basic {
        /// RPC username.
        user: String,
        /// RPC password retained until startup hashes it into the RPC runtime policy.
        password: String,
    },
    /// Bitcoin Core cookie-auth file.
    Cookie {
        /// Cookie file path.
        path: PathBuf,
    },
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
    pub fn to_rpc_auth(&self) -> Result<bitcoin_rs_rpc::Auth> {
        match self {
            Self::Basic { user, password } => {
                Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
            }
            Self::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
        }
    }

    fn basic_parts(&self) -> (String, String) {
        match self {
            Self::Basic { user, password } => (user.clone(), password.clone()),
            Self::Cookie { .. } => (DEFAULT_RPC_USER.to_owned(), DEFAULT_RPC_PASSWORD.to_owned()),
        }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self::basic(DEFAULT_RPC_USER, DEFAULT_RPC_PASSWORD)
    }
}

/// One configured ZMQ PUB notification endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmqPublication {
    /// Notification topic name.
    pub topic: crate::zmq_publisher::ZmqTopic,
    /// ZMQ endpoint to bind.
    pub endpoint: String,
    /// PUB socket high-water mark.
    pub hwm: u32,
}

/// Fully merged node configuration. Fixed-peer hostnames are intentionally
/// resolved later by the P2P bootstrap worker.
#[derive(Clone, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// Bitcoin network selected for consensus and default ports.
    #[serde(deserialize_with = "deserialize_network")]
    pub network: Network,
    /// Optional P2P message-start override for fork networks sharing this chain's genesis.
    pub p2p_magic: Option<[u8; 4]>,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Storage backend name: `rocksdb`, `fjall`, `redb`, or `mdbx`.
    pub storage_backend: String,
    /// JSON-RPC bind address.
    pub rpc_bind: SocketAddr,
    /// Whether the Bitcoin Core-compatible REST gateway is enabled.
    pub rest: bool,
    /// JSON-RPC authentication configuration.
    pub rpc_auth: Auth,
    /// Whether the generic script index is enabled for address and scripthash Esplora routes.
    pub script_index: bool,
    /// P2P listener bind addresses.
    pub p2p_listen: Vec<SocketAddr>,
    /// Whether DNS seeds are used for peer bootstrap.
    pub dns_seeds_enabled: bool,
    /// Fixed outbound peer endpoints to connect to. Hostnames remain unresolved
    /// until the P2P dial path so transient DNS failures do not prevent startup.
    /// When non-empty, DNS seed bootstrap is disabled and the node dials only
    /// these endpoints (Bitcoin Core `-connect`).
    pub connect: Vec<String>,
    /// Pruning target in MiB. Zero disables pruning.
    pub prune_target_mb: u64,
    /// Whether utreexo mode is enabled.
    pub utreexo_mode: bool,
    /// Whether the transaction index is enabled.
    pub txindex: bool,
    /// Database cache target in MiB.
    pub dbcache_mb: u64,
    /// Tracing filter level used when `RUST_LOG` is unset.
    pub log_level: String,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
    /// Optional path for applied-block G2 `MuHash` samples.
    pub g2_muhash_samples: Option<PathBuf>,
    /// Optional final applied height to include in G2 `MuHash` samples.
    pub g2_muhash_tip_height: Option<u32>,
    /// Optional path for applied-block G14 UTXO commit timing samples.
    pub g14_utxo_commit_samples: Option<PathBuf>,
    /// Optional IBD window start height for G14 UTXO commit samples.
    pub g14_utxo_commit_ibd_start_height: Option<u32>,
    /// Optional IBD window stop height for G14 UTXO commit samples.
    pub g14_utxo_commit_ibd_stop_height: Option<u32>,
    /// Optional IBD window start block hash for G14 UTXO commit samples.
    pub g14_utxo_commit_ibd_start_hash: Option<String>,
    /// Optional IBD window stop block hash for G14 UTXO commit samples.
    pub g14_utxo_commit_ibd_stop_hash: Option<String>,
    /// ZMQ `hashblock` PUB bind endpoints.
    pub zmqpubhashblock: Vec<String>,
    /// ZMQ `hashtx` PUB bind endpoints.
    pub zmqpubhashtx: Vec<String>,
    /// ZMQ `rawblock` PUB bind endpoints.
    pub zmqpubrawblock: Vec<String>,
    /// ZMQ `rawtx` PUB bind endpoints.
    pub zmqpubrawtx: Vec<String>,
    /// Optional `hashblock` PUB socket high-water mark.
    pub zmqpubhashblockhwm: Option<u32>,
    /// Optional `hashtx` PUB socket high-water mark.
    pub zmqpubhashtxhwm: Option<u32>,
    /// Optional `rawblock` PUB socket high-water mark.
    pub zmqpubrawblockhwm: Option<u32>,
    /// Optional `rawtx` PUB socket high-water mark.
    pub zmqpubrawtxhwm: Option<u32>,
    /// ZMQ `sequence` PUB bind endpoints.
    pub zmqpubsequence: Vec<String>,
    /// Optional `sequence` PUB socket high-water mark.
    pub zmqpubsequencehwm: Option<u32>,
    /// Block height at or below which script verification is skipped during block apply.
    ///
    /// On mainnet the default is the hash-pinned assume-valid anchor
    /// ([`Network::assume_valid_anchor`]): blocks at or below the anchor height skip script
    /// execution only while the active header chain is verified to contain the pinned anchor
    /// block, matching Bitcoin Core's `-assumevalid` posture. Setting `0` opts into full
    /// script verification of every block. Any other custom height applies the height-only
    /// trust shortcut without a hash pin.
    pub assume_valid_height: u32,
    #[serde(skip)]
    pub(crate) shutdown_signal: Option<Receiver<()>>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("network", &self.network)
            .field("p2p_magic", &self.p2p_magic)
            .field("data_dir", &self.data_dir)
            .field("storage_backend", &self.storage_backend)
            .field("rpc_bind", &self.rpc_bind)
            .field("rest", &self.rest)
            .field("rpc_auth", &self.rpc_auth)
            .field("script_index", &self.script_index)
            .field("p2p_listen", &self.p2p_listen)
            .field("dns_seeds_enabled", &self.dns_seeds_enabled)
            .field("connect", &self.connect)
            .field("prune_target_mb", &self.prune_target_mb)
            .field("utreexo_mode", &self.utreexo_mode)
            .field("txindex", &self.txindex)
            .field("dbcache_mb", &self.dbcache_mb)
            .field("log_level", &self.log_level)
            .field("metrics_bind", &self.metrics_bind)
            .field("g2_muhash_samples", &self.g2_muhash_samples)
            .field("g2_muhash_tip_height", &self.g2_muhash_tip_height)
            .field("g14_utxo_commit_samples", &self.g14_utxo_commit_samples)
            .field(
                "g14_utxo_commit_ibd_start_height",
                &self.g14_utxo_commit_ibd_start_height,
            )
            .field(
                "g14_utxo_commit_ibd_stop_height",
                &self.g14_utxo_commit_ibd_stop_height,
            )
            .field(
                "g14_utxo_commit_ibd_start_hash",
                &self.g14_utxo_commit_ibd_start_hash,
            )
            .field(
                "g14_utxo_commit_ibd_stop_hash",
                &self.g14_utxo_commit_ibd_stop_hash,
            )
            .field("zmqpubhashblock", &self.zmqpubhashblock)
            .field("zmqpubhashtx", &self.zmqpubhashtx)
            .field("zmqpubrawblock", &self.zmqpubrawblock)
            .field("zmqpubrawtx", &self.zmqpubrawtx)
            .field("zmqpubhashblockhwm", &self.zmqpubhashblockhwm)
            .field("zmqpubhashtxhwm", &self.zmqpubhashtxhwm)
            .field("zmqpubrawblockhwm", &self.zmqpubrawblockhwm)
            .field("zmqpubrawtxhwm", &self.zmqpubrawtxhwm)
            .field("zmqpubsequence", &self.zmqpubsequence)
            .field("zmqpubsequencehwm", &self.zmqpubsequencehwm)
            .field("assume_valid_height", &self.assume_valid_height)
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_for_network(Network::Mainnet)
    }
}

impl Config {
    /// Returns defaults for `network`, including network-specific RPC and P2P ports.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        Self {
            network,
            p2p_magic: None,
            data_dir: PathBuf::from(".bitcoin-rs"),
            storage_backend: DEFAULT_STORAGE_BACKEND.to_owned(),
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port())),
            rest: false,
            rpc_auth: Auth::default(),
            script_index: false,
            p2p_listen: vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))],
            dns_seeds_enabled: true,
            connect: Vec::new(),
            prune_target_mb: 0,
            utreexo_mode: false,
            txindex: false,
            dbcache_mb: DEFAULT_DBCACHE_MB,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            metrics_bind: None,
            g2_muhash_samples: None,
            g2_muhash_tip_height: None,
            g14_utxo_commit_samples: None,
            g14_utxo_commit_ibd_start_height: None,
            g14_utxo_commit_ibd_stop_height: None,
            g14_utxo_commit_ibd_start_hash: None,
            g14_utxo_commit_ibd_stop_hash: None,
            zmqpubhashblock: Vec::new(),
            zmqpubhashtx: Vec::new(),
            zmqpubrawblock: Vec::new(),
            zmqpubrawtx: Vec::new(),
            zmqpubhashblockhwm: None,
            zmqpubhashtxhwm: None,
            zmqpubrawblockhwm: None,
            zmqpubrawtxhwm: None,
            zmqpubsequence: Vec::new(),
            zmqpubsequencehwm: None,
            assume_valid_height: network
                .assume_valid_anchor()
                .map_or(0, |(height, _)| height),
            shutdown_signal: None,
        }
    }

    /// Loads configuration from defaults, optional Core/TOML files, environment, and CLI args.
    pub fn load_from_args<I, T>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = match ConfigLayer::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                err.exit();
            }
        };
        let env = std::env::vars();
        Self::from_layers(cli.config.as_ref(), cli.bitcoin_conf.as_ref(), env, &cli)
    }

    /// Testable layered loader with an explicit environment source.
    pub fn from_layered_sources<E, K, V, A, T>(
        toml_path: Option<&Path>,
        bitcoin_conf_path: Option<&Path>,
        env: E,
        args: A,
    ) -> Result<Self>
    where
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
        A: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut cli = ConfigLayer::try_parse_from(args)?;
        if cli.config.is_none() {
            cli.config = toml_path.map(Path::to_path_buf);
        }
        if cli.bitcoin_conf.is_none() {
            cli.bitcoin_conf = bitcoin_conf_path.map(Path::to_path_buf);
        }
        Self::from_layers(cli.config.as_ref(), cli.bitcoin_conf.as_ref(), env, &cli)
    }

    /// Returns a copy that receives an extra in-process shutdown notification channel.
    #[must_use]
    pub fn with_shutdown_receiver(mut self, rx: Receiver<()>) -> Self {
        self.shutdown_signal = Some(rx);
        self
    }

    /// Validates backend names and simple cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        if self.p2p_magic.is_some() {
            ensure!(
                self.network == Network::Mainnet,
                "P2P magic overrides currently require --network mainnet"
            );
            ensure!(
                !self.connect.is_empty(),
                "P2P magic overrides require at least one --connect peer"
            );
            ensure!(
                !self.dns_seeds_enabled,
                "P2P magic overrides require --dns-seeds-enabled=false"
            );
        }
        match self.storage_backend.as_str() {
            "rocksdb" | "fjall" | "redb" | "mdbx" => {}
            other => bail!("unsupported storage backend {other}"),
        }
        match (&self.g2_muhash_samples, self.g2_muhash_tip_height) {
            (Some(_), Some(0)) => bail!("g2_muhash_tip_height must be greater than zero"),
            (Some(_), None) => bail!("g2_muhash_samples requires g2_muhash_tip_height"),
            (None, Some(_)) => bail!("g2_muhash_tip_height requires g2_muhash_samples"),
            (None, None) | (Some(_), Some(_)) => {}
        }
        match (
            &self.g14_utxo_commit_samples,
            self.g14_utxo_commit_ibd_start_height,
            self.g14_utxo_commit_ibd_stop_height,
            &self.g14_utxo_commit_ibd_start_hash,
            &self.g14_utxo_commit_ibd_stop_hash,
        ) {
            (None, None, None, None, None) => {}
            (Some(_), Some(start_height), Some(stop_height), Some(start_hash), Some(stop_hash)) => {
                if stop_height < start_height {
                    bail!(
                        "g14_utxo_commit_ibd_stop_height must be greater than or equal to g14_utxo_commit_ibd_start_height"
                    );
                }
                validate_block_hash_hex(start_hash, "g14_utxo_commit_ibd_start_hash")?;
                validate_block_hash_hex(stop_hash, "g14_utxo_commit_ibd_stop_hash")?;
            }
            _ => bail!(
                "g14_utxo_commit_samples requires g14_utxo_commit_ibd_start_height, g14_utxo_commit_ibd_stop_height, g14_utxo_commit_ibd_start_hash, and g14_utxo_commit_ibd_stop_hash"
            ),
        }
        for (name, hwm) in [
            ("zmqpubhashblockhwm", self.zmqpubhashblockhwm),
            ("zmqpubhashtxhwm", self.zmqpubhashtxhwm),
            ("zmqpubrawblockhwm", self.zmqpubrawblockhwm),
            ("zmqpubrawtxhwm", self.zmqpubrawtxhwm),
            ("zmqpubsequencehwm", self.zmqpubsequencehwm),
        ] {
            if hwm.is_some_and(|value| value > 2_147_483_647) {
                bail!("{name} exceeds libzmq SNDHWM range");
            }
        }
        Ok(())
    }

    /// Returns the effective P2P message-start bytes.
    #[must_use]
    pub fn p2p_magic(&self) -> [u8; 4] {
        self.p2p_magic.unwrap_or_else(|| self.network.magic())
    }

    /// Returns active ZMQ publications in Core notification order.
    #[must_use]
    pub fn zmq_publications(&self) -> Vec<ZmqPublication> {
        let mut publications = Vec::new();
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::HashBlock,
            &self.zmqpubhashblock,
            self.zmqpubhashblockhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::HashTx,
            &self.zmqpubhashtx,
            self.zmqpubhashtxhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::RawBlock,
            &self.zmqpubrawblock,
            self.zmqpubrawblockhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::RawTx,
            &self.zmqpubrawtx,
            self.zmqpubrawtxhwm,
        );
        push_zmq_publications(
            &mut publications,
            crate::zmq_publisher::ZmqTopic::Sequence,
            &self.zmqpubsequence,
            self.zmqpubsequencehwm,
        );
        publications
    }

    fn from_layers<E, K, V>(
        toml_path: Option<&PathBuf>,
        bitcoin_conf_path: Option<&PathBuf>,
        env: E,
        cli: &ConfigLayer,
    ) -> Result<Self>
    where
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let toml_layer = match toml_path {
            Some(path) => Some(load_toml_layer(path)?),
            None => None,
        };
        let env_layer = ConfigLayer::from_env(env)?;
        let network = effective_network(toml_layer.as_ref(), &env_layer, cli);
        let mut config = Self::default_for_network(network);

        if let Some(path) = &bitcoin_conf_path {
            crate::bitcoin_conf_compat::apply_file(&mut config, path)?;
        }
        if let Some(layer) = &toml_layer {
            config.apply_layer(layer);
        }
        config.apply_layer(&env_layer);
        config.apply_layer(cli);
        config.validate()?;
        Ok(config)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_layer(&mut self, layer: &ConfigLayer) {
        if let Some(network) = layer.network {
            self.apply_network_selection(network);
        }
        if let Some(p2p_magic) = layer.p2p_magic {
            self.p2p_magic = Some(p2p_magic);
        }
        if let Some(data_dir) = &layer.data_dir {
            self.data_dir.clone_from(data_dir);
        }
        if let Some(storage_backend) = &layer.storage_backend {
            self.storage_backend.clone_from(storage_backend);
        }
        if let Some(rpc_bind) = layer.rpc_bind {
            self.rpc_bind = rpc_bind;
        }
        if let Some(rest) = layer.rest {
            self.rest = rest;
        }
        if let Some(auth) = &layer.rpc_auth {
            self.rpc_auth = auth.clone();
        }
        if let Some(path) = &layer.rpc_cookie {
            self.rpc_auth = Auth::Cookie { path: path.clone() };
        } else if layer.rpc_user.is_some() || layer.rpc_password.is_some() {
            let (old_user, old_password) = self.rpc_auth.basic_parts();
            self.rpc_auth = Auth::basic(
                layer.rpc_user.clone().unwrap_or(old_user),
                layer.rpc_password.clone().unwrap_or(old_password),
            );
        }
        if let Some(script_index) = layer.script_index {
            self.script_index = script_index;
        }
        if let Some(p2p_listen) = &layer.p2p_listen {
            self.p2p_listen.clone_from(p2p_listen);
        }
        if let Some(dns_seeds_enabled) = layer.dns_seeds_enabled {
            self.dns_seeds_enabled = dns_seeds_enabled;
        }
        if let Some(connect) = &layer.connect {
            self.connect.clone_from(connect);
        }
        if let Some(prune_target_mb) = layer.prune_target_mb {
            self.prune_target_mb = prune_target_mb;
        }
        if let Some(utreexo_mode) = layer.utreexo_mode {
            self.utreexo_mode = utreexo_mode;
        }
        if let Some(txindex) = layer.txindex {
            self.txindex = txindex;
        }
        if let Some(dbcache_mb) = layer.dbcache_mb {
            self.dbcache_mb = dbcache_mb;
        }
        if let Some(log_level) = &layer.log_level {
            self.log_level.clone_from(log_level);
        }
        if let Some(metrics_bind) = layer.metrics_bind {
            self.metrics_bind = Some(metrics_bind);
        }
        if layer.clear_metrics_bind {
            self.metrics_bind = None;
        }
        if let Some(path) = &layer.g2_muhash_samples {
            self.g2_muhash_samples = Some(path.clone());
        }
        if let Some(height) = layer.g2_muhash_tip_height {
            self.g2_muhash_tip_height = Some(height);
        }
        self.apply_g14_utxo_commit_layer(layer);
        if let Some(endpoints) = &layer.zmqpubhashblock {
            self.zmqpubhashblock.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubhashtx {
            self.zmqpubhashtx.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubrawblock {
            self.zmqpubrawblock.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubrawtx {
            self.zmqpubrawtx.clone_from(endpoints);
        }
        if let Some(endpoints) = &layer.zmqpubsequence {
            self.zmqpubsequence.clone_from(endpoints);
        }
        if let Some(hwm) = layer.zmqpubhashblockhwm {
            self.zmqpubhashblockhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubhashtxhwm {
            self.zmqpubhashtxhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubrawblockhwm {
            self.zmqpubrawblockhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubrawtxhwm {
            self.zmqpubrawtxhwm = Some(hwm);
        }
        if let Some(hwm) = layer.zmqpubsequencehwm {
            self.zmqpubsequencehwm = Some(hwm);
        }
        if let Some(height) = layer.assume_valid_height {
            self.assume_valid_height = height;
        }
    }

    fn apply_network_selection(&mut self, selection: NetworkSelection) {
        let network = selection.consensus_network();
        self.network = network;
        self.p2p_magic = None;
        self.rpc_bind = SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port()));
        self.p2p_listen = vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))];
        self.dns_seeds_enabled = true;
        self.connect.clear();

        if selection == NetworkSelection::Drynet4 {
            self.p2p_magic = Some(DRYNET4_P2P_MAGIC);
            self.dns_seeds_enabled = false;
            self.connect = vec![DRYNET4_CONNECT.to_owned()];
        }
    }

    fn apply_g14_utxo_commit_layer(&mut self, layer: &ConfigLayer) {
        if let Some(path) = &layer.g14_utxo_commit_samples {
            self.g14_utxo_commit_samples = Some(path.clone());
        }
        if let Some(height) = layer.g14_utxo_commit_ibd_start_height {
            self.g14_utxo_commit_ibd_start_height = Some(height);
        }
        if let Some(height) = layer.g14_utxo_commit_ibd_stop_height {
            self.g14_utxo_commit_ibd_stop_height = Some(height);
        }
        if let Some(hash) = &layer.g14_utxo_commit_ibd_start_hash {
            self.g14_utxo_commit_ibd_start_hash = Some(hash.clone());
        }
        if let Some(hash) = &layer.g14_utxo_commit_ibd_stop_hash {
            self.g14_utxo_commit_ibd_stop_hash = Some(hash.clone());
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Parser)]
#[command(name = "bitcoin-rs-node", about = "Run a bitcoin-rs node")]
#[serde(default)]
pub(crate) struct ConfigLayer {
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long = "bitcoin-conf")]
    pub(crate) bitcoin_conf: Option<PathBuf>,
    /// Select the Bitcoin or fork network, including its P2P bootstrap profile.
    #[arg(long, value_parser = parse_network_selection)]
    pub(crate) network: Option<NetworkSelection>,
    /// Override the four P2P message-start bytes for a fork network.
    #[arg(long = "p2p-magic", value_parser = parse_p2p_magic)]
    #[serde(deserialize_with = "deserialize_optional_p2p_magic")]
    pub(crate) p2p_magic: Option<[u8; 4]>,
    #[arg(long = "data-dir")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(long = "storage-backend")]
    pub(crate) storage_backend: Option<String>,
    #[arg(long = "rpc-bind")]
    pub(crate) rpc_bind: Option<SocketAddr>,
    /// Enable the Bitcoin Core-compatible REST gateway.
    #[arg(long)]
    pub(crate) rest: Option<bool>,
    #[arg(skip)]
    pub(crate) rpc_auth: Option<Auth>,
    #[arg(long = "rpc-user")]
    pub(crate) rpc_user: Option<String>,
    #[arg(long = "rpc-password")]
    pub(crate) rpc_password: Option<String>,
    #[arg(long = "rpc-cookie")]
    pub(crate) rpc_cookie: Option<PathBuf>,
    #[arg(
        long = "scriptindex",
        visible_alias = "script-index",
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    pub(crate) script_index: Option<bool>,
    #[arg(long = "p2p-listen", value_delimiter = ',')]
    pub(crate) p2p_listen: Option<Vec<SocketAddr>>,
    #[arg(long = "dns-seeds-enabled")]
    pub(crate) dns_seeds_enabled: Option<bool>,
    #[arg(
        long = "connect",
        value_delimiter = ',',
        value_parser = parse_connect_endpoint
    )]
    pub(crate) connect: Option<Vec<String>>,
    #[arg(long = "prune-target-mb")]
    pub(crate) prune_target_mb: Option<u64>,
    #[arg(long = "utreexo-mode")]
    pub(crate) utreexo_mode: Option<bool>,
    #[arg(long)]
    pub(crate) txindex: Option<bool>,
    #[arg(long = "dbcache-mb")]
    pub(crate) dbcache_mb: Option<u64>,
    #[arg(long = "log-level")]
    pub(crate) log_level: Option<String>,
    #[arg(long = "metrics-bind")]
    pub(crate) metrics_bind: Option<SocketAddr>,
    #[arg(skip)]
    pub(crate) clear_metrics_bind: bool,
    #[arg(long = "g2-muhash-samples")]
    pub(crate) g2_muhash_samples: Option<PathBuf>,
    #[arg(long = "g2-muhash-tip-height")]
    pub(crate) g2_muhash_tip_height: Option<u32>,
    #[arg(long = "g14-utxo-commit-samples")]
    pub(crate) g14_utxo_commit_samples: Option<PathBuf>,
    #[arg(long = "g14-utxo-commit-ibd-start-height")]
    pub(crate) g14_utxo_commit_ibd_start_height: Option<u32>,
    #[arg(long = "g14-utxo-commit-ibd-stop-height")]
    pub(crate) g14_utxo_commit_ibd_stop_height: Option<u32>,
    #[arg(long = "g14-utxo-commit-ibd-start-hash")]
    pub(crate) g14_utxo_commit_ibd_start_hash: Option<String>,
    #[arg(long = "g14-utxo-commit-ibd-stop-hash")]
    pub(crate) g14_utxo_commit_ibd_stop_hash: Option<String>,
    #[arg(long = "zmqpubhashblock", value_delimiter = ',')]
    pub(crate) zmqpubhashblock: Option<Vec<String>>,
    #[arg(long = "zmqpubhashtx", value_delimiter = ',')]
    pub(crate) zmqpubhashtx: Option<Vec<String>>,
    #[arg(long = "zmqpubrawblock", value_delimiter = ',')]
    pub(crate) zmqpubrawblock: Option<Vec<String>>,
    #[arg(long = "zmqpubrawtx", value_delimiter = ',')]
    pub(crate) zmqpubrawtx: Option<Vec<String>>,
    #[arg(long = "zmqpubsequence", value_delimiter = ',')]
    pub(crate) zmqpubsequence: Option<Vec<String>>,
    #[arg(long = "zmqpubhashblockhwm")]
    pub(crate) zmqpubhashblockhwm: Option<u32>,
    #[arg(long = "zmqpubhashtxhwm")]
    pub(crate) zmqpubhashtxhwm: Option<u32>,
    #[arg(long = "zmqpubrawblockhwm")]
    pub(crate) zmqpubrawblockhwm: Option<u32>,
    #[arg(long = "zmqpubrawtxhwm")]
    pub(crate) zmqpubrawtxhwm: Option<u32>,
    #[arg(long = "zmqpubsequencehwm")]
    pub(crate) zmqpubsequencehwm: Option<u32>,
    #[arg(long = "assume-valid-height")]
    pub(crate) assume_valid_height: Option<u32>,
}

impl ConfigLayer {
    pub(crate) fn apply_to(&self, config: &mut Config) {
        config.apply_layer(self);
    }

    fn from_env<E, K, V>(env: E) -> Result<Self>
    where
        E: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut layer = Self::default();
        for (key, value) in env {
            let key = key.as_ref();
            let value = value.as_ref();
            match key {
                "BITCOIN_RS_NETWORK" => layer.network = Some(parse_network_selection(value)?),
                "BITCOIN_RS_P2P_MAGIC" => layer.p2p_magic = Some(parse_p2p_magic(value)?),
                "BITCOIN_RS_DATA_DIR" => layer.data_dir = Some(PathBuf::from(value)),
                "BITCOIN_RS_STORAGE_BACKEND" => layer.storage_backend = Some(value.to_owned()),
                "BITCOIN_RS_RPC_BIND" => layer.rpc_bind = Some(value.parse()?),
                "BITCOIN_RS_REST" => layer.rest = Some(parse_bool(value)?),
                "BITCOIN_RS_RPC_USER" => layer.rpc_user = Some(value.to_owned()),
                "BITCOIN_RS_RPC_PASSWORD" => layer.rpc_password = Some(value.to_owned()),
                "BITCOIN_RS_RPC_COOKIE" => layer.rpc_cookie = Some(PathBuf::from(value)),
                "BITCOIN_RS_SCRIPTINDEX" => layer.script_index = Some(parse_bool(value)?),
                "BITCOIN_RS_P2P_LISTEN" => layer.p2p_listen = Some(parse_socket_list(value)?),
                "BITCOIN_RS_DNS_SEEDS_ENABLED" => {
                    layer.dns_seeds_enabled = Some(parse_bool(value)?);
                }
                "BITCOIN_RS_CONNECT" => layer.connect = Some(parse_connect_list(value)?),
                "BITCOIN_RS_PRUNE_TARGET_MB" => layer.prune_target_mb = Some(value.parse()?),
                "BITCOIN_RS_UTREEXO_MODE" => layer.utreexo_mode = Some(parse_bool(value)?),
                "BITCOIN_RS_TXINDEX" => layer.txindex = Some(parse_bool(value)?),
                "BITCOIN_RS_DBCACHE_MB" => layer.dbcache_mb = Some(value.parse()?),
                "BITCOIN_RS_LOG_LEVEL" => layer.log_level = Some(value.to_owned()),
                "BITCOIN_RS_METRICS_BIND" => layer.metrics_bind = Some(value.parse()?),
                "BITCOIN_RS_G2_MUHASH_SAMPLES" => {
                    layer.g2_muhash_samples = Some(PathBuf::from(value));
                }
                "BITCOIN_RS_G2_MUHASH_TIP_HEIGHT" => {
                    layer.g2_muhash_tip_height = Some(value.parse()?);
                }
                "BITCOIN_RS_G14_UTXO_COMMIT_SAMPLES" => {
                    layer.g14_utxo_commit_samples = Some(PathBuf::from(value));
                }
                "BITCOIN_RS_G14_UTXO_COMMIT_IBD_START_HEIGHT" => {
                    layer.g14_utxo_commit_ibd_start_height = Some(value.parse()?);
                }
                "BITCOIN_RS_G14_UTXO_COMMIT_IBD_STOP_HEIGHT" => {
                    layer.g14_utxo_commit_ibd_stop_height = Some(value.parse()?);
                }
                "BITCOIN_RS_G14_UTXO_COMMIT_IBD_START_HASH" => {
                    layer.g14_utxo_commit_ibd_start_hash = Some(value.to_owned());
                }
                "BITCOIN_RS_G14_UTXO_COMMIT_IBD_STOP_HASH" => {
                    layer.g14_utxo_commit_ibd_stop_hash = Some(value.to_owned());
                }
                "BITCOIN_RS_ZMQPUBHASHBLOCK" => {
                    layer.zmqpubhashblock = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBHASHTX" => {
                    layer.zmqpubhashtx = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBRAWBLOCK" => {
                    layer.zmqpubrawblock = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBRAWTX" => {
                    layer.zmqpubrawtx = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBSEQUENCE" => {
                    layer.zmqpubsequence = Some(parse_string_list(value));
                }
                "BITCOIN_RS_ZMQPUBHASHBLOCKHWM" => {
                    layer.zmqpubhashblockhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBHASHTXHWM" => {
                    layer.zmqpubhashtxhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBRAWBLOCKHWM" => {
                    layer.zmqpubrawblockhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBRAWTXHWM" => {
                    layer.zmqpubrawtxhwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ZMQPUBSEQUENCEHWM" => {
                    layer.zmqpubsequencehwm = Some(value.parse()?);
                }
                "BITCOIN_RS_ASSUME_VALID_HEIGHT" => {
                    layer.assume_valid_height = Some(value.parse()?);
                }
                _ => {}
            }
        }
        Ok(layer)
    }
}

fn validate_block_hash_hex(value: &str, name: &str) -> Result<()> {
    let value = value.trim();
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{name} must be 64 lowercase hex characters"
    );
    Ok(())
}

fn load_toml_layer(path: &Path) -> Result<ConfigLayer> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    let layer = toml::from_str(&text)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
    Ok(layer)
}

fn effective_network(toml: Option<&ConfigLayer>, env: &ConfigLayer, cli: &ConfigLayer) -> Network {
    layer_network(cli)
        .or_else(|| layer_network(env))
        .or_else(|| toml.and_then(layer_network))
        .unwrap_or(Network::Mainnet)
}

fn layer_network(layer: &ConfigLayer) -> Option<Network> {
    layer.network.map(NetworkSelection::consensus_network)
}

fn parse_socket_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| Ok(part.trim().parse()?))
        .collect()
}

fn parse_connect_endpoint(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(value.to_owned());
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(format!("connect peer `{value}` must include a port"));
    };
    if host.is_empty() {
        return Err(format!("connect peer `{value}` has an empty hostname"));
    }
    port.parse::<u16>()
        .map_err(|error| format!("connect peer `{value}` has an invalid port: {error}"))?;
    Ok(value.to_owned())
}

fn parse_connect_list(value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_connect_endpoint(part.trim()).map_err(anyhow::Error::msg))
        .collect()
}

fn parse_string_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn push_zmq_publications(
    publications: &mut Vec<ZmqPublication>,
    topic: crate::zmq_publisher::ZmqTopic,
    endpoints: &[String],
    hwm: Option<u32>,
) {
    let hwm = hwm.unwrap_or(DEFAULT_ZMQ_HWM);
    publications.extend(endpoints.iter().cloned().map(|endpoint| ZmqPublication {
        topic,
        endpoint,
        hwm,
    }));
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}

fn parse_p2p_magic(value: &str) -> Result<[u8; 4]> {
    let value = value.trim();
    ensure!(
        value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "p2p magic must be exactly eight hexadecimal characters"
    );
    let mut magic = [0_u8; 4];
    for (index, slot) in magic.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16)?;
    }
    Ok(magic)
}

fn parse_network(value: &str) -> anyhow::Result<Network> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(Network::Mainnet),
        "test" | "testnet" | "testnet3" => Ok(Network::Testnet3),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => bail!("unsupported network {other}"),
    }
}

fn parse_network_selection(value: &str) -> anyhow::Result<NetworkSelection> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(NetworkSelection::Mainnet),
        "test" | "testnet" | "testnet3" => Ok(NetworkSelection::Testnet3),
        "testnet4" => Ok(NetworkSelection::Testnet4),
        "signet" => Ok(NetworkSelection::Signet),
        "regtest" => Ok(NetworkSelection::Regtest),
        "drynet4" => Ok(NetworkSelection::Drynet4),
        other => bail!("unknown network {other}"),
    }
}

fn deserialize_network<'de, D>(deserializer: D) -> core::result::Result<Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_network(&raw).map_err(serde::de::Error::custom)
}

fn deserialize_optional_p2p_magic<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<[u8; 4]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    raw.as_deref()
        .map(parse_p2p_magic)
        .transpose()
        .map_err(serde::de::Error::custom)
}
