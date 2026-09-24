use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin_rs_chainstate::ValidationMode;
use bitcoin_rs_node::options::{
    parse_connect_endpoint, parse_network, parse_p2p_magic, parse_script_index,
    parse_storage_backend, parse_validation_mode,
};
use bitcoin_rs_node::{
    ChainstateJournalOverrides, IndexOverrides, MiningOverrides, NetworkSelection,
    ObservabilityOverrides, P2pOverrides, RpcOverrides, ScriptIndexMode, StorageOverrides,
    UserConfig, ValidationOverrides,
};
use bitcoin_rs_storage::StorageBackend;
use clap::Parser;

#[derive(Clone, Debug, Parser)]
#[command(name = "bitcoin-rs", about = "Run a bitcoin-rs node")]
pub(crate) struct CliArgs {
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long = "bitcoin-conf")]
    pub(crate) bitcoin_conf: Option<PathBuf>,
    #[arg(long, value_parser = parse_network)]
    pub(crate) network: Option<NetworkSelection>,
    #[arg(long = "p2p-magic", value_parser = parse_p2p_magic)]
    pub(crate) p2p_magic: Option<[u8; 4]>,
    #[arg(long = "data-dir")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(long = "storage-backend", value_parser = parse_storage_backend)]
    pub(crate) storage_backend: Option<StorageBackend>,
    #[arg(long = "rpc-bind")]
    pub(crate) rpc_bind: Option<SocketAddr>,
    #[arg(long)]
    pub(crate) rest: Option<bool>,
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
        default_missing_value = "true",
        value_parser = parse_script_index
    )]
    pub(crate) script_index: Option<ScriptIndexMode>,
    #[arg(long = "p2p-listen", value_delimiter = ',')]
    pub(crate) p2p_listen: Option<Vec<SocketAddr>>,
    #[arg(long = "dns-seeds-enabled")]
    pub(crate) dns_seeds_enabled: Option<bool>,
    #[arg(long = "connect", value_delimiter = ',', value_parser = parse_connect_endpoint)]
    pub(crate) connect: Option<Vec<String>>,
    /// Fast sync: fan out block requests early and shallowly over a larger outbound peer set.
    #[arg(long = "fast-sync", num_args = 0..=1, default_missing_value = "true")]
    pub(crate) fast_sync: Option<bool>,
    #[arg(long = "prune-target-mb")]
    pub(crate) prune_target_mb: Option<u64>,
    #[arg(long)]
    pub(crate) txindex: Option<bool>,
    #[arg(long = "dbcache-mb")]
    pub(crate) dbcache_mb: Option<u64>,
    #[arg(long = "log-level")]
    pub(crate) log_level: Option<String>,
    #[arg(long = "metrics-bind")]
    pub(crate) metrics_bind: Option<SocketAddr>,
    #[arg(long = "assume-valid-height")]
    pub(crate) assume_valid_height: Option<u32>,
    #[arg(long = "validation-mode", value_parser = parse_validation_mode)]
    pub(crate) validation_mode: Option<ValidationMode>,
    /// Watch-only coinbase payout address for solo mining templates.
    #[arg(long = "mining-payout-address")]
    pub(crate) mining_payout_address: Option<String>,
    /// Measure data-directory storage ledgers and exit. Does not start the node.
    #[arg(long = "measure-storage")]
    pub(crate) measure_storage: bool,
    /// Write `--measure-storage` JSON to this path instead of stdout.
    #[arg(long = "measure-storage-output")]
    pub(crate) measure_storage_output: Option<PathBuf>,
    /// Conservative peak allocated bytes from an isolated filesystem or project quota.
    #[arg(long = "storage-high-water-bytes")]
    pub(crate) storage_high_water_bytes: Option<u64>,
    /// Recorded stop height. Pairing and hash format: `FP-03`.
    #[arg(long = "measure-storage-stop-height")]
    pub(crate) measure_storage_stop_height: Option<u32>,
    /// Recorded stop hash. Pairing and hash format: `FP-03`.
    #[arg(long = "measure-storage-stop-hash")]
    pub(crate) measure_storage_stop_hash: Option<String>,
}

impl CliArgs {
    pub(crate) fn into_user_config(self) -> UserConfig {
        UserConfig {
            network: self.network,
            data_dir: self.data_dir,
            storage: StorageOverrides {
                backend: self.storage_backend,
                dbcache_mb: self.dbcache_mb,
                prune_target_mb: self.prune_target_mb,
            },
            p2p: P2pOverrides {
                magic: self.p2p_magic,
                listen: self.p2p_listen,
                dns_seeds: self.dns_seeds_enabled,
                connect: self.connect,
                fast_sync: self.fast_sync,
            },
            rpc: RpcOverrides {
                bind: self.rpc_bind,
                rest: self.rest,
                user: self.rpc_user,
                password: self.rpc_password,
                cookie: self.rpc_cookie,
            },
            indexes: IndexOverrides {
                txindex: self.txindex,
                script_index: self.script_index,
            },
            observability: ObservabilityOverrides {
                log_level: self.log_level,
                metrics_bind: self.metrics_bind,
            },
            notifications: None,
            chainstate_journal: ChainstateJournalOverrides::default(),
            validation: ValidationOverrides {
                assume_valid_height: self.assume_valid_height,
                mode: self.validation_mode,
            },
            mining: MiningOverrides {
                payout_address: self.mining_payout_address,
            },
        }
    }
}
