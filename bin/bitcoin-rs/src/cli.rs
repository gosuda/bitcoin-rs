use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin_rs_chainstate::ValidationMode;
use bitcoin_rs_node::options::{
    parse_connect_endpoint, parse_network, parse_p2p_magic, parse_script_index,
    parse_storage_backend, parse_validation_mode,
};
use bitcoin_rs_node::{
    ChainstateJournalOverrides, IndexOverrides, MiningOverrides, NetworkSelection,
    NotificationConfig, ObservabilityOverrides, P2pOverrides, RpcOverrides, ScriptIndexMode,
    StorageOverrides, UserConfig, ValidationOverrides,
};
use bitcoin_rs_storage::StorageBackend;
use clap::Parser;

/// Expands the node option table into the command-line surface: one field per
/// table row, carrying the row's clap attributes, plus the conversion of the
/// parsed arguments into one configuration layer.
///
/// PRE: a row's `cli` column holds its complete clap attributes; a row the
/// command line does not expose carries `#[arg(skip)]`.
/// POST: `CliArgs` exposes exactly the flags the table names, and
/// `into_user_config` writes each parsed value into its row's slot.
/// INVARIANT: flag names, aliases, value parsers, and error strings come from
/// the table, so the command line cannot drift from the other process-input
/// surfaces. `--scriptindex` and its `--script-index` alias are the table's
/// doing, not this file's. Meta flags that never reach `UserConfig` stay
/// hand-written here.
macro_rules! emit_cli {
    (
        fields {
            $(
                $(#[$fdoc:meta])*
                $fid:ident : $fty:ty {
                    cli[ $($fcli:tt)* ]
                    $( env[ $ekey:literal, $egram:expr ] )?
                    $( toml $tmode:ident ( $tkey:literal $(, $tgram:expr )? ) )?
                    $( conf[ $ckey:literal ] )?
                }
            )*
        }
        groups {
            $(
                $(#[$gdoc:meta])*
                group $gid:ident : $gty:ident $(table($gkey:literal))? $(#[$gattr:meta])*
                {
                    $(
                        $(#[$rdoc:meta])*
                        $rfield:ident as $rid:ident : $rty:ty {
                            cli[ $($gcli:tt)* ]
                            $( env[ $gekey:literal, $gegram:expr ] )?
                            $( toml $gtmode:ident ( $gtkey:literal $(, $gtgram:expr )? ) )?
                            $( conf[ $gckey:literal ] )?
                        }
                    )*
                }
            )*
        }
    ) => {
        #[derive(Clone, Debug, Parser)]
        #[command(name = "bitcoin-rs", about = "Run a bitcoin-rs node")]
        pub(crate) struct CliArgs {
            #[arg(long)]
            pub(crate) config: Option<PathBuf>,
            #[arg(long = "bitcoin-conf")]
            pub(crate) bitcoin_conf: Option<PathBuf>,
            $(
                $(#[$fdoc])*
                $($fcli)*
                pub(crate) $fid: $fty,
            )*
            $(
                $(
                    $(#[$rdoc])*
                    $($gcli)*
                    pub(crate) $rid: $rty,
                )*
            )*
            /// Measure data-directory storage ledgers and exit. Does not
            /// start the node.
            #[arg(long = "measure-storage")]
            pub(crate) measure_storage: bool,
            /// Write `--measure-storage` JSON to this path instead of stdout.
            #[arg(long = "measure-storage-output")]
            pub(crate) measure_storage_output: Option<PathBuf>,
            /// Conservative peak allocated bytes from an isolated filesystem
            /// or project quota.
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
            /// Maps the parsed command line into one configuration layer.
            pub(crate) fn into_user_config(self) -> UserConfig {
                UserConfig {
                    $( $fid: self.$fid, )*
                    $(
                        $gid: $gty { $( $rfield: self.$rid, )* },
                    )*
                }
            }
        }
    };
}

bitcoin_rs_node::option_rows!(emit_cli);
