//! The node option table: every operator option declared once.
//!
//! [`option_rows!`] holds one row per operator-settable node option. Each row
//! names its configuration slot, its text value grammar, and its spelling on
//! every process-input surface: the command line, the environment, the TOML
//! configuration file, and Bitcoin Core's `bitcoin.conf`. Consumer macros
//! derive each surface from the same rows, so an option is written once and
//! appears everywhere with one grammar.
//!
//! PRE: each row names a [`UserConfig`] slot that is `None` until a surface
//! sets it.
//! POST: every surface a row lists parses its own spelling of that option
//! into the slot with the row's grammar.
//! INVARIANT: a surface column absent from a row means the option does not
//! exist on that surface. The chainstate-journal bounds are environment-only
//! (their TOML spellings live inside the `chainstate_journal` table group),
//! and the notification adapters are a TOML-only whole-value option.

use std::convert::Infallible;
use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr as _;

use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use serde::de::{Error as _, MapAccess, Visitor};

use crate::config::{NetworkSelection, NotificationConfig, ScriptIndexMode};
use bitcoin_rs_chainstate::ValidationMode;
use bitcoin_rs_storage::StorageBackend;

/// Parses a network selection spelling.
pub fn parse_network(value: &str) -> std::result::Result<NetworkSelection, String> {
    NetworkSelection::from_str(value)
}

/// Parses a storage backend name.
pub fn parse_storage_backend(value: &str) -> std::result::Result<StorageBackend, String> {
    StorageBackend::from_str(value)
}

/// Parses a script-index mode, keeping the historical boolean spellings.
pub fn parse_script_index(value: &str) -> std::result::Result<ScriptIndexMode, String> {
    ScriptIndexMode::parse(value).ok_or_else(|| {
        format!("invalid scriptindex value `{value}`: expected `utxo`, `full`, or a boolean")
    })
}

/// Parses a validation mode.
pub fn parse_validation_mode(value: &str) -> std::result::Result<ValidationMode, String> {
    ValidationMode::parse(value).ok_or_else(|| {
        format!(
            "invalid validation-mode value `{value}`: expected `full`, `assume-valid`, or `fast`"
        )
    })
}

/// Parses an environment or file boolean.
pub fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("invalid boolean {other}"),
    }
}

/// Parses P2P message-start bytes as eight hexadecimal characters.
pub fn parse_p2p_magic(value: &str) -> Result<[u8; 4]> {
    let value = value.trim();
    ensure!(
        value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "p2p magic must be exactly eight hexadecimal characters"
    );
    let mut magic = [0; 4];
    for (index, slot) in magic.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(magic)
}

/// Parses one fixed outbound peer endpoint: a socket address or a
/// `host:port` pair whose hostname is resolved later.
pub fn parse_connect_endpoint(value: &str) -> std::result::Result<String, String> {
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

/// Parses a comma-separated listener bind list.
pub fn parse_socket_list(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| Ok(part.trim().parse()?))
        .collect()
}

/// Parses a comma-separated fixed-peer list.
pub fn parse_connect_list(value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| parse_connect_endpoint(part.trim()).map_err(anyhow::Error::msg))
        .collect()
}

/// Accepts any text as a free-form string.
///
/// The wrap is deliberate: a row's grammar is one function shape, so an option
/// that cannot fail still reports through `Result`.
#[allow(clippy::unnecessary_wraps)]
fn parse_text(value: &str) -> std::result::Result<String, Infallible> {
    Ok(value.to_owned())
}

/// Accepts any text as a filesystem path, for the same reason as
/// [`parse_text`].
#[allow(clippy::unnecessary_wraps)]
fn parse_path(value: &str) -> std::result::Result<PathBuf, Infallible> {
    Ok(PathBuf::from(value))
}

/// Applies a row grammar to one text value.
fn parsed<T, E: fmt::Display>(
    value: &str,
    grammar: fn(&str) -> std::result::Result<T, E>,
) -> Result<T> {
    grammar(value).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Reads an environment value, naming the variable when it is not UTF-8.
fn environment_text<'a>(key: &str, value: &'a OsStr) -> Result<&'a str> {
    value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("environment variable {key} is not valid UTF-8"))
}

/// One TOML key arm of the `UserConfig` deserializer.
macro_rules! toml_row {
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, native($want:literal)) => {
        if $key == $want {
            $($slot).* = Some($map.next_value()?);
            $matched = true;
        }
    };
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, text($want:literal, $gram:expr)) => {
        if $key == $want {
            let value: String = $map.next_value()?;
            $($slot).* = Some(
                $crate::options::parsed(&value, $gram)
                    .map_err($crate::options::toml_error::<_, A::Error>)?,
            );
            $matched = true;
        }
    };
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, each($want:literal, $gram:expr)) => {
        if $key == $want {
            let values: Vec<String> = $map.next_value()?;
            $($slot).* = Some(
                values
                    .into_iter()
                    .map(|value| {
                        $crate::options::parsed(&value, $gram)
                            .map_err($crate::options::toml_error::<_, A::Error>)
                    })
                    .collect::<std::result::Result<_, _>>()?,
            );
            $matched = true;
        }
    };
    ($key:ident, $($slot:ident).*, $map:ident, $matched:ident, table($want:literal)) => {
        if $key == $want {
            $($slot).* = $map.next_value()?;
            $matched = true;
        }
    };
}

/// Re-raises a value-grammar error as a deserializer error.
fn toml_error<E: fmt::Display, F: serde::de::Error>(error: E) -> F {
    F::custom(error)
}

/// Generates the source-layer types, the environment surface, and the flat
/// TOML surface from the option table.
macro_rules! emit_user_config {
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
        $(
            $(#[$gdoc])*
            #[derive(Clone, Debug, Default)]
            $(#[$gattr])*
            pub struct $gty {
                $(
                    $(#[$rdoc])*
                    pub $rfield: $rty,
                )*
            }
        )*

        /// One parser-independent configuration layer: every option is a slot
        /// that is `None` until a surface sets it.
        #[derive(Clone, Debug, Default)]
        pub struct UserConfig {
            $(
                $(#[$fdoc])*
                pub $fid: $fty,
            )*
            $(
                $(#[$gdoc])*
                pub $gid: $gty,
            )*
        }

        impl UserConfig {
            /// Overlays `upper` onto `self` field by field: a field `upper`
            /// sets wins, a field `upper` leaves unset keeps this layer's
            /// value.
            ///
            /// INVARIANT: the RPC credentials are one auth group rather than
            /// three independent fields. The highest auth-bearing layer owns
            /// the mode: a layer that sets a cookie drops the basic
            /// credentials it accumulated, and a layer that sets either basic
            /// credential drops an accumulated cookie. Within one layer the
            /// two halves of Basic authentication merge field-wise.
            pub fn overlay(&mut self, upper: &Self) {
                $(
                    if upper.$fid.is_some() {
                        self.$fid.clone_from(&upper.$fid);
                    }
                )*
                $(
                    $(
                        if upper.$gid.$rfield.is_some() {
                            self.$gid.$rfield.clone_from(&upper.$gid.$rfield);
                        }
                    )*
                )*
                if upper.rpc.cookie.is_some() {
                    self.rpc.user = None;
                    self.rpc.password = None;
                } else if upper.rpc.user.is_some() || upper.rpc.password.is_some() {
                    self.rpc.cookie = None;
                }
            }

            /// Parses one environment entry into this layer.
            ///
            /// PRE: `key` is an environment variable name.
            /// POST: when `key` names a table option, that slot holds the
            /// parsed value; any other name leaves this layer untouched.
            pub fn apply_env(&mut self, key: &str, value: &OsStr) -> Result<()> {
                match key {
                    $(
                        $(
                            $ekey => {
                                let text = $crate::options::environment_text(key, value)?;
                                self.$fid = Some($crate::options::parsed(text, $egram)?);
                            }
                        )?
                    )*
                    $(
                        $(
                            $(
                                $gekey => {
                                    let text =
                                        $crate::options::environment_text(key, value)?;
                                    self.$gid.$rfield =
                                        Some($crate::options::parsed(text, $gegram)?);
                                }
                            )?
                        )*
                    )*
                    _ => {}
                }
                Ok(())
            }
        }

        impl<'de> Deserialize<'de> for UserConfig {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                /// The TOML spellings this layer accepts, for the
                /// unknown-field error.
                const TOML_KEYS: &[&str] = &[
                    $(
                        $( $tkey, )?
                    )*
                    $(
                        $( $( $gtkey, )? )*
                        $( $gkey, )?
                    )*
                ];

                struct LayerVisitor;

                impl<'de> Visitor<'de> for LayerVisitor {
                    type Value = UserConfig;

                    fn expecting(
                        &self,
                        formatter: &mut fmt::Formatter<'_>,
                    ) -> fmt::Result {
                        formatter.write_str("a node configuration layer")
                    }

                    fn visit_map<A>(
                        self,
                        mut map: A,
                    ) -> std::result::Result<UserConfig, A::Error>
                    where
                        A: MapAccess<'de>,
                    {
                        let mut config = UserConfig::default();
                        while let Some(key) = map.next_key::<String>()? {
                            let mut matched = false;
                            $(
                                $(
                                    toml_row!(
                                        key, config.$fid, map, matched,
                                        $tmode ( $tkey $(, $tgram )? )
                                    );
                                )?
                            )*
                            $(
                                $(
                                    $(
                                        toml_row!(
                                            key, config.$gid.$rfield, map, matched,
                                            $gtmode ( $gtkey $(, $gtgram )? )
                                        );
                                    )?
                                )*
                                $(
                                    toml_row!(
                                        key, config.$gid, map, matched, table($gkey)
                                    );
                                )?
                            )*
                            if !matched {
                                return Err(A::Error::unknown_field(&key, TOML_KEYS));
                            }
                        }
                        Ok(config)
                    }
                }

                deserializer.deserialize_map(LayerVisitor)
            }
        }
    };
}

#[macro_export]
/// Forwards the canonical option table to a consumer macro.
///
/// The table grammar is one `fields` block of top-level rows and one `groups`
/// block of grouped rows. Each row carries its documentation, its type, and
/// any of four surface columns:
///
/// ```text
/// fields {
///     /// help text
///     id: Type {
///         cli[#[arg(long = "flag", …)]]  env["BITCOIN_RS_ID", grammar]
///         toml native("key")             conf["core-key"]
///     }
/// }
/// groups {
///     /// group help text
///     group id: GroupType table("nested-key") extra-attrs {
///         /// help text
///         field as id: Type { …same columns… }
///     }
/// }
/// ```
///
/// `toml` modes are `native` (the value's own deserializer), `text` (one
/// string through the row grammar), and `each` (a list, element by element).
/// A `table` group deserializes as one nested TOML table and its rows carry
/// no TOML column.
///
/// Invoke it with a consumer macro name; the consumer receives the canonical
/// table and expands the surface it owns.
macro_rules! option_rows {
    ($m:ident) => {
        $m! {
            fields {
                /// Network profile.
                network: Option<NetworkSelection> {
                    cli[#[arg(long = "network", value_parser = parse_network)]]
                    env["BITCOIN_RS_NETWORK", parse_network]
                    toml native("network")
                }
                /// Node data directory.
                data_dir: Option<PathBuf> {
                    cli[#[arg(long = "data-dir")]]
                    env["BITCOIN_RS_DATA_DIR", parse_path]
                    toml native("data_dir")
                }
                /// External notification adapters. `None` means this layer does not
                /// speak to them.
                notifications: Option<NotificationConfig> {
                    cli[#[arg(skip)]]
                    toml native("notifications")
                }
            }
            groups {
                /// User-supplied storage overrides.
                group storage: StorageOverrides {
                    /// Selected storage backend.
                    backend as storage_backend: Option<StorageBackend> {
                        cli[#[arg(long = "storage-backend", value_parser = parse_storage_backend)]]
                        env["BITCOIN_RS_STORAGE_BACKEND", parse_storage_backend]
                        toml text("storage_backend", parse_storage_backend)
                    }
                    /// Database cache budget in MiB.
                    dbcache_mb as dbcache_mb: Option<u64> {
                        cli[#[arg(long = "dbcache-mb")]]
                        env["BITCOIN_RS_DBCACHE_MB", str::parse]
                        toml native("dbcache_mb")
                        conf["dbcache"]
                    }
                    /// Pruning target in MiB.
                    prune_target_mb as prune_target_mb: Option<u64> {
                        cli[#[arg(long = "prune-target-mb")]]
                        env["BITCOIN_RS_PRUNE_TARGET_MB", str::parse]
                        toml native("prune_target_mb")
                        conf["prune"]
                    }
                }
                /// User-supplied P2P overrides.
                group p2p: P2pOverrides {
                    /// P2P message-start bytes.
                    magic as p2p_magic: Option<[u8; 4]> {
                        cli[#[arg(long = "p2p-magic", value_parser = parse_p2p_magic)]]
                        env["BITCOIN_RS_P2P_MAGIC", parse_p2p_magic]
                        toml text("p2p_magic", parse_p2p_magic)
                    }
                    /// P2P listener bind addresses.
                    listen as p2p_listen: Option<Vec<SocketAddr>> {
                        cli[#[arg(long = "p2p-listen", value_delimiter = ',')]]
                        env["BITCOIN_RS_P2P_LISTEN", parse_socket_list]
                        toml native("p2p_listen")
                    }
                    /// Whether DNS seeds are enabled.
                    dns_seeds as dns_seeds_enabled: Option<bool> {
                        cli[#[arg(long = "dns-seeds-enabled")]]
                        env["BITCOIN_RS_DNS_SEEDS_ENABLED", parse_bool]
                        toml native("dns_seeds_enabled")
                    }
                    /// Fixed outbound peer endpoints.
                    connect as connect: Option<Vec<String>> {
                        cli[#[arg(long = "connect", value_delimiter = ',', value_parser = parse_connect_endpoint)]]
                        env["BITCOIN_RS_CONNECT", parse_connect_list]
                        toml each("connect", parse_connect_endpoint)
                    }
                    /// Whether fast sync (shallow, early fan-out over a larger
                    /// outbound set) is enabled.
                    fast_sync as fast_sync: Option<bool> {
                        cli[#[arg(long = "fast-sync", num_args = 0..=1, default_missing_value = "true")]]
                        env["BITCOIN_RS_FAST_SYNC", parse_bool]
                        toml native("fast_sync")
                    }
                }
                /// User-supplied RPC overrides.
                group rpc: RpcOverrides {
                    /// JSON-RPC bind address.
                    bind as rpc_bind: Option<SocketAddr> {
                        cli[#[arg(long = "rpc-bind")]]
                        env["BITCOIN_RS_RPC_BIND", str::parse]
                        toml native("rpc_bind")
                    }
                    /// Whether the REST gateway is enabled.
                    rest as rest: Option<bool> {
                        cli[#[arg(long = "rest")]]
                        env["BITCOIN_RS_REST", parse_bool]
                        toml native("rest")
                        conf["rest"]
                    }
                    /// Basic-auth username.
                    user as rpc_user: Option<String> {
                        cli[#[arg(long = "rpc-user")]]
                        env["BITCOIN_RS_RPC_USER", parse_text]
                        toml native("rpc_user")
                        conf["rpcuser"]
                    }
                    /// Basic-auth password.
                    password as rpc_password: Option<String> {
                        cli[#[arg(long = "rpc-password")]]
                        env["BITCOIN_RS_RPC_PASSWORD", parse_text]
                        toml native("rpc_password")
                        conf["rpcpassword"]
                    }
                    /// Cookie-auth path.
                    cookie as rpc_cookie: Option<PathBuf> {
                        cli[#[arg(long = "rpc-cookie")]]
                        env["BITCOIN_RS_RPC_COOKIE", parse_path]
                        toml native("rpc_cookie")
                        conf["rpccookiefile"]
                    }
                }
                /// User-supplied index overrides.
                group indexes: IndexOverrides {
                    /// Whether the transaction index is enabled.
                    txindex as txindex: Option<bool> {
                        cli[#[arg(long = "txindex")]]
                        env["BITCOIN_RS_TXINDEX", parse_bool]
                        toml native("txindex")
                        conf["txindex"]
                    }
                    /// Script index mode.
                    script_index as script_index: Option<ScriptIndexMode> {
                        cli[#[arg(long = "scriptindex", visible_alias = "script-index", num_args = 0..=1, default_missing_value = "true", value_parser = parse_script_index)]]
                        env["BITCOIN_RS_SCRIPTINDEX", parse_script_index]
                        toml text("script_index", parse_script_index)
                    }
                }
                /// User-supplied observability overrides.
                group observability: ObservabilityOverrides {
                    /// Tracing filter level.
                    log_level as log_level: Option<String> {
                        cli[#[arg(long = "log-level")]]
                        env["BITCOIN_RS_LOG_LEVEL", parse_text]
                        toml native("log_level")
                    }
                    /// Optional Prometheus metrics bind address.
                    metrics_bind as metrics_bind: Option<SocketAddr> {
                        cli[#[arg(long = "metrics-bind")]]
                        env["BITCOIN_RS_METRICS_BIND", str::parse]
                        toml native("metrics_bind")
                    }
                }
                /// User-supplied validation overrides.
                group validation: ValidationOverrides {
                    /// Height through which script verification may be skipped.
                    assume_valid_height as assume_valid_height: Option<u32> {
                        cli[#[arg(long = "assume-valid-height")]]
                        env["BITCOIN_RS_ASSUME_VALID_HEIGHT", str::parse]
                        toml native("assume_valid_height")
                    }
                    /// Which script verification the apply path may skip.
                    mode as validation_mode: Option<ValidationMode> {
                        cli[#[arg(long = "validation-mode", value_parser = parse_validation_mode)]]
                        env["BITCOIN_RS_VALIDATION_MODE", parse_validation_mode]
                        toml text("validation_mode", parse_validation_mode)
                    }
                }
                /// User-supplied mining overrides.
                group mining: MiningOverrides {
                    /// Watch-only coinbase payout address. Decoded after every config
                    /// layer has been applied, against the resolved consensus network.
                    payout_address as mining_payout_address: Option<String> {
                        cli[#[arg(long = "mining-payout-address")]]
                        env["BITCOIN_RS_MINING_PAYOUT_ADDRESS", parse_text]
                        toml native("mining_payout_address")
                    }
                }
                /// User-supplied chainstate journal overrides.
                group chainstate_journal: ChainstateJournalOverrides
                table("chainstate_journal")
                #[derive(serde::Deserialize)]
                #[serde(default, deny_unknown_fields)]
                {
                    /// Whether the journal is active.
                    enabled as enabled: Option<bool> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL", parse_bool]
                    }
                    /// Durability batch size, in blocks.
                    blocks as blocks: Option<u32> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_BLOCKS", str::parse]
                    }
                    /// Durability batch period, in seconds.
                    seconds as seconds: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_SECONDS", str::parse]
                    }
                    /// Active-segment rotation threshold, in MiB.
                    rotate_mib as rotate_mib: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_ROTATE_MIB", str::parse]
                    }
                    /// Total-journal retention bound, in MiB.
                    max_journal_mib as max_journal_mib: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_MAX_JOURNAL_MIB", str::parse]
                    }
                    /// Backpressure threshold, in blocks.
                    max_lag_blocks as max_lag_blocks: Option<u32> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_MAX_LAG_BLOCKS", str::parse]
                    }
                    /// Backpressure threshold, in seconds.
                    max_lag_seconds as max_lag_seconds: Option<u64> {
                        cli[#[arg(skip)]]
                        env["BITCOIN_RS_CHAINSTATE_JOURNAL_MAX_LAG_SECONDS", str::parse]
                    }
                }
            }
        }
    };
}

option_rows!(emit_user_config);
