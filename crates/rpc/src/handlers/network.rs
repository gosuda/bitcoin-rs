use alloc::sync::Arc;

use core::str::FromStr;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hex::DisplayHex;
use bitcoin_rs_p2p::{BannedSubnet, IpSubnet};
use bitcoin_rs_primitives::{USER_AGENT, unix_time_secs};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};

use crate::context::Context;
use crate::convert::{i64_saturated, sat_to_btc, typed_to_sonic, typed_to_sonic_omitting_nulls};
use crate::error::RpcError;
use crate::handlers::{
    ensure_no_params, optional_bool, params_array, required_str, wrong_type_plain,
};
use corepc_types::v31::{self, ConnectionType, GetNetworkInfoNetwork, TransportProtocolType};

const DEFAULT_RELAY_FEE_BTC_PER_KVB: f64 = 0.00001;
const DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB: f64 = 0.00001;
const DEFAULT_BAN_TIME_SECS: u64 = 24 * 60 * 60;

fn parse_setban_target(raw: &str) -> Result<IpSubnet, RpcError> {
    if let Ok(subnet) = IpSubnet::from_str(raw) {
        return Ok(subnet);
    }

    if let Ok(socket) = SocketAddr::from_str(raw) {
        return Ok(IpSubnet::from_ip(socket.ip()));
    }

    if let Ok(ip) = IpAddr::from_str(raw) {
        return Ok(IpSubnet::from_ip(ip));
    }

    Err(RpcError::InvalidParams(
        "subnet must be IP, IP/prefix, or host:port",
    ))
}

fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs())
}

/// Resolves the finite expiry requested by `setban`.
///
/// SETBAN-EXPIRY-01: zero relative bantime uses `DEFAULT_BAN_TIME_SECS`;
/// absolute bantime is measured from `UNIX_EPOCH`. An unrepresentable expiry
/// returns `RpcError::InvalidParameter` (-8) before any ban-list mutation.
/// It must never become `BannedSubnet::banned_until = None`, which means a
/// permanent ban. Signed-input policy is unchanged.
///
/// SETBAN-ABSOLUTE-01: Bitcoin Core v31.1 `src/rpc/net.cpp::setban` rejects
/// absolute bantime below the current whole epoch second with
/// `RpcError::InvalidParameter` (-8), before any ban-list mutation. Equality
/// is allowed, including when `now` has subsecond precision.
fn ban_until(now: SystemTime, bantime: u64, absolute: bool) -> Result<SystemTime, RpcError> {
    if absolute && bantime < epoch_seconds(now) {
        return Err(RpcError::InvalidParameter(
            "Error: Absolute timestamp is in the past".to_owned(),
        ));
    }
    let until = if absolute {
        UNIX_EPOCH.checked_add(Duration::from_secs(bantime))
    } else {
        let duration = if bantime == 0 {
            Duration::from_secs(DEFAULT_BAN_TIME_SECS)
        } else {
            Duration::from_secs(bantime)
        };
        now.checked_add(duration)
    };
    until.ok_or_else(|| {
        RpcError::InvalidParameter("bantime exceeds supported timestamp range".to_owned())
    })
}

fn optional_u64(params: &Value, index: usize, default: u64) -> Result<u64, RpcError> {
    let Some(array) = params.as_array() else {
        return Ok(default);
    };
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    if !value.is_number() {
        return Err(wrong_type_plain(value, "number"));
    }
    value
        .as_u64()
        .ok_or_else(|| RpcError::InvalidParameter("value is out of range".to_owned()))
}

/// Reports the configured reachability of each network.
///
/// Reachability is *outbound* reachability: Core reports `reachable` for a
/// network we can dial, and `limited` when we cannot. For onion that means the
/// SOCKS route an onion dial goes through — `--onion`, or `--proxy` as its
/// documented fallback (`DialRoutes::onion`) — and nothing else.
///
/// A Tor control connection is deliberately not enough. `tor_control` only
/// publishes an inbound onion service and retires stale inbound streams; it
/// carries no dial capability, so a node configured with control alone cannot
/// originate a single onion connection. Reporting it as reachable would tell
/// an operator their node can reach the onion network when every outbound
/// onion dial fails with "no onion proxy route is configured". Inbound
/// service publication is already reported where it belongs: the endpoint
/// appears in `localaddresses`.
fn configured_networks(overlay: &bitcoin_rs_p2p::OverlayConfig) -> Vec<GetNetworkInfoNetwork> {
    let onlynet = &overlay.onlynet;
    let allowed =
        |label: bitcoin_rs_primitives::NetworkLabel| onlynet.is_empty() || onlynet.contains(&label);
    let onion_proxy = overlay.onion.or(overlay.proxy);
    let ipv4_reachable = allowed(bitcoin_rs_primitives::NetworkLabel::Ipv4);
    let ipv6_reachable = allowed(bitcoin_rs_primitives::NetworkLabel::Ipv6);
    let onion_reachable =
        allowed(bitcoin_rs_primitives::NetworkLabel::Onion) && onion_proxy.is_some();
    let i2p_reachable =
        allowed(bitcoin_rs_primitives::NetworkLabel::I2p) && overlay.i2p_sam.is_some();
    [
        (
            "ipv4",
            !ipv4_reachable,
            ipv4_reachable,
            overlay
                .proxy
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            overlay.proxy.is_some() && overlay.proxy_randomize_credentials,
        ),
        (
            "ipv6",
            !ipv6_reachable,
            ipv6_reachable,
            overlay
                .proxy
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            overlay.proxy.is_some() && overlay.proxy_randomize_credentials,
        ),
        (
            "onion",
            !onion_reachable,
            onion_reachable,
            onion_proxy.map(|addr| addr.to_string()).unwrap_or_default(),
            onion_proxy.is_some(),
        ),
        (
            "i2p",
            !i2p_reachable,
            i2p_reachable,
            overlay
                .i2p_sam
                .map(|addr| addr.to_string())
                .unwrap_or_default(),
            false,
        ),
    ]
    .into_iter()
    .map(
        |(name, limited, reachable, proxy, randomize)| GetNetworkInfoNetwork {
            name: name.to_owned(),
            limited,
            reachable,
            proxy,
            proxy_randomize_credentials: randomize,
        },
    )
    .collect()
}

pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.network.peer_table.infos();
    let total = peers.len();
    let inbound = peers.iter().filter(|p| p.inbound).count();
    let outbound = total.saturating_sub(inbound);
    let network_active = ctx.network.p2p.network_active();
    // Reachability and proxy strings are *configured*, never probed:
    // they state what the operator configured, exactly as Core reports
    // its configured proxies without testing them.
    let networks = configured_networks(&ctx.network.overlay);
    let local_addresses = ctx
        .network
        .p2p
        .overlay_addresses()
        .into_iter()
        .map(|endpoint| v31::GetNetworkInfoAddress {
            address: endpoint.host().to_string(),
            port: endpoint.port(),
            score: 0,
        })
        .collect::<Vec<_>>();
    let mut local_services =
        ctx.network.local_services & !bitcoin::p2p::ServiceFlags::COMPACT_FILTERS.to_u64();
    if ctx
        .indexes
        .compact_filters
        .as_ref()
        .is_some_and(|index| index.filter_index_info().is_ok_and(|info| info.synced))
    {
        local_services |= bitcoin::p2p::ServiceFlags::COMPACT_FILTERS.to_u64();
    }
    typed_to_sonic(&v31::GetNetworkInfo {
        version: usize::try_from(bitcoin_rs_primitives::client_version()).unwrap_or(usize::MAX),
        subversion: USER_AGENT.to_owned(),
        protocol_version: usize::try_from(bitcoin_rs_p2p::wire::PROTOCOL_VERSION)
            .unwrap_or(usize::MAX),
        local_services: format!("{local_services:016x}"),
        local_services_names: bitcoin_rs_p2p::service_flag_names(local_services)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        local_relay: true,
        time_offset: isize::try_from(median_time_offset(&peers)).unwrap_or(0),
        connections: total,
        connections_in: inbound,
        connections_out: outbound,
        network_active,
        networks,
        relay_fee: DEFAULT_RELAY_FEE_BTC_PER_KVB,
        incremental_fee: DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB,
        local_addresses,
        warnings: Vec::new(),
    })
}

/// Samples below which Core does not compute an offset at all.
///
/// `TimeOffsets::Median` in `node/timeoffsets.cpp`: "Only calculate the median
/// if we have 5 or more offsets". Below it the answer is zero -- not because
/// the clocks agree, but because too few samples is not a measurement.
const MIN_TIME_OFFSET_SAMPLES: usize = 5;

/// The node's clock offset, as the median of what its outbound peers claim.
///
/// Bitcoin Core samples each peer's declared time at handshake and reports the
/// median of those samples. The figure exists to warn an operator that their
/// own clock is wrong, so what matters is that no one else can produce that
/// warning: hence outbound peers only, and hence a floor below which there is
/// no answer at all.
///
/// With too few samples the offset is zero, which is also what Core answers.
/// The zero is "not measured", not "the clocks agree" -- the two are
/// indistinguishable in this field, in Core as here.
///
/// One difference from Core worth naming: Core medians over a rolling deque of
/// the last 50 offsets it sampled, which outlives the connections that produced
/// them. This medians over the peers connected now. The two agree while the
/// peer set is stable and diverge after churn, where Core still remembers a
/// departed peer's sample and this does not.
fn median_time_offset(peers: &[bitcoin_rs_p2p::PeerInfo]) -> i64 {
    // **Outbound peers only.** Core's reason, in its own words at the call
    // site in `net_processing.cpp`: "Don't use timedata samples from inbound
    // peers to make it harder for others to create false warnings about our
    // clock being out of sync." Anyone can open an inbound connection and
    // declare any time they like; medianing over all of them hands that
    // attacker the node's reported clock offset, and with it the operator's
    // belief about whether the machine's clock is wrong.
    let mut offsets: Vec<i64> = peers
        .iter()
        .filter(|peer| !peer.inbound)
        .map(|peer| peer.time_offset)
        .collect();
    if offsets.len() < MIN_TIME_OFFSET_SAMPLES {
        return 0;
    }
    offsets.sort_unstable();
    // The element at `len / 2`, on an even count as on an odd one. Core takes
    // exactly this and says why it does not interpolate: "approximate median is
    // good enough, keep it simple". Averaging the two middle values would
    // answer a number neither peer reported, and would differ from Core on
    // every even sample count.
    offsets.get(offsets.len() / 2).copied().unwrap_or(0)
}

/// Renders every handshake-complete connection, including anonymous inbound
/// overlay sessions.
///
/// `id` is the connection's own process-unique identity
/// ([`bitcoin_rs_p2p::PeerLease::node_id`]) — Core's `nodeid`, not a position
/// in this array. The distinction is observable: a positional index shifts
/// for every peer behind a departed one and is reused by the next connection
/// to register, so a caller that read an index and then acted on it could
/// reach a different connection than the one it described. A connection
/// identity names one connection for exactly as long as that connection is
/// live, and it is the value `disconnectnode`'s `nodeid` selects. Sessions
/// are still ordered by it, so the array keeps connection order.
///
/// The id is serialized at its full unsigned 64-bit width. The pinned
/// `corepc_types::v31::PeerInfo::id` is a `u32`, but connection identities
/// come from a counter that only rises and is never reused, so on a
/// long-running node every id past the 2^32nd connection would fail the whole
/// query, and narrowing or clamping it would alias two live connections.
/// Rows are therefore rendered through [`PeerInfoWire`], which differs from
/// the pinned type in the width of `id` alone. `disconnectnode` selects by
/// the same 64-bit value.
pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    // `sessions` carries the lease — role and manual flag — that `infos`
    // strips, so `connection_type` and `relaytxes` can report the connection
    // kind the operator actually opened.
    let sessions = ctx.network.peer_table.sessions();
    let rows = sessions
        .iter()
        .filter_map(|session| {
            let peer = session.info.as_ref()?;
            let fee_filter = sat_to_btc(
                ctx.network
                    .peer_table
                    .transaction_fee_filter(session.lease.source(session.endpoint)),
            );
            Some(peer_info_wire(session, peer, fee_filter))
        })
        .collect::<Vec<_>>();
    typed_to_sonic_omitting_nulls(&rows)
}

/// Whether we selected the peer, and the peer selected us, as a high-bandwidth
/// compact-block relay. Flattened into the row, so the two keys stay adjacent
/// top-level fields as in the pinned type.
#[derive(serde::Serialize)]
struct Bip152Flags {
    bip152_hb_to: bool,
    bip152_hb_from: bool,
}

/// One `getpeerinfo` row: `corepc_types::v31::PeerInfo` field for field, with
/// the same keys, except that `id` is the connection's full `u64` identity
/// rather than a `u32`. Unset optional fields are dropped by
/// [`typed_to_sonic_omitting_nulls`], exactly as for the pinned type.
/// `getpeerinfo_rows_match_the_pinned_v31_row` holds the two shapes together.
#[derive(serde::Serialize)]
struct PeerInfoWire {
    id: u64,
    #[serde(rename = "addr")]
    address: String,
    #[serde(rename = "addrbind")]
    address_bind: Option<String>,
    #[serde(rename = "addrlocal")]
    address_local: Option<String>,
    network: String,
    mapped_as: Option<u32>,
    services: String,
    #[serde(rename = "servicesnames")]
    services_names: Vec<String>,
    #[serde(rename = "relaytxes")]
    relay_transactions: bool,
    #[serde(rename = "lastsend")]
    last_send: i64,
    #[serde(rename = "lastrecv")]
    last_received: i64,
    last_transaction: i64,
    last_block: i64,
    #[serde(rename = "bytessent")]
    bytes_sent: u64,
    #[serde(rename = "bytesrecv")]
    bytes_received: u64,
    #[serde(rename = "conntime")]
    connection_time: i64,
    #[serde(rename = "timeoffset")]
    time_offset: i64,
    #[serde(rename = "pingtime")]
    ping_time: Option<f64>,
    #[serde(rename = "minping")]
    minimum_ping: Option<f64>,
    #[serde(rename = "pingwait")]
    ping_wait: Option<f64>,
    version: u32,
    #[serde(rename = "subver")]
    subversion: String,
    inbound: bool,
    #[serde(flatten)]
    bip152: Bip152Flags,
    #[serde(rename = "startingheight")]
    starting_height: Option<i64>,
    presynced_headers: Option<i64>,
    synced_headers: Option<i64>,
    synced_blocks: Option<i64>,
    inflight: Option<Vec<u64>>,
    #[serde(rename = "addr_relay_enabled")]
    addresses_relay_enabled: Option<bool>,
    #[serde(rename = "addr_processed")]
    addresses_processed: Option<usize>,
    #[serde(rename = "addr_rate_limited")]
    addresses_rate_limited: Option<usize>,
    permissions: Vec<String>,
    #[serde(rename = "minfeefilter")]
    minimum_fee_filter: f64,
    #[serde(rename = "bytessent_per_msg")]
    bytes_sent_per_message: std::collections::BTreeMap<String, u64>,
    #[serde(rename = "bytesrecv_per_msg")]
    bytes_received_per_message: std::collections::BTreeMap<String, u64>,
    inv_to_send: u64,
    last_inv_sequence: u64,
    connection_type: Option<ConnectionType>,
    transport_protocol_type: TransportProtocolType,
    session_id: String,
}

/// Renders one handshake-complete session as a `getpeerinfo` row. The row's
/// `id` is the session lease's own `node_id()`, the only place it is read.
fn peer_info_wire(
    session: &bitcoin_rs_p2p::PeerSession,
    peer: &bitcoin_rs_p2p::PeerInfo,
    minimum_fee_filter: f64,
) -> PeerInfoWire {
    PeerInfoWire {
        id: session.lease.node_id(),
        address: peer
            .endpoint
            .map_or_else(|| "unknown".to_owned(), |endpoint| endpoint.to_string()),
        address_bind: Some(peer.addr_bind.to_string()),
        address_local: None,
        network: peer.network.as_str().to_owned(),
        mapped_as: None,
        services: format!("{:016x}", peer.services),
        services_names: peer
            .services_names()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        // Only full-relay connections carry the transaction relay
        // stream; block-relay-only and inbound-nonrelay leases do not.
        relay_transactions: peer.relay_transactions
            && session.lease.role() == bitcoin_rs_p2p::PeerRole::FullRelay,
        last_send: i64::try_from(peer.counters.last_send()).unwrap_or(i64::MAX),
        last_received: i64::try_from(peer.counters.last_recv()).unwrap_or(i64::MAX),
        last_transaction: 0,
        last_block: 0,
        bytes_sent: peer.counters.bytes_sent(),
        bytes_received: peer.counters.bytes_recv(),
        connection_time: i64_saturated(peer.conn_time),
        time_offset: peer.time_offset,
        // No `pingtime`, `minping` or `pingwait`. This node never sends a
        // ping, so it has never measured a round trip, and Core omits all
        // three until it has one. Reporting `0.0` would state a round trip
        // of zero seconds -- a placeholder in the shape of a measurement,
        // and the best-looking latency a peer could possibly have.
        ping_time: None,
        minimum_ping: None,
        ping_wait: None,
        version: peer.version,
        subversion: peer.user_agent.clone(),
        inbound: peer.inbound,
        // Core's `bip152_hb_to`/`bip152_hb_from` (v25+): whether WE have
        // selected this peer as a high-bandwidth compact-block relay
        // (the announcement worker's current set), and whether the peer
        // has selected US (its `sendcmpct(true)` preference recorded at
        // handshake). High-bandwidth peers announce new blocks as
        // unsolicited `cmpctblock` instead of `inv`.
        bip152: Bip152Flags {
            bip152_hb_to: session.bip152_hb_to,
            bip152_hb_from: session.bip152_hb_from,
        },
        // Core 31 does not emit `startingheight` at all -- the name does
        // not appear anywhere in its source. corepc keeps the field
        // `Option` for older versions, so `None` is what v31 looks like.
        starting_height: None,
        presynced_headers: Some(-1),
        synced_headers: Some(-1),
        synced_blocks: Some(-1),
        inflight: Some(Vec::new()),
        addresses_relay_enabled: None,
        addresses_processed: None,
        addresses_rate_limited: None,
        permissions: if session.lease.is_no_ban() {
            vec!["noban".to_owned()]
        } else {
            Vec::new()
        },
        minimum_fee_filter,
        bytes_sent_per_message: std::collections::BTreeMap::new(),
        bytes_received_per_message: std::collections::BTreeMap::new(),
        inv_to_send: 0,
        last_inv_sequence: 0,
        connection_type: Some(if session.lease.is_inbound() {
            ConnectionType::Inbound
        } else if session.lease.is_manual() {
            ConnectionType::Manual
        } else {
            match session.lease.role() {
                bitcoin_rs_p2p::PeerRole::BlockRelayOnly => ConnectionType::BlockRelayOnly,
                bitcoin_rs_p2p::PeerRole::FullRelay => ConnectionType::OutboundFullRelay,
            }
        }),
        // Core reports the BIP324 session id as hex in byte order, and an
        // empty string for v1.
        transport_protocol_type: match peer.transport {
            bitcoin_rs_p2p::TransportProtocol::V1 => TransportProtocolType::V1,
            bitcoin_rs_p2p::TransportProtocol::V2 { .. } => TransportProtocolType::V2,
        },
        session_id: match peer.transport {
            bitcoin_rs_p2p::TransportProtocol::V1 => String::new(),
            bitcoin_rs_p2p::TransportProtocol::V2 { session_id } => {
                session_id.to_lower_hex_string()
            }
        },
    }
}

pub(crate) fn getaddednodeinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let _ = params_array(params)?;
    let added = ctx.network.p2p.added_nodes();
    let entries = added
        .into_iter()
        .map(|addr| v31::AddedNode {
            added_node: addr.to_string(),
            connected: false,
            addresses: Vec::new(),
        })
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::GetAddedNodeInfo(entries))
}

pub(crate) fn listbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let banned = ctx.network.p2p.banned();
    let now = unix_time_secs();
    let entries = banned
        .iter()
        .map(|entry| {
            let banned_until = entry.banned_until.map_or(0, epoch_seconds);
            let ban_created = epoch_seconds(entry.ban_created);
            v31::Banned {
                address: entry.subnet.to_string(),
                ban_created: u32::try_from(ban_created).unwrap_or(u32::MAX),
                banned_until: u32::try_from(banned_until).unwrap_or(u32::MAX),
                ban_duration: u32::try_from(banned_until.saturating_sub(ban_created))
                    .unwrap_or(u32::MAX),
                time_remaining: u32::try_from(banned_until.saturating_sub(now)).unwrap_or(u32::MAX),
            }
        })
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::ListBanned(entries))
}

pub(crate) fn setban(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let subnet_str = required_str(params, 0, "subnet is required")?;
    let command = required_str(params, 1, "command is required")?;
    let subnet = parse_setban_target(subnet_str)?;
    match command {
        "add" => {
            let now = SystemTime::now();
            let bantime = optional_u64(params, 2, 0)?;
            let absolute = optional_bool(params, 3, false)?;
            let banned_until = ban_until(now, bantime, absolute)?;
            ctx.network.p2p.set_ban(BannedSubnet {
                subnet,
                banned_until: Some(banned_until),
                ban_created: now,
                reason: "manual".to_owned(),
            });
        }
        "remove" => {
            ctx.network.p2p.remove_ban(subnet);
        }
        _ => return Err(RpcError::InvalidParams("command must be 'add' or 'remove'")),
    }
    Ok(Value::new_null())
}

pub(crate) fn clearbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    ctx.network.p2p.clear_banned();
    Ok(Value::new_null())
}

pub(crate) fn setnetworkactive(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let state = array
        .first()
        .and_then(JsonValueTrait::as_bool)
        .ok_or(RpcError::InvalidParams("state must be a boolean"))?;
    ctx.network.p2p.set_network_active(state);
    typed_to_sonic(&v31::SetNetworkActive(state))
}
pub(crate) fn ping(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    // Core's `ping` schedules a P2P ping; we don't have async-ping wiring yet,
    // so we return null per the Core contract. Per-peer pingtime surfaces via
    // getpeerinfo when measurements are available.
    Ok(Value::new_null())
}

pub(crate) fn addnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let node = required_str(params, 0, "node is required")?;
    let command = required_str(params, 1, "command is required")?;
    let addr = bitcoin_rs_p2p::parse_endpoint(node).ok_or(RpcError::InvalidParams(
        "node must be a valid host:port address",
    ))?;
    match command {
        "add" => {
            ctx.network
                .p2p
                .add_node(addr, true)
                .map_err(control_error_to_rpc_error)?;
        }
        "onetry" => {
            ctx.network
                .p2p
                .add_node(addr, false)
                .map_err(control_error_to_rpc_error)?;
        }
        "remove" => {
            ctx.network.p2p.remove_node(addr);
        }
        _ => {
            return Err(RpcError::InvalidParams(
                "command must be one of: add, remove, onetry",
            ));
        }
    }
    Ok(Value::new_null())
}

fn control_error_to_rpc_error(error: bitcoin_rs_p2p::P2pControlError) -> RpcError {
    match error {
        bitcoin_rs_p2p::P2pControlError::Banned => RpcError::InvalidParams("node is banned"),
        bitcoin_rs_p2p::P2pControlError::QueueFull => {
            RpcError::Internal("p2p outbound queue full".to_owned())
        }
        bitcoin_rs_p2p::P2pControlError::Closed => {
            RpcError::Internal("p2p outbound channel closed".to_owned())
        }
    }
}

/// `disconnectnode ( "address" nodeid )`
///
/// Three selectors, one per way a caller can name a connection:
///
/// - `address` alone disconnects whatever connection is live there.
/// - `nodeid` alone — or with an empty `address`, Core's spelling
///   (`src/rpc/net.cpp`) — disconnects exactly that connection.
/// - `address` and `nodeid` together disconnect the connection only when the
///   live one at that address *is* the one `nodeid` names. Core rejects this
///   combination; bitcoin-rs has always accepted it, so it stays a
///   conjunction rather than becoming an error.
///
/// Every form targets a *connected* node: one that has completed its
/// handshake and so appears in `getpeerinfo`. A vacant address, and a session
/// still handshaking, both answer `NotFound`.
///
/// Readiness and selection are checked and applied under the peer table's own
/// write lock ([`bitcoin_rs_p2p::PeerTable::disconnect_ready`],
/// [`bitcoin_rs_p2p::PeerTable::disconnect_ready_node_id`] and
/// [`bitcoin_rs_p2p::PeerTable::disconnect_ready_node_id_at`]). Reading a peer
/// list here and then disconnecting by address would let a same-address
/// replacement register in between, and the operator would lose a connection
/// the call never named. Because the identity names a connection rather than
/// a position, an anonymous inbound overlay session — which has no logical
/// endpoint to name — is selectable by `nodeid` too.
pub(crate) fn disconnectnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["address", "nodeid"])?;
    let array = params_array(&bound)?;
    // A present, non-null address keeps `required_str`'s exact Core type
    // error, so the address-only form's error text and precedence are what
    // they were before `nodeid` became selectable on its own.
    let address = if array.first().is_some_and(|value| !value.is_null()) {
        Some(required_str(&bound, 0, "address is required")?)
    } else {
        None
    };
    let nodeid = array
        .get(1)
        .filter(|value| !value.is_null())
        .map(|value| {
            if !value.is_number() {
                return Err(wrong_type_plain(value, "number"));
            }
            value
                .as_u64()
                .ok_or_else(|| RpcError::InvalidParameter("nodeid is out of range".to_owned()))
        })
        .transpose()?;

    match (address, nodeid) {
        (Some(address), None) => {
            let addr = bitcoin_rs_p2p::parse_endpoint(address)
                .ok_or(RpcError::InvalidParams("address must be a valid host:port"))?;
            if !ctx.network.p2p.disconnect_ready(addr) {
                return Err(RpcError::NotFound("Node not found in connected nodes"));
            }
        }
        (None | Some(""), Some(id)) => {
            if !ctx.network.p2p.disconnect_ready_node_id(id) {
                return Err(RpcError::NotFound("Node not found in connected nodes"));
            }
        }
        (Some(address), Some(id)) => {
            let addr = bitcoin_rs_p2p::parse_endpoint(address)
                .ok_or(RpcError::InvalidParams("address must be a valid host:port"))?;
            if !ctx.network.p2p.disconnect_ready_node_id_at(addr, id) {
                return Err(RpcError::NotFound("Node not found in connected nodes"));
            }
        }
        (None, None) => return Err(RpcError::InvalidParams("address is required")),
    }

    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let count = u64::try_from(ctx.network.peer_table.len()).unwrap_or(u64::MAX);
    typed_to_sonic(&v31::GetConnectionCount(count))
}

pub(crate) fn getnettotals(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    // `PeerTable` is the single owner of traffic accounting: it measures each
    // live connection and folds in the counters of every connection it drops,
    // so the totals — like Core's — never decrease across disconnects.
    let (total_bytes_received, total_bytes_sent) = ctx.network.peer_table.traffic_totals();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    typed_to_sonic(&v31::GetNetTotals {
        total_bytes_received,
        total_bytes_sent,
        time_millis: now,
        upload_target: v31::UploadTarget {
            timeframe: 0,
            target: 0,
            target_reached: true,
            serve_historical_blocks: true,
            bytes_left_in_cycle: 0,
            time_left_in_cycle: 0,
        },
    })
}

/// `getnodeaddresses [count]` — returns known peer addresses.
///
/// The address source is the live peer registry plus persisted `addnode add`
/// entries, deduplicated by socket address.  `count` defaults to 1; `0`
/// returns every known address.  Each entry follows Core's shape:
/// `{ time, services, address, port, network }`.
pub(crate) fn getnodeaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let count = optional_u64(params, 0, 1)?;

    let now = unix_time_secs();
    let mut seen: HashSet<bitcoin_rs_p2p::PeerEndpoint> = HashSet::new();
    let mut entries: Vec<v31::NodeAddress> = Vec::new();

    // Live peers carry real service flags and handshake times. Unidentified
    // peers have no known address to report.
    for peer in ctx.network.peer_table.infos() {
        let Some(endpoint) = peer.endpoint else {
            continue;
        };
        if !seen.insert(endpoint) {
            continue;
        }
        entries.push(v31::NodeAddress {
            time: peer.conn_time,
            services: peer.services,
            address: endpoint.host().to_string(),
            port: endpoint.port(),
            network: endpoint.net().as_str().to_owned(),
        });
    }

    // Persisted added nodes have no known services; advertise NODE_NETWORK.
    for addr in ctx.network.p2p.added_nodes() {
        if !seen.insert(addr) {
            continue;
        }
        entries.push(v31::NodeAddress {
            time: now,
            services: 1,
            address: addr.host().to_string(),
            port: addr.port(),
            network: addr.net().as_str().to_owned(),
        });
    }

    // Core semantics: count == 0 returns all, otherwise truncate to count.
    if count > 0 {
        let max = usize::try_from(count).unwrap_or(usize::MAX);
        if max < entries.len() {
            entries.truncate(max);
        }
    }

    typed_to_sonic(&v31::GetNodeAddresses(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

    #[test]
    fn getnetworkinfo_reports_zero_connections_on_fresh_context() {
        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        let Some(connections) = result.get("connections").and_then(JsonValueTrait::as_u64) else {
            panic!("connections missing: {result:?}");
        };
        assert_eq!(connections, 0);
        let Some(connections_in) = result
            .get("connections_in")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("connections_in missing: {result:?}");
        };
        assert_eq!(connections_in, 0);
    }

    #[test]
    fn getnetworkinfo_reports_configured_overlay_state_without_probing()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = Context::new();
        // Dead proxy/SAM addresses on purpose: reporting must reflect
        // configuration, never a live probe.
        ctx.network.overlay = bitcoin_rs_p2p::OverlayConfig {
            onion: Some("127.0.0.1:1".parse()?),
            i2p_sam: Some("127.0.0.1:2".parse()?),
            proxy_randomize_credentials: true,
            ..bitcoin_rs_p2p::OverlayConfig::default()
        };
        let ctx = Arc::new(ctx);
        let result = getnetworkinfo(&ctx, &json!(null))?;
        let Some(networks) = result
            .get("networks")
            .and_then(JsonContainerTrait::as_array)
        else {
            return Err("networks array missing".into());
        };
        let by_name = |name: &str| {
            networks
                .iter()
                .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some(name))
                .cloned()
                .ok_or_else(|| format!("network {name} missing"))
        };
        let onion = by_name("onion")?;
        assert_eq!(
            onion.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            onion.get("limited").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            onion.get("proxy").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1:1")
        );
        assert_eq!(
            onion
                .get("proxy_randomize_credentials")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        let i2p = by_name("i2p")?;
        assert_eq!(
            i2p.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            i2p.get("limited").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            i2p.get("proxy").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1:2")
        );
        assert_eq!(
            i2p.get("proxy_randomize_credentials")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        Ok(())
    }

    /// A Tor control connection publishes an inbound onion service; it does
    /// not carry dial capability. A node with control alone cannot originate
    /// an onion connection, so `networks.onion` must report unreachable and
    /// limited, with no proxy to claim. Inbound publication is reported in
    /// `localaddresses`, which this must leave alone.
    #[test]
    fn getnetworkinfo_does_not_call_onion_reachable_with_control_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = Context::new();
        ctx.network.overlay = bitcoin_rs_p2p::OverlayConfig {
            tor_control: Some("127.0.0.1:9051".to_owned()),
            onion_key_path: Some(std::path::PathBuf::from("/tmp/onion_v3_private_key")),
            tor_virtual_port: 8333,
            ..bitcoin_rs_p2p::OverlayConfig::default()
        };
        let ctx = Arc::new(ctx);

        let result = getnetworkinfo(&ctx, &json!(null))?;
        let Some(networks) = result
            .get("networks")
            .and_then(JsonContainerTrait::as_array)
        else {
            return Err("networks array missing".into());
        };
        let Some(onion) = networks
            .iter()
            .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("onion"))
        else {
            return Err("onion entry missing".into());
        };
        assert_eq!(
            onion.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(false),
            "no outbound SOCKS route is configured, so onion is not dialable"
        );
        assert_eq!(
            onion.get("limited").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            onion.get("proxy").and_then(JsonValueTrait::as_str),
            Some(""),
            "control port is not a SOCKS proxy and must not be reported as one"
        );
        // `localaddresses` keeps its own owner: it lists published service
        // endpoints, and configuration alone publishes none. Reporting a
        // configured-but-unregistered service here would be a fabricated
        // address, and dropping the field would hide the real one.
        let Some(addresses) = result
            .get("localaddresses")
            .and_then(JsonContainerTrait::as_array)
        else {
            return Err("localaddresses array missing".into());
        };
        assert!(
            addresses.is_empty(),
            "configuration alone publishes no local address: {addresses:?}"
        );
        Ok(())
    }

    /// The dial route the onion network actually uses — `--onion`, or
    /// `--proxy` as its documented fallback — is what makes it reachable.
    #[test]
    fn getnetworkinfo_calls_onion_reachable_with_an_outbound_socks_route()
    -> Result<(), Box<dyn std::error::Error>> {
        for (label, overlay) in [
            (
                "onion route",
                bitcoin_rs_p2p::OverlayConfig {
                    onion: Some("127.0.0.1:9050".parse()?),
                    ..bitcoin_rs_p2p::OverlayConfig::default()
                },
            ),
            (
                "general proxy fallback",
                bitcoin_rs_p2p::OverlayConfig {
                    proxy: Some("127.0.0.1:9050".parse()?),
                    ..bitcoin_rs_p2p::OverlayConfig::default()
                },
            ),
        ] {
            let mut ctx = Context::new();
            ctx.network.overlay = overlay;
            let ctx = Arc::new(ctx);
            let result = getnetworkinfo(&ctx, &json!(null))?;
            let Some(networks) = result
                .get("networks")
                .and_then(JsonContainerTrait::as_array)
            else {
                return Err("networks array missing".into());
            };
            let Some(onion) = networks
                .iter()
                .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("onion"))
            else {
                return Err("onion entry missing".into());
            };
            assert_eq!(
                onion.get("reachable").and_then(JsonValueTrait::as_bool),
                Some(true),
                "{label} must make onion reachable"
            );
            assert_eq!(
                onion.get("limited").and_then(JsonValueTrait::as_bool),
                Some(false),
                "{label} must not mark onion limited"
            );
            assert_eq!(
                onion.get("proxy").and_then(JsonValueTrait::as_str),
                Some("127.0.0.1:9050"),
                "{label} must report the SOCKS endpoint it dials"
            );
        }
        Ok(())
    }

    #[test]
    fn getnetworkinfo_reports_default_overlays_unconfigured_and_unreachable()
    -> Result<(), Box<dyn std::error::Error>> {
        // Default context: overlays unconfigured and unreachable.
        let plain = getnetworkinfo(&Arc::new(Context::new()), &json!(null))?;
        let Some(plain_networks) = plain.get("networks").and_then(JsonContainerTrait::as_array)
        else {
            return Err("plain networks array missing".into());
        };
        let Some(plain_onion) = plain_networks
            .iter()
            .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("onion"))
        else {
            return Err("plain onion entry missing".into());
        };
        assert_eq!(
            plain_onion
                .get("reachable")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            plain_onion.get("limited").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            plain_onion
                .get("proxy_randomize_credentials")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        let Some(plain_i2p) = plain_networks
            .iter()
            .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some("i2p"))
        else {
            return Err("plain i2p entry missing".into());
        };
        assert_eq!(
            plain_i2p.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            plain_i2p.get("limited").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            plain_i2p.get("proxy").and_then(JsonValueTrait::as_str),
            Some("")
        );
        assert_eq!(
            plain_i2p
                .get("proxy_randomize_credentials")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        Ok(())
    }

    #[test]
    fn getnetworkinfo_reports_onlynet_and_credential_isolation()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_primitives::NetworkLabel;

        let mut ctx = Context::new();
        ctx.network.overlay = bitcoin_rs_p2p::OverlayConfig {
            proxy: Some("127.0.0.1:9050".parse()?),
            proxy_randomize_credentials: false,
            onlynet: vec![NetworkLabel::Onion],
            ..bitcoin_rs_p2p::OverlayConfig::default()
        };
        let ctx = Arc::new(ctx);
        let result = getnetworkinfo(&ctx, &json!(null))?;
        let Some(networks) = result
            .get("networks")
            .and_then(JsonContainerTrait::as_array)
        else {
            return Err("networks array missing".into());
        };
        let by_name = |name: &str| {
            networks
                .iter()
                .find(|n| n.get("name").and_then(JsonValueTrait::as_str) == Some(name))
                .cloned()
                .ok_or_else(|| format!("network {name} missing"))
        };
        let ipv4 = by_name("ipv4")?;
        assert_eq!(
            ipv4.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            ipv4.get("limited").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            ipv4.get("proxy").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1:9050")
        );
        assert_eq!(
            ipv4.get("proxy_randomize_credentials")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );

        let onion = by_name("onion")?;
        assert_eq!(
            onion.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            onion.get("limited").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            onion.get("proxy").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1:9050")
        );
        // Tor transport in endpoint.rs enforces mandatory per-dial credential
        // isolation regardless of general IP proxy settings; reports true
        // whenever an onion proxy route is configured.
        assert_eq!(
            onion
                .get("proxy_randomize_credentials")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );

        let i2p = by_name("i2p")?;
        assert_eq!(
            i2p.get("reachable").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            i2p.get("limited").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        Ok(())
    }

    #[test]
    fn getnetworkinfo_emits_relayfee_default_of_one_sat_per_vbyte() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        let Some(relayfee) = result.get("relayfee").and_then(JsonValueTrait::as_f64) else {
            panic!("relayfee missing: {result:?}");
        };
        assert!(
            (relayfee - 0.00001).abs() < 1e-9,
            "expected ~0.00001, got {relayfee}"
        );
    }

    #[test]
    fn getnetworkinfo_localservices_advertises_only_supported_services() {
        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result.get("localservices").and_then(|v| v.as_str()),
            Some("0000000000000009")
        );
        let names: Vec<String> = result
            .get("localservicesnames")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|n| n.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        assert!(names.contains(&"NETWORK".to_owned()));
        assert!(names.contains(&"WITNESS".to_owned()));
        assert!(!names.contains(&"COMPACT_FILTERS".to_owned()));
    }
}
#[cfg(test)]
mod ping_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;
    use sonic_rs::json;

    #[test]
    fn ping_returns_null() {
        let ctx = Arc::new(Context::new());
        let result = ping(&ctx, &json!([])).unwrap_or_else(|err| panic!("ping failed: {err}"));
        assert!(result.is_null());
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod addnode_validation_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;
    use sonic_rs::json;

    #[test]
    fn addnode_rejects_bad_address() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["definitely-not-an-address", "add"]));
        assert!(result.is_err());
    }

    #[test]
    fn addnode_rejects_unknown_command() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }

    #[test]
    fn addnode_accepts_well_formed_input() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "onetry"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        assert!(result.is_null());
    }

    #[test]
    fn addnode_skips_queueing_while_network_is_inactive() {
        let ctx = Arc::new(Context::new());
        ctx.network.p2p.set_network_active(false);

        let persisted = bitcoin_rs_p2p::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333)));
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));
        assert!(result.is_ok());
        assert_eq!(ctx.network.p2p.added_nodes().as_slice(), &[persisted]);

        ctx.network.p2p.set_network_active(true);
        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));
        assert!(result.is_ok());
    }

    #[test]
    fn addnode_add_persists_node() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        assert_eq!(
            ctx.network.p2p.added_nodes().as_slice(),
            &[bitcoin_rs_p2p::PeerEndpoint::Ip(SocketAddr::from((
                [127, 0, 0, 1],
                8333
            )))]
        );
    }

    #[test]
    fn addnode_returns_error_when_outbound_queue_is_full() {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                outbound_queue_limit: 1,
                ..bitcoin_rs_p2p::P2pServiceConfig::default()
            },
            bitcoin_rs_chain::LatchReader::fixture_never(),
        ));
        p2p.add_node(
            bitcoin_rs_p2p::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333))),
            false,
        )
        .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let mut ctx = Context::new();
        ctx.network.p2p = Arc::clone(&p2p);
        let ctx = Arc::new(ctx);

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));

        assert!(matches!(
            result,
            Err(RpcError::Internal(message)) if message == "p2p outbound queue full"
        ));
    }

    #[test]
    fn addnode_add_persists_when_outbound_queue_is_full() {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                outbound_queue_limit: 1,
                ..bitcoin_rs_p2p::P2pServiceConfig::default()
            },
            bitcoin_rs_chain::LatchReader::fixture_never(),
        ));
        p2p.add_node(
            bitcoin_rs_p2p::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333))),
            false,
        )
        .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let mut ctx = Context::new();
        ctx.network.p2p = Arc::clone(&p2p);
        let ctx = Arc::new(ctx);

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let added = ctx.network.p2p.added_nodes();
        assert_eq!(
            added.as_slice(),
            [bitcoin_rs_p2p::PeerEndpoint::Ip(
                std::net::SocketAddr::from(([127, 0, 0, 2], 8333))
            )]
        );
    }

    #[test]
    fn addnode_rejects_manually_banned_subnet() {
        let ctx = Arc::new(Context::new());
        if let Err(err) = setban(&ctx, &json!(["127.0.0.0/24", "add"])) {
            panic!("setban failed: {err}");
        }

        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams("node is banned"))
        ));
        assert_eq!(ctx.network.p2p.added_nodes().as_slice(), &[]);
    }

    #[test]
    fn disconnectnode_rejects_bad_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["definitely-not-an-address"]));
        assert!(result.is_err());
    }

    #[test]
    fn disconnectnode_rejects_unconnected_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["127.0.0.1:8333"]));
        assert!(matches!(result, Err(RpcError::NotFound(_))));
    }

    #[test]
    fn disconnectnode_cancels_lease_and_removes_peer() {
        use bitcoin_rs_p2p::{PeerInfo, PeerLease};
        use crossbeam_channel::unbounded;

        let addr: SocketAddr = "127.0.0.1:8333".parse().expect("addr");
        let ctx = Context::new();
        let info = PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(addr)),
            network: bitcoin_rs_p2p::PeerEndpoint::Ip(addr).net(),
            version: 70_016,
            services: 9,
            user_agent: "test".to_owned(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new(addr),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        };
        let (tx, _rx) = unbounded();
        let lease = PeerLease::new(tx);
        ctx.network
            .peer_table
            .register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), lease.clone());
        ctx.network
            .peer_table
            .publish_info(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), &lease, info);
        let ctx = Arc::new(ctx);

        let result = disconnectnode(&ctx, &json!([addr.to_string().as_str()]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
        assert!(lease.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        assert_eq!(ctx.network.peer_table.infos(), []);
    }

    /// Handshake metadata for an outbound test peer at `addr`.
    fn peer_info_at(addr: SocketAddr) -> bitcoin_rs_p2p::PeerInfo {
        let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
        bitcoin_rs_p2p::PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            endpoint: Some(endpoint),
            network: endpoint.net(),
            version: 70_016,
            services: 9,
            user_agent: "test".to_owned(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new(addr),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        }
    }

    /// A session registered at `addr` that has not completed its handshake:
    /// no metadata is published, so `getpeerinfo` does not list it.
    fn register_pending_peer(ctx: &Context, addr: SocketAddr) -> bitcoin_rs_p2p::PeerLease {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = bitcoin_rs_p2p::PeerLease::new(tx);
        ctx.network
            .peer_table
            .register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), lease.clone());
        lease
    }

    /// A fixture outbound session registered at `addr` with published
    /// metadata, the shape `getpeerinfo` lists.
    fn register_peer(ctx: &Context, addr: SocketAddr) -> bitcoin_rs_p2p::PeerLease {
        let lease = register_pending_peer(ctx, addr);
        let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
        assert!(
            ctx.network
                .peer_table
                .publish_info(endpoint, &lease, peer_info_at(addr))
        );
        lease
    }

    /// The wire row mirrors the pinned `v31::PeerInfo` by hand because the
    /// pinned `id` is a `u32`. The pinned crate denies unknown fields, so
    /// strict deserialization rejects an extra or renamed key, and the key sets
    /// must agree once the pinned type's unset optionals are dropped. The typed
    /// round trip reads a populated optional the mirror forgot as `None` too,
    /// so the optionals the row always carries are checked directly.
    #[test]
    fn getpeerinfo_rows_match_the_pinned_v31_row() -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::BTreeSet;

        let ctx = Context::new();
        let _lease = register_peer(&ctx, "127.0.0.1:9101".parse()?);
        let ctx = Arc::new(ctx);

        let wire = getpeerinfo(&ctx, &json!(null))?;
        let typed: v31::GetPeerInfo = sonic_rs::from_str(&sonic_rs::to_string(&wire)?)?;
        let pinned = sonic_rs::to_value(&typed)?;

        let keys = |rows: &Value, keep_null: bool| -> Option<BTreeSet<String>> {
            let row = rows.as_array()?.first()?.as_object()?;
            Some(
                row.iter()
                    .filter(|(_, field)| keep_null || !field.is_null())
                    .map(|(key, _)| key.to_owned())
                    .collect(),
            )
        };
        let wire_keys =
            keys(&wire, true).ok_or("the wire row is a one-element array of objects")?;
        let pinned_keys =
            keys(&pinned, false).ok_or("the pinned row is a one-element array of objects")?;
        assert_eq!(wire_keys, pinned_keys);

        let row = wire
            .as_array()
            .and_then(|rows| rows.first())
            .ok_or("the wire row is a one-element array")?;
        for key in [
            "connection_type",
            "presynced_headers",
            "synced_headers",
            "synced_blocks",
            "inflight",
        ] {
            assert!(row.get(key).is_some(), "{key} must stay populated: {row:?}");
        }
        Ok(())
    }

    /// Every field of a rendered row except `id`, keyed for semantic comparison.
    fn fields_but_id(
        row: &Value,
    ) -> Result<std::collections::BTreeMap<&str, &Value>, Box<dyn std::error::Error>> {
        let object = row.as_object().ok_or("rows are objects")?;
        Ok(object.iter().filter(|(key, _)| *key != "id").collect())
    }

    /// A connection id above `u32::MAX` is serialized exactly, in the same
    /// whole-query response as its neighbours, and never aliases another id.
    /// The process-wide connection counter cannot be driven that far in a test,
    /// so each row is the real projection of one session with its id replaced
    /// at the width boundary.
    #[test]
    fn getpeerinfo_row_carries_ids_above_u32_max_exactly() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = Context::new();
        let _lease = register_peer(&ctx, "127.0.0.1:9102".parse()?);
        let sessions = ctx.network.peer_table.sessions();
        let session = sessions.first().ok_or("the fixture session is listed")?;
        let peer = session
            .info
            .as_ref()
            .ok_or("the fixture session completed its handshake")?;

        // The allocator aborts rather than hand out `u64::MAX`.
        let ids = [
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::from(u32::MAX) + 2,
            u64::MAX - 1,
        ];
        assert_eq!(
            peer_info_wire(session, peer, 0.0).id,
            session.lease.node_id(),
            "the projection takes the id from the session's own lease"
        );
        let rows = ids
            .iter()
            .map(|&id| PeerInfoWire {
                id,
                ..peer_info_wire(session, peer, 0.0)
            })
            .collect::<Vec<_>>();
        let rendered = typed_to_sonic_omitting_nulls(&rows)?;
        let Some(rendered) = rendered.as_array() else {
            return Err("getpeerinfo must return an array".into());
        };

        let rendered_ids = rendered
            .iter()
            .map(|row| row.get("id").and_then(JsonValueTrait::as_u64))
            .collect::<Vec<_>>();
        assert_eq!(rendered_ids, ids.map(Some));

        // Width is the only thing the id changes: every other field is the
        // same row.
        let Some((first, rest)) = rendered.split_first() else {
            return Err("the rendered rows are not empty".into());
        };
        let expected = fields_but_id(first)?;
        for row in rest {
            assert_eq!(fields_but_id(row)?, expected);
        }
        Ok(())
    }

    /// A `nodeid` selector above `u32::MAX` is a different connection from
    /// the live one that shares its low 32 bits, so it finds nothing and
    /// disconnects nothing.
    #[test]
    fn disconnectnode_nodeid_above_u32_max_never_aliases_a_live_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let lease = register_peer(&ctx, "127.0.0.1:9103".parse()?);
        let ctx = Arc::new(ctx);

        let wide = lease.node_id() + (u64::from(u32::MAX) + 1);
        let refused = disconnectnode(&ctx, &json!({ "nodeid": wide }));
        assert!(
            matches!(refused, Err(RpcError::NotFound(_))),
            "a wide selector is well-formed but names no connection"
        );
        assert!(!lease.is_cancelled());
        Ok(())
    }

    /// `getpeerinfo.id` is the connection's identity, not its position, so a
    /// caller can name the connection it read about after the array shifts.
    #[test]
    fn getpeerinfo_ids_are_connection_identities_not_positions()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr_a: SocketAddr = "127.0.0.1:9001".parse()?;
        let addr_b: SocketAddr = "127.0.0.1:9002".parse()?;
        let addr_c: SocketAddr = "127.0.0.1:9003".parse()?;
        let lease_a = register_peer(&ctx, addr_a);
        let lease_b = register_peer(&ctx, addr_b);
        let lease_c = register_peer(&ctx, addr_c);
        let ctx = Arc::new(ctx);

        let first = getpeerinfo(&ctx, &json!(null))?;
        let Some(rows) = first.as_array() else {
            return Err("getpeerinfo must return an array".into());
        };
        let ids: Vec<u64> = rows
            .iter()
            .map(|row| {
                row.get("id")
                    .and_then(JsonValueTrait::as_u64)
                    .ok_or("every row carries an id")
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(
            ids,
            [lease_a.node_id(), lease_b.node_id(), lease_c.node_id()],
            "the reported id is the connection's own, in connection order"
        );

        // Removing an earlier connection shifts positions but not identities.
        assert!(ctx.network.p2p.disconnect_ready_node_id(lease_a.node_id()));
        let after = getpeerinfo(&ctx, &json!(null))?;
        let Some(rows) = after.as_array() else {
            return Err("getpeerinfo must return an array".into());
        };
        let ids: Vec<u64> = rows
            .iter()
            .map(|row| {
                row.get("id")
                    .and_then(JsonValueTrait::as_u64)
                    .ok_or("every row carries an id")
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(ids, [lease_b.node_id(), lease_c.node_id()]);
        assert!(!lease_b.is_cancelled());
        assert!(!lease_c.is_cancelled());
        Ok(())
    }

    /// The former handler checked `peers[index].endpoint` and then asked for
    /// an address-only disconnect. A replacement registered between those two
    /// steps was the one cancelled — a connection the call never named. The
    /// identity form resolves and removes under one table write, so the
    /// selected connection's id stops resolving and its successor survives.
    #[test]
    fn disconnectnode_nodeid_never_disconnects_a_replacement_at_the_same_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr: SocketAddr = "127.0.0.1:8333".parse()?;
        let selected = register_peer(&ctx, addr);
        let selected_id = selected.node_id();

        // A fresh connection takes the address over before the operator acts;
        // registering at an occupied address cancels the predecessor.
        let replacement = register_peer(&ctx, addr);
        assert!(selected.is_cancelled());
        let replacement_id = replacement.node_id();
        assert_ne!(selected_id, replacement_id);
        let ctx = Arc::new(ctx);

        let stale = disconnectnode(&ctx, &json!(["", selected_id]));
        assert!(
            matches!(stale, Err(RpcError::NotFound(_))),
            "the named connection is gone, so the call must refuse instead of hitting its successor: {stale:?}"
        );
        assert!(
            !replacement.is_cancelled(),
            "the replacement was never named and must survive"
        );
        assert_eq!(ctx.network.peer_table.len(), 1);

        let named = disconnectnode(&ctx, &json!(["", replacement_id]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(named.is_null());
        assert!(replacement.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        Ok(())
    }

    /// An anonymous inbound overlay session has no logical endpoint, so no
    /// address can name it; `nodeid` is the only handle that reaches it.
    #[test]
    fn disconnectnode_nodeid_addresses_an_anonymous_inbound_session()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_p2p::{PeerInfo, PeerLease};
        use crossbeam_channel::unbounded;

        let ctx = Context::new();
        let (tx, _rx) = unbounded();
        let anon = PeerLease::new_inbound(tx);
        assert!(!ctx.network.peer_table.register_unidentified(anon.clone()));
        let info = PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            endpoint: None,
            network: bitcoin_rs_primitives::NetworkLabel::Onion,
            version: 70_016,
            services: 0,
            user_agent: "anon".to_owned(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: true,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new("127.0.0.1:9000".parse()?),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        };
        let published = ctx
            .network
            .peer_table
            .publish_info_unidentified(&anon, info);
        assert!(published);
        let node_id = anon.node_id();
        let ctx = Arc::new(ctx);

        // `getpeerinfo` exposes it with the documented `unknown` address.
        let peers = getpeerinfo(&ctx, &json!(null))?;
        let Some(rows) = peers.as_array() else {
            return Err("getpeerinfo must return an array".into());
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("addr").and_then(JsonValueTrait::as_str),
            Some("unknown")
        );
        assert_eq!(
            rows[0].get("id").and_then(JsonValueTrait::as_u64),
            Some(node_id)
        );

        // No address can name it, so the empty-address form is required.
        let result = disconnectnode(&ctx, &json!(["", node_id]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
        assert!(anon.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        Ok(())
    }

    /// Address and nodeid together name one connection: the one at that
    /// address, and only if it carries that id. The pair is checked under the
    /// table lock, so a replacement at the address fails the identity half
    /// rather than being disconnected in the stale connection's place.
    #[test]
    fn disconnectnode_address_and_nodeid_is_a_conjunction_under_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr: SocketAddr = "127.0.0.1:8350".parse()?;
        let selected = register_peer(&ctx, addr);
        let selected_id = selected.node_id();
        let replacement = register_peer(&ctx, addr);
        let replacement_id = replacement.node_id();
        let ctx = Arc::new(ctx);
        let address = addr.to_string();

        let stale = disconnectnode(&ctx, &json!([address.as_str(), selected_id]));
        assert!(
            matches!(stale, Err(RpcError::NotFound(_))),
            "the stale id must not resolve to the connection now at the address: {stale:?}"
        );
        assert!(!replacement.is_cancelled());
        assert_eq!(ctx.network.peer_table.len(), 1);

        let other: SocketAddr = "127.0.0.1:8351".parse()?;
        let wrong_address = other.to_string();
        let wrong = disconnectnode(&ctx, &json!([wrong_address.as_str(), replacement_id]));
        assert!(
            matches!(wrong, Err(RpcError::NotFound(_))),
            "the id names a connection at a different address: {wrong:?}"
        );
        assert!(!replacement.is_cancelled());

        let matched = disconnectnode(&ctx, &json!([address.as_str(), replacement_id]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(matched.is_null());
        assert!(replacement.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        Ok(())
    }

    /// A named `nodeid` alone is Core's identity-only form and needs no
    /// address; a malformed address still fails before any lookup.
    #[test]
    fn disconnectnode_accepts_a_named_nodeid_alone_and_keeps_address_precedence()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr: SocketAddr = "127.0.0.1:8360".parse()?;
        let lease = register_peer(&ctx, addr);
        let node_id = lease.node_id();
        let ctx = Arc::new(ctx);

        assert!(matches!(
            disconnectnode(&ctx, &json!(["not-an-address", node_id])),
            Err(RpcError::InvalidParams(_))
        ));
        assert!(!lease.is_cancelled());

        let named = disconnectnode(&ctx, &json!({ "nodeid": node_id }))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(named.is_null());
        assert!(lease.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        Ok(())
    }

    /// Address-only behaviour is unchanged, including its error precedence.
    #[test]
    fn disconnectnode_address_only_still_selects_by_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr: SocketAddr = "127.0.0.1:8340".parse()?;
        let lease = register_peer(&ctx, addr);
        let ctx = Arc::new(ctx);

        let result = disconnectnode(&ctx, &json!([addr.to_string().as_str()]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
        assert!(lease.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        assert!(matches!(
            disconnectnode(&ctx, &json!(["not-an-address"])),
            Err(RpcError::InvalidParams(_))
        ));
        Ok(())
    }

    /// The address-only form targets a *connected* node, one `getpeerinfo`
    /// lists. A session that is registered but has not completed its
    /// handshake answers `NotFound` and survives, exactly as before the
    /// identity forms existed; the same call succeeds once it is ready.
    #[test]
    fn disconnectnode_address_only_ignores_a_session_still_handshaking()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr: SocketAddr = "127.0.0.1:8370".parse()?;
        let pending = register_pending_peer(&ctx, addr);
        let ctx = Arc::new(ctx);
        let address = addr.to_string();

        let refused = disconnectnode(&ctx, &json!([address.as_str()]));
        assert!(
            matches!(refused, Err(RpcError::NotFound(_))),
            "a handshaking session is not a connected node: {refused:?}"
        );
        assert!(!pending.is_cancelled());
        assert_eq!(ctx.network.peer_table.len(), 1);

        assert!(ctx.network.peer_table.publish_info(
            bitcoin_rs_p2p::PeerEndpoint::Ip(addr),
            &pending,
            peer_info_at(addr)
        ));
        let accepted = disconnectnode(&ctx, &json!([address.as_str()]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(accepted.is_null());
        assert!(pending.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
        Ok(())
    }

    /// The identity forms obey the same rule: a handshaking session has no
    /// `getpeerinfo` id for an operator to have read, so naming its id, alone
    /// or with its address, reaches nothing.
    #[test]
    fn disconnectnode_identity_forms_ignore_a_session_still_handshaking()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let addr: SocketAddr = "127.0.0.1:8371".parse()?;
        let pending = register_pending_peer(&ctx, addr);
        let node_id = pending.node_id();
        let ctx = Arc::new(ctx);
        let address = addr.to_string();

        for params in [
            json!(["", node_id]),
            json!([address.as_str(), node_id]),
            json!({ "nodeid": node_id }),
        ] {
            let refused = disconnectnode(&ctx, &params);
            assert!(
                matches!(refused, Err(RpcError::NotFound(_))),
                "{params:?}: {refused:?}"
            );
            assert!(!pending.is_cancelled());
        }
        assert_eq!(ctx.network.peer_table.len(), 1);
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod admin_rpc_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

    #[test]
    fn getaddednodeinfo_returns_empty_array() {
        let ctx = Arc::new(Context::new());
        let result = getaddednodeinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn listbanned_returns_empty_array() {
        let ctx = Arc::new(Context::new());
        let result =
            listbanned(&ctx, &json!(null)).unwrap_or_else(|err| panic!("listbanned failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn setnetworkactive_stores_and_echoes_state() {
        for active in [true, false] {
            let ctx = Arc::new(Context::new());
            let result = setnetworkactive(&ctx, &json!([active]))
                .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
            assert_eq!(result.as_bool(), Some(active));
            assert_eq!(ctx.network.p2p.network_active(), active);
        }
    }

    #[test]
    fn setnetworkactive_false_cancels_all_leases() {
        use bitcoin_rs_p2p::PeerLease;
        use crossbeam_channel::unbounded;

        let addr_a: SocketAddr = "127.0.0.1:8333".parse().expect("addr");
        let addr_b: SocketAddr = "127.0.0.2:8333".parse().expect("addr");
        let ctx = Context::new();
        let (tx_a, _rx_a) = unbounded();
        let (tx_b, _rx_b) = unbounded();
        let lease_a = PeerLease::new(tx_a);
        let lease_b = PeerLease::new(tx_b);
        ctx.network
            .peer_table
            .register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr_a), lease_a.clone());
        ctx.network
            .peer_table
            .register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr_b), lease_b.clone());
        let ctx = Arc::new(ctx);

        let _ = setnetworkactive(&ctx, &json!([false]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert!(lease_a.is_cancelled());
        assert!(lease_b.is_cancelled());
        assert_eq!(ctx.network.peer_table.len(), 2);
    }

    #[test]
    fn getnetworkinfo_reports_network_active_state() {
        let ctx = Arc::new(Context::new());
        ctx.network.p2p.set_network_active(false);
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result
                .get("networkactive")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
    }
    #[test]
    fn setban_accepts_add_and_remove() {
        let ctx = Arc::new(Context::new());
        assert!(setban(&ctx, &json!(["10.0.0.1:8333", "add"])).is_ok());
        let result = match listbanned(&ctx, &json!(null)) {
            Ok(result) => result,
            Err(err) => panic!("listbanned failed: {err}"),
        };
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        let Some(entry) = arr.first() else {
            panic!("expected one ban entry");
        };
        assert_eq!(
            entry.get("address").and_then(JsonValueTrait::as_str),
            Some("10.0.0.1/32")
        );
        assert!(setban(&ctx, &json!(["10.0.0.1:8333", "remove"])).is_ok());
        assert_eq!(ctx.network.p2p.banned().as_slice(), &[]);
    }

    #[test]
    fn setban_rejects_unknown_command() {
        let ctx = Arc::new(Context::new());
        let result = setban(&ctx, &json!(["10.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }
}
#[cfg(test)]
mod ban_state_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

    fn listbanned_ok(ctx: &Arc<Context>) -> Value {
        match listbanned(ctx, &json!(null)) {
            Ok(result) => result,
            Err(err) => panic!("listbanned failed: {err}"),
        }
    }

    fn setban_ok(ctx: &Arc<Context>, target: &str, command: &str) {
        if let Err(err) = setban(ctx, &json!([target, command])) {
            panic!("setban failed: {err}");
        }
    }

    fn clearbanned_ok(ctx: &Arc<Context>) {
        if let Err(err) = clearbanned(ctx, &json!(null)) {
            panic!("clearbanned failed: {err}");
        }
    }

    fn list_addresses(ctx: &Arc<Context>) -> Vec<String> {
        let result = listbanned_ok(ctx);
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        arr.iter()
            .filter_map(|entry| entry.get("address").and_then(JsonValueTrait::as_str))
            .map(str::to_owned)
            .collect()
    }

    fn sole_address(ctx: &Arc<Context>) -> String {
        let addresses = list_addresses(ctx);
        assert_eq!(addresses.len(), 1);
        let Some(address) = addresses.first() else {
            panic!("expected one ban address");
        };
        address.to_owned()
    }

    #[test]
    fn setban_add_persists_in_context() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "127.0.0.1:8333", "add");
        assert_eq!(ctx.network.p2p.banned().len(), 1);
    }

    #[test]
    fn listbanned_returns_added_entries() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.1:8333", "add");
        let result = listbanned_ok(&ctx);
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        let Some(entry) = arr.first() else {
            panic!("expected one ban entry");
        };
        assert_eq!(
            entry.get("address").and_then(JsonValueTrait::as_str),
            Some("192.168.1.1/32")
        );
        // Core's listbanned entries carry only address, ban_created,
        // banned_until, ban_duration, and time_remaining — no ban_reason —
        // and the pinned v31::Banned shape matches.
        assert!(
            entry.get("ban_reason").is_none(),
            "ban_reason must stay absent from listbanned entries: {entry:?}"
        );
        let Some(created) = entry.get("ban_created").and_then(JsonValueTrait::as_u64) else {
            panic!("ban_created missing");
        };
        let Some(until) = entry.get("banned_until").and_then(JsonValueTrait::as_u64) else {
            panic!("banned_until missing");
        };
        assert!(until >= created);
    }

    #[test]
    fn setban_cidr_add_list_roundtrip() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "10.0.0.0/8", "add");

        assert_eq!(sole_address(&ctx), "10.0.0.0/8");
    }

    #[test]
    fn setban_normalizes_host_bits() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.99/24", "add");

        assert_eq!(sole_address(&ctx), "192.168.1.0/24");
    }

    #[test]
    fn setban_bare_ip_stores_single_address_subnet() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.99", "add");

        assert_eq!(sole_address(&ctx), "192.168.1.99/32");
    }

    #[test]
    fn setban_ipv6_cidr_canonicalizes() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "2001:db8::1/64", "add");

        assert_eq!(sole_address(&ctx), "2001:db8::/64");
    }

    #[test]
    fn setban_rejects_invalid_subnet() {
        let ctx = Arc::new(Context::new());
        let result = setban(&ctx, &json!(["10.0.0.1/33", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams(
                "subnet must be IP, IP/prefix, or host:port"
            ))
        ));
    }

    #[test]
    fn setban_remove_matches_exact_subnet() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "10.0.0.0/24", "add");
        setban_ok(&ctx, "10.0.0.1", "add");

        setban_ok(&ctx, "10.0.0.1", "remove");

        assert_eq!(list_addresses(&ctx), vec!["10.0.0.0/24".to_owned()]);
    }

    #[test]
    fn clearbanned_empties_vec() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.1", "add");
        clearbanned_ok(&ctx);
        assert_eq!(ctx.network.p2p.banned().as_slice(), &[]);
    }

    #[test]
    fn addnode_add_persists_in_added_nodes_list() {
        let ctx = Arc::new(Context::new());
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        assert_eq!(ctx.network.p2p.added_nodes().len(), 1);
    }

    #[test]
    fn getaddednodeinfo_returns_persisted_entries() {
        let ctx = Arc::new(Context::new());
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        let result = getaddednodeinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }
}

#[cfg(test)]
mod peer_counter_tests {
    use alloc::sync::Arc;
    use std::io::{Read as _, Write as _};
    use std::net::SocketAddr;

    use bitcoin_rs_p2p::{CountingStream, PeerCounters, PeerInfo, PeerLease, PeerTable};
    use crossbeam_channel::unbounded;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

    use super::{getnetworkinfo, getpeerinfo};
    use crate::context::Context;

    fn peer(addr: &str, bind: &str, time_offset: i64, counters: Arc<PeerCounters>) -> PeerInfo {
        directed_peer(addr, bind, time_offset, counters, true)
    }

    /// A peer whose direction the test chooses.
    ///
    /// The clock offset is sampled from outbound peers only, so a fixture that
    /// cannot make one cannot exercise the median at all.
    fn directed_peer(
        addr: &str,
        bind: &str,
        time_offset: i64,
        counters: Arc<PeerCounters>,
        inbound: bool,
    ) -> PeerInfo {
        let parse = |text: &str| -> SocketAddr {
            text.parse()
                .unwrap_or_else(|_| panic!("test address {text} must parse"))
        };
        PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(parse(addr))),
            network: bitcoin_rs_p2p::PeerEndpoint::Ip(parse(addr)).net(),
            version: 70_016,
            services: 0,
            user_agent: "/test/".to_owned(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new(parse(bind)),
            time_offset,
            counters,
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        }
    }

    /// `count` outbound peers, each declaring the offset `offsets` gives it.
    fn outbound_peers(offsets: &[i64]) -> Vec<PeerInfo> {
        offsets
            .iter()
            .enumerate()
            .map(|(index, offset)| {
                directed_peer(
                    &format!("127.0.0.1:{}", index + 1),
                    &format!("127.0.0.1:{}", 1000 + index),
                    *offset,
                    Arc::new(PeerCounters::default()),
                    false,
                )
            })
            .collect()
    }

    fn context_with(peers: Vec<PeerInfo>) -> Arc<Context> {
        let peer_table = PeerTable::new();
        for info in peers {
            let (tx, _rx) = unbounded();
            let lease = PeerLease::new(tx);
            let Some(endpoint) = info.endpoint else {
                panic!("identified test peer missing endpoint");
            };
            peer_table.register(endpoint, lease.clone());
            peer_table.publish_info(endpoint, &lease, info);
        }
        let mut ctx = Context::new();
        ctx.network.peer_table = Arc::new(peer_table);
        Arc::new(ctx)
    }

    fn first_peer(ctx: &Arc<Context>) -> sonic_rs::Value {
        let result = getpeerinfo(ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getpeerinfo failed: {err}"));
        let Some(entry) = result.as_array().and_then(|array| array.first()) else {
            panic!("getpeerinfo returned no peers: {result:?}");
        };
        entry.clone()
    }

    /// The byte counts are the connection's own, not a placeholder.
    ///
    /// The traffic is put through a `CountingStream`, the way a real connection
    /// does it, so this covers the wiring and not just the rendering.
    #[test]
    fn getpeerinfo_reports_what_the_connection_actually_moved() {
        let counters = Arc::new(PeerCounters::default());
        {
            let mut sent = CountingStream::new(Vec::new(), Arc::clone(&counters));
            let _written = sent
                .write(&[0_u8; 42])
                .unwrap_or_else(|error| panic!("write failed: {error}"));
            let mut received =
                CountingStream::new(std::io::Cursor::new(vec![1_u8; 7]), Arc::clone(&counters));
            let mut buffer = [0_u8; 7];
            let _read = received
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("read failed: {error}"));
        }

        let ctx = context_with(vec![peer(
            "127.0.0.1:8333",
            "10.0.0.2:51234",
            0,
            Arc::clone(&counters),
        )]);
        let entry = first_peer(&ctx);

        assert_eq!(
            entry.get("bytessent").and_then(JsonValueTrait::as_u64),
            Some(42)
        );
        assert_eq!(
            entry.get("bytesrecv").and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        assert_ne!(
            entry.get("lastsend").and_then(JsonValueTrait::as_u64),
            Some(0),
            "a connection that sent something has a last-send time"
        );
        assert_ne!(
            entry.get("lastrecv").and_then(JsonValueTrait::as_u64),
            Some(0)
        );
    }

    /// `addrbind` is this node's end of the connection.
    ///
    /// It used to repeat `addr`, which told an operator listening on several
    /// interfaces nothing at all about which one carried the peer.
    #[test]
    fn getpeerinfo_reports_the_bind_address_not_the_peer_address() {
        let ctx = context_with(vec![peer(
            "203.0.113.7:8333",
            "10.0.0.2:51234",
            0,
            Arc::new(PeerCounters::default()),
        )]);
        let entry = first_peer(&ctx);

        assert_eq!(
            entry.get("addr").and_then(JsonValueTrait::as_str),
            Some("203.0.113.7:8333")
        );
        assert_eq!(
            entry.get("addrbind").and_then(JsonValueTrait::as_str),
            Some("10.0.0.2:51234")
        );
    }

    /// A peer's clock offset is reported with its sign.
    #[test]
    fn getpeerinfo_reports_the_peers_clock_offset() {
        for offset in [-90_i64, 0, 120] {
            let ctx = context_with(vec![peer(
                "127.0.0.1:8333",
                "127.0.0.1:1234",
                offset,
                Arc::new(PeerCounters::default()),
            )]);
            assert_eq!(
                first_peer(&ctx)
                    .get("timeoffset")
                    .and_then(JsonValueTrait::as_i64),
                Some(offset)
            );
        }
    }

    /// The negotiated transport is reported as Core does: `v2` with the
    /// BIP324 session id in byte order, or `v1` with an empty id.
    #[test]
    fn getpeerinfo_reports_the_negotiated_transport() {
        let mut session_id = [0_u8; 32];
        session_id[0] = 0xab;
        session_id[31] = 0x01;
        for (transport, kind, id) in [
            (bitcoin_rs_p2p::TransportProtocol::V1, "v1", String::new()),
            (
                bitcoin_rs_p2p::TransportProtocol::V2 { session_id },
                "v2",
                format!("ab{}01", "00".repeat(30)),
            ),
        ] {
            let mut info = peer(
                "127.0.0.1:8333",
                "127.0.0.1:1234",
                0,
                Arc::new(PeerCounters::default()),
            );
            info.transport = transport;
            let ctx = context_with(vec![info]);
            let row = first_peer(&ctx);
            assert_eq!(
                row.get("transport_protocol_type")
                    .and_then(JsonValueTrait::as_str),
                Some(kind)
            );
            assert_eq!(
                row.get("session_id").and_then(JsonValueTrait::as_str),
                Some(id.as_str())
            );
        }
    }

    /// The node's own offset is the median, so one peer cannot move it.
    ///
    /// The figure exists to tell an operator their clock is wrong. A single
    /// peer claiming an absurd time must not be able to raise that alarm, which
    /// is exactly what a mean would let it do.
    #[test]
    fn getnetworkinfo_timeoffset_is_the_median_of_its_peers() {
        let ctx = context_with(outbound_peers(&[10, 20, 30, 40, 100_000]));

        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

        assert_eq!(
            result.get("timeoffset").and_then(JsonValueTrait::as_i64),
            Some(30),
            "the outlier must not move the median"
        );
    }

    /// An inbound peer cannot move the node's reported clock offset.
    ///
    /// Core takes samples from outbound peers only, and says why at the call
    /// site: "Don't use timedata samples from inbound peers to make it harder
    /// for others to create false warnings about our clock being out of sync."
    /// Anyone can open an inbound connection and declare any time they like, so
    /// medianing over every peer hands whoever does that the operator's belief
    /// about whether this machine's clock is wrong.
    ///
    /// Five outbound peers agreeing on ten seconds, and a crowd of inbound ones
    /// declaring an hour. The inbound peers outnumber the outbound ones, so a
    /// median over all of them lands on the inbound value and this fails.
    #[test]
    fn getnetworkinfo_timeoffset_ignores_inbound_peers() {
        let mut peers = outbound_peers(&[10, 10, 10, 10, 10]);
        for index in 0..9 {
            peers.push(directed_peer(
                &format!("127.0.0.2:{}", index + 1),
                &format!("127.0.0.1:{}", 2000 + index),
                3_600,
                Arc::new(PeerCounters::default()),
                true,
            ));
        }
        let ctx = context_with(peers);

        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

        assert_eq!(
            result.get("timeoffset").and_then(JsonValueTrait::as_i64),
            Some(10),
            "inbound peers must not be sampled, however many of them there are"
        );
    }

    /// Too few samples is not a measurement, and is reported as none.
    ///
    /// `TimeOffsets::Median` returns zero below five offsets: "Only calculate
    /// the median if we have 5 or more offsets". Four peers all an hour ahead
    /// used to be reported as an hour, which reads as a confident finding about
    /// the local clock drawn from four strangers.
    #[test]
    fn getnetworkinfo_timeoffset_needs_five_samples() {
        let four = context_with(outbound_peers(&[3_600, 3_600, 3_600, 3_600]));
        assert_eq!(
            getnetworkinfo(&four, &json!(null))
                .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
                .get("timeoffset")
                .and_then(JsonValueTrait::as_i64),
            Some(0),
            "four samples is below Core's floor, so there is no offset to report"
        );

        // The paired case, so the zero above is the floor and not an inability
        // to report anything at all.
        let five = context_with(outbound_peers(&[3_600, 3_600, 3_600, 3_600, 3_600]));
        assert_eq!(
            getnetworkinfo(&five, &json!(null))
                .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
                .get("timeoffset")
                .and_then(JsonValueTrait::as_i64),
            Some(3_600),
            "one more sample crosses the floor and the offset is reported"
        );
    }

    /// Offsets at the extremes of `i64` are reported, not halved.
    ///
    /// The even-count branch used to average the two middle samples as
    /// `lower.saturating_add(upper) / 2`. With both near `i64::MAX` the sum
    /// saturates *before* the division, so the answer comes back at roughly
    /// half the magnitude -- and these are values a peer can simply put in its
    /// version message, so an attacker controlling two outbound peers could
    /// pick what the node reported about its own clock.
    ///
    /// There is no averaging any more: Core indexes `sorted[size / 2]` and so
    /// does this, which removes the arithmetic rather than making it
    /// overflow-safe. This test is what says the class is gone rather than
    /// relocated -- an extreme value must arrive at the output unchanged, at
    /// both ends of the range.
    #[test]
    fn extreme_offsets_are_reported_at_their_own_magnitude() {
        for extreme in [i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1] {
            // Six samples, so the even-count path is the one taken, with both
            // middle values at the extreme.
            let ctx = context_with(outbound_peers(&[
                i64::MIN,
                i64::MIN,
                extreme,
                extreme,
                i64::MAX,
                i64::MAX,
            ]));
            let reported = getnetworkinfo(&ctx, &json!(null))
                .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
                .get("timeoffset")
                .and_then(JsonValueTrait::as_i64);

            // Sorted, `[MIN, MIN, extreme, extreme, MAX, MAX]` puts an extreme
            // at index 3 whichever way `extreme` sorts, except when it *is* an
            // endpoint -- in which case the value at index 3 is that endpoint
            // too. Either way the answer is a sample, never a computed number.
            let Some(reported) = reported else {
                panic!("time_offset missing for {extreme}");
            };
            assert!(
                [i64::MIN, i64::MAX, extreme].contains(&reported),
                "{reported} is not one of the offsets any peer reported"
            );
            assert_ne!(
                reported,
                extreme / 2,
                "an extreme offset must not come back halved"
            );
        }
    }

    /// An even sample count takes the upper middle, as Core does.
    ///
    /// Core indexes `sorted[size / 2]` whatever the parity, and says why it
    /// does not interpolate: "approximate median is good enough, keep it
    /// simple". Averaging the two middle values answers a number no peer
    /// reported and differs from Core on every even count -- here 40 against
    /// the 35 an average of the two middle samples would give.
    #[test]
    fn getnetworkinfo_timeoffset_does_not_interpolate() {
        let ctx = context_with(outbound_peers(&[10, 20, 30, 40, 50, 60]));

        assert_eq!(
            getnetworkinfo(&ctx, &json!(null))
                .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"))
                .get("timeoffset")
                .and_then(JsonValueTrait::as_i64),
            Some(40),
            "the upper of the two middle values, not their average"
        );
    }

    /// A round trip that was never measured is not reported as zero.
    ///
    /// Core omits `pingtime` and `minping` until it has a measurement. These
    /// used to be `0.0`, which is not merely wrong but flattering: zero is the
    /// best latency a peer could possibly have.
    #[test]
    fn getpeerinfo_omits_ping_times_it_has_never_measured() {
        let ctx = context_with(vec![peer(
            "127.0.0.1:8333",
            "127.0.0.1:1234",
            0,
            Arc::new(PeerCounters::default()),
        )]);
        let entry = first_peer(&ctx);

        assert!(entry.get("pingtime").is_none(), "{entry:?}");
        assert!(entry.get("minping").is_none(), "{entry:?}");
        assert!(entry.get("pingwait").is_none(), "{entry:?}");
    }

    /// The reported client version follows the release, not a constant.
    ///
    /// The expected number is derived here from the package version rather than
    /// read back from the function under test, which could not disagree with
    /// itself.
    #[test]
    fn getnetworkinfo_version_tracks_the_release() {
        let mut expected = 0_i64;
        for (field, scale) in bitcoin_rs_primitives::PKG_VERSION
            .split('.')
            .zip([10_000_i64, 100, 1])
        {
            let digits: String = field.chars().take_while(char::is_ascii_digit).collect();
            expected += digits.parse::<i64>().unwrap_or(0) * scale;
        }
        assert_ne!(
            expected, 10_000,
            "the fixture must not match the old constant"
        );

        let result = getnetworkinfo(&Arc::new(Context::new()), &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

        assert_eq!(
            result.get("version").and_then(JsonValueTrait::as_i64),
            Some(expected)
        );
    }

    /// With no peers there is nothing to compare against.
    #[test]
    fn getnetworkinfo_timeoffset_is_zero_without_peers() {
        let result = getnetworkinfo(&Arc::new(Context::new()), &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result.get("timeoffset").and_then(JsonValueTrait::as_i64),
            Some(0)
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod getnodeaddresses_tests {
    use super::*;
    use alloc::sync::Arc;
    use bitcoin_rs_p2p::{PeerInfo, PeerLease};
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

    fn peer(addr: &str, services: u64) -> PeerInfo {
        let parsed: SocketAddr = addr.parse().expect("addr");
        PeerInfo {
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(parsed)),
            network: bitcoin_rs_p2p::PeerEndpoint::Ip(parsed).net(),
            version: 70_016,
            services,
            user_agent: "test".to_owned(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 100,
            inbound: false,
            addr_bind: bitcoin_rs_p2p::TransportRemote::new(parsed),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
            transport: bitcoin_rs_p2p::TransportProtocol::V1,
        }
    }

    fn add_peer(ctx: &Context, info: PeerInfo) {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        ctx.network
            .peer_table
            .register(info.endpoint.expect("identified test peer"), lease.clone());
        ctx.network.peer_table.publish_info(
            info.endpoint.expect("identified test peer"),
            &lease,
            info,
        );
    }

    #[test]
    fn empty_context_returns_empty_array() {
        let ctx = Arc::new(Context::new());
        let result = getnodeaddresses(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn returns_live_peer_addresses() {
        let ctx = Context::new();
        add_peer(&ctx, peer("127.0.0.1:8333", 9));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([0]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        let entry = &arr[0];
        assert_eq!(
            entry.get("address").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(
            entry.get("port").and_then(JsonValueTrait::as_u64),
            Some(8333)
        );
        assert_eq!(
            entry.get("services").and_then(JsonValueTrait::as_u64),
            Some(9)
        );
        assert_eq!(
            entry.get("network").and_then(JsonValueTrait::as_str),
            Some("ipv4")
        );
    }

    #[test]
    fn deduplicates_peer_and_added_node() {
        let ctx = Context::new();
        add_peer(&ctx, peer("127.0.0.1:8333", 9));
        ctx.network
            .p2p
            .add_node(
                bitcoin_rs_p2p::parse_endpoint("127.0.0.1:8333").expect("addr"),
                true,
            )
            .expect("add_node");
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([0]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn count_limits_results() {
        let ctx = Context::new();
        add_peer(&ctx, peer("127.0.0.1:8333", 9));
        add_peer(&ctx, peer("127.0.0.2:8333", 9));
        add_peer(&ctx, peer("127.0.0.3:8333", 9));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([2]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn default_count_returns_one() {
        let ctx = Context::new();
        add_peer(&ctx, peer("127.0.0.1:8333", 9));
        add_peer(&ctx, peer("127.0.0.2:8333", 9));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn added_nodes_appear_when_no_live_peer() {
        let ctx = Context::new();
        ctx.network
            .p2p
            .add_node(
                bitcoin_rs_p2p::parse_endpoint("10.0.0.1:8333").expect("addr"),
                true,
            )
            .expect("add_node");
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([0]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0].get("address").and_then(JsonValueTrait::as_str),
            Some("10.0.0.1")
        );
        assert_eq!(
            arr[0].get("services").and_then(JsonValueTrait::as_u64),
            Some(1)
        );
    }
}

#[cfg(test)]
mod setban_absolute_time_tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::ban_until;
    use crate::error::RpcError;

    // SETBAN-ABSOLUTE-01 on `ban_until` above; independent reference:
    // Bitcoin Core v31.1 `src/rpc/net.cpp::setban` compares banTime < GetTime().
    // Synthetic clock values cover the strict whole-second boundary without
    // sleeps or changing any process-global clock.
    #[test]
    fn absolute_bantime_compares_whole_epoch_seconds() -> Result<(), RpcError> {
        let now_seconds = 1_000;
        for nanos in [0, 1, 999_999_999] {
            let now = UNIX_EPOCH + Duration::new(now_seconds, nanos);
            for seconds in [0, now_seconds - 1] {
                let Err(error) = ban_until(now, seconds, true) else {
                    panic!("past absolute timestamp must be rejected");
                };
                assert_eq!(error.code(), -8);
                assert!(matches!(
                    error,
                    RpcError::InvalidParameter(message)
                        if message == "Error: Absolute timestamp is in the past"
                ));
            }
            for seconds in [now_seconds, now_seconds + 1] {
                assert_eq!(
                    ban_until(now, seconds, true)?,
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    "current whole second and future timestamps are accepted"
                );
            }
        }
        Ok(())
    }
}
