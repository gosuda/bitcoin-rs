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
/// SETBAN-EXPIRY-01: zero relative bantime uses `DEFAULT_BAN_TIME_SECS`; absolute
/// bantime is measured from `UNIX_EPOCH`. An unrepresentable expiry returns
/// `RpcError::InvalidParameter` (-8) before any ban-list mutation.
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

pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.network.peer_table.infos();
    let total = peers.len();
    let inbound = peers.iter().filter(|p| p.inbound).count();
    let outbound = total.saturating_sub(inbound);
    let network_active = ctx.network.p2p.network_active();
    let states = ctx.network.p2p.network_states();
    let networks = states
        .iter()
        .map(|state| GetNetworkInfoNetwork {
            name: state.network.name().to_owned(),
            limited: !state.allowed,
            reachable: state.allowed
                && network_active
                && match state.network {
                    bitcoin_rs_p2p::PeerNetwork::Ipv4 | bitcoin_rs_p2p::PeerNetwork::Ipv6 => {
                        state.proxy.is_none() || state.operational
                    }
                    bitcoin_rs_p2p::PeerNetwork::Onion | bitcoin_rs_p2p::PeerNetwork::I2p => {
                        state.proxy.is_some()
                    }
                },
            proxy: state
                .proxy
                .map_or_else(String::new, |socket| socket.to_string()),
            proxy_randomize_credentials: state.proxy.is_some()
                && state.network != bitcoin_rs_p2p::PeerNetwork::I2p
                && ctx.network.p2p.proxy_randomize_credentials(),
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
        local_addresses: {
            let mut seen: HashSet<bitcoin_rs_p2p::PeerEndpoint> = HashSet::new();
            let mut addresses: Vec<corepc_types::v17::GetNetworkInfoAddress> = states
                .iter()
                .filter_map(|state| state.local_address)
                .map(|endpoint| {
                    seen.insert(endpoint);
                    corepc_types::v17::GetNetworkInfoAddress {
                        address: endpoint.address().to_string(),
                        port: endpoint.port(),
                        score: 1,
                    }
                })
                .collect();
            for endpoint in ctx.network.p2p.overlay_addresses() {
                if !matches!(
                    endpoint.address().network(),
                    bitcoin_rs_p2p::PeerNetwork::Onion | bitcoin_rs_p2p::PeerNetwork::I2p
                ) || !seen.insert(endpoint)
                {
                    continue;
                }
                addresses.push(corepc_types::v17::GetNetworkInfoAddress {
                    address: endpoint.host().to_string(),
                    port: endpoint.port(),
                    score: 0,
                });
            }
            addresses
        },
        warnings: Vec::new(),
    })
}

/// Samples below which Core does not compute an offset at all.
const MIN_TIME_OFFSET_SAMPLES: usize = 5;

/// The node's clock offset, as the median of what its outbound peers claim.
fn median_time_offset(peers: &[bitcoin_rs_p2p::PeerInfo]) -> i64 {
    let mut offsets: Vec<i64> = peers
        .iter()
        .filter(|peer| !peer.inbound)
        .map(|peer| peer.time_offset)
        .collect();
    if offsets.len() < MIN_TIME_OFFSET_SAMPLES {
        return 0;
    }
    offsets.sort_unstable();
    offsets.get(offsets.len() / 2).copied().unwrap_or(0)
}

/// Renders every handshake-complete connection, including anonymous inbound
/// overlay sessions.
pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let sessions = ctx.network.peer_table.sessions();
    let rows = sessions
        .iter()
        .filter_map(|session| session.info.as_ref().map(|info| (session, info)))
        .map(|(session, peer)| {
            let minimum_fee_filter = sat_to_btc(
                ctx.network
                    .peer_table
                    .transaction_fee_filter(session.lease.source(session.endpoint)),
            );
            peer_info_wire(session, peer, minimum_fee_filter)
        })
        .collect::<Vec<_>>();
    typed_to_sonic_omitting_nulls(&rows)
}

#[derive(serde::Serialize)]
struct Bip152Flags {
    bip152_hb_to: bool,
    bip152_hb_from: bool,
}

/// One `getpeerinfo` row: `corepc_types::v31::PeerInfo` field for field, with the same
/// keys, except that `id` is the connection's full `u64` identity rather than a `u32`.
///
/// Unset optional fields are dropped by
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

fn peer_info_wire(
    session: &bitcoin_rs_p2p::PeerSession,
    peer: &bitcoin_rs_p2p::PeerInfo,
    minimum_fee_filter: f64,
) -> PeerInfoWire {
    PeerInfoWire {
        id: session.lease.node_id(),
        address: peer.addr.to_string(),
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
        ping_time: None,
        minimum_ping: None,
        ping_wait: None,
        version: peer.version,
        subversion: peer.user_agent.clone(),
        inbound: peer.inbound,
        bip152: Bip152Flags {
            bip152_hb_to: session.bip152_hb_to,
            bip152_hb_from: session.bip152_hb_from,
        },
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
    Ok(Value::new_null())
}

#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "The lowercased I2P DNS suffix selects a transport, not a filesystem extension"
)]
pub(crate) fn addnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let node = required_str(params, 0, "node is required")?;
    let command = required_str(params, 1, "command is required")?;
    if !matches!(command, "add" | "onetry" | "remove") {
        return Err(RpcError::InvalidParams(
            "command must be one of: add, remove, onetry",
        ));
    }
    let addr = if let Ok(endpoint) = bitcoin_rs_p2p::PeerEndpoint::from_str(node) {
        endpoint
    } else if command != "remove"
        && node
            .to_ascii_lowercase()
            .rsplit_once(':')
            .is_some_and(|(host, _)| host.ends_with(".i2p"))
    {
        ctx.network
            .p2p
            .resolve_peer(node)
            .map_err(|_| RpcError::InvalidParams("I2P name resolution failed"))?
            .into_iter()
            .next()
            .ok_or(RpcError::InvalidParams("I2P name has no destination"))?
    } else {
        return Err(RpcError::InvalidParams(
            "node must be a valid host:port address",
        ));
    };
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
        bitcoin_rs_p2p::P2pControlError::NetworkDisabled => {
            RpcError::InvalidParams("destination network disabled")
        }
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
pub(crate) fn disconnectnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["address", "nodeid"])?;
    let array = params_array(&bound)?;
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
            let addr = address
                .parse::<bitcoin_rs_p2p::PeerRemote>()
                .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;
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
            let addr = address
                .parse::<bitcoin_rs_p2p::PeerRemote>()
                .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;
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
/// The address source is the live peer registry plus persisted `addnode add` entries,
/// deduplicated by socket address.  `count` defaults to 1; `0` returns every known
/// address.  Each entry follows Core's shape: `{ time, services, address, port, network
/// }`.
pub(crate) fn getnodeaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let count = optional_u64(params, 0, 1)?;

    let now = unix_time_secs();
    let mut seen: HashSet<bitcoin_rs_p2p::PeerEndpoint> = HashSet::new();
    let mut entries: Vec<v31::NodeAddress> = Vec::new();

    for peer in ctx.network.peer_table.infos() {
        let Some(endpoint) = peer.addr.endpoint() else {
            continue;
        };
        if !seen.insert(endpoint) {
            continue;
        }
        entries.push(v31::NodeAddress {
            time: peer.conn_time,
            services: peer.services,
            address: endpoint.address().to_string(),
            port: endpoint.port(),
            network: peer.addr.network().name().to_owned(),
        });
    }

    for addr in ctx.network.p2p.added_nodes() {
        if !seen.insert(addr) {
            continue;
        }
        entries.push(v31::NodeAddress {
            time: now,
            services: 1,
            address: addr.address().to_string(),
            port: addr.port(),
            network: addr.address().network().name().to_owned(),
        });
    }

    if count > 0 {
        let max = usize::try_from(count).unwrap_or(usize::MAX);
        if max < entries.len() {
            entries.truncate(max);
        }
    }

    typed_to_sonic(&v31::GetNodeAddresses(entries))
}

#[cfg(test)]
mod tests;
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
mod addnode_validation_tests;

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
mod peer_counter_tests;

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
            addr: parsed.into(),
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
    fn anonymous_handles_are_visible_and_disconnectable_but_not_destinations() {
        let ctx = Context::new();
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new_inbound(tx);
        let remote = bitcoin_rs_p2p::PeerRemote::AnonymousTor(lease.connection_id());
        let mut info = peer("127.0.0.1:8333", 9);
        info.addr = remote;
        info.endpoint = None;
        info.network = bitcoin_rs_primitives::NetworkLabel::Onion;
        info.inbound = true;
        ctx.network.peer_table.register(remote, lease.clone());
        ctx.network.peer_table.publish_info(remote, &lease, info);
        let ctx = Arc::new(ctx);
        let listed = getpeerinfo(&ctx, &json!([])).expect("peer info");
        let row = &listed.as_array().expect("peers")[0];
        let handle = remote.to_string();
        assert_eq!(
            row.get("addr").and_then(JsonValueTrait::as_str),
            Some(handle.as_str())
        );
        assert_eq!(
            row.get("network").and_then(JsonValueTrait::as_str),
            Some("onion")
        );
        let destinations = getnodeaddresses(&ctx, &json!([0])).expect("destinations");
        assert_eq!(destinations.as_array().expect("addresses").len(), 0);
        assert!(addnode(&ctx, &json!([handle.as_str(), "add"])).is_err());
        assert!(disconnectnode(&ctx, &json!([handle.as_str()])).is_ok());
        assert!(lease.is_cancelled());
        assert!(ctx.network.peer_table.is_empty());
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
