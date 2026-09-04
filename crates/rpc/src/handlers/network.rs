use alloc::sync::Arc;

use core::str::FromStr;
use core::sync::atomic::Ordering;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_rs_p2p::{BannedSubnet, IpSubnet};
use bitcoin_rs_primitives::USER_AGENT;
use crossbeam_channel::TrySendError;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};

use crate::compat::convert::{i64_saturated, typed_to_sonic, typed_to_sonic_omitting_nulls};
use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str};
use corepc_types::v31::{self, ConnectionType, GetNetworkInfoNetwork, TransportProtocolType};

// Local service flags this node advertises:
// - NODE_NETWORK (1 << 0) = 1 — full block serving.
// - NODE_WITNESS (1 << 3) = 8 — segwit data.
// Sum = 9 = 0x09.
const LOCAL_SERVICES_FLAGS: u64 = (1_u64 << 0) | (1_u64 << 3);
const LOCAL_SERVICES_HEX: &str = "0000000000000009";

const _: () = assert!(LOCAL_SERVICES_FLAGS == 0x09);
/// Decodes a Bitcoin service-flags bitmask into a list of name strings.
///
/// Order follows Bitcoin Core's bit assignment. Unrecognized bits are dropped.
fn services_names_from_flags(flags: u64) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if flags & (1_u64 << 0) != 0 {
        names.push("NETWORK".to_owned());
    }
    if flags & (1_u64 << 1) != 0 {
        names.push("GETUTXO".to_owned());
    }
    if flags & (1_u64 << 2) != 0 {
        names.push("BLOOM".to_owned());
    }
    if flags & (1_u64 << 3) != 0 {
        names.push("WITNESS".to_owned());
    }
    if flags & (1_u64 << 10) != 0 {
        names.push("NETWORK_LIMITED".to_owned());
    }
    if flags & (1_u64 << 11) != 0 {
        names.push("P2P_V2".to_owned());
    }
    names
}

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

fn ban_until(now: SystemTime, bantime: u64, absolute: bool) -> Option<SystemTime> {
    if absolute {
        return UNIX_EPOCH.checked_add(Duration::from_secs(bantime));
    }

    let duration = if bantime == 0 {
        Duration::from_secs(DEFAULT_BAN_TIME_SECS)
    } else {
        Duration::from_secs(bantime)
    };
    now.checked_add(duration)
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
    value
        .as_u64()
        .ok_or(RpcError::InvalidType("parameter must be unsigned integer"))
}

/// Maps an IP address to Bitcoin Core's `network` field label.
fn network_name(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peer_table.infos();
    let total = peers.len();
    let inbound = peers.iter().filter(|p| p.inbound).count();
    let outbound = total.saturating_sub(inbound);
    let network_active = ctx.network_active.load(Ordering::SeqCst);
    let networks = [
        ("ipv4", false, true),
        ("ipv6", false, true),
        ("onion", true, false),
    ]
    .into_iter()
    .map(|(name, limited, reachable)| GetNetworkInfoNetwork {
        name: name.to_owned(),
        limited,
        reachable,
        proxy: String::new(),
        proxy_randomize_credentials: false,
    })
    .collect::<Vec<_>>();
    typed_to_sonic(&v31::GetNetworkInfo {
        version: usize::try_from(bitcoin_rs_primitives::client_version()).unwrap_or(usize::MAX),
        subversion: USER_AGENT.to_owned(),
        protocol_version: 70016,
        local_services: LOCAL_SERVICES_HEX.to_owned(),
        local_services_names: services_names_from_flags(LOCAL_SERVICES_FLAGS),
        local_relay: true,
        time_offset: isize::try_from(median_time_offset(&peers)).unwrap_or(0),
        connections: total,
        connections_in: inbound,
        connections_out: outbound,
        network_active,
        networks,
        relay_fee: DEFAULT_RELAY_FEE_BTC_PER_KVB,
        incremental_fee: DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB,
        local_addresses: Vec::new(),
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
    // declare any time they like; medianing over all peers hands that
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

pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peer_table.infos();
    let rows = peers
        .iter()
        .enumerate()
        .map(|(id, peer)| v31::PeerInfo {
            id: u32::try_from(id).unwrap_or(u32::MAX),
            address: peer.addr.to_string(),
            address_bind: Some(peer.addr_bind.to_string()),
            address_local: None,
            network: network_name(peer.addr.ip()).to_owned(),
            mapped_as: None,
            services: format!("{:016x}", peer.services),
            services_names: peer
                .services_names()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            relay_transactions: true,
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
            bip152_hb_to: false,
            bip152_hb_from: false,
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
            permissions: Vec::new(),
            minimum_fee_filter: 0.0,
            bytes_sent_per_message: std::collections::BTreeMap::new(),
            bytes_received_per_message: std::collections::BTreeMap::new(),
            inv_to_send: 0,
            last_inv_sequence: 0,
            connection_type: Some(if peer.inbound {
                ConnectionType::Inbound
            } else {
                ConnectionType::OutboundFullRelay
            }),
            transport_protocol_type: TransportProtocolType::V1,
            session_id: String::new(),
        })
        .collect::<Vec<_>>();
    typed_to_sonic_omitting_nulls(&v31::GetPeerInfo(rows))
}

pub(crate) fn getaddednodeinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let _ = params_array(params)?;
    let added = ctx.added_nodes.read();
    let entries = added
        .iter()
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
    let banned = ctx.banned.read();
    let now = epoch_seconds(SystemTime::now());
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
            let mut banned = ctx.banned.write();
            banned.retain(|entry| entry.subnet != subnet);
            banned.push(BannedSubnet {
                subnet,
                banned_until: ban_until(now, bantime, absolute),
                ban_created: now,
                reason: "manual".to_owned(),
            });
        }
        "remove" => {
            ctx.banned.write().retain(|entry| entry.subnet != subnet);
        }
        _ => return Err(RpcError::InvalidParams("command must be 'add' or 'remove'")),
    }
    Ok(Value::new_null())
}

pub(crate) fn clearbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    ctx.banned.write().clear();
    Ok(Value::new_null())
}

pub(crate) fn setnetworkactive(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let state = array
        .first()
        .and_then(JsonValueTrait::as_bool)
        .ok_or(RpcError::InvalidParams("state must be a boolean"))?;
    ctx.network_active.store(state, Ordering::SeqCst);
    if !state {
        ctx.peer_table.cancel_all();
    }
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
    let addr = SocketAddr::from_str(node)
        .map_err(|_| RpcError::InvalidParams("node must be a valid host:port address"))?;
    match command {
        "add" | "onetry" => {
            let now = SystemTime::now();
            let banned = ctx.banned.read();
            if bitcoin_rs_p2p::subnet::is_banned(banned.as_slice(), addr.ip(), now) {
                return Err(RpcError::InvalidParams("node is banned"));
            }
            drop(banned);

            let persist = command == "add";
            if persist {
                let mut list = ctx.added_nodes.write();
                if !list.contains(&addr) {
                    list.push(addr);
                }
            }

            if ctx.network_active.load(Ordering::Acquire)
                && let Some(sender) = &ctx.p2p_outbound_sender
            {
                match sender.try_send(addr) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) if persist => {}
                    Err(TrySendError::Full(_)) => {
                        return Err(RpcError::Internal("p2p outbound queue full".to_owned()));
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        return Err(RpcError::Internal("p2p outbound channel closed".to_owned()));
                    }
                }
            }
        }
        "remove" => {
            let mut list = ctx.added_nodes.write();
            list.retain(|a| *a != addr);
        }
        _ => {
            return Err(RpcError::InvalidParams(
                "command must be one of: add, remove, onetry",
            ));
        }
    }
    Ok(Value::new_null())
}

pub(crate) fn disconnectnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let address = required_str(params, 0, "address is required")?;
    let addr = SocketAddr::from_str(address)
        .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;

    // Optional nodeid — the index reported by `getpeerinfo`, used to
    // disambiguate when several peers share one address.
    let nodeid: Option<usize> = array
        .get(1)
        .filter(|v| !v.is_null())
        .and_then(JsonValueTrait::as_u64)
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX));

    // Verify the peer is currently connected before mutating anything.
    let found = {
        let peers = ctx.peer_table.infos();
        match nodeid {
            Some(id) => id < peers.len() && peers[id].addr == addr,
            None => peers.iter().any(|p| p.addr == addr),
        }
    };
    if !found {
        return Err(RpcError::NotFound("Node not found in connected nodes"));
    }

    ctx.peer_table.disconnect(addr);

    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let count = u64::try_from(ctx.peer_table.len()).unwrap_or(u64::MAX);
    typed_to_sonic(&v31::GetConnectionCount(count))
}

pub(crate) fn getnettotals(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let network = ctx.network.read();
    typed_to_sonic(&v31::GetNetTotals {
        total_bytes_received: network.bytes_recv,
        total_bytes_sent: network.bytes_sent,
        time_millis: network.timestamp,
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

    let now = epoch_seconds(SystemTime::now());
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut entries: Vec<v31::NodeAddress> = Vec::new();

    // Live peers carry real service flags and handshake times.
    for peer in ctx.peer_table.infos() {
        if !seen.insert(peer.addr) {
            continue;
        }
        entries.push(v31::NodeAddress {
            time: peer.conn_time,
            services: peer.services,
            address: peer.addr.ip().to_string(),
            port: peer.addr.port(),
            network: network_name(peer.addr.ip()).to_owned(),
        });
    }

    // Persisted added nodes have no known services; advertise NODE_NETWORK.
    for &addr in ctx.added_nodes.read().iter() {
        if !seen.insert(addr) {
            continue;
        }
        entries.push(v31::NodeAddress {
            time: now,
            services: 1,
            address: addr.ip().to_string(),
            port: addr.port(),
            network: network_name(addr.ip()).to_owned(),
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
    use sonic_rs::JsonValueTrait;
    use sonic_rs::json;

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

    #[test]
    fn local_services_flags_hex_matches_bitmask() {
        assert_eq!(format!("{LOCAL_SERVICES_FLAGS:016x}"), LOCAL_SERVICES_HEX);
    }

    #[test]
    fn services_names_from_flags_decodes_known_bits() {
        let names = services_names_from_flags(0_u64);
        assert!(names.is_empty());

        let names = services_names_from_flags((1_u64 << 0) | (1_u64 << 3));
        assert_eq!(names, vec!["NETWORK".to_owned(), "WITNESS".to_owned()]);

        let names = services_names_from_flags((1_u64 << 0) | (1_u64 << 3) | (1_u64 << 10));
        assert_eq!(
            names,
            vec![
                "NETWORK".to_owned(),
                "WITNESS".to_owned(),
                "NETWORK_LIMITED".to_owned()
            ]
        );
    }

    #[test]
    fn getpeerinfo_servicesnames_matches_peer_info_services_names() {
        use bitcoin_rs_p2p::PeerInfo;

        let info = PeerInfo {
            addr: "127.0.0.1:8333".parse().unwrap_or_else(|_| panic!("addr")),
            version: 70_016,
            services: (1_u64 << 0) | (1_u64 << 3),
            user_agent: "stub".to_owned(),
            start_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: "127.0.0.1:8333".parse().unwrap_or_else(|_| panic!("addr")),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        };

        assert_eq!(info.services_names(), vec!["NETWORK", "WITNESS"]);
    }

    #[test]
    fn services_names_from_flags_ignores_unknown_bits() {
        // Bit 63 is not in the decoder's recognized set.
        let names = services_names_from_flags(1_u64 << 63);
        assert!(names.is_empty());
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
#[allow(clippy::expect_used)]
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
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        ctx.network_active.store(false, Ordering::Release);
        let ctx = Arc::new(ctx);

        let persisted = SocketAddr::from(([127, 0, 0, 1], 8333));
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));
        assert!(result.is_ok());
        assert_eq!(ctx.added_nodes.read().as_slice(), &[persisted]);
        assert!(rx.try_recv().is_err());

        ctx.network_active.store(true, Ordering::Release);
        assert!(rx.try_recv().is_err());
        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));
        assert!(result.is_ok());
        assert_eq!(
            rx.try_recv().ok(),
            Some(SocketAddr::from(([127, 0, 0, 2], 8333)))
        );
    }

    #[test]
    fn addnode_add_sends_outbound_request() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let Ok(sent) = rx.try_recv() else {
            panic!("addnode did not send outbound request");
        };
        assert_eq!(sent, std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
    }

    #[test]
    fn addnode_returns_error_when_outbound_queue_is_full() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        tx.try_send(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)))
            .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));

        assert!(matches!(
            result,
            Err(RpcError::Internal(message)) if message == "p2p outbound queue full"
        ));
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[test]
    fn addnode_add_persists_when_outbound_queue_is_full() {
        let (tx, _rx) = crossbeam_channel::bounded(1);
        tx.try_send(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)))
            .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let added = ctx.added_nodes.read();
        assert_eq!(
            added.as_slice(),
            [std::net::SocketAddr::from(([127, 0, 0, 2], 8333))]
        );
    }

    #[test]
    fn addnode_rejects_manually_banned_subnet() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);
        if let Err(err) = setban(&ctx, &json!(["127.0.0.0/24", "add"])) {
            panic!("setban failed: {err}");
        }

        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams("node is banned"))
        ));
        assert!(ctx.added_nodes.read().is_empty());
        assert!(rx.try_recv().is_err());
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
            addr,
            version: 70_016,
            services: 9,
            user_agent: "test".to_owned(),
            start_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        };
        let (tx, _rx) = unbounded();
        let lease = PeerLease::new(tx);
        ctx.peer_table.register(addr, lease.clone());
        ctx.peer_table.publish_info(addr, &lease, info);
        let ctx = Arc::new(ctx);

        let result = disconnectnode(&ctx, &json!([addr.to_string().as_str()]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
        assert!(lease.is_cancelled());
        assert!(ctx.peer_table.is_empty());
        assert!(ctx.peer_table.infos().is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
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
        let ctx = Arc::new(Context::new());
        let result = setnetworkactive(&ctx, &json!([false]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
        assert!(!ctx.network_active.load(std::sync::atomic::Ordering::SeqCst));
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
        ctx.peer_table.register(addr_a, lease_a.clone());
        ctx.peer_table.register(addr_b, lease_b.clone());
        let ctx = Arc::new(ctx);

        let _ = setnetworkactive(&ctx, &json!([false]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert!(lease_a.is_cancelled());
        assert!(lease_b.is_cancelled());
        assert_eq!(ctx.peer_table.len(), 2);
    }

    #[test]
    fn getnetworkinfo_reports_network_active_state() {
        let ctx = Arc::new(Context::new());
        ctx.network_active
            .store(false, std::sync::atomic::Ordering::SeqCst);
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
        assert!(ctx.banned.read().is_empty());
    }

    #[test]
    fn setban_rejects_unknown_command() {
        let ctx = Arc::new(Context::new());
        let result = setban(&ctx, &json!(["10.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }

    #[test]
    fn setnetworkactive_echoes_state() {
        let ctx = Arc::new(Context::new());
        let result = setnetworkactive(&ctx, &json!([true]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert_eq!(result.as_bool(), Some(true));
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
        let banned = ctx.banned.read();
        assert_eq!(banned.len(), 1);
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
        assert!(ctx.banned.read().is_empty());
    }

    #[test]
    fn addnode_add_persists_in_added_nodes_list() {
        let ctx = Arc::new(Context::new());
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        let added = ctx.added_nodes.read();
        assert_eq!(added.len(), 1);
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
            addr: parse(addr),
            version: 70_016,
            services: 0,
            user_agent: "/test/".to_owned(),
            start_height: 0,
            conn_time: 0,
            inbound,
            addr_bind: parse(bind),
            time_offset,
            counters,
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
            peer_table.register(info.addr, lease.clone());
            peer_table.publish_info(info.addr, &lease, info);
        }
        let mut ctx = Context::new();
        ctx.peer_table = Arc::new(peer_table);
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
#[allow(clippy::expect_used)]
mod getnodeaddresses_tests {
    use super::*;
    use alloc::sync::Arc;
    use bitcoin_rs_p2p::{PeerInfo, PeerLease};
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

    fn peer(addr: &str, services: u64) -> PeerInfo {
        let parsed: SocketAddr = addr.parse().expect("addr");
        PeerInfo {
            addr: parsed,
            version: 70_016,
            services,
            user_agent: "test".to_owned(),
            start_height: 0,
            conn_time: 100,
            inbound: false,
            addr_bind: parsed,
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        }
    }

    fn add_peer(ctx: &Context, info: PeerInfo) {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        ctx.peer_table.register(info.addr, lease.clone());
        ctx.peer_table.publish_info(info.addr, &lease, info);
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
        ctx.added_nodes
            .write()
            .push("127.0.0.1:8333".parse().expect("addr"));
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
        ctx.added_nodes
            .write()
            .push("10.0.0.1:8333".parse().expect("addr"));
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
