use alloc::sync::Arc;

use core::str::FromStr;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_rs_p2p::{AddNodeError, BanError, ConnectedPeer, IpSubnet, NetworkControls};
use bitcoin_rs_primitives::USER_AGENT;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str};

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

fn require_controls(ctx: &Context) -> Result<&NetworkControls, RpcError> {
    ctx.network_controls
        .as_deref()
        .ok_or(RpcError::MethodDisabled("network controls are unavailable"))
}

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

fn epoch_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).ok().map_or(0, |duration| {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    })
}

fn epoch_micros(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).ok().map_or(0, |duration| {
        u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
    })
}

fn optional_i64(params: &Value, index: usize, default: i64) -> Result<i64, RpcError> {
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
        .as_i64()
        .ok_or(RpcError::InvalidType("parameter must be integer"))
}

fn map_ban_error(error: BanError) -> RpcError {
    RpcError::Misc(error.to_string())
}

fn map_add_node_error(error: AddNodeError) -> RpcError {
    RpcError::Misc(error.to_string())
}

fn duration_secs(duration: Option<Duration>) -> f64 {
    duration.map_or(0.0, |value| value.as_secs_f64())
}

fn peer_json(peer: &ConnectedPeer) -> Value {
    let stats = peer.stats.as_ref();
    let (version, services, user_agent, start_height, conn_time) = match &peer.info {
        Some(info) => (
            info.version,
            info.services,
            info.user_agent.clone(),
            info.start_height,
            info.conn_time,
        ),
        None => (0, 0, String::new(), 0, 0),
    };
    let services_names = match &peer.info {
        Some(info) => info
            .services_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        None => services_names_from_flags(services),
    };
    json!({
        "id": peer.node_id,
        "addr": peer.addr.to_string(),
        "addrbind": peer.addr.to_string(),
        "services": format!("{services:016x}"),
        "servicesnames": services_names,
        "relaytxes": true,
        "lastsend": 0,
        "lastrecv": 0,
        "bytessent": stats.bytes_sent(),
        "bytesrecv": stats.bytes_recv(),
        "conntime": conn_time,
        "timeoffset": stats.time_offset().unwrap_or(0),
        "pingtime": duration_secs(stats.ping_time()),
        "minping": duration_secs(stats.min_ping()),
        "version": version,
        "subver": user_agent,
        "inbound": peer.inbound,
        "startingheight": start_height,
        "presynced_headers": -1,
        "synced_headers": -1,
        "synced_blocks": -1,
        "inflight": Vec::<u32>::new(),
        "addr_processed": 0,
        "addr_rate_limited": 0,
        "permissions": Vec::<String>::new(),
        "minfeefilter": 0.0,
        "bytessent_per_msg": serde_json::Map::<String, serde_json::Value>::new(),
        "bytesrecv_per_msg": serde_json::Map::<String, serde_json::Value>::new(),
        "connection_type": if peer.inbound { "inbound" } else { "outbound-full-relay" },
    })
}

fn added_node_json(info: &bitcoin_rs_p2p::AddedNodeInfo) -> Value {
    let addresses = if info.connected {
        info.resolved
            .map(|addr| {
                vec![json!({
                    "address": addr.to_string(),
                    "connected": "outbound",
                })]
            })
            .unwrap_or_default()
    } else {
        Vec::<Value>::new()
    };
    json!({
        "addednode": info.spec,
        "connected": info.connected,
        "addresses": addresses,
    })
}
pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let controls = require_controls(ctx)?;
    let counts = controls.connection_counts();
    Ok(json!({
        "version": 10000,
        "subversion": USER_AGENT,
        "protocolversion": 70016_i64,
        "localservices": LOCAL_SERVICES_HEX,
        "localservicesnames": services_names_from_flags(LOCAL_SERVICES_FLAGS),
        "localrelay": true,
        "timeoffset": controls.time_offset().unwrap_or(0),
        "networkactive": controls.network_active(),
        "connections": counts.total(),
        "connections_in": counts.inbound,
        "connections_out": counts.outbound,
        "networks": [
            {"name": "ipv4", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "ipv6", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "onion", "limited": true, "reachable": false, "proxy": "", "proxy_randomize_credentials": false}
        ],
        "relayfee": DEFAULT_RELAY_FEE_BTC_PER_KVB,
        "incrementalfee": DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB,
        "localaddresses": Vec::<String>::new(),
        "warnings": ctx
            .rpc_lifecycle
            .as_ref()
            .map_or_else(String::new, |lifecycle| lifecycle.warnings_text())
    }))
}

pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let controls = require_controls(ctx)?;
    let peers = controls.connected_peers();
    let array: Vec<Value> = peers.iter().map(peer_json).collect();
    Ok(json!(array))
}

pub(crate) fn getaddednodeinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let controls = require_controls(ctx)?;
    let mut infos = controls.added_node_infos();
    if let Some(node) = array.first().and_then(JsonValueTrait::as_str) {
        infos.retain(|entry| entry.spec == node);
        if infos.is_empty() {
            return Err(RpcError::Misc("Error: Node has not been added.".to_owned()));
        }
    }
    let entries: Vec<Value> = infos.iter().map(added_node_json).collect();
    Ok(json!(entries))
}

pub(crate) fn listbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let controls = require_controls(ctx)?;
    let now = SystemTime::now();
    let entries: Vec<Value> = controls
        .banned_list(now)
        .into_iter()
        .map(|entry| {
            json!({
                "address": entry.subnet.to_string(),
                "banned_until": entry.banned_until.map_or(0, epoch_seconds),
                "ban_created": epoch_seconds(entry.ban_created),
                "ban_reason": entry.reason,
            })
        })
        .collect();
    Ok(json!(entries))
}

pub(crate) fn setban(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let subnet_str = required_str(params, 0, "subnet is required")?;
    let command = required_str(params, 1, "command is required")?;
    let subnet = parse_setban_target(subnet_str)?;
    let controls = require_controls(ctx)?;
    match command {
        "add" => {
            let bantime = optional_i64(params, 2, 0)?;
            let absolute = optional_bool(params, 3, false)?;
            controls
                .ban(subnet, bantime, absolute, SystemTime::now(), "manual")
                .map_err(map_ban_error)?;
        }
        "remove" => {
            controls.unban(&subnet).map_err(map_ban_error)?;
        }
        _ => return Err(RpcError::InvalidParams("command must be 'add' or 'remove'")),
    }
    Ok(Value::new_null())
}

pub(crate) fn clearbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    require_controls(ctx)?.clear_banned();
    Ok(Value::new_null())
}

pub(crate) fn setnetworkactive(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let state = array
        .first()
        .and_then(JsonValueTrait::as_bool)
        .ok_or(RpcError::InvalidParams("state must be a boolean"))?;
    let controls = require_controls(ctx)?;
    Ok(json!(controls.set_network_active(state)))
}

pub(crate) fn ping(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let controls = require_controls(ctx)?;
    let _ = controls.send_pings(epoch_micros(SystemTime::now()));
    Ok(Value::new_null())
}

pub(crate) fn addnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let node = required_str(params, 0, "node is required")?;
    let command = required_str(params, 1, "command is required")?;
    let controls = require_controls(ctx)?;
    match command {
        "add" => controls.add_node(node).map_err(map_add_node_error)?,
        "remove" => controls
            .remove_added_node(node)
            .map_err(map_add_node_error)?,
        "onetry" => controls.try_node_connection(node),
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
    let address = array.first().and_then(JsonValueTrait::as_str).unwrap_or("");
    let node_id = array.get(1).and_then(JsonValueTrait::as_i64);
    let controls = require_controls(ctx)?;

    let disconnected = if !address.is_empty() {
        let addr = SocketAddr::from_str(address)
            .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;
        controls.disconnect_node(&addr)
    } else if let Some(node_id) = node_id {
        let node_id = u64::try_from(node_id)
            .map_err(|_| RpcError::InvalidParams("nodeid must be non-negative"))?;
        controls.disconnect_node_by_id(node_id)
    } else {
        return Err(RpcError::InvalidParams(
            "No address provided for disconnectnode",
        ));
    };

    if !disconnected {
        return Err(RpcError::Misc(
            "Node not found in connected nodes".to_owned(),
        ));
    }
    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let counts = require_controls(ctx)?.connection_counts();
    Ok(json!(counts.total()))
}

pub(crate) fn getnettotals(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let controls = require_controls(ctx)?;
    let now = SystemTime::now();
    let now_secs = i64::try_from(epoch_seconds(now)).unwrap_or(i64::MAX);
    let totals = controls.totals();
    let upload = totals.upload_target(now_secs);
    Ok(json!({
        "totalbytesrecv": totals.total_bytes_recv(),
        "totalbytessent": totals.total_bytes_sent(),
        "timemillis": epoch_millis(now),
        "uploadtarget": {
            "timeframe": upload.timeframe_secs,
            "target": upload.target_bytes,
            "target_reached": upload.target_reached,
            "serve_historical_blocks": upload.serve_historical_blocks,
            "bytes_left_in_cycle": upload.bytes_left_in_cycle,
            "time_left_in_cycle": upload.time_left_in_cycle_secs
        }
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

    fn fresh_controls() -> Arc<NetworkControls> {
        Arc::new(NetworkControls::new(
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            8_333,
        ))
    }

    fn ctx_with(controls: Arc<NetworkControls>) -> Arc<Context> {
        Arc::new(Context::new().with_network_controls(controls))
    }

    #[test]
    fn getnetworkinfo_reports_zero_connections_on_fresh_context() {
        let ctx = ctx_with(fresh_controls());
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
        assert_eq!(
            result
                .get("networkactive")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
    }

    #[test]
    fn getnetworkinfo_emits_relayfee_default_of_one_sat_per_vbyte() {
        let ctx = ctx_with(fresh_controls());
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
        let ctx = ctx_with(fresh_controls());
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
        };

        assert_eq!(info.services_names(), vec!["NETWORK", "WITNESS"]);
    }

    #[test]
    fn services_names_from_flags_ignores_unknown_bits() {
        let names = services_names_from_flags(1_u64 << 63);
        assert!(names.is_empty());
    }

    #[test]
    fn handlers_require_network_controls() {
        let ctx = Arc::new(Context::new());
        assert!(matches!(
            getconnectioncount(&ctx, &json!(null)),
            Err(RpcError::MethodDisabled("network controls are unavailable"))
        ));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod ping_tests {
    use super::*;
    use alloc::sync::Arc;
    use bitcoin_rs_p2p::{Message, PeerLease};

    fn fresh_controls() -> Arc<NetworkControls> {
        Arc::new(NetworkControls::new(
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            8_333,
        ))
    }

    #[test]
    fn ping_queues_through_shared_controls() {
        let controls = fresh_controls();
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let (tx, rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        controls.peer_outbound().write().insert(addr, lease.clone());
        let ctx = Arc::new(Context::new().with_network_controls(Arc::clone(&controls)));

        let result = ping(&ctx, &json!([])).unwrap_or_else(|err| panic!("ping failed: {err}"));
        assert!(result.is_null());
        assert!(matches!(rx.try_recv(), Ok(Message::Ping(_))));
        assert!(
            lease
                .stats()
                .ping_wait(epoch_micros(SystemTime::now()))
                .is_some()
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod addnode_validation_tests {
    use super::*;
    use alloc::sync::Arc;

    fn ctx_with_dial() -> (Arc<Context>, crossbeam_channel::Receiver<SocketAddr>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let controls = NetworkControls::new(
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            8_333,
        )
        .with_dial_sender(tx);
        (
            Arc::new(Context::new().with_network_controls(Arc::new(controls))),
            rx,
        )
    }

    fn bare_ctx() -> Arc<Context> {
        Arc::new(
            Context::new().with_network_controls(Arc::new(NetworkControls::new(
                Arc::new(parking_lot::RwLock::new(Vec::new())),
                Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
                Arc::new(parking_lot::RwLock::new(Vec::new())),
                8_333,
            ))),
        )
    }

    #[test]
    fn addnode_rejects_unknown_command() {
        let ctx = bare_ctx();
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }

    #[test]
    fn addnode_accepts_well_formed_input() {
        let (ctx, rx) = ctx_with_dial();
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "onetry"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        assert!(result.is_null());
        assert_eq!(
            rx.try_recv().ok(),
            Some(SocketAddr::from(([127, 0, 0, 1], 8333)))
        );
    }

    #[test]
    fn addnode_add_sends_outbound_request() {
        let (ctx, rx) = ctx_with_dial();
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let Ok(sent) = rx.try_recv() else {
            panic!("addnode did not send outbound request");
        };
        assert_eq!(sent, SocketAddr::from(([127, 0, 0, 1], 8333)));
    }

    #[test]
    fn addnode_duplicate_returns_exact_error() {
        let ctx = bare_ctx();
        addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("first addnode failed: {err}"));
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));
        assert!(matches!(
            result,
            Err(RpcError::Misc(message)) if message == "node already added"
        ));
    }

    #[test]
    fn addnode_remove_missing_returns_exact_error() {
        let ctx = bare_ctx();
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "remove"]));
        assert!(matches!(
            result,
            Err(RpcError::Misc(message))
                if message == "node could not be removed. it has not been added previously."
        ));
    }

    #[test]
    fn disconnectnode_rejects_bad_address() {
        let ctx = bare_ctx();
        let result = disconnectnode(&ctx, &json!(["definitely-not-an-address"]));
        assert!(result.is_err());
    }

    #[test]
    fn disconnectnode_missing_peer_returns_exact_error() {
        let ctx = bare_ctx();
        let result = disconnectnode(&ctx, &json!(["127.0.0.1:8333"]));
        assert!(matches!(
            result,
            Err(RpcError::Misc(message)) if message == "Node not found in connected nodes"
        ));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod admin_rpc_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};

    fn bare_ctx() -> Arc<Context> {
        Arc::new(
            Context::new().with_network_controls(Arc::new(NetworkControls::new(
                Arc::new(parking_lot::RwLock::new(Vec::new())),
                Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
                Arc::new(parking_lot::RwLock::new(Vec::new())),
                8_333,
            ))),
        )
    }

    #[test]
    fn getaddednodeinfo_returns_empty_array() {
        let ctx = bare_ctx();
        let result = getaddednodeinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn listbanned_returns_empty_array() {
        let ctx = bare_ctx();
        let result =
            listbanned(&ctx, &json!(null)).unwrap_or_else(|err| panic!("listbanned failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn setban_accepts_add_and_remove() {
        let ctx = bare_ctx();
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
        assert!(
            listbanned(&ctx, &json!(null))
                .unwrap_or_else(|err| panic!("listbanned failed: {err}"))
                .as_array()
                .is_some_and(sonic_rs::Array::is_empty)
        );
    }

    #[test]
    fn setban_rejects_unknown_command() {
        let ctx = bare_ctx();
        let result = setban(&ctx, &json!(["10.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }

    #[test]
    fn setnetworkactive_toggles_shared_state() {
        let controls = Arc::new(NetworkControls::new(
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            8_333,
        ));
        let ctx = Arc::new(Context::new().with_network_controls(Arc::clone(&controls)));
        let result = setnetworkactive(&ctx, &json!([false]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
        assert!(!controls.network_active());
        let info = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            info.get("networkactive").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        let result = setnetworkactive(&ctx, &json!([true]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert_eq!(result.as_bool(), Some(true));
        assert!(controls.network_active());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod ban_state_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};

    fn bare_ctx() -> Arc<Context> {
        Arc::new(
            Context::new().with_network_controls(Arc::new(NetworkControls::new(
                Arc::new(parking_lot::RwLock::new(Vec::new())),
                Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
                Arc::new(parking_lot::RwLock::new(Vec::new())),
                8_333,
            ))),
        )
    }

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
    fn setban_add_persists_through_controls() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "127.0.0.1:8333", "add");
        assert_eq!(list_addresses(&ctx).len(), 1);
    }

    #[test]
    fn listbanned_returns_added_entries() {
        let ctx = bare_ctx();
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
        assert_eq!(
            entry.get("ban_reason").and_then(JsonValueTrait::as_str),
            Some("manual")
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
        let ctx = bare_ctx();
        setban_ok(&ctx, "10.0.0.0/8", "add");

        assert_eq!(sole_address(&ctx), "10.0.0.0/8");
    }

    #[test]
    fn setban_normalizes_host_bits() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "192.168.1.99/24", "add");

        assert_eq!(sole_address(&ctx), "192.168.1.0/24");
    }

    #[test]
    fn setban_bare_ip_stores_single_address_subnet() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "192.168.1.99", "add");

        assert_eq!(sole_address(&ctx), "192.168.1.99/32");
    }

    #[test]
    fn setban_ipv6_cidr_canonicalizes() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "2001:db8::1/64", "add");

        assert_eq!(sole_address(&ctx), "2001:db8::/64");
    }

    #[test]
    fn setban_rejects_invalid_subnet() {
        let ctx = bare_ctx();
        let result = setban(&ctx, &json!(["10.0.0.1/33", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams(
                "subnet must be IP, IP/prefix, or host:port"
            ))
        ));
    }

    #[test]
    fn setban_duplicate_returns_exact_error() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "10.0.0.1", "add");
        let result = setban(&ctx, &json!(["10.0.0.1", "add"]));
        assert!(matches!(
            result,
            Err(RpcError::Misc(message)) if message == "ip/subnet already banned"
        ));
    }

    #[test]
    fn setban_remove_missing_returns_exact_error() {
        let ctx = bare_ctx();
        let result = setban(&ctx, &json!(["10.0.0.1", "remove"]));
        assert!(matches!(
            result,
            Err(RpcError::Misc(message))
                if message == "address/subnet was not previously manually banned"
        ));
    }

    #[test]
    fn setban_remove_matches_exact_subnet() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "10.0.0.0/24", "add");
        setban_ok(&ctx, "10.0.0.1", "add");

        setban_ok(&ctx, "10.0.0.1", "remove");

        assert_eq!(list_addresses(&ctx), vec!["10.0.0.0/24".to_owned()]);
    }

    #[test]
    fn clearbanned_empties_shared_state() {
        let ctx = bare_ctx();
        setban_ok(&ctx, "192.168.1.1", "add");
        clearbanned_ok(&ctx);
        assert!(list_addresses(&ctx).is_empty());
    }

    #[test]
    fn addnode_add_persists_for_getaddednodeinfo() {
        let ctx = bare_ctx();
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        let result = getaddednodeinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0].get("addednode").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1:8333")
        );
    }
}
