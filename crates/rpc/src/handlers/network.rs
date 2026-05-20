use alloc::sync::Arc;

use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, required_str};

const DEFAULT_RELAY_FEE_BTC_PER_KVB: f64 = 0.00001;
const DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB: f64 = 0.00001;

pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peers.read();
    let total = peers.len();
    let inbound = peers.iter().filter(|p| p.inbound).count();
    let outbound = total.saturating_sub(inbound);
    Ok(json!({
        "version": 10000,
        "subversion": "/bitcoin-rs:0.1.0/",
        "protocolversion": 70016_i64,
        "localservices": "0000000000000000",
        "localservicesnames": Vec::<String>::new(),
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": total,
        "connections_in": inbound,
        "connections_out": outbound,
        "networks": [
            {"name": "ipv4", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "ipv6", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "onion", "limited": true, "reachable": false, "proxy": "", "proxy_randomize_credentials": false}
        ],
        "relayfee": DEFAULT_RELAY_FEE_BTC_PER_KVB,
        "incrementalfee": DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB,
        "localaddresses": Vec::<String>::new(),
        "warnings": ""
    }))
}

pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peers.read();
    let mut array = Vec::with_capacity(peers.len());
    for (id, peer) in peers.iter().enumerate() {
        array.push(json!({
            "id": id,
            "addr": peer.addr.to_string(),
            "addrbind": peer.addr.to_string(),
            "services": format!("{:016x}", peer.services),
            "servicesnames": Vec::<String>::new(),
            "relaytxes": true,
            "lastsend": 0,
            "lastrecv": 0,
            "bytessent": 0,
            "bytesrecv": 0,
            "conntime": peer.conn_time,
            "timeoffset": 0,
            "pingtime": 0.0,
            "minping": 0.0,
            "version": peer.version,
            "subver": peer.user_agent.clone(),
            "inbound": peer.inbound,
            "startingheight": peer.start_height,
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
            "connection_type": if peer.inbound { "inbound" } else { "outbound" },
        }));
    }
    Ok(json!(array))
}

pub(crate) fn addnode(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    let node = required_str(params, 0, "node is required")?;
    let command = required_str(params, 1, "command is required")?;
    // Parse the address. Accept host:port form via SocketAddr::from_str; bare
    // hostnames need DNS resolution which is deferred.
    std::net::SocketAddr::from_str(node)
        .map_err(|_| RpcError::InvalidParams("node must be a valid host:port address"))?;
    match command {
        "add" | "remove" | "onetry" => {}
        _ => {
            return Err(RpcError::InvalidParams(
                "command must be one of: add, remove, onetry",
            ));
        }
    }
    // TODO(p2p-outbound): wire to a Sender<NetworkCommand> on Context so the
    // node's P2P listener can establish/teardown the outbound connection.
    Ok(Value::new_null())
}

pub(crate) fn disconnectnode(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    let address = required_str(params, 0, "address is required")?;
    std::net::SocketAddr::from_str(address)
        .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;
    // TODO(p2p-outbound): wire to a disconnection sender on Context.
    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let count = ctx.peers.read().len();
    Ok(json!(count))
}

pub(crate) fn getnettotals(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let network = ctx.network.read();
    Ok(json!({
        "totalbytesrecv": network.bytes_recv,
        "totalbytessent": network.bytes_sent,
        "timemillis": network.timestamp,
        "uploadtarget": {
            "timeframe": 0,
            "target": 0,
            "target_reached": true,
            "serve_historical_blocks": true,
            "bytes_left_in_cycle": 0,
            "time_left_in_cycle": 0
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

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
}

#[cfg(test)]
mod addnode_validation_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

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
    fn disconnectnode_rejects_bad_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["definitely-not-an-address"]));
        assert!(result.is_err());
    }

    #[test]
    fn disconnectnode_accepts_well_formed_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["127.0.0.1:8333"]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
    }
}
