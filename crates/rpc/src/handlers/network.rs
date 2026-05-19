use alloc::sync::Arc;

use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, required_str};

pub(crate) fn getnetworkinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    Ok(json!({
        "version": 0,
        "subversion": "/bitcoin-rs:0.1.0/",
        "protocolversion": 70016,
        "localservices": "0000000000000000",
        "localservicesnames": [],
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": 0,
        "connections_in": 0,
        "connections_out": 0,
        "networks": [
            {"name": "ipv4", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "ipv6", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "onion", "limited": true, "reachable": false, "proxy": "", "proxy_randomize_credentials": false}
        ],
        "relayfee": 0.0,
        "incrementalfee": 0.0,
        "localaddresses": [],
        "warnings": ""
    }))
}

pub(crate) fn getpeerinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    Ok(json!([]))
}

pub(crate) fn addnode(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "node is required")?;
    required_str(params, 1, "command is required")?;
    Ok(Value::new_null())
}

pub(crate) fn disconnectnode(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "address is required")?;
    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    Ok(json!(ctx.network.read().connection_count))
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
