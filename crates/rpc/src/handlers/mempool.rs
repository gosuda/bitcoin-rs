use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::Txid;
use bitcoin_rs_mempool::MempoolEntry;
use serde_json::json as serde_json_value;
use sonic_rs::{JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, required_str, serde_to_sonic};

pub(crate) fn getmempoolinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let pool = ctx.mempool.read();
    Ok(json!({
        "loaded": true,
        "size": pool.len(),
        "bytes": pool.total_vsize(),
        "usage": 0,
        "total_fee": 0.0,
        "maxmempool": 300_000_000_u64,
        "mempoolminfee": 0.0,
        "minrelaytxfee": 0.0,
        "incrementalrelayfee": 0.0,
        "unbroadcastcount": 0,
        "fullrbf": true
    }))
}

pub(crate) fn getmempoolentry(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let pool = ctx.mempool.read();
    let id = pool
        .by_txid
        .get(&txid)
        .ok_or(RpcError::NotFound("transaction not in mempool"))?;
    let entry = pool
        .entry(*id)
        .ok_or(RpcError::NotFound("transaction not in mempool"))?;
    entry_to_value(entry)
}

pub(crate) fn getrawmempool(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let verbose = optional_bool(params, 0, false)?;
    let pool = ctx.mempool.read();
    if !verbose {
        let txids = pool
            .entries
            .iter()
            .map(|(_id, entry)| entry.tx.compute_txid().to_string())
            .collect::<Vec<_>>();
        return Ok(json!(txids));
    }
    let mut object = serde_json::Map::new();
    for (_id, entry) in &pool.entries {
        object.insert(entry.tx.compute_txid().to_string(), entry_to_serde(entry));
    }
    serde_to_sonic(&serde_json::Value::Object(object))
}

pub(crate) fn getmempoolancestors(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    mempool_relatives(ctx, params)
}

pub(crate) fn getmempooldescendants(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    mempool_relatives(ctx, params)
}

fn mempool_relatives(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = params_array(params)?
        .get(1)
        .and_then(JsonValueTrait::as_bool)
        .unwrap_or(false);
    let pool = ctx.mempool.read();
    if !pool.by_txid.contains_key(&txid) {
        return Err(RpcError::NotFound("transaction not in mempool"));
    }
    if verbose {
        serde_to_sonic(&serde_json_value!({}))
    } else {
        Ok(json!([]))
    }
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

fn entry_to_value(entry: &MempoolEntry) -> Result<Value, RpcError> {
    serde_to_sonic(&entry_to_serde(entry))
}

fn entry_to_serde(entry: &MempoolEntry) -> serde_json::Value {
    serde_json_value!({
        "vsize": entry.vsize,
        "weight": u64::from(entry.vsize).saturating_mul(4),
        "time": entry.time,
        "height": entry.height,
        "descendantcount": 1,
        "descendantsize": entry.descendant_size,
        "ancestorcount": 1,
        "ancestorsize": entry.ancestor_size,
        "wtxid": entry.tx.compute_wtxid().to_string(),
        "fees": {
            "base": sats_to_btc(entry.fee),
            "modified": sats_to_btc(entry.fee),
            "ancestor": sats_to_btc(entry.ancestor_fee),
            "descendant": sats_to_btc(entry.descendant_fee)
        },
        "depends": [],
        "spentby": [],
        "bip125-replaceable": false,
        "unbroadcast": false
    })
}

fn sats_to_btc(sats: u64) -> f64 {
    bitcoin::Amount::from_sat(sats).to_btc()
}
