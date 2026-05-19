use alloc::sync::Arc;
use core::time::Duration;

use sonic_rs::{JsonValueTrait as _, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{params_array, required_str};

pub(crate) fn getblocktemplate(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    if !params.is_null() {
        let request = params_array(params)?.first();
        if let Some(request) = request {
            if let Some(longpollid) = request.get("longpollid").and_then(|value| value.as_str()) {
                let current = ctx.mining_template_id.load();
                if longpollid == current.as_str() {
                    let _result = ctx
                        .mining_notifications
                        .recv_timeout(Duration::from_secs(60));
                }
            }
        }
    }
    let tip_hash = ctx.best_hash().to_string_be();
    let template_id = ctx.mining_template_id.load().to_string();
    Ok(json!({
        "version": 0,
        "rules": ["segwit"],
        "vbavailable": {},
        "vbrequired": 0,
        "previousblockhash": tip_hash,
        "transactions": [],
        "coinbaseaux": {},
        "coinbasevalue": 0,
        "longpollid": template_id,
        "target": "0000000000000000000000000000000000000000000000000000000000000000",
        "mintime": 0,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 0,
        "sizelimit": 4_000_000,
        "weightlimit": 4_000_000,
        "curtime": 0,
        "bits": "00000000",
        "height": ctx.height().saturating_add(1),
        "default_witness_commitment": ""
    }))
}

pub(crate) fn submitblock(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "block hex is required")?;
    Ok(Value::new_null())
}

pub(crate) fn prioritisetransaction(
    _ctx: &Arc<Context>,
    params: &Value,
) -> Result<Value, RpcError> {
    required_str(params, 0, "txid is required")?;
    Ok(json!(true))
}
