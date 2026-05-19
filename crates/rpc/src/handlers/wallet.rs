use alloc::sync::Arc;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::DisplayHex as _;
use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{invalid_psbt, params_array, required_str};

pub(crate) fn getdescriptorinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let checksum =
        sha256::Hash::hash(descriptor.as_bytes()).as_byte_array()[..4].to_lower_hex_string();
    Ok(json!({
        "descriptor": descriptor,
        "checksum": checksum,
        "isrange": descriptor.contains('*'),
        "issolvable": false,
        "hasprivatekeys": false
    }))
}

pub(crate) fn deriveaddresses(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "descriptor is required")?;
    Ok(json!([]))
}

pub(crate) fn scantxoutset(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "action is required")?;
    Ok(json!({
        "success": true,
        "txouts": 0,
        "height": 0,
        "bestblock": bitcoin_rs_primitives::Hash256::default().to_string_be(),
        "unspents": [],
        "total_amount": 0.0
    }))
}

pub(crate) fn walletcreatefundedpsbt(
    _ctx: &Arc<Context>,
    params: &Value,
) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    if array.len() < 2 {
        return Err(RpcError::InvalidParams("inputs and outputs are required"));
    }
    Ok(json!({
        "psbt": "",
        "fee": 0.0,
        "changepos": -1
    }))
}

pub(crate) fn walletprocesspsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "psbt is required")?;
    Ok(invalid_psbt())
}

pub(crate) fn finalizepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "psbt is required")?;
    Ok(json!({"hex": "", "complete": false}))
}

pub(crate) fn combinepsbt(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    if array.is_empty() {
        return Err(RpcError::InvalidParams("psbt array is required"));
    }
    Ok(json!(""))
}

pub(crate) fn bumpfee(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_str(params, 0, "txid is required")?;
    Ok(json!({
        "psbt": "",
        "origfee": 0.0,
        "fee": 0.0,
        "errors": []
    }))
}
