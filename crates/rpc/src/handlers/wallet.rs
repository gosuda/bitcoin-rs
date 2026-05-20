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

pub(crate) fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let action = required_str(params, 0, "action is required")?;
    match action {
        "start" => {
            // Aggregate UTXO-set summary. Descriptor filtering is NOT applied in v1;
            // the descriptor argument is accepted but ignored. A future strand will
            // wire a real descriptor-matched scan.
            // TODO(descriptors): match `params[1]` against `bitcoin::miniscript::Descriptor`
            // and stream only matching outpoints into `unspents`.
            let snapshot = ctx.coin_stats.snapshot();
            let total_amount_btc = bitcoin::Amount::from_sat(snapshot.total_amount).to_btc();
            Ok(json!({
                "success": true,
                "txouts": ctx.utxo.len(),
                "height": ctx.applied_height(),
                "bestblock": ctx.applied_hash().to_string_be(),
                "unspents": [],
                "total_amount": total_amount_btc
            }))
        }
        "abort" => Ok(json!(false)),
        "status" => Ok(Value::new_null()),
        _ => Err(RpcError::InvalidParams(
            "action must be one of: start, abort, status",
        )),
    }
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

#[cfg(test)]
mod tests {
    use sonic_rs::JsonValueTrait as _;

    use super::*;

    #[test]
    fn scantxoutset_start_returns_real_summary_from_utxoset() {
        let ctx = Arc::new(Context::new());
        let result = scantxoutset(&ctx, &json!(["start"]))
            .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        let Some(success) = result.get("success").and_then(Value::as_bool) else {
            panic!("success missing: {result:?}");
        };
        assert!(
            success,
            "scantxoutset start should report success: {result:?}"
        );
        let Some(_height) = result.get("height").and_then(Value::as_u64) else {
            panic!("height missing: {result:?}");
        };
        let Some(txouts) = result.get("txouts").and_then(Value::as_u64) else {
            panic!("txouts missing: {result:?}");
        };
        assert_eq!(txouts, 0, "fresh ctx has empty utxoset");
    }

    #[test]
    fn scantxoutset_abort_returns_false() {
        let ctx = Arc::new(Context::new());
        let result = scantxoutset(&ctx, &json!(["abort"]))
            .unwrap_or_else(|err| panic!("scantxoutset abort failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
    }
}
