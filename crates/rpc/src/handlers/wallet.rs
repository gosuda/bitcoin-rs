use alloc::sync::Arc;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::DisplayHex as _;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

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
    let array = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("psbts must be an array"))?;
    if array.is_empty() {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    }

    let mut iter = array.iter();
    let Some(first_val) = iter.next() else {
        return Err(RpcError::InvalidParams("psbts array must not be empty"));
    };
    let Some(first_str) = first_val.as_str() else {
        return Err(RpcError::InvalidType("each psbt must be a string"));
    };
    let mut psbt = bitcoin::psbt::Psbt::deserialize(&decode_base64(first_str)?)
        .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;

    for value in iter {
        let Some(s) = value.as_str() else {
            return Err(RpcError::InvalidType("each psbt must be a string"));
        };
        let other = bitcoin::psbt::Psbt::deserialize(&decode_base64(s)?)
            .map_err(|_| RpcError::InvalidParams("invalid base64 PSBT"))?;
        psbt.combine(other)
            .map_err(|err| RpcError::Internal(format!("combine failed: {err}")))?;
    }

    Ok(json!(encode_base64(&psbt.serialize())))
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_base64(input: &str) -> Result<Vec<u8>, RpcError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(RpcError::InvalidParams("invalid base64 PSBT"));
    }

    let chunk_count = bytes.len() / 4;
    let mut out = Vec::with_capacity(chunk_count * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == chunk_count;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if chunk[0] == b'=' || chunk[1] == b'=' || pad2 && !pad3 || pad3 && !last {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        }

        let Some(a) = base64_value(chunk[0]) else {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        };
        let Some(b) = base64_value(chunk[1]) else {
            return Err(RpcError::InvalidParams("invalid base64 PSBT"));
        };
        let c = if pad2 {
            0
        } else {
            let Some(value) = base64_value(chunk[2]) else {
                return Err(RpcError::InvalidParams("invalid base64 PSBT"));
            };
            value
        };
        let d = if pad3 {
            0
        } else {
            let Some(value) = base64_value(chunk[3]) else {
                return Err(RpcError::InvalidParams("invalid base64 PSBT"));
            };
            value
        };

        out.push((a << 2) | (b >> 4));
        if !pad2 {
            out.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            out.push((c << 6) | d);
        }
    }

    Ok(out)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(char::from(BASE64_ALPHABET[usize::from(b0 >> 2)]));
        out.push(char::from(
            BASE64_ALPHABET[usize::from(((b0 & 0b0000_0011) << 4) | (b1 >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64_ALPHABET[usize::from(((b1 & 0b0000_1111) << 2) | (b2 >> 6))],
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(BASE64_ALPHABET[usize::from(b2 & 0b0011_1111)]));
        } else {
            out.push('=');
        }
    }
    out
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

#[cfg(test)]
mod combinepsbt_tests {
    use alloc::sync::Arc;

    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn empty_psbt_str() -> String {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
            .unwrap_or_else(|err| panic!("from_unsigned_tx: {err}"));
        encode_base64(&psbt.serialize())
    }

    #[test]
    fn combinepsbt_single_input_returns_same_psbt() {
        let ctx = Arc::new(Context::new());
        let psbt_str = empty_psbt_str();
        let result = combinepsbt(&ctx, &json!([[psbt_str.as_str()]]))
            .unwrap_or_else(|err| panic!("combinepsbt: {err}"));
        let Some(out) = result.as_str() else {
            panic!("expected string: {result:?}");
        };
        assert_eq!(out, psbt_str);
    }

    #[test]
    fn combinepsbt_empty_array_errors() {
        let ctx = Arc::new(Context::new());
        let result = combinepsbt(&ctx, &json!([[]]));
        assert!(result.is_err());
    }
}
