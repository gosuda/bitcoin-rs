use alloc::sync::Arc;
use bitcoin::hex::DisplayHex as _;
use core::str::FromStr as _;

use bitcoin_rs_primitives::Hash256;
use sonic_rs::{JsonValueTrait, Value, json};

use crate::context::{BlockRecord, Context};
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str, required_u64};

pub(crate) fn getblockchaininfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let applied = ctx.applied_height();
    let headers = ctx.height();
    Ok(json!({
        "chain": "main",
        "blocks": applied,
        "headers": headers,
        "bestblockhash": ctx.applied_hash().to_string_be(),
        "difficulty": 0,
        "time": 0,
        "mediantime": 0,
        "verificationprogress": 0.0,
        "initialblockdownload": applied < headers,
        "chainwork": ctx.chainwork_hex(),
        "size_on_disk": 0,
        "pruned": false,
        "warnings": ""
    }))
}

pub(crate) fn getblockcount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    Ok(json!(ctx.applied_height()))
}

pub(crate) fn getblockhash(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let height = required_u64(params, 0, "height is required")?;
    let height =
        u32::try_from(height).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?;
    ctx.block_hash_at_height(height)
        .map(|hash| json!(hash.to_string_be()))
        .ok_or(RpcError::NotFound("block height not found"))
}

pub(crate) fn getbestblockhash(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    Ok(json!(ctx.applied_hash().to_string_be()))
}

pub(crate) fn getblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbosity = params_array(params)?
        .get(1)
        .and_then(JsonValueTrait::as_u64)
        .unwrap_or(1);
    let record = ctx
        .block_by_hash(hash)
        .unwrap_or_else(|| BlockRecord::synthetic(ctx.height(), hash));
    if verbosity == 0 {
        return Ok(json!(record.block_hex));
    }
    Ok(json!({
        "hash": record.hash.to_string_be(),
        "confirmations": confirmations(ctx, record.height),
        "height": record.height,
        "version": 0,
        "versionHex": "00000000",
        "merkleroot": Hash256::default().to_string_be(),
        "time": 0,
        "mediantime": 0,
        "nonce": 0,
        "bits": "00000000",
        "difficulty": 0,
        "chainwork": "00",
        "nTx": record.tx_count,
        "previousblockhash": null,
        "nextblockhash": null,
        "strippedsize": 0,
        "size": record.block_hex.len() / 2,
        "weight": 0,
        "tx": []
    }))
}

pub(crate) fn getblockheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbose = optional_bool(params, 1, true)?;
    let record = ctx
        .block_by_hash(hash)
        .unwrap_or_else(|| BlockRecord::synthetic(ctx.height(), hash));
    if !verbose {
        return Ok(json!(record.header_hex));
    }
    Ok(json!({
        "hash": record.hash.to_string_be(),
        "confirmations": confirmations(ctx, record.height),
        "height": record.height,
        "version": 0,
        "versionHex": "00000000",
        "merkleroot": Hash256::default().to_string_be(),
        "time": 0,
        "mediantime": 0,
        "nonce": 0,
        "bits": "00000000",
        "difficulty": 0,
        "chainwork": "00",
        "nTx": record.tx_count,
        "previousblockhash": null,
        "nextblockhash": null
    }))
}

pub(crate) fn getblockstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let target = params_array(params)?
        .first()
        .ok_or(RpcError::InvalidParams("hash_or_height is required"))?;
    let height = if let Some(height) = target.as_u64() {
        u32::try_from(height).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?
    } else if let Some(hash) = target.as_str() {
        parse_hash(hash)?;
        ctx.height()
    } else {
        return Err(RpcError::InvalidType(
            "hash_or_height must be string or number",
        ));
    };
    Ok(json!({
        "avgfee": 0,
        "avgfeerate": 0,
        "avgtxsize": 0,
        "blockhash": ctx.block_hash_at_height(height).unwrap_or_default().to_string_be(),
        "feerate_percentiles": [0, 0, 0, 0, 0],
        "height": height,
        "ins": 0,
        "maxfee": 0,
        "maxfeerate": 0,
        "maxtxsize": 0,
        "medianfee": 0,
        "mediantime": 0,
        "mediantxsize": 0,
        "minfee": 0,
        "minfeerate": 0,
        "mintxsize": 0,
        "outs": 0,
        "subsidy": 0,
        "swtotal_size": 0,
        "swtotal_weight": 0,
        "swtxs": 0,
        "time": 0,
        "total_out": 0,
        "total_size": 0,
        "total_weight": 0,
        "totalfee": 0,
        "txs": 0,
        "utxo_increase": 0,
        "utxo_size_inc": 0
    }))
}

pub(crate) fn gettxoutsetinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let snapshot = ctx.coin_stats.snapshot();
    let muhash_bytes = snapshot.muhash.finalize();
    let mut muhash_hex = String::with_capacity(muhash_bytes.len() * 2);
    for byte in muhash_bytes {
        use core::fmt::Write as _;

        let _: core::fmt::Result = write!(&mut muhash_hex, "{byte:02x}");
    }
    let total_amount_btc = bitcoin::Amount::from_sat(snapshot.total_amount).to_btc();
    Ok(json!({
        "height": ctx.applied_height(),
        "bestblock": ctx.applied_hash().to_string_be(),
        "txouts": ctx.utxo.len(),
        "bogosize": snapshot.bogo_size,
        "hash_serialized_2": muhash_hex,
        "total_amount": total_amount_btc,
        "transactions": ctx.utxo.record_count(),
        "disk_size": 0
    }))
}

pub(crate) fn getblockfilter(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = required_str(params, 0, "block hash is required")?;
    let hash = parse_hash(hash)?;
    let filter_bytes = ctx
        .filter_index
        .filter(hash)
        .map_err(|error| RpcError::Internal(error.to_string()))?
        .unwrap_or_default();
    let header = ctx
        .filter_index
        .filter_header(hash)
        .map_err(|error| RpcError::Internal(error.to_string()))?
        .unwrap_or_default();
    Ok(json!({
        "filter": filter_bytes.to_lower_hex_string(),
        "header": header.to_string_be()
    }))
}

fn parse_hash(value: &str) -> Result<Hash256, RpcError> {
    Hash256::from_str(value).map_err(|_| RpcError::InvalidParams("hash must be 64 hex characters"))
}

fn confirmations(ctx: &Context, height: u32) -> u32 {
    ctx.height().saturating_sub(height).saturating_add(1)
}
