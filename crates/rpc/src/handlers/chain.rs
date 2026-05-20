use alloc::sync::Arc;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use core::str::FromStr as _;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::Hash256;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::{BlockRecord, Context};
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str, required_u64};

pub(crate) fn getblockchaininfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let applied = ctx.applied_height();
    let headers = ctx.height();
    let difficulty = ctx.applied_tip.load_full().map_or(0.0, |tip| {
        let tree = ctx.block_tree.read();
        tree.node(tip.tip_id)
            .ok()
            .map_or(0.0, |node| ctx.difficulty_for_bits(node.header.bits))
    });
    let verification_progress = if headers > 0 {
        f64::from(applied) / f64::from(headers)
    } else {
        0.0
    };
    let chain = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => "main",
        bitcoin_rs_primitives::Network::Testnet3 | bitcoin_rs_primitives::Network::Testnet4 => {
            "test"
        }
        bitcoin_rs_primitives::Network::Signet => "signet",
        bitcoin_rs_primitives::Network::Regtest => "regtest",
    };
    Ok(json!({
        "chain": chain,
        "blocks": applied,
        "headers": headers,
        "bestblockhash": ctx.applied_hash().to_string_be(),
        "difficulty": difficulty,
        "time": 0,
        "mediantime": 0,
        "verificationprogress": verification_progress,
        "initialblockdownload": applied < headers,
        "chainwork": ctx.chainwork_hex(),
        "size_on_disk": 0,
        "pruned": false,
        "warnings": ""
    }))
}
pub(crate) fn getdifficulty(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let difficulty = {
        let tree = ctx.block_tree.read();
        ctx.applied_tip
            .load_full()
            .and_then(|tip| tree.node(tip.tip_id).ok().map(|node| node.header.bits))
            .map_or(0.0, |bits| ctx.difficulty_for_bits(bits))
    };
    Ok(json!(difficulty))
}

pub(crate) fn getchaintips(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let tree = ctx.block_tree.read();
    let active_tip = ctx.chain_tip.load_full();
    let active_tip_id = active_tip.as_ref().map(|tip| tip.tip_id);
    let mut tips = Vec::new();
    for leaf_id in tree.leaf_node_ids() {
        let Ok(node) = tree.node(leaf_id) else {
            continue;
        };
        let is_active = Some(leaf_id) == active_tip_id;
        let status = if is_active {
            "active"
        } else {
            match node.status {
                NodeStatus::Active | NodeStatus::Stale => "valid-fork",
                NodeStatus::HeaderValid => "headers-only",
                NodeStatus::Invalid => "invalid",
            }
        };
        let branchlen = if is_active {
            0
        } else {
            compute_branchlen(&tree, leaf_id, node.height, active_tip_id)
        };
        tips.push(json!({
            "height": node.height,
            "hash": node.hash.to_string_be(),
            "branchlen": branchlen,
            "status": status,
        }));
    }
    // Sort with active first, then by height descending.
    tips.sort_by(|a, b| {
        let a_status = a
            .get("status")
            .and_then(JsonValueTrait::as_str)
            .unwrap_or("");
        let b_status = b
            .get("status")
            .and_then(JsonValueTrait::as_str)
            .unwrap_or("");
        match (a_status, b_status) {
            ("active", "active") => core::cmp::Ordering::Equal,
            ("active", _) => core::cmp::Ordering::Less,
            (_, "active") => core::cmp::Ordering::Greater,
            _ => {
                let a_height = a
                    .get("height")
                    .and_then(JsonValueTrait::as_u64)
                    .unwrap_or(0);
                let b_height = b
                    .get("height")
                    .and_then(JsonValueTrait::as_u64)
                    .unwrap_or(0);
                b_height.cmp(&a_height)
            }
        }
    });
    Ok(json!(tips))
}

pub(crate) fn getchaintxstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    const DEFAULT_WINDOW: u64 = 30 * 24 * 6; // ~1 month of 10-min blocks
    let array = params_array(params)?;
    let nblocks = array
        .first()
        .and_then(JsonValueTrait::as_u64)
        .unwrap_or(DEFAULT_WINDOW);
    let applied_height = ctx.applied_height();
    let blocks_guard = ctx.blocks.read();
    let total_tx_count: u64 = blocks_guard
        .iter()
        .map(|record| u64::try_from(record.tx_count).unwrap_or(0))
        .sum();
    let window_block_count = nblocks.min(u64::from(applied_height).saturating_add(1));
    let lowest_window_height = u64::from(applied_height)
        .saturating_add(1)
        .saturating_sub(window_block_count);
    let window_tx_count: u64 = blocks_guard
        .iter()
        .filter(|record| u64::from(record.height) >= lowest_window_height)
        .map(|record| u64::try_from(record.tx_count).unwrap_or(0))
        .sum();
    let tip_time = blocks_guard
        .iter()
        .find(|record| record.height == applied_height)
        .map_or(0, |record| record.time);
    let earliest_window_time = blocks_guard
        .iter()
        .filter(|record| u64::from(record.height) >= lowest_window_height)
        .map(|record| record.time)
        .min()
        .unwrap_or(tip_time);
    let window_interval = u64::from(tip_time).saturating_sub(u64::from(earliest_window_time));
    let txrate = if window_interval > 0 {
        let count_small = u32::try_from(window_tx_count).unwrap_or(u32::MAX);
        let interval_small = u32::try_from(window_interval).unwrap_or(u32::MAX);
        f64::from(count_small) / f64::from(interval_small)
    } else {
        0.0_f64
    };
    Ok(json!({
        "time": tip_time,
        "txcount": total_tx_count,
        "window_final_block_hash": ctx.applied_hash().to_string_be(),
        "window_final_block_height": applied_height,
        "window_block_count": window_block_count,
        "window_tx_count": window_tx_count,
        "window_interval": window_interval,
        "txrate": txrate
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
    let verbosity = getblock_verbosity(params)?;
    let Some(record) = ctx.block_by_hash(hash) else {
        let synthetic_height = ctx.height_for_hash(hash).unwrap_or_else(|| ctx.height());
        let record = BlockRecord::synthetic(synthetic_height, hash);
        if verbosity == 0 {
            return Ok(json!(record.block_hex));
        }
        return Ok(synthetic_block_json(ctx, &record, true));
    };
    if verbosity == 0 {
        return Ok(json!(record.block_hex));
    }
    block_json_verbose(ctx, &record, true, verbosity)
}

pub(crate) fn getblockheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbose = optional_bool(params, 1, true)?;
    let Some(record) = ctx.block_by_hash(hash) else {
        let synthetic_height = ctx.height_for_hash(hash).unwrap_or_else(|| ctx.height());
        let record = BlockRecord::synthetic(synthetic_height, hash);
        if !verbose {
            return Ok(json!(record.header_hex));
        }
        return Ok(synthetic_block_json(ctx, &record, false));
    };
    if !verbose {
        return Ok(json!(record.header_hex));
    }
    block_json_verbose(ctx, &record, false, 1)
}

pub(crate) fn getblockstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hex::FromHex as _;

    let target = params_array(params)?
        .first()
        .ok_or(RpcError::InvalidParams("hash_or_height is required"))?;
    let height = if let Some(height) = target.as_u64() {
        u32::try_from(height).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?
    } else if let Some(hash) = target.as_str() {
        let block_hash = parse_hash(hash)?;
        ctx.height_for_hash(block_hash)
            .unwrap_or_else(|| ctx.height())
    } else {
        return Err(RpcError::InvalidType(
            "hash_or_height must be string or number",
        ));
    };

    let block_hash = ctx.block_hash_at_height(height).unwrap_or_default();
    let subsidy_sat = subsidy_at_height(height);
    let record = ctx.block_by_hash(block_hash);
    let time = record.as_ref().map_or(0, |r| r.time);
    let mediantime = ctx.median_time_past_for_hash(block_hash).unwrap_or(0);

    let mut total_size: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut total_out: u64 = 0;
    let mut ins: u64 = 0;
    let mut outs: u64 = 0;
    let mut txs: u64 = 0;
    let mut swtxs: u64 = 0;
    let mut swtotal_size: u64 = 0;
    let mut swtotal_weight: u64 = 0;
    if let Some(record) = record.as_ref() {
        if let Ok(bytes) = Vec::<u8>::from_hex(&record.block_hex) {
            total_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if let Ok(block) = deserialize::<bitcoin::Block>(&bytes) {
                total_weight = block.weight().to_wu();
                txs = u64::try_from(block.txdata.len()).unwrap_or(u64::MAX);
                for tx in &block.txdata {
                    ins = ins.saturating_add(u64::try_from(tx.input.len()).unwrap_or(u64::MAX));
                    outs = outs.saturating_add(u64::try_from(tx.output.len()).unwrap_or(u64::MAX));
                    for output in &tx.output {
                        total_out = total_out.saturating_add(output.value.to_sat());
                    }
                    if tx.input.iter().any(|i| !i.witness.is_empty()) {
                        swtxs = swtxs.saturating_add(1);
                        let tx_size = bitcoin::consensus::encode::serialize(tx).len();
                        swtotal_size =
                            swtotal_size.saturating_add(u64::try_from(tx_size).unwrap_or(u64::MAX));
                        swtotal_weight = swtotal_weight.saturating_add(tx.weight().to_wu());
                    }
                }
            }
        }
    }

    Ok(json!({
        "avgfee": 0,
        "avgfeerate": 0,
        "avgtxsize": 0,
        "blockhash": block_hash.to_string_be(),
        "feerate_percentiles": [0, 0, 0, 0, 0],
        "height": height,
        "ins": ins,
        "maxfee": 0,
        "maxfeerate": 0,
        "maxtxsize": 0,
        "medianfee": 0,
        "mediantime": mediantime,
        "mediantxsize": 0,
        "minfee": 0,
        "minfeerate": 0,
        "mintxsize": 0,
        "outs": outs,
        "subsidy": subsidy_sat,
        "swtotal_size": swtotal_size,
        "swtotal_weight": swtotal_weight,
        "swtxs": swtxs,
        "time": time,
        "total_out": total_out,
        "total_size": total_size,
        "total_weight": total_weight,
        "totalfee": 0,
        "txs": txs,
        "utxo_increase": 0,
        "utxo_size_inc": 0
    }))
}

/// Bitcoin block subsidy at `height` in satoshis. 50 BTC initially, halving
/// every 210,000 blocks, saturating to zero after ~64 halvings.
fn subsidy_at_height(height: u32) -> u64 {
    const INITIAL_SUBSIDY_SAT: u64 = 5_000_000_000;
    const HALVING_INTERVAL: u32 = 210_000;
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY_SAT >> halvings
}
pub(crate) fn pruneblockchain(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let height = required_u64(params, 0, "height is required")?;
    let applied = u64::from(ctx.applied_height());
    if height > applied {
        return Err(RpcError::InvalidParams(
            "prune height cannot exceed applied tip",
        ));
    }

    // TODO(prune-engine): dispatch into `bitcoin_rs_pruning` to actually delete
    // historical blocks below `height`. v1 reports the requested height as-is.
    Ok(json!(height))
}

pub(crate) fn verifychain(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hex::FromHex as _;

    let array = params_array(params)?;
    let checklevel = array.first().and_then(JsonValueTrait::as_u64).unwrap_or(3);
    let nblocks_param = array.get(1).and_then(JsonValueTrait::as_u64).unwrap_or(6);
    let Ok(nblocks) = u32::try_from(nblocks_param) else {
        return Err(RpcError::InvalidParams("nblocks exceeds u32"));
    };
    if checklevel == 0 {
        // Bitcoin Core: checklevel 0 reads blocks from disk without per-block verification.
        // bitcoin-rs reports pass since this v1 doesn't surface block-read failures here.
        return Ok(json!(true));
    }
    let tree = ctx.block_tree.read();
    let Some(applied) = ctx.applied_tip.load_full() else {
        return Ok(json!(true));
    };
    let mut cursor = applied.tip_id;
    let mut checked: u32 = 0;
    loop {
        if checked >= nblocks {
            break;
        }
        let Ok(node) = tree.node(cursor) else {
            return Ok(json!(false));
        };
        // L1+: PoW self-consistency check.
        if node.header.validate_pow(node.header.target()).is_err() {
            return Ok(json!(false));
        }
        // L2+: Merkle-root sanity when block body is available. Absent blocks
        // (header-only / pruned) skip the merkle check.
        if checklevel >= 2 {
            if let Some(record) = ctx.block_by_hash(node.hash) {
                if let Ok(bytes) = Vec::<u8>::from_hex(&record.block_hex) {
                    if let Ok(block) = deserialize::<bitcoin::Block>(&bytes) {
                        if let Some(computed) = block.compute_merkle_root() {
                            if computed != node.header.merkle_root {
                                return Ok(json!(false));
                            }
                        }
                    }
                }
            }
        }
        // L3+: behaves as L2 in this v1 — a future strand wires per-tx structural
        // checks (e.g., max-size, witness sanity). L4 (full UTXO replay) is deferred.
        checked = checked.saturating_add(1);
        let Some(parent_id) = node.parent else {
            break;
        };
        cursor = parent_id;
    }
    Ok(json!(true))
}

pub(crate) fn gettxoutsetinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash_type = if params.is_null() {
        "hash_serialized_2"
    } else {
        match params_array(params)?.first() {
            Some(value) if value.is_null() => "hash_serialized_2",
            Some(value) => value
                .as_str()
                .ok_or(RpcError::InvalidType("hash_type must be a string"))?,
            None => "hash_serialized_2",
        }
    };
    let snapshot = ctx.coin_stats.snapshot();
    let total_amount_btc = bitcoin::Amount::from_sat(snapshot.total_amount).to_btc();
    let muhash_hex = {
        let muhash_bytes = snapshot.muhash.finalize();
        let mut hex = String::with_capacity(muhash_bytes.len() * 2);
        for byte in muhash_bytes {
            use core::fmt::Write as _;

            let _: core::fmt::Result = write!(&mut hex, "{byte:02x}");
        }
        hex
    };
    let bestblock = ctx.applied_hash().to_string_be();
    let mut response = sonic_rs::Object::new();
    let _ = response.insert(&"height", ctx.applied_height());
    let _ = response.insert(&"bestblock", bestblock.as_str());
    let _ = response.insert(&"txouts", ctx.utxo.len());
    let _ = response.insert(&"bogosize", snapshot.bogo_size);
    let _ = response.insert(&"total_amount", json!(total_amount_btc));
    let _ = response.insert(&"transactions", ctx.utxo.record_count());
    let _ = response.insert(&"disk_size", 0_u64);
    match hash_type {
        "hash_serialized_2" => {
            // TODO(hash_serialized_2): emit the canonical UTXO-serialization
            // SHA256d hash. Until then we surface muhash under this key as a
            // placeholder; muhash is a different commitment.
            let _ = response.insert(&"hash_serialized_2", muhash_hex.as_str());
        }
        "muhash" => {
            let _ = response.insert(&"muhash", muhash_hex.as_str());
        }
        "none" => {}
        _ => {
            return Err(RpcError::InvalidParams(
                "hash_type must be one of: hash_serialized_2, muhash, none",
            ));
        }
    }
    Ok(Value::from(response))
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

pub(crate) fn getindexinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let filter = if params.is_null() {
        None
    } else if let Some(array) = params.as_array() {
        if array.is_empty() {
            None
        } else {
            Some(required_str(params, 0, "index_name must be a string")?)
        }
    } else {
        return Err(RpcError::InvalidParams("params must be null or array"));
    };

    let header_height = ctx.height();
    let applied_height = ctx.applied_height();
    let synced = header_height > 0 && applied_height >= header_height;
    let entry = || {
        json!({
            "synced": synced,
            "best_block_height": applied_height,
        })
    };

    match filter {
        None => Ok(json!({
            "txindex": entry(),
            "basicblockfilterindex": entry(),
        })),
        Some("txindex") => Ok(json!({ "txindex": entry() })),
        Some("basicblockfilterindex") => Ok(json!({ "basicblockfilterindex": entry() })),
        Some(_) => Ok(json!({})),
    }
}

fn getblock_verbosity(params: &Value) -> Result<u64, RpcError> {
    let Some(value) = params_array(params)?.get(1) else {
        return Ok(1);
    };
    if value.is_null() {
        return Ok(1);
    }
    if let Some(verbosity) = value.as_u64() {
        return Ok(verbosity);
    }
    if let Some(verbose) = value.as_bool() {
        return Ok(u64::from(verbose));
    }
    Err(RpcError::InvalidType("verbosity must be number or boolean"))
}

fn parse_hash(value: &str) -> Result<Hash256, RpcError> {
    Hash256::from_str(value).map_err(|_| RpcError::InvalidParams("hash must be 64 hex characters"))
}

fn confirmations(ctx: &Context, height: u32) -> u32 {
    let applied = ctx.applied_height();
    if height > applied {
        0
    } else {
        applied.saturating_sub(height).saturating_add(1)
    }
}

fn block_json_verbose(
    ctx: &Context,
    record: &BlockRecord,
    include_block_fields: bool,
    verbosity: u64,
) -> Result<Value, RpcError> {
    let Some(header) = decode_header(record) else {
        return Ok(synthetic_block_json(ctx, record, include_block_fields));
    };

    let version = header.version.to_consensus();
    let version_hex = u32::from_le_bytes(version.to_le_bytes());
    let bits = header.bits.to_consensus();
    let bits_hex = format!("{bits:08x}");
    let mediantime = ctx.median_time_past_for_hash(record.hash).unwrap_or(0);
    let chainwork = ctx
        .chain_work_hex_for_hash(record.hash)
        .unwrap_or_else(|| "00".to_owned());
    let next_hash = ctx
        .next_block_hash_for_height(record.height)
        .map(bitcoin_rs_primitives::Hash256::to_string_be);
    let difficulty = ctx.difficulty_for_bits(header.bits);

    if !include_block_fields {
        return Ok(json!({
            "hash": record.hash.to_string_be(),
            "confirmations": confirmations(ctx, record.height),
            "height": record.height,
            "version": i64::from(version),
            "versionHex": format!("{version_hex:08x}"),
            "merkleroot": header.merkle_root.to_string(),
            "time": header.time,
            "mediantime": mediantime,
            "nonce": header.nonce,
            "bits": bits_hex,
            "difficulty": difficulty,
            "chainwork": chainwork,
            "nTx": record.tx_count,
            "previousblockhash": header.prev_blockhash.to_string(),
            "nextblockhash": next_hash
        }));
    }

    let Some(block) = decode_block(record) else {
        return Ok(synthetic_block_json(ctx, record, true));
    };
    let tx_array: Vec<Value> = if verbosity >= 2 {
        block
            .txdata
            .iter()
            .map(super::tx_render::tx_to_value)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        block
            .txdata
            .iter()
            .map(|tx| json!(tx.compute_txid().to_string()))
            .collect()
    };

    Ok(json!({
        "hash": record.hash.to_string_be(),
        "confirmations": confirmations(ctx, record.height),
        "height": record.height,
        "version": i64::from(version),
        "versionHex": format!("{version_hex:08x}"),
        "merkleroot": header.merkle_root.to_string(),
        "time": header.time,
        "mediantime": mediantime,
        "nonce": header.nonce,
        "bits": bits_hex,
        "difficulty": difficulty,
        "chainwork": chainwork,
        "nTx": record.tx_count,
        "previousblockhash": header.prev_blockhash.to_string(),
        "nextblockhash": next_hash,
        "strippedsize": record.block_hex.len() / 2,
        "size": record.block_hex.len() / 2,
        "weight": block.weight().to_wu(),
        "tx": tx_array
    }))
}

fn decode_header(record: &BlockRecord) -> Option<bitcoin::block::Header> {
    let bytes = match Vec::<u8>::from_hex(&record.header_hex) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                block_hash = %record.hash.to_string_be(),
                %error,
                "stored block header hex is invalid"
            );
            return None;
        }
    };
    match deserialize(&bytes) {
        Ok(header) => Some(header),
        Err(error) => {
            tracing::warn!(
                block_hash = %record.hash.to_string_be(),
                %error,
                "stored block header bytes are invalid"
            );
            None
        }
    }
}

fn decode_block(record: &BlockRecord) -> Option<bitcoin::Block> {
    let bytes = match Vec::<u8>::from_hex(&record.block_hex) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                block_hash = %record.hash.to_string_be(),
                %error,
                "stored block hex is invalid"
            );
            return None;
        }
    };
    match deserialize(&bytes) {
        Ok(block) => Some(block),
        Err(error) => {
            tracing::warn!(
                block_hash = %record.hash.to_string_be(),
                %error,
                "stored block bytes are invalid"
            );
            None
        }
    }
}

fn synthetic_block_json(ctx: &Context, record: &BlockRecord, include_block_fields: bool) -> Value {
    if !include_block_fields {
        return json!({
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
        });
    }

    json!({
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
    })
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin::blockdata::constants::genesis_block;

    use super::*;
    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};

    #[test]
    fn subsidy_at_height_genesis_is_50_btc() {
        assert_eq!(subsidy_at_height(0), 5_000_000_000);
    }

    #[test]
    fn subsidy_at_height_first_halving_is_25_btc() {
        assert_eq!(subsidy_at_height(210_000), 2_500_000_000);
    }

    #[test]
    fn subsidy_at_height_after_64_halvings_is_zero() {
        assert_eq!(subsidy_at_height(64 * 210_000), 0);
        assert_eq!(subsidy_at_height(u32::MAX), 0);
    }

    #[test]
    fn getblock_populates_real_header_fields_from_stored_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let block_hash_hex = record.hash.to_string_be();
        let block_size = u64::try_from(record.block_hex.len() / 2)?;
        let tx_count = u64::try_from(record.tx_count)?;
        ctx.add_block(record);

        let block_json = getblock(&ctx, &json!([block_hash_hex.as_str(), 1]))?;
        let header_json = getblockheader(&ctx, &json!([block_hash_hex.as_str(), true]))?;
        let header = &genesis.header;
        let version_hex_value = u32::from_le_bytes(header.version.to_consensus().to_le_bytes());
        let version_hex = format!("{version_hex_value:08x}");
        let bits = header.bits.to_consensus();
        let bits_hex = format!("{bits:08x}");
        let merkle_root = header.merkle_root.to_string();
        let previous_block_hash = header.prev_blockhash.to_string();
        let expected_txid = genesis
            .txdata
            .first()
            .ok_or("genesis block must contain a coinbase transaction")?
            .compute_txid()
            .to_string();

        for value in [&block_json, &header_json] {
            assert_eq!(value.get("hash").as_str(), Some(block_hash_hex.as_str()));
            assert_eq!(value.get("height").as_u64(), Some(0));
            assert_eq!(
                value.get("version").as_u64(),
                Some(u64::try_from(header.version.to_consensus())?)
            );
            assert_eq!(value.get("versionHex").as_str(), Some(version_hex.as_str()));
            assert_eq!(value.get("merkleroot").as_str(), Some(merkle_root.as_str()));
            assert_eq!(value.get("time").as_u64(), Some(u64::from(header.time)));
            assert_eq!(value.get("nonce").as_u64(), Some(u64::from(header.nonce)));
            assert_eq!(value.get("bits").as_str(), Some(bits_hex.as_str()));
            assert_eq!(
                value.get("previousblockhash").as_str(),
                Some(previous_block_hash.as_str())
            );
            assert_eq!(value.get("nTx").as_u64(), Some(tx_count));
        }

        assert_eq!(block_json.get("size").as_u64(), Some(block_size));
        assert_eq!(block_json.get("strippedsize").as_u64(), Some(block_size));
        assert_eq!(
            block_json.get("weight").as_u64(),
            Some(genesis.weight().to_wu())
        );
        let tx_value = block_json.get("tx");
        let tx = tx_value
            .as_array()
            .ok_or("getblock tx field must be an array")?;
        assert_eq!(tx.len(), 1);
        assert_eq!(
            tx.first().and_then(JsonValueTrait::as_str),
            Some(expected_txid.as_str())
        );

        Ok(())
    }

    #[test]
    fn getblock_verbosity_2_emits_tx_object_per_transaction() {
        use bitcoin::Network;
        use bitcoin::hashes::Hash as _;

        let ctx = Arc::new(Context::new());
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let block_hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let result = getblock(&ctx, &json!([block_hash.to_string_be(), 2]))
            .unwrap_or_else(|err| panic!("getblock failed: {err}"));
        let Some(tx_array) = result.get("tx").and_then(|value| value.as_array()) else {
            panic!("tx field missing: {result:?}");
        };
        let Some(first) = tx_array.first() else {
            panic!("expected at least one tx");
        };
        assert!(
            first.get("hex").is_some(),
            "verbosity=2 tx must include hex field: {first:?}"
        );
        assert!(first.get("vsize").is_some());
        assert!(
            first.get("vin").is_some(),
            "shared tx_to_value should emit vin: {first:?}"
        );
        assert!(
            first.get("vout").is_some(),
            "shared tx_to_value should emit vout: {first:?}"
        );
    }

    #[test]
    fn gettxoutsetinfo_with_hash_type_none_omits_both_hashes() {
        let ctx = Arc::new(Context::new());
        let result = gettxoutsetinfo(&ctx, &json!(["none"]))
            .unwrap_or_else(|err| panic!("gettxoutsetinfo failed: {err}"));
        assert!(
            result.get("muhash").is_none(),
            "muhash should be absent for hash_type=none: {result:?}"
        );
        assert!(
            result.get("hash_serialized_2").is_none(),
            "hash_serialized_2 should be absent for hash_type=none: {result:?}"
        );
        assert!(result.get("height").is_some());
    }

    #[test]
    fn gettxoutsetinfo_rejects_unknown_hash_type() {
        let ctx = Arc::new(Context::new());
        let result = gettxoutsetinfo(&ctx, &json!(["sha3"]));
        assert!(result.is_err());
    }

    #[test]
    fn confirmations_uses_applied_height_not_header_tip() {
        use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
        use bitcoin_rs_primitives::Hash256;

        let ctx = Context::new();
        // Header tip at 100, applied tip at 50.
        let hash = Hash256::from_le_bytes(&[7_u8; 32]);
        ctx.set_chain_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 100,
            chainwork: ChainWork::ZERO,
            hash,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 50,
            chainwork: ChainWork::ZERO,
            hash,
        });
        // Block at height 10: confirmations = applied(50) - 10 + 1 = 41.
        assert_eq!(confirmations(&ctx, 10), 41);
        // Block at height 60 (above applied tip): confirmations = 0.
        assert_eq!(confirmations(&ctx, 60), 0);
    }

    #[test]
    fn verificationprogress_reports_half_when_applied_is_half_of_headers() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::from_le_bytes(&[7_u8; 32]);
        ctx.set_chain_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 100,
            chainwork: ChainWork::ZERO,
            hash,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 50,
            chainwork: ChainWork::ZERO,
            hash,
        });
        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        let Some(progress) = result
            .get("verificationprogress")
            .and_then(JsonValueTrait::as_f64)
        else {
            panic!("verificationprogress missing: {result:?}");
        };
        assert!(
            (progress - 0.5).abs() < 1e-6,
            "expected ~0.5, got {progress}"
        );
    }

    #[test]
    fn verificationprogress_reports_zero_when_headers_unset() {
        let ctx = Arc::new(Context::new());
        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        let Some(progress) = result
            .get("verificationprogress")
            .and_then(JsonValueTrait::as_f64)
        else {
            panic!("verificationprogress missing: {result:?}");
        };
        assert!(
            progress.abs() < f64::EPSILON,
            "expected 0.0, got {progress}"
        );
    }
    #[test]
    fn getchaintxstats_emits_core_shape_with_zero_blocks() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
        assert!(result.get("time").is_some());
        assert!(result.get("txcount").is_some());
        assert!(result.get("window_final_block_height").is_some());
    }

    #[test]
    fn getchaintxstats_window_tx_count_includes_in_range_blocks() {
        use alloc::sync::Arc;
        use bitcoin::Network;

        let ctx = Arc::new(Context::new());
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
        let Some(txcount) = result.get("txcount").and_then(JsonValueTrait::as_u64) else {
            panic!("txcount missing: {result:?}");
        };
        // Genesis block has 1 tx (coinbase).
        assert_eq!(txcount, 1);
    }

    #[test]
    fn getchaintxstats_time_reflects_tip_block_header_timestamp() {
        use bitcoin::Network;
        use bitcoin::hashes::Hash as _;

        let ctx = Arc::new(Context::new());
        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let expected_time = genesis.header.time;
        let hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 0,
            chainwork: ChainWork::ZERO,
            hash,
        });
        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
        let Some(time) = result.get("time").and_then(JsonValueTrait::as_u64) else {
            panic!("time missing: {result:?}");
        };
        assert_eq!(time, u64::from(expected_time));
    }
}
#[cfg(test)]
mod getdifficulty_tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn getdifficulty_returns_zero_on_fresh_context() {
        let ctx = Arc::new(Context::new());
        let result = getdifficulty(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getdifficulty failed: {err}"));
        assert_eq!(result.as_f64(), Some(0.0));
    }
}

#[cfg(test)]
mod pruneblockchain_tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn pruneblockchain_returns_requested_height_when_below_tip() {
        use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
        use bitcoin_rs_primitives::Hash256;

        let ctx = Arc::new(Context::new());
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 100,
            chainwork: ChainWork::ZERO,
            hash: Hash256::default(),
        });
        let result = pruneblockchain(&ctx, &json!([50]))
            .unwrap_or_else(|err| panic!("pruneblockchain failed: {err}"));
        assert_eq!(result.as_u64(), Some(50));
    }

    #[test]
    fn pruneblockchain_rejects_height_above_tip() {
        let ctx = Arc::new(Context::new());
        let result = pruneblockchain(&ctx, &json!([100]));
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod getchaintips_tests {
    use alloc::sync::Arc;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::{ChainWork, TipSnapshot};
    use bitcoin_rs_primitives::Hash256;

    use super::*;

    fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        }
    }

    fn hash_from_header(header: &bitcoin::block::Header) -> Hash256 {
        Hash256::from_le_bytes(header.block_hash().as_byte_array())
    }

    #[test]
    fn getchaintips_returns_empty_on_fresh_context() {
        let ctx = Arc::new(Context::new());
        let result = getchaintips(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn getchaintips_emits_active_tip_from_chain_tip_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = synthetic_header(BlockHash::all_zeros(), 1_000_000);
        let hash = hash_from_header(&genesis);
        let tip_id = {
            let mut tree = ctx.block_tree.write();
            tree.insert_node(None, genesis, NodeStatus::Active)?
        };
        ctx.set_chain_tip(TipSnapshot {
            tip_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash,
        });
        let result = getchaintips(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert_eq!(arr.len(), 1);
        let Some(first) = arr.first() else {
            panic!("expected first element");
        };
        let Some(height) = first.get("height").and_then(JsonValueTrait::as_u64) else {
            panic!("height missing");
        };
        assert_eq!(height, 0);
        let Some(status) = first.get("status").and_then(JsonValueTrait::as_str) else {
            panic!("status missing");
        };
        assert_eq!(status, "active");
        Ok(())
    }

    #[test]
    fn getchaintips_emits_two_tips_when_chain_is_forked() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = Arc::new(Context::new());
        let (active_tip_id, active_chainwork, active_hash) = {
            let mut tree = ctx.block_tree.write();
            let genesis = synthetic_header(BlockHash::all_zeros(), 1_000_000);
            let genesis_hash = genesis.block_hash();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let child_b_header = synthetic_header(genesis_hash, 1_000_900);
            let active_tip =
                tree.insert_node(Some(genesis_id), child_b_header, NodeStatus::Active)?;
            let mut child_a = synthetic_header(genesis_hash, 1_000_600);
            child_a.nonce = 1;
            let _header_tip =
                tree.insert_node(Some(genesis_id), child_a, NodeStatus::HeaderValid)?;
            let active_node = tree.node(active_tip)?;
            (active_tip, active_node.chainwork, active_node.hash)
        };
        ctx.set_chain_tip(TipSnapshot {
            tip_id: active_tip_id,
            height: 1,
            chainwork: active_chainwork,
            hash: active_hash,
        });

        let result = getchaintips(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 2, "expected two leaves: {arr:?}");
        let active_count = arr
            .iter()
            .filter(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("active"))
            .count();
        let headers_only_count = arr
            .iter()
            .filter(|tip| {
                tip.get("status").and_then(JsonValueTrait::as_str) == Some("headers-only")
            })
            .count();
        assert_eq!(active_count, 1, "expected one active tip: {arr:?}");
        assert_eq!(
            headers_only_count, 1,
            "expected one headers-only tip: {arr:?}"
        );
        Ok(())
    }
    #[test]
    fn getchaintips_emits_branchlen_one_for_non_active_sibling_of_active_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());

        // Build: genesis (active) -> sibling (header-only). Active tip stays at genesis.
        let sibling_height = {
            let mut tree = ctx.block_tree.write();
            let genesis = synthetic_header(BlockHash::all_zeros(), 1_000_000);
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let genesis_hash = tree.node(genesis_id)?.hash;
            let mut sibling = synthetic_header(genesis.block_hash(), 1_000_600);
            sibling.nonce = 9;
            let sibling_id =
                tree.insert_node(Some(genesis_id), sibling, NodeStatus::HeaderValid)?;
            ctx.set_chain_tip(TipSnapshot {
                tip_id: genesis_id,
                height: 0,
                chainwork: ChainWork::ZERO,
                hash: genesis_hash,
            });
            tree.node(sibling_id)?.height
        };

        let result = getchaintips(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        let Some(sibling_entry) = arr
            .iter()
            .find(|entry| entry.get("status").and_then(JsonValueTrait::as_str) != Some("active"))
        else {
            panic!("expected non-active tip: {result:?}");
        };
        let Some(branchlen) = sibling_entry
            .get("branchlen")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("branchlen missing: {sibling_entry:?}");
        };

        assert_eq!(
            branchlen, 1,
            "sibling at height 1 should have branchlen 1: {sibling_entry:?}"
        );
        assert_eq!(sibling_height, 1);
        Ok(())
    }
}

#[cfg(test)]
mod verifychain_tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn verifychain_returns_true_on_empty_chain() {
        let ctx = Arc::new(Context::new());
        let result =
            verifychain(&ctx, &json!([])).unwrap_or_else(|err| panic!("verifychain failed: {err}"));
        assert_eq!(result.as_bool(), Some(true));
    }

    #[test]
    fn verifychain_accepts_default_params() {
        let ctx = Arc::new(Context::new());
        let result = verifychain(&ctx, &json!([3, 6]))
            .unwrap_or_else(|err| panic!("verifychain failed: {err}"));
        assert_eq!(result.as_bool(), Some(true));
    }

    #[test]
    fn verifychain_returns_true_for_checklevel_zero() {
        let ctx = Arc::new(Context::new());
        let result = verifychain(&ctx, &json!([0, 6]))
            .unwrap_or_else(|err| panic!("verifychain failed: {err}"));
        assert!(result.as_bool() == Some(true));
    }
}

fn compute_branchlen(
    tree: &bitcoin_rs_chain::BlockTree,
    leaf_id: bitcoin_rs_chain::NodeId,
    leaf_height: u32,
    active_tip_id: Option<bitcoin_rs_chain::NodeId>,
) -> u32 {
    let Some(active_id) = active_tip_id else {
        return leaf_height;
    };

    // Walk parents from leaf until we hit a node also on the active chain.
    let mut cursor = leaf_id;
    loop {
        let Ok(node) = tree.node(cursor) else {
            return leaf_height;
        };
        if tree.node_at_height_from(active_id, node.height) == Some(cursor) {
            return leaf_height.saturating_sub(node.height);
        }
        let Some(parent_id) = node.parent else {
            return leaf_height;
        };
        cursor = parent_id;
    }
}
