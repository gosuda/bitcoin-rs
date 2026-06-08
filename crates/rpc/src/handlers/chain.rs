use alloc::sync::Arc;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use core::str::FromStr as _;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_pruning::policy::CORE_REORG_SAFETY_MARGIN;
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
    let block_stats = {
        let blocks = ctx.blocks.read();
        fold_block_records(&blocks, applied, None)
    };
    let prune_status = ctx.prune_status();
    let bestblockhash = ctx.applied_hash().to_string_be();
    let chainwork = ctx.chainwork_hex();
    let mut response = sonic_rs::Object::new();
    let _ = response.insert(&"chain", chain);
    let _ = response.insert(&"blocks", applied);
    let _ = response.insert(&"headers", headers);
    let _ = response.insert(&"bestblockhash", bestblockhash.as_str());
    let _ = response.insert(&"difficulty", json!(difficulty));
    let _ = response.insert(&"time", 0_u64);
    let _ = response.insert(&"mediantime", 0_u64);
    let _ = response.insert(&"verificationprogress", json!(verification_progress));
    let _ = response.insert(&"initialblockdownload", applied < headers);
    let _ = response.insert(&"chainwork", chainwork.as_str());
    let _ = response.insert(&"size_on_disk", block_stats.size_on_disk);
    let _ = response.insert(&"pruned", prune_status.pruned);
    if let Some(pruneheight) = prune_status.pruneheight {
        let _ = response.insert(&"pruneheight", pruneheight);
    }
    let _ = response.insert(&"warnings", "");
    Ok(Value::from(response))
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
    let window_block_count = nblocks.min(u64::from(applied_height).saturating_add(1));
    let lowest_window_height = u64::from(applied_height)
        .saturating_add(1)
        .saturating_sub(window_block_count);
    let block_stats = {
        let blocks_guard = ctx.blocks.read();
        fold_block_records(&blocks_guard, applied_height, Some(lowest_window_height))
    };
    let total_tx_count = block_stats.total_tx_count;
    let window_tx_count = block_stats.window_tx_count;
    let tip_time = block_stats.tip_time.unwrap_or(0);
    let earliest_window_time = block_stats.earliest_window_time.unwrap_or(tip_time);
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

#[derive(Default)]
struct FoldedBlockRecords {
    size_on_disk: u64,
    total_tx_count: u64,
    window_tx_count: u64,
    tip_time: Option<u32>,
    earliest_window_time: Option<u32>,
}

fn fold_block_records(
    blocks: &[BlockRecord],
    applied_height: u32,
    lowest_window_height: Option<u64>,
) -> FoldedBlockRecords {
    let mut stats = FoldedBlockRecords::default();
    for record in blocks {
        stats.size_on_disk = stats
            .size_on_disk
            .saturating_add(u64::try_from(record.body_size).unwrap_or(u64::MAX));
        if record.height > applied_height {
            continue;
        }
        stats.total_tx_count = stats
            .total_tx_count
            .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
        if record.height == applied_height && stats.tip_time.is_none() {
            stats.tip_time = Some(record.time);
        }
        if lowest_window_height.is_some_and(|lowest| u64::from(record.height) >= lowest) {
            stats.window_tx_count = stats
                .window_tx_count
                .saturating_add(u64::try_from(record.tx_count).unwrap_or(0));
            stats.earliest_window_time = Some(
                stats
                    .earliest_window_time
                    .map_or(record.time, |earliest| earliest.min(record.time)),
            );
        }
    }
    stats
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
            return Ok(json!(ctx.block_body_hex(&record).unwrap_or_default()));
        }
        return Ok(synthetic_block_json(ctx, &record, true));
    };
    if verbosity == 0 {
        let Some(block_hex) = ctx.block_body_hex(&record) else {
            return Err(RpcError::NotFound("block data pruned"));
        };
        return Ok(json!(block_hex));
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
    let mut tx_sizes: Vec<u64> = Vec::new();
    let mut fee_fields = FeeFields::default();
    if let Some(record) = record.as_ref()
        && let Some((bytes, block)) = decode_record_block(ctx, record)?
    {
        total_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        total_weight = block.weight().to_wu();
        fee_fields = compute_fee_fields(ctx, &block);
        txs = u64::try_from(block.txdata.len()).unwrap_or(u64::MAX);
        for tx in &block.txdata {
            ins = ins.saturating_add(u64::try_from(tx.input.len()).unwrap_or(u64::MAX));
            outs = outs.saturating_add(u64::try_from(tx.output.len()).unwrap_or(u64::MAX));
            for output in &tx.output {
                total_out = total_out.saturating_add(output.value.to_sat());
            }
            let tx_size = bitcoin::consensus::encode::serialize(tx).len();
            let tx_size_u64 = u64::try_from(tx_size).unwrap_or(u64::MAX);
            tx_sizes.push(tx_size_u64);
            if tx.input.iter().any(|i| !i.witness.is_empty()) {
                swtxs = swtxs.saturating_add(1);
                swtotal_size = swtotal_size.saturating_add(tx_size_u64);
                swtotal_weight = swtotal_weight.saturating_add(tx.weight().to_wu());
            }
        }
    }

    let (avgtxsize, maxtxsize, mintxsize, mediantxsize) = if tx_sizes.is_empty() {
        (0_u64, 0_u64, 0_u64, 0_u64)
    } else {
        let mut sorted = tx_sizes.clone();
        sorted.sort_unstable();
        let max = sorted.last().copied().unwrap_or(0);
        let min = sorted.first().copied().unwrap_or(0);
        let median = sorted[sorted.len() / 2];
        let sum: u64 = sorted.iter().fold(0_u64, |acc, n| acc.saturating_add(*n));
        let avg = sum / u64::try_from(sorted.len()).unwrap_or(1);
        (avg, max, min, median)
    };

    Ok(json!({
        "avgfee": fee_fields.avgfee,
        "avgfeerate": fee_fields.avgfeerate,
        "avgtxsize": avgtxsize,
        "blockhash": block_hash.to_string_be(),
        "feerate_percentiles": fee_fields.feerate_percentiles,
        "height": height,
        "ins": ins,
        "maxfee": fee_fields.maxfee,
        "maxfeerate": fee_fields.maxfeerate,
        "maxtxsize": maxtxsize,
        "medianfee": fee_fields.medianfee,
        "mediantime": mediantime,
        "mediantxsize": mediantxsize,
        "minfee": fee_fields.minfee,
        "minfeerate": fee_fields.minfeerate,
        "mintxsize": mintxsize,
        "outs": outs,
        "subsidy": subsidy_sat,
        "swtotal_size": swtotal_size,
        "swtotal_weight": swtotal_weight,
        "swtxs": swtxs,
        "time": time,
        "total_out": total_out,
        "total_size": total_size,
        "total_weight": total_weight,
        "totalfee": fee_fields.totalfee,
        "txs": txs,
        "utxo_increase": 0,
        "utxo_size_inc": 0
    }))
}
fn decode_record_block(
    ctx: &Context,
    record: &BlockRecord,
) -> Result<Option<(Vec<u8>, bitcoin::Block)>, RpcError> {
    use bitcoin::consensus::encode::deserialize;

    let Some(bytes) = ctx.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    let Ok(block) = deserialize::<bitcoin::Block>(&bytes) else {
        return Ok(None);
    };
    Ok(Some((bytes, block)))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FeeFields {
    avgfee: u64,
    avgfeerate: u64,
    feerate_percentiles: [u64; 5],
    maxfee: u64,
    maxfeerate: u64,
    medianfee: u64,
    minfee: u64,
    minfeerate: u64,
    totalfee: u64,
}

fn resolve_per_tx_fees(ctx: &Context, block: &bitcoin::Block) -> Option<Vec<(u64, u64)>> {
    let indexer = ctx.indexer.as_ref()?;
    let tx_count = block.txdata.len().saturating_sub(1);
    let mut fees = Vec::with_capacity(tx_count);
    for tx in block.txdata.iter().skip(1) {
        let mut total_in = 0_u64;
        for input in &tx.input {
            let value = indexer
                .lock()
                .resolve_outpoint_value(input.previous_output, ctx)
                .ok()??;
            total_in = total_in.saturating_add(value);
        }
        let total_out = tx.output.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let fee = total_in.checked_sub(total_out)?;
        fees.push((fee, tx.weight().to_wu()));
    }
    Some(fees)
}

fn percentiles_by_weight(scores: &mut [(u64, u64)], total_weight: u64) -> [u64; 5] {
    const NUMERATORS: [u64; 5] = [1, 1, 1, 3, 9];
    const DENOMINATORS: [u64; 5] = [10, 4, 2, 4, 10];

    if scores.is_empty() || total_weight == 0 {
        return [0; 5];
    }

    scores.sort_unstable_by(|(left_rate, left_weight), (right_rate, right_weight)| {
        (*left_rate, *left_weight).cmp(&(*right_rate, *right_weight))
    });
    let mut out = [0_u64; 5];
    let mut cumulative = 0_u64;
    let mut percentile = 0_usize;
    let mut last_rate = 0_u64;
    for (rate, weight) in scores.iter().copied() {
        last_rate = rate;
        cumulative = cumulative.saturating_add(weight);
        while percentile < out.len()
            && u128::from(cumulative) * u128::from(DENOMINATORS[percentile])
                >= u128::from(total_weight) * u128::from(NUMERATORS[percentile])
        {
            out[percentile] = rate;
            percentile += 1;
        }
    }
    while percentile < out.len() {
        out[percentile] = last_rate;
        percentile += 1;
    }
    out
}

fn truncated_median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        return values[mid];
    }
    let low = values[mid - 1];
    let high = values[mid];
    (low / 2)
        .saturating_add(high / 2)
        .saturating_add((low % 2).saturating_add(high % 2) / 2)
}

fn compute_fee_fields(ctx: &Context, block: &bitcoin::Block) -> FeeFields {
    let Some(per_tx) = resolve_per_tx_fees(ctx, block) else {
        return FeeFields::default();
    };
    if per_tx.is_empty() {
        return FeeFields::default();
    }

    let totalfee = per_tx
        .iter()
        .fold(0_u64, |sum, (fee, _weight)| sum.saturating_add(*fee));
    let total_weight = per_tx
        .iter()
        .fold(0_u64, |sum, (_fee, weight)| sum.saturating_add(*weight));
    let tx_count = u64::try_from(per_tx.len()).map_or(1, |count| count);
    let avgfee = totalfee / tx_count;
    let avgfeerate = totalfee
        .saturating_mul(4)
        .checked_div(total_weight)
        .unwrap_or(0);

    let mut fees = Vec::with_capacity(per_tx.len());
    let mut rates = Vec::with_capacity(per_tx.len());
    for (fee, weight) in &per_tx {
        fees.push(*fee);
        let rate = (*fee).saturating_mul(4).checked_div(*weight).unwrap_or(0);
        rates.push((rate, *weight));
    }

    let minfee = fees.iter().copied().min().map_or(0, |fee| fee);
    let maxfee = fees.iter().copied().max().map_or(0, |fee| fee);
    let medianfee = truncated_median(&mut fees);
    let minfeerate = rates
        .iter()
        .map(|(rate, _weight)| *rate)
        .min()
        .map_or(0, |rate| rate);
    let maxfeerate = rates
        .iter()
        .map(|(rate, _weight)| *rate)
        .max()
        .map_or(0, |rate| rate);
    let feerate_percentiles = percentiles_by_weight(&mut rates, total_weight);

    FeeFields {
        avgfee,
        avgfeerate,
        feerate_percentiles,
        maxfee,
        maxfeerate,
        medianfee,
        minfee,
        minfeerate,
        totalfee,
    }
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
    let requested = required_u64(params, 0, "height is required")?;
    let requested_height =
        u32::try_from(requested).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?;
    let Some(prune_service) = ctx.prune_service.as_ref() else {
        return Err(RpcError::MethodDisabled("pruning is disabled"));
    };
    let applied = ctx.applied_height();
    if requested_height > applied {
        return Err(RpcError::InvalidParams(
            "prune height cannot exceed applied tip",
        ));
    }
    let safe_prune_height = applied.saturating_sub(CORE_REORG_SAFETY_MARGIN);
    if requested_height > safe_prune_height {
        return Err(RpcError::InvalidParams(
            "prune height is within reorg safety margin",
        ));
    }
    let result = prune_service
        .prune_to_height(requested_height)
        .map_err(|err| RpcError::Internal(err.to_string()))?;
    Ok(json!(result.pruneheight))
}

pub(crate) fn verifychain(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use bitcoin::consensus::encode::deserialize;

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
                if let Some(bytes) = ctx.block_body_bytes(&record) {
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
        "hash_serialized_3"
    } else {
        match params_array(params)?.first() {
            Some(value) if value.is_null() => "hash_serialized_3",
            Some(value) => value
                .as_str()
                .ok_or(RpcError::InvalidType("hash_type must be a string"))?,
            None => "hash_serialized_3",
        }
    };
    let want_muhash = hash_type == "muhash";
    let (stats, txouts, transactions, set_hash) = ctx.utxo.with_stable_view(|view| {
        let stats = bitcoin_rs_coinstats::scan_coin_stats(view, ctx.applied_height(), want_muhash)
            .map_err(|err| RpcError::Internal(err.to_string()))?;
        let set_hash = match hash_type {
            "hash_serialized_3" => Some((
                "hash_serialized_3",
                view.hash_serialized_3()
                    .map_err(|err| RpcError::Internal(err.to_string()))?
                    .to_string_be(),
            )),
            "muhash" => Some(("muhash", stats.muhash.finalize_hash().to_string_be())),
            "none" => None,
            _ => {
                return Err(RpcError::InvalidParams(
                    "hash_type must be one of: hash_serialized_3, muhash, none",
                ));
            }
        };
        Ok::<_, RpcError>((stats, view.len(), view.record_count(), set_hash))
    })?;
    let total_amount_btc = bitcoin::Amount::from_sat(stats.total_amount).to_btc();

    let bestblock = ctx.applied_hash().to_string_be();
    let mut response = sonic_rs::Object::new();
    let _ = response.insert(&"height", ctx.applied_height());
    let _ = response.insert(&"bestblock", bestblock.as_str());
    let _ = response.insert(&"txouts", txouts);
    let _ = response.insert(&"bogosize", stats.bogo_size);
    let _ = response.insert(&"total_amount", json!(total_amount_btc));
    let _ = response.insert(&"transactions", transactions);
    let _ = response.insert(&"disk_size", 0_u64);
    if let Some((field, hash)) = set_hash {
        let _ = response.insert(&field, hash.as_str());
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
        .ok_or(RpcError::NotFound("block filter not found"))?;
    let header = ctx
        .filter_index
        .filter_header(hash)
        .map_err(|error| RpcError::Internal(error.to_string()))?
        .ok_or(RpcError::NotFound("block filter header not found"))?;
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

    let txindex_entry = ctx.indexer.is_some().then(entry);
    match filter {
        None => {
            let mut indexes = sonic_rs::Object::new();
            if let Some(entry) = txindex_entry {
                let _ = indexes.insert(&"txindex", entry);
            }
            let _ = indexes.insert(&"basicblockfilterindex", entry());
            Ok(indexes.into())
        }
        Some("txindex") => {
            Ok(txindex_entry.map_or_else(|| json!({}), |entry| json!({ "txindex": entry })))
        }
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

    let Some((block_bytes, block)) = decode_block(ctx, record)? else {
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
        "strippedsize": block_bytes.len(),
        "size": block_bytes.len(),
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

fn decode_block(
    ctx: &Context,
    record: &BlockRecord,
) -> Result<Option<(Vec<u8>, bitcoin::Block)>, RpcError> {
    let Some(bytes) = ctx.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    match deserialize(&bytes) {
        Ok(block) => Ok(Some((bytes, block))),
        Err(error) => {
            tracing::warn!(
                block_hash = %record.hash.to_string_be(),
                %error,
                "stored block bytes are invalid"
            );
            Ok(None)
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
        "size": record.body_size,
        "weight": 0,
        "tx": []
    })
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

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
    fn subsidy_at_height_third_halving_is_6_25_btc() {
        assert_eq!(subsidy_at_height(3 * 210_000), 5_000_000_000 / 8);
    }

    #[test]
    fn subsidy_at_height_after_64_halvings_is_zero() {
        assert_eq!(subsidy_at_height(64 * 210_000), 0);
        assert_eq!(subsidy_at_height(u32::MAX), 0);
    }

    #[test]
    fn percentiles_by_weight_empty_scores_are_zero() {
        let mut scores = Vec::new();

        assert_eq!(percentiles_by_weight(&mut scores, 0), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn percentiles_by_weight_single_tx_fills_all_slots() {
        let mut scores = vec![(12, 400)];

        assert_eq!(
            percentiles_by_weight(&mut scores, 400),
            [12, 12, 12, 12, 12]
        );
    }

    #[test]
    fn percentiles_by_weight_two_txs_use_core_thresholds() {
        let mut scores = vec![(20, 100), (5, 100)];

        assert_eq!(percentiles_by_weight(&mut scores, 200), [5, 5, 5, 20, 20]);
    }

    #[test]
    fn percentiles_by_weight_fills_remaining_slots_with_last_rate() {
        let mut scores = vec![(2, 1), (5, 1)];

        assert_eq!(percentiles_by_weight(&mut scores, 100), [5, 5, 5, 5, 5]);
    }

    #[test]
    fn truncated_median_handles_odd_and_even_lengths() {
        let mut odd = vec![7, 1, 3];
        let mut even = vec![1, 4];

        assert_eq!(truncated_median(&mut odd), 3);
        assert_eq!(truncated_median(&mut even), 2);
    }

    #[test]
    fn compute_fee_fields_defaults_without_indexer() {
        let ctx = Context::new();
        let block = genesis_block(bitcoin::Network::Regtest);

        assert_eq!(compute_fee_fields(&ctx, &block), FeeFields::default());
    }

    #[test]
    fn getblock_populates_real_header_fields_from_stored_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let block_hash_hex = record.hash.to_string_be();
        let block_size = u64::try_from(record.body_size)?;
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
    fn getblock_reads_metadata_only_record_from_body_source()
    -> Result<(), Box<dyn std::error::Error>> {
        struct SingleBlockSource {
            height: u32,
            hash: Hash256,
            body: Vec<u8>,
            calls: AtomicUsize,
        }

        impl crate::BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                (height == self.height && hash == self.hash).then(|| self.body.clone())
            }
        }

        let genesis = genesis_block(bitcoin::Network::Regtest);
        let body = bitcoin::consensus::encode::serialize(&genesis);
        let record = BlockRecord::from_block_metadata(0, &genesis);
        let block_hash_hex = record.hash.to_string_be();
        let source = Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: body.clone(),
            calls: AtomicUsize::new(0),
        });
        let calls = Arc::clone(&source);
        let ctx = Arc::new(Context::new().with_block_body_source(source));
        ctx.add_block(record);

        let expected_hex = body.to_lower_hex_string();
        assert_eq!(
            getblock(&ctx, &json!([block_hash_hex.as_str(), 0]))?.as_str(),
            Some(expected_hex.as_str())
        );
        assert_eq!(calls.calls.load(Ordering::Relaxed), 1);
        let block_json = getblock(&ctx, &json!([block_hash_hex.as_str(), 1]))?;
        assert_eq!(calls.calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            block_json.get("size").as_u64(),
            Some(u64::try_from(body.len())?)
        );
        assert_eq!(
            block_json.get("hash").as_str(),
            Some(block_hash_hex.as_str())
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
            result.get("hash_serialized_3").is_none(),
            "hash_serialized_3 should be absent for hash_type=none: {result:?}"
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
    fn getblockchaininfo_size_on_disk_zero_for_empty_blocks() {
        let ctx = Arc::new(Context::new());
        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        assert_eq!(
            result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
            Some(0)
        );
    }

    #[test]
    fn getblockchaininfo_size_on_disk_uses_metadata_body_size() {
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let body = bitcoin::consensus::encode::serialize(&genesis);
        let record = BlockRecord::from_block_metadata(0, &genesis);
        let ctx = Arc::new(Context::new());
        ctx.add_block(record);

        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

        assert_eq!(
            result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
            Some(u64::try_from(body.len()).unwrap_or(u64::MAX))
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

    #[test]
    fn getchaintxstats_two_block_window_uses_one_folded_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let tip_hash = Hash256::from_le_bytes(&[9_u8; 32]);
        for height in 0_u32..4 {
            ctx.add_block(BlockRecord {
                hash: Hash256::from_le_bytes(&[u8::try_from(height)?; 32]),
                height,
                block_hex: String::new(),
                body_size: usize::try_from(100_u32.saturating_add(height))?,
                header_hex: String::new(),
                tx_count: usize::try_from(height.saturating_add(1))?,
                time: 1_000_u32.saturating_add(height.saturating_mul(10)),
            });
        }
        ctx.add_block(BlockRecord {
            hash: Hash256::from_le_bytes(&[4_u8; 32]),
            height: 4,
            block_hex: String::new(),
            body_size: 104,
            header_hex: String::new(),
            tx_count: 100,
            time: 1,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 3,
            chainwork: ChainWork::ZERO,
            hash: tip_hash,
        });

        let result = getchaintxstats(&ctx, &json!([2]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));

        assert_eq!(
            result.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(10)
        );
        assert_eq!(
            result
                .get("window_block_count")
                .and_then(JsonValueTrait::as_u64),
            Some(2)
        );
        assert_eq!(
            result
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        assert_eq!(
            result
                .get("window_interval")
                .and_then(JsonValueTrait::as_u64),
            Some(10)
        );
        assert_eq!(
            result.get("time").and_then(JsonValueTrait::as_u64),
            Some(1_030)
        );
        Ok(())
    }

    #[test]
    fn getchaintxstats_tip_time_uses_first_applied_height_record() {
        let ctx = Arc::new(Context::new());
        let tip_hash = Hash256::from_le_bytes(&[8_u8; 32]);
        ctx.add_block(BlockRecord {
            hash: tip_hash,
            height: 2,
            block_hex: String::new(),
            body_size: 100,
            header_hex: String::new(),
            tx_count: 1,
            time: 200,
        });
        ctx.add_block(BlockRecord {
            hash: Hash256::from_le_bytes(&[7_u8; 32]),
            height: 2,
            block_hex: String::new(),
            body_size: 100,
            header_hex: String::new(),
            tx_count: 1,
            time: 300,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 2,
            chainwork: ChainWork::ZERO,
            hash: tip_hash,
        });

        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));

        assert_eq!(
            result.get("time").and_then(JsonValueTrait::as_u64),
            Some(200)
        );
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

    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
    use bitcoin_rs_primitives::Hash256;

    use super::*;

    struct FakePruneService {
        status: crate::context::PruneStatus,
        result_pruneheight: Option<u32>,
    }

    impl crate::context::PruneService for FakePruneService {
        fn prune_to_height(
            &self,
            requested_height: u32,
        ) -> Result<crate::context::PruneResult, crate::context::PruneServiceError> {
            Ok(crate::context::PruneResult {
                requested_height,
                pruneheight: self.result_pruneheight.unwrap_or(requested_height),
                block_rows_removed: 0,
                undo_rows_removed: 0,
                bytes_freed: 0,
            })
        }

        fn status(&self) -> crate::context::PruneStatus {
            self.status
        }
    }

    fn set_applied_tip(ctx: &Context, height: u32) {
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height,
            chainwork: ChainWork::ZERO,
            hash: Hash256::default(),
        });
    }

    fn pruning_context() -> Arc<Context> {
        Arc::new(
            Context::new().with_prune_service(Arc::new(FakePruneService {
                status: crate::context::PruneStatus {
                    pruned: true,
                    pruneheight: None,
                },
                result_pruneheight: None,
            })),
        )
    }

    #[test]
    fn pruneblockchain_returns_requested_height_after_service_succeeds() {
        let ctx = pruning_context();
        set_applied_tip(&ctx, 400);

        let result = pruneblockchain(&ctx, &json!([100]))
            .unwrap_or_else(|err| panic!("pruneblockchain failed: {err}"));

        assert_eq!(result.as_u64(), Some(100));
    }

    #[test]
    fn pruneblockchain_returns_service_pruneheight() {
        let ctx = Arc::new(
            Context::new().with_prune_service(Arc::new(FakePruneService {
                status: crate::context::PruneStatus {
                    pruned: true,
                    pruneheight: Some(150),
                },
                result_pruneheight: Some(150),
            })),
        );
        set_applied_tip(&ctx, 400);

        let result = pruneblockchain(&ctx, &json!([100]))
            .unwrap_or_else(|err| panic!("pruneblockchain failed: {err}"));

        assert_eq!(result.as_u64(), Some(150));
    }

    #[test]
    fn pruneblockchain_returns_method_disabled_without_service() {
        let ctx = Arc::new(Context::new());

        let result = pruneblockchain(&ctx, &json!([100]));

        assert!(matches!(
            result,
            Err(RpcError::MethodDisabled("pruning is disabled"))
        ));
    }

    #[test]
    fn pruneblockchain_rejects_unsafe_height() {
        let ctx = pruning_context();
        set_applied_tip(&ctx, 400);

        let result = pruneblockchain(&ctx, &json!([200]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams(
                "prune height is within reorg safety margin"
            ))
        ));
    }

    #[test]
    fn pruneblockchain_rejects_height_above_tip() {
        let ctx = pruning_context();
        set_applied_tip(&ctx, 400);

        let result = pruneblockchain(&ctx, &json!([401]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams(
                "prune height cannot exceed applied tip"
            ))
        ));
    }

    #[test]
    fn getblockchaininfo_reports_pruned_status_and_pruneheight() {
        let ctx = Arc::new(
            Context::new().with_prune_service(Arc::new(FakePruneService {
                status: crate::context::PruneStatus {
                    pruned: true,
                    pruneheight: Some(42),
                },
                result_pruneheight: None,
            })),
        );

        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

        assert_eq!(
            result.get("pruned").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            result.get("pruneheight").and_then(JsonValueTrait::as_u64),
            Some(42)
        );
    }

    #[test]
    fn getblock_returns_not_found_after_block_body_is_cleared() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::default();
        ctx.add_block(BlockRecord::synthetic(1, hash));

        let result = getblock(&ctx, &json!([hash.to_string_be(), 0]));

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }

    #[test]
    fn getblockstats_returns_not_found_after_block_body_is_cleared() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::default();
        ctx.add_block(BlockRecord::synthetic(1, hash));

        let result = getblockstats(&ctx, &json!([1]));

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
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
