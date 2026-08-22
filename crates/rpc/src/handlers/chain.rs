use alloc::sync::Arc;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use core::str::FromStr as _;
use core::{fmt, fmt::Write as _};

use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_pruning::policy::CORE_REORG_SAFETY_MARGIN;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::{BlockRecord, ChainControlError, Context, TxQueryError};
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str, required_u64};

pub(crate) fn getblockchaininfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let applied_tip = ctx.applied_tip.load_full();
    let applied = applied_tip.as_ref().map_or(0, |tip| tip.height);
    let headers = ctx.height();
    let (difficulty, time, mediantime) = applied_tip.as_ref().map_or((0.0, 0_u64, 0_u64), |tip| {
        let tree = ctx.block_tree.read();
        tree.node(tip.tip_id).map_or((0.0, 0, 0), |node| {
            (
                ctx.difficulty_for_bits(node.header.bits),
                u64::from(node.header.time),
                u64::from(tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0)),
            )
        })
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
        fold_block_records(&blocks, applied)
    };
    let prune_status = ctx.prune_status();
    let bestblockhash = applied_tip
        .as_ref()
        .map_or_else(Hash256::default, |tip| tip.hash)
        .to_string_be();
    let chainwork = applied_tip
        .as_deref()
        .map_or_else(|| ctx.chainwork_hex(), chainwork_hex);
    let mut response = sonic_rs::Object::new();
    let _ = response.insert(&"chain", chain);
    let _ = response.insert(&"blocks", applied);
    let _ = response.insert(&"headers", headers);
    let _ = response.insert(&"bestblockhash", bestblockhash.as_str());
    let _ = response.insert(&"difficulty", json!(difficulty));
    let _ = response.insert(&"time", time);
    let _ = response.insert(&"mediantime", mediantime);
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

fn chainwork_hex(tip: &TipSnapshot) -> String {
    let bytes: [u8; 32] = tip.chainwork.to_be_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _: fmt::Result = write!(&mut out, "{byte:02x}");
    }
    out
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

/// Number of blocks Bitcoin Core's median-time-past looks back over.
const MEDIAN_TIME_SPAN: usize = 11;

pub(crate) fn getchaintxstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    // Bitcoin Core's default: one month of ten-minute blocks.
    const DEFAULT_WINDOW: i64 = 30 * 24 * 6;

    let array = params_array(params)?;
    let final_block = window_final_block(ctx, array.get(1))?;
    let window_block_count = match array.first().filter(|value| !value.is_null()) {
        // An explicit count is validated, not clamped. Core refuses a window
        // that reaches past genesis rather than quietly shortening it, because
        // silently answering about a different window is the worse failure.
        Some(value) => {
            let requested = value
                .as_i64()
                .ok_or(RpcError::InvalidType("block count must be an integer"))?;
            if requested < 0 || (requested > 0 && requested >= i64::from(final_block.height)) {
                return Err(RpcError::InvalidParameter(
                    "Invalid block count: should be between 0 and the block's height - 1"
                        .to_owned(),
                ));
            }
            requested
        }
        None => DEFAULT_WINDOW.min(i64::from(final_block.height)).max(0),
    };

    let mut response = sonic_rs::Object::new();
    let _ = response.insert(&"time", final_block.time);
    // Core omits `txcount` when the block's cumulative count is unknown rather
    // than reporting a zero that reads like an empty chain. This node knows the
    // cumulative count for its applied tip and for no other block.
    if let Some(txcount) = chain_tx_count_at(ctx, &final_block) {
        let _ = response.insert(&"txcount", txcount);
    }
    let _ = response.insert(
        &"window_final_block_hash",
        final_block.hash.to_string_be().as_str(),
    );
    let _ = response.insert(&"window_final_block_height", final_block.height);
    let _ = response.insert(&"window_block_count", window_block_count);

    // A zero-block window has no interval and no transactions to report, so
    // Core emits neither. Reporting `0` for both would state a measurement that
    // was never taken.
    if window_block_count > 0 {
        let past_height = u32::try_from(i64::from(final_block.height) - window_block_count)
            .unwrap_or_else(|_| unreachable!("the window is bounded by the block's own height"));
        let interval = window_interval(ctx, &final_block, past_height);
        let _ = response.insert(&"window_interval", interval);

        if let Some(window_tx_count) = window_tx_count(ctx, final_block.height, past_height) {
            let _ = response.insert(&"window_tx_count", window_tx_count);
            // A non-positive interval is not a rate. Block timestamps only have
            // to beat the median of the last eleven, so a window can end no
            // later than it began.
            if interval > 0 {
                let count = i32::try_from(window_tx_count).unwrap_or(i32::MAX);
                let seconds = i32::try_from(interval).unwrap_or(i32::MAX);
                let _ = response.insert(&"txrate", json!(f64::from(count) / f64::from(seconds)));
            }
        }
    }

    Ok(Value::from(response))
}

/// The block a window ends at: its hash, height, timestamp and tree node.
struct WindowFinalBlock {
    node_id: bitcoin_rs_chain::NodeId,
    hash: Hash256,
    height: u32,
    time: u32,
    is_applied_tip: bool,
}

/// Resolves the `blockhash` argument, defaulting to the applied tip.
///
/// Core requires the named block to be on the active chain: the statistics are
/// about a window of the chain, and a block off it is not the end of one.
fn window_final_block(
    ctx: &Context,
    blockhash: Option<&Value>,
) -> Result<WindowFinalBlock, RpcError> {
    let tip = ctx.applied_tip.load_full();
    let tree = ctx.block_tree.read();

    let Some(blockhash) = blockhash.filter(|value| !value.is_null()) else {
        let Some(tip) = tip else {
            // No applied tip at all: nothing has been connected, so the window
            // ends nowhere. Core cannot reach this state; its chain always has
            // at least genesis.
            return Ok(WindowFinalBlock {
                node_id: bitcoin_rs_chain::NodeId::new(0),
                hash: Hash256::default(),
                height: 0,
                time: 0,
                is_applied_tip: true,
            });
        };
        // The tree keeps every header it has accepted and is restored in full,
        // so it answers for a tip the in-process record log never saw. The log
        // is the fallback for the reverse: a record pushed before its header
        // reached the tree.
        let time = tree
            .node(tip.tip_id)
            .map(|node| node.header.time)
            .ok()
            .or_else(|| logged_time_at_height(ctx, tip.height))
            .unwrap_or(0);
        return Ok(WindowFinalBlock {
            node_id: tip.tip_id,
            hash: tip.hash,
            height: tip.height,
            time,
            is_applied_tip: true,
        });
    };

    let hash = blockhash
        .as_str()
        .and_then(|text| Hash256::from_str_be(text).ok())
        .ok_or(RpcError::InvalidType("blockhash must be 64 hex characters"))?;
    let node_id = tree
        .lookup(hash)
        .ok_or(RpcError::NotFound("Block not found"))?;
    let node = tree
        .node(node_id)
        .map_err(|_| RpcError::NotFound("Block not found"))?;
    // On the active chain means: the chain's own block at that height is this
    // one. A stale block keeps its height, so height alone proves nothing.
    if tree
        .active_node_at_height(node.height)
        .map(|active| active.hash)
        != Some(hash)
    {
        return Err(RpcError::InvalidParameter(
            "Block is not in main chain".to_owned(),
        ));
    }
    Ok(WindowFinalBlock {
        node_id,
        hash,
        height: node.height,
        time: node.header.time,
        is_applied_tip: tip.is_some_and(|tip| tip.hash == hash),
    })
}

/// The window's length in seconds, as the difference of two median times.
///
/// Bitcoin Core measures a window between the median-time-past of its two
/// boundary blocks, not between raw header timestamps. A miner may stamp a
/// block up to two hours ahead and only has to beat the median of the previous
/// eleven, so raw timestamps are not ordered and their difference is not a
/// duration. The median is, which is why every consensus rule that needs a
/// clock uses it.
fn window_interval(ctx: &Context, final_block: &WindowFinalBlock, past_height: u32) -> i64 {
    let tree = ctx.block_tree.read();
    let Some(past_id) = tree.node_at_height_from(final_block.node_id, past_height) else {
        return 0;
    };
    let final_mtp = tree.median_time_past_at(final_block.node_id, MEDIAN_TIME_SPAN);
    let past_mtp = tree.median_time_past_at(past_id, MEDIAN_TIME_SPAN);
    match (final_mtp, past_mtp) {
        (Some(final_mtp), Some(past_mtp)) => i64::from(final_mtp) - i64::from(past_mtp),
        _ => 0,
    }
}

/// The cumulative transaction count through `final_block`, when it is known.
///
/// Three outcomes, and Core distinguishes them the same way: the durable
/// counter knows; the record log knows when it still holds the chain back to
/// genesis; and otherwise nobody does, so the field is omitted. Core omits it
/// on the same condition -- `m_chain_tx_count == 0` -- rather than reporting a
/// zero that reads like a chain with no transactions in it.
///
/// The counter tracks the applied tip and nothing else, so a window ending
/// anywhere else has no answer here.
fn chain_tx_count_at(ctx: &Context, final_block: &WindowFinalBlock) -> Option<u64> {
    if !final_block.is_applied_tip {
        return None;
    }
    if let Some(count) = ctx.chain_tx_count() {
        return Some(count);
    }
    let blocks = ctx.blocks.read();
    if blocks.is_empty() {
        // An empty log at height zero is an empty chain, which is a count of
        // none rather than a count nobody knows.
        return (final_block.height == 0).then_some(0);
    }
    // The log is rebuilt empty on every open and appended to contiguously, so
    // holding a record for genesis is what distinguishes a complete log from
    // one that starts wherever this process happened to begin applying.
    let complete = blocks.iter().any(|record| record.height == 0);
    complete.then(|| fold_block_records(&blocks, final_block.height).total_tx_count)
}

/// The timestamp the record log holds for the first block at `height`.
///
/// First rather than last: a reorg leaves the superseded record in place, and
/// this is the reading `getchaintxstats` has always taken.
fn logged_time_at_height(ctx: &Context, height: u32) -> Option<u32> {
    ctx.blocks
        .read()
        .iter()
        .find(|record| record.height == height)
        .map(|record| record.time)
}

/// Transactions in `(past_height, final_height]`, when the log holds them all.
///
/// This is Core's `nChainTx` difference between the two boundary blocks, summed
/// per block instead of subtracted, because this node keeps a cumulative count
/// only for its tip. The sum is therefore answerable only for blocks applied in
/// this process: the record log is rebuilt empty on every open. When it is not,
/// the field is omitted rather than under-reported -- a partial sum looks like
/// a quiet chain, and a miner or a fee estimator would believe it.
///
/// Records are folded by height with the last one winning, so a height the log
/// holds twice -- a reorg leaves the superseded record behind -- is counted
/// once, from the block that is actually on the chain now.
fn window_tx_count(ctx: &Context, final_height: u32, past_height: u32) -> Option<u64> {
    let expected = u64::from(final_height) - u64::from(past_height);
    let mut by_height = hashbrown::HashMap::new();
    {
        let blocks = ctx.blocks.read();
        for record in blocks.iter() {
            if record.height > past_height && record.height <= final_height {
                let _ = by_height.insert(record.height, record.tx_count);
            }
        }
    }
    if u64::try_from(by_height.len()).unwrap_or(u64::MAX) != expected {
        return None;
    }
    Some(by_height.into_values().fold(0_u64, |total, count| {
        total.saturating_add(u64::try_from(count).unwrap_or(0))
    }))
}

/// What a walk of the whole block-record log can still answer.
///
/// The window figures left: `getchaintxstats` measures its window between two
/// median times and counts only the heights inside it, so neither an
/// earliest-timestamp nor a running window sum has a reader any more.
#[derive(Default)]
struct FoldedBlockRecords {
    size_on_disk: u64,
    total_tx_count: u64,
}

fn fold_block_records(blocks: &[BlockRecord], applied_height: u32) -> FoldedBlockRecords {
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
        fee_fields = compute_fee_fields(ctx, &block).map_err(TxQueryError::into_rpc_error)?;
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

fn resolve_per_tx_fees(
    ctx: &Context,
    block: &bitcoin::Block,
) -> Result<Vec<(u64, u64)>, TxQueryError> {
    let Some(tx_index) = ctx.tx_index.as_ref() else {
        return Err(TxQueryError::Unavailable(
            "transaction index disabled".into(),
        ));
    };
    let tx_count = block.txdata.len().saturating_sub(1);
    let mut fees = Vec::with_capacity(tx_count);
    for tx in block.txdata.iter().skip(1) {
        let mut total_in = 0_u64;
        for input in &tx.input {
            match tx_index.outpoint_value(&input.previous_output) {
                Ok(Some(value)) => total_in = total_in.saturating_add(value),
                Ok(None) => {
                    return Err(TxQueryError::Unavailable(
                        "input value missing from complete index".into(),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        let total_out = tx.output.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let Some(fee) = total_in.checked_sub(total_out) else {
            return Err(TxQueryError::Unavailable("negative fee".into()));
        };
        fees.push((fee, tx.weight().to_wu()));
    }
    Ok(fees)
}

fn truncated_median(scores: &mut [u64]) -> u64 {
    if scores.is_empty() {
        return 0;
    }
    scores.sort_unstable();
    let n = scores.len();
    if n == 1 {
        return scores[0];
    }
    if n == 2 {
        return u64::midpoint(scores[0], scores[1]);
    }
    let lo = n / 4;
    let hi = n - lo;
    let slice = &scores[lo..hi];
    let m = slice.len();
    if m % 2 == 1 {
        slice[m / 2]
    } else {
        u64::midpoint(slice[m / 2 - 1], slice[m / 2])
    }
}

fn percentiles_by_weight(scores: &mut [(u64, u64)], total_weight: u64) -> [u64; 5] {
    if total_weight == 0 || scores.is_empty() {
        return [0; 5];
    }
    scores.sort_by_key(|score| score.0);
    let thresholds = [
        total_weight * 10 / 100,
        total_weight * 25 / 100,
        total_weight * 50 / 100,
        total_weight * 75 / 100,
        total_weight * 90 / 100,
    ];
    let mut result = [0_u64; 5];
    let mut cumulative = 0_u64;
    let mut index = 0;
    let n = scores.len();
    for (i, threshold) in thresholds.iter().enumerate() {
        while cumulative < *threshold && index < n {
            cumulative = cumulative.saturating_add(scores[index].1);
            index += 1;
        }
        result[i] = if cumulative < *threshold {
            scores[n - 1].0
        } else if index == 0 {
            scores[0].0
        } else {
            scores[index - 1].0
        };
    }
    result
}

fn compute_fee_fields(ctx: &Context, block: &bitcoin::Block) -> Result<FeeFields, TxQueryError> {
    let per_tx = resolve_per_tx_fees(ctx, block)?;
    if per_tx.is_empty() {
        return Ok(FeeFields::default());
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

    Ok(FeeFields {
        avgfee,
        avgfeerate,
        feerate_percentiles,
        maxfee,
        maxfeerate,
        medianfee,
        minfee,
        minfeerate,
        totalfee,
    })
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

pub(crate) fn invalidateblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let control = ctx
        .chain_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("invalidateblock is unavailable"))?;
    match control.invalidate_block(hash) {
        Ok(()) => Ok(json!(null)),
        Err(ChainControlError::UnknownBlock) => Err(RpcError::NotFound("block not found")),
        Err(ChainControlError::Genesis) => Err(RpcError::InvalidParams(
            "cannot invalidate the genesis block",
        )),
        Err(ChainControlError::Failed(message)) => Err(RpcError::Internal(message)),
    }
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

    let txindex_entry = ctx
        .tx_index
        .as_ref()
        .map(|tx_index| tx_index.index_info())
        .transpose()?;
    let txindex_entry = txindex_entry.map(|info| {
        json!({
            "synced": info.synced,
            "best_block_height": info.best_block_height,
        })
    });

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
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode, block::Header, block::Version};

    use super::*;
    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};

    fn context_with_tip(
        network: bitcoin_rs_primitives::Network,
        bits: u32,
        times: &[u32],
    ) -> Arc<Context> {
        let mut context = Context::new();
        context.chain_network = network;
        let ctx = Arc::new(context);
        let (tip_id, tip_hash) = {
            let mut tree = ctx.block_tree.write();
            let mut parent = None;
            let mut previous_hash = BlockHash::all_zeros();
            let mut tip_id = NodeId::new(0);
            let mut tip_hash = Hash256::default();
            for (index, time) in times.iter().copied().enumerate() {
                let header = Header {
                    version: Version::ONE,
                    prev_blockhash: previous_hash,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time,
                    bits: CompactTarget::from_consensus(bits),
                    nonce: u32::try_from(index).unwrap_or(u32::MAX),
                };
                previous_hash = header.block_hash();
                tip_id = tree
                    .insert_node(parent, header, NodeStatus::Active)
                    .unwrap_or(tip_id);
                tip_hash = Hash256::from_le_bytes(previous_hash.as_byte_array());
                parent = Some(tip_id);
            }
            (tip_id, tip_hash)
        };
        let tip = TipSnapshot {
            tip_id,
            height: u32::try_from(times.len().saturating_sub(1)).unwrap_or(u32::MAX),
            chainwork: ChainWork::ZERO,
            hash: tip_hash,
        };
        ctx.set_chain_tip(tip.clone());
        ctx.set_applied_tip(tip);
        ctx
    }

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
    fn compute_fee_fields_errors_without_indexer() {
        let ctx = Context::new();
        let block = genesis_block(bitcoin::Network::Regtest);

        assert!(
            matches!(
                compute_fee_fields(&ctx, &block),
                Err(TxQueryError::Unavailable(_))
            ),
            "expected error when txindex is disabled"
        );
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
    fn difficulty_matches_core_for_mainnet_and_regtest_targets() {
        let ctx = Context::new();
        let mainnet = ctx.difficulty_for_bits(CompactTarget::from_consensus(0x1d00_ffff));
        assert_eq!(mainnet.to_bits(), 1.0_f64.to_bits());
        let regtest = ctx.difficulty_for_bits(CompactTarget::from_consensus(0x207f_ffff));
        let expected = 4.656_542_373_906_924_7e-10_f64;
        assert_eq!(regtest.to_bits(), expected.to_bits());
    }

    #[test]
    fn getblockchaininfo_reports_tip_time_and_median_time_past() {
        let ctx = context_with_tip(
            bitcoin_rs_primitives::Network::Regtest,
            0x207f_ffff,
            &[100, 300, 200],
        );
        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

        assert_eq!(
            result.get("time").and_then(JsonValueTrait::as_u64),
            Some(200)
        );
        assert_eq!(
            result.get("mediantime").and_then(JsonValueTrait::as_u64),
            Some(200)
        );
        let difficulty = result
            .get("difficulty")
            .and_then(JsonValueTrait::as_f64)
            .unwrap_or_default();
        assert_eq!(
            difficulty.to_bits(),
            4.656_542_373_906_924_7e-10_f64.to_bits()
        );
    }

    #[test]
    fn getblockchaininfo_uses_one_applied_tip_snapshot() {
        use bitcoin_rs_chain::ChainWork;

        let ctx = context_with_tip(
            bitcoin_rs_primitives::Network::Regtest,
            0x207f_ffff,
            &[100, 300, 200],
        );
        let Some(applied) = ctx.applied_tip.load_full() else {
            panic!("applied tip missing");
        };
        let applied_chainwork = ChainWork::from_be_bytes([1; 32]);
        ctx.set_applied_tip(TipSnapshot {
            chainwork: applied_chainwork,
            ..(*applied).clone()
        });
        ctx.set_chain_tip(TipSnapshot {
            tip_id: applied.tip_id,
            height: 99,
            chainwork: ChainWork::from_be_bytes([2; 32]),
            hash: Hash256::from_le_bytes(&[9; 32]),
        });

        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        let expected_hash = applied.hash.to_string_be();
        let expected_chainwork = "01".repeat(32);
        assert_eq!(
            result.get("blocks").and_then(JsonValueTrait::as_u64),
            Some(2)
        );
        assert_eq!(
            result.get("headers").and_then(JsonValueTrait::as_u64),
            Some(99)
        );
        assert_eq!(
            result.get("bestblockhash").and_then(JsonValueTrait::as_str),
            Some(expected_hash.as_str())
        );
        assert_eq!(
            result.get("chainwork").and_then(JsonValueTrait::as_str),
            Some(expected_chainwork.as_str())
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
        // The interval is a difference of two median times and the tree is what
        // holds those, so this log-only fixture cannot produce one. The
        // median-time behaviour is pinned in `chaintxstats_window_tests`.
        assert_eq!(
            result
                .get("window_interval")
                .and_then(JsonValueTrait::as_u64),
            Some(0)
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

#[cfg(test)]
mod chaintxstats_durability_tests {
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicU64;

    use bitcoin::block::Version;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::NodeStatus;
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    const TIP_TIME: u32 = 1_700_000_123;

    /// A context whose applied tip is a real tree node, and whose block-record
    /// log is **empty** — the state a node is in after a restart, which is when
    /// folding the log stops being able to answer.
    fn restarted_ctx(chain_tx_count: Option<u64>) -> Arc<Context> {
        let ctx = Context::new();
        let tip = {
            let mut tree = ctx.block_tree.write();
            let genesis = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            let Ok(genesis_id) = tree.insert_node(None, genesis, NodeStatus::Active) else {
                panic!("genesis insert failed");
            };
            let child = bitcoin::block::Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: TIP_TIME,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 1,
            };
            let Ok(_child_id) = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)
            else {
                panic!("child insert failed");
            };
            let Some(tip) = tree.tip() else {
                panic!("no tip published");
            };
            (*tip).clone()
        };
        ctx.set_applied_tip(tip);
        let ctx = match chain_tx_count {
            Some(count) => ctx.with_chain_tx_count(Arc::new(AtomicU64::new(count))),
            None => ctx,
        };
        let ctx = Arc::new(ctx);
        assert!(
            ctx.blocks.read().is_empty(),
            "the fixture must leave the record log empty, or it is not a restart"
        );
        ctx
    }

    /// The record log answers only when it covers the chain back to genesis.
    ///
    /// A single record at the tip height is not a chain total -- a chain of
    /// height 1 has two blocks in it -- so reporting its transaction count as
    /// `txcount` states a number that is simply wrong. Core omits a count it
    /// does not know rather than publishing a placeholder, and an omitted field
    /// is the one answer a caller cannot mistake for a measurement.
    #[test]
    fn txcount_uses_the_log_only_when_the_log_covers_the_chain() {
        let partial = restarted_ctx(None);
        let Some(tip) = partial.applied_tip.load_full() else {
            panic!("fixture has no applied tip");
        };
        partial.add_block(logged(tip.hash, tip.height, 7, TIP_TIME));
        assert_eq!(
            stats_of(&partial)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            None,
            "a log that starts above genesis cannot answer for the whole chain"
        );

        let complete = restarted_ctx(None);
        complete.add_block(logged(Hash256::from_le_bytes(&[0x11; 32]), 0, 1, 1_000_000));
        complete.add_block(logged(tip.hash, tip.height, 7, TIP_TIME));
        assert_eq!(
            stats_of(&complete)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(8),
            "a log reaching genesis is the chain total"
        );
    }

    fn logged(hash: Hash256, height: u32, tx_count: usize, time: u32) -> BlockRecord {
        BlockRecord {
            hash,
            height,
            block_hex: String::new(),
            body_size: 0,
            header_hex: String::new(),
            tx_count,
            time,
        }
    }

    /// With nothing to answer from, the field is absent.
    ///
    /// It used to be `0`, which is a transaction count a real chain never has:
    /// genesis alone contributes one. A caller reading zero would conclude the
    /// chain was empty rather than that the node could not say.
    #[test]
    fn txcount_is_omitted_when_neither_the_counter_nor_the_log_knows() {
        assert_eq!(
            stats_of(&restarted_ctx(None))
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            None,
            "it must not invent a count it does not have"
        );
    }

    fn stats_of(ctx: &Arc<Context>) -> sonic_rs::Value {
        getchaintxstats(ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"))
    }

    #[test]
    fn txcount_comes_from_the_durable_counter_not_the_in_process_log() {
        let value = stats_of(&restarted_ctx(Some(1_315_805_869)));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(1_315_805_869),
            "folding the empty log would have reported zero"
        );
    }

    #[test]
    fn time_is_the_applied_tips_block_time_even_with_no_record_for_it() {
        let value = stats_of(&restarted_ctx(Some(10)));
        assert_eq!(
            value.get("time").and_then(JsonValueTrait::as_u64),
            Some(u64::from(TIP_TIME)),
            "the tree knows the tip's timestamp; the log does not have to"
        );
    }
}

#[cfg(test)]
mod chaintxstats_window_tests {
    use alloc::sync::Arc;

    use bitcoin::block::Version;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::NodeStatus;
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    const REGTEST_BITS: u32 = 0x207f_ffff;

    /// Timestamps that are not in order, because block times are not.
    ///
    /// A miner only has to beat the median of the previous eleven blocks, so a
    /// header may be stamped earlier than its parent. These dip twice, which is
    /// what separates a median-time window from a raw-timestamp one.
    const TIMES: [u32; 13] = [
        1_000_000, 1_000_600, 1_001_200, 1_000_900, 1_002_400, 1_003_000, 1_002_100, 1_004_200,
        1_004_800, 1_005_400, 1_006_000, 1_005_100, 1_007_200,
    ];

    /// Bitcoin Core's `GetMedianTimePast`, written out rather than borrowed.
    ///
    /// The median of the block and its ten ancestors. An oracle that called the
    /// block tree could not disagree with the block tree.
    fn median_time_past(times: &[u32], height: usize) -> u32 {
        let start = height.saturating_sub(10);
        let mut window = times[start..=height].to_vec();
        window.sort_unstable();
        window[window.len() / 2]
    }

    fn header(previous: BlockHash, time: u32, nonce: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: Version::ONE,
            prev_blockhash: previous,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce,
        }
    }

    /// A node whose active chain carries `times`, in both the tree and the log.
    ///
    /// Each block is given `height + 1` transactions, so a window sum is a
    /// number the test can state in closed form.
    fn chain_ctx(times: &[u32]) -> Arc<Context> {
        let ctx = Arc::new(Context::new());
        let mut previous = BlockHash::all_zeros();
        let mut parent = None;
        let mut tip = None;
        for (index, &time) in times.iter().enumerate() {
            let height = u32::try_from(index).unwrap_or(u32::MAX);
            let candidate = header(previous, time, height);
            previous = candidate.block_hash();
            let hash = Hash256::from_le_bytes(previous.as_byte_array());
            let id = {
                let mut tree = ctx.block_tree.write();
                tree.insert_node(parent, candidate, NodeStatus::Active)
                    .unwrap_or_else(|err| panic!("insert_node failed: {err}"))
            };
            parent = Some(id);
            tip = Some((id, hash, height));
            ctx.add_block(BlockRecord {
                hash,
                height,
                block_hex: String::new(),
                body_size: 0,
                header_hex: String::new(),
                tx_count: usize::try_from(height).unwrap_or(0) + 1,
                time,
            });
        }
        let Some((tip_id, hash, height)) = tip else {
            panic!("a chain fixture needs at least one block");
        };
        ctx.set_applied_tip(bitcoin_rs_chain::TipSnapshot {
            tip_id,
            height,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash,
        });
        ctx
    }

    fn stats(ctx: &Arc<Context>, params: &sonic_rs::Value) -> sonic_rs::Value {
        getchaintxstats(ctx, params).unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"))
    }

    fn field(value: &sonic_rs::Value, key: &str) -> Option<i64> {
        value.get(key).and_then(JsonValueTrait::as_i64)
    }

    /// The window is measured between two median times, as Core measures it.
    ///
    /// The raw-timestamp difference is asserted to be a *different* number, so
    /// the previous implementation could not have passed this: it subtracted
    /// the earliest raw timestamp in the window from the tip's.
    #[test]
    fn window_interval_is_the_difference_of_two_median_times() {
        let ctx = chain_ctx(&TIMES);
        let blocks = 4_i64;
        let final_height = TIMES.len() - 1;
        let past_height = final_height - usize::try_from(blocks).unwrap_or(0);

        let expected = i64::from(median_time_past(&TIMES, final_height))
            - i64::from(median_time_past(&TIMES, past_height));
        let raw = i64::from(TIMES[final_height]) - i64::from(TIMES[past_height]);
        assert_ne!(
            expected, raw,
            "the fixture must separate the two definitions, or it proves nothing"
        );

        assert_eq!(
            field(&stats(&ctx, &json!([blocks])), "window_interval"),
            Some(expected)
        );
    }

    /// The rate follows the interval, so it follows the median times too.
    #[test]
    fn txrate_is_the_window_count_over_the_median_time_interval() {
        let ctx = chain_ctx(&TIMES);
        let blocks = 4_usize;
        let final_height = TIMES.len() - 1;
        let past_height = final_height - blocks;

        // Heights `past_height + 1 ..= final_height`, each with height + 1 txs.
        let count: i64 = (past_height + 1..=final_height)
            .map(|height| i64::try_from(height).unwrap_or(0) + 1)
            .sum();
        let interval = i64::from(median_time_past(&TIMES, final_height))
            - i64::from(median_time_past(&TIMES, past_height));

        let result = stats(&ctx, &json!([blocks]));
        assert_eq!(field(&result, "window_tx_count"), Some(count));
        let Some(txrate) = result.get("txrate").and_then(JsonValueTrait::as_f64) else {
            panic!("txrate missing: {result:?}");
        };
        let count_f = i32::try_from(count).unwrap_or(i32::MAX);
        let interval_f = i32::try_from(interval).unwrap_or(i32::MAX);
        assert!(
            (txrate - f64::from(count_f) / f64::from(interval_f)).abs() < f64::EPSILON,
            "got {txrate}"
        );
    }

    /// A window of no blocks is not a window, and Core reports nothing about it.
    ///
    /// The three window fields are absent rather than zero: a zero interval and
    /// a zero count are measurements, and none was taken.
    #[test]
    fn a_zero_block_window_reports_no_window_fields() {
        let result = stats(&chain_ctx(&TIMES), &json!([0]));
        assert_eq!(field(&result, "window_block_count"), Some(0));
        assert!(result.get("window_interval").is_none(), "{result:?}");
        assert!(result.get("window_tx_count").is_none(), "{result:?}");
        assert!(result.get("txrate").is_none(), "{result:?}");
    }

    /// A rate needs a window that advanced. This one does not.
    ///
    /// The count is still reported -- the transactions are real -- but dividing
    /// by a non-positive interval is not a rate, so Core omits it.
    #[test]
    fn txrate_is_omitted_when_the_window_does_not_advance() {
        // Eleven identical times, so every median time in the chain is equal
        // and any window between them is zero seconds long.
        let flat = [1_500_000_u32; 12];
        let result = stats(&chain_ctx(&flat), &json!([3]));
        assert_eq!(field(&result, "window_interval"), Some(0));
        assert!(result.get("window_tx_count").is_some(), "{result:?}");
        assert!(result.get("txrate").is_none(), "{result:?}");
    }

    /// An explicit count that reaches past genesis is refused, not clamped.
    #[test]
    fn a_block_count_past_the_chain_is_refused() {
        let ctx = chain_ctx(&TIMES);
        let height = i64::try_from(TIMES.len()).unwrap_or(0) - 1;
        for requested in [height, height + 1, 10_000] {
            let error = getchaintxstats(&ctx, &json!([requested]))
                .err()
                .unwrap_or_else(|| panic!("a {requested}-block window must be refused"));
            assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER, "{error:?}");
        }
        // One below the height is the largest window that fits.
        assert!(getchaintxstats(&ctx, &json!([height - 1])).is_ok());
    }

    /// A negative count is refused rather than read as an unsigned number.
    #[test]
    fn a_negative_block_count_is_refused() {
        let error = getchaintxstats(&chain_ctx(&TIMES), &json!([-1]))
            .err()
            .unwrap_or_else(|| panic!("a negative window must be refused"));
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
    }

    /// The default window is clamped, because the caller did not choose it.
    ///
    /// Core clamps its own default to `height - 1` and refuses only what a
    /// caller asked for explicitly.
    #[test]
    fn the_default_window_is_clamped_to_the_chain() {
        let result = stats(&chain_ctx(&TIMES), &json!([]));
        let height = i64::try_from(TIMES.len()).unwrap_or(0) - 1;
        assert_eq!(field(&result, "window_block_count"), Some(height));
    }

    /// The window ends where `blockhash` says, not always at the tip.
    #[test]
    fn a_blockhash_selects_the_block_the_window_ends_at() {
        let ctx = chain_ctx(&TIMES);
        let chosen_height = 8_usize;
        let hash = {
            let tree = ctx.block_tree.read();
            let Some(node) = tree.active_node_at_height(u32::try_from(chosen_height).unwrap_or(0))
            else {
                panic!("the fixture has a block at that height");
            };
            node.hash
        };

        let result = stats(&ctx, &json!([2, hash.to_string_be()]));

        assert_eq!(
            field(&result, "window_final_block_height"),
            Some(i64::try_from(chosen_height).unwrap_or(0))
        );
        assert_eq!(
            result
                .get("window_final_block_hash")
                .and_then(JsonValueTrait::as_str),
            Some(hash.to_string_be().as_str())
        );
        assert_eq!(
            field(&result, "time"),
            Some(i64::from(TIMES[chosen_height]))
        );
        let expected = i64::from(median_time_past(&TIMES, chosen_height))
            - i64::from(median_time_past(&TIMES, chosen_height - 2));
        assert_eq!(field(&result, "window_interval"), Some(expected));
        // The cumulative count is known for the applied tip and for no other
        // block, so a window ending elsewhere omits it rather than reporting
        // the tip's total against a different block.
        assert!(result.get("txcount").is_none(), "{result:?}");
    }

    /// A hash the node has never seen is not found.
    #[test]
    fn an_unknown_blockhash_is_not_found() {
        let unknown = Hash256::from_le_bytes(&[0x5c; 32]).to_string_be();
        let error = getchaintxstats(&chain_ctx(&TIMES), &json!([2, unknown]))
            .err()
            .unwrap_or_else(|| panic!("an unknown block must be refused"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    }

    /// A block the node knows but has reorged away from ends no window.
    ///
    /// It keeps its height, so a check that only compared heights would accept
    /// it and then measure a window through a chain that does not exist.
    #[test]
    fn a_blockhash_off_the_active_chain_is_refused() {
        let ctx = chain_ctx(&TIMES);
        let stale = {
            let mut tree = ctx.block_tree.write();
            let Some(parent) = tree.active_node_at_height(3).map(|node| node.hash) else {
                panic!("the fixture has a block at height 3");
            };
            let Some(parent_id) = tree.lookup(parent) else {
                panic!("a node the tree returned must be findable");
            };
            let sibling = header(
                BlockHash::from_byte_array(parent.to_le_bytes()),
                1_002_000,
                9_999,
            );
            let hash = Hash256::from_le_bytes(sibling.block_hash().as_byte_array());
            let _id = tree
                .insert_node(Some(parent_id), sibling, NodeStatus::Stale)
                .unwrap_or_else(|err| panic!("insert_node failed: {err}"));
            hash
        };

        let error = getchaintxstats(&ctx, &json!([2, stale.to_string_be()]))
            .err()
            .unwrap_or_else(|| panic!("a stale block must be refused"));
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
    }

    /// A window the record log does not cover reports no count.
    ///
    /// The log is rebuilt empty on every open, so after a restart the sum over
    /// a window is a fraction of it. Reporting that fraction would read as a
    /// quiet chain, which is what a fee estimator would then believe.
    #[test]
    fn window_tx_count_is_omitted_when_the_log_does_not_cover_the_window() {
        let ctx = chain_ctx(&TIMES);
        ctx.blocks.write().clear();

        let result = stats(&ctx, &json!([4]));

        assert!(result.get("window_interval").is_some(), "{result:?}");
        assert!(result.get("window_tx_count").is_none(), "{result:?}");
        assert!(result.get("txrate").is_none(), "{result:?}");
    }
}
