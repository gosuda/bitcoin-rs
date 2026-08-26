use alloc::sync::Arc;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::DisplayHex as _;
use core::str::FromStr as _;
use core::{fmt, fmt::Write as _};

use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_pruning::policy::CORE_REORG_SAFETY_MARGIN;
use hashbrown::HashMap;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use super::util::{descriptor_checksum, strip_addr_wrapper};
use crate::context::{BlockRecord, ChainControlError, Context, TxQueryError, chain_stats};
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
    // Core's estimate when this node knows how many transactions it has
    // verified, and the old height ratio when it does not.
    //
    // The count is unknown only for a datadir written before the node tracked
    // it: nothing short of re-reading every block body could recover it, so
    // those chains keep the answer they have always had rather than being told
    // a confident 0.0. A node that syncs, or resyncs, after that change always
    // takes the first branch.
    let now = unix_now();
    let verification_progress = ctx.chain_tx_count().map_or_else(
        || {
            if headers > 0 {
                (f64::from(applied) / f64::from(headers)).min(1.0)
            } else {
                0.0
            }
        },
        |chain_tx_count| {
            verification_progress(
                ctx.chain_network,
                chain_tx_count,
                applied,
                headers,
                time,
                now,
            )
        },
    );
    let initialblockdownload = ctx.is_initial_block_download(now);
    let chain = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => "main",
        bitcoin_rs_primitives::Network::Testnet3 => "test",
        bitcoin_rs_primitives::Network::Testnet4 => "testnet4",
        bitcoin_rs_primitives::Network::Signet => "signet",
        bitcoin_rs_primitives::Network::Regtest => "regtest",
    };
    // Bytes on disk, from whatever owns them.
    //
    // The block store knows what its files occupy and shrinks when pruning
    // deletes one. The record log can only offer the sum of the block sizes it
    // has seen: records outlive the bodies they describe, so that sum goes on
    // counting bytes that are gone — under a field name people read to check
    // that pruning worked. It stays as the fallback for a context with no
    // durable storage behind it, which is every test fixture and nothing else.
    //
    // Either way the read is O(1) and the log's lock — the one block
    // application takes to append — is released immediately.
    let size_on_disk = ctx
        .block_storage_disk_usage()
        .unwrap_or_else(|| ctx.blocks.read().size_on_disk());
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
    let _ = response.insert(&"initialblockdownload", initialblockdownload);
    let _ = response.insert(&"chainwork", chainwork.as_str());
    let _ = response.insert(&"size_on_disk", size_on_disk);
    let _ = response.insert(&"pruned", prune_status.pruned);
    if let Some(pruneheight) = prune_status.pruneheight {
        let _ = response.insert(&"pruneheight", pruneheight);
    }
    let _ = response.insert(&"warnings", "");
    Ok(Value::from(response))
}

/// UNIX seconds now.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Bitcoin Core's `GuessVerificationProgress`, as a fraction in `[0, 1]`.
///
/// The quantity is **transactions verified over transactions believed to
/// exist** — not a ratio of heights. Early blocks are nearly empty, so a height
/// ratio reports the chain as most of the way done while most of the work is
/// still ahead; Core moved off height for that reason.
///
/// The denominator cannot be known, so it is extrapolated from the network's
/// pinned [`ChainTxData`] observation at `tx_rate` transactions per second. When
/// the node is already past that observation its own count is used as the
/// baseline instead, which keeps the fraction from sticking at 1.0 forever.
///
/// `tip_time` is the applied tip's block timestamp. When the tip is within two
/// hours of `now`, Core stops trusting that miner-set timestamp and estimates
/// the tip's age from how many blocks the header chain is ahead instead — which
/// also quantizes the answer near 1.0, where people expect to see it settle.
fn verification_progress(
    network: bitcoin_rs_primitives::Network,
    chain_tx_count: u64,
    applied_height: u32,
    header_height: u32,
    tip_time: u64,
    now: u64,
) -> f64 {
    const RECENT_TIP_WINDOW_SECONDS: i64 = 2 * 60 * 60;

    if chain_tx_count == 0 {
        return 0.0;
    }
    let data = network.chain_tx_data();

    let now_signed = i64::try_from(now).unwrap_or(i64::MAX);
    let tip_time_signed = i64::try_from(tip_time).unwrap_or(i64::MAX);
    let block_time = if (now_signed - tip_time_signed).abs() <= RECENT_TIP_WINDOW_SECONDS
        && header_height >= applied_height
    {
        let behind = i64::from(header_height - applied_height);
        let spacing = i64::from(network.target_spacing_seconds());
        now_signed.saturating_sub(behind.saturating_mul(spacing))
    } else {
        tip_time_signed
    };

    let total = if chain_tx_count <= data.tx_count {
        // Still behind the pinned observation: extrapolate forward from it.
        let elapsed = now_signed.saturating_sub(i64::try_from(data.time).unwrap_or(i64::MAX));
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(data.tx_count))
    } else {
        // Past it, so this node's own count is the better baseline. Without
        // this the fraction would pin at 1.0 and stay there.
        let elapsed = now_signed.saturating_sub(block_time);
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(chain_tx_count))
    };
    if total <= 0.0 {
        return 0.0;
    }
    (u64_to_f64(chain_tx_count) / total).clamp(0.0, 1.0)
}

/// `u64` to `f64` without a silent `as` cast, which this crate forbids.
///
/// Exact for every input up to `2^53`; above that the low half rounds, which is
/// inherent to `f64` and is what Bitcoin Core accepts here too.
fn u64_to_f64(value: u64) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;

    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(high).mul_add(TWO_POW_32, f64::from(low))
}

/// [`u64_to_f64`] with a sign; the elapsed times here can run either way.
fn i64_to_f64(value: i64) -> f64 {
    let magnitude = u64_to_f64(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
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
        chain_stats(&blocks_guard, applied_height, lowest_window_height)
    };
    // The chain total comes from the durable counter when the node has one.
    // Folding the record log cannot answer it after a restart: the log is
    // rebuilt empty on every open while the applied tip resumes at its real
    // height, so the sum covers only blocks applied in this process.
    let total_tx_count = ctx.chain_tx_count().unwrap_or(block_stats.total_tx_count);
    let window_tx_count = block_stats.window_tx_count;
    // Likewise the tip's timestamp: the log has no record for a tip restored
    // from a checkpoint, and reported `time: 0` for it. The block tree does.
    let tip_time = applied_tip_block_time(ctx)
        .or(block_stats.tip_time)
        .unwrap_or(0);
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

/// The applied tip's block timestamp, read from the block tree.
///
/// The tree keeps every header it has accepted and is restored in full, so it
/// can answer for a tip the in-process record log never saw. `getblockchaininfo`
/// takes the same route to the same value.
fn applied_tip_block_time(ctx: &Context) -> Option<u32> {
    let tip = ctx.applied_tip.load_full()?;
    let tree = ctx.block_tree.read();
    tree.node(tip.tip_id).ok().map(|node| node.header.time)
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
    let record = ctx
        .block_by_hash(hash)
        .ok_or(RpcError::NotFound("block not found"))?;
    if verbosity == 0 {
        let Some(block_payload_hex) = ctx.block_body_hex(&record) else {
            return Err(RpcError::NotFound("block data pruned"));
        };
        return Ok(json!(block_payload_hex));
    }
    block_json_verbose(ctx, &record, true, verbosity)
}

pub(crate) fn getblockheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbose = optional_bool(params, 1, true)?;
    let record = ctx
        .block_by_hash(hash)
        .ok_or(RpcError::NotFound("block not found"))?;
    if !verbose {
        return Ok(json!(record.header_hex()));
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

pub(crate) fn getindexinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let index_name = if params.is_null() {
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

    match index_name {
        None => {
            let mut indexes = sonic_rs::Object::new();
            if let Some(entry) = txindex_entry {
                let _ = indexes.insert(&"txindex", entry);
            }
            Ok(indexes.into())
        }
        Some("txindex") => {
            Ok(txindex_entry.map_or_else(|| json!({}), |entry| json!({ "txindex": entry })))
        }
        Some(_) => Ok(json!({})),
    }
}

#[derive(Clone, Debug)]
struct ScanScript {
    script_pubkey: bitcoin::ScriptBuf,
    desc: String,
}

pub(crate) fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let action = required_str(params, 0, "action is required")?;
    match action {
        "start" => scantxoutset_addr_scan(ctx, scanobjects_param(params)?),
        "abort" => Ok(json!(false)),
        "status" => Ok(Value::new_null()),
        _ => Err(RpcError::InvalidParams(
            "action must be one of: start, abort, status",
        )),
    }
}

fn scanobjects_param(params: &Value) -> Result<&sonic_rs::Array, RpcError> {
    let array = params_array(params)?;
    let Some(scanobjects) = array.get(1) else {
        return Err(RpcError::InvalidParams(
            "scanobjects are required for scantxoutset start",
        ));
    };
    let scanobjects = scanobjects
        .as_array()
        .ok_or(RpcError::InvalidType("scanobjects must be an array"))?;
    if scanobjects.is_empty() {
        return Err(RpcError::InvalidParams("scanobjects must not be empty"));
    }
    Ok(scanobjects)
}

fn scantxoutset_addr_scan(
    ctx: &Arc<Context>,
    scanobjects: &sonic_rs::Array,
) -> Result<Value, RpcError> {
    let scan_scripts = parse_scan_scripts(ctx.chain_network, scanobjects)?;
    let scripts = scan_scripts
        .iter()
        .map(|scan| scan.script_pubkey.clone())
        .collect::<Vec<_>>();
    let (tip, scan) = ctx.with_stable_chainstate(|| {
        let tip = ctx.applied_tip.load_full();
        let scan = ctx.utxo.scan_script_pubkeys(&scripts);
        (tip, scan)
    });
    let scan = scan.map_err(|error| RpcError::Internal(error.to_string()))?;
    let height = tip.as_ref().map_or(0, |tip| tip.height);
    let bestblock = tip.as_ref().map_or_else(Hash256::default, |tip| tip.hash);
    let (unspents, total_amount) = scan_unspents(&scan, &scan_scripts, height);

    Ok(json!({
        "success": true,
        "txouts": scan.txouts,
        "height": height,
        "bestblock": bestblock.to_string_be(),
        "unspents": unspents,
        "total_amount": bitcoin::Amount::from_sat(total_amount).to_btc()
    }))
}

fn parse_scan_scripts(
    chain_network: bitcoin_rs_primitives::Network,
    scanobjects: &sonic_rs::Array,
) -> Result<Vec<ScanScript>, RpcError> {
    let network = bitcoin_network(chain_network);
    let mut scripts = Vec::with_capacity(scanobjects.len());
    for scanobject in scanobjects {
        let descriptor = scanobject_descriptor(scanobject)?;
        scripts.push(parse_addr_scan_script(descriptor, network)?);
    }
    Ok(scripts)
}

fn scanobject_descriptor(scanobject: &Value) -> Result<&str, RpcError> {
    if let Some(descriptor) = scanobject.as_str() {
        return Ok(descriptor);
    }
    let Some(descriptor) = scanobject.get("desc") else {
        return Err(RpcError::InvalidParams("scan object missing desc"));
    };
    let descriptor = descriptor
        .as_str()
        .ok_or(RpcError::InvalidType("scan object desc must be a string"))?;
    if let Some(range) = scanobject.get("range") {
        validate_scanobject_range(range)?;
    }
    Ok(descriptor)
}

fn validate_scanobject_range(range: &Value) -> Result<(), RpcError> {
    if range.as_u64().is_some() {
        return Ok(());
    }
    let Some(bounds) = range.as_array() else {
        return Err(RpcError::InvalidType(
            "scan object range must be an integer or two-integer array",
        ));
    };
    if bounds.len() != 2 {
        return Err(RpcError::InvalidParams(
            "scan object range array must contain two entries",
        ));
    }
    let Some(start) = bounds.first().and_then(Value::as_u64) else {
        return Err(RpcError::InvalidType(
            "scan object range start must be an integer",
        ));
    };
    let Some(end) = bounds.get(1).and_then(Value::as_u64) else {
        return Err(RpcError::InvalidType(
            "scan object range end must be an integer",
        ));
    };
    if start > end {
        return Err(RpcError::InvalidParams(
            "scan object range start must not exceed end",
        ));
    }
    Ok(())
}

fn parse_addr_scan_script(
    descriptor: &str,
    network: bitcoin::Network,
) -> Result<ScanScript, RpcError> {
    let payload = checked_descriptor_payload(descriptor)?;
    if payload.contains('*') {
        return Err(RpcError::InvalidParams(
            "ranged scantxoutset descriptors are not supported",
        ));
    }
    let Some(address_text) = strip_addr_wrapper(payload) else {
        return Err(RpcError::InvalidParams(
            "unsupported scantxoutset descriptor; only addr() is supported",
        ));
    };
    let Ok(unchecked) = bitcoin::Address::from_str(address_text) else {
        return Err(RpcError::InvalidParams("Address is not valid"));
    };
    let Ok(address) = unchecked.require_network(network) else {
        return Err(RpcError::InvalidParams("Address is not valid"));
    };
    let payload = format!("addr({address})");
    let desc = descriptor_checksum(&payload).map_or_else(
        || payload.clone(),
        |checksum| format!("{payload}#{checksum}"),
    );
    Ok(ScanScript {
        script_pubkey: address.script_pubkey(),
        desc,
    })
}

fn checked_descriptor_payload(descriptor: &str) -> Result<&str, RpcError> {
    let Some((body, checksum)) = descriptor.rsplit_once('#') else {
        return Ok(descriptor);
    };
    let expected = descriptor_checksum(body).ok_or(RpcError::InvalidParams(
        "descriptor contains invalid characters",
    ))?;
    if checksum == expected {
        Ok(body)
    } else {
        Err(RpcError::InvalidParams("descriptor checksum mismatch"))
    }
}

fn scan_unspents(
    scan: &bitcoin_rs_utxo::UtxoScan,
    scan_scripts: &[ScanScript],
    applied_height: u32,
) -> (Vec<Value>, u64) {
    let descs = scan_scripts
        .iter()
        .map(|scan| (scan.script_pubkey.as_bytes(), scan.desc.as_str()))
        .collect::<HashMap<_, _>>();
    let mut total_amount = 0_u64;
    let unspents = scan
        .unspents
        .iter()
        .map(|utxo| {
            total_amount = total_amount.saturating_add(utxo.txout.value.to_sat());
            let desc = descs
                .get(utxo.txout.script_pubkey.as_bytes())
                .copied()
                .unwrap_or("");
            let outpoint = utxo.outpoint;
            let txid = outpoint.txid;
            let vout = outpoint.vout;
            json!({
                "txid": txid.to_string_be(),
                "vout": vout,
                "scriptPubKey": utxo.txout.script_pubkey.as_bytes().to_lower_hex_string(),
                "desc": desc,
                "amount": utxo.txout.value.to_btc(),
                "coinbase": utxo.coinbase,
                "height": utxo.height,
                "confirmations": scan_confirmations(applied_height, utxo.height)
            })
        })
        .collect();
    (unspents, total_amount)
}

fn scan_confirmations(applied_height: u32, output_height: u32) -> u64 {
    if output_height > applied_height {
        0
    } else {
        u64::from(applied_height - output_height) + 1
    }
}

const fn bitcoin_network(chain_network: bitcoin_rs_primitives::Network) -> bitcoin::Network {
    match chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
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

/// The block's depth in the **active chain**, or `-1` when it is not in the
/// active chain at all.
///
/// This is Bitcoin Core's `chain.Contains(pindex) ? chain.Height() -
/// pindex->nHeight + 1 : -1`, and the membership test is the whole point.
/// Height alone cannot answer it: a block that lost a reorg keeps its height,
/// so deriving the answer from height reports a *positive* confirmation count
/// for a block that is no longer in the chain — and anything gating on
/// `confirmations >= N` reads that as buried.
///
/// The chain asked is the **applied** chain, not the header chain. Core's
/// `m_chain` is the connected, fully-validated chain, and header-first sync
/// keeps headers ahead of it; a block whose header is known but which has not
/// been connected is not in it, so it is `-1` rather than `0`.
fn confirmations(ctx: &Context, hash: Hash256, height: u32) -> i64 {
    // Membership and depth must come from the same published applied-tip state.
    let Some(tip) = ctx.applied_tip.load_full() else {
        return -1;
    };
    if height > tip.height {
        return -1;
    }
    let active_hash = if height == tip.height {
        Some(tip.hash)
    } else {
        let tree = ctx.block_tree.read();
        tree.node_at_height_from(tip.tip_id, height)
            .and_then(|id| tree.node(id).ok().map(|node| node.hash))
    };
    if active_hash != Some(hash) {
        return -1;
    }
    i64::from(tip.height)
        .saturating_sub(i64::from(height))
        .saturating_add(1)
}

fn block_json_verbose(
    ctx: &Context,
    record: &BlockRecord,
    include_block_fields: bool,
    verbosity: u64,
) -> Result<Value, RpcError> {
    let header = decode_header(record)?;

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
            "confirmations": confirmations(ctx, record.hash, record.height),
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

    let (block_bytes, block) = decode_block(ctx, record)?;
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
        "confirmations": confirmations(ctx, record.hash, record.height),
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

fn decode_header(record: &BlockRecord) -> Result<bitcoin::block::Header, RpcError> {
    let Some(bytes) = record.header_bytes() else {
        return Err(RpcError::Internal(
            "stored block header is corrupt".to_owned(),
        ));
    };
    deserialize(bytes.as_slice()).map_err(|error| {
        tracing::warn!(
            block_hash = %record.hash.to_string_be(),
            %error,
            "stored block header bytes are invalid"
        );
        RpcError::Internal("stored block header is corrupt".to_owned())
    })
}

fn decode_block(
    ctx: &Context,
    record: &BlockRecord,
) -> Result<(Vec<u8>, bitcoin::Block), RpcError> {
    let Some(bytes) = ctx.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    deserialize(bytes.as_slice())
        .map(|block| (bytes, block))
        .map_err(|error| {
            tracing::warn!(
                block_hash = %record.hash.to_string_be(),
                %error,
                "stored block bytes are invalid"
            );
            RpcError::Internal("stored block body is corrupt".to_owned())
        })
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode, block::Header, block::Version};

    use super::*;
    use crate::context::BlockLog;
    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};

    struct SingleBlockSource {
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: Vec<u8>,
        calls: core::sync::atomic::AtomicUsize,
    }

    struct MultiBlockSource {
        bodies: Vec<(u32, bitcoin_rs_primitives::Hash256, Vec<u8>)>,
    }

    impl crate::context::BlockBodySource for MultiBlockSource {
        fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::Hash256) -> Option<Vec<u8>> {
            self.bodies
                .iter()
                .find(|(h, k, _)| *h == height && *k == hash)
                .map(|(_, _, body)| body.clone())
        }
    }

    impl crate::context::BlockBodySource for SingleBlockSource {
        fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::Hash256) -> Option<Vec<u8>> {
            self.calls
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            (height == self.height && hash == self.hash).then(|| self.body.clone())
        }
    }

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

    /// Makes `ctx` know `block` the way a running node does: header in the block
    /// tree, record in the log.
    ///
    /// A record on its own is not a node's state. `apply_block` puts the header
    /// in the tree first and pushes the record after, through the same handles,
    /// and the record carries no header of its own — the tree is where one
    /// lives. A fixture that pushes only a record is asking `getblock` to answer
    /// from half the state a node would have.
    fn seed_block(ctx: &Arc<Context>, block: &bitcoin::Block, record: BlockRecord) {
        {
            let mut tree = ctx.block_tree.write();
            let _ = tree.insert_node(None, block.header, NodeStatus::Active);
        }
        ctx.add_block(record);
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

    /// Unknown hashes must not produce empty hex or zero-filled block JSON.
    ///
    /// The removed fallback fabricated successful blocks at the current height,
    /// so both verbosity forms returned HTTP-level success for absent identity.
    #[test]
    fn getblock_reports_not_found_for_an_unknown_hash() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::from_le_bytes(&[0xab_u8; 32]).to_string_be();

        for verbosity in [0, 1, 2] {
            assert!(matches!(
                getblock(&ctx, &json!([hash.as_str(), verbosity])),
                Err(RpcError::NotFound("block not found"))
            ));
        }
    }

    /// Unknown hashes must not produce empty hex or zero-filled header JSON.
    ///
    /// The removed fallback made both header response forms look like valid
    /// blocks even though the tree had never seen the requested identity.
    #[test]
    fn getblockheader_reports_not_found_for_an_unknown_hash() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::from_le_bytes(&[0xcd_u8; 32]).to_string_be();

        for verbose in [false, true] {
            assert!(matches!(
                getblockheader(&ctx, &json!([hash.as_str(), verbose])),
                Err(RpcError::NotFound("block not found"))
            ));
        }
    }

    #[test]
    fn getblock_populates_real_header_fields_from_stored_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let ctx = Arc::new(
            Context::new().with_block_body_source(Arc::new(SingleBlockSource {
                height: 0,
                hash: record.hash,
                body: serialize(&genesis),
                calls: core::sync::atomic::AtomicUsize::new(0),
            })),
        );
        let block_hash_hex = record.hash.to_string_be();
        let block_size = u64::try_from(record.body_size)?;
        let tx_count = u64::try_from(record.tx_count)?;
        seed_block(&ctx, &genesis, record);

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

        impl crate::context::BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                (height == self.height && hash == self.hash).then(|| self.body.clone())
            }
        }

        let genesis = genesis_block(bitcoin::Network::Regtest);
        let body = bitcoin::consensus::encode::serialize(&genesis);
        let record = BlockRecord::from_block(0, &genesis);
        let block_hash_hex = record.hash.to_string_be();
        let source = Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: body.clone(),
            calls: AtomicUsize::new(0),
        });
        let calls = Arc::clone(&source);
        let ctx = Arc::new(Context::new().with_block_body_source(source));
        seed_block(&ctx, &genesis, record);

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
    /// Corrupt cached body bytes must not become synthetic zero-valued JSON.
    ///
    /// The old decode fallback hid storage corruption behind a successful block
    /// response, preventing callers from distinguishing damage from real data.
    #[test]
    fn getblock_reports_corrupt_stored_body() {
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let hash = record.hash.to_string_be();
        let ctx = Arc::new(
            Context::new().with_block_body_source(Arc::new(SingleBlockSource {
                height: 0,
                hash: record.hash,
                body: vec![0x00],
                calls: core::sync::atomic::AtomicUsize::new(0),
            })),
        );
        seed_block(&ctx, &genesis, record);

        assert!(matches!(
            getblock(&ctx, &json!([hash.as_str(), 1])),
            Err(RpcError::Internal(message))
                if message == "stored block body is corrupt"
        ));
    }

    #[test]
    fn getblock_verbosity_2_emits_tx_object_per_transaction() {
        use bitcoin::Network;
        use bitcoin::hashes::Hash as _;

        let genesis = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let ctx = Arc::new(
            Context::new().with_block_body_source(Arc::new(SingleBlockSource {
                height: 0,
                hash: record.hash,
                body: serialize(&genesis),
                calls: core::sync::atomic::AtomicUsize::new(0),
            })),
        );
        seed_block(&ctx, &genesis, record);
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

    /// A genesis, an applied child at height 1, and a competing branch off the
    /// same genesis whose *header* chain reaches height 2.
    ///
    /// ```text
    ///   genesis ──> applied            (height 1, the applied tip)
    ///           └─> fork ──> fork_tip  (heights 1 and 2, headers only)
    /// ```
    ///
    /// `fork` sits at height 1 exactly like `applied` does, which is the state
    /// a height-only confirmation count cannot tell apart.
    struct Fork {
        ctx: Arc<Context>,
        /// Height 1, on the applied chain.
        applied: Hash256,
        /// Height 1 as well, on the branch that lost.
        fork: Hash256,
        /// Height 2, header-only — never connected.
        header_tip: Hash256,
        /// The headers behind `applied` and `fork`, so a test can build log
        /// records that actually decode.
        applied_header: bitcoin::block::Header,
        fork_header: bitcoin::block::Header,
    }

    fn forked_ctx() -> Result<Fork, Box<dyn std::error::Error>> {
        use bitcoin::block::Version;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
        use bitcoin_rs_chain::NodeStatus;

        let ctx = Context::new();
        let header = |prev: BlockHash, nonce: u32, time: u32| bitcoin::block::Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        };

        let (applied_tip, header_tip, fork_hash, applied_header, fork_header) = {
            let mut tree = ctx.block_tree.write();
            let genesis = header(BlockHash::all_zeros(), 0, 1_000_000);
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

            let applied = header(genesis.block_hash(), 1, 1_000_900);
            let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
            assert_eq!(applied_tip.tip_id, applied_id);

            let fork = header(genesis.block_hash(), 2, 1_000_901);
            let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
            let fork_hash = tree.node(fork_id)?.hash;
            let fork_tip = header(fork.block_hash(), 3, 1_001_800);
            let _header_tip_id =
                tree.insert_node(Some(fork_id), fork_tip, NodeStatus::HeaderValid)?;
            let header_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing header tip"))?;
            (applied_tip, header_tip, fork_hash, applied, fork)
        };

        ctx.set_applied_tip((*applied_tip).clone());
        ctx.set_chain_tip((*header_tip).clone());
        Ok(Fork {
            ctx: Arc::new(ctx),
            applied: applied_tip.hash,
            fork: fork_hash,
            header_tip: header_tip.hash,
            applied_header,
            fork_header,
        })
    }

    #[test]
    fn confirmations_uses_applied_height_not_header_tip() -> Result<(), Box<dyn std::error::Error>>
    {
        let Fork {
            ctx,
            applied: applied_hash,
            ..
        } = forked_ctx()?;

        // Header tip is height 2, applied tip height 1. The applied block is one
        // deep, not two: the header chain does not count.
        assert_eq!(confirmations(&ctx, applied_hash, 1), 1);
        Ok(())
    }

    #[test]
    fn confirmations_is_negative_one_for_a_block_that_lost_the_reorg()
    -> Result<(), Box<dyn std::error::Error>> {
        let Fork {
            ctx,
            applied: applied_hash,
            fork: fork_hash,
            ..
        } = forked_ctx()?;

        assert_ne!(applied_hash, fork_hash, "the fixture branches must differ");
        // Same height as the applied block, different chain. Deriving the answer
        // from height alone reports 1 here, which says "in the chain, one deep".
        assert_eq!(
            confirmations(&ctx, fork_hash, 1),
            -1,
            "a block off the applied chain is not in it at any depth"
        );
        Ok(())
    }

    #[test]
    fn confirmations_is_negative_one_for_a_header_above_the_applied_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let Fork {
            ctx,
            header_tip: header_tip_hash,
            ..
        } = forked_ctx()?;

        // Known header, never connected. Core's m_chain does not contain it.
        assert_eq!(confirmations(&ctx, header_tip_hash, 2), -1);
        Ok(())
    }
    /// Header-only tree nodes remain addressable even without a log record.
    ///
    /// Rejecting unknown identities must not accidentally require active-chain
    /// membership or a body: this fork header is known but not applied.
    #[test]
    fn getblockheader_answers_a_header_only_tree_node() -> Result<(), Box<dyn std::error::Error>> {
        let Fork {
            ctx,
            fork,
            fork_header,
            ..
        } = forked_ctx()?;
        let hash = fork.to_string_be();

        let raw = getblockheader(&ctx, &json!([hash.as_str(), false]))?;
        assert_eq!(
            raw.as_str(),
            Some(serialize(&fork_header).to_lower_hex_string().as_str())
        );

        let verbose = getblockheader(&ctx, &json!([hash.as_str(), true]))?;
        assert_eq!(verbose.get("hash").as_str(), Some(hash.as_str()));
        assert_eq!(verbose.get("confirmations").as_i64(), Some(-1));
        assert_eq!(verbose.get("height").as_u64(), Some(1));
        assert_eq!(
            verbose.get("version").as_i64(),
            Some(i64::from(fork_header.version.to_consensus()))
        );
        assert_eq!(
            verbose.get("merkleroot").as_str(),
            Some(fork_header.merkle_root.to_string().as_str())
        );
        assert_eq!(
            verbose.get("time").as_u64(),
            Some(u64::from(fork_header.time))
        );
        assert_eq!(
            verbose.get("nonce").as_u64(),
            Some(u64::from(fork_header.nonce))
        );
        assert_eq!(verbose.get("nTx").as_u64(), Some(0));
        Ok(())
    }

    #[test]
    fn confirmations_is_negative_one_for_a_hash_the_tree_never_saw()
    -> Result<(), Box<dyn std::error::Error>> {
        let Fork { ctx, .. } = forked_ctx()?;
        let unknown = Hash256::from_le_bytes(&[0xab_u8; 32]);

        assert_eq!(confirmations(&ctx, unknown, 1), -1);
        Ok(())
    }

    /// A log record for `header`, either carrying the block or standing in for
    /// one whose body the node no longer has.
    fn record_for(header: bitcoin::block::Header, with_body: bool) -> BlockRecord {
        use bitcoin::hashes::Hash as _;

        let hash = Hash256::from_le_bytes(header.block_hash().as_byte_array());
        if !with_body {
            return BlockRecord::synthetic(1, hash);
        }
        let block = bitcoin::Block {
            header,
            txdata: Vec::new(),
        };
        BlockRecord::from_block(1, &block)
    }

    /// `getblock` and `getblockheader` both render `confirmations` when a body
    /// is available. A pruned body still leaves enough tree state for
    /// `getblockheader`, while Core-compatible `getblock` rejects that request
    /// as unavailable. The body-less fixture therefore checks the header RPC;
    /// the complete fixture checks both rendering paths.
    fn assert_reorged_block_reports_negative_confirmations(
        with_body: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Fork {
            mut ctx,
            applied: applied_hash,
            fork: fork_hash,
            applied_header,
            fork_header,
            ..
        } = forked_ctx()?;
        let applied_record = record_for(applied_header, with_body);
        let fork_record = record_for(fork_header, with_body);
        if with_body {
            let applied_block = bitcoin::Block {
                header: applied_header,
                txdata: Vec::new(),
            };
            let fork_block = bitcoin::Block {
                header: fork_header,
                txdata: Vec::new(),
            };
            Arc::get_mut(&mut ctx)
                .expect("unique fork fixture context")
                .block_body_source = Some(Arc::new(MultiBlockSource {
                bodies: vec![
                    (
                        applied_record.height,
                        applied_record.hash,
                        bitcoin::consensus::encode::serialize(&applied_block),
                    ),
                    (
                        fork_record.height,
                        fork_record.hash,
                        bitcoin::consensus::encode::serialize(&fork_block),
                    ),
                ],
            }));
        }
        ctx.add_block(applied_record);
        ctx.add_block(fork_record);

        let handler = crate::Handler::new(Arc::clone(&ctx));
        let confirmations_of =
            |method: &str, hash: Hash256| -> Result<i64, Box<dyn std::error::Error>> {
                let value = handler.dispatch(method, &json!([hash.to_string_be(), true]))?;
                value
                    .get("confirmations")
                    .and_then(JsonValueTrait::as_i64)
                    .ok_or_else(|| {
                        Box::<dyn std::error::Error>::from(format!(
                            "confirmations missing or not an integer: {value:?}"
                        ))
                    })
            };

        let methods = if with_body {
            &["getblockheader", "getblock"][..]
        } else {
            &["getblockheader"][..]
        };
        for method in methods {
            assert_eq!(confirmations_of(method, applied_hash)?, 1, "{method}");
            assert_eq!(
                confirmations_of(method, fork_hash)?,
                -1,
                "{method} must carry the -1 through, not clamp it"
            );
        }
        if !with_body {
            for hash in [applied_hash, fork_hash] {
                assert!(matches!(
                    handler.dispatch("getblock", &json!([hash.to_string_be(), true])),
                    Err(RpcError::NotFound("block data pruned"))
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn reorged_block_reports_negative_confirmations_with_the_block_stored()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_reorged_block_reports_negative_confirmations(true)
    }

    #[test]
    fn reorged_block_reports_negative_confirmations_without_the_block_stored()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_reorged_block_reports_negative_confirmations(false)
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

    /// Regtest's pinned observation is `{time: 0, tx_count: 0, tx_rate: 0.001}`,
    /// so the estimate reduces to arithmetic that can be done by hand:
    /// `total = verified + elapsed * 0.001`.
    #[test]
    fn verification_progress_is_transactions_verified_over_transactions_estimated() {
        let now = 1_800_000_000_u64;
        // Ten thousand seconds behind, which is outside the two-hour window, so
        // the tip's own timestamp is the one used.
        let tip_time = now - 10_000;

        // 100 / (100 + 10_000 * 0.001) = 100 / 110
        let progress = verification_progress(
            bitcoin_rs_primitives::Network::Regtest,
            100,
            9,
            9,
            tip_time,
            now,
        );
        assert!(
            (progress - (100.0 / 110.0)).abs() < 1e-12,
            "expected 100/110, got {progress}"
        );
    }

    #[test]
    fn verification_progress_is_not_the_height_ratio_it_replaced() {
        let now = 1_800_000_000_u64;
        // Half the headers applied, on a mainnet whose pinned observation counts
        // more than a billion transactions. The old field said 0.5 here.
        let progress = verification_progress(
            bitcoin_rs_primitives::Network::Mainnet,
            5_000,
            50,
            100,
            now - 10_000,
            now,
        );
        assert!(
            progress < 0.001,
            "50 blocks of a 1.3-billion-transaction chain is not half of it, got {progress}"
        );
    }

    #[test]
    fn verification_progress_ignores_the_tip_timestamp_when_the_tip_is_recent() {
        let now = 1_800_000_000_u64;
        // Both inside the two-hour window: Core stops trusting the miner-set
        // timestamp there and derives the tip's age from the header chain, so
        // these must agree despite an hour between them.
        let a = verification_progress(
            bitcoin_rs_primitives::Network::Regtest,
            100,
            9,
            10,
            now - 60,
            now,
        );
        let b = verification_progress(
            bitcoin_rs_primitives::Network::Regtest,
            100,
            9,
            10,
            now - 3_600,
            now,
        );
        let boundary = verification_progress(
            bitcoin_rs_primitives::Network::Regtest,
            100,
            9,
            10,
            now - 2 * 60 * 60,
            now,
        );
        assert!((a - b).abs() < 1e-12, "{a} != {b}");
        assert!(
            (a - boundary).abs() < 1e-12,
            "Core includes the exact two-hour boundary: {a} != {boundary}"
        );

        // Outside the window the timestamp is used again, so this one differs.
        let outside = verification_progress(
            bitcoin_rs_primitives::Network::Regtest,
            100,
            9,
            10,
            now - 100_000,
            now,
        );
        assert!(outside < a, "{outside} should trail {a}");
    }

    #[test]
    fn verification_progress_is_zero_before_anything_is_verified() {
        assert!(
            (verification_progress(
                bitcoin_rs_primitives::Network::Mainnet,
                0,
                0,
                0,
                0,
                1_800_000_000
            ) - 0.0)
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn verification_progress_never_exceeds_one_for_a_future_dated_tip() {
        let now = 1_800_000_000_u64;
        // A miner-set timestamp ahead of our clock by more than the two-hour
        // window, so the tip's own time is used and the elapsed term goes
        // negative — the estimated total lands *below* what this node has
        // already verified. Unclamped that is a progress above 1.0.
        let tip_time = now + 10_000;
        let unclamped_total = 10_000.0_f64.mul_add(-0.001, 100.0_f64);
        assert!(
            100.0 / unclamped_total > 1.0,
            "the fixture must actually overshoot, or the clamp is untested"
        );

        let progress = verification_progress(
            bitcoin_rs_primitives::Network::Regtest,
            100,
            9,
            10,
            tip_time,
            now,
        );
        assert!((progress - 1.0).abs() < f64::EPSILON, "got {progress}");
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
    fn verificationprogress_is_capped_when_applied_tip_is_temporarily_higher() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::from_le_bytes(&[8_u8; 32]);
        ctx.set_chain_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 50,
            chainwork: ChainWork::ZERO,
            hash,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 100,
            chainwork: ChainWork::ZERO,
            hash,
        });

        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        assert_eq!(
            result
                .get("verificationprogress")
                .and_then(JsonValueTrait::as_f64),
            Some(1.0)
        );
    }

    #[test]
    fn getblockchaininfo_names_testnet4_separately_from_testnet3() {
        let mut context = Context::new();
        context.chain_network = bitcoin_rs_primitives::Network::Testnet4;
        let result = getblockchaininfo(&Arc::new(context), &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

        assert_eq!(
            result.get("chain").and_then(JsonValueTrait::as_str),
            Some("testnet4")
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
        let record = BlockRecord::from_block(0, &genesis);
        let ctx = Arc::new(Context::new());
        ctx.add_block(record);

        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

        assert_eq!(
            result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
            Some(u64::try_from(body.len()).unwrap_or(u64::MAX))
        );
    }

    /// `size_on_disk` reports what the block store says, not the record sum.
    ///
    /// The record sum keeps counting blocks whose bytes pruning has deleted, so
    /// it cannot be what a field named "size on disk" reports. This gives the
    /// context a store that answers with a figure deliberately unrelated to the
    /// records, so a handler that quietly went on summing them fails here rather
    /// than looking right by coincidence.
    #[test]
    fn getblockchaininfo_size_on_disk_comes_from_the_block_store() {
        struct SizedStore(u64);

        impl crate::context::BlockBodySource for SizedStore {
            fn block_body(&self, _height: u32, _hash: Hash256) -> Option<Vec<u8>> {
                None
            }
            fn disk_usage(&self) -> Option<u64> {
                Some(self.0)
            }
        }

        let genesis = genesis_block(bitcoin::Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let record_bytes = u64::try_from(record.body_size).unwrap_or(u64::MAX);
        let store_bytes = record_bytes.saturating_add(4_096);
        let ctx =
            Arc::new(Context::new().with_block_body_source(Arc::new(SizedStore(store_bytes))));
        ctx.add_block(record);

        let result = getblockchaininfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));

        assert_eq!(
            result.get("size_on_disk").and_then(JsonValueTrait::as_u64),
            Some(store_bytes),
            "size_on_disk must come from the store that owns the bytes"
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

    /// A log with every shape the windowed search has to survive.
    ///
    /// Heights are non-decreasing, which is the invariant the binary searches
    /// rest on, but they are not a clean `0..n`: height 3 is recorded twice, as
    /// a reorg leaves it, so the "first record at this height" and
    /// "records at or below this height" boundaries are not the same thing.
    /// Timestamps dip at height 5, because block times are not monotonic and an
    /// earliest-in-window that assumed they were would be wrong there.
    fn shaped_log() -> BlockLog {
        const HEIGHTS: [u32; 10] = [0, 1, 2, 3, 3, 4, 5, 6, 7, 8];
        const TIMES: [u32; 10] = [
            1_000, 1_010, 1_020, 1_030, 1_031, 1_040, 1_035, 1_060, 1_070, 1_080,
        ];
        let mut log = BlockLog::new();
        for (index, (height, time)) in HEIGHTS.into_iter().zip(TIMES).enumerate() {
            log.push(BlockRecord {
                hash: Hash256::from_le_bytes(&[u8::try_from(index).unwrap_or(0); 32]),
                height,
                body_size: 100 + index * 7,
                header: None,
                tx_count: 1 + index * 3,
                time,
            });
        }
        log
    }

    /// `chain_stats` figures, pinned to values computed by hand from
    /// `shaped_log`. The log records height 3 twice (reorg shape), so the
    /// applied-tip boundary, the first-at-height tip time, and the window
    /// boundary are three different indices.
    ///
    /// Catches treating a duplicate applied height as one record or choosing
    /// its last timestamp rather than its first.
    #[test]
    fn chain_stats_at_the_duplicate_height() {
        let log = shaped_log();
        // applied=3, window from height 2: end = 5 (indices 0..=4 are <= 3),
        // tip is the FIRST record at height 3 (time 1030, not 1031), window
        // covers indices 2..=4.
        let stats = chain_stats(&log, 3, 2);
        assert_eq!(stats.total_tx_count, 1 + 4 + 7 + 10 + 13);
        assert_eq!(stats.window_tx_count, 7 + 10 + 13);
        assert_eq!(stats.tip_time, Some(1_030));
        assert_eq!(stats.earliest_window_time, Some(1_020));
    }

    /// Catches counting records above the applied tip in the total or window.
    #[test]
    fn chain_stats_applied_tip_bounds_exclude_records_above_the_tip() {
        let log = shaped_log();
        // applied=4, whole-chain window: indices 5..=9 (tx 19+22+25+28) sit
        // above the tip and must not leak into either count.
        let stats = chain_stats(&log, 4, 0);
        assert_eq!(stats.total_tx_count, 1 + 4 + 7 + 10 + 13 + 16);
        assert_eq!(stats.window_tx_count, 1 + 4 + 7 + 10 + 13 + 16);
        assert_eq!(stats.tip_time, Some(1_040));
        assert_eq!(stats.earliest_window_time, Some(1_000));
    }

    /// Catches using the first window timestamp instead of its true minimum.
    #[test]
    fn chain_stats_earliest_window_time_survives_non_monotonic_timestamps() {
        let log = shaped_log();
        // applied=8 (whole log), window from height 4: the window's earliest
        // time is 1035 at height 5, INSIDE the window — an implementation that
        // assumed times rise with height would answer 1040 (the window front).
        let stats = chain_stats(&log, 8, 4);
        assert_eq!(stats.total_tx_count, 145);
        assert_eq!(stats.window_tx_count, 16 + 19 + 22 + 25 + 28);
        assert_eq!(stats.tip_time, Some(1_080));
        assert_eq!(stats.earliest_window_time, Some(1_035));
    }

    /// Catches exclusive lower bounds, nonempty zero windows, and failures to
    /// handle sparse applied heights beyond the log without panicking.
    #[test]
    fn chain_stats_at_the_log_edges() {
        let log = shaped_log();
        // Window entirely above the applied tip: empty, never a panic.
        let stats = chain_stats(&log, 8, 9);
        assert_eq!(stats.total_tx_count, 145);
        assert_eq!(stats.window_tx_count, 0);
        assert_eq!(stats.tip_time, Some(1_080));
        assert_eq!(stats.earliest_window_time, None);
        // Applied tip past the end of the log: everything counts, no tip time.
        let stats = chain_stats(&log, 10, 0);
        assert_eq!(stats.total_tx_count, 145);
        assert_eq!(stats.window_tx_count, 145);
        assert_eq!(stats.tip_time, None);
        assert_eq!(stats.earliest_window_time, Some(1_000));
        // Applied tip at the log's first record.
        let stats = chain_stats(&log, 0, 0);
        assert_eq!(stats.total_tx_count, 1);
        assert_eq!(stats.window_tx_count, 1);
        assert_eq!(stats.tip_time, Some(1_000));
        assert_eq!(stats.earliest_window_time, Some(1_000));
    }

    /// The running sums are the log's only aggregates; push, pop, clear and the
    /// `tx_count_before` clamp are pinned to hand-computed fixture values.
    ///
    /// Catches stale totals after disconnect or clear and an unclamped prefix
    /// lookup that panics when the requested count exceeds the log length.
    #[test]
    fn block_log_running_sums_track_push_pop_and_clear() {
        let mut log = shaped_log();
        assert_eq!(log.size_on_disk(), 1_315);
        assert_eq!(log.total_tx_count(), 145);
        assert_eq!(log.tx_count_before(4), 1 + 4 + 7 + 10);
        assert_eq!(log.tx_count_before(0), 0);
        // `count` is clamped to the log's length rather than panicking.
        assert_eq!(log.tx_count_before(usize::MAX), 145);

        // The disconnect path: popping the tip takes its bytes and txs back out.
        let _popped = log.pop();
        assert_eq!(log.size_on_disk(), 1_315 - 163);
        assert_eq!(log.total_tx_count(), 145 - 28);
        assert_eq!(log.tx_count_before(usize::MAX), 145 - 28);

        log.clear();
        assert_eq!(log.size_on_disk(), 0, "clear must reset the running sums");
        assert_eq!(log.total_tx_count(), 0, "clear must reset the running sums");
    }

    /// The running sums must use saturating `u64` addition.
    ///
    /// A previous implementation wrapped the body-size and tx-count totals
    /// on the very next push after saturation (`u64::MAX + 1` became `0`).
    /// The max-sized first push and the following `+1` push together catch
    /// that concrete wrapping bug.
    #[test]
    fn block_log_running_sums_saturate_instead_of_wrapping() {
        let max = usize::try_from(u64::MAX).unwrap_or(usize::MAX);
        let record = |body_size: usize, tx_count: usize| BlockRecord {
            hash: Hash256::from_le_bytes(&[0_u8; 32]),
            height: 0,
            body_size,
            header: None,
            tx_count,
            time: 0,
        };
        let mut log = BlockLog::new();
        log.push(record(max, max));
        assert_eq!(log.size_on_disk(), u64::MAX);
        assert_eq!(log.total_tx_count(), u64::MAX);
        // A second push must not wrap the sums back to small values.
        log.push(record(1, 1));
        assert_eq!(log.size_on_disk(), u64::MAX);
        assert_eq!(log.total_tx_count(), u64::MAX);
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
                body_size: usize::try_from(100_u32.saturating_add(height))?,
                header: None,
                tx_count: usize::try_from(height.saturating_add(1))?,
                time: 1_000_u32.saturating_add(height.saturating_mul(10)),
            });
        }
        ctx.add_block(BlockRecord {
            hash: Hash256::from_le_bytes(&[4_u8; 32]),
            height: 4,
            body_size: 104,
            header: None,
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
            body_size: 100,
            header: None,
            tx_count: 1,
            time: 200,
        });
        ctx.add_block(BlockRecord {
            hash: Hash256::from_le_bytes(&[7_u8; 32]),
            height: 2,
            body_size: 100,
            header: None,
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
    use bitcoin::hashes::Hash as _;
    use bitcoin::{TxMerkleNode, block::Header, block::Version};

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
    fn getblock_returns_pruned_error_for_a_header_only_block() {
        let ctx = Arc::new(Context::new());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = {
            let mut tree = ctx.block_tree.write();
            let id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("genesis header must insert: {err}"));
            tree.node(id)
                .unwrap_or_else(|err| panic!("inserted header must resolve: {err}"))
                .hash
        };

        for verbosity in [0, 1] {
            assert!(matches!(
                getblock(&ctx, &json!([hash.to_string_be(), verbosity])),
                Err(RpcError::NotFound("block data pruned"))
            ));
        }
    }

    #[test]
    fn getblockstats_reports_pruned_error_for_a_header_only_block() {
        let ctx = Arc::new(Context::new());
        let applied_tip = {
            let mut tree = ctx.block_tree.write();
            let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let genesis_id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("genesis header must insert: {err}"));
            let child = Header {
                version: Version::ONE,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: genesis.header.time.saturating_add(1),
                bits: genesis.header.bits,
                nonce: genesis.header.nonce.saturating_add(1),
            };
            let _ = tree
                .insert_node(Some(genesis_id), child, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("child header must insert: {err}"));
            tree.tip()
                .unwrap_or_else(|| panic!("inserted child must publish a tip"))
        };
        ctx.set_applied_tip((*applied_tip).clone());

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
    fn txcount_falls_back_to_the_log_when_the_counter_is_unknown() {
        let ctx = restarted_ctx(None);
        // The log must hold something, or "fell back to the fold" and "reported
        // zero" are the same observation and this proves neither.
        let Some(tip) = ctx.applied_tip.load_full() else {
            panic!("fixture has no applied tip");
        };
        ctx.add_block(BlockRecord {
            hash: tip.hash,
            height: tip.height,
            body_size: 0,
            header: None,
            tx_count: 7,
            time: TIP_TIME,
        });

        assert_eq!(
            stats_of(&ctx)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(7),
            "an unknown counter must leave the old fold answering, not report zero"
        );
    }

    #[test]
    fn txcount_is_zero_when_neither_the_counter_nor_the_log_knows() {
        assert_eq!(
            stats_of(&restarted_ctx(None))
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(0),
            "it must not invent a count it does not have"
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
mod verification_progress_wiring_tests {
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicU64;

    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
    use bitcoin_rs_primitives::Hash256;
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    /// Applied at height 50 of a 100-header chain, so the height ratio is
    /// exactly 0.5 and any answer that is not 0.5 cannot have come from it.
    fn half_applied_ctx(chain_tx_count: Option<u64>) -> Arc<Context> {
        let ctx = Context::new();
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
        let ctx = match chain_tx_count {
            Some(count) => ctx.with_chain_tx_count(Arc::new(AtomicU64::new(count))),
            None => ctx,
        };
        Arc::new(ctx)
    }

    fn progress_of(ctx: &Arc<Context>) -> f64 {
        let result = getblockchaininfo(ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getblockchaininfo failed: {err}"));
        let Some(progress) = result
            .get("verificationprogress")
            .and_then(JsonValueTrait::as_f64)
        else {
            panic!("verificationprogress missing: {result:?}");
        };
        progress
    }

    #[test]
    fn a_known_count_is_answered_with_cores_estimate_not_the_height_ratio() {
        // 5000 transactions against mainnet's billion-transaction observation is
        // nowhere near half the chain, whatever the heights say.
        let progress = progress_of(&half_applied_ctx(Some(5_000)));
        assert!(
            progress < 0.001,
            "expected Core's transaction-count estimate, got {progress}"
        );
    }

    #[test]
    fn an_unknown_count_keeps_the_height_ratio_rather_than_reporting_zero() {
        // A datadir written before the node tracked the count. Reporting 0.0
        // here would break every caller that gates on `verificationprogress`,
        // which is why the fallback exists at all.
        let progress = progress_of(&half_applied_ctx(None));
        assert!(
            (progress - 0.5).abs() < 1e-9,
            "expected the height ratio, got {progress}"
        );
    }
}

#[cfg(test)]
mod float_conversion_tests {
    use super::{i64_to_f64, u64_to_f64};

    #[test]
    fn u64_to_f64_is_exact_below_two_to_the_fifty_third() {
        for value in [
            0_u64,
            1,
            4_294_967_295,
            4_294_967_296,
            1_315_805_869,
            1 << 52,
        ] {
            // Independently derived: the halves recombined by hand.
            let expected = f64::from(u32::try_from(value >> 32).unwrap_or(u32::MAX))
                * 4_294_967_296.0_f64
                + f64::from(u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX));
            assert!(
                (u64_to_f64(value) - expected).abs() < f64::EPSILON,
                "{value}"
            );
        }
    }

    #[test]
    fn i64_to_f64_carries_the_sign() {
        assert!((i64_to_f64(-3_600) + 3_600.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(3_600) - 3_600.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(0) - 0.0).abs() < f64::EPSILON);
    }
}

#[cfg(test)]
mod initial_block_download_tests {
    use alloc::sync::Arc;

    use bitcoin::block::Version;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Network;

    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    /// A context whose applied tip is a real tree node stamped `tip_time`, so
    /// the tip has an age to be judged on. Chain work comes from the tree's own
    /// accounting, which for a two-block regtest chain is far below any
    /// production `nMinimumChainWork` — hence the network parameter: regtest
    /// pins that floor at zero, mainnet does not.
    fn ctx_with_tip_at(network: Network, tip_time: u32) -> Arc<Context> {
        let mut ctx = Context::new();
        ctx.chain_network = network;
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
                time: tip_time,
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
        Arc::new(ctx)
    }

    #[test]
    fn a_node_that_has_applied_nothing_is_in_initial_block_download() {
        let ctx = Arc::new(Context::new());
        assert!(ctx.is_initial_block_download(1_800_000_000));
    }

    #[test]
    fn a_recent_tip_without_the_networks_minimum_work_is_still_initial_block_download() {
        let now = 1_800_000_000_u64;
        // Timestamped one minute ago, so recency is satisfied and only the work
        // floor can be what decides. A two-block regtest-difficulty chain has
        // nowhere near mainnet's `nMinimumChainWork`.
        let ctx = ctx_with_tip_at(
            Network::Mainnet,
            u32::try_from(now - 60).unwrap_or(u32::MAX),
        );
        assert!(
            ctx.is_initial_block_download(now),
            "a chain this cheap must not count as synced merely for being recent"
        );
    }

    #[test]
    fn a_stale_tip_with_enough_work_is_still_initial_block_download() {
        let now = 1_800_000_000_u64;
        // Regtest's work floor is zero, so only the tip's age is left to decide.
        let ctx = ctx_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY - 60).unwrap_or(u32::MAX),
        );
        assert!(ctx.is_initial_block_download(now));
    }

    #[test]
    fn a_recent_tip_with_enough_work_has_left_initial_block_download() {
        let now = 1_800_000_000_u64;
        let ctx = ctx_with_tip_at(
            Network::Regtest,
            u32::try_from(now - 60).unwrap_or(u32::MAX),
        );
        assert!(!ctx.is_initial_block_download(now));
    }

    #[test]
    fn the_tip_age_boundary_is_twenty_four_hours() {
        let now = 1_800_000_000_u64;
        let at_the_edge = ctx_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY).unwrap_or(u32::MAX),
        );
        assert!(
            !at_the_edge.is_initial_block_download(now),
            "exactly `max_tip_age` old is still recent enough"
        );

        let past_the_edge = ctx_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY - 1).unwrap_or(u32::MAX),
        );
        assert!(past_the_edge.is_initial_block_download(now));
    }

    #[test]
    fn leaving_initial_block_download_latches() {
        let now = 1_800_000_000_u64;
        let ctx = ctx_with_tip_at(
            Network::Regtest,
            u32::try_from(now - 60).unwrap_or(u32::MAX),
        );
        assert!(!ctx.is_initial_block_download(now));

        // Two days later, with no new block. Judged afresh the tip is stale and
        // the answer would flip back to `true`; latched, it does not. This is
        // the defect the field had — it went true again every time the node went
        // quiet, and callers read that as "resyncing, do not trust me".
        assert!(
            !ctx.is_initial_block_download(now + 2 * DAY),
            "the answer must not flip back once the node has left initial sync"
        );
    }

    #[test]
    fn the_latch_does_not_fire_before_the_conditions_are_met() {
        let now = 1_800_000_000_u64;
        let ctx = ctx_with_tip_at(
            Network::Regtest,
            u32::try_from(now - DAY - 60).unwrap_or(u32::MAX),
        );
        assert!(ctx.is_initial_block_download(now));
        // Same tip, asked later at a time when it *is* within the window.
        assert!(!ctx.is_initial_block_download(now - DAY));
    }
}

#[cfg(test)]
mod scantxoutset_tests {
    use alloc::sync::Arc;
    use core::str::FromStr as _;

    use bitcoin::{Amount, ScriptBuf};
    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use sonic_rs::JsonValueTrait as _;

    use super::*;

    fn test_txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(7).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(17).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(99).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn commit_test_utxo(
        ctx: &Context,
        outpoint: OutPoint,
        txout: TxOut,
        coinbase: bool,
        height: u32,
    ) {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
        ctx.utxo
            .commit_block(&changes, &test_txid(8_000))
            .unwrap_or_else(|err| panic!("commit utxo failed: {err}"));
    }

    #[test]
    fn scantxoutset_addr_returns_matching_unspents() {
        let ctx = Arc::new(Context::new());
        let address = "1111111111111111111114oLvT2";
        let script = bitcoin::Address::from_str(address)
            .unwrap_or_else(|err| panic!("address parse failed: {err}"))
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap_or_else(|err| panic!("network check failed: {err}"))
            .script_pubkey();
        let txout = TxOut {
            value: Amount::from_sat(12_345),
            script_pubkey: script.clone(),
        };
        let outpoint = OutPoint::new(test_txid(11), 0);
        commit_test_utxo(&ctx, outpoint, txout, true, 0);
        commit_test_utxo(
            &ctx,
            OutPoint::new(test_txid(12), 0),
            TxOut {
                value: Amount::from_sat(9_999),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            false,
            0,
        );

        let result = scantxoutset(&ctx, &json!(["start", [format!("addr({address})")]]))
            .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        let Some(unspents) = result.get("unspents").and_then(Value::as_array) else {
            panic!("unspents missing: {result:?}");
        };

        assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(2));
        assert_eq!(
            result.get("total_amount").and_then(Value::as_f64),
            Some(0.000_123_45)
        );
        assert_eq!(unspents.len(), 1);
        let first = &unspents[0];
        let expected_txid = {
            let txid = outpoint.txid;
            txid.to_string_be()
        };
        assert_eq!(
            first.get("txid").and_then(Value::as_str),
            Some(expected_txid.as_str())
        );
        assert_eq!(first.get("vout").and_then(Value::as_u64), Some(0));
        assert_eq!(
            first.get("scriptPubKey").and_then(Value::as_str),
            Some(script.as_bytes().to_lower_hex_string().as_str())
        );
        assert_eq!(
            first.get("amount").and_then(Value::as_f64),
            Some(0.000_123_45)
        );
        assert_eq!(first.get("coinbase").and_then(Value::as_bool), Some(true));
        assert_eq!(first.get("height").and_then(Value::as_u64), Some(0));
        assert_eq!(first.get("confirmations").and_then(Value::as_u64), Some(1));
        let Some(desc) = first.get("desc").and_then(Value::as_str) else {
            panic!("desc missing: {first:?}");
        };
        assert!(desc.starts_with("addr(1111111111111111111114oLvT2)#"));
    }

    #[test]
    fn scantxoutset_waits_for_one_consistent_utxo_and_tip_transition() {
        let transition = Arc::new(parking_lot::Mutex::new(()));
        let context = Context::new().with_chain_transition(Arc::clone(&transition));
        let old_tip = TipSnapshot {
            tip_id: NodeId::new(0),
            height: 0,
            chainwork: ChainWork::ZERO,
            hash: test_txid(100),
        };
        context.set_applied_tip(old_tip);
        let ctx = Arc::new(context);
        let address = "1111111111111111111114oLvT2";
        let script = bitcoin::Address::from_str(address)
            .unwrap_or_else(|err| panic!("address parse failed: {err}"))
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap_or_else(|err| panic!("network check failed: {err}"))
            .script_pubkey();
        commit_test_utxo(
            &ctx,
            OutPoint::new(test_txid(101), 0),
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: script.clone(),
            },
            false,
            0,
        );

        let transition_guard = transition.lock();
        let (started_tx, started_rx) = crossbeam_channel::bounded(1);
        let scan_ctx = Arc::clone(&ctx);
        let scanner = std::thread::spawn(move || {
            started_tx
                .send(())
                .unwrap_or_else(|err| panic!("started signal failed: {err}"));
            scantxoutset(&scan_ctx, &json!(["start", [format!("addr({address})")]]))
        });
        started_rx
            .recv()
            .unwrap_or_else(|err| panic!("started receive failed: {err}"));

        commit_test_utxo(
            &ctx,
            OutPoint::new(test_txid(102), 0),
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: script,
            },
            false,
            1,
        );
        let new_tip = TipSnapshot {
            tip_id: NodeId::new(1),
            height: 1,
            chainwork: ChainWork::from(1_u64),
            hash: test_txid(103),
        };
        ctx.set_applied_tip(new_tip.clone());
        drop(transition_guard);

        let result = scanner
            .join()
            .unwrap_or_else(|_| panic!("scanner thread panicked"))
            .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(2));
        assert_eq!(result.get("height").and_then(Value::as_u64), Some(1));
        assert_eq!(
            result.get("bestblock").and_then(Value::as_str),
            Some(new_tip.hash.to_string_be().as_str())
        );
        let unspents = result
            .get("unspents")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("unspents missing: {result:?}"));
        assert_eq!(unspents.len(), 2);
        assert!(unspents.iter().any(|entry| {
            entry.get("height").and_then(Value::as_u64) == Some(0)
                && entry.get("confirmations").and_then(Value::as_u64) == Some(2)
        }));
        assert!(unspents.iter().any(|entry| {
            entry.get("height").and_then(Value::as_u64) == Some(1)
                && entry.get("confirmations").and_then(Value::as_u64) == Some(1)
        }));
    }

    #[test]
    fn scantxoutset_accepts_object_form_addr_descriptor() {
        let ctx = Arc::new(Context::new());
        let address = "1111111111111111111114oLvT2";
        let script = bitcoin::Address::from_str(address)
            .unwrap_or_else(|err| panic!("address parse failed: {err}"))
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap_or_else(|err| panic!("network check failed: {err}"))
            .script_pubkey();
        let txout = TxOut {
            value: Amount::from_sat(12_345),
            script_pubkey: script,
        };
        let outpoint = OutPoint::new(test_txid(13), 0);
        commit_test_utxo(&ctx, outpoint, txout, true, 0);

        let result = scantxoutset(
            &ctx,
            &json!(["start", [{"desc": format!("addr({address})"), "range": [0, 1]}]]),
        )
        .unwrap_or_else(|err| panic!("scantxoutset failed: {err}"));
        let Some(unspents) = result.get("unspents").and_then(Value::as_array) else {
            panic!("unspents missing: {result:?}");
        };

        assert_eq!(result.get("txouts").and_then(Value::as_u64), Some(1));
        assert_eq!(unspents.len(), 1);
        let first = &unspents[0];
        let expected_txid = {
            let txid = outpoint.txid;
            txid.to_string_be()
        };
        assert_eq!(
            first.get("txid").and_then(Value::as_str),
            Some(expected_txid.as_str())
        );
    }

    #[test]
    fn scantxoutset_rejects_empty_scanobjects() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", []])) {
            Ok(value) => panic!("empty scanobjects succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("scanobjects must not be empty"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_scanobject_without_desc() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", [{"range": 0}]])) {
            Ok(value) => panic!("scanobject without desc succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("missing desc"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_ranged_scan_descriptor() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!(["start", [{"desc": "addr(foo*)", "range": 1}]]),
        ) {
            Ok(value) => panic!("ranged descriptor succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("ranged scantxoutset descriptors are not supported"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_malformed_scanobject_range() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!(["start", [{"desc": "addr(1111111111111111111114oLvT2)", "range": [2, 1]}]]),
        ) {
            Ok(value) => panic!("bad range succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("range start must not exceed end"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_object_form_unsupported_scan_descriptor() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", [{"desc": "raw(51)"}]])) {
            Ok(value) => panic!("unsupported object descriptor succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("only addr() is supported"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_unsupported_scan_descriptors() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", ["raw(51)"]])) {
            Ok(value) => panic!("unsupported descriptor succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("only addr() is supported"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_bad_descriptor_checksum() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!(["start", ["addr(1111111111111111111114oLvT2)#badbadba"]]),
        ) {
            Ok(value) => panic!("bad checksum succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("checksum mismatch"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_wrong_network_address() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(
            &ctx,
            &json!([
                "start",
                ["addr(tb1qfm7h7nh4jjmzm0m2z8q9nu4n4yhndxj3x6gzt4)"]
            ]),
        ) {
            Ok(value) => panic!("wrong network address succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("Address is not valid"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_non_array_scanobjects() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start", "addr(1111111111111111111114oLvT2)"])) {
            Ok(value) => panic!("non-array scanobjects succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("scanobjects must be an array"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_rejects_missing_scanobjects() {
        let ctx = Arc::new(Context::new());
        let err = match scantxoutset(&ctx, &json!(["start"])) {
            Ok(value) => panic!("missing scanobjects succeeded: {value:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("scanobjects are required"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn scantxoutset_abort_returns_false() {
        let ctx = Arc::new(Context::new());
        let result = scantxoutset(&ctx, &json!(["abort"]))
            .unwrap_or_else(|err| panic!("scantxoutset abort failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
    }
}
