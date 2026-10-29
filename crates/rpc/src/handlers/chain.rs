use alloc::sync::Arc;
use core::cell::OnceCell;
use core::str::FromStr as _;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_primitives::{
    Block, BlockHash, CompactTarget, Hash256, Header, Network, TxOut, consensus_bytes, deserialize,
    u64_to_f64,
};

#[cfg(test)]
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
use corepc_types::v31::{self, ChainTips, ChainTipsStatus};
use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait, Value, json};

#[cfg(test)]
use super::util::scan_descriptor_range;
use super::util::{ScanScript, parse_derivation_range, scan_descriptor};
use bitcoin::hex::DisplayHex as _;

use crate::context::{AppliedView, ChainControlError, Context, TxQueryError, TxUnavailableCause};
use crate::convert::{
    self, compact_target_hex, i32_saturated, i64_saturated, sat_to_btc, typed_to_sonic,
    typed_to_sonic_omitting_nulls,
};
use crate::error::RpcError;
use crate::handlers::{
    ensure_no_params, optional_bool, params_array, required_i64, required_str, required_u64,
};
use bitcoin_rs_index::block_log::{BlockLog, BlockRecord, cumulative_tx_count_through};

pub(crate) fn getblockchaininfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let applied = ctx.chain.applied_view();
    let progress = ctx.chain.sync_progress_at(&applied);
    let tip_bits = applied
        .tip()
        .map_or(CompactTarget::from_consensus(0), |tip| {
            ctx.chain
                .block_tree
                .read()
                .node(tip.tip_id)
                .map_or(CompactTarget::from_consensus(0), |node| node.header.bits)
        });
    let chain = crate::convert::chain_name(progress.network);
    let response = v31::GetBlockchainInfo {
        chain: chain.to_owned(),
        blocks: i64::from(progress.blocks),
        headers: i64::from(progress.headers),
        best_block_hash: progress.best_block_hash.to_string_be(),
        bits: format!("{tip_bits:08x}"),
        target: compact_target_hex(tip_bits),
        difficulty: progress.difficulty,
        time: i64_saturated(progress.time),
        median_time: i64_saturated(progress.median_time),
        verification_progress: progress.verification_progress,
        initial_block_download: progress.initial_block_download,
        chain_work: progress.chain_work,
        size_on_disk: progress.size_on_disk,
        pruned: progress.pruned,
        prune_height: progress.prune_height.map(i64::from),
        automatic_pruning: None,
        prune_target_size: None,
        signet_challenge: None,
        warnings: ctx
            .chain
            .rollback_warnings
            .as_ref()
            .map(|source| source.rollback_warnings())
            .unwrap_or_default(),
    };
    let mut response = typed_to_sonic_omitting_nulls(&response)?;
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "is_closed_for_recovery",
            json!(ctx.chain.closed_for_recovery.load()),
        );
    }
    Ok(response)
}

fn snapshot_error(error: crate::context::SnapshotControlError) -> RpcError {
    use crate::context::SnapshotControlError;
    match error {
        SnapshotControlError::File(message) => RpcError::InvalidParameter(message),
        SnapshotControlError::Invalid(message) => RpcError::Deserialization(message),
        SnapshotControlError::Unavailable(message) | SnapshotControlError::Failed(message) => {
            RpcError::Internal(message)
        }
        SnapshotControlError::Interrupted => RpcError::Misc(error.to_string()),
    }
}

pub(crate) fn loadtxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let path = if let Some(object) = params.as_object() {
        if object.len() != 1 || !object.contains_key(&"path") {
            return Err(RpcError::InvalidParams(
                "loadtxoutset requires only the named path parameter",
            ));
        }
        object
            .get(&"path")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::InvalidType("path must be a string".to_owned()))?
    } else {
        let values = params_array(params)?;
        if values.len() != 1 {
            return Err(RpcError::InvalidParams(
                "loadtxoutset requires a snapshot path",
            ));
        }
        required_str(params, 0, "path")?
    };
    let control = ctx
        .chain
        .chain_control
        .as_ref()
        .ok_or_else(|| RpcError::Internal("snapshot control unavailable".to_owned()))?;
    typed_to_sonic(
        &control
            .load_txoutset(std::path::Path::new(path))
            .map_err(snapshot_error)?,
    )
}

/// Core 31.1 `dumptxoutset`, restricted to `type = "latest"`: the snapshot is
/// the applied tip's UTXO set. Rollback snapshots and `options` are not served.
pub(crate) fn dumptxoutset(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_chain::LatchReader,
) -> Result<Value, RpcError> {
    let params = super::bind_named_params(params, &["path", "type"])?;
    super::ensure_at_most_params(&params, 2)?;
    let path = required_str(&params, 0, "path is required")?;
    let snapshot_type = match params_array(&params)?.get(1) {
        Some(value) if !value.is_null() => value
            .as_str()
            .ok_or_else(|| super::wrong_type_plain(value, "string"))?,
        _ => "",
    };
    if snapshot_type != "latest" {
        return Err(RpcError::InvalidParameter(format!(
            "Invalid snapshot type \"{snapshot_type}\" specified. Only \"latest\" is supported"
        )));
    }
    let control = ctx
        .chain
        .chain_control
        .as_ref()
        .ok_or_else(|| RpcError::Internal("snapshot control unavailable".to_owned()))?;
    typed_to_sonic(
        &control
            .dump_txoutset(std::path::Path::new(path), cancellation)
            .map_err(snapshot_error)?,
    )
}

pub(crate) fn getchainstates(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    if !params.as_object().is_some_and(sonic_rs::Object::is_empty) {
        ensure_no_params(params)?;
    }
    let control = ctx
        .chain
        .chain_control
        .as_ref()
        .ok_or_else(|| RpcError::Internal("chainstate lifecycle unavailable".to_owned()))?;
    typed_to_sonic(&control.chainstates().map_err(snapshot_error)?)
}

pub(crate) fn getdifficulty(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let difficulty = {
        let tree = ctx.chain.block_tree.read();
        ctx.chain
            .applied_tip
            .load_full()
            .and_then(|tip| tree.node(tip.tip_id).ok().map(|node| node.header.bits))
            .map_or(0.0, |bits| ctx.chain.difficulty_for_bits(bits))
    };
    typed_to_sonic(&v31::GetDifficulty(difficulty))
}

pub(crate) fn getchaintips(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let tree = ctx.chain.block_tree.read();
    let active_tip = ctx.chain.applied_tip.load_full();
    let active_tip_id = active_tip.as_ref().map(|tip| tip.tip_id);

    let mut tip_ids = tree.leaf_node_ids();
    if let Some(active_id) = active_tip_id {
        if !tip_ids.contains(&active_id) {
            tip_ids.push(active_id);
        }
    }
    let mut tips = Vec::new();
    for leaf_id in tip_ids {
        let is_active = Some(leaf_id) == active_tip_id;
        let Ok(node) = tree.node(leaf_id) else {
            if !is_active {
                continue;
            }
            let Some(tip) = active_tip.as_ref() else {
                continue;
            };
            tips.push(ChainTips {
                height: i64::from(tip.height),
                hash: tip.hash.to_string_be(),
                branch_length: 0,
                status: ChainTipsStatus::Active,
            });
            continue;
        };
        let status = match node.status {
            NodeStatus::Invalid => ChainTipsStatus::Invalid,
            _ if is_active => ChainTipsStatus::Active,
            NodeStatus::Stale | NodeStatus::Active | NodeStatus::HeaderValid => {
                ChainTipsStatus::HeadersOnly
            }
        };
        let branchlen = if is_active {
            0
        } else {
            compute_branchlen(&tree, leaf_id, node.height, active_tip_id)
        };
        tips.push(ChainTips {
            height: i64::from(node.height),
            hash: node.hash.to_string_be(),
            branch_length: i64::from(branchlen),
            status,
        });
    }
    tips.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| a.hash.cmp(&b.hash)));
    typed_to_sonic(&v31::GetChainTips(tips))
}

pub(crate) fn getchaintxstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    const DEFAULT_WINDOW: u64 = 30 * 24 * 6;

    let array = params_array(params)?;
    let applied = ctx.chain.applied_view();
    let tip_hash = match array.get(1).filter(|value| !value.is_null()) {
        None => applied.hash(ctx.chain.chain_network),
        Some(value) => {
            let hash =
                parse_hash(value.as_str().ok_or_else(|| {
                    RpcError::InvalidType("blockhash must be a string".to_owned())
                })?)?;
            let Some(height) = ctx.chain.height_for_hash(hash) else {
                return Err(RpcError::NotFound("block not found"));
            };
            if ctx.chain.block_hash_at_height_in_view(&applied, height) != Some(hash) {
                return Err(RpcError::InvalidParameter(
                    "Block is not in main chain".to_owned(),
                ));
            }
            hash
        }
    };
    let tip_height = ctx
        .chain
        .height_for_hash(tip_hash)
        .unwrap_or_else(|| applied.height());
    let default_window = DEFAULT_WINDOW.min(u64::from(tip_height.saturating_sub(1)));
    let window_block_count = match array.first().filter(|value| !value.is_null()) {
        None => default_window,
        Some(value) => {
            let nblocks = value
                .as_i64()
                .ok_or_else(|| RpcError::InvalidType("nblocks must be a number".to_owned()))?;
            if nblocks < 0 || (nblocks > 0 && nblocks >= i64::from(tip_height)) {
                return Err(RpcError::InvalidParameter(
                    "Invalid block count: should be between 0 and the block's height - 1"
                        .to_owned(),
                ));
            }
            u64::try_from(nblocks).unwrap_or(0)
        }
    };
    let stats = {
        let tree = ctx.chain.block_tree.read();
        window_stats(ctx, &tree, &applied, tip_hash, window_block_count)?
    };
    let tip_hash_hex = tip_hash.to_string_be();
    let window_open = window_block_count > 0;
    let tx_rate = match (
        stats.window_tx_count,
        window_open && stats.window_interval > 0,
    ) {
        (Some(count), true) => Some(u64_to_f64(count) / u64_to_f64(stats.window_interval)),
        _ => None,
    };
    let mut result = typed_to_sonic_omitting_nulls(&v31::GetChainTxStats {
        time: i64::from(stats.tip_time),
        tx_count: i64_saturated(stats.total_tx_count.unwrap_or(0)),
        window_final_block_hash: tip_hash_hex,
        window_final_block_height: i64::from(tip_height),
        window_block_count: i64_saturated(window_block_count),
        window_tx_count: stats.window_tx_count.map(i64_saturated),
        window_interval: window_open.then(|| i64_saturated(stats.window_interval)),
        tx_rate,
    })?;
    if (!stats.selected || (!stats.is_applied_tip && stats.total_tx_count.is_none()))
        && let Some(object) = result.as_object_mut()
    {
        object.remove(&"txcount");
    }
    Ok(result)
}

struct ChainTxStats {
    selected: bool,
    is_applied_tip: bool,
    /// Cumulative transactions through the selected block, when known.
    total_tx_count: Option<u64>,
    tip_time: u32,
    /// Transactions inside the window, when the window is open and known.
    window_tx_count: Option<u64>,
    /// The window's length in seconds (a difference of two median times).
    window_interval: u64,
}

fn branch_hashes(
    tree: &bitcoin_rs_chain::BlockTree,
    branch_tip: bitcoin_rs_chain::NodeId,
) -> Option<Vec<Hash256>> {
    let floor = tree.node(branch_tip).ok()?.height;
    let width = usize::try_from(floor).ok()?.checked_add(1)?;
    let mut hashes = vec![Hash256::default(); width];
    let mut cursor = Some(branch_tip);
    while let Some(id) = cursor {
        let node = tree.node(id).ok()?;
        if let Ok(index) = usize::try_from(node.height)
            && index < width
        {
            hashes[index] = node.hash;
        }
        cursor = node.parent;
    }
    Some(hashes)
}

fn log_prefix_count(
    log: &BlockLog,
    tree: &bitcoin_rs_chain::BlockTree,
    branch_tip: bitcoin_rs_chain::NodeId,
    branch: &OnceCell<Option<Vec<Hash256>>>,
    height: u32,
) -> Option<u64> {
    let total = cumulative_tx_count_through(log, height)?;
    let branch = branch
        .get_or_init(|| branch_hashes(tree, branch_tip))
        .as_deref()?;
    let records: &[BlockRecord] = log;
    for record in &records[..records.partition_point(|candidate| candidate.height <= height)] {
        let index = usize::try_from(record.height).ok()?;
        if branch.get(index)? != &Hash256::from(record.hash) {
            return None;
        }
    }
    Some(total)
}

fn count_through(
    ctx: &Context,
    tree: &bitcoin_rs_chain::BlockTree,
    applied: &AppliedView,
    node_id: bitcoin_rs_chain::NodeId,
    branch: &OnceCell<Option<Vec<Hash256>>>,
) -> Option<u64> {
    let node = tree.node(node_id).ok()?;
    if let Some(count) = node.chain_tx_count.get() {
        return Some(count);
    }
    if applied.hash(ctx.chain.chain_network) == node.hash
        && let Some(count) = applied.chain_tx_count()
    {
        return Some(count);
    }
    let log = ctx.chain.blocks.read();
    log_prefix_count(&log, tree, node_id, branch, node.height)
}

fn window_tx_count_between(
    ctx: &Context,
    tree: &bitcoin_rs_chain::BlockTree,
    start_id: bitcoin_rs_chain::NodeId,
    end_id: bitcoin_rs_chain::NodeId,
    branch: &OnceCell<Option<Vec<Hash256>>>,
) -> Option<u64> {
    let start = tree.node(start_id).ok()?;
    let end = tree.node(end_id).ok()?;
    if let (Some(end_count), Some(start_count)) =
        (end.chain_tx_count.get(), start.chain_tx_count.get())
    {
        return Some(end_count.saturating_sub(start_count));
    }
    let log = ctx.chain.blocks.read();
    let end_count = log_prefix_count(&log, tree, end_id, branch, end.height)?;
    let start_count = log_prefix_count(&log, tree, end_id, branch, start.height)?;
    Some(end_count.saturating_sub(start_count))
}

fn window_stats(
    ctx: &Context,
    tree: &bitcoin_rs_chain::BlockTree,
    applied: &AppliedView,
    tip_hash: Hash256,
    window_block_count: u64,
) -> Result<ChainTxStats, RpcError> {
    let Some(selected_id) = tree.lookup(tip_hash) else {
        let tip_time = applied
            .tip()
            .and_then(|tip| tree.node(tip.tip_id).ok().map(|node| node.header.time))
            .unwrap_or(0);
        let is_applied_tip = applied.tip().is_some_and(|tip| tip.hash == tip_hash);
        return Ok(ChainTxStats {
            selected: is_applied_tip,
            is_applied_tip,
            total_tx_count: None,
            tip_time,
            window_tx_count: None,
            window_interval: 0,
        });
    };
    let selected = tree
        .node(selected_id)
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    let is_applied_tip = applied.hash(ctx.chain.chain_network) == tip_hash;
    let branch_cache = OnceCell::new();
    let total_tx_count = count_through(ctx, tree, applied, selected_id, &branch_cache);
    let tip_time = selected.header.time;
    if window_block_count == 0 {
        return Ok(ChainTxStats {
            selected: true,
            is_applied_tip,
            total_tx_count,
            tip_time,
            window_tx_count: None,
            window_interval: 0,
        });
    }
    let start_height = selected
        .height
        .saturating_sub(u32::try_from(window_block_count).unwrap_or(u32::MAX));
    let Some(start_id) = tree.node_at_height_from(selected_id, start_height) else {
        return Err(RpcError::Internal(
            "selected chain is missing the window ancestor".to_owned(),
        ));
    };
    let window_tx_count = window_tx_count_between(ctx, tree, start_id, selected_id, &branch_cache);
    let end_mtp = tree.median_time_past_at(selected_id).unwrap_or(0);
    let start_mtp = tree.median_time_past_at(start_id).unwrap_or(0);
    let window_interval = u64::from(end_mtp.saturating_sub(start_mtp));
    Ok(ChainTxStats {
        selected: true,
        is_applied_tip,
        total_tx_count,
        tip_time,
        window_tx_count,
        window_interval,
    })
}

pub(crate) fn getblockcount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    typed_to_sonic(&v31::GetBlockCount(u64::from(ctx.chain.applied_height())))
}

pub(crate) fn getblockhash(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let height = required_i64(params, 0, "height is required")?;
    let height = u32::try_from(height)
        .map_err(|_| RpcError::InvalidParameter("Block height out of range".to_owned()))?;
    ctx.chain
        .block_hash_at_height(height)
        .map(|hash| typed_to_sonic(&v31::GetBlockHash(hash.to_string_be())))
        .transpose()?
        .ok_or_else(|| RpcError::InvalidParameter("Block height out of range".to_owned()))
}

pub(crate) fn getbestblockhash(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    typed_to_sonic(&v31::GetBestBlockHash(
        ctx.chain.applied_hash().to_string_be(),
    ))
}

pub(crate) fn getblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["blockhash", "verbosity"])?;
    let params = bound.as_ref();
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbosity = getblock_verbosity(params)?;
    let _render = if verbosity >= 2 {
        Some(ctx.try_acquire_block_render().ok_or_else(|| {
            RpcError::Misc("too many concurrent full-block reads; retry".to_owned())
        })?)
    } else {
        None
    };
    let record = if verbosity >= 2 && ctx.chain.block_undo_source.is_some() {
        ctx.chain.header_record(hash)
    } else {
        ctx.chain.block_by_hash(hash)
    }
    .ok_or(RpcError::NotFound("block not found"))?;
    if verbosity == 0 {
        let Some(block_payload_hex) = ctx.chain.block_body_hex(&record) else {
            return Err(RpcError::NotFound("block data pruned"));
        };
        return typed_to_sonic(&v31::GetBlockVerboseZero(block_payload_hex));
    }
    block_verbose_typed(ctx, &record, true, verbosity)
}

pub(crate) fn getblockheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbose = optional_bool(params, 1, true)?;
    let record = ctx
        .chain
        .block_by_hash(hash)
        .ok_or(RpcError::NotFound("block not found"))?;
    if !verbose {
        let header = decode_header(&record)?;
        return typed_to_sonic(&v31::GetBlockHeader(crate::render::header_hex(&header)));
    }
    block_verbose_typed(ctx, &record, false, 1)
}

fn blockstats_record(ctx: &Context, params: &Value) -> Result<BlockRecord, RpcError> {
    let target = params_array(params)?
        .first()
        .ok_or(RpcError::InvalidParams("hash_or_height is required"))?;
    let record = if let Some(height) = target.as_u64() {
        let height =
            u32::try_from(height).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?;
        ctx.chain.block_by_height(height)
    } else if let Some(hash) = target.as_str() {
        let hash = parse_hash(hash)?;
        let record = ctx.chain.block_by_hash(hash);
        if let Some(record) = &record
            && ctx.chain.block_hash_at_height(record.height) != Some(hash)
        {
            return Err(RpcError::InvalidParams("Block is not in main chain"));
        }
        record
    } else {
        return Err(RpcError::InvalidType(
            "hash_or_height must be string or number".to_owned(),
        ));
    };
    record.ok_or(RpcError::NotFound("block not found"))
}

pub(crate) fn getblockstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let record = blockstats_record(ctx, params)?;

    let (_bytes, block) = decode_block(ctx, &record)?;
    let height = record.height;
    let block_hash = record.hash;
    let subsidy_sat = bitcoin_rs_consensus::block_subsidy(
        height,
        ctx.chain.chain_network.subsidy_halving_interval(),
    );
    let mediantime = ctx
        .chain
        .median_time_past_for_hash(Hash256::from(block_hash))
        .unwrap_or(0);
    let fee_fields = compute_fee_fields(ctx, &block).map_err(crate::error::RpcError::from)?;
    let utxo_size_inc =
        utxo_size_inc_for_block(ctx, &block).map_err(crate::error::RpcError::from)?;
    let txs = u64::try_from(block.txs.len()).unwrap_or(u64::MAX);
    let mut total_out = 0_u64;
    let mut total_size = 0_u64;
    let mut total_weight = 0_u64;
    let mut ins = 0_u64;
    let mut outs = 0_u64;
    let mut swtxs = 0_u64;
    let mut swtotal_size = 0_u64;
    let mut swtotal_weight = 0_u64;
    let mut tx_sizes = Vec::new();
    for (index, tx) in block.txs.iter().enumerate() {
        outs = outs.saturating_add(u64::try_from(tx.outputs.len()).unwrap_or(u64::MAX));
        if index == 0 {
            continue;
        }
        ins = ins.saturating_add(u64::try_from(tx.inputs.len()).unwrap_or(u64::MAX));
        for output in &tx.outputs {
            total_out = total_out.saturating_add(output.value.to_sat());
        }
        let tx_size = u64::try_from(tx.total_size()).unwrap_or(u64::MAX);
        let tx_weight = tx.weight();
        tx_sizes.push(tx_size);
        total_size = total_size.saturating_add(tx_size);
        total_weight = total_weight.saturating_add(tx_weight);
        if tx.inputs.iter().any(|input| !input.witness.is_empty()) {
            swtxs = swtxs.saturating_add(1);
            swtotal_size = swtotal_size.saturating_add(tx_size);
            swtotal_weight = swtotal_weight.saturating_add(tx_weight);
        }
    }

    let (avgtxsize, maxtxsize, mintxsize, mediantxsize) = if tx_sizes.is_empty() {
        (0_u64, 0_u64, 0_u64, 0_u64)
    } else {
        let non_coinbase = u64::try_from(tx_sizes.len()).unwrap_or(1);
        let avg = total_size / non_coinbase;
        let max = tx_sizes.iter().copied().max().unwrap_or(0);
        let min = tx_sizes.iter().copied().min().unwrap_or(0);
        let median = truncated_median(&mut tx_sizes);
        (avg, max, min, median)
    };
    let utxo_increase = i64::try_from(outs)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(ins).unwrap_or(i64::MAX));

    typed_to_sonic(&v31::GetBlockStats {
        average_fee: Some(fee_fields.avgfee),
        average_fee_rate: Some(fee_fields.avgfeerate),
        average_tx_size: Some(i64_saturated(avgtxsize)),
        block_hash: Some(block_hash.to_string()),
        fee_rate_percentiles: Some(fee_fields.feerate_percentiles),
        height: Some(i64::from(height)),
        inputs: Some(i64_saturated(ins)),
        max_fee: Some(fee_fields.maxfee),
        max_fee_rate: Some(fee_fields.maxfeerate),
        max_tx_size: Some(i64_saturated(maxtxsize)),
        median_fee: Some(fee_fields.medianfee),
        median_time: Some(i64_saturated(u64::from(mediantime))),
        median_tx_size: Some(i64_saturated(mediantxsize)),
        minimum_fee: Some(fee_fields.minfee),
        minimum_fee_rate: Some(fee_fields.minfeerate),
        minimum_tx_size: Some(i64_saturated(mintxsize)),
        outputs: Some(i64_saturated(outs)),
        subsidy: Some(subsidy_sat),
        segwit_total_size: Some(i64_saturated(swtotal_size)),
        segwit_total_weight: Some(swtotal_weight),
        segwit_txs: Some(i64_saturated(swtxs)),
        time: Some(i64_saturated(u64::from(record.time))),
        total_out: Some(total_out),
        total_size: Some(i64_saturated(total_size)),
        total_weight: Some(total_weight),
        total_fee: Some(fee_fields.totalfee),
        txs: Some(i64_saturated(txs)),
        utxo_increase: Some(i32_saturated(utxo_increase)),
        utxo_size_increase: Some(i32_saturated(utxo_size_inc)),
        utxo_increase_actual: None,
        utxo_size_increase_actual: None,
    })
}

#[derive(Debug, Default, Eq, PartialEq)]
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

fn resolve_per_tx_fees(ctx: &Context, block: &Block) -> Result<Vec<(u64, u64)>, TxQueryError> {
    let Some(derived_index) = ctx.indexes.derived_index.as_ref() else {
        return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
            "transaction index disabled".into(),
        )));
    };
    let tx_count = block.txs.len().saturating_sub(1);
    let mut fees = Vec::with_capacity(tx_count);
    for tx in block.txs.iter().skip(1) {
        let mut total_in = 0_u64;
        for input in &tx.inputs {
            match derived_index.outpoint_value(&input.previous_output) {
                Ok(Some(value)) => total_in = total_in.saturating_add(value),
                Ok(None) => {
                    return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                        "input value missing from complete index".into(),
                    )));
                }
                Err(error) => return Err(error),
            }
        }
        let total_out = tx.outputs.iter().fold(0_u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
        let Some(fee) = total_in.checked_sub(total_out) else {
            return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                "negative fee".into(),
            )));
        };
        fees.push((fee, tx.weight()));
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

fn compute_fee_fields(ctx: &Context, block: &Block) -> Result<FeeFields, TxQueryError> {
    if block.txs.len() <= 1 {
        return Ok(FeeFields::default());
    }
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
    let tx_count = u64::try_from(per_tx.len()).unwrap_or(1);
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

    let minfee = fees.iter().copied().min().unwrap_or(0);
    let maxfee = fees.iter().copied().max().unwrap_or(0);
    let medianfee = truncated_median(&mut fees);
    let minfeerate = rates.iter().map(|(rate, _weight)| *rate).min().unwrap_or(0);
    let maxfeerate = rates.iter().map(|(rate, _weight)| *rate).max().unwrap_or(0);
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

/// Core's `PER_UTXO_OVERHEAD`: serialized outpoint plus creation height.
const PER_UTXO_OVERHEAD: u64 = 36 + 4;

fn output_utxo_size(output: &TxOut) -> u64 {
    u64::try_from(consensus_bytes(output).len())
        .unwrap_or(u64::MAX)
        .saturating_add(PER_UTXO_OVERHEAD)
}

fn utxo_size_inc_for_block(ctx: &Context, block: &Block) -> Result<i64, TxQueryError> {
    let mut size_inc = 0_i64;
    for tx in &block.txs {
        for output in &tx.outputs {
            let added = i64::try_from(output_utxo_size(output)).unwrap_or(i64::MAX);
            size_inc = size_inc.saturating_add(added);
        }
    }
    if block.txs.len() <= 1 {
        return Ok(size_inc);
    }
    let Some(derived_index) = ctx.indexes.derived_index.as_ref() else {
        return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
            "transaction index disabled".into(),
        )));
    };
    for tx in block.txs.iter().skip(1) {
        for input in &tx.inputs {
            let Some(prev) = derived_index.transaction(&input.previous_output.txid)? else {
                return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                    "input transaction missing from complete index".into(),
                )));
            };
            let Some(output) = prev
                .outputs
                .get(usize::try_from(input.previous_output.vout).unwrap_or(usize::MAX))
            else {
                return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                    "input vout missing from complete index".into(),
                )));
            };
            let removed = i64::try_from(output_utxo_size(output)).unwrap_or(i64::MAX);
            size_inc = size_inc.saturating_sub(removed);
        }
    }
    Ok(size_inc)
}

pub(crate) fn pruneblockchain(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let requested = required_u64(params, 0, "height is required")?;
    let requested_height =
        u32::try_from(requested).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?;
    let Some(prune_service) = ctx.chain.prune_service.as_ref() else {
        return Err(RpcError::MethodDisabled("pruning is disabled"));
    };
    let applied = ctx.chain.applied_height();
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
    typed_to_sonic(&v31::PruneBlockchain(i64::from(result.pruneheight)))
}

pub(crate) fn invalidateblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let control = ctx
        .chain
        .chain_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("invalidateblock is unavailable"))?;
    match control.invalidate_block(hash) {
        Ok(()) => Ok(Value::new_null()),
        Err(ChainControlError::UnknownBlock) => Err(RpcError::NotFound("block not found")),
        Err(ChainControlError::Genesis) => Err(RpcError::InvalidParams(
            "cannot invalidate the genesis block",
        )),
        Err(ChainControlError::Interrupted) => {
            Err(RpcError::Misc("Block verification interrupted".to_owned()))
        }
        Err(ChainControlError::Unavailable) => Err(RpcError::Misc(
            "Chainstate is unavailable for verification".to_owned(),
        )),
        Err(ChainControlError::Failed(message)) => Err(RpcError::Internal(message)),
    }
}

pub(crate) fn verifychain(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_chain::LatchReader,
) -> Result<Value, RpcError> {
    super::ensure_at_most_params(params, 2)?;
    let array = params_array(params)?;
    if cancellation.is_triggered() {
        return Err(RpcError::Misc("Block verification interrupted".to_owned()));
    }
    let parameter = |index: usize, name: &str, default: i64| -> Result<i64, RpcError> {
        let Some(value) = array.get(index).filter(|value| !value.is_null()) else {
            return Ok(default);
        };
        if !value.is_number() {
            return Err(super::wrong_type(index + 1, name, value, "number"));
        }
        value
            .as_i64()
            .or_else(|| value.as_u64().map(|_| i64::MAX))
            .ok_or_else(|| RpcError::Misc("JSON integer out of range".to_owned()))
    };
    let checklevel = i32::try_from(parameter(0, "checklevel", 3)?)
        .map_err(|_| RpcError::Misc("JSON integer out of range".to_owned()))?
        .clamp(0, 4);
    let depth = parameter(1, "nblocks", 6)?;
    let nblocks = match i32::try_from(depth) {
        Ok(depth) => u32::try_from(depth).unwrap_or(0),
        Err(_) => return Err(RpcError::Misc("JSON integer out of range".to_owned())),
    };
    let level = u8::try_from(checklevel).unwrap_or(4);
    if ctx.chain.closed_for_recovery.is_triggered() {
        return Err(RpcError::Misc(
            "Chainstate is unavailable for verification".to_owned(),
        ));
    }
    if ctx.chain.applied_tip.load_full().is_none() {
        return typed_to_sonic(&v31::VerifyChain(true));
    }
    let verified = ctx
        .chain
        .chain_control
        .as_ref()
        .map_or(Ok(false), |control| {
            control.verify_chain(level, nblocks, cancellation)
        })
        .map_err(|error| match error {
            ChainControlError::Interrupted => {
                RpcError::Misc("Block verification interrupted".to_owned())
            }
            ChainControlError::Unavailable => {
                RpcError::Misc("Chainstate is unavailable for verification".to_owned())
            }
            ChainControlError::UnknownBlock => RpcError::NotFound("block not found"),
            ChainControlError::Genesis => {
                RpcError::InvalidParams("cannot invalidate the genesis block")
            }
            ChainControlError::Failed(message) => RpcError::Internal(message),
        })?;
    typed_to_sonic(&v31::VerifyChain(verified))
}

pub(crate) fn gettxoutsetinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = if params.is_null() {
        None
    } else {
        let values = params_array(params)?;
        if values.len() > 3 {
            return Err(RpcError::InvalidParams("expected at most three parameters"));
        }
        Some(values)
    };
    let hash_type = match array.and_then(|values| values.first()) {
        None => "hash_serialized_3",
        Some(value) if value.is_null() => "hash_serialized_3",
        Some(value) => value
            .as_str()
            .ok_or_else(|| RpcError::InvalidType("hash_type must be a string".to_owned()))?,
    };
    let specific_block = match array.and_then(|values| values.get(1)) {
        None => false,
        Some(value) if value.is_null() => false,
        Some(_) => true,
    };
    let _use_index = optional_bool(params, 2, true)?;
    if specific_block {
        return Err(RpcError::InvalidParameter(
            "Querying specific block heights requires coinstatsindex".to_owned(),
        ));
    }
    let want_muhash = hash_type == "muhash";
    let scan = |view: &AppliedView| {
        ctx.chain.utxo.with_stable_view(|stable| {
            let stats = bitcoin_rs_utxo::stats::scan_coin_stats(stable, view.height(), want_muhash)
                .map_err(|err| RpcError::Internal(err.to_string()))?;
            let set_hash = match hash_type {
                "hash_serialized_3" => Some((
                    "hash_serialized_3",
                    stable
                        .hash_serialized_3()
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
            Ok::<_, RpcError>((
                stats,
                stable.len(),
                stable.record_count(),
                set_hash,
                u64::try_from(stable.memory_report().accounted_bytes()).unwrap_or(u64::MAX),
            ))
        })
    };
    let mut contested = 0usize;
    let (view, (stats, txouts, transactions, set_hash, disk_size)) = loop {
        let view = ctx.chain.applied_view();
        let scanned = scan(&view)?;
        if ctx.chain.applied_view().tip() == view.tip() {
            break (view, scanned);
        }
        contested += 1;
        if contested == 4 {
            break ctx.chain.with_stable_chainstate(|| {
                let view = ctx.chain.applied_view();
                scan(&view).map(|scanned| (view, scanned))
            })?;
        }
    };
    let applied_height = view.height();
    let best_block = view.hash(ctx.chain.chain_network);
    let (hash_serialized_3, muhash) = set_hash.map_or((None, None), |(name, hash)| {
        if name == "hash_serialized_3" {
            (Some(hash), None)
        } else {
            (None, Some(hash))
        }
    });
    typed_to_sonic_omitting_nulls(&v31::GetTxOutSetInfo {
        height: i64::from(applied_height),
        best_block: best_block.to_string_be(),
        transactions: Some(i64_saturated(transactions)),
        tx_outs: i64_saturated(u64::try_from(txouts).unwrap_or(u64::MAX)),
        bogo_size: i64_saturated(stats.bogo_size),
        hash_serialized_3,
        disk_size: Some(i64_saturated(disk_size)),
        total_amount: sat_to_btc(stats.total_amount),
        muhash,
        total_unspendable_amount: None,
        block_info: None,
    })
}

pub(crate) fn getblockfilter(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["blockhash", "filtertype"])?;
    let params = bound.as_ref();
    let hash =
        parse_hash(required_str(params, 0, "block hash is required")?).map_err(
            |error| match error {
                RpcError::InvalidParams(message) => RpcError::InvalidParameter(message.into()),
                error => error,
            },
        )?;
    let args = params_array(params)?;
    if args.len() > 2 {
        return Err(RpcError::InvalidParams(
            "expected blockhash and optional filtertype",
        ));
    }
    if let Some(kind) = args.get(1).filter(|value| !value.is_null()) {
        let kind = kind
            .as_str()
            .ok_or_else(|| RpcError::InvalidType("filtertype must be a string".into()))?;
        if kind != "basic" {
            return Err(RpcError::InvalidAddressOrKey("Unknown filtertype".into()));
        }
    }
    if ctx.chain.block_tree.read().lookup(hash).is_none() {
        return Err(RpcError::NotFound("Block not found"));
    }
    let index = ctx
        .indexes
        .compact_filters
        .as_ref()
        .ok_or_else(|| RpcError::Misc("Index is not enabled for filtertype basic".into()))?;
    let filter = index.block_filter(hash).map_err(|error| {
        use bitcoin_rs_index::TxQueryError;
        match error {
            TxQueryError::Retry => RpcError::Misc("Block filter index is still catching up; retry later".into()),
            TxQueryError::Unavailable(cause) =>
                RpcError::Misc(format!("Block filter index unavailable: {cause}")),
            TxQueryError::Storage(reason) =>
                RpcError::Misc(format!("Block filter index unavailable: {reason}")),
        }
    })?.ok_or_else(|| RpcError::Misc("Filter not found. This could be because the block was not connected to the active chain.".into()))?;
    Ok(json!({
        "filter": filter.filter.to_lower_hex_string(),
        "header": Hash256::from_le_bytes(&filter.header).to_string_be(),
    }))
}

pub(crate) fn getindexinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let index_name = if params.is_null() {
        None
    } else if let Some(array) = params.as_array() {
        if array.is_empty() {
            None
        } else {
            Some(required_str(params, 0, "index_name must be a string")?.to_owned())
        }
    } else {
        return Err(RpcError::InvalidParams("params must be null or array"));
    };

    let txindex_entry = ctx
        .indexes
        .derived_index
        .as_ref()
        .filter(|_| index_name.as_deref().is_none_or(|name| name == "txindex"))
        .map(|derived_index| derived_index.index_info())
        .transpose()?;
    let txindex_entry = txindex_entry.map(|info| v31::GetIndexInfoName {
        synced: info.synced,
        best_block_height: info.best_block_height,
    });
    let mut indexes = alloc::collections::BTreeMap::new();
    if let Some(entry) = txindex_entry {
        indexes.insert("txindex".to_owned(), entry);
    }
    if let Some(filters) = &ctx.indexes.compact_filters
        && index_name
            .as_deref()
            .is_none_or(|name| name == "basic block filter index")
        && let Ok(info) = filters.filter_index_info()
    {
        indexes.insert(
            "basic block filter index".to_owned(),
            v31::GetIndexInfoName {
                synced: info.synced,
                best_block_height: info.best_block_height,
            },
        );
    }
    let selected = match index_name {
        None => indexes,
        Some(name) => {
            let mut selected = alloc::collections::BTreeMap::new();
            if let Some(entry) = indexes.remove(&name) {
                selected.insert(name, entry);
            }
            selected
        }
    };
    typed_to_sonic(&v31::GetIndexInfo(selected))
}

/// bitcoin-rs extension `getcapabilities`.
pub(crate) fn getcapabilities(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let snapshot = bitcoin_rs_index::txindex_snapshot(ctx.indexes.derived_index_status.as_deref());
    Ok(json!({ "capabilities": snapshot.capabilities }))
}

const MAX_SCAN_DESCRIPTOR_BYTES: usize = 16_384;
const MAX_SCAN_INPUT_BYTES: usize = 1_048_576;
const MAX_SCAN_ANCESTRY_STEPS: usize = 2_000_000;
const MAX_SCAN_RESPONSE_BYTES: usize = 16 * 1_048_576;

pub(crate) fn scantxoutset(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &bitcoin_rs_chain::LatchReader,
) -> Result<Value, RpcError> {
    let params = super::bind_named_params(params, &["action", "scanobjects"])?;
    let (action, objects) = scan_arguments(&params)?;
    match action {
        "start" => {
            let permit = ctx
                .chain
                .utxo
                .reserve_scan()
                .map_err(|error| scan_error(&error))?;
            let objects = objects.ok_or_else(|| {
                RpcError::Misc("scanobjects argument is required for the start action".into())
            })?;
            let scripts = parse_scan_scripts(ctx.chain.chain_network, objects, || {
                permit
                    .cancelled(|| cancellation.is_triggered())
                    .map_err(|error| scan_error(&error))
            })?;
            scantxoutset_scan(ctx, &permit, &scripts, cancellation)
        }
        "abort" => Ok(json!(ctx.chain.utxo.abort_scan())),
        "status" => Ok(ctx
            .chain
            .utxo
            .scan_progress()
            .map_or_else(Value::new_null, |progress| json!({"progress": progress}))),
        _ => Err(RpcError::InvalidParameter(format!(
            "Invalid action '{action}'"
        ))),
    }
}

fn scan_arguments(params: &Value) -> Result<(&str, Option<&sonic_rs::Array>), RpcError> {
    let array = params_array(params)?;
    if array.len() > 2 {
        return Err(RpcError::InvalidParams("too many parameters"));
    }
    let (action, objects) = (array.first(), array.get(1));
    let action = action
        .ok_or_else(|| RpcError::Misc("scantxoutset \"action\" ( [scanobjects,...] )".into()))?;
    let action = action
        .as_str()
        .ok_or_else(|| super::wrong_type(1, "action", action, "string"))?;
    let objects = objects
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| super::wrong_type(2, "scanobjects", value, "array"))
        })
        .transpose()?;
    Ok((action, objects))
}

fn scan_error(error: &bitcoin_rs_utxo::scan::UtxoScanError) -> RpcError {
    match error {
        bitcoin_rs_utxo::scan::UtxoScanError::InProgress => {
            RpcError::InvalidParameter(error.to_string())
        }
        _ => RpcError::Misc(error.to_string()),
    }
}

fn scantxoutset_scan(
    ctx: &Context,
    permit: &bitcoin_rs_utxo::scan::UtxoScanPermit<'_>,
    scan_scripts: &std::collections::BTreeMap<Vec<u8>, String>,
    cancellation: &bitcoin_rs_chain::LatchReader,
) -> Result<Value, RpcError> {
    let scripts = scan_scripts.keys().cloned().collect();
    let (applied, complete, mut scan) = loop {
        if permit
            .cancelled(|| cancellation.is_triggered())
            .map_err(|error| scan_error(&error))?
        {
            break (
                ctx.chain.applied_view(),
                false,
                bitcoin_rs_utxo::UtxoScan::default(),
            );
        }
        if let Some(transition) = ctx
            .chain
            .chain_transition
            .try_lock_for(std::time::Duration::from_millis(50))
        {
            let applied = ctx.chain.applied_view();
            let (complete, scan) = permit
                .scan(&scripts, || cancellation.is_triggered())
                .map_err(|error| scan_error(&error))?;
            drop(transition);
            break (applied, complete, scan);
        }
    };
    let cancelled = || {
        permit
            .cancelled(|| cancellation.is_triggered())
            .map_err(|error| scan_error(&error))
    };
    let mut complete = complete;
    let hashes = scan_ancestry(ctx, &scan, &applied, cancelled, MAX_SCAN_ANCESTRY_STEPS)?;
    let hashes = if let Some(hashes) = hashes {
        hashes
    } else {
        complete = false;
        scan.unspents.clear();
        std::collections::BTreeMap::new()
    };
    if cancelled()? {
        complete = false;
        scan.unspents.clear();
    }
    scan.unspents.sort_unstable_by_key(|coin| {
        let outpoint = coin.outpoint;
        let txid = outpoint.txid;
        (Hash256::from(txid).to_le_bytes(), outpoint.vout)
    });
    let (unspents, total_amount, projected) =
        scan_unspents(&scan, scan_scripts, &hashes, applied.height(), cancelled)?;
    let mut result = typed_to_sonic(&v31::ScanTxOutSetStart {
        success: complete && projected && !cancelled()?,
        tx_outs: u64::try_from(scan.txouts).unwrap_or(u64::MAX),
        height: u64::from(applied.height()),
        best_block: applied.hash(ctx.chain.chain_network).to_string_be(),
        unspents,
        total_amount: sat_to_btc(total_amount),
    })?;
    if cancelled()?
        && let Some(object) = result.as_object_mut()
    {
        let _ = object.insert("success", json!(false));
    }
    Ok(result)
}

fn scan_ancestry(
    ctx: &Context,
    scan: &bitcoin_rs_utxo::UtxoScan,
    applied: &AppliedView,
    cancelled: impl Fn() -> Result<bool, RpcError>,
    max_steps: usize,
) -> Result<Option<std::collections::BTreeMap<u32, Hash256>>, RpcError> {
    let mut heights = scan
        .unspents
        .iter()
        .map(|coin| coin.height)
        .collect::<std::collections::BTreeSet<_>>();
    let mut hashes = std::collections::BTreeMap::new();
    if heights.remove(&applied.height()) {
        hashes.insert(applied.height(), applied.hash(ctx.chain.chain_network));
    }
    if heights.is_empty() {
        return Ok(Some(hashes));
    }
    let unavailable = || RpcError::Misc("scan block ancestry is unavailable".into());
    let tip = applied.tip().ok_or_else(unavailable)?;
    let tree = loop {
        if cancelled()? {
            return Ok(None);
        }
        if let Some(tree) = ctx
            .chain
            .block_tree
            .try_read_for(std::time::Duration::from_millis(50))
        {
            break tree;
        }
    };
    let mut cursor = tip.tip_id;
    let mut previous_height = None;
    for steps in 0..max_steps {
        if steps.is_multiple_of(256) && cancelled()? {
            return Ok(None);
        }
        let node = tree.node(cursor).map_err(|_| unavailable())?;
        if (steps == 0 && (node.hash != tip.hash || node.height != tip.height))
            || previous_height.is_some_and(|height| node.height >= height)
        {
            return Err(unavailable());
        }
        if heights.remove(&node.height) {
            hashes.insert(node.height, node.hash);
            if heights.is_empty() {
                return Ok(Some(hashes));
            }
        }
        if heights.last().is_some_and(|height| *height > node.height) {
            return Err(unavailable());
        }
        previous_height = Some(node.height);
        cursor = node.parent.ok_or_else(unavailable)?;
    }
    Err(RpcError::Misc(
        "UTXO scan limit exceeded: 2 million ancestry steps".into(),
    ))
}

fn parse_scan_scripts(
    network: Network,
    scanobjects: &sonic_rs::Array,
    cancelled: impl Fn() -> Result<bool, RpcError>,
) -> Result<std::collections::BTreeMap<Vec<u8>, String>, RpcError> {
    if scanobjects.len() > bitcoin_rs_utxo::scan::MAX_SCAN_SCRIPTS {
        return Err(RpcError::InvalidParameter(
            "At most 1024 scan descriptors are supported".into(),
        ));
    }
    let mut descriptors = Vec::with_capacity(scanobjects.len());
    let mut input_bytes = 0usize;
    let mut script_count = 0usize;
    for scanobject in scanobjects {
        if cancelled()? {
            return Ok(std::collections::BTreeMap::new());
        }
        let (descriptor, range) = scanobject_descriptor(scanobject)?;
        let range = range.map(parse_derivation_range).transpose()?;
        input_bytes = input_bytes.saturating_add(descriptor.len());
        if descriptor.len() > MAX_SCAN_DESCRIPTOR_BYTES || input_bytes > MAX_SCAN_INPUT_BYTES {
            return Err(RpcError::InvalidParameter(
                "Scan descriptor byte limit exceeded".into(),
            ));
        }
        let descriptor = scan_descriptor(descriptor, range, network)?;
        script_count = script_count.saturating_add(descriptor.script_count());
        if script_count > bitcoin_rs_utxo::scan::MAX_SCAN_SCRIPTS {
            return Err(RpcError::InvalidParameter(
                "At most 1024 scan script expansions are supported".into(),
            ));
        }
        descriptors.push(descriptor);
    }
    let mut scripts = std::collections::BTreeMap::new();
    let mut script_bytes = 0usize;
    for descriptor in descriptors {
        if cancelled()? {
            break;
        }
        descriptor.expand(
            &cancelled,
            |ScanScript {
                 script_pubkey,
                 desc,
             }| {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    scripts.entry(script_pubkey)
                {
                    script_bytes += entry.key().len();
                    if script_bytes > bitcoin_rs_utxo::scan::MAX_SCAN_SCRIPT_BYTES {
                        return Err(RpcError::InvalidParameter(
                            "Scan script byte limit exceeded".into(),
                        ));
                    }
                    entry.insert(desc);
                }
                Ok(())
            },
        )?;
    }
    Ok(scripts)
}

fn scanobject_descriptor(scanobject: &Value) -> Result<(&str, Option<&Value>), RpcError> {
    if let Some(descriptor) = scanobject.as_str() {
        return Ok((descriptor, None));
    }
    let object = scanobject.as_object().ok_or_else(|| {
        RpcError::InvalidParameter("Scan object needs to be either a string or an object".into())
    })?;
    let descriptor = object
        .get(&"desc")
        .filter(|value| !value.is_null())
        .ok_or_else(|| {
            RpcError::InvalidParameter("Descriptor needs to be provided in scan object".into())
        })?;
    let descriptor = descriptor
        .as_str()
        .ok_or_else(|| super::wrong_type_plain(descriptor, "string"))?;
    let range = object.get(&"range").filter(|value| !value.is_null());
    Ok((descriptor, range))
}

fn scan_unspents(
    scan: &bitcoin_rs_utxo::UtxoScan,
    descs: &std::collections::BTreeMap<Vec<u8>, String>,
    hashes: &std::collections::BTreeMap<u32, Hash256>,
    applied_height: u32,
    cancelled: impl Fn() -> Result<bool, RpcError>,
) -> Result<(Vec<v31::ScanTxOutSetUnspent>, u64, bool), RpcError> {
    let mut total_amount = 0_u64;
    let mut response_bytes = 0usize;
    let mut unspents = Vec::with_capacity(scan.unspents.len());
    for utxo in &scan.unspents {
        if cancelled()? {
            return Ok((unspents, total_amount, false));
        }
        let desc = descs
            .get(utxo.txout.script_pubkey.as_slice())
            .ok_or_else(|| RpcError::Internal("scan matched an unknown script".into()))?;
        response_bytes += desc.len() + utxo.txout.script_pubkey.len() * 2 + 1024;
        if response_bytes > MAX_SCAN_RESPONSE_BYTES {
            return Err(RpcError::Misc(
                "UTXO scan limit exceeded: 16 MiB response budget".into(),
            ));
        }
        let outpoint = utxo.outpoint;
        let txid = outpoint.txid;
        let block_hash = hashes
            .get(&utxo.height)
            .ok_or_else(|| RpcError::Misc("scan block ancestry is unavailable".into()))?;
        unspents.push(v31::ScanTxOutSetUnspent {
            txid: txid.to_string(),
            vout: outpoint.vout,
            script_pubkey: utxo.txout.script_pubkey.to_lower_hex_string(),
            descriptor: desc.clone(),
            amount: sat_to_btc(utxo.txout.value.to_sat()),
            coinbase: utxo.coinbase,
            height: u64::from(utxo.height),
            block_hash: block_hash.to_string(),
            confirmations: scan_confirmations(applied_height, utxo.height),
        });
        total_amount = total_amount
            .checked_add(utxo.txout.value.to_sat())
            .ok_or_else(|| RpcError::Internal("scan amount overflow".into()))?;
    }
    Ok((unspents, total_amount, !cancelled()?))
}

fn scan_confirmations(applied_height: u32, output_height: u32) -> u64 {
    if output_height > applied_height {
        0
    } else {
        u64::from(applied_height - output_height) + 1
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
    Err(RpcError::InvalidType(
        "verbosity must be number or boolean".to_owned(),
    ))
}

fn parse_hash(value: &str) -> Result<Hash256, RpcError> {
    Hash256::from_str(value).map_err(|_| RpcError::InvalidParams("hash must be 64 hex characters"))
}

/// The block's depth in the **active chain**, or `-1` when it is not in the
/// active chain at all.
pub(super) fn confirmations(ctx: &Context, view: &AppliedView, hash: Hash256, height: u32) -> i64 {
    let Some(tip) = view.tip() else {
        return -1;
    };
    if height > tip.height {
        return -1;
    }
    let active_hash = if height == tip.height {
        Some(tip.hash)
    } else {
        let tree = ctx.chain.block_tree.read();
        tree.node_at_height_from(tip.tip_id, height)
            .and_then(|id| tree.node(id).ok().map(|node| node.hash))
    };
    let on_active = active_hash == Some(hash);
    crate::render::confirmations(view.height(), height, on_active)
}

fn block_verbose_typed(
    ctx: &Context,
    record: &BlockRecord,
    include_block_fields: bool,
    verbosity: u64,
) -> Result<Value, RpcError> {
    let header = decode_header(record)?;
    let hash = Hash256::from(record.hash);
    let view = ctx.chain.applied_view();
    let block_confirmations = confirmations(ctx, &view, hash, record.height);
    let mediantime = ctx.chain.median_time_past_for_hash(hash).unwrap_or(0);
    let chainwork_hex = ctx
        .chain
        .chain_work_hex_for_hash(hash)
        .unwrap_or_else(|| "00".to_owned());
    let next_block_hash = (block_confirmations > 0)
        .then(|| {
            record
                .height
                .checked_add(1)
                .and_then(|next| ctx.chain.active_hash_in_view(&view, next))
        })
        .flatten()
        .map(BlockHash::from);
    if !include_block_fields {
        return render_block_header_verbose(
            ctx,
            record,
            &header,
            BlockHeaderRenderFacts {
                confirmations: block_confirmations,
                mediantime,
                chainwork_hex,
                next_block_hash,
            },
        );
    }
    let (block, spent) = block_with_spends(ctx, record, &view, verbosity)?;
    let coinbase_tx = convert::coinbase_transaction_typed(block.txs.first())
        .ok_or_else(|| RpcError::Internal("block has no coinbase transaction".to_owned()))?;
    let coinbase_version = u32::from_le_bytes(coinbase_tx.version.to_le_bytes());
    let mut value = if verbosity < 2 {
        typed_to_sonic(&v31::GetBlockVerboseOne {
            hash: record.hash.to_string(),
            confirmations: block_confirmations,
            size: i64_saturated(block.total_size()),
            stripped_size: Some(i64_saturated(block.stripped_size())),
            weight: block.weight(),
            coinbase_tx,
            height: i64::from(record.height),
            version: header.version,
            version_hex: format!("{:08x}", u32::from_le_bytes(header.version.to_le_bytes())),
            merkle_root: header.merkle_root.to_string_be(),
            tx: block.txs.iter().map(|tx| tx.txid().to_string()).collect(),
            time: i64::from(header.time),
            median_time: Some(i64_saturated(u64::from(mediantime))),
            nonce: i64::from(header.nonce),
            bits: format!("{:08x}", header.bits),
            target: compact_target_hex(header.bits),
            difficulty: ctx.chain.difficulty_for_bits(header.bits),
            chain_work: chainwork_hex,
            n_tx: i64_saturated(record.tx_count),
            previous_block_hash: Some(header.prev_blockhash.to_string()),
            next_block_hash: next_block_hash.map(|hash| hash.to_string()),
        })?
    } else {
        let base = v31::GetBlockVerboseTwo {
            hash: record.hash.to_string(),
            confirmations: block_confirmations,
            size: i64_saturated(block.total_size()),
            stripped_size: Some(i64_saturated(block.stripped_size())),
            weight: block.weight(),
            coinbase_tx,
            height: i64::from(record.height),
            version: header.version,
            version_hex: format!("{:08x}", u32::from_le_bytes(header.version.to_le_bytes())),
            merkle_root: header.merkle_root.to_string_be(),
            tx: Vec::new(),
            time: i64::from(header.time),
            median_time: Some(i64_saturated(u64::from(mediantime))),
            nonce: i64::from(header.nonce),
            bits: format!("{:08x}", header.bits),
            target: compact_target_hex(header.bits),
            difficulty: ctx.chain.difficulty_for_bits(header.bits),
            chain_work: chainwork_hex,
            n_tx: i64_saturated(block.txs.len()),
            previous_block_hash: (record.height > 0).then(|| header.prev_blockhash.to_string()),
            next_block_hash: next_block_hash.map(|hash| hash.to_string()),
        };
        render_detailed_block(
            &base,
            &block,
            spent.as_deref(),
            verbosity,
            ctx.chain.chain_network,
        )?
    };
    let coinbase = value
        .as_object_mut()
        .ok_or_else(|| RpcError::Internal("typed block response is not an object".to_owned()))?
        .get_mut(&"coinbase_tx")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| RpcError::Internal("typed block coinbase is not an object".to_owned()))?;
    let _ = coinbase.insert("version", json!(coinbase_version));
    Ok(value)
}

struct BlockHeaderRenderFacts {
    confirmations: i64,
    mediantime: u32,
    chainwork_hex: String,
    next_block_hash: Option<BlockHash>,
}

fn render_block_header_verbose(
    ctx: &Context,
    record: &BlockRecord,
    header: &Header,
    facts: BlockHeaderRenderFacts,
) -> Result<Value, RpcError> {
    typed_to_sonic(&v31::GetBlockHeaderVerbose {
        hash: record.hash.to_string(),
        confirmations: facts.confirmations,
        height: i64::from(record.height),
        version: header.version,
        version_hex: format!("{:08x}", u32::from_le_bytes(header.version.to_le_bytes())),
        merkle_root: header.merkle_root.to_string_be(),
        time: i64::from(header.time),
        median_time: i64_saturated(u64::from(facts.mediantime)),
        nonce: i64::from(header.nonce),
        bits: format!("{:08x}", header.bits),
        target: compact_target_hex(header.bits),
        difficulty: ctx.chain.difficulty_for_bits(header.bits),
        chain_work: facts.chainwork_hex,
        n_tx: u32::try_from(record.tx_count).unwrap_or(u32::MAX),
        previous_block_hash: Some(header.prev_blockhash.to_string()),
        next_block_hash: facts.next_block_hash.map(|hash| hash.to_string()),
    })
}

type SpentCoins = Vec<Vec<bitcoin_rs_utxo::UtxoCoin>>;

pub(super) fn block_with_spends(
    ctx: &Context,
    record: &BlockRecord,
    view: &AppliedView,
    verbosity: u64,
) -> Result<(Block, Option<SpentCoins>), RpcError> {
    if verbosity >= 2
        && let Some(source) = &ctx.chain.block_undo_source
    {
        let result = source
            .block_spends(record.hash.into(), view.hash(ctx.chain.chain_network))
            .map_err(block_spends_error)?;
        let spent = match result.spent {
            Ok(spent) => Some(spent),
            Err(
                bitcoin_rs_utxo::contract::HistoryUnavailable::Missing
                | bitcoin_rs_utxo::contract::HistoryUnavailable::Pruned { .. },
            ) => None,
            Err(reason) => {
                return Err(block_spends_error(
                    bitcoin_rs_utxo::contract::BlockSpendsError::History(reason),
                ));
            }
        };
        if spent
            .as_ref()
            .is_some_and(|rows| rows.len() != result.block.txs.len())
        {
            return Err(RpcError::CoreInternal(
                "block undo transaction count differs".to_owned(),
            ));
        }
        return Ok((result.block, spent));
    }
    let (_, block) = decode_block(ctx, record)?;
    Ok((block, None))
}

fn block_spends_error(error: bitcoin_rs_utxo::contract::BlockSpendsError) -> RpcError {
    use bitcoin_rs_utxo::contract::{BlockSpendsError as E, BoundedReadError, HistoryUnavailable};
    match error {
        E::UnknownBlock => RpcError::InvalidAddressOrKey("Block not found".to_owned()),
        E::History(HistoryUnavailable::Pruned { .. }) => RpcError::Misc("Block not available (pruned data)".to_owned()),
        E::History(HistoryUnavailable::Missing) | E::BodyRead(BoundedReadError::Storage(_)) => RpcError::Misc("Block not found on disk".to_owned()),
        E::Undo(_) | E::Corrupt(_) | E::BoundedRead(BoundedReadError::Storage(_)) => RpcError::CoreInternal(
            "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.".to_owned()),
        other => RpcError::Misc(other.to_string()),
    }
}

fn render_detailed_block(
    base: &v31::GetBlockVerboseTwo,
    block: &Block,
    spent: Option<&[Vec<bitcoin_rs_utxo::UtxoCoin>]>,
    verbosity: u64,
    network: Network,
) -> Result<Value, RpcError> {
    let tx = block
        .txs
        .iter()
        .enumerate()
        .map(|(index, tx)| {
            let coins = spent.and_then(|spent| spent.get(index)).map(Vec::as_slice);
            crate::tx_render::transaction_json_with_spends(tx, network, None, coins, verbosity >= 3)
        })
        .collect::<Result<Vec<_>, RpcError>>()?;
    let mut value = typed_to_sonic_omitting_nulls(base)?;
    let _ = value.insert("tx", json!(tx));
    Ok(value)
}

fn decode_header(record: &BlockRecord) -> Result<Header, RpcError> {
    let Some(bytes) = record.header_bytes() else {
        return Err(RpcError::Internal(
            "stored block header is corrupt".to_owned(),
        ));
    };
    deserialize(bytes.as_slice()).map_err(|error| {
        tracing::warn!(
            block_hash = %record.hash,
            %error,
            "stored block header bytes are invalid"
        );
        RpcError::Internal("stored block header is corrupt".to_owned())
    })
}

fn decode_block(ctx: &Context, record: &BlockRecord) -> Result<(Vec<u8>, Block), RpcError> {
    let Some(bytes) = ctx.chain.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    deserialize(bytes.as_slice())
        .map(|block| (bytes, block))
        .map_err(|error| {
            tracing::warn!(
                block_hash = %record.hash,
                %error,
                "stored block bytes are invalid"
            );
            RpcError::Internal("stored block body is corrupt".to_owned())
        })
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::unwrap_used)]
mod tests;
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
                pruneheight: self.result_pruneheight.unwrap_or(requested_height),
            })
        }

        fn status(&self) -> crate::context::PruneStatus {
            self.status
        }
    }

    fn set_applied_tip(ctx: &Context, height: u32) {
        ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: NodeId::new(0),
            height,
            chainwork: ChainWork::ZERO,
            hash: Hash256::default(),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
        })));
    }

    fn pruning_context() -> Arc<Context> {
        {
            let mut ctx = Context::new();
            ctx.chain.prune_service = Some(Arc::new(FakePruneService {
                status: crate::context::PruneStatus {
                    pruned: true,
                    pruneheight: None,
                },
                result_pruneheight: None,
            }));
            Arc::new(ctx)
        }
    }

    fn fixture_genesis_header() -> Header {
        Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_296_688_602,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        }
    }

    #[test]
    fn pruneblockchain_answers_the_service_height_and_refuses_unsafe_requests() {
        let ctx = pruning_context();
        set_applied_tip(&ctx, 400);
        let requested = pruneblockchain(&ctx, &json!([100]))
            .unwrap_or_else(|err| panic!("pruneblockchain failed: {err}"));
        assert_eq!(requested.as_u64(), Some(100));

        assert!(matches!(
            pruneblockchain(&ctx, &json!([200])),
            Err(RpcError::InvalidParams(
                "prune height is within reorg safety margin"
            ))
        ));
        assert!(matches!(
            pruneblockchain(&ctx, &json!([401])),
            Err(RpcError::InvalidParams(
                "prune height cannot exceed applied tip"
            ))
        ));

        let mut reporting = Context::new();
        reporting.chain.prune_service = Some(Arc::new(FakePruneService {
            status: crate::context::PruneStatus {
                pruned: true,
                pruneheight: Some(150),
            },
            result_pruneheight: Some(150),
        }));
        let reporting = Arc::new(reporting);
        set_applied_tip(&reporting, 400);
        let served = pruneblockchain(&reporting, &json!([100]))
            .unwrap_or_else(|err| panic!("pruneblockchain failed: {err}"));
        assert_eq!(served.as_u64(), Some(150));

        assert!(matches!(
            pruneblockchain(&Arc::new(Context::new()), &json!([100])),
            Err(RpcError::MethodDisabled("pruning is disabled"))
        ));
    }

    #[test]
    fn getblockchaininfo_reports_pruned_status_and_pruneheight() {
        let mut ctx = Context::new();
        ctx.chain.prune_service = Some(Arc::new(FakePruneService {
            status: crate::context::PruneStatus {
                pruned: true,
                pruneheight: Some(42),
            },
            result_pruneheight: None,
        }));
        let ctx = Arc::new(ctx);

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
        let genesis = fixture_genesis_header();
        let hash = {
            let mut tree = ctx.chain.block_tree.write();
            let id = tree
                .insert_node(None, genesis, NodeStatus::Active)
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
            let mut tree = ctx.chain.block_tree.write();
            let genesis = fixture_genesis_header();
            let genesis_id = tree
                .insert_node(None, genesis, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("genesis header must insert: {err}"));
            let child = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: genesis.time.saturating_add(1),
                bits: genesis.bits,
                nonce: genesis.nonce.saturating_add(1),
            };
            let _ = tree
                .insert_node(Some(genesis_id), child, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("child header must insert: {err}"));
            tree.tip()
                .unwrap_or_else(|| panic!("inserted child must publish a tip"))
        };
        ctx.chain
            .applied_tip
            .store(Some(Arc::new((*applied_tip).clone())));

        let result = getblockstats(&ctx, &json!([1]));

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }
}
#[cfg(test)]
mod getchaintips_tests;

#[cfg(test)]
mod verifychain_tests;

fn compute_branchlen(
    tree: &bitcoin_rs_chain::BlockTree,
    leaf_id: bitcoin_rs_chain::NodeId,
    leaf_height: u32,
    active_tip_id: Option<bitcoin_rs_chain::NodeId>,
) -> u32 {
    let Some(active_id) = active_tip_id else {
        return leaf_height;
    };

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
#[expect(clippy::unwrap_used)]
mod chaintxstats_durability_tests;

#[cfg(test)]
mod chaintxstats_window_tests;

#[cfg(test)]
mod verification_progress_wiring_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_chain::{ChainWork, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::Hash256;
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    fn half_applied_ctx(chain_tx_count: Option<u64>) -> Arc<Context> {
        let ctx = Context::new();
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let id = {
            let mut tree = ctx.chain.block_tree.write();
            let id = tree
                .insert_node(None, header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert: {err}"));
            if let Some(count) = chain_tx_count {
                tree.restore_chain_tx_count(id, bitcoin_rs_chain::ChainTxCount::established(count))
                    .unwrap_or_else(|err| panic!("restore: {err}"));
            }
            id
        };
        let applied_chain_tx_count = chain_tx_count.map_or(
            bitcoin_rs_chain::ChainTxCount::UNKNOWN,
            bitcoin_rs_chain::ChainTxCount::established,
        );
        let hash = header.compute_hash().0;
        ctx.chain.chain_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: id,
            height: 100,
            chainwork: ChainWork::ZERO,
            hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
        })));
        ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: id,
            height: 50,
            chainwork: ChainWork::ZERO,
            hash,
            chain_tx_count: applied_chain_tx_count,
        })));
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
        let progress = progress_of(&half_applied_ctx(Some(5_000)));
        assert!(
            progress < 0.001,
            "expected Core's transaction-count estimate, got {progress}"
        );
    }

    #[test]
    fn an_unknown_count_keeps_the_height_ratio_rather_than_reporting_zero() {
        let progress = progress_of(&half_applied_ctx(None));
        assert!(
            (progress - 0.5).abs() < 1e-9,
            "expected the height ratio, got {progress}"
        );
    }
}

#[cfg(test)]
mod scantxoutset_tests;

#[cfg(test)]
mod dumptxoutset_tests {
    use alloc::sync::Arc;
    use std::path::PathBuf;
    use std::sync::{Mutex, PoisonError};

    use bitcoin_rs_primitives::Hash256;
    use sonic_rs::{JsonValueTrait as _, json};

    use crate::context::{
        ChainControl, ChainControlError, Context, SnapshotControlError, SnapshotExport,
    };
    use crate::handlers::Handler;

    struct Exporter {
        seen: Mutex<Option<PathBuf>>,
        failure: Option<fn() -> SnapshotControlError>,
    }

    impl Exporter {
        fn handler(failure: Option<fn() -> SnapshotControlError>) -> (Arc<Self>, Handler) {
            let exporter = Arc::new(Self {
                seen: Mutex::new(None),
                failure,
            });
            let ctx = Context::new().with_chain_control(exporter.clone());
            (exporter, Handler::new(Arc::new(ctx)))
        }

        fn seen(&self) -> Option<PathBuf> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl ChainControl for Exporter {
        fn dump_txoutset(
            &self,
            path: &std::path::Path,
            cancellation: &bitcoin_rs_chain::LatchReader,
        ) -> Result<SnapshotExport, SnapshotControlError> {
            *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(path.to_path_buf());
            if cancellation.is_triggered() {
                return Err(SnapshotControlError::Interrupted);
            }
            if let Some(failure) = self.failure {
                return Err(failure());
            }
            Ok(SnapshotExport {
                coins_written: 3,
                base_hash: Hash256::from_le_bytes(&[1; 32]).to_string_be(),
                base_height: 7,
                path: "/data/out.dat".to_owned(),
                txoutset_hash: Hash256::from_le_bytes(&[2; 32]).to_string_be(),
                nchaintx: 9,
            })
        }

        fn invalidate_block(&self, _hash: Hash256) -> Result<(), ChainControlError> {
            Err(ChainControlError::UnknownBlock)
        }

        fn verify_chain(
            &self,
            _check_level: u8,
            _nblocks: u32,
            _cancellation: &bitcoin_rs_chain::LatchReader,
        ) -> Result<bool, ChainControlError> {
            Ok(false)
        }
    }

    #[test]
    fn positional_and_named_arguments_delegate_and_report_the_core_fields() {
        for params in [
            json!(["out.dat", "latest"]),
            json!({"path": "out.dat", "type": "latest"}),
        ] {
            let (exporter, handler) = Exporter::handler(None);
            let result = handler
                .dispatch("dumptxoutset", &params)
                .unwrap_or_else(|error| panic!("{params}: {error}"));
            assert_eq!(exporter.seen(), Some(PathBuf::from("out.dat")), "{params}");
            assert_eq!(result["coins_written"].as_u64(), Some(3));
            assert_eq!(
                result["base_hash"].as_str(),
                Some(Hash256::from_le_bytes(&[1; 32]).to_string_be().as_str())
            );
            assert_eq!(result["base_height"].as_u64(), Some(7));
            assert_eq!(result["path"].as_str(), Some("/data/out.dat"));
            assert_eq!(
                result["txoutset_hash"].as_str(),
                Some(Hash256::from_le_bytes(&[2; 32]).to_string_be().as_str())
            );
            assert_eq!(result["nchaintx"].as_u64(), Some(9));
        }
    }

    #[test]
    fn only_the_latest_type_is_served_and_refusals_never_reach_the_control() {
        for params in [
            json!(["out.dat"]),
            json!(["out.dat", null]),
            json!(["out.dat", ""]),
            json!(["out.dat", "rollback"]),
            json!(["out.dat", "Latest"]),
            json!({"path": "out.dat"}),
        ] {
            let (exporter, handler) = Exporter::handler(None);
            let error = handler
                .dispatch("dumptxoutset", &params)
                .err()
                .unwrap_or_else(|| panic!("{params} must be refused"));
            assert_eq!(error.code(), -8, "{params}: {error}");
            assert_eq!(exporter.seen(), None, "{params}");
        }
        for (params, code) in [
            (json!([]), -32602),
            (json!([5, "latest"]), -3),
            (json!(["out.dat", 5]), -3),
            (json!(["out.dat", "latest", {}]), -32602),
            (
                json!({"path": "out.dat", "type": "latest", "rollback": 1}),
                -8,
            ),
        ] {
            let (exporter, handler) = Exporter::handler(None);
            let error = handler
                .dispatch("dumptxoutset", &params)
                .err()
                .unwrap_or_else(|| panic!("{params} must be refused"));
            assert_eq!(error.code(), code, "{params}: {error}");
            assert_eq!(exporter.seen(), None, "{params}");
        }
    }

    #[test]
    fn control_errors_keep_their_transport_codes_and_a_stopped_handler_interrupts() {
        let params = json!(["out.dat", "latest"]);
        let cases: [(fn() -> SnapshotControlError, i64); 4] = [
            (|| SnapshotControlError::File("exists".to_owned()), -8),
            (
                || SnapshotControlError::Unavailable("busy".to_owned()),
                -32603,
            ),
            (|| SnapshotControlError::Failed("disk".to_owned()), -32603),
            (|| SnapshotControlError::Interrupted, -1),
        ];
        for (failure, code) in cases {
            let (_exporter, handler) = Exporter::handler(Some(failure));
            let error = handler
                .dispatch("dumptxoutset", &params)
                .err()
                .unwrap_or_else(|| panic!("the control failure must surface"));
            assert_eq!(error.code(), code, "{error}");
        }

        let (exporter, handler) = Exporter::handler(None);
        handler.stop();
        let error = handler
            .dispatch("dumptxoutset", &params)
            .err()
            .unwrap_or_else(|| panic!("a stopped handler must interrupt the export"));
        assert_eq!(error.code(), -1, "{error}");
        assert_eq!(exporter.seen(), Some(PathBuf::from("out.dat")));
    }

    #[test]
    fn missing_chain_control_is_an_internal_error() {
        let handler = Handler::new(Arc::new(Context::new()));
        let error = handler
            .dispatch("dumptxoutset", &json!(["out.dat", "latest"]))
            .err()
            .unwrap_or_else(|| panic!("no control must refuse the export"));
        assert_eq!(error.code(), -32603, "{error}");
    }
}
