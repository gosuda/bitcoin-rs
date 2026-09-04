use alloc::sync::Arc;
use core::str::FromStr as _;
use core::{fmt, fmt::Write as _};

use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, TxOut, consensus_bytes, deserialize,
};
use corepc_types::v31::{self, ChainTips, ChainTipsStatus};
use hashbrown::HashMap;
use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait, Value, json};

use super::util::{descriptor_checksum, strip_addr_wrapper};
use crate::compat::convert::{
    self, compact_target_hex, i32_saturated, i64_saturated, i64_saturated_len, sat_to_btc,
    typed_to_sonic, typed_to_sonic_omitting_nulls,
};
use crate::context::{
    BlockRecord, ChainControlError, Context, TxQueryError, cumulative_tx_count_through,
};
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str, required_u64};

pub(crate) fn getblockchaininfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let applied_tip = ctx.applied_tip.load_full();
    let applied = applied_tip.as_ref().map_or(0, |tip| tip.height);
    let headers = ctx.height();
    let (difficulty, time, mediantime, tip_bits) =
        applied_tip
            .as_ref()
            .map_or((0.0, 0_u64, 0_u64, 0_u32), |tip| {
                let tree = ctx.block_tree.read();
                tree.node(tip.tip_id).map_or((0.0, 0, 0, 0), |node| {
                    (
                        ctx.difficulty_for_bits(node.header.bits),
                        u64::from(node.header.time),
                        u64::from(tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0)),
                        node.header.bits,
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
        Network::Mainnet => "main",
        Network::Testnet3 => "test",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    };
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
    let response = v31::GetBlockchainInfo {
        chain: chain.to_owned(),
        blocks: i64::from(applied),
        headers: i64::from(headers),
        best_block_hash: bestblockhash,
        bits: format!("{tip_bits:08x}"),
        target: compact_target_hex(tip_bits),
        difficulty,
        time: i64_saturated(time),
        median_time: i64_saturated(mediantime),
        verification_progress,
        initial_block_download: initialblockdownload,
        chain_work: chainwork,
        size_on_disk,
        pruned: prune_status.pruned,
        prune_height: prune_status.pruneheight.map(i64::from),
        automatic_pruning: None,
        prune_target_size: None,
        signet_challenge: None,
        warnings: ctx
            .rollback_warnings
            .as_ref()
            .map(|source| source.rollback_warnings())
            .unwrap_or_default(),
    };
    typed_to_sonic(&response)
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
/// Lowercase hex encoding for arbitrary byte slices.
fn hex_encode(bytes: &[u8]) -> String {
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
    typed_to_sonic(&v31::GetDifficulty(difficulty))
}

pub(crate) fn getchaintips(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    // Tree guard first, then the tip -- and that order is load-bearing rather
    // than incidental. A connect inserts its node under the tree's write lock
    // and publishes the applied tip afterwards, so while this read guard is
    // held no new node can appear, and any tip published in the meantime names
    // a node that was already in the tree when the guard was taken. Loading the
    // tip first would allow the reverse: a tip whose node this view has never
    // seen, and every lookup below it answering `None` for a block the node has
    // certainly connected.
    let tree = ctx.block_tree.read();
    // The active chain is the one this node has *connected*, not the one its
    // headers describe. Header-first sync runs the header tree thousands of
    // blocks ahead of the applied tip during initial sync, and calling that
    // lead "active" reports a chain the node has not validated -- while the
    // chain it has validated goes unreported. Bitcoin Core asks
    // `ActiveChain().Tip()`, which is the connected tip.
    let active_tip = ctx.applied_tip.load_full();
    let active_tip_id = active_tip.as_ref().map(|tip| tip.tip_id);

    // Core reports the active tip whether or not it is a leaf, and during
    // initial sync it is not one: the headers already describe its
    // descendants, so nothing here would list it.
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
            // The applied-tip snapshot is the authority on the active tip even
            // when the tree holds no row for it (fresh wiring, pruned rows):
            // Core's `active_chain.Contains` marks that tip active regardless.
            // A non-active id without a row cannot be a tip.
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
        // `NodeStatus` is not a validation record. `BlockTree::insert_node`
        // stamps whichever node carries the most work `Active` and demotes the
        // one it displaced to `Stale`, so on a header-first node every accepted
        // header on the best chain is `Active` while its block sits
        // unconnected. Reading it as "this block was validated" is what made a
        // header tip report itself as the active chain.
        //
        // What is decidable: a block is connected exactly when it is the
        // applied tip or an ancestor of it, and a leaf is never an ancestor of
        // anything. So every leaf but the applied tip is unconnected *now*, and
        // the only question left is whether it ever was.
        let status = match node.status {
            // **Invalid first, ahead of being the applied tip.** The two can
            // both be true at once, and only for as long as it takes an
            // invalidation to finish: `reorg::invalidate_block` marks the
            // subtree invalid under the tree's write lock and releases it, and
            // republishes `applied_tip` afterwards, when the disconnect has
            // run. A call landing in between holds a tree view that says
            // "invalid" and an applied tip that still names the block -- and
            // deciding on the tip first labels a block the node has just
            // rejected as the chain it is following. There is no ordering that
            // removes the window, because the two are published separately;
            // what removes the wrong answer is preferring the fact that cannot
            // be stale. A block that is invalid was invalid before this call
            // and stays invalid after it.
            NodeStatus::Invalid => ChainTipsStatus::Invalid,
            _ if is_active => ChainTipsStatus::Active,
            // Everything else is a leaf whose block is not connected now, and
            // the tree keeps no evidence that it ever was.
            //
            // `Stale` is not that evidence, which is the trap: the tree demotes
            // whichever header it displaced, whether or not the block behind it
            // was ever received, let alone applied. On a header-first node most
            // stale nodes are headers whose bodies never arrived. Calling those
            // `valid-fork` -- Core's "fully validated, since reorganised" --
            // claims a validation that never happened.
            //
            // So `valid-fork` is never emitted. Core's `valid-headers` is not
            // either: it means the body is present and unvalidated, which this
            // node cannot reach because it applies a block as it arrives.
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
    // Core orders by height descending, with no special place for the active
    // tip -- a longer fork is listed above it, which is the thing an operator
    // is looking for. Ties break on the hash, so the order is the same on
    // every call rather than following slab layout.
    tips.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| a.hash.cmp(&b.hash)));
    typed_to_sonic(&v31::GetChainTips(tips))
}

pub(crate) fn getchaintxstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ctx.with_stable_chainstate(|| {
        // Bitcoin Core's default: one month of ten-minute blocks.
        const DEFAULT_WINDOW: u64 = 30 * 24 * 6; // ~1 month of 10-min blocks

        let array = params_array(params)?;
        let tip_hash = match array.get(1).filter(|value| !value.is_null()) {
            None => ctx.applied_hash(),
            Some(value) => {
                let hash = parse_hash(
                    value
                        .as_str()
                        .ok_or(RpcError::InvalidType("blockhash must be a string"))?,
                )?;
                let Some(height) = ctx.height_for_hash(hash) else {
                    return Err(RpcError::NotFound("block not found"));
                };
                if ctx.block_hash_at_height(height) != Some(hash) {
                    return Err(RpcError::InvalidParameter(
                        "Block is not in main chain".to_owned(),
                    ));
                }
                hash
            }
        };
        let tip_height = ctx
            .height_for_hash(tip_hash)
            .unwrap_or_else(|| ctx.applied_height());
        let default_window = DEFAULT_WINDOW.min(u64::from(tip_height.saturating_sub(1)));
        let window_block_count = match array.first().filter(|value| !value.is_null()) {
            None => default_window,
            Some(value) => {
                let nblocks = value
                    .as_i64()
                    .ok_or(RpcError::InvalidType("nblocks must be a number"))?;
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
            let tree = ctx.block_tree.read();
            window_stats(ctx, &tree, tip_hash, window_block_count)?
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
        // The applied tip always answers `txcount` (0 when nobody counted it);
        // a historical block omits it when the count is unknown, and so does a
        // call that selected nothing.
        if (!stats.selected || (!stats.is_applied_tip && stats.total_tx_count.is_none()))
            && let Some(object) = result.as_object_mut()
        {
            object.remove(&"txcount");
        }
        Ok(result)
    })
}

/// The figures a `getchaintxstats` response is built from.
///
/// `total_tx_count` and `window_tx_count` are `Option` because a count nobody
/// measured is omitted rather than reported as a zero that reads as real. The
/// applied tip is the one block that always answers `txcount` (with `0` when
/// it is the unknown case); any other block omits the field when the count
/// cannot be found.
struct ChainTxStats {
    /// Whether a block answered the selection at all.
    selected: bool,
    /// Whether the selected block is the applied tip.
    is_applied_tip: bool,
    /// Cumulative transactions through the selected block, when known.
    total_tx_count: Option<u64>,
    /// The selected block's header time.
    tip_time: u32,
    /// Transactions inside the window, when the window is open and known.
    window_tx_count: Option<u64>,
    /// The window's length in seconds (a difference of two median times).
    window_interval: u64,
}

/// The cumulative transaction count through `node_id`, when it is known.
///
/// The node's own count answers when the block was counted; the durable
/// counter answers for the applied tip alone; the record log answers for any
/// height it still holds back to genesis. `None` when nobody knows.
fn count_through(
    ctx: &Context,
    tree: &bitcoin_rs_chain::BlockTree,
    node_id: bitcoin_rs_chain::NodeId,
    is_applied_tip: bool,
) -> Option<u64> {
    let node = tree.node(node_id).ok()?;
    if node.chain_tx_count > 0 {
        return Some(node.chain_tx_count);
    }
    if is_applied_tip && let Some(count) = ctx.chain_tx_count() {
        return Some(count);
    }
    let log = ctx.blocks.read();
    cumulative_tx_count_through(&log, node.height)
}

/// Transactions inside the window, from one source for both ends.
///
/// The durable counter is a tip total and cannot name the ancestor, so it
/// does not participate here. Mixing it with a log prefix would report
/// `durable_tip - log_start` whenever the two disagreed. The tree answers
/// when both nodes were counted; otherwise a complete genesis-to-end log
/// prefix answers both ends together. `None` when neither source can.
fn window_tx_count_between(
    ctx: &Context,
    tree: &bitcoin_rs_chain::BlockTree,
    start_id: bitcoin_rs_chain::NodeId,
    end_id: bitcoin_rs_chain::NodeId,
) -> Option<u64> {
    let start = tree.node(start_id).ok()?;
    let end = tree.node(end_id).ok()?;
    if end.chain_tx_count > 0 && start.chain_tx_count > 0 {
        return Some(end.chain_tx_count.saturating_sub(start.chain_tx_count));
    }
    let log = ctx.blocks.read();
    let end_count = cumulative_tx_count_through(&log, end.height)?;
    let start_count = cumulative_tx_count_through(&log, start.height)?;
    Some(end_count.saturating_sub(start_count))
}

/// Computes the figures behind a `getchaintxstats` response against a block
/// tree the caller already holds a read guard on.
///
/// `window_interval` is the difference of the median-time-past of the window's
/// two boundary blocks, matching Bitcoin Core: raw header timestamps are not
/// ordered, so their difference cannot measure an elapsed time.
fn window_stats(
    ctx: &Context,
    tree: &bitcoin_rs_chain::BlockTree,
    tip_hash: Hash256,
    window_block_count: u64,
) -> Result<ChainTxStats, RpcError> {
    let Some(selected_id) = tree.lookup(tip_hash) else {
        let applied = ctx.applied_tip.load_full();
        let tip_time = applied
            .as_ref()
            .and_then(|tip| tree.node(tip.tip_id).ok().map(|node| node.header.time))
            .unwrap_or(0);
        // The applied tip answers `txcount` even when its node is not in the
        // tree (the count is simply unknown, reported as 0). Only a call with
        // no applied tip at all selects nothing and omits the field.
        let is_applied_tip = applied.is_some_and(|tip| tip.hash == tip_hash);
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
    let is_applied_tip = ctx.applied_hash() == tip_hash;
    let total_tx_count = count_through(ctx, tree, selected_id, is_applied_tip);
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
    let window_tx_count = window_tx_count_between(ctx, tree, start_id, selected_id);
    let end_mtp = tree.median_time_past_at(selected_id, 11).unwrap_or(0);
    let start_mtp = tree.median_time_past_at(start_id, 11).unwrap_or(0);
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
    typed_to_sonic(&v31::GetBlockCount(u64::from(ctx.applied_height())))
}

pub(crate) fn getblockhash(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let height = required_u64(params, 0, "height is required")?;
    let height =
        u32::try_from(height).map_err(|_| RpcError::InvalidParams("height exceeds u32"))?;
    ctx.block_hash_at_height(height)
        .map(|hash| typed_to_sonic(&v31::GetBlockHash(hash.to_string_be())))
        .transpose()?
        .ok_or(RpcError::NotFound("block height not found"))
}

pub(crate) fn getbestblockhash(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    typed_to_sonic(&v31::GetBestBlockHash(ctx.applied_hash().to_string_be()))
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
        return typed_to_sonic(&v31::GetBlockVerboseZero(block_payload_hex));
    }
    block_verbose_typed(ctx, &record, true, verbosity)
}

pub(crate) fn getblockheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let verbose = optional_bool(params, 1, true)?;
    let record = ctx
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
        ctx.block_by_height(height)
    } else if let Some(hash) = target.as_str() {
        let hash = parse_hash(hash)?;
        let record = ctx.block_by_hash(hash);
        if let Some(record) = &record
            && ctx.block_hash_at_height(record.height) != Some(hash)
        {
            return Err(RpcError::InvalidParams("Block is not in main chain"));
        }
        record
    } else {
        return Err(RpcError::InvalidType(
            "hash_or_height must be string or number",
        ));
    };
    record.ok_or(RpcError::NotFound("block not found"))
}

pub(crate) fn getblockstats(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let record = blockstats_record(ctx, params)?;

    let (_bytes, block) = decode_block(ctx, &record)?;
    let height = record.height;
    let block_hash = record.hash;
    let subsidy_sat =
        bitcoin_rs_consensus::block_subsidy(height, ctx.chain_network.subsidy_halving_interval());
    let mediantime = ctx
        .median_time_past_for_hash(Hash256::from(block_hash))
        .unwrap_or(0);
    let fee_fields = compute_fee_fields(ctx, &block).map_err(TxQueryError::into_rpc_error)?;
    let utxo_size_inc =
        utxo_size_inc_for_block(ctx, &block).map_err(TxQueryError::into_rpc_error)?;
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
            total_out = total_out.saturating_add(output.value);
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

fn resolve_per_tx_fees(ctx: &Context, block: &Block) -> Result<Vec<(u64, u64)>, TxQueryError> {
    let Some(tx_index) = ctx.tx_index.as_ref() else {
        return Err(TxQueryError::Unavailable(
            "transaction index disabled".into(),
        ));
    };
    let tx_count = block.txs.len().saturating_sub(1);
    let mut fees = Vec::with_capacity(tx_count);
    for tx in block.txs.iter().skip(1) {
        let mut total_in = 0_u64;
        for input in &tx.inputs {
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
        let total_out = tx
            .outputs
            .iter()
            .fold(0_u64, |sum, output| sum.saturating_add(output.value));
        let Some(fee) = total_in.checked_sub(total_out) else {
            return Err(TxQueryError::Unavailable("negative fee".into()));
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
    let Some(tx_index) = ctx.tx_index.as_ref() else {
        return Err(TxQueryError::Unavailable(
            "transaction index disabled".into(),
        ));
    };
    for tx in block.txs.iter().skip(1) {
        for input in &tx.inputs {
            let Some(prev) = tx_index.transaction(&input.previous_output.txid)? else {
                return Err(TxQueryError::Unavailable(
                    "input transaction missing from complete index".into(),
                ));
            };
            let Some(output) = prev
                .outputs
                .get(usize::try_from(input.previous_output.vout).unwrap_or(usize::MAX))
            else {
                return Err(TxQueryError::Unavailable(
                    "input vout missing from complete index".into(),
                ));
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
    typed_to_sonic(&v31::PruneBlockchain(i64::from(result.pruneheight)))
}

pub(crate) fn invalidateblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let hash = parse_hash(required_str(params, 0, "block hash is required")?)?;
    let control = ctx
        .chain_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("invalidateblock is unavailable"))?;
    match control.invalidate_block(hash) {
        Ok(()) => Ok(Value::new_null()),
        Err(ChainControlError::UnknownBlock) => Err(RpcError::NotFound("block not found")),
        Err(ChainControlError::Genesis) => Err(RpcError::InvalidParams(
            "cannot invalidate the genesis block",
        )),
        Err(ChainControlError::Failed(message)) => Err(RpcError::Internal(message)),
    }
}

pub(crate) fn verifychain(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let checklevel = array.first().and_then(JsonValueTrait::as_u64).unwrap_or(3);
    let nblocks_param = array.get(1).and_then(JsonValueTrait::as_u64).unwrap_or(6);
    let Ok(nblocks) = u32::try_from(nblocks_param) else {
        return Err(RpcError::InvalidParams("nblocks exceeds u32"));
    };
    if checklevel == 0 {
        // Bitcoin Core: checklevel 0 reads blocks from disk without per-block verification.
        // bitcoin-rs reports pass since this v1 doesn't surface block-read failures here.
        return typed_to_sonic(&v31::VerifyChain(true));
    }
    let tree = ctx.block_tree.read();
    let Some(applied) = ctx.applied_tip.load_full() else {
        return typed_to_sonic(&v31::VerifyChain(true));
    };
    let mut cursor = applied.tip_id;
    let mut checked: u32 = 0;
    loop {
        if checked >= nblocks {
            break;
        }
        let Ok(node) = tree.node(cursor) else {
            return typed_to_sonic(&v31::VerifyChain(false));
        };
        // L1+: PoW self-consistency check.
        if !compact_target_met_by(node.header.bits, node.header.compute_hash().0) {
            return typed_to_sonic(&v31::VerifyChain(false));
        }
        // L2+: Merkle-root sanity when block body is available. Absent blocks
        // (header-only / pruned) skip the merkle check.
        if checklevel >= 2 {
            if let Some(record) = ctx.block_by_hash(node.hash) {
                if let Some(bytes) = ctx.block_body_bytes(&record) {
                    if let Ok(block) = deserialize::<Block>(&bytes) {
                        let txids = block.txids();
                        if !bitcoin_rs_consensus::verify_block::block_merkle_root_matches_txids(
                            &block, &txids,
                        ) {
                            return typed_to_sonic(&v31::VerifyChain(false));
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
    typed_to_sonic(&v31::VerifyChain(true))
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
        let stats =
            bitcoin_rs_utxo::stats::scan_coin_stats(view, ctx.applied_height(), want_muhash)
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
    let disk_size = ctx.utxo.with_stable_view(|view| {
        u64::try_from(view.memory_report().accounted_bytes()).unwrap_or(u64::MAX)
    });
    let (hash_serialized_3, muhash) = set_hash.map_or((None, None), |(name, hash)| {
        if name == "hash_serialized_3" {
            (Some(hash), None)
        } else {
            (None, Some(hash))
        }
    });
    typed_to_sonic_omitting_nulls(&v31::GetTxOutSetInfo {
        height: i64::from(ctx.applied_height()),
        best_block: ctx.applied_hash().to_string_be(),
        transactions: Some(i64_saturated_len(transactions)),
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
        .tx_index
        .as_ref()
        .map(|tx_index| tx_index.index_info())
        .transpose()?;
    let txindex_entry = txindex_entry.map(|info| v31::GetIndexInfoName {
        synced: info.synced,
        best_block_height: info.best_block_height,
    });
    let mut indexes = alloc::collections::BTreeMap::new();
    if let Some(entry) = txindex_entry {
        indexes.insert("txindex".to_owned(), entry);
    }
    // Core answers a named request with only that index; an unknown name
    // yields an empty object, as does a name for a disabled index.
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
///
/// Reports every compiled capability with its compiled/enabled state and
/// live lifecycle status. Extension surface, not Core parity; declared as
/// `Status::Extension` in the compatibility manifest.
pub(crate) fn getcapabilities(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let snapshot = ctx
        .capabilities
        .as_ref()
        .map_or_else(Default::default, |provider| provider.snapshot());
    Ok(json!({ "capabilities": snapshot.capabilities }))
}

#[derive(Clone, Debug)]
struct ScanScript {
    script_pubkey: Vec<u8>,
    desc: String,
}

pub(crate) fn scantxoutset(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let action = required_str(params, 0, "action is required")?;
    match action {
        "start" => scantxoutset_addr_scan(ctx, scanobjects_param(params)?),
        "abort" => typed_to_sonic(&v31::ScanTxOutSetAbort(false)),
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
    let (unspents, total_amount) = scan_unspents(ctx, &scan, &scan_scripts, height);
    typed_to_sonic(&v31::ScanTxOutSetStart {
        success: true,
        tx_outs: u64::try_from(scan.txouts).unwrap_or(u64::MAX),
        height: u64::from(height),
        best_block: bestblock.to_string_be(),
        unspents,
        total_amount: sat_to_btc(total_amount),
    })
}

fn parse_scan_scripts(
    chain_network: Network,
    scanobjects: &sonic_rs::Array,
) -> Result<Vec<ScanScript>, RpcError> {
    let mut scripts = Vec::with_capacity(scanobjects.len());
    for scanobject in scanobjects {
        let descriptor = scanobject_descriptor(scanobject)?;
        scripts.push(parse_addr_scan_script(descriptor, chain_network)?);
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
    chain_network: Network,
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
    let Ok(address) = unchecked.require_network(convert::bitcoin_network(chain_network)) else {
        return Err(RpcError::InvalidParams("Address is not valid"));
    };
    let payload = format!("addr({address})");
    let desc = descriptor_checksum(&payload).map_or_else(
        || payload.clone(),
        |checksum| format!("{payload}#{checksum}"),
    );
    Ok(ScanScript {
        script_pubkey: address.script_pubkey().as_bytes().to_vec(),
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
    ctx: &Context,
    scan: &bitcoin_rs_utxo::UtxoScan,
    scan_scripts: &[ScanScript],
    applied_height: u32,
) -> (Vec<v31::ScanTxOutSetUnspent>, u64) {
    let descs = scan_scripts
        .iter()
        .map(|scan| (scan.script_pubkey.as_slice(), scan.desc.as_str()))
        .collect::<HashMap<_, _>>();
    let mut total_amount = 0_u64;
    let unspents = scan
        .unspents
        .iter()
        .map(|utxo| {
            total_amount = total_amount.saturating_add(utxo.txout.value);
            let desc = descs
                .get(utxo.txout.script_pubkey.as_slice())
                .copied()
                .unwrap_or("");
            // Field copies come before any `&self` method: `OutPoint` is
            // `#[repr(packed)]` (consensus wire layout).
            let (txid, vout) = {
                let outpoint = utxo.outpoint;
                (outpoint.txid, outpoint.vout)
            };
            let block_hash = ctx
                .block_hash_at_height(utxo.height)
                .map_or_else(|| "0".repeat(64), |hash| hash.to_string());
            v31::ScanTxOutSetUnspent {
                txid: txid.to_string(),
                vout,
                script_pubkey: hex_encode(&utxo.txout.script_pubkey),
                descriptor: desc.to_owned(),
                amount: sat_to_btc(utxo.txout.value),
                coinbase: utxo.coinbase,
                height: u64::from(utxo.height),
                block_hash,
                confirmations: scan_confirmations(applied_height, utxo.height),
            }
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

fn block_verbose_typed(
    ctx: &Context,
    record: &BlockRecord,
    include_block_fields: bool,
    verbosity: u64,
) -> Result<Value, RpcError> {
    let header = decode_header(record)?;
    let block_confirmations = confirmations(ctx, Hash256::from(record.hash), record.height);
    let mediantime = ctx
        .median_time_past_for_hash(Hash256::from(record.hash))
        .unwrap_or(0);
    let chainwork_hex = ctx
        .chain_work_hex_for_hash(Hash256::from(record.hash))
        .unwrap_or_else(|| "00".to_owned());
    let next_block_hash = next_applied_block_hash(ctx, record.height);
    if !include_block_fields {
        return typed_to_sonic(&v31::GetBlockHeaderVerbose {
            hash: record.hash.to_string(),
            confirmations: block_confirmations,
            height: i64::from(record.height),
            version: header.version,
            version_hex: format!("{:08x}", u32::from_le_bytes(header.version.to_le_bytes())),
            merkle_root: header.merkle_root.to_string_be(),
            time: i64::from(header.time),
            median_time: i64_saturated(u64::from(mediantime)),
            nonce: i64::from(header.nonce),
            bits: format!("{:08x}", header.bits),
            target: compact_target_hex(header.bits),
            difficulty: ctx.difficulty_for_bits(header.bits),
            chain_work: chainwork_hex,
            n_tx: u32::try_from(record.tx_count).unwrap_or(u32::MAX),
            previous_block_hash: Some(header.prev_blockhash.to_string()),
            next_block_hash: next_block_hash.map(|hash| hash.to_string()),
        });
    }
    let (_bytes, block) = decode_block(ctx, record)?;
    let coinbase_tx = convert::coinbase_transaction_typed(block.txs.first())
        .ok_or_else(|| RpcError::Internal("block has no coinbase transaction".to_owned()))?;
    let size = i64_saturated_len(consensus_bytes(&block).len());
    let stripped_size = i64_saturated_len(crate::render::stripped_size(&block));
    let weight = crate::render::block_weight(&block);
    let bits = format!("{:08x}", header.bits);
    let version_hex = format!("{:08x}", u32::from_le_bytes(header.version.to_le_bytes()));
    if verbosity < 2 {
        return typed_to_sonic(&v31::GetBlockVerboseOne {
            hash: record.hash.to_string(),
            confirmations: block_confirmations,
            size,
            stripped_size: Some(stripped_size),
            weight,
            coinbase_tx,
            height: i64::from(record.height),
            version: header.version,
            version_hex,
            merkle_root: header.merkle_root.to_string_be(),
            tx: block.txs.iter().map(|tx| tx.txid().to_string()).collect(),
            time: i64::from(header.time),
            median_time: Some(i64_saturated(u64::from(mediantime))),
            nonce: i64::from(header.nonce),
            bits,
            target: compact_target_hex(header.bits),
            difficulty: ctx.difficulty_for_bits(header.bits),
            chain_work: chainwork_hex,
            n_tx: i64_saturated_len(record.tx_count),
            previous_block_hash: Some(header.prev_blockhash.to_string()),
            next_block_hash: next_block_hash.map(|hash| hash.to_string()),
        });
    }
    // Verbosity 3 serves the verbosity-2 shape here: no prevout source is
    // wired into block rendering, so per-input prevouts stay absent.
    let mut txs = Vec::with_capacity(block.txs.len());
    for tx in &block.txs {
        txs.push(v31::GetBlockVerboseTwoTransaction {
            transaction: convert::raw_transaction_verbose(tx, ctx.chain_network, None)?,
            fee: None,
        });
    }
    typed_to_sonic(&v31::GetBlockVerboseTwo {
        hash: record.hash.to_string(),
        confirmations: block_confirmations,
        size,
        stripped_size: Some(stripped_size),
        weight,
        coinbase_tx,
        height: i64::from(record.height),
        version: header.version,
        version_hex,
        merkle_root: header.merkle_root.to_string_be(),
        tx: txs,
        time: i64::from(header.time),
        median_time: Some(i64_saturated(u64::from(mediantime))),
        nonce: i64::from(header.nonce),
        bits,
        target: compact_target_hex(header.bits),
        difficulty: ctx.difficulty_for_bits(header.bits),
        chain_work: chainwork_hex,
        n_tx: i64_saturated_len(record.tx_count),
        previous_block_hash: Some(header.prev_blockhash.to_string()),
        next_block_hash: next_block_hash.map(|hash| hash.to_string()),
    })
}

fn next_applied_block_hash(ctx: &Context, height: u32) -> Option<BlockHash> {
    let tip = ctx.applied_tip.load_full()?;
    let next_height = height.checked_add(1)?;
    if next_height > tip.height {
        return None;
    }
    let tree = ctx.block_tree.read();
    let node_id = tree.node_at_height_from(tip.tip_id, next_height)?;
    let node = tree.node(node_id).ok()?;
    Some(BlockHash::from(node.hash))
}

/// WHY-local: the chain crate's compact-target helpers are `pub(crate)`, and
/// this crate must not grow a dependency to reach them. `verifychain` only
/// needs the `PoW` self-consistency verdict the old `validate_pow` call made:
/// decode `bits` into a 256-bit target and compare the header hash against it
/// (both read as little-endian integers, as consensus does).
fn compact_target_met_by(bits: u32, hash: Hash256) -> bool {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    // A zero mantissa or a negative sign bit decodes to a zero target, and an
    // exponent past 32 bytes overflows the 256-bit range; none are meetable.
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let mut target = [0_u8; 32];
    let mantissa_bytes = mantissa.to_le_bytes();
    let start = exponent - 3;
    target[start..start + 3].copy_from_slice(&mantissa_bytes[..3]);
    let hash_bytes = hash.to_le_bytes();
    hash_bytes
        .iter()
        .rev()
        .zip(target.iter().rev())
        .map(|(hash_byte, target_byte)| hash_byte.cmp(target_byte))
        .find(|ordering| *ordering != core::cmp::Ordering::Equal)
        .unwrap_or(core::cmp::Ordering::Equal)
        != core::cmp::Ordering::Greater
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
    let Some(bytes) = ctx.block_body_bytes(record) else {
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, Txid};

    use super::*;
    use crate::context::BlockLog;
    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};

    struct SingleBlockSource {
        height: u32,
        hash: BlockHash,
        body: Vec<u8>,
        calls: core::sync::atomic::AtomicUsize,
    }

    struct MultiBlockSource {
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    }

    impl crate::context::BlockBodySource for MultiBlockSource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
            self.bodies
                .iter()
                .find(|(h, k, _)| *h == height && *k == hash)
                .map(|(_, _, body)| body.clone())
        }
    }

    impl crate::context::BlockBodySource for SingleBlockSource {
        fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
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
            let mut previous_hash = BlockHash::default();
            let mut tip_id = NodeId::new(0);
            let mut tip_hash = Hash256::default();
            for (index, time) in times.iter().copied().enumerate() {
                let header = Header {
                    version: 1,
                    prev_blockhash: previous_hash,
                    merkle_root: Hash256::default(),
                    time,
                    bits,
                    nonce: u32::try_from(index).unwrap_or(u32::MAX),
                };
                previous_hash = header.compute_hash();
                tip_id = tree
                    .insert_node(parent, header, NodeStatus::Active)
                    .unwrap_or(tip_id);
                tip_hash = previous_hash.0;
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
    fn seed_block(ctx: &Arc<Context>, block: &Block, record: BlockRecord) {
        {
            let mut tree = ctx.block_tree.write();
            let _ = tree.insert_node(None, block.header, NodeStatus::Active);
        }
        ctx.add_block(record);
    }

    /// A minimal native genesis stand-in: one coinbase transaction whose txid
    /// is the merkle root, so the block hash derives from the fixture itself.
    fn fixture_genesis() -> Block {
        let coinbase = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: coinbase.txid().0,
                time: 1_296_688_602,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![coinbase],
        }
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
    fn compute_fee_fields_skips_indexer_for_coinbase_only_blocks() {
        let ctx = Context::new();
        let block = fixture_genesis();

        let fields = compute_fee_fields(&ctx, &block)
            .unwrap_or_else(|err| panic!("coinbase-only fees should not need txindex: {err}"));
        assert_eq!(fields, FeeFields::default());
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
        let genesis = fixture_genesis();
        let record = BlockRecord::from_block(0, &genesis);
        let ctx = Arc::new(
            Context::new().with_block_body_source(Arc::new(SingleBlockSource {
                height: 0,
                hash: record.hash,
                body: consensus_bytes(&genesis),
                calls: core::sync::atomic::AtomicUsize::new(0),
            })),
        );
        let block_hash_hex = record.hash.to_string();
        let block_size = u64::try_from(record.body_size)?;
        let tx_count = u64::try_from(record.tx_count)?;
        seed_block(&ctx, &genesis, record);

        let block_json = getblock(&ctx, &json!([block_hash_hex.as_str(), 1]))?;
        let header_json = getblockheader(&ctx, &json!([block_hash_hex.as_str(), true]))?;
        let header = &genesis.header;
        let version_hex_value = u32::from_le_bytes(header.version.to_le_bytes());
        let version_hex = format!("{version_hex_value:08x}");
        let bits = header.bits;
        let bits_hex = format!("{bits:08x}");
        let merkle_root = header.merkle_root.to_string();
        let previous_block_hash = header.prev_blockhash.to_string();
        let expected_txid = genesis
            .txs
            .first()
            .ok_or("genesis block must contain a coinbase transaction")?
            .txid()
            .to_string();

        for value in [&block_json, &header_json] {
            assert_eq!(value.get("hash").as_str(), Some(block_hash_hex.as_str()));
            assert_eq!(value.get("height").as_u64(), Some(0));
            assert_eq!(
                value.get("version").as_u64(),
                Some(u64::from(u32::from_le_bytes(header.version.to_le_bytes())))
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
        // Witness-free fixture: weight is exactly 4x total size (Core formula).
        assert_eq!(block_json.get("weight").as_u64(), Some(block_size * 4));
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
            hash: BlockHash,
            body: Vec<u8>,
            calls: AtomicUsize,
        }

        impl crate::context::BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                (height == self.height && hash == self.hash).then(|| self.body.clone())
            }
        }

        let genesis = fixture_genesis();
        let body = consensus_bytes(&genesis);
        let record = BlockRecord::from_block(0, &genesis);
        let block_hash_hex = record.hash.to_string();
        let source = Arc::new(SingleBlockSource {
            height: 0,
            hash: record.hash,
            body: body.clone(),
            calls: AtomicUsize::new(0),
        });
        let calls = Arc::clone(&source);
        let ctx = Arc::new(Context::new().with_block_body_source(source));
        seed_block(&ctx, &genesis, record);

        let expected_hex = hex_encode(&body);
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
        let genesis = fixture_genesis();
        let record = BlockRecord::from_block(0, &genesis);
        let hash = record.hash.to_string();
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
        let genesis = fixture_genesis();
        let record = BlockRecord::from_block(0, &genesis);
        let ctx = Arc::new(
            Context::new().with_block_body_source(Arc::new(SingleBlockSource {
                height: 0,
                hash: record.hash,
                body: consensus_bytes(&genesis),
                calls: core::sync::atomic::AtomicUsize::new(0),
            })),
        );
        seed_block(&ctx, &genesis, record);
        let block_hash = genesis.block_hash().0;
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
    fn gettxoutsetinfo_omits_core_optionals_for_hash_type_none() {
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
        assert!(
            result.get("total_unspendable_amount").is_none(),
            "total_unspendable_amount should be absent for hash_type=none: {result:?}"
        );
        assert!(
            result.get("block_info").is_none(),
            "block_info should be absent for hash_type=none: {result:?}"
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
        applied_header: Header,
        fork_header: Header,
    }

    fn forked_ctx() -> Result<Fork, Box<dyn std::error::Error>> {
        use bitcoin_rs_chain::NodeStatus;

        let ctx = Context::new();
        let header = |prev: BlockHash, nonce: u32, time: u32| Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: 0x207f_ffff,
            nonce,
        };

        let (applied_tip, header_tip, fork_hash, applied_header, fork_header) = {
            let mut tree = ctx.block_tree.write();
            let genesis = header(BlockHash::default(), 0, 1_000_000);
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

            let applied = header(genesis.compute_hash(), 1, 1_000_900);
            let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
            let applied_tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
            assert_eq!(applied_tip.tip_id, applied_id);

            let fork = header(genesis.compute_hash(), 2, 1_000_901);
            let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
            let fork_hash = tree.node(fork_id)?.hash;
            let fork_tip = header(fork.compute_hash(), 3, 1_001_800);
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
            Some(hex_encode(&consensus_bytes(&fork_header)).as_str())
        );

        let verbose = getblockheader(&ctx, &json!([hash.as_str(), true]))?;
        assert_eq!(verbose.get("hash").as_str(), Some(hash.as_str()));
        assert_eq!(verbose.get("confirmations").as_i64(), Some(-1));
        assert_eq!(verbose.get("height").as_u64(), Some(1));
        assert_eq!(
            verbose.get("version").as_i64(),
            Some(i64::from(u32::from_le_bytes(
                fork_header.version.to_le_bytes(),
            )))
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

    #[test]
    fn getblockstats_rejects_a_stale_block_hash() -> Result<(), Box<dyn std::error::Error>> {
        let Fork {
            ctx,
            fork: fork_hash,
            ..
        } = forked_ctx()?;
        ctx.add_block(BlockRecord::synthetic(1, BlockHash::from(fork_hash)));

        let result = getblockstats(&ctx, &json!([fork_hash.to_string_be()]));
        assert!(
            matches!(
                result,
                Err(RpcError::InvalidParams("Block is not in main chain"))
            ),
            "stale hash must not compute fees from the active index, got {result:?}"
        );
        Ok(())
    }

    /// A structurally plausible stored block: one coinbase transaction, as
    /// every real block carries. Verbose rendering requires the coinbase, so
    /// an empty body trips production's typed absence error instead.
    fn coinbase_only_block(header: Header) -> Block {
        let coinbase = Tx {
            version: 1,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![0x51],
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50 * 100_000_000,
                script_pubkey: vec![0x51],
            }],
        };
        Block {
            header,
            txs: vec![coinbase],
        }
    }

    /// A log record for `header`, either carrying the block or standing in for
    /// one whose body the node no longer has.
    fn record_for(header: Header, with_body: bool) -> BlockRecord {
        if !with_body {
            let hash = header.compute_hash().0;
            return BlockRecord::synthetic(1, BlockHash::from(hash));
        }
        BlockRecord::from_block(1, &coinbase_only_block(header))
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
            let applied_block = coinbase_only_block(applied_header);
            let fork_block = coinbase_only_block(fork_header);
            Arc::get_mut(&mut ctx)
                .expect("unique fork fixture context")
                .block_body_source = Some(Arc::new(MultiBlockSource {
                bodies: vec![
                    (
                        applied_record.height,
                        applied_record.hash,
                        consensus_bytes(&applied_block),
                    ),
                    (
                        fork_record.height,
                        fork_record.hash,
                        consensus_bytes(&fork_block),
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
        let mainnet = ctx.difficulty_for_bits(0x1d00_ffff);
        assert_eq!(mainnet.to_bits(), 1.0_f64.to_bits());
        let regtest = ctx.difficulty_for_bits(0x207f_ffff);
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
        let genesis = fixture_genesis();
        let body = consensus_bytes(&genesis);
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
            fn block_body(&self, _height: u32, _hash: BlockHash) -> Option<Vec<u8>> {
                None
            }
            fn disk_usage(&self) -> Option<u64> {
                Some(self.0)
            }
        }

        let genesis = fixture_genesis();
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
        assert!(result.get("window_final_block_height").is_some());
        // `txcount` used to be present and zero here. Zero is not a missing
        // measurement, it is a wrong one: genesis carries a coinbase, so the
        // cumulative count at a genesis tip is one. Neither the durable counter
        // nor an empty log knows it, so Core's answer -- and now this one -- is
        // to omit the field.
        assert!(result.get("txcount").is_none(), "{result:?}");
    }

    #[test]
    fn getchaintxstats_window_tx_count_includes_in_range_blocks() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let tip = {
            let mut tree = ctx.block_tree.write();
            let id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert genesis: {err}"));
            tree.restore_chain_tx_count(id, 1)
                .unwrap_or_else(|err| panic!("record genesis: {err}"));
            let node = tree
                .node(id)
                .unwrap_or_else(|err| panic!("genesis node: {err}"));
            TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        ctx.set_applied_tip(tip);
        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
        let Some(txcount) = result.get("txcount").and_then(JsonValueTrait::as_u64) else {
            panic!("txcount missing: {result:?}");
        };
        // Genesis block has 1 tx (coinbase).
        assert_eq!(txcount, 1);
    }

    #[test]
    fn getchaintxstats_uses_applied_atomic_when_per_node_count_is_unset() {
        use alloc::sync::Arc;

        let ctx =
            Context::new().with_chain_tx_count(Arc::new(core::sync::atomic::AtomicU64::new(42)));
        let ctx = Arc::new(ctx);
        let genesis = fixture_genesis();
        let tip = {
            let mut tree = ctx.block_tree.write();
            let id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert genesis: {err}"));
            let node = tree
                .node(id)
                .unwrap_or_else(|err| panic!("genesis node: {err}"));
            TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        ctx.set_applied_tip(tip);
        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
        let Some(txcount) = result.get("txcount").and_then(JsonValueTrait::as_u64) else {
            panic!("txcount missing: {result:?}");
        };
        assert_eq!(txcount, 42);
    }

    #[test]
    fn getchaintxstats_time_reflects_tip_block_header_timestamp() {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let expected_time = genesis.header.time;
        let tip = {
            let mut tree = ctx.block_tree.write();
            let id = tree
                .insert_node(None, genesis.header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert genesis: {err}"));
            let node = tree
                .node(id)
                .unwrap_or_else(|err| panic!("genesis node: {err}"));
            TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        ctx.set_applied_tip(tip);
        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));
        let Some(time) = result.get("time").and_then(JsonValueTrait::as_u64) else {
            panic!("time missing: {result:?}");
        };
        assert_eq!(time, u64::from(expected_time));
    }

    /// A log with a duplicate height and uneven record sizes.
    ///
    /// Heights are non-decreasing, which is the invariant the prefix sums rest
    /// on, but they are not a clean `0..n`: height 3 is recorded twice, as a
    /// reorg leaves it. The running totals must count both records.
    fn shaped_log() -> BlockLog {
        const HEIGHTS: [u32; 10] = [0, 1, 2, 3, 3, 4, 5, 6, 7, 8];
        const TIMES: [u32; 10] = [
            1_000, 1_010, 1_020, 1_030, 1_031, 1_040, 1_035, 1_060, 1_070, 1_080,
        ];
        let mut log = BlockLog::new();
        for (index, (height, time)) in HEIGHTS.into_iter().zip(TIMES).enumerate() {
            log.push(BlockRecord {
                hash: BlockHash::from(Hash256::from_le_bytes(
                    &[u8::try_from(index).unwrap_or(0); 32],
                )),
                height,
                body_size: 100 + index * 7,
                header: None,
                tx_count: 1 + index * 3,
                time,
            });
        }
        log
    }

    /// A complete genesis-to-height prefix is a chain total; anything else is not.
    ///
    /// Height 3 is recorded twice in the fixture. The prefix through that
    /// height includes both records. A log that starts after genesis cannot
    /// answer at all — the sum would be an under-count, not a chain total.
    #[test]
    fn cumulative_tx_count_through_requires_a_genesis_prefix() {
        let log = shaped_log();
        assert_eq!(
            cumulative_tx_count_through(&log, 3),
            Some(1 + 4 + 7 + 10 + 13)
        );
        assert_eq!(cumulative_tx_count_through(&log, 8), Some(145));
        assert_eq!(
            cumulative_tx_count_through(&log, 9),
            None,
            "a height the log has not reached is unknown"
        );

        let mut without_genesis = BlockLog::new();
        for record in log.iter().skip(1).cloned() {
            without_genesis.push(record);
        }
        assert_eq!(
            cumulative_tx_count_through(&without_genesis, 3),
            None,
            "a prefix that does not start at genesis is not a chain total"
        );
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
            hash: BlockHash::from(Hash256::from_le_bytes(&[0_u8; 32])),
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
        let tip = {
            let mut tree = ctx.block_tree.write();
            let mut parent = None;
            let mut prev = BlockHash::default();
            let mut tip = None;
            let mut cumulative = 0_u64;
            for height in 0_u32..4 {
                let header = Header {
                    version: 1,
                    prev_blockhash: prev,
                    merkle_root: Hash256::default(),
                    time: 1_000_u32.saturating_add(height.saturating_mul(10)),
                    bits: 0x207f_ffff,
                    nonce: height,
                };
                prev = header.compute_hash();
                let id = tree.insert_node(parent, header, NodeStatus::Active)?;
                cumulative = cumulative.saturating_add(u64::from(height.saturating_add(1)));
                tree.restore_chain_tx_count(id, cumulative)?;
                parent = Some(id);
                let node = tree.node(id)?;
                tip = Some(TipSnapshot {
                    tip_id: id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                });
            }
            tip.ok_or("missing tip")?
        };
        ctx.set_applied_tip(tip);

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
                .and_then(JsonValueTrait::as_i64),
            Some(10)
        );
        assert_eq!(
            result.get("time").and_then(JsonValueTrait::as_u64),
            Some(1_030)
        );
        Ok(())
    }

    #[test]
    fn getchaintxstats_rejects_nblocks_equal_to_selected_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let tip = {
            let mut tree = ctx.block_tree.write();
            let mut parent = None;
            let mut prev = BlockHash::default();
            let mut tip = None;
            for height in 0_u32..4 {
                let header = Header {
                    version: 1,
                    prev_blockhash: prev,
                    merkle_root: Hash256::default(),
                    time: 1_000_u32.saturating_add(height.saturating_mul(10)),
                    bits: 0x207f_ffff,
                    nonce: height,
                };
                prev = header.compute_hash();
                let id = tree.insert_node(parent, header, NodeStatus::Active)?;
                parent = Some(id);
                let node = tree.node(id)?;
                tip = Some(TipSnapshot {
                    tip_id: id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                });
            }
            tip.ok_or("missing tip")?
        };
        ctx.set_applied_tip(tip);

        let rejected = getchaintxstats(&ctx, &json!([3]));
        assert!(
            matches!(
                &rejected,
                Err(RpcError::InvalidParameter(message))
                    if message == "Invalid block count: should be between 0 and the block's height - 1"
            ),
            "nblocks equal to height must be rejected, got {rejected:?}"
        );
        getchaintxstats(&ctx, &json!([2]))
            .unwrap_or_else(|err| panic!("height - 1 must remain accepted: {err}"));
        Ok(())
    }

    #[test]
    fn getchaintxstats_tip_time_uses_first_applied_height_record() {
        let ctx = Arc::new(Context::new());
        let tip = {
            let mut tree = ctx.block_tree.write();
            let mut parent = None;
            let mut prev = BlockHash::default();
            let mut tip = None;
            for (height, time) in [(0_u32, 100_u32), (1, 150), (2, 200)] {
                let header = Header {
                    version: 1,
                    prev_blockhash: prev,
                    merkle_root: Hash256::default(),
                    time,
                    bits: 0x207f_ffff,
                    nonce: height,
                };
                prev = header.compute_hash();
                let id = tree
                    .insert_node(parent, header, NodeStatus::Active)
                    .unwrap_or_else(|err| panic!("insert {height}: {err}"));
                tree.restore_chain_tx_count(id, u64::from(height) + 1)
                    .unwrap_or_else(|err| panic!("count {height}: {err}"));
                parent = Some(id);
                let node = tree
                    .node(id)
                    .unwrap_or_else(|err| panic!("node {height}: {err}"));
                tip = Some(TipSnapshot {
                    tip_id: id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                });
            }
            tip.unwrap_or_else(|| panic!("missing tip"))
        };
        ctx.set_applied_tip(tip);

        let result = getchaintxstats(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"));

        assert_eq!(
            result.get("time").and_then(JsonValueTrait::as_u64),
            Some(200)
        );
    }

    #[test]
    fn getchaintips_marks_active_from_applied_tip() {
        let ctx = Arc::new(Context::new());
        let genesis = fixture_genesis();
        let applied_hash = genesis.block_hash().0;
        let applied_id = {
            let mut tree = ctx.block_tree.write();
            tree.insert_node(None, genesis.header, NodeStatus::Active)
                .expect("genesis")
        };
        let header_only = Header {
            version: 1,
            prev_blockhash: genesis.header.compute_hash(),
            merkle_root: Hash256::default(),
            time: genesis.header.time.saturating_add(600),
            bits: genesis.header.bits,
            nonce: 7,
        };
        let header_hash = header_only.compute_hash().0;
        let header_id = {
            let mut tree = ctx.block_tree.write();
            tree.insert_node(Some(applied_id), header_only, NodeStatus::HeaderValid)
                .expect("header")
        };
        ctx.set_applied_tip(TipSnapshot {
            tip_id: applied_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash: applied_hash,
        });
        ctx.set_chain_tip(TipSnapshot {
            tip_id: header_id,
            height: 1,
            chainwork: ChainWork::ZERO,
            hash: header_hash,
        });
        let tips = getchaintips(&ctx, &json!([])).unwrap();
        let tips = tips.as_array().expect("array");
        let active = tips
            .iter()
            .find(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("active"))
            .expect("active tip");
        let expected = applied_hash.to_string_be();
        assert_eq!(
            active.get("hash").and_then(JsonValueTrait::as_str),
            Some(expected.as_str())
        );
    }
}
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
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

    /// Regtest-shaped genesis header for header-only fixtures; only its
    /// self-consistent identity matters, never its field values.
    fn fixture_genesis_header() -> Header {
        Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_296_688_602,
            bits: 0x207f_ffff,
            nonce: 0,
        }
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
        let genesis = fixture_genesis_header();
        let hash = {
            let mut tree = ctx.block_tree.write();
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
            let mut tree = ctx.block_tree.write();
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
        ctx.set_applied_tip((*applied_tip).clone());

        let result = getblockstats(&ctx, &json!([1]));

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }
}
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod getchaintips_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
    use bitcoin_rs_primitives::Hash256;

    use super::*;

    fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        }
    }

    fn hash_from_header(header: &Header) -> Hash256 {
        header.compute_hash().0
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
    fn getchaintips_emits_the_applied_tip_as_active() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = synthetic_header(BlockHash::default(), 1_000_000);
        let hash = hash_from_header(&genesis);
        let tip_id = {
            let mut tree = ctx.block_tree.write();
            tree.insert_node(None, genesis, NodeStatus::Active)?
        };
        let tip = TipSnapshot {
            tip_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash,
        };
        ctx.set_chain_tip(tip.clone());
        ctx.set_applied_tip(tip);
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
    fn getchaintips_serves_snapshot_tip_without_a_tree_row() {
        let ctx = Arc::new(Context::new());
        let hash = Hash256::from_le_bytes(&[42_u8; 32]);
        ctx.set_applied_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 42,
            chainwork: ChainWork::ZERO,
            hash,
        });
        let tips = getchaintips(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(list) = tips.as_array() else {
            panic!("expected array, got {tips:?}");
        };
        assert_eq!(list.len(), 1, "the snapshot tip must be listed: {tips:?}");
        let Some(tip) = list.first() else {
            panic!("expected first element");
        };
        assert_eq!(
            tip.get("status").and_then(JsonValueTrait::as_str),
            Some("active"),
            "applied tip must map to Core's active status: {tip:?}"
        );
        assert_eq!(
            tip.get("hash").and_then(JsonValueTrait::as_str),
            Some(hash.to_string_be().as_str())
        );
        assert_eq!(tip.get("height").and_then(JsonValueTrait::as_i64), Some(42));
        assert_eq!(
            tip.get("branchlen").and_then(JsonValueTrait::as_i64),
            Some(0)
        );
    }

    #[test]
    fn getchaintips_emits_two_tips_when_chain_is_forked() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = Arc::new(Context::new());
        let (active_tip_id, active_chainwork, active_hash) = {
            let mut tree = ctx.block_tree.write();
            let genesis = synthetic_header(BlockHash::default(), 1_000_000);
            let genesis_hash = genesis.compute_hash();
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
        let tip = TipSnapshot {
            tip_id: active_tip_id,
            height: 1,
            chainwork: active_chainwork,
            hash: active_hash,
        };
        ctx.set_chain_tip(tip.clone());
        ctx.set_applied_tip(tip);

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
            let genesis = synthetic_header(BlockHash::default(), 1_000_000);
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let genesis_hash = tree.node(genesis_id)?.hash;
            let mut sibling = synthetic_header(genesis.compute_hash(), 1_000_600);
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

    /// A chain whose headers run ahead of what has been applied.
    ///
    /// Returns the context, the applied tip's id, and the header tip's id.
    fn ctx_with_headers_ahead(
        applied_height: u32,
        header_height: u32,
    ) -> Result<
        (
            Arc<Context>,
            bitcoin_rs_chain::NodeId,
            bitcoin_rs_chain::NodeId,
        ),
        Box<dyn std::error::Error>,
    > {
        let ctx = Arc::new(Context::new());
        let mut previous = BlockHash::default();
        let mut parent = None;
        let mut applied = None;
        let mut header_tip = None;
        {
            let mut tree = ctx.block_tree.write();
            for height in 0..=header_height {
                let header = synthetic_header(previous, 1_000_000 + height * 600);
                previous = header.compute_hash();
                // Applied blocks are Active; the headers past the applied tip
                // have never been connected.
                let status = if height <= applied_height {
                    NodeStatus::Active
                } else {
                    NodeStatus::HeaderValid
                };
                let id = tree.insert_node(parent, header, status)?;
                parent = Some(id);
                if height == applied_height {
                    applied = Some((id, tree.node(id)?.hash, tree.node(id)?.chainwork));
                }
                header_tip = Some(id);
            }
        }
        let (Some((applied_id, applied_hash, applied_work)), Some(header_id)) =
            (applied, header_tip)
        else {
            panic!("the fixture builds both tips");
        };
        ctx.set_applied_tip(TipSnapshot {
            tip_id: applied_id,
            height: applied_height,
            chainwork: applied_work,
            hash: applied_hash,
        });
        Ok((ctx, applied_id, header_id))
    }

    fn tips_of(ctx: &Arc<Context>) -> Vec<sonic_rs::Value> {
        let result = getchaintips(ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(array) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        array.iter().cloned().collect()
    }

    fn field<'a>(tip: &'a sonic_rs::Value, key: &str) -> &'a str {
        tip.get(key)
            .and_then(JsonValueTrait::as_str)
            .unwrap_or_else(|| panic!("{key} missing from {tip:?}"))
    }

    /// The tip the node has connected is reported, even when it is not a leaf.
    ///
    /// During initial sync the applied tip never is one: the header tree
    /// already describes its descendants. Listing only leaves left the chain
    /// this node had actually validated out of the answer entirely, while the
    /// unvalidated header tip was labelled "active" in its place.
    #[test]
    fn the_applied_tip_is_reported_even_when_headers_run_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;

        let tips = tips_of(&ctx);

        assert_eq!(
            tips.len(),
            2,
            "the header tip and the applied tip: {tips:?}"
        );
        let active: Vec<&sonic_rs::Value> = tips
            .iter()
            .filter(|tip| field(tip, "status") == "active")
            .collect();
        assert_eq!(active.len(), 1, "exactly one active tip: {tips:?}");
        assert_eq!(
            active
                .first()
                .and_then(|tip| tip.get("height"))
                .and_then(JsonValueTrait::as_u64),
            Some(3),
            "the active tip is the applied one, not the header one"
        );
        Ok(())
    }

    /// A header the node has not connected is not the active chain.
    ///
    /// It is reported as `headers-only` with the distance it runs ahead, which
    /// is what tells an operator the node is behind its own headers.
    #[test]
    fn a_header_tip_ahead_of_the_applied_tip_is_headers_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;

        let tips = tips_of(&ctx);
        let Some(header_tip) = tips
            .iter()
            .find(|tip| tip.get("height").and_then(JsonValueTrait::as_u64) == Some(6))
        else {
            panic!("no tip at the header height: {tips:?}");
        };

        assert_eq!(field(header_tip, "status"), "headers-only");
        assert_eq!(
            header_tip.get("branchlen").and_then(JsonValueTrait::as_u64),
            Some(3),
            "three headers past the applied tip"
        );
        Ok(())
    }

    /// The active tip's own branch length is zero: it forks from itself.
    #[test]
    fn the_active_tip_has_no_branch_length() -> Result<(), Box<dyn std::error::Error>> {
        let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;
        let tips = tips_of(&ctx);
        let Some(active) = tips.iter().find(|tip| field(tip, "status") == "active") else {
            panic!("no active tip: {tips:?}");
        };
        assert_eq!(
            active.get("branchlen").and_then(JsonValueTrait::as_u64),
            Some(0)
        );
        Ok(())
    }

    /// A branch that was the chain and is not any more reads as a valid fork.
    ///
    /// This is the state a reorg leaves: the abandoned tip keeps its height and
    /// its data, and Core reports it as `valid-fork` with the distance back to
    /// the fork point. This node reports `headers-only`, and the assertion
    /// below says why -- displacing a header is the only thing the block tree
    /// records, and that is a fact about headers rather than about validation.
    #[test]
    fn a_branch_left_behind_by_a_reorg_is_reported_as_headers_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let (abandoned_height, new_tip) = {
            let mut tree = ctx.block_tree.write();
            let genesis = synthetic_header(BlockHash::default(), 1_000_000);
            let genesis_hash = genesis.compute_hash();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

            let a1 = synthetic_header(genesis_hash, 1_000_600);
            let a1_hash = a1.compute_hash();
            let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::Active)?;
            let a2 = synthetic_header(a1_hash, 1_001_200);
            let a2_id = tree.insert_node(Some(a1_id), a2, NodeStatus::Active)?;
            let abandoned_height = tree.node(a2_id)?.height;

            // A longer branch from a1. The second block carries more work than
            // a2, so the tree publishes it and demotes a2 to Stale -- the same
            // sequence a real reorg follows.
            let mut b2 = synthetic_header(a1_hash, 1_001_100);
            b2.nonce = 77;
            let b2_id = tree.insert_node(Some(a1_id), b2, NodeStatus::HeaderValid)?;
            let b3 = synthetic_header(b2.compute_hash(), 1_001_700);
            let b3_id = tree.insert_node(Some(b2_id), b3, NodeStatus::Active)?;

            assert_eq!(
                tree.node(a2_id)?.status,
                NodeStatus::Stale,
                "the fixture must actually displace the old tip"
            );
            let node = tree.node(b3_id)?;
            (
                abandoned_height,
                (b3_id, node.height, node.chainwork, node.hash),
            )
        };
        // The node followed the reorg: the new branch is what it has applied.
        let (tip_id, height, chainwork, hash) = new_tip;
        ctx.set_applied_tip(TipSnapshot {
            tip_id,
            height,
            chainwork,
            hash,
        });

        let tips = tips_of(&ctx);
        let Some(abandoned) = tips.iter().find(|tip| {
            tip.get("height").and_then(JsonValueTrait::as_u64) == Some(u64::from(abandoned_height))
        }) else {
            panic!("the abandoned tip is missing: {tips:?}");
        };

        // **Not `valid-fork`.** This fixture never applied a2's block -- it
        // only inserted headers -- and the tree kept no record that anything
        // did. `Stale` says the header was displaced, which is a fact about the
        // header tree and not about validation; on a header-first node most
        // stale nodes are headers whose bodies never arrived at all. Core's
        // `valid-fork` means "fully validated, since reorganised", so emitting
        // it here would claim a validation that did not happen.
        assert_eq!(field(abandoned, "status"), "headers-only");
        assert_eq!(
            abandoned.get("branchlen").and_then(JsonValueTrait::as_u64),
            Some(1),
            "one block past the fork point"
        );
        Ok(())
    }

    /// An invalidated block is never reported as the chain being followed.
    ///
    /// `reorg::invalidate_block` marks the subtree invalid under the tree's
    /// write lock and releases it, then disconnects and republishes
    /// `applied_tip`. Between those two a caller holds a tree view that says
    /// "invalid" and an applied tip that still names the block, and deciding on
    /// the tip first labels a block the node has just rejected as `active` --
    /// an operator reading that sees the node following a chain it has thrown
    /// away.
    ///
    /// The window cannot be closed by ordering, because the two facts are
    /// published separately. What removes the wrong answer is preferring the
    /// one that cannot go stale: a block that is invalid was invalid before
    /// this call and stays invalid after it.
    ///
    /// The fixture *is* that window, reproduced exactly: the subtree is
    /// invalidated and the applied tip is left where invalidation found it.
    #[test]
    fn an_invalidated_applied_tip_is_not_reported_as_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let tip = {
            let mut tree = ctx.block_tree.write();
            let genesis = synthetic_header(BlockHash::default(), 1_000_000);
            let genesis_hash = genesis.compute_hash();
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let child = synthetic_header(genesis_hash, 1_000_600);
            let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)?;
            let node = tree.node(child_id)?;
            TipSnapshot {
                tip_id: child_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        ctx.set_applied_tip(tip.clone());

        // Before: the applied tip is the chain being followed.
        let before = tips_of(&ctx);
        let Some(active) = before
            .iter()
            .find(|reported| field(reported, "status") == "active")
        else {
            panic!("the applied tip must start out active: {before:?}");
        };
        assert_eq!(
            active.get("height").and_then(JsonValueTrait::as_u64),
            Some(u64::from(tip.height))
        );

        // The invalidation's first half, with the tip not yet republished.
        {
            let mut tree = ctx.block_tree.write();
            tree.invalidate_subtree(tip.tip_id)?;
        }

        let after = tips_of(&ctx);
        let Some(reported) = after.iter().find(|reported| {
            reported.get("hash").and_then(JsonValueTrait::as_str)
                == Some(tip.hash.to_string_be().as_str())
        }) else {
            panic!("the invalidated block must still be listed: {after:?}");
        };
        assert_eq!(
            field(reported, "status"),
            "invalid",
            "an invalidated block must not be reported as the active chain"
        );
        assert!(
            !after
                .iter()
                .any(|reported| field(reported, "status") == "active"),
            "nothing is active while the invalidation is in flight: {after:?}"
        );
        Ok(())
    }

    /// Tips come back highest first, with no special place for the active one.
    ///
    /// Core orders by height descending. A fork longer than the active chain
    /// is what an operator is looking for, and sorting the active tip to the
    /// front would bury it.
    #[test]
    fn tips_are_ordered_by_height_descending() -> Result<(), Box<dyn std::error::Error>> {
        let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;

        let heights: Vec<u64> = tips_of(&ctx)
            .iter()
            .map(|tip| {
                tip.get("height")
                    .and_then(JsonValueTrait::as_u64)
                    .unwrap_or_default()
            })
            .collect();

        assert_eq!(heights, vec![6, 3], "highest first: {heights:?}");
        Ok(())
    }

    #[test]
    fn getchaintips_marks_unapplied_best_header_as_headers_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let (genesis_id, genesis_chainwork, genesis_hash) = {
            let mut tree = ctx.block_tree.write();
            let genesis = synthetic_header(BlockHash::default(), 1_000_000);
            let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
            let genesis_hash = tree.node(genesis_id)?.hash;
            let child = synthetic_header(genesis.compute_hash(), 1_000_900);
            let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
            assert_eq!(
                tree.node(child_id)?.status,
                NodeStatus::Active,
                "the heavier header leaf is promoted even before apply"
            );
            let genesis_node = tree.node(genesis_id)?;
            (genesis_id, genesis_node.chainwork, genesis_hash)
        };
        ctx.set_applied_tip(TipSnapshot {
            tip_id: genesis_id,
            height: 0,
            chainwork: genesis_chainwork,
            hash: genesis_hash,
        });

        let result = getchaintips(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        let headers_only_count = arr
            .iter()
            .filter(|tip| {
                tip.get("status").and_then(JsonValueTrait::as_str) == Some("headers-only")
            })
            .count();
        let valid_fork_count = arr
            .iter()
            .filter(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("valid-fork"))
            .count();
        assert_eq!(
            headers_only_count, 1,
            "unapplied best header must be headers-only: {arr:?}"
        );
        assert_eq!(
            valid_fork_count, 0,
            "header-first continuation is not a valid-fork: {arr:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod chaintxstats_durability_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    pub(super) const TIP_TIME: u32 = 1_700_000_123;

    pub(super) fn insert_counted_chain(
        ctx: &Context,
        times: &[u32],
        counts: &[u64],
    ) -> TipSnapshot {
        assert_eq!(times.len(), counts.len());
        let mut tree = ctx.block_tree.write();
        let mut parent = None;
        let mut prev = BlockHash::default();
        let mut tip = None;
        for (index, (time, count)) in times
            .iter()
            .copied()
            .zip(counts.iter().copied())
            .enumerate()
        {
            let height = u32::try_from(index).unwrap_or(u32::MAX);
            let header = Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time,
                bits: 0x207f_ffff,
                nonce: height,
            };
            prev = header.compute_hash();
            let id = tree
                .insert_node(parent, header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert {height}: {err}"));
            tree.restore_chain_tx_count(id, count)
                .unwrap_or_else(|err| panic!("count {height}: {err}"));
            parent = Some(id);
            let node = tree
                .node(id)
                .unwrap_or_else(|err| panic!("node {height}: {err}"));
            tip = Some(TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            });
        }
        tip.unwrap_or_else(|| panic!("missing tip"))
    }

    fn restarted_ctx(chain_tx_count: Option<u64>) -> Arc<Context> {
        let ctx = Context::new();
        let counts = match chain_tx_count {
            Some(count) => [1_u64, count],
            None => [0, 0],
        };
        let tip = insert_counted_chain(&ctx, &[1_000_000, TIP_TIME], &counts);
        ctx.set_applied_tip(tip);
        let ctx = Arc::new(ctx);
        assert!(
            ctx.blocks.read().is_empty(),
            "the fixture must leave the record log empty, or it is not a restart"
        );
        ctx
    }

    pub(super) fn stats_of(ctx: &Arc<Context>) -> sonic_rs::Value {
        getchaintxstats(ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"))
    }

    #[test]
    fn txcount_comes_from_the_selected_node_not_the_in_process_log() {
        let value = stats_of(&restarted_ctx(Some(1_315_805_869)));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(1_315_805_869),
            "folding the empty log would have reported zero"
        );
    }

    #[test]
    fn txcount_is_zero_when_the_selected_node_count_is_unknown() {
        let ctx = restarted_ctx(None);
        let Some(tip) = ctx.applied_tip.load_full() else {
            panic!("fixture has no applied tip");
        };
        ctx.add_block(BlockRecord {
            hash: BlockHash::from(tip.hash),
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
            Some(0),
            "an unknown node count must not fall back to the in-process log"
        );
    }

    #[test]
    fn txcount_is_zero_when_the_node_count_is_unknown_and_the_log_is_empty() {
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

    #[test]
    fn historical_selection_uses_the_selected_nodes_count_and_mtp() {
        let ctx = Context::new();
        let tip = insert_counted_chain(
            &ctx,
            &[1_000, 1_600, 2_200, 2_800, 3_400],
            &[1, 4, 9, 16, 25],
        );
        ctx.set_applied_tip(tip.clone());
        let ctx = Arc::new(ctx);
        let mid_hash = {
            let tree = ctx.block_tree.read();
            let id = tree
                .node_at_height_from(tip.tip_id, 3)
                .unwrap_or_else(|| panic!("missing height 3"));
            tree.node(id)
                .unwrap_or_else(|err| panic!("mid node: {err}"))
                .hash
        };
        let value = getchaintxstats(&ctx, &json!([1, mid_hash.to_string_be()]))
            .unwrap_or_else(|err| panic!("historical getchaintxstats failed: {err}"));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(16)
        );
        assert_eq!(
            value
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        assert_eq!(
            value
                .get("window_interval")
                .and_then(JsonValueTrait::as_u64),
            Some(600)
        );
        assert_eq!(
            value
                .get("window_final_block_height")
                .and_then(JsonValueTrait::as_u64),
            Some(3)
        );
    }

    #[test]
    fn default_tip_selection_uses_the_applied_node_count() {
        let ctx = Context::new();
        let tip = insert_counted_chain(&ctx, &[1_000, TIP_TIME], &[1, 11]);
        ctx.set_applied_tip(tip);
        let ctx = Arc::new(ctx);
        assert_eq!(
            stats_of(&ctx)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(11)
        );
    }

    #[test]
    fn historical_stats_survive_an_empty_block_log() {
        let ctx = Context::new();
        let tip = insert_counted_chain(&ctx, &[1_000_000, 1_000_100, TIP_TIME], &[1, 1, 42]);
        ctx.set_applied_tip(tip);
        let ctx = Arc::new(ctx);
        assert!(ctx.blocks.read().is_empty());
        let hash = ctx.applied_hash().to_string_be();
        let value = getchaintxstats(&ctx, &json!([1, hash.as_str()]))
            .unwrap_or_else(|err| panic!("reopen stats failed: {err}"));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(42)
        );
        assert_eq!(
            value
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(41)
        );
    }

    /// Builds genesis, a lost equal-work sibling, and the winning branch with
    /// its child, returning (genesis hash, lost hash, winning tip snapshot).
    fn reorg_fixture(ctx: &Context) -> (Hash256, Hash256, TipSnapshot) {
        let mut tree = ctx.block_tree.write();
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        let genesis_id = tree
            .insert_node(None, genesis, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("genesis: {err}"));
        tree.restore_chain_tx_count(genesis_id, 1)
            .unwrap_or_else(|err| panic!("genesis count: {err}"));
        let lost = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_100,
            bits: 0x207f_ffff,
            nonce: 1,
        };
        let lost_id = tree
            .insert_node(Some(genesis_id), lost, NodeStatus::HeaderValid)
            .unwrap_or_else(|err| panic!("lost: {err}"));
        tree.restore_chain_tx_count(lost_id, 3)
            .unwrap_or_else(|err| panic!("lost count: {err}"));
        let won = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_200,
            bits: 0x207f_ffff,
            nonce: 2,
        };
        let won_id = tree
            .insert_node(Some(genesis_id), won, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("won: {err}"));
        tree.restore_chain_tx_count(won_id, 8)
            .unwrap_or_else(|err| panic!("won count: {err}"));
        let child = Header {
            version: 1,
            prev_blockhash: won.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_300,
            bits: 0x207f_ffff,
            nonce: 3,
        };
        let child_id = tree
            .insert_node(Some(won_id), child, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("child: {err}"));
        tree.restore_chain_tx_count(child_id, 15)
            .unwrap_or_else(|err| panic!("child count: {err}"));
        let lost_hash = tree
            .node(lost_id)
            .unwrap_or_else(|err| panic!("lost node: {err}"))
            .hash;
        let child_node = tree
            .node(child_id)
            .unwrap_or_else(|err| panic!("child node: {err}"));
        (
            tree.node(genesis_id)
                .unwrap_or_else(|err| panic!("genesis node: {err}"))
                .hash,
            lost_hash,
            TipSnapshot {
                tip_id: child_id,
                height: child_node.height,
                chainwork: child_node.chainwork,
                hash: child_node.hash,
            },
        )
    }

    #[test]
    fn reorg_selects_the_winning_branch_counts() {
        let ctx = Context::new();
        let (genesis_hash, lost_hash, won) = reorg_fixture(&ctx);
        ctx.set_applied_tip(won.clone());
        let ctx = Arc::new(ctx);
        let _ = genesis_hash;
        assert_eq!(
            stats_of(&ctx)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(15),
            "default selection must follow the applied branch"
        );
        let err = getchaintxstats(&ctx, &json!([1, lost_hash.to_string_be()])).unwrap_err();
        assert!(matches!(
            err,
            RpcError::InvalidParameter(message) if message == "Block is not in main chain"
        ));
        let value = getchaintxstats(&ctx, &json!([1, won.hash.to_string_be()]))
            .unwrap_or_else(|err| panic!("winning branch stats failed: {err}"));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(15)
        );
        assert_eq!(
            value
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(7)
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod chaintxstats_window_tests {
    use alloc::sync::Arc;

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

    fn header(previous: BlockHash, time: u32, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash: previous,
            merkle_root: Hash256::default(),
            time,
            bits: REGTEST_BITS,
            nonce,
        }
    }

    /// A node whose active chain carries `times`, in both the tree and the log.
    ///
    /// Each block is given `height + 1` transactions, so a window sum is a
    /// number the test can state in closed form.
    fn chain_ctx(times: &[u32]) -> Arc<Context> {
        chain_ctx_with_counter(times, None)
    }

    /// [`chain_ctx`], with the node's durable cumulative counter set.
    ///
    /// The counter tracks the applied tip and nothing else, so a fixture that
    /// leaves it unset cannot tell "the shortcut is restricted to the tip" from
    /// "there is no shortcut to take".
    fn chain_ctx_with_counter(times: &[u32], chain_tx_count: Option<u64>) -> Arc<Context> {
        let ctx = Context::new();
        let ctx = match chain_tx_count {
            Some(count) => {
                ctx.with_chain_tx_count(Arc::new(core::sync::atomic::AtomicU64::new(count)))
            }
            None => ctx,
        };
        let ctx = Arc::new(ctx);
        let mut previous = BlockHash::default();
        let mut parent = None;
        let mut tip = None;
        for (index, &time) in times.iter().enumerate() {
            let height = u32::try_from(index).unwrap_or(u32::MAX);
            let candidate = header(previous, time, height);
            previous = candidate.compute_hash();
            let hash = previous;
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
                body_size: 0,
                header: None,
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
            hash: hash.into(),
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
        let expected = super::u64_to_f64(u64::try_from(count).unwrap_or(0))
            / super::u64_to_f64(u64::try_from(interval).unwrap_or(0));
        assert!(
            (txrate - expected).abs() < f64::EPSILON,
            "got {txrate}, expected {expected}"
        );
    }

    /// A rate must keep the full window count, not the low 32 bits.
    ///
    /// Capping through `u32::try_from` locks `txrate` once the window's
    /// transactions pass 4_294_967_295. Bitcoin Core divides the 64-bit
    /// count by the 64-bit interval; so does [`u64_to_f64`].
    #[test]
    fn txrate_keeps_counts_above_u32_max() {
        const PAST: u64 = 3;
        // `u32::MAX + 100`. Written as a literal because `u64::from` is not
        // const-stable here; the inequality below is what keeps it honest.
        const END: u64 = 4_294_967_395;
        let ctx = Context::new();
        // Four blocks so a one-block window is legal and the two MTP
        // boundaries differ (three or fewer keep the same median).
        let tip = super::chaintxstats_durability_tests::insert_counted_chain(
            &ctx,
            &[1_000, 2_000, 3_000, 4_000],
            &[1, 2, PAST, END],
        );
        ctx.set_applied_tip(tip);
        let ctx = Arc::new(ctx);
        assert!(
            END > u64::from(u32::MAX),
            "END must sit above the old 32-bit cap"
        );

        let result = stats(&ctx, &json!([1]));
        let count = END - PAST;
        assert_eq!(
            result
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(count)
        );
        let Some(interval) = result
            .get("window_interval")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("window_interval missing: {result:?}");
        };
        let Some(txrate) = result.get("txrate").and_then(JsonValueTrait::as_f64) else {
            panic!("txrate missing: {result:?}");
        };
        let expected = super::u64_to_f64(count) / super::u64_to_f64(interval);
        let capped = f64::from(u32::MAX) / super::u64_to_f64(interval);
        assert_ne!(
            expected, capped,
            "the fixture must sit above the old 32-bit cap"
        );
        assert!(
            (txrate - expected).abs() < f64::EPSILON,
            "got {txrate}, expected {expected}"
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
        assert_eq!(field(&result, "window_block_count"), Some(height - 1));
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
        // The count is the cumulative one *through the chosen block*, not the
        // tip's total. The durable counter tracks the tip alone, so this can
        // only come from a log prefix that reaches genesis -- which this
        // fixture has, and which a restarted node would not.
        //
        // The fixture gives block `h` exactly `h + 1` transactions, so the
        // cumulative count through height 8 is 1 + 2 + ... + 9.
        let expected_txcount = (1..=i64::try_from(chosen_height).unwrap_or(0) + 1).sum::<i64>();
        assert_eq!(
            field(&result, "txcount"),
            Some(expected_txcount),
            "a historical block on the applied chain has a knowable count: {result:?}"
        );
        assert_ne!(
            field(&result, "txcount"),
            field(&stats(&ctx, &json!([2])), "txcount"),
            "reporting the tip's total against another block would pass the check above \
             only by coincidence; these must differ"
        );
    }

    /// A block whose body this node has not applied is not the end of a window.
    ///
    /// Membership used to be decided against the header tree's own best chain.
    /// Headers run ahead of validation for most of a sync, so that accepts a
    /// block this node has never verified -- and answers about it with the same
    /// confidence as one it has. Resolved from the applied tip, it is refused.
    #[test]
    fn a_header_only_block_above_the_applied_tip_is_refused() {
        let ctx = chain_ctx(&TIMES);
        let Some(tip) = ctx.applied_tip.load_full() else {
            panic!("the fixture has an applied tip");
        };
        // One more header on the same chain, with no record and no application.
        let ahead = {
            let mut tree = ctx.block_tree.write();
            let Ok(tip_node) = tree.node(tip.tip_id) else {
                panic!("the applied tip must be in the tree");
            };
            let candidate = header(tip_node.header.compute_hash(), 1_008_000, 99);
            let hash = Hash256::from_le_bytes(candidate.compute_hash().as_bytes());
            let _id = tree
                .insert_node(Some(tip.tip_id), candidate, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert_node failed: {err}"));
            hash
        };

        let error = getchaintxstats(&ctx, &json!([2, ahead.to_string_be()]))
            .err()
            .unwrap_or_else(|| panic!("a header-only block must be refused"));
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
    }

    /// A restarted node cannot name a count it never counted.
    ///
    /// The log is rebuilt empty on every open, so a prefix that does not reach
    /// genesis sums to a number that is not a chain total. Omitting is Core's
    /// own signal for an unknown count; under-reporting would read as a quiet
    /// chain and a fee estimator would believe it.
    #[test]
    fn a_log_that_does_not_reach_genesis_reports_no_count() {
        let ctx = chain_ctx(&TIMES);
        {
            // Drop the genesis record, leaving the rest of the log intact.
            let mut blocks = ctx.blocks.write();
            let kept: Vec<BlockRecord> = blocks.iter().skip(1).cloned().collect();
            blocks.clear();
            for record in kept {
                blocks.push(record);
            }
        }
        let chosen = TIMES.len() - 5;
        let hash = {
            let tree = ctx.block_tree.read();
            let Some(node) = tree.active_node_at_height(u32::try_from(chosen).unwrap_or(0)) else {
                panic!("the fixture has a block at that height");
            };
            node.hash
        };
        let result = stats(&ctx, &json!([2, hash.to_string_be()]));
        assert!(result.get("txcount").is_none(), "{result:?}");
    }

    /// The durable counter answers for the applied tip, and for nothing else.
    ///
    /// It carries one number, the total through the tip. Handing that number
    /// back for a block six deep reports the whole chain's transactions as
    /// though they had all arrived by then -- an over-count that grows with the
    /// distance, and reads as a confident measurement.
    ///
    /// The log is what knows the rest, and it knows them exactly: the fixture
    /// gives block `h` exactly `h + 1` transactions, so the count through `h`
    /// is `(h + 1)(h + 2) / 2` however the counter is set.
    #[test]
    fn the_durable_counter_does_not_answer_for_a_historical_block() {
        const TIP_TOTAL: u64 = 999_999;

        let ctx = chain_ctx_with_counter(&TIMES, Some(TIP_TOTAL));
        let chosen = TIMES.len() - 5;
        let hash = {
            let tree = ctx.block_tree.read();
            let Some(node) = tree.active_node_at_height(u32::try_from(chosen).unwrap_or(0)) else {
                panic!("the fixture has a block at that height");
            };
            node.hash
        };

        // The tip still answers from the counter, which is what makes the
        // historical answer below a restriction rather than a removal.
        assert_eq!(
            field(&stats(&ctx, &json!([2])), "txcount"),
            Some(i64::try_from(TIP_TOTAL).unwrap_or(0)),
            "the applied tip is exactly what the durable counter is for"
        );

        let historical = i64::try_from(chosen).unwrap_or(0);
        assert_eq!(
            field(&stats(&ctx, &json!([2, hash.to_string_be()])), "txcount"),
            Some((historical + 1) * (historical + 2) / 2),
            "a historical block is counted through the log, not handed the tip's total"
        );
    }

    /// A known durable tip total must not suppress a window the log can count.
    ///
    /// The counter is one number, the total through the tip. Subtracting a
    /// log prefix from that number is only right when the two agree. The
    /// fixture sets them apart on purpose: mixing them would report
    /// `TIP_TOTAL - log_start` instead of the window the log actually holds.
    #[test]
    fn a_durable_tip_total_does_not_block_a_complete_log_window() {
        const TIP_TOTAL: u64 = 999_999;
        let ctx = chain_ctx_with_counter(&TIMES, Some(TIP_TOTAL));
        let blocks = 4_i64;
        let final_height = TIMES.len() - 1;
        let past_height = final_height - usize::try_from(blocks).unwrap_or(0);
        let expected: i64 = (past_height + 1..=final_height)
            .map(|height| i64::try_from(height).unwrap_or(0) + 1)
            .sum();
        let mixed = i64::try_from(TIP_TOTAL).unwrap_or(0)
            - (0..=past_height)
                .map(|height| i64::try_from(height).unwrap_or(0) + 1)
                .sum::<i64>();
        assert_ne!(
            expected, mixed,
            "the fixture must separate the two sources, or it proves nothing"
        );

        let result = stats(&ctx, &json!([blocks]));
        assert_eq!(
            field(&result, "txcount"),
            Some(i64::try_from(TIP_TOTAL).unwrap_or(0)),
            "the applied tip still answers from the durable counter"
        );
        assert_eq!(
            field(&result, "window_tx_count"),
            Some(expected),
            "the window must come from the log, not durable_tip - log_start: {result:?}"
        );
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
                BlockHash::from(Hash256::from_le_bytes(&parent.to_le_bytes())),
                1_002_000,
                9_999,
            );
            let hash = Hash256::from_le_bytes(sibling.compute_hash().as_bytes());
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

    #[test]
    fn historical_selection_uses_the_selected_nodes_count_and_mtp() {
        let ctx = Context::new();
        let tip = super::chaintxstats_durability_tests::insert_counted_chain(
            &ctx,
            &[1_000, 1_600, 2_200, 2_800, 3_400],
            &[1, 4, 9, 16, 25],
        );
        ctx.set_applied_tip(tip.clone());
        let ctx = Arc::new(ctx);
        let mid_hash = {
            let tree = ctx.block_tree.read();
            let id = tree
                .node_at_height_from(tip.tip_id, 3)
                .unwrap_or_else(|| panic!("missing height 3"));
            tree.node(id)
                .unwrap_or_else(|err| panic!("mid node: {err}"))
                .hash
        };
        let value = getchaintxstats(&ctx, &json!([1, mid_hash.to_string_be()]))
            .unwrap_or_else(|err| panic!("historical getchaintxstats failed: {err}"));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(16)
        );
        assert_eq!(
            value
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        assert_eq!(
            value
                .get("window_interval")
                .and_then(JsonValueTrait::as_u64),
            Some(600)
        );
        assert_eq!(
            value
                .get("window_final_block_height")
                .and_then(JsonValueTrait::as_u64),
            Some(3)
        );
    }

    #[test]
    fn default_tip_selection_uses_the_applied_node_count() {
        let ctx = Context::new();
        let tip = super::chaintxstats_durability_tests::insert_counted_chain(
            &ctx,
            &[1_000, super::chaintxstats_durability_tests::TIP_TIME],
            &[1, 11],
        );
        ctx.set_applied_tip(tip);
        let ctx = Arc::new(ctx);
        assert_eq!(
            super::chaintxstats_durability_tests::stats_of(&ctx)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(11)
        );
    }

    #[test]
    fn historical_stats_survive_an_empty_block_log() {
        let ctx = Context::new();
        let tip = super::chaintxstats_durability_tests::insert_counted_chain(
            &ctx,
            &[
                1_000_000,
                1_000_100,
                super::chaintxstats_durability_tests::TIP_TIME,
            ],
            &[1, 1, 42],
        );
        ctx.set_applied_tip(tip);
        let ctx = Arc::new(ctx);
        assert!(ctx.blocks.read().is_empty());
        let hash = ctx.applied_hash().to_string_be();
        let value = getchaintxstats(&ctx, &json!([1, hash.as_str()]))
            .unwrap_or_else(|err| panic!("reopen stats failed: {err}"));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(42)
        );
        assert_eq!(
            value
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(41)
        );
    }

    /// Builds genesis, a lost equal-work sibling, and the winning branch with
    /// its child, returning (genesis hash, lost hash, winning tip snapshot).
    fn reorg_fixture(ctx: &Context) -> (Hash256, Hash256, TipSnapshot) {
        let mut tree = ctx.block_tree.write();
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        let genesis_id = tree
            .insert_node(None, genesis, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("genesis: {err}"));
        tree.restore_chain_tx_count(genesis_id, 1)
            .unwrap_or_else(|err| panic!("genesis count: {err}"));
        let lost = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_100,
            bits: 0x207f_ffff,
            nonce: 1,
        };
        let lost_id = tree
            .insert_node(Some(genesis_id), lost, NodeStatus::HeaderValid)
            .unwrap_or_else(|err| panic!("lost: {err}"));
        tree.restore_chain_tx_count(lost_id, 3)
            .unwrap_or_else(|err| panic!("lost count: {err}"));
        let won = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_200,
            bits: 0x207f_ffff,
            nonce: 2,
        };
        let won_id = tree
            .insert_node(Some(genesis_id), won, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("won: {err}"));
        tree.restore_chain_tx_count(won_id, 8)
            .unwrap_or_else(|err| panic!("won count: {err}"));
        let child = Header {
            version: 1,
            prev_blockhash: won.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_300,
            bits: 0x207f_ffff,
            nonce: 3,
        };
        let child_id = tree
            .insert_node(Some(won_id), child, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("child: {err}"));
        tree.restore_chain_tx_count(child_id, 15)
            .unwrap_or_else(|err| panic!("child count: {err}"));
        let lost_hash = tree
            .node(lost_id)
            .unwrap_or_else(|err| panic!("lost node: {err}"))
            .hash;
        let child_node = tree
            .node(child_id)
            .unwrap_or_else(|err| panic!("child node: {err}"));
        (
            tree.node(genesis_id)
                .unwrap_or_else(|err| panic!("genesis node: {err}"))
                .hash,
            lost_hash,
            TipSnapshot {
                tip_id: child_id,
                height: child_node.height,
                chainwork: child_node.chainwork,
                hash: child_node.hash,
            },
        )
    }

    #[test]
    fn reorg_selects_the_winning_branch_counts() {
        let ctx = Context::new();
        let (genesis_hash, lost_hash, won) = reorg_fixture(&ctx);
        ctx.set_applied_tip(won.clone());
        let ctx = Arc::new(ctx);
        let _ = genesis_hash;
        assert_eq!(
            super::chaintxstats_durability_tests::stats_of(&ctx)
                .get("txcount")
                .and_then(JsonValueTrait::as_u64),
            Some(15),
            "default selection must follow the applied branch"
        );
        let err = getchaintxstats(&ctx, &json!([1, lost_hash.to_string_be()])).unwrap_err();
        assert!(matches!(
            err,
            RpcError::InvalidParameter(message) if message == "Block is not in main chain"
        ));
        let value = getchaintxstats(&ctx, &json!([1, won.hash.to_string_be()]))
            .unwrap_or_else(|err| panic!("winning branch stats failed: {err}"));
        assert_eq!(
            value.get("txcount").and_then(JsonValueTrait::as_u64),
            Some(15)
        );
        assert_eq!(
            value
                .get("window_tx_count")
                .and_then(JsonValueTrait::as_u64),
            Some(7)
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod verification_progress_wiring_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_chain::{ChainWork, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::Hash256;
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    fn half_applied_ctx(chain_tx_count: Option<u64>) -> Arc<Context> {
        let mut ctx = Context::new();
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        let id = {
            let mut tree = ctx.block_tree.write();
            let id = tree
                .insert_node(None, header, NodeStatus::Active)
                .unwrap_or_else(|err| panic!("insert: {err}"));
            if let Some(count) = chain_tx_count {
                tree.restore_chain_tx_count(id, count)
                    .unwrap_or_else(|err| panic!("restore: {err}"));
            }
            id
        };
        if let Some(count) = chain_tx_count {
            ctx = ctx.with_chain_tx_count(Arc::new(core::sync::atomic::AtomicU64::new(count)));
        }
        let hash = header.compute_hash().0;
        ctx.set_chain_tip(TipSnapshot {
            tip_id: id,
            height: 100,
            chainwork: ChainWork::ZERO,
            hash,
        });
        ctx.set_applied_tip(TipSnapshot {
            tip_id: id,
            height: 50,
            chainwork: ChainWork::ZERO,
            hash,
        });
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod initial_block_download_tests {
    use alloc::sync::Arc;

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
            let genesis = Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            };
            let Ok(genesis_id) = tree.insert_node(None, genesis, NodeStatus::Active) else {
                panic!("genesis insert failed");
            };
            let child = Header {
                version: 1,
                prev_blockhash: genesis.compute_hash(),
                merkle_root: Hash256::default(),
                time: tip_time,
                bits: 0x207f_ffff,
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

    use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
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

    /// P2PKH script for the burn address these fixtures scan for: base58check
    /// decodes to version 0 with an all-zero 20-byte hash160.
    fn burn_p2pkh_script() -> Vec<u8> {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[0_u8; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        script
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
        let script = burn_p2pkh_script();
        let txout = TxOut {
            value: 12_345,
            script_pubkey: script.clone(),
        };
        let outpoint = OutPoint::new(Txid::from(test_txid(11)), 0);
        commit_test_utxo(&ctx, outpoint, txout, true, 0);
        commit_test_utxo(
            &ctx,
            OutPoint::new(Txid::from(test_txid(12)), 0),
            TxOut {
                value: 9_999,
                script_pubkey: vec![0x51],
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
            txid.to_string()
        };
        assert_eq!(
            first.get("txid").and_then(Value::as_str),
            Some(expected_txid.as_str())
        );
        assert_eq!(first.get("vout").and_then(Value::as_u64), Some(0));
        assert_eq!(
            first.get("scriptPubKey").and_then(Value::as_str),
            Some(hex_encode(&script).as_str())
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
        let script = burn_p2pkh_script();
        commit_test_utxo(
            &ctx,
            OutPoint::new(Txid::from(test_txid(101)), 0),
            TxOut {
                value: 10_000,
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
            OutPoint::new(Txid::from(test_txid(102)), 0),
            TxOut {
                value: 20_000,
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
        let script = burn_p2pkh_script();
        let txout = TxOut {
            value: 12_345,
            script_pubkey: script,
        };
        let outpoint = OutPoint::new(Txid::from(test_txid(13)), 0);
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
            txid.to_string()
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

#[cfg(test)]
mod stripped_size_tests {
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    };

    /// A block whose single transaction carries a witness stack.
    fn witness_block() -> Block {
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0_u8; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: vec![vec![0x21_u8; 64], vec![0x03_u8; 33]],
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            }],
        };
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_700_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![tx],
        }
    }

    /// A block whose transaction carries no witness.
    fn witness_free_block() -> Block {
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0_u8; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            }],
        };
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_700_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![tx],
        }
    }

    #[test]
    fn stripped_size_is_below_total_for_a_witness_block() {
        let block = witness_block();
        let total = consensus_bytes(&block).len();
        let stripped = crate::render::stripped_size(&block);

        assert!(
            stripped < total,
            "the witness discount must be visible: {stripped} vs {total}"
        );
    }

    #[test]
    fn stripped_size_equals_the_sum_of_base_sizes_plus_header_and_count() {
        let block = witness_block();
        let manual: usize = 80
            + 1 // compact size for 1 tx
            + block.txs.iter().map(Tx::base_size).sum::<usize>();
        assert_eq!(crate::render::stripped_size(&block), manual);
    }

    #[test]
    fn stripped_size_equals_total_for_a_witness_free_block() {
        let block = witness_free_block();
        let total = consensus_bytes(&block).len();
        assert_eq!(crate::render::stripped_size(&block), total);
    }
}
