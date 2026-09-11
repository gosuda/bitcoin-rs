//! Typed synchronization progress projection for the embedding surface.

use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin_rs_primitives::{Hash256, Network};

use super::{Node, SyncProgress};

impl Node {
    /// Returns typed synchronization progress without touching RPC JSON.
    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        let ctx = &self.context;
        let applied_tip = ctx.applied_tip.load_full();
        let applied = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let headers = ctx.height();
        let (difficulty, time, median_time) =
            applied_tip.as_ref().map_or((0.0, 0_u64, 0_u64), |tip| {
                let tree = ctx.block_tree.read();
                tree.node(tip.tip_id).map_or((0.0, 0, 0), |node| {
                    (
                        ctx.difficulty_for_bits(node.header.bits),
                        u64::from(node.header.time),
                        u64::from(tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0)),
                    )
                })
            });
        let now = unix_time_secs();
        let verification_progress = ctx.chain_tx_count().map_or_else(
            || height_ratio_progress(applied, headers),
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
        let prune_status = ctx.prune_status();
        SyncProgress {
            network: ctx.chain_network,
            blocks: applied,
            headers,
            best_block_hash: applied_tip
                .as_ref()
                .map_or_else(Hash256::default, |tip| tip.hash),
            difficulty,
            time,
            median_time,
            verification_progress,
            initial_block_download: ctx.is_initial_block_download(now),
            chain_work: ctx.chainwork_hex(),
            size_on_disk: ctx
                .block_storage_disk_usage()
                .unwrap_or_else(|| ctx.blocks.read().size_on_disk()),
            pruned: prune_status.pruned,
            prune_height: prune_status.pruneheight,
        }
    }
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn height_ratio_progress(applied: u32, headers: u32) -> f64 {
    if headers == 0 {
        0.0
    } else {
        (f64::from(applied) / f64::from(headers)).min(1.0)
    }
}

fn u64_to_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

fn i64_to_f64(value: i64) -> f64 {
    if value >= 0 {
        u64_to_f64(u64::try_from(value).unwrap_or(u64::MAX))
    } else {
        -u64_to_f64(value.unsigned_abs())
    }
}

// Keep this projection op-for-op identical with the RPC progress calculation;
// moving its module must not change externally observed progress values.
#[allow(clippy::too_many_arguments)]
fn verification_progress(
    network: Network,
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
        let elapsed = now_signed.saturating_sub(i64::try_from(data.time).unwrap_or(i64::MAX));
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(data.tx_count))
    } else {
        let elapsed = now_signed.saturating_sub(block_time);
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(chain_tx_count))
    };
    if total <= 0.0 {
        return 0.0;
    }
    (u64_to_f64(chain_tx_count) / total).clamp(0.0, 1.0)
}
