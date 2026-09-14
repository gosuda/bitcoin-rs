//! Network hash-rate estimation for `getnetworkhashps` and `getmininginfo`.

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Network;
use compact_str::CompactString;

use crate::MiningControlError;

/// Core `GetNetworkHashPS` for `getnetworkhashps` (API-06). Owns lookup and
/// height validation.
// CONTRACT: docs/contracts/external-api.md#API-06
pub fn network_hash_ps(
    tree: &BlockTree,
    tip: Option<&TipSnapshot>,
    lookup: i64,
    height: i64,
    network: Network,
) -> Result<f64, MiningControlError> {
    if lookup < -1 || lookup == 0 {
        return Err(MiningControlError::InvalidRequest(CompactString::from(
            "Invalid nblocks. Must be a positive number or -1.",
        )));
    }
    // Any height the snapshot cannot resolve is Core's invalid-parameter
    // error: below -1, above the tip, or absent from the tip's ancestry.
    let missing_height = || {
        MiningControlError::InvalidRequest(CompactString::from(
            "Block does not exist at specified height",
        ))
    };
    let tip_height = tip.map_or(-1, |snapshot| i64::from(snapshot.height));
    if height < -1 || height > tip_height {
        return Err(missing_height());
    }
    let Some(tip) = tip else {
        return Ok(0.0);
    };
    let start = if height < 0 {
        tip.tip_id
    } else {
        let requested = u32::try_from(height).map_err(|_| missing_height())?;
        tree.node_at_height_from(tip.tip_id, requested)
            .ok_or_else(missing_height)?
    };
    Ok(estimate_network_hashps(tree, Some(start), lookup, network))
}

/// Estimates hashes/s over `lookup` blocks ending at an already-resolved start.
///
/// The window is Core's parent walk (`GetNetworkHashPS`): `lookup` parent pointers from the start
/// node, min/max header time, `chainwork` delta over that span. A missing
/// start or unwalkable window is a zero rate so `getmininginfo` can stay
/// best-effort.
// CONTRACT: docs/contracts/external-api.md#API-06
pub fn estimate_network_hashps(
    tree: &BlockTree,
    start_id: Option<NodeId>,
    lookup: i64,
    network: Network,
) -> f64 {
    let Some(start_id) = start_id else {
        return 0.0;
    };
    let Some(start_node) = tree.node(start_id).ok().filter(|node| node.height != 0) else {
        return 0.0;
    };
    let mut walk = if lookup == -1 {
        let interval = i64::from(network.retarget_interval());
        if interval <= 0 {
            1
        } else {
            i64::from(start_node.height) % interval + 1
        }
    } else {
        lookup
    };
    if walk > i64::from(start_node.height) {
        walk = i64::from(start_node.height);
    }
    // A negative lookup other than -1 has no window; treat it as an empty walk.
    let walk = u32::try_from(walk).unwrap_or(0);
    if walk == 0 {
        return 0.0;
    }

    let mut min_time = start_node.header.time;
    let mut max_time = min_time;
    let mut earliest_id = start_id;
    for _ in 0..walk {
        let Some(parent) = tree.node(earliest_id).ok().and_then(|node| node.parent) else {
            return 0.0;
        };
        earliest_id = parent;
        let Ok(parent_node) = tree.node(parent) else {
            return 0.0;
        };
        min_time = min_time.min(parent_node.header.time);
        max_time = max_time.max(parent_node.header.time);
    }
    if min_time == max_time {
        return 0.0;
    }
    let Ok(earliest_node) = tree.node(earliest_id) else {
        return 0.0;
    };
    let work_delta = start_node.chainwork.saturating_sub(earliest_node.chainwork);
    let time_delta_secs = i64::from(max_time).saturating_sub(i64::from(min_time));
    let work_bytes: [u8; 32] = work_delta.to_be_bytes();
    hashes_per_second(work_bytes, time_delta_secs)
}

fn hashes_per_second(work_be_bytes: [u8; 32], time_delta_secs: i64) -> f64 {
    if time_delta_secs <= 0 {
        return 0.0;
    }
    let work = work_be_bytes
        .iter()
        .fold(0.0_f64, |acc, &byte| acc.mul_add(256.0, f64::from(byte)));
    work / f64::from(u32::try_from(time_delta_secs).unwrap_or(u32::MAX))
}

/// Oracle: Bitcoin Core `GetNetworkHashPS`, `src/rpc/mining.cpp` (kernel 31.99).
#[cfg(test)]
mod oracle_tests;
