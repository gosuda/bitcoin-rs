//! Experimental, authenticated, one-block BIP352 read adapter. No durable state.

use alloc::sync::Arc;
use core::str::FromStr as _;
use std::time::Duration;

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::silent_payments::{BlockTweaks, block_tweaks};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::contract::{BlockSpendsError, BoundedReadError};
use sonic_rs::{JsonValueTrait as _, Value, json};

use crate::context::{AppliedView, Context};
use crate::error::RpcError;

const MAX_SELECTION_HOPS: usize = 4_096;

fn unavailable(message: &str) -> RpcError {
    RpcError::Misc(format!("Silent payments unavailable: {message}"))
}

/// Activation follows `consensus::verify_flags`, never the tip height; source
/// rechecks certify the read, not the CPU/JSON projection it feeds, and the
/// single-work slot bounds projection without waiting on validation or holding transition exclusion.
pub(crate) fn getblocktweaks(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let service = ctx
        .silent_payments
        .as_ref()
        .ok_or(RpcError::MethodDisabled(
            "getblocktweaks is disabled; enable --silent-payments",
        ))?;
    let params = super::bind_named_params(params, &["block"])?;
    super::ensure_at_most_params(&params, 1)?;
    let params = super::params_array(&params)?;
    let selector = params
        .first()
        .ok_or(RpcError::InvalidParams("block height or hash is required"))?;
    let view = ctx.chain.applied_view();
    let tip = view.tip().ok_or_else(|| unavailable("no applied tip"))?;
    if ctx.chain.progress.initial_block_download(
        bitcoin_rs_primitives::unix_time_secs(),
        ctx.chain.chain_network,
    ) {
        return Err(RpcError::ClientInInitialDownload(
            "getblocktweaks is unavailable during initial block download".to_owned(),
        ));
    }
    let _admission = service
        .try_lock()
        .ok_or_else(|| unavailable("busy; retry"))?;
    let (height, hash) = select_block(ctx, &view, selector)?;
    let materialization = ctx
        .try_acquire_block_render()
        .ok_or_else(|| unavailable("full-block read limit; retry"))?;
    let source = ctx
        .chain
        .block_undo_source
        .as_ref()
        .ok_or_else(|| unavailable("certified block inputs are not configured"))?;
    let inputs = source
        .block_spends(hash, tip.hash)
        .map_err(|error| read_error(&error))?;
    if Hash256::from(inputs.block.block_hash()) != hash {
        return Err(RpcError::Internal(
            "silent payment body hash differs from selection".to_owned(),
        ));
    }
    let taproot_active = ctx.chain.chain_network.is_taproot_active(height);
    let material = block_tweaks(&inputs, taproot_active).map_err(|error| read_error(&error))?;
    drop(inputs);
    drop(materialization);
    let result = render(&material, height, tip, taproot_active);
    let _stable = ctx
        .chain
        .chain_transition
        .try_lock_for(Duration::ZERO)
        .ok_or_else(|| unavailable("chain transition in progress; retry"))?;
    if ctx.chain.closed_for_recovery.is_triggered() {
        return Err(unavailable("closed for recovery"));
    }
    if ctx.chain.applied_view().tip().map(|tip| tip.hash) != Some(tip.hash) {
        return Err(unavailable(
            "applied chain changed during projection; retry",
        ));
    }
    Ok(result)
}

fn select_block(
    ctx: &Context,
    view: &AppliedView,
    block: &Value,
) -> Result<(u32, Hash256), RpcError> {
    let tip = view.tip().ok_or_else(|| unavailable("no applied tip"))?;
    let tree = ctx.chain.block_tree.read();
    let (height, expected_hash) = if let Some(text) = block.as_str() {
        let hash = Hash256::from_str(text).map_err(|_| {
            RpcError::InvalidParameter("block must be a 64-character hexadecimal hash".to_owned())
        })?;
        let height = tree
            .height_of_hash(hash)
            .ok_or(RpcError::NotFound("Block not found"))?;
        (height, Some(hash))
    } else {
        let height = block
            .as_u64()
            .and_then(|height| u32::try_from(height).ok())
            .ok_or(RpcError::InvalidParams(
                "block must be a nonnegative u32 height or hash string",
            ))?;
        (height, None)
    };
    if height > view.height() {
        return Err(RpcError::InvalidParameter(
            "block height exceeds the applied tip".to_owned(),
        ));
    }
    let mut remaining = MAX_SELECTION_HOPS;
    let id = tree
        .node_at_height_from_bounded(tip.tip_id, height, &mut remaining)
        .map_err(|_| unavailable("applied ancestry selection exceeds its hop budget"))?
        .ok_or_else(|| unavailable("applied ancestry is incomplete"))?;
    let hash = tree
        .node(id)
        .map_err(|_| unavailable("applied ancestor is absent"))?
        .hash;
    if expected_hash.is_some_and(|expected| expected != hash) {
        return Err(RpcError::InvalidParameter(
            "block is not on the applied chain".to_owned(),
        ));
    }
    Ok((height, hash))
}

fn read_error(error: &BlockSpendsError) -> RpcError {
    match error {
        BlockSpendsError::Corrupt(_)
        | BlockSpendsError::Storage(_)
        | BlockSpendsError::Undo(_)
        | BlockSpendsError::BodyRead(BoundedReadError::Storage(_))
        | BlockSpendsError::BoundedRead(BoundedReadError::Storage(_)) => {
            tracing::warn!(%error, "silent payment block input read failed");
            RpcError::Internal("Unable to read silent payment block inputs".to_owned())
        }
        _ => unavailable(&error.to_string()),
    }
}

fn render(material: &BlockTweaks, height: u32, tip: &TipSnapshot, active: bool) -> Value {
    let transactions = material
        .transactions
        .iter()
        .map(|tx| {
            let outputs = tx
                .outputs
                .iter()
                .map(|output| {
                    json!({
                        "vout": output.vout,
                        "output_key": output.output_key.to_lower_hex_string(),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "txid": tx.txid.to_string(),
                "tweak": tx.tweak.to_lower_hex_string(),
                "outputs": outputs,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "height": height,
        "hash": material.hash.to_string(),
        "tip_height": tip.height,
        "tip_hash": tip.hash.to_string_be(),
        "taproot_active": active,
        "transactions": transactions,
    })
}

#[cfg(test)]
mod tests;
