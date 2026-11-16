use alloc::sync::Arc;
use core::str::FromStr as _;
use std::time::Duration;

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_chain::chain::TipSnapshot;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_index::silent_payments::{BlockTweaks, block_tweaks};
use bitcoin_rs_storage::utxo::contract::{BlockSpendsError, BoundedReadError};
use sonic_rs::{JsonValueTrait as _, Value, json};

use crate::context::{AppliedView, Context};
use crate::error::RpcError;

const MAX_SELECTION_HOPS: usize = 4_096;

fn unavailable(message: &str) -> RpcError {
    RpcError::Misc(format!("Silent payments unavailable: {message}"))
}

pub(crate) fn getblocktweaks(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let service = ctx
        .silent_payments
        .as_ref()
        .ok_or(RpcError::MethodDisabled(
            "getblocktweaks is disabled; enable --silent-payments",
        ))?;
    super::ensure_at_most_params(params, 1)?;
    let params = super::params_array(params)?;
    let selector = params
        .first()
        .ok_or(RpcError::InvalidParams("block height or hash is required"))?;
    let view = ctx.chain.applied_view();
    let tip = view.tip().ok_or_else(|| unavailable("no applied tip"))?;
    if ctx.chain.progress.initial_block_download(
        bitcoin_rs_consensus::primitives::unix_time_secs(),
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
        | BlockSpendsError::BodyRead(BoundedReadError::CorruptFrame(_))
        | BlockSpendsError::BoundedRead(BoundedReadError::Storage(_))
        | BlockSpendsError::BoundedRead(BoundedReadError::CorruptFrame(_)) => {
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
mod tests {
    use super::*;
    use bitcoin_rs_chain::chain::{NodeStatus, TipSnapshot};
    use bitcoin_rs_consensus::primitives::{Block, Network};
    use bitcoin_rs_storage::utxo::contract::{BlockSpends, BlockUndoSource, HistoryUnavailable};

    type Result<T = ()> = std::result::Result<T, crate::test_error::TestError>;

    struct Source<F>(F);
    impl<F> BlockUndoSource for Source<F>
    where
        F: Fn(Hash256, Hash256) -> std::result::Result<BlockSpends, BlockSpendsError> + Send + Sync,
    {
        fn block_spends(
            &self,
            hash: Hash256,
            tip: Hash256,
        ) -> std::result::Result<BlockSpends, BlockSpendsError> {
            (self.0)(hash, tip)
        }
    }

    fn fixture() -> Result<(Context, Block)> {
        let mut ctx = Context::from_handles(crate::context::ContextHandles {
            silent_payments: true,
            ..crate::context::ContextHandles::default()
        });
        ctx.chain.chain_network = Network::Regtest;
        let mut block = Network::Regtest.genesis_block();
        block.header.time = u32::try_from(bitcoin_rs_consensus::primitives::unix_time_secs())?;
        let tip = {
            let mut tree = ctx.chain.block_tree.write();
            let id = tree.insert_node(None, block.header, NodeStatus::Active)?;
            let node = tree.node(id)?;
            TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            }
        };
        ctx.chain.applied_tip.store(Some(Arc::new(tip)));
        let body = block.clone();
        ctx.chain.block_undo_source = Some(Arc::new(Source(move |hash, expected| {
            assert_eq!(hash, Hash256::from(body.block_hash()));
            assert_eq!(expected, hash);
            Ok(BlockSpends {
                block: body.clone(),
                spent: Ok(vec![vec![]]),
            })
        })));
        Ok((ctx, block))
    }

    #[test]
    fn unavailable_history_never_becomes_empty_success() -> Result {
        for reason in [
            HistoryUnavailable::Missing,
            HistoryUnavailable::Pruned { below: 1 },
            HistoryUnavailable::Reserved { below: 1 },
            HistoryUnavailable::Shutdown,
        ] {
            let (mut ctx, block) = fixture()?;
            ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
                Ok(BlockSpends {
                    block: block.clone(),
                    spent: Err(reason),
                })
            })));
            let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
                .err()
                .ok_or("unavailable")?;
            assert_eq!(error.code(), -1);
            assert!(error.to_string().contains(&reason.to_string()));
        }
        Ok(())
    }

    #[test]
    fn moved_tip_and_recovery_after_source_read_refuse_publication() -> Result {
        for close in [false, true] {
            let (mut ctx, block) = fixture()?;
            let applied = ctx.chain.applied_tip.clone();
            let closed = bitcoin_rs_consensus::latch::LatchWriter::new();
            ctx.chain.closed_for_recovery = closed.reader();
            ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
                if close {
                    closed.trigger();
                } else {
                    let mut tip = applied
                        .load_full()
                        .ok_or(BlockSpendsError::Retry)?
                        .as_ref()
                        .clone();
                    tip.hash = Hash256::default();
                    applied.store(Some(Arc::new(tip)));
                }
                Ok(BlockSpends {
                    block: block.clone(),
                    spent: Ok(vec![vec![]]),
                })
            })));
            let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
                .err()
                .ok_or("must refuse")?;
            assert_eq!(error.code(), -1);
        }
        Ok(())
    }

    #[test]
    fn body_identity_and_read_errors_are_preserved() -> Result {
        for wrap in [BlockSpendsError::BodyRead, BlockSpendsError::BoundedRead] {
            let disk =
                BoundedReadError::from(std::io::Error::other("private/path: disk read failed"));
            let error = read_error(&wrap(disk));
            assert_eq!(error.code(), RpcError::INTERNAL_ERROR);
            let corrupt = BoundedReadError::CorruptFrame("bad frame");
            assert_eq!(read_error(&wrap(corrupt)).code(), RpcError::INTERNAL_ERROR);
            for refusal in [
                BoundedReadError::Unsupported,
                BoundedReadError::Limit { size: 2, limit: 1 },
            ] {
                assert_eq!(read_error(&wrap(refusal)).code(), -1);
            }
        }
        assert_eq!(read_error(&BlockSpendsError::Retry).code(), -1);
        let (mut ctx, mut block) = fixture()?;
        block.header.nonce ^= 1;
        ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
            Ok(BlockSpends {
                block: block.clone(),
                spent: Ok(vec![vec![]]),
            })
        })));
        let error = getblocktweaks(&Arc::new(ctx), &json!([0]))
            .err()
            .ok_or("wrong body")?;
        assert_eq!(error.code(), RpcError::INTERNAL_ERROR);
        Ok(())
    }

    #[test]
    fn shared_materialization_budget_and_transition_never_queue_tweak_work() -> Result {
        let (ctx, _) = fixture()?;
        let ctx = Arc::new(ctx);
        let held = ctx.silent_payments.as_ref().ok_or("service")?.lock();
        assert!(getblocktweaks(&ctx, &json!([0])).is_err());
        drop(held);
        getblocktweaks(&ctx, &json!([0]))?;
        getblocktweaks(&ctx, &json!([0]))?;
        let first = ctx.try_acquire_block_render().ok_or("permit")?;
        let second = ctx.try_acquire_block_render().ok_or("permit")?;
        let error = getblocktweaks(&ctx, &json!([0]))
            .err()
            .ok_or("must refuse")?;
        assert_eq!(error.code(), -1);
        drop((first, second));

        let (ctx, _) = fixture()?;
        let ctx = Arc::new(ctx);
        let held = ctx.chain.chain_transition.lock();
        let error = getblocktweaks(&ctx, &json!([0]))
            .err()
            .ok_or("must refuse")?;
        assert_eq!(error.code(), -1);
        drop(held);
        Ok(())
    }

    #[test]
    fn ibd_and_missing_applied_tip_are_not_empty_success() -> Result {
        let (mut ctx, _) = fixture()?;
        ctx.chain.chain_network = Network::Mainnet;
        let ctx = Arc::new(ctx);
        assert!(matches!(
            getblocktweaks(&ctx, &json!([0])),
            Err(RpcError::ClientInInitialDownload(_))
        ));
        ctx.chain.applied_tip.store(None);
        let error = getblocktweaks(&ctx, &json!([0]))
            .err()
            .ok_or("missing tip")?;
        assert_eq!(error.code(), -1);
        Ok(())
    }
}
