use super::*;
use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use bitcoin_rs_primitives::{Block, Network};
use bitcoin_rs_utxo::contract::{BlockSpends, BlockUndoSource, HistoryUnavailable};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

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
    block.header.time = u32::try_from(bitcoin_rs_primitives::unix_time_secs())?;
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
        let closed = Arc::new(core::sync::atomic::AtomicBool::new(false));
        ctx.chain.closed_for_recovery = bitcoin_rs_chain::LatchReader::new(closed.clone());
        ctx.chain.block_undo_source = Some(Arc::new(Source(move |_, _| {
            if close {
                closed.store(true, core::sync::atomic::Ordering::Release);
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
        assert!(
            error
                .to_string()
                .contains(if close { "recovery" } else { "changed" })
        );
    }
    Ok(())
}

#[test]
fn body_identity_and_read_errors_are_preserved() -> Result {
    for wrap in [BlockSpendsError::BodyRead, BlockSpendsError::BoundedRead] {
        let disk = std::io::Error::other("private/path: disk read failed").into();
        let error = read_error(&wrap(BoundedReadError::Storage(disk)));
        assert_eq!(error.code(), RpcError::INTERNAL_ERROR);
        assert_eq!(
            error.to_string(),
            "internal error: Unable to read silent payment block inputs"
        );
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
    assert!(error.to_string().contains("full-block read limit"));
    drop((first, second));

    let (ctx, _) = fixture()?;
    let ctx = Arc::new(ctx);
    let held = ctx.chain.chain_transition.lock();
    let error = getblocktweaks(&ctx, &json!([0]))
        .err()
        .ok_or("must refuse")?;
    assert!(error.to_string().contains("transition in progress"));
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
    assert!(error.to_string().contains("no applied tip"));
    Ok(())
}
