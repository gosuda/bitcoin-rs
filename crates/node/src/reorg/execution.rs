//! Streamed disconnect/connect execution and mempool reconsideration under one transition.

use super::DISCONNECT_STREAM_WINDOW;
use super::LoadedBranchBody;
use super::LoadedPlanProgress;
use super::ReorgError;
use super::bodies::load_branch_body;
use crate::DisconnectError;
use crate::apply::ChainTransition;
use crate::apply::Chainstate;
use crate::chain_effects::ChainFollowers;
use alloc::vec::Vec;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::ReorgPlan;
use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_chain::plan_reorg;
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Txid;
use hashbrown::HashSet;

/// Validates that every disconnect-side body is present, decodable, and
/// hash-correct without retaining any of them.
///
/// This is the first of two passes: it discovers a missing or corrupt
/// old-branch body before the rollback starts, preserving the "nothing was
/// touched" failure model for body-load errors. The execution pass
/// ([`execute_streamed_plan`]) re-reads each body in a bounded window;
/// storage can fail between the two passes, and that mid-rollback failure is
/// reported as [`ReorgError::DisconnectBodyLost`].
pub(super) fn preflight_disconnect_bodies<F>(
    handles: &Chainstate,
    nodes: &[(Hash256, u32)],
    staged_body: &mut F,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    for (hash, height) in nodes {
        load_branch_body(handles, *hash, *height, staged_body)?;
    }
    Ok(())
}

/// Returns the current applied-tip height, or 0 when no tip is set.
pub(super) fn applied_tip_height(handles: &Chainstate) -> u32 {
    handles.applied_tip.load_full().map_or(0, |tip| tip.height)
}

pub(super) fn execute_streamed_plan<F>(
    transition: &ChainTransition<'_>,
    followers: &ChainFollowers,
    disconnect_nodes: &[(Hash256, u32)],
    connect: &[LoadedBranchBody],
    staged_body: &mut F,
) -> (LoadedPlanProgress, core::result::Result<(), ReorgError>)
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    let handles = transition.chainstate();
    let mut progress = LoadedPlanProgress {
        disconnected: 0,
        connected: 0,
    };

    // Disconnect: stream bodies in bounded windows. Each window is fully
    // loaded before any of its blocks are disconnected, so a load failure
    // within a window leaves the chain at the tip the previous window
    // reached — no partial disconnect within the window.
    for window in disconnect_nodes.chunks(DISCONNECT_STREAM_WINDOW) {
        let mut bodies = Vec::with_capacity(window.len());
        for (hash, height) in window {
            match load_branch_body(handles, *hash, *height, staged_body) {
                Ok(body) => bodies.push(body),
                Err(source) => {
                    return (
                        progress,
                        Err(ReorgError::DisconnectBodyLost {
                            disconnected: progress.disconnected,
                            stopped_at: applied_tip_height(handles),
                            source: Box::new(source),
                        }),
                    );
                }
            }
        }
        for body in bodies {
            match transition.disconnect(&body.block) {
                Ok(outcome) => {
                    followers.disconnected(&outcome);
                    progress.disconnected += 1;
                }
                Err(
                    error @ (DisconnectError::Fatal { .. } | DisconnectError::MarkerStuck { .. }),
                ) => {
                    handles.admission.close_permanently();
                    return (progress, Err(ReorgError::Fatal(Box::new(error))));
                }
                Err(error) => {
                    return (
                        progress,
                        Err(ReorgError::Refused {
                            disconnected: progress.disconnected,
                            stopped_at: body.height,
                            source: Box::new(error),
                        }),
                    );
                }
            }
        }
    }

    // Connect: from the loaded prefix (bounded by staging).
    for body in connect {
        match transition.connect_serialized(&body.block, body.serialized.clone()) {
            Ok(outcome) => {
                followers.connected(&body.block, &outcome);
                progress.connected += 1;
            }
            Err(source) => {
                let invalidated = if crate::apply::window::is_permanent_apply_error(&source) {
                    let mut tree = handles.block_tree.write();
                    tree.lookup(body.hash)
                        .and_then(|node_id| tree.invalidate_subtree(node_id).ok())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                return (
                    progress,
                    Err(ReorgError::ConnectFailed {
                        disconnected: progress.disconnected,
                        connected: progress.connected,
                        hash: body.hash,
                        stopped_at: body.height.saturating_sub(1),
                        source: Box::new(source),
                        invalidated,
                    }),
                );
            }
        }
    }
    (progress, Ok(()))
}

/// Re-admits the transactions a completed disconnect walk carried out of the
/// chain.
///
/// Core returns disconnected transactions to the mempool so a reorg does not
/// silently destroy everything the departed branch confirmed. The walk runs
/// in dependency order — blocks oldest-first, the reverse of the tip-down
/// disconnect order, and block order within a block, which consensus keeps
/// topological — so a transaction's inputs are decided before the
/// transaction spending them is offered. Coinbase transactions are skipped
/// by the mempool candidate preparer, never by position: a disconnected coinbase
/// must never re-enter the mempool.
///
/// Pricing reads the post-disconnect UTXO set plus the outputs of
/// candidates already offered in this batch, because an unconfirmed sibling
/// output is not a coin yet. A candidate with an unresolvable input is left
/// out, which also keeps its own unconfirmed descendants out. Each offered
/// candidate goes through the [`MempoolGateway`] exactly once; a pool
/// refusal (duplicate, policy floor, package limits) is final and the
/// transaction is dropped, matching Core's best-effort re-add — and a
/// parent that its own successful insert immediately evicted (size
/// pressure) drops its spenders the same way. Transactions the successful
/// connected prefix put back on-chain are excluded by txid, matching Core's
/// `ReconsiderDisconnectedTransactions`: they are confirmed again, not
/// disconnected. An empty disconnect set flows through as the no-op it is.
///
/// Disconnect bodies are re-read from storage one at a time rather than
/// retained from the execution pass, keeping memory bounded by
/// [`DISCONNECT_STREAM_WINDOW`] across the entire reorg. A body that cannot
/// be re-read is skipped, matching Core's best-effort re-add contract.
pub(super) fn reconsider_disconnected_transactions<F>(
    handles: &Chainstate,
    disconnect_nodes: &[(Hash256, u32)],
    disconnected_count: usize,
    reconnected: &[LoadedBranchBody],
    staged_body: &mut F,
) where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    let height = handles.applied_tip.load_full().map_or(0, |tip| tip.height);
    let time = u64::from(current_unix_seconds());
    let still_on_chain: HashSet<Txid> = reconnected
        .iter()
        .flat_map(|body| body.block.txs.iter().map(bitcoin_rs_primitives::Tx::txid))
        .collect();
    let mut candidates = bitcoin_rs_mempool::reconsider::DisconnectedCandidates::new(time, height);
    for (hash, block_height) in disconnect_nodes[..disconnected_count].iter().rev() {
        let Ok(body) = load_branch_body(handles, *hash, *block_height, staged_body) else {
            continue;
        };
        for tx in &body.block.txs {
            if still_on_chain.contains(&tx.txid()) {
                continue;
            }
            candidates.offer(tx, |outpoint| handles.utxo.get(outpoint));
        }
    }
    let _ = handles
        .mempool_gateway
        .reconsider_disconnected(AdmissionOrigin::Reorg, candidates.into_entries());
}

pub(super) fn current_reorg_plan(
    handles: &Chainstate,
    target: NodeId,
) -> core::result::Result<Option<ReorgPlan>, ReorgError> {
    let tree = handles.block_tree.read();
    let Some(current) = handles.applied_tip.load_full() else {
        return Ok(None);
    };
    let Some(current_id) = tree.lookup(current.hash) else {
        return Err(ReorgError::Plan(
            bitcoin_rs_chain::ChainError::UnknownNode { id: target },
        ));
    };
    plan_reorg(&tree, current_id, target)
        .map(Some)
        .map_err(ReorgError::Plan)
}
