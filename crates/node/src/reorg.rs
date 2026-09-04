//! Switching the applied chain from one tip to another.
//!
//! [`plan_reorg`] says which blocks to disconnect and which to connect;
//! [`crate::apply::disconnect_block`] rolls one back and
//! [`crate::apply::apply_block_with_serialized`] applies one. This joins them.
//! Without it the node follows the chain forward and cannot leave a branch that
//! loses, which is the difference between a chain follower and a full node.

use std::sync::Arc;

use alloc::vec::Vec;

use bitcoin_rs_chain::{NodeId, ReorgPlan, current_unix_seconds, plan_reorg};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};
use bitcoin_rs_primitives::{Block, DecodeError, Hash256, Tx, Txid};
use bitcoin_rs_storage::StorageError;
use hashbrown::{HashMap, HashSet};

use crate::apply::ApplyHandles;
use crate::{ApplyError, DisconnectError};

/// Settles a rolled-back disconnect marker once the reorg owner has released
/// its chain-transition proof.
///
/// A successful chainstate-journal rewind already disarms the marker, in which
/// case this is a no-op. Publication runs only when `RolledBack` debt remains.
fn settle_disconnect_debt(handles: &ApplyHandles) -> core::result::Result<(), ReorgError> {
    let Some(publisher) = &handles.checkpoint_publisher else {
        return Ok(());
    };
    match publisher.settle_disconnect_debt() {
        Ok(true) => {
            tracing::info!("published checkpoint after branch switch");
            Ok(())
        }
        Ok(false) => Ok(()),
        Err(error) => Err(ReorgError::CheckpointSettlement(anyhow::Error::new(error))),
    }
}

/// Maximum number of disconnect-side block bodies held in memory at once
/// during the streaming execution pass.
///
/// The disconnect walk is strictly serial — each disconnect produces the
/// applied tip the next consumes — so this window is a memory ceiling, not a
/// throughput buffer. At the consensus-maximum block size of 4 MiB, 8 bodies
/// cap peak serialized payload at 32 MiB, negligible next to the UTXO working
/// set of a full node. 4 would underutilize sequential storage read locality;
/// 16 would double the ceiling for no throughput gain in a serial walk.
pub(crate) const DISCONNECT_STREAM_WINDOW: usize = 8;

/// Invalidates `hash` and its descendants, then moves applied chainstate to the
/// best remaining valid tip.
pub fn invalidate_block(
    handles: &ApplyHandles,
    hash: Hash256,
) -> core::result::Result<(), ReorgError> {
    // Validate the block exists and is not genesis before beginning a chain
    // change. A failed validation must not leave the generation odd.
    {
        let tree = handles.block_tree.read();
        let root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
        if tree.node(root).map_err(ReorgError::Plan)?.height == 0 {
            return Err(ReorgError::CannotInvalidateGenesis);
        }
    }

    let transition = handles
        .begin_chain_transition()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;
    let guard = handles
        .mempool_gateway
        .begin_chain_change()
        .map_err(|_| ReorgError::Unavailable(Box::new(ApplyError::Shutdown)))?;
    let proof = crate::apply::ChainChangeProof::new(transition, guard);
    loop {
        let (root, target) = {
            let tree = handles.block_tree.read();
            let root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
            if tree.node(root).map_err(ReorgError::Plan)?.height == 0 {
                return Err(ReorgError::CannotInvalidateGenesis);
            }
            let target = tree
                .tip_after_invalidation(root)
                .map_err(ReorgError::Plan)?
                .ok_or(ReorgError::NoValidTip)?;
            (root, target)
        };

        let plan = current_reorg_plan(handles, target)?;
        let mut no_staged_body = |_| None;
        let (disconnect_nodes, connect) = match plan.as_ref() {
            Some(plan) => {
                let disconnect_nodes = branch_nodes(handles, &plan.disconnect)?;
                let connect = load_branch_bodies(handles, &plan.connect, &mut no_staged_body)?;
                (disconnect_nodes, connect)
            }
            None => (Vec::new(), Vec::new()),
        };
        if !disconnect_nodes.is_empty() {
            preflight_disconnect_bodies(handles, &disconnect_nodes, &mut no_staged_body)?;
        }

        let published_target = {
            let mut tree = handles.block_tree.write();
            let current_root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
            let current_target = tree
                .tip_after_invalidation(current_root)
                .map_err(ReorgError::Plan)?
                .ok_or(ReorgError::NoValidTip)?;
            if current_root != root || current_target != target {
                continue;
            }
            tree.invalidate_subtree(root).map_err(ReorgError::Plan)?;
            let tip = tree.tip().ok_or(ReorgError::NoValidTip)?;
            handles.chain_tip.store(Some(tip.clone()));
            handles.assume_valid_gate.evaluate(&tree);
            tip.tip_id
        };
        debug_assert_eq!(published_target, target);

        let (progress, outcome) = execute_streamed_plan(
            handles,
            &disconnect_nodes,
            &connect,
            &proof,
            &mut no_staged_body,
        );
        match &outcome {
            // A fatal disconnect marker left the chainstate torn: abort
            // without reconsidering anything.
            Err(ReorgError::Fatal(_)) => {}
            // Nonfatal: the final active chain is the successful connected
            // prefix. Reconsider exactly the disconnected transactions that
            // remain off-chain, once, while the transition is still held.
            Ok(()) => {
                reconsider_disconnected_transactions(
                    handles,
                    &disconnect_nodes,
                    progress.disconnected,
                    &connect[..progress.connected],
                    &mut no_staged_body,
                );
            }
            Err(_) => reconsider_disconnected_transactions(
                handles,
                &disconnect_nodes,
                progress.disconnected,
                &connect[..progress.connected],
                &mut no_staged_body,
            ),
        }
        if matches!(&outcome, Ok(())) {
            let _ = proof.finish();
        } else {
            drop(proof);
        }
        let settle_debt = !matches!(&outcome, Err(ReorgError::Fatal(_)));
        if settle_debt {
            if let Err(settlement) = settle_disconnect_debt(handles) {
                outcome?;
                return Err(settlement);
            }
        }
        return outcome;
    }
}

/// Why a branch switch stopped, and what the chain looks like now.
///
/// Four outcomes rather than one error type, because the caller must act
/// differently for each and the difference is exactly how much damage there is.
#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    /// The requested block hash is unknown.
    #[error("unknown block {0}")]
    UnknownBlock(Hash256),
    /// The genesis block cannot be invalidated.
    #[error("cannot invalidate the genesis block")]
    CannotInvalidateGenesis,
    /// Invalidation unexpectedly left no valid chain tip.
    #[error("invalidation left no valid chain tip")]
    NoValidTip,
    /// Planning failed: the two tips share no ancestor, or a node is unknown.
    ///
    /// Nothing was touched.
    #[error("reorg planning failed: {0}")]
    Plan(#[source] bitcoin_rs_chain::ChainError),
    /// A block in the remaining target branch has no stored body.
    ///
    /// If the first connect body is missing, chainstate is untouched. A later
    /// missing body can follow a committed contiguous prefix; the caller must
    /// continue from the published applied tip when that body arrives.
    #[error("no stored body for block {hash} at height {height}")]
    MissingBody {
        /// Block whose body is absent.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
    },
    /// Reading a durable block body failed.
    ///
    /// Nothing was touched. This is not download lag and must remain
    /// distinguishable from an absent body.
    #[error("failed to read body for block {hash} at height {height}: {source}")]
    BodyStore {
        /// Block whose durable body could not be read.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
        /// Storage backend failure.
        #[source]
        source: StorageError,
    },
    /// A durable block body was present but malformed.
    ///
    /// Nothing was touched. Corruption must not be treated as a request retry.
    #[error("failed to decode body for block {hash} at height {height}: {source}")]
    BodyDecode {
        /// Block whose durable body was malformed.
        hash: Hash256,
        /// Height it sits at.
        height: u32,
        /// Consensus decoding failure.
        #[source]
        source: DecodeError,
    },
    /// A loaded body's header names a block other than the planned node.
    ///
    /// Nothing was touched.
    #[error("body hash {actual} does not match planned block {expected} at height {height}")]
    BodyHashMismatch {
        /// Hash named by the reorg plan.
        expected: Hash256,
        /// Hash of the loaded body's header.
        actual: Hash256,
        /// Planned height.
        height: u32,
    },
    /// Preserved bytes are not the serialization of the supplied staged block.
    ///
    /// Nothing was touched.
    #[error("preserved bytes do not match staged block {hash} at height {height}")]
    BodyBytesMismatch {
        /// Planned block hash.
        hash: Hash256,
        /// Planned height.
        height: u32,
    },
    /// Admission closed before this switch mutated chainstate.
    #[error("reorg unavailable before mutation: {0}")]
    Unavailable(#[source] Box<ApplyError>),
    /// A disconnect refused before touching anything.
    ///
    /// The chain is consistent at whatever tip the walk reached. Earlier
    /// disconnects in this switch stand: each one committed fully, so the node
    /// sits on a shorter valid chain and connecting forward recovers it. No
    /// rollback is attempted, because rolling back means disconnecting, and
    /// disconnecting is what just refused.
    #[error("reorg stopped at height {stopped_at}: {source}")]
    Refused {
        /// Fully disconnected blocks before the refusal, in plan order.
        disconnected: usize,
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the disconnect refused.
        #[source]
        source: Box<DisconnectError>,
    },
    /// A disconnect-side body that the preflight pass proved readable could
    /// not be loaded when the streaming execution pass reached it. Storage
    /// can fail between the two passes — a body present and valid in
    /// preflight may be gone or unreadable by the time the walk arrives.
    ///
    /// Earlier disconnects in this switch stand: each committed fully, so the
    /// chain is coherent at whatever tip the walk reached. No rollback is
    /// attempted, because rolling back means disconnecting, and the body
    /// needed for the next disconnect is the one that just became
    /// unreadable. A later switch can move the chain from here once the body
    /// is available again.
    #[error(
        "reorg stopped at height {stopped_at} after {disconnected} disconnects: body lost mid-rollback: {source}"
    )]
    DisconnectBodyLost {
        /// Fully disconnected blocks before the loss, in plan order.
        disconnected: usize,
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the body could not be loaded.
        #[source]
        source: Box<Self>,
    },
    /// A connect failed after some of the new branch was applied.
    ///
    /// The chain is consistent at a prefix of the target branch: every block
    /// before this one committed fully. The switch is abandoned rather than
    /// rolled back — undoing the prefix means disconnecting blocks that just
    /// applied, which can fail Fatal and turn a recoverable stop into an
    /// unrecoverable one. A later switch can move the chain from here.
    ///
    /// When `source` is permanently invalid (`PoW`, `nBits`, or consensus),
    /// the failed block's subtree is invalidated while the chain transition is
    /// still held, and `invalidated` carries every hash that was marked
    /// `Invalid` so the caller can purge staged/download state after releasing
    /// the transition. Operational failures leave `invalidated` empty.
    #[error("reorg stopped after connecting to height {stopped_at} at block {hash}: {source}")]
    ConnectFailed {
        /// Fully disconnected blocks before the failure, in plan order.
        disconnected: usize,
        /// Fully connected new-branch blocks before the failure, in plan order.
        connected: usize,
        /// Hash of the block that failed to connect.
        hash: Hash256,
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the connect failed.
        #[source]
        source: Box<ApplyError>,
        /// Hashes of the invalid subtree, in deterministic slab order, when the
        /// failure was allowlisted for permanent invalidation. Empty for
        /// operational failures.
        invalidated: Vec<Hash256>,
    },
    /// A disconnect died partway. The chainstate is torn.
    ///
    /// Propagated immediately and never continued past: applying the new branch
    /// on top of a half-rolled-back state would build on a chain the node
    /// cannot describe. The in-flight marker is already durable, so a restart
    /// refuses rather than serving it.
    #[error("reorg left the chainstate inconsistent: {0}")]
    Fatal(#[source] Box<DisconnectError>),
    /// A nonfatal reorg completed, but the rolled-back state could not be
    /// checkpointed. The chain is coherent at the reached tip and the
    /// disconnect marker remains `RolledBack`; a restart will refuse the data
    /// directory until a later checkpoint publishes this state.
    #[error("disconnect left a checkpoint debt the node could not settle: {0}")]
    CheckpointSettlement(#[source] anyhow::Error),
}

/// Switches the applied chain to `target`.
///
/// Disconnects back to the common ancestor, then applies the target branch
/// forward. Both walks take the plan's order: `disconnect` runs from the old
/// tip downward, `connect` from the ancestor's child upward. `connected_body`
/// runs once per committed new-branch block after the transition guard releases.
///
/// # Errors
///
/// Every outcome other than reaching `target` is a [`ReorgError`] variant
/// naming how far the chain moved, because "it failed" does not tell a caller
/// whether the node is fine, degraded, or unusable.
pub fn switch_to_branch<F, G>(
    handles: &ApplyHandles,
    target: NodeId,
    mut staged_body: F,
    mut connected_body: G,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    G: FnMut(Hash256),
{
    loop {
        let Some(plan) = current_reorg_plan(handles, target)? else {
            return Ok(());
        };

        // A staged prefix can be committed without waiting for the entire
        // winning branch to fit in the bounded stager.
        let (connect, missing_connect) =
            load_available_branch_prefix(handles, &plan.connect, &mut staged_body)?;
        if connect.is_empty()
            && let Some((hash, height)) = missing_connect
        {
            return Err(ReorgError::MissingBody { hash, height });
        }
        let disconnect_nodes = branch_nodes(handles, &plan.disconnect)?;
        preflight_disconnect_bodies(handles, &disconnect_nodes, &mut staged_body)?;

        let transition = handles
            .begin_chain_transition()
            .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;

        // Preloading is optimistic. Only an identical plan recomputed while the
        // transition lock is held may mutate chainstate.
        let Some(authoritative) = current_reorg_plan(handles, target)? else {
            return Ok(());
        };
        if plan != authoritative {
            drop(transition);
            continue;
        }

        // G5: start the guard after fallible read-only planning and before the
        // first chain mutation. A replan above drops the transition without
        // beginning a generation, so the gateway stays even and the loop
        // retries. An error during execution leaves the generation odd by
        // design — admission stays closed.
        let guard = handles
            .mempool_gateway
            .begin_chain_change()
            .map_err(|_| ReorgError::Unavailable(Box::new(ApplyError::Shutdown)))?;
        let proof = crate::apply::ChainChangeProof::new(transition, guard);
        let (progress, outcome) = execute_streamed_plan(
            handles,
            &disconnect_nodes,
            &connect,
            &proof,
            &mut staged_body,
        );
        match &outcome {
            // A fatal disconnect marker left the chainstate torn: abort
            // without reconsidering anything.
            Err(ReorgError::Fatal(_)) => {}
            // Every other outcome leaves the final active chain known: the
            // successful connected prefix. Reconsider exactly the
            // disconnected transactions that remain off-chain, exactly once,
            // while the chain transition is still held.
            _ => reconsider_disconnected_transactions(
                handles,
                &disconnect_nodes,
                progress.disconnected,
                &connect[..progress.connected],
                &mut staged_body,
            ),
        }
        for body in &connect[..progress.connected] {
            connected_body(body.hash);
        }
        if matches!(&outcome, Ok(())) {
            let _ = proof.finish();
        } else {
            drop(proof);
        }
        if !matches!(&outcome, Err(ReorgError::Fatal(_))) {
            if let Err(settlement) = settle_disconnect_debt(handles) {
                outcome?;
                return Err(settlement);
            }
        }
        outcome?;
        if let Some((hash, height)) = missing_connect {
            return Err(ReorgError::MissingBody { hash, height });
        }
        return Ok(());
    }
}

/// How far a loaded branch-switch walk got before it stopped.
///
/// Both counts are exact committed progress: every block past them was left
/// untouched by this walk.
#[derive(Clone, Copy, Debug)]
struct LoadedPlanProgress {
    /// Fully disconnected blocks, in plan (old-tip-down) order.
    disconnected: usize,
    /// Fully connected new-branch blocks, in plan (ancestor-child-up) order.
    connected: usize,
}

/// Validates that every disconnect-side body is present, decodable, and
/// hash-correct without retaining any of them.
///
/// This is the first of two passes: it discovers a missing or corrupt
/// old-branch body before the rollback starts, preserving the "nothing was
/// touched" failure model for body-load errors. The execution pass
/// ([`execute_streamed_plan`]) re-reads each body in a bounded window;
/// storage can fail between the two passes, and that mid-rollback failure is
/// reported as [`ReorgError::DisconnectBodyLost`].
fn preflight_disconnect_bodies<F>(
    handles: &ApplyHandles,
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
fn applied_tip_height(handles: &ApplyHandles) -> u32 {
    handles.applied_tip.load_full().map_or(0, |tip| tip.height)
}

fn execute_streamed_plan<F>(
    handles: &ApplyHandles,
    disconnect_nodes: &[(Hash256, u32)],
    connect: &[LoadedBranchBody],
    proof: &crate::apply::ChainChangeProof<'_>,
    staged_body: &mut F,
) -> (LoadedPlanProgress, core::result::Result<(), ReorgError>)
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
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
            match crate::apply::disconnect_block_admitted(handles, &body.block, proof) {
                Ok(_) => progress.disconnected += 1,
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
        match crate::apply::apply_block_with_serialized_admitted(
            handles,
            &body.block,
            body.serialized.clone(),
            proof,
        ) {
            Ok(_) => progress.connected += 1,
            Err(source) => {
                let invalidated = if crate::apply::is_permanent_apply_error(&source) {
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
/// by structure (`is_coinbase`), never by position: a disconnected coinbase
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
fn reconsider_disconnected_transactions<F>(
    handles: &ApplyHandles,
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
    let mut offered: HashMap<Txid, Vec<u64>> = HashMap::new();
    let mut entries = Vec::new();
    for (hash, block_height) in disconnect_nodes[..disconnected_count].iter().rev() {
        let Ok(body) = load_branch_body(handles, *hash, *block_height, staged_body) else {
            continue;
        };
        for tx in &body.block.txs {
            if is_coinbase(tx) || still_on_chain.contains(&tx.txid()) {
                continue;
            }
            let Some((entry, output_values)) =
                reconsider_entry(&handles.utxo, tx, time, height, &offered)
            else {
                continue;
            };
            offered.insert(tx.txid(), output_values);
            entries.push(entry);
        }
    }
    let _ = handles
        .mempool_gateway
        .reconsider_disconnected(AdmissionOrigin::Reorg, entries);
}

/// Core's `IsCoinBase`: a single input spending the null prevout (zero txid,
/// `vout` `u32::MAX`). The derived all-zero outpoint (`vout` 0) is not null.
fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}

/// Prices `tx` for re-admission, or returns `None` when an input is neither a
/// restored confirmed coin nor an output of an earlier candidate in the same
/// batch.
fn reconsider_entry(
    utxo: &bitcoin_rs_utxo::UtxoSet,
    tx: &Tx,
    time: u64,
    height: u32,
    offered: &HashMap<Txid, Vec<u64>>,
) -> Option<(MempoolEntry, Vec<u64>)> {
    let mut input_total = 0_u64;
    for input in &tx.inputs {
        let outpoint = input.previous_output;
        if let Some(output) = utxo.get(&outpoint) {
            input_total = input_total.saturating_add(output.value);
            continue;
        }
        let values = offered.get(&input.previous_output.txid)?;
        let value = values
            .get(usize::try_from(input.previous_output.vout).ok()?)
            .copied()?;
        input_total = input_total.saturating_add(value);
    }
    let output_values: Vec<u64> = tx.outputs.iter().map(|output| output.value).collect();
    let output_total = output_values
        .iter()
        .fold(0_u64, |total, value| total.saturating_add(*value));
    let fee = input_total.saturating_sub(output_total);
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    Some((
        MempoolEntry::new(Arc::new(tx.clone()), vsize, fee, time, height),
        output_values,
    ))
}

fn current_reorg_plan(
    handles: &ApplyHandles,
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

struct LoadedBranchBody {
    hash: Hash256,
    block: Block,
    serialized: bytes::Bytes,
    height: u32,
}

type LoadedBranchPrefix = (Vec<LoadedBranchBody>, Option<(Hash256, u32)>);

/// Loads every block named by a branch, in the order given.
fn load_branch_bodies<F>(
    handles: &ApplyHandles,
    ids: &[NodeId],
    staged_body: &mut F,
) -> core::result::Result<Vec<LoadedBranchBody>, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    branch_nodes(handles, ids)?
        .into_iter()
        .map(|(hash, height)| load_branch_body(handles, hash, height, staged_body))
        .collect()
}

/// Loads the contiguous available prefix and names the first missing body.
fn load_available_branch_prefix<F>(
    handles: &ApplyHandles,
    ids: &[NodeId],
    staged_body: &mut F,
) -> core::result::Result<LoadedBranchPrefix, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    let nodes = branch_nodes(handles, ids)?;
    let mut loaded = Vec::with_capacity(nodes.len());
    for (hash, height) in nodes {
        match load_branch_body(handles, hash, height, staged_body) {
            Ok(body) => loaded.push(body),
            Err(ReorgError::MissingBody { .. }) => {
                return Ok((loaded, Some((hash, height))));
            }
            Err(error) => return Err(error),
        }
    }
    Ok((loaded, None))
}

fn branch_nodes(
    handles: &ApplyHandles,
    ids: &[NodeId],
) -> core::result::Result<Vec<(Hash256, u32)>, ReorgError> {
    let tree = handles.block_tree.read();
    ids.iter()
        .map(|id| {
            let node = tree.node(*id).map_err(ReorgError::Plan)?;
            Ok((node.hash, node.height))
        })
        .collect()
}

fn load_branch_body<F>(
    handles: &ApplyHandles,
    hash: Hash256,
    height: u32,
    staged_body: &mut F,
) -> core::result::Result<LoadedBranchBody, ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
{
    if let Some((block, serialized)) = staged_body(hash) {
        return validate_branch_body(hash, height, block, serialized);
    }
    if let Some(store) = handles.block_body_store.as_ref()
        && let Some(body) =
            store
                .load_block_body(height, hash)
                .map_err(|source| ReorgError::BodyStore {
                    hash,
                    height,
                    source,
                })?
    {
        return decode_branch_body(hash, height, bytes::Bytes::from(body));
    }
    Err(ReorgError::MissingBody { hash, height })
}

fn decode_branch_body(
    hash: Hash256,
    height: u32,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let block =
        Block::consensus_decode(serialized.as_ref()).map_err(|source| ReorgError::BodyDecode {
            hash,
            height,
            source,
        })?;
    validate_branch_body(hash, height, block, serialized)
}

fn validate_branch_body(
    expected: Hash256,
    height: u32,
    block: Block,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let actual = block.block_hash().0;
    if actual != expected {
        return Err(ReorgError::BodyHashMismatch {
            expected,
            actual,
            height,
        });
    }
    if !crate::apply::bytes_are_block(serialized.as_ref(), &block) {
        return Err(ReorgError::BodyBytesMismatch {
            hash: expected,
            height,
        });
    }
    Ok(LoadedBranchBody {
        hash: expected,
        block,
        serialized,
        height,
    })
}
