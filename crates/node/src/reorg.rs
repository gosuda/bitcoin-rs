//! Switching the applied chain from one tip to another.
//!
//! [`plan_reorg`] says which blocks to disconnect and which to connect;
//! [`crate::apply::disconnect_block`] rolls one back and
//! [`crate::apply::apply_block_with_serialized`] applies one. This joins them.
//! Without it the node follows the chain forward and cannot leave a branch that
//! loses, which is the difference between a chain follower and a full node.

mod bodies;
mod execution;
mod settlement;

use crate::ApplyError;
use crate::DisconnectError;
use crate::apply::Chainstate;
use crate::chain_effects::ChainFollowers;
use alloc::vec::Vec;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::DecodeError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;
use bodies::branch_nodes;
use bodies::load_available_branch_prefix;
use bodies::load_branch_bodies;
use execution::current_reorg_plan;
use execution::execute_streamed_plan;
use execution::preflight_disconnect_bodies;
use execution::reconsider_disconnected_transactions;
use settlement::settle_reorg_transition;

#[cfg(test)]
mod tests;

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
    handles: &Chainstate,
    followers: &ChainFollowers,
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
        .begin_transition()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;
    // Keep read-only planning refusals in the same settlement path as the
    // execution outcome; an early `?` must not strand a coherent generation.
    let outcome = (|| {
        let target = {
            let tree = handles.block_tree.read();
            let root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
            if tree.node(root).map_err(ReorgError::Plan)?.height == 0 {
                return Err(ReorgError::CannotInvalidateGenesis);
            }
            tree.tip_after_invalidation(root)
                .map_err(ReorgError::Plan)?
                .ok_or(ReorgError::NoValidTip)?
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

        let (progress, outcome) = execute_streamed_plan(
            &transition,
            followers,
            &disconnect_nodes,
            &connect,
            &mut no_staged_body,
        );
        if progress.disconnected == disconnect_nodes.len()
            && !outcome.as_ref().is_err_and(ReorgError::requires_recovery)
        {
            let mut tree = handles.block_tree.write();
            let root = tree.lookup(hash).ok_or(ReorgError::UnknownBlock(hash))?;
            tree.invalidate_subtree(root).map_err(ReorgError::Plan)?;
            let tip = tree.tip().ok_or(ReorgError::NoValidTip)?;
            handles.chain_tip.store(Some(tip));
            handles.assume_valid_gate.evaluate(&tree);
        }
        if !outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
            reconsider_disconnected_transactions(
                handles,
                &disconnect_nodes,
                progress.disconnected,
                &connect[..progress.connected],
                &mut no_staged_body,
            );
        }
        outcome
    })();
    settle_reorg_transition(transition, outcome)
}

/// Why a branch switch stopped, and what the chain looks like now.
///
/// Typed outcomes preserve whether the reached state is coherent or requires
/// recovery, along with the committed prefix and original failure.
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
    /// Every block before this one committed fully. A refusal before the UTXO
    /// commit leaves a consistent prefix of the target branch; a
    /// [`ApplyError::UtxoCommit`] failure may leave partial coin changes and
    /// requires recovery with admission closed. The switch is abandoned
    /// rather than rolled back — undoing the prefix means disconnecting blocks that just
    /// applied, which can fail Fatal and turn a recoverable stop into an
    /// unrecoverable one. A later switch can continue from a coherent prefix;
    /// a failed UTXO commit must first recover its authoritative state.
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
    /// The chain walk concluded, but its stable generation could not be
    /// published. Admission is permanently closed and shutdown is requested.
    #[error("reorg generation could not be settled: {source}")]
    TransitionSettlement {
        /// Why the reserved even generation could not be published.
        #[source]
        source: Box<ApplyError>,
        /// Execution failure retained when settlement followed a refusal.
        original: Option<Box<Self>>,
    },
    /// A nonfatal reorg completed, but the rolled-back state could not be
    /// checkpointed. The chain is coherent at the reached tip and the
    /// disconnect marker remains `RolledBack`; a restart will refuse the data
    /// directory until a later checkpoint publishes this state.
    #[error("disconnect left a checkpoint debt the node could not settle: {0}")]
    CheckpointSettlement(#[source] anyhow::Error),
}

impl ReorgError {
    /// Whether the execution outcome forbids stable publication and derived
    /// work. Keep this decision with the original typed cause, not a second
    /// disposition that can drift from it.
    fn requires_recovery(&self) -> bool {
        match self {
            Self::Fatal(_) | Self::TransitionSettlement { .. } => true,
            Self::ConnectFailed { source, .. } => {
                matches!(source.as_ref(), ApplyError::UtxoCommit(_))
            }
            Self::UnknownBlock(_)
            | Self::CannotInvalidateGenesis
            | Self::NoValidTip
            | Self::Plan(_)
            | Self::MissingBody { .. }
            | Self::BodyStore { .. }
            | Self::BodyDecode { .. }
            | Self::BodyHashMismatch { .. }
            | Self::BodyBytesMismatch { .. }
            | Self::Unavailable(_)
            | Self::Refused { .. }
            | Self::DisconnectBodyLost { .. }
            | Self::CheckpointSettlement(_) => false,
        }
    }
}

/// Switches the applied chain to `target`.
///
/// Disconnects back to the common ancestor, then applies the target branch
/// forward. Both walks take the plan's order: `disconnect` runs from the old
/// tip downward, `connect` from the ancestor's child upward. `connected_body`
/// runs once per committed new-branch block while the transition is still held.
///
/// # Errors
///
/// Every outcome other than reaching `target` is a [`ReorgError`] variant
/// naming how far the chain moved, because "it failed" does not tell a caller
/// whether the node is fine, degraded, or unusable.
pub fn switch_to_branch<F, G>(
    handles: &Chainstate,
    followers: &ChainFollowers,
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

        let lock = handles
            .lock_transition()
            .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;

        // Preloading is optimistic. Only an identical plan recomputed while the
        // transition lock is held may mutate chainstate.
        let Some(authoritative) = current_reorg_plan(handles, target)? else {
            return Ok(());
        };
        if plan != authoritative {
            drop(lock);
            continue;
        }

        // G5: start the guard after fallible read-only planning and before the
        // first chain mutation. A replan above drops the lock without
        // beginning a generation, so the gateway stays even and the loop
        // retries. Execution settles coherent prefixes explicitly; possibly
        // torn state retains the odd generation until recovery.
        let transition = handles
            .begin_transition_locked(lock)
            .map_err(|_| ReorgError::Unavailable(Box::new(ApplyError::Shutdown)))?;
        let (progress, outcome) = execute_streamed_plan(
            &transition,
            followers,
            &disconnect_nodes,
            &connect,
            &mut staged_body,
        );
        if !outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
            // Reconsider only against a coherent committed prefix, before
            // reopening admission at the reserved even generation.
            reconsider_disconnected_transactions(
                handles,
                &disconnect_nodes,
                progress.disconnected,
                &connect[..progress.connected],
                &mut staged_body,
            );
        }
        for body in &connect[..progress.connected] {
            connected_body(body.hash);
        }
        settle_reorg_transition(transition, outcome)?;
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

struct LoadedBranchBody {
    hash: Hash256,
    block: Block,
    serialized: bytes::Bytes,
    height: u32,
}

type LoadedBranchPrefix = (Vec<LoadedBranchBody>, Option<(Hash256, u32)>);
