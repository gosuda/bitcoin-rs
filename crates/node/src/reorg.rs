//! Switching the applied chain from one tip to another.
//!
//! [`plan_reorg`] says which blocks to disconnect and which to connect;
//! [`crate::apply::disconnect_block`] rolls one back and
//! [`crate::apply::apply_block_with_serialized`] applies one. This joins them.
//! Without it the node follows the chain forward and cannot leave a branch that
//! loses, which is the difference between a chain follower and a full node.

use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin::Transaction;
use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_chain::{NodeId, ReorgPlan, plan_reorg};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;

use crate::apply::ApplyHandles;
use crate::{ApplyError, DisconnectError};

/// Invalidates `hash` and its descendants, then moves applied chainstate to the
/// best remaining valid tip.
pub fn invalidate_block(
    handles: &ApplyHandles,
    hash: Hash256,
) -> core::result::Result<(), ReorgError> {
    let transition = handles
        .begin_chain_transition()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;

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
        let (disconnect, connect) = if let Some(plan) = plan.as_ref() {
            let mut no_staged_body = |_| None;
            (
                load_branch_bodies(handles, &plan.disconnect, &mut no_staged_body)?,
                load_branch_bodies(handles, &plan.connect, &mut no_staged_body)?,
            )
        } else {
            (Vec::new(), Vec::new())
        };

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

        let (_, outcome) = execute_loaded_plan(handles, &disconnect, &connect, &transition);
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
        source: bitcoin::consensus::encode::Error,
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
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
        /// Why the disconnect refused.
        #[source]
        source: Box<DisconnectError>,
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
    F: FnMut(Hash256) -> Option<(bitcoin::Block, bytes::Bytes)>,
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
        let disconnect = load_branch_bodies(handles, &plan.disconnect, &mut staged_body)?;

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

        let (connected, outcome) = execute_loaded_plan(handles, &disconnect, &connect, &transition);
        drop(transition);
        for body in &connect[..connected] {
            connected_body(body.hash);
        }
        outcome?;
        if let Some((hash, height)) = missing_connect {
            return Err(ReorgError::MissingBody { hash, height });
        }
        return Ok(());
    }
}

fn execute_loaded_plan(
    handles: &ApplyHandles,
    disconnect: &[LoadedBranchBody],
    connect: &[LoadedBranchBody],
    transition: &crate::apply::ChainTransition<'_>,
) -> (usize, core::result::Result<(), ReorgError>) {
    // Tip-first disconnect order. Re-admission reverses only the block list so
    // ancestor blocks land first while each block keeps its original tx order.
    let mut disconnected_blocks: Vec<&[Transaction]> = Vec::new();
    for body in disconnect {
        match crate::apply::disconnect_block_admitted(handles, &body.block, transition) {
            Ok(_) => {
                disconnected_blocks.push(body.block.txdata.as_slice());
            }
            Err(error @ (DisconnectError::Fatal { .. } | DisconnectError::MarkerStuck { .. })) => {
                handles.admission.close_permanently();
                return (0, Err(ReorgError::Fatal(Box::new(error))));
            }
            Err(error) => {
                readmit_disconnected_transactions(handles, &disconnected_blocks, transition);
                return (
                    0,
                    Err(ReorgError::Refused {
                        stopped_at: body.height,
                        source: Box::new(error),
                    }),
                );
            }
        }
    }

    let mut connected = 0_usize;
    for body in connect {
        match crate::apply::apply_block_with_serialized_admitted(
            handles,
            &body.block,
            body.serialized.clone(),
            transition,
        ) {
            Ok(_) => connected += 1,
            Err(source) => {
                let invalidated = if is_permanent_invalid(&source) {
                    let mut tree = handles.block_tree.write();
                    tree.lookup(body.hash)
                        .and_then(|node_id| tree.invalidate_subtree(node_id).ok())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                readmit_disconnected_transactions(handles, &disconnected_blocks, transition);
                return (
                    connected,
                    Err(ReorgError::ConnectFailed {
                        hash: body.hash,
                        stopped_at: body.height.saturating_sub(1),
                        source: Box::new(source),
                        invalidated,
                    }),
                );
            }
        }
    }
    readmit_disconnected_transactions(handles, &disconnected_blocks, transition);
    (connected, Ok(()))
}

/// Re-admits disconnected non-coinbase transactions against the applied tip.
///
/// Blocks are walked ancestor-first (the reverse of tip-first disconnect).
/// Transactions inside each block keep their original order; coinbases are
/// skipped. Canonical `admit_transaction` is the sole readmission path.
/// Failures drop that transaction only — they never fail the reorg.
fn readmit_disconnected_transactions(
    handles: &ApplyHandles,
    disconnected_blocks: &[&[Transaction]],
    _transition: &crate::apply::ChainTransition<'_>,
) {
    if disconnected_blocks.is_empty() {
        return;
    }
    let admission = bitcoin_rs_rpc::admission::AdmissionHandles {
        mempool: Arc::clone(&handles.mempool),
        utxo: Arc::clone(&handles.utxo),
        applied_tip: Arc::clone(&handles.applied_tip),
        block_tree: Arc::clone(&handles.block_tree),
        transactions: Arc::clone(&handles.transactions),
    };
    for txdata in disconnected_blocks.iter().rev() {
        for tx in txdata.iter().skip(1) {
            let _ = bitcoin_rs_rpc::admission::admit_transaction(&admission, tx, None);
        }
    }
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
    block: bitcoin::Block,
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
    F: FnMut(Hash256) -> Option<(bitcoin::Block, bytes::Bytes)>,
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
    F: FnMut(Hash256) -> Option<(bitcoin::Block, bytes::Bytes)>,
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
    F: FnMut(Hash256) -> Option<(bitcoin::Block, bytes::Bytes)>,
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
    let mut cursor = std::io::Cursor::new(serialized.as_ref());
    let block =
        bitcoin::Block::consensus_decode(&mut cursor).map_err(|source| ReorgError::BodyDecode {
            hash,
            height,
            source,
        })?;
    validate_branch_body(hash, height, block, serialized)
}

fn validate_branch_body(
    expected: Hash256,
    height: u32,
    block: bitcoin::Block,
    serialized: bytes::Bytes,
) -> core::result::Result<LoadedBranchBody, ReorgError> {
    let actual = Hash256::from_le_bytes(block.block_hash().as_byte_array());
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

/// Returns true when a connect failure is a permanent block-invalidity
/// condition, not an operational error.
///
/// Only these failures poison the branch: the block and its descendants can
/// never become valid, so invalidating the subtree is safe and the node
/// republishes the best valid tip rather than retrying the same block.
/// Operational failures (storage, UTXO commit, undo record) are transient
/// and must not permanently mark a block invalid.
fn is_permanent_invalid(error: &ApplyError) -> bool {
    match error {
        ApplyError::ProofOfWork { .. }
        | ApplyError::TargetAboveLimit
        | ApplyError::NbitsNonRetargetMismatch { .. } => true,
        ApplyError::Consensus(error) => !matches!(
            error,
            bitcoin_rs_consensus::ConsensusError::PrevoutMatrixSize { .. }
                | bitcoin_rs_consensus::ConsensusError::Kernel(_)
                | bitcoin_rs_consensus::ConsensusError::Encoding(_)
        ),
        _ => false,
    }
}
